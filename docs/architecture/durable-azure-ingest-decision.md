# Decision: durable queue for the Azure Functions collector

Status: **proposed** (09-11-2026), awaiting approval. Issue: #137.

## Context

The [Azure Functions collector](../deployment/azure-function.md) validates, redacts and
selects events like the HTTP collector, but it has no durable queue: it uploads to the
Logs Ingestion API inside the request and answers 202 only after Azure acknowledged the
batch. When Logs Ingestion throttles or is down, the producer gets 429 or 503 and must
retry. There is no dead-letter queue, no replay and no ledger, and suppression cannot run
because it needs durable counts.

The goal is a hosted intake that answers 202 once the redacted, policy-approved event is
durably stored, then delivers asynchronously with retries, idempotency, a visible
dead-letter queue and audited replay.

## Options

| | (a) Durable Functions | (b) Web or Container App plus Event Grid | (c) Function plus Service Bus queue |
|---|---|---|---|
| Shape | HTTP starter, orchestration, upload activity | Always-on intake publishes to Event Grid, which pushes to a delivery handler | HTTP intake function sends to a Service Bus queue; a Service Bus triggered function delivers |
| Durability before 202 | Task hub write (Storage, Netherite or MSSQL backend) | Event Grid publish | Service Bus send acknowledged |
| Duplicate handling | Orchestration instance ids, reasoned about per replay | None (at-least-once push) | Native duplicate detection on `MessageId` (Standard and Premium tiers, set at queue creation) |
| Dead letters | No native concept; build it | Dead-letter to blob, separate replay tooling | Native dead-letter subqueue with reason, max delivery count |
| Replay | Custom | Custom from blob | Resubmit from the dead-letter subqueue |
| Fit for a per-event pipeline | Heavy: orchestration history per batch, replay semantics | Fan-out Bower doesn't use; adds a hop | Point to point, peek-lock, batching |
| Code change | New orchestration model | New always-on host | Keeps the existing function and its pipeline; adds one trigger |

## Recommendation

**(c), Service Bus, without Event Grid.** It keeps `FunctionCollector` and the existing
`SecurityEventProcessor`, gives native duplicate detection and dead-lettering, and adds no
extra at-least-once hop. If an always-on intake is ever needed for latency or network
reasons, the same queue works behind a Container App.

Design:

1. **Intake** (existing HTTP function): authenticate, validate, redact, decide, then send the
   envelope to the queue. Answer 202 only after the send is acknowledged; 503 with
   `Retry-After` only for retryable send failures.
   - **Retry-stable `MessageId`:** derive it from the producer's `eventId` and source
     identity, not from a fingerprint over redacted content. A privacy HMAC key rotation
     between attempts changes redacted values, so a content fingerprint would let Service
     Bus accept both attempts.
   - **Identity conflicts before 202:** Service Bus duplicate detection drops a second send
     with the same `MessageId` and still acknowledges it, so it can't report a conflict. The
     intake keeps a small durable identity record (`MessageId` to a hash of the redacted
     envelope, for example in Table Storage) and answers **409**
     `event-identity-conflict` when a different envelope arrives under the same identity,
     exactly as the HTTP collector does
     ([event identity conflicts](../operations/event-identity-conflicts.md)). Only a match or
     a new identity proceeds to the send.
   - **Oversized events:** the intake already refuses events over 1 MiB with 413, but
     Standard Service Bus refuses messages over 256 KB. On Standard the intake must reject an
     encoded envelope over the tier limit with a permanent **413** and an actionable reason
     before sending, never 503, so producers don't retry an unchanged event forever.
2. **Delivery** (new Service Bus triggered function): batch, upload with the managed identity
   through the existing `AzureLogsIngestionOutput`, honour `Retry-After` and adaptive
   concurrency. Retryable failures abandon with back-off; non-retryable ones
   (`payload-invalid-json`, `azure-http-400-isolated`) dead-letter at once with the Bower
   reason code. Retryable failures dead-letter after the queue's max delivery count.
   Delivery is **at-least-once**: if an upload succeeds but the message lock is lost before
   completion, the message is delivered and uploaded again, and Sentinel gets a second row
   with the same `EventId`. Neither duplicate detection nor deterministic ids prevent this.
   Analytics and reconciliation queries must deduplicate on `EventId` (for example
   `summarize arg_max(TimeGenerated, *) by EventId`), as they already must for the
   collector's own at-least-once boundary.
3. **Dead letters**: counts and reason codes in fleet health; audited replay of selected
   dead letters by `Bower.Operator` or above through the management API, metadata only.
4. **Identity and network**: managed identity for Service Bus (Data Sender for intake, Data
   Receiver for delivery) and Logs Ingestion; no connection strings. Australian regions by
   default, with a Bicep check refusing others unless explicitly allowed.

## Consequences and costs

- **New dependency:** `Azure.Messaging.ServiceBus` and the Functions Service Bus extension,
  both Microsoft-owned. `docs/architecture/dependencies.md` needs the justification.
- **Tier:** Standard covers duplicate detection and dead-lettering. **Private endpoints and
  public access off need Premium**, which costs far more (a messaging unit is billed
  hourly). The Bicep would offer Standard by default and Premium as an explicit choice.
- **Plan:** Flex Consumption supports VNet integration and target-based scaling for Service
  Bus triggers.
- **Data at rest:** only redacted, policy-approved events reach the queue. Service Bus
  encrypts at rest; customer-managed keys need Premium.
- **Identity record:** a small table of `MessageId` to envelope hash, kept at least as long
  as the duplicate detection window; no event bodies.
- **Threat model:** a new trust boundary at the queue. The delivery identity can only send
  to the granted DCR.
- **Testing:** unit tests can cover enqueue-before-ack, identity to `MessageId`, the 409
  identity-conflict check, the tier size limit and error classification. Poison, duplicate, throttling and outage behaviour need a real throwaway
  namespace, which means Azure spend and is out of scope until approved.

## Decisions needed

1. Approve (c) and the two new Microsoft packages.
2. Standard by default with Premium optional, or Premium only (private endpoints mandatory)?
3. Who may spend on a throwaway namespace for the integration tests, and when?
