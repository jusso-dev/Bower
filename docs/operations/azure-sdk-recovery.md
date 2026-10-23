# Azure delivery and SDK recovery (AZ-01, AZ-03, AZ-04, DUR-01)

This change is validated with simulated HTTP responses and local queues only.
Ingestion acceptance is not Sentinel query verification. No live Azure permission,
upload, production replay or historical loss claim is made.

## Request ownership and failure classification

Both data planes construct their own JSON-array requests, at most 1,048,576
uncompressed UTF-8 bytes including brackets and commas. Default concurrency remains
four; each result belongs to the IDs in its own request. C# uses the supported
`LogsIngestionClient.UploadAsync(RequestContent, ...)` protocol overload, not the
SDK enumerable batching/callback overload. Rust has its own reordered-response
regression; it does not inherit the defective callback attribution algorithm.
Acknowledgements contain only `azure-logs-ingestion:accepted:owned-batches` and the
accepted IDs; arbitrary service request IDs and response bodies are not retained.

Malformed, mismatched and locally invalid payloads still fail individually.
An HTTP error alone does not prove record poison: 401/403, DCR/stream errors,
throttling, transport/token failures and 5xx become retryable `destination-*`
failures. Ambiguous 400 batches can be bisected, with at most 16 additional
requests per delivery call (SDK transport retries are separately bounded).
Valid siblings can progress; unresolved singletons stay pending. A future
server retry deadline suppresses immediate isolation. There is intentionally no
heuristic parsing of potentially sensitive service error bodies to condemn a
record. Persistent unresolved 400s need operator investigation.

## Durable destination circuit and persistence integration

The queue currently feeds one configured destination. A future retrying row with
`last_failure_code GLOB 'destination-*'` pauses **all new leases** from that queue,
including newly queued backlog. Its existing `next_attempt_at` survives process
restart. The worker uses the later of a 30-second destination cooldown and the
terminal response's Retry-After deadline (seconds, HTTP date, or Azure millisecond
headers). Healthy records do not exhaust poison budgets during an outage: the
same failure-settlement transaction refunds the lease's attempt increment.
The circuit opens again when the greatest outstanding deadline expires. Request
concurrency and queue capacity remain bounded; a full queue must apply intake
backpressure rather than delete pending records.

No new persisted columns or migration are needed. The integration is six SQL
lines in each queue implementation: a lease-selection `NOT EXISTS` guard and an
attempt refund restricted to retryable destination settlements. Persistence/lease
fencing changes must preserve those operations inside their existing transactions
and guards. `destination-` is a reserved internal code prefix, case-sensitive in
both runtimes; adapters must not use it for individual permanent failures.

Upgrade all workers using a queue together. Do not concurrently run an older
worker: older workers ignore this circuit and can still consume attempt budgets.
The on-disk schema stays readable, but rollback restores the older unsafe delivery
semantics; stop delivery and preserve the queue instead of rolling back an active
outage. These changes alone do not add a mixed-version runtime rejection fence;
that remains part of persistence migration coordination. Multi-destination routing
would require destination-keyed circuit storage before sharing a queue.

## SDK accounting and migration

`EmitResult.AcceptedForDelivery` means accepted into process memory, not durable
storage and not confirmed collector acceptance. The nonblocking channel now returns
`bounded-buffer-full` instead of silently discarding while reporting acceptance.
Applications needing critical audit durability must use a transactional outbox;
process crash recovery is not supplied by this in-memory SDK.

Resolve `IBowerTelemetryDiagnostics` from the service provider (registered by
`AddBower`) and read `DeliveryStatus`, a payload-free, consistent snapshot:

- `Accepted = Delivered + Failed + Pending`.
- `Rejected` counts calls never accepted (overflow, stopped or faulted sender).
- `Delivered` means collector HTTP acceptance, not Azure or Sentinel delivery.
- `Retries`, `LastFailureCode` and `SenderState` expose sender health without bodies.

The existing `IBowerTelemetry` interface is unchanged; diagnostics are an optional
additive interface, so custom implementations do not acquire a required member.
The built-in client defaults to three send attempts, a 250 ms retry delay and the
existing request timeout. Retry applies only to network/timeouts, 408, 429 and 5xx;
422 and other permanent collector rejections are explicitly failed. Options bound
attempts to 1–10, retry delay to 0–30 seconds, request timeout and shutdown flush to
at most one minute. Retries reuse the same event ID. An HTTP response lost after
collector acceptance can cause replay; collector idempotency remains necessary.

Fail-open continues accepting later events while exposing failures. Strict mode
closes the writer on terminal failure; later producers receive `sender-faulted`.
Shutdown closes intake, drains within the configured flush timeout, then cancels
and joins the sender before disposing transport resources. Every remaining
accepted item becomes explicitly failed with `shutdown-timeout`; no accepted
items remain pending when disposal returns. Poll/export status before application
exit; counters are in-memory and are not an audit ledger.

## Conditional historical reconciliation and controlled replay

The prior false acknowledgement was reproduced with simulated HTTP. Historical
production loss is **not established**. If an affected deployment existed:

1. Identify exact release, default/explicit concurrency, deployment and retention
   windows. Stop unsafe delivery/purge as appropriate under operator authority.
   Preserve consistent queue/WAL backups, source identities and retained evidence.
2. Compare available source event IDs with destination query results for the
   intended workspace/table and time window. Review mismatched acknowledgements;
   neither an old acknowledgement nor one successful canary proves completeness.
   Purged records may not be reconstructable. Do not infer missing IDs from counts.
3. Repair identity, exact-DCR permissions, endpoint and stream configuration.
   Pending destination failures resume automatically after the persisted deadline;
   no replay is needed for those rows. Verify a separately authorised canary by ID
   and expected sanitized fields at the destination.
4. Inventory old dead letters with metadata-only commands, select reviewed IDs,
   and replay in bounded groups only under explicit operational authority:

   ```sh
   bower queue dead-letters --database /path/to/bower.db --max 100
   bower queue replay --database /path/to/bower.db --event REVIEWED_EVENT_ID --max 1
   ```

   Historical auth failures may have `azure-http-401`, `azure-http-403`, or
   `max-attempts-exceeded:` codes. Prefer exact IDs; broad prefix replay can include
   unrelated poison events. Existing replay handles dead letters only; it cannot
   recover purged records or automatically replay incorrectly delivered rows.
   Source replay requires stable IDs, retained content and separate reconciliation.
5. Retain an external change/audit record: operator, approval, selected IDs,
   failure classification, before/after counts, exact command, timestamp and
   destination query evidence. Existing CLI replay prints a count; it does **not**
   create a complete operator audit trail. Do not call that count proof of delivery.

No recovery or replay operation was performed as part of this implementation.
