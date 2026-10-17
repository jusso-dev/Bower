# Architecture

Bower separates candidate acquisition, local protection, deterministic selection,
durability and delivery. No source or output adapter may bypass redaction, schema
validation or policy decision.

## Trust boundaries

1. Source records are untrusted, bounded input.
2. Privacy & Secret Protection Engine (`Bower.Redaction`) removes field-name
   secrets and scans string values for regulated AU identifiers, credentials and
   crypto material before typed parsing and persistence. See
   [privacy engine](../privacy/privacy-secret-engine.md).
3. Policy Engine accepts only approved semantic types with required context.
4. SQLite queue is tenant-controlled durable state; delivery leases recover after
   crashes and acknowledged rows remain auditable until retention.
5. Output adapters receive only arranged, redacted envelopes.
6. Azure acknowledgement proves API acceptance, not Sentinel queryability.

Stable fingerprints exclude collection and ingestion times. Current fingerprint
uses source ID, semantic type/action, application/tenant, actor, target, result and
source generation time.

## Queue transitions

```text
queued → uploading → delivered
                 ├→ retrying → uploading
                 └→ dead-lettered
```

Only leased `uploading` records can transition. Expired leases become eligible
after abrupt shutdown. Payload rows are not deleted during acknowledgement; the
`queue-retention` job removes `delivered` rows only after the retention window.
Retryable failures dead-letter after `BOWER_MAX_DELIVERY_ATTEMPTS` leases.
Events an adapter acknowledges in one delivery batch are marked `delivered` in a
single queue transaction; an event whose lease was reclaimed meanwhile is skipped.
Failed events in the batch (retrying and dead-lettered, including events the
adapter did not report) are settled in one more transaction with the same
`uploading` guard. Either batch is all-or-nothing: on a storage error nothing in it
is settled, the events stay leased and are redelivered after the lease expires
(at-least-once).

Enqueue checks for a duplicate (same event id or fingerprint, in any state) before
the capacity check, inside the same `BEGIN IMMEDIATE` transaction, so a re-sent
event is reported as a duplicate even when the queue is full. Invalid input (blank,
NUL-containing or over-128-character event id, blank fingerprint, empty payload) is
rejected as an error and is never reported as a duplicate. Ledger verification
reads events and ledger entries in one read transaction, so concurrent enqueues
cannot produce false issues.

The source cursor store runs `CREATE TABLE IF NOT EXISTS` on every start (WAL only
for a new file) and treats any failed cursor write as a lost race (`false`). The
C# and Rust stores share the same DDL, column order and timestamp text.
Queue schema version 4 adds a covering index on `(state, payload_bytes,
received_at)` so the per-enqueue capacity check does not read stored payloads; it
is created idempotently on start-up.

## Agents and cloud queues

Agents (`Bower.Agent.Docker`, `Bower.Agent.Cloud`) are producers, not collectors:
they map source records to candidate events and post them to a collector through
`Bower.Forwarding`, so every event still passes redaction, schema validation and
policy there. Their upstream position (a file cursor, an SQS message, a Pub/Sub ack
id) advances only when the collector accepted or definitively rejected every event
derived from it. Cloud queues keep their own dead-letter policies; the cloud agent
releases malformed messages to them and never deletes on backpressure. See
[AWS](../deployment/aws.md) and [Google Cloud](../deployment/gcp.md).

## Background jobs

Delivery is a low-latency hosted loop (`QueueDeliveryWorker`) driven by queue
leases. The in-process cron scheduler (`Bower.Jobs`, in-memory state) runs only
idempotent maintenance and reporting: queue retention, SQLite maintenance and the
management heartbeat on collectors, and collector staleness and inactivity on the
management API. Losing scheduler state on restart is harmless because durable state lives in Bower's
SQLite stores. See [background jobs](../operations/background-jobs.md).

## Current limits

Configuration is environment-based in collector host. YAML policy matching uses
bounded category/type lists; every policy must name its event types and unknown
YAML keys fail the load. Sampling, aggregation, source cursors, evidence query
proof and policy population diff are not implemented.
