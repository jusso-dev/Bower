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

## Background jobs

Delivery is a low-latency hosted loop (`QueueDeliveryWorker`) driven by queue
leases. Hangfire (`Bower.Jobs`, in-memory storage) runs only idempotent
maintenance and reporting: queue retention, SQLite maintenance and the management
heartbeat on collectors, and collector staleness on the management API. Losing
Hangfire state on restart is harmless because durable state lives in Bower's
SQLite stores. See [background jobs](../operations/background-jobs.md).

## Current limits

Configuration is environment-based in collector host. YAML policy matching uses
bounded category/type lists; every policy must name its event types and unknown
YAML keys fail the load. Sampling, aggregation, source cursors, evidence query
proof and policy population diff are not implemented.
