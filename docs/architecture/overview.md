# Architecture

Bower separates candidate acquisition, local protection, deterministic selection,
durability and delivery. No source or output adapter may bypass redaction, schema
validation or policy decision.

## Trust boundaries

1. Source records are untrusted, bounded input.
2. Redaction removes known dangerous fields before typed parsing and persistence.
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
after abrupt shutdown. Payload rows are not deleted during acknowledgement.

## Current limits

Configuration is environment-based in collector host. YAML policy matching uses
bounded category/type lists. Sampling, aggregation, source cursors, evidence query
proof and policy population diff are not implemented.
