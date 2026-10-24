# Event identity conflicts

`eventId` is globally unique within a collector queue, across every producer,
application and intake endpoint. Generate a globally random ID (for example a
UUID v4) once per new event and retain it with the upstream event, or use a stable,
globally namespaced mapping of the source identity. Retries must reuse the same
ID and source identity. A producer-local sequence, raw log ID or resettable
counter alone is insufficient. Raw pack parsers map their configured ID field to
`eventId`, so the same requirement applies to raw intake.

Both C# and Rust collectors return HTTP **409 Conflict** with
`reasons: ["event-identity-conflict"]` when a different durable identity already
owns that ID. The existing ingest response fields remain; an additive
`remediation` string explains recovery. Ordinary policy rejection stays 422,
quarantine stays 400, and a replay of the same durable identity stays 200.
No persistence schema, fingerprint, required request field or ID is changed.

## Recovery

1. Preserve the upstream event and its current ID. Do not acknowledge, delete,
   discard or advance its source cursor on 409. The collector has not queued the
   conflicting event; the original queued event remains intact.
2. Identify the submitting credential using authenticated `/v1/status`
   `eventIdentityConflicts.producers`. Investigate the producer's ID namespace and
   stable source mapping. Do not put event bodies or credentials in diagnostics.
3. Repair the producer's mapping with an operator-controlled migration/replay
   plan. Do not silently regenerate IDs per attempt: that destroys idempotency.
   Keep blocked events pending until repair, then replay and confirm acceptance.
   For SQS/Pub/Sub or other expiring upstream retention, preserve pending or
   dead-lettered events before expiry; retry alone does not repair a collision.

The shared forwarding client classifies 409 as `RetryLater`. Cloud forwarders
release the affected upstream message for retry without acknowledging it, including
partially accepted batches. Replays retain stable event IDs.

## Bounded diagnostics

`GET /v1/status` adds `eventIdentityConflicts`:

```json
{"producers":[{"producer":"sidecar-01","count":2}],"unattributed":0,"overflow":0}
```

Counts describe conflict **attempts**, not distinct lost events or delivery
proof. They are process-local, reset on restart and saturate at signed 64-bit
maximum. At most 1,024 authenticated producer labels (at most 64 UTF-16 units,
as in the credential registry) are retained, even across credential-file churn.
Existing labels keep counting; additional labels contribute only to `overflow`.
When ingest authentication is disabled, only `unattributed` increases. Producer
labels come from successful credential authentication, never request payloads,
headers naming producers or event IDs. Counts contain no event IDs, payloads,
fingerprints, tokens or competing producer identity. The status endpoint retains
its existing authentication requirement; anonymous health exposes status only.
