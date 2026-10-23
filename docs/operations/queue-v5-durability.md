# Queue v5 durability and SQL cursor v2

This change addresses DUR-02 through DUR-07 and OPS-01. It changes persisted queue
state and settlement APIs in both C# and Rust. No Sentinel query or live SQL Server
validation is implied by the local fixtures.

## Identity and replay

`sha256:v2:` fingerprints use UTF-8 byte-length framing over the identity version,
collector ID, source adapter, application name/environment/tenant/instance, source
hostname, identity kind and stable original source ID. Without an original ID,
use the producer's stable event ID. Keep these source identifiers stable across
restarts and failover. Source IP, correlation ID, outcome and timestamps are facts,
not deduplication keys. Two attempts with different stable IDs persist independently.
An original ID must identify one immutable fact within its source namespace.

Both event-ID and fingerprint uniqueness remain enforced. A collision is only an
identical replay when both the stable fingerprint and normalized source content
match. Reusing an event ID across source namespaces is an identity conflict. Object key order is
normalized recursively; unknown source fields and number text are retained.
Collector-owned `collector`, `security` and `timeObserved` decoration is excluded.
When `eventOriginalId` is present, reconstructed `eventId` is excluded from content
comparison. Changed source content raises `EventIdentityConflictException` in C# /
`StoreError::Invalid("event-identity-conflict")` in Rust. The processor returns a
quarantine result with that code, never duplicate success. Original data remains.
This comparison operates on redacted content; removed original secrets are never
stored or compared.

Deduplication lasts while the acknowledged row remains retained. After retention
purges that row, the same stable identity may be accepted as a new incarnation.
Unacknowledged, retrying and dead-lettered rows are never removed by retention.

## Upgrade, rollback and mixed writers

Stop old writers and take a consistent SQLite backup, including committed WAL
state, before upgrading. Startup transactionally renames the writable table to
`queue_events_v5`, adds `enqueue_sequence` and `lease_generation`, creates retention
checkpoint storage and records schema version 5. The legacy `queue_events` name
becomes a read-only view. Old binaries cannot insert, lease, settle, replay or purge
through it; their old index initialization also fails rather than silently writing.

Existing valid envelope fingerprints are recomputed without changing payload or
ledger bytes. Opaque legacy queue clients retain their explicit fingerprint. A
new identity collision, missing live ledger entry or corrupt chain aborts the
migration. No accepted row is discarded to resolve a collision. Investigate the
source identity configuration and restore the pre-upgrade backup for old-version
operation. Do not drop the view or rename tables to force a downgrade.

Legacy DDL/backfill and v5 migration are transactional. Restart after an aborted
transaction sees the prior committed state and can retry. Tests inject rollback
at schema-history insertion on populated old databases and verify restart, data
preservation and old-writer refusal. They also exercise failed settlement rollback.
These are SQLite interruption simulations, not power-loss certification.

C# and Rust v5 share the schema, identity hashes, ledger hashes, timestamp format
and token contract. Either can open the other's committed v5 database. Concurrent
v5 workers must use the same queue limits and source identity configuration. Older
writers and future unknown schema versions are unsupported and refused. There is
no in-place rollback to v4; use the preserved backup and reconcile all events
accepted since that backup before resuming old software.

## Lease ownership

Each lease returns `LeaseToken` / `lease_token`: `enqueue_sequence:lease_generation`.
Generation increases on every acquisition and is not reset by dead-letter replay.
A post-retention enqueue gets a new sequence. Settlement predicates require both
uploading state and the exact token supplied with the acquired lease.

Single-record settlement now requires a token before the C# cancellation argument
(last argument in Rust). Delivered batches take an event-ID/token map. Failure
settlements carry the token themselves. Missing or stale claims cannot mutate
state; batch APIs return those IDs, single APIs reject the transition. Workers
must use claims from their original batch, never read current claims at settlement
time. Delivery worker changes in this patch only integrate this contract.

## Retention and physical storage

Purging and checkpoint compaction commit together. Consecutive purged ledger rows
collapse into one checkpoint retaining start/end sequence, previous/end chain
hashes and a boundary hash. Adjacent checkpoints merge. At most one purged run
exists between each pair of live ledger rows; an unresolved early event therefore
cannot pin all later history. Live payload verification is keyed by enqueue
sequence, not a reusable event ID. Chain/checkpoint corruption aborts compaction.
The witnessed ledger head stays stable across compaction.

Checkpoints are local hash-bound evidence with the same trust boundary as the old
local anchor, not independently signed attestations. A writer controlling the
whole database can rewrite local evidence. Continue independent external head
witnessing; do not infer destination delivery from local acknowledgement or hashes.

For configured logical payload limit `M`, the physical DB+WAL ceiling is
`4 * M + 16 MiB`. SQLite database pages are capped at one quarter of that ceiling.
Every write reserves two capped database sizes plus WAL frame/header allowance
before starting mutations: one for the WAL transaction and one for database growth
during checkpoint. Cache spill is disabled, WAL autocheckpoint runs after each
commit and retained WAL size is zero after a successful reset. Accepted data is
never deleted to satisfy the limit. A pinned reader can prevent checkpointing;
writers then report capacity/backpressure until the reader closes and maintenance
checkpoints the WAL. A database already larger than its page allowance is refused;
configure an adequate limit before migration. Database free pages are reused.

The physical cap includes retained delivered payloads, ledger/checkpoint pages and
indexes; it can reject new events before the logical undelivered payload limit.
SQLite `FULL` is surfaced as capacity, not duplicate success. Exact replay still
wins over normal admission backpressure. This limit covers the queue DB and WAL,
not unrelated disk users, output spool directories or filesystem failure. SQLite's
small shared-memory file and transient memory are additional overhead. All writers
must use the supported APIs and matching limits; raw administrative SQL is outside
this enforcement boundary.

## SQL Server timestamp cursor and allocation bounds

Timestamp cursor v2 keeps forward `(eventTime, sequence)` progress separate from a
bounded overlap sweep. Forward pages use strict keyset comparison; an overlap sweep
has a fixed high watermark and its own persisted `(eventTime, sequence)` position.
Full tied-timestamp pages progress with zero or positive overlap. Finishing a sweep
resumes forward polling. Later sweeps recover late rows still inside the configured
overlap horizon. Rows arriving outside that horizon require an operator replay;
no finite overlap guarantees recovery of arbitrarily delayed commits.

Version 1 checkpoints upgrade when read; new checkpoints are v2. Old adapters reject
v2, and optimistic checkpoint versions reject concurrent stale commits. Commit a
checkpoint only after every selected row has been durably accepted by the sink.

EF Core LINQ projects bounded fields on SQL Server before `ToListAsync`.
`DATALENGTH` (including trailing spaces), summed as bigint, bounds combined identity
columns and combined value columns independently to `MaximumRecordBytes` each.
Oversized identity columns return only a marker and stop polling without advancing.
Oversized value columns return null plus a marker: `OmitValues` emits the marked
bounded audit fact, while `Fail` stops without advancing. The final serialized row
limit still applies, including escaping. Row count times configured record size is
at most 64 MiB; the projected string data is at most twice that bound, plus CLR and
serialization overhead. No unrestricted value is first materialized then discarded.

Tests cover the actual EF-generated SQL, in-memory keyset pages, persisted restart,
late arrival, rejection markers and cursor version checks. A live SQL Server
allocation/plan test remains required in the integration environment. No Rust SQL
adapter exists in the supported port; SQL changes apply to the C# adapter only.
