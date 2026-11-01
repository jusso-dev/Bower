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
Collector-owned `collector`, `security`, `timeObserved` and top-level
`attributes.bowerDetections` decoration is excluded. Pack upgrades can change
detection metadata without making a source replay conflict; retained evidence is
not rewritten. Other source attributes remain part of strict content comparison.
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
state, before upgrading (`bower queue backup`; see
[Upgrades, backup and recovery](../production-readiness/04-upgrade-backup-recovery.md#backup-and-restore)).
Builds from this release check `schema_history` before any DDL and refuse a newer
schema without changing the file; earlier builds did not. Startup transactionally renames the writable table to
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

Before upgrading either runtime, run the standalone C# identity preflight against
the stopped v4 queue or a consistent backup. It uses the canonical C#
`EventIdentity` implementation and does not invoke either runtime's queue startup:

```sh
dotnet run --project tools/queue-migration-check --configuration Release -- --database /absolute/path/bower.db
```

Build the tool before the maintenance window. Exit 0 means the bounded identity
scan completed without collisions; 2 means collisions; 1 means refused or
incomplete (including limits, unsupported schema or unreadable database). JSON
contains completion/status, scanned/opaque row counts and colliding event-ID
pairs only. No payload, original source ID, fingerprint or parser error is
printed. The check opens SQLite read-only, uses a single read transaction, and
never initializes, migrates, checkpoints or changes DB/WAL/schema contents. SQLite
may use its normal shared-memory read locks; this is not a forensic no-filesystem-
activity tool. Never use SQLite `immutable` mode to skip a committed WAL.

Limits are 100,000 rows, 1 MiB per payload, 64 MiB total payload and 100 reported
pairs. Hitting a limit is an incomplete result, never a clean bill of health.
Only known v4 schema history is supported; future, v5, older and unknown schemas
are refused. Opaque rows retain their explicit fingerprints, matching migration.
Pairs include conflicts in ordered re-keying, including retained opaque keys.
This is an identity check, not a ledger verification or guarantee that the full
upgrade will succeed. Keep writers stopped between the check and upgrade.

If collisions appear, preserve the backup and keep the v4 queue intact. Investigate
the reported IDs in the authorized source system: distinguish a resend of one
fact from producers reusing source identities. Record the reconciliation decision
and evidence. Drain/acknowledge through the supported old runtime and normal
retention where appropriate, or seek a separately reviewed data-preserving
reconciliation plan. Do not delete accepted rows, rewrite payloads/ledger entries,
or remove uniqueness constraints to force upgrade. Repeat the preflight on the
reconciled consistent backup before upgrading. No automatic reconciliation or
deletion is provided.

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
time.

### C# delivery deadlines and restart recovery

`BOWER_DELIVERY_LEASE_SECONDS` defaults to 300 and accepts 31–3600 seconds.
`BOWER_DELIVERY_TIMEOUT_SECONDS` defaults to 240 and must leave at least 30 seconds
between the output cancellation deadline and lease expiry for queue settlement.
Invalid combinations fail collector startup, including when delivery is disabled.
Nondefault delivery profiles append both values to the reported configuration hash;
the default profile preserves existing configuration hashes shared with Rust.
Configuration identity does not identify software behavior: record the binary
version and artifact hash separately. No database migration or lease-token change
is involved. These options apply to the C# collector only.

The output receives a token linked to the deadline and host shutdown. A deadline
cancellation becomes `destination-output-timeout`: the batch stays durable, the
destination circuit pauses delivery for 30 seconds, and the poison-record attempt
budget is preserved. Settlement uses the host token, so an expired output deadline
does not prevent committing the retry. Host shutdown still leaves outstanding
leases intact for recovery. Metadata-only warnings never include the batch body.

If an AMA file or an owned Azure request completed before a later operation was
cancelled, the adapter returns those known acknowledgements and marks only the
unfinished events with `destination-ama-cancelled` or `destination-azure-cancelled`.
The worker commits those acknowledgements instead of replaying confirmed output.
Restart regressions cover both partial-output paths. With no acknowledged output,
the adapter still propagates cancellation to the worker's deadline handling.

Cancellation is cooperative. The worker awaits the adapter rather than abandoning
an upload task and launching overlapping attempts. Adapters must honor cancellation;
a blocked filesystem or an adapter that ignores the token cannot be made responsive
by this setting. A request may reach the destination before its response is lost or
cancelled: replay remains at least once, not exactly once. Reconcile by event identity
and measure duplicates at the destination; lease fencing protects queue state, not
external side effects.

For qualification of the 120-second crash-recovery target, the candidate profile is
a 90-second lease and 60-second output timeout. Set **both** environment variables.
Existing leases keep their original expiry after a configuration change. Shorter
deadlines can interrupt valid large uploads on slow links, so benchmark batch sizes
and destination latency before selecting this profile. No startup path resets all
leases or steals another worker's live claim.

`DeliveryDeadlineTests` covers timed cancellation, retained retry state across
restarts, destination-circuit delay, preserved poison budget, successful slow
acknowledgement, host cancellation and live-lease exclusion. Its clock-driven
restart checks are not a process-kill, Windows reboot or real Azure delivery test.
The failed AWS recovery scorecard remains unresolved until the exact candidate
artifact passes those external checks; see [production readiness](production-readiness.md).

## Throttling and pauses

The Logs Ingestion output adapts request concurrency inside one delivery and never
holds events outside the queue: a leased batch either settles or expires and is
reclaimed. After a `Retry-After`, batches of that delivery that were not sent fail
as `destination-azure-paused` with the server deadline (capped at one hour). Like
every `destination-*` failure, they do not spend delivery attempts and open the
durable destination circuit, so nothing is leased for the stream until the
deadline, across restarts. Leases stay valid while a delivery waits for a slot
(bounded by the batch and the lease duration). Acknowledgement, dead-letter and
ledger semantics are unchanged. See
[adaptive request concurrency](../deployment/logs-ingestion-api.md#adaptive-request-concurrency).

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
wins over normal admission backpressure. A suppressed event commits a counter
change, so it takes the same physical check after the duplicate lookup: when the
budget is spent it is refused with capacity, its window counts stay unchanged and
it is not reported as suppressed. This limit covers the queue DB and WAL,
not unrelated disk users, output spool directories or filesystem failure. SQLite's
small shared-memory file and transient memory are additional overhead. All writers
must use the supported APIs and matching limits; raw administrative SQL is outside
this enforcement boundary.

## SQL Server timestamp cursor v3 and allocation bounds

Timestamp cursor v3 keeps forward `(eventTime, sequence)` progress separate from a
bounded overlap sweep. Forward and replay pages alternate, each limited to
`BatchSize`, even when every forward page is full. Both streams use strict keyset
comparison, including the sequence tie-breaker. Zero overlap uses forward pages
only. An already pending sweep finishes even if overlap is changed to zero.

The first forward checkpoint atomically saves its new watermark and a replay lower
bound derived from the **pre-page** watermark minus `TimestampOverlap`. The sweep's
upper `(eventTime, sequence)` bound is fixed at that page's new watermark. Replay
position, upper bound and next-page selection survive restart; subsequent forward
pages cannot move the active sweep's bounds. After a short replay page completes
the sweep, its upper bound remains saved. The next sweep starts at that saved upper
timestamp minus overlap and ends at the new forward watermark. This covers forward
progress made during the previous sweep without a gap. A full page at the upper
bound needs a later empty replay page to confirm completion.

This is a finite **event-time** lateness contract, not a wall-clock commit-delay
guarantee. A row within a pending sweep is recovered if it is visible before that
sweep's keyset passes it, and it remains readable until fetched. A row becoming
visible behind the replay position needs a subsequent sweep whose lower bound
still includes it. Advancing forward pages cannot discard a pending interval, but
arbitrarily delayed or backdated commits can fall outside subsequent intervals.
Choose overlap for the source's timestamp/commit behavior and polling throughput;
use an operator-controlled replay for older rows. Timestamp and sequence must
identify immutable, deterministically ordered facts. Overlap intentionally repeats
rows; the sink must durably deduplicate stable fingerprints.

Version 1 and 2 checkpoints upgrade in memory when read; subsequent checkpoints
are v3. A v2 active sweep retains its exact replay position and old forward
watermark as its fixed upper bound. A legacy forward-only checkpoint starts the
new overlap at its stored watermark; migration cannot recover rows already skipped
outside that horizon. Reconcile such historical gaps with an operator replay.
Old adapters reject v3. Stop old SQL pollers before upgrading, back up the cursor
store consistently, and do not run mixed cursor versions. Downgrade requires the
pre-upgrade cursor backup plus reconciliation of subsequently accepted rows;
do not edit the schema version to force old readers to accept new state.

Optimistic checkpoint versions reject concurrent stale commits. Commit a checkpoint
only after every selected row has been durably accepted by the sink, including
checkpoints on empty pages that change replay state. A crash before commit repeats
the page; it never skips ahead. No persistence queue or cursor-store API changes
are required.

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
full forward backlogs with late commits, interleaved tied-timestamp replay, crashes
before checkpoint commit, stale commits, legacy migration, malformed bounds and
rejection markers. A live SQL Server
allocation/plan test remains required in the integration environment. No Rust SQL
adapter exists in the supported port; SQL changes apply to the C# adapter only.
