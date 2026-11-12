# Design 004: SQL Server polling integration

**Status:** Design for review, not implemented. **Go** for implementation (product owner decision, 2026-11-13). · **Date:** 2026-11-12, decisions 2026-11-13 · **Planned and checked at:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [004-sql-server-integration.md](004-sql-server-integration.md)

## Decision

**Go: build it now** (product owner decision, 2026-11-13). This goes against the design's original recommendation, which was no-go until a named deployment needed it. Customer demand is still **unverified**. The product owner accepts that gap as a risk they own (section 6). The integration boundary below is unchanged.

The original no-go reasoning is kept in section 6, so it stays visible why waiting was recommended.

Build a **separate non-AOT forwarder** (`Bower.Agent.SqlServer`, following the `Bower.Agent.Docker` and `Bower.Agent.Cloud` precedent). It polls one approved view with an incrementing cursor and posts fixed-shape records to the collector's signed pack route. It advances its cursor only after the collector answers with a durable or definitive outcome for every record in the batch. The collector stays Native AOT and never holds SQL credentials. A non-AOT collector variant is rejected: it doubles the collector release matrix and puts a SQL driver and SQL credentials in the process that owns the queue. It would make cursor and enqueue atomic, but that gain is a smaller duplicate window, not a different delivery guarantee.

Only one mapping is recommended: application **failed sign-in rows → `authentication_failure`** under the existing default policy. Nothing in the repository names a customer, table or request (section 6).

The first version supports **gMSA (integrated Windows auth) and Entra managed identity** sign-in (decision Q4, against the recommendation to defer Entra). Entra sign-in needs a dependency, so it carries an implementation gate: a written justification in `docs/architecture/dependencies.md` before it merges (section 5). That file is not changed by this design.

Drift check (step 1): HEAD equals the planned commit. `git diff --stat 64859aa..HEAD -- README.md src/Bower.Source.SqlServer src/Bower.Collector tests` is empty. `test -f src/Bower.Source.SqlServer/SqlServerSourceAdapter.cs && test -f src/Bower.Source.SqlServer/AGENTS.md` exits 0.

No STOP condition is hit (section 7). All three STOP conditions stay in force for implementation.

## Decisions (2026-11-13)

All five open questions (section 6) and the go/no-go are decided. "Against" marks a choice that differs from this design's recommendation.

| ID | Question | Choice | Consequence |
|---|---|---|---|
| GO | Go or no-go | **Against:** go. Build it now | Implementation starts without a named deployment. The demand gap is an accepted risk owned by the product owner (section 6). Every STOP condition and every per-deployment qualification gate (4.3) still applies |
| Q4 | Entra or managed identity in the first version | **Against:** yes, alongside gMSA | Managed identity sign-in is in scope (3.2). Implementation gate: written dependency justification in `docs/architecture/dependencies.md` before the Entra code merges. Tokens stay in memory |
| Q5 | Late-row audit signal | Raise a health signal. The forwarder keeps running | No stop on an audit finding. The skipped range and difference are reported (4.1). An operator decides what to do |
| Q3 | Audited skip-row command | Required before go-live | Added to the first version (3.2, section 5). A poison row no longer needs a database change to clear |
| Q1 | Time column type | `datetimeoffset` only. Refuse anything else at startup | No zone conversion. A startup column check refuses `datetime`, `datetime2` and `smalldatetime`, and a nullable column (3.1) |
| Q2 | Sequence column type | `bigint` only | No `int` converter. The startup check refuses any other type (3.1) |

## 1. What is wired today (step 2)

### 1.1 The adapter is a library with no host

| Fact | Evidence |
|---|---|
| Only the unit test project references it. No `src/` project, Dockerfile, installer or workflow does | `tests/Bower.UnitTests/Bower.UnitTests.csproj:33`; `Bower.sln:36`; `src/Bower.Collector/Bower.Collector.csproj:15-28` has no SQL reference |
| The collector has no SQL source in its startup set or composition | `src/Bower.Collector/CollectorStartupSources.cs:26-33`; `src/Bower.Collector/CollectorApplication.cs:135-198` wires syslog, Windows Event Log and file tail only |
| Documented as library-only | `README.md:184`; `docs/operations/console-sources.md:12-14`; `docs/security/adversarial-remediation-2026-10-23.md:154-156` |
| Opted out of AOT by design: EF Core LINQ over a runtime-chosen table needs reflection | `src/Bower.Source.SqlServer/Bower.Source.SqlServer.csproj:3-9`; `README.md:990-991`; `docs/architecture/dependencies.md:91` |
| AOT analysers are errors for every `src/` project, so an AOT host referencing it would fail to build rather than change silently | `Directory.Build.props:7,47-52` |
| `PollInterval` is validated but unused. There is no poll loop | `SqlServerSourceOptions.cs:62,121-126`; no consumer in `src/` |

### 1.2 Adapter behaviour

- **Query.** EF Core LINQ only, with no free-form SQL (`src/Bower.Source.SqlServer/AGENTS.md:3-7`). Identifiers must match `^[A-Za-z_][A-Za-z0-9_]*$`, at most 128 characters (`SqlServerSourceOptions.cs:95-105,200-216`). The keyset predicate and order are fixed per cursor kind (`SqlServerSourceAdapter.cs:213-241`). `Take(BatchSize)` applies, with 1–10,000 rows and at most 64 MiB of batch × record size (`SqlServerSourceOptions.cs:107-112,160-164`). It is a no-tracking keyless entity (`SqlServerAuditDbContext.cs:26-27,47`).
- **Bounded projection.** `DATALENGTH` runs server-side. An oversized identity column group returns a marker and the batch throws. Oversized values are nulled and flagged (`SqlServerSourceAdapter.cs:151-187,243-271`). This is tested against generated SQL only (`tests/Bower.UnitTests/SqlServerAdversarialTests.cs:50-79`).
- **Commit settle.** Incrementing and composite cursors stop at the first row newer than `CommitSettleDelay` (default 5 s). That delay is measured against the poller's clock (`SqlServerSourceAdapter.cs:80-91`; `SqlServerSourceOptions.cs:75-81`). Transactions open longer than the window can be skipped (`docs/security/threat-model.md:311-312`).
- **Identity.** The fingerprint is SHA-256 over source id, sequence and UTC event time, so it stays stable across replay (`SqlServerSourceAdapter.cs:273-297`).
- **Checkpoint.** There is one checkpoint per batch. It is null when unchanged and carries `ExpectedVersion` (`SqlServerSourceAdapter.cs:24-31,143-148`). `CommitAsync` compare-and-swaps through `ISourceCursorStore` and throws `SourceCursorConflictException` on a lost race (`SqlServerSourceAdapter.cs:189-211`). **No per-record checkpoint is exposed**, so a partly accepted batch can only be replayed from its start.
- **Connection.** The only check is `ApplicationIntent=ReadOnly` (`SqlServerSourceOptions.cs:178-182`). That setting is a routing hint for readable secondaries, not a permission. Read-only access comes from the principal's grants alone (`README.md:1050-1052`). `Encrypt` and `TrustServerCertificate` are not checked.

### 1.3 Retry and idempotency mechanisms that exist

| Mechanism | Where | Relevance |
|---|---|---|
| Cursor compare-and-swap, `BEGIN IMMEDIATE`, version predicate. Any failed write returns `false` | `src/Bower.Persistence/EfSourceCursorStore.cs:90-171` (`:156-161`) | Stale or concurrent commits are refused. A full disk is reported as a conflict, which is a health-reporting gap, not a safety gap |
| Atomic queue plus cursor commit, only when the cursor table is in the queue database | `src/Bower.Persistence/QueueEnqueueBatch.cs:49-50,97-154` | Used by Windows Event Log (`src/Bower.Source.WindowsEventLog/WindowsEventLogSource.cs:508-518,553-588`). **Not available across processes** |
| Queue duplicate check on `event_id` or fingerprint. A different payload under the same id raises a conflict. Idempotency takes priority over backpressure | `src/Bower.Persistence/SqliteEventQueue.cs:338-343,468-490` | Absorbs replays |
| Queue identity includes the receiving collector id and `SourceAdapter` | `src/Bower.Persistence/EventIdentity.cs:14-26` | Replays deduplicate only to the same collector, producer and pack route |
| Delivered rows are kept for deduplication for 7 days (1–2160 h), down to the pressure floor (default 1 h) | `src/Bower.Collector/CollectorSettings.cs:33-42,497-506` | This is the duplicate window |
| SQLite `synchronous = FULL`. HTTP enqueue commits before the response | `SqliteEventQueue.cs:1246,289-298` | A 200 or 202 means durable |
| Forwarder rule: acknowledge only on Accepted or Rejected | `src/Bower.Forwarding/AGENTS.md:5-6`; `src/Bower.Forwarding/CollectorClient.cs:94-104` | The ack boundary for the forwarder |
| Readiness probe before reading | `CollectorClient.cs:76-92`; `src/Bower.Agent.Cloud/CloudForwarderWorker.cs:89-95` | Avoids pointless reads during an outage |
| Backoff and cursor rewind to the first refused record | `src/Bower.Agent.Docker/DockerSidecarWorker.cs:28,52-64,103-136` | Loop precedent |
| Redaction-retry outcome: never acknowledged | `src/Bower.Core/SecurityEventProcessor.cs:765-769`; `src/Bower.Collector/PackEndpoints.cs:109-124` (503) | A redaction failure blocks the cursor and drops nothing |
| None in the adapter: no EF `EnableRetryOnFailure` and no internal retry | `SqlServerAuditDbContext.cs:40-50` | The host loop owns retry |

### 1.4 Test coverage and gaps

Covered (in memory and on generated SQL): options rejection, including a read-only intent failure that does not echo the server name (`SqlServerSourceAdapterTests.cs:21-78`). Also covered: cursor restart and stale commit (`:81-119`), settle hold-back and oversize (`:257-309`), timestamp tie traversal across restart (`SqlServerAdversarialTests.cs:9-48`), and a crash before checkpoint repeating the page (`SqlServerReplayTests.cs:96-136`).

Not covered: `PollAsync` against any database, cancellation, CLR and column type compatibility, nulls in key columns, and any host or loop. A live SQL Server exercise is an open external gate (`docs/security/adversarial-remediation-2026-10-23.md:90-91`; `docs/operations/queue-v5-durability.md:314-315`).

### 1.5 Drift recorded, not fixed here

- `README.md:999-1000` says "A saturated overlap window fails explicitly". `SqlServerOverlapWindowSaturatedException` is declared (`SqlServerSourceAdapter.cs:386-388`) but nothing in `src/` throws it. The v3 alternating pages appear to make saturation unreachable, so the README sentence needs revising.
- `Directory.Build.props:47-49` says every shipped executable is Native AOT. `Bower.Functions.Collector.csproj:7-9` is not, and the proposed forwarder would be another exception.
- `src/Bower.Agent.Cloud/AGENTS.md:42-44` says the host is not AOT because of `Google.Apis.Auth`. The project file and the dependency record say otherwise (`Bower.Agent.Cloud.csproj:4-7`; `docs/architecture/dependencies.md:90`).
- Issue #99 lists SQL Server among existing sources. It is library-only.

## 2. Deployment options (step 3)

| Aspect | (A) Separate non-AOT forwarder | (B) Non-AOT collector variant |
|---|---|---|
| Packaging | New executable and image (framework `runtime` base, not `runtime-deps` chiseled: `deploy/docker/Dockerfile:26-27`), plus a Windows service. The collector artefacts are unchanged | A second collector flavour across deb, rpm and MSI × 6 RIDs, with separate CI publish and install jobs. It must be a separate host project, because adding the reference to `Bower.Collector` fails the AOT build |
| AOT impact | None to shipped AOT hosts. One documented non-AOT exception is added | The collector loses AOT in that flavour: JIT start-up, larger memory and a different performance profile from the qualified build |
| Credentials | The SQL credential exists only in the forwarder. The collector sees an ingest token, as other agents do (`src/Bower.Agent.Docker/AGENTS.md:13`) | The SQL credential sits in the process that also holds ingest tokens, the Azure credential and the management credential |
| Least privilege | Its own service account (gMSA or virtual account) with `SELECT` on one view. The collector account needs no database rights | `NT SERVICE\Bower` gains database rights, and the queue directory and DB login belong to one identity |
| Network | Forwarder → SQL (TLS) and forwarder → collector (HTTPS plus token, or loopback). The collector needs no outbound DB path | Collector → SQL egress. That path is new for a host that otherwise only listens and calls Azure |
| Managed identity | Integrated Windows auth needs no new package. Entra or managed identity is not in the resolved graph (`src/Bower.Source.SqlServer/packages.lock.json` has no `Azure.*`) and would need a justified dependency (`AGENTS.md:92-93`). **Feasibility unverified.** In scope for (A) from 2026-11-13 (Q4); feasibility is confirmed at the dependency gate (section 5) | The same dependency question, but it lands in the collector's graph |
| Failure isolation | A driver hang, native SNI fault or memory spike stops only the forwarder. Queueing and delivery continue (`PRODUCT.md:63-64`) | The same faults share a process with `QueueDeliveryWorker`. The command timeout bounds queries but not native faults |
| Cursor and enqueue | **Not atomic.** The cursor commits after HTTP acks. A crash in between replays the batch, which the queue deduplicates | Atomic through `QueueEnqueueBatch.CommitWithCursorAsync`. Duplicates come only from timestamp overlap |
| Support cost | One more binary, image, config schema and state file to back up, plus version skew with the collector. It reuses `CollectorClient` and the agent patterns | Every collector defect must be reproduced in two flavours, the installer and qualification matrix doubles, and the 72-hour soak evidence does not transfer |

**Recommendation: (A).** (B) only reduces how many duplicates occur, and the collector queue already absorbs them. It pays for that with credential concentration, a second collector build and loss of failure isolation. Revisit (B) only if measured replay duplicates exceed the retention window in practice, which is unlikely with the bounds in section 3.

## 3. Recommended shape

### 3.1 Mapping: one event, one table

| Item | Specification |
|---|---|
| Source | An operator-created **view** over the application's audit table, filtered to failed sign-in rows, `SELECT` granted to the forwarder principal only. Rows must be immutable, with a `bigint` identity sequence and a `datetimeoffset` `EventTime` set by the database in the inserting statement (for example `DEFAULT SYSDATETIMEOFFSET()`), so `EventTime` does not decrease as the sequence rises (section 4.1) |
| Column types (decisions Q1, Q2) | At startup, before the first poll, the forwarder reads the declared types of the configured view's columns from `sys.columns` (visible to a principal with `SELECT` on the view) through a fixed, parameterised metadata query. It refuses to start unless Sequence is `bigint` and EventTime is `datetimeoffset`, and both are declared `NOT NULL` (`is_nullable = 0`). A NULL Sequence would never be read, because the keyset predicate `Sequence > cursor` excludes it (`SqlServerSourceAdapter.cs:220`), so the row would be skipped silently with no sequence to name in a stall. A NULL EventTime would fail materialisation into `DateTimeOffset` for the whole query. The refusal names the column and the type or nullability only. This matches the adapter's entity model (`long Sequence`, `DateTimeOffset EventTime`, `SqlServerAuditDbContext.cs:65,67`). The metadata query is fixed text owned by the forwarder, not operator SQL |
| Cursor | `Incrementing` only. `Timestamp` and `Composite` are out of scope for the first slice. `CommitSettleDelay` must be at least 5 s and set from measured transaction durations |
| Columns read | Sequence, EventTime, Username, Action, SourceIp. The adapter currently also projects TargetType, TargetId, PreviousValue and NewValue. The forwarder discards them in memory before building the record. Never put them in the record, logs or state. Follow-up: an adapter option to leave them out of the projection |
| Record (fixed shape, not configurable) | `{"id":"sqlsrv-<first 32 hex of fingerprint>","timeCreated":<UTC ISO-8601>,"action":<Action>,"user":<Username>,"sourceIp":<SourceIp>}`, with `sourceIp` omitted when SourceIp is NULL or blank, at most 4 KiB (`MaximumRecordBytes = 4096`, well under the 32 KiB pack limit `src/Bower.Packs/PackRuntime.cs:20`) |
| Route | `POST /v1/packs/{pack}/parsers/{i}/events` (`src/Bower.Collector/PackEndpoints.cs:15`) to a **tenant-signed** pack. `CollectorClient` needs a pack-route send method; it only posts `v1/events` today (`CollectorClient.cs:41`) |
| Parser | `match: {action: "<tenant literal>"}`. Fields: `eventId←id`, `timeGenerated←timeCreated`, `actor.username←user`, `source.ipAddress←sourceIp`. These all fit the allowed targets (`src/Bower.Pipeline/CustomLogParser.cs:429-437`). SourceIp is nullable (`SqlServerAuditDbContext.cs:81`), and a mapped field that is missing, null or blank throws (`PackRuntime.cs:52-58`), which returns 400 and lets the cursor pass the row (`PackEndpoints.cs:63-66`). So the pack carries a second parser with the same `match` and no `source.ipAddress` mapping, and the forwarder sends rows without an IP to it. The policy only recommends `source.ipAddress`, so those rows are still accepted. Rows are immutable, so a row always takes the same parser index, which is part of its queue identity (`PackEndpoints.cs:98`). Runtime: `authentication` / `authentication_failure` / `authentication.attempt` / `failure` |
| Policy | Existing `BWR-POL-AUTH-FAILURE` (`policies/default/authentication-failure.yaml:11-35`). No schema, catalogue or policy change |

Why this event: it fits the pack runtime with no new targets. It needs no before or after values, which are the most sensitive columns. It also has an existing default policy. Role membership or admin changes need `target.*` and `change.*`, which the pack runtime cannot map, plus the value columns.

### 3.2 Controls

- **No free SQL.** The forwarder exposes only identifiers that pass the existing validation. There is no query text, filter expression, `FromSql` or stored procedure (`src/Bower.Source.SqlServer/AGENTS.md:3-5`). Row filtering belongs in the view, which the DBA owns.
- **Bounded records.** One source per process. `BatchSize` defaults to 100 (maximum 1,000, because posts are per event and pass the ingest rate limiter). Records are at most 4 KiB, and each field is at most 2,048 characters (`PackRuntime.cs:52-58`). The command timeout is 1–300 s.
- **Default deny, layered.** View grant → fixed LINQ → fixed record shape → signed parser `match`, where unmatched records get 422 and are counted (`PackEndpoints.cs:82-85`) → producer scope on the application name (`:89-92`) → collector policy.
- **Redaction before persistence.** The forwarder persists only the cursor (`SqlServerSourceAdapter.cs:356-365`) and the pending late-row audit ranges (4.1), which hold sequence, count and time values, plus the skip-row audit file, which holds no row values. There is no spool or buffer of rows on disk. The collector redacts before enqueue (`SecurityEventProcessor.cs:236` before `:402`).
- **Credentials.** Two sign-in modes in the first version (decision Q4):
  - integrated auth with a gMSA (Windows);
  - Entra managed identity (system- or user-assigned, on Azure or Arc-connected hosts) to Azure SQL, SQL Managed Instance or SQL Server 2022 with Entra enabled. Only `Authentication=Active Directory Managed Identity` is accepted, with an optional user-assigned client id. Modes that need a stored secret or a person (`Active Directory Password`, `Interactive`, `Device Code Flow`, service principal with secret) and the ambiguous `Active Directory Default` are refused at startup. Access tokens are held in memory only and never written to disk, logs or state (`AGENTS.md`, no persisted access tokens).
  A connection string with a SQL password is still allowed only from an owner-only file that the operator supplies. Bower never writes, copies or logs it. Refuse `TrustServerCertificate=true`, `Encrypt` other than `Mandatory` or `Strict`, and `Persist Security Info=true`. Keep the `ApplicationIntent=ReadOnly` requirement.
- **Logging.** Log ids, counts, failure types and `SqlException.Number` only. Never log exception messages, which can carry the server, login or converted values. Never enable EF sensitive-data logging.
- **Durable ack boundary.** A batch checkpoint is committed only when **every** record in it got `Accepted` (200 or 202) or `Rejected` (400, 413 or 422: definitive). A 202 means the event was committed to the collector queue or, if the matching policy suppresses it, counted in a durable suppression window in the same transaction (`PackEndpoints.cs:111`; `SqliteEventQueue.cs:295-297,347-356`). The recommended policy is `neverSample`, which cannot define suppression (`PolicyLoader.cs:157-160`), so suppression applies only if another policy matches these events. On the first `RetryLater`, `Throttled`, `Unauthorized`, 404 or 409, stop and do not commit. Keep the settled prefix in memory, back off and resume at the refused record, as the Docker sidecar does (`DockerSidecarWorker.cs:52-64,103-136`). Do not resend the prefix in process: the ingest limiter is a token bucket of twice `BOWER_INGEST_RATE_PER_SECOND` (default 500) with no queueing, and a duplicate spends a token too (`CollectorSettings.cs:98`; `CollectorApplication.cs:207-213`). Replaying a batch larger than the free tokens would hit 429 at the same record every time. Pace sends below the configured rate. Once all records are settled, commit the checkpoint with `CancellationToken.None`, as Windows Event Log does (`WindowsEventLogSource.cs:555-560`).
- **Stall isolation.** A row that throws during batch building (oversized identity columns, `SqlServerSourceAdapter.cs:98,153-156`) fails the whole batch, so the valid rows before it are never sent. On such a failure the forwarder polls again with a batch size of 1 (a second adapter instance with `BatchSize` 1, within the existing 1–10,000 bound) and settles and checkpoints each earlier row as normal, until a single-row poll throws. Only then is the stall recorded, with the stalled sequence and the committed cursor version at that moment. Every row below the stalled sequence that was visible then has an outcome before any skip.
- **Audited skip-row command** (decision Q3, required before go-live). A forwarder CLI command that moves the cursor past exactly one stalled sequence value. It runs only while the forwarder service is stopped, takes the source id, the sequence and a reason, and refuses unless the last recorded stall names that sequence and the committed cursor version still equals the one recorded with the stall. Identity values can have gaps, so it does not assume the stalled row is cursor + 1. It advances with the same compare-and-swap (`SqlServerSourceAdapter.cs:189-211`), so a concurrent poller wins and the skip is refused. It adds `(cursor, stalled sequence]` to the pending late-row audit ranges (4.1) with a settled count of 1, in the same compare-and-swap. It never reads or prints the row's values. Skipping more than one row needs one command per row. The audit file is append-only, beside the cursor database, and every entry is flushed to disk before the next step. Entries hold time, operator account, source id, skipped sequence, expected cursor version and reason, and no row values. Commit order:
  1. append a `pending` entry;
  2. compare-and-swap the cursor;
  3. append `complete`, or `aborted` if the compare-and-swap was refused.

  On start, before its first poll, the forwarder reconciles every `pending` entry that has no later entry. If the committed cursor version is the expected version + 1 and its sequence equals the skipped sequence, the skip happened, and the forwarder appends `complete`. Otherwise it appends `aborted`. It then emits one `row-skipped` health signal for each `complete` entry without a later `signalled` entry, and appends `signalled` after each. A crash before `signalled` repeats the signal on the next start. The signal is never lost, and a skip that did not happen is never signalled. An audit file that cannot be read or parsed stops the forwarder before polling, with a health signal naming the failure type.

## 4. Crash, restart and concurrency matrix (step 4)

A = forwarder (recommended), B = collector variant for comparison. "Replay" means the batch is read again from the committed cursor.

| Case | A: outcome | B: outcome | Required test |
|---|---|---|---|
| Crash before any send | Nothing sent. Replay | Batch rolled back. Replay | Kill before the first POST. Cursor unchanged |
| Crash after collector commit, before the response arrives | `RetryLater`. Replay gets 200 duplicate | n/a | Kill the collector connection after the commit. Queue count unchanged on replay |
| Crash after all acks, before checkpoint | Replay of the whole batch. All 200 duplicates | Atomic, so no gap | SIGKILL between the last ack and `CommitAsync` |
| Crash after checkpoint | Next batch | Same | Restart resumes at sequence + 1 |
| Restart while late-row recounts are pending | Ranges restored from the cursor database. Overdue recounts run at once, the rest on schedule. An unrestorable range is a health signal | n/a | SIGKILL between a checkpoint and its range's final recount. Commit a held row in that range during the outage. Assert the range is restored and the restart recount reports difference 1. Corrupt one range row: assert the health signal and that the others still run |
| Duplicate replay within retention | Deduplicated if collector, producer and pack route are the same (`EventIdentity.cs:17-18`) | Deduplicated | Replay 3 times. Queue holds exactly 1 |
| Replay after retention, or to another collector | **Sentinel duplicate** | Same | Documented limit. Test with retention 1 h and fake time |
| Stale checkpoint (two pollers, one cursor DB) | CAS refuses, `SourceCursorConflictException`. Re-read and re-poll | Conflict result. Read again | Exists in part (`SqlServerReplayTests.cs:116-124`). Add a loop-level test |
| Two pollers with separate cursor DBs | Same producer token: every row sent twice, absorbed as 200 duplicates. Different tokens: same `event_id`, different identity → 409 conflict → stall | Same across collectors | Must be prevented (one instance per source). Assert the stall is reported as health, not looped silently |
| Partial batch refusal (503 or 429 mid-batch) | No checkpoint. Back off and resume at record k. 1..k−1 are not resent. After a restart the whole batch replays as 200 or 422 again | Savepoint per record. Handled prefix commits | Refuse at record k. All of 1..k−1 are queued once and sent once. Also set `BOWER_INGEST_RATE_PER_SECOND=1` with `BatchSize` 10: the checkpoint commits and no record before a 429 is resent |
| Overlap saturation | Not applicable (incrementing only). The exception is unreachable (section 1.5) | Same | Timestamp cursor deferred. Tests are due before it is enabled |
| Out-of-order identity commits | Held back within `CommitSettleDelay`. **Skipped beyond it**; the late-row audit reports it as a health signal and the forwarder keeps running (Q5), only if n commits before the final recount (`8 × CommitSettleDelay`), otherwise no signal | Same | Disposable DB: transaction T1 holds id n open past the window while T2 commits n+1. Commit n before the final recount: assert the skip and the audit signal. Commit n after it: assert the skip and no signal |
| `EventTime` lower than an earlier sequence (application-supplied time) | n+1 passes the window while n is uncommitted. **n is skipped even if it commits within the window**. Not visible in process; the late-row audit reports it at the first recount after n commits, only if that is no later than `8 × CommitSettleDelay`, otherwise no signal | Same | Disposable DB with `READ_COMMITTED_SNAPSHOT` on: hold id n open, commit n+1 with an older `EventTime`, poll, then commit n inside the window. Assert the skip, no in-process signal, and an audit signal with range and difference 1. Repeat with n committed after the final recount: assert no signal, which the documented limit predicts |
| Clock or time-zone skew in `EventTime` | `datetimeoffset` only (Q1), so a zone-less local time cannot be read. A `datetimeoffset` filled with a wrong offset still shifts hold-back | Same | Startup refuses a `datetime2` and a `datetime` EventTime with no poll issued. A `datetimeoffset` column is accepted. Document that the offset must be set by the database |
| Cancellation mid-query | `OperationCanceledException`. No checkpoint | Same | Cancel during `ToListAsync`. Cursor unchanged, no partial send |
| Cancellation mid-batch | Stop sending. No checkpoint. Replay | Roll back | Cancel after k sends. Queue holds k, deduplicated on restart |
| DB outage or failover | `SqlException`. Back off, no checkpoint | Same, inside the collector | Stop or pause the container mid-poll. Resume without a gap |
| Collector outage | Probe fails. No read | n/a | Collector down. No SQL query issued |
| Malformed row: NULL sequence or time | Prevented. The startup column check refuses a nullable Sequence or EventTime column (3.1), so no poll is issued | Same | A view with a nullable Sequence and one with a nullable EventTime are each refused with the column named and no poll issued |
| Malformed row: invalid IP, NULL or blank Username or Action, or field over 2,048 characters | 400 → definitive drop, counted. Cursor advances | Invalid, counted | Verify the counter. Verify no value in logs |
| NULL or blank SourceIp | Sent without `sourceIp` to the no-IP parser. Accepted | Same | Seed NULL and blank SourceIp rows. Assert 202, not 400, and the same parser index on replay |
| Oversized identity columns | Throws. Single-row polls settle and checkpoint the valid rows before it (3.2). **Source then stalls** by design (`queue-v5-durability.md:304`) until skip-row is used | Same | Real `DATALENGTH` on SQL Server, with valid rows before the oversized one in the same batch. Assert those rows are queued and checkpointed before the stall is recorded, and that the stall names the oversized sequence. Skip-row clears it. It refuses a different sequence, a running service, a changed cursor version and a lost compare-and-swap |
| Crash during skip-row | After the `pending` entry, before the compare-and-swap: next start appends `aborted`, cursor unchanged, no signal. After the compare-and-swap, before `complete`: next start appends `complete` and emits `row-skipped`. After `complete`, before `signalled`: next start emits `row-skipped` and appends `signalled` | n/a | Kill the command at each of the three points. Assert the audit file entries, the cursor and exactly one `row-skipped` signal for each completed skip and none for an aborted one. Repeat the restart after `signalled`: no second signal |
| Column type mismatch (`int` identity, `datetime2`) | Refused at startup by the column check (Q1, Q2). No poll | Same | Type matrix on a real engine: `int`, `smallint`, `numeric`, `datetime`, `datetime2`, `smalldatetime` each refused with the column named; `bigint` plus `datetimeoffset`, both `NOT NULL`, accepted |
| Collector storage pressure or full | 503 → `RetryLater`. No checkpoint | Batch refused | Fill the queue. Cursor holds. Recovery drains |
| Forwarder disk full (cursor DB) | CAS write fails and returns `false` (conflict). No advance | n/a | Classify separately for health. Replay is safe |
| Redaction failure or event id redacted | 503 retry. **Stalls until fixed**, nothing dropped | Unavailable, retried | Active privacy profile must not alter `sqlsrv-<hex>` ids. Assert with real detectors |
| Privacy profile changed between first enqueue and replay | Payload differs → 409 → stall | Same | Document. Test that the stall is visible |
| Secret leakage | Must not occur | Must not occur | Seed canary secrets in value and username columns. Assert absent from logs, cursor DB, skip audit file and tap, and that queue values are redacted |
| Entra token acquisition fails (no identity, wrong client id, IMDS down) | `SqlException` or authentication failure. Back off, no checkpoint | Same | Health shows the failure type only. No token, client id or endpoint text in logs. Refused modes fail at startup |

### 4.1 Testable at-least-once statement (no exactly-once claim)

For one forwarder instance per source, with an incrementing cursor and an `EventTime` that does not decrease in sequence order, a row qualifies when it is:

1. visible through the approved view;
2. above the committed cursor; and
3. committed within `CommitSettleDelay` of its `EventTime`.

The ordering assumption is required. The adapter stops at the first row newer than the window (`SqlServerSourceAdapter.cs:85-91`) and the cursor moves to the highest sequence returned (`:219-221`). If a later sequence carries an older `EventTime`, it can pass the window while an earlier sequence is uncommitted, and the earlier row is then skipped even if it commits within the window. An in-process comparison cannot detect this: while n is uncommitted the forwarder sees only n-1 and n+1, so the decrease involving n is never observed. Detection therefore needs a separate **late-row audit**. For each committed batch the forwarder keeps metadata only: the sequence range `(previous cursor, new cursor]` and the count of rows it settled. After `2 × CommitSettleDelay` it re-counts rows in that range through the same view (`COUNT_BIG(*)`, bounded to the range, no column values read). A higher count means rows were skipped. It is reported as a health signal with the range and the difference only, and the forwarder keeps running (decision Q5). It covers out-of-order identity commits beyond the window as well. The audit detects a skip after the fact; it does not prevent or replay it.

Detection is limited to rows **visible at a recount**. Under `READ_COMMITTED_SNAPSHOT` a row that commits after the last recount leaves the count unchanged. Each range is therefore recounted at `2 ×`, `4 ×` and `8 × CommitSettleDelay`, then dropped. That bound is not enforceable from the forwarder, because it cannot limit how long an application transaction stays open. A row whose transaction commits after the final recount is skipped with no signal. Qualification on the real table must measure the longest open transaction against `8 × CommitSettleDelay` (section 5). Retained ranges are bounded (for example the last 1,000 batches); a range evicted early is counted as health, so the forwarder never silently shortens the audit.

Pending ranges are durable. Each range holds its sequence bounds, settled count, checkpoint commit time and the recounts still due. It is written in the same SQLite transaction as the batch checkpoint's compare-and-swap. A forwarder-owned `ISourceCursorStore` (`SqlServerSourceAdapter.cs:189-211`) writes the cursor row and a ranges table in the cursor database together. A range is updated after each recount and deleted after its final one. A lost compare-and-swap writes neither the cursor nor the range. On start, before its first poll, the forwarder restores every pending range. It runs any recount that fell due during the outage at once, and the rest on schedule from the stored commit time. A late recount can only see more committed rows, so it never hides a skip. Ranges that cannot be restored (an unreadable table or a row that does not parse) are reported as a health signal with their count, as for eviction, and the forwarder keeps running (Q5).

Every qualifying row reaches one of five outcomes: **queued in the collector at least once**, **counted in a suppression window** (only if a suppressing policy matches, section 3.2), **definitively rejected** (counted), **not selected** (counted) or **skipped by an operator** through the audited skip-row command (audited, signalled, one row at a time; section 3.2). The cursor never passes a row without one of these outcomes. Duplicates can follow a crash, cancellation or partial refusal. The queue suppresses them only within `DeliveredRetention` on the same collector and pack route. A replayed suppressed row is not deduplicated, because nothing was stored for it (`SqliteEventQueue.cs:340-356`), so it is counted again or queued in a later window. Rows committed after the settle window can be skipped. The late-row audit reports such skips only after the fact, and only for rows that commit before the final recount of their range. Sentinel arrival is not claimed without a destination query (`AGENTS.md:80-81`).

Assertable properties: no skip within the window except by audited skip-row, no advance without an outcome, at most one queue row per source row within retention, no plaintext canary outside redacted queue payloads, and memory bounded by `BatchSize × MaximumRecordBytes`.

### 4.2 Local disposable database tests (CI)

- An `mcr.microsoft.com/mssql/server` Developer container, following the AWS emulator e2e precedent (`.github/workflows/ci.yml:513-514`). It is linux/amd64 only, so CI is the reference; Apple silicon emulation does not count as evidence.
- Generate the SA password per run and never print it. Create a login with `SELECT` on the view only, and **assert that `INSERT` is refused**. This shows that read-only access comes from grants, not from `ApplicationIntent`.
- TLS with a test CA and server certificate mounted into the container. Do **not** use `TrustServerCertificate=true`.
- Run the matrix rows marked for the disposable DB: type matrix, nullable key columns, real `DATALENGTH`, a long-open transaction, pause and stop, SIGKILL injection, and a real collector container with a pack signed by a test key.
- Entra managed identity cannot be exercised against the container. CI covers mode parsing, refusal of the other modes and the absence of tokens in logs and state only.
- Results are local evidence only, labelled as such.

### 4.3 Real SQL Server qualification (separate, not CI)

- A customer-representative SQL Server 2019 or 2022 on Windows.
- An availability group with read-only routing, and failover during polling.
- gMSA integrated auth, and Entra managed identity sign-in (Q4) on an Azure SQL or Entra-enabled target, with tokens confirmed absent from disk.
- An enterprise CA.
- A permissions audit.
- A check that `EventTime` does not decrease in sequence order on the real table.
- The longest open transaction on the audit table under production load, compared with `8 × CommitSettleDelay`. A longer one is a no-go for that deployment unless the operator accepts undetected skips in writing.
- Plan and allocation checks: index seek on the identity column with `TOP` and `ORDER BY`, as required by `queue-v5-durability.md:314-315`.
- The audited skip-row command on a real stall, with the audit record and `row-skipped` signal checked.
- A soak at production insert rates with real long transactions, measuring duplicates and skips, and confirming the late-row audit reports each induced skip whose row commits before the final recount, that skips committing later produce no signal (the documented limit), and that its `COUNT_BIG` seeks on the identity index.
- Sentinel arrival checked by query under a separate identity.

## 5. Implementation scope (approved 2026-11-13)

This follows the root invariants (`AGENTS.md:89-93`):

- a scoped `src/Bower.Agent.SqlServer/AGENTS.md`;
- a config schema;
- cancellation, malformed-input, backpressure and durable-cursor tests;
- the pack-route method in `Bower.Forwarding` with tests;
- a sample tenant pack with parsers for rows with and without a source IP;
- deployment and threat-model docs;
- the `Directory.Build.props` comment and the README status row;
- the startup column type and nullability check (Q1, Q2);
- single-row stall isolation, the audited skip-row command, its audit file with start-up reconciliation and the `row-skipped` health signal (Q3);
- the late-row audit health signal with durable pending ranges, with the forwarder left running (Q5);
- managed identity sign-in and refusal of the other Entra modes (Q4).

No new package is needed for SQL or integrated auth.

Implementation gates:

- **Entra dependency (Q4).** Before the Entra code merges, add a written justification to `docs/architecture/dependencies.md` for every package it brings into the forwarder's graph, with alternatives considered. `Azure.Identity` is already pinned centrally for other hosts (`Directory.Packages.props:11`), but it is not in the SQL adapter's graph today (`src/Bower.Source.SqlServer/packages.lock.json`). Whether the resolved `Microsoft.Data.SqlClient` 7.1.1 needs a separate Azure authentication package for managed identity is not checked here and must be confirmed then. This design does not edit that file.
- **Skip-row before go-live (Q3).** No release of the forwarder is marked ready for production until the command and its tests pass.
- **Per-deployment qualification (4.3).** Each production deployment still needs its own qualification, including the longest open transaction against `8 × CommitSettleDelay`.

Optional adapter follow-ups, each separately reviewed:

- leave unused value columns out of the projection;
- validate encryption settings;
- add per-record checkpoints for incrementing cursors;
- resolve the unreachable saturation exception.

## 6. Unresolved trade-offs

- **Demand (unverified, accepted risk).** The product owner decided on 2026-11-13 to build without verified demand and owns that risk. The original analysis follows. The repository has no customer, issue or evidence asking for SQL polling. Issue #99 only lists it among sources. The README example `legacy-finance-audit` is illustrative. Alternatives already exist:
  - SQL Server Audit to the Security log (event 33205), using the Windows Event Log source with a new signed parser (`docs/deployment/database-audit.md:84-87`);
  - Azure SQL auditing to Sentinel (`:88-90`);
  - SDK or HTTP intake for applications that can change.

  **Original go gate (no longer a precondition to build):** a named deployment with an immutable, identity-keyed audit table, an application that cannot emit events, no viable route through the alternatives, and a DBA willing to create the view and grant. It stays useful as a per-deployment fit check before qualification (4.3). Risk if no such deployment appears: a shipped non-AOT executable, image and config schema with support cost and no users.
- **AOT.** The forwarder adds a second non-AOT shipped executable and a runtime-based image. That is a deliberate, documented exception, but it is a new support surface.
- **Operational.**
  - Cursor and enqueue are not atomic, so a duplicate window depends on retention, and the pressure floor can shrink it to 1 h.
  - Commit-settle skips are possible, and also occur within the window if `EventTime` decreases in sequence order. The late-row audit reports them after the fact, only for rows that commit before the final recount, and does not recover them.
  - Poison rows stall the source until an operator uses the audited skip-row command (Q3).
  - Late-row audit findings do not stop the forwarder (Q5). Skipped rows stay skipped unless the operator acts on the signal.
  - Entra sign-in adds a token path and a dependency to the forwarder (Q4).
  - Active-active HA is not supported (single poller per source).
  - The forwarder and collector must be upgraded together.

Open questions. All are decided; see [Decisions (2026-11-13)](#decisions-2026-11-13).

1. **Decided (Q1):** refuse non-`datetimeoffset` at startup. Should the forwarder refuse non-`datetimeoffset` time columns, or convert from a declared zone?
2. **Decided (Q2):** `bigint` only. Is `bigint` identity required, or should `int` be supported through a converter?
3. **Decided (Q3):** required before go-live. Is an audited skip-row command needed before go-live?
4. **Decided (Q4, against the recommendation):** in scope, with a dependency gate. Is the Entra or managed identity dependency in scope?
5. **Decided (Q5):** health signal, keep running. Is `EventTime` ordering only a deployment gate checked at qualification, or should a late-row audit signal also stop the forwarder until an operator reviews it? (The forwarder cannot see the decrease in process, section 4.1.)

## 7. STOP conditions

| Condition | Assessment |
|---|---|
| Cursor advancement cannot be tied safely to durable outcomes | **Not hit.** (A) advances only after collector-durable or definitive outcomes (`CollectorClient.cs:94-104`; `SqliteEventQueue.cs:289-298`). (B) could use the atomic path. The commit-settle skip is a source visibility limit and is declared in 4.1, not hidden |
| Deployment would silently change Native AOT support | **Not hit.** (A) leaves every AOT host unchanged. (B) cannot be silent, because the AOT analysers fail the build (`Directory.Build.props:7,47-52`), and it is rejected anyway |
| Credentials must be logged or persisted | **Not hit**, provided gMSA or managed identity is used, or the operator supplies a credential file that Bower only reads. Managed identity tokens stay in memory, and modes that need a stored secret are refused (3.2). If a target environment needed Bower to store a SQL password, a client secret or an access token, this would become a STOP |

These conditions are unchanged by the go decision and apply throughout implementation. If any is hit, implementation stops and returns to the product owner.
