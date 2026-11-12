# Design 004: SQL Server polling integration

**Status:** Design for review, not implemented · **Date:** 2026-11-12 · **Planned and checked at:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [004-sql-server-integration.md](004-sql-server-integration.md)

## Decision

**No-go for implementation at this commit. The integration boundary is settled so that work can start once the demand gate (section 6) is met.**

If it goes ahead, build a **separate non-AOT forwarder** (`Bower.Agent.SqlServer`, following the `Bower.Agent.Docker` and `Bower.Agent.Cloud` precedent). It polls one approved view with an incrementing cursor and posts fixed-shape records to the collector's signed pack route. It advances its cursor only after the collector answers with a durable or definitive outcome for every record in the batch. The collector stays Native AOT and never holds SQL credentials. A non-AOT collector variant is rejected: it doubles the collector release matrix and puts a SQL driver and SQL credentials in the process that owns the queue. It would make cursor and enqueue atomic, but that gain is a smaller duplicate window, not a different delivery guarantee.

Only one mapping is recommended: application **failed sign-in rows → `authentication_failure`** under the existing default policy. Customer demand is **unverified**. Nothing in the repository names a customer, table or request (section 6).

Drift check (step 1): HEAD equals the planned commit. `git diff --stat 64859aa..HEAD -- README.md src/Bower.Source.SqlServer src/Bower.Collector tests` is empty. `test -f src/Bower.Source.SqlServer/SqlServerSourceAdapter.cs && test -f src/Bower.Source.SqlServer/AGENTS.md` exits 0.

No STOP condition is hit (section 7).

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
| Managed identity | Integrated Windows auth needs no new package. Entra or managed identity is not in the resolved graph (`src/Bower.Source.SqlServer/packages.lock.json` has no `Azure.*`) and would need a justified dependency (`AGENTS.md:92-93`). **Feasibility unverified** | The same dependency question, but it lands in the collector's graph |
| Failure isolation | A driver hang, native SNI fault or memory spike stops only the forwarder. Queueing and delivery continue (`PRODUCT.md:63-64`) | The same faults share a process with `QueueDeliveryWorker`. The command timeout bounds queries but not native faults |
| Cursor and enqueue | **Not atomic.** The cursor commits after HTTP acks. A crash in between replays the batch, which the queue deduplicates | Atomic through `QueueEnqueueBatch.CommitWithCursorAsync`. Duplicates come only from timestamp overlap |
| Support cost | One more binary, image, config schema and state file to back up, plus version skew with the collector. It reuses `CollectorClient` and the agent patterns | Every collector defect must be reproduced in two flavours, the installer and qualification matrix doubles, and the 72-hour soak evidence does not transfer |

**Recommendation: (A).** (B) only reduces how many duplicates occur, and the collector queue already absorbs them. It pays for that with credential concentration, a second collector build and loss of failure isolation. Revisit (B) only if measured replay duplicates exceed the retention window in practice, which is unlikely with the bounds in section 3.

## 3. Recommended shape

### 3.1 Mapping: one event, one table

| Item | Specification |
|---|---|
| Source | An operator-created **view** over the application's audit table, filtered to failed sign-in rows, `SELECT` granted to the forwarder principal only. Rows must be immutable, with a `bigint` identity sequence and an `EventTime` set by the database in the inserting statement (for example `DEFAULT SYSUTCDATETIME()`), so `EventTime` does not decrease as the sequence rises (section 4.1) |
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
- **Redaction before persistence.** The forwarder persists only the cursor, which holds sequence and time values (`SqlServerSourceAdapter.cs:356-365`). There is no spool or buffer of rows on disk. The collector redacts before enqueue (`SecurityEventProcessor.cs:236` before `:402`).
- **Credentials.** Prefer integrated auth (gMSA). A connection string with a password comes from an owner-only file that the operator supplies. Bower never writes, copies or logs it. Refuse `TrustServerCertificate=true`, `Encrypt` other than `Mandatory` or `Strict`, and `Persist Security Info=true`. Keep the `ApplicationIntent=ReadOnly` requirement.
- **Logging.** Log ids, counts, failure types and `SqlException.Number` only. Never log exception messages, which can carry the server, login or converted values. Never enable EF sensitive-data logging.
- **Durable ack boundary.** A batch checkpoint is committed only when **every** record in it got `Accepted` (200 or 202) or `Rejected` (400, 413 or 422: definitive). A 202 means the event was committed to the collector queue or, if the matching policy suppresses it, counted in a durable suppression window in the same transaction (`PackEndpoints.cs:111`; `SqliteEventQueue.cs:295-297,347-356`). The recommended policy is `neverSample`, which cannot define suppression (`PolicyLoader.cs:157-160`), so suppression applies only if another policy matches these events. On the first `RetryLater`, `Throttled`, `Unauthorized`, 404 or 409, stop and do not commit. Keep the settled prefix in memory, back off and resume at the refused record, as the Docker sidecar does (`DockerSidecarWorker.cs:52-64,103-136`). Do not resend the prefix in process: the ingest limiter is a token bucket of twice `BOWER_INGEST_RATE_PER_SECOND` (default 500) with no queueing, and a duplicate spends a token too (`CollectorSettings.cs:98`; `CollectorApplication.cs:207-213`). Replaying a batch larger than the free tokens would hit 429 at the same record every time. Pace sends below the configured rate. Once all records are settled, commit the checkpoint with `CancellationToken.None`, as Windows Event Log does (`WindowsEventLogSource.cs:555-560`).

## 4. Crash, restart and concurrency matrix (step 4)

A = forwarder (recommended), B = collector variant for comparison. "Replay" means the batch is read again from the committed cursor.

| Case | A: outcome | B: outcome | Required test |
|---|---|---|---|
| Crash before any send | Nothing sent. Replay | Batch rolled back. Replay | Kill before the first POST. Cursor unchanged |
| Crash after collector commit, before the response arrives | `RetryLater`. Replay gets 200 duplicate | n/a | Kill the collector connection after the commit. Queue count unchanged on replay |
| Crash after all acks, before checkpoint | Replay of the whole batch. All 200 duplicates | Atomic, so no gap | SIGKILL between the last ack and `CommitAsync` |
| Crash after checkpoint | Next batch | Same | Restart resumes at sequence + 1 |
| Duplicate replay within retention | Deduplicated if collector, producer and pack route are the same (`EventIdentity.cs:17-18`) | Deduplicated | Replay 3 times. Queue holds exactly 1 |
| Replay after retention, or to another collector | **Sentinel duplicate** | Same | Documented limit. Test with retention 1 h and fake time |
| Stale checkpoint (two pollers, one cursor DB) | CAS refuses, `SourceCursorConflictException`. Re-read and re-poll | Conflict result. Read again | Exists in part (`SqlServerReplayTests.cs:116-124`). Add a loop-level test |
| Two pollers with separate cursor DBs | Same producer token: every row sent twice, absorbed as 200 duplicates. Different tokens: same `event_id`, different identity → 409 conflict → stall | Same across collectors | Must be prevented (one instance per source). Assert the stall is reported as health, not looped silently |
| Partial batch refusal (503 or 429 mid-batch) | No checkpoint. Back off and resume at record k. 1..k−1 are not resent. After a restart the whole batch replays as 200 or 422 again | Savepoint per record. Handled prefix commits | Refuse at record k. All of 1..k−1 are queued once and sent once. Also set `BOWER_INGEST_RATE_PER_SECOND=1` with `BatchSize` 10: the checkpoint commits and no record before a 429 is resent |
| Overlap saturation | Not applicable (incrementing only). The exception is unreachable (section 1.5) | Same | Timestamp cursor deferred. Tests are due before it is enabled |
| Out-of-order identity commits | Held back within `CommitSettleDelay`. **Skipped beyond it** | Same | Disposable DB: transaction T1 holds id n open past the window while T2 commits n+1. Measure and document the skip |
| `EventTime` lower than an earlier sequence (application-supplied time) | n+1 passes the window while n is uncommitted. **n is skipped even if it commits within the window**. The decrease is counted as health | Same | Disposable DB with `READ_COMMITTED_SNAPSHOT` on: hold id n open, commit n+1 with an older `EventTime`, poll, then commit n inside the window. Assert the skip and the health signal |
| Clock or time-zone skew in `EventTime` | Local-time values shift hold-back by the UTC offset (hours in Australia) | Same | Column stored in local time. Refuse or require `datetimeoffset` (open question) |
| Cancellation mid-query | `OperationCanceledException`. No checkpoint | Same | Cancel during `ToListAsync`. Cursor unchanged, no partial send |
| Cancellation mid-batch | Stop sending. No checkpoint. Replay | Roll back | Cancel after k sends. Queue holds k, deduplicated on restart |
| DB outage or failover | `SqlException`. Back off, no checkpoint | Same, inside the collector | Stop or pause the container mid-poll. Resume without a gap |
| Collector outage | Probe fails. No read | n/a | Collector down. No SQL query issued |
| Malformed row: NULL sequence or time | Materialisation throws. **Source stalls** | Same | Stall reported as health with type only. No checkpoint |
| Malformed row: invalid IP, NULL or blank Username or Action, or field over 2,048 characters | 400 → definitive drop, counted. Cursor advances | Invalid, counted | Verify the counter. Verify no value in logs |
| NULL or blank SourceIp | Sent without `sourceIp` to the no-IP parser. Accepted | Same | Seed NULL and blank SourceIp rows. Assert 202, not 400, and the same parser index on replay |
| Oversized identity columns | Throws. **Source stalls** by design (`queue-v5-durability.md:304`) | Same | Real `DATALENGTH` on SQL Server. Stall reported |
| Column type mismatch (`int` identity, `datetime2`) | Probable `InvalidCastException`. **Unverified** | Same | Type matrix on a real engine (open question) |
| Collector storage pressure or full | 503 → `RetryLater`. No checkpoint | Batch refused | Fill the queue. Cursor holds. Recovery drains |
| Forwarder disk full (cursor DB) | CAS write fails and returns `false` (conflict). No advance | n/a | Classify separately for health. Replay is safe |
| Redaction failure or event id redacted | 503 retry. **Stalls until fixed**, nothing dropped | Unavailable, retried | Active privacy profile must not alter `sqlsrv-<hex>` ids. Assert with real detectors |
| Privacy profile changed between first enqueue and replay | Payload differs → 409 → stall | Same | Document. Test that the stall is visible |
| Secret leakage | Must not occur | Must not occur | Seed canary secrets in value and username columns. Assert absent from logs, cursor DB and tap, and that queue values are redacted |

### 4.1 Testable at-least-once statement (no exactly-once claim)

For one forwarder instance per source, with an incrementing cursor and an `EventTime` that does not decrease in sequence order, a row qualifies when it is:

1. visible through the approved view;
2. above the committed cursor; and
3. committed within `CommitSettleDelay` of its `EventTime`.

The ordering assumption is required. The adapter stops at the first row newer than the window (`SqlServerSourceAdapter.cs:85-91`) and the cursor moves to the highest sequence returned (`:219-221`). If a later sequence carries an older `EventTime`, it can pass the window while an earlier sequence is uncommitted, and the earlier row is then skipped even if it commits within the window. The forwarder counts each `EventTime` decrease against the previous row or the committed cursor as a health signal. That makes a violation visible but does not prevent the skip.

Every qualifying row reaches one of four outcomes: **queued in the collector at least once**, **counted in a suppression window** (only if a suppressing policy matches, section 3.2), **definitively rejected** (counted) or **not selected** (counted). The cursor never passes a row without one of these outcomes. Duplicates can follow a crash, cancellation or partial refusal. The queue suppresses them only within `DeliveredRetention` on the same collector and pack route. A replayed suppressed row is not deduplicated, because nothing was stored for it (`SqliteEventQueue.cs:340-356`), so it is counted again or queued in a later window. Rows committed after the settle window can be skipped without a gap signal. Sentinel arrival is not claimed without a destination query (`AGENTS.md:80-81`).

Assertable properties: no skip within the window, no advance without an outcome, at most one queue row per source row within retention, no plaintext canary outside redacted queue payloads, and memory bounded by `BatchSize × MaximumRecordBytes`.

### 4.2 Local disposable database tests (CI)

- An `mcr.microsoft.com/mssql/server` Developer container, following the AWS emulator e2e precedent (`.github/workflows/ci.yml:513-514`). It is linux/amd64 only, so CI is the reference; Apple silicon emulation does not count as evidence.
- Generate the SA password per run and never print it. Create a login with `SELECT` on the view only, and **assert that `INSERT` is refused**. This shows that read-only access comes from grants, not from `ApplicationIntent`.
- TLS with a test CA and server certificate mounted into the container. Do **not** use `TrustServerCertificate=true`.
- Run the matrix rows marked for the disposable DB: type matrix, NULL keys, real `DATALENGTH`, a long-open transaction, pause and stop, SIGKILL injection, and a real collector container with a pack signed by a test key.
- Results are local evidence only, labelled as such.

### 4.3 Real SQL Server qualification (separate, not CI)

- A customer-representative SQL Server 2019 or 2022 on Windows.
- An availability group with read-only routing, and failover during polling.
- gMSA integrated auth, plus Entra or managed identity only if that dependency is approved.
- An enterprise CA.
- A permissions audit.
- A check that `EventTime` does not decrease in sequence order on the real table.
- Plan and allocation checks: index seek on the identity column with `TOP` and `ORDER BY`, as required by `queue-v5-durability.md:314-315`.
- A soak at production insert rates with real long transactions, measuring duplicates and skips.
- Sentinel arrival checked by query under a separate identity.

## 5. Implementation scope if approved

This follows the root invariants (`AGENTS.md:89-93`):

- a scoped `src/Bower.Agent.SqlServer/AGENTS.md`;
- a config schema;
- cancellation, malformed-input, backpressure and durable-cursor tests;
- the pack-route method in `Bower.Forwarding` with tests;
- a sample tenant pack with parsers for rows with and without a source IP;
- deployment and threat-model docs;
- the `Directory.Build.props` comment and the README status row.

No new package is needed for SQL or integrated auth. Any Entra-auth package needs an entry in `docs/architecture/dependencies.md`.

Optional adapter follow-ups, each separately reviewed:

- leave unused value columns out of the projection;
- validate encryption settings;
- add per-record checkpoints for incrementing cursors;
- resolve the unreachable saturation exception.

## 6. Unresolved trade-offs

- **Demand (unverified).** The repository has no customer, issue or evidence asking for SQL polling. Issue #99 only lists it among sources. The README example `legacy-finance-audit` is illustrative. Alternatives already exist:
  - SQL Server Audit to the Security log (event 33205), using the Windows Event Log source with a new signed parser (`docs/deployment/database-audit.md:84-87`);
  - Azure SQL auditing to Sentinel (`:88-90`);
  - SDK or HTTP intake for applications that can change.

  **Go gate:** a named deployment with an immutable, identity-keyed audit table, an application that cannot emit events, no viable route through the alternatives, and a DBA willing to create the view and grant.
- **AOT.** The forwarder adds a second non-AOT shipped executable and a runtime-based image. That is a deliberate, documented exception, but it is a new support surface.
- **Operational.**
  - Cursor and enqueue are not atomic, so a duplicate window depends on retention, and the pressure floor can shrink it to 1 h.
  - Commit-settle skips are possible, and also occur within the window if `EventTime` decreases in sequence order.
  - Poison rows stall the source with no audited skip tool.
  - Active-active HA is not supported (single poller per source).
  - The forwarder and collector must be upgraded together.

Open questions:

1. Should the forwarder refuse non-`datetimeoffset` time columns, or convert from a declared zone?
2. Is `bigint` identity required, or should `int` be supported through a converter?
3. Is an audited skip-row command needed before go-live?
4. Is the Entra or managed identity dependency in scope?
5. Is `EventTime` ordering only a deployment gate checked at qualification, or should the forwarder stop advancing when it sees a decrease?

## 7. STOP conditions

| Condition | Assessment |
|---|---|
| Cursor advancement cannot be tied safely to durable outcomes | **Not hit.** (A) advances only after collector-durable or definitive outcomes (`CollectorClient.cs:94-104`; `SqliteEventQueue.cs:289-298`). (B) could use the atomic path. The commit-settle skip is a source visibility limit and is declared in 4.1, not hidden |
| Deployment would silently change Native AOT support | **Not hit.** (A) leaves every AOT host unchanged. (B) cannot be silent, because the AOT analysers fail the build (`Directory.Build.props:7,47-52`), and it is rejected anyway |
| Credentials must be logged or persisted | **Not hit**, provided integrated auth is used or the operator supplies a credential file that Bower only reads. If a target environment needed Bower to store a SQL password, this would become a STOP |
