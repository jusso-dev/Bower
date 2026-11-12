# Design 005: Delivery-gap investigation

**Status:** Design for review, not implemented · **Date:** 2026-11-12 · **Planned and checked at:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [005-delivery-gap-investigation.md](005-delivery-gap-investigation.md)

## Decision

Build the first slice as an **on-demand KQL investigation workbook plus a new runbook section (R9)**. It runs under the operator's own read-only workspace access and reports per collector and per run (`CollectorId`, `collectorStartedAt`), with an explicit state for each. It must not be deployed as an alert. Do not integrate it with the management console yet. Revisit that after plan 001 provides declared inventory and the health record authenticity release blocker is closed (`docs/production-readiness/06-monitoring-and-runbooks.md:1113-1122`).

The investigation reports what Sentinel shows. It never infers that all records arrived, and a missing health record is never turned into a count of lost security events. Without declared inventory, fleet coverage is always reported as **unknown**.

Drift check (step 1): HEAD equals the planned commit, so there is no drift. All cited files exist (`test -f` on both delivery queries exits 0).

## 1. What the existing signals detect (step 2)

### 1.1 How sequence numbers and `collectorStartedAt` are produced

`src/Bower.Collector/Jobs/DeliveryHealth.cs` only evaluates queue state. It calls itself "Queue observations, never a claim of destination query verification" (`DeliveryHealth.cs:5`) and does not infer arrival from retained acknowledgements (`DeliveryHealth.cs:28-32`). The series fields come from elsewhere:

| Fact | Source |
|---|---|
| `collectorStartedAt` is `PipelineTelemetry.StartedAt`, taken once from the clock when the process starts | `src/Bower.Core/PipelineTelemetry.cs:47,70`; `src/Bower.Collector/CollectorHealthWorker.cs:94` |
| `sequence` is an in-memory counter, starting at 0. The first record of a run is 1 | `CollectorHealthWorker.cs:41,95` |
| **The sequence is incremented before the record is queued.** A record the queue refuses (`QueueCapacityExceededException`), that policy does not queue, or whose processing throws, still uses up its number | `CollectorHealthWorker.cs:95` vs `:117-144`, `:57-60` |
| The managed privacy gate returns before the increment, so gated intervals leave no gap | `CollectorHealthWorker.cs:79-85` |
| One record at start-up, then one per interval of 60–3600 s. The period drifts by the processing time | `CollectorHealthWorker.cs:12-13,47-70`; `src/Bower.Collector/CollectorSettings.cs:528` |
| `EventId` is derived from collector id, process start and sequence, so duplicates of a record share an id | `src/Bower.Collector/CollectorHealthRecord.cs:200-206` |
| `TimeGenerated` is the collector's clock when it sampled the record | `CollectorHealthRecord.cs:212` |
| Counters are deltas since the last *queued* record of the same process and reset on restart | `CollectorHealthRecord.cs:177-181,289-293,442`; runbook `:141-143` |
| Every number, including `sequence`, is clamped to 9,999,999 | `CollectorHealthRecord.cs:59-60,606-607` |

Consequence: the comment "A missing number means a record Bower queued never reached the table" (`delivery-sequence-gaps.kql:3`) overstates the evidence. A gap means the record **was not in the table at query time**. It may never have been queued (host log events 1330, 1331, 1332) or it may have been lost after queueing. This is a documentation correction for a follow-up. This design does not edit the query.

### 1.2 `delivery-sequence-gaps.kql`

| Aspect | Behaviour |
|---|---|
| Detects | Within one run (`CollectorId`, `collectorStartedAt`), sequence numbers missing **between** the lowest and highest observed in the window: `MissingRecords = Last - First + 1 - dcount(Sequence)` (`:20-27`) |
| Lookback and lag | 24 h of `TimeGenerated`, ending 30 min before `now()` (`:13-16,19`) |
| Duplicates | Harmless: `dcount(Sequence)` (`:22-23`) |
| Live evidence | #249 deliberate loss of 100 events also lost one health record. The query returned 1 for that collector and 0 for the clean one (`:9-11`; `docs/deployment/ama-syslog-output.md:195-198`) |
| Deployment | Not loaded by `deploy/sentinel/monitoring/monitoring.bicep`. Its `healthRules` array (`:127-241`) loads the eleven other queries. |

What it can miss or misreport:

- **Event loss without health-record loss.** Health records are small and periodic. A loss that falls between records, or that only hits larger events (rsyslog `MaxMessageSize` cut, undecodable message, rate-limit burst), leaves the series contiguous (`ama-syslog-output.md:170-175`).
- **Leading loss.** `min(Sequence)` is used rather than 1, so missing records 1…k at the start of a run are invisible.
- **Trailing loss.** There is no upper bound. Missing final records before a crash, a restart or now cannot be seen.
- **Whole-run loss.** A run with no rows in the window produces no row at all.
- **Runs with one record** cannot show a gap.
- **Records without `sequence`** are dropped silently (`:21`). If `collectorStartedAt` is missing, runs merge under an empty `Started`, and that can hide gaps.
- **Late arrival.** A record delayed by more than 30 min shows as a gap that later closes. The result depends on when the query ran.
- **Local refusal** shows as a gap even though the destination path did nothing wrong (1.1).
- **Forged rows** on the AMA syslog path can fill a gap or create one (`ama-syslog-output.md:209-219`; runbook `:1113-1122`).
- **Clamp.** A run that passes sequence 9,999,999 stops increasing. That is about 19 years at 60 s, so in practice it does not matter.

`MissingRecords` counts health records. It is not a number of lost security events.

### 1.3 `delivery-reconciliation.kql`

| Aspect | Behaviour |
|---|---|
| Detects | Per `CollectorId`: `Reported = sum(pipeline.eventsQueued)` from health records by `TimeGenerated` (`:23-31`), against `Arrived = distinct EventId` for that collector by `ingestion_time()` (`:32-36`). Returns a row when `Missing / Reported > 0.5 %` (`:20,40-42`) |
| Lookback and lag | 24 h of `TimeGenerated` ending 30 min ago for Reported. Ingestion time from window start to `now()` for Arrived (`:18-22,34`) |
| Live evidence | No false alarm (304 reported, 306 arrived). Missed the 100-event loss (`:4-6`; `ama-syslog-output.md:186-194`) |
| Deployment | Not wired into monitoring (`:6`) |

What it can miss or misreport:

- **The health record covering a loss is lost too.** Its `eventsQueued` is never reported, so the loss disappears from both sides. This is the #249 case.
- **Extra arrivals cancel out losses.** Examples: events queued after the last record of a run (`:13-14`), anything queued outside the selection counters (`:16`), backlog reported before the window but ingested inside it (different time bases on the two sides), and forged rows that claim the `CollectorId`.
- **Losses under the tolerance**, for example a few events from a busy collector.
- **Negative `Missing` and `Reported == 0`** never return a row (`:41-42`). A collector with no health records in the window does not appear at all, because the join starts from the reported side.
- **It groups by `CollectorId` only.** Restarts and output changes are mixed together, and `Output = take_any` (`:29`) hides that.
- Events still queued or dead-lettered show as missing. `DeadLetteredNow` is a current total, not a delta for the window (`:15,30`).
- Scanning every row for distinct `EventId` gets expensive as volume grows.

`Missing` is an approximate difference between two counts measured on different time bases. It is not a list or count of specific lost events.

### 1.4 The other queries in the folder (supporting evidence only)

| Query | Use in an investigation | Limit |
|---|---|---|
| `collector-health-missing.kql` | Has the series stopped? Newest health ingestion per collector. `expectedCollectorIds` adds never-seen collectors (`:5-15`) | Without a declared list, a collector that never reported cannot appear (runbook `:1081-1089`) |
| `queue-backlog.kql` | Arrival lag (`ingestion_time() - TimeGenerated`) and oldest undelivered age (`:9-17`). Shows whether "pending" is plausible | Newest record only. Can report incomplete metrics |
| `dead-letters.kql` | Events set aside locally that will never arrive without replay (`:3-8`) | Current total |
| `queue-storage.kql` | Refusals and pressure that explain locally refused records (`:10-12,19-23`) | Older collectors cannot report while full |
| `destination-credential.kql`, `dcr-errors.kql` | Explain failures on the Logs Ingestion path. `dcr-errors` projects only bounded names (`dcr-errors.kql:4-6`) | Not evidence for the AMA syslog hops |
| `destination-freshness.kql`, `source-overdue.kql` | Silence per source. Separates "source quiet" from "delivery lost" | Cannot find sources with no rows (runbook `:1086-1089`) |
| `source-transport-errors.kql` | Loss **before** acceptance, which the delivery queries never cover | Coverage flags can be incomplete (`:38-46`) |
| `table-no-ingestion.kql`, `syslog-tls-expiry.kql` | Context only | Event-time silence is not proof of absence (runbook `:1106-1111`) |

Alert qualification status: the revised rules have not been qualified end to end (runbook `:180-183`).

## 2. Operator workflow (step 3)

### 2.1 Unit of evidence and provenance

One row per **run** (`CollectorId`, `collectorStartedAt`), rolled up to one row per collector. Each result carries this provenance:

- Workspace ID, the query identifier, and a SHA-256 of the exact query text (the repository version).
- `QueryRunAt` (`now()` at execution). Event-time window `[WindowStart, WindowEnd]`. Ingestion cutoff (= `QueryRunAt`). Lag allowance.
- Completeness flag (complete, partial, error, or truncated by service limits).
- Per run: observed `delivery.output` values, `recordVersion`, `intervalSeconds`, record count, duplicate copies, first and last `TimeGenerated`, maximum observed arrival delay, and the distribution of `Origin.kind`/`Origin.host` on the AMA syslog path (`docs/reference/sentinel-table.md:41-68`).
- An authenticity note on every result: "health records are not authenticated (runbook `:1113-1122`)".

### 2.2 Time windows, current versus stale

- The operator chooses the window. The default is the existing 24 h ending at `now() - lag`. The query also reads **one interval before** the window, so it can find the previous record of each run.
- Lag is not taken as fixed: derive a per-collector figure from observed arrival delay (runbook `:164-166`). Use `max(30 min, observed p99 delay + one interval)`. A gap whose neighbouring records are younger than that is **pending**, not missing.
- Every result is "as of `QueryRunAt`". The runbook tells operators to re-run after one further lag period before raising a gap. A gap that later closes is recorded as *resolved by late arrival*. The first result is then stale, not wrong.
- If this is ever wired as an alert, the rule's `windowSize` must cover lookback plus lag. The current `healthWindow` of 30 min (`monitoring.bicep:46`) would leave the 24 h query with almost nothing to read. Not in scope here.

### 2.3 State table

"Absence of evidence" means the data cannot answer the question. "Evidence of absence" means a complete query shows that specific expected rows were not in the table at query time. Only GAP-OBSERVED is evidence of absence, and it applies only to health records.

| State | Condition | Absence of evidence or evidence of absence | What it does **not** mean | Next check |
|---|---|---|---|---|
| QUERY-INCOMPLETE | Error, partial result, timeout or truncation (compare `src/Bower.Evidence/AzureClients.cs:68-73,92-104`) | Absence of evidence | Not "no gaps" | Narrow the window or the collector filter and re-run |
| COVERAGE-UNKNOWN | Fleet scope with no declared inventory (plan 001 not implemented) | Absence of evidence | Not "every collector reported" | Supply a declared list, labelled as such |
| NOT-SENTINEL-OUTPUT | Declared or last observed output is `s3`, `http` or `none`. Health records do not reach `BowerSecurity_CL` | Absence of evidence (not applicable) | Not loss, not delivery | Verify at that sink. Bower cannot prove it from Sentinel |
| NO-HEALTH-EVIDENCE | Collector declared, or seen in other rows, with zero health records in the window | Absence of evidence | Not a loss count. It may be stopped, gated, or health records not enabled | R1. Host check. `collector-health-missing` |
| SCHEMA-UNKNOWN | Records without `sequence` or `collectorStartedAt`, or an unknown `recordVersion` | Absence of evidence | Not contiguous | Upgrade the collector. Check the policy |
| INSUFFICIENT | One record of the run in the window | Absence of evidence | Not contiguous | Widen the window |
| PENDING | A gap, or the window end, is within the lag allowance | Absence of evidence (not yet) | Not loss | Re-run after the lag |
| HEAD-UNKNOWN | `collectorStartedAt` falls inside the window and the first observed sequence is greater than 1 | Absence of evidence for records 1…First-1 | Not loss | Host log 1330/1331/1332 around start-up. Re-run later |
| TAIL-UNKNOWN | A later run exists, or the last record is older than about two intervals plus lag | Absence of evidence after Last | Not loss, and not a clean stop | Host or service logs for a crash or stop. R1 |
| GAP-OBSERVED | Complete query, past the lag, sequence numbers missing between First and Last | **Evidence of absence** of those health records, as of `QueryRunAt` | Not a count of lost security events. Not proof the record was ever queued | Host logs 1330/1331/1332. `queue-storage`. Dead letters. On AMA syslog: journald and rsyslog logs, agent log, the `Syslog` table for undecoded messages (`ama-syslog-output.md:170-175`) |
| GAP-RESOLVED | An earlier GAP-OBSERVED is filled at a later run of the query | Earlier result stale | Not a false alarm in the query, the record was late | Record the arrival delay |
| NO-GAP-OBSERVED | Complete query, past the lag, First…Last contiguous | Evidence that this health series arrived between First and Last only | Not proof that every security event arrived. Head and tail stay unknown | Reconciliation, plus per-event proof when needed (`azure-logs-ingestion`, `ama-syslog-output.md:207`) |
| COUNT-SHORTFALL | Reconciliation above tolerance, complete query, no restart in the window | Indicative only: counts on different time bases | Not a list or exact count of lost events | Check the queue and dead letters. Run per-run reconciliation |
| COUNT-UNEVALUABLE | `Reported` is 0, mixed outputs, a restart in the window, or `Missing` negative | Absence of evidence | Not "reconciled" | Shorter window inside one run |
| DUPLICATES-SEEN | More than one copy of an `EventId` | Informational (at-least-once delivery) | Not an error | None. Deduplicate on `EventId` |
| ORIGIN-UNEXPECTED | Health rows for the collector with an unexpected `Origin.kind`/`host` | Weakens every other state | Not proof of forgery | Install the rsyslog origin filter (`ama-syslog-output.md:221-236`). Restrict DCR writers |

States combine. A run can be HEAD-UNKNOWN, GAP-OBSERVED and TAIL-UNKNOWN at the same time. The collector roll-up shows the worst evidence state and lists the unknowns. A roll-up never reports "healthy".

### 2.4 Duplicates and restarts

- Duplicates: count each `EventId` (health) or `Sequence` once. Report the copies separately.
- Restart: a new `collectorStartedAt` starts a new series at 1 (runbook `:132-134`). Show runs in time order with the gap between the last record of one run and the start of the next. That gap and its two edges are HEAD-UNKNOWN/TAIL-UNKNOWN and are never counted as missing records. Run reconciliation per run, not per collector, because counters reset (`CollectorHealthRecord.cs:289-293`).
- Two runs with the same `CollectorId` overlapping in time point to a cloned identity. Flag it, and do not merge the runs.

### 2.5 Least privilege

- Operators: read access to `BowerSecurity_CL` only. Use table-level read if the tenant supports it (to be confirmed), otherwise Log Analytics Reader, the verifier role used in every evidence run (for example `docs/evidence/resoak-20261106-092539/README.md:35`). Add `Syslog` read only for the AMA syslog undecoded-message check. No role on the DCR, the DCE, alert rules or the ingestion identity.
- Publishing the workbook needs workbook write access once, by the maintainer only. Operators can also paste the versioned KQL from the runbook without any write access.
- Host-side next checks: prefer the host check output and logs. `GET /v1/status` needs the ingest token when one is set (`ama-syslog-output.md:158-159`), and that token can also submit events. Do not hand it to investigators. Open question 5.
- `LAQueryLogs`, if the tenant enables it, records who ran which query. Recommended, not required.

### 2.6 Options compared

| | A. KQL workbook and runbook (recommended) | B. Management console integration |
|---|---|---|
| Availability | Works when the optional management plane is down (`PRODUCT.md:24-27`) | Fails with the management plane |
| Identity | The operator's own read-only role. No new stored credential | A new verifier identity with workspace read, held by the API (pattern: `src/Bower.Management.Api/SetupCanary.cs:128-131`). Broad read across the workspace unless table-scoped |
| Correctness tooling | KQL only. Completeness depends on the operator reading the portal's partial-result notice | Can enforce QUERY-INCOMPLETE in code (`AzureClients.cs:63-65,92-104`) and attach Entra roles (`Bower.Viewer`, `ManagementApplication.cs:107`) |
| Inventory | Takes a declared list as a parameter, labelled as declared | Fleet records are observed heartbeats, not independent inventory (plan 001). It risks implying completeness |
| Cost | No new ingestion. Query cost depends on the table plan (check current Azure Monitor pricing). Reconciliation scans every row, so filter it per collector | The same query cost, plus polling if results are cached. Cached results go stale. Ongoing API, UI and test maintenance |
| Effort | S–M: query functions, workbook JSON, R9, fixtures | M–L: API, UI, storage, RBAC, tests, and the same KQL anyway |
| Authenticity | Same open blocker | Same open blocker. A console makes it look more authoritative than it is |

Recommend A. B adds a broad-read identity and depends on the management plane. It gains enforcement that can be had in A by testing the query and the runbook, and its main benefit (a join to inventory) needs plan 001 first. B can reuse A's KQL text unchanged later.

### 2.7 Dependency on declared inventory

Until plan 001 is implemented, the investigation lists only collectors that have rows in the window. Fleet scope is COVERAGE-UNKNOWN. An operator may pass a list of collector ids and expected outputs (as `expectedCollectorIds` does, `monitoring.bicep:51-52`). The result labels it "declared by operator, not verified". Once a declared inventory exists, join it on the left, so every declared collector gets a state (NO-HEALTH-EVIDENCE rather than nothing) and NOT-SENTINEL-OUTPUT comes from the declaration rather than observation.

## 3. Fixtures and qualification (step 4)

### 3.1 Testable query shape

Write each investigation query as a KQL function over a **normalised input** with columns `CollectorId, EventType, EventId, TimeGenerated, IngestedAt, Sequence, CollectorStartedAt, IntervalSeconds, RecordVersion, Output, EventsQueued, OriginKind, OriginHost`. In the workspace, a thin adapter projects `BowerSecurity_CL` into it, with `IngestedAt = ingestion_time()`. Fixtures use `datatable(...)` with the same columns, because `ingestion_time()` cannot be set in a fixture. Parameters: `QueryRunAt` (in place of `now()`), window, lag, optional declared list.

Local checks: a structural test that the function and adapter text match the versioned files, and a C# test of the state rules against the table in 3.2. A local Kusto engine (an emulator) is a new dependency and needs written justification in `docs/architecture/dependencies.md` (AGENTS.md). It is optional. Local fixture success proves state logic only. It is not live evidence and must not be recorded as such.

### 3.2 Fixture matrix

Collector `c1`, interval 300 s, `QueryRunAt = T`, window ending `T - 30m`, unless stated otherwise.

| # | Case | Input | Expected |
|---|---|---|---|
| F1 | Known gap | Run S, seq 1,2,3,5,6, all ingested before T−30m | GAP-OBSERVED, missing {4}, MissingRecords 1. Shown without any event-loss figure |
| F2 | No gap | Seq 1–6 contiguous | NO-GAP-OBSERVED. Note "health series only". TAIL-UNKNOWN only if the last record is stale |
| F3 | Duplicates | Seq 1–6, seq 3 twice (same `EventId`), and one security event twice | NO-GAP-OBSERVED plus DUPLICATES-SEEN (2 copies). Reconciliation counts each `EventId` once |
| F4a | Reordered | Seq 1–6 ingested in the order 1,3,2,5,4,6 | NO-GAP-OBSERVED (order is irrelevant) |
| F4b | Late, within lag | Seq 5 has `TimeGenerated` T−40m and is not yet ingested, seq 6 at T−35m | PENDING if the observed delay rule covers it, otherwise GAP-OBSERVED |
| F4c | Late, then arrives | F4b, then seq 5 ingested. Re-run at T+1h | First run GAP-OBSERVED, second GAP-RESOLVED. Both keep their `QueryRunAt` |
| F5 | Restart | Run S1 seq 1–4, run S2 (later start) seq 1–3 | Two runs, both NO-GAP-OBSERVED. S1 TAIL-UNKNOWN. Restart shown. No records counted missing across runs. Reconciliation per run, or COUNT-UNEVALUABLE |
| F6a | Missing first record | `CollectorStartedAt` inside the window, seq 3–6 | HEAD-UNKNOWN (1–2). Not GAP-OBSERVED |
| F6b | Missing first, start before window | Start 2 days ago, seq 280–288 | No head state (the start is outside the window). NO-GAP-OBSERVED |
| F6c | Missing last record | Seq 1–4, last at T−3h, no later run | TAIL-UNKNOWN. `collector-health-missing` would also fire |
| F7 | No health records | Security rows for `c1` only. Declared list includes `c2`, which has no rows | `c1`: NO-HEALTH-EVIDENCE. `c2`: NO-HEALTH-EVIDENCE (declared). Without the list: `c2` absent and fleet COVERAGE-UNKNOWN |
| F8 | Incomplete query | Client fixture: HTTP 200 with `tables` and `error`. HTTP 504. Empty body | QUERY-INCOMPLETE in every case. No row-level states shown (matches `AzureClients.cs:92-104`) |
| F9 | Non-Sentinel output | Declared output `s3` for `c3`, no rows. Separately, `c4` with health rows with `Output = "http"` | `c3`: NOT-SENTINEL-OUTPUT. `c4`: flag a provenance inconsistency (an `http` output does not write to Sentinel, so something else forwarded these rows). Never "no gap" |
| F10 | Local refusal | Seq 1,2,4, with seq 4 reporting `intake.capacityRefusals > 0` | GAP-OBSERVED plus a hint "local refusal possible, check host log 1330". Not attributed to the destination |
| F11 | Single record | Seq 7 only | INSUFFICIENT |
| F12 | Old schema | Rows without `Sequence` | SCHEMA-UNKNOWN. Not dropped silently |
| F13 | Unexpected origin | Seq 1–5 from host `vm-a`, an extra seq 4 copy from `vm-b` | ORIGIN-UNEXPECTED alongside NO-GAP-OBSERVED |
| F14 | Reconciliation masking | Health record for an interval with 100 queued events lost. 100 events lost | Sequence: GAP-OBSERVED. Reconciliation: no shortfall (it reproduces #249). The documented limit holds |
| F15 | Cloned identity | Two runs of `c1` overlapping in time | Flagged. Runs not merged |

### 3.3 Security and privacy of metadata

- Health records are metadata only (`CollectorHealthRecord.cs:15,40`). Collector ids, `Origin.host`, application names and timing still describe infrastructure and activity patterns. Project only the fields in 2.1. Never project `Attributes` wholesale, payload columns or security-event `EventId` lists (the `dcr-errors` precedent, `dcr-errors.kql:4-6`).
- Exports carry the provenance block and the wording "Sentinel query result as of `QueryRunAt`; not delivery proof for events". If an export is ever signed, it must say what it proves. Simulated or fixture output must say `simulated` (AGENTS.md).
- Fixtures use synthetic ids and reserved documentation host names. No real tenant, workspace or host identifiers in the repository.
- Treat every health row as unauthenticated until the blocker in runbook `:1113-1122` is closed. On the AMA syslog path any local account can write rows (`ama-syslog-output.md:209-219`).

### 3.4 Authorised live Sentinel qualification (separate)

Prerequisites: written authorisation for a named, isolated tenant and workspace. The repository Bicep table, DCE and DCR. A separate ingestion identity and a verifier identity with read only, queries run as the verifier in an isolated CLI cache (the existing evidence pattern). Collectors on `ama-syslog` and `azure-logs-ingestion`, with health records at 60 s. No production data.

| # | Scenario | Pass criterion |
|---|---|---|
| L0 | Run fixtures F1–F15 as `datatable` queries in the workspace | Same states as locally (qualifies the KQL on the real engine only) |
| L1 | Clean run, 2 h | NO-GAP-OBSERVED, no false PENDING after lag |
| L2 | Deliberate loss (#249 method: journal emptied with rsyslog stopped) | GAP-OBSERVED for that run. No event-loss count shown |
| L3 | Agent stopped 10 min, then started (`ama-syslog-output.md:177-182`) | PENDING or GAP-OBSERVED, then GAP-RESOLVED on re-run |
| L4 | Collector restart mid-stream | New run. TAIL/HEAD states only. No false gap |
| L5 | Retried batch or duplicate | DUPLICATES-SEEN |
| L6 | Health record refused locally (queue at capacity) | GAP-OBSERVED with the local-refusal hint. Host log 1330 matches |
| L7 | Collector on a non-Sentinel output | NOT-SENTINEL-OUTPUT when declared |
| L8 | Forged health row from another local account, with and without the origin filter | ORIGIN-UNEXPECTED without the filter. Row absent with it |
| L9 | Query at T+lag and at T+lag+1 h | Both results kept with `QueryRunAt`. Change explained |
| L10 | Window large enough to hit service limits | QUERY-INCOMPLETE, never partial states |

Keep the results under `docs/evidence/<run-id>/`, marked live, with query hashes, times and a teardown record. Failure or inaccessible evidence does not pass. Until L1–L10 pass, the runbook labels the workbook "unqualified".

## 4. STOP-conditions assessment

| STOP condition (plan 005) | Assessment |
|---|---|
| Treats local acknowledgement as arrival | **Not hit.** Every state rests on a Sentinel query. Queue state is used only as an explanation. The design also corrects the query comment that implies a gap proves a record was queued (1.1) |
| Assumes complete inventory before plan 001 | **Not hit.** Fleet scope is COVERAGE-UNKNOWN. A list the operator supplies is labelled declared and not verified |
| Needs broad write privileges | **Not hit.** Operators need read only. Option B would add a broad *read* identity, one reason it is deferred |

Revalidate when: the health record schema changes, `sequence` or `collectorStartedAt` semantics change (including any change to when the counter increments), restart behaviour changes, the ingestion delay profile changes, or the queries are wired into alert rules.

## 5. Open questions

1. Should the collector report health records it could not queue (for example a `healthRecordsNotQueued` delta), so a gap can be split into local and downstream? Code change, separate plan.
2. On the `relay` output, which `CollectorId` and `Origin` do relayed health rows carry, and does the sequence describe one hop or the whole path?
3. Do DCR metrics M1–M4 (runbook `:200-203`) cover the AMA syslog DCR, or only Logs Ingestion?
4. Is table-level read on `BowerSecurity_CL` available and adequate in target tenants, or is Log Analytics Reader the floor?
5. Should `/v1/status` accept a read-only token distinct from the ingest token?
6. Should the investigation use the fixed lag (30 min) or one derived per collector? Who owns the value?
7. Should reconciliation be rewritten per run and on one time base, or retired in favour of sequence gaps plus per-event proof?
8. Workbook delivery: a template JSON in the repository, or KQL in the runbook only?
