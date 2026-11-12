# Design 001: Expected collector and source inventory

**Status:** Draft for review. Design only: nothing here is implemented, deployed or validated against Sentinel. · **Date:** 2026-11-12 · **Commit:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [001-expected-inventory.md](001-expected-inventory.md)

## Decision

Adopt **option A, a versioned offline inventory**, as the source of truth for what should exist. It is a tenant-owned, change-controlled JSON file, compiled into Azure Monitor and Sentinel rule parameters and evaluated only in the workspace. It is the only option that is independent of both the collector and the optional management plane, works when management is down, and reuses a mechanism Bower already has (`expectedCollectorIds`, `monitoring.bicep:51-52`, `sentinel-health-rules.bicep:20-21`).

First slice (scoped below): an inventory schema and offline validator, a generator that emits the existing `expectedCollectorIds` and a new `expectedSources` parameter, and one new disabled-by-default rule that reports declared sources as `missing`, `stale` or `unknown`. Management-owned declarations (B) and external inventory integration (C) are deferred. C can later feed the same file format. B can show reconciliation but must not become the source of truth.

The slice resolves neither of the two release blockers it depends on: late arrival (`docs/production-readiness/06-monitoring-and-runbooks.md:1106-1111`) and health-record authenticity (`…:1113-1122`). Until both are validated, a `healthy` result means "a matching row was ingested in time". It does not prove that the source exists or is genuine.

Step 1 drift check: HEAD equals the planned commit, so there is no drift. Every cited path exists (`test -f` for both queries exited 0).

## 1. Current state (evidence)

### 1.1 Identifiers

| Identifier | Origin | Bounds and comparison | Evidence |
|---|---|---|---|
| `CollectorId` (collector) | `BOWER_COLLECTOR_ID` if set; otherwise the machine name, persisted to `collector-id` beside the queue on first start | 1–128 chars, no whitespace or control characters; ordinal | `src/Bower.Collector/CollectorIdentityFile.cs:35,45-93,99-100` |
| `CollectorId` (fallback path in settings) | `BOWER_COLLECTOR_ID` or `Environment.MachineName` | none here | `src/Bower.Collector/CollectorSettings.cs:326` |
| `CollectorId` (Sentinel column) | `collector.id`, set by the collector, never by the producer | truncated to 128 | `src/Bower.Core/SecurityEventProcessor.cs:376-384`, `src/Bower.Dcr/SentinelSchema.cs:70` |
| `ApplicationName` / `ApplicationEnvironment` | event `application.name/environment`, from the producer or a signed pack parser (for example `packs/linux-ssh-gateway/parsers/sshd-json.json:42`) | truncated to 128 and **64** at the destination | `src/Bower.Dcr/SentinelSchema.cs:60-61` |
| Expected source (collector view) | `BOWER_SOURCE_EXPECTATIONS` file on the collector host | 1–1000 entries, unique `(application, environment)`, allowance 1–10080 min; **no length limit** on either string | `schemas/configuration/source-expectations.schema.json:15,21-23`, `src/Bower.Core/SourceExpectations.cs:62-88` |
| Management collector record | `collectors.id` primary key in one SQLite database, bound to a principal object ID | ≤128; conflict when bound to another principal | `src/Bower.Management.Api/ManagementStore.cs:31-44,158-168,1126` |
| Management source report | `collector_sources (collector_id, source_id)` | ≤250 per report, unique IDs | `ManagementStore.cs:45-54,1143-1152` |

Nothing in Bower requires `CollectorId` to be unique across hosts at the destination. Two hosts with the same machine name, or a copied `collector-id` file, would write the same `CollectorId`. Only management enforces one principal per ID (`ManagementStore.cs:164-168`), and management is optional (`PRODUCT.md:26-27`).

A declared environment longer than 64 characters can never match at the destination, because the DCR truncates it (`SentinelSchema.cs:61`) and the expectations schema does not bound it (`source-expectations.schema.json:22`).

### 1.2 What each current signal can and cannot see

| Signal | Provenance | Window | Sees never-seen? | Evidence |
|---|---|---|---|---|
| `collector-health-missing` (A1/S1) | `collector_health` rows the collector sends to Sentinel | rule `absenceWindow` `P2D` (Azure); `queryPeriod` `P1D` (Sentinel); missing after 15 min | **Only** for IDs listed in `expectedCollectorIds` (default `[]`) | `queries/collector-health-missing.kql:5-17`; `monitoring.bicep:48-57,133-136`; `sentinel-health-rules.bicep:18-21,39` |
| `destination-freshness` (A6/S2) | non-health, non-canary, non-replay rows | `absenceWindow`; default allowance 60 min plus overrides | **No.** It summarises rows that exist, and overrides are only joined `leftouter` onto observed keys | `queries/destination-freshness.kql:11-21`; runbook `:1086-1089` |
| `source-overdue` (A5) | collector's own view, newest health record | `healthWindow` `PT30M` | Yes, but only from the collector's own expectations file. Lists at most 25 | `queries/source-overdue.kql:3-13`; `monitoring.bicep:46,169-176`; runbook `:160` |
| `table-no-ingestion` (A9) | any Bower row | event-time `absenceWindow` | Fleet-wide only; unqualified | `queries/table-no-ingestion.kql:1-8`; `monitoring.bicep:31-32,257` |
| Heartbeat v2 and fleet view | collector to management every 60 s | stale after 2 intervals, offline after 15 min | No. Sources are whatever the collector last reported | runbook `:80-81`; `CollectorCommands.cs:144-166`; `Jobs/CollectorStalenessJob.cs:14` |

Current gaps that this design addresses:

- With an empty `expectedCollectorIds`, a collector that never reports is invisible. A missing collector drops out after `P2D` (runbook `:1081-1085`; `monitoring.bicep:48`).
- No destination-side rule knows which sources should exist. The collector-side expectations file depends on the collector running and sending health records (`source-overdue.kql:3-5`). Health records are off unless `BOWER_HEALTH_RECORD_INTERVAL_SECONDS` is set (runbook `:117-118`).
- Management source rows are deleted and replaced from each registration and heartbeat (`ManagementStore.cs:210-216,322,1067-1099`). The heartbeat builds them from the collector's own expectations (`src/Bower.Collector/Jobs/ManagementHeartbeatJob.cs:93-103`). **Heartbeats are self-reports, not independent inventory.**
- Management collector rows are created by the collector's own `register` call (`ManagementStore.cs:181-209`). The nearest administrator-created artefact is an enrolment token that can name a `collector_id` (`ManagementStore.Enrolment.cs:39,78-80,271-272`). Tokens are single use and expire within 168 h (`CollectorEnrolment.cs:36`), so they are not a lasting declaration.
- A never-reporting registered collector is suspended after 30 days (`Jobs/CollectorInactivityJob.cs:19-26`) and then shows as `Paused` (`FleetStatus.cs:171-173`), not as missing. Revoked collectors are left out of the home view (`HomeStatus.cs:103-104`).
- The fleet check returns UNKNOWN for an empty fleet (runbook `:1130-1131`; `fleet/bower-fleet-check.py:70-72`). That is the right shape, but it covers only collectors that management knows about.

### 1.3 Trust boundaries and existing limits (not changed by this design)

- The Azure path is the paging path because it works without management or host access (runbook `:65-68`).
- Health records can be forged by direct DCR writers or a compromised downstream collector or relay key (runbook `:1113-1122`). Any destination row, health or security, has the same weakness for direct DCR writers.
- Late backlog with an old `TimeGenerated` can fall outside the event-time window (runbook `:1106-1111`; `table-no-ingestion.kql:1-3`).
- Health records cap listeners and subscriptions at 25, and coverage flags mark truncation (runbook `:1073-1079`). Per-device syslog silence is not available (runbook `:1059-1062`).
- Management authenticates against one Entra tenant (`ManagementApplication.cs:83-99`) and stores everything in one SQLite file (`ManagementApplication.cs:125-127`). The collectors table has no tenant column (`ManagementStore.cs:31-44`), and neither does `BowerSecurity_CL` (`SentinelSchema.cs:52-80`). Tenant isolation today comes from separate deployments and workspaces, not from data.
- Rules deploy into one workspace (`monitoring.bicep:11-12,260-262`) and are disabled by default (`monitoring.bicep:25-26`).

## 2. Inventory states

Every declared item has exactly one state per evaluation. Only `healthy` is good news, and an empty result is never treated as proof (runbook `:1088-1089`).

| State | Meaning | Alerts? |
|---|---|---|
| `healthy` | A qualifying row for the declared key was ingested within its allowance | No |
| `stale` | Last qualifying row is inside the lookback but older than the allowance | Yes |
| `missing` | Declared and effective, past its first allowance, with no qualifying row in the lookback. This covers both never-seen and aged-out items, and the query cannot tell them apart | Yes |
| `unknown` | Cannot be judged: still pending inside its first allowance; inventory past its review date; or a declaration that is invalid for this workspace. A query that failed, was throttled or returned partial results is also `unknown`, but the rule may not see it (§7) | Yes for inventory expiry; pending does not alert |
| `decommissioning` | Declared as being retired. Rows are still reported, but nothing alerts | No |
| `undeclared` (reconciliation only) | Observed but not declared | Report only, not paged (product owner decision D4) |

A collector's health and its sources are judged separately. A missing collector makes its sources `missing` as well, and runbook R1 then gives the cause (runbook `:578-598`).

## 3. Option comparison

A: versioned offline inventory file in the tenant's own repository, compiled into rule parameters. B: declarations stored and approved in `Bower.Management.Api`, then exported to rules. C: an external system of record (CMDB, cloud resource inventory or a Sentinel watchlist), mapped into the evaluation.

| Dimension | A: offline versioned file | B: management-owned | C: external integration |
|---|---|---|---|
| Owner | Tenant security or platform team that owns monitoring IaC | Bower Administrator or Approver | CMDB or asset owner, outside Bower |
| Source identity and uniqueness | `(workspace, CollectorId)` and `(workspace, CollectorId, ApplicationName, ApplicationEnvironment)`. The validator enforces uniqueness, destination bounds (128/128/64) and flags case-only duplicates | Same keys. Uniqueness via a SQLite key in one deployment; no uniqueness across management deployments | Needs a mapping from asset ID (host name, resource ID) to `CollectorId`. No mapping exists, and machine-name defaults make it fragile (`CollectorIdentityFile.cs:67`) |
| Independent authorisation | Repository review plus the deployer's Azure roles (Monitoring Contributor, Microsoft Sentinel Contributor, runbook `:314-315`). Separate from collector identity and from Bower roles | Bower roles. The same Administrator can revoke a collector (`ManagementApplication.cs:584-591`) and could delete its declaration unless four-eyes applies. A four-eyes pattern exists (`ManagementStore.SourceSetup.cs:188`) | Whatever the external system enforces. Unknown |
| Tenant scope | One file per workspace; the generator refuses a mismatched workspace | One management deployment per Entra tenant (`ManagementApplication.cs:83-87`) | Unknown; depends on the system |
| Approved changes | Pull request plus required reviewer in the tenant's VCS (tenant process; Bower cannot enforce it) | Submit/approve with a reason and a different approver, enforced by the API (pattern `ManagementStore.SourceSetup.cs:24-31,188`) | External change process |
| Audit | VCS history plus Azure deployment history. The deployed rule carries the inventory version and hash in tags or description (proposal) | `management_audit` rows in the same transaction (`ManagementStore.cs:85-93,1154-1188`). This review found no `UPDATE`/`DELETE` on that table in the API | External; Bower sees only the result |
| Bootstrap | Write the file before first deployment. An optional seed from observed rows needs human review (D3) | Declare in the console before enrolment | Import plus mapping |
| Updates | Edit, review, regenerate, redeploy. Latency is the deployment | Immediate in management; reaching rules needs an export or redeploy that does not exist | Depends on sync. A watchlist could avoid redeploys, but that is not used in Bower and is unvalidated |
| Decommissioning | `decommissioning` with an end date, then removed. History stays in VCS | State change with audit; can be tied to revoke | External retirement; Bower may lag |
| Stale inventory | A `reviewBy` date embedded at deploy time makes the rule emit `unknown` after expiry | Same idea is possible; staleness of the export is a separate problem | Sync lag and CMDB accuracy are unknown |
| Lost management | Unaffected: evaluation is fully in Azure | **Declarations unavailable** for re-export. Rules keep their last export, which may be stale | Unaffected by Bower management; affected by the external system's outage |
| Scaling | Bounded by rule query text size (unknown limit, §7). Proposed caps: 1000 sources, matching `source-expectations.schema.json:15` | Bounded by SQLite and export size; same query limit | Large lists likely need a watchlist or table lookup; unvalidated |
| Privacy | Host names and application names in rule text, readable by anyone who can read the rule resource. No personal data; owner as team, not person | In management DB (already holds machine names, `ManagementStore.cs:33`) | Whatever the CMDB exports; may bring in extra personal or asset data |
| Reconciliation with observed data | In KQL: declared minus seen, seen minus declared. Offline report against `/api/fleet` when available | Can join directly to collector records, but those are self-reports | Three-way: CMDB, declared mapping, observed |
| Independence from a missing collector | **Yes** | Partly: declaration independent, but the evaluation path depends on management export | Yes, if the CMDB is authoritative |
| Works offline / air-gapped | Validator and generator are offline. Evaluation needs the workspace | Needs management | Needs connectivity to the external system |
| New dependencies | None for the slice | None | Likely (connector, SDK), which needs `docs/architecture/dependencies.md` justification (`AGENTS.md:92-93`) |

Why A: it is the only option where neither the subject (collector) nor the optional plane (management) holds the declaration. It also matches the documented paging model (runbook `:65-68`). Its weaknesses are a manual update path and the unknown limit on rule query size. Both are bounded and listed below.

## 4. Recommended first slice (option A)

In scope:

1. **Schema** `schemas/configuration/expected-inventory.schema.json`, `apiVersion: bower.security/v1`, `kind: ExpectedInventory`. This is a new, additive schema. It does not change `SentinelSchema.Default`, the DCR or event contracts (`AGENTS.md:83,86-88`). Fields:
   - `workspace` (resource ID or name), `version`, `reviewBy` (date)
   - `collectors[]`: `id`, `state` (`active` | `decommissioning`), `effectiveFrom`, optional `until`, `healthRecordsExpected` (bool)
   - `sources[]`: `collectorId`, `application`, `environment`, `maximumSilenceMinutes`, `state`, `effectiveFrom`, optional `until`
   - No free-form notes in the generated parameters.
2. **Offline validator** (deterministic, no network). It rejects:
   - duplicate keys, and case-only or whitespace-variant duplicates
   - values over 128/128/64 or with whitespace or control characters in `CollectorId`
   - sources whose `collectorId` is not declared
   - an allowance at or above the target lookback minus margin. Sentinel `P1D` and Azure `P2D` differ (`sentinel-health-rules.bicep:18`, `monitoring.bicep:49`). The expectations file allows 10080 min (`source-expectations.schema.json:23`), which neither window can judge
   - a `reviewBy` date in the past
   - more entries than the cap
   - `healthRecordsExpected: false` combined with `expectedCollectorIds`, since such collectors would always be missing (`collector-health-missing.kql:4`)
3. **Generator** that emits `expectedCollectorIds` (existing parameter, unchanged semantics) and a new `expectedSources` array for both Bicep files. It also emits the inventory version and SHA-256 for rule tags. It refuses output for a different `workspace`.
4. **New rule** `expected-source-missing` in `monitoring.bicep` (and an optional Sentinel twin), disabled by default and needing its own opt-in like the other unqualified rules (`monitoring.bicep:28-32,257`). The query:
   - takes the same qualifying-row filter as `destination-freshness.kql:12-16`
   - `union`s declared keys with observed keys
   - emits one row per non-healthy declared key, with `State` in {`missing`, `stale`, `unknown`}, `InventoryVersion`, `LastIngested`, `AllowedMinutes`
   - emits a single `unknown` row with `Reason = inventory-expired` when `now() > reviewBy`
   - leaves out `decommissioning` items and pending items (`now() < effectiveFrom + allowance`).
   Keeping it separate from `destination-freshness` avoids changing a qualified rule's semantics. The cost of a second table scan is accepted for the slice (D6).
5. **Tests**: local fixtures (§6) and a written live qualification procedure modelled on `lab/aws/monitoring/qualify-azure.py`. The live run itself is out of scope.

Out of scope: management UI or storage, CMDB or watchlist integration, per-device syslog granularity, an `undeclared` alert, merging with `destination-freshness`, and any fix for late arrival or health authenticity.

Lifecycle:

- **Declare** in a PR. Rules deploy and the item is `unknown` (pending) until `effectiveFrom + allowance`. After that it is `missing` until rows arrive.
- **Decommission:** set `decommissioning` with `until`. Revoke the collector in management separately (`ManagementApplication.cs:584-591`). After `until`, remove the entry; VCS keeps the history.
- **Reconcile** offline, when management is reachable, by comparing the inventory with `/api/fleet` (Viewer role, `ManagementApplication.cs:326-330`). Report declared-but-revoked, active-but-undeclared and suspended-but-declared. This is a report only. Management state never edits the inventory automatically, which keeps the two independent.

## 5. Decisions needing product owner input

| ID | Decision | Why it matters |
|---|---|---|
| D1 | Confirm option A as the source of truth, with management (B) limited to read-only reconciliation | Sets ownership outside Bower roles. Bower cannot enforce VCS review |
| D2 | Source granularity: `(CollectorId, application, environment)` only, or also per device or listener | Per-device needs a pack field or one listener per device (runbook `:1059-1062`), which would change schemas |
| D3 | Bootstrap: may the first inventory be seeded from observed rows or `/api/fleet`, with mandatory review? | Seeding from observed data carries any existing gap into the inventory. That conflicts with the plan's purpose unless every seeded entry is reviewed |
| D4 | Handling of `undeclared` collectors and sources: page, report or ignore | Paging catches rogue or forgotten collectors but adds noise during rollout |
| D5 | Shared-workspace (MSSP) deployments: refuse, or add a tenant discriminator | No tenant column exists (`SentinelSchema.cs:52-80`). A discriminator would be a schema change (`AGENTS.md:86-88`) |
| D6 | Cost: accept a second scan of `BowerSecurity_CL` every 5 min, or fold into `destination-freshness` after qualification | Cost is unmeasured. Folding changes a rule that already has measurements |
| D7 | Maximum inventory size and the review interval for `reviewBy` | The rule query size limit is unknown. Interval trades staleness against workload |
| D8 | Require explicit `BOWER_COLLECTOR_ID` for any declared collector | Machine-name defaults are not unique across sites (`CollectorIdentityFile.cs:67`) |
| D9 | Privacy classification of host and application names in Azure rule definitions | Rule text is visible to the rule's readers. This may matter for government tenants (`PRODUCT.md:9-11`) |

## 6. Test matrix

Local fixtures are synthetic JSON inventories plus synthetic row sets. They cover the validator, the generator, placeholder substitution, query structure (as in `lab/aws/tests/test_monitoring_stack.py:323-360`) and `az bicep lint` (`deploy/sentinel/monitoring/README.md:19-21`). A local reference evaluator written from the state table in §2 can check the specification against synthetic rows. **No Kusto engine is in the repo**, so local tests cannot prove what the KQL does.

Live validation uses an isolated workspace with explicitly labelled synthetic rows and a read-only verifier identity (`docs/production-readiness/07-soak-and-release-validation.md:151-153`). It rejects partial results (`qualify-azure.py:81-82`) and cleans up (`qualify-azure.py:1-5`). Live validation proves KQL semantics and alert firing for that tenant and build only. It needs a separately authorised tenant (`plans/README.md:13`).

| # | Scenario | Expected | Local fixture proves | Local cannot prove | Live validation proves |
|---|---|---|---|---|---|
| 1 | Never-seen declared collector | `collector-health-missing` row; its sources `missing` after their allowance | Generator emits the ID; reference evaluator gives `missing` | KQL `leftanti` behaviour; alert fires | Row and alert appear (existing harness asserts this for one ID: `qualify-azure.py:91,197-198`; retained evidence for that assertion was not located) |
| 2 | Never-seen declared source on a healthy collector | `missing` after `effectiveFrom + allowance`; `unknown` (pending) before | Pending/missing boundary at the exact minute | Clock skew between deploy time and `now()` | Boundary within one evaluation period |
| 3 | Missing after lookback (last row older than `P2D`/`P1D`) | Still `missing`, not dropped | Evaluator keeps declared keys with no rows | Window filtering on `TimeGenerated` | Declared key stays reported after its rows age out |
| 4 | Stale within lookback | `stale` with `LastIngested` | Allowance arithmetic, overrides | `ingestion_time()` behaviour | Fire and auto-resolve times (A6 took 683–843 s to fire, runbook `:194`) |
| 5 | Decommissioning, then removal | No alert while `decommissioning`; after removal, rows show as `undeclared` | Validator requires `until`; generator leaves item out | Nothing more needed | Rule text update resolves the open alert |
| 6 | Delayed events (old `TimeGenerated`, recent ingestion) | **Known gap**: may be reported `missing`/`stale` falsely | That the gap is documented in output and runbook | Whether it occurs | Size of the false result. Runbook `:1106-1111` stays open |
| 7 | Absent health records (collector not configured or records refused) | Collector `missing`; validator warns if `healthRecordsExpected` is false while listed | Validator rule | Cause on host (R1) | Matches A1 |
| 8 | Truncated health (`monitoringCoverage` false, >25 listeners) | Destination-side source result unaffected (uses security rows); collector-view rules report `coverage-incomplete` (runbook `:1074-1077`) | Fixture with 26 listeners does not change inventory states | n/a | Both rules together |
| 9 | Duplicate IDs in the inventory, including case or whitespace variants | Validator rejects | Fully | n/a | n/a |
| 10 | Duplicate observed `CollectorId` from two hosts | **Not detectable** by this slice. A possible later check: overlapping `collectorStartedAt`/`sequence` series in health records (runbook `:151`) | Nothing | Everything | Whether series overlap is a usable signal (unvalidated) |
| 11 | Cross-tenant: inventory for workspace X deployed to Y | Generator refuses | Fully, for the generator | Manual deploy bypassing the generator | Rule in Y never lists X's IDs |
| 12 | Cross-tenant: another tenant's rows in a shared workspace | Out of scope (D5); a matching `CollectorId` would look `healthy` | Nothing | Everything | n/a until D5 |
| 13 | Management outage | Inventory rules unaffected; offline reconciliation reports UNKNOWN (like `bower-fleet-check.py` exit 3) | Reconciliation handles 3/unreachable as `unknown`, never `healthy` | n/a | Rules fire with management stopped |
| 14 | Inventory past `reviewBy` | One `unknown` row, `inventory-expired` | Generator embeds the date; evaluator output | n/a | Row and alert appear |
| 15 | Partial, throttled or failed query | `unknown`; must not read as "no problems" | Harness rejects partial results (`qualify-azure.py:81-82`) | How Azure Monitor and Sentinel rules treat partial or failed results | **Required**, and currently unknown |
| 16 | Oversized inventory | Validator rejects above the cap | Cap enforcement | Real service limit | Largest list that deploys and evaluates within one period |
| 17 | New workspace or DCR before first rows | All declared items `missing` after their allowance; no query error | n/a | Absent-table behaviour (compare `monitoring.bicep:238-239`) | Behaviour during the 6.5-minute cold start (runbook `:1053`) |
| 18 | Undeclared source or collector appears | Reported by reconciliation, not paged (pending D4) | Set difference in evaluator | KQL output | Row appears in report query |
| 19 | Environment value longer than 64 characters | Validator rejects | Fully | n/a | Confirms truncation (`SentinelSchema.cs:61`) |
| 20 | Forged healthy row from a direct DCR writer | **Known gap**: item looks `healthy` | Documented only | Everything | Not a goal. Runbook `:1113-1122` stays open |

RBAC and operation checks:

- The validator and generator need no credentials and work offline.
- Deploying needs Monitoring Contributor and Microsoft Sentinel Contributor (runbook `:314-315`). Verifying needs Log Analytics Reader only, as an identity separate from ingestion (`07-soak-and-release-validation.md:151-153`).
- Reconciliation needs a Viewer token held only in the environment (runbook `:545-551`).
- No collector or management credential can change the inventory. That has to be proved by review of the deployment pipeline; tests cannot show it.

Query size and cost (all unmeasured):

- Today, `expectedCollectorIds` is inlined into rule text with `string(...)` (`monitoring.bicep:136`). The new parameter would be inlined the same way.
- Scan cost should be similar to `destination-freshness` (same filter and window) and runs every 5 min (`monitoring.bicep:43`). Health records add about 5 KB each (runbook `:144-145`), but the source query filters them out.
- The live run must record query duration, rows scanned and the largest inventory that deploys.

## 7. Unvalidated claims and things not proven

- No part of this design has run. All rule, query and alert behaviour is a proposal.
- How Azure Monitor log alerts and Sentinel scheduled rules handle a failed, throttled or partial query, and whether either reports it, is not established in this repository. An inventory rule that silently fails would look like "all healthy". This must be qualified live before the rule is enabled.
- The maximum rule query length, and therefore the largest inventory that can be inlined, is unknown. The 1000-entry cap is borrowed from `source-expectations.schema.json:15`, not measured.
- Kusto string comparison in `join` is assumed case-sensitive. The validator rejects case-only duplicates regardless, but this should be confirmed live.
- Query cost and evaluation duration are not measured.
- The existing harness asserts that a never-seen expected collector appears (`qualify-azure.py:91,197-198`). This review did not find retained evidence of that assertion passing. The 2026-11-03 smoke records A1 firing for collectors that stopped, not for never-seen ones (`docs/evidence/sentinel-20261103-054834/README.md:56`).
- Late arrivals can still produce false `missing`/`stale` (runbook `:1106-1111`). Not resolved.
- Forged rows from direct DCR writers or compromised relays can still produce false `healthy` (runbook `:1113-1122`). Not resolved.
- Duplicate observed `CollectorId`s from different hosts cannot be detected. The series-overlap idea is untested.
- Cross-tenant isolation in a shared workspace is unresolved (D5).
- VCS review of the inventory is a tenant process that Bower cannot enforce or prove.
- Whether a watchlist (option C) would avoid redeploys and stay within limits is unknown. Bower does not use watchlists today (no references in the repository outside `website/`).

## 8. STOP-condition assessment

| STOP condition (plan) | Triggered? | Basis |
|---|---|---|
| Identity cannot be made unambiguous | **No, for declarations; partially open for observations.** | Declared keys can be made unique and bounded by the validator, matching destination truncation (`SentinelSchema.cs:60-61,70`). Bower cannot stop two hosts emitting the same `CollectorId`. D8 (explicit IDs) reduces the risk; scenario 10 stays unproven. The slice does not depend on solving this, so it does not stop the design |
| An expected source cannot be declared independently | **No** | Option A keeps declarations outside the collector and management, and evaluates them in the workspace. Heartbeat and `BOWER_SOURCE_EXPECTATIONS` data are explicitly not used as inventory (§1.2) |
| Required schema compatibility is unresolved | **No, for the slice** | The slice adds a new configuration schema and a new Bicep parameter only. No change to `SentinelSchema.Default`, the DCR or event contracts (`AGENTS.md:83,86-88`). D2 or D5 would need schema changes and are deferred |
| Validation would need real cloud access | **No, for this design task; yes, for qualification** | This artefact and its local gates need no cloud. Enabling the rule needs live validation in an authorised, isolated tenant (`plans/README.md:13`). That is deferred, not attempted, and listed in §7 |

No STOP condition was hit for this design task. The decisions left open (D1–D9) and the unproven items in §7 must be settled before implementation starts or the rule is enabled.
