# Design 001: Expected collector and source inventory

**Status:** Design for review. Product owner decisions recorded 2026-11-13. Nothing here is implemented, deployed or validated against Sentinel. · **Date:** 2026-11-12, decisions 2026-11-13 · **Commit:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [001-expected-inventory.md](001-expected-inventory.md)

## Decision

**Option B, management-owned declarations, is the source of truth for what should exist** (product owner decision D1, 2026-11-13). This goes against the design's recommendation of option A, a versioned offline file. The option comparison in §3 is kept unchanged, so the reasons A was recommended stay visible.

Management rebuilds its collector and source rows from what collectors report (`ManagementStore.cs:210-216,1067-1099`; `ManagementHeartbeatJob.cs:93-103`). Declarations are therefore stored in their own tables, separate from those observed rows. They are written only through a new approved and audited API (four-eyes, following the source setup pattern), never by registration, heartbeat or enrolment. Management generates the rule parameters from the declarations as a signed export, and the monitoring IaC owner deploys it with the existing Bicep. Evaluation runs in the workspace and never calls management.

First slice (§4): declaration tables and API, a signed export that emits `expectedCollectorIds` in an alias mode and a new `expectedSources` parameter, the original validation rules enforced on submit and on export, opaque aliases in rule text (D9), and one disabled-by-default rule that reports declared sources as `missing`, `stale` or `unknown`. External inventory integration (C) is deferred.

What B loses against A, stated plainly: while the management API is down, declarations cannot be added, changed or exported, so a newly missing collector is detected only if it was in an export deployed beforehand. Deploying the generated parameters keeps detection running in Sentinel during an outage for everything in the last deployed export. That narrows the outage gap but does not close it (§4.1).

The slice resolves neither of the two release blockers it depends on: late arrival (`docs/production-readiness/06-monitoring-and-runbooks.md:1106-1111`) and health-record authenticity (`…:1113-1122`). Until both are validated, a `healthy` result means "a matching row was ingested in time". It does not prove that the source exists or is genuine.

Step 1 drift check: HEAD equals the planned commit, so there is no drift. Every cited path exists (`test -f` for both queries exited 0).

## Decisions (2026-11-13)

All nine items in §5 are decided. "Against" marks a choice that differs from this design's recommendation.

| ID | Question | Choice | Consequence |
|---|---|---|---|
| D1 | Source of truth for the expected list | **Against:** option B, the console (management API) owns the list | Declarations get separate tables, an approved and audited API, and a signed export deployed by the IaC owner (§4). Declarations cannot change during a management outage (§4.1). The management database backup becomes load-bearing |
| D2 | Source granularity | Collector + application + environment. No per-device tracking | No schema change. Per-device silence stays unavailable (runbook `:1059-1062`) |
| D3 | Bootstrap from observed data | Allowed. A person reviews every entry | Seeding creates one pending request per entry. There is no bulk approval (§4 item 4) |
| D4 | Undeclared collectors and sources | Reported, not paged | Reconciliation report only. No alert rule for `undeclared` |
| D5 | Shared (MSSP) workspaces | Not supported for now. Refused | One management deployment binds to one workspace. Bower cannot detect two deployments writing to the same workspace (§7) |
| D6 | Cost of a second scan | A separate rule, off by default. Measure its cost first | `expected-source-missing` stays separate from `destination-freshness`. Cost measurement is a gate before enabling |
| D7 | Size cap and review interval | 200 entries, reviewed every 90 days. Raise the cap after measuring | The API and export refuse more than 200 entries per workspace (collectors and sources together). `reviewBy` is at most 90 days after export |
| D8 | Explicit collector ids | `BOWER_COLLECTOR_ID` is required for every declared collector | A deployment requirement. Bower cannot enforce it yet, because the collector logs its id source but reports it nowhere else (§7) |
| D9 | Real names in rule definitions | Rules use opaque aliases. The mapping to real names stays in the inventory | Rule text carries aliases and salted match tokens (§4 item 6). The mapping lives in the management store and in a restricted mapping file with each export. `collector-health-missing` needs an additive alias mode |

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
| Tenant scope | One file per workspace resource ID; the generator refuses a mismatched target | One management deployment per Entra tenant (`ManagementApplication.cs:83-87`) | Unknown; depends on the system |
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

Why A (original recommendation): it is the only option where neither the subject (collector) nor the optional plane (management) holds the declaration. It also matches the documented paging model (runbook `:65-68`). Its weaknesses are a manual update path and the unknown limit on rule query size. Both are bounded and listed below.

Product owner decision (D1, 2026-11-13): option B. The comparison above is unchanged. The B column's weak rows (lost management, works offline, independence from a missing collector) are what §4 has to address. §4.1 states what remains.

## 4. First slice (option B, management-owned declarations)

In scope:

1. **Declaration storage, separate from observed rows.** New tables in the management SQLite database: `inventory_collectors`, `inventory_sources`, `inventory_requests` and `inventory_exports`. They have no foreign key to `collectors`, so the `ON DELETE CASCADE` rules on observed tables (`ManagementStore.cs:53,63,73`) and the delete-and-replace of source rows on every registration and heartbeat (`ManagementStore.cs:210-216,1067-1099`) cannot reach them. The table change is an additive management schema migration. It does not change `SentinelSchema.Default`, the DCR or event contracts (`AGENTS.md:83,86-88`). Fields:
   - per deployment: `workspace` (full Log Analytics workspace resource ID from configuration; a bare name is refused), `version` (increments on every approved change), `reviewBy` (date)
   - collectors: `id`, `alias`, `state` (`active` | `decommissioning`), `effectiveFrom`, optional `until`, `healthRecordsExpected` (bool), `explicitIdConfirmed` (bool, D8)
   - sources: `collectorId`, `application`, `environment`, `alias`, `maximumSilenceMinutes`, `state`, `effectiveFrom`, optional `until`
   - aliases are opaque, generated by management (for example `c-<8 random hex>` and `s-<8 random hex>`), unique per deployment and never reused (D9).
2. **Approved, audited write path only.** A new API: submit a declare, change, decommission or remove request (Operator or Administrator, with a reason), then approve or reject it (Approver or Administrator). The approver must differ from the requester, and a self-approval attempt is refused and audited, following `ManagementStore.SourceSetup.cs:24-31,180-195`. Each request and decision writes its `management_audit` row in the same transaction. The `Collector` role and the `EnrolledCollector` policy (`ManagementApplication.cs:118-122`) are refused on every inventory route. Registration, heartbeat, enrolment and the background jobs never write these tables. A deployment with only one person holding Approver or Administrator cannot approve anything, which is intended.
3. **Validation on submit, again on approval and again on export** (deterministic, no network). Pending requests reserve no capacity and no keys. Approval re-runs every check below against the declarations as they stand in the approval's own transaction. If the change would now break a check (for example a 201st entry, or a key another approved request has since taken), the approval is refused and audited, and the request stays pending until it is rejected or replaced by a new request. Export therefore never meets an approved inventory that breaks a check. Validation refuses:
   - a deployment `workspace` that is not a full workspace resource ID
   - duplicate keys, and case-only or whitespace-variant duplicates
   - values over 128/128/64 or with whitespace or control characters in `CollectorId`
   - sources whose `collectorId` is not declared
   - an allowance at or above the target lookback minus margin. Sentinel `P1D` and Azure `P2D` differ (`sentinel-health-rules.bicep:18`, `monitoring.bicep:49`). The expectations file allows 10080 min (`source-expectations.schema.json:23`), which neither window can judge
   - a `reviewBy` in the past or more than 90 days ahead (D7)
   - more than 200 entries per workspace, collectors and sources together (D7)
   - a collector declared without `explicitIdConfirmed` (D8)
   - `healthRecordsExpected: false` combined with listing in `expectedCollectorIds`, since such collectors would always be missing (`collector-health-missing.kql:4`)
4. **Bootstrap from observed data** (D3). A seed action reads observed collectors and reported sources (the data behind `/api/fleet`) and creates **one pending request per entry**, marked `origin: observed-seed`. There is no bulk approval: an approver reviews and decides each request. Seeding never writes a declaration directly.
5. **Signed export, deployed by the IaC owner.** Management generates the rule parameters from the declarations:
   - `expectedCollectorIds` in alias mode and a new `expectedSources` array for both Bicep files, plus `inventoryVersion`, `inventorySha256`, `reviewBy`, `workspaceResourceId` (the declared full workspace resource ID) and the per-export alias salt, for rule tags and query text
   - a separate restricted mapping file (alias to real name). It is never deployed to Azure
   - a signature over the parameters file, with a new optional signing key like the existing management signers (`ManagementApplication.cs:129-137`). Without a key, export answers 503
   - the export takes the target subscription, resource group and workspace name, and refuses unless the full resource ID equals the declared `workspace`, compared case-insensitively. Both Bicep files take only `workspaceName` (`monitoring.bicep:12,117`, `sentinel-health-rules.bicep:9,34`), and a name can repeat across subscriptions and resource groups
   - `effectiveFrom` handling: the existing query treats every listed ID as expected at once (`collector-health-missing.kql:6-8,13`). The export lists a collector only when it is `active` and its `effectiveFrom` is at or before export time, and reports any other as pending activation. The IaC owner must export and redeploy after that time. Set `effectiveFrom` no earlier than the time the collector starts sending health records.
   The IaC owner verifies the signature and target (a CLI step). The CLI takes the same subscription, resource group and workspace name as the deployment command, builds the full workspace resource ID from them and refuses unless it equals the signed `workspaceResourceId`, compared case-insensitively. This needs no Azure credentials. The IaC owner then keeps the signed export and mapping file in the tenant's IaC repository, and deploys with the existing Bicep (Monitoring Contributor and Microsoft Sentinel Contributor, runbook `:314-315`). Management never deploys. Evaluation reads only the deployed rule text.
6. **Opaque aliases in rules** (D9). Rule text and alert rows carry aliases, never real names. The query matches observed rows by a salted token computed after `summarize` (for example `hash_sha256(strcat(salt, CollectorId))`), so it hashes distinct keys only. `collector-health-missing` gets an additive alias mode: the expected list holds aliases and tokens, and the alert dimension becomes the alias. In alias mode it also emits a single `unknown` row with `Alias = inventory` and `Reason = inventory-expired` when `now() > reviewBy`, so expiry alerts without the optional `expected-source-missing` rule. That row needs no table scan. With alias mode off the query is unchanged. The salt sits in the rule text, so a reader who can read the rule and guess a name can still test that guess. Aliases keep names out of casual view; they do not make names secret.
7. **New rule** `expected-source-missing` in `monitoring.bicep` (and an optional Sentinel twin), disabled by default and needing its own opt-in like the other unqualified rules (`monitoring.bicep:28-32,257`). The query:
   - takes the same qualifying-row filter as `destination-freshness.kql:12-16`
   - `union`s declared keys with observed keys
   - emits one row per non-healthy declared key, with `Alias`, `State` in {`missing`, `stale`, `unknown`}, `InventoryVersion`, `LastIngested`, `AllowedMinutes`
   - emits a single `unknown` row with `Reason = inventory-expired` when `now() > reviewBy`, as the alias mode of `collector-health-missing` does (item 6)
   - leaves out `decommissioning` items and pending items (`now() < effectiveFrom + allowance`).
   It stays separate from `destination-freshness`, so a qualified rule's semantics do not change (D6). Its cost must be measured in the live qualification before it is enabled.
8. **Tests**: local fixtures and API tests (§6) and a written live qualification procedure modelled on `lab/aws/monitoring/qualify-azure.py`. The live run itself is out of scope.

Out of scope: console UI beyond the request and decision screens the API needs, CMDB or watchlist integration, per-device syslog granularity (D2), an `undeclared` alert (D4), merging with `destination-freshness` (D6), shared workspaces (D5), import of a signed export back into management, and any fix for late arrival or health authenticity.

Lifecycle:

- **Declare** through a request and a second person's approval. The item reaches the rules only at the next export and deploy. After deploy it is `unknown` (pending) until `effectiveFrom + allowance`, then `missing` until rows arrive. A collector with a future `effectiveFrom` joins `expectedCollectorIds` only at the export and deploy after that time (§4 item 5).
- **Decommission:** a request sets `decommissioning` with `until`. Revoking the collector (`ManagementApplication.cs:584-591`) does not change its declaration; the console offers the decommission request beside the revoke action. After `until`, a remove request deletes the declaration. The audit rows keep the history.
- **Reconcile** in management, by comparing declarations with observed collector records. Report declared-but-revoked, active-but-undeclared, suspended-but-declared, approved-but-not-exported and declared collectors whose observed id equals their reported machine name (a heuristic hint for D8; default ids are machine names, `CollectorIdentityFile.cs:67`). This is a report only, never paged (D4). Observed state never edits declarations.

### 4.1 Management outage and loss

| Situation | Detection in Sentinel | Declarations |
|---|---|---|
| Management down, export deployed | **Continues** for every item in the last deployed export: the rules read only their own text | Cannot be added, changed, approved or exported until management returns |
| Change approved but not yet deployed | Not covered until the IaC owner deploys the next export. This lag exists even when management is up | Held in management |
| Management down past `reviewBy` | `collector-health-missing` in alias mode and `expected-source-missing` each emit `inventory-expired` (`unknown`), which alerts. At least one of them must be enabled; with neither enabled, expiry does not alert | No new export can be made |
| Management database lost | Unaffected while the deployed export is current | Lost unless backed up. The signed export and mapping file in the IaC repository are a record, but there is no import path in the slice |

Does deploying generated parameters remove the outage gap? **Partly.** It removes the gap for every collector and source in the last deployed export: they are still reported `missing` or `stale` with management down. It does not remove it for anything declared, changed or due to activate after that export, which option A could still deploy during an outage. The approval-to-deploy lag is a second, smaller version of the same gap that exists whenever exports are not deployed promptly.

## 5. Decisions needing product owner input

All items below are decided. See [Decisions (2026-11-13)](#decisions-2026-11-13). The original questions are kept for the record.

| ID | Decision | Why it matters | Status |
|---|---|---|---|
| D1 | Confirm option A as the source of truth, with management (B) limited to read-only reconciliation | Sets ownership outside Bower roles. Bower cannot enforce VCS review | Decided: against, option B |
| D2 | Source granularity: `(CollectorId, application, environment)` only, or also per device or listener | Per-device needs a pack field or one listener per device (runbook `:1059-1062`), which would change schemas | Decided |
| D3 | Bootstrap: may the first inventory be seeded from observed rows or `/api/fleet`, with mandatory review? | Seeding from observed data carries any existing gap into the inventory. That conflicts with the plan's purpose unless every seeded entry is reviewed | Decided |
| D4 | Handling of `undeclared` collectors and sources: page, report or ignore | Paging catches rogue or forgotten collectors but adds noise during rollout | Decided |
| D5 | Shared-workspace (MSSP) deployments: refuse, or add a tenant discriminator | No tenant column exists (`SentinelSchema.cs:52-80`). A discriminator would be a schema change (`AGENTS.md:86-88`) | Decided |
| D6 | Cost: accept a second scan of `BowerSecurity_CL` every 5 min, or fold into `destination-freshness` after qualification | Cost is unmeasured. Folding changes a rule that already has measurements | Decided |
| D7 | Maximum inventory size and the review interval for `reviewBy` | The rule query size limit is unknown. Interval trades staleness against workload | Decided |
| D8 | Require explicit `BOWER_COLLECTOR_ID` for any declared collector | Machine-name defaults are not unique across sites (`CollectorIdentityFile.cs:67`) | Decided |
| D9 | Privacy classification of host and application names in Azure rule definitions | Rule text is visible to the rule's readers. This may matter for government tenants (`PRODUCT.md:9-11`) | Decided |

## 6. Test matrix

Local fixtures are synthetic declarations, created through the management API in tests (pattern `tests/Bower.UnitTests/SourceSetupApiTests.cs`), plus synthetic row sets. They cover the API and its authorisation, validation, the export, placeholder substitution, query structure (as in `lab/aws/tests/test_monitoring_stack.py:323-360`) and `az bicep lint` (`deploy/sentinel/monitoring/README.md:19-21`). A local reference evaluator written from the state table in §2 can check the specification against synthetic rows. **No Kusto engine is in the repo**, so local tests cannot prove what the KQL does.

Live validation uses an isolated workspace with explicitly labelled synthetic rows and a read-only verifier identity (`docs/production-readiness/07-soak-and-release-validation.md:151-153`). It rejects partial results (`qualify-azure.py:81-82`) and cleans up (`qualify-azure.py:1-5`). Live validation proves KQL semantics and alert firing for that tenant and build only. It needs a separately authorised tenant (`plans/README.md:13`).

| # | Scenario | Expected | Local fixture proves | Local cannot prove | Live validation proves |
|---|---|---|---|---|---|
| 1 | Never-seen declared collector | `collector-health-missing` row (by alias); its sources `missing` after their allowance | Export emits the alias and token; reference evaluator gives `missing` | KQL `leftanti` behaviour; alert fires | Row and alert appear (existing harness asserts this for one ID: `qualify-azure.py:91,197-198`; retained evidence for that assertion was not located) |
| 2 | Never-seen declared source on a healthy collector | `missing` after `effectiveFrom + allowance`; `unknown` (pending) before | Pending/missing boundary at the exact minute | Clock skew between deploy time and `now()` | Boundary within one evaluation period |
| 3 | Missing after lookback (last row older than `P2D`/`P1D`) | Still `missing`, not dropped | Evaluator keeps declared keys with no rows | Window filtering on `TimeGenerated` | Declared key stays reported after its rows age out |
| 4 | Stale within lookback | `stale` with `LastIngested` | Allowance arithmetic, overrides | `ingestion_time()` behaviour | Fire and auto-resolve times (A6 took 683–843 s to fire, runbook `:194`) |
| 5 | Decommissioning, then removal | No alert while `decommissioning`; after removal, rows show as `undeclared` | Validation requires `until`; export leaves item out | Nothing more needed | Rule text update resolves the open alert |
| 6 | Delayed events (old `TimeGenerated`, recent ingestion) | **Known gap**: may be reported `missing`/`stale` falsely | That the gap is documented in output and runbook | Whether it occurs | Size of the false result. Runbook `:1106-1111` stays open |
| 7 | Absent health records (collector not configured or records refused) | Collector `missing`; validation refuses `healthRecordsExpected` false while listed | Validation rule | Cause on host (R1) | Matches A1 |
| 8 | Truncated health (`monitoringCoverage` false, >25 listeners) | Destination-side source result unaffected (uses security rows); collector-view rules report `coverage-incomplete` (runbook `:1074-1077`) | Fixture with 26 listeners does not change inventory states | n/a | Both rules together |
| 9 | Duplicate IDs in the inventory, including case or whitespace variants | Submit and export refuse | Fully | n/a | n/a |
| 10 | Duplicate observed `CollectorId` from two hosts | **Not detectable** by this slice. A possible later check: overlapping `collectorStartedAt`/`sequence` series in health records (runbook `:151`) | Nothing | Everything | Whether series overlap is a usable signal (unvalidated) |
| 11 | Cross-tenant: inventory for workspace X deployed to Y, including a Y with the same name in another subscription or resource group | Export refuses; a bare name is refused; the deploy-side CLI check refuses when the resource ID built from the deployment's subscription, resource group and name differs from the signed `workspaceResourceId` | Fully, for the export and the CLI check | Manual deploy bypassing the export and check | Rule in Y never lists X's IDs |
| 12 | Cross-tenant: another tenant's rows in a shared workspace | Not supported (D5). The deployment refuses a second workspace binding, but Bower cannot see another deployment writing to the same workspace; a matching `CollectorId` would look `healthy` | The binding refusal | Detection of a second writer | n/a |
| 13 | Management outage | Rules from the last deployed export unaffected. Declarations cannot change. A collector declared after that export is not detected (§4.1). Reconciliation reports UNKNOWN (like `bower-fleet-check.py` exit 3) | Reconciliation handles 3/unreachable as `unknown`, never `healthy`; export refuses while the store is unavailable | n/a | Rules fire with management stopped; a collector approved but not exported produces no row |
| 14 | Inventory past `reviewBy` | One `unknown` row, `inventory-expired`, from each enabled rule; with only `collector-health-missing` (alias mode) enabled, its row still appears | Export embeds the date and refuses more than 90 days; evaluator output; query structure has the expiry row in both rules | n/a | Row and alert appear, including with `expected-source-missing` disabled |
| 15 | Partial, throttled or failed query | `unknown`; must not read as "no problems" | Harness rejects partial results (`qualify-azure.py:81-82`) | How Azure Monitor and Sentinel rules treat partial or failed results | **Required**, and currently unknown |
| 16 | Oversized inventory | Submit, approval and export refuse above 200 entries (D7) | Cap enforcement | Real service limit | Largest list that deploys and evaluates within one period, as evidence for raising the cap |
| 17 | New workspace or DCR before first rows | All declared items `missing` after their allowance; no query error | n/a | Absent-table behaviour (compare `monitoring.bicep:238-239`) | Behaviour during the 6.5-minute cold start (runbook `:1053`) |
| 18 | Undeclared source or collector appears | Reported by reconciliation, not paged (D4) | Set difference in evaluator | KQL output | Row appears in report query |
| 19 | Environment value longer than 64 characters | Submit refuses | Fully | n/a | Confirms truncation (`SentinelSchema.cs:61`) |
| 20 | Forged healthy row from a direct DCR writer | **Known gap**: item looks `healthy` | Documented only | Everything | Not a goal. Runbook `:1113-1122` stays open |
| 21 | Declared collector with a future `effectiveFrom` | Left out of `expectedCollectorIds` and reported as pending activation; listed after an export and redeploy past `effectiveFrom` | Export output either side of `effectiveFrom` | Whether the owner redeploys on time | No `collector-health-missing` row before activation; row appears after the redeploy if the collector stays silent |
| 22 | Heartbeat or registration from a collector, including one reporting new or fewer sources | Declarations unchanged; only observed rows change | API test: declaration rows and audit identical before and after; inventory routes refuse the `Collector` role | n/a | n/a |
| 23 | Self-approval, or approval by a role without Approver or Administrator | Refused and audited | Fully (pattern `ManagementStore.SourceSetup.cs:180-195`) | n/a | n/a |
| 24 | Seed from observed data | One pending request per entry, `origin: observed-seed`; nothing declared until each is approved | Fully | Reviewer diligence | n/a |
| 25 | Collector revoked or deleted in management | Declaration unchanged (no cascade); reconciliation reports declared-but-revoked | Fully | n/a | n/a |
| 26 | Tampered or retargeted export | Signature check fails, or target mismatch refuses | Fully | Deploys that skip the check | n/a |
| 27 | Alias rows | Alert rows and rule text carry aliases only; no declared name appears in the deployed parameters | Text search of exported parameters for every declared name | n/a | Alert payload holds the alias only |
| 28 | Declared collector without explicit id | Submit refuses without `explicitIdConfirmed`; reconciliation hints when the observed id equals the machine name | Fully | Whether the host really sets `BOWER_COLLECTOR_ID` | n/a |
| 29 | Two pending requests that each pass submit, at 199 entries or for the same key | The first approval succeeds; the second is refused and audited and stays pending until rejected or replaced | Fully, including approvals in parallel transactions | n/a | n/a |

RBAC and operation checks:

- Declaring needs Operator or Administrator; approving needs a different Approver or Administrator; exporting needs Administrator. The `Collector` role has no inventory route.
- Validation and the deploy-side signature check need no Azure credentials. The export needs management to be reachable.
- Deploying needs Monitoring Contributor and Microsoft Sentinel Contributor (runbook `:314-315`). Verifying needs Log Analytics Reader only, as an identity separate from ingestion (`07-soak-and-release-validation.md:151-153`).
- Reconciliation needs a Viewer token held only in the environment (runbook `:545-551`).
- No collector credential can change declarations (test 22). Only an approved export deployed by the IaC owner reaches the rules. That the IaC owner deploys only signed, checked exports is a tenant process that tests cannot show.

Query size and cost (all unmeasured):

- Today, `expectedCollectorIds` is inlined into rule text with `string(...)` (`monitoring.bicep:136`). The new parameter would be inlined the same way.
- Scan cost should be similar to `destination-freshness` (same filter and window) and runs every 5 min (`monitoring.bicep:43`). Health records add about 5 KB each (runbook `:144-145`), but the source query filters them out.
- The live run must record query duration, rows scanned and the largest inventory that deploys. Under D6 this measurement is a gate: the rule is not enabled until its cost is measured. Under D7 the cap rises above 200 only after this measurement.
- Salted tokens are computed after `summarize`, on distinct keys only. Their extra cost is unmeasured.

## 7. Unvalidated claims and things not proven

- No part of this design has run. All rule, query and alert behaviour is a proposal.
- How Azure Monitor log alerts and Sentinel scheduled rules handle a failed, throttled or partial query, and whether either reports it, is not established in this repository. An inventory rule that silently fails would look like "all healthy". This must be qualified live before the rule is enabled.
- The maximum rule query length, and therefore the largest inventory that can be inlined, is unknown. The 200-entry cap (D7) is a decision, not a measurement.
- Kusto string comparison in `join` is assumed case-sensitive. Validation refuses case-only duplicates regardless, but this should be confirmed live.
- Query cost and evaluation duration are not measured.
- The existing harness asserts that a never-seen expected collector appears (`qualify-azure.py:91,197-198`). This review did not find retained evidence of that assertion passing. The 2026-11-03 smoke records A1 firing for collectors that stopped, not for never-seen ones (`docs/evidence/sentinel-20261103-054834/README.md:56`).
- Late arrivals can still produce false `missing`/`stale` (runbook `:1106-1111`). Not resolved.
- Forged rows from direct DCR writers or compromised relays can still produce false `healthy` (runbook `:1113-1122`). Not resolved.
- Duplicate observed `CollectorId`s from different hosts cannot be detected. The series-overlap idea is untested.
- Shared workspaces are refused (D5), but Bower cannot detect two management deployments, or another tenant's collectors, writing to one workspace.
- Four-eyes approval is enforced by the API, but it is only as independent as the people holding Approver and Administrator. Bower roles sit in the same Entra tenant as the collectors' management identities (`ManagementApplication.cs:83-99`).
- During a management outage, declarations cannot change and newly declared collectors cannot be detected (§4.1). Deploying exports narrows this gap but does not close it.
- The management database becomes the only full record of declarations. Its backup and restore are not designed here, and the slice has no import from a signed export.
- Deployment of each export is a manual step for the IaC owner. Nothing in the slice proves that the deployed rule matches the latest approved version, beyond the `inventoryVersion` and `inventorySha256` tags.
- D8 cannot be enforced by Bower: the collector logs whether its id was configured (`StartupLog.cs:12`) but does not report it. `explicitIdConfirmed` is an operator attestation.
- Aliases do not make names secret. The per-export salt is in the rule text, so a reader can test a guessed name (D9).
- The export and redeploy at a collector's `effectiveFrom` is a manual step for the IaC owner. Nothing in the slice enforces it. If it is missed, `collector-health-missing` does not cover that collector until the next redeploy.
- Whether a watchlist (option C) would avoid redeploys and stay within limits is unknown. Bower does not use watchlists today (no references in the repository outside `website/`).

## 8. STOP-condition assessment

| STOP condition (plan) | Triggered? | Basis |
|---|---|---|
| Identity cannot be made unambiguous | **No, for declarations; partially open for observations.** | Declared keys can be made unique and bounded by validation on submit and export, matching destination truncation (`SentinelSchema.cs:60-61,70`). Bower cannot stop two hosts emitting the same `CollectorId`. D8 (explicit IDs, now required) reduces the risk but is an attestation; scenario 10 stays unproven. The slice does not depend on solving this, so it does not stop the design |
| An expected source cannot be declared independently | **Re-checked for option B (2026-11-13): not hit, with conditions.** | Independence from the collector holds: declarations live in separate tables with no foreign key to observed rows, are written only by approved, audited requests, and no collector role, registration, heartbeat, enrolment or background job can write them (§4 items 1–2; tests 22, 23, 25). Heartbeat and `BOWER_SOURCE_EXPECTATIONS` data are still not used as inventory, and seeded entries need individual approval (D3). Evaluation stays in the workspace and reads only the deployed export. Independence from management is weaker than under A: management holds the only full record, and nothing declared after the last deployed export can be evaluated during an outage (§4.1). That is an availability limit, not a loss of independence from the collector, so the condition is not hit. It becomes a STOP if implementation needs any collector-writable path into the declaration tables, or a cascade from `collectors` |
| Required schema compatibility is unresolved | **No, for the slice** | The slice adds management tables (additive migration), a new Bicep parameter and an additive alias mode for `collector-health-missing`. No change to `SentinelSchema.Default`, the DCR or event contracts (`AGENTS.md:83,86-88`). D2 and D5 were decided in ways that need no schema change |
| Validation would need real cloud access | **No, for this design task; yes, for qualification** | This artefact and its local gates need no cloud. Enabling the rule needs live validation in an authorised, isolated tenant (`plans/README.md:13`). That is deferred, not attempted, and listed in §7 |

No STOP condition was hit for this design task, including after the D1 change to option B. D1–D9 are decided (see [Decisions (2026-11-13)](#decisions-2026-11-13)). The unproven items in §7 must be settled before the rule is enabled.
