# Replay-safe Sentinel queries and scheduled alerts

**Status: not qualified.** A real Microsoft Sentinel test on 31 October 2026
found duplicate alert keys after missed evaluations. The current rules contain
an unverified mitigation; see [How we tested this](#how-we-tested-this). Keep
these rules disabled until the current content is independently validated. The
archive-replay origin labels are producer-controlled and must not be used as an
identity. The current function uses the stamped collector identity; cross-collector
archive replay remains an open deduplication gap. Restrict direct DCR ingestion
permissions to approved collectors: a direct writer can forge `CollectorId`.
This permission check alone does not bind an ingestion identity to a particular
collector ID; a compromised approved writer can impersonate another collector.
The revised query has not been validated against a live workspace. Bower
releases and packages are still **unsigned**; this guide does not change that.

Bower delivers to Microsoft Sentinel **at least once**. It never deletes an event
from its durable queue before the Logs Ingestion API acknowledges it. When an
acknowledgement is lost, Bower uploads the event again, and `BowerSecurity_CL` then
holds two rows for one event. In the native pilot, all 59,400 Windows events arrived,
plus [four replayed rows](../evidence/pilot-native-20261030/windows-duplicate-proof.json).

You need queries and analytics rules that:

1. count each event once, however many rows it has; and
2. evaluate events that arrive late (for example an hour late after a destination
   outage), while limiting repeated alerts when a replayed copy arrives.

This guide ships and explains that content:

| File | What it is |
| --- | --- |
| [`bower-security-events.kql`](../../deploy/sentinel/analytics/bower-security-events.kql) | `BowerSecurityEvents` workspace function: one row per `(CollectorId, EventId)` |
| [`rules/wec-brute-force.kql`](../../deploy/sentinel/analytics/rules/wec-brute-force.kql) | Windows 4625 failed network logons from one address (WEF/WEC and the `windows-security-logon` pack) |
| [`rules/firewall-deny.kql`](../../deploy/sentinel/analytics/rules/firewall-deny.kql) | Repeated firewall denials from one address (syslog over mutual TLS) |
| [`rules/beyond-tolerance.kql`](../../deploy/sentinel/analytics/rules/beyond-tolerance.kql) | Informational monitor: events later than the rules evaluate |
| [`main.bicep`](../../deploy/sentinel/analytics/main.bicep) | Deploys the function and the three scheduled rules (disabled by default) |
| [`validation/`](../../deploy/sentinel/analytics/validation/fault_proxy.py) | The fault-injection proxy, event driver and verifier used for the test procedure |

Nothing here changes `BowerSecurity_CL`, the DCR, the stream or `SentinelSchema.Default`.

## Contents

1. [Why replayed rows happen](#1-why-replayed-rows-happen)
2. [How the replay-safe pattern works](#2-how-the-replay-safe-pattern-works)
3. [Choosing frequency, look-back and tolerated delay](#3-choosing-frequency-look-back-and-tolerated-delay)
4. [Deploy the parser and rules](#4-deploy-the-parser-and-rules)
5. [Convert an existing rule to the replay-safe pattern](#5-convert-an-existing-rule-to-the-replay-safe-pattern)
6. [Hunting, workbooks and exports](#6-hunting-workbooks-and-exports)
7. [Why `dcount()` cannot be used for exact counts](#7-why-dcount-cannot-be-used-for-exact-counts)
8. [Keep `CollectorId` stable in every environment](#8-keep-collectorid-stable-in-every-environment)
9. [Validate in your own workspace](#9-validate-in-your-own-workspace)
10. [Troubleshooting](#10-troubleshooting)
11. [Known limits](#11-known-limits)
12. [How we tested this](#how-we-tested-this)

## 1. Why replayed rows happen

### What happened in the pilot

The Windows WEC collector in the [native pilot](../evidence/pilot-native-20261030/README.md)
used `BOWER_DELIVERY_LEASE_SECONDS=90` and `BOWER_DELIVERY_TIMEOUT_SECONDS=60`. The
monitor script started the one-hour outage at `09:28:00 + 658 s = 09:38:58 UTC` by adding
an outbound Windows Firewall rule for `Bower.Collector.exe` on TCP 443.

| Time (UTC) | Observation | Source |
| --- | --- | --- |
| 09:38:23.88–.91 | Four 4625 events generated on the source host | `sourceTimes` |
| 09:38:58 | Outbound firewall block added | `pilot-wec-monitor.ps1` (`$blockAt`) |
| 09:39:02.96 | All four rows ingested by Azure, in one request (one shared `ingestion_time()`) | `ingestionTimes[0]` |
| 10:39:05 | Firewall rule removed (3,606.15 s outage) | `windows-monitor.json` |
| 10:39:25.24 | The same four events ingested again, in the first drain upload | `ingestionTimes[1]` |

The upload carrying those four events reached the data collection endpoint around the
moment the block was added. Azure accepted and stored it, but the firewall stopped the
HTTP response from reaching the collector. To Bower this looks the same as a request
that never arrived. The 60-second delivery deadline cancelled the request, the events
were settled as retryable (`destination-output-timeout`), the destination circuit held
them through the outage, and the first upload after restoration sent them again.

This is an **ambiguous acknowledgement**. It is not a lease problem:

- The lease (90 s) cannot expire during an upload. `QueueDeliveryOptions.Validate`
  requires the delivery deadline to end at least 30 s before the lease, the worker
  awaits cancelled uploads cooperatively and settles them with the host token, and the
  collector runs one sequential delivery loop. No second worker can take the same events.
- Lease fencing (`lease_generation`) rejects settlement by a stale lease.
- Batches are split only by size (1 MiB). An HTTP 400 is bisected, but Azure rejects a
  whole request on 400, so a resent half cannot duplicate stored rows.
- Partial outcomes are kept: if an earlier owned batch succeeded before a later one was
  cancelled, its acknowledgements are committed, not replayed.

### What Bower cannot remove

The Logs Ingestion API has no idempotency key and no "already received" check. Bower
cannot tell "stored, response lost" from "never arrived". The only ways to avoid the
retry would be to delete events whose outcome is unknown (losing data, against the
**never delete before acknowledgement** invariant) or to query the workspace before each
retry (which needs read access for the ingestion identity, breaking least privilege, and
still races with ingestion latency). Neither is acceptable. Replays are therefore an
expected, bounded property of at-least-once delivery, triggered by:

| Trigger | Typical copies | Typical gap between copies |
| --- | --- | --- |
| Response lost, then the network recovers (deadline 60 s, destination circuit 30 s) | 2 | about 90 seconds |
| Collector killed or host rebooted after Azure accepted the upload, before Bower committed the acknowledgement | 2 | lease remaining after restart (up to 90 s with the qualification profile, 300 s by default) |
| Response lost at the start of a destination outage | 2 | the outage length (one hour in the pilot) |
| Azure.Core transport retry after a connection reset mid-response (inside one delivery) | 2 | seconds |
| Delivered row purged by queue retention (`BOWER_QUEUE_RETENTION_HOURS`, default 168), then the same source record re-read | 2 | days |
| Queue backup restored after some of its pending rows had reached Sentinel | 2 | time since the backup |
| `bower queue replay` of dead letters that Azure had in fact accepted | 2 | time since the dead-letter |
| `bower archive replay` of archived (delivered) events through another collector | 2 or more | time since the archive |

Every path except archive replay re-sends the stored queue row byte for byte, so the
copies share `CollectorId` and `EventId`. Archive replay posts the archived envelope to
another collector's `/v1/events`, and that collector stamps **its own** `CollectorId`
(a producer cannot choose its collector identity). Keyed by `(CollectorId, EventId)`,
those copies never collapse: an archive-replay drill found 238 rows for 119 events.
The archive replay labels are producer-controlled hints, not authenticated provenance.
The parser must not use them as identity. Cross-collector archive replay remains
distinct until a separately authorized, verifiable provenance mechanism is available.

The queue already rejects a re-read source record while its delivered row is retained
([identity and replay](../operations/queue-v5-durability.md#identity-and-replay)).

### What to do about it

Treat `(CollectorId, EventId)` as the event identity in every query. This does not
collapse archive replays through another collector. Measure replays at the destination
with the reconciliation query in [section 9](#9-validate-in-your-own-workspace).

## 2. How the replay-safe pattern works

### The parser: one row per event

`BowerSecurityEvents` collapses copies with
`summarize arg_min(ingestion_time(), *) ... by CollectorId, EventId` and adds:

| Column | Meaning |
| --- | --- |
| `BowerFirstIngested` | `ingestion_time()` of the first copy: when Sentinel could first see the event |
| `BowerLastIngested` | `ingestion_time()` of the latest copy |
| `BowerCopies` | Rows for this identity (1 means no replay) |
| `BowerEventTime` | The event time Bower sent (`RawEnvelope.timeGenerated`) |
| `BowerTimeRewritten` | `true` when Azure Monitor rewrote `TimeGenerated` |

The parser keeps the **first** copy (`arg_min`), not the latest. Replays are identical
within one collector identity, so the earliest ingested row is retained. A producer
that reuses an `EventId` can still cause distinct events to share a key. Archive
replays through another collector retain that collector's identity and are not collapsed.

Azure Monitor replaces `TimeGenerated` with the receive time when it is more than two
days before ingestion ([standard columns](https://learn.microsoft.com/azure/azure-monitor/logs/log-standard-columns#timegenerated),
[ingestion time](https://learn.microsoft.com/azure/azure-monitor/logs/data-ingestion-time)).
The original time survives in `RawEnvelope`, so detections bucket on `BowerEventTime`.
The test confirmed this with a three-day-old event.

### Why `TimeGenerated` windows alone fail

A rule that runs every 5 minutes over `TimeGenerated > ago(5m)` misses an event that
was generated an hour ago and ingested now. A longer look-back finds it, but then every
run inside the look-back re-counts the same events and raises the same alert again.
A replayed copy is ingested later with the original `TimeGenerated`, so it is inside
the look-back as well. Microsoft's guidance is to use a longer `TimeGenerated`
look-back and to restrict each run to rows with `ingestion_time() > ago(5m)`
([handle ingestion delay](https://learn.microsoft.com/azure/sentinel/ingestion-delay)).
That still fires again for a replay, because the replay has a new `ingestion_time()`.

### The Bower rule logic

Each detection rule:

1. Reads `BowerSecurityEvents`, so a replay adds no row and never changes a count.
2. Keeps events within the tolerated delay: `BowerFirstIngested - BowerEventTime <= maxDelay`.
   Later events are reported by the beyond-tolerance monitor instead.
3. Buckets events by **event time** (`bin(BowerEventTime, bucketSize)`) and entity
   (`SourceIpAddress`), so the answer does not depend on when events arrived.
4. Orders each bucket's events by `BowerFirstIngested` and finds `CrossedAt`, the first
   ingestion time of the `threshold`-th distinct event. `CrossedAt` is the moment the
   bucket became alert-worthy. It never moves after that: replays do not change first
   ingestion times, and new late events are ingested after it.
5. Computes the crossing's **slot**: `toint((now() - settle - CrossedAt) / frequency)`.
   In a scheduled run, `now()` is the end of the run's scheduled query window, not
   the moment the query executes (measured: `EvaluatedAt` equalled the alert's
   `EndTime` to the 100 ns, and the query ran about five minutes later). Consecutive
   runs' slot 0 (the **owned window**, `[now() - settle - frequency, now() - settle)`)
   therefore tile time without gaps or overlaps, and slot 0 alerts each crossing once.
6. Retries a crossing that slot 0 did not alert (a skipped or disabled run, or a row
   that became queryable late) in **even catch-up slots** 2, 4, … up to `catchUp`, and
   drops any result whose deterministic `BowerDetectionKey` (`rule|address|bucket start`)
   is already in `SecurityAlert`. Only even slots, because a run's own alerts are
   written after its window end (about five minutes later), so they are outside the
   next run's look-back: the next run cannot see them, the run after can. The first
   live test retried in every slot and raised a **second alert** for both catch-up
   crossings (one incident each, thanks to grouping). The even-slot rule is a
   proposed mitigation and has not been qualified against the retained evidence.
7. Raises one alert per result (`AlertPerResult`) with an `IP` entity. Alert grouping
   by IP (5 hours by default) is a final guard: even a duplicate alert joins the same
   incident.

The rules never use **suppression**. Suppression stops the whole rule for every entity
after an alert, so late events for other addresses would be skipped. Steps 4–6 aim
to reduce repeat alerts but do not guarantee exactly-once evaluation.

```text
event time       ──[bucket 08:10–08:20]──────────────────────────────────────────▶
first ingestion   e1..e5 08:18      (outage 08:19–09:30)      e6..e12 09:30
                                                            ▲ CrossedAt (10th event)
rule runs        │08:20│08:25│ ... │09:30│09:35│09:40│ ... │10:30│
                                         owned window at 09:40 contains CrossedAt → one alert
replay of e1..e5 at 09:30 → BowerCopies = 2, counts unchanged → no new alert
```

## 3. Choosing frequency, look-back and tolerated delay

All values are `main.bicep` parameters. Each rule file carries the same defaults in
`let` statements, so you can run a file unchanged in **Logs** to see what it would raise.

| Parameter | Default | Meaning and trade-off |
| --- | --- | --- |
| `frequencyMinutes` | 5 | How often each rule runs (Sentinel minimum 5). Shorter: alerts sooner, more query cost. |
| `settleDelayMinutes` | 5 | Rows ingested in the last `settle` minutes wait for the next run, so they are queryable when read. Raise it if `ingestion_time()` rows appear late in queries. |
| `catchUpMinutes` | 60 | How far back a run re-checks crossings without an alert (every second run). Covers missed runs up to `catchUp − 2 × frequency`. |
| `maxIngestionDelayMinutes` | 360 | Longest event-time-to-first-ingestion delay evaluated. Set it to your outage SLO plus backlog drain plus margin. Maximum 2,820 (47 hours) because Azure Monitor rewrites event times older than two days. |
| `bucketMinutes` | 10 | Event-time bucket for the threshold. |
| `bruteForceThreshold` | 10 | Distinct 4625 failures from one address per bucket. |
| `firewallDenyThreshold` | 20 | Distinct firewall denials from one address per bucket. |
| `incidentGroupingLookback` | `PT5H` | Alerts for the same IP join one incident within this time. |
| `reopenClosedIncidents` | `false` | Reopen a closed incident instead of creating one (not available in the Defender portal). |

The template derives the **rule look-back** (Sentinel *Lookup data from the last*):

```text
queryPeriod = maxDelay + bucket + catchUp + settle + 10 minutes
            = 360 + 10 + 60 + 5 + 10 = 445 minutes (PT445M) by default
```

The 10 minutes cover Sentinel's built-in five-minute scheduling delay
([query scheduling](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview#query-scheduling))
plus margin. The beyond-tolerance monitor runs hourly over 50 hours, past the
two-day rewrite limit.

**Detection latency.** A crossing that is not delayed alerts within
`settle + frequency + 5 minutes (Sentinel delay)`, about 15 minutes by default. A
crossing that needs late events alerts the same interval after those events are first
ingested. Missed runs add up to one more catch-up cycle.

**Cost.** Every run reads `queryPeriod` of `BowerSecurity_CL` and `SecurityAlert`.
The parser summarises over all Bower rows in that period. At large volumes, raise
`frequencyMinutes` or lower `maxIngestionDelayMinutes` to what your SLO really needs.

**Tuning for an outage SLO.** Use the measured drain rate (the pilot drained a one-hour,
45,090-event backlog in 55.8 seconds) and your longest tolerated destination outage:

| Declared outage SLO | Suggested `maxIngestionDelayMinutes` | Resulting `queryPeriod` |
| --- | --- | --- |
| 1 hour | 120 | 205 minutes |
| 4 hours | 360 (default) | 445 minutes |
| 12 hours | 900 | 985 minutes |
| 24 hours | 1,680 | 1,765 minutes |
| More than 47 hours | Not supported: event times are rewritten. Hunt manually after recovery. | n/a |

Collector-side outages count too: a collector that is down while its source keeps
buffering (WEF subscription, rsyslog disk queue) delivers late when it returns.

## 4. Deploy the parser and rules

**Purpose:** install `BowerSecurityEvents` and the three rules into the workspace that
receives `BowerSecurity_CL`.

**Prerequisites**

- Workspace with Microsoft Sentinel enabled and `BowerSecurity_CL` deployed by
  [`deploy/bicep/main.bicep`](../../deploy/bicep/main.bicep) (see
  [Logs Ingestion API](../deployment/logs-ingestion-api.md)).
- **Microsoft Sentinel Contributor** and **Log Analytics Contributor** on the workspace
  (or its resource group) for the deploying identity. The collector's ingestion identity
  needs nothing new.
- Azure CLI 2.60+ with Bicep (`az bicep version`), or PowerShell 7.4 with `Az.Resources`
  11+ and the Bicep CLI on `PATH`.
- At least one Bower event already ingested, so the table is queryable.

Following [deploy/AGENTS.md](../../deploy/AGENTS.md), the rules are created **disabled**
(`enableRules=false`). Enable them after the [validation](#9-validate-in-your-own-workspace) passes.

### 4.1 Azure CLI (bash)

```bash
RG=rg-sentinel
WS=law-sentinel
az account show --query "{subscription:id, tenant:tenantId}" -o table   # confirm the target
cd deploy/sentinel/analytics
az deployment group what-if -g "$RG" --template-file main.bicep \
  --parameters workspaceName="$WS" maxIngestionDelayMinutes=360
az deployment group create -g "$RG" -n bower-analytics --template-file main.bicep \
  --parameters workspaceName="$WS" maxIngestionDelayMinutes=360 enableRules=false \
  --query "properties.outputs" -o json
```

### 4.2 Azure CLI (PowerShell)

```powershell
$Rg = 'rg-sentinel'; $Ws = 'law-sentinel'
az account show --query "{subscription:id, tenant:tenantId}" -o table
Set-Location deploy/sentinel/analytics
az deployment group what-if -g $Rg --template-file main.bicep `
  --parameters workspaceName=$Ws maxIngestionDelayMinutes=360
az deployment group create -g $Rg -n bower-analytics --template-file main.bicep `
  --parameters workspaceName=$Ws maxIngestionDelayMinutes=360 enableRules=false `
  --query "properties.outputs" -o json
```

### 4.3 Azure PowerShell (Az module)

```powershell
Connect-AzAccount -Tenant '<tenant-id>' -Subscription '<subscription-id>'
Get-AzContext | Format-List Subscription, Tenant      # confirm the target
$params = @{ workspaceName = 'law-sentinel'; maxIngestionDelayMinutes = 360; enableRules = $false }
New-AzResourceGroupDeployment -ResourceGroupName 'rg-sentinel' -Name bower-analytics `
  -TemplateFile deploy/sentinel/analytics/main.bicep -TemplateParameterObject $params -WhatIf
New-AzResourceGroupDeployment -ResourceGroupName 'rg-sentinel' -Name bower-analytics `
  -TemplateFile deploy/sentinel/analytics/main.bicep -TemplateParameterObject $params
```

### 4.4 Azure portal

1. Compile the template once: `az bicep build --file deploy/sentinel/analytics/main.bicep --outfile bower-analytics.json`.
2. In the portal, open **Deploy a custom template** → **Build your own template in the editor** →
   **Load file**, choose `bower-analytics.json`, then **Save**.
3. Choose the workspace's subscription and resource group, enter `workspaceName`, keep
   `enableRules` at `false`, set `maxIngestionDelayMinutes`, then **Review + create**.

Without a template (for example to review each piece):

1. **Log Analytics workspace → Logs**. Paste `bower-security-events.kql`, run it, then
   **Save → Save as function**: name `BowerSecurityEvents`, category `Bower`. Do not
   add parameters.
2. **Microsoft Sentinel → Analytics → Create → Scheduled query rule**. Use the values in
   [`main.bicep`](../../deploy/sentinel/analytics/main.bicep) for the chosen rule:
   paste the rule file (edit its `let` values to your parameters), *Run query every* =
   `frequencyMinutes`, *Lookup data from the last* = the `queryPeriod` above,
   *Generate alert when number of query results* is greater than 0, *Event grouping*:
   **Trigger an alert for each event**, *Suppression*: **Off**.
3. Entity mapping: **IP → Address = `SourceIpAddress`**. Custom details: map
   `BowerDetectionKey`, `BucketStart`, `DistinctEvents`, `CrossedAt`, `EvaluationPath`,
   `EvaluatedAt`, `ReplayedRows`, `LateEvents` and `MaxDeliveryDelay` to the columns of
   the same names. **`BowerDetectionKey` is required**; without it the alert
   deduplication in step 6 of the rule logic cannot work.
4. Incident settings: **Group related alerts** on, *Group alerts into a single incident
   if the selected entity types and details match*: **IP**, time frame 5 hours.

### Verify the deployment

```bash
WSID=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query customerId -o tsv)
az monitor log-analytics query -w "$WSID" --analytics-query \
  "BowerSecurityEvents | summarize Events=count(), Rows=sum(BowerCopies), Replayed=countif(BowerCopies > 1)" -t P1D
az rest --method get --url "https://management.azure.com$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv)/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01" \
  --query "value[?starts_with(properties.displayName,'Bower')].{name:properties.displayName,enabled:properties.enabled,every:properties.queryFrequency,lookBack:properties.queryPeriod}" -o table
```

**Expected:** one row with `Rows >= Events`, and three Bower rules with the frequency
and look-back you chose. **Pass:** the function returns rows and the rules exist.
**Fail:** `Failed to resolve table or column expression named 'BowerSecurityEvents'`
(see [troubleshooting](#10-troubleshooting)).

To enable after validation, re-run the deployment with `enableRules=true`, or enable
each rule under **Analytics → Active rules**.

**Rollback:** disable or delete the three `Bower:` rules under **Analytics** and delete
the `BowerSecurityEvents` function (**Logs → Functions**). Bower ingestion is unaffected.

## 5. Convert an existing rule to the replay-safe pattern

A typical existing rule:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(1h)
| where EventType == "authentication_failure"
| summarize Failures = count() by SourceIpAddress, bin(TimeGenerated, 10m)
| where Failures >= 10
```

It double-counts replays and either misses late events (short look-back) or alerts
again on every run (long look-back). Convert it step by step:

1. **Read the parser, not the table.** Replace `BowerSecurity_CL` with `BowerSecurityEvents`.
   Replace `TimeGenerated` with `BowerEventTime` in the logic.
2. **Remove `ago()` filters on `TimeGenerated`.** The rule's *Lookup data from the last*
   setting limits `TimeGenerated`; set it to the `queryPeriod` formula.
3. **Bound the tolerated delay.** Add `| where BowerFirstIngested - BowerEventTime <= maxDelay`.
4. **Bucket by event time and entity**, ordered by first ingestion, and compute
   `CrossedAt` with `row_number()` and `minif()`, as in `rules/wec-brute-force.kql`.
5. **Choose the window by `CrossedAt`**: slot 0 (the owned window) plus even catch-up slots.
6. **Add a `BowerDetectionKey`** built only from values that never change for that
   detection (rule name, entity, bucket start), map it as a custom detail and exclude
   keys already in `SecurityAlert`.
7. **Set the rule**: one alert per result, entity mapping, grouping by entity, no
   suppression. Keep the old rule disabled (not deleted) until the new one is validated.

A rule that alerts **per event** (no threshold) is simpler: alert on events with
`BowerFirstIngested` in the owned window, use `strcat(CollectorId, "|", EventId)` as
`BowerDetectionKey`, and keep the catch-up and `SecurityAlert` check.

Rules on other tables (`SecurityEvent`, `CommonSecurityLog`) are not affected by Bower
replays, but they suffer the same ingestion-delay problem; the same structure applies.

**Verify a converted rule** with section 9's procedure and compare one week of the old
and new query results in **Logs** (same counts, minus replays).

## 6. Hunting, workbooks and exports

| Use | Do | Do not |
| --- | --- | --- |
| Hunting queries | Start from `BowerSecurityEvents`; filter on `BowerEventTime`. Set the time picker wider than the outage you are investigating. | Count `BowerSecurity_CL` rows. |
| Workbooks | Use `BowerSecurityEvents` in every tile; chart `count()` by `bin(BowerEventTime, …)`. Add a replay tile: `summarize Replayed = countif(BowerCopies > 1), ExtraRows = sum(BowerCopies - 1)`. | Use `dcount(EventId)` for totals shown as exact. |
| Livestream / NRT rules | NRT rules evaluate each row once at ingestion and cannot see the parser's earlier copies. Prefer scheduled rules for Bower data. | Assume NRT rules collapse replays. |
| Data export rules, Event Hubs, Storage | Exports carry every raw row. Deduplicate downstream by `(CollectorId, EventId)` and keep the earliest arrival. | Assume one exported row per event. |
| Azure Data Explorer / Fabric | Use a materialised view keyed like the parser: `arg_min(ingestion_time(), *) by CollectorId, EventId`. | Use producer-controlled labels as the collector identity. |
| Summary rules | Summarise from `BowerSecurityEvents`, and keep the summary window behind `settleDelay`. | Summarise raw rows. |
| Search jobs, restore | Run the parser logic over the search results table before counting. | |

A reconciliation query for any period:

```kusto
BowerSecurity_CL
| where TimeGenerated between (datetime(2026-10-31 00:00) .. datetime(2026-11-01 00:00))
| summarize Copies = count() by CollectorId, EventId
| summarize Events = count(), Rows = sum(Copies), ReplayedEvents = countif(Copies > 1),
    ExtraRows = sum(Copies - 1), MaxCopies = max(Copies)
```

## 7. Why `dcount()` cannot be used for exact counts

`dcount()` uses the HyperLogLog estimator. Its result is an estimate with a relative
error of about 1% at the default accuracy, and the error does not shrink to zero for
small sets ([`dcount()`](https://learn.microsoft.com/kusto/query/dcount-aggfunction)).
A reconciliation such as "59,400 events sent, 59,400 events present" or a threshold such
as "10 failures" must be exact. Use the parser and `count()`, or
`summarize ... by CollectorId, EventId | count`. `count_distinct()` is exact but limited
and slower; the parser approach also exposes copies and arrival times.

## 8. Keep `CollectorId` stable in every environment

Replays under the same collector are collapsed by `(CollectorId, EventId)`. The collector
stamps its identity and stores it with the event ID **when the event is queued**, so a replay from the
queue always carries the original `CollectorId`, even after a rename. Deduplication
breaks when the same source record is accepted again under a **different** collector ID,
for example after a reinstall that lost the queue, or a container that got a new
hostname and re-read its source. Pinning, persisting and restoring the collector ID
across upgrades, reinstalls and host replacement requires a tested operational
procedure; upgrade and recovery qualification remains open. This section covers what
the ID means for Sentinel queries.

**Restoring a queue backup replays exactly the rows that were pending in it.** Those
rows keep their stamped `CollectorId` and `EventId`, so if some had already reached
Sentinel before the failure, `BowerSecurityEvents` can collapse copies visible within
the query's time range. Alert evaluations can still repeat; their handling remains
unqualified. The upgrade and recovery campaign measured 2,678 such duplicates
after a WEC restore. Restore under the **same** `CollectorId`.

`EventId` comes from the source record:

| Source | `EventId` derivation |
| --- | --- |
| Windows Event Log / WEC | `winevt-` + SHA-256 of channel, computer, record ID and time created |
| Syslog (firewall) | `syslog-` + SHA-256 of listener, sender address and exact frame bytes |
| HTTP ingest, SDK | Producer-supplied; the SDK uses one UUIDv7 per event across retries |
| Docker source | `docker-` + SHA-256 of container, log file fingerprint and offset |
| AWS / GCP mappers | SHA-256 of source ID, kind, original ID and time |

`CollectorId` is `BOWER_COLLECTOR_ID`, otherwise the machine name:

| Environment | Default | Stable? | What to do |
| --- | --- | --- | --- |
| Linux deb/rpm + systemd | Host name (`bower.env` leaves `BOWER_COLLECTOR_ID` commented out) | While the host name is unchanged. Uninstall deletes `bower.env`. | Set `BOWER_COLLECTOR_ID` in `/etc/bower/bower.env` and in your configuration management. |
| Windows MSI + service (WEC hosts) | `COLLECTORID` property, default `[ComputerName]` (NetBIOS, upper case, 15 chars) | Remembered in `HKLM\SOFTWARE\Bower\Collector` for repair and upgrade. A full uninstall/reinstall falls back to the computer name. | Pass `COLLECTORID=` on every install, including reinstalls. |
| Docker / Compose | Container hostname (the container ID): **changes every recreate** | No | Set `BOWER_COLLECTOR_ID` to a stable, unique value and verify it persists across recreation. |
| Kubernetes | Pod hostname (`bower-collector-<hash>-<suffix>`): **changes on every rollout or reschedule** | No | Set `BOWER_COLLECTOR_ID` to a stable, unique value. For several replicas use a StatefulSet and `metadata.name` via the downward API, then test replacement and replay. |
| AWS EC2 | OS host name (`ip-10-0-1-23...`, cut at the first dot), which changes when an instance is replaced | Per instance | Set `BOWER_COLLECTOR_ID` to a role name (for example from a launch template tag), not the instance ID. |
| Azure VM | OS computer name | While the VM keeps its name | Set `BOWER_COLLECTOR_ID`; for scale sets use a stable per-instance name. |
| Azure Functions collector | `azure-function:<site>` (Bicep sets the app name) | Yes, shared by all instances | Nothing. |
| AWS Lambda (Rust) | Function name; CloudFormation generates it and it changes if the function is replaced | Until replacement | Set `BOWER_COLLECTOR_ID`. |
| Relay | Keeps the downstream collector's ID | Yes | Rename downstream collectors only together with their relay pin. |
| On-premises | Host name | While unchanged | Set `BOWER_COLLECTOR_ID`. |

C# uses `Environment.MachineName`; the Rust collector reads the host name and cuts it
at the first dot. On Windows the two can differ in case, so never switch runtimes on
one host without setting `BOWER_COLLECTOR_ID`.

**Verify the configured value.** `/v1/status` does not report the ID; check the setting
the service starts with, then confirm it in Sentinel.

```bash
# Linux packages: an empty result means the host name is used
sudo grep '^BOWER_COLLECTOR_ID=' /etc/bower/bower.env || hostname -s
# Docker
docker inspect bower --format '{{range .Config.Env}}{{println .}}{{end}}' | grep BOWER_COLLECTOR_ID
# Kubernetes
kubectl get deploy bower-collector -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="BOWER_COLLECTOR_ID")].value}'
```

```powershell
# Windows MSI: remembered property and the service environment
(Get-ItemProperty 'HKLM:\SOFTWARE\Bower\Collector').CollectorId
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment | Select-String BOWER_COLLECTOR_ID
```

**In Sentinel:** `BowerSecurity_CL | summarize Last = max(TimeGenerated) by CollectorId`
should show one stable ID per collector. A new ID appearing for a known host after a
restart means the ID is not pinned.

**Changing an ID on purpose:** drain the queue first (`pending` 0 in `/v1/status`),
then change it. Already queued events keep the old ID; a relay pins the ID and
dead-letters a mismatch ([relay](../deployment/relay.md)).

### Generated event IDs are never masked by privacy detectors

The other half of the key is `EventId`. The native pilot found that the default privacy
detectors changed 31 of 59,400 Windows record IDs, and two later campaigns saw the same
on syslog IDs (one destination row could no longer be found by its ID). The cause,
reproduced in the tests: a lowercase hex digest such as
`winevt-dd97c1d25d12d2e202c1e010d70d55f4` matched the IBAN detector's case-insensitive
pattern and passed mod-97 about once per thousand IDs (20 of 20,000 sampled), and the
mask kept only `winevt-dd…f4`. Distinct events could then share an identity. The
conservative `fin.iban` checksum detector remains unchanged, including its possible
false positives for digest-shaped data. Both the C# and Rust collectors apply this
narrowly scoped change:

**Record ids that Bower's own syslog and Windows Event Log sources compute skip value
   detectors**, so a custom detector (for example one an operator adds for 32-character
   hex API keys) cannot mask them either. Only the root `eventId` and `eventOriginalId`,
   only while they still equal the id the source computed after the pack's transforms,
   and only when the id is a lowercase prefix plus 32 lowercase hex characters.
Every other field, including `request.correlationId`, nested
copies of the ID and the rest of the record, is scanned as before; explicit
privacy-profile field rules and length limits still apply to the ID. An ID or number
sent by a producer (`/v1/events`, `/v1/packs/.../events`, agents, the SDK, Azure
Functions, Lambda) is source data and is still scanned. Numeric fields in internally
generated health records are also scanned and may be masked by a checksum detector;
the health-record representation requires further qualification. `CollectorId`, `PolicyHash`, the
configuration hash and `collector.receivedAt` are stamped after redaction, so detectors
never saw them. Numeric **source** fields (ports, byte counts in firewall events) are
still scanned: a detection that compares an 8-digit or longer number from the source
can see it masked. Pack privacy profiles do not change, so no pack version changes.

**High-availability WEC.** Two WEC collectors that receive the same forwarded event
produce the same `EventId` with different `CollectorId` values. They are two
deliveries, not a replay, and the parser keeps both. If you run WEC subscriptions to
two collectors on purpose, change the parser's `by` clause to `by EventId` for those
`ApplicationName` values and document the decision.

## 9. Validate in your own workspace

**Purpose:** prove, in a non-production workspace, that replays create no extra
incidents and late events are not missed, before enabling the rules in production.

**Prerequisites:** a test workspace deployed with `deploy/bicep/main.bicep`; a test
collector built from the release you deploy; Python 3.9+; the
[validation scripts](../../deploy/sentinel/analytics/validation/drive.py); an identity
that can read the workspace and Sentinel incidents; for direct uploads, the ingestion
identity signed in to an isolated Azure CLI profile (`AZURE_CONFIG_DIR`). Synthetic
data only.

1. Deploy the analytics content with `enableRules=true`, `frequencyMinutes=5` and a
   `maxIngestionDelayMinutes` above your test outage (120 for a 70-minute outage).
2. Start the fault proxy and point the test collector at it:

   ```bash
   python3 -I deploy/sentinel/analytics/validation/fault_proxy.py --log proxy.jsonl &
   export HTTPS_PROXY=http://127.0.0.1:8899 NO_PROXY=127.0.0.1,localhost
   export BOWER_DELIVERY_LEASE_SECONDS=90 BOWER_DELIVERY_TIMEOUT_SECONDS=60
   # plus your usual BOWER_OUTPUT=azure-logs-ingestion, DCE, DCR and credential settings
   ```

   ```powershell
   Start-Process python3 -ArgumentList '-I','deploy/sentinel/analytics/validation/fault_proxy.py','--log','proxy.jsonl'
   $env:HTTPS_PROXY = 'http://127.0.0.1:8899'; $env:NO_PROXY = '127.0.0.1,localhost'
   ```

3. Drive each scenario with its own addresses (`--address`):

   | Scenario | Commands |
   | --- | --- |
   | Clean | `drive.py collector --scenario clean --kind logon --address 192.0.2.10 --count 12 --manifest m.jsonl` |
   | Replay soon after | `curl 127.0.0.1:8898/mode/drop-next`, then the same with a new address |
   | Kill mid-delivery | arm `drop-next`, send, wait for `response-dropped` in `proxy.jsonl`, `kill -9` (or `Stop-Process -Force`) the collector, restart it |
   | Replay after the window | arm `drop-next-then-outage`, send, keep the outage for at least 65 minutes, then `curl 127.0.0.1:8898/mode/pass` |
   | Late originals | during that outage, send more events with new addresses |
   | Beyond tolerance | `drive.py direct ... --age-minutes 150` (expect no detection, one monitor alert) |

   Repeat each with `--kind deny --count 25` for the firewall rule.
4. Wait at least `settle + frequency + 10` minutes after the last event, then run:

   ```bash
   python3 -I deploy/sentinel/analytics/validation/verify.py report \
     --workspace-id "$WSID" --workspace-resource "$WORKSPACE_ARM_ID" \
     --manifest m.jsonl --expect expect.json > report.json
   ```

   `expect.json` lists the incidents expected per address, for example
   `{"incidentsPerAddress": {"192.0.2.10": 1}, "alertsPerKeyPrefix": {"bower-wec-brute-force|192.0.2.10|": 1}}`.

**Pass:** every scenario has `missing: 0`; replay scenarios show `extraRows > 0` (the
fault really happened); every expected address has exactly the expected incidents and
`duplicateAlertKeys` is empty; beyond-tolerance addresses have no detection incident.
**Fail:** any missing event, any second alert for one key, any second incident for
one address, or a replay scenario with `extraRows: 0` (the fault was not injected; repeat it).

**Rollback:** delete the test resource group; the scripts keep no state elsewhere.

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Deployment fails: `Failed to resolve table or column expression named 'BowerSecurityEvents'` | Function not created yet, or deployed to another workspace | Re-run the template (it orders the function first) or save the function manually |
| Deployment fails: `SEM0255 format_datetime()` or other semantic errors | Rule edited by hand with an unsupported format | Use the shipped rule files; `tostring()` keeps ISO 8601 |
| Rule never alerts | Rule disabled (default), threshold not reached, or crossing older than `catchUp` when first visible | Enable it; run the rule file in Logs; raise `catchUpMinutes` |
| Alert expected after an outage, none raised | Events exceeded `maxIngestionDelayMinutes` | Check the beyond-tolerance incident; raise the tolerance to your real outage SLO |
| Two alerts with the same `BowerDetectionKey` | `BowerDetectionKey` custom detail missing; a hand-edited rule that retries in every catch-up slot (the next run cannot see the previous run's alerts); a schedule move after redeploying or re-enabling; or `SecurityAlert` written more than two runs late | Map the custom detail; keep the even-slot filter; avoid redeploying during incidents; raise `frequencyMinutes` if alert latency exceeds it. Grouping still keeps one incident. |
| Two incidents for one address | Grouping disabled, grouping window shorter than the attack, or closed incident with `reopenClosedIncidents=false` | Enable grouping by IP; lengthen `incidentGroupingLookback` |
| `BowerCopies` > 1 on many events | Repeated ambiguous acknowledgements: unstable network, too short a delivery deadline, or crash loops | Check collector logs for `exceeded its delivery timeout`; fix the network or deadline |
| Same `EventId` with two `CollectorId` values | Collector ID changed, or two WEC collectors on purpose | See [section 8](#8-keep-collectorid-stable-in-every-environment) |
| `BowerTimeRewritten` true | Event more than two days old at ingestion | Expected after a very long outage; hunt those events manually |

## Identity changes and failures during redaction

The C# collector returns `event-id-redacted` without the original or transformed
ID when privacy processing changes the root `eventId`. It does not queue the
event or acknowledge it as a duplicate: distinct original IDs can otherwise
collapse to the same redacted value. HTTP `/v1/events`, pack HTTP and the Azure
Functions collector return 503 so senders must retain and retry the event. A WEC
subscription holds its bookmark before the event; a TCP syslog listener retries
the frame and applies backpressure. UDP cannot backpressure or retry: it counts
the frame as dropped and the sender needs its own replay mechanism. Monitor these
conditions and retain the source log until the cause is resolved.

An operational redaction or pack-detection failure likewise returns the bounded
reason `redaction-unavailable` and follows the same retry path without persisting
the event. Malformed input and policy rejection remain distinct. The authenticated
operator tap (`bower tap --stage redacted`, when enabled and authorized) can show
the bounded reason, stage and action without an event body; WEC status otherwise
reports generic retries/backpressure. The tap is transient and bounded, and can
drop records; it is not a durable alert. These early refusals do not enqueue a
`sensitive_data_detected` SOC privacy alert. Monitor source silence, backpressure
and the tap while investigating; do not treat the absence of a SOC alert as
evidence that no sensitive input was seen.

Investigate the privacy profile and source in an isolated environment using
synthetic examples. Keep privacy protection enabled; never put the raw identity
or other sensitive payload into support reports. A permanent identity mapping,
producer remediation and operational replay procedure need separate qualification;
retries alone cannot repair a deterministic privacy collision. This is a fail-closed
safeguard, not a complete identity solution: even a false-positive privacy match can
stall a WEC subscription or TCP sender until an operator resolves the configuration
or producer issue. WEC and the originating sender have finite retention: prolonged
stalls can roll events out of the source log, so monitor available retention and
escalate before it expires. Preserve the upstream records, correct the cause using a
trusted configuration, then verify the bookmark resumes and reconcile source and
destination identities before declaring recovery. Rows already accepted under an altered identity cannot be
automatically reconstructed or repaired; investigate and replay from the source
where retained, with independent destination reconciliation. The behavior is not
evidence of lossless UDP or of a completed Sentinel alert qualification.

## 11. Known limits

- At-least-once delivery remains. The parser aims to deduplicate counts; the current
  rules have not established exact alert or incident counts. Exports and raw-table
  queries still see replays.
- Exactly-once alerts on the catch-up path assume that an alert is queryable in
  `SecurityAlert` within two rule runs of its window end (10 minutes by default;
  measured at most 2.1 minutes after creation). If Sentinel writes it later, a
  second alert can appear; grouping by IP still keeps one incident.
- Owned windows tile only while Sentinel keeps a rule's schedule. Redeploying or
  re-enabling a rule can move its schedule (observed twice in the test); a crossing in
  a resulting overlap can alert twice before `SecurityAlert` shows the first alert.
  Grouping keeps one incident.
- Missed runs are recovered for up to `catchUpMinutes − 2 × frequencyMinutes`, at the next even slot.
  A longer Sentinel scheduling gap needs manual hunting.
- Events delayed more than `maxIngestionDelayMinutes` are not evaluated; the monitor
  reports them. Delays over two days lose the original `TimeGenerated` (the parser
  still recovers `BowerEventTime`).
- Thresholds use fixed event-time buckets. An attack split across two buckets
  (for example 6 + 6 attempts) does not reach a 10-per-bucket threshold.
- `reopenClosedIncidents` is not available in the Defender portal; there, a match
  after closure creates a new incident.
- The test used the collector's HTTP intake with pack-shaped events and the Logs
  Ingestion API directly, not native WEF or syslog sources; those paths were qualified
  in the [native pilot](../evidence/pilot-native-20261030/README.md). Replay behaviour
  is a property of the delivery path, which both use.

## How we tested this

The retained `report-1044.json` from 31 October 2026 failed the
`noDuplicateAlertKeys` check: WEC and firewall threshold crossings generated two
alerts each after missed rule evaluations. Sentinel grouped each pair into one
incident; grouping did not prevent duplicate alerts. An earlier report passed a
smaller set of scenarios. The current even-slot mitigation has different KQL
hashes from the recorded deployment, so neither report proves it works. Re-run
the full validation against the exact proposed rule hashes, including skipped
evaluations and delayed `SecurityAlert` visibility, and retain both alert and
incident counts before changing this status. Until then, this gate remains open.
