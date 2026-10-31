# Operational monitoring, alerting and runbooks

Production-readiness gap 6 of 7: **actionable, tested alerts and runbooks** for the
scoped rollout, Windows WEF/WEC (`ForwardedEvents`) and firewall syslog (RFC 5424 over
mutual TLS) → Bower collector → Microsoft Sentinel (Logs Ingestion API / DCR).

**Status: alerts and runbooks validated live in Azure and AWS on 31 October 2026, with
retained failures.** Every alert in the catalogue below fired for a real fault and
resolved after recovery, with one exception: the Azure storage alert cannot report a queue
that is *already* full (`collector-health-missing` covers that case). The drill also found
a **queue page-ceiling defect** that stops delivery after the queue file fills, and a
recovery procedure that worked. See [known defects](#known-defects-found-by-this-work)
and the [evidence](../evidence/ws6-20261031-074751/README.md). Releases are **unsigned**
development builds; this document does not change the production-readiness status.

## Contents

1. [How monitoring works](#how-monitoring-works)
2. [Signal inventory](#signal-inventory)
3. [The collector health record](#the-collector-health-record)
4. [Alert catalogue](#alert-catalogue)
5. [Deploy: enable health records on every collector](#deploy-1-enable-health-records-on-every-collector)
6. [Deploy: Azure Monitor and Sentinel rules](#deploy-2-azure-monitor-and-sentinel-rules)
7. [Deploy: host-side checks and watchdogs](#deploy-3-host-side-checks-and-watchdogs)
8. [Deploy: management fleet check](#deploy-4-management-fleet-check)
9. [Runbooks R1–R8](#runbooks)
10. [Audited replay](#audited-replay)
11. [Escalation](#escalation)
12. [Weekly operational checklist](#weekly-operational-checklist)
13. [Dashboard queries](#dashboard-queries)
14. [How we tested this](#how-we-tested-this)
15. [Known defects found by this work](#known-defects-found-by-this-work)
16. [Known limits](#known-limits)

## How monitoring works

Three independent paths watch each collector. No single failure (the collector, the
host, the network, Azure ingestion or the management plane) silences all three.

```text
 firewall ──syslog/mTLS──┐                      ┌── (A) Azure-side: BowerSecurity_CL
 WEF → WEC ForwardedEvents┤                      │      collector_health records, freshness,
                          ▼                      │      DCR metrics and error logs
                   Bower collector ──Logs Ingestion──▶ Azure Monitor log/metric alerts
                     │   │   └─ heartbeat ──▶ (C) Management API /api/fleet ──▶ fleet check
                     │   └─ /health, /v1/status ──▶ (B) host check (systemd timer / scheduled task)
                     └─ journald / Windows Application log ──▶ CloudWatch agent / AMA / SIEM agent
```

| Failure | (A) Azure-side | (B) Host-side | (C) Management |
|---|---|---|---|
| Firewall or WEC stops sending | `source-overdue`, `destination-freshness` | `source-overdue` warning; WEC subscription state | "Needs a check: an expected app has gone quiet" |
| Delivery to Sentinel fails (network, credential, DCR) | `collector-health-missing`; DCR metrics and `dcr-errors` | `backlog` warning/critical | "Can't deliver to Sentinel" |
| Old queued events | `queue-backlog` (while delivery is slow, or after recovery) | `backlog` | "Events waiting more than 15 minutes" |
| Storage pressure | `queue-storage` (before the queue is full) | `queue-file`, `queue-storage`, `capacity-refusals`, `disk-free` | not reported today |
| Collector or host down | `collector-health-missing`; `dcr-no-ingestion` (whole fleet) | `collector-unreachable`; systemd/SCM restart | "Not heard from recently" (amber after minutes, red after 15) |
| Loss before acceptance | `source-transport-errors` (syslog) | `syslog-errors`, `syslog-churn`, `wec-subscription`, `wec-source` | not reported |
| Events set aside | `dead-letters` | `dead-letters` | "Has events that could not be sent and were set aside" |

The Azure path cannot tell "the collector is down" from "delivery is failing": both mean
no new records arrive. The host and management paths separate them. Use the Azure path for
paging (it works without the management plane and without access to the host), and the
other two for diagnosis.

## Signal inventory

What already existed on `main` (commit `9d1bbcd`) and what this work adds.

| Signal | Where | Content | Used by |
|---|---|---|---|
| `GET /health` | Collector, no token | `healthy` or `degraded` (dead letters or an overdue expected source). HTTP 200 either way | Readiness/liveness probes, host check |
| `GET /v1/status` | Collector, ingest token | Queue counts, `oldestUndelivered`, `undeliveredBytes`; `intake` (attempts, capacity refusals, last refusal); `pipeline`; `sources` (silence state per expected source); `syslog` per listener (connections, TLS failures, frames, drops, timeouts); `windowsEventLog` per subscription (state, reads, errors, gaps, bookmark); jobs; adaptive delivery concurrency | Host check, runbooks |
| Source silence | `BOWER_SOURCE_EXPECTATIONS` ([details](../operations/suppression-archive-and-source-silence.md#source-silence)) | Per application/environment allowance, durable across restarts | `/health`, status, heartbeat, health record |
| Heartbeat v2 | Collector → management every 60 s ([schema](../architecture/heartbeat-v2.md)) | Delivery status, undelivered count, oldest age, dead letters, sources, jobs, ledger head | Fleet and home views, fleet check |
| Fleet view | `GET /api/fleet` (Viewer role) | One plain state and traffic light per collector ([console](../operations/console-fleet.md)) | Fleet check |
| Collector logs | journald (`bower.service`); Windows Application log, source `Bower.Collector` (warnings and errors) | Event IDs below | Log shippers, runbooks |
| DCR metrics | Azure Monitor, `Microsoft.Insights/dataCollectionRules` | `ApiCallReceived_Count` (by `ResponseCode`), `RowsReceived_Count`, `RowsDropped_Count`, `TransformationErrors_Count`, `ColumnsDroppedCount`, bytes | Metric alerts |
| DCR error logs | Diagnostic setting category `LogErrors` → `DCRLogErrors` | Rejected or failed ingestion | `dcr-errors` |
| Workspace operations | `_LogOperation` | Ingestion warnings and errors | `dcr-errors` |
| **New: `collector_health` record** | `BowerSecurity_CL`, `EventType == "collector_health"` | Queue, storage, delivery, intake, sources, syslog and Windows Event Log counters, every interval | All `(A)` health rules |
| **New: host checks** | [`deploy/sentinel/monitoring/host`](../../deploy/sentinel/monitoring/host) | Exit code 0/1/2/3, JSON, Prometheus text, Application log events 9100–9103 | Monitoring agents |
| **New: fleet check** | [`deploy/sentinel/monitoring/fleet`](../../deploy/sentinel/monitoring/fleet) | Exit code and Prometheus text from `/api/fleet` | Monitoring agents |

Collector log events worth alerting on (all metadata only):

| Event ID | Level | Meaning | Runbook |
|---|---|---|---|
| 1001 | Warning | Output failed; batch will retry | R1, R2 |
| 1002 | Error | Delivery loop failed (for example `SqliteException`); retrying after back-off. Repeating every 5 s means delivery is stalled | R5 |
| 1004 | Warning | Delivery attempts exhausted; event dead-lettered | R3 |
| 1006 | Warning | Retry-After above one hour was capped | R2 |
| 1007 | Warning | Output exceeded its delivery timeout; batch will retry (seen throughout a destination outage) | R1 |
| 1101 | Warning | Management heartbeat failed; collection continues | R8 |
| 1302 | Warning | Suppression windows could not close (often queue capacity) | R5 |
| 1321 | Warning | Monitoring start of expected sources forgotten (expectations changed) | R6 |
| 1330 | Warning | **New**: health record refused, queue at capacity | R5 |
| 1331 | Warning | **New**: health record not queued (policy or validation) | R1 |
| 1332 | Warning | **New**: health record failed | R1 |
| 1333 | Information | **New**: health record skipped while the managed privacy profile gates intake | R8 |
| 3001 | Warning | Background job attempt failed | R5 (retention), R8 |

Azure Sentinel's own `SentinelHealth` table reports analytics rule and connector health; it
does not see Bower's custom table and is not used here. Enable it separately if you monitor
analytics rule failures.

## The collector health record

A collector with `BOWER_HEALTH_RECORD_INTERVAL_SECONDS` set (60–3600; `0` or unset turns it
off) queues one `collector_health` event at start-up and then every interval. It goes
through the same redaction, policy, queue and output as any security event, so its arrival
in Sentinel proves the whole path and its absence is the destination-side outage signal.
Records are metadata only: no payloads, event ids, credentials, endpoints or free-form
error text. Delivery, acknowledgement and queue state stay in the delivery worker; the
health worker only reads metadata and enqueues its own record.

- **Managed privacy gate.** While a collector in management mode waits for its assigned
  privacy profile (intake refused), it skips health records too (event 1333); the missing
  records are the destination signal.
- **Policy (required).** The bundle must accept it, or the collector does not start.
  Add [`examples/policies/collector-health/collector-health.yaml`](../../examples/policies/collector-health/collector-health.yaml)
  (`BWR-POL-COLLECTOR-HEALTH` 1.0.0) to the policy directory. It is not in
  `policies/default`, so the default bundle hash of existing collectors does not change.
- **Identity.** `eventId` is `collector-health-` and 32 letters derived from the collector
  id, process start and sequence. Letters only: a run of digits can match a numeric privacy
  detector (the earlier pilot saw generated ids masked). A restart starts a new series.
- **Numbers stay below eight digits.** Default privacy detectors scan JSON numbers, and an
  eight-digit or longer value can match a card, TFN, ABN or Medicare checksum and be masked
  (measured: up to 9 % of random 8–10 digit values, 0–3 % for 11–16 digits, none at 7 or
  fewer). So counters are **deltas since the
  previous queued record** (`countersSince`), sizes are MiB and ages are clamped to
  9,999,999. Lifetime totals stay in `/v1/status`.
- **Cost.** About 5 KB billed per record (measured): 7 MB/day per collector at 60 s,
  1.4 MB/day at the recommended 300 s.
- **Rust.** C#-only for now. `bower-collector` (Rust) refuses the setting at start-up
  rather than pretend to send records.

| Field (`Attributes.…`) | Meaning |
|---|---|
| `recordVersion`, `intervalSeconds`, `sequence`, `collectorStartedAt`, `countersSince` | Record series and the start of this record's counter window |
| `status`, `problems[]` | `healthy` or `degraded`; bounded codes: `dead-letters`, `backpressure`, `stalled`, `retrying`, `capacity-refusals`, `source-overdue`, `syslog-errors`, `windows-event-log-errors` |
| `delivery.output`, `delivery.status`, `delivery.lastSuccessfulDeliveryAt` | Output type; `idle`, `waiting`, `pending`, `retrying`, `stalled` (oldest > 5 min), `backpressure` (≥ 90 % of the cap), `degraded` (dead letters), `disabled` |
| `queue.queued`, `retrying`, `uploading`, `undelivered`, `deadLettered`, `oldestUndeliveredAt`, `oldestUndeliveredAgeSeconds` | Queue state when the record was written |
| `storage.queueCapacityMiB`, `undeliveredMiB`, `storedMiB`, `capacityUsedPercent` | Undelivered payload against `BOWER_QUEUE_MAX_BYTES` |
| `storage.queueFileMiB`, `queueFileLimitMiB`, `queueFileUsedPercent` | Queue database file against its SQLite page limit (see [defects](#known-defects-found-by-this-work)). **Extension point:** free disk and watermark fields join `storage` additively |
| `intake.attemptedRequests`, `capacityRefusals`, `privacyAlertRefusals`, `lastRefusalAt`, `lastRefusalReason` | Intake in this window |
| `pipeline.eventsIn`, `eventsQueued`, `duplicates`, `suppressed` | Selection in this window (includes the previous health record) |
| `sources.configured`, `expected`, `active`, `pending`, `silent`, `neverSeen`, `overdue[]` | Source expectations; `overdue[]` lists up to 25 by `application`, `environment`, `state`, `silentSeconds`, `allowedSilenceSeconds`, `lastSeenAt` |
| `syslog[]` | Per listener (up to 25): `activeConnections`, and window deltas of `connectionsAccepted`, `connectionsRejected`, `sendersDenied`, `tlsHandshakeFailures`, `framesReceived`, `queued`, `notRouted`, `parserErrors`, `malformed`, `oversized`, `framingErrors`, `timeouts`, `dropped`, `retries`, `submitFailures`, `receiveErrors`; `lastFrameAt` |
| `windowsEventLog[]` | Per subscription (up to 25): `state`, window deltas of `eventsRead`, `queued`, `notSelected`, `parserErrors`, `readErrors`, `gaps`, `resets`, `retries`, `submitFailures`, `cursorConflicts`; `lastEventAt`, `lastPollAt` |

Interpretation: a record's `TimeGenerated` is when it was written and `ingestion_time()`
is when Sentinel stored it, so `ingestion_time() - TimeGenerated` is the end-to-end
delivery delay of the pipeline at that moment.

## Alert catalogue

Azure rules are in [`deploy/sentinel/monitoring/monitoring.bicep`](../../deploy/sentinel/monitoring/monitoring.bicep)
(queries in [`queries/`](../../deploy/sentinel/monitoring/queries)); Sentinel analytics
rules in [`sentinel-health-rules.bicep`](../../deploy/sentinel/monitoring/sentinel-health-rules.bicep).
All log rules run every 5 minutes (one-minute rules are refused by Azure for these
queries), count result rows (`> 0` fires), split by the listed dimensions and auto-resolve.
"Measured" columns come from the [live drill](#how-we-tested-this) with the drill
thresholds; production defaults are in the threshold column.

| ID | Alert (rule name suffix) | Signal and query | Default threshold (drill) | Sev | Rationale | Expected false positives | Measured fire / resolve |
|---|---|---|---|---|---|---|---|
| A1 | `collector-health-missing` | Newest `collector_health` per `CollectorId` ingested longer ago than the threshold; `expectedCollectorIds` also alert when never seen ([KQL](../../deploy/sentinel/monitoring/queries/collector-health-missing.kql)) | 15 min (5) over 2 days | 1 | Only destination-side proof that a collector and its delivery path work | Planned maintenance; decommissioned collector still in `expectedCollectorIds`; new DCR cold start (first rows took 6.5 min) | Fired 310–417 s after stop/outage; resolved 716–884 s after recovery |
| A2 | `dead-letters` | Newest record `queue.deadLettered > 0` ([KQL](../../deploy/sentinel/monitoring/queries/dead-letters.kql)) | > 0 | 2 | Set-aside events never reach Sentinel without an audited replay | Reviewed poison events stay dead-lettered (no purge exists): the alert stays until they are replayed and delivered | Fired 384 s after three poison events |
| A3 | `queue-backlog` | Newest record `oldestUndeliveredAgeSeconds` above threshold, or any record in the window arrived later than the lag threshold ([KQL](../../deploy/sentinel/monitoring/queries/queue-backlog.kql)) | 900 s age, 15 min lag (300 s, 5 min) | 2 | Old events mean late detections; lag shows an outage that just ended | New DCR cold start; deliberate maintenance outages | Fired 243 s after a 12-minute outage drained; resolved 1,204 s later |
| A4 | `queue-storage` | Newest record `queueFileUsedPercent` or `capacityUsedPercent` at or above threshold, delivery `backpressure`, or capacity refusals in the window ([KQL](../../deploy/sentinel/monitoring/queries/queue-storage.kql)) | file 70 %, undelivered 40 % | 2 | Warn before refusals and the page-ceiling stall | File size includes SQLite free pages, so it stays high after retention frees space | Fired 490 s after records showed 92 %; resolved 830 s after the cap was raised. **Did not fire for a queue already full** (see A1) |
| A5 | `source-overdue` | Newest record `sources.overdue[]` ([KQL](../../deploy/sentinel/monitoring/queries/source-overdue.kql)) | per `BOWER_SOURCE_EXPECTATIONS` (3 min) | 2 | Collector's own view of a firewall or WEC that went quiet | Genuinely quiet sources: size each allowance from real traffic | Fired 397–405 s after the source stopped; resolved 913–1,033 s after |
| A6 | `destination-freshness` | Newest non-health row per `CollectorId` and `ApplicationName/Environment` older than its allowance ([KQL](../../deploy/sentinel/monitoring/queries/destination-freshness.kql)) | 60 min, per-source overrides (10 min) | 2 | Independent of collector logic and of health records | Low-volume sources (set overrides); retired sources age out after 2 days. Rows without a Bower identity and archive replays are excluded | Fired 683–843 s after the source stopped; resolved 860–900 s after |
| A7 | `source-transport-errors` | Syslog refusal/TLS/framing/parse/timeout/drop deltas, connection churn above threshold; Windows read errors, gaps, resets or failed state ([KQL](../../deploy/sentinel/monitoring/queries/source-transport-errors.kql)) | any error; churn > 5 new connections per interval | 3 | Loss before acceptance (the pilot lost syslog frames before acceptance) | Scanners hitting the listener; sender restarts; per-message reconnecting senders (raise churn) | Fired 290 s after 10 TLS failures; resolved 1,809 s after the last error |
| A8 | `dcr-errors` | `DCRLogErrors` for the DCR and `_LogOperation` ingestion warnings ([KQL](../../deploy/sentinel/monitoring/queries/dcr-errors.kql)) | any | 2 | Azure accepted the request but failed or dropped rows | Other producers writing to the same DCR | Fired 427 s after invalid requests |
| M1 | `dcr-rows-dropped` (metric) | `RowsDropped_Count` Total | > 0 in 15 min | 1 | Rows silently dropped by Azure | As A8 | Fired 255 s |
| M2 | `dcr-transformation-errors` (metric) | `TransformationErrors_Count` Count | > 0 in 15 min | 1 | Transform failed for some rows | As A8 | Fired 197 s |
| M3 | `dcr-columns-dropped` (metric) | `ColumnsDroppedCount` **Maximum** | > 0 in 15 min | 2 | Stream/table schema drift | None seen. `Count` fires on every request (one sample per request): use `Maximum` | Not triggered in the drill |
| M4 | `dcr-request-errors` (metric) | `ApiCallReceived_Count` excluding `ResponseCode` 200/202/204 | > 0 in 15 min | 2 | Error responses to collectors | Expired or revoked credentials during rotation | Not triggered: the API returned 204 even for malformed bodies (validation is asynchronous) |
| M5 | `dcr-no-ingestion` (metric) | `ApiCallReceived_Count` | < 1 in 30 min | 1 | Whole fleet silent | Fleet maintenance | Fired with no traffic, resolved 4.7 min after the first request |
| S1 | Sentinel: *Bower collector health record missing* | Same query as A1 | 15 min, look-back 1 day (5 min) | High incident | SOC queue, grouped per collector | As A1 | Incident 806 s after a collector stop |
| S2 | Sentinel: *Bower source silent at the destination* | Same query as A6 | 60 min (10 min) | Medium incident | SOC queue per source | As A6 | Incidents created for both genuine and (before the fix) synthetic/replay rows |
| H1 | Host check (Linux and Windows) | `/health`, `/v1/status`, queue file, disk, WEC `wecutil gr` | exit 1/2 | — | Live state while Azure cannot see it | Restarts during deployments | `collector-unreachable` ≤ 65 s; `syslog-errors` 6 s; `capacity-refusals` 22 s; `queue-file` while `/health` still said healthy |
| F1 | Fleet check | `/api/fleet` light per collector | amber → 1, red → 2 | — | Management view: not heard from, cannot deliver, quiet source, set aside | Collectors awaiting approval (ignore that state if needed) | Amber at 7 min, red at 15.4 min after a stop |

## Deploy 1: enable health records on every collector

**Purpose:** make each collector send `collector_health`. **Prerequisites:** collector
build with this change, the policy file above, the queue already delivering to Sentinel.
Recommended interval: **300 s** (60 s in the drill). Thresholds below assume 300 s; with a
different interval keep `healthMissingMinutes` at three intervals or more.

### Linux packages (RPM/DEB, systemd)

```bash
sudo install -m 0640 -o root -g bower \
  examples/policies/collector-health/collector-health.yaml /etc/bower/policies/collector-health.yaml
echo 'BOWER_HEALTH_RECORD_INTERVAL_SECONDS=300' | sudo tee -a /etc/bower/bower.env
sudo systemctl restart bower
journalctl -u bower -n 20 --no-pager      # no "no loaded policy accepts collector_health"
```

Expected: the service is `active`; within one interval a row appears:

```kusto
BowerSecurity_CL
| where EventType == "collector_health" and CollectorId == "<collector id>"
| project TimeGenerated, Ingested = ingestion_time(), Status = tostring(Attributes.status)
| order by TimeGenerated desc | take 5
```

### Windows (MSI service, WEC hosts)

```powershell
Copy-Item .\examples\policies\collector-health\collector-health.yaml "$env:ProgramData\Bower\policies\"
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
$environment = @((Get-ItemProperty $key).Environment | Where-Object { $_ -notlike 'BOWER_HEALTH_RECORD_INTERVAL_SECONDS=*' })
Set-ItemProperty $key -Name Environment -Type MultiString -Value ($environment + 'BOWER_HEALTH_RECORD_INTERVAL_SECONDS=300')
Restart-Service Bower
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.Collector' } -MaxEvents 5
```

### Docker

The image is chiseled (no shell). Mount a policy directory that holds the defaults plus the
health policy, and set the interval:

```bash
mkdir -p ./bower-policies && cp policies/default/*.yaml examples/policies/collector-health/collector-health.yaml ./bower-policies/
docker run -d --name bower --restart unless-stopped --read-only \
  -e BOWER_POLICY_DIRECTORY=/etc/bower/policies -v "$PWD/bower-policies:/etc/bower/policies:ro" \
  -e BOWER_HEALTH_RECORD_INTERVAL_SECONDS=300 ... ghcr.io/<owner>/bower:<version>
```

### Kubernetes ([manifest](../../deploy/kubernetes/deployment.yaml))

```bash
kubectl --context <context> create configmap bower-policies \
  --from-file=policies/default/ --from-file=examples/policies/collector-health/collector-health.yaml
kubectl --context <context> set env deployment/bower-collector \
  BOWER_POLICY_DIRECTORY=/etc/bower/policies BOWER_HEALTH_RECORD_INTERVAL_SECONDS=300
# then mount the ConfigMap at /etc/bower/policies (volumeMounts + volumes) and roll out
kubectl --context <context> rollout status deployment/bower-collector
```

### AWS EC2 and Azure VMs

Use the Linux or Windows steps above on the instance (SSM Run Command or Azure Run Command).
On AWS run `aws sts get-caller-identity` and confirm the account first; on Azure run
`az account show` and confirm the subscription.

**Acceptance:** every collector has a `collector_health` row newer than two intervals.
**Rollback:** set the interval to `0` (or remove the line) and restart; removing the policy
file is optional. **Troubleshooting:**

| Symptom | Cause | Fix |
|---|---|---|
| Collector exits: "no loaded policy accepts collector_health" | Policy file missing or not in `BOWER_POLICY_DIRECTORY` | Copy the file; check the directory setting |
| Rust collector exits: "supported only by the C# collector" | Rust runtime | Use the C# collector or set the interval to `0` |
| Event 1331 "not queued" | A managed privacy profile or validation now refuses the record | Check `bower policy test` with a record; check the profile |
| Event 1330 "refused" | Queue at capacity | Runbook R5 |
| Rows exist but `Attributes` values are strings like `""` | Value masked by privacy (should not happen below eight digits) | Report it; the record clamps numbers to seven digits |

## Deploy 2: Azure Monitor and Sentinel rules

**Purpose:** create the A1–A8, M1–M5 and S1–S2 rules. **Prerequisites:**

- The workspace, DCE and DCR from [`deploy/bicep/main.bicep`](../../deploy/bicep/main.bicep),
  in one resource group.
- Roles: **Monitoring Contributor** on the resource group (log and metric alerts,
  diagnostic setting), **Microsoft Sentinel Contributor** on the workspace (analytics rules).
- An action group, or none (alerts are still recorded in Azure Monitor).
- Health records enabled ([Deploy 1](#deploy-1-enable-health-records-on-every-collector)).
- Note the collector IDs you expect (`BOWER_COLLECTOR_ID`).

Parameters (`monitoring.parameters.json`):

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspaceName": { "value": "<workspace>" },
    "dataCollectionRuleName": { "value": "<prefix>-dcr" },
    "enabled": { "value": true },
    "actionGroupResourceIds": { "value": ["/subscriptions/<sub>/resourceGroups/<rg>/providers/microsoft.insights/actionGroups/<group>"] },
    "expectedCollectorIds": { "value": ["fw-collector-01", "wec-01"] },
    "healthMissingMinutes": { "value": 15 },
    "sourceSilenceMinutes": { "value": 60 },
    "sourceSilenceOverrides": { "value": [ { "application": "windows-security", "environment": "production", "maximumSilenceMinutes": 30 } ] },
    "tags": { "value": { "owner": "secops" } }
  }
}
```

### Bicep with `az`

```bash
az account show --query "{subscription:id, tenant:tenantId}" -o table   # confirm the target
az deployment group what-if -g <rg> --template-file deploy/sentinel/monitoring/monitoring.bicep \
  --parameters @monitoring.parameters.json
az deployment group create -g <rg> -n bower-monitoring \
  --template-file deploy/sentinel/monitoring/monitoring.bicep --parameters @monitoring.parameters.json
az deployment group create -g <rg> -n bower-sentinel-health \
  --template-file deploy/sentinel/monitoring/sentinel-health-rules.bicep \
  --parameters workspaceName=<workspace> enabled=true 'expectedCollectorIds=["fw-collector-01","wec-01"]'
```

### PowerShell (Az module)

```powershell
Get-AzContext | Select-Object Subscription, Tenant                       # confirm the target
New-AzResourceGroupDeployment -ResourceGroupName <rg> -Name bower-monitoring -WhatIf `
  -TemplateFile deploy/sentinel/monitoring/monitoring.bicep -TemplateParameterFile monitoring.parameters.json
New-AzResourceGroupDeployment -ResourceGroupName <rg> -Name bower-monitoring `
  -TemplateFile deploy/sentinel/monitoring/monitoring.bicep -TemplateParameterFile monitoring.parameters.json
New-AzResourceGroupDeployment -ResourceGroupName <rg> -Name bower-sentinel-health `
  -TemplateFile deploy/sentinel/monitoring/sentinel-health-rules.bicep -workspaceName <workspace> -enabled $true
```

(`New-AzResourceGroupDeployment` needs the Bicep CLI on `PATH`; or run
`az bicep build --file deploy/sentinel/monitoring/monitoring.bicep` and deploy the ARM JSON.)

### Portal

1. Run `az bicep build --file deploy/sentinel/monitoring/monitoring.bicep --outfile monitoring.json`.
2. Portal → **Deploy a custom template** → **Build your own template in the editor** →
   **Load file** `monitoring.json` → **Save** → choose the resource group, fill the
   parameters → **Review + create**.
3. Or create one rule by hand: Monitor → Alerts → **Create alert rule** → scope the
   workspace → condition **Custom log search** → paste the KQL from `queries/` with the
   `__PLACEHOLDERS__` replaced → measurement **Table rows**, aggregation granularity
   equal to the window → **Split by dimensions** as in the catalogue → operator **Greater
   than** 0 → frequency 5 minutes → **Automatically resolve alerts** on.
4. Sentinel → Analytics → **Create → Scheduled query rule** with the same KQL, entity-free,
   custom details `CollectorId` (and `Source`), alert grouping per result.

### Verify

```bash
az monitor scheduled-query list -g <rg> --query "[?starts_with(name,'bower')].{name:name,enabled:enabled,frequency:evaluationFrequency}" -o table
az monitor metrics alert list -g <rg> --query "[?starts_with(name,'bower')].{name:name,enabled:enabled}" -o table
az monitor diagnostic-settings list --resource <dcr resource id> -o table   # <prefix>-dcr-errors, LogErrors
```

**Acceptance:** 8 log rules (7 without a DCR name), 5 metric rules, the diagnostic setting
and 2 Sentinel rules exist and are enabled. With healthy collectors, no alert is fired
after 30 minutes except `collector-health-missing` for expected collectors that are not
yet sending. **Rollback:** redeploy with `enabled=false`, or delete the rules
(`az monitor scheduled-query delete`, `az monitor metrics alert delete`,
`az sentinel alert-rule delete`/portal). Rules hold no data; deleting them is safe.

| Deployment problem | Cause | Fix |
|---|---|---|
| "One-minute frequency is not supported for this query" | Azure limits one-minute rules | Use `PT5M` (the template no longer offers `PT1M`) |
| "WindowSize of 2880 minutes is not supported for one minute alert rules" | Same | Same |
| Sentinel: "When queryPeriod ≥ 2 days, queryFrequency should be ≥ 1 hour" | Sentinel limit | Keep `queryPeriod` at `P1D`, or use `PT1H` frequency |
| `dcr-errors` validation error for `DCRLogErrors` | Table appears after the first error | The rule skips validation; this is expected |
| `dcr-columns-dropped` fires constantly | `Count` aggregation counts one sample per request | Use the template (aggregation `Maximum`) |
| Alerts never resolve | Azure resolves only after about three healthy evaluations | Expect 12–20 minutes after recovery (measured) |

## Deploy 3: host-side checks and watchdogs

### Linux (systemd)

Files: [`bower-healthcheck.py`](../../deploy/sentinel/monitoring/host/bower-healthcheck.py)
(Python 3.9+ standard library), [`bower-healthcheck.service`](../../deploy/sentinel/monitoring/host/bower-healthcheck.service),
[`bower-healthcheck.timer`](../../deploy/sentinel/monitoring/host/bower-healthcheck.timer),
[`bower-monitoring.conf`](../../deploy/sentinel/monitoring/host/bower-monitoring.conf) (drop-in).

```bash
sudo install -d -m 0755 /opt/bower/monitoring
sudo install -m 0755 deploy/sentinel/monitoring/host/bower-healthcheck.py /opt/bower/monitoring/
sudo install -m 0644 deploy/sentinel/monitoring/host/bower-healthcheck.{service,timer} /etc/systemd/system/
sudo install -d /etc/systemd/system/bower.service.d
sudo install -m 0644 deploy/sentinel/monitoring/host/bower-monitoring.conf /etc/systemd/system/bower.service.d/10-monitoring.conf
grep -q '^BOWER_QUEUE_PATH=' /etc/bower/bower.env || echo 'BOWER_QUEUE_PATH=/var/lib/bower/queue.db' | sudo tee -a /etc/bower/bower.env
sudo systemctl daemon-reload && sudo systemctl enable --now bower-healthcheck.timer && sudo systemctl restart bower
sudo -u bower python3 /opt/bower/monitoring/bower-healthcheck.py --token-file /etc/bower/secrets/ingest-token --format json
```

Expected: `{"status": "OK", ...}` and exit 0. Each minute the timer writes one line to the
journal (`SyslogIdentifier=bower-healthcheck`) and `/var/lib/bower/healthcheck.prom`. A
WARNING or CRITICAL run marks `bower-healthcheck.service` failed (`systemctl --failed`).
The drop-in sets `Restart=always` (measured: SIGKILL → serving again in 6.3 s) with a start
limit of 20 per 10 minutes.

| Check (code) | Level | Default |
|---|---|---|
| `collector-unreachable` | CRITICAL | `/health` did not answer |
| `health-degraded` | WARNING | `/health` says degraded |
| `dead-letters` | WARNING | any |
| `backlog` | WARNING / CRITICAL | 900 s / 3600 s |
| `queue-storage` | WARNING / CRITICAL | 40 % / 60 % of `BOWER_QUEUE_MAX_BYTES` |
| `queue-file` | WARNING / CRITICAL | 70 % / 85 % of the page limit `(4 × cap + 16 MiB) / 4` |
| `capacity-refusals` | CRITICAL | a refusal in the last 900 s |
| `source-overdue` | WARNING | per expectation |
| `syslog-errors`, `syslog-churn` | WARNING | new errors; more than 5 new connections per run |
| `windows-event-log` | CRITICAL / WARNING | failed state / new read errors |
| `disk-free` | WARNING / CRITICAL | 20 % / 10 % free on the queue volume |
| `status-unavailable` | UNKNOWN (3) | token given but `/v1/status` unreadable |

Ship it:

- **Prometheus:** node_exporter `--collector.textfile.directory=/var/lib/bower` (or copy
  the file), alert on `bower_check_status >= 1`, `bower_up == 0`,
  `bower_queue_oldest_undelivered_age_seconds > 900`, `bower_queue_file_limit_used_percent > 70`.
- **CloudWatch agent (EC2):** collect the journal lines into a log group, then a metric
  filter and alarm:

  ```bash
  aws logs put-metric-filter --log-group-name /bower/healthcheck --filter-name bower-critical \
    --filter-pattern '"CRITICAL:"' --metric-transformations metricName=BowerCritical,metricNamespace=Bower,metricValue=1
  aws cloudwatch put-metric-alarm --alarm-name bower-critical --namespace Bower --metric-name BowerCritical \
    --statistic Sum --period 300 --evaluation-periods 1 --threshold 0 --comparison-operator GreaterThanThreshold \
    --treat-missing-data notBreaching
  ```

  (Agent config: `"logs": {"logs_collected": {"files": {"collect_list": [{"file_path": "/var/log/bower-healthcheck.log", ...}]}}}`
  with `StandardOutput=append:/var/log/bower-healthcheck.log` in a drop-in, or the agent's journald input where available.)
- **Azure Monitor Agent (Azure VM, Arc):** a DCR collecting `Syslog` (facility `daemon`,
  level Warning+) picks up the journal lines through rsyslog; alert with
  `Syslog | where ProcessName == "bower-healthcheck" and SyslogMessage startswith "CRITICAL"`.

### Windows (service recovery, scheduled task, Event Log)

The MSI already sets restart on failure (5 s, three times, reset daily; measured: process
killed → serving again in 6.3 s). Install the check
([`Test-BowerCollectorHealth.ps1`](../../deploy/sentinel/monitoring/host/Test-BowerCollectorHealth.ps1)):

```powershell
New-Item -ItemType Directory "$env:ProgramData\Bower\monitoring" -Force | Out-Null
Copy-Item .\deploy\sentinel\monitoring\host\Test-BowerCollectorHealth.ps1 "$env:ProgramData\Bower\monitoring\"
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$env:ProgramData\Bower\monitoring\Test-BowerCollectorHealth.ps1`" " +
  "-TokenFile `"$env:ProgramData\Bower\secrets\ingest-token`" -WecSubscription <subscription> " +
  "-StateFile `"$env:ProgramData\Bower\monitoring\healthcheck-state.json`" -WriteEventLog"
Register-ScheduledTask -TaskName BowerHealthCheck -User SYSTEM -RunLevel Highest -Force `
  -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument $arguments) `
  -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) `
  -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew)
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Bower.HealthCheck' } -MaxEvents 3
```

Events: 9100 OK, 9101 WARNING, 9102 CRITICAL, 9103 UNKNOWN. Collect them with an AMA DCR
XPath `Application!*[System[Provider[@Name='Bower.HealthCheck'] and (EventID=9101 or EventID=9102)]]`
(and `Provider[@Name='Bower.Collector']` for collector warnings), then alert on
`Event | where Source == "Bower.HealthCheck" and EventID == 9102`. On EC2, the CloudWatch
agent's `windows_events` input does the same. `-WecSubscription` adds `wecutil gr` state:
`wec-subscription` (CRITICAL unless `Active`) and `wec-source` (an event source not
`Active`).

### Docker

The chiseled image has no shell, so there is no in-container `HEALTHCHECK`. Keep
`restart: unless-stopped` and run the Linux check on the Docker host against the published
loopback port; point `--queue-path` at the volume:

```bash
python3 bower-healthcheck.py --url http://127.0.0.1:4319 --token-file /etc/bower/ingest-token \
  --queue-path "$(docker volume inspect -f '{{ .Mountpoint }}' <project>_bower-data)/queue.db" --queue-max-bytes <cap>
docker inspect -f '{{.State.Status}} restarts={{.RestartCount}}' bower
docker logs --since 15m bower 2>&1 | grep -E 'warn:|fail:'
```

### Kubernetes

The manifest now has a **liveness probe** on `/health` (restarts only a hung process:
`/health` answers 200 when degraded) besides the readiness probe. Watch restarts and logs:

```bash
kubectl --context <context> get pods -l app.kubernetes.io/name=bower-collector
kubectl --context <context> describe pod <pod> | grep -A3 -E 'Liveness|Readiness|Last State'
kubectl --context <context> logs deploy/bower-collector --since=15m | grep -E 'warn:|fail:'
kubectl --context <context> port-forward deploy/bower-collector 4319:4319   # then run the host check locally
```

**Acceptance (all hosts):** the check runs every minute, exits 0 on a healthy collector,
and its WARNING/CRITICAL output reaches your monitoring system. **Rollback:** disable the
timer or task (`systemctl disable --now bower-healthcheck.timer`,
`Unregister-ScheduledTask BowerHealthCheck`) and remove the drop-in.

## Deploy 4: management fleet check

The management plane already computes one state per collector from heartbeats. The
[fleet check](../../deploy/sentinel/monitoring/fleet/bower-fleet-check.py) turns it into an
exit code. Run it from a monitoring host with a Viewer token, never written to disk:

```bash
export BOWER_TOKEN="$(az account get-access-token --resource api://<management-app-id> --query accessToken -o tsv)"
python3 deploy/sentinel/monitoring/fleet/bower-fleet-check.py --url https://<management-host> \
  --token-env BOWER_TOKEN --ignore-state waiting-for-approval --format json
unset BOWER_TOKEN
```

Exit 2 when any collector is red ("Not heard from" for more than 15 minutes, "Can't
deliver" for more than 15 minutes, history changed), 1 when amber, 3 when the API is
unreachable. Schedule it every 5 minutes (cron, Azure Automation, a Kubernetes CronJob with
workload identity). Management unavailability never stops collection; treat exit 3 as a
management incident, not a collector incident.

## Runbooks

Each runbook: trigger, impact, diagnosis per environment, recovery, verification. Start
with the Azure alert's `CollectorId` (and `Source`), then use the host and management
paths. Never delete queue files, reset the queue or disable policy to clear an alert.

Common diagnosis commands:

| Environment | Service state | Logs | Collector status |
|---|---|---|---|
| Linux (RPM/DEB) | `systemctl status bower --no-pager` | `journalctl -u bower --since -30min --no-pager` | `curl -s -H "Authorization: Bearer $(sudo cat /etc/bower/secrets/ingest-token)" http://127.0.0.1:4319/v1/status \| python3 -m json.tool` |
| Windows (MSI) | `Get-Service Bower; sc.exe qfailure Bower` | `Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Bower.Collector';StartTime=(Get-Date).AddMinutes(-30)}` | `Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers @{Authorization="Bearer $((Get-Content $env:ProgramData\Bower\secrets\ingest-token -Raw).Trim())"}` |
| WEC host | `wecutil es; wecutil gr <subscription>` | `Get-WinEvent -LogName 'Microsoft-Windows-EventCollector/Operational' -MaxEvents 20` | `Get-WinEvent -LogName ForwardedEvents -MaxEvents 1` |
| Docker | `docker ps -a --filter name=bower` | `docker logs --since 30m bower` | host check against `127.0.0.1:4319` |
| Kubernetes | `kubectl get pods -l app.kubernetes.io/name=bower-collector` | `kubectl logs deploy/bower-collector --since=30m` | `kubectl port-forward` then the host check |
| AWS EC2 | `aws ec2 describe-instance-status --instance-ids <id>`; SSM `AWS-RunShellScript`/`AWS-RunPowerShellScript` with the commands above | CloudWatch Logs group | as Linux/Windows via SSM |
| Azure VM | `az vm get-instance-view -g <rg> -n <vm> --query instanceView.statuses` | `az vm run-command invoke ... --scripts "journalctl -u bower -n 50"`; AMA `Syslog`/`Event` tables | as Linux/Windows via Run Command |

### R1 Collector health record missing (A1, S1, M5)

**Impact:** no security events from that collector reach Sentinel; either the collector
or host is down, or delivery fails. Events keep queueing locally while the collector runs.

1. Is the collector running? Host check / `systemctl status bower` / `Get-Service Bower`
   / pod status. If stopped: start it (`systemctl start bower`, `Start-Service Bower`) and
   read the last error before it stopped. On AWS/Azure check the instance itself first.
2. If running, is it delivering? `/v1/status`: `queue.oldestUndelivered` growing and
   `retrying`/`uploading` non-zero means delivery fails. Logs: repeated 1001 with a
   `destination-azure-*` code (network, DNS, proxy, firewall to `*.ingest.monitor.azure.com`
   and `login.microsoftonline.com`), credential errors (expired certificate or secret,
   managed identity removed), HTTP 403 (role assignment *Monitoring Metrics Publisher* on
   the DCR removed). Check the DCR metrics (`ApiCallReceived_Count` by `ResponseCode`).
3. Repeated 1002 `SqliteException` every 5 s: the queue file is full; go to R5.
4. If every collector is missing (M5 fired): suspect the DCE/DCR, the workspace or tenant-wide
   network; check Azure status and `_LogOperation`.
5. Recover the cause. The backlog drains automatically (measured: 2,479 events in 4.3 s).

**Verify:** a new `collector_health` row within one interval; A3 (`queue-backlog`) may fire
once for the drained backlog and then resolve; A1 resolves after about 15 minutes.

### R2 DCR or ingestion errors (A8, M1–M4)

**Impact:** Azure accepted requests but dropped or failed rows, or rejected requests.

1. `DCRLogErrors | where TimeGenerated > ago(1h) | summarize count() by OperationName, InputStreamId`
   (read messages in the workspace; they can echo submitted values).
2. Schema drift: compare the deployed DCR with the generated one:
   `bower dcr diff` ([doctor and DCR](../operations/doctor-and-dcr.md)); the stream and
   table must match `SentinelSchema.Default`.
3. Non-Bower producers writing to the same DCR (as in the drill's synthetic requests) also
   raise these alerts; identify them by `CollectorId`.
4. Error responses (M4): 401/403 credential or role problems (R1 step 2), 413 size, 429
   throttling (the collector backs off; sustained 429 means capacity planning).
5. Fix the DCR with the reviewed template (`deploy/bicep/main.bicep`), never by hand.

**Verify:** metrics return to zero; `RowsReceived_Count` tracks collector traffic.

### R3 Events set aside (A2)

**Impact:** dead-lettered events are not delivered. Bower dead-letters only poison events
(Azure would truncate or reject them, for example `preflight-field-too-large`, invalid
JSON, payload too large, an isolated HTTP 400) or events whose non-destination failures
exhausted `BOWER_MAX_DELIVERY_ATTEMPTS`. Destination outages never dead-letter.

1. List them (read-only, collector stopped or not):
   `bower queue dead-letters --database /var/lib/bower/queue.db --max 100`
   (Windows: `& "$env:ProgramFiles\Bower\bower.exe" queue dead-letters --database "$env:ProgramData\Bower\state\queue.db"`).
2. Group by failure code. Fix the producer or pack for `preflight-*` codes first: replaying
   unchanged poison events dead-letters them again (measured).
3. When the cause is fixed (for example a corrected DCR, or an upgraded collector), run the
   [audited replay](#dead-letter-replay-audited-offline).

**Verify:** `queue.deadLettered` returns to 0; A2 resolves. Poison events that can never be
delivered keep the collector `degraded` and A2 fired: record the decision in the change
ticket and close the Azure alert manually; there is no purge command by design.

### R4 Old queued events (A3)

**Impact:** detections run late. Causes: a delivery outage that just ended (lag), slow or
throttled delivery, or a stuck lease.

1. Newest health record: `queue.oldestUndeliveredAgeSeconds`, `delivery.status`.
2. `retrying` with 429/5xx codes: Azure throttling or an incident; check M4 and Azure status.
3. `stalled` with no progress: check the network and credentials (R1) and the queue file (R5).
4. Only lag (age near 0 now): a past outage. Record its duration from the health records:

   ```kusto
   BowerSecurity_CL
   | where EventType == "collector_health" and CollectorId == "<id>" and TimeGenerated > ago(6h)
   | project TimeGenerated, Lag = ingestion_time() - TimeGenerated, Age = toint(Attributes.queue.oldestUndeliveredAgeSeconds)
   ```

5. Scheduled detections that ran during the outage missed the late events: rerun them over
   the outage window (with the dedup query below).

### R5 Storage pressure (A4, host `queue-file`/`queue-storage`/`capacity-refusals`/`disk-free`)

**Impact:** at the limit, intake is refused (HTTP 503; syslog TCP and Windows Event Log stop
reading and retry, UDP drops). **Known defect:** when the queue *file* reaches its page
limit, delivery can stall too ([details](#known-defects-found-by-this-work)).

1. Host check or health record: which signal? `queue-file` (file against page limit),
   `queue-storage` (undelivered against the cap), `disk-free` (volume).
2. Delivery stalled (1002 `SqliteException` every 5 s, `uploading` stuck, refusals with zero
   undelivered)? Apply the **verified recovery**: raise the cap, which raises the page limit,
   and restart. Nothing is deleted:

   ```bash
   # Linux: double the cap (bytes); keep it within the volume's free space
   sudo sed -i 's/^BOWER_QUEUE_MAX_BYTES=.*/BOWER_QUEUE_MAX_BYTES=<new bytes>/' /etc/bower/bower.env
   grep -q '^BOWER_QUEUE_MAX_BYTES=' /etc/bower/bower.env || echo 'BOWER_QUEUE_MAX_BYTES=<new bytes>' | sudo tee -a /etc/bower/bower.env
   sudo systemctl restart bower
   ```

   ```powershell
   $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
   $environment = @((Get-ItemProperty $key).Environment | Where-Object { $_ -notlike 'BOWER_QUEUE_MAX_BYTES=*' })
   Set-ItemProperty $key -Name Environment -Type MultiString -Value ($environment + 'BOWER_QUEUE_MAX_BYTES=<new bytes>')
   Restart-Service Bower
   ```

   Measured: a stalled 2,479-event backlog drained 4.3 s after the restart; a queue that
   refused every event with zero backlog accepted again immediately.
3. No stall yet: find what fills the file. Retained acknowledged rows count against the page
   limit for `BOWER_QUEUE_RETENTION_HOURS` (default 168). At 10 events/s that is several
   GiB a week. Lower the retention (keeping your replay needs) or raise the cap, and size
   the volume for `4 × cap + 16 MiB`.
4. Undelivered data high: R1/R4 first (the cause is usually delivery).
5. Disk low: free space on the volume; never delete `queue.db*` files.

**Verify:** `queueFileUsedPercent` and `capacityUsedPercent` fall below the thresholds;
`intake.capacityRefusals` stays 0; A4 resolves (measured 830 s).

### R6 Source silent (A5, A6, S2)

**Impact:** a firewall or WEC stopped sending, or its path to Bower broke; detections for
that source see nothing.

Firewall (syslog over mutual TLS):

1. `/v1/status` → `syslog[]`: `activeConnections` 0 and `lastFrameAt` old means the sender
   is not connected; check the sender (rsyslog: `systemctl status rsyslog`,
   `journalctl -u rsyslog`, the action queue directory), the network and the certificates.
2. Connected but no frames: the firewall stopped logging, or its rule changed.
3. Frames arriving but `notRouted`/`parserErrors` growing: the route (`appName`/`hostname`)
   or pack parser no longer matches the sender's format.
4. Connections refused (`tlsHandshakeFailures`, `sendersDenied`): R7.

Windows WEF/WEC:

1. On the WEC: `wecutil gr <subscription>` → `RunTimeStatus` should be `Active` for the
   subscription and every event source; `LastError` non-zero shows the cause. The drill
   showed `Access is denied` (WSMan fault 5) until the WEC and WinRM services were restarted
   after adding `NETWORK SERVICE` to *Event Log Readers*. Disabled: `wecutil ss <subscription> /e:true`.
2. `Get-WinEvent -LogName ForwardedEvents -MaxEvents 1`: newest forwarded event time.
3. Sources: `Microsoft-Windows-Forwarding/Operational` on each source (event 100/105
   success, 102/103 errors), Group Policy (`gpresult /h`), WinRM (`winrm qc`), and the
   subscription ACL (Domain Controllers group for DCs).
4. Bower side: `windowsEventLog[]` `state` (`running`), `readErrors`, `lastEventAt`;
   `winevt-access-denied` means `NT SERVICE\Bower` lost read access to `ForwardedEvents`
   (`wevtutil gl ForwardedEvents` channel access).

**Verify:** new rows from the source; A5/A6 resolve about 15 minutes later. Adjust
`BOWER_SOURCE_EXPECTATIONS` or `sourceSilenceOverrides` for sources that are legitimately
quiet, with a change record.

### R7 Source loss indicators (A7; host `syslog-errors`, `syslog-churn`, `wec-*`)

**Impact:** events may be lost **before** Bower accepts them; syslog has no
application-level acknowledgement, so the sender's buffer is the only copy.

1. TLS failures/refusals: certificate expiry or rotation, an untrusted sender, or a scanner.
   `openssl s_client -connect <collector>:6514 -cert <client.pem> -key <client-key.pem> -CAfile <ca.pem>`.
2. Churn: the sender reconnects per message or after errors. The pilot lost events with
   `RebindInterval="1"`; use a persistent connection and a bounded listener idle timeout.
3. `timeouts`/`framingErrors`: idle timeouts or a non-octet-counted sender.
4. `dropped` (UDP): buffer or capacity; prefer TLS.
5. WEC: R6 Windows steps.
6. **Sender queues are invisible to Bower.** When Bower back-pressures a sender (queue
   full, delivery stalled, collector stopped), the sender's own queue is the only copy.
   Monitor it: for rsyslog add `module(load="impstats" interval="60" format="json"
   log.syslog="on")` and alert on the action queue's `size`, `discarded.full` and
   `discarded.nf`, and on queue files under `/var/lib/rsyslog` that stop shrinking. In
   the drill, rsyslog's disk-assisted queue (the pilot's sender profile) held about 2,970
   frames during Bower back-pressure, never forwarded them, and dropped them on restart.
7. After fixing, reconcile counts for the affected window (sender counters, or native log
   lines, vs `syslog[].queued` and Sentinel), and record any unrecoverable loss.

### R8 Management: collector not heard from (F1)

1. Is it also missing in Azure (A1)? If yes, R1. If no (delivering but no heartbeat):
   the management channel only is broken. Logs 1101/1102/1103, proxy and CA bundle
   settings, enrolment credential (`rotate-credential`), suspension in the console.
2. "Paused" or "Removed": an administrator action; check the Audit page.
3. Management API down (fleet check exit 3): restart it; collectors keep collecting.

## Audited replay

Replay is the only way to re-send events after the fact. Both procedures below are audited
(intent recorded before acting, outcome after) and were exercised live.

### Dead-letter replay (audited, offline)

Uses [`tools/audited-replay/replay.py`](../../tools/audited-replay/replay.py) (Python
standard library, POSIX) around `bower queue replay`, which returns exact reviewed
dead-lettered IDs to the queue. The collector must be stopped (offline queue).

Prerequisites: an approved change reference, the reviewed IDs (at most 100), a private
audit parent directory (0700, owned by the operator), the trusted compiled CLI.

```bash
sudo install -d -m 0700 /var/lib/bower-audit
sudo systemctl stop bower
sudo /opt/bower/bower queue dead-letters --database /var/lib/bower/queue.db --max 100     # review IDs and codes
sudo python3 tools/audited-replay/replay.py --cli /opt/bower/bower --database /var/lib/bower/queue.db \
  --audit-directory /var/lib/bower-audit/<CHANGE-REF> --operator <operator-id> --change-reference <CHANGE-REF> \
  --event <id-1> --event <id-2>
sudo cat /var/lib/bower-audit/<CHANGE-REF>/intent.json /var/lib/bower-audit/<CHANGE-REF>/outcome.json
sudo systemctl start bower
sudo /opt/bower/bower queue verify --database /var/lib/bower/queue.db    # "Ledger intact."
```

Windows: the tool is POSIX-only. Record intent (operator, change, IDs, time, CLI hash) in
the change ticket first, stop the service, run
`& "$env:ProgramFiles\Bower\bower.exe" queue replay --database "$env:ProgramData\Bower\state\queue.db" --max <n> --event <id> ...`,
record the outcome, start the service.

Rules: never reuse an audit directory (the tool refuses it, and so must a manual wrapper; the
drill preserved an empty directory from a failed wrapper run and used a new reference);
never retry automatically; a zero exit proves neither replay counts nor delivery. Verify in
Sentinel with the reviewed IDs:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(7d) and EventId in ("<id-1>", "<id-2>")
| summarize Rows = count(), Collectors = make_set(CollectorId) by EventId
```

### Archive replay (re-delivering acknowledged events)

When destination data was lost or a workspace restored, replay from the
[verified archive](../operations/suppression-archive-and-source-silence.md#archive-and-replay)
through a **separate, loopback-only replay collector with its own queue** (the original
queue would answer duplicates). Each replayed event carries `Labels.bowerReplay = "archive"`
and the replay collector's `CollectorId`.

1. Record intent: operator, change reference, window, event types, `bower archive verify`
   output (head sequence and hash), and a `--dry-run` count.
2. Start the replay collector (`BOWER_COLLECTOR_ID=<id>-replay`, `BOWER_LISTEN_URL=http://127.0.0.1:4329`,
   its own `BOWER_QUEUE_PATH`, the same output and packs, `BOWER_SINGLE_TRUST_DOMAIN=true`
   on loopback only).
3. `BOWER_INGEST_TOKEN=<token> bower archive replay --archive <dir> --collector-url http://127.0.0.1:4329 --from <ISO> --to <ISO> --event-type <type>`
4. Record the outcome (CLI summary: `selected`, responses by status code). Stop the replay
   collector when its queue is empty.
5. Verify and deduplicate. **Deduplicate by `EventId` alone**: the replayed copy has a
   different `CollectorId`, so the pilot's `by CollectorId, EventId` does not collapse it
   (measured: 238 rows instead of 119):

   ```kusto
   BowerSecurity_CL
   | where TimeGenerated between (datetime(<from>) .. datetime(<to>))
   | extend BowerIngested = ingestion_time()
   | summarize arg_max(BowerIngested, *) by EventId
   ```

Drill result: 119 events selected and accepted (HTTP 202), all delivered; every `EventId`
had exactly 2 rows (original and replay), the two identity sets had the same SHA-256
digest, and the query above returned exactly 119. Alerts and detections should exclude or
deduplicate `Labels.bowerReplay` rows; the freshness rules already ignore them.

## Escalation

| Severity | Examples | Respond | Escalate to |
|---|---|---|---|
| Sev 1 / Sentinel High | A1 for a production collector, M1/M2, M5, fleet red | 15 minutes, 24×7 | Collector owner (platform), then Security Operations lead; Microsoft support for Azure ingestion incidents |
| Sev 2 / Medium | A2–A6, A8, M3, M4 | Same business day | Collector owner; source owner (firewall/Windows team) for A5/A6 |
| Sev 3 | A7, host WARNING | Next business day | Source owner; network/PKI for TLS failures |
| Data loss suspected | Unrecoverable source loss, poison events discarded, replay ambiguity | Immediately | Security Operations lead and the data owner; record in the incident |

Record for every incident: alert id, `CollectorId`, start and end of impact (from health
records and `ingestion_time()`), actions with change references, and whether a replay or a
detection rerun was needed.

## Weekly operational checklist

1. Every expected collector has a `collector_health` row in the last 15 minutes:
   `BowerSecurity_CL | where EventType == "collector_health" | summarize max(ingestion_time()) by CollectorId`.
2. No fired or unresolved Bower alerts older than a week (`az monitor alert` / Alerts blade);
   review every alert of the week against its runbook.
3. Dead letters: zero, or each one documented with a decision.
4. Storage: `queueFileUsedPercent` peak under 50 % and `capacityUsedPercent` under 20 %
   for each collector; disk free over 30 %.
5. Delivery delay: p95 of `ingestion_time() - TimeGenerated` for health records under
   2 minutes outside known outages.
6. Sources: `BOWER_SOURCE_EXPECTATIONS` and `sourceSilenceOverrides` still match the
   firewalls and WEC subscriptions in service; `wecutil gr` shows every source `Active`.
7. Host checks ran every minute (`journalctl -u bower-healthcheck --since -7d | grep -c OK`;
   Bower.HealthCheck events); fleet check exit codes reached your monitoring system.
8. Certificates and credentials (syslog server/client, DCR publisher, management) expire
   more than 30 days from now.
9. Test one alert end to end (for example stop a lab collector) and confirm the notification
   path still reaches the on-call rota.
10. Archive verifies (`bower archive verify --anchor <witnessed head>`) where an archive is used.

## Dashboard queries

Use these in a Sentinel workbook (one query per tile) or the Logs blade.

```kusto
// Collector overview: newest health record per collector
BowerSecurity_CL
| where EventType == "collector_health" and TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, Attributes) by CollectorId
| project CollectorId, LastRecord = TimeGenerated, Status = tostring(Attributes.status),
    Problems = tostring(Attributes.problems), Delivery = tostring(Attributes.delivery.status),
    Undelivered = toint(Attributes.queue.undelivered), OldestAge = toint(Attributes.queue.oldestUndeliveredAgeSeconds),
    QueueFilePercent = todouble(Attributes.storage.queueFileUsedPercent), DeadLettered = toint(Attributes.queue.deadLettered)
```

```kusto
// Delivery delay and backlog over time
BowerSecurity_CL
| where EventType == "collector_health" and TimeGenerated > ago(1d)
| extend DelaySeconds = datetime_diff('second', ingestion_time(), TimeGenerated),
    Undelivered = toint(Attributes.queue.undelivered)
| summarize max(DelaySeconds), max(Undelivered) by CollectorId, bin(TimeGenerated, 5m)
| render timechart
```

```kusto
// Events per source per hour (spot silent or noisy sources)
BowerSecurity_CL
| where TimeGenerated > ago(7d) and EventType !in ("collector_health", "collector_canary")
| summarize Events = count() by Source = strcat(ApplicationName, "/", ApplicationEnvironment), bin(TimeGenerated, 1h)
| render timechart
```

## How we tested this

Full evidence: [`docs/evidence/ws6-20261031-074751`](../evidence/ws6-20261031-074751/README.md).
Run `bower-ws6-20261031-074751`, 31 October 2026. Azure: fresh workspace with Microsoft
Sentinel, `BowerSecurity_CL`, DCE and DCR from the repo Bicep, Azure Monitor rules at
five-minute frequency with drill thresholds, Sentinel rules, an action group without
receivers. AWS: one private Amazon Linux 2023 `t3.small` (RPM-layout collector under
systemd, nftables denies → rsyslog → RFC 5424 over mutual TLS, management API with
development authentication on loopback) and one private Windows Server 2022 `t3.medium`
(collector as `NT SERVICE\Bower`, real Security 4625 failures → collector-initiated WEC
subscription → `ForwardedEvents`). Collectors were built from this branch (managed
self-contained publish, not Native AOT, unsigned).

| Scenario | Fault | Result |
|---|---|---|
| D1 silent sources | Firewall generator stopped; WEC subscription disabled | A5 fired 405 s / 397 s; A6 691 s / 683 s; host warnings at 203 s and within one minute; fleet "Needs a check"; all resolved ~15 min after recovery. **Passed** |
| D2 loss indicators | 10 unauthenticated TLS/plain connections; 8 sender reconnects | A7 fired 290 s; host `syslog-errors` 6 s. **Passed** |
| D3 delivery failure | Collector HTTPS blocked 12 min | A1 fired 310 s; A3 fired 243 s after the backlog drained. **Passed** |
| D4 queue cap | 4,500 packets at 200/s into a 4 MiB queue during the outage | Host `capacity-refusals` CRITICAL 22 s after the first refusal; **A4 did not fire** (records refused while full, counters reset by the recovery restart); delivery **stalled** at the page limit until the cap was raised (drained in 4.3 s). **Partially failed; defect found** |
| D4b storage early warning | Retained rows filled the page budget with no backlog | A4 fired 490 s after records showed 92 %; host `queue-file` CRITICAL while `/health` was healthy; then refusals with zero backlog; cap raised. **Passed (alert); defect confirmed** |
| D5 collector down | Windows service stopped; process kills on both hosts | A1 fired 335 s; SCM and systemd restarted killed collectors in 6.3 s each. **Passed** |
| D6 DCR errors | Malformed synthetic requests to the DCR | Requests answered 204; M2 197 s, M1 255 s, A8 427 s. M4 not triggered. **Passed (M4 not exercised)** |
| D7 dead letters and replay | 3 oversized synthetic events; audited replay; archive replay of 119 events | A2 fired 384 s; replay audit trail complete, poison events re-dead-lettered, 0 destination rows; archive replay 119/119 delivered, dedup by `EventId` exact. **Passed** |
| M collector stop (16 min) | Linux collector stopped | A1 394 s; A6 843 s; Sentinel incident 806 s; fleet amber 7 min, red 15.4 min; host CRITICAL within a minute. **Passed** |
| Accounting | All drills, firewall path | Accepted 7,092 = Sentinel 7,092 (same SHA-256): no loss after acceptance. Native 10,069: 2,977 lost before acceptance in the sender ([defect 4](#known-defects-found-by-this-work)) |

## Known defects found by this work

1. **Queue page ceiling stalls delivery (C# persistence; reported to the storage
   workstream).** `SqliteEventStore` sets `PRAGMA max_page_count` to
   `(4 × BOWER_QUEUE_MAX_BYTES + 16 MiB) / 4`, about the logical cap plus 4 MiB, while the
   file also holds indexes, the ledger and acknowledged rows retained for
   `BOWER_QUEUE_RETENTION_HOURS`. Measured overhead was 1.6–1.9 × payload, so the file
   reaches the limit at roughly half the logical cap (sooner with retained rows). Then
   (a) enqueue fails with SQLite error 13 (reported as capacity refusals) and (b) the
   delivery loop's lease and settlement writes fail too (`Delivery loop failed with
   SqliteException`, event 1002, every 5 s): **delivery does not resume when the
   destination returns**, and a restart does not help. Reproduced live twice and in a
   local unit-test reproduction
   ([evidence](../evidence/ws6-20261031-074751/README.md#queue-page-ceiling-defect)).
   Workaround: raise the cap and restart (R5). Fix belongs with the queue/storage work:
   reserve page headroom for delivery state transitions and count retained rows.
2. **The Azure storage alert cannot see a full queue.** Health records are refused like any
   event at capacity. A1 covers the full-queue case; A4 is an early warning.
3. **Archive replays are not collapsed by `by CollectorId, EventId`.** Use `by EventId`.
4. **Sender-side loss under back-pressure (outside Bower; reported to the syslog
   workstream).** Over the drill, the kernel logged 10,069 denied packets before 10:20 UTC
   and Bower accepted 7,092. Every accepted event reached Sentinel (identical identity
   digest), so all 2,977 missing events were lost before acceptance, inside the lab's
   rsyslog sender. 2,280 were lost during the burst into a refusing queue, 439 while
   delivery was stalled and 252 around the second saturation. A 16-minute collector stop
   with an in-memory sender queue lost none. Bower's back-pressure is correct (it never
   accepts what it cannot store). The sender's disk-assisted queue is the weak point and
   needs its own monitoring (R7).

## Known limits

- One collector of each kind, synthetic traffic, short drills (about two hours); not a
  multi-day soak. Thresholds are starting points; tune them from real traffic.
- Azure alert latency is bounded below by the five-minute evaluation, ingestion delay and
  the threshold itself; auto-resolution took 12–20 minutes (about three healthy
  evaluations), and 30 minutes for windowed rules. Azure cannot alert faster than this.
- A new DCR or table took 6.5 minutes to make the first rows queryable.
- `queueFileUsedPercent` uses the file size, which includes free pages; it overstates use
  after retention until pages are reused. The page-limit formula mirrors the current
  persistence code and must change with it.
- WEC subscription health is host-side only: Bower reads `ForwardedEvents` and cannot see
  the subscription's own state. Per-device (per firewall or per WEF source) silence needs
  one syslog listener per device or a pack field that maps the device; this work does not
  add one.
- Health records are C#-only; the Rust collector refuses the setting.
- The management path was tested with development authentication on loopback, not Entra.
- Dead-letter replay was exercised with poison events only (which correctly re-dead-letter);
  Bower does not dead-letter destination outages, so there was no transient dead letter to
  replay successfully.
- Releases are unsigned development builds; signing is out of scope here.
