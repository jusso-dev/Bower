# Monitoring, alerting and runbook drill — 31 October 2026

**Every catalogue alert fired for a real fault and resolved after recovery, except the
Azure storage alert for an already-full queue (the outage alert covered it).** The drill
also found a queue page-ceiling defect that stalls delivery, and sender-side syslog loss
under back-pressure. Neither changes the readiness status. Builds were **unsigned**
development builds. [Temporary-resource cleanup is verified](cleanup.json) (30 of 30
independent checks).

Guide: [Operational monitoring, alerting and runbooks](../../production-readiness/06-monitoring-and-runbooks.md).

| Scenario (fault) | Alert | Time to alert | Time to resolve after recovery | Result |
|---|---|---:|---:|---|
| D1 firewall generator stopped | `source-overdue` (3 min allowance) | 405.0 s | 919.7 s | Passed |
| D1 WEC subscription disabled | `source-overdue` | 396.9 s | 912.7 s | Passed |
| D1 both | `destination-freshness` (10 min) | 691.4 s / 683.4 s | 899.7 s / 892.7 s | Passed |
| D2 10 TLS/plain connection failures, 8 reconnects | `source-transport-errors` | 289.6 s | 1,809.3 s after the last error | Passed |
| D3 collector HTTPS blocked 12 min | `collector-health-missing` | 310.0 s | 871.1 s | Passed |
| D3 backlog drained after recovery | `queue-backlog` (lag) | 243 s after the drain (942.1 s after the fault) | 1,204.0 s | Passed |
| D4 4,500 packets into a full 4 MiB queue | `queue-storage` | **did not fire** | — | **Failed** (records refused while full; restart reset counters). `collector-health-missing` covered it |
| D4b queue file 92–97 % of its page limit, no backlog | `queue-storage` | 490.1 s after the first record showing it | 830.1 s | Passed |
| D5 Windows service stopped | `collector-health-missing` | 335.0 s | 799.6 s | Passed |
| D6 three malformed requests to the DCR (answered 204) | `dcr-transformation-errors` / `dcr-rows-dropped` / `dcr-errors` | 197.4 s / 255.3 s / 426.9 s | — | Passed; `dcr-request-errors` not exercised |
| D7 three oversized events dead-lettered | `dead-letters` | 383.7 s | stays fired (poison events cannot be delivered) | Passed |
| M Linux collector stopped 16 min | `collector-health-missing` / `destination-freshness` | 394.3 s / 842.8 s | 716.0 s / 860.2 s | Passed |
| M | Sentinel incident "Bower collector ws6-linux-01 stopped reporting" | 806 s | — | Passed |
| Unplanned: local smoke collector ended | `collector-health-missing` | 417.5 s after its last record | — | Passed |

Host and management paths ([host detection](host-detection.json), [fleet](management-fleet.json)):

| Fault | Host check | Management fleet check |
|---|---|---|
| D1 firewall silent | WARNING `source-overdue` at 202.5 s | "Needs a check" (amber, exit 1) |
| D1 WEC disabled | CRITICAL `wec-subscription ... Disabled` (Application log 9102) after the parser fix | — |
| D2 TLS failures | WARNING `syslog-errors: 10 new` 6 s after the fault | — |
| D4 queue full | CRITICAL `capacity-refusals` 22 s after the first refusal | — |
| D4b page limit | CRITICAL `queue-file: 97.2%` while `/health` said healthy | — |
| D5 process killed | systemd `Restart=always`: serving again 6.3 s after SIGKILL; Windows SCM: 6.3 s after `Stop-Process -Force` | — |
| M collector stopped | CRITICAL `collector-unreachable` at the next run | amber at 7 min, red (exit 2) at 15.4 min |

## What ran where

- Run `bower-ws6-20261031-074751`. Azure subscription `945092a0-2500-4b25-85a4-99f1c3135906`,
  tenant `f4f33fb1-b681-40d1-a854-6f888d45b891`, `australiaeast`, resource group
  `rg-bower-ws6-20261031-074751`: Log Analytics workspace `law-ws6-20261031` (customer ID
  `e45b11e4-7e19-4946-b729-1fcf284c6e88`) with Microsoft Sentinel; `BowerSecurity_CL`,
  DCE and DCR from [`deploy/bicep/main.bicep`](../../../deploy/bicep/main.bicep);
  [`monitoring.bicep`](../../../deploy/sentinel/monitoring/monitoring.bicep) (8 log, 5
  metric rules, DCR `LogErrors` diagnostic setting) and
  [`sentinel-health-rules.bicep`](../../../deploy/sentinel/monitoring/sentinel-health-rules.bicep);
  an action group with no receivers. [Rules](log-alert-rules.json),
  [metric rules](metric-alert-rules.json), [Sentinel rules](sentinel-rules.json),
  [resources](azure-resources.json), [action group](action-group.json),
  [DCR metric definitions](dcr-metric-definitions.json).
- Identities: `bower-ws6-20261031-074751-ingest` (Monitoring Metrics Publisher on the DCR,
  certificate) for the collectors and the D6 requests; `bower-ws6-20261031-074751-reader`
  (Log Analytics Reader on the workspace) in an isolated Azure CLI cache for every
  destination query; the operator login for alert state. Both apps were deleted and purged.
- AWS account `959038055523`, `ap-southeast-2`, stack `bower-ws6-20261031-074751`: a new
  private subnet `172.31.216.0/24` in the default VPC routed to the existing NAT gateway,
  a security group with **no inbound rules**, an encrypted private artifact bucket, Amazon
  Linux 2023 `t3.small` and Windows Server 2022 `t3.medium` (IMDSv2, encrypted gp3,
  terminate on shutdown, no public address), and an EventBridge Scheduler expiry at
  `2026-10-31T19:21:40Z` terminating exactly the two instances. [Hosts](aws-hosts.json),
  [volumes](aws-volumes.json), [security group](aws-security-group.json),
  [SSM command index with script hashes](ssm-commands.jsonl).
- Linux: collector under the repo's `bower.service` plus the monitoring drop-in, RPM
  layout; nftables logs and drops packets to `192.0.2.10`, rsyslog (`rsyslog-openssl`)
  forwards them as RFC 5424 over mutual TLS (`RebindInterval="0"`, disk-assisted queue,
  the pilot's sender profile) to the Bower listener; source expectation 3 min; queue cap
  4 MiB, then 8 MiB and 64 MiB after recoveries; health records every 60 s; management API
  with development authentication on loopback and token enrolment.
- Windows: collector as `NT SERVICE\Bower`, recovery restart 5 s; `net use \\127.0.0.1\IPC$`
  with a nonexistent account every 5 s produced real Security 4625 events, forwarded by a
  collector-initiated WEC subscription to `ForwardedEvents`; signed
  `windows-security-logon` 1.0.2 pack with HMAC usernames.
- Builds from this branch (managed self-contained, not Native AOT):
  [artifact manifest](artifact-manifest.json). v1 ran D1–D5; v2 (adds
  `storage.queueFile*`) ran D4b onwards. Packs signed with an ephemeral lab key.
- Health record shape: [one Linux and one Windows record](health-record-samples.json).

Timeline with every fault, recovery, alert start and resolution:
[`drills.json`](drills.json). All alert instances: [`alert-instances.json`](alert-instances.json);
Sentinel incidents: [`sentinel-incidents.json`](sentinel-incidents.json).

## Replay

- [Audited dead-letter replay](replay-dead-letter.json): three oversized synthetic events
  were dead-lettered (`preflight-field-too-large`) and raised `dead-letters`. With the
  collector stopped, `tools/audited-replay/replay.py` (change `CHG-WS6-DLQ-001`) wrote
  `intent.json` then `outcome.json` (0600, CLI and database hashed, `queue_effect:
  unverified`, `delivery_verified: false`). The queue showed the three IDs queued. After
  the start the output preflight dead-lettered them again. Sentinel had **0** rows for
  them and the ledger verified intact. Replay does not bypass the preflight.
- [Audited archive replay](replay-archive.json): the archive (5 segments, 5,252 events,
  intact) was replayed for 08:40–08:42 UTC into a separate loopback replay collector
  (change `CHG-WS6-ARCHIVE-002`): 119 selected, 119 × HTTP 202, all delivered. Sentinel:
  119 original + 119 replayed rows (all `Labels.bowerReplay = "archive"`), exactly 2 rows
  per `EventId`, identical sorted-ID SHA-256
  `3560592983cab0ddcc2795c390ab2e44c22ebc9e3c7ee0151175056deea5f26b`. Dedup by `EventId`
  returned **119**; dedup by `CollectorId, EventId` returned **238**. The first attempt
  (`CHG-WS6-ARCHIVE-001`) failed before writing intent because the wrapper misread the
  CLI's multi-line JSON; its empty audit directory was kept and not reused.

## Queue page-ceiling defect

[Details](queue-page-ceiling.json), [local reproduction](queue-page-ceiling-repro.cs.txt).
`SqliteEventStore` limits the database to `(4 × BOWER_QUEUE_MAX_BYTES + 16 MiB) / 4`
pages. Rows, indexes, the ledger and acknowledged rows kept for retention filled that limit
before undelivered payloads reached the cap.

- D4 (4 MiB cap): after the burst the file was 2,048 pages (8 MiB) with 0 free pages and
  2.87 MB undelivered (68.5 % of the cap). After egress was restored, **delivery did not
  resume**: 183 expired leases could not be re-leased and the delivery loop logged
  `Delivery loop failed with SqliteException` 86 times in 15 minutes. Raising the cap to
  8 MiB and restarting drained the backlog in **4.3 s**.
- D4b (8 MiB cap): with **zero** backlog, retained acknowledged rows put the file at
  92–97 % of its limit. `queue-storage` fired; two minutes later intake was refused (233
  refusals, nothing undelivered). Raising the cap to 64 MiB restored intake at once.
- Local unit-test reproduction: 1,300 delivered rows, then enqueue until refused at 3,475
  undelivered (3.85 MB, 92 % of the cap). The next `LeaseAsync` threw
  `SQLite Error 13: 'database or disk is full'`.

This belongs to the queue/storage workstream, which is reworking the same code; it was
not changed here. The recovery is runbook R5.

## Source accounting

[`source-accounting.json`](source-accounting.json). Every event Bower accepted reached
Sentinel: 7,092 accepted (received before 10:20 UTC) and 7,092 in Sentinel, with
identical SHA-256 `c4460a3660c9cbad9645da55580a38bb1e9beb859b069cece48cca8aa7883508`.
That held across the outage, both saturations, the stall, process kills, upgrades and the
16-minute stop.

The kernel logged 10,069 denies before 10:20 UTC, so **2,977 were lost before
acceptance**. By window: 0 at baseline; 2 during the sender reconnect drill; **2,280**
during the burst into a refusing queue; **439** while delivery was stalled; **252**
around the second saturation; 4 around restarts; 0 during the 16-minute collector stop.
rsyslog held a 412,864-byte disk-assisted queue file that did not shrink while live frames
flowed. Restarting rsyslog removed it without forwarding anything (90 live frames in
90 s). Bower's back-pressure behaved as designed. The loss is in the sender profile and
needs sender-side monitoring (runbook R7). Reported for the syslog workstream.

## Other findings

- [Privacy number scan](privacy-number-scan.json): default detectors masked 166–279 of
  3,000 random 8–10 digit numbers and up to 96 of 3,000 for 13–16 digits; none with 7 or
  fewer. The health record clamps numbers and uses letter-only IDs. In the drill, 6 of
  about 6,700 hex syslog event IDs were masked (the known pilot finding); none of 158
  health records were.
- New DCR: the first records were queryable 6.5 minutes after acceptance (cold start), so
  `queue-backlog` fired once on arrival lag before any fault.
- `dcr-no-ingestion` fired at deployment (no traffic yet) and resolved 4.7 minutes after
  the first request.
- The Logs Ingestion API answered **204** to an invalid-JSON body, a non-array body and a
  record with an invalid timestamp. Validation is asynchronous; errors appear only in
  metrics and `DCRLogErrors`.
- Alerts auto-resolved 12–17 minutes after recovery (about three healthy five-minute
  evaluations), and up to 30 minutes for rules whose window still contains the fault.

## Failed attempts retained

[`failed-attempts.json`](failed-attempts.json) keeps every failure and its correction:

- One-minute rules refused by Azure.
- `ColumnsDroppedCount` `Count` false positive.
- Sentinel look-back limit.
- Archive replay wrapper.
- Freshness false positives from a synthetic D6 row and from the one-off replay collector.
- Harness setup errors: package name, S3 permission, macOS tar metadata, spool directory,
  WEC delete, `sc.exe` quoting, ACL, WEC access denied.
- Timestamp-parser and WEC-status bugs in the new scripts.
- The host check's queue cap source.

## Limits

One collector of each kind, synthetic traffic, about two hours. Drill thresholds were
shorter than the production defaults. `dcr-columns-dropped` and `dcr-request-errors` did
not fire because nothing triggered them. Management ran with development authentication on
loopback, not Entra. The WEC subscription was collector-initiated from the same host, not a
domain WEF deployment. The Rust collector was not tested (it refuses health records). This
drill does not qualify a production workload, longer outages or the signed release.

## Cleanup

[`cleanup.json`](cleanup.json), audited at the end of the run with independent queries:

- AWS: stack absent; both instances terminated; no run-tagged volumes, snapshots, security
  groups, subnets, route tables or network interfaces; the subnet CIDR free; bucket, IAM
  roles and instance profiles, schedules, secrets and log groups absent.
- Azure: resource group absent; no run-tagged resources; workspace not in the soft-deleted
  list (force delete); no run action groups.
- Entra: both apps and service principals absent and purged from deleted items; no role
  assignments.

Local lab keys, certificates, tokens, HMAC key, isolated CLI caches and staged artifacts
were deleted; the operator's Azure CLI login was preserved. The expiry schedule was
removed with the stack.
