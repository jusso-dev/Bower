# RELP firewall syslog qualification: `bower-fw-20261101-111911`

**Result: with the recommended sender (rsyslog 8.2610.0 + omrelp over mutual TLS), every
scenario delivered every native identity to Bower's queue and to Microsoft Sentinel, 0
missing.** The three scenarios that lost events with plain TLS syslog on 1 November
(SIGKILL 21/6,000, TCP reset 4/1,200, collector stop + sender reboot 2/600) now pass. One
earlier attempt failed and is preserved: collector stop + sender reboot lost 6 of 600 with
the distribution's rsyslog 8.2204.0 (cause and fix below).

## What ran, where

| Item | Value |
|---|---|
| AWS | account 959038055523, ap-southeast-2, stack `bower-fw-20261101-111911` (private /24 172.31.61.0/24 in the default VPC via the existing NAT gateway; SSM only; IMDSv2; encrypted gp3; expiry schedule 2026-11-01T22:24:06 UTC) |
| Collector | Amazon Linux 2023, t3.small, CI-built NativeAOT `linux-x64` collector from commit `24ece92b96fb5b2605cffbffa8396b5ef8a9548b` (CI run 41301411476), `Bower.Collector` SHA-256 `715d947a697f738bd7b9822ed51127e0e08b16ce9f089e7221393cb3098a505f`, `libe_sqlite3.so` `eddcd4aa561d5b8f252db77e8272e7d1aed96bcab9fda3f177ca542f916290bf`; listener `a13` `protocol: relp`, mutual TLS, port 6514, `idleTimeoutSeconds: 0` |
| Sender | Amazon Linux 2023, t3.small; nftables deny rule logging UDP probes from a namespace; journald persistent; rsyslog `imjournal` → disk-assisted action queue → `omrelp` (`windowSize=128`, `timeout=90`, TLS `authmode=name`) |
| Sender software | Phase 1: rsyslog 8.2204.0-3.amzn2023.0.9 with `omrelp` built from rsyslog-8.2204.0 source (`7eb52db7…245d`) and librelp 1.12.0 (`e2e53a98…496a`, OpenSSL). Phase 2 (from 12:42:18 UTC): rsyslog 8.2610.0 built from source (`7bdf95e8…404b`), `rsyslogd` `b9707a54…a8dc`, `omrelp` `3e3def05…da0e` |
| Pack | `syslog-reliability` 1.0.0 signed with a run-generated key, SHA-256 `44aa95145b1662dcca81c0f54f1c24dbc61bcaa832de3e4de14171d062636bc5` (samples 4/4 pass) |
| Azure | subscription 945092a0-…, `rg-bower-fw-20261101-111911` (australiaeast): Log Analytics workspace + Sentinel, repository Bicep DCE/DCR/table, ingestion app `bower-fw-20261101-111911-ingest` (certificate), verifier app `bower-fw-20261101-111911-verifier` (Log Analytics Reader on the workspace only) |

## Results

Native = nftables counter delta (equal to the generated count in every attempt). Queue and
Sentinel are exact distinct identity sets compared by SHA-256; missing/extra are against the
frozen plan. "Sentinel rows" counts every destination row; duplicates are rows above the
distinct count. Attempts are in time order; phase 2 used sequence offset 900000.

| Scenario | Attempt | Sender rsyslog | Native | Queue distinct (missing) | Sentinel distinct (missing) | Sentinel rows at reconciliation / final | Outcome |
|---|---|---|---|---|---|---|---|
| `a-steady` | 1 | 8.2204.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sigkill` | 1 | 8.2204.0 | 6000 | 6000 (0) | 6000 (0) | 6011 / 6011 | PASS: 0 missing; 11 duplicate Sentinel rows, collapse to 6000 |
| `a-reset` | 1 | 8.2204.0 | 1200 | 1200 (0) | 1200 (0) | 1200 / 1200 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-reboot` | 1 | 8.2204.0 | 600 | 594 (6) | 594 (6) | 594 / 594 | **FAIL**: 6 missing at the queue, 6 at Sentinel |
| `a-sender-reboot-only` | 1 | 8.2204.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-reboot` | 2 | 8.2610.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-reboot-only` | 2 | 8.2610.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sigkill` | 2 | 8.2610.0 | 6000 | 6000 (0) | 6000 (0) | 6000 / 6021 | PASS: 0 missing; 21 duplicate Sentinel rows, collapse to 6000 |
| `a-reset` | 2 | 8.2610.0 | 1200 | 1200 (0) | 1200 (0) | 1200 / 1200 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-restart` | 1 | 8.2610.0 | 6000 | 6000 (0) | 6000 (0) | 6000 / 6004 | PASS: 0 missing; 4 duplicate Sentinel rows, collapse to 6000 |
| `a-collector-reboot` | 1 | 8.2610.0 | 3000 | 3000 (0) | 3000 (0) | 3000 / 3000 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-blackhole` | 1 | 8.2610.0 | 1800 | 1800 (0) | 1800 (0) | 1800 / 1800 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-stop-start` | 1 | 8.2610.0 | 1800 | 1800 (0) | 1800 (0) | 1800 / 1800 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-burst` | 1 | 8.2610.0 | 6000 | 6000 (0) | 6000 (0) | 6000 / 6000 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-steady` | 2 | 8.2610.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `b-idle-gaps` | 1 | 8.2610.0 | 6300 | 6300 (0) | 6300 (0) | 6300 / 6300 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-destination-outage-15m` | 1 | 8.2610.0 | 9000 | 9000 (0) | 9000 (0) | 9000 / 9000 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-capacity-refusal` | 1 | 8.2610.0 | 20000 | 20000 (0) | 20000 (0) | 20000 / 20000 | PASS (strict: 0 missing, 0 duplicate rows) |

Per-attempt files are in `scenarios/<scenario>-attempt<N>/` (listed with hashes in [`public-manifest.json`](public-manifest.json)): redacted plan, generator result,
queue measurement, collector and sender snapshots, fault record, reconciliation report,
queue identities (`[EventId, GeneratedAt, ReceivedAt]` JSONL), Sentinel rows
(`[EventId, Copies, FirstGenerated, LastGenerated, FirstIngested, LastIngested]` JSONL with
the query envelope), and `dedup-proof.json` (raw rows, rows after the documented
`arg_min(ingestion_time(), *) by EventId` collapse, distinct ids). [`summary.json`](summary.json)
holds every count and hash; [`public-manifest.json`](public-manifest.json) holds byte counts
and SHA-256 for every file.

## Scenario details

**Sender reboot (cause of the one failure).** Attempt 1 of `a-sender-reboot` (rsyslog
8.2204.0): the collector was stopped at 12:02:04.8 for 240 s; generation ran 12:02:09.8 to
12:03:09.8; the sender rebooted at 12:03:24. The six missing identities
(`a13-n4412x20000`…`20005`) are the first six generated. The sender's own rsyslog log
([`operations/a-sender-reboot-attempt1-diag.txt`](operations/a-sender-reboot-attempt1-diag.txt))
shows the action suspending at 12:02:10.5 (broken session after Bower's stop), retrying every
5 s while the collector was down, `exiting on signal 15` at 12:03:25, and after the reboot
`a13 queue[DA]: queue files exist on disk, re-starting with 594 messages`: exactly the 594
that later reached Bower. The six were the batch rsyslog's action worker held in memory while
retrying; 8.2204.0 does not re-enqueue it at shutdown. rsyslog's ChangeLog entry of 2026-05-31
("action: keep transactional queue batches on shutdown", released in 8.2606.0) fixes exactly
this. After upgrading only the sender to 8.2610.0 (12:42:18 UTC; build record
[`operations/sender-rsyslog-8.2610.json`](operations/sender-rsyslog-8.2610.json)), attempt 2
delivered 600 of 600. Bower never saw the six; the RELP session was already closed.

**Idle gaps.** One RELP session carried all four pulses (no reconnect: the listener's
`connectionsAccepted` stayed at 3 from 14:24 to 16:00). Measured generator end to next start:
300.085 s, 1,803.995 s and 3,903.905 s; the final burst (6,000 at 99.99/s) after the 65-minute
gap arrived complete.

**Destination outage (15 minutes).** The ingestion-only block (Bower's UID, TCP 443, IPv4 and
IPv6) was applied at 16:03:53 by `destination-outage.sh` with an independent systemd timer
and restored at 16:21:26.65 (`blockedSecondsLowerBound` 1,053.2, boot unchanged). Generation
ran 16:06:20 to 16:21:20 at 10/s; RELP intake continued throughout (16:15:14 snapshot: 5,345
undelivered, `relpAcknowledged` rising, no busy closes). The first scoped Sentinel row was
ingested at 16:21:30.02, after restoration; all 9,000 by 16:21:34.84.

**Queue-capacity refusal and recovery.** `queue-cap.sh` set `BOWER_QUEUE_MAX_BYTES` to
124,432,440 (queue 99,266,616 bytes + 24 MiB) and restarted Bower before the scenario.
Destination blocked from 16:30:22 with an independent restore scheduled for 16:42:55 (its applied record is retained; the restoration record was not downloaded before the run bucket was deleted, so the restore time is shown by the collector delivering again by 16:44:47, not by that record); 20,000 events generated 16:32:49 to 16:36:09.
Bower admitted 15,869 events by 16:35, then reached its page limit. The collector's own health
record in Sentinel (queried with the verifier,
[`health-records-during-refusal.json`](scenarios/a-capacity-refusal-attempt1/health-records-during-refusal.json))
reports at 16:36:14 `critical` with `capacity-refusals`, `stalled`, `retrying`, 45 retries
and queue pages 122.7 of 122.7 MiB; no further health record could be admitted until recovery.
RELP never answered the refused messages and the sender kept them. At 16:43:29 the scenario's
`raise-cap` step (operator recovery) removed the cap and restarted Bower; the restarted
process received exactly the 4,131 held events (lags up to 500 s), 0 duplicates, and all
20,000 reached Sentinel. Bower's RELP counters of the refusing process were lost with that
restart, so `relpBusyCloses` for this phase comes only from the unit tests; the live proof is
the health record, the queue receive gap and the exact identity sets.

**Duplicates.** RELP resends after a kill or reset are deduplicated in the queue (for example
102 queue duplicates after the first SIGKILL; none reached Sentinel twice from RELP). Sentinel
duplicate rows came only from at-least-once delivery after a collector kill or restart: 11 and
21 rows (SIGKILL) and 4 (restart), all collapsing to the exact sets with the documented query.


**Review changes after the live run (not re-run on AWS, deliberately).** The campaign ran
collector commit `24ece92`. Review then changed five RELP behaviours in both runtimes:

- a timestamp-less message's id now includes the receive time again;
- every field separator must be one space;
- oversized `syslog` frames of any declared length are read past and answered;
- a refused frame gets one attempt once a session is closing;
- a busy close reads the rest of the window away so it ends with a FIN.

None of these changes the measured paths. The lab messages always carry RFC 5424
timestamps, and the pack keys events by port pair. librelp always sends single spaces. No
oversized or closing-time refusal occurred. The capacity scenario's busy closes are covered
by the busy-close unit tests and a repeated local run with real librelp 1.12.0 against both
collectors (3 SIGKILLs, a 12-second refusal, 3 graceful stops: 0 missing, 0 duplicate rows).

## Failed and repeated attempts (preserved)

- `a-sender-reboot` attempt 1 (rsyslog 8.2204.0): **failed, 6 of 600 missing** at the queue
  and at Sentinel (the in-flight batch rsyslog dropped at shutdown, above). Attempt 2 on
  8.2610.0 passed.
- `a-sender-reboot-only` attempt 1: the first two Sentinel reconciliations were refused
  (exit 2) by the harness's binding check, because the collector still had the original lab
  helper while the plan recorded the revised helper (the one that builds rsyslog 8.2610.0).
  The same reviewed helper was installed on the collector and the queue re-exported
  (`queue-identities-2`): identical 600 rows, only the recorded helper hash changed; then it
  reconciled.
- Phase 1 (rsyslog 8.2204.0) attempts of `a-steady`, `a-sigkill`, `a-reset` and
  `a-sender-reboot-only` passed and were all repeated in phase 2 (8.2610.0, sequence offset
  900000) so every result in the recommended profile uses one sender build.
- `a-destination-outage-15m`: the first Sentinel reconciliation was refused (exit 2) because
  the reconciler's plan check rejected digits in scenario names (`15m`); the exporter had the
  same bug. Both patterns were fixed (with a test) and the driver's next query passed.
- Late duplicates: the reconciliation queries of `a-sigkill` attempt 2 and `a-restart` ran
  before Bower redelivered batches whose delivery the collector had not recorded when it was
  killed or restarted (lease expiry), so they showed 0 duplicate rows; the later
  deduplication query found 21 and 4. Both counts are shown; all collapse to the exact set.


## Limits

- Lab sender, not a firewall appliance; a production appliance's first hop is not tested
  (see the relay topology in the guide).
- A sender crash or power loss with an unanswered RELP window was not tested; librelp keeps
  that window in memory.
- Only the C# collector ran live. The Rust listener passed the shared vectors, its unit
  tests and a local real-librelp interop run.
- Windows, Docker, Kubernetes and Azure collectors were not part of this run.
- rsyslog 8.2610.0 and the 8.2204.0 `omrelp` module were built from pinned upstream sources;
  they are not distribution packages. Release signing is deferred; packages are unsigned.
- Plans are published with local operator paths replaced (`<operator-home>`); summary.json
  records both the original hash bound by each reconciliation and the public hash.

## Cleanup

Independent audit after teardown: [`cleanup.json`](cleanup.json), produced by
[`lab/aws/monitoring/relp-cleanup-audit.py`](../../../lab/aws/monitoring/relp-cleanup-audit.py),
**34 of 34 checks absent: zero resources with RunId `bower-fw-20261101-111911` remain in AWS
or Azure.** It checked the CloudFormation stack; both instances (terminated) and their two EBS
volumes; the three security groups, subnet and route table; three IAM roles and two instance
profiles; the S3 bucket (emptied, then deleted with the stack); the EventBridge Scheduler
expiry schedule; snapshots, log groups and secrets tagged with the RunId; a RunId tag sweep of
the region, re-verifying each ARN the tagging API still listed; the Azure resource group, any
resource tagged with the RunId, the soft-deleted workspace list (the workspace was
force-deleted); both Entra applications and service principals (deleted and purged from deleted
items); and their role assignments. The shared VPC, NAT gateway and every other pre-existing
resource were untouched. Local private staging (keys, certificates, tokens, Azure identity
files and caches) was deleted.

Every absence is proven by the exact not-found code of its own query (recorded as `errorCode`
on each check: for example `InvalidInstanceID.NotFound`, `NoSuchEntity`, `404` for the bucket,
`ResourceNotFoundException`, and Graph `Request_ResourceNotFound` for each purged application
and service principal) or by a successful empty listing. Throttling, access denied, an expired
token or any other error fails the audit. This is the corrected audit, re-run read-only on
2 November after review found that the earlier version counted any failed query as absence.
Its inputs were rebuilt from the earlier audit's recorded IDs
([`operations/cleanup-audit-inputs-*.json`](operations/cleanup-audit-inputs-stack-resources.json)).
History is preserved: the first run (tagging-API lag)
[`operations/cleanup-first-audit-run.txt`](operations/cleanup-first-audit-run.txt) and the
superseded second run [`operations/cleanup-audit-superseded.json`](operations/cleanup-audit-superseded.json).
