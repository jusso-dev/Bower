# 24-hour soak: `bower-soak-20261102-015614`

**Result: the soak FAILED.** Neither collector met all six pre-registered criteria. The
firewall failed criteria 3 and 5; the WEC failed 3, 4 and 5. No event was missing at the queue
or at Sentinel on either collector. Soak window: 2026-11-02T03:35:00Z to 2026-11-03T03:35:00Z,
main `1a4c4c2`. This file was corrected after review on 2026-11-03 (see
[Corrections after review](#corrections-after-review)); superseded figures stay visible there.

| # | Criterion | Firewall (RPM, RELP) | WEC (MSI) |
|---|---|---|---|
| 1 | Native = accepted = distinct Sentinel, exactly | **PASS**: 896,400 = 896,400 = 896,400; 54 duplicate rows | **UNQUALIFIED: observed delivery; accepted extras and source coverage not verified**: 896,400 native records, 0 missing at the queue, 0 missing and 0 extra at Sentinel; 101 duplicate rows |
| 2 | No process restarts | **PASS**: one PID for the whole soak, `NRestarts` 0, one boot | **PASS**: one PID, one boot. The source restarted in-process twice (below) |
| 3 | No unbounded growth (30-day projection of the hours 3–24 slope under 10% of the mean) | **FAIL**: RSS +75 KB/h (61%), FDs +0.055/h (166%), queue +106 KB/h (36%); threads falling | **FAIL**: private bytes +461 KB/h (735%), handles +0.54/h (93%), threads +0.12/h (527%), queue +73 KB/h (17%) |
| 4 | p99 latency ≤ 2× the pilot's connected p99 | **PASS**: 8.68 s ≤ 13.3 s. Three hours were above the limit (10:33, 00:33, 02:33) | **FAIL**: 881.8 s against 18.16 s; 23 of 25 hours were above the limit |
| 5 | No alerts | **FAIL**: `syslog-tls-expiry` fired for the whole run (a false positive, fixed on main by #171) | **FAIL**: `source-transport-errors` fired twice and resolved (12:02Z, 17:02Z) |
| 6 | 0 privacy-marker matches | **PASS**: 0 of 897,940 rows | **PASS**: 0 of 897,977 rows |

Identity digests (SHA-256 of the sorted ids joined by newline), as computed at the run:
firewall `ea5daf5b618ff8a3f6aa6399ec9b2509a91c4005cd5b89bf6069921b209b936e`,
WEC `d65064b301a6a951636072af79d44bfaba585c458fe58c9407faec9aa7a9089a`. The native and
Sentinel digests are full-set digests. The **accepted** digest was taken over
`accepted ∩ native`, which cannot show accepted extras (see corrections).
Source: [`final/final-reconciliation.json`](final/final-reconciliation.json).

## What ran, where

| Item | Value |
|---|---|
| AWS | account 959038055523, ap-southeast-2, stack `bower-soak-20261102-015614` (`lab/aws/upgrade-recovery/lab.py`, profile `soak`), private subnet 172.31.247.0/24 in the default VPC via the existing NAT gateway; SSM only, no public addresses, IMDSv2, encrypted gp3; EventBridge Scheduler expiry at 2026-11-03T07:56:59Z (30 hours) terminating all four instances |
| Hosts | `Dc` t3.medium Windows Server 2022, the `bower.test` domain controller and 4625 source. `Wec` t3.medium, domain member, WEC source-initiated subscription (100-event batches, 1 s latency), ForwardedEvents 4 GiB. `Sender` t3.small AL2023. `Linux` t3.small AL2023. All four on **standard** CPU credits |
| Packages | CI run [41374800326](https://github.com/jusso-dev/Bower/actions/runs/41374800326) (workflow_dispatch, full) on main `1a4c4c2bc0c0fccdd7b41ac88947e02221f23052`. **Unsigned**: release signing is deferred. RPM `bower-collector-0.1.0~dev.337-1.x86_64.rpm` `e974d51e2fd571f9ccfa42684eb77fe85369758cc7b197f6b316de4948a1b273`, installed `/opt/bower/Bower.Collector` `8fae8c0300398c46e31151fe91cfc9499fbb29ca225a4f16045bc0e569a0552d`. MSI `bower-collector-0.1.0-dev.337-x64.msi` `dd8469f7e70f6aca3453717f102adc23e2238c34efc1c27a720062496c89bd3a` (Authenticode `NotSigned`), installed `Bower.Collector.exe` `207c9ae80c083f8c2e2f6d4eab2b9e3296bbd22e07ea50f8e57f6b230cda2450` |
| Collector settings | Both: Sentinel Logs Ingestion API with a certificate credential, `BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60`, `BOWER_QUEUE_RETENTION_HOURS=2`, lease 90 s, output deadline 60 s, the `collector-health` policy. Linux: packaged `bower.service`, RELP listener `a13` with mutual TLS on 6514. Windows: `%ProgramData%\Bower\bower.env`, `BOWER_QUEUE_MAX_BYTES=4294967296`, ForwardedEvents 4625 subscription (poll 1 s, batch 256), per-minute `Test-BowerCollectorHealth.ps1` task. Linux: `bower-healthcheck.timer` |
| Packs | Signed with a run-generated key (public key `2619e966a7d5e063f4830bf69e00ce8f48a1b42a0103301025fea84ae0d9af29`): `syslog-reliability-1.0.0` `3afe4ee7…0a64`, `windows-security-logon-1.0.2` `aeee20de…98bc`; all pack samples pass |
| Sender | rsyslog 8.2610.0 built from pinned source (`7bdf95e8…404b`); `rsyslogd` `b9707a54…a8dc`, `omrelp` `3e3def05…da0e`, librelp 1.12.0; `imjournal` to a disk-assisted queue to `omrelp` over mutual TLS (`windowSize=128`, `timeout=90`). This is the [RELP profile](../fw-20261101-111911/README.md) |
| Azure | `rg-bower-soak-20261102-015614` (australiaeast): workspace and Sentinel; repository Bicep DCE, DCR and table; ingestion app `…-ingest`; verifier app `…-verifier` (Log Analytics Reader on the workspace only); 11 log and 4 metric alert rules (`monitoring/`) from `deploy/sentinel/monitoring/monitoring.bicep`, enabled, both collectors expected, DCR error logs on |
| Load | 10/s per collector, plus 60 s at 100/s at +2 h, +6 h … +22 h: 896,400 events per collector. Firewall identities are sequence numbers 100,000 to 996,399. Windows: 896,400 NTLM LDAP binds to the DC, all returning LDAP result 49 (0 successful logons) |

## Results in detail

### 1. Exact delivery (firewall PASS; WEC UNQUALIFIED)

- **Firewall.** 18 generator segments sent 896,400. The nftables counter delta was 896,400,
  every segment exact ([`generators/sender/segments.jsonl`](generators/sender/segments.jsonl)).
  The accepted union of the queue (exported every 30 minutes, so rows purged by the 2-hour
  retention are still counted) held all 896,400. Sentinel held 896,400 distinct ids in 896,454 rows.
  The accepted scope (sequence range 100,000–996,399) is exactly the native range, so no accepted
  id in scope can be extra.
- **WEC.** The DC Security log held 896,400 4625 records in 25 hourly windows: 24 scheduled
  (`native-windows/scheduled/`) plus `h24` (31 events, exported on demand). That equals the
  896,400 attempts in `generators/dc/`. These counts are recomputable from the committed
  metadata. At the run, the reconciler counted 896,400 distinct **original** ids (probe
  column 4). The committed metadata holds only the probe's **redacted**-id counts: 896,399
  distinct, because two ids in `h23` collapse to one masked form (`duplicateIdentities: 1`). That
  is a redaction collision, not a native duplicate. The original-id count cannot be recomputed:
  the identity lists were deleted with the lab. Accepted: all 896,400 native ids were in the
  accepted union; whether the union also held extra soak-window `winevt-` ids was not checked
  and cannot be now. Sentinel: 896,400 distinct in 896,501 rows, 0 extra (a full-set comparison).
- **Duplicate rows.** Firewall 54 (45 in the 10:33 hour, 9 in 00:33); WEC 101 (51, 10, 40 in
  10:33, 15:33 and 00:33). Both collectors duplicated in the same two hours, and those hours also
  had latency spikes on both. Neither collector logged a delivery failure in those hours. The
  pattern points at the destination side of at-least-once delivery. Every duplicate collapses with
  the documented `arg_min(ingestion_time(), *) by EventId` query.

### 2. No restarts (both PASS)

Linux: PID 30340 started at 02:32:51Z (the pre-soak certificate restart) and ran to the end.
`NRestarts` was 0 and there was one boot ID in all 297 samples. WEC: PID 3924 started at
2026-11-02T02:22:34Z and ran to the end with one boot.
The WEC's Windows Event Log **source** failed and recovered twice inside the process. Health
records show `winevt-source-failed` at 12:00:46Z and 17:00:28Z. In both cases the hourly
`queue-retention` job was purging 41,458 and 36,045 rows (43 s and 72 s). The delivery loop logged
`SqliteException` (event 1002, retried after back-off) at 16:00:44Z, 22:00:44Z and 02:00:44Z,
also at retention time. The observed native IDs were found at the queue and destination;
source coverage and accepted-stage extras were not fully verified, so losslessness was not
established. The Linux collector logged no warnings.

### 3. Resource trends (both FAIL the registered threshold)

Slopes are least squares over hours 3–24 of the **workload** (03:35Z to 03:35Z the next day),
taken from the committed 5-minute samples (`series/`), 252 samples per collector. The delivery
drain after the workload is reported separately. Recomputed with
`reconcile.py series --series-dir series/` into
[`final/resource-trends-recomputed.json`](final/resource-trends-recomputed.json). The "30-day %"
column is the slope × 720 h as a percentage of the mean. The registered threshold is under 10%;
a falling series passes.

| Series | Firewall slope/h | 30-day % | Range | WEC slope/h | 30-day % | Range |
|---|---|---|---|---|---|---|
| Memory (RSS / private bytes) | +75 KB | 61% fail | 80.4–100.0 MB | +461 KB | 735% fail | 31.0–73.3 MB |
| FDs / handles | +0.055 | 166% fail | 23–28 | +0.54 | 93% fail | 403–426 |
| Threads | −0.008 | −32% flat | 17–20 | +0.12 | 527% fail | 15–18 |
| Queue DB + WAL | +106 KB | 36% fail | 186–215 MB | +73 KB | 17% fail | 262–327 MB |

The first published table (RSS +165 KB/h, 133%; private bytes +486 KB/h, 771%; FDs 163%; handles
82%; threads 473%; queue 34% and 20%) used samples up to hour 25, including the drain. It is
superseded. The verdict for each series is unchanged except firewall threads, which are falling
and pass under the registered rule.

The absolute changes are small. One day cannot separate .NET warm-up from a slow leak, and the
second half behaves differently. Over hours 12–24 the firewall queue file is flat (+1.8 KB/h,
0.6%), and the WEC private-byte slope turns negative. These are reported as failures because that
was the rule set in advance. A longer run is needed to settle them.

**WEC CPU is the real growth** (an observation; CPU was not part of the registered criterion 3 and
is recommended as a gate for future runs). At a constant 10 events/s, the collector's CPU seconds per hour went
450, 808, 1,308 … 2,049 (hour 12) … 2,503 (hour 20; hours counted from 0). The curve flattened only when the instance ran out
of CPU credits. `CPUCreditBalance` was 0 from about 15:00Z. The firewall collector used 3.2% of one
core (p50) all day.

### 4. Latency

[Hourly p50 / p95 / p99 in seconds](final/final-reconciliation.json) (first ingestion minus
event time):

| Hour (UTC) | FW distinct | FW dup | FW p50 / p95 / p99 | WEC distinct | WEC dup | WEC p50 / p95 / p99 |
|---|---|---|---|---|---|---|
| 11-02 03:33 | 34,800 | 0 | 3.9 / 6.6 / 9.1 | 34,790 | 0 | 6.8 / 9.7 / 12.5 |
| 11-02 04:33 | 36,000 | 0 | 3.8 / 6.3 / 8.2 | 36,000 | 0 | 6.9 / 9.6 / 11.6 |
| 11-02 05:33 (burst) | 41,364 | 0 | 3.8 / 6.2 / 8.1 | 41,397 | 0 | 8.0 / 218.7 / 257.6 |
| 11-02 06:33 | 36,000 | 0 | 3.8 / 6.1 / 8.1 | 36,000 | 0 | 7.4 / 10.5 / 22.9 |
| 11-02 07:33 | 35,982 | 0 | 3.9 / 6.3 / 11.1 | 35,999 | 0 | 7.4 / 11.2 / 30.0 |
| 11-02 08:33 | 36,000 | 0 | 3.8 / 6.1 / 7.6 | 36,000 | 0 | 7.3 / 10.6 / 27.8 |
| 11-02 09:33 (burst) | 41,366 | 0 | 3.9 / 6.1 / 8.2 | 41,400 | 0 | 8.5 / 240.4 / 276.3 |
| 11-02 10:33 | 36,000 | 45 | 3.8 / 6.2 / **43.1** | 35,999 | 51 | 7.6 / 11.2 / 42.3 |
| 11-02 11:33 | 35,982 | 0 | 3.9 / 6.0 / 7.2 | 36,000 | 0 | 7.5 / 10.3 / 32.6 |
| 11-02 12:33 | 36,000 | 0 | 3.8 / 6.0 / 7.1 | 35,999 | 0 | 7.5 / 10.5 / 30.3 |
| 11-02 13:33 (burst) | 41,366 | 0 | 3.8 / 6.0 / 7.4 | 41,397 | 0 | 9.3 / 294.0 / 326.5 |
| 11-02 14:33 | 36,000 | 0 | 3.8 / 6.0 / 7.1 | 36,000 | 0 | 7.8 / 17.0 / 27.8 |
| 11-02 15:33 | 35,983 | 0 | 3.9 / 6.0 / 7.1 | 35,999 | 10 | 11.6 / 61.9 / 88.5 |
| 11-02 16:33 | 36,000 | 0 | 3.9 / 6.1 / 7.6 | 36,000 | 0 | 12.0 / 36.5 / 74.1 |
| 11-02 17:33 (burst) | 41,365 | 0 | 3.9 / 6.3 / 7.6 | 41,398 | 0 | 325.1 / 485.9 / 497.1 |
| 11-02 18:33 | 36,000 | 0 | 4.2 / 7.1 / 8.6 | 36,000 | 0 | 134.3 / 200.8 / 213.1 |
| 11-02 19:33 | 35,983 | 0 | 4.2 / 7.0 / 8.9 | 36,000 | 0 | 42.7 / 107.1 / 130.5 |
| 11-02 20:33 | 36,000 | 0 | 4.1 / 7.0 / 8.4 | 35,999 | 0 | 16.4 / 49.7 / 78.2 |
| 11-02 21:33 (burst) | 41,365 | 0 | 4.0 / 7.3 / 8.8 | 41,400 | 0 | 442.2 / 573.1 / 608.8 |
| 11-02 22:33 | 36,000 | 0 | 4.0 / 7.2 / 9.3 | 36,000 | 0 | 344.7 / 448.3 / 487.4 |
| 11-02 23:33 | 35,982 | 0 | 3.9 / 6.7 / 9.1 | 35,999 | 0 | 261.2 / 349.1 / 370.9 |
| 11-03 00:33 | 36,000 | 9 | 4.0 / 7.5 / **30.9** | 36,000 | 40 | 223.2 / 314.2 / 339.7 |
| 11-03 01:33 (burst) | 41,364 | 0 | 3.8 / 6.4 / 8.2 | 41,394 | 0 | 803.4 / 883.9 / 913.7 |
| 11-03 02:33 | 36,000 | 0 | 3.9 / 7.0 / **13.8** | 35,999 | 0 | 782.1 / 925.1 / 955.2 |
| 11-03 03:33 | 1,498 | 0 | 3.7 / 5.9 / 7.6 | 1,231 | 0 | 770.2 / 776.9 / 780.0 |

Whole soak: firewall p50/p95/p99 3.9/6.4/8.7 s, max 151 s; WEC 11.7/771.8/881.8 s, max 969 s.

**WEC delay and the measurement limit.** Bower's sampled pending queue stayed at 36 or
fewer, and its oldest undelivered age stayed at 7 s or less. The destination latency above
still failed the gate. The previously reported reader backlog subtracted the process's
`windowsEventLog.eventsRead` counter from the channel's retained `forwardedEvents.records`
count. These have different baselines and the channel can wrap: the final sample gives
−103, which cannot be an unread-event count. The earlier backlog sizes and drain times are
therefore unproven; this run did not capture the newest channel record ID. The archived
sample file is unchanged.

The measured collector CPU rose from about 450 s/h at 42,000 retained records to about
2,500 s/h at 860,000; that correlation alone does not establish the cause. A later
[wecfix investigation](../wecfix-20261103-043750/README.md) found the query cost roughly
flat over its tested range and identified per-event durable commits as a throughput limit.
The original CPU growth remains unexplained. **The WEC path still requires the failed
latency gate and the re-soak to pass before production qualification.**

### 5. Alerts (FAIL)

[`monitoring/alerts-final.json`](monitoring/alerts-final.json):

- `syslog-tls-expiry` (Sev2) fired at 2026-11-02T02:36:41Z, before the smoke, and stayed
  `Fired`. The certificates were valid: server to 2026-12-02 and CA to 2026-12-03, re-issued for
  30 days before any traffic. The qualified RELP profile has no client revocation list, and
  the rule read the missing CRL date as unknown TLS metadata. This is a product false positive,
  fixed on main after this soak by
  [#171](https://github.com/jusso-dev/Bower/pull/171) (health records now carry
  `clientCertificateAuthorityConfigured` and `clientRevocationListConfigured`). The soak ran
  `1a4c4c2`, which does not include that fix.
- `source-transport-errors` (Sev3) fired at 12:02:37Z (resolved 12:43:38Z) and at 17:02:39Z
  (resolved 17:43:40Z). These were true positives: they follow the two WEC source failures
  during queue retention (section 2).
- No other rule fired, no metric alert fired, and Sentinel had no incidents. The DCR, health,
  freshness, backlog, storage and dead-letter rules stayed quiet throughout.

### 6. Privacy (PASS)

`bower-probe`, `BOWER_DENY` and `synthetic-invalid` matched 0 of 897,940 firewall rows and
0 of 897,977 WEC rows (`tostring(pack_all())`, including health records).

### Natural events (all occurred)

| Event | Evidence |
|---|---|
| `queue-retention` hourly | 25 runs logged on Linux (journal); 47 and 50 status-observed runs; WEC purged 36–41k rows per run |
| `queue-maintenance` daily 03:00Z | Ran 2026-11-02T03:00Z and 2026-11-03T03:00Z on both, `Succeeded` |
| Entra token refresh | Certificate credential; delivery continued for 24 h with no `lastFailureCode` on either collector (many token lifetimes) |
| journald rotation (sender) | System journal archived about every 2.3 h (09:40Z to 01:53Z, 498 MB total under the 1 GiB cap); `imjournal` read across every rotation (exact firewall delivery) |
| Health records | 1,484 (Linux) and 1,472 + 2 (WEC) records; largest gap 63 s and 95 s |
| Bursts | Six 6,000-event bursts per collector; the firewall absorbed each with no latency change |
| Generator drift | Firewall segment starts drifted to 29.8 s late by the last segment (one second added per segment by `max(planned, now + 1)`); DC segments to 3.1 s late. Recorded per segment |

## Setup record and failures (preserved)

- Sender setup attempt 1 failed with `ConnectionResetError` downloading the pinned upstream
  source; attempt 2 passed. The rsyslog 8.2610.0 build also failed once the same way and passed
  on retry. Sources are SHA-256 pinned.
- The collector agent's first tick failed (`unable to open database`: a URI attach without
  `uri=True`). It was fixed before any traffic.
- The shipped 14-day TLS-expiry threshold would have fired on the lab's 2-day certificates. Before
  any traffic the lab CA and both certificates were re-issued for 30 days with the same keys
  (`rotate-lab-certs.sh`). The alert fired anyway, for the CRL reason above.
- One path-check denial (`a13-n4449x59999`, index 1,999,999, outside every soak range) was sent at
  02:33Z.
- **Smoke attempt 1 failed on Windows (harness).** It showed 2 missing and 2 extra ids
  ([`smoke/smoke-attempt1-probe-redacted-ids.json`](smoke/smoke-attempt1-probe-redacted-ids.json)).
  The lab probe passed native ids through the default privacy detectors, which masked two
  `winevt-` hashes. The collector keeps the originals. The probe now also emits the original id,
  and it was redeployed to the DC before the soak. Attempt 2 was exact on both collectors
  ([`smoke/smoke-attempt2.json`](smoke/smoke-attempt2.json)).
- **Sampler gap (harness).** From 03:40Z to 04:45Z, and in 2 later samples, the Linux sampler
  lost the status part of 20 samples. Python 3.9's `fromisoformat` rejects .NET's seven fractional
  digits (`ValueError`). Process, file and disk metrics in those samples are intact. It was fixed at
  04:48Z by replacing the timer's script only (`samplesWithoutStatus: 20`).
- **Final reconciliation attempt 1** ([`final/final-attempt1-h24-window-not-yet-exported.json`](final/final-attempt1-h24-window-not-yet-exported.json))
  showed 31 extra WEC ids. They were the last 3 s of generation, which landed in window `h24`
  because the DC segments drifted 3 s late; that window had not closed yet. After exporting `h24`
  on demand (31 events) the reconciliation was exact.
- **WEC final export.** The scheduled ticks at 04:05Z and 04:10Z returned 0x0 but did not write
  `final.json`. The cause was not established (the probable one is the task's 10-minute limit on
  two unions of about 900k ids). The final export was then run through SSM at 04:13Z. The
  WEC sample series has one 786 s gap (04:00:05Z to 04:13:11Z), after the soak window.
- Interim reconciliation (first hour) was exact on both collectors:
  [`interim/interim-h00.json`](interim/interim-h00.json).

## Limits

- Lab hosts, not a firewall appliance or a production domain. Standard-credit t3 instances. The WEC
  result shows that CPU credits change the outcome, so production WEC sizing must be measured.
- One 24-hour run. Slow memory growth cannot be told apart from warm-up within it.
- The soak qualifies only `1a4c4c2`. Later merges are not covered by it and rely on their own
  evidence: #161 (storage pressure), #169 (replay-safe detections) and #171 (TLS-expiry fix).
- The C# collector only. Docker, Kubernetes and Azure-hosted collectors did not run.
- Packages are unsigned (signing deferred).
- Identity lists are not published (900k ids per collector). Digests, counts and the hourly and
  per-window metadata are published, and `lab/aws/soak/reconcile.py` recomputes them from the
  host exports.

## Cleanup

**Zero resources with RunId `bower-soak-20261102-015614` remain in AWS or Azure.**
[`cleanup.json`](cleanup.json) was produced on 2026-11-03 after teardown by
[`relp-cleanup-audit.py`](../../../lab/aws/monitoring/relp-cleanup-audit.py) and records
**37 of 37 checks absent**. This run added an exact Secrets Manager check (`describe-secret`
must return `ResourceNotFoundException`).

Teardown order:

1. Account check and tag check of the stack, bucket and secret.
2. Bucket emptied, then `delete-stack` and `stack-delete-complete`.
3. `azure-environment.py cleanup --apply`: workspace force-deleted, applications and service
   principals deleted and purged, role assignments removed, resource group deleted (including the
   monitoring alert rules and the DCR diagnostic setting); `cleanupErrors: []`.
4. The audit.

Every check is proven by one of:
- the exact not-found code of its own query: `404` (bucket), `InvalidVolume.NotFound`,
  `InvalidGroup.NotFound`, `InvalidSubnetID.NotFound`, `InvalidRouteTableID.NotFound`,
  `NoSuchEntity` (3 roles, 2 profiles), `ResourceNotFoundException` (expiry schedule, secret),
  or Graph `Request_ResourceNotFound` (2 purged applications and 2 service principals);
- a successful empty listing: snapshots, log groups, tagged secrets, the region-wide RunId tag
  sweep, the Azure group and tagged resources, the soft-deleted workspace list, app and SP
  display names, role assignments;
- a `terminated` instance state for the four instances.

Audit inputs: `operations/` (`operations/`). The shared VPC, NAT gateway and every other
pre-existing resource were untouched. The local private staging directory (keys, certificates,
tokens, Azure identity files and caches) was deleted. The 30-hour expiry schedule was not
relied on: it was deleted with the stack before it fired.

## Corrections after review

Council round 1 on PR #170 found defects in the reconciler and the write-up. They were fixed on
2026-11-03, after the lab and its identity lists had been deleted, so only conclusions
derivable from the committed evidence were recomputed. Nothing below changes a pass into a fail
or a fail into a pass, except where stated.

| Issue | What the run did | Now |
|---|---|---|
| Native completeness was not enforced | `final` could report `exact: true` with partial or empty native input | `reconcile.py` requires the profile: 18 generator segments with exact counters, 896,400 planned events, all 25 native windows, original-id columns, and native = DC attempts. Fixture tests cover missing, extra, duplicate and empty inputs. Re-run on the committed evidence: the firewall meets every gate (18 segments, 896,400 ids, every counter exact). The WEC meets the window, record and generator gates (25 windows, 896,400 records = 896,400 attempts, all LDAP result 49). Its original-id gates (ids files, original-id count, duplicates) need the deleted lists and report incomplete |
| Accepted extras were hidden | Accepted counts and digest were taken over `queue ∩ native` | Accepted ids are scoped by source and window and compared as full sets (`extraAtAccepted`). Firewall: no change possible (scope = native range). WEC: **accepted extras not verified**; cannot be recomputed |
| Growth included the drain | Resource slopes used samples to hour 25 | Hours 3–24 of the workload only, recomputed from `series/` ([resource-trends-recomputed.json](final/resource-trends-recomputed.json)); drain reported separately. Both collectors still fail; firewall threads now pass (falling) |
| Mixed identity forms | `crossWindowOrInWindowDuplicates: 1` in `final-reconciliation.json` | That was the probe's redacted-id collision in `h23`. Native counts and duplicates now use original ids; redacted counts are labelled `probeRedacted*` |
| CPU added to criterion 3 after registration | The guide's criterion 3 said "CPU per event does not trend upwards" | Moved to a recommendation for future runs; the WEC CPU growth is an observation, not a criterion-3 result |
| Latency comment | `reconcile.py` said the gate applied to every hour | The registered rule is the whole-run p99; hours above are listed |
| WEC backlog estimate | Earlier notes used `RecordCount - eventsRead` | Unknown: the two values have different baselines; the final sample gives −103. The historical export lacks the newest record ID. |
| Alerts read | First page only, failures recorded as an error object | Paginated, fail closed, and each alert is marked active or not during the run. This run's list (`monitoring/alerts-final.json`) was captured with one request returning three items; whether a further page existed was not checked |
| Line endings | 25 Windows-origin JSON files had CRLF | Normalised to LF (content otherwise unchanged) |
| Interim latency set | The interim firewall latency used every row the padded query returned: 39,000 rows against 36,000 reconciled ids (the extra 3,000 are 04:35Z to 04:40Z) | `sentinel()` applies the identity scope before any count or latency. The published interim p99 (8.97 s) includes those rows and cannot be recomputed without the deleted lists. The final reconciliation is not affected: its firewall latency count is exactly the 896,400 reconciled ids |
| Final-export retry | The Linux agent wrote `final.json` before uploading, the WEC agent gated on `final.json`, and the DC exporter skipped a window once exported, so a failed upload was never retried | Completion markers are written only after the uploads succeed (`final.json` after data on Linux, `published.json` on the WEC, `<window>.json.uploaded` on the DC). In this run, the WEC final export was completed by hand, as recorded above |

`final/final-reconciliation.json` and the two smoke and interim reports are the reports as
produced at the run and are kept unchanged; read their accepted figures with the caveat above.
