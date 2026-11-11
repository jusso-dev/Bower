# 72-hour re-soak: `bower-resoak-20261106-092539`

**Result: the re-soak FAILED.** `final.json` has `verdict.pass: false`. Neither collector met
all six pre-registered criteria. The firewall failed criteria 3 and 5. The WEC failed 3 and 5,
and criterion 1 is not met because one native export window is missing (blocked, below). Every
fault outcome held (`faultOutcomesPass: true`), both collectors reported the candidate version
(`versionMatches: true`), there were no unplanned restarts and no privacy-marker matches.
Soak window: 2026-11-06T11:05:00Z to 2026-11-09T11:05:00Z (72 h), main `8f615b8`.

| # | Criterion | Firewall (RPM, RELP) | WEC (MSI) |
|---|---|---|---|
| 1 | Native = accepted = distinct Sentinel, exactly | **PASS**: 2,693,520 = 2,693,520 = 2,693,520; 0 duplicate rows | **FAIL (blocked: native evidence missing)**: accepted 2,693,520 = distinct Sentinel 2,693,520, 0 duplicate rows, 0 missing; native 2,693,469 because window `h72` was never exported (`missing-window-h72`), so 51 accepted and Sentinel ids have no native record |
| 2 | Only the scheduled restarts | **PASS**: 4 process identities, 2 boots, as scheduled (F05, F08, F09); none unexplained | **PASS**: 4 process identities, 2 boots, as scheduled (F06, F07, F09); none unexplained |
| 3 | No unbounded growth (both registered windows) | **FAIL**: hours 3–24 queue DB + WAL +55%, threads +19%; after the last restart memory +199%, FDs +55% | **FAIL**: hours 3–24 memory +210%, threads +294%, queue +26%, handles +15%; after the last restart memory +49%, threads +41%, handles +23% |
| 4 | p99 latency outside fault windows ≤ 2× the pilot's connected p99 | **PASS**: 7.9 s ≤ 13.3 s; one hour above the limit (hour 58) | **PASS**: 11.5 s ≤ 18.16 s; one hour above the limit (hour 58) |
| 5 | No alerts outside the registered fault accounting | **FAIL**: one unexcused `dcr-request-errors` alert, 2026-11-08T21:28:49Z to 21:48:52Z | **FAIL**: the same alert (the rule is per DCR, shared by both collectors) |
| 6 | 0 privacy-marker matches | **PASS**: 0 of 2,697,897 rows | **PASS**: 0 of 2,697,894 rows |

Identity digests (SHA-256 of the sorted ids joined by newline), from
[`final/final.json`](final/final.json): firewall native, accepted and Sentinel all
`57dc803d81f2199590905e4120ef0c802112569bdd9b6ec5243baffe774c0142`. WEC accepted and Sentinel
`cdd628ed7488c5b92f0aab3c6c6a1a0456a128dcf33d06fa7d0fd67ecdced634`; WEC native (72 of 73
windows) `ac42b3d05cbb66ec4449e40ccd75934bc8b286db6fbdbde3c2174136bea5c5fa`.

## What ran, where

| Item | Value |
|---|---|
| Plan | Pre-registered on 2026-11-03: `lab/aws/resoak/preregistration.json` SHA-256 `b06e344f786d89bedfabc4f76908916103270225f7a2a52daa271754e7299d6e`. The staged plan and the plan the reconciler checked are byte-identical ([`operations/stage.json`](operations/stage.json), [`final/final.json`](final/final.json) `planSha256`) |
| Harness | Branch `test/resoak-72h-v2` (not merged). Launched at `de3ca08`; refreshed on 2026-11-07 to `4b529bc` for the final reconciliation, which adds the query-cache fix [#199](https://github.com/jusso-dev/Bower/pull/199) (`Cache-Control: no-cache`, partial results rejected). Only query code changed; the plan hash did not |
| Candidate | main `8f615b8ed10d84d6a4b19ff42415b24d9a89b623`, CI run [42130604210](https://github.com/jusso-dev/Bower/actions/runs/42130604210) (workflow_dispatch, build 416), version `0.1.1-dev.416`. **Unsigned**: release signing is deferred. RPM `bower-collector-0.1.1~dev.416-1.x86_64.rpm` `7b02d15d9596d888ce5b7b0e9e794ec87fda4423c56c6c066d58aab04985f59e`; MSI `bower-collector-0.1.1-dev.416-x64.msi` `f26c00ea2090c73bb5a80a9fc0f3f6de068953c98e8a31003159b526f73093b6` ([`operations/candidate.json`](operations/candidate.json)) |
| Release check 0 | [`operations/candidate.json`](operations/candidate.json) was captured when the CI run's conclusion was `failure`: `windows-event-log` failed twice with "Access is denied" opening a test event log on the hosted runner. Attempt 3 re-ran only the failed jobs and finished `success` at 2026-11-07T01:25:34Z, about 14 h 20 m after the soak started, which closed check 0 for `8f615b8` ([`operations/ci-run-42130604210-attempt-3.json`](operations/ci-run-42130604210-attempt-3.json)). The build, package and install jobs passed in attempt 1 and were not rebuilt, so the RPM and MSI under test are the ones hashed above |
| Hosts | AWS account 959038055523, ap-southeast-2, stack `bower-resoak-20261106-092539`. Four `m6i.large` (fixed performance, no CPU credits): `Dc` and `Wec` Windows Server 2022 (the WEC runs the MSI collector, `ForwardedEvents` 4 GiB), `Sender` and `Linux` Amazon Linux 2023 (the Linux collector runs the RPM with the RELP listener; the sender runs rsyslog 8.2610.0 with `omrelp`). Private subnet 172.31.248.0/24 through the existing NAT gateway, no inbound rules |
| Collector settings | `BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60`, `BOWER_QUEUE_RETENTION_HOURS=2` (from the registered profile) |
| Azure | `rg-bower-resoak-20261106-092539` (Australia East): workspace with Sentinel, the repository Bicep DCE, DCR and table, the monitoring alert rules from `deploy/sentinel/monitoring/monitoring.bicep`, an ingestion application and a verifier application (Log Analytics Reader on the workspace only). Every query in `final.json` ran as the verifier |
| Load | 10 events/s per collector, plus 60 s at 100/s every 4 hours from +2 h: 2,689,200 events per collector, plus one canary a minute per source (4,320). Windows events are failed NTLM LDAP binds to the DC (all 2,689,200 attempts returned LDAP result 49) |
| Faults | F01 to F11 on the registered schedule (below). Sentinel throttling was registered as skipped and is not passed |
| Packs | Signed with a run key (public key SHA-256 `637f1b0d…5a41`): `syslog-reliability-1.0.0`, `windows-security-logon-1.0.2` ([`operations/stage.json`](operations/stage.json)) |

The re-soak differs from the [24-hour soak](../soak-20261102-015614/README.md) in four ways:
it ran 72 hours, on fixed-performance hosts, with scheduled faults, and with each fault's
expected restarts, latency and alerts accounted for by rules fixed before the run. The
[pre-registration](https://github.com/jusso-dev/Bower/blob/4b529bc71f4d43da8969d0d7fb6e3fe3aadeed8b/lab/aws/resoak/preregistration.json)
(on the harness branch, not on main) copies the six criteria verbatim from the 24-hour soak's
table (`criteriaSource`: guide section 2 at `71d5de7`), then its `faultAccounting` rules change
how criteria 2 to 5 are judged. So the re-soak's gates are **not** the section 2 table as
written. The registered rules:

- Criterion 1 is unchanged and applies to every event, fault windows and canaries included.
- Criterion 2 allows exactly the scheduled restarts and reboots, each starting inside its fault
  window, instead of one process identity for the whole run.
- Criterion 3 must pass on two windows: hours 3–24 (no restart in it) and from 3 hours after the
  last scheduled restart (F09 at +35:20, so from +38:20) to +72:00.
- Criterion 4's gated p99 is over events whose event time is outside every fault window, not
  the whole run; the p99 including fault windows is reported only.
- Criterion 5 excuses only an alert of a rule the fault lists, starting inside that fault's
  alert window (fault start to fault end + impact allowance + 1 hour). `syslog-tls-expiry` and
  `destination-credential` are never excused.
- Criterion 6 is unchanged, with `bower-canary` added as a marker.

## Results in detail

### 1. Exact delivery (firewall PASS; WEC FAIL, blocked)

- **Firewall.** 54 generator segments, every one exact against the nftables counter: 2,689,200
  events plus 4,320 canaries. Native = accepted = distinct Sentinel = 2,693,520, the same digest
  on all three, 0 missing, 0 extra, 0 duplicate rows.
- **WEC.** The DC generator made 2,689,200 attempts in 54 clean segments, and 4,320 canary
  attempts; 2,693,520 in all. Accepted and Sentinel both hold exactly 2,693,520 distinct ids with
  the same digest, 0 missing, 0 duplicate rows. The DC native export holds 2,693,469 in
  windows `h00` to `h71`; window `h72` is missing. The reconciler reports
  `missing-window-h72` and `native-2693469-differs-from-2693520-attempts`, so
  `extraAtAccepted` and `extraAtSentinel` are both 51.
- **Why `h72` is missing.** The generators drift late: the firewall's last segment ended at
  11:06:44Z, 104 s after the soak end. The DC generator ran past the end of `h71`
  (11:05:00Z) too, and the run's handoff prescribed exporting `h72` on demand (`native-h72`)
  before the hosts powered themselves off at 2026-11-09T15:05Z. The scheduled final
  reconciliation produced `final.json` (its recorded generation time, set before its queries,
  is 11:45:58Z; its health data runs to 12:01Z) but was interrupted before it ran
  `native-h72`. The hosts then terminated, so the window cannot be exported now.
- **Reading.** The 51 ids equal the number of generator attempts not covered by an exported
  window, and accepted and Sentinel equal the attempt count exactly, so the most likely reading
  is that they are events generated after 11:05:00Z. That is not proof: without the `h72`
  export no native record exists for them. **Criterion 1 is not met for the WEC.** It is
  recorded as blocked by missing native evidence, not as a proven delivery failure.
- **Canaries.** 4,320 of 4,320 at Sentinel per source, no minute without a canary, none over
  120 s outside fault windows.

### 2. Restarts (both PASS)

| Collector | Process identity first seen (UTC) | Fault |
|---|---|---|
| Linux | 2026-11-06T11:05:00Z, 11-07T13:30:00Z, 11-07T20:30:01Z, 11-07T22:30:01Z | start, F05 kill, F08 reboot, F09 credential rotation |
| WEC | 2026-11-06T11:05:02Z, 11-07T15:30:01Z, 11-07T18:30:02Z, 11-07T22:30:01Z | start, F06 kill, F07 reboot, F09 credential rotation |

Each collector had 4 process identities and 2 boots, exactly as scheduled, and
`unexplained: []`. Times are the first 5-minute sample of each identity.

### 3. Resource trends (both FAIL)

Least squares over 5-minute samples; "30-day %" is slope × 720 h as a percentage of the mean,
and must be under 10% (a falling series passes). Both windows are registered and both must pass.

**Hours 3–24** (2026-11-06T14:05Z to 11-07T11:05Z, 252 samples, no restart):

| Series | Firewall slope/h | 30-day % | Range | WEC slope/h | 30-day % | Range |
|---|---|---|---|---|---|---|
| Memory (RSS / private bytes) | −35.7 KB | −24.4% pass (falling) | 94.8–116.2 MB | +111.7 KB | **210.2% fail** | 32.0–46.0 MB |
| FDs / handles | −0.004 | −14.5% pass (falling) | 21–23 | +0.082 | **14.6% fail** | 397–427 |
| Threads | +0.005 | **19.1% fail** | 17–18 | +0.061 | **293.9% fail** | 14–19 |
| Queue DB + WAL | +219.8 KB | **54.8% fail** | 273.3–294.1 MB | +110.4 KB | **26.2% fail** | 294.7–324.3 MB |

**From +38:20 to +72:00** (2026-11-08T01:25Z to 11-09T11:05Z, 404 samples, 3 hours after the
F09 restart):

| Series | Firewall slope/h | 30-day % | Range | WEC slope/h | 30-day % | Range |
|---|---|---|---|---|---|---|
| Memory | +252.4 KB | **199.2% fail** | 72.4–108.3 MB | +24.6 KB | **49.2% fail** | 30.6–49.6 MB |
| FDs / handles | +0.017 | **55.3% fail** | 21–24 | +0.133 | **23.4% fail** | 398–425 |
| Threads | about 0 | −1.1% pass | 16–18 | +0.008 | **40.8% fail** | 13–18 |
| Queue DB + WAL | +9.1 KB | 2.3% pass | 289.4–303.1 MB | +6.8 KB | 1.6% pass | 303.4–324.9 MB |

Context, which does not change the registered result:

- The queue file rose through hours 3–24 and was flat (2.3% and 1.6%) in the later window, which
  fits a database file growing to a steady size under 2-hour retention and then reusing its
  pages. That is a reading of the shape, not a proof.
- The later window starts 3 hours after a process restart, so its memory slope includes
  whatever warm-up the new process still had. The firewall's memory fell over hours 3–24 and
  rose after the restart; one run cannot tell warm-up from a slow leak.
- Thread and FD counts are small integers (firewall threads 17–18, FDs 21–24), so a single
  extra thread or handle for part of a window moves the slope a long way.

Still, every failing series is above the threshold registered before the run, so criterion 3
fails on both collectors.

**CPU** (reported, not gated). The firewall averaged 60.1 CPU seconds an hour over the first 24
hours and 58.2 over the last 24; the WEC 38.4 and 38.8. The WEC's growth to about 2,500 s/h in
the 24-hour soak (on a credit-limited `t3.medium`) did not recur over 72 hours on `m6i.large`,
including after `ForwardedEvents` filled (below).

### 4. Latency (both PASS)

First `ingestion_time()` minus event time, from [`final/final.json`](final/final.json):

| | Firewall | WEC |
|---|---|---|
| Limit (2× pilot connected p99) | 13.3 s | 18.16 s |
| Outside fault windows (gated): count, p50 / p95 / p99, max | 2,570,950; 3.9 / 6.3 / **7.9** s; max 1,845.8 s | 2,597,956; 6.8 / 9.5 / **11.5** s; max 66.3 s |
| Including fault windows (reported): p50 / p95 / p99, max | 3.9 / 6.5 / 9.8 s; max 1,845.8 s | 6.8 / 9.7 / 13.7 s; max 1,813.7 s |
| Hours above the limit | hour 58 | hour 58 |

- **Hour 58** (2026-11-08T21:05Z to 22:05Z) was the only hour whose p99 was above the limit, on
  both collectors: firewall p95 17.0 s, p99 46.2 s, max 77.6 s; WEC p95 17.3 s, p99 39.8 s,
  max 66.3 s. It contains a scheduled 100/s burst (firewall 21:06:24Z to 21:07:24Z) and the
  `dcr-request-errors` alert (section 5). Every other burst hour had a firewall p99 between 6.7 s and
  8.6 s (`latency.hourly`, gated), so the burst alone does not explain it. Both collectors slowing in the same hour, together with
  an alert on non-success responses at the shared DCR, points at the destination side, but the
  evidence does not prove it.
- **The large maxima come from F01**, the 30-minute destination outage from 12:25Z on
  2026-11-06. Events written during it were held until the destination returned at about
  12:55Z: F01's maximum was 1,845.1 s (firewall) and 1,813.7 s (WEC). The firewall's
  1,845.8 s maximum outside fault windows is in the same hour (11-06 12:05Z to 13:05Z, whose
  other events had a p99 of 7.3 s) and matches the outage length, so it is most likely an event
  stamped just before the window opened and delivered after the restore. The WEC's largest
  latency outside fault windows was 66.3 s, in hour 58.
- **Per fault** (maximum latency inside the window): F01 1,845.1 s and 1,813.7 s; F02 16.1 and
  12.4 s; F03 10.6 s; F04 23.7 s; F05 24.8 s; F06 11.3 s; F07 22.4 s; F08 36.6 s; F09 20.8 and
  11.7 s; F10 17.0 and 19.9 s; F11 13.5 s.

### 5. Alerts (both FAIL)

Seven alert instances were listed; five were active during the run. Sentinel had no incidents.

| Rule | Started (UTC) | Resolved (UTC) | Accounting |
|---|---|---|---|
| `collector-health-missing` × 2 | 2026-11-06T09:30:44Z | 09:56:42Z and 10:01:44Z | Before the run, before the collectors sent health records; not counted |
| `collector-health-missing` × 2 | 2026-11-06T12:40:40Z | 13:06:42Z and 13:11:42Z | Excused by F01 |
| `queue-backlog` × 2 | 2026-11-06T12:57:25Z | 13:23:58Z | Excused by F01 |
| `dcr-request-errors` | **2026-11-08T21:28:49Z** | **21:48:52Z** | **Violation**: no fault lists this rule |

`dcr-request-errors` is an Azure Monitor metric alert on the DCR: it fires when
`ApiCallReceived_Count` with a response code other than 200, 202 or 204 is above 0 in a
15-minute window. It started inside F11's alert window (F11 was a log rollover at 20:25Z; its
alert window ran to 21:40Z), but F11 permits no alerts, and F09, the ingestion-credential
rotation, was 23 hours earlier (2026-11-07T22:25Z). So it is not excused.

**The cause is not determined.** The evidence does not record the response code or the
request. What it does show:

- The alert falls in hour 58, the one hour with latency above the limit on both collectors.
- Neither collector restarted, and every 60-second health record outside F01 was `healthy`. A
  retry shorter than a sample would not show there.
- There were no duplicate rows and nothing missing at Sentinel.
- `naturalEvents.deliveryFailureCodes` lists the distinct codes seen over the whole run, without
  times. It holds only `delivery-failure`, which F01 also produces, so it cannot place a failure
  at 21:00Z.

The workspace and DCR are deleted, so the metric cannot be split by response code now.

### 6. Privacy (PASS)

`tostring(pack_all())` of every row, including health records, matched none of the synthetic
markers (with `bower-canary` added for this run): 0 of 2,697,897 firewall rows and 0 of
2,697,894 WEC rows.

### Faults (all outcomes PASS)

| Fault | At (UTC) | Collectors | Outcome |
|---|---|---|---|
| F01 destination outage, 30 min | 11-06 12:25 | both | Blocked for the full 30 minutes, restored on both hosts at 12:55Z; `collector-health-missing` and `queue-backlog` fired and resolved; no restart |
| F02 sender restart | 11-06 15:25 | both | Ran on Sender and Dc |
| F03 log rollover | 11-06 19:25 | firewall | Ran on Sender and Linux |
| F04 syslog TLS certificate rotation | 11-06 23:25 | firewall | Hot reload, no restart |
| F05 collector kill | 11-07 13:25 | firewall | One new process |
| F06 collector kill | 11-07 15:25 | WEC | One new process |
| F07 host reboot | 11-07 18:25 | WEC | Back after reboot |
| F08 host reboot | 11-07 20:25 | firewall | Back after reboot |
| F09 ingestion certificate rotation | 11-07 22:25 | both | One restart each, inside the window; no `destination-credential` alert |
| F10 sender restart | 11-08 08:25 | both | As F02 |
| F11 log rollover | 11-08 20:25 | firewall | As F03 |

Every fault ran on every expected host within 120 s of its schedule, with no failed or missed
step, and every check in `faultOutcomes` is true. Criterion 1 covers every event inside every
fault window: nothing was missing at Sentinel on either collector.

### Natural events

| Event | Evidence |
|---|---|
| `queue-retention` hourly | 136 runs observed on Linux, 143 on the WEC (`Processing`, `Succeeded`) |
| `queue-maintenance` daily | 3 runs on each collector, all `Succeeded` (last 2026-11-09T03:00Z) |
| `ForwardedEvents` full | First full sample 2026-11-08T14:35Z: 1,936,262 records, 4,230,025,216 bytes. Reader gaps, resets, cursor conflicts and read errors all 0 for the whole run |
| Entra token refresh with no delivery failure code | **Not demonstrated.** `deliveryFailureCodes` holds `delivery-failure` with no times, so a refresh-related failure cannot be told apart from F01's, and the evidence has no separate token-refresh record |
| Sender journald rotation | **Not recorded.** No committed file holds a journald rotation observation for this run. F03 and F11 (scheduled log rollovers) ran, but they are faults, not the natural rotation |
| Health records | Linux 4,375, WEC 4,372; largest gap 61 s and 68 s. Non-healthy outcomes (`retrying`, `stalled`) only during F01 |
| Samples | 864 per collector; largest gap 301 s. Linux: 9 samples without status (`URLError`, `ValueError`); WEC: 1 without the process (`ProcessCommandException`) |
| Disk | Minimum free: Linux 29.3 GB, WEC 15.1 GB |
| Queue | Peak pending 18,065 (firewall) and 18,050 (WEC), oldest undelivered about 1,800 s: the F01 outage |

## Smoke and interim

- **Smoke** (2026-11-06T10:30Z to 10:45Z, ended 20 minutes before the soak): exact on both
  collectors, 9,000 native = accepted = distinct Sentinel, 0 duplicates, p99 7.1 s and 10.0 s,
  privacy 0 matches, both reporting `0.1.1-dev.416`
  ([`smoke/smoke.json`](smoke/smoke.json), [`smoke/smoke-summary.json`](smoke/smoke-summary.json)).
- **Interim** ([`interim/interim.json`](interim/interim.json)) ran at 2026-11-07T01:18Z, soak
  +14 h 13 m, not at the planned +2 h 10. Its window was hour 0 (`h00`, 11:05Z to 12:05Z). The WEC was exact
  for hour 0: 36,059 native = 36,059 distinct at Sentinel, same digest, 0 duplicates (its
  `extraAtAccepted` 18,003 counts ids accepted after hour 0). The firewall figures are **not a
  valid comparison**: the interim reads the firewall native set from the host export, which does
  not stop at hour 0. At +14 h it held 526,260 ids while the Sentinel query covered hour 0, hence 487,201 "missing at Sentinel"
  and 9,173 "missing at accepted". They are timing, not loss: the final reconciliation is exact
  for every firewall id. Interim privacy, health and alerts passed.

## Aborted first attempt: `bower-resoak-20261105-234529`

An earlier attempt on the same candidate started its soak at 2026-11-06T02:05:00Z
([`aborted-run/run.json`](aborted-run/run.json)) and was aborted at about 09:20Z, before any
verdict (the abort time is from the operator's record; no committed file holds it). The
attempt's interim, generated at 03:36:24Z (soak +1 h 31 m) over hour 0 (02:05Z to 03:05Z), lists
two `destination-freshness` alerts, one per collector, that started at 02:04:36Z, 24 s before
the soak start, and resolved at 02:20:36Z. Its `alertAccounting` records both as violations
([`aborted-run/interim.json`](aborted-run/interim.json),
[`aborted-run/interim-summary.json`](aborted-run/interim-summary.json)), so the run could not
pass criterion 5. The cause was the harness: the smoke's workload ended at 01:00:00Z and the
soak's started at 02:05:00Z (`run.json`), a 65-minute gap against the rule's 60-minute silence
allowance. The harness was fixed (the smoke now ends 20 minutes before the soak) and the run was
replaced by this one.

What the committed files show for that attempt:

- **Smoke** (00:45Z to 01:00Z, [`aborted-run/smoke.json`](aborted-run/smoke.json),
  [`aborted-run/smoke-summary.json`](aborted-run/smoke-summary.json)): exact on both
  collectors, 9,000 native = accepted = distinct Sentinel, 0 duplicate rows, privacy 0 matches.
- **Hour 0 interim:** 0 missing at Sentinel and 0 duplicate rows on both collectors; canaries
  56 of 56 (firewall) and 60 of 60 (WEC) at Sentinel. The accepted counts (33,066 and 19,225)
  were short of native, while Sentinel held every native id. The operator's reading is that the
  interim ran before the hosts' hourly upload of the accepted set; it is not a delivery loss.
- **Hour 0 latency** was above the limits: p99 25.1 s (firewall, limit 13.3 s) and 32.8 s
  (WEC, limit 18.16 s), maxima 48.1 s and 49.3 s. The cause was not investigated; similar
  maxima on both paths are consistent with destination-side latency but do not show it.

It was torn down and audited: **38 of 38 absent**
([`aborted-run/cleanup.json`](aborted-run/cleanup.json), 2026-11-06).

## Limits

- One 72-hour run on lab hosts, not a firewall appliance or a production domain. Fixed-performance
  `m6i.large`; burstable hosts were not re-tested.
- WEC criterion 1 cannot be completed: the `h72` export does not exist and the hosts are gone.
- The `dcr-request-errors` response code was not captured, and cannot be now.
- The harness relies on an operator step after the end (`final`, and `native-h72` when the DC
  generator drifts past the last window) before the hosts power off at end + 4 h. This run missed
  that step.
- Sentinel throttling (HTTP 429) was registered as skipped, not passed.
- The run qualifies only `8f615b8` (`0.1.1-dev.416`). Packages are unsigned (signing deferred).
- The C# collector only. Docker, Kubernetes, Azure-hosted and on-premises collectors did not run.
- Identity lists are not published (2.7 million ids per collector). They were kept in the RunId's
  identity bucket during the run and deleted with it at teardown. Digests, counts, segment and
  per-window metadata are published.

## Cleanup

**Zero resources with RunId `bower-resoak-20261106-092539` remain in AWS or Azure.**
[`cleanup.json`](cleanup.json) was produced on 2026-11-10T11:49Z after teardown by
`relp-cleanup-audit.py` and records **38 of 38 checks absent** (`allAbsent: true`): the stack,
both buckets (run and identity), the four instances and four volumes, the subnet, route table and
security group, three IAM roles and two instance profiles, the expiry schedule, the secret,
tagged snapshots, log groups and secrets, a region-wide RunId tag sweep, the Azure resource group
and tagged resources, the soft-deleted workspace, and both Entra applications with their service
principals, purged deleted items and role assignments. The private lab directory (keys,
certificates, credentials) was deleted after the audit.

The hosts had already been terminated by their expiry guard, set for 2026-11-09T15:05Z. The
estimated cost of this run was about USD 110–125 (an estimate from the run's plan: EC2, storage
and transfer, Log Analytics and Sentinel ingestion of about 10 GB, alert rules), plus about USD 11
for the aborted attempt. Two subscription-level resource-provider registrations
(`Microsoft.Insights` re-registered, `Microsoft.Logic` registered) were kept; they have no
running cost.

## Files

| File | What it is |
|---|---|
| [`final/final.json`](final/final.json) | The final reconciliation and verdict; recorded generation time (set before its queries) 2026-11-09T11:45:58Z |
| [`interim/interim.json`](interim/interim.json) | The interim reconciliation (+14 h 13 m); read the firewall figures with the caveat above |
| [`smoke/smoke.json`](smoke/smoke.json), [`smoke/smoke-summary.json`](smoke/smoke-summary.json) | The 15-minute smoke |
| [`operations/candidate.json`](operations/candidate.json) | The candidate build, package hashes and CI state at capture |
| [`operations/stage.json`](operations/stage.json) | Plan, manifest, tool, pack and certificate hashes (no keys) |
| [`operations/run.json`](operations/run.json) | Smoke and soak times and the expiry-guard times |
| [`cleanup.json`](cleanup.json) | The cleanup audit of this run |
| [`operations/ci-run-42130604210-attempt-3.json`](operations/ci-run-42130604210-attempt-3.json) | CI run 42130604210 attempt 3: run conclusion and every job's name, conclusion and times (fetched from the GitHub REST API on 2026-11-11) |
| [`aborted-run/run.json`](aborted-run/run.json), [`aborted-run/smoke.json`](aborted-run/smoke.json), [`aborted-run/smoke-summary.json`](aborted-run/smoke-summary.json), [`aborted-run/interim.json`](aborted-run/interim.json), [`aborted-run/interim-summary.json`](aborted-run/interim-summary.json) | The aborted attempt's times, smoke and hour 0 interim, including its alert list and accounting |
| [`aborted-run/cleanup.json`](aborted-run/cleanup.json) | The cleanup audit of the aborted attempt |

All files are metadata: counts, digests, hashes and resource names. The application ids in
`final.json` and the cleanup audits belong to deleted Entra applications.
