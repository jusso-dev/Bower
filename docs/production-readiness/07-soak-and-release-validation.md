# 7. 24-hour soak and release validation

**Gap:** prove that the scoped rollout stays correct and stable for a full day of ordinary
traffic, including the hourly and daily housekeeping that short tests never reach, and give
every release a repeatable gate that ties gaps 1 to 6 together.

**Scope:** the scoped rollout, Windows WEF/WEC (`ForwardedEvents`) and firewall syslog over
RELP with mutual TLS, to the C# Bower collector, to Microsoft Sentinel (Logs Ingestion API).
Releases and packages are **unsigned** (signing is deferred). Bower still refuses unsigned or
untrusted packs.

**Status: the soak was run and FAILED three of six criteria.** Every one of 896,400 events
per collector reached Sentinel exactly (native = accepted = distinct Sentinel, SHA-256
identical, duplicates counted separately), with no process restarts and no privacy-marker
matches. It failed on:

- **WEC latency.** p99 reached 882 s. The Windows Event Log reader's CPU cost grows with the
  size of `ForwardedEvents`, so on a CPU-credit-limited host the reader fell up to about 12
  minutes behind.
- **Alerts.** The TLS-expiry false positive fired all run (fixed afterwards on main by #171),
  and the source-transport alert fired twice, correctly, when the WEC source failed during the
  hourly queue retention.
- **Growth.** The pre-registered slope threshold failed for memory and handles on both
  collectors over 24 hours.

The firewall path is ready on this evidence. **The WEC path is not ready** until the reader
cost is fixed and the soak is repeated. See [results](#6-results-of-the-soak) and the
[evidence](../evidence/soak-20261102-015614/README.md).

The soak ran main at **`1a4c4c2`**. Later merges are not covered by it and rely on their own
evidence: [#161](https://github.com/jusso-dev/Bower/pull/161) storage pressure
([gap 3](03-storage-pressure.md)), [#169](https://github.com/jusso-dev/Bower/pull/169)
replay-safe detections ([gap 2](02-replay-safe-detections.md)) and
[#171](https://github.com/jusso-dev/Bower/pull/171) the TLS-expiry fix. Main is now
`d7ddc55`. A release built from it needs its own soak (section 4).

Contents:

1. [What a soak proves, and what it does not](#1-what-a-soak-proves-and-what-it-does-not)
2. [Pass criteria](#2-pass-criteria)
3. [The soak method (all environments)](#3-the-soak-method-all-environments)
4. [Step by step, per environment](#4-step-by-step-per-environment)
5. [Release checklist (gaps 1 to 7)](#5-release-checklist-gaps-1-to-7)
6. [Results of the soak](#6-results-of-the-soak)
7. [Troubleshooting](#7-troubleshooting)
8. [How we tested this](#8-how-we-tested-this)
9. [Known defects found by this work](#9-known-defects-found-by-this-work)
10. [Known limits](#10-known-limits)

## 1. What a soak proves, and what it does not

A soak runs the real topology at a realistic, steady rate for long enough that:

- every recurring job runs many times: `queue-retention` hourly, `queue-maintenance` daily at
  03:00 UTC, `source-activity` every minute, Entra token refresh, health records;
- logs and journals rotate, and event logs grow to sizes that short tests never reach;
- slow resource growth (memory, handles, queue file) becomes measurable;
- latency is observed through bursts, not just averaged.

It injects **no faults**. Faults are qualified by gaps 1 to 6. A soak that passes does not
replace those tests, and a fault test does not replace a soak.

## 2. Pass criteria

Register these before the run starts. Never change them afterwards. A run passes only if **all**
of them hold for **every** collector.

| # | Criterion | How it is measured | Pass |
|---|---|---|---|
| 1 | Exact delivery | Native, accepted and distinct Sentinel identity sets, compared by SHA-256 of the sorted ids joined by newline | All three equal, 0 missing, 0 extra. Duplicate rows are counted and reported separately; they are allowed (at-least-once) if they collapse with the documented `arg_min(ingestion_time(), *) by EventId` query |
| 2 | No restarts | Collector PID and start time in every sample; systemd `NRestarts`; container `RestartCount`; pod `restartCount`; boot ID | One process identity for the whole run |
| 3 | No unbounded growth | Least-squares slope over hours 3–24 of memory (RSS / private bytes), FDs / handles, threads and queue DB + WAL bytes, plus **CPU seconds per hour at constant rate** | The slope × 720 h is under 10% of the mean, and CPU per event does not trend upwards |
| 4 | Latency | First `ingestion_time()` minus event time, per hour and overall | Whole-run p99 at most twice the pilot's connected p99 (13.3 s firewall, 18.16 s WEC; [pilot](../evidence/pilot-native-20261030/README.md)). Every hour above the limit is listed |
| 5 | No alerts | Azure Monitor alert instances and Sentinel incidents from the [monitoring rules](06-monitoring-and-runbooks.md) | None fired during the run |
| 6 | Privacy | `tostring(pack_all())` of every destination row searched for the synthetic markers (the synthetic user name, raw kernel prefix, synthetic password prefix) | 0 matches |

Natural events that must occur and be recorded: hourly retention purging rows (set
`BOWER_QUEUE_RETENTION_HOURS` below the run length, for example 2), the daily maintenance job,
token refresh with no delivery failure code, journal or event-log rotation, health records with
no gap longer than two intervals.

## 3. The soak method (all environments)

The method is the same everywhere. Only the commands for sampling and exporting change.

**Purpose:** run the candidate release at production-like settings for 24 hours and decide pass
or fail on evidence.

**Prerequisites:**

- The candidate packages or image, with SHA-256 recorded and signature status recorded
  (currently unsigned).
- Collectors configured exactly as for production: packs signed by your trusted key,
  `BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60`, the delivery output, the source (RELP listener
  and/or Windows Event Log subscription).
- A **separate** Sentinel workspace or a dedicated, filterable `CollectorId`, plus a read-only
  verifier identity (Log Analytics Reader on the workspace only) that is not the ingestion
  identity.
- The alert rules from `deploy/sentinel/monitoring/monitoring.bicep` deployed **enabled**, with
  the soak collectors in `expectedCollectorIds` ([gap 6](06-monitoring-and-runbooks.md)).
- A synthetic source that numbers its events or can be counted natively:
  - firewall: nftables denials with sequence-encoded ports (the lab's `syslog-host.py generate`);
  - Windows: failed NTLM LDAP binds against a DC, counted in the DC Security log.
- Hosts sized for production. Burstable instances (AWS `t3`, Azure `B`) must use unlimited
  credits, or the soak measures the credit policy, not Bower (section 6).

**Steps:**

1. **Freeze the candidate.** Record commit, CI run, package hashes and `UNSIGNED.txt`.
2. **Deploy** using the gap 4 procedures ([upgrade, backup and recovery](04-upgrade-backup-recovery.md)).
3. **Smoke for 15 minutes** at 10 events/sec and reconcile exactly before starting the clock.
   A smoke that does not reconcile stops the soak.
4. **Start the soak** with everything host-side: the generator, a 5-minute sampler, a 30-minute
   accepted-identity export (it must run more often than retention purges), an hourly upload and
   an end-of-run export. Nothing may depend on an operator session.
5. **Profile:** 10 events/sec per collector, plus a 60-second burst at 100/sec every 4 hours.
   This gives 896,400 events per collector in 24 hours.
6. **Interim reconciliation** after the first hour. Find harness defects early.
7. **Final reconciliation** after the end plus 30 minutes, with the verifier identity.
8. **Analyse** against section 2. Preserve every failed attempt.
9. **Tear down** the soak resources and keep metadata-only evidence.

**Expected output:** a reconciliation report per collector with native/accepted/Sentinel
counts and digests, hourly latency, resource slopes, the health-record summary, alert instances
and privacy counts. In the lab this is
[`final-reconciliation.json`](../evidence/soak-20261102-015614/final/final-reconciliation.json).

**Rollback:** a soak changes nothing in production. If a production-like environment was used,
remove the soak collector IDs from `expectedCollectorIds` and delete the soak workspace.

## 4. Step by step, per environment

The lab harness ([`lab/aws/soak/`](https://github.com/jusso-dev/Bower/tree/main/lab/aws/soak))
implements these steps for AWS-hosted Linux and Windows collectors. The commands below are the
same steps for each supported environment.

### 4.1 Linux packages (RPM / DEB, systemd)

1. Install the candidate package and configure `/etc/bower/bower.env` as for production. Add
   the soak settings:

   ```bash
   sudo tee -a /etc/bower/bower.env >/dev/null <<'ENV'
   BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60
   BOWER_QUEUE_RETENTION_HOURS=2
   ENV
   sudo systemctl restart bower && systemctl is-active bower
   ```

   Expected: `active`. Install the host check:
   `sudo systemctl enable --now bower-healthcheck.timer` (from `deploy/sentinel/monitoring/host/`).
2. Record the restart baseline:

   ```bash
   systemctl show bower --property=MainPID,NRestarts,ActiveEnterTimestamp
   cat /proc/sys/kernel/random/boot_id
   ```

3. Sample every 5 minutes with a systemd timer, as root. Each sample needs the PID, CPU
   seconds, RSS, threads, FDs, `NRestarts`, queue file sizes and `/v1/status` (queue, jobs,
   delivery activity, source counters):

   ```bash
   pid=$(systemctl show bower --property=MainPID --value)
   awk '{print "cpu_ticks="$14+$15, "threads="$20, "rss_pages="$24}' /proc/$pid/stat
   ls /proc/$pid/fd | wc -l
   stat -c '%n %s' /var/lib/bower/queue.db*
   curl -fsS -H "Authorization: Bearer $(sudo cat /etc/bower/secrets/ingest-token)" \
     http://127.0.0.1:4319/v1/status | jq -c '{status, queue, jobs, deliveryActivity}'
   ```

   The lab version is `lab/aws/soak/collector-agent.sh` (`BOWER_SOAK_ACTION=install`). .NET
   writes timestamps with seven fractional digits; parse them with a tolerant parser (Python 3.9's
   `fromisoformat` rejects them).
4. Every 30 minutes, add the queue's identities to a union outside the queue (retention purges
   delivered rows). This is read-only:

   ```bash
   sudo sqlite3 /var/lib/bower-lab/accepted.db \
     "ATTACH 'file:/var/lib/bower/queue.db?mode=ro' AS q;
      CREATE TABLE IF NOT EXISTS ids(event_id TEXT PRIMARY KEY, first_seen TEXT);
      INSERT OR IGNORE INTO ids SELECT event_id, datetime('now') FROM q.queue_events_v5;"
   ```

5. At the end, export the union and the samples, then reconcile (section 4.8).

**Pass/fail:** section 2. **Troubleshooting:** section 7.

### 4.2 Windows MSI, including WEC hosts

1. Install the MSI. Put operator settings in `%ProgramData%\Bower\bower.env` (it survives
   upgrades), including the soak settings, then restart:

   ```powershell
   msiexec /i bower-collector-<version>-x64.msi /qn /norestart COLLECTORID=wec-soak-01 BOWERENVIRONMENT=soak
   Add-Content C:\ProgramData\Bower\bower.env "BOWER_HEALTH_RECORD_INTERVAL_SECONDS=60`r`nBOWER_QUEUE_RETENTION_HOURS=2"
   Restart-Service Bower; (Get-Service Bower).Status
   ```

   Expected: `Running`. Register `Test-BowerCollectorHealth.ps1` as a one-minute SYSTEM task
   ([gap 6](06-monitoring-and-runbooks.md)).
2. **Size `ForwardedEvents` to production.** Do not shrink it for the soak. The defect in
   section 9 only appears once the channel holds hundreds of thousands of records.

   ```powershell
   wevtutil gl ForwardedEvents | Select-String maxSize
   ```

3. Record the baseline and sample every 5 minutes from a SYSTEM scheduled task:

   ```powershell
   $svc = Get-CimInstance Win32_Service -Filter "Name='Bower'"
   $p = Get-Process -Id $svc.ProcessId
   [ordered]@{ pid=$p.Id; started=$p.StartTime.ToUniversalTime().ToString('o'); cpu=$p.TotalProcessorTime.TotalSeconds
     privateBytes=$p.PrivateMemorySize64; handles=$p.HandleCount; threads=$p.Threads.Count
     forwarded=(Get-WinEvent -ListLog ForwardedEvents).RecordCount } | ConvertTo-Json -Compress
   ```

   Also record `/v1/status` `windowsEventLog` (`eventsRead`, `state`, `lastEventAt`). The
   difference between `ForwardedEvents` records and `eventsRead` is the reader backlog, which is
   the key WEC signal. The lab version is `lab/aws/soak/wec-agent.ps1`.
4. Every 30 minutes, add the queue's identities to a union with
   `Bower.LabProbe.exe queue-union <queue.db> <union.tsv> <summary.json>` (read-only;
   `lab/aws/upgrade-recovery/probe`). A union of about 900,000 ids takes minutes, so give the
   task more than 10 minutes. The lab's 10-minute limit is the probable reason its last scheduled
   final export did not complete.
5. On the source (a DC or another WEF source), export native 4625 identities per closed hour:
   `Bower.LabProbe.exe native Security <from> <out.json> <until>`. Compare on the **original**
   id (column 4). The collector does not redact `winevt-` ids, and the default detectors
   would mask some.
6. Watch **CPU seconds per hour** at constant rate. On a burstable host also watch
   `CPUCreditBalance`.

**Pass/fail:** section 2. On `1a4c4c2` the WEC failed criteria 3 to 5 (section 6).

### 4.3 Docker / containers

1. Run the candidate image with the queue on a named volume and the soak settings:

   ```bash
   docker run -d --name bower-soak --restart unless-stopped \
     -v bower-soak-data:/var/lib/bower --env-file soak.env \
     -p 127.0.0.1:4319:4319 ghcr.io/<org>/bower:<candidate>
   docker inspect -f '{{.RestartCount}} {{.State.StartedAt}}' bower-soak
   ```

   `soak.env` holds the same `BOWER_*` settings as section 4.1. Secrets are mounted as files,
   not passed in the environment.
2. Sample every 5 minutes: `docker stats --no-stream --format '{{json .}}' bower-soak`,
   `docker inspect` (restart count, start time), the volume's `queue.db*` sizes and `/v1/status`.
3. Union the identities from a read-only copy:
   `docker run --rm -v bower-soak-data:/q:ro -v "$PWD":/out alpine/sqlite ...` with the same
   SQL as section 4.1 (`file:/q/queue.db?mode=ro`).
4. Pass/fail as section 2, with `RestartCount` unchanged.

Not run in this soak.

### 4.4 Kubernetes (`deploy/kubernetes`)

1. Deploy `deploy/kubernetes/deployment.yaml` with the candidate image into a dedicated
   namespace. The queue is on PVC `bower-data` at `/var/lib/bower`. Add the soak settings to the
   pod environment.
2. Record and sample every 5 minutes:

   ```bash
   kubectl -n bower-soak get pod -l app.kubernetes.io/name=bower-collector \
     -o jsonpath='{range .items[*]}{.metadata.name} {.status.containerStatuses[0].restartCount} {.status.startTime}{"\n"}{end}'
   kubectl -n bower-soak top pod -l app.kubernetes.io/name=bower-collector --containers
   kubectl -n bower-soak exec deploy/bower-collector -- ls -l /var/lib/bower
   ```

3. Union identities with a read-only job mounting the PVC (`readOnly: true`), using the SQL of
   section 4.1. Never copy the queue out of the cluster.
4. Pass/fail as section 2: `restartCount` unchanged and no evictions (`kubectl get events`).

Not run in this soak.

### 4.5 AWS-hosted collectors (EC2)

As 4.1 or 4.2 on the instance, plus:

- **Credits:** use `t3`/`t3a` with `--credit-specification CpuCredits=unlimited`, or a
  non-burstable type. Record `CPUCreditBalance` and `CPUUtilization` for the whole run:

  ```bash
  aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUCreditBalance \
    --dimensions Name=InstanceId,Value=<id> --start-time <start> --end-time <end> \
    --period 3600 --statistics Average
  ```

- The lab reproduces the whole soak on EC2 with `lab/aws/upgrade-recovery/lab.py`
  (`BOWER_LAB_PROFILE=soak`) and the scripts in `lab/aws/soak/`. See its README.

### 4.6 Azure-hosted collectors (VMs)

As 4.1 or 4.2 on the VM. Avoid `B`-series for WEC hosts, or record credits:

```bash
az monitor metrics list --resource <vm-id> --metric "CPU Credits Remaining" "Percentage CPU" \
  --interval PT1H --start-time <start> --end-time <end> -o table
```

A managed identity can replace the certificate credential. Token refresh then happens through
IMDS and must show no delivery failure codes over the run. Not run in this soak.

### 4.7 On-premises

As 4.1 or 4.2. Run the generator only in an isolated lab segment. Never generate failed logons
against a production DC or firewall. Use NTP on every host (latency is measured across clocks).
Size `ForwardedEvents` and the queue volume as in production.

### 4.8 Reconcile and decide (operator, any environment)

With the verifier identity, query per collector and per hour of event time:

```kusto
BowerSecurity_CL
| where TimeGenerated >= datetime(<hour start>) and TimeGenerated < datetime(<hour end>)
| where CollectorId == "<collector>" and EventType == "<event type>"
| summarize Copies=count(), Generated=min(TimeGenerated), FirstIngested=min(ingestion_time()) by EventId
```

Compare the full sets with the native and accepted sets (SHA-256), count `Copies - 1` as
duplicates, compute latency from `FirstIngested - Generated`, then run the health, privacy and
alert checks. The lab does all of this with `lab/aws/soak/reconcile.py final`.

## 5. Release checklist (gaps 1 to 7)

Tick every line for the exact candidate commit before calling a release production-ready for the
scoped rollout. "Evidence" means a run on that commit, or a documented reason why an earlier run
still applies.

| # | Check | Guide | Latest evidence |
|---|---|---|---|
| 0 | CI green on the candidate, including `package-*` and `install-*`; package hashes recorded; signature status recorded (currently **unsigned**, deferred) | [installers](../deployment/installers.md) | CI per commit |
| 1 | Firewall syslog uses RELP with mutual TLS and the recommended sender (rsyslog ≥ 8.2606, `omrelp`); fault scenarios reconcile with 0 missing | [01 syslog delivery](01-syslog-delivery-reliability.md) | [fw-20261101-111911](../evidence/fw-20261101-111911/README.md) |
| 2 | Detections are replay-safe (deduplicate by `EventId`, outage-aware lookback) | [02 replay-safe detections](02-replay-safe-detections.md) | #169 |
| 3 | Storage pressure: watermarks, `queue-storage` alert, recovery without discarding unacknowledged events | [03 storage pressure](03-storage-pressure.md) | #161 |
| 4 | Upgrade, downgrade refusal, backup and restore procedures pass for every package in use | [04 upgrade, backup, recovery](04-upgrade-backup-recovery.md) | [ws4-20261031-074918](../evidence/ws4-20261031-074918/README.md) |
| 5 | Credential rotation and security-failure handling (ingestion certificate, TLS, tokens) | [05 credential rotation](05-credential-rotation-and-security-failures.md) | [ws5-20261031-074543](../evidence/ws5-20261031-074543/README.md) |
| 6 | Health records on every collector; alert rules deployed and enabled; host checks; runbooks reviewed | [06 monitoring and runbooks](06-monitoring-and-runbooks.md) | [ws6-20261101-final](../evidence/ws6-20261101-final/README.md) |
| 7 | 24-hour soak passes all six criteria for **every** collector type in the rollout | this guide | [soak-20261102-015614](../evidence/soak-20261102-015614/README.md): **failed** (WEC latency, alerts, growth) |
| 8 | Pilot envelope (10/s, 100/s bursts, one-hour outage) reconciles | [pilot](https://github.com/jusso-dev/Bower/blob/main/lab/aws/PILOT.md) | [pilot-native-20261030](../evidence/pilot-native-20261030/README.md) |
| 9 | Known limits of each guide reviewed and accepted by the owner | each guide | — |

**Current state (2026-11-03).**

- **Firewall over RELP:** every check has evidence. The soak firewall path met criteria 1, 2, 4
  and 6. Its alert failure was the TLS-expiry false positive, fixed by #171. Its growth
  failure is small: RSS 80 to 107 MB, and the queue file was flat after hour 12. It needs a
  longer run to settle.
- **WEC:** not ready. Check 7 failed on reader latency and CPU growth.
- **Releases:** unsigned until signing is enabled.

## 6. Results of the soak

Run `bower-soak-20261102-015614`, 2026-11-02T03:35:00Z to 2026-11-03T03:35:00Z, main
`1a4c4c2`, CI packages `0.1.0-dev.337` (RPM and MSI, unsigned). Full detail is in the
[evidence README](../evidence/soak-20261102-015614/README.md).

| # | Criterion | Firewall (RPM, RELP) | WEC (MSI) |
|---|---|---|---|
| 1 | Exact delivery | **PASS**: 896,400 = 896,400 = 896,400; 54 duplicate rows | **PASS**: 896,400 = 896,400 = 896,400; 101 duplicate rows |
| 2 | No restarts | **PASS** | **PASS** (the source restarted in-process twice) |
| 3 | No unbounded growth | **FAIL**: RSS +165 KB/h, FDs 23→28 | **FAIL**: private bytes 31→73 MB, handles 403→426, CPU per hour ×5.6 |
| 4 | p99 latency | **PASS**: 8.7 s (limit 13.3 s); 3 hours above | **FAIL**: 881.8 s (limit 18.16 s); 23 of 25 hours above |
| 5 | No alerts | **FAIL**: `syslog-tls-expiry` all run (false positive, #171) | **FAIL**: `source-transport-errors` twice (true positive) |
| 6 | Privacy | **PASS**: 0 matches | **PASS**: 0 matches |

What else the run showed:

- **Housekeeping all happened:** retention every hour (WEC purged 36,000–41,000 rows per
  run), maintenance at 03:00Z on both days, 24 hours of token refresh with no delivery failure
  code, sender journald rotation about every 2.3 hours read across by `imjournal`, about 1,480
  health records per collector.
- **Firewall latency** stayed at p50 3.9 s and p95 6.4 s through all six bursts.
- **Duplicates** came in the same two hours (10:33Z and 00:33Z) on both collectors, during
  latency spikes, with no collector-side delivery failure logged. This points at the
  destination side of at-least-once delivery. All collapse with the documented query.

## 7. Troubleshooting

| Symptom | Likely cause | Check | Action |
|---|---|---|---|
| WEC latency grows over hours while Bower's queue stays empty | Windows Event Log reader cost grows with `ForwardedEvents` size (section 9) | `ForwardedEvents` `RecordCount` minus `/v1/status` `windowsEventLog.eventsRead`; CPU seconds per hour | Until fixed: a non-burstable WEC host, `ForwardedEvents` sized to hold hours not days, and a reader-backlog alert |
| Latency grows after every burst and never recovers | Burstable instance out of CPU credits | `CPUCreditBalance` (AWS), `CPU Credits Remaining` (Azure) | Unlimited credits or a fixed-performance size |
| `source-transport-errors` at :00 | Hourly retention purge holding the queue while the source or delivery writes (`SqliteException`, `winevt-source-failed`) | Application log event 1002 and health `windowsEventLog.state` at :00 | Recovers by itself without loss. Track section 9 |
| `syslog-tls-expiry` fires with valid certificates | No client CRL configured; the rule on `1a4c4c2` treats the missing date as unknown | Rule query output `tls-metadata-unknown` | Upgrade to a build with #171 |
| Reconciliation shows N missing and N extra Windows ids | Native ids compared after default-detector redaction | Probe `redactionChangedIds` | Compare on the original id (probe column 4) |
| Extra Sentinel ids at the end | Generation drifted past the last native window | Last window's event times | Export the window after the end (`h24`) |
| Sampler records `ValueError` | Seven-digit .NET fractional seconds | Sample `error` field | Truncate to six digits before parsing |

## 8. How we tested this

One 24-hour soak plus a 15-minute smoke and an interim reconciliation, on AWS (Sydney) into a
fresh Sentinel workspace (Australia East):

- a Windows Server 2022 domain controller generating 4625s through NTLM LDAP binds;
- a WEC host on the MSI with a source-initiated subscription;
- an Amazon Linux 2023 sender with real nftables denials, rsyslog 8.2610.0 and `omrelp`
  over mutual TLS;
- an Amazon Linux 2023 collector on the RPM.

All hosts were `t3` on standard credits. A separate verifier identity did every query. Evidence:
[soak-20261102-015614](../evidence/soak-20261102-015614/README.md). Cleanup was audited
independently (37 of 37 checks absent).

## 9. Known defects found by this work

1. **Windows Event Log reader cost grows with channel size** (open). At a constant 10
   events/sec, CPU per hour went from about 450 s to about 2,500 s as `ForwardedEvents` grew to
   900,000 records. `WindowsEventLogChannel.Read` builds a new filtered `EventLogQuery` and
   seeks to the bookmark on every 1-second poll. Once CPU was capped, the reader fell about
   7,000 records (about 12 minutes) behind. This needs a fix (for example a long-lived reader or
   subscription that is not re-seeked every poll), unit or benchmark coverage, and a re-soak.
2. **Hourly retention contends with queue writers on Windows** (open). The source failed
   in-process twice and the delivery loop logged `SqliteException` three times, each while
   retention purged 36,000–41,000 rows (43–72 s). It recovered with no loss and fired a true
   `source-transport-errors` alert. Smaller purge batches or yielding between batches should be
   evaluated.
3. **TLS-expiry false positive without a CRL** (fixed after this soak by
   [#171](https://github.com/jusso-dev/Bower/pull/171); not covered by this soak).
4. Harness defects found and fixed during the run (all preserved in the evidence): probe id
   redaction in the smoke, the sampler's timestamp parsing, and the final export's task time limit.

## 10. Known limits

- One 24-hour run per collector type. Slow growth cannot be told apart from warm-up within it.
- Lab hosts, not a firewall appliance or a production domain. Burstable instances changed the
  WEC outcome.
- Docker, Kubernetes, Azure-hosted and on-premises collectors were not soaked. Their procedures
  above are not qualified by this run.
- The soak covers `1a4c4c2` only. Later commits need their own soak before release.
- Releases are unsigned (deferred).
