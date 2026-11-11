# 7. 24-hour soak and release validation

**Gap:** prove that the scoped rollout stays correct and stable for a full day of ordinary
traffic, including the hourly and daily housekeeping that short tests never reach, and give
every release a repeatable gate that ties gaps 1 to 6 together.

**Scope:** the scoped rollout, Windows WEF/WEC (`ForwardedEvents`) and firewall syslog over
RELP with mutual TLS, to the C# Bower collector, to Microsoft Sentinel (Logs Ingestion API).
Releases and packages are **unsigned** (signing is deferred). Bower still refuses unsigned or
untrusted packs.

**Status (11 November 2026): the 72-hour re-soak was run and FAILED, so check 7 stays
open.** Run `bower-resoak-20261106-092539` soaked main `8f615b8` (`0.1.1-dev.416`, unsigned)
from 2026-11-06T11:05Z to 2026-11-09T11:05Z on fixed-performance hosts, with eleven scheduled
faults. Neither collector met all six criteria (`final.json` `verdict.pass: false`):

- **Firewall (RELP):** criteria 1, 2, 4 and 6 met; 3 and 5 failed.
- **WEC:** criteria 2, 4 and 6 met; 3 and 5 failed; criterion 1 is **not met, blocked by
  missing native evidence**. Accepted and Sentinel both hold exactly 2,693,520 ids, 0 missing,
  0 duplicates, but one native export window (`h72`) was never taken before the hosts
  terminated, so 51 ids have no native record.
- **Growth (criterion 3)** failed on both registered windows for both collectors, for example
  the WEC's private bytes (+210%) and threads (+294%) over hours 3–24.
- **Alerts (criterion 5):** one `dcr-request-errors` alert (2026-11-08T21:28Z to 21:48Z) that no
  fault excuses. Its cause is not determined.

Every fault outcome held, both collectors reported the candidate version, every restart was a
scheduled one, and there were no privacy-marker matches. WEC latency now passes (p99 11.5 s
against 18.16 s), where the 24-hour soak failed at 881.8 s. That is consistent with #178's group
commit, but not isolated from the host change: the 24-hour soak ran on credit-limited `t3`
hosts and the re-soak on `m6i.large`. See [re-soak results](#6b-results-of-the-72-hour-re-soak)
and the [evidence](../evidence/resoak-20261106-092539/README.md).

**Neither path is production-ready.** Check 7 closes only when a re-soak passes all six criteria
for both collectors, with every fault outcome and the version check, on the release candidate.
Before that run, the growth failures need an explanation or a fix, and the harness should export
its last native window without depending on an operator step (section 10).

**The earlier 24-hour soak also FAILED** (`bower-soak-20261102-015614`, main `1a4c4c2`, no
faults). Firewall: criteria 1, 2, 4 and 6 met, 3 and 5 failed. WEC: criteria 2 and 6 met, 3, 4
and 5 failed; criterion 1 is unqualified because accepted-stage extras and complete native
coverage were not verified (section 6). All 896,400 observed native IDs per collector appeared in
Sentinel, with no process restarts and no privacy-marker matches. The failures:

- **WEC latency.** p99 reached 882 s on a CPU-credit-limited host. Historical reader
  backlog is unknown: the earlier estimate subtracted a process counter from the channel's
  retained record count. Profiling afterwards
  ([wecfix](../evidence/wecfix-20261103-043750/README.md)) found the reader's poll cost flat
  with `ForwardedEvents` size; the limit was one durable queue commit per event (about 44
  events/sec), addressed by group commit (section 9).
- **Alerts.** The TLS-expiry false positive fired all run (fixed afterwards on main by #171),
  and the source-transport alert fired twice, correctly, when the WEC source failed during the
  hourly queue retention.
- **Growth.** The registered slope threshold (hours 3–24, 30-day projection under 10% of the
  mean) failed for memory, handles or FDs and the queue file on both collectors, and for
  threads on the WEC.

See [results](#6-results-of-the-soak) and the
[evidence](../evidence/soak-20261102-015614/README.md).

The 24-hour soak ran main at **`1a4c4c2`**; the re-soak ran **`8f615b8`**, which includes
[#161](https://github.com/jusso-dev/Bower/pull/161) storage pressure
([gap 3](03-storage-pressure.md)), [#169](https://github.com/jusso-dev/Bower/pull/169)
replay-safe detections ([gap 2](02-replay-safe-detections.md)),
[#171](https://github.com/jusso-dev/Bower/pull/171) the TLS-expiry fix, and
[#178](https://github.com/jusso-dev/Bower/pull/178) the WEC reader's group commit and batched
retention. A release built from a later commit needs its own soak (section 4).

An isolated re-soak harness dry run on 3 November was interrupted before its final
reconciliation ([interrupted campaign record](../evidence/interrupted-20261103/README.md)). A
first 72-hour attempt, `bower-resoak-20261105-234529`, was aborted on 6 November because a
harness gap between the smoke and the soak let `destination-freshness` fire on both collectors
24 s before the soak start, which the registered accounting counts as a criterion 5 failure (its
committed interim lists both alerts as violations). It was torn down (38 of 38 checks absent) and
replaced by the run above
([record](../evidence/resoak-20261106-092539/README.md#aborted-first-attempt-bower-resoak-20261105-234529)).
Neither closes the soak gate.

Contents:

1. [What a soak proves, and what it does not](#1-what-a-soak-proves-and-what-it-does-not)
2. [Pass criteria](#2-pass-criteria)
3. [The soak method (all environments)](#3-the-soak-method-all-environments)
4. [Step by step, per environment](#4-step-by-step-per-environment)
5. [Release checklist (CI, gaps 1 to 7, pilot)](#5-release-checklist-ci-gaps-1-to-7-pilot)
6. [Results of the soak](#6-results-of-the-soak) and [of the 72-hour re-soak](#6b-results-of-the-72-hour-re-soak)
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

The 24-hour soak injected **no faults**. Faults are qualified by gaps 1 to 6. A soak that
passes does not replace those tests, and a fault test does not replace a soak. The 72-hour
re-soak added eleven scheduled faults (outage, kills, reboots, rotations, rollovers) with
their expected restarts, latency and alerts accounted for by rules registered before the run.
Those rules change how criteria 2 to 5 are judged, so the re-soak was not gated by the section 2
table as written (section 6b).

## 2. Pass criteria

These are the criteria of the **24-hour soak** (no scheduled faults). Register them before the
run starts. Never change them afterwards. A run passes only if **all** of them hold for
**every** collector. A run with scheduled faults, like the 72-hour re-soak, keeps the six
criteria but must register how each fault's restarts, latency and alerts are accounted for; the
re-soak's rules are summarised in [section 6b](#6b-results-of-the-72-hour-re-soak).

| # | Criterion | How it is measured | Pass |
|---|---|---|---|
| 1 | Exact delivery | Native, accepted and distinct Sentinel identity sets, compared by SHA-256 of the sorted ids joined by newline | All three equal, 0 missing, 0 extra. Duplicate rows are counted and reported separately; they are allowed (at-least-once) if they collapse with the documented `arg_min(ingestion_time(), *) by EventId` query |
| 2 | No restarts | Collector PID and start time in every sample; systemd `NRestarts`; container `RestartCount`; pod `restartCount`; boot ID | One process identity for the whole run |
| 3 | No unbounded growth | Least-squares slope over hours 3–24 of the workload (not the drain after it) of memory (RSS / private bytes), FDs / handles, threads and queue DB + WAL bytes | The slope × 720 h is under 10% of the mean (a falling series passes) |
| 4 | Latency | First `ingestion_time()` minus event time, per hour and overall | Whole-run p99 at most twice the pilot's connected p99 (13.3 s firewall, 18.16 s WEC; [pilot](../evidence/pilot-native-20261030/README.md)). Every hour above the limit is listed |
| 5 | No alerts | Azure Monitor alert instances and Sentinel incidents from the [monitoring rules](06-monitoring-and-runbooks.md) | None fired during the run |
| 6 | Privacy | `tostring(pack_all())` of every destination row searched for the synthetic markers (the synthetic user name, raw kernel prefix, synthetic password prefix) | 0 matches |

**Recommended for future runs (added after the 24-hour soak, before the 72-hour re-soak was
registered; not part of either run's registered criterion 3):**
record CPU seconds per hour at the constant rate and fail when CPU per event trends upwards.
This soak's WEC result shows that memory and handle slopes alone can miss a cost that grows
with input size. Register it before the next run if it is to be used as a gate.

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
   # The leading newline guards against a file whose last line has no newline.
   printf '\nBOWER_HEALTH_RECORD_INTERVAL_SECONDS=60\nBOWER_QUEUE_RETENTION_HOURS=2\n' |
     sudo tee -a /etc/bower/bower.env >/dev/null
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
   # The header goes to curl on stdin (-K -), never in its argument list (visible in ps).
   sudo cat /etc/bower/secrets/ingest-token | sed 's/^/header = "Authorization: Bearer /; s/$/"/' |
     curl -fsS -K - http://127.0.0.1:4319/v1/status | jq -c '{status, queue, jobs, deliveryActivity}'
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
   # The leading line break guards against a file whose last line has no line break.
   Add-Content C:\ProgramData\Bower\bower.env "`r`nBOWER_HEALTH_RECORD_INTERVAL_SECONDS=60`r`nBOWER_QUEUE_RETENTION_HOURS=2"
   Restart-Service Bower; (Get-Service Bower).Status
   ```

   Expected: `Running`. Register `Test-BowerCollectorHealth.ps1` as a one-minute SYSTEM task
   ([gap 6](06-monitoring-and-runbooks.md)).
2. **Size `ForwardedEvents` to production.** Do not shrink it for the soak. Use the
   production retention and expected load when evaluating the WEC path.

   ```powershell
   wevtutil gl ForwardedEvents | Select-String maxSize
   ```

3. Record the baseline and sample every 5 minutes from a SYSTEM scheduled task. This
   example uses the hash-verified `Bower.LabProbe.exe` installed by the soak lab at
   `C:\BowerLab\soak\probe.exe`; provision and verify that probe before running the
   example on another host. It works in Windows PowerShell 5.1 and PowerShell 7:

   ```powershell
   function Get-ReceivingBookmarkRecordId([string]$ProbePath, [string]$Channel) {
     try {
       if ($Channel -cnotin @('ForwardedEvents', 'Application', 'System')) { return $null }
       $output = @(& $ProbePath 'receiving-position' $Channel 2>$null)
       if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) { return $null }
       $json = [string]$output[0]
       if ($json.Length -gt 512) { return $null }
       # The verified probe emits exactly these three fields in this order. Anchoring
       # the whole ASCII grammar rejects duplicate, escaped and unexpected properties.
       $pattern = '\A\{"kind":"receiving-position","channel":"' + [regex]::Escape($Channel) + '","newestRecordId":([1-9][0-9]{0,18})\}\z'
       $match = [regex]::Match($json, $pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
       $position = 0L
       if (-not $match.Success -or -not [long]::TryParse($match.Groups[1].Value,
               [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture,
               [ref]$position)) { return $null }
       return $position
     } catch { return $null }
   }
   function Get-ReceivingPositionState($RecordCount, $Position) {
     if (($Position -is [int32] -or $Position -is [int64]) -and [long]$Position -gt 0) { return 'observed' }
     if (($RecordCount -is [int32] -or $RecordCount -is [int64]) -and [long]$RecordCount -gt 0) {
       return 'missing-bookmark-with-records'
     }
     return 'unknown'
   }
   $probe = 'C:\BowerLab\soak\probe.exe'
   $svc = Get-CimInstance Win32_Service -Filter "Name='Bower'"
   $p = Get-Process -Id $svc.ProcessId
   $recordCount = (Get-WinEvent -ListLog ForwardedEvents).RecordCount
   $newestId = Get-ReceivingBookmarkRecordId $probe 'ForwardedEvents'
   $positionState = Get-ReceivingPositionState $recordCount $newestId
   [ordered]@{ pid=$p.Id; started=$p.StartTime.ToUniversalTime().ToString('o'); cpu=$p.TotalProcessorTime.TotalSeconds
     privateBytes=$p.PrivateMemorySize64; handles=$p.HandleCount; threads=$p.Threads.Count
     forwarded=$recordCount; newestRecordId=$newestId; newestRecordIdState=$positionState
     newestRecordIdBasis='native-receiving-bookmark-v1' } | ConvertTo-Json -Compress
   ```

   Also record `/v1/status` `windowsEventLog` (`eventsRead`, `state`, `lastEventAt`,
   `bookmarkRecordId`). Compare the newest channel record ID with the bookmark only when
   both are available and refer to the same unreset channel. Use the receiving bookmark's
   `RecordId`, not the event's origin `RecordId`; missing or invalid bookmark metadata is
   unknown. `missing-bookmark-with-records` means the probe failed to obtain a position
   for a nonempty channel; investigate the probe and channel read access. Their difference is an ID
   distance, which can exceed the number of unread events; missing or reset IDs leave it
   unknown. `RecordCount` minus `eventsRead` is not a backlog: a retained record count and
   a process counter have different baselines. The lab version is `lab/aws/soak/wec-agent.ps1`.
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
   pod environment. Create the `bower-ingest` and `bower-intake-tls` secrets and the reviewed
   `bower-producer-scopes` ConfigMap **before** applying: the collector listens on HTTPS, and
   without the TLS secret the pod waits in `ContainerCreating`. Load generators send to
   `https://bower-collector.bower-soak.svc:4319` and trust the issuing CA. See
   [upgrading an existing Kubernetes installation](../deployment/hosted-collectors.md#upgrading-an-existing-kubernetes-installation).
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
  non-burstable type. For WEC hosts prefer a non-burstable type (`m6i.large` or larger, as
  measured in [wecfix](../evidence/wecfix-20261103-043750/README.md); see
  [WEC sizing](../deployment/windows-event-log-source.md#throughput-cpu-and-wec-sizing)). Record `CPUCreditBalance` and `CPUUtilization` for the whole run:

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

## 5. Release checklist (CI, gaps 1 to 7, pilot)

Tick every line for the exact candidate commit before calling a release production-ready for the
scoped rollout. "Evidence" means a run on that commit, or a documented reason why an earlier run
still applies.

| # | Check | Guide | Latest evidence |
|---|---|---|---|
| 0 | CI green on the candidate, including `version`, `package-*` and `install-*` (upgrade, refused downgrade and rollback); the exact Bower version, build number, deb/rpm versions and MSI ProductVersion recorded (below); package hashes recorded; signature status recorded (currently **unsigned**, deferred) | [release versioning](../operations/release-versioning.md), [installers](../deployment/installers.md) | CI per commit |
| 1 | Firewall syslog uses RELP with mutual TLS and the recommended sender (rsyslog ≥ 8.2606, `omrelp`); fault scenarios reconcile with 0 missing | [01 syslog delivery](01-syslog-delivery-reliability.md) | [fw-20261101-111911](../evidence/fw-20261101-111911/README.md) |
| 2 | Detections are replay-safe (deduplicate by `EventId`, outage-aware lookback) | [02 replay-safe detections](02-replay-safe-detections.md) | #169 |
| 3 | Storage pressure: watermarks, `queue-storage` alert, recovery without discarding unacknowledged events | [03 storage pressure](03-storage-pressure.md) | #161 |
| 4 | Upgrade, downgrade refusal, backup and restore procedures pass for every package in use | [04 upgrade, backup, recovery](04-upgrade-backup-recovery.md) | [ws4-20261031-074918](../evidence/ws4-20261031-074918/README.md) |
| 5 | Credential rotation and security-failure handling (ingestion certificate, TLS, tokens) | [05 credential rotation](05-credential-rotation-and-security-failures.md) | [ws5-20261031-074543](../evidence/ws5-20261031-074543/README.md) |
| 6 | Health records on every collector; alert rules deployed and enabled; host checks; runbooks reviewed | [06 monitoring and runbooks](06-monitoring-and-runbooks.md) | [ws6-20261101-final](../evidence/ws6-20261101-final/README.md) |
| 7 | Soak passes all six criteria for **every** collector type in the rollout | this guide | [resoak-20261106-092539](../evidence/resoak-20261106-092539/README.md) (72 h, `8f615b8`): **failed** (growth and alerts on both; WEC criterion 1 blocked by a missing native window). Earlier: [soak-20261102-015614](../evidence/soak-20261102-015614/README.md) (24 h, `1a4c4c2`): **failed** (WEC latency, alerts, growth) |
| 8 | Pilot envelope (10/s, 100/s bursts, one-hour outage) reconciles | [pilot](https://github.com/jusso-dev/Bower/blob/main/lab/aws/PILOT.md) | [pilot-native-20261030](../evidence/pilot-native-20261030/README.md) |
| 9 | Known limits of each guide reviewed and accepted by the owner | each guide | — |

**Record the exact version.** Every check above is evidence for one build, so write its
identity into the release record before ticking anything. The version comes from the CI
`version` job of the candidate run (`tools/ci/version.py`, see
[release versioning](../operations/release-versioning.md)); a release is tagged
`v<VERSION>`, a candidate `v<VERSION>-rc.N`.

| Field | Where to read it | Example |
| --- | --- | --- |
| Bower version | CI `version` job output; `bower --version`; `/v1/status` `version`; heartbeat `version`; `collector.version` on every event | `0.2.0-rc.1` |
| Build number | CI run number (`version` job `build`) | `412` |
| Commit | The tag's commit; image label `org.opencontainers.image.revision` | `5b7ded8` |
| deb / rpm version | `dpkg-query -W bower-collector` / `rpm -q bower-collector` | `0.2.0~rc.1-1` / `0.2.0~rc.1-1` |
| MSI ProductVersion | `DisplayVersion` in Programs and Features (`MAJOR.MINOR.BUILD`) | `0.2.412` |
| Release version on Windows | `HKLM\SOFTWARE\Bower\Collector\Version` | `0.2.0-rc.1` |
| Image tag and label | `ghcr.io/<owner>/bower-collector:<version>`; `org.opencontainers.image.version` | `0.2.0-rc.1` |
| SHA-256 of each package and image digest | `sha256sum`, `Get-FileHash`, `docker buildx imagetools inspect` | — |
| Signature status | `UNSIGNED.txt` in the bundles | unsigned (deferred) |

Then check on every collector in the rollout that the reported version is the recorded one:

```bash
bower --version                                   # bower 0.2.0-rc.1
# The header goes to curl on stdin (-K -), never in its argument list (visible in ps).
sudo cat /etc/bower/secrets/ingest-token | sed 's/^/header = "Authorization: Bearer /; s/$/"/' |
  curl -fsS -K - http://127.0.0.1:4319/v1/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'
```

```powershell
& "$env:ProgramFiles\Bower\bower.exe" --version
(Get-ItemProperty 'HKLM:\SOFTWARE\Bower\Collector').Version
```

In Sentinel, `BowerSecurity_CL | where TimeGenerated > ago(1h) | summarize by tostring(RawEnvelope.collector.version), CollectorId`
lists the version each collector runs. A soak, pilot or fault-test result counts only for the
version it recorded.

**Current state (2026-11-11).**

- **Check 0 for `8f615b8`:** closed, about 14 h after the re-soak started. CI run
  [42130604210](https://github.com/jusso-dev/Bower/actions/runs/42130604210) finished
  `success` on attempt 3 (2026-11-07T01:25:34Z); only the `windows-event-log` job, which had
  failed on a runner permission error, and the `ci-success` gate were re-run, so the packages
  under test were not rebuilt
  ([jobs listing](../evidence/resoak-20261106-092539/operations/ci-run-42130604210-attempt-3.json)).
- **Firewall over RELP:** checks 0–6 and 8 have evidence. Check 7 is **open**. In the 72-hour
  re-soak the firewall met criteria 1 (exact: 2,693,520 native = accepted = distinct Sentinel),
  2, 4 and 6 and failed 3 (queue file and threads over hours 3–24; memory and FDs after the last
  restart) and 5 (the unexcused `dcr-request-errors` alert). The TLS-expiry false positive did
  not recur.
- **WEC:** check 7 is **open**. In the re-soak it met criteria 2, 4 (p99 11.5 s) and 6 and
  failed 3 (memory, threads, handles and queue over hours 3–24) and 5 (the same alert).
  Criterion 1 is not met: blocked by the missing `h72` native window.
- **To close check 7:** a re-soak on the release candidate that passes all six criteria for
  both collectors, every fault outcome and the version check. Before it: explain or fix the
  growth slopes, capture DCR response codes so an alert like this one can be explained, and
  make the last native export independent of the operator (section 10). The criteria and
  thresholds stay as registered.
- **Releases:** unsigned until signing is enabled.

## 6. Results of the soak

Run `bower-soak-20261102-015614`, 2026-11-02T03:35:00Z to 2026-11-03T03:35:00Z, main
`1a4c4c2`, CI packages `0.1.0-dev.337` (RPM and MSI, unsigned). Full detail is in the
[evidence README](../evidence/soak-20261102-015614/README.md).

| # | Criterion | Firewall (RPM, RELP) | WEC (MSI) |
|---|---|---|---|
| 1 | Exact delivery | **PASS**: native 896,400 = accepted 896,400 = distinct Sentinel 896,400; 54 duplicate rows | **UNQUALIFIED**: 896,400 observed native IDs found at the queue and Sentinel, 0 extra Sentinel IDs, 101 duplicate rows; accepted extras and complete source coverage unverified |
| 2 | No restarts | **PASS** | **PASS** (the source restarted in-process twice) |
| 3 | No unbounded growth (hours 3–24) | **FAIL**: RSS +75 KB/h (61%), FDs +0.055/h (166%), queue +106 KB/h (36%); threads falling (flat) | **FAIL**: private bytes +461 KB/h (735%), handles +0.54/h (93%), threads +0.12/h (527%), queue +73 KB/h (17%) |
| 4 | p99 latency | **PASS**: 8.7 s (limit 13.3 s); 3 hours above | **FAIL**: 881.8 s (limit 18.16 s); 23 of 25 hours above |
| 5 | No alerts | **FAIL**: `syslog-tls-expiry` all run (false positive, #171) | **FAIL**: `source-transport-errors` twice (true positive) |
| 6 | Privacy | **PASS**: 0 matches | **PASS**: 0 matches |

Criterion 1 detail. The run's reconciler counted accepted ids as `queue ∩ native`, so
accepted ids that are not native ids were not reported. That defect is fixed after the run:
`reconcile.py` now scopes accepted ids by source and window and reports `extraAtAccepted`.
The identity lists were deleted with the lab, so the comparison cannot be re-run:

- Firewall: the accepted scope is the sequence range 100,000–996,399, which is exactly the
  native range, so an accepted extra in scope is impossible. The result stands.
- WEC: accepted extras were not checked and cannot be now. Missing-at-queue, missing-at-Sentinel
  and extra-at-Sentinel were computed against the full sets and were all 0.

Criterion 3 numbers are recomputed from the committed sample series over the workload hours
3–24 ([resource-trends-recomputed.json](../evidence/soak-20261102-015614/final/resource-trends-recomputed.json)).
The figures first published (RSS +165 KB/h, private bytes +486 KB/h) used samples up to
hour 25, including the drain, and are superseded. The verdict is unchanged.

What else the run showed:

- **Housekeeping all happened:** retention every hour (WEC purged 36,000–41,000 rows per
  run), maintenance at 03:00Z on both days, 24 hours of token refresh with no delivery failure
  code, sender journald rotation about every 2.3 hours read across by `imjournal`, about 1,480
  health records per collector.
- **Firewall latency** stayed at p50 3.9 s and p95 6.4 s through all six bursts.
- **Duplicates** came in the same two hours (10:33Z and 00:33Z) on both collectors, during
  latency spikes, with no collector-side delivery failure logged. This points at the
  destination side of at-least-once delivery. All collapse with the documented query.

## 6b. Results of the 72-hour re-soak

Run `bower-resoak-20261106-092539`, 2026-11-06T11:05Z to 2026-11-09T11:05Z, main `8f615b8`,
CI packages `0.1.1-dev.416` (RPM and MSI, unsigned), CI run 42130604210. Harness: branch
`test/resoak-72h-v2` at `4b529bc`, which includes the query-cache fix
[#199](https://github.com/jusso-dev/Bower/pull/199); the plan was registered on 2026-11-03
and its SHA-256 matched at stage time and at the final reconciliation. Four `m6i.large` hosts
(Linux collector, sender, WEC, DC). Faults F01 to F11 ran on the registered schedule. Full
detail is in the [evidence README](../evidence/resoak-20261106-092539/README.md).

**Result: FAILED** (`verdict.pass: false`; `faultOutcomesPass: true`, `versionMatches: true`).

**Registered rules.** The
[pre-registration](https://github.com/jusso-dev/Bower/blob/4b529bc71f4d43da8969d0d7fb6e3fe3aadeed8b/lab/aws/resoak/preregistration.json)
(SHA-256 `b06e344f…`, on the harness branch, not on main) copies the six criteria of
section 2 verbatim, then adds `faultAccounting` rules that change how four of them are judged:

- **1** unchanged, over every event, fault windows and canaries included.
- **2** allows exactly 1 + the scheduled restarts (and boots) per collector, each starting inside
  its fault window, instead of one process identity for the whole run.
- **3** must pass on two windows: hours 3–24 and from 3 hours after the last scheduled restart
  (+38:20) to +72:00.
- **4** gates the p99 of events whose event time is outside every fault window; the p99
  including fault windows is reported only.
- **5** excuses an alert only if its rule is listed by the fault whose alert window (fault start
  to fault end + impact allowance + 1 hour) it started in. `syslog-tls-expiry` and
  `destination-credential` are never excused.
- **6** unchanged, with `bower-canary` added as a marker.

| # | Criterion | Firewall (RPM, RELP) | WEC (MSI) |
|---|---|---|---|
| 1 | Exact delivery | **PASS**: native 2,693,520 = accepted 2,693,520 = distinct Sentinel 2,693,520; 0 duplicate rows | **FAIL (blocked: native evidence missing)**: accepted 2,693,520 = distinct Sentinel 2,693,520, 0 missing, 0 duplicate rows; native 2,693,469 (`missing-window-h72`) |
| 2 | Only scheduled restarts | **PASS**: 4 process identities, 2 boots (F05, F08, F09); none unexplained | **PASS**: 4 process identities, 2 boots (F06, F07, F09); none unexplained |
| 3 | No unbounded growth (two registered windows) | **FAIL**: hours 3–24 queue DB + WAL +55%, threads +19%, memory and FDs falling; after the last restart memory +199%, FDs +55% | **FAIL**: hours 3–24 private bytes +210%, threads +294%, queue +26%, handles +15%; after the last restart memory +49%, threads +41%, handles +23% |
| 4 | p99 latency outside fault windows | **PASS**: 7.9 s (limit 13.3 s); hour 58 above | **PASS**: 11.5 s (limit 18.16 s); hour 58 above |
| 5 | No alerts outside the fault accounting | **FAIL**: `dcr-request-errors`, 2026-11-08T21:28:49Z to 21:48:52Z | **FAIL**: the same alert |
| 6 | Privacy | **PASS**: 0 of 2,697,897 rows | **PASS**: 0 of 2,697,894 rows |

Percentages are slope × 720 h as a share of the mean; the threshold is under 10%.

**Criterion 1, WEC.** The DC generator made 2,689,200 attempts plus 4,320 canaries, 2,693,520
in all, and the accepted and Sentinel sets equal that count with one digest. The native export
covers windows `h00` to `h71` (2,693,469 records). The DC generator ran past the end of `h71`,
and the run's handoff prescribed exporting `h72` on demand (`native-h72`) before the hosts
powered themselves off at 2026-11-09T15:05Z. The scheduled final reconciliation produced
`final.json` (the report's recorded generation time, set before its queries, is 11:45:58Z; its
health data runs to 12:01Z) but was interrupted before running `native-h72`, and the hosts are
gone. The 51 extra ids are most likely those generated after 11:05:00Z, but no native record
proves it. The criterion is not met; it is recorded as blocked by missing native evidence, not
as a proven delivery failure.

**Criterion 3.** The registered measure is the least-squares slope on two windows, both of
which must pass: hours 3–24 (no restart in it) and from 3 hours after the last scheduled
restart to the end (+38:20 to +72:00).

| Series | Firewall 3–24 | Firewall after last restart | WEC 3–24 | WEC after last restart |
|---|---|---|---|---|
| Memory (RSS / private bytes) | −24.4% (falling) | **+199.2%** | **+210.2%** | **+49.2%** |
| FDs / handles | −14.5% (falling) | **+55.3%** | **+14.6%** | **+23.4%** |
| Threads | **+19.1%** | −1.1% | **+293.9%** | **+40.8%** |
| Queue DB + WAL | **+54.8%** | +2.3% | **+26.2%** | +1.6% |

The context does not excuse the result. The queue file rose during hours 3–24 (273–294 MB on
the firewall, 295–324 MB on the WEC) and was flat in the later window. That fits a database
file growing to a steady size under 2-hour retention, then reusing its pages. The later
window starts 3 hours after a scheduled restart, so its memory slope includes the new process's
warm-up. Thread and FD counts are small integers (firewall threads 17–18), so one extra thread
for part of a window moves the slope a long way. Every series in bold is still above the
threshold registered before the run. CPU, reported but not gated, was flat: the WEC averaged
38.4 CPU seconds an hour over the first 24 hours and 38.8 over the last 24.

**Criterion 4.** Outside fault windows: firewall p50/p95/p99 3.9/6.3/7.9 s, WEC 6.8/9.5/11.5 s.
Including fault windows (reported, not gated): firewall p99 9.8 s, WEC 13.7 s. Only hour 58
(2026-11-08T21:05Z to 22:05Z) had a p99 above the limit on either collector: firewall 46.2 s (max
77.6 s), WEC 39.8 s (max 66.3 s). That hour holds a scheduled burst and the `dcr-request-errors`
alert; other burst hours stayed at a firewall p99 of 6.7–8.6 s (gated `latency.hourly`). The large
maxima come from F01, the 30-minute destination outage on 2026-11-06 from 12:25Z: 1,845.1 s
(firewall) and 1,813.7 s (WEC) inside its window. The firewall's 1,845.8 s maximum outside fault
windows is in the same hour and matches the outage length, so it is most likely an event stamped
just before the window opened.

**Criterion 5.** The F01 outage's `collector-health-missing` and `queue-backlog` alerts were
excused, as registered. Two `collector-health-missing` alerts fired before the run, before the
collectors sent health records (09:30Z to 10:01Z on 2026-11-06); they resolved before the soak
started and are not counted. One alert is not excused: `dcr-request-errors`, a metric alert on DCR
requests answered with a code other than 200, 202 or 204, active 2026-11-08T21:28:49Z to 21:48:52Z.
It started inside F11's alert window, but F11 (a log rollover at 20:25Z) permits no alerts. F09, the
ingestion-credential rotation, was at 2026-11-07T22:25Z, 23 hours earlier. **The cause is not
determined.** The evidence records no response code. It falls in hour 58, when both collectors'
latency rose, which points at the destination side but does not prove it. Neither collector
restarted, health records stayed `healthy`, and nothing was duplicated or missing. The DCR is
deleted, so the metric cannot be split by response code now.

**Restarts.** Each collector had exactly the scheduled process identities (start, kill,
reboot, F09 credential rotation) and boots, `unexplained: []`.

What else the run showed:

- **Faults:** all eleven ran on every expected host within 120 s of schedule, and every
  registered outcome held. Nothing inside any fault window was missing at Sentinel.
- **Natural events:** 136 and 143 `queue-retention` runs, 3 `queue-maintenance` runs on each
  collector, health records with a largest gap of 61 s and 68 s, and `ForwardedEvents` full from
  2026-11-08T14:35Z (1,936,262 records, 4.2 GB) with reader gaps, resets, cursor conflicts and
  read errors all 0. No `source-transport-errors` alert fired, and outside F01 every health
  record was `healthy`; in the 24-hour soak the WEC source failed twice during retention.
- **Two registered natural events were not shown.** Entra token refresh with no delivery
  failure code is not demonstrated: `deliveryFailureCodes` holds `delivery-failure`, with no
  times, so it cannot be told apart from F01's failures. Sender journald rotation is not
  recorded in the committed evidence.
- **TLS expiry:** `syslog-tls-expiry`, deployed and enabled from the `monitoring.bicep` of
  `8f615b8` (which includes #171), did not fire in the 72 hours, including F04's syslog TLS
  certificate rotation. That shows no false positive in this lab configuration; the rule was not
  tested against a certificate near expiry.
- **Canaries:** 4,320 of 4,320 per source at Sentinel.
- **Smoke** exact on both collectors. The **interim** ran at +14 h 13 m instead of +2 h 10 and
  covered hour 0 (`h00`, 11:05Z to 12:05Z): the WEC was exact for hour 0, and the firewall figures are
  not a valid comparison because the native export does not stop at hour 0 (the final is exact
  for every firewall id).
- **Cleanup:** the audit recorded 38 of 38 checks absent on 2026-11-10, and the private lab
  directory was deleted. The estimated cost was about USD 110–125.

## 7. Troubleshooting

| Symptom | Likely cause | Check | Action |
|---|---|---|---|
| WEC latency grows over hours while Bower's queue stays empty | Reader backlog: before group commit, one durable commit per event capped a subscription at about 44 events/sec; on a burstable host out of credits, lower (section 9) | `ForwardedEvents` newest record minus `/v1/status` `windowsEventLog.bookmarkRecordId`; CPU seconds per hour | Upgrade to a build with group commit; a non-burstable WEC host ([sizing](../deployment/windows-event-log-source.md#throughput-cpu-and-wec-sizing)); `ForwardedEvents` sized to hold hours, not days |
| Latency grows after every burst and never recovers | Burstable instance out of CPU credits | `CPUCreditBalance` (AWS), `CPU Credits Remaining` (Azure) | Unlimited credits or a fixed-performance size |
| `source-transport-errors` at :00 | Hourly retention purge holding the queue while the source or delivery writes (`SqliteException`, `winevt-source-failed`) | Application log event 1002 and health `windowsEventLog.state` at :00 | Investigate and track section 9. In this soak it recovered without a measured loss |
| `syslog-tls-expiry` fires with valid certificates | No client CRL configured; the rule on `1a4c4c2` treats the missing date as unknown | Rule query output `tls-metadata-unknown` | Upgrade to a build with #171 |
| Reconciliation shows N missing and N extra Windows ids | Native ids compared after default-detector redaction | Probe `redactionChangedIds` | Compare on the original id (probe column 4) |
| Extra Sentinel ids at the end | Generation drifted past the last native window | Last window's event times | Export the window after the end (`h24`, `h72`) while the hosts still run; once they terminate it is lost (section 10) |
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

Then one 72-hour re-soak of the same topology on four `m6i.large` hosts (fixed performance),
with a pre-registered plan, eleven scheduled faults, per-minute canaries, a RunId-owned
identity bucket so the identity sets could be compared in full, and three expiry guards for an
unattended run. Evidence:
[resoak-20261106-092539](../evidence/resoak-20261106-092539/README.md). Cleanup was audited
independently (38 of 38 checks absent), as was the aborted first attempt (38 of 38).

## 9. Known defects found by this work

1. **WEC reader falls behind** (mitigated by group commit, #178; [wecfix evidence](../evidence/wecfix-20261103-043750/README.md)).
   In the 24-hour soak (`1a4c4c2`, credit-limited `t3.medium`) the WEC's p99 latency was
   881.8 s. It was first attributed to reader cost growing with `ForwardedEvents`; profiling
   ruled that out (a poll costs 0.8–0.95 ms from 10,000 to 1,040,000 records). The limit was one
   durable queue commit per event (about 22 ms of flushes on gp3), capping a subscription at
   about 44 events/sec, below the tested burst rate. The wecfix run exercised an earlier
   group-commit build at 100 events/sec; its reader lag is unknown.
   In the 72-hour re-soak (`8f615b8`, `m6i.large`) the WEC's p99 outside fault windows was
   11.5 s against the 18.16 s limit, only hour 58 was above it (also on the firewall), reader
   gaps, resets and read errors stayed 0, and CPU was flat at about 38 s an hour, including after
   `ForwardedEvents` filled at 1.9 million records. That is consistent with #178, but not isolated
   from the host change: the re-soak changed both the build and the host type, and burstable
   hosts were not re-tested. It does not qualify the WEC path, because growth (criterion 3) still
   fails (defect 6).
   Still unexplained: in the 24-hour soak, WEC CPU rose from about 450 s to about 2,500 s an hour
   as `ForwardedEvents` grew to 900,000 retained records. It did not recur on `m6i.large`; the
   credit-limited host is a candidate, not a proven cause. Backlog sizes and drain times reported
   for that soak subtracted the process `eventsRead` counter from `RecordCount` and are invalid
   (the archived final sample yields −103); the run did not record the newest record ID.
2. **Hourly retention contends with queue writers on Windows** (mitigated: 1,000-row purge
   transactions with pauses, ledger compaction scanning through the purge boundary (including
   any unresolved prefix), SQLite busy treated as a
   back-off). In the [wecfix evidence](../evidence/wecfix-20261103-043750/README.md),
   the second purge window's observed Sentinel sample had a 35.7-second p99 against
   the 18.16-second limit; completeness of the workload was not proven. Repeat that
   scenario and the re-soak before calling the issue qualified. The source failed
   in-process twice and the delivery loop logged `SqliteException` three times, each while
   retention purged 36,000–41,000 rows (43–72 s). It recovered and fired a true
   `source-transport-errors` alert; the historical native exports do not establish complete
   no-loss reconciliation. Smaller purge batches or yielding between batches should be
   evaluated. In the 72-hour re-soak on `8f615b8` (with #178's batched retention) the WEC ran
   143 retention runs with no `source-transport-errors` alert, health records `healthy`
   outside F01 and every WEC id accepted and at Sentinel exactly once; the second purge
   scenario itself was not repeated.
3. **TLS-expiry false positive without a CRL** (fixed after the 24-hour soak by
   [#171](https://github.com/jusso-dev/Bower/pull/171)). The 72-hour re-soak ran a build with
   #171, rotated the syslog TLS certificate (F04), and `syslog-tls-expiry` never fired.
4. Harness defects found and fixed during the runs (all preserved in the evidence): probe id
   redaction in the smoke, the sampler's timestamp parsing, and the final export's task time
   limit (24-hour soak); the 65-minute gap between smoke and soak that tripped
   `destination-freshness` (first re-soak attempt, fixed by ending the smoke 20 minutes before
   the soak); a cached empty Sentinel query result that could look like missing events (fixed
   by #199 before the final). Not fixed:
   the re-soak's last native window depends on an operator step (section 10).
5. **Suppression replay around a bookmark update.** In the default collector, the new WEC
   batch path commits the cursor and queue together and rolls back an entire refused record,
   including its suppression and generated alert. This has focused tests but has not been
   qualified by a native Windows process kill, Windows-host backup/restore, or live
   Sentinel re-soak. A platform-neutral SQLite backup/restore test passes.
   Earlier committed suppressions and custom or separate cursor stores retain the prior
   replay limitation; see [bookmarks and restart](../deployment/windows-event-log-source.md#bookmarks-restart-and-backpressure).
   The re-soak killed (F06) and rebooted (F07) the WEC with nothing missing or duplicated at
   Sentinel, but it did not check suppressions or generated alerts, so this stays unqualified.
6. **Resource growth above the registered threshold** (open; found by both soaks). In the
   72-hour re-soak: firewall queue DB + WAL +54.8% and threads +19.1% over hours 3–24, and
   memory +199.2% and FDs +55.3% after the last restart; WEC private bytes +210.2%, threads
   +293.9%, queue +26.2% and handles +14.6% over hours 3–24, and memory +49.2%, threads +40.8%
   and handles +23.4% after the last restart. Queue growth flattened in the later window (2.3%
   and 1.6%). Memory growth could be warm-up after a restart or a slow leak; one run cannot
   tell. Investigate with heap and handle profiles over a long steady window before the next
   re-soak. Do not relax the threshold.
7. **Unexplained `dcr-request-errors` alert** (open). The DCR answered at least one Logs
   Ingestion request with a code other than 200, 202 or 204 in the rule's 15-minute window
   before 2026-11-08T21:28:49Z; the alert resolved at 21:48:52Z. The response code was not captured and cannot be now. Both collectors' latency rose in the
   same hour; nothing was lost or duplicated. The next run should record the DCR metric split
   by `ResponseCode` (or the DCR error logs) and the collectors' delivery failures with
   timestamps, so an alert like this can be attributed.

## 10. Known limits

- One 24-hour run and one 72-hour run per collector type. Slow growth cannot be told apart from
  warm-up within them.
- Lab hosts, not a firewall appliance or a production domain. Burstable instances changed the
  WEC outcome in the 24-hour soak; the re-soak used fixed-performance hosts only.
- Docker, Kubernetes, Azure-hosted and on-premises collectors were not soaked. Their procedures
  above are not qualified by these runs.
- The 24-hour soak covers `1a4c4c2` and the re-soak `8f615b8` only. Later commits need their
  own soak before release.
- **One WEC native window is missing from the re-soak.** `h72` was not exported before the hosts
  terminated, so the WEC's criterion 1 cannot be completed for that run: 51 accepted and
  Sentinel ids have no native record.
- **The harness depends on a timely final step.** The DC generator drifts past the soak end,
  and only an operator's `native-h72` export, run after the final reconciliation and before the
  hosts power off at end + 4 h, captures that window. One missed step loses the evidence for
  good. **Recommended (not implemented):** have the hosts export the window after the end
  themselves before shutdown. For example, the DC agent exports `h72` (end to end + 1 h) as part
  of its own final publish, and the expiry guard refuses to power off until that export is
  uploaded or a later deadline passes. The reconciler then never needs an operator on the hosts.
- Sentinel throttling (HTTP 429) was registered as skipped in the re-soak, not passed.
- Releases are unsigned (deferred).
