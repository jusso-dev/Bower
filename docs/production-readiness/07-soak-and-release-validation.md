# 7. 24-hour soak and release validation

**Gap:** prove that the scoped rollout stays correct and stable for a full day of ordinary
traffic, including the hourly and daily housekeeping that short tests never reach, and give
every release a repeatable gate that ties gaps 1 to 6 together.

**Scope:** the scoped rollout, Windows WEF/WEC (`ForwardedEvents`) and firewall syslog over
RELP with mutual TLS, to the C# Bower collector, to Microsoft Sentinel (Logs Ingestion API).
Releases and packages are **unsigned** (signing is deferred). Bower still refuses unsigned or
untrusted packs.

**Status: the soak was run and FAILED.** Neither collector met all six criteria, so the
release check for the soak (check 7) stays open. Firewall: criteria 1, 2, 4 and 6 met, 3 and 5
failed. WEC: criteria 2 and 6 met, 3, 4 and 5 failed; criterion 1 is unqualified because
accepted-stage extras and complete native coverage were not verified (section 6). All
896,400 observed native IDs per collector appeared in Sentinel, with no process restarts
and no privacy-marker matches. The failures:

- **WEC latency.** p99 reached 882 s on a CPU-credit-limited host. Historical reader
  backlog is unknown: the earlier estimate subtracted a process counter from the channel's
  retained record count. Profiling afterwards
  ([wecfix](../evidence/wecfix-20261103-043750/README.md)) found the reader's poll cost flat
  with `ForwardedEvents` size; the limit was one durable queue commit per event (about 44
  events/sec), addressed by group commit; a re-soak remains required (section 9).
- **Alerts.** The TLS-expiry false positive fired all run (fixed afterwards on main by #171),
  and the source-transport alert fired twice, correctly, when the WEC source failed during the
  hourly queue retention.
- **Growth.** The registered slope threshold (hours 3–24, 30-day projection under 10% of the
  mean) failed for memory, handles or FDs and the queue file on both collectors, and for
  threads on the WEC.

**Neither path is production-ready on this soak.** Check 7 stays open until a re-soak passes all
six criteria on a build that includes #171 (the TLS-expiry fix) and a fix for the WEC reader
cost. The firewall's remaining failure is growth: small (RSS 80–100 MB over the workload) but
above the registered threshold, so the re-soak must settle it. See [results](#6-results-of-the-soak) and the
[evidence](../evidence/soak-20261102-015614/README.md).

The soak ran main at **`1a4c4c2`**. Later merges are not covered by it and rely on their own
evidence: [#161](https://github.com/jusso-dev/Bower/pull/161) storage pressure
([gap 3](03-storage-pressure.md)), [#169](https://github.com/jusso-dev/Bower/pull/169)
replay-safe detections ([gap 2](02-replay-safe-detections.md)) and
[#171](https://github.com/jusso-dev/Bower/pull/171) the TLS-expiry fix. At that snapshot,
main was `d7ddc55`. A release built from a later commit needs its own soak (section 4).

An isolated re-soak harness dry run on 3 November was interrupted before its final
reconciliation. Its hosts were subsequently terminated by the run's expiry guard, and
available synthetic result files and destination counts were retained for recovery. The
planned 72-hour qualification has not run; neither the dry run nor the partial counts close
the soak gate. See the [interrupted campaign record](../evidence/interrupted-20261103/README.md).

Contents:

1. [What a soak proves, and what it does not](#1-what-a-soak-proves-and-what-it-does-not)
2. [Pass criteria](#2-pass-criteria)
3. [The soak method (all environments)](#3-the-soak-method-all-environments)
4. [Step by step, per environment](#4-step-by-step-per-environment)
5. [Release checklist (CI, gaps 1 to 7, pilot)](#5-release-checklist-ci-gaps-1-to-7-pilot)
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
| 3 | No unbounded growth | Least-squares slope over hours 3–24 of the workload (not the drain after it) of memory (RSS / private bytes), FDs / handles, threads and queue DB + WAL bytes | The slope × 720 h is under 10% of the mean (a falling series passes) |
| 4 | Latency | First `ingestion_time()` minus event time, per hour and overall | Whole-run p99 at most twice the pilot's connected p99 (13.3 s firewall, 18.16 s WEC; [pilot](../evidence/pilot-native-20261030/README.md)). Every hour above the limit is listed |
| 5 | No alerts | Azure Monitor alert instances and Sentinel incidents from the [monitoring rules](06-monitoring-and-runbooks.md) | None fired during the run |
| 6 | Privacy | `tostring(pack_all())` of every destination row searched for the synthetic markers (the synthetic user name, raw kernel prefix, synthetic password prefix) | 0 matches |

**Recommended for future runs (added after this soak; not part of its registered criterion 3):**
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
| 7 | 24-hour soak passes all six criteria for **every** collector type in the rollout | this guide | [soak-20261102-015614](../evidence/soak-20261102-015614/README.md): **failed** (WEC latency, alerts, growth) |
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

**Current state (2026-11-03).**

- **Firewall over RELP:** checks 0–6 and 8 have evidence. Check 7 is **open**: the firewall
  met criteria 1, 2, 4 and 6 and failed 3 (growth above the registered threshold) and 5 (the
  TLS-expiry false positive, fixed by #171 after the soak). It needs a re-soak on a build with
  #171 that passes all six.
- **WEC:** check 7 is **open**. It failed criteria 3, 4 and 5 on reader latency, growth slopes
  (memory, handles, threads, queue) and retention contention. It needs the reader fix and a
  re-soak.
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

## 7. Troubleshooting

| Symptom | Likely cause | Check | Action |
|---|---|---|---|
| WEC latency grows over hours while Bower's queue stays empty | Reader backlog: before group commit, one durable commit per event capped a subscription at about 44 events/sec; on a burstable host out of credits, lower (section 9) | `ForwardedEvents` newest record minus `/v1/status` `windowsEventLog.bookmarkRecordId`; CPU seconds per hour | Upgrade to a build with group commit; a non-burstable WEC host ([sizing](../deployment/windows-event-log-source.md#throughput-cpu-and-wec-sizing)); `ForwardedEvents` sized to hold hours, not days |
| Latency grows after every burst and never recovers | Burstable instance out of CPU credits | `CPUCreditBalance` (AWS), `CPU Credits Remaining` (Azure) | Unlimited credits or a fixed-performance size |
| `source-transport-errors` at :00 | Hourly retention purge holding the queue while the source or delivery writes (`SqliteException`, `winevt-source-failed`) | Application log event 1002 and health `windowsEventLog.state` at :00 | Investigate and track section 9. In this soak it recovered without a measured loss |
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

1. **WEC reader falls behind** (mitigated by group commit; [wecfix evidence](../evidence/wecfix-20261103-043750/README.md),
   re-soak still required). The suspected cause below was profiled and is not it: a poll
   costs 0.8–0.95 ms from 10,000 to 1,040,000 records. Each event was its own durable commit
   (about 22 ms of flushes on gp3), capping a subscription at about 44 events/sec, below the
   tested burst rate. The earlier group-commit build was exercised at 100/sec, but its
   historical reader lag is unknown, and subsequent runtime changes have not been live-qualified.
   The CPU growth did not reproduce on `m6i.large` and stays unexplained (the soak's
   `t3.medium` is the candidate). In the original soak, CPU per hour rose from about 450 s
   to about 2,500 s as `ForwardedEvents` grew to 900,000 retained records; the cause is
   unproven. Previously reported backlog sizes and drain times were computed by subtracting
   the process `eventsRead` counter from `RecordCount` and are invalid. The archived final
   sample yields −103 by that calculation; the run did not record the newest record ID.
   Repeat the failed destination latency gate and the full re-soak before qualification.
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
   evaluated.
3. **TLS-expiry false positive without a CRL** (fixed after this soak by
   [#171](https://github.com/jusso-dev/Bower/pull/171); not covered by this soak).
4. Harness defects found and fixed during the run (all preserved in the evidence): probe id
   redaction in the smoke, the sampler's timestamp parsing, and the final export's task time limit.
5. **Suppression replay around a bookmark update.** In the default collector, the new WEC
   batch path commits the cursor and queue together and rolls back an entire refused record,
   including its suppression and generated alert. This has focused tests but has not been
   qualified by a native Windows process kill, Windows-host backup/restore, or live
   Sentinel re-soak. A platform-neutral SQLite backup/restore test passes.
   Earlier committed suppressions and custom or separate cursor stores retain the prior
   replay limitation; see [bookmarks and restart](../deployment/windows-event-log-source.md#bookmarks-restart-and-backpressure).

## 10. Known limits

- One 24-hour run per collector type. Slow growth cannot be told apart from warm-up within it.
- Lab hosts, not a firewall appliance or a production domain. Burstable instances changed the
  WEC outcome.
- Docker, Kubernetes, Azure-hosted and on-premises collectors were not soaked. Their procedures
  above are not qualified by this run.
- The soak covers `1a4c4c2` only. Later commits need their own soak before release.
- Releases are unsigned (deferred).
