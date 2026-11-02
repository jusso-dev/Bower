# 3. Full queues and low disk space

**Gap:** prove backpressure, early warning and safe recovery when storage fills,
without ever discarding unacknowledged events.

**Scope:** the scoped rollout, Windows WEF/WEC (`ForwardedEvents`) and firewall
syslog (RFC 5424 over mutual TLS) to the C# Bower collector to Microsoft Sentinel
(Logs Ingestion API). Releases and packages are **unsigned** at the moment (signing
is deferred); Bower still refuses unsigned or untrusted packs.

**Status: qualified on AWS for the scoped rollout, with the limits below.** Four
storage defects found on AWS (including the page-ceiling stall workstream 6 also
reported) are fixed. Free-space watermarks, storage status, `collector_health`
storage fields, the `queue-storage` alert and host checks are in place. A final run on
1 GiB (Linux) and 2 GiB (Windows) queue volumes reconciled every accepted
sequence-numbered event in Sentinel through queue saturation, the watermarks, a
completely full volume and a restart while full. Plain syslog over TCP still loses
frames held in socket buffers if the collector restarts while backpressured (measured;
RELP senders do not). Releases are unsigned. See [how we tested this](#10-how-we-tested-this)
and [known limits](#known-limits).

Contents:

1. [How Bower behaves when storage fills](#1-how-bower-behaves-when-storage-fills)
2. [What changed](#2-what-changed)
3. [Capacity planning](#3-capacity-planning)
4. [Configuration reference](#4-configuration-reference)
5. [Early-warning signals](#5-early-warning-signals)
6. [Procedures by environment](#6-procedures-by-environment)
7. [WEC `ForwardedEvents` size and retention](#7-wec-forwardedevents-size-and-retention)
8. [Recovery runbook](#8-recovery-runbook)
9. [Troubleshooting](#9-troubleshooting)
10. [How we tested this](#10-how-we-tested-this)
11. [Known limits](#known-limits)

---

## 1. How Bower behaves when storage fills

Bower keeps every accepted event in one SQLite database (`BOWER_QUEUE_PATH`, WAL
mode, `synchronous=FULL`). An event is **accepted** once its queue transaction has
committed; it is deleted only after the destination acknowledged it **and** the
acknowledged-row retention has passed. Storage can run out in five places, checked
in this order on every new event:

| Limit | What it bounds | Default | When reached |
| --- | --- | --- | --- |
| Free-space **critical** watermark | Free bytes on the queue volume | below max(256 MiB, 5%) | New events refused (`storage-critical`) |
| Pre-write physical budget | Database + WAL bytes | 4 × M + 16 MiB minus a half-ceiling reserve | All writes refused until the WAL resets |
| **Intake page limit** | Database pages in use | 85% of (M + 4 MiB) | New events refused (`queue-capacity`) |
| Logical cap `BOWER_QUEUE_MAX_BYTES` (M) | Undelivered payload bytes | 10 GiB | New events refused (`queue-capacity`) |
| SQLite page ceiling | Database file | 1.75 × (M + 4 MiB) | Only settlement can reach it |

`M` is `BOWER_QUEUE_MAX_BYTES`. The free-space and physical-budget checks can bind
before the intake page limit. With enough free space and a resettable WAL, a queued row
takes about **2.2 times its payload** on disk once its ledger entry and indexes are
counted (measured 2.6 KB per syslog event and 3.0 KB per Windows 4625 event for
1.2 KB and 1.4 KB payloads). The queue therefore refuses new events when undelivered
payload is about **40–45% of `BOWER_QUEUE_MAX_BYTES`**, not 100%, and retained
acknowledged rows count against the same pages. Size the queue in events, with
[the formula below](#3-capacity-planning).

### What keeps running when new events are refused

Free-space watermark refusals apply to **new** events only. The candidate reserves
room for leasing, delivery, acknowledgement, retries, dead-lettering and retention
when the intake page limit is reached. Progress is not guaranteed if the physical
volume is full or a pinned WAL exhausts the write budget; those failures require
space or the reader to be released before writes can resume:

- The free-space watermarks never refuse settlement writes.
- Settlement may grow the database up to 1.75 × (M + 4 MiB), past the intake page
  limit. Acknowledging a row enlarges it, and pages filled by appends split; settling a
  full backlog grew the database to 140% of the intake limit in the regression test.
- When pages in use reach 80% of the intake limit, or the volume is below its warning
  watermark, retention removes **acknowledged** rows older than
  `BOWER_QUEUE_PRESSURE_RETENTION_MINUTES` (default 60), oldest first. At 95% of
  the intake limit it can remove acknowledged rows of any age, before the 100%
  intake-page refusal threshold.
  Undelivered, retrying and dead-lettered rows are never removed. With an archive
  configured, only rows the archive verifiably holds are removed.
- A write over the physical budget first attempts a `wal_checkpoint(TRUNCATE)` (at
  most every 10 seconds), so a WAL that readers kept from resetting no longer refuses
  acknowledgements until the daily maintenance job.

### How each source reacts to a refusal

| Source | On refusal | Event kept by | Loss window |
| --- | --- | --- | --- |
| HTTP `POST /v1/events`, pack endpoints, relay intake | HTTP 503; nothing committed | The producer, which must retry | None if the producer retries |
| Syslog TCP/TLS | Holds the frame, **stops reading**, keeps the connection, retries every second (`retries` counter) | Kernel socket buffers, then the sender's queue | **Frames in kernel buffers are lost if the collector restarts or the connection resets** (measured below) |
| Syslog RELP | Withholds the acknowledgement; after 30 seconds of refusals closes the session (`relpBusyCloses`) | The sender, which resends unacknowledged messages | None for a RELP sender that resends |
| Syslog UDP | Drops and counts (`dropped`) | Nobody | Every refused datagram |
| Windows Event Log / WEC `ForwardedEvents` | Stops reading; the bookmark stays before the first unread event; subscription `state` is `backpressure` | The event log channel | Events overwritten when the channel wraps (`gaps` counter) |

Disk-full errors from SQLite during intake (`SQLITE_FULL`, or an I/O error while the
volume is critical) are reported as the same backpressure (`storage-full`). Before
this change they closed the syslog connection, losing buffered frames.

### Filesystem cases

| Case | What happens now | Data at risk |
| --- | --- | --- |
| Volume below the warning watermark | Warning state, `/v1/status` and log `1501`; acknowledged rows past the floor are reclaimed so new events reuse pages | None |
| Volume below the critical watermark | New events refused (`storage-critical`); `/health` reports `degraded`; delivery and acknowledgement continue | None accepted; syslog TCP kernel buffers on restart |
| WAL growth (checkpoint starvation) | Bounded by the pre-write budget; the next write over budget truncates the WAL once readers release it | None |
| Checkpoint cannot grow the database (volume full) | Committed pages remain in the WAL. Writes can fail until space returns and a checkpoint succeeds | Previously accepted events remain durable subject to the underlying filesystem; in-flight syslog frames remain at risk |
| `SQLITE_FULL` during commit | The transaction rolls back; intake reports `storage-full`; settlement retries after 5 seconds; leases expire and are re-leased | None (acknowledged uploads may be replayed: duplicates, not loss) |
| Cursor or bookmark write fails | The bookmark stays at the last committed position; events are re-read and deduplicated by event id | None |
| Logs fill the same disk | Bower writes no log files: Linux logs go to journald, Windows warnings to the Application log. Storage logs are bounded (below) | Depends on what else shares the volume |
| Restart on a full volume | The collector starts and serves reads; new events are refused until space returns; settlement fails until a write fits | Syslog frames in kernel buffers at the moment of restart |
| Retained acknowledgements fill the pages | Fixed: pressure retention reclaims them | None |

### Bounded logging

Storage conditions log **state changes**, not events. Every message is metadata only:
byte counts, percentages, reasons, counts. Never paths, payloads or event ids.

| Event id | Level | When |
| --- | --- | --- |
| `1500` | Error | Volume entered the critical watermark |
| `1501` | Warning | Volume entered the warning watermark |
| `1502` | Information | Free space recovered |
| `1503` | Warning | Free space cannot be measured (watermarks not enforced; the queue limits still apply) |
| `1504` | Warning | Refusal summary, at most once a minute: count, latest reason, storage refusals |
| `1505` | Warning | Storage sampling failed (at most once a minute) |
| `1506` | Warning | Retention removed acknowledged rows early (trigger, page use before and after) |
| `1002` | Error | Delivery loop failure: first occurrence, then every 12th consecutive one (about one a minute) |

On AWS, a 19-minute queue-full run logged 45 lines (7.4 KB) in total.

---

## 2. What changed

| Change | Why |
| --- | --- |
| Free-space watermarks (`BOWER_STORAGE_*`) with hysteresis, enforced on every insert | Intake stops before the volume is exhausted; nothing previously looked at free disk space |
| Intake page limit at 85% and a 1.75× settlement ceiling | **Defect fixed:** a backlog that filled the page ceiling could never be leased or acknowledged (`SQLITE_FULL`), so the queue never drained. Seen on both AWS collectors |
| Pressure retention of acknowledged rows | **Defect fixed:** acknowledged rows kept for duplicate detection (7 days by default) filled the pages and refused all intake with nothing undelivered. At 10/sec and the default 10 GiB cap this happens after about 4.5 days |
| Intake-blocked reclaim ignores the retention floor | **Defect fixed:** after a full backlog drained, every page held a fresh acknowledgement and intake stayed refused for the floor duration |
| WAL truncate before refusing a write | **Defect fixed:** a WAL that checkpoints could not reset exceeded the write budget and refused acknowledgements (72.6 MB WAL on the Windows collector) |
| `SQLITE_FULL` and disk-full I/O errors on intake are backpressure | Syslog keeps the frame and the connection; WEC keeps the bookmark |
| `storage` block in `/v1/status` and the management heartbeat; `/health` `degraded` when critical; `deliveryStatus` `backpressure` when the volume is critical or pages reach 95% | Early warning, metadata only |
| `queuePages` (workstream 6's page snapshot) now reports the limit at which new events are refused, plus `ceilingBytes` | One page computation for status, health records, alerts and host checks |
| `collector_health` `storage` gains volume state, free space, thresholds, WAL size, storage refusals and pressure purges; problem codes `storage-critical` and `storage-low` | The `queue-storage` alert and host checks see the volume (see [monitoring](06-monitoring-and-runbooks.md)) |
| The collector's own health record uses the settlement reserve, skips the critical watermark and may use a small logical reserve past `BOWER_QUEUE_MAX_BYTES` (a sixteenth of it, at most 1 MiB) | **Defect fixed (workstream 6):** the storage alert could not see a full queue because its records were refused, including when large events filled the byte cap with pages to spare |
| A large event refused by the page limit triggers retention at any page use | **Defect fixed:** an event needing more pages than remained was refused below the 80% trigger, and its source retried it forever |
| New queues use incremental auto-vacuum; retention returns free pages to the file system in 8 MiB steps under pressure, at most 10 seconds per run with one checkpoint at the end. It keeps a reserve of free pages for the undelivered rows to settle (about twice their payload, plus 64 pages) and releases the rest, even while a backlog waits for the destination. Without disk pressure it waits until pages in use are back within the intake limit | Pruning reclaims disk, not only pages (existing queues keep reusing free pages); the reserve lets a draining backlog reuse pages instead of regrowing the file. Also runs when archive coverage refuses purging |
| Rust queue: same intake limit and settlement ceiling | Either runtime opens and drains a queue the other grew while settling |
| Archive-backed retention purges only the archive-verified sequences | A concurrent purge could shift a verified batch onto unverified rows |
| Bounded storage logs; delivery-loop failure logs throttled | A full disk must not also fill the journal |
| Kubernetes manifest sets `BOWER_QUEUE_MAX_BYTES` (5 GiB), a 16Gi claim and ephemeral-storage | The 10 GiB default, and settlement growth, could exceed the old 10Gi claim |

The Rust collector (`bower-collector-rs`) now shares the page model: the same 85%
intake limit and 1.75× settlement ceiling, so either runtime opens and drains a queue
the other grew while settling. It has no watermarks, pressure retention, incremental
vacuum or `storage` status; see [known limits](#known-limits). The Sentinel schema, DCR
and table are unchanged.

---

## 3. Capacity planning

### Inputs

| Symbol | Meaning | Measured on AWS |
| --- | --- | --- |
| `R` | Accepted events per second (after selection) | 10/sec steady, 100/sec burst in the pilot envelope |
| `T` | Longest destination outage the collector must ride through | 1 hour (pilot), 24 or 72 hours for weekend coverage |
| `F` | Database bytes per queued row | 2.6 KB syslog, 3.0 KB Windows 4625 (use 3 KB) |
| `P` | Payload bytes per event (`undeliveredBytes / undelivered rows`) | 1.2 KB syslog, 1.4 KB Windows 4625 |
| `T_floor` | `BOWER_QUEUE_PRESSURE_RETENTION_MINUTES` | 60 minutes |
| `E` | `ForwardedEvents` bytes per forwarded event | 2.2 KB (Security 4625, `ContentFormat=Events`) |

Measure `F` and `P` on your own traffic: run steady load for ten minutes with the
destination blocked, then divide `storage.queueDatabaseBytes` by the undelivered row
count, and `queue.undeliveredBytes` by the same count.

### Formula

1. **Rows to hold:** `N = R × T + R × T_floor` (the backlog plus the acknowledged rows
   pressure retention must keep).
2. **Queue cap:** `M ≥ N × F / 0.85 − 4 MiB`. Round up. The logical rule
   `M ≥ R × T × P` is then always met because `F > P`.
3. **Database ceiling on disk:** `D = 1.75 × (M + 4 MiB)`.
4. **Queue volume:** `V ≥ max((D + 128 MiB + 1 GiB) / (1 − r), (D + 128 MiB) / (0.9 − r))`
   with the default watermarks (warning below max(1 GiB, 10%) of the filesystem). `r` is
   the share reserved for root, which the service cannot use: 0 for xfs and for ext4
   created with `-m 0`, 0.05 for ext4 defaults. `V` is the filesystem size; a disk or
   claim of that size formats to about 2% less on ext4 (inode tables and journal), so
   request `V / 0.98`. The 128 MiB covers WAL bursts (a 5,000-row retention purge wrote
   up to 72 MB of WAL on AWS, truncated within 5 seconds) and shared memory. Add archive
   and spool space if they share the volume.
5. **`ForwardedEvents`:** `S ≥ R × E × T_stall × 1.2`, where `T_stall` is the longest
   time Bower itself may stop reading (service down, queue full, volume critical). A
   destination outage alone does not use this budget while Bower's queue has room.
6. **Acknowledged retention:** keeping `BOWER_QUEUE_RETENTION_HOURS` (default 168) of
   acknowledged rows needs `R × hours × 3600 × F` more. At 10/sec, 168 hours is about
   18 GB. Either budget it, or lower the retention (for example 24 hours) and let
   pressure retention trim it under load.

### Worked examples (F = 3 KB, E = 2.2 KB, 1-hour floor, xfs: r = 0)

| Rate | Outage | Events | `BOWER_QUEUE_MAX_BYTES` (M) | Database ceiling 1.75 × (M + 4 MiB) | Queue volume | `ForwardedEvents` for the same stall |
| --- | --- | ---: | --- | --- | ---: | --- |
| 10/sec | 1 hour | 36,000 | `268435456` (256 MiB) | 455 MiB | 2 GiB | 91 MiB |
| 10/sec | 24 hours | 864,000 | `3221225472` (3 GiB) | 5.3 GiB | 7 GiB | 2.1 GiB |
| 10/sec | 72 hours | 2,592,000 | `9663676416` (9 GiB) | 15.8 GiB | 18 GiB | 6.4 GiB |
| 100/sec | 1 hour | 360,000 | `2684354560` (2.5 GiB) | 4.4 GiB | 6 GiB | 906 MiB |
| 100/sec | 24 hours | 8,640,000 | `32212254720` (30 GiB) | 52.5 GiB | 59 GiB | 21.2 GiB |
| 100/sec | 72 hours | 25,920,000 | `93415538688` (87 GiB) | 152.3 GiB | 170 GiB | 63.7 GiB |

The default `BOWER_QUEUE_MAX_BYTES` (10 GiB) holds about 3 million rows: roughly 84
hours at 10/sec or 8 hours at 100/sec, less the acknowledged rows still retained.

`ForwardedEvents` above about 4 GiB is impractical on one WEC: plan shorter Bower
stall budgets at 100/sec (see [section 7](#7-wec-forwardedevents-size-and-retention)).

---

## 4. Configuration reference

All settings are environment variables of the collector (`/etc/bower/bower.env` on
Linux, the service `Environment` value on Windows, the pod spec on Kubernetes). They
apply to the C# collector only.

| Variable | Default | Range | Meaning |
| --- | --- | --- | --- |
| `BOWER_QUEUE_PATH` | `/var/lib/bower/queue.db` (packages) | path | Queue database. Put its directory on the dedicated volume |
| `BOWER_QUEUE_MAX_BYTES` | `10737418240` (10 GiB) | ≥ 1 MiB | `M` above. Raising it later is safe; lowering it below the current database is refused at start. The collector's own health records may exceed it by min(M/16, 1 MiB) |
| `BOWER_QUEUE_RETENTION_HOURS` | `168` | 1–2160 | Acknowledged rows kept for duplicate detection |
| `BOWER_QUEUE_PRESSURE_RETENTION_MINUTES` | `60` | 1 to the retention | Acknowledged rows younger than this survive pressure retention (unless intake is blocked) |
| `BOWER_STORAGE_WARNING_FREE_BYTES` | `1073741824` (1 GiB) | ≥ critical bytes | Warning when free space is below max(bytes, percent) |
| `BOWER_STORAGE_WARNING_FREE_PERCENT` | `10` | 0–50, ≥ critical percent | |
| `BOWER_STORAGE_CRITICAL_FREE_BYTES` | `268435456` (256 MiB) | ≥ 16 MiB | New events refused below max(bytes, percent) |
| `BOWER_STORAGE_CRITICAL_FREE_PERCENT` | `5` | 0–50 | |
| `BOWER_DELIVERY_LEASE_SECONDS` / `BOWER_DELIVERY_TIMEOUT_SECONDS` | `300` / `240` | see [queue durability](../operations/queue-v5-durability.md) | The pilot used 90/60 |

A state is left only once free space clears its threshold by max(16 MiB, 1% of the
volume), so intake does not flap. Free space is measured as the service account sees
it (`statvfs` `f_bavail` on Linux, `GetDiskFreeSpaceEx` on Windows, which follows NTFS
mounted folders). Reserved root blocks (ext4 keeps 5% by default) are excluded.
Non-default values append to the reported configuration hash; defaults keep existing
hashes.

The thresholds suit volumes of about 10 GiB and larger. On a small dedicated volume
set them explicitly (the AWS lab used 256 MiB warning and 128 MiB critical on 1 GiB,
and 512/256 MiB on 2 GiB, both with percentages at `0`). Keep the critical threshold
large enough for a retention purge's WAL burst and settlement growth: at least
128 MiB.

---

## 5. Early-warning signals

`GET /v1/status` (bearer token) reports metadata only:

- `queuePages`: `pageSize`, `pageLimitBytes` (in-use bytes at which new events are
  refused), `usedBytes`, `freeListBytes`, `usedPercent` (100 = refused) and
  `ceilingBytes` (largest size settlement may reach).
- `storage`: the queue volume and storage refusals (below). The management heartbeat
  carries the same object (older management servers ignore it).

| `storage` field | Meaning | Suggested alert |
| --- | --- | --- |
| `state` | `normal`, `warning`, `critical`, `unknown` | Page on `critical`; ticket on `warning` or `unknown` for 15 minutes |
| `intakePaused` | True while the critical watermark refuses new events | Page |
| `freeBytes`, `totalBytes`, `freePercent` | Queue volume as the service sees it | Trend; complements host disk alerts |
| `warningFreeBytes`, `criticalFreeBytes` | Effective thresholds | — |
| `stateChangedAt`, `warningTransitions`, `criticalTransitions` | Since start | Flapping: more than 3 transitions an hour |
| `queueFileBytes`, `queueDatabaseBytes`, `queueWalBytes` | Physical queue files | WAL above 10% of the database for 30 minutes |
| `queueMaximumBytes`, `queueUndeliveredBytes`, `queueUtilisationPercent` | Logical cap and use | Informational (the page limit binds first) |
| `oldestPendingAgeSeconds` | Age of the oldest undelivered event | Page above 15 minutes (or your SLA) |
| `pressurePurgedEvents`, `lastPressurePurgeAt` | Acknowledged rows removed early since start | Ticket on any increase: retention is undersized |
| `storageRefusals`, `storageRefusedBytes`, `lastStorageRefusalAt`, `lastStorageRefusalReason` | Refusals caused by free space (`storage-critical`, `storage-full`); a subset of `intake.capacityRefusals` plus `intake.privacyAlertRefusals` | Page on any increase |

Existing signals that matter here: `intake.capacityRefusals` and `lastRefusalReason`
(all refusals, shape shared with the Rust collector), `queue.oldestUndelivered`,
`syslog[].retries`, `dropped` and `relpBusyCloses`, `windowsEventLog[].state`
(`backpressure`), `gaps` and `bookmarkRecordId`, `/health` (`degraded` when critical,
dead-lettered or a source is overdue), and the heartbeat `deliveryStatus`.

### In Sentinel and on the host

With `BOWER_HEALTH_RECORD_INTERVAL_SECONDS` set ([monitoring](06-monitoring-and-runbooks.md#the-collector-health-record)),
each `collector_health` record carries, under `Attributes.storage`, MiB and percent
values only: `queuePagesUsedPercent`, `queuePagesUsedMiB`, `queueFreeListMiB`,
`queuePageLimitMiB`, `queueCeilingMiB`, `volumeState`, `intakePaused`, `volumeFreeMiB`,
`volumeFreePercent`, `volumeWarningFreeMiB`, `volumeCriticalFreeMiB`, `queueWalMiB`,
and window deltas `storageRefusals` and `pressurePurgedEvents`. Problem codes
`storage-low` (medium) and `storage-critical` (high) join `problems[]`; `backpressure`
also applies at 95% page use or a critical volume. The record is queued from the
settlement reserve, so it still arrives while new events are refused (measured below).

The [`queue-storage` alert](../../deploy/sentinel/monitoring/queries/queue-storage.kql)
fires on page use, undelivered bytes, `volumeState` warning or critical,
`intakePaused`, a critical record in the window, backpressure, or refusals in the
window; `volumeState` `unknown` is incomplete coverage. The host checks
([Linux](../../deploy/sentinel/monitoring/host/bower-healthcheck.py),
[Windows](../../deploy/sentinel/monitoring/host/Test-BowerCollectorHealth.ps1)) report
`queue-volume` WARNING/CRITICAL from `storage.state` and `queue-pages` from
`queuePages.usedPercent`. Runbook R5 in the monitoring guide links back to section 8.

---

## 6. Procedures by environment

Each procedure gives the queue its own volume, sets limits, verifies, and can be
rolled back. Do them during a maintenance window: moving a queue means stopping the
collector, and **a syslog sender connected while the collector stops loses whatever
sits in the kernel socket buffers**. Stop or pause the sender's forwarding first.

### 6.1 Linux packages (RPM or DEB, systemd)

**Purpose:** queue on a dedicated filesystem at `/var/lib/bower`, sized from section 3,
with watermarks and journald limits.

**Prerequisites:** root; the collector package installed
([installers](../deployment/installers.md)); a spare block device of size `V`.

1. Check the queue is drained or note its size, then stop the collector and the
   syslog sender's forwarding.

   ```bash
   TOKEN=$(sudo cat /etc/bower/secrets/ingest-token)   # or your BOWER_INGEST_TOKEN_FILE
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4319/v1/status | jq '.queue'
   sudo systemctl stop rsyslog   # or pause the appliance's forwarding
   sudo systemctl stop bower
   ```

2. Create the filesystem. xfs has no reserved root blocks; for ext4 use `-m 0` so the
   service account sees the whole volume.

   ```bash
   lsblk -o NAME,SIZE,TYPE,MOUNTPOINT          # identify the empty disk, e.g. /dev/nvme1n1
   sudo mkfs.xfs -L bowerqueue /dev/nvme1n1
   ```

3. Move existing state onto it, preserving ownership and mode.

   ```bash
   sudo mkdir -p /mnt/bowerqueue && sudo mount LABEL=bowerqueue /mnt/bowerqueue
   sudo rsync -aHAX /var/lib/bower/ /mnt/bowerqueue/
   sudo umount /mnt/bowerqueue
   echo 'LABEL=bowerqueue /var/lib/bower xfs defaults,noatime 0 2' | sudo tee -a /etc/fstab
   sudo mount /var/lib/bower
   sudo chown bower:bower /var/lib/bower && sudo chmod 0700 /var/lib/bower
   ```

   Do not add `nofail` without the next step: the service would write into the bare
   mount point on the root filesystem.

4. Make the service require the mount.

   ```bash
   sudo install -d /etc/systemd/system/bower.service.d
   printf '[Unit]\nRequiresMountsFor=/var/lib/bower\n' | sudo tee /etc/systemd/system/bower.service.d/queue-volume.conf
   sudo systemctl daemon-reload
   ```

5. Set limits in `/etc/bower/bower.env` (example: 10/sec, 24-hour outage, 8 GiB volume).

   ```bash
   sudo tee -a /etc/bower/bower.env >/dev/null <<'EOF'
   BOWER_QUEUE_MAX_BYTES=3221225472
   BOWER_QUEUE_RETENTION_HOURS=24
   BOWER_STORAGE_WARNING_FREE_BYTES=1073741824
   BOWER_STORAGE_CRITICAL_FREE_BYTES=268435456
   EOF
   ```

6. Bound the journal so logs cannot fill the root volume, then start everything.

   ```bash
   sudo install -d /etc/systemd/journald.conf.d
   printf '[Journal]\nSystemMaxUse=1G\nSystemKeepFree=2G\nRateLimitIntervalSec=30s\nRateLimitBurst=10000\n' |
     sudo tee /etc/systemd/journald.conf.d/bower.conf
   sudo systemctl restart systemd-journald
   sudo systemctl start bower && sudo systemctl start rsyslog
   ```

7. Verify.

   ```bash
   TOKEN=$(sudo cat /etc/bower/secrets/ingest-token)
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4319/v1/status | jq '{volume: (.storage | {state, freeBytes, totalBytes, warningFreeBytes, criticalFreeBytes, queueMaximumBytes}), pages: .queuePages.usedPercent}'
   findmnt /var/lib/bower
   systemctl show bower -p RequiresMountsFor
   ```

   Expected: `state` `normal`; `totalBytes` is the dedicated volume, not the root disk;
   `queueMaximumBytes` matches; `RequiresMountsFor=/var/lib/bower`.

**Pass:** status shows the dedicated volume and `normal`; `journalctl --disk-usage`
stays below `SystemMaxUse`; a filler test (section 8.6) produces `warning` then
`critical` and recovers. **Fail:** `totalBytes` equals the root disk (wrong mount), or
`state` is `unknown`.

**Rollback:** stop the collector, copy `/var/lib/bower` back to the root filesystem,
remove the fstab line and the drop-in, `systemctl daemon-reload`, start. Never delete
`queue.db`, `queue.db-wal` or `queue.db-shm` separately: they are one database.

### 6.2 Windows (MSI service, including WEC hosts)

**Purpose:** queue on its own NTFS volume **without changing `BOWER_QUEUE_PATH`**.
The MSI rewrites the service `Environment` value on repair and upgrade
([installers](../deployment/installers.md)), so a custom queue path would silently
revert to `%ProgramData%\Bower\state` after an upgrade, leaving the old queue
orphaned. Mount the volume **at** the state folder instead.

**Prerequisites:** local administrator; the MSI installed; an empty disk.

1. Stop the collector (and, on a WEC host, nothing else: WEF keeps forwarding into
   `ForwardedEvents`, which Bower reads after the restart).

   ```powershell
   Stop-Service Bower
   ```

2. Initialise and format the disk with a temporary drive letter (`Q:` here).

   ```powershell
   Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Format-Table Number, Size
   $disk = 1   # the empty disk
   Initialize-Disk -Number $disk -PartitionStyle GPT
   New-Partition -DiskNumber $disk -UseMaximumSize -DriveLetter Q | Out-Null
   Format-Volume -DriveLetter Q -FileSystem NTFS -NewFileSystemLabel bowerqueue -Confirm:$false
   ```

3. Give the **volume root** the state folder's rights. An ACL set on the mount point
   later applies to the reparse point, not to the volume, and the service then cannot
   create the WAL (in the lab it hung at start until the SCM timed out). Never combine
   `icacls /inheritance:r` with `/T`: it strips inherited entries from existing files
   and leaves them with an empty ACL.

   ```powershell
   icacls Q:\ /grant 'NT SERVICE\Bower:(OI)(CI)M'
   icacls Q:\ /remove:g 'BUILTIN\Users' 'Everyone' 'CREATOR OWNER'
   icacls Q:\      # expect only NT SERVICE\Bower (M), Administrators and SYSTEM (F)
   ```

   Move the state folder's contents (all `queue.db*` files together) onto the volume
   and mount it at the now empty folder:

   ```powershell
   $state = 'C:\ProgramData\Bower\state'
   Get-ChildItem $state -Force | Move-Item -Destination Q:\
   Add-PartitionAccessPath -DriveLetter Q -AccessPath "$state\"
   # Optional, once verified: Remove-PartitionAccessPath -DriveLetter Q -AccessPath 'Q:\'
   ```

4. Set the limits. Other settings are not MSI properties and are rewritten on
   upgrade; re-apply this step after every MSI upgrade or repair.

   ```powershell
   $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
   $environment = @((Get-ItemProperty $key).Environment | Where-Object { $_ -notmatch '^BOWER_(QUEUE_MAX_BYTES|QUEUE_RETENTION_HOURS|STORAGE_)' })
   $environment += 'BOWER_QUEUE_MAX_BYTES=3221225472', 'BOWER_QUEUE_RETENTION_HOURS=24',
       'BOWER_STORAGE_WARNING_FREE_BYTES=1073741824', 'BOWER_STORAGE_CRITICAL_FREE_BYTES=268435456'
   Set-ItemProperty $key -Name Environment -Type MultiString -Value $environment
   Start-Service Bower
   ```

5. Size the event logs (section 7) and verify.

   ```powershell
   $token = (Get-Content C:\ProgramData\Bower\secrets\ingest-token -Raw).Trim()
   (Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers @{Authorization = "Bearer $token"}).storage |
     Select-Object state, freeBytes, totalBytes, queueMaximumBytes
   Get-Partition -DiskNumber $disk | Select-Object AccessPaths
   ```

   Expected: `totalBytes` is the dedicated volume (the probe follows the mounted
   folder), `state` is `normal`.

**Pass:** as for Linux; after a test MSI repair, `BOWER_QUEUE_PATH` is unchanged and
`totalBytes` still shows the dedicated volume. **Fail:** `totalBytes` equals `C:`.

**Rollback:** stop the service, copy the `queue.db*` files from the volume to a
temporary folder on `C:`, remove the access path
(`Remove-PartitionAccessPath -DriveLetter Q -AccessPath 'C:\ProgramData\Bower\state\'`),
move the files back into the (now ordinary) state folder, reset their ACL with
`icacls C:\ProgramData\Bower\state\queue.db* /reset`, and start.

### 6.3 Docker and containers

1. Back the queue with a volume on a dedicated filesystem, never the container's
   writable layer. A bind mount makes the filesystem explicit:

   ```bash
   sudo mkfs.xfs -L bowerqueue /dev/sdb && sudo mkdir -p /srv/bower-queue
   echo 'LABEL=bowerqueue /srv/bower-queue xfs defaults,noatime 0 2' | sudo tee -a /etc/fstab && sudo mount /srv/bower-queue
   sudo chown 1654:1654 /srv/bower-queue && sudo chmod 0700 /srv/bower-queue   # the image runs as 1654:1654
   docker run -d --name bower --read-only \
     -v /srv/bower-queue:/var/lib/bower \
     -e BOWER_QUEUE_PATH=/var/lib/bower/queue.db -e BOWER_QUEUE_MAX_BYTES=3221225472 \
     --log-driver json-file --log-opt max-size=20m --log-opt max-file=5 \
     ghcr.io/jusso-dev/bower-collector:VERSION
   ```

   Named volumes (`docker volume create`) live under `/var/lib/docker` and share that
   filesystem with images and other containers; give `/var/lib/docker` its own
   volume if you use them. `--storage-opt size=` limits only the writable layer
   (overlay2 on xfs with `pquota`), not volumes.
2. Cap container logs (`max-size`, `max-file` above, or in `/etc/docker/daemon.json`).
3. The image is chiseled (no shell), so query `/v1/status` through the published
   port as in 6.1. Expected: `totalBytes` is the dedicated filesystem. The image
   declares `VOLUME /var/lib/bower`; without `-v` Docker creates an anonymous volume
   under `/var/lib/docker`.

**Rollback:** stop the container, copy the bind-mounted directory to the previous
volume, start with the previous mount.

### 6.4 Kubernetes (`deploy/kubernetes`)

The [manifest](../../deploy/kubernetes/deployment.yaml) now sets
`BOWER_QUEUE_MAX_BYTES=5368709120` (5 GiB) with a `16Gi` claim, and an
`ephemeral-storage` request of 64Mi and limit of 512Mi (logs only; the root filesystem
is read-only). The claim follows section 3 for a typical ext4 storage class (`r` =
0.05): `D = 1.75 × (5 GiB + 4 MiB)` = 8.8 GiB needs `V` = 10.4 GiB, requested as about
10.7 GiB. The earlier `10Gi` claim was too small: at the settlement ceiling it left
less free space than the warning watermark. A claim that cannot be expanded keeps
`10Gi` with `BOWER_QUEUE_MAX_BYTES=4294967296` (4 GiB, `D` = 7.0 GiB, about 8.7 GiB
needed).

1. Size the claim from section 3 (`V`), and `BOWER_QUEUE_MAX_BYTES` to match. Use a
   storage class that supports expansion (`allowVolumeExpansion: true`).
2. Keep the collector's `ephemeral-storage` limit: the kubelet evicts a pod that
   exceeds it, and evicts pods under node `nodefs`/`imagefs` pressure (defaults
   `nodefs.available<10%`). The queue on the PVC is not ephemeral and survives eviction
   and rescheduling (`ReadWriteOnce`, `strategy: Recreate`).
3. Apply and verify.

   ```bash
   kubectl --context YOUR-CONTEXT -n bower apply -f deploy/kubernetes/deployment.yaml
   kubectl --context YOUR-CONTEXT -n bower get pvc bower-data
   kubectl --context YOUR-CONTEXT -n bower port-forward deploy/bower-collector 4319:4319 &
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4319/v1/status | jq .storage
   ```

4. To grow the queue: patch the claim (`resources.requests.storage`), wait for
   `FileSystemResizePending` to clear, then raise `BOWER_QUEUE_MAX_BYTES` and roll the
   deployment.

The readiness probe uses `/health`, which reports `degraded` but still answers 200;
the pod stays ready while refusing intake so producers get 503 rather than connection
errors. **Rollback:** restore the previous manifest; the PVC keeps the queue.

### 6.5 AWS-hosted collectors (EC2)

1. Add an encrypted gp3 volume of size `V` (3,000 IOPS and 125 MiB/s baseline are
   ample: the AWS lab peaked below 1 MB/s at 100/sec) and follow 6.1 or 6.2.

   ```bash
   aws ec2 create-volume --availability-zone ap-southeast-2b --size 8 --volume-type gp3 --encrypted \
     --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=bower-queue}]'
   aws ec2 attach-volume --volume-id vol-XXXX --instance-id i-XXXX --device /dev/sdf
   ```

2. Publish disk metrics with the CloudWatch agent (`/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json`):

   ```json
   {"metrics": {"append_dimensions": {"InstanceId": "${aws:InstanceId}"},
     "metrics_collected": {"disk": {"measurement": ["used_percent", "inodes_free"],
       "resources": ["/var/lib/bower"], "metrics_collection_interval": 60}}}}
   ```

   On Windows use `"LogicalDisk": {"measurement": ["% Free Space"], "resources": ["*"]}`.

3. Alarm before Bower's own warning so both layers fire in order:

   ```bash
   aws cloudwatch put-metric-alarm --alarm-name bower-queue-disk --namespace CWAgent \
     --metric-name disk_used_percent --dimensions Name=InstanceId,Value=i-XXXX Name=path,Value=/var/lib/bower \
       Name=device,Value=nvme1n1 Name=fstype,Value=xfs \
     --statistic Maximum --period 300 --evaluation-periods 1 --threshold 80 \
     --comparison-operator GreaterThanOrEqualToThreshold --alarm-actions arn:aws:sns:REGION:ACCOUNT:TOPIC
   ```

4. Grow online: `aws ec2 modify-volume --size N`, then `sudo xfs_growfs /var/lib/bower`
   (Linux) or `Resize-Partition` (Windows). Raise `BOWER_QUEUE_MAX_BYTES` afterwards.

### 6.6 Azure VMs

1. Attach a managed disk (Premium SSD v2 or Standard SSD; size `V`) and follow 6.1 or 6.2.

   ```bash
   az vm disk attach -g RG --vm-name VM --name bower-queue --new --size-gb 8 --sku StandardSSD_LRS
   ```

2. Collect disk metrics with the Azure Monitor Agent (data collection rule with
   performance counters `\LogicalDisk(*)\% Free Space` on Windows,
   `Logical Disk(*)\% Free Space` on Linux) or VM insights, then alert:

   ```bash
   az monitor scheduled-query create -g RG -n bower-queue-disk --scopes WORKSPACE_ID \
     --condition "count 'Disk' > 0" --condition-query Disk="InsightsMetrics | where Namespace == 'LogicalDisk' and Name == 'FreeSpacePercentage' | where Tags has '/var/lib/bower' | where Val < 20" \
     --evaluation-frequency 5m --window-size 5m --severity 2 --action-groups ACTION_GROUP_ID
   ```

3. Grow: `az disk update --size-gb N` (detach-free for most SKUs), then grow the
   filesystem and raise `BOWER_QUEUE_MAX_BYTES`.

### 6.7 On-premises

Use a dedicated LUN or partition as in 6.1 or 6.2. Monitor it with the platform's
agent at 80% used, and alert on Bower's `storage.state` through the management
heartbeat or `/v1/status`. Thin-provisioned datastores can fill underneath a volume
that still reports free space: monitor the datastore too.

---

## 7. WEC `ForwardedEvents` size and retention

`ForwardedEvents` is the buffer while Bower is not reading: collector stopped, queue
full, or volume critical. WEF keeps delivering into it, and when it is full the
oldest records are overwritten. Bower counts overwritten-before-read records as
`gaps`; those events are lost upstream.

**Measured:** 64 MiB held 30,709 forwarded Security 4625 events (2,185 bytes each with
`ContentFormat=Events`). The Windows default of 20 MiB holds about 9,500: about 16
minutes at 10/sec, under 2 minutes at 100/sec.

| Rate | Bower stall to survive | `ForwardedEvents` maximum size |
| --- | --- | --- |
| 10/sec | 1 hour | 100 MiB |
| 10/sec | 24 hours | 2.2 GiB |
| 100/sec | 1 hour | 1 GiB |
| 100/sec | 6 hours | 5.5 GiB (split across WEC servers instead) |

```powershell
wevtutil sl ForwardedEvents /ms:2361393152 /rt:false    # 2.2 GiB, overwrite oldest
wevtutil gl ForwardedEvents                              # verify maxSize and retention
```

- Keep `/rt:false` (overwrite). `/rt:true` stops the log when full, and WEF then backs
  up on the sources; `/ab:true` archives full logs to files Bower never reads.
- Put the event log on a volume with room for it: `wevtutil sl ForwardedEvents /lfn:D:\Logs\ForwardedEvents.evtx`.
- Size each source's Security log too (the pilot used 1 GiB): with source-initiated
  subscriptions a source keeps unforwarded events in its own log while WEC is unreachable.
- Alert on `windowsEventLog[].gaps` increasing and on `state` = `backpressure` for
  more than a quarter of the stall budget.

---

## 8. Recovery runbook

Never delete or edit `queue.db`, `queue.db-wal` or `queue.db-shm`. Never run `VACUUM`
or SQL against a running queue.

### 8.1 Warning watermark

1. Confirm: `storage.state` = `warning`, log `1501`.
2. Find what grew: `queueDatabaseBytes` vs the volume. If the queue is small, another
   writer is filling the volume (`du -xh --max-depth=2 /var/lib/bower`; on Windows
   `Get-ChildItem -Recurse | Sort-Object Length -Descending | Select-Object -First 20`).
3. Remove or move that writer's files, or grow the volume (6.5, 6.6). Intake continues.

### 8.2 Critical watermark (intake refused)

1. Confirm: `storage.intakePaused` = true, log `1500`, `/health` `degraded`, sources
   show `retries` (syslog) or `backpressure` (WEC).
2. Free space or grow the volume. **Do not restart the collector**: it is not needed,
   and a restart drops syslog frames held in socket buffers.
3. Within one sample (5 seconds) `state` returns to `warning` or `normal` (log `1502`)
   and intake resumes by itself. Expected: syslog `retries` stop increasing, the WEC
   bookmark moves again.
4. Check delivery drains: `queue.queued + retrying + uploading` falls,
   `oldestPendingAgeSeconds` falls.

### 8.3 Queue full (page limit)

1. Confirm: `intake.lastRefusalReason` = `queue-capacity`,
   `queuePages.usedPercent` ≥ 95.
2. Restore the destination and monitor backlog age, settlement errors and free
   disk space. Retention may reclaim acknowledged rows (log `1506`, trigger
   `intake-blocked`) and reopen intake. A full volume, pinned WAL or insufficient
   settlement headroom can prevent progress; use the recovery steps below and
   do not assume a drain deadline without a validated measurement.
3. If the queue is too small for your outages, raise `BOWER_QUEUE_MAX_BYTES` (and the
   volume) at the next maintenance window. That needs a restart; see 8.5 for syslog.

### 8.4 Collectors from before this change stuck with a full backlog

Symptom: destination reachable, `oldestUndelivered` growing, nothing delivered, log
`1002` with `SqliteException`. Upgrade the collector (the upgrade restart drains it;
the AWS Windows collector drained 22,516 events within a minute). If you cannot
upgrade, raise `BOWER_QUEUE_MAX_BYTES` by at least 50% and restart (the AWS Linux
collector drained 27,374 events in 10 seconds). Read 8.5 first.

### 8.5 Restarting while a syslog sender is backpressured

Plain syslog has no application acknowledgement. While Bower holds a frame the kernel
keeps accepting the sender's bytes into socket buffers (megabytes with Linux
autotuning); a restart resets the connection and those frames are gone, although the
sender believes it sent them. **On AWS a restart in this state lost 21,494 frames.**

1. Avoid the restart (8.2, 8.3 do not need one).
2. If you must restart, first stop the sender from sending new data **and** wait for
   Bower to read what is buffered, which only happens if the queue has room. If it has
   none, the buffered frames will be lost: record the sender's sequence or counters
   before and after, and replay from the sender's source if it can.

### 8.6 Restart on a full volume

The candidate retries settlement every 5 seconds; a full-volume restart and recovery
have not yet been qualified for the final binaries. Free space, then verify service
health, delivery and intake; restart only if needed after considering the syslog
loss window in 8.5. On Linux, `RequiresMountsFor` keeps it from starting if the volume is
missing. On Windows, if the volume behind the mounted folder is missing the folder is
just an empty directory on `C:` and the collector would start a new, empty queue
there: check that `storage.totalBytes` is the dedicated volume after every reboot and
keep the original disk attached until you have.

### 8.7 WEC gaps

`gaps` increased: events were overwritten in `ForwardedEvents` before Bower read them.
They are lost to Bower. Re-forward from the sources' Security logs if they still hold
them (create a temporary subscription with `ReadExistingEvents=true` scoped to the
affected period), then enlarge `ForwardedEvents` (section 7).

### 8.8 Testing the procedure (filler)

On a test collector, with the destination blocked by a host firewall rule scoped to
the service, create a bounded filler on the queue volume and remove it afterwards:

```bash
sudo fallocate -l 700M /var/lib/bower/filler && sleep 15 &&
  curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4319/v1/status | jq '.storage.state'
sudo rm /var/lib/bower/filler
```

```powershell
fsutil file createnew C:\ProgramData\Bower\state\filler 734003200; Start-Sleep 15
Remove-Item C:\ProgramData\Bower\state\filler
```

---

## 9. Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `storage.state` = `unknown`, log `1503` | The queue directory's volume cannot be measured (permissions, unusual filesystem) | Check the service can stat the directory; watermarks are off until it can |
| `totalBytes` is the root or `C:` volume | Queue not on the dedicated volume (mount missing, Windows path not mounted) | Fix the mount; on Linux confirm `RequiresMountsFor` |
| Refusals with `queuePages.usedPercent` near 100 and low `storage.queueUtilisationPercent` | Normal: pages bind before the logical cap | Size by section 3 |
| `pressurePurgedEvents` keeps growing | Retention or the queue is too small for the rate | Raise `BOWER_QUEUE_MAX_BYTES` or lower `BOWER_QUEUE_RETENTION_HOURS` |
| Destination up, nothing delivered, log `1002` repeating | Old collector stuck at the page ceiling | 8.4 |
| `queueWalBytes` large for a long time | A reader pins the WAL (backup tool, `sqlite3` shell, probe) | Close the reader; the next write truncates the WAL |
| Syslog sender shows sent, Bower missing frames after a restart | Socket buffer loss (8.5) | Avoid restarts while backpressured; qualify sender replay |
| WEC `gaps` > 0 | `ForwardedEvents` wrapped during a stall | 8.7, section 7 |
| Service does not start after a volume change | Mount missing or ACL wrong | `systemctl status bower`, `findmnt`; Windows: the state folder ACL |
| `BOWER_QUEUE_MAX_BYTES` lowered and start fails with capacity | Database already larger than the new ceiling | Restore the previous value; queues cannot shrink without migration |

---

## 10. How we tested this

Two AWS runs, both preserved. The [first run](../evidence/ws3-20261031-081023/README.md)
found the drain deadlock, the WAL over budget, intake stuck after a drain and the syslog
restart loss, and tested the fixes in place. The
[final run](../evidence/ws3b-20261102-005001/README.md) used one CI build (`261f61a`,
unsigned) on a 1 GiB Linux volume and a 2 GiB Windows volume mounted at the MSI state
folder, with sequence-numbered input reconciled in Sentinel by a separate verifier:

| Scenario | Linux syslog | Windows WEC |
| --- | --- | --- |
| ws6 stall, retained acknowledgements fill the page limit (16 MiB cap, 60-min floor) | Intake reopened 50 s after the first refusal; no restart | Reopened 42 s after |
| ws6 stall, backlog fills the page limit, destination restored | Delivery resumed 6 s after restore, intake 46 s | 15 s and 72 s |
| Watermarks: warning, critical, space freed | Intake resumed 6 s after freeing | 1 s |
| Volume completely full, destination restored while full, restart while full | Answering 6 s after restart; intake 6 s after freeing | At once; 6 s |
| Accepted events in Sentinel | **83,725 of 83,725**, 0 duplicates | **74,415 of 74,415**, 1,008 duplicate rows |
| Lost before acceptance | **7,109** frames in socket buffers at the restart while full | 0 (bookmark) |

Health records written while intake was refused arrived after restore with
`storage-critical`, `intakePaused` and `backpressure`, and the `queue-storage` alert
fired for both collectors. Payloads averaged 1,208 and 1,369 bytes; `ForwardedEvents`
at 64 MiB held 30,705 forwarded events. Not run within the time box: a
`ForwardedEvents` wrap loss, RELP under the watermark live, UDP and long soaks.

Unit and integration tests (`StoragePressureTests`, plus additions to
`SyslogCollectorTests`, `WindowsEventLogCollectorTests` and
`HeartbeatV2CollectorTests`) cover watermark thresholds and hysteresis, sampling
bounds, configuration validation and hashes, refusal without commit and with exact
replay still answered as duplicate, settlement during critical, pressure and
intake-blocked retention, the drain-deadlock regression, WAL self-healing, page-limit
refusal with crash/recovery, restart while critical, syslog frames held without
dropping or closing the connection, WEC bookmarks held, status, health and heartbeat
fields.

---

## Known limits

- **Plain TCP and TLS syslog: socket-buffer loss on restart or reset while
  backpressured** (measured above). These transports have no application
  acknowledgement, so frames the kernel accepted but Bower had not queued are lost;
  qualify each sender's retention and replay. RELP (from #168) is different: Bower
  acknowledges a message only after it is durably queued, withholds the acknowledgement
  while intake is refused, and closes the session after 30 seconds of refusals
  (`relpBusyCloses`); the sender keeps and resends every unacknowledged message, so
  nothing is lost but resends can arrive as duplicates. RELP under the watermark is
  unit-tested only. UDP is best effort.
- **Real disk-full** is qualified on AWS volumes (xfs and NTFS filled to 20 KB and 0
  bytes free, with a restart while full); unit tests cover the page-limit and
  restart-while-critical paths but cannot produce ENOSPC portably.
- **Existing queue files** created without SQLite incremental auto-vacuum do not
  return freed pages to the filesystem through the new incremental-vacuum path.
  Freed pages can be reused inside the database, but that does not recover volume
  free space. An offline `VACUUM` (as in the
  [rollback procedure](04-upgrade-backup-recovery.md#rollback-after-settlement-growth))
  returns it but does not switch the file to incremental auto-vacuum; use additional disk
  capacity until a migration is qualified.
- **Rust collector:** the intake limit and settlement ceiling are ported (tests open a
  queue grown past the intake ceiling, refuse intake at the limit while a backlog still
  leases and acknowledges, and refuse a file past the settlement ceiling). Watermarks,
  pressure retention, the large-event reclaim, incremental vacuum and the `storage`
  status are **not** ported: Rust has no free-space watermark, and only
  age retention frees pages. A C# to Rust switch with a grown queue was not run live.
  **A Rust collector refuses new events about 15% earlier in practice:** it stops at the
  same 85% intake limit, but without pressure retention the acknowledged rows kept for
  duplicate detection (`BOWER_QUEUE_RETENTION_HOURS`) hold that room until the hourly
  age purge removes them. Size Rust queues for the backlog plus the retained
  acknowledgements, or lower the retention.
- **Rollback to builds without the settlement ceiling** (C# before this change, Rust
  before the port): they refuse to open a database larger than `M + 4 MiB`. Follow the
  [downgrade procedure](04-upgrade-backup-recovery.md#rollback-after-settlement-growth)
  (drain, purge, `VACUUM`) before rolling back. Raising `BOWER_QUEUE_MAX_BYTES` on the
  older build is not a qualified recovery and changes the storage budget.
- **Management** accepts the heartbeat `storage` object but does not store or display
  it yet (workstream 6).
- Free space is sampled once a second on the insert path and every 5 seconds by the
  monitor; a writer that fills the volume faster than that can still cause
  `storage-full` refusals (handled as backpressure).
- **Large events below the pressure trigger:** a large event can need more pages than
  remain below the intake limit, so it is refused well below 80%. The refusal now
  triggers retention, which removes only as many of the oldest acknowledged rows as the
  event needs (at any age, in batches of 50), so the rest keep detecting duplicates;
  unacknowledged rows are never touched. An
  event larger than the whole intake limit is refused permanently. Not for archived
  queues (next item): there the source retries until age retention or the 80%/95%
  triggers free enough pages. Unit-tested only.
- **Archive-backed retention:** retention now deletes only the sequence set whose
  archive segments it re-hashed, and rechecks acknowledgement and cutoff in the write
  transaction. Interleaved purge and corrupted-segment regressions cover the previously
  shifted-batch failure. Segment verification and queue commit are separate operations:
  a segment can be changed or replaced after its hash is checked but before its local
  row is deleted. The archive writer lock coordinates cooperating writers; it does not
  prevent an external writer or storage mutation. Protect the archive directory against
  concurrent modification. Refusal-triggered reclamation remains blocked for archived
  queues until an immutable or version-retained archive guarantees the verified copy
  survives the queue commit, and adversarial mutation and crash recovery are tested.
  Until then retain and retry the source event where the source supports it, and restore
  capacity without deleting recent acknowledgements or unverified rows. UDP can drop
  events under backpressure.
- Pressure and intake-blocked retention shorten duplicate detection. Replays of
  events whose acknowledged rows were removed are accepted again and duplicated at
  the destination. Production queries should deduplicate by `CollectorId, EventId`
  as in the [pilot guide](../../lab/aws/PILOT.md).
- The settlement ceiling raises the worst-case database size from `M + 4 MiB` to
  `1.75 × (M + 4 MiB)`; volumes sized for the old figure may reach the critical
  watermark while a large backlog is acknowledged (intake pauses; nothing is lost).
- Power loss, filesystem corruption and backup/restore are not covered here.
