# Upgrades, backup and recovery with existing data

This guide covers how to upgrade, back up, restore and recover a Bower collector that
already holds data, for every supported environment: queued and in-flight events,
delivered rows kept for deduplication, Windows Event Log bookmarks, configuration, keys
and trusted packs. It is the operator procedure for production-readiness gap 4. Each
procedure lists its purpose, prerequisites, exact commands, expected output, checks,
pass/fail criteria, rollback steps and known limits.

The procedures were run on real hosts. Upgrades used RPM, MSI and Docker. Faults were
SIGKILL, `taskkill /F` and forced EC2 stop/start. The run also covered online backup,
restore onto fresh hosts, and downgrades. Every accepted event was reconciled against
Microsoft Sentinel. See [How we tested this](#how-we-tested-this). Kubernetes and Azure
VM procedures follow the same rules but were **not** run live.

Packages are currently **unsigned**; release signing is a separate, deferred gate. Bower
still verifies signed packs against the trusted keys you configure.

## Summary: what is safe today

| Operation | Supported? | Data guarantee | Evidence |
| --- | --- | --- | --- |
| In-place upgrade, RPM/DEB (`dnf upgrade`, `apt install`) | Yes | Queue, leases, delivered rows, `bower.env`, TLS, packs, keys and permissions kept | 264 → 270 → 277 under load with a blocked destination |
| In-place upgrade, MSI (major upgrade) | Yes, **once settings are in `bower.env`** | Same; without `bower.env`, older MSIs drop hand-edited service settings | 264 → 270 dropped 12 settings; 270 → 277 with `bower.env` kept them |
| Docker image swap on the same volume | Yes; the collector id persists in the volume | Same | 264 → 277 under load |
| Kubernetes image change | Yes, `Recreate` with one replica | Same | Not run live |
| Process crash (SIGKILL / `taskkill /F`) | Yes | No accepted event lost; healthy in about 6 s | Both platforms |
| Host power loss / forced stop | Yes | Pending backlog kept on disk | Both platforms |
| Online backup (`bower queue backup`) | Yes | Point-in-time copy of queue, ledger, cursors and suppression state | 0.5–0.7 s for 20–33 MB |
| Restore onto a new host (`bower queue restore`) | Yes | Every row in the backup is kept. Rows pending at backup time are delivered again. | Linux and WEC |
| Downgrade inside the same queue schema (5) | Works, but test first | See [downgrades](#supported-versions-downgrades-and-limits) | RPM 277 → 264 |
| Old binary on a newer queue schema | Refused, nothing changed (this release on) | Fails closed with `UnsupportedQueueSchemaException` | Real binaries, two shapes of future schema |

## What Bower keeps on disk

Upgrades must keep all of this, and backups have to cover it. "In queue backup" means
`bower queue backup` captures it. Everything else needs its own backup or comes from
your configuration management or secret store.

| Item | Linux (RPM/DEB) | Windows (MSI) | Docker / Kubernetes | In queue backup | Secret |
| --- | --- | --- | --- | --- | --- |
| Queue, retained delivered rows, ledger (`queue_events_v5`, `queue_ledger*`) | `/var/lib/bower/queue.db` plus `-wal` and `-shm` | `%ProgramData%\Bower\state\queue.db` | `/var/lib/bower/queue.db` (volume/PVC) | Yes | No; payloads are already redacted |
| Source cursors, including Windows Event Log bookmarks (`source_cursors`) | Same database | Same database | Same database | Yes | No |
| Suppression windows, source activity (`suppression_windows`, `source_*`) | Same database | Same database | Same database | Yes | No |
| Settings | `/etc/bower/bower.env` (root:bower 0640) plus the unit's `Environment=` | `%ProgramData%\Bower\bower.env` (`BOWER_SETTINGS_FILE`) plus MSI properties | Environment / ConfigMap | No | Holds paths, not secrets; keep `AZURE_CLIENT_SECRET` out of it |
| Syslog / Windows Event Log source config | `BOWER_SYSLOG_CONFIG` file | `BOWER_WINDOWS_EVENTLOG_CONFIG` file | Mounted file | No | No |
| Signed packs and trusted public keys | `/etc/bower/packs`, `/etc/bower/keys` | `%ProgramData%\Bower\packs`, `keys` | Image or mounted files | No | No |
| Policies | `/etc/bower/policies` (`config|noreplace`) | `%ProgramData%\Bower\policies` (**MSI-managed: replaced on upgrade**) | Image | No | No |
| Privacy HMAC key (`BOWER_PRIVACY_HMAC_KEY_FILE`) | `/etc/bower/secrets/` | `%ProgramData%\Bower\secrets\` | Secret | **No** | **Yes**; the same key is needed to keep pseudonyms stable |
| Ingest token, Azure client certificate, TLS private keys | `/etc/bower/secrets`, TLS directory | `secrets` | Secret | **No** | **Yes** |
| Management credential (`management-credential/credential.json`) | Next to `queue.db` | `state\management-credential` | Next to `queue.db` | **No** | **Yes**; key-bound. Re-enrol on a new host. |
| Collector identity (`BOWER_COLLECTOR_ID`, else `collector-id` beside `queue.db`) | `bower.env`, else `/var/lib/bower/collector-id` | MSI `COLLECTORID` (remembered) | Environment, else `collector-id` in the volume/PVC | `collector-id` is not; record the id with `--collector-id` | No |
| Archive segments (`BOWER_ARCHIVE_PATH`), AMA spool | Configured paths | Configured paths | Volumes | No | No |

The collector never stores the HMAC key, token or Azure credentials in the queue, so a
queue backup holds no secrets. It still holds **redacted security telemetry**:
pseudonymised usernames, source IPs, event metadata. Treat it as sensitive and encrypt it
at rest (see [Backup handling](#backup-handling-and-encryption)).

## Compatibility rules

- **Queue schema.** Version 5 is current; the queue records it in `schema_history`. A build
  opens only the schema it writes. From this release, a newer schema is refused **before any
  change**. Expected log line:
  `Bower collector failed: UnsupportedQueueSchemaException: Queue schema version 6 is newer than this Bower build supports (5). The database was not modified.`
  Older builds (dev.264/270) did not check first, and on some future layouts they wrote
  tables into the newer database before failing. Never run a pre-check build against a
  queue that a newer release has opened. Upgrades from schema 1–4 to 5 are automatic, but
  you need a backup first; see [Queue durability](../operations/queue-v5-durability.md).
- **Windows Event Log bookmarks.** v2 stores a native receiving-log position. v1 (builds
  before #157) stored the event's own EventRecordID. Starting a v2 build on a v1 bookmark
  re-reads the whole channel once, and the queue deduplicates every event it still retains.
  A v1 build refuses a v2 bookmark (`winevt-bookmark-invalid`) and changes nothing. In the
  tested WEC configuration, builds before #157 could not read `ForwardedEvents` at all
  (`winevt-read-failed`: forwarded records have no `RecordId`), so v1 bookmarks are
  expected only for local channels such as `Security`.
- **Collector id.** When `BOWER_COLLECTOR_ID` is unset, the first start writes the machine
  name it would have used to `collector-id` beside the queue database, and later starts
  reuse it (C# and Rust read the same file). Existing installs therefore keep their current
  id, and containers or pods keep theirs after a recreate as long as the volume persists. A
  configured `BOWER_COLLECTOR_ID` always wins and never rewrites the file. An invalid
  `collector-id` stops startup instead of being replaced. The startup log records the id
  and its source (`Configured`, `Persisted` or `Created`).
- **Event identity.** Fingerprints include the collector id. A Windows event id
  combines channel, origin computer, origin record id and creation time, and does not depend
  on the WEC host or Bower subscription id. A syslog id combines listener id, sender address
  and the exact frame. Keep the collector id, listener ids and the HMAC key stable across
  upgrades and restores, or replays are no longer recognised as duplicates.
- **Deduplication window.** The queue deduplicates a replayed event only while its delivered
  row is retained (`BOWER_QUEUE_RETENTION_HOURS`, default 168). After that, a replay is a new
  delivery. The destination must deduplicate by `CollectorId, EventId`; see
  [Destination-side deduplication](#destination-side-deduplication).

## Pre-upgrade checklist (all environments)

Work through each step and record the result.

1. **Read the release notes** for queue schema, bookmark version, settings and package
   changes. Confirm the target is newer than the installed version (see the
   [MSI version limit](#supported-versions-downgrades-and-limits)).
2. **Record the artifact hash** and compare it with the release manifest. Packages are
   unsigned today; the hash is your integrity check.

   ```bash
   sha256sum bower-collector-0.1.0~dev.277-1.x86_64.rpm
   ```

   ```powershell
   (Get-FileHash .\bower-collector-0.1.0-dev.277-x64.msi -Algorithm SHA256).Hash
   ```

3. **Capture a metadata baseline** (health, queue counts, bookmarks, configuration hashes),
   so you can compare after the upgrade:

   ```bash
   sudo systemctl is-active bower; rpm -q bower-collector || dpkg -s bower-collector | grep Version
   sudo sha256sum /etc/bower/bower.env /etc/bower/packs/* /etc/bower/keys/* /opt/bower/Bower.Collector
   curl -fsS -H "Authorization: Bearer $(sudo cat /etc/bower/secrets/token)" http://127.0.0.1:4319/v1/status \
     | python3 -c 'import json,sys;s=json.load(sys.stdin);print(json.dumps({k:s.get(k) for k in ["status","queue","windowsEventLog","syslog"]},indent=1))'
   ```

   ```powershell
   $root = "$env:ProgramData\Bower"
   Get-Service Bower | Format-List Status, StartType
   (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Bower Collector').DisplayVersion
   Get-FileHash "$root\bower.env", "$root\packs\*", "$root\keys\*", 'C:\Program Files\Bower\Bower.Collector.exe' -Algorithm SHA256
   $token = [IO.File]::ReadAllText("$root\secrets\token").Trim()
   $s = Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers @{ Authorization = "Bearer $token" }
   $s.queue; $s.windowsEventLog | Format-Table id, state, bookmarkRecordId, gaps, resets, readErrors
   ```

   Expected: `status` is `healthy` (or `degraded` with a known cause), `deadLettered` is 0
   or understood, and each Windows subscription is `running` with `readErrors` 0.
4. **Take a backup** with `bower queue backup` (see
   [Back up a live collector](#back-up-a-live-collector)), and snapshot the host or volume
   if your platform supports it. Keep both until the upgrade is verified.
5. **Windows only: move hand-edited service settings into `bower.env`** before your first
   upgrade to a release that has `BOWER_SETTINGS_FILE` (see
   [Windows MSI](#windows-msi-including-wec-hosts)). An MSI upgrade rewrites the service
   `Environment` value every time.
6. **Check capacity.** Free disk should be at least twice the current `queue.db` + `-wal`
   size. An upgrade does not rewrite the queue, but a v1 → v2 bookmark re-read or a backlog
   drain adds work.
7. **Plan the outage window.** A package upgrade stops the service for a few seconds.
   Push sources (syslog, HTTP producers) must retry: anything they send while the listener
   is down is lost unless they buffer and resend. WEF sources buffer on their own.
8. **Never run two writers on one queue** (an old and a new collector, or two pods on one
   PVC).

Pass: every item is recorded, a verified backup exists, and on Windows `bower.env` holds
all operator settings.

## Linux packages (RPM/DEB, systemd)

**Purpose.** Replace binaries in place and keep all state and settings.

**What the package does on upgrade.** `postinstall.sh` treats rpm `2` and deb
`configure <old>` as an upgrade and runs `systemctl try-restart bower`. It leaves
`/etc/bower/bower.env` alone (it copies the example only when the file is missing), and
policies are `config|noreplace`. Users, groups and the directory owners and modes are
kept. `dnf remove` / `apt remove` (not upgrade) deletes `bower.env`, the secrets and the
credential, and keeps the queue.

### Upgrade

```bash
# 1. Baseline and backup (see the checklist).
sudo /usr/bin/bower queue backup --database /var/lib/bower/queue.db \
  --output /var/backups/bower/queue-$(date -u +%Y%m%dT%H%M%SZ).bowerbackup --collector-id "$(sudo sed -n 's/^BOWER_COLLECTOR_ID=//p' /etc/bower/bower.env)"
# 2. Upgrade in place (RHEL/Rocky/Amazon Linux):
sudo dnf upgrade -y ./bower-collector-0.1.0~dev.277-1.x86_64.rpm
#    Debian/Ubuntu:
sudo apt-get install -y ./bower-collector_0.1.0~dev.277-1_amd64.deb
# 3. Confirm the restart and health.
systemctl is-active bower && curl -fsS http://127.0.0.1:4319/health
```

Expected output: dnf/apt reports the new version, `active`, and
`{"status":"healthy"}` within a few seconds. In the lab the package step took 3.7–5.2 s,
and the collector answered `/health` 0.02 s after the package completed.

### Verify (pass/fail)

```bash
rpm -q bower-collector               # new version
sudo rpm -V bower-collector          # no output: no packaged file differs (bower.env is not packaged)
systemctl show bower --property=User,MainPID,NRestarts
sudo stat -c '%U:%G %a %n' /etc/bower /etc/bower/secrets /etc/bower/bower.env /var/lib/bower /var/lib/bower/queue.db
sudo sha256sum /etc/bower/bower.env /etc/bower/packs/* /etc/bower/keys/*   # equal to the baseline
curl -fsS -H "Authorization: Bearer $(sudo cat /etc/bower/secrets/token)" http://127.0.0.1:4319/v1/status \
  | python3 -c 'import json,sys;s=json.load(sys.stdin);print(s["status"], s["queue"], s.get("packs"))'
```

Pass:

- The service is active as `bower`, with a new PID.
- Owners and modes are `root:root 755 /etc/bower`, `root:bower 750 secrets`,
  `root:bower 640 bower.env`, `bower:bower 700 /var/lib/bower` and
  `bower:bower 600 queue.db`.
- Configuration, pack and key hashes match the baseline.
- `delivered` has not fallen, and `queued + uploading + retrying` accounts for every event
  pending before the upgrade.
- Leases held at stop time return as `retrying` once they expire.
- Syslog `connectionsAccepted` rises as senders reconnect.

Fail: the service is not active, a hash changed, the delivered count fell, or there are
new dead letters.

### Rollback

Same queue schema (check the release notes): reinstall the previous package with
`sudo dnf downgrade -y ./bower-collector-<previous>.rpm` (or `apt-get install --allow-downgrades`).
In the lab, 277 → 264 took 3.4 s and continued from the same queue. If the new release
changed the queue schema, the old build refuses to start (from this release on). Then
stop the service and move `/var/lib/bower/queue.db*` aside (do not delete it). Restore the
pre-upgrade backup with `bower queue restore`, install the old package, and accept that
events accepted after the backup must come again from their sources.

### Troubleshooting

| Symptom | Cause | Action |
| --- | --- | --- |
| `UnauthorizedAccessException: Access to the path '/etc/bower/...'` | A directory created with a restrictive umask | `chmod 0755` the directory, or `chown root:bower` with `0750` |
| `Unsupported queue schema version.` / `UnsupportedQueueSchemaException` | Older binary than the queue | Install the newer release, or restore a backup made by this version |
| Service active, but syslog `connectionsAccepted` stays flat | Sender not reconnecting | Restart or repair the sender. Bower cannot recover frames a sender never resends. |
| `rpm -V` lists files | Packaged files edited by hand | Reinstall the package; keep local changes in `bower.env` |

## Windows MSI, including WEC hosts

**Purpose.** Major upgrade of the MSI without losing settings, the service identity, ACLs,
the queue or bookmarks.

**What the MSI does.** `MajorUpgrade` removes the old product and installs the new one. The
service account stays `NT SERVICE\Bower`, with a deterministic service SID. The data-folder
ACLs are set again with the same SDDL (the lab hashes were identical before and after
every upgrade). The queue, credential, `secrets`, `keys` and `packs` folders are kept.
Two things are **replaced on every install, repair and upgrade**:

- the service `Environment` registry value
  (`HKLM\SYSTEM\CurrentControlSet\Services\Bower`), and
- the MSI-managed policy files in `%ProgramData%\Bower\policies`.

Only the MSI properties `COLLECTORID`, `BOWERENVIRONMENT`, `MANAGEMENTENDPOINT`, `PACKS`,
`PACKTRUSTEDKEYS` and `COMMANDTRUSTEDKEYS` are remembered across upgrades. Everything
else, such as output, Azure identity, HMAC key file and Windows Event Log config, belongs
in `%ProgramData%\Bower\bower.env`. The service environment points at that file with
`BOWER_SETTINGS_FILE`.

`bower.env` format:

- One `KEY=VALUE` per line; only `BOWER_*` and `AZURE_*` names are accepted.
- Lines starting with `#` or `;` are comments, and blank lines are allowed.
- A value may be wrapped in one matching pair of single (`'…'`) or double (`"…"`) quotes,
  which are removed.
- There are **no escapes, variable expansion or line continuations**, so Windows paths need
  no doubling. This is simpler than systemd `EnvironmentFile=`; do not rely on its
  escaping rules.
- File values override the service environment.
- Errors give the line number, never the value. Startup stops on a repeated key, an
  unterminated quote, any other bad line, or a file over 64 KiB.

The file can change trust anchors (`BOWER_PACK_TRUSTED_KEYS`,
`BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS`), paths and outputs. The collector therefore refuses
it unless only trusted principals can change it:

- **Windows:** the file and its folder must be owned by SYSTEM, Administrators or
  TrustedInstaller. Only those principals may hold write, delete, change-permission or
  take-ownership rights; the service account gets read only. The MSI sets that protected ACL
  on `%ProgramData%\Bower`, and a file created there inherits it. Elevated administrators on
  Windows 10/11 own the files they create, so set the owner explicitly:
  `icacls "%ProgramData%\Bower\bower.env" /setowner *S-1-5-32-544`.
- **Linux:** the file and its folder must be owned by root or the collector's account,
  must not be group- or world-writable, and the file must not be a symbolic link.
- **macOS:** the same mode and link checks, without the owner check.

Startup and logging:

- A missing file is **not** an error, because fresh MSI installs set the path before any
  file exists. Startup does fail if a `bower.env.txt` sibling exists (an editor added
  `.txt`), or if the file exists but cannot be read, for example because the service cannot
  traverse its folder.
- The startup log records `Settings file <path>: Applied|NotPresent|NotConfigured,
  <n> setting(s) applied.`, metadata only.

Uninstall (not upgrade) deletes the file.

> Measured: upgrading dev.264 → dev.270 with settings in the registry **dropped 12 settings**
> (output, Azure identity, HMAC key file, Windows Event Log config, lease and timeout). The
> collector then ran healthy with **no source and no output** until the settings were put
> back. Upgrading 270 → 277 with `bower.env` kept everything; the WEC subscription continued
> from its bookmark with 0 gaps.

### One-time migration: registry settings to `bower.env`

Do this **before** upgrading from a release without `BOWER_SETTINGS_FILE` (dev.270 and
older). The script copies every non-MSI setting out of the current service environment.
It writes names and paths, never secret values; keep secrets in files referenced by
`*_FILE` settings.

```powershell
#Requires -RunAsAdministrator
$root = "$env:ProgramData\Bower"
$msiOwned = 'BOWER_LISTEN_URL','BOWER_QUEUE_PATH','BOWER_POLICY_DIRECTORY','BOWER_AMA_SPOOL_PATH','BOWER_COLLECTOR_ID',
  'BOWER_ENVIRONMENT','BOWER_MANAGEMENT_ENDPOINT','BOWER_MANAGEMENT_AUTH','BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE',
  'BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE','BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS','BOWER_SETTINGS_FILE'
$current = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment
$lines = $current | Where-Object { $msiOwned -notcontains ($_ -split '=', 2)[0] -and ($_ -split '=', 2)[1] }
if ($lines -match '^(BOWER_INGEST_TOKEN|AZURE_CLIENT_SECRET)=') { throw 'Move inline secrets to files first' }
Set-Content -LiteralPath "$root\bower.env" -Value (@('# Operator settings kept across upgrades') + $lines) -Encoding ASCII
icacls "$root\bower.env" /setowner '*S-1-5-32-544' | Out-Null        # owner must be SYSTEM or Administrators
Get-Content "$root\bower.env" | ForEach-Object { ($_ -split '=', 2)[0] }   # names only
```

Expected output: the setting names, such as `BOWER_OUTPUT`, `BOWER_DCE_ENDPOINT`,
`BOWER_WINDOWS_EVENTLOG_CONFIG` and `BOWER_PRIVACY_HMAC_KEY_FILE`. With a `PACKS` MSI
property, `BOWER_PACKS` comes from the MSI. If you set it by hand, keep it in `bower.env`.

### Upgrade (interactive or scripted)

```powershell
#Requires -RunAsAdministrator
$msi = 'C:\Install\bower-collector-0.1.0-dev.277-x64.msi'
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$msi`" /qn /norestart /l*v C:\Install\bower-upgrade.log"
$p.ExitCode        # 0, or 3010 if a reboot is pending for another reason
Get-Service Bower | Format-List Status, StartType
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower').Environment -match '^BOWER_SETTINGS_FILE='
```

Expected: exit code `0`, the service `Running`, and
`BOWER_SETTINGS_FILE=C:\ProgramData\Bower\bower.env`. In the lab the MSI step took
4.1–5.3 s, and `/health` answered 0.03 s after msiexec returned. You do not need to pass
`COLLECTORID` again; the MSI remembers it.

Note for Windows PowerShell 5.1 scripts: with `$ErrorActionPreference = 'Stop'`, any
stderr text from a native command (for example the notice that `bower queue restore`
prints) raises `NativeCommandError` even when the command succeeded. Check `$LASTEXITCODE`
instead, or set `$ErrorActionPreference = 'Continue'` around the call.

### WEC hosts: verify the subscription carried on

```powershell
$s = Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers @{ Authorization = "Bearer $token" }
$s.windowsEventLog | Format-Table id, channel, state, bookmarkRecordId, eventsRead, duplicates, gaps, resets, readErrors
(Get-WinEvent -ListLog ForwardedEvents).RecordCount
wecutil.exe gr <YourSubscription>     # RunTimeStatus: Active, LastError: 0 for each source
```

Pass:

- Every subscription is `running`.
- `bookmarkRecordId` is at or above its pre-upgrade value and keeps rising while
  `ForwardedEvents` grows.
- `gaps` and `resets` are 0. One reset is expected only for a v1 bookmark or a log that
  was cleared.
- `eventsRead` after the upgrade covers only the new records, not the whole log.
- `queue.delivered` has not fallen.
- `Get-Acl` on `state`, `secrets`, `keys` and `packs` shows only SYSTEM, Administrators and
  `NT SERVICE\Bower`.

Fail: `windowsEventLog` is empty or `null` (the settings were lost; check `bower.env` and
`BOWER_SETTINGS_FILE`), `winevt-bookmark-invalid`, or the bookmark is not moving.

WEC note: during the service restart, WEF keeps writing to `ForwardedEvents`, and Bower
catches up from the bookmark. The lab caught up 816 events buffered during a forced
power-off with no gap.

### Group Policy, ConfigMgr (SCCM) and Intune silent upgrades

- Ship `bower.env` (no secrets) **before** the MSI, as a separate configuration item: a
  Group Policy Preferences file item, a ConfigMgr configuration item, or an Intune
  remediation script. That covers the first upgrade from a pre-`BOWER_SETTINGS_FILE`
  release too.
- Upgrade command line: `msiexec /i bower-collector-<version>-x64.msi /qn /norestart /l*v %TEMP%\bower.log`.
  No properties are needed; the remembered ones apply. Never pass tokens as properties.
- Detection: the MSI product code of the new version, plus
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ProductCode}\DisplayVersion`.
  Add a compliance check that the `Bower` service is `Running` and
  `/v1/status` reports `running` subscriptions.
- Treat exit code `1603` as a failure and collect the msiexec log. `3010` means a reboot is
  required but not forced; Bower itself needs no reboot.
- Stagger WEC upgrades. WEF buffers on the sources, but upgrading every WEC at once
  stalls all forwarding.

### Rollback

**The MSI does not reliably stop downgrades today.** MSI compares only the first three
version fields, and every development build is `0.1.0.N`. With
`AllowSameVersionUpgrades`, installing an older dev MSI over a newer one succeeds; the lab
showed 277 → 264 succeeding. A rollback to a release **without** `BOWER_SETTINGS_FILE`
also loses the settings file wiring.

1. Back up the queue (`bower queue backup`), and check that the target release uses the
   same queue schema and bookmark version (see the
   [compatibility table](#supported-versions-downgrades-and-limits)).
2. Install the previous MSI: `msiexec /i <previous>.msi /qn /norestart`.
3. If that release predates `BOWER_SETTINGS_FILE`, copy the `bower.env` lines back into the
   service `Environment` value, then `Restart-Service Bower`.
4. Verify as above. A pre-#157 build refuses v2 bookmarks (`winevt-bookmark-invalid`), and
   cannot read `ForwardedEvents` at all; never roll a WEC back that far.

### Troubleshooting

| Symptom | Cause | Action |
| --- | --- | --- |
| After the upgrade, `windowsEventLog` is null and nothing is delivered | Settings were in the registry and the MSI rewrote them | Create `bower.env` (above) and restart the service |
| `BOWER_SETTINGS_FILE line N is not a BOWER_* or AZURE_* KEY=VALUE setting` | Typo, or another variable in the file | Fix line N; only `BOWER_*` / `AZURE_*` names are allowed |
| `winevt-bookmark-invalid` | Bookmark from a newer format, or another channel | Upgrade to the release that wrote it; never edit the cursor |
| `winevt-read-failed` on `ForwardedEvents` | Pre-#157 build, or no read access for `NT SERVICE\Bower` | Upgrade; grant `(A;;0x1;;;<service SID>)` on the channel |
| Edited policy files reverted | MSI-managed files | Use signed packs or a separate policy directory set in `bower.env` |

## Docker and Compose

**Purpose.** Change the image and keep the named volume.

**Prerequisites:**

- A stable collector id. Either set a unique `BOWER_COLLECTOR_ID`, or keep the data volume:
  the first start writes the container hostname to `/var/lib/bower/collector-id`, and later
  containers reuse it. A new id breaks replay deduplication and destination identity.
  Before this release the id was the container hostname on every start, so it changed on
  each recreate.
- The queue on a named volume (`bower-data:/var/lib/bower`) owned by uid 1654.
- Secrets mounted read-only and readable by uid 1654.

### Upgrade

```bash
export BOWER_COLLECTOR_ID=edge-syd-01           # optional; otherwise collector-id in the volume is reused
# Back up the live queue from the host (the image has no shell); the CLI only needs the file path.
sudo bower queue backup --database /var/lib/docker/volumes/bower-data/_data/queue.db \
  --output /var/backups/bower/edge-syd-01-$(date -u +%Y%m%dT%H%M%SZ).bowerbackup --collector-id "$BOWER_COLLECTOR_ID"
# Swap the image: compose stops the old container (SIGTERM, grace period) and starts the new one on the same volume.
docker compose -f deploy/docker/compose.yaml pull     # or build
docker compose -f deploy/docker/compose.yaml up -d
docker compose -f deploy/docker/compose.yaml ps
curl -fsS http://127.0.0.1:4319/health
```

Plain `docker run` equivalent, as used in the lab:

```bash
docker stop -t 30 bower && docker rm bower
docker run -d --name bower --read-only --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped \
  --tmpfs /tmp:size=16m --env-file /etc/bower/docker.env -e BOWER_COLLECTOR_ID=edge-syd-01 \
  -v bower-data:/var/lib/bower -v /etc/bower-docker:/etc/bower:ro <registry>/bower-collector:<new-tag>
```

Expected: the new container is `running` as `1654:1654` with the same volume, and `/health`
answers within about a second (0.16 s stop and 0.7 s to healthy in the lab).

### Verify, rollback and troubleshooting

- Verify: `docker inspect -f '{{.Config.Image}} {{.Config.User}} {{range .Mounts}}{{.Name}} {{end}}' bower`
  shows the new image, the same user and the same volume. `/v1/status` shows the same
  `delivered` count and a falling backlog. The collector id in status and at the destination
  is unchanged.
- Rollback: run the previous tag on the same volume, if the queue schema is the same.
  Otherwise restore the backup into a new volume (see
  [Restore](#restore-onto-the-same-or-a-new-host)).
- Never run two containers on one volume. Never `docker compose down -v`, which deletes
  the queue.

| Symptom | Cause | Action |
| --- | --- | --- |
| `Access to the path '/var/lib/bower/...' is denied` | Volume owned by another uid | `chown -R 1654:1654` on the volume path, or create the volume from the image |
| Duplicates at the destination after every recreate | Release before the persisted id, or a new volume each time | Upgrade, keep the volume or set `BOWER_COLLECTOR_ID`; deduplicate past duplicates at query time |
| Senders refused after the swap | Port/network mode changed, or `allowedSenders` does not match NATed addresses | Keep host networking or preserve the client source address |

## Kubernetes

**Not run live.** These steps follow the same rules as Docker.

- **One writer per queue.** Use `replicas: 1` with `strategy: Recreate` (as in
  `deploy/kubernetes/deployment.yaml`) and a `ReadWriteOnce` PVC. `RollingUpdate` starts the
  new pod before the old one stops; with a `ReadWriteOnce` volume, the new pod either cannot
  attach or, on the same node, runs two SQLite writers on one queue. Do not use it.
- **Stable identity.** Pod names change on every rollout. Without `BOWER_COLLECTOR_ID`, the
  first pod writes its name to `collector-id` on the PVC and later pods reuse it. Set
  `BOWER_COLLECTOR_ID` explicitly to choose a meaningful, unique id; never copy one literal id
  into several manifests. For several collectors,
  use a StatefulSet with `volumeClaimTemplates` and derive the id from the stable pod name
  (`metadata.name`, for example `bower-0`). Keep `podManagementPolicy: OrderedReady` and
  `updateStrategy: RollingUpdate`; a StatefulSet replaces each pod after the old one has
  stopped.
- **Upgrade:** `kubectl -n bower set image deployment/bower-collector collector=<registry>/bower-collector:<tag>`,
  then `kubectl -n bower rollout status deployment/bower-collector`.
- **Backup:** run `bower queue backup` in a short-lived Job that mounts the same PVC
  (`readOnly: false`, because SQLite needs the `-shm` file), and write to a second volume.
  A `ReadWriteOnce` volume can only be mounted on the collector's node, so give the Job
  node affinity to the collector pod. The Job only reads the queue.
  Or take a CSI `VolumeSnapshot`. A snapshot is crash-consistent: as good as a power loss,
  which SQLite WAL survives, but it includes the WAL only if the CSI driver captures both
  files atomically from one volume.
- **Verify:** `kubectl logs` shows no `Bower collector failed`, the readiness probe on
  `/health` is ready, and `/v1/status` (through `kubectl port-forward`) shows the same
  `delivered` count.
- **Rollback:** `kubectl rollout undo deployment/bower-collector` when the schema is the
  same. Otherwise restore the backup into a new PVC.

## AWS EC2

- **Upgrade:** use the Linux or Windows package procedure on each instance (SSM Run Command
  works; never put secrets in command parameters).
- **EBS snapshots** are crash-consistent: restoring one is equivalent to the forced
  stop/start the lab survived. For an application-consistent copy, run `bower queue backup`
  first and snapshot the backup file, or stop the service before the snapshot. Encrypt
  snapshots with KMS and tag them with the collector id.
- **AMI-based fleets:** bake binaries, packs, public keys and configuration templates into
  the AMI, **never a queue or a credential**. Replace instances one at a time:
  1. Drain the old instance: stop the sources, wait for `queued + retrying + uploading = 0`.
  2. If you can't drain, back up the queue and restore it on the replacement.
  3. Stop the old instance before the new one starts with the same `BOWER_COLLECTOR_ID`.
  4. Keep the data volume separate (a second EBS volume for `/var/lib/bower`) so it can be
     detached and re-attached to the replacement. That is a restore without the backup gap.
- **Hard stop or reboot:** measured recovery was about 3 minutes of instance boot. The
  backlog was kept, and the service started automatically (Windows MSI service start is not
  delayed).

## Azure VMs and on-premises hosts

- **Upgrade:** use the Linux or Windows package procedure, through Azure Arc / Run Command,
  ConfigMgr or Ansible.
- **Managed disk snapshots and VM backup** are crash-consistent unless they use
  application-consistent pre/post scripts. Run `bower queue backup` in the pre-script, or
  stop the service around the snapshot on Linux.
- **VMSS and image-based fleets:** follow the AMI guidance: no state in images, one
  writer per collector id, and drain or restore before deleting an instance.
- **On-premises VMs:** a hypervisor snapshot taken with the service running is
  crash-consistent and recoverable. Quiesce, or back up with the CLI, for a consistent point.

## Backup and restore

### What a backup is

`bower queue backup` uses the SQLite online backup API. The result is a single,
self-contained database file (journal mode DELETE, no `-wal`) holding a point-in-time copy
of every committed row, including WAL frames not yet checkpointed. Next to it,
`BACKUP.manifest.json` records:

- schema version and database size,
- the SHA-256 of the file,
- row counts per state (queued, uploading, retrying, delivered, dead-lettered),
- the number of source cursors,
- the ledger head sequence and hash, and the ledger and `integrity_check` results,
- the optional collector id;
- `integrityOk` and `ledgerIntact`.

The command never initialises, migrates or repairs the source. It refuses a schema it does
not support, refuses to overwrite an existing file, and refuses an output path that is the
live database or its `-wal`/`-shm`/`-journal` file. It leaves the live collector running.

- **Permissions.** The copy and manifest are created owner-only (0600, or a protected ACL
  for SYSTEM, Administrators and the current user) **before** any page is copied, so an
  interrupted backup never leaves a readable copy. A missing output directory is created
  owner-only (0700 / the same ACL). An existing directory is left as it is.
- **Busy queues.** If the queue stays busy or locked (`SQLITE_BUSY`/`SQLITE_LOCKED`, for
  example during a checkpoint), the copy is retried with backoff for up to 30 seconds.
  After that it gives up with an error and writes nothing.
- **Damaged queues.** If the copy fails the SQLite integrity check or the ledger check,
  **the backup is still written**, with `integrityOk`/`ledgerIntact` set to `false`. That is
  exactly when you need a copy. The command then prints a warning and **exits 3**.
  `bower queue restore` refuses such a backup unless you pass `--allow-damaged`.
Writers keep writing during the copy (WAL readers do not block writers). Run it on a
schedule that matches your recovery point objective.

### Back up a live collector

Linux, Docker host or Kubernetes Job (run as root or the `bower` user):

```bash
sudo install -d -m 0700 /var/backups/bower
sudo /usr/bin/bower queue backup --database /var/lib/bower/queue.db \
  --output /var/backups/bower/linux-edge-01-$(date -u +%Y%m%dT%H%M%SZ).bowerbackup --collector-id linux-edge-01
```

Windows (elevated):

```powershell
$dir = 'D:\BowerBackup'; New-Item -ItemType Directory -Force $dir | Out-Null
icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
& 'C:\Program Files\Bower\bower.exe' queue backup --database "$env:ProgramData\Bower\state\queue.db" `
  --output "$dir\wec-01-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')).bowerbackup" --collector-id wec-01
if ($LASTEXITCODE -ne 0) { throw "backup failed: $LASTEXITCODE" }
```

Expected output: the manifest as JSON, the same as the `.manifest.json` file, for example:

```json
{ "schemaVersion": 5, "databaseBytes": 19628032, "databaseSha256": "…",
  "counts": { "queued": 2178, "uploading": 0, "retrying": 500, "delivered": 4784, "deadLettered": 0, "total": 7462 },
  "sourceCursors": 1, "ledgerSequence": 7462, "ledgerIntact": true, "integrityOk": true, "integrityCheck": "ok",
  "collectorId": "wec-01", "damaged": false }
```

Pass: exit code 0, `damaged` false, a backup file of mode 0600
(Linux) or restricted ACL (Windows), and the manifest present. Measured: 0.5–0.7 s for
20–33 MB under live load.

**Offline alternative (stop–copy–start).** If the CLI is not available, stop the service,
copy `queue.db`, `queue.db-wal` and `queue.db-shm` **together**, then start the service.
Never copy only `queue.db` from a running collector: committed events can still be in the
WAL. Restore such a copy by putting all three files back in place before the first start,
not with `bower queue restore` (which expects a manifest).

### Backup handling and encryption

- A backup contains no secrets (no HMAC key, token, Azure credential, TLS private key or
  management credential). It does contain redacted security telemetry. Store it
  encrypted: S3 with SSE-KMS and a bucket policy denying non-TLS access, Azure Storage with
  customer-managed keys, BitLocker/LUKS volumes, or `age`/`gpg` on the file. Restrict reads
  to the recovery role.
- Keep the manifest with the file; restore verifies the hash before it changes anything.
- Back up configuration (`bower.env`, source configs, packs, public keys) through your
  configuration management. Keep secrets in your secret store (Key Vault, Secrets Manager,
  CyberArk), not with the queue backup.
- Retention: keep at least one backup older than `BOWER_QUEUE_RETENTION_HOURS`. Newer
  backups are better: an old backup re-delivers more events (see below).

### Restore onto the same or a new host

Restore writes a **new** queue file. It refuses to overwrite an existing queue, and refuses
to sit next to an existing `-wal`, `-shm` or `-journal` file, because a stale WAL applied to
the restored database would corrupt it. It checks the hash, schema, integrity, ledger and
counts against the manifest before renaming the copy into place.

Linux (also a Docker volume path):

```bash
sudo systemctl stop bower
sudo install -d -m 0700 /var/lib/bower/pre-restore
sudo mv /var/lib/bower/queue.db* /var/lib/bower/pre-restore/ 2>/dev/null || true   # keep, do not delete
sudo /usr/bin/bower queue restore --backup /var/backups/bower/linux-edge-01-20261031T090022Z.bowerbackup \
  --database /var/lib/bower/queue.db
sudo chown bower:bower /var/lib/bower/queue.db       # restore runs as root; the service runs as bower
sudo systemctl start bower
```

Windows:

```powershell
Stop-Service Bower
$state = "$env:ProgramData\Bower\state"
New-Item -ItemType Directory -Force C:\BowerPreRestore | Out-Null
Get-ChildItem $state -Filter 'queue.db*' | Move-Item -Destination C:\BowerPreRestore
$ErrorActionPreference = 'Continue'   # restore prints a notice on stderr
& 'C:\Program Files\Bower\bower.exe' queue restore --backup D:\BowerBackup\wec-01-20261031T090022Z.bowerbackup `
  --database "$state\queue.db"
if ($LASTEXITCODE -ne 0) { throw "restore failed: $LASTEXITCODE" }
Start-Service Bower
```

The restored file inherits the `state` folder ACL (the service gets Modify). Expected
stderr: `Restored. Unsettled rows will be delivered again (at least once); source cursors
resume from the backup point.` stdout reports:

- `backup`: the backup's own manifest, unchanged, including its `createdAt` and hash;
- `restoredDatabaseSha256` and `restoredDatabaseBytes`: the restored `queue.db` after its
  final WAL header change, at `restoredAt`;
- `restoredDamagedBackup`.

The restored hash differs from the backup hash because the journal mode is set in the file
header. Measured: 0.56 s for 33 MB.

**New host checklist:**

1. Install the same or a newer release.
2. Use the **same** `BOWER_COLLECTOR_ID`; on Windows pass `COLLECTORID=` on the first
   install, because the default is the computer name. Use the same listener ids, the same
   HMAC key file and the same packs and trusted keys. Otherwise replays get new
   fingerprints and pseudonyms change.
3. Re-enrol with management instead of copying `management-credential` (it is key-bound to
   the old host). Retire the old collector's entry in the console.
4. Keep the old host's collector stopped: two collectors with one id must never run
   together.
5. Re-point the sources: DNS for syslog senders, the WEF `SubscriptionManager` policy for
   WEC (see below). Allow-lists (`allowedSenders`) must still match the senders' addresses;
   syslog event ids include the sender address.

### What happens after a restore (replays and deduplication)

A restore rewinds the collector to the backup point. Measured outcomes:

| Situation | Effect | Measured |
| --- | --- | --- |
| Rows pending (queued, leased or retrying) in the backup that the old host delivered later | Delivered again: destination duplicates | Linux 2,009 and WEC 2,678 extra rows, exactly the pending rows in each backup |
| Rows delivered before the backup | Kept as delivered. A replay of the same event is a queue duplicate and is not re-sent. | No extra rows |
| Events accepted by the old host after the backup | Not in the restored queue. **Push sources (syslog, HTTP):** lost unless the sender resends them, or the old host delivered them before it failed. **WEC:** read again only if they reach the new WEC's `ForwardedEvents` | All delivered by the old host before loss in the lab |
| Source cursors | Resume from the backup point. WEC re-reads, and the queue deduplicates retained events. | See the WEC section |
| Leases in the backup | Expire and are retried (`uploading` → `retrying`) | 500 leases recovered on each host |

#### Destination-side deduplication

At-least-once delivery means detections and queries must collapse replays. Use:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(ingestion_time(), *) by CollectorId, EventId
```

This works only while `CollectorId` and `EventId` stay stable, which is why the collector id
must survive restores and container recreates. The production-readiness workstream on
duplicate handling defines the full detection guidance. This guide only guarantees that
replays carry the same identity.

#### Windows Event Log and WEC restores

A WEC bookmark is a position in **that host's** `ForwardedEvents` log. On another host it
means nothing; Bower detects a smaller log and resets to 0 (`resets: 1`), then reads
everything there, deduplicating events it still retains. Follow this order:

1. Configure the new WEC: create the subscription, size `ForwardedEvents`, and grant the
   service SID read access to the channel.
2. Restore the queue and **start Bower before re-pointing any source**. Check that
   `/v1/status` shows `resets: 1` and `bookmarkRecordId` 0 or near the start.
3. Re-point the sources (GPO `SubscriptionManager`, or the registry on lab hosts) and check
   that `wecutil gr` shows them `Active`.

If sources were re-pointed first and the new log already has more records than the restored
bookmark, Bower could start after those records. In that case, before the first start, change
the subscription `id` in `windows-eventlog.json` (for example `wec-security` to
`wec-security-dr1`) and keep `readExisting: true`. The new id has no bookmark, so Bower reads
the whole log. Event identity does not include the subscription id or WEC host, so the queue
deduplicates every event it retains.

**WEC source-side gap.** Sources consider an event delivered once the WEC accepts it,
whether or not Bower has read it. If the old WEC is lost, events in its `ForwardedEvents`
that Bower had not read yet are on that host only. In the lab, 62 events
forwarded during the last ~15 seconds were missing until the old host's disk was brought
back and Bower read past its bookmark. Mitigations, in order of preference:

- recover the failed WEC's disk or EBS snapshot and run Bower on it once to drain past its
  bookmark (verified, closed the gap);
- run two WECs with sources subscribed to both, each with its own collector id; identities
  are origin-based, so the destination can collapse by `EventId`;
- a new DR subscription id with `ReadExistingEvents=true` should make sources resend their
  retained log, but **in the lab the source replayed nothing in 6 minutes; not qualified**.

### Disaster recovery scenarios

| Scenario | Recovery | Recovery point | Measured recovery time |
| --- | --- | --- | --- |
| Collector process crash | Automatic (systemd `Restart=on-failure`, SCM recovery, container restart policy) | No accepted event lost | 5.7 s Linux, 5.8 s Windows |
| Host reboot or power loss | Automatic on boot | No accepted event lost; WEC catches up from the bookmark | About 3 minutes (EC2 boot) |
| Disk or volume corruption, host intact | Stop, move the queue aside, `bower queue restore` the last backup, start | Last backup; rows pending at backup are re-delivered | Under 1 min plus the backlog drain |
| Host lost, volume recoverable | Attach the volume to a replacement with the same collector id; or drain the old WEC disk | No loss | Minutes |
| Host lost, volume lost | New host, restore the last backup, re-point sources | Push sources: since the last backup, unless resent. WEC: events forwarded but not read are lost unless sources resend. | Minutes |
| Bad upgrade | Package rollback (same schema), or restore the pre-upgrade backup | Pre-upgrade backup | Minutes |
| Queue from a newer release opened by an older one | Refused before any change (this release on); install the newer release | No loss | Immediate |

## Crash and power-loss behaviour

- Every accepted event is committed (SQLite WAL, `synchronous=FULL`) before the source is
  acknowledged or its cursor moves. A crash before that point means the source
  resends: WEC re-reads from the bookmark, and an HTTP producer gets no `202`. For syslog,
  the frame is lost unless the sender resends it.
- Leases held at a crash expire (`BOWER_DELIVERY_LEASE_SECONDS`) and are retried. A batch
  may have reached the destination before the crash, so expect occasional duplicates; the
  lab's kills during drain produced none.
- systemd restarts the service 5 s after a failure, and the MSI service recovery restarts
  it after 5 s. Containers need `restart: unless-stopped` (compose) or the Kubernetes
  default `restartPolicy: Always`.
- Firewall or outage rules you add for maintenance may not persist across a reboot (the
  lab's nftables table did not). Do not rely on them to hold a backlog.

## Supported versions, downgrades and limits

| From → to | Queue | Windows bookmarks | Settings | Supported | Notes |
| --- | --- | --- | --- | --- | --- |
| Any v5 release → newer v5 release (dev.264 → dev.270 → dev.277) | Unchanged | v2 → v2 | Linux `bower.env` kept. Windows: registry settings lost before `BOWER_SETTINGS_FILE`; kept with it. | Yes | Measured |
| Pre-#157 (v1 bookmark) → current | Unchanged | v1 → v2: one full channel re-read with deduplication | As above | Yes | Re-read volume is the whole channel; replays older than retention are re-delivered |
| v1–v4 queue → v5 | Automatic migration | — | — | Yes, after a backup | [Queue durability](../operations/queue-v5-durability.md) |
| Newer v5 → older v5 (downgrade) | Same | v2 → v2 | The older build may not read `bower.env` | Works; test first | RPM measured. MSI does not block it for dev builds. |
| Current → pre-#157 | Same | v2 refused (`winevt-bookmark-invalid`) | — | **No** | WEC cannot read `ForwardedEvents` at all on pre-#157 |
| Future schema (6+) → this release | Refused, unchanged | — | — | **No** (fails closed) | Older dev builds could write into a future database |
| Queue backup → older or newer release | Restore requires schema 5 | — | — | Same schema only | `bower queue restore` refuses a newer manifest |

Known limits:

- **MSI downgrade protection.** MSI ignores the fourth version field, and dev builds are
  `0.1.0.N`, so any dev MSI replaces any other. Releases must increment `major.minor.patch`
  for `DowngradeErrorMessage` to apply.
- **Reported version.** The collector reports `0.1.0` in status and management whatever
  the package version. Verify upgrades with the package version
  (`rpm -q`, `DisplayVersion`) and the executable SHA-256.
- **Rust.** The Rust CLI has no `queue backup` / `queue restore`; use the C# CLI (schema 5
  is shared). The Rust collector does not read `BOWER_SETTINGS_FILE`; on Linux, use systemd
  `EnvironmentFile`. Both runtimes implement the newer-schema refusal and the persisted
  `collector-id`.
- **Lab coverage of later changes.** The AWS run used build `4c30b2a`. Review fixes made
  afterwards were covered by unit, CI install and local tests only, not re-run on AWS:
  - owner-only temporary copies, busy retry, damaged-queue backups and the restore result
    fields;
  - the settings-file trust, quoting and logging rules;
  - the persisted `collector-id`.
- **Syslog.** There is no application acknowledgement: frames in flight when a collector
  crashes, restarts or is replaced are lost unless the sender resends them.
- **WEC.** The source-side gap above applies when a WEC host is lost. DR-subscription
  replay is not qualified.
- **Not tested live:** Kubernetes, Azure VMs, DEB packages (same scripts as RPM), Windows
  arm64, signed packages, queues larger than 33 MB, and a re-read of a 1 GiB channel.

## How we tested this

Lab run `bower-ws4-20261031-074918`, evidence in
[docs/evidence/ws4-20261031-074918](../evidence/ws4-20261031-074918/README.md):

- Hosts: a Windows Server 2022 DC that was also the WEF source, two WEC hosts and two
  Amazon Linux 2023 hosts in a private AWS subnet.
- Destination: a real Sentinel workspace through the repository Bicep DCR.
- Traffic: real NTLM LDAP failures (native 4625, forwarded by WEF) at 5/sec, and a
  sequence-numbered RFC 5424 mutual-TLS sender at 10/sec.
- Baseline: the pilot's CI artifacts (`0.1.0-dev.264`), upgraded to main (`dev.270`) and
  this branch (`dev.277`).

Exact accounting against an independent verifier query:

- Windows: 13,021 native identities = 13,021 accepted = 13,021 distinct at Sentinel
  (identical SHA-256 digests).
- Linux: 23,727 sequence numbers accepted with no gaps, all at Sentinel.
- Docker: 6,240 / 6,240.
- Every extra destination row (2,678 Windows, 2,009 Linux) is a row that was pending in the
  restored backup.

The [evidence README](../evidence/ws4-20261031-074918/README.md) lists every scenario
result, the failed and blocked attempts, and the cleanup audit.
