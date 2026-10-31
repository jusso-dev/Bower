# Upgrade, crash and restore with populated queues — 31 October 2026

**Zero accepted events were lost in any scenario, and every destination duplicate is
explained by at-least-once replay.** The run also found five product defects. Four are
fixed in this change; the MSI downgrade check is still open. No production approval is
implied. The operator guide is
[Upgrades, backup and recovery](../../production-readiness/04-upgrade-backup-recovery.md).

| Measured result | Windows WEC (`wec-ws4`) | Linux RPM (`linux-ws4`) | Docker (`linux-docker-ws4`) |
| --- | ---: | ---: | ---: |
| Source events in scope | 13,021 native DC 4625 | 23,727 sequence-numbered frames | 6,240 sequence-numbered frames |
| Accepted by Bower | 13,021 | 23,727 (no gaps) | 6,240 (no gaps) |
| Distinct at Sentinel | 13,021 | 23,727 | 6,240 |
| Extra destination rows | 2,678 | 2,009 | 0 |
| Rows pending in the restored backup | 2,678 | 2,009 | n/a |
| Native/accepted identity digest equals destination digest | yes | per stream, yes | yes |

[Accounting](accounting.json) · [Snapshots](snapshots.json) · [Operations](operations.json) ·
[v1 → v2 bookmarks](v1-bookmark-upgrade.json) · [Future schema](future-schema-fail-closed.json) ·
[Backup manifests](backup-manifests.json) · [Failures and blocked items](failed-and-blocked.json) ·
[Infrastructure](infrastructure.json) · [Artifacts](artifact-manifest.json) · [Cleanup](cleanup.json)

## What was run

AWS run `bower-ws4-20261031-074918`, account `959038055523`, `ap-southeast-2`. The stack
had five private hosts in a dedicated `172.31.244.0/24` subnet, with no public addresses,
no inbound rules beyond the group itself, SSM only, encrypted gp3 volumes, IMDSv2 and a
10-hour EventBridge Scheduler termination guard:

- `Dc` (Windows Server 2022, `t3.medium`): the `bower.test` domain controller and the WEF
  source. NTLM LDAP bind failures generated real Security 4625 records (logon type 3) at
  5/sec.
- `Wec` and `Wec2` (Windows Server 2022, `t3.medium`): real source-initiated WEC
  `ForwardedEvents` subscriptions. `Wec2` was the fresh restore target.
- `Linux` (Amazon Linux 2023, `t3.medium`): the RPM collector, then the Docker collector.
- `Linux2` (Amazon Linux 2023, `t3.small`): a sequence-numbered RFC 5424 sender over mutual
  TLS (10/sec), then the fresh restore target.

The destination was a real Log Analytics workspace with Sentinel enabled, in
`rg-bower-ws4-20261031-074918`, deployed with the repository Bicep. A separate verifier
service principal ran the queries; the ingestion principal could not read. An outage
blocked only the collector's outbound TCP 443: nftables matched the service uid, Windows
Firewall matched the `Bower` service SID. That gives real in-flight leases that fail as
`destination-azure-unavailable` without spending attempts.

Every frame the sender writes is a pure function of `(stream, base, rate, sequence)`, so
the collector event id of every sequence number can be recomputed exactly. The DC's own
Security log is the Windows source of truth, read with the
[lab harness](../../../lab/aws/upgrade-recovery/README.md) probe, which uses the pilot
probe's approach: the signed parser plus default identity redaction. Expected ids pass through the same default privacy
detectors as persisted ids. These detectors masked 5 Windows and 20 syslog generated ids as
false positives, and the comparison accounts for that.

Provenance is recorded in [artifact-manifest.json](artifact-manifest.json):

- Baseline: pilot commit `2644669`, CI run `41016990194` (`0.1.0-dev.264`).
- Main: `9d1bbcd`, run `41058963882` (`0.1.0-dev.270`). Its `src/` is identical to the
  baseline.
- Candidate: this branch at `4c30b2a`, run `41184468318` (`0.1.0-dev.277`). The full CI
  dispatch was green.
- Legacy v1-bookmark build: `74e250f`. No CI artifacts exist for it, so it is a **local**
  managed self-contained publish, side-loaded.

All packages are **unsigned**; release signing is deferred. The packs were signed with an
ephemeral lab key, which was deleted after the run, and verified against its public key.

## Scenario results

| Scenario | Result | Measurement |
| --- | --- | --- |
| RPM `dnf upgrade` 264 → 270 under load, destination blocked | **Pass** | 5.2 s package time, service healthy 0.02 s after. `rpm -V` clean; `bower.env`, TLS, pack, key and unit hashes unchanged; owner and modes unchanged. 539 queued, 10 leased and 1,237 delivered before; after, the leases were reclaimed and nothing was lost. |
| RPM 270 → 277 (candidate) under load | **Pass** | 3.7 s; same checks. |
| MSI major upgrade 264 → 270 under load (settings in the service registry) | **Fail (product defect)** | 4.1 s; queue and bookmark intact. The MSI rewrote the service `Environment` and **12 operator settings were dropped**: output, Azure identity, HMAC key file, WEC config, lease and timeout. The collector reported healthy with no source and no output. Collection resumed from bookmark 2183 with no gap only after the settings were re-applied. |
| MSI 270 → 277 with `%ProgramData%\Bower\bower.env` | **Pass (fix verified)** | 5.3 s. The environment was rewritten again, but `BOWER_SETTINGS_FILE` kept every setting. The subscription continued from bookmark 6851 to 7116 with 0 gaps and 0 resets; 500 leases and the 1,831-event backlog were kept. ACL SDDL hashes of every data folder were unchanged. |
| Docker image swap 264 → 277, same named volume, destination blocked | **Pass** | 0.16 s graceful stop, healthy 0.7 s later; uid 1654. Delivered rows kept, pending rows and leases recovered. Collector id pinned explicitly (see defects). |
| SIGKILL on Linux during backlog drain | **Pass** | Healthy 5.7 s after `kill -9` (systemd `Restart=on-failure`); the backlog drained; no destination duplicates came from the kill. |
| `taskkill /F` on Windows during drain | **Pass** | Healthy 5.8 s later (SCM recovery); bookmark continuous; no duplicates. |
| Forced EC2 stop/start under load, connected | **Pass** | Both hosts recovered. WEC read the 816 events the DC buffered meanwhile, with 0 gaps. The sender's resend window deduplicated (1,198 duplicates). |
| Forced EC2 stop/start with a blocked backlog | **Pass** | WEC: 669 pending at power loss, 1,516 after boot with delivered unchanged (backlog kept on disk). Linux: 1,407 pending at power loss; the nftables outage table is not persistent, so it drained on boot. SQLite quick checks passed. |
| Online backup under load (`bower queue backup`) | **Pass** | WEC: 0.7 s, 19.6 MB, 7,462 rows (2,178 queued, 500 retrying) plus the bookmark. Linux: 0.5 s, 33 MB, 12,888 rows (including 500 in-flight leases). Both ledger-intact, `integrity_check` ok, mode 0600. |
| Restore onto a fresh WEC host (`Wec2`, PR MSI, same `COLLECTORID`) | **Pass, with a source-side gap** | The restored queue inherited the service ACL. The bookmark reset to 0 against the empty new log (`resets: 1`), as designed. The 2,678 rows pending at backup time were redelivered; these are the 2,678 duplicates. **62 events** that the DC forwarded to the original WEC after its service stopped were never read; re-pointing used the same subscription id, so the DC did not resend them. Recovering the old host's disk and reading after its bookmark delivered the rest (56 events read). After that, all 13,021 native identities were at Sentinel. Bower lost no accepted event. |
| Restore onto a fresh Linux host (`Linux2`, PR RPM) | **Pass** | 0.56 s; `chown bower:bower` was required. The 2,009 rows pending at backup were redelivered (exactly the 2,009 duplicates). The sender resumed with a bounded replay; no accepted sequence is missing. |
| RPM downgrade 277 → 264 under load | **Works, same schema** | 3.4 s; the queue continued. Both versions use queue schema 5 and the same syslog identity. |
| MSI downgrade 277 → 264 | **Fail (open defect)** | **Not blocked.** MSI compares only `major.minor.build`, and every dev build is `0.1.0.N`. The old service then ran without the settings file and without a source. Re-installing 277 resumed from the bookmark. |
| Old binary on a newer queue schema | **Fail in 264, fixed** | Simulated v6 database with a renamed queue table: the **dev.264 binary modified it**, creating a legacy `queue_events` table and 2 other objects before an unrelated SQLite error. The candidate refuses with `UnsupportedQueueSchemaException` and leaves the file byte-identical. With only a v6 history row, both refuse without changes. |
| WEC v1 → v2 bookmark migration (DC local Security subscription) | **Pass** | The legacy build wrote a v1 bookmark (record 377494) with 2,688 queued. Starting dev.270: 1 reset, a full re-read with 2,809 events read in the first 5 s, all **2,688 re-read events deduplicated**, 742 new, 0 gaps; the bookmark was rewritten as v2. |
| Legacy (v1) binary on a v2 bookmark | **Pass (fails closed)** | `winevt-bookmark-invalid`, 0 events read, bookmark unchanged. |
| Legacy build on real WEC `ForwardedEvents` | **Fail (historical)** | 0 events read: every poll was `winevt-read-failed`, because forwarded records have no `EventRecord.RecordId`. v1 bookmarks can only exist for local channels. |
| DR subscription with a new id and `ReadExistingEvents=true` | **Blocked** | The subscription was Active, but the DC replayed nothing within about 6 minutes. Not qualified. |
| Kubernetes, Azure VM | **Not tested** | Procedures are documented; there was no live run. |

## Product defects found

1. **No supported backup.** Fixed: `bower queue backup` / `bower queue restore` (C#) use the
   SQLite online backup API, a self-contained output file and a SHA-256 manifest. They never
   initialise or migrate the source. Restore refuses to overwrite a queue or adopt a stale
   WAL, and verifies integrity, ledger and counts before renaming.
2. **Old binaries could write into a newer schema.** Fixed in C# and Rust: the schema
   version is checked before any DDL or journal change, and the cursor store refuses too.
   Proven above with real binaries.
3. **MSI upgrades drop operator settings.** Fixed: the collector reads `BOWER_SETTINGS_FILE`
   (`KEY=VALUE`, `BOWER_*`/`AZURE_*` only, bounded, fails closed), and the MSI points it at
   `%ProgramData%\Bower\bower.env`, which upgrades never rewrite. Uninstall deletes it like
   the Linux `bower.env`. The CI install test covers the setting.
4. **Compose and Kubernetes had no stable collector id.** The id fell back to the
   container or pod hostname, which changes on every recreate and breaks replay
   deduplication and destination identity. Fixed after review in both runtimes: without
   `BOWER_COLLECTOR_ID`, the first start persists the machine name to `collector-id` in the
   data volume, and later starts reuse it. Existing installs keep their current id, and the
   sample manifests no longer ship a shared literal id. Found by review; the Docker run
   pinned the id explicitly.
5. **MSI downgrade protection is ineffective for dev builds** (fourth version field).
   **Open**: release versioning must bump `major.minor.patch`. Documented as a limit.

Post-review hardening was covered by unit and CI tests, not by another AWS run:
- the backup copy is owner-only from creation;
- busy queues are retried within a bound;
- damaged queues are still backed up but need `--allow-damaged` to restore;
- restore reports the backup's own manifest plus the restored file's hash;
- the settings file has ownership/ACL trust checks, a startup log line and a defined quoting
  rule;
- the collector id persists.

These changed after the measured build `4c30b2a`.

Rust parity: the queue fix and the persisted `collector-id` are ported. `BOWER_SETTINGS_FILE` and backup/restore exist in C#
only. The Rust collector does not run on Windows, and Linux uses the systemd
`EnvironmentFile`. The backup format is plain SQLite schema 5, which either runtime opens.

## Failed and blocked attempts (preserved)

[failed-and-blocked.json](failed-and-blocked.json) records:

- a generator that rejected its own duration;
- an nftables reserved-word syntax error;
- a Windows PowerShell 5.1 `NativeCommandError` on the CLI's stderr notice after a
  successful restore;
- a first future-schema run in which the service user could not reach the test paths
  (discarded as invalid and rerun);
- a mislabelled harness phase;
- the resumed sender stream's label;
- the blocked DR subscription replay.

None is counted as a pass.

## Limits

- One run on synthetic, low-rate traffic (5–10/sec) with small queues (up to 33 MB). Not a
  soak, not queue saturation, not a 1 GiB `ForwardedEvents` re-read.
- The EC2 forced stop is a hypervisor stop, not a guaranteed torn-write power cut. The
  SQLite checks are `quick_check` and backup `integrity_check`.
- The Docker images reuse the CI collector binaries on the official chiseled runtime-deps
  base; they were not the published GHCR images (none exist for these commits).
- The legacy build is a local managed publish, not a CI Native AOT artifact.
- Syslog has no application acknowledgement. The lab sender resends a bounded window on
  reconnect; a sender without one can lose in-flight frames on a collector crash or restore.
- Destination duplicates were measured, not alerting behaviour. See the pilot's query-time
  deduplication notes.

## Cleanup

**Zero resources with this RunId remain in AWS or Azure.** The independent
[cleanup audit](cleanup.json) verified, from fresh queries:

- AWS: the stack is `DELETE_COMPLETE`; all five instances are terminated; there are no
  tagged volumes, snapshots, images, security groups, subnets, route tables or subnet ENIs;
  no IAM roles or instance profiles; no live secret; no bucket; no expiry schedule; no log
  groups.
- Azure: the resource group is absent; the workspace was force-deleted and is not in the
  soft-deleted list; both Entra apps and service principals were deleted and purged from
  deleted items; no role assignments remain.

Local lab keys, certificates, tokens and isolated CLI caches were deleted. The shared VPC
and NAT gateway were untouched.
