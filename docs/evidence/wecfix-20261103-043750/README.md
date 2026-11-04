# wecfix: Windows reader throughput and retention collisions (`bower-wecfix-20261103-043750`)

**Result.** Both soak defects were profiled on real Windows hosts, and the fixes were measured
against the previous build on the same hardware, under the same load and at the same fill level.
The observed identity sets matched on both collectors, but exact delivery is
unqualified because native source coverage was not proven.

- **The suspected cause of Defect 1 is not the cause.** A poll's cost does not grow with
  `ForwardedEvents`. It was 0.8–0.95 ms from 10,000 to 1,040,000 records. The real limit is
  the per-event durable commit: about 44 events a second per subscription, set by disk flush
  latency rather than CPU. Every burst above that rate became a backlog. **Group commit** (one
  durable commit per read) removes the limit: 100 events a second, sustained. Reader lag is
  unknown for this historical run because it did not capture the newest record ID.
- **The soak's CPU growth did not reproduce.** On `m6i.large`, the old build's CPU went from
  74–82 s/h with about 17,000 retained queue rows to 89–103 s/h with about 150,000. The soak's
  growth to 2,500 s/h on a credit-limited `t3.medium` is not explained by this run (see
  Limits).
- **Defect 2: retention no longer stalls intake.** Purging 151,878 rows stalled the old
  build's reading for about 2 minutes (0.6 events/s). The new build kept reading
  at 10/s. Historical reader lag is unknown. Neither build logged a `SqliteException` on this
  hardware.

| Criterion (brief) | Old build (Wec2) | New build (Wec) |
|---|---|---|
| Native = accepted = Sentinel, exact | **UNQUALIFIED**: observed exports gave 293,400 = 293,400 = 293,400, 0 duplicate rows; native coverage was not proven | **UNQUALIFIED**: same observed counts; native coverage was not proven |
| ≥ 1,000,000 records in `ForwardedEvents` before the run | 1,040,001 (2.53 GB), growing to 1,333,401 | same channel content |
| ≥ 2 h at 10/s with ≥ 2 retention runs of tens of thousands of rows | 07:03–09:17Z, purges 151,875 and 95,452 | 07:03–09:17Z, purges 151,878 and 95,461 |
| p99 latency ≤ 18.16 s (07:03–09:47Z, 139,802 observed events) | **UNQUALIFIED**: observed p50 / p95 / p99 51.2 / 667.4 / 728.5 s | **UNQUALIFIED**: observed p50 / p95 / p99 6.0 / 9.1 / 13.3 s |
| p99 within each retention window (10 min) | **UNQUALIFIED**: observed p99 158.0 s (08:00), 80.0 s (09:00) | **UNQUALIFIED**: observed p99 16.2 s (08:00), 35.7 s (09:00) |
| Collector `SqliteException` loop failures (1002) / source failures | 0 / 0 | 0 / 0 (and 0 busy back-offs, 1009) |
| CPU at 10/s with 100,000–125,000 retained rows | 104 s/h | **42 s/h** |

Source: [`live/final-reconciliation.json`](live/final-reconciliation.json). The observed identity digest
(SHA-256 of the sorted ids, newline-separated) is
`ec573d33b880181cc43c21b2ee5e09c231155ce43cdab7bd4c0900b74e4606d3` for native, both
accepted sets and both Sentinel sets.

## What ran, where

| Item | Value |
|---|---|
| AWS | Account 959038055523, ap-southeast-2. Stack `bower-wecfix-20261103-043750` from #170's `lab/aws/upgrade-recovery/lab.py` with a `wecfix` profile ([diff](operations/lab-profile-wecfix.diff)), template SHA-256 `5b05da1f…dd33b`. Private subnet 172.31.249.0/24 in the default VPC via the existing NAT. SSM only, no public addresses, IMDSv2, encrypted gp3 (60 GB). EventBridge Scheduler expiry at 2026-11-03T15:38:08Z (11 hours), which terminates all instances |
| Hosts | `Dc`, `Wec` and `Wec2`, all **`m6i.large`** (2 vCPU, 8 GiB, no CPU credits). Windows Server 2022 `ami-086db0bc6076e24da`. `Dc` is the `bower.test` DC and the 4625 source, forwarding source-initiated to both WECs (subscription batches of 100 events, 1 s, as in the soak). Each WEC has `ForwardedEvents` at 4 GiB, so both read identical channels |
| Old build | CI run [41411891627](https://github.com/jusso-dev/Bower/actions/runs/41411891627) on main `d7ddc55`. `bower-collector-0.1.0-dev.354-x64.msi` `1308fd53…3a1e`, `Bower.Collector.exe` `1b10e07b…c051` |
| New build | CI run [41591542377](https://github.com/jusso-dev/Bower/actions/runs/41591542377) on `3812ba5`. Subsequent runtime changes in this branch have not been live-qualified by this run. `bower-collector-0.1.0-dev.370-x64.msi` `c5cd759e…8a72`, `Bower.Collector.exe` `42c21142…fbe7`. Installed on `Wec` at 07:02:17Z as an in-place MSI upgrade under load: exit 0, 4 s, healthy immediately, settings file unchanged ([`live/upgrade-wec.json`](live/upgrade-wec.json)) |
| Packages | **Unsigned** (release signing is deferred). Pack `windows-security-logon-1.0.2`, signed with a run-generated key |
| Collector settings | Soak `bower.env`: Sentinel through the Logs Ingestion API (certificate credential), health records every 60 s, lease 90 s, output timeout 60 s, queue cap 4 GiB, subscription `ForwardedEvents` 4625, poll 1 s, batch 256, `readExisting: false` (started after the pre-fill). Queue retention: 1 h from the start, 6 h during the row build-up (06:08–07:02Z), then 1 h again |
| Azure | `rg-bower-wecfix-20261103-043750` (australiaeast): workspace and Sentinel, repository Bicep DCE/DCR/table, ingestion and verifier applications |
| Load | DC generator (#170's, `bower-probe` NTLM LDAP binds): 10/s from 05:17:00Z for 3.5 h, with 100/s for 60 s at 07:17Z, plus a 10/s tail from 08:47 to 09:17Z. Extra 90/s for 1,000 s at 06:08Z (`rows1`, to reach soak-level queue rows) and for 600 s at 07:21Z (`sustained`). Total 293,400 attempts, all LDAP result 49, 0 successful logons ([`live/generators.txt`](live/generators.txt)) |
| Pre-fill | 1,040,000 real 4625s from local network logons of the unknown user `bower-fill` at about 1,900/s (04:51–05:03Z). WEF batching was raised to 2,000 events and 200 ms only while filling, then restored to 100 events and 1 s |

## Defect 1: profiling

### Reader cost against channel size (refutes the suspected cause)

Measured with [`lab/aws/wecfix/bench`](../../../lab/aws/wecfix/bench) (`profile` and `source`
modes) against the real `ForwardedEvents` channel, with the soak's allow-list:

| `ForwardedEvents` records | One poll (range + allow-listed query from the bookmark), median wall time | Collector CPU per poll | Event Log service CPU per poll |
|---|---|---|---|
| 10,001 | 0.95 ms | below timer resolution | below timer resolution |
| 172,658 (140,514 polls, one session) | 0.81 ms | 0.20 ms, flat across all ten deciles | 0.63–0.66 ms |
| 1,040,001 (71,617 polls) | 0.81 ms (p95 0.89) | 0.21 ms | 0.62 ms |

Files: [`profiling/reader-profile-10k.json`](profiling/reader-profile-10k.json),
[`reader-profile-1m.json`](profiling/reader-profile-1m.json),
[`reader-source-1m.json`](profiling/reader-source-1m.json) and
[`transcribed-runs.json`](profiling/transcribed-runs.json). At one poll a second this is under
1 s of collector CPU an hour. Neither the seek nor a long-lived session explains the soak.

A long-lived reader is not an option either. An `EvtQuery` result set does not see records
appended after the query was created. After the end, `ReadEvent` throws
`InvalidOperationException`, and re-seeking to the current position or to the last bookmark
returned 0 of the roughly 1,300 records appended between rounds
([`reader-long-lived-none.json`](profiling/reader-long-lived-none.json), [`-current`](profiling/reader-long-lived-current.json), [`-bookmark`](profiling/reader-long-lived-bookmark.json)).

### What the soak's CPU tracked

The soak's own 5-minute samples show WEC CPU following **retained queue rows**, not
`ForwardedEvents`. At each hourly purge, rows fell from about 108,000 to about 75,000 and CPU
from about 1,550 to about 1,150 s/h. It climbed back as rows refilled, while the queue file
stayed at 302 MB and `ForwardedEvents` only grew. We reproduced soak-level rows on `m6i.large`
(152,000 retained) and measured the old build:

| Retained rows (old build, 10/s steady) | Collector CPU |
|---|---|
| 3,000–17,400 | 74–82 s/h |
| 148,900–151,900 | 89–103 s/h |

Ten times the rows added about 10%. The queue paths were checked with the actual statements:
- Lease: multi-index OR on `state`.
- Snapshot: covering index.
- Ledger head: `MERGE (UNION ALL)` with a reverse primary-key scan and `LIMIT 1`.
- Duplicate check: primary key and unique fingerprint.

Enqueue cost was flat from 1,300 to 100,300 retained rows on the Mac, and from 1,300 to 30,300
on Windows (1.8–1.9 ms CPU, ~17 ms wall per event). It was also flat from a 31 MB to a 1.2 GB
database file on Windows ([`queue-cost-vs-retained-rows-windows.json`](profiling/queue-cost-vs-retained-rows-windows.json), [`transcribed-runs.json`](profiling/transcribed-runs.json)). No row-proportional query was found.

### The real limit: one durable commit per event

A CPU profile (in-box WPR, symbolised by [`etlstacks`](../../../lab/aws/wecfix/etlstacks)
with the build's PDBs) during the 90/s load showed:
- the collector at **12% of one core**;
- 54% of its samples in `SqliteEventStore.EnqueueAsync`;
- 43% in the kernel (file I/O).

Each event was its own transaction: a WAL flush, then a checkpoint flush
(`wal_autocheckpoint=1`, `synchronous=FULL`). That is about 22 ms each on gp3, run one after
another, so the old build read at **44–45 events a second** whatever the CPU.

| Load | Old build | New build (group commit) |
|---|---|---|
| 100/s for 60 s (07:17Z) | 44/s; p99 79.8 s | 98/s; p99 9.1 s |
| 100/s for 10 min (07:21–07:31Z) | 45.2/s; p99 738.2 s | 99.8/s; p99 8.5 s; 456 s/h CPU (12.7% of a vCPU) |
| 10/s, 100,000–125,000 rows | 104 s/h | 42 s/h |
| 10/s, 39,000–46,000 rows | 86 s/h | 34 s/h |

Steady-state profiles at 10/s: [`cpu-profile-old-steady-10eps.txt`](profiling/cpu-profile-old-steady-10eps.txt)
and [`cpu-profile-new-steady-10eps.txt`](profiling/cpu-profile-new-steady-10eps.txt). Under
WPR they read 165 and 75 s/h respectively; the profiler adds overhead.

This explains the soak's burst hours even before CPU credits ran out: p95 219–294 s in the
first three burst hours. A credit-limited t3 has a lower ceiling and less spare capacity
to drain.

## Defect 2: retention

| Purge | Old build (5,000-row transactions, full ledger compaction each) | New build (1,000-row transactions, compaction through the purge boundary, 100 ms pauses) |
|---|---|---|
| 08:00Z, 151,875 / 151,878 rows | 2.7 min; reading stalled about 2 min (0.6–0.7 events/s); p95 / p99 139.8 / 158.0 s | 5.9 min; reading 9.7–10.4/s; p95 / p99 14.3 / 16.2 s |
| 09:00Z, 95,452 / 95,461 rows | 1.4 min; reading 0.3/s for a minute; p95 / p99 62.7 / 80.0 s | 3.4 min; reading 9.2–10.4/s; p95 / p99 **21.9 / 35.7 s** |

Neither build logged loop failures (1002), busy back-offs (1009) or source failures
([`collector-logs-Wec.json`](live/collector-logs-Wec.json), [`collector-logs-Wec2.json`](live/collector-logs-Wec2.json)). Each old 5,000-row transaction finished inside the 5 s
busy timeout on `m6i.large`, so the soak's `SqliteException`s (on a credit-starved t3) did not
reproduce. The stall they caused did.

## Failed attempts and corrections (preserved)

- `continue` benchmark attempt 1: `EventLogException` on every round. A reader `BatchSize` of
  100,000 is invalid; it was capped at 512 and re-run.
- `queue` benchmark attempt 1: `DllNotFoundException`. The single-file publish lacked the
  native SQLite library; it was republished with `IncludeNativeLibrariesForSelfExtract`.
- The `rows` benchmark first ran on Wec2 from 05:27 to 05:33Z. It was cancelled because its
  fsync load competed with Wec2's collector, and re-run on the DC. Wec2's samples in those
  six minutes are disturbed (they are outside every comparison window).
- WPR capture attempt 1 failed: Windows PowerShell 5.1 turned `wpr.exe` stderr into an error.
  It now runs through `cmd /c`.
- The first CI run of the branch (41583610926) failed. The shortened compaction scan no longer
  verified the ledger when a purge removed nothing (`DurabilityAdversarialTests:151`, Rust
  `adversarial.rs:170`). It was fixed before any live use (`05ff5ae`).
- The log-count script's first run used the wrong epoch (09:00Z, not 08:00Z) and parsed the
  event id as the purge count. Both were fixed and re-run.
- Native windows: the four hourly windows held 293,399. The remaining event was created just
  after 09:17Z (generator drift) and is in `w5`.

## Limits

- **The soak's CPU growth is not explained.** It did not reproduce on `m6i.large` with
  1.3 million `ForwardedEvents` records and 152,000 retained rows. The candidate is the
  `t3.medium` itself: 4 GiB shared by a 2 GB event log and a 300 MB queue, and standard
  credits (the CPU step at 15:00Z coincides with the credit balance reaching 0). This run did
  not test a `t3.medium`, so that is unproven. The sizing guidance therefore asks for
  non-burstable WEC hosts.
- In the 09:00Z purge window the new build's observed-sample p99 was 35.7 s, above 18.16 s.
  The observed post-upgrade sample p99 was 13.3 s; neither figure qualifies the complete
  workload because capture and destination completeness are unproven.
  Tuning `BatchSize` or `BatchPause` against delivery and repeating this gate remain open.
- Limiting the sequence scanned by compaction does not bound work by the purge batch size:
  a large unresolved prefix is still scanned while the write transaction is held. That
  workload has not been qualified.
- The source and queue tests inject failures or dispose objects; they do not demonstrate an
  abrupt process kill at the batch commit and bookmark boundary. Suppressed-event replay
  across that boundary remains unqualified.
- About 3.5 hours, one hardware class, one run. Not a 24-hour re-soak, so memory and handle
  trends were not re-measured.
- Group commit holds the queue's write lock for one read (up to 256 events, tens of
  milliseconds here). Other writers wait for it.
- The C# collector only. The Rust collector does not run the Windows source (see
  `rust/AGENTS.md` for the recorded gaps). Packages are unsigned.
- Identity lists are not published, only counts and digests. The original reconciliation
  excluded accepted IDs absent from both native and Sentinel sets as outside the window,
  without establishing their generation time. The final published export reports zero such
  excluded IDs on both hosts; narrower interim results that excluded IDs cannot prove exact
  equality. The updated probe exports each WEC event's normalized generation time from its
  redacted queue envelope, without its payload. The updated `lab/aws/wecfix/reconcile.py`
  uses that time for window membership; missing or malformed generation times are
  indeterminate and prevent an exact pass. The historical export predates this field and
  cannot pass the updated check without recoverable generation times. Intake time alone
  cannot prove generation-window membership.
- Native coverage is not proven. These exports lack the time the Windows Event Log query
  began, and `w5` was captured at 09:20:38Z even though its declared window ends at
  09:47Z. Earlier windows also report 168 redaction-changed identities in aggregate;
  the source export's digest covers redacted IDs while the original reconciliation compared
  original IDs. The updated check requires capture to start after the declared window,
  verifies counts and the redacted-ID digest, and requires IDs to be unchanged. Even a
  complete, internally consistent export proves only the events observed in the channel:
  channel wrap, clearing or other loss before capture must be excluded separately. The
  current reconciler keeps `exact` false while channel continuity and complete queue-union
  capture lack independent proof, and reports matching available observations separately.
  It also exposes missing/invalid sample and union artifacts and observed union failures.
- Historical reader lag is unknown. The original calculations subtracted the bookmark's
  record ID from the channel's `RecordCount`, which is a count and can diverge from record
  IDs after wrap. Ignore `readerLagRecords` in the archived reconciliation JSON; it retains
  the original, invalid calculations. New samples include the newest record ID; its distance from the bookmark
  is an ID distance, not necessarily the number of unread events, and a missing or reset
  ID is reported as unknown.

## Cleanup

**Zero resources with RunId `bower-wecfix-20261103-043750` remain in AWS or Azure.**
[`cleanup.json`](cleanup.json) was written at 2026-11-03T09:30:46Z by #170's
`relp-cleanup-audit.py`: **33 of 33 checks absent**. Every check is proven by an exact
not-found code of its own query, a `terminated` instance state, or a successful empty
listing. Audit inputs: [`operations/cleanup-audit-inputs-stack-resources.json`](operations/cleanup-audit-inputs-stack-resources.json) and [`operations/cleanup-audit-inputs-volumes.json`](operations/cleanup-audit-inputs-volumes.json).

Teardown order:
1. Account check, then the RunId tag check on the stack, bucket and secret.
2. Bucket emptied (0 versions, 0 delete markers), `delete-stack`, `stack-delete-complete`.
3. `azure-environment.py cleanup --apply`: workspace force-deleted; applications and
   service principals deleted and purged; role assignments removed; resource group deleted;
   `cleanupErrors: []`.
4. The audit.
5. The private local directory (keys, certificates, identity lists, Azure caches) was
   deleted.

The 11-hour expiry schedule was not relied on; it was deleted with the stack before it fired.
