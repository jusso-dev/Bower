# Storage pressure, final AWS run — 2 November 2026

**Passed for accepted events on both collectors, with one measured loss before acceptance.**
Every event Bower accepted reached Microsoft Sentinel through the ws6 page-ceiling stall,
the free-space watermarks, a completely full volume and a restart while full: 83,725 of
83,725 accepted syslog events and 74,415 of 74,415 Windows events, by exact sequence
number, queried with a separate verifier identity. **7,109 syslog frames were lost before
acceptance** when the collector restarted while the full volume was refusing them
(plain TCP syslog has no application acknowledgement). Windows has **1,008 duplicate
rows** from at-least-once replays. [Cleanup is verified](cleanup.json) (36 of 36
independent checks). The [first run](../ws3-20261031-081023/README.md) holds the earlier
failures that led to the fixes.

Guide: [Full queues and low disk space](../../production-readiness/03-storage-pressure.md).

## What ran where

- AWS account `959038055523`, `ap-southeast-2`, run `bower-ws3b-20261102-005001`. One new
  private subnet (172.31.233.0/24) in the default VPC through the existing NAT; no public
  addresses, SSM only, encrypted gp3, IMDSv2, `terminate` on shutdown and a 10-hour
  Step Functions termination guard.
  - Linux: Amazon Linux 2023 `t3.small`, collector RPM, **1 GiB** xfs queue volume at
    `/var/lib/bower` with `RequiresMountsFor`.
  - Windows: Server 2022 `t3.medium` domain controller (WEF source) and `t3.medium` WEC
    plus collector MSI, **2 GiB** NTFS volume **mounted at `C:\ProgramData\Bower\state`**
    (the MSI default queue path; the probe reported 2,130,636,800 bytes, not `C:`).
- Azure: `australiaeast`, group `rg-bower-ws3b-20261102-005001`, Sentinel workspace, DCR
  from `deploy/bicep/main.bicep`, certificate publisher identity, separate Log Analytics
  Reader verifier in an isolated Azure CLI cache.
- Build `261f61a`, CI run 41368830338, unsigned ([manifest](artifact-manifest.json)).
  The pushed head differs only in tests, the alert query and documentation.
- Input: sequence-numbered RFC 5424 frames (`ws3lNNNNNNN`) through a local rsyslog sender
  (disk-assisted queue, mutual TLS); real NTLM LDAP failures for nonexistent `ws3wNNNNNNN`
  accounts on the DC, forwarded by WEF into `ForwardedEvents`. Destination blocked by a
  host firewall rule scoped to the collector service only.
- `collector_health` every 60 s on both collectors.

## Results

| Scenario | Linux syslog (1 GiB) | Windows WEC (2 GiB) |
| --- | --- | --- |
| **ws6 stall, phase 1**: 16 MiB cap, default 60-min floor, destination up, acknowledged rows fill the page limit | Refused at 66 s; intake reopened 50 s later, no restart, cap unchanged | Refused at 130 s; reopened 42 s later |
| **ws6 stall, phase 2**: destination blocked, backlog fills the page limit, destination restored | Full 26 s after the block; delivery resumed 6 s after restore; intake 46 s; 160 refusals, 0 dropped, 0 submit failures | Full 47 s after the block; delivery resumed 15 s after restore; intake 72 s; 171 refusals, bookmark held, 0 gaps |
| **Watermarks** (Linux 256/128 MiB, Windows 512/256 MiB free) | Warning 6 s after the filler; critical 102 s after the near-critical filler; 124 frames held; intake resumed **6 s** after space was freed; drained 176 s after restore | Warning at the first sample; critical 197 s after the near-critical filler; 122 events held at the bookmark; resumed **1 s** after freeing |
| **Full volume** | 20,480 bytes free; critical in 2 s; destination restored while full | 0 bytes free; critical at once; destination restored while full |
| **Restart while full** | Answering 6 s after restart; intake resumed 6 s after space was freed; 43 log lines for the run | Running and answering at once (8 Application log entries); intake resumed 6 s after freeing |
| Destination (exact sequences) | 90,834 generated, **83,725 distinct, 0 duplicates**; missing = exactly one block 77112–84220 (7,109), the frames sent between the refusal and the restart ([ranges](linux-disk-full-missing-ranges.json)) | 74,415 generated, **74,415 distinct, 0 missing**, 1,008 duplicate rows ([duplicates](destination-duplicates.json)) |

Summaries: Linux [ws6](linux-ws6-summary.json), [watermarks](linux-watermarks-summary.json),
[full disk](linux-disk-full-summary.json); Windows [ws6](wec-ws6-summary.json),
[watermarks](wec-watermarks-summary.json), [full disk](wec-disk-full-summary.json); per-run
journal metrics (`journal-*.json`); destination reports
([Linux](linux-destination-final.json), [Windows](wec-destination-final.json),
[Linux after ws6](linux-destination-after-ws6.json)); queue reconciliation with SQLite
`integrity_check` `ok` on both ([Linux](linux-queue-reconcile.json),
[Windows](wec-queue-reconcile.json)).

### Monitoring path

- [Health records](health-timeline.json) written while intake was refused and the
  destination blocked were queued from the reserve and arrived after restore: Linux shows
  `storage-low` at warning, then `volumeState` `critical`, `intakePaused` true,
  `storage-critical` and `backpressure`; Windows shows pages at 99.9–100% and
  `backpressure` during the ws6 stall.
- The deployed [`queue-storage`](../../../deploy/sentinel/monitoring/queries/queue-storage.kql)
  query fired for both collectors over a 20-minute window
  ([Linux](linux-alert-queue-storage.json), [Windows](wec-alert-queue-storage.json)).
  Run while the destination was still blocked, it returned nothing
  ([record](linux-alert-while-destination-blocked.json)): Azure sees the state only once
  delivery resumes. That run also showed storage refusals being added to capacity refusals
  (248 for 124); the query was corrected to show them separately.
- Incremental vacuum ran live on the new Linux queue (log `1507`, free pages returned).

### Measured sizes

Average payload 1,208 bytes (syslog) and 1,369 bytes (Windows 4625). `ForwardedEvents` at
64 MiB wrapped to 30,705 records (67,112,960 bytes) without overwriting unread records
(`gaps` 0). Sentinel ingestion latency p95 348 s (Linux) and 406 s (Windows) across
outages.

## Not run

- `ForwardedEvents` wrap loss (Bower stalled longer than the channel holds): measured as
  capacity only; the wrap scenario was not run within the time box.
- RELP under the watermark live (unit-tested; RELP itself is qualified in #168), UDP,
  long soaks, power loss.

## Cleanup

`storage-cleanup.py teardown` recorded the stack resources and the six EBS volume ids,
deleted the stack, bucket and run secrets, force-deleted the workspace, deleted the
resource group and both Entra applications, and purged them from deleted items. The
[independent audit](cleanup.json) counts absence only on exact not-found codes: stack,
three instances, six volumes, subnet, route table, security group, IAM roles and profile,
expiry state machine and schedule, bucket, snapshots, secrets, log groups, tagged
resources, resource group, Azure resources, soft-deleted workspace, applications, service
principals, deleted items and role assignments: **36 of 36 absent**. Local keys,
certificates, the pseudonym map and the isolated Azure CLI cache were deleted. The
`bower-soak-` run on main was not touched.
