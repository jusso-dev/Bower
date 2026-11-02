# Storage pressure, first AWS run — 31 October 2026

**Partial, and it found the defects the final build fixes.** This run qualified
nothing on its own. It found a drain deadlock at the queue page ceiling, a WAL that
could exceed the write budget, intake that stayed refused after a drain, and syslog
frames lost when the collector restarted while backpressured. The fixes were tested in
place on these hosts. The complete qualification, with exact destination
reconciliation, is the [second run](../ws3b-20261102-005001/README.md).
[Cleanup is verified](cleanup.json) (24 of 24 independent checks).

Guide: [Full queues and low disk space](../../production-readiness/03-storage-pressure.md).

## What ran where

- AWS account `959038055523`, `ap-southeast-2`, run `bower-ws3-20261031-081023`. One
  private subnet (172.31.233.0/24) in the default VPC through the existing NAT gateway;
  no public addresses, SSM only, encrypted gp3, IMDSv2, a 10-hour termination guard.
  Amazon Linux 2023 `t3.small` with a **1 GiB** xfs queue volume; Windows Server 2022
  `t3.medium` domain controller (WEF source); Windows Server 2022 `t3.medium` WEC plus
  collector with a **2 GiB** NTFS queue volume.
- Azure `945092a0-…-3135906`, `australiaeast`, group `rg-bower-ws3-20261031-081023`,
  Microsoft Sentinel workspace, DCR from `deploy/bicep/main.bicep`, separate publisher
  (certificate) and verifier (Log Analytics Reader) identities.
- Input: sequence-numbered RFC 5424 (`ws3lNNNNNNN`) through a local rsyslog sender with a
  disk-assisted queue over mutual TLS; real NTLM LDAP failures for nonexistent
  `ws3wNNNNNNN` accounts on the DC, forwarded by WEF into `ForwardedEvents`.
- Builds: three CI development packages, unsigned ([manifest](artifact-manifest.json)).

## Results

| Scenario | Build | Result |
| --- | --- | --- |
| Smoke, Linux, 301 events | 243c10b | 301 generated = 301 queued = 301 distinct in Sentinel, 0 duplicates ([query](linux-smoke-destination.json)) |
| Queue cap, Linux, 64 MiB, 100/sec | 243c10b | Refused after 247 s at **100% of pages with 45% of the cap undelivered**; then **delivery never resumed** (SQLITE_FULL on every lease and acknowledgement) — **failed, defect** ([summary](linux-queue-cap-attempt2-summary.json)) |
| Recovery: raise cap to 96 MiB and restart | 243c10b | 27,374 drained in 10 s ([record](linux-recovery-raise-cap.json)), but **21,494 frames in socket buffers lost** at the restart ([queue](linux-reconcile-after-attempt2.json), [destination](linux-destination-after-attempt2.json)) — **failed: loss before acceptance** |
| Queue cap, Windows, 64 MiB, 50/sec | 243c10b | Bookmark held, then delivery stalled; WAL 72.6 MB refused all writes ([status](wec-stuck-status-old-build.json)) — **failed, defect** |
| Upgrade the stuck Windows collector in place | b14f149 | 22,516 drained within 60 s with the same cap, no data deleted ([status](wec-after-upgrade-60s.json)); intake then stayed refused (pages 99.95%) — **defect** |
| Queue cap, Linux, final | 131b37e | Refused 235 s after the block (151 held frames, 0 dropped, 0 submit failures); **drained 208 s after the destination returned, no restart** ([runs](linux-queue-cap-runs.json)) — passed locally; no destination reconciliation in this run |
| Queue cap, Windows, final | 131b37e | Refused 482 s after the block (200 refusals, bookmark held, 0 gaps); **drained 166 s after restore, no restart** ([runs](wec-queue-cap-runs.json)) — passed locally |
| Watermarks, Linux (1 GiB, warning 256 MiB / critical 128 MiB free) | 131b37e | Warning 5 s after the filler; critical after the queue grew; 123 frames held (0 dropped); **intake resumed 2 s after space was freed**; drained 135 s after restore; 8 log lines in 13 minutes ([summary](linux-watermarks-summary.json)) — passed locally |
| Watermarks, Windows; disk full and restart, both | 131b37e | Harness failures, not completed ([failures](failed-attempts.json)) |

Measured sizes: average payload 1,200–1,369 bytes; about 2.6 KB (syslog) and 3.0 KB
(Windows 4625) of database per queued row. `ForwardedEvents` at 64 MiB held 30,709
forwarded events (2,185 bytes each).

## Failures retained

All product defects and harness failures are listed in
[failed-attempts.json](failed-attempts.json). The syslog restart loss is not hidden by
the later successful runs.

## Limits

Destination reconciliation covers the smoke and the first queue-cap attempt only. The
second run repeats every scenario on one final build with exact reconciliation.

## Cleanup

The coordinator deleted the stack, bucket and resource group after this session was
interrupted. This session then purged what remained: the soft-deleted Log Analytics
workspace (recovered into a temporary group and force-deleted) and both Entra
applications and service principals from deleted items. The
[independent audit](cleanup.json) checks the stack, instances, subnet, security group,
bucket, secrets, tagged resources, the resource group, the soft-deleted workspace, both
applications and service principals, their deleted items and role assignments: 24 of 24
absent. The run's EBS volume ids were not recorded; its instances used
`DeleteOnTermination`, and a read-only sweep found no unattached volumes created in the
run window. Local keys, certificates and the isolated Azure CLI cache were deleted.
