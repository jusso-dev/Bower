# 24-hour soak: `bower-soak-20261102-015614`

**Status: running. No result is claimed yet.** Soak window 2026-11-02T03:35:00Z to
2026-11-03T03:35:00Z. This file is completed after the soak ends.

## What runs, where

| Item | Value |
|---|---|
| AWS | account 959038055523, ap-southeast-2, stack `bower-soak-20261102-015614`, private subnet 172.31.247.0/24 in the default VPC via the existing NAT gateway; SSM only; IMDSv2; encrypted gp3; expiry schedule 2026-11-03T07:56:59Z (30 hours) terminating all four instances |
| Packages | CI run [41374800326](https://github.com/jusso-dev/Bower/actions/runs/41374800326) on main `1a4c4c2bc0c0fccdd7b41ac88947e02221f23052` (workflow_dispatch, full). **Unsigned** (signing deferred). RPM `bower-collector-0.1.0~dev.337-1.x86_64.rpm` SHA-256 `e974d51e2fd571f9ccfa42684eb77fe85369758cc7b197f6b316de4948a1b273` (installed `/opt/bower/Bower.Collector` `8fae8c0300398c46e31151fe91cfc9499fbb29ca225a4f16045bc0e569a0552d`); MSI `bower-collector-0.1.0-dev.337-x64.msi` SHA-256 `dd8469f7e70f6aca3453717f102adc23e2238c34efc1c27a720062496c89bd3a` (Authenticode `NotSigned`; installed `Bower.Collector.exe` `207c9ae80c083f8c2e2f6d4eab2b9e3296bbd22e07ea50f8e57f6b230cda2450`) |
| Packs | signed with a run-generated key (public key SHA-256 `2619e966a7d5e063f4830bf69e00ce8f48a1b42a0103301025fea84ae0d9af29`): `syslog-reliability-1.0.0` `3afe4ee7b171fd969052bf130026717a4b5fa715140243da5879b2d718dd0a64`, `windows-security-logon-1.0.2` `aeee20deb62513edea0f88aa07a854e2ce43945db6507c868d8356219c6098bc`; all samples pass |
| Sender | rsyslog 8.2610.0 from pinned source (`7bdf95e8…404b`), `rsyslogd` `b9707a54…a8dc`, `omrelp` `3e3def05…da0e`, librelp 1.12.0; `omrelp` mutual TLS, `windowSize=128`, disk-assisted queue (the [RELP profile](../fw-20261101-111911/README.md)) |
| Azure | `rg-bower-soak-20261102-015614` (australiaeast): workspace `bower-soak-20261102-015614-logs` + Sentinel, repository Bicep DCE/DCR/table, ingestion app `bower-soak-20261102-015614-ingest`, verifier app `…-verifier` (Log Analytics Reader on the workspace only), alert rules from `deploy/sentinel/monitoring/monitoring.bicep` (enabled, both collectors expected, DCR error logs on) |

## Setup record (preserved, including failures)

- Sender setup attempt 1 failed: `ConnectionResetError` downloading the pinned upstream
  source. Attempt 2 passed. The rsyslog 8.2610.0 build also failed once the same way and passed
  on retry. Sources are SHA-256 pinned, so a retry cannot change what is built.
- The collector soak agent's first tick failed (`unable to open database`: a URI attach
  without `uri=True`). Fixed and redeployed before any traffic (`BOWER_SOAK_ACTION=update`).
- The shipped TLS-expiry alert (14 days) would have fired on the lab's 2-day certificates.
  Before any traffic the lab CA and both certificates were re-issued for 30 days with the
  same keys (`rotate-lab-certs.sh`), so the alert set stays as shipped.
- One path-check denial (`a13-n4449x59999`, index 1,999,999, outside every soak range) was
  sent at 02:33Z to prove RELP end to end before the smoke.

## Smoke (15 minutes, 02:50:00Z to 03:05:00Z, before the soak)

9,000 events per collector at 10/sec. [Attempt 2](smoke/smoke-attempt2.json) shows an exact
match on both collectors: native = accepted = distinct Sentinel = 9,000, with 0 duplicate rows
and 0 extra rows. Firewall native is the nftables counter delta (9,000) and generator sent
(9,000). Windows native is the DC's 9,000 distinct 4625 records. Latency p50/p95/p99 was
4.0/6.7/10.4 s on the firewall path and 6.7/9.8/12.7 s on the WEC path. Privacy markers: 0. Health
records arrived every 60 s from both collectors. [Attempt 1](smoke/smoke-attempt1-probe-redacted-ids.json)
is preserved. It reported 2 Windows ids missing and 2 extra. Those were the same two events: the
lab probe passed native ids through the default privacy detectors, which masked two `winevt-`
hashes (`redactionChangedIds: 2`). The collector keeps the original ids. The probe now also
emits the original id (column 4), and it was redeployed to the DC before the soak (SHA-256
`2a80c79f16bf98eac7928fec19a19d37b1e93e6aec720717c0c4ad9abd55520a`). This was a harness defect, not loss.

Alert state at smoke: `syslog-tls-expiry` fired at 02:36:41Z, before the soak and before any
traffic. It was evaluated on health records that still carried the 2-day lab certificates
replaced at 02:32Z. It is tracked separately and is not hidden.
