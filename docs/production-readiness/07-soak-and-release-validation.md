# 07: 24-hour soak and release validation

> **Status: soak in progress (draft).** The 24-hour soak `bower-soak-20261102-015614` runs
> from 2026-11-02T03:35:00Z to 2026-11-03T03:35:00Z. Results, the full per-environment
> procedure and the release checklist are added when it finishes. Nothing here is a pass yet.

## Purpose

Gaps 1 to 6 qualified delivery, upgrades, credentials and monitoring in runs of minutes to an
hour. This gap asks a different question: does the scoped rollout (Windows WEF/WEC and
firewall syslog over RELP, into Microsoft Sentinel) stay correct and stable for a full day of
ordinary traffic, including the timer jobs and housekeeping that only happen over hours?
It is a stability soak. No faults are injected.

## Pass criteria (registered before the soak started)

A run passes only if **all** of these hold for **both** collectors. Anything else is a failure
and is reported as one.

| # | Criterion | How it is measured |
|---|---|---|
| 1 | Native = accepted = distinct Sentinel identities, exactly | SHA-256 of the sorted identity sets; duplicates counted separately |
| 2 | No process restarts | Collector PID and start time unchanged in every 5-minute sample; systemd `NRestarts` 0; boot unchanged |
| 3 | No unbounded growth | Least-squares slope of memory (RSS / private bytes), FDs / handles, threads and queue DB + WAL bytes over hours 3 to 24. Flat means the 30-day projection of the slope is under 10% of the mean |
| 4 | Latency within the pilot envelope | Whole-soak p99 of first ingestion minus event time no more than twice the pilot's connected p99: 13.3 s firewall, 18.16 s WEC. Hours above the limit are listed |
| 5 | No alerts | No Azure Monitor alert instance and no Sentinel incident from the deployed `deploy/sentinel/monitoring` rules |
| 6 | No privacy-marker matches | `bower-probe`, `BOWER_DENY` and `synthetic-invalid` absent from every destination row (`pack_all()`) |

Natural events that must occur and be recorded: the hourly `queue-retention` job (with
`BOWER_QUEUE_RETENTION_HOURS=2` so it actually purges), the daily `queue-maintenance` job
(03:00 UTC), Entra token refresh (the ingestion token lifetime is far shorter than 24 hours),
journald rotation on the Linux hosts and event-log growth on Windows.

## Topology

| Host | Role | Size |
|---|---|---|
| `Dc` | Windows Server 2022 domain controller `bower.test`, the 4625 source (NTLM LDAP bind failures to its own address), WEF source-initiated forwarding | t3.medium |
| `Wec` | Windows Server 2022, domain member, WEC `ForwardedEvents`, Bower **MSI** `0.1.0-dev.337` from main | t3.medium |
| `Sender` | Amazon Linux 2023, real nftables denials, rsyslog **8.2610.0** with `omrelp` over mutual TLS | t3.small |
| `Linux` | Amazon Linux 2023, Bower **RPM** `0.1.0~dev.337` from main, RELP listener `a13` | t3.small |

Both collectors deliver to a fresh Sentinel workspace deployed with `deploy/bicep/main.bicep`.
A separate read-only verifier identity queries it. The alert rules come from
`deploy/sentinel/monitoring/monitoring.bicep`, enabled, with both collectors expected.

## Load profile

10 events/sec per collector, a 60-second 100/sec burst every 4 hours (at +2 h, +6 h, ... +22 h),
896,400 events per collector. Firewall identities are sequence numbers (`a13-n<port>x<sport>`
from index 100,000). Windows identities are Bower's `winevt-` ids of the DC's 4625 records,
exported hourly from the DC Security log.

## How the run works (harness)

See [`lab/aws/soak/README.md`](../../lab/aws/soak/README.md). Generators, samplers and the
end-of-run export run on the hosts under systemd units and scheduled tasks.

## Results

Pending. Smoke and interim reconciliations are recorded in
[`docs/evidence/soak-20261102-015614`](../evidence/soak-20261102-015614/README.md).
