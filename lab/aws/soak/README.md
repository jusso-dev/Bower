# 24-hour soak harness (gap 7)

Runs the scoped rollout for a day: Windows WEF/WEC and firewall syslog over RELP into
Sentinel, at 10 events/sec per collector with a 100/sec burst every 4 hours. Evidence:
[`docs/evidence/soak-20261102-015614`](../../../docs/evidence/soak-20261102-015614/README.md).
Guide: [07-soak-and-release-validation.md](../../../docs/production-readiness/07-soak-and-release-validation.md).

It reuses the proven pieces and adds only what a day-long, unattended run needs:

| Reused | For |
|---|---|
| `upgrade-recovery/lab.py` (profile `soak`) | Stack: `Dc`, `Wec`, `Linux`, `Sender`, 30-hour expiry, sender role limited to its own prefix; `run HOST SCRIPT env:NAME=VALUE` for the `monitoring/` scripts |
| `upgrade-recovery/scripts/init.ps1`, `dc.ps1`, `join.ps1` | AWS CLI, hostnames, the `bower.test` forest, the WEC domain join |
| `monitoring/azure-environment.py` | Workspace, repository Bicep DCE/DCR/table, Sentinel, ingest and verifier applications |
| `monitoring/setup-firewall-collector.sh` (`BOWER_COLLECTOR_PACKAGE=rpm`, `BOWER_QUEUE_RETENTION_HOURS`) | The RPM collector with RELP listener `a13` |
| `monitoring/setup-firewall-sender.sh`, `update-sender-rsyslog.sh` | nftables, journald, `omrelp` over mutual TLS, rsyslog 8.2610.0 |
| `upgrade-recovery/probe` (`Bower.LabProbe`, new `queue-union` and windowed `native`) | Accepted and native Windows identities |
| `deploy/sentinel/monitoring` | Alert rules and the host health checks |

| New here | Runs on | Does |
|---|---|---|
| `wec-subscription.ps1`, `dc-forwarder.ps1` | Wec, Dc | ws4 subscription/forwarder with 100-event batches and 4 GiB logs |
| `wec-install.ps1` | Wec | MSI from main, `%ProgramData%\Bower\bower.env`, signed pack, health task |
| `rotate-lab-certs.sh` | Linux, Sender | Re-issues the lab CA and certificates for 30 days (same keys) so the shipped 14-day TLS-expiry alert does not fire on lab certificates |
| `generator-windows.ps1`, `dc-agent.ps1` | Dc | Scheduled-task generator (LDAP bind failures) and the 15-minute native exporter of closed hourly windows |
| `sender-generator.sh` | Sender | Transient systemd unit running the segment schedule through `syslog-host.py generate` |
| `collector-agent.sh`, `wec-agent.ps1` | Linux, Wec | 5-minute samples, accepted-identity union every 30 minutes, hourly upload, final export |
| `dc-native-window.ps1` | Dc | On-demand native export for the smoke |
| `reconcile.py` | operator | `fetch`, then `smoke`, `interim` or `final` reconciliation with the verifier identity |

## Schedule

Both generators compute the same segments from the start epoch: 10/sec, and 100/sec for 60
seconds at +7,200 s and every 14,400 s after, steady chunks of at most two hours. A late
segment starts late rather than being skipped, and its actual start is recorded.

## Final collection (after the soak end + 30 minutes)

The agents export by themselves at end + 30 minutes. Then, from the repository root:

```bash
export BOWER_LAB_RUN_ID=bower-soak-20261102-015614 BOWER_LAB_PROFILE=soak \
  BOWER_LAB_CIDR=172.31.247.0/24 BOWER_LAB_DIR=/tmp/bower-soak-20261102-015614
cd lab/aws/upgrade-recovery
python3 lab.py status                       # account, stack and SSM check
python3 lab.py run Linux ../soak/collector-agent.sh env:BOWER_SOAK_ACTION=status
python3 lab.py run Wec ../soak/wec-agent.ps1 ACTION=status SOAK_START=1793590500 SOAK_SECONDS=86400 PROBE_SHA256=<probe sha>
cd ../soak
python3 reconcile.py fetch --lab-dir "$BOWER_LAB_DIR"
python3 reconcile.py final --lab-dir "$BOWER_LAB_DIR" --out "$BOWER_LAB_DIR/final.json"
```

## Cleanup

1. `aws --profile homelab-admin sts get-caller-identity` is `959038055523`; the stack and bucket
   carry `Project=bower-lab` and `RunId=bower-soak-20261102-015614`.
2. Empty the run bucket, `aws cloudformation delete-stack --stack-name bower-soak-20261102-015614`
   and wait for `stack-delete-complete`.
3. `python3 lab/aws/monitoring/azure-environment.py cleanup --state-dir /tmp/bower-soak-20261102-015614/azure --apply --timeout-seconds 1200`
   (the monitoring alert rules live in the same resource group).
4. Run the independent audit (`relp-cleanup-audit.py`, exact not-found codes only) and remove
   `/tmp/bower-soak-20261102-015614`.
