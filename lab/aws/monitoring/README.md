# Monitoring drill harness

Scripts used for the live monitoring and runbook drill
([report](../../../docs/evidence/ws6-20261031-074751/README.md),
[guide](../../../docs/production-readiness/06-monitoring-and-runbooks.md)). They follow
[`lab/aws/AGENTS.md`](../AGENTS.md): one owned stack per run, explicit instance IDs,
account and tag checks before every command, SSM only, no secrets in commands.

| Script | Purpose |
|---|---|
| `stack.py` | CloudFormation: a private subnet in an existing VPC routed to an existing NAT gateway, a no-inbound security group, an encrypted private artifact bucket, one Amazon Linux 2023 and one Windows Server 2022 host (IMDSv2, encrypted disks, terminate on shutdown) and an EventBridge Scheduler expiry that terminates exactly those two instances |
| `run.py` | Runs one reviewed script on `Linux` or `Windows` through SSM after verifying the account, the instance tags and state; records the script hash |
| `upload.sh` | Syncs local drill artifacts to the run's bucket after an account check |
| `linux-setup.sh`, `windows-setup.ps1` | Collector, syslog sender (rsyslog mutual TLS) and nftables fixture; WEC collector-initiated subscription and failed-logon generator; host checks |
| `linux-management.sh` | Management API with development authentication on loopback, token enrolment and approval |
| `drill-linux.sh`, `drill-windows.ps1`, `drill-replay.sh`, `drill-archive.sh` | Fault injection and recovery steps; each prints when it took effect |
| `alerts.py` | Watches Azure Monitor alert instances until one fires or resolves; lists Sentinel incidents |
| Others | Read-only diagnostics (queue states and pages, source counts, rsyslog state) and the recovery used in the drill (`raise-cap.sh`) |

```bash
python3 lab/aws/monitoring/stack.py /tmp/stack.json && uvx cfn-lint==1.57.2 /tmp/stack.json
python3 -m unittest discover -s lab/aws/tests -v
```
