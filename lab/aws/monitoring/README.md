# Monitoring drill harness

Scripts used for the live monitoring and runbook drill
([report](../../../docs/evidence/ws6-20261031-074751/README.md),
[guide](../../../docs/production-readiness/06-monitoring-and-runbooks.md)). They follow
[`lab/aws/AGENTS.md`](../AGENTS.md): one owned stack per run, explicit instance IDs,
account and tag checks before host commands, SSM only, and no secrets in SSM
command text. The archive replay CLI currently reads its ingest token from the
child process environment; that token may be visible to sufficiently privileged
local processes. Restrict access to the isolated lab host and treat this as a lab
security limitation. Do not include the environment or token in command output.

| Script | Purpose |
|---|---|
| `stack.py` | CloudFormation: a private subnet in an existing VPC routed to an existing NAT gateway, a no-inbound security group, an encrypted private artifact bucket, one Amazon Linux 2023 and one Windows Server 2022 host (IMDSv2, encrypted disks, terminate on shutdown) and an EventBridge Scheduler expiry that terminates exactly those two instances |
| `run.py` | Runs one reviewed script on `Linux` or `Windows` through SSM after verifying the account, the instance tags and state; records the script hash |
| `upload.sh` | Syncs local drill artifacts after checking the account and the bucket's project and run tags |
| `linux-setup.sh`, `windows-setup.ps1` | Collector, syslog sender (rsyslog mutual TLS) and nftables fixture; WEC collector-initiated subscription and failed-logon generator; host checks |
| `linux-management.sh` | Management API with development authentication on loopback, token enrolment and approval |
| `drill-linux.sh`, `drill-windows.ps1`, `drill-replay.sh`, `drill-archive.sh` | Fault injection and recovery steps; each prints when it took effect |
| `alerts.py` | Watches Azure Monitor alert instances until one fires or resolves; lists Sentinel incidents |
| Others | Read-only diagnostics (queue states and pages, source counts, rsyslog state) and the recovery used in the drill (`raise-cap.sh`) |

```bash
python3 lab/aws/monitoring/stack.py /tmp/stack.json && uvx cfn-lint==1.57.2 /tmp/stack.json
python3 -m unittest discover -s lab/aws/tests -v
```

### Clean up the drill after use

The expiry schedule terminates the two hosts; it does **not** delete the stack,
bucket, IAM resources, subnet or schedule. Complete these steps at the end of
every run. The existing VPC and NAT gateway are shared inputs and must be left
alone. AWS credentials use the `homelab-admin` profile and Sydney region.

1. Read the run state file used for the drill and obtain its `runId`, `stack`
   and `outputs.Bucket`. Check the account with `aws --profile homelab-admin
   --region ap-southeast-2 sts get-caller-identity` and confirm it is
   `959038055523`. Stop if the account or run is unexpected.
2. Inspect the exact stack by name with `aws --profile homelab-admin --region
   ap-southeast-2 cloudformation describe-stacks --stack-name <stack>`. Confirm
   its `Project=bower-lab` and `RunId=<runId>` tags. Inspect the bucket's tags
   with `aws --profile homelab-admin --region ap-southeast-2 s3api
   get-bucket-tagging --bucket <bucket>` and confirm the same tags. Stop on any
   mismatch. Review which files need to be retained outside AWS before deletion.
3. After confirming the bucket is the one owned by this run, empty it with
   `aws --profile homelab-admin --region ap-southeast-2 s3 rm s3://<bucket> --recursive`.
   The generated bucket is unversioned; if versioning was enabled separately,
   remove its versions and delete markers too before deleting the stack.
4. Delete only the verified stack with `aws --profile homelab-admin --region
   ap-southeast-2 cloudformation delete-stack --stack-name <stack>`, then wait
   with `aws --profile homelab-admin --region ap-southeast-2 cloudformation
   wait stack-delete-complete --stack-name <stack>`. Investigate any failed
   deletion; instance expiry is not a substitute.
5. Independently verify the recorded instance IDs are terminated, their EBS
   volumes are deleted, the bucket and expiry schedule are absent, and no
   resources bearing that run's tags remain. Record check results; do not infer
   cleanup from the command returning.
6. For Azure, select the authorised subscription with `az account set --subscription
   945092a0-2500-4b25-85a4-99f1c3135906`, then verify `az account show` reports
   tenant `f4f33fb1-b681-40d1-a854-6f888d45b891` and the expected subscription.
   Inspect the drill's recorded resource-group name with `az group show --name
   <drill-resource-group>` and `az resource list --resource-group
   <drill-resource-group> --output table`. Confirm ownership and that all listed
   resources are disposable before `az group delete --name <drill-resource-group>
   --yes`. Wait for deletion and verify with `az group exists --name
   <drill-resource-group>`. Separately check the run inventory for resources outside
   the group, such as application identities or role assignments, and remove only
   those created for this run. Record the independent results.
