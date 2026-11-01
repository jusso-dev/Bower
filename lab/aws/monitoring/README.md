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

The [2026-11-01 final-candidate qualification snapshot](../../../docs/evidence/ws6-20261101-final/README.md)
records exact firewall and Windows WEC Sentinel reconciliation, preserved failed
attempts, resource sampling and the remaining outage/recovery/cleanup checks.
Its local HTML screenshot is evidence of the rendered report, not a cloud portal.

| Script | Purpose |
|---|---|
| `stack.py` | CloudFormation: a private subnet in an existing VPC routed to an existing NAT gateway, an encrypted private artifact bucket, Linux collector and Windows WEC hosts, and an optional separate Linux firewall sender (`EnableSyslogSender=true`). The current qualification uses all three hosts. IMDSv2, encrypted disks and an expiry schedule apply to every owned host; only the sender can reach the collector's syslog port. |
| `run.py` | Runs one reviewed script on `Linux`, `Windows` or `Sender` through SSM after verifying the account, exact instance ID, run/role tags and state; records the script hash |
| `upload.sh` | Syncs local drill artifacts after checking the account and the bucket's project and run tags |
| `linux-setup.sh`, `windows-setup.ps1` | Collector, syslog sender (rsyslog mutual TLS) and nftables fixture; WEC collector-initiated subscription and failed-logon generator; host checks |
| `linux-management.sh` | Management API with development authentication on loopback, token enrolment and approval |
| `drill-linux.sh`, `drill-windows.ps1`, `drill-replay.sh`, `drill-archive.sh` | Fault injection and recovery steps; each prints when it took effect |
| `alerts.py` | Watches Azure Monitor alert instances until one fires or resolves; lists Sentinel incidents |
| `azure-environment.py` | Prepares/plans/applies the isolated Azure destination, owns separate ingest/verifier applications, and verifies RG/application/service-principal/owned-role cleanup |
| `qualify-azure.py` | Separately validates Azure KQL with explicitly labelled direct synthetic ingestion, then removes its own RG and temporary user role; it is not collector-delivery proof |
| Others | Read-only diagnostics (queue states and pages, source counts, rsyslog state) and the recovery used in the drill (`raise-cap.sh`) |

```bash
python3 lab/aws/monitoring/stack.py /tmp/stack.json && uvx cfn-lint==1.57.2 /tmp/stack.json
python3 -m unittest discover -s lab/aws/tests -v
```

### Clean up the drill after use

The expiry schedule terminates the owned hosts, including the optional sender; it does **not** delete the stack,
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
5. Independently verify every recorded instance ID (`LinuxId`, `WindowsId` and
   `SenderId` when present) is terminated, its EBS
   volumes are deleted, the bucket and expiry schedule are absent, and no
   resources bearing that run's tags remain. Record check results; do not infer
   cleanup from the command returning.
6. Complete the Azure and private-file cleanup below. An AWS stack deletion alone
   does not remove the Azure ingestion destination or local credential copies.

### Remove and independently verify the Azure destination

Use the same private state directory supplied to `azure-environment.py prepare`.
Read its recorded run, RG, workspace, app IDs and principal IDs as metadata;
do not print PEMs, token caches, staging manifests or environment-file contents.
The Azure run name differs from the AWS run name: use its recorded `azure-state.json`,
not a group inferred from the AWS name.

1. Verify the operator's current Azure tenant and target subscription are
   `f4f33fb1-b681-40d1-a854-6f888d45b891` and
   `945092a0-2500-4b25-85a4-99f1c3135906`. The helper checks both the selected
   target and active tenant before Graph/ARM operations. Do not use the
   limited ingestion/verifier principal to administer cleanup.
2. Inspect the exact recorded RG and resources with `az group show` and
   `az resource list`, passing `--subscription 945092a0-2500-4b25-85a4-99f1c3135906`
   and its exact name. Confirm `Project=bower-lab`, the recorded Azure `RunId`
   and that all children are disposable. Stop on an ownership mismatch.
3. Run the reviewed cleanup:

   ```bash
   python3 lab/aws/monitoring/azure-environment.py cleanup \
     --state-dir <private-state-directory> --apply --timeout-seconds 900
   ```

   It reconciles interrupted application creation only when an attempt was
   recorded, checks pinned application/SP IDs, removes those identities and
   their role assignments only within the run RG, requests RG deletion, and
   polls for independent absence. An `ExpiresAt` tag is metadata, not an Azure
   automatic-deletion mechanism. Preserve `cleanupCheckedAt` and `cleanupErrors`
   from state; a nonempty error list or CLI failure means cleanup is incomplete.
4. Independently check `az group exists --name <exact-group> --subscription <sub>`
   is false. For each recorded ingest/verifier app ID, query `az ad app list`
   and `az ad sp list` with `--filter "appId eq '<exact-app-id>'" --query '[].id'`;
   both must be empty. List role assignments for each recorded principal with
   `az role assignment list --all --assignee-object-id <exact-principal-id>
   --subscription <sub>` and inspect only ID/scope metadata. No run-owned grants
   may remain. Investigate any unexpected shared-scope grant; never issue a
   broad tenant/subscription role deletion to make the check pass.
5. If `qualify-azure.py` ran, also preserve its separate `cleanup.json`. Require
   **both** `resourceGroupAbsent=true` and `ingestionRoleAssignmentAbsent=true`,
   with no errors. Its temporary user role is removed by exact assignment ID
   and re-listed after RG deletion. A lost create response is reconciled using
   the recorded user principal and exact disposable DCR scope. Its query-test
   `result.json` alone is not cleanup evidence or collector-delivery evidence.

The destination helper removes its top-level ingest/verifier PEMs and isolated
`azure-cli-ingest`/`azure-cli-verifier` caches on explicit cleanup. It preserves
campaign credentials on a failed `status`, `plan`, `apply` or `sentinel` command
so a transient authentication failure does not destroy an active campaign.
A failed initial prepare still removes its local private files; reconcile any
recorded cloud resources through explicit cleanup. The normal `~/.azure` cache
is never a cleanup target, and cache symlinks are unlinked without following them.

### Remove every private local copy after evidence export

Azure cleanup does **not** remove duplicated ingestion PEMs, collector tokens,
HMAC keys, TLS CA/server/client keys or pack-signing keys in the campaign's
`artifacts/`, `pki/` and `signing/` directories. Removing six top-level PEM files
is insufficient. After AWS/Azure absence is verified, copy only explicitly
reviewed, sanitized reports/screenshots/provenance into an evidence directory
outside the private staging root. Do not recursively copy the staging root into
Git or another evidence store. Preserve failed results and cleanup verification
metadata as well as successful results.

For the disposable combined campaign, the following local-only command removes
the entire protected `/tmp/bower-*` staging root, including duplicated credentials
and isolated token caches. Replace both placeholders with exact absolute paths.
It refuses symlinks, non-private/unowned roots, unrelated root names, absent
campaign markers, or an evidence directory inside the deletion target. It does
not contact a cloud service, so execute it **only after** the checks above pass.

```bash
python3 - <private-staging-root> <sanitized-evidence-directory> <<'PY'
import json, os, shutil, stat, sys
from pathlib import Path
supplied = Path(sys.argv[1]).expanduser()
if supplied.is_symlink():
    raise SystemExit('Refusing a staging symlink')
root = supplied.resolve(strict=True)
evidence = Path(sys.argv[2]).expanduser().resolve(strict=True)
info = root.stat()
allowed_parents = {Path('/tmp').resolve(), Path('/private/tmp').resolve()}
if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or info.st_mode & 0o077 or root.parent not in allowed_parents
        or not root.name.startswith('bower-') or not evidence.is_dir()
        or evidence == root or root in evidence.parents):
    raise SystemExit('Refusing unowned, unprotected or overlapping staging paths')
aws = json.loads((root / 'state.json').read_text())
azure = json.loads((root / 'azure-state.json').read_text())
if (aws.get('account') != '959038055523'
        or azure.get('subscription') != '945092a0-2500-4b25-85a4-99f1c3135906'
        or azure.get('tenant') != 'f4f33fb1-b681-40d1-a854-6f888d45b891'
        or not azure.get('cleanupCheckedAt') or azure.get('cleanupErrors') != []):
    raise SystemExit('Campaign markers or completed Azure cleanup are missing')
shutil.rmtree(root)
print(json.dumps({'privateStagingAbsent': not root.exists(), 'removedRoot': str(root)}))
PY
```

Retain that metadata-only absence result outside the deleted root. Independently
check the root is absent, including `artifacts/`, `pki/`, `signing/` and isolated
CLI caches beneath it. Keep the repository, reviewed evidence directory,
normal Azure CLI cache, shared AWS VPC/NAT and unrelated resources intact.
Final completion requires cloud absence **and** private-staging absence; neither
an expiry schedule nor a cleanup command's successful exit is sufficient alone.

For bounded 15-second process, queue and actual-volume disk evidence throughout the
one-hour outage, follow [RESOURCE-SAMPLING.md](RESOURCE-SAMPLING.md). It includes
separate Linux/Windows smoke tests, background start/status/export commands, full
series hashes, incomplete-run interpretation and teardown requirements.

### Reproduce the owned DCR first-error diagnostic

This sends **one intentionally malformed synthetic request** to the disposable
lab's owned Data Collection Rule (DCR). It is a diagnostic exercise, not collector
or Sentinel delivery qualification. Use an isolated workspace and disable external
alert actions for the exercise. The helper checks the approved tenant/subscription,
run-owned resource-group tags, the separately created ingestion application and
service principal, the DCR and its associated ingestion endpoint before sending.
It uses an owner-only temporary Azure CLI cache and removes that cache on normal
success and handled errors; the normal `~/.azure` cache is not changed.

1. Prepare and apply the disposable Azure environment with `azure-environment.py`.
   Confirm the DCR has a `LogErrors` diagnostic setting targeting the intended
   Log Analytics workspace. Confirm the independent verifier identity can query
   that workspace. Keep state, certificate files and caches private; never print
   them or paste access tokens into a terminal or support report.
2. From the repository root, set `STATE_DIR` to the private state directory and
   run the reviewed helper. `--apply` is mandatory because this deliberately
   sends a malformed request. `--repo` is optional when running from this tree.

   ```bash
   STATE_DIR=/path/to/private/lab-state
   python3 lab/aws/monitoring/probe-dcr-error.py \
     --state-dir "$STATE_DIR" --repo "$PWD" --apply
   ```

   The helper sends a single 31-byte synthetic JSON fragment with a request ID,
   writes a private metadata-only `dcr-malformed-probe-<request-id>.json`, and
   does not print response bodies, headers, or tokens. It never retries the POST.
   **HTTP 204 means accepted for processing**, not that Azure accepted a row or
   emitted a diagnostic. **HTTP 400 means rejected**, not that a diagnostic
   exists. Any other status or a transport error is inconclusive; a timeout may
   have occurred after Azure received the request, so do not automatically resend.
3. In the Azure portal, open the owned resource group and the DCR named for its
   recorded run; copy its resource ID from **Properties**. Open the owned Log
   Analytics workspace's **Logs** view as the independent verifier. Substitute
   the probe report's `startedAt` value and that DCR ID into this bounded query,
   using the deployed alert's time window:

   ```kusto
   DCRLogErrors
   | where TimeGenerated >= datetime(<probe-startedAt-UTC>)
   | where _ResourceId =~ '<exact-run-owned-DCR-resource-id>'
   | summarize Errors = count(), LastError = max(TimeGenerated)
       by Operation = substring(OperationName, 0, 128)
   | where Errors > 0
   ```

   Do not print error-message fields, which can echo input. Query failures,
   missing tables, incomplete or paginated results, and a zero count are **not**
   passes. Allow for ingestion delay and repeat the read-only query if necessary;
   do not repeat the malformed POST automatically. A count from the same DCR and
   interval is evidence of a DCR error, but may include other requests unless you
   can correlate the diagnostic with the recorded request ID or otherwise isolate
   the source. Save a redacted query hash, time and count separately. The helper's
   report always leaves `diagnosticQueryVerified` false; record the independent
   check separately rather than editing the original report into a pass.
4. Use the documented Azure cleanup procedure above. Verify the run-owned resource
   group, applications, service principals and role assignments are absent, then
   remove private state and all dedicated CLI caches. If a process was killed
   before its `finally` block, inspect the private state directory for leftover
   `dcr-probe-cli-*` directories and remove only those owned by this run. Do not
   delete the normal Azure CLI cache.

A prior disposable-lab run received HTTP 204 and subsequently observed one
`Transformation` error from the scoped DCR at `2026-11-01T03:00:10.8560931Z`.
An earlier report expected HTTP 400; preserve that original failed assumption
as historical evidence. No HTTP 400 was observed in the later positive diagnostic.
