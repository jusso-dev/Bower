# Interrupted implementation campaigns and cleanup

Five disposable campaigns were interrupted on 3 November 2026 when their test
agents stopped. Expiry guards stopped the AWS hosts and removed the disposable
EKS cluster. The planned 72-hour re-soak was not started. The earlier dry run
did not receive final reconciliation and does not close the soak gate.

Before cleanup, direct Sentinel queries captured the aggregate event counts in
[destination-counts.json](destination-counts.json). These are destination rows,
not a comparison with generated or accepted identities: they do not prove zero
loss, zero duplication, a successful fault test or production readiness. The
EKS audit campaign also observed platform-generated audit events that require
classification before its detections can be qualified.

The re-soak and implementation artifact buckets held 51 synthetic result files.
All 51 were copied to owner-only local recovery storage and checked against the
S3 object sizes and single-part ETags before their buckets were emptied. These
private files have not been reviewed for public release or fully reconciled.

## Cleanup scope

After the agents stopped, the five run-tagged CloudFormation stacks reached
`DELETE_COMPLETE`; their 109 recorded stack resources also reported deletion.
The four owned S3 buckets, disposable EKS clusters and ECR repository were
checked absent. No run-tagged active EC2 instances, EBS volumes or snapshots
were found; six previously tagged volumes and two network interfaces returned
not-found on exact lookup. The shared VPC and NAT remained available.

The five run-owned Azure resource groups, applications and service principals
were removed. The 22 saved application and principal object IDs returned
not-found from the deleted-items endpoint. The auto-created network watcher
group was removed after confirming it had not existed before this test. Nine
older, tagged Bower test workspaces from this session were recovered and
permanently deleted after retaining aggregate counts where available. No
matching Bower soft-deleted workspaces remained at the final check.

Six of the seven Azure resource providers newly registered for the Azure-hosted
test had returned to `Unregistered` at the last check; `Microsoft.Web` remained
`Unregistering`. Registration is not an active test resource, but restoration
is not yet confirmed. The installed CLI did not support `functionapp deleted list`,
and its `webapp deleted list` request returned not-found while that provider was
unregistering, so deleted Function App history could not be verified. No matching
active storage accounts or soft-deleted key vaults were listed. Twenty identified run-owned local credential files were
removed; default Azure and AWS configuration was preserved.

These checks cover the named test runs in the configured Sydney AWS account and
the selected Azure subscription. They are not an account-wide or all-region
billing audit. Stack-delete retries, the original local cleanup timeouts and the
soft-deleted workspace recovery are preserved in the private recovery record.
