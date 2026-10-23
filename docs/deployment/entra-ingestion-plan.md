# Entra ingestion deployment plan

Prepare deterministic, non-secret inputs without calling Azure:

```sh
python3 deploy/entra/plan_ingestion.py --workspace-name security-law \
  --location australiaeast --create-managed-identity --out artifacts/entra-plan
```

For an existing managed identity, workload identity or service principal, replace
`--create-managed-identity` with `--principal-object-id <object-guid>`. This is the
service principal object ID, not its client ID. Credentials never enter this plan.
The planner rejects ambiguous identity choices and refuses to overwrite a plan.

`ingestion.plan.json` hashes the Bicep bytes and parameter bytes. Review those
exact inputs with Azure what-if in the intended tenant/subscription before an
explicit apply. This command does not run what-if, grant permissions or deploy.
The Bicep template optionally creates a user-assigned identity and grants only
Monitoring Metrics Publisher on this DCR. It does not grant workspace write or
query access. Its output contains identity IDs, endpoint and immutable DCR ID,
never credentials. Attach the identity to collector compute separately.

Configure `BOWER_OUTPUT=azure-logs-ingestion`, `BOWER_AZURE_CREDENTIAL=managed-identity`,
`BOWER_AZURE_CLIENT_ID=<created-client-id>`, `BOWER_DCE_ENDPOINT=<endpoint>`,
`BOWER_DCR_ID=<immutable-id>` and `BOWER_STREAM_NAME=Custom-BowerSecurity`.
For Kubernetes federation use `workload-identity`; off Azure use `environment`
with tenant/client IDs and protected certificate or runtime-injected secret.
Do not use human username/password credentials for unattended ingestion.

After approved deployment and RBAC propagation, run `bower evidence run` with a
separate read-only verifier and the exact workspace ID. See
[evidence bundles](../operations/evidence-bundles.md). Check the returned event ID,
policy hash, intended table, and sanitised target/change/context fields. Capture
negative wrong-DCR/identity tests and recovery evidence. Until those checks run,
delivery remains unverified; local mock tests are simulated only.

For the additive schema update, deploy table/stream/transform together before
relying on new fields. Existing column types and order remain unchanged. Historic
rows lack the new fields. The template's total retention includes archive and
does not itself prove searchable retention.
