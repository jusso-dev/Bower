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

For a new workload identity, add `--federation-issuer <exact-https-issuer>` and
`--federation-subject system:serviceaccount:<namespace>:<service-account>` to the
managed-identity plan. Both values are required together; wildcards are rejected.
The template binds exactly that tuple with audience `api://AzureADTokenExchange`.
It does not enable an issuer, install a webhook, modify Kubernetes service
accounts or provision credential files. Confirm issuer ownership and exact subject
in the review. Existing principals keep their separately managed federation.

Configure `BOWER_OUTPUT=azure-logs-ingestion`, `BOWER_AZURE_CREDENTIAL=managed-identity`,
`BOWER_AZURE_CLIENT_ID=<created-client-id>`, `BOWER_DCE_ENDPOINT=<endpoint>`,
`BOWER_DCR_ID=<immutable-id>` and `BOWER_STREAM_NAME=Custom-BowerSecurity`.
For Kubernetes federation use `workload-identity`; off Azure use `environment`
with tenant/client IDs and protected certificate or runtime-injected secret.
Do not use human username/password credentials for unattended ingestion.
`environment` credentials use `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` plus either
`AZURE_CLIENT_CERTIFICATE_PATH` (and protected certificate password when needed)
or runtime-injected `AZURE_CLIENT_SECRET`. Mount certificate/token files read-only
with least-privilege filesystem access; keep their values out of CLI arguments,
plans and logs. Workload identity uses projected `AZURE_FEDERATED_TOKEN_FILE` with
`AZURE_TENANT_ID` and `AZURE_CLIENT_ID`. Collector `BOWER_AZURE_CLIENT_ID` selects
its managed identity; it is not a substitute for the environment credential fields.
See [network and cloud prerequisites](logs-ingestion-api.md).

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

## Destination field acceptance check

After authorised provisioning, emit a role-change fixture through a scoped
producer and keep its generated event ID. Use a separate read-only identity in
the intended workspace to run this query with the fixture's expected values:

```kusto
let expectedEventId = "REPLACE_WITH_EMITTED_EVENT_ID";
let expectedTarget = "fixture-member";
let expectedRole = "fixture-auditor";
BowerSecurity_CL
| where TimeGenerated > ago(1d) and EventId == expectedEventId
| project EventId, PolicyHash, EventType,
    TypeMatches = EventType == "role_membership_changed",
    TargetMatches = tostring(Target.id) == expectedTarget,
    ChangeMatches = tostring(Change.newValue) == expectedRole,
    HasPolicy = isnotempty(PolicyHash)
```

Require a row with all booleans true and the expected policy hash. A successful
upload with zero rows or a missing field fails this gate. Retain only event ID,
policy hash, booleans, workspace/table identity, query time and exact revision in
the evidence record. Do not export event payloads. Run the sensitive-export
fixture separately and assert `tolong(Attributes.recordCount)` equals its known
synthetic count. The built-in canary proves arrival; these representative fixtures
separately prove application field preservation. Neither establishes historical
completeness, secret absence across arbitrary inputs or regulatory compliance.
