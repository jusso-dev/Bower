# README-ready notes: Azure Functions collector (vanilla native hosting)

Lead-owned README integration input. `artifacts/` is git-ignored; this file is
force-added on `feat/azure-function-20261024`. Full guide:
`docs/deployment/azure-function.md`.

## Suggested README section

### Serverless intake on Azure Functions

Run Bower as a native C# Azure Function (isolated worker, .NET 10, Flex
Consumption) when you want a central, tenant-owned intake without a VM, container
or queue. Producers POST the same `/v1/events` envelope as to the HTTP collector,
authenticated with Microsoft Entra tokens that carry the application-only
`Bower.Producer` role; producer scopes bind each caller (`oid`) to the event
identities it may assert. The function runs the same redaction, privacy profile,
default-deny policy and privacy-alert logic as the collector, then uploads to
Microsoft Sentinel through the Logs Ingestion API with its managed identity
(system-assigned by default) holding Monitoring Metrics Publisher on the DCR only.
No storage keys, connection strings or client secrets.

It answers `202` only after Logs Ingestion accepted the event; otherwise `503`
or `429` with `Retry-After` and nothing kept, so producers retry (at-least-once;
de-duplicate by `EventId` in KQL). There is no durable queue, ledger, duplicate
collapse or management heartbeat; use the HTTP collector where you need those.

```bash
az bicep build --file deploy/azure-function/main.bicep --stdout > /dev/null
az deployment group what-if --resource-group <rg> \
  --template-file deploy/azure-function/main.bicep \
  --parameters dcrResourceId=<dcr-resource-id> logsIngestionEndpoint=<https://...ingest.monitor.azure.com> \
               entraTenantId=<tenant-guid> entraAudience=<ingest-api-client-id> \
               producerScopesJson="$(cat producer-scopes.json)"
```

## Settings table (README size)

| Setting | Default | Purpose |
|---|---|---|
| `BOWER_ENTRA_TENANT_ID` | required | Tenant GUID issuing producer tokens. |
| `BOWER_ENTRA_AUDIENCE` | required | Bower Ingest API client ID (exact v2 `aud`). |
| `BOWER_PRODUCER_SCOPES_JSON` / `_FILE` | deny all | Producer scopes (same format as the collector). |
| `BOWER_PRODUCER_CLAIM` | `oid` | `oid` or `azp` identifies the producer. |
| `BOWER_DCE_ENDPOINT`, `BOWER_DCR_ID`, `BOWER_STREAM_NAME` | required, required, `Custom-BowerSecurity` | Logs Ingestion target (Bicep fills the DCR immutable ID). |
| `BOWER_AZURE_CLIENT_ID` | system-assigned | User-assigned identity client ID for Logs Ingestion. |
| `BOWER_PRIVACY_PROFILE`, `BOWER_PACKS`, `BOWER_PACK_TRUSTED_KEYS` | defaults | Packaged privacy profile / signed packs (`config/`). |
| `BOWER_DELIVERY_TIMEOUT_SECONDS` | `30` | Upload bound before answering 503. |
| `BOWER_DEVELOPMENT_AUTH` | `false` | Local only; refused outside `AZURE_FUNCTIONS_ENVIRONMENT=Development`. |

## Deployment parameters (`deploy/azure-function/main.bicep`)

`location` (`australiaeast`), `namePrefix` (`bower`), `dcrResourceId`,
`logsIngestionEndpoint`, `streamName`, `entraTenantId`, `entraAudience`,
optional `userAssignedIdentityResourceId`, `producerClaim`, `producerScopesJson`,
`privacyProfilePath`, `applicationInsightsWorkspaceResourceId`,
`maximumInstanceCount`, `instanceMemoryMB`, `httpPerInstanceConcurrency`,
`storageSku`.

## Entra change

New single-tenant registration manifest `deploy/entra/ingest-api-app-manifest.json`
("Bower Ingest API") with one application-only role `Bower.Producer`
(`12859e27-8403-42a7-b3e4-66cc808de79f`, stable). The management API manifest is
unchanged.
