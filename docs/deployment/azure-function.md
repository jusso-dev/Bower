# Azure Functions collector (vanilla native hosting)

`src/Bower.Functions.Collector` is a serverless Bower collector: a native C# Azure
Function (isolated worker, .NET 10) on the Flex Consumption plan. Producers POST
the same `/v1/events` envelope they send to the HTTP collector, authenticated with
Microsoft Entra access tokens. The function validates, applies the default-deny
policy and the Privacy & Secret Protection Engine, then uploads to a Log Analytics
workspace / Microsoft Sentinel through the existing Azure Monitor Logs Ingestion
output, authenticating with its managed identity.

Use it when you want a central, tenant-owned intake with no VM, container or
queue to operate. Keep the [HTTP collector](logs-ingestion-api.md) where you need
the durable queue, tamper-evident ledger, offline buffering, management
heartbeats or AMA spool output.

## Architecture

```text
producer (managed identity / service principal with Bower.Producer)
  │  POST /v1/events  Authorization: Bearer <Entra v2 token for the Bower Ingest API>
  ▼
Azure Functions (Flex Consumption, Linux, dotnet-isolated 10.0, HTTPS only, TLS ≥ 1.2)
  1. Entra token validation in code (signature via OIDC keys, v2 issuer + tid,
     exact audience, lifetime, app-only Bower.Producer role)          → 401 / 403
  2. Content-Type, 1 MiB bound, UTF-8 + JSON parse                    → 415 / 413 / 400
  3. Producer scope: caller oid (or azp) must own the event identity  → 403
  4. SecurityEventProcessor (unchanged): redact → validate → policy → privacy alert
     into a per-request in-memory buffer                              → 400 / 422
  5. AzureLogsIngestionOutput (unchanged) uploads the buffer with the managed identity
       all records acknowledged                                       → 202
       throttled                                                      → 429 + Retry-After
       transient / timeout / partial                                  → 503 + Retry-After
       permanent (preflight, size, isolated 400)                      → 422
  ▼
DCR (Monitoring Metrics Publisher on this DCR only) → BowerSecurity_CL / Sentinel
```

The function reuses Bower libraries rather than forking them: `PolicyBundle`
(policies, signed packs, privacy profile), `JsonEventRedactor` with the loaded
`PrivacyPolicy` (so custom privacy profiles and detectors behave exactly as in the
collector), `PackDetectionRedactor`, `SecurityEventProcessor`,
`ProducerAuthorization` and `AzureLogsIngestionOutput`. `PolicyBundle` moved to
`Bower.Packs` and `ProducerAuthorization` to `Bower.Core` for this; the HTTP
collector's behaviour is unchanged.

## Endpoints and responses

| Route | Auth | Purpose |
|---|---|---|
| `POST /v1/events` | Entra, `Bower.Producer` + producer scope | Same envelope and status classes as the collector. |
| `GET /health` | Anonymous | `{"status":"healthy"}` only. No configuration or delivery detail. |
| `GET /v1/status` | Entra, `Bower.Producer` | Metadata only: mode, policy hash/ids, pack ids, privacy profile id, output, stream, credential kind, `durableQueue:false`, `ledger:false`, number of scopes. |

Ingest responses keep the collector fields (`eventId`, `decision`, `queued`,
`duplicate`, `reasons`, `policy`) and add `delivered`. `queued` is always `false`
(there is no queue); `delivered:true` means the Logs Ingestion API accepted every
record staged for the request. `202` is never returned before that
acknowledgement. Reasons never contain payload values.

Function-level keys are not used (`AuthorizationLevel.Anonymous`): they are shared
secrets. Every protected route validates the Entra token in code and fails closed.

## Settings

The Bicep template sets these app settings; names match the HTTP collector where
the meaning is the same. Missing or unsafe authentication settings stop the worker.

| Setting | Required | Default | Notes |
|---|---|---|---|
| `BOWER_ENTRA_TENANT_ID` | yes | — | Tenant GUID. `common`/`organizations` are refused. |
| `BOWER_ENTRA_AUDIENCE` | yes | — | Bower Ingest API **client ID** (v2 `aud`). No wildcards. |
| `BOWER_PRODUCER_CLAIM` | no | `oid` | `oid` (service principal object ID) or `azp` (client ID) names the producer in scopes. |
| `BOWER_PRODUCER_SCOPES_JSON` | one of | empty (deny all) | Producer scopes JSON array, same format as the collector file. Not a secret. |
| `BOWER_PRODUCER_SCOPES_FILE` | one of | — | Packaged file path (relative paths resolve next to the worker). Mutually exclusive with `_JSON`. |
| `BOWER_DCE_ENDPOINT` | yes | — | HTTPS Logs Ingestion endpoint. |
| `BOWER_DCR_ID` | yes | — | DCR immutable ID (`dcr-…`); Bicep reads it from `dcrResourceId`. |
| `BOWER_STREAM_NAME` | no | `Custom-BowerSecurity` | Must be a `Custom-` stream. |
| `BOWER_AZURE_CREDENTIAL` | no | `managed-identity` | `azure-cli` only when `AZURE_FUNCTIONS_ENVIRONMENT=Development`. Nothing else. |
| `BOWER_AZURE_CLIENT_ID` | no | empty | User-assigned identity client ID; empty = system-assigned. |
| `BOWER_POLICY_DIRECTORY` | no | `policies/default` (packaged) | Default Bower policies ship in the package. |
| `BOWER_PRIVACY_PROFILE` | no | default profile | Packaged YAML, e.g. `config/privacy.yaml`. |
| `BOWER_PRIVACY_HMAC_KEY_FILE`, `BOWER_PRIVACY_HMAC_KEY_ID` | for `hmac` actions | —, `k1` | See limits: no secret file is deployed by the template. |
| `BOWER_PACKS`, `BOWER_PACK_TRUSTED_KEYS` | no | — | Signed packs and trusted public keys in `config/`; unsigned packs are refused. |
| `BOWER_DELIVERY_TIMEOUT_SECONDS` | no | `30` | 5–120. Upload not acknowledged in time → 503. |
| `BOWER_COLLECTOR_ID` | no | `azure-function:<site>` | Stamped on `collector.id`. |
| `BOWER_DEVELOPMENT_AUTH` | no | `false` | Local only. Refused unless `AZURE_FUNCTIONS_ENVIRONMENT=Development`; never set by Bicep. |
| `AZURE_FUNCTIONS_ENVIRONMENT` | — | `Production` | Pinned to `Production` by Bicep. |
| `AzureWebJobsStorage__accountName` | yes | — | Identity-based host storage; no connection string. |
| `FUNCTIONS_REQUEST_BODY_SIZE_LIMIT` | — | `1048576` | Host-level body bound in addition to the worker's 1 MiB check. |

`collector.sourceAdapter` on every delivered row is `azure-function:<producer>`,
so Sentinel shows which Entra identity sent the event (never the token).

## Entra setup

1. Create the **Bower Ingest API** registration from
   [`deploy/entra/ingest-api-app-manifest.json`](../../deploy/entra/ingest-api-app-manifest.json):
   single tenant, `requestedAccessTokenVersion: 2`, no delegated scopes, one
   application-only role `Bower.Producer` (`12859e27-8403-42a7-b3e4-66cc808de79f`,
   a stable contract ID; never regenerate it). Replace the placeholder identifier
   URI with `api://<ingest-client-id>`. No client secret is needed: the function only
   validates tokens. The management API registration is separate; its tokens are
   refused by audience.
2. Assign `Bower.Producer` to each producer identity (managed identity or service
   principal) on the Bower Ingest API enterprise application, for example:

   ```bash
   az rest --method POST \
     --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<producer-sp-object-id>/appRoleAssignments" \
     --body '{"principalId":"<producer-sp-object-id>","resourceId":"<ingest-api-sp-object-id>","appRoleId":"12859e27-8403-42a7-b3e4-66cc808de79f"}'
   ```

3. Add one producer scope per producer `oid` (the managed identity's
   `principalId`) and exact event identity tuple; see
   [producer scopes](../security/producer-scopes.md). Without a matching scope,
   ingest returns 403 before redaction, policy or delivery.
4. Producers request tokens for `api://<ingest-client-id>/.default` with their own
   managed identity and send them as `Authorization: Bearer …`.

## Managed identity and role assignments

| Identity | Role | Scope | Why |
|---|---|---|---|
| Function system-assigned identity (or the user-assigned identity, if given) | Monitoring Metrics Publisher | the one DCR | Logs Ingestion upload. Nothing broader. |
| Function system-assigned identity | Storage Blob Data Owner | the function's own storage account | Host state, keys and the Flex deployment package container. |
| Function system-assigned identity (only with Application Insights) | Monitoring Metrics Publisher | the Application Insights component | Entra-authenticated telemetry (`DisableLocalAuth: true`). |

Storage has shared key access disabled, blob public access off, HTTPS only and
TLS 1.2 minimum. The site is HTTPS only with minimum TLS 1.2 (also for SCM), and
FTP and SCM basic-auth publishing credentials are disabled (Flex Consumption has
no FTPS at all). No keys, connection strings or client secrets are created or
output. A user-assigned identity is used only for Logs Ingestion; host storage
and the deployment package always use the system-assigned identity.

## Build, plan and deploy

Plan-only by default (see `deploy/AGENTS.md`). Build locally without Core Tools:

```bash
dotnet restore --locked-mode
dotnet build src/Bower.Functions.Collector --configuration Release
dotnet publish src/Bower.Functions.Collector --configuration Release --output artifacts/function
(cd artifacts/function && zip -r ../bower-function.zip .)
az bicep build --file deploy/azure-function/main.bicep --stdout > /dev/null
```

Review the plan first, in the intended tenant and subscription:

```bash
az deployment group what-if \
  --resource-group <rg> \
  --template-file deploy/azure-function/main.bicep \
  --parameters namePrefix=bower \
               dcrResourceId=/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/bower-dcr \
               logsIngestionEndpoint=https://<dce>.australiaeast-1.ingest.monitor.azure.com \
               entraTenantId=<tenant-guid> entraAudience=<ingest-client-id> \
               producerScopesJson="$(cat producer-scopes.json)"
```

Only with explicit apply intent, after reviewing what-if:

```bash
az deployment group create --resource-group <rg> --template-file deploy/azure-function/main.bicep --parameters …
az functionapp deployment source config-zip --resource-group <rg> --name <functionAppName> --src artifacts/bower-function.zip
```

`location` defaults to `australiaeast` (check Flex Consumption availability for
other regions). The DCR may live in another resource group or subscription; the
role assignment is deployed at the DCR itself. Verify after deployment: `/health`
returns 200, an authenticated canary returns 202, and a separate reader identity
finds it in `BowerSecurity_CL` (upload acceptance is not proof of queryability).

Optional parameters: `userAssignedIdentityResourceId`, `producerClaim`,
`privacyProfilePath`, `applicationInsightsWorkspaceResourceId`,
`maximumInstanceCount` (40), `instanceMemoryMB` (2048),
`httpPerInstanceConcurrency` (16), `storageSku` (`Standard_ZRS`).

## Delivery and duplicate semantics

There is no local durable queue. A request succeeds only after the Logs Ingestion
API accepted every record staged for it (the event and, when the privacy engine
raised one, its privacy alert). Otherwise the function answers 503 (or 429 when
Azure throttles) with `Retry-After`, keeps nothing, and the producer retries:
**at-least-once**. Bower forwarders (`Bower.Forwarding`) already treat 429/503 as retry and
202/400/413/422 as final; the SDK surfaces any non-success status to the caller.

A retry after a partial or ambiguous outcome (for example a timeout after Azure
accepted the upload) can duplicate rows. Event IDs are stable and privacy-alert
IDs are derived from the source event, so de-duplicate by `EventId` in KQL:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(1d)
| summarize arg_min(ingestion_time(), *) by EventId
```

Logs Ingestion limits are enforced by the existing output unchanged: 1 MiB per
upload, schema preflight (lengths, types), owned batches and Retry-After handling.
SDK retries are bounded (2 retries, ≤ 4 s back-off, 20 s network timeout) and the
whole delivery is bounded by `BOWER_DELIVERY_TIMEOUT_SECONDS`, so producers see a
prompt 503 instead of a long hold. Permanent record failures (preflight, oversized
row, isolated HTTP 400) return 422 with the failure code. An ambiguous single
record HTTP 400 returns 503: check the DCR and stream before replaying.

## Limits compared with the HTTP collector

| Capability | HTTP collector | Azure Functions collector |
|---|---|---|
| Durable queue, offline buffering, backpressure by queue size | yes | **no** – producers must retry and buffer |
| Tamper-evident ledger, dead-letter queue, replay | yes | **no** |
| Duplicate collapse (200 on repeat) and event-identity conflict detection (409) | yes | **no** – de-duplicate by `EventId` in KQL |
| Management registration and heartbeat | optional | **no** (not implemented) |
| Background jobs | yes | none |
| AMA spool output | yes | no – Logs Ingestion only |
| Producer auth | per-producer bearer tokens | Entra app role + producer scopes |
| Rate limiting | per-collector token bucket | Flex `maximumInstanceCount` × `httpPerInstanceConcurrency`; Azure throttling surfaces as 429 |
| Pack parser endpoints (`/v1/packs/...`) | yes | no |
| Native AOT | yes | no – the Functions host runs the framework-dependent isolated worker; AOT analysers still run on Bower libraries |

Keyed-hash (`hmac`) privacy actions need an HMAC key file. The template deploys
no secrets, so profiles using `hmac` fail start-up unless you supply the key
through your own reviewed secret delivery (for example a Key Vault-backed file
mount); profiles without `hmac` need nothing extra.

## Logging and privacy

The worker logs only metadata (failure codes and counts). It never logs payloads,
tokens, claims or exception text; Entra and Azure SDK exception messages are
dropped because they can carry secrets. `host.json` sets warning-level logging,
disables Application Insights sampling and dependency tracking, and the template
creates Application Insights only when a workspace is given, with local auth
disabled. Request bodies are never written to storage.

## Local development

Core Tools (`func start`) sets `AZURE_FUNCTIONS_ENVIRONMENT=Development`. Only then
may `BOWER_DEVELOPMENT_AUTH=true` (every caller becomes producer `development`)
and `BOWER_AZURE_CREDENTIAL=azure-cli` be used. Use a scratch DCR and never point a
development bypass at a production workspace. Unit tests
(`tests/Bower.Functions.Collector.Tests`) run fully offline with fake Entra keys and
in-memory Logs Ingestion transports.
