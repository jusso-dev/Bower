# Bower.Functions.Collector instructions

Serverless Bower collector on Azure Functions (isolated worker, .NET 10, Flex
Consumption). Same `/v1/events` contract as `Bower.Collector`, no durable queue.

- `CollectorFunctions` is a thin HTTP trigger adapter; logic lives in the
  framework-free `FunctionCollector` so tests run without the Functions host.
- Auth is Entra only, validated in code (`EntraProducerAuthenticator`): v2 issuer and
  `tid`, exact audience, RS256 signature from OIDC metadata, lifetime, application-only
  `Bower.Producer` role. Function keys stay unused (`AuthorizationLevel.Anonymous`).
  Never weaken `FunctionSettings.Validate`; the development bypass is refused outside
  `AZURE_FUNCTIONS_ENVIRONMENT=Development` and must never appear in the Bicep.
- Producer scopes reuse `Bower.Core.ProducerAuthorization` unchanged; missing scope denies
  before redaction, policy or delivery.
- Processing reuses `SecurityEventProcessor`, `PolicyBundle` and `PackDetectionRedactor`
  unchanged. Do not fork redaction, validation or policy logic here.
- `RequestEventBuffer` lives for one request only. Never persist, cache or log payloads,
  tokens or exception text. Answer success only after Logs Ingestion acknowledged every
  staged record; otherwise 503/429 with Retry-After (or 422 for permanent rejection).
- Logs Ingestion uses exactly one managed identity credential (system-assigned unless
  `BOWER_AZURE_CLIENT_ID` names a user-assigned identity). No secrets or chains.
- Bound every input: 1 MiB body, 16 KiB token, delivery timeout, SDK retries.
