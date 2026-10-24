# Logs Ingestion API mode

Configure HTTPS DCE endpoint, immutable DCR ID and stream name. Choose exactly
one credential source with `BOWER_AZURE_CREDENTIAL` (`managed-identity` default,
`workload-identity`, `environment`, `azure-cli` for development). Set
`BOWER_AZURE_CLIENT_ID` for a user-assigned managed identity. Assign only the
Monitoring Metrics Publisher (DCR data sender) role on the required rule.

```text
BOWER_OUTPUT=azure-logs-ingestion
BOWER_DCE_ENDPOINT=https://<name>.<region>.ingest.monitor.azure.com
BOWER_DCR_ID=dcr-<immutable-id>
BOWER_STREAM_NAME=Custom-BowerSecurity
```

Bower builds bounded requests and tracks the event IDs belonging to each request;
concurrent completion cannot attach another batch's failure to those IDs. C# uses
the supported Azure SDK protocol upload API; Rust owns its HTTP batches. Successful
responses yield `azure-logs-ingestion:accepted:owned-batches`. This records API
acceptance only, never Sentinel queryability.

Local malformed/mismatched payloads and failed schema preflight are individual
permanent failures. Remote authentication, DCR/stream configuration, throttling,
transport and server failures pause delivery through a durable destination circuit.
Retry-After survives terminal SDK retries and collector restart. Configuration
outages do not consume per-record poison budgets. Ambiguous HTTP 400 batches use
bounded isolation; unresolved singletons remain pending for operator investigation.
Queue/storage limits apply producer backpressure rather than deleting pending
records. See [outage recovery and historical reconciliation](../operations/azure-sdk-recovery.md).

Use the [Entra ingestion planner](entra-ingestion-plan.md) for exact-DCR sender
RBAC and optional managed identity/federation. An existing Log Analytics workspace
and permission to create the reviewed table/DCE/DCR are prerequisites. Keep ingest
identity separate from the read-only query verifier. Never persist access tokens
or put credentials in arguments/source-controlled configuration.

Current templates and audience defaults target Azure public cloud. DNS and TLS
access to the selected ingestion endpoint and Entra token service are required;
private endpoint deployments must provide their own approved DNS/network route.
Do not point public-cloud credentials at a sovereign-cloud endpoint and claim it
supported: authority, ingestion audience, query/ARM hosts and deployment APIs need
a separately tested cloud configuration. No network or identity proof is implied
by template compilation.
