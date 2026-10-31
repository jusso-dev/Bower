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
permanent failures. A credential that cannot obtain a token fails as retryable
`destination-azure-credential-failed`; a missing role is `destination-azure-http-403`.
Remote authentication, DCR/stream configuration, throttling,
transport and server failures pause delivery through a durable destination circuit.
Retry-After survives terminal SDK retries and collector restart. Configuration
outages do not consume per-record poison budgets. Ambiguous HTTP 400 batches use
bounded isolation; unresolved singletons remain pending for operator investigation.
Queue/storage limits apply producer backpressure rather than deleting pending
records. See [outage recovery and historical reconciliation](../operations/azure-sdk-recovery.md).

## Adaptive request concurrency

Each output (one DCR stream) runs an AIMD controller over its upload requests, in
C# and Rust alike. `MaximumConcurrency` / `maximum_concurrency` (1 to 32, default
4) is the ceiling and the starting limit, so the healthy case is never slower than
the old fixed setting. The minimum is 1. The collector uses one controller for the
whole output (`ConcurrencyScope.Output`), because its single delivery loop is the only
caller. The Azure Functions host delivers up to `httpPerInstanceConcurrency` caller
requests at once through one output, so it uses `ConcurrencyScope.Delivery`: each
request gets its own controller, bounded as the fixed setting was.

- Decrease: halve the limit on 429, 5xx, 408, network timeout or transport failure;
  cut it by a quarter on a latency spike (RTT above twice the EWMA and at least
  250 ms above it, judged after four samples; EWMA weight 0.25). At most one
  decrease per window: attempts started before the last decrease do not count.
- Increase: one slot after `limit` consecutive healthy attempts in the current
  window, up to the ceiling.
- Every attempt, including Azure.Core / pipeline retries, is observed after the
  token is obtained. Other 4xx responses and caller cancellation are neutral.
- `Retry-After` (and `retry-after-ms`) on any failed attempt pauses the stream: no
  further batch of that delivery starts before the deadline. That includes short
  delays (60 s or less) that the SDK / retry loop waits out in memory before retrying
  the same batch. Unsent batches fail as
  retryable `destination-azure-paused` with that deadline, which opens the durable
  destination circuit (see [queue v5 durability](../operations/queue-v5-durability.md#throttling-and-pauses)).
- Back-pressure is a wait for a request slot over the already-leased batch, in batch
  order. Nothing is buffered beyond it; queue byte caps still return 503 to
  producers. No change to acknowledgement, dead-letter or ledger semantics.

The controller is deterministic: it takes RTT and time from its caller (C#
`TimeProvider`, Rust `IngestionClientOptions::time`), with no randomness. `/v1/status` (bearer token) adds a `delivery`
block, omitted for outputs without adaptive concurrency:

```json
"delivery": {"outputId": "azure-logs-ingestion", "limit": 2, "minimumLimit": 1,
  "maximumLimit": 4, "inFlight": 1, "latencyEwmaMilliseconds": 163, "requests": 9,
  "throttles": 3, "serverErrors": 1, "timeouts": 0, "latencySpikes": 1,
  "decreases": 2, "increases": 1, "pauses": 1,
  "processLocalPausedUntil": "2026-07-26T02:16:19+00:00"}
```

Counters are since start and metadata only: no payloads, event IDs or response
bodies. The whole block is process-local and resets on restart.
`processLocalPausedUntil` is this process's latest Retry-After deadline, null once
it passes. It is not the durable pause: after a restart the queue's destination
circuit still holds the stream (retrying `destination-*` rows, see
`/v1/status` `queue.retrying`) while this field reads null. The Functions host
reports no block because it keeps no output-wide controller. Tests: shared controller
trace (C# `AdaptiveConcurrencyTests`, Rust `adaptive_concurrency.rs`), and a fake
ingestion endpoint injecting 429, 503, latency and `Retry-After`, through the real
SQLite queue and delivery worker (no loss, no premature acknowledgement, no
dead-lettering of retryable events, cancellation releases every slot). Not
verified against a live Azure endpoint.

Rotate and revoke ingestion credentials with the
[credential rotation runbook](../production-readiness/05-credential-rotation-and-security-failures.md):
secrets, certificates and environment variables are read when the process starts
(restart to apply), while a cached access token keeps working until it expires
(measured 62–67 minutes after issue).

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
