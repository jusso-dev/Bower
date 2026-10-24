# Evidence bundles

`bower evidence run` proves that Bower delivery works end to end, in a form an
assessor can check. Azure's ingestion API, Elastic's Logstash plugin and Cribl all
stop at "the API accepted it"; a Bower bundle shows the event was **queried back out
of Sentinel**.

## What it does

1. Sends a synthetic `collector_canary` event to the collector with the producer
   token. It passes redaction, policy (`BWR-POL-EVIDENCE-CANARY`), the durable
   queue and the configured output exactly like real events.
2. Polls Log Analytics with KQL until the canary row appears:

   ```kusto
   BowerSecurity_CL
   | where TimeGenerated > ago(1d)
   | where EventId == "bower-canary-…"
   | project TimeGenerated, IngestionTime = ingestion_time(), EventId, PolicyHash
   | take 1
   ```

3. Records end-to-end latency (send to `ingestion_time()`), the policy hash on the
   row, table plan and retention (via ARM), the workspace region, and `DCRLogErrors`
   from the last hour when DCR error logging is enabled.
4. Maps the result to controls and signs the bundle (ECDSA P-256).

```bash
export BOWER_INGEST_TOKEN=…            # the collector's ingest token
bower keys generate --out-dir ./keys   # once; keep the private key in a vault

bower evidence run \
  --collector-url https://collector.example.org:4319 \
  --workspace-id <log-analytics-workspace-guid> \
  --workspace-resource-id /subscriptions/…/workspaces/<name> \
  --credential azure-cli \
  --signing-key ./keys/bower-signing.key.pem \
  --out evidence-2026-10.json

bower evidence verify evidence-2026-10.json --trusted-key ./keys/bower-signing.pub.pem
```

Exit codes: `0` verified, `2` failed or simulated, `1` error.

`--timeout-minutes N` (default 15) bounds how long the canary is polled for and must
be between 1 and 1440 (one day). Each HTTP request (collector, query, ARM) times out
after 30 seconds; a timeout is reported as an error with exit code 1, never a crash.
`evidence verify` exits 1 with `Evidence bundle is unreadable.` for a file that is not
a JSON object with a `bundle` object.

## Modes

| Mode | Meaning |
|---|---|
| `verified` | The canary row was returned by a Sentinel query. |
| `failed` | The collector refused the canary or it did not arrive before the timeout (default 15 minutes). |
| `simulated` | No workspace was given, so no query ran. Never delivery evidence; the bundle says so. |

## Control mapping

| Control | Evidenced when |
|---|---|
| ISM-0580 central logging observation | The specific canary is found in Sentinel; this does not assess the organisation's entire logging policy. |
| ISM-1988 searchable retention of at least 12 months | `not-assessed` when total retention is sufficient: archive retention does not prove searchability or historic availability. Insufficient total retention is `not-evidenced`. |
| Essential Eight ML2 centralised, protected event logs | `not-assessed`: arrival does not establish access controls, immutability or deletion protection. |
| Privacy Act APP 11 technical measures | `not-assessed`: a policy hash and canary arrival do not establish effective redaction. Independent privacy testing is required. |

Statuses are evidence statements for an assessor, not compliance determinations.
Control identifiers follow the ISM release current in October 2026; confirm them
against the ISM version you are assessed against.

## Identities

Run evidence under a **verifier identity** separate from the ingest identity: Log
Analytics Reader on the workspace (and Reader on the table for retention) is enough.
The ingest identity keeps only Monitoring Metrics Publisher on the DCR.

## What a bundle contains

Metadata only: canary id and timestamps, collector host and HTTP status, policy id,
query text, latency, retention, region, control statuses, limitations and the
signature. No event payloads, tokens or query response bodies.

## Limitations

- A bundle proves delivery for one canary at one time; schedule it (for example daily)
  to show continuity.
- In AMA spool mode, the bundle is the only way Bower can confirm the hand-off to AMA
  reached Sentinel.
- The Logs Ingestion API has no per-record receipt, so Bower never treats an HTTP 2xx
  as proof; only the query does.
