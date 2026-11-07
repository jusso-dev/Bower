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
   row (`null` when the cell is not a string), table plan and retention (via ARM), the workspace region, and `DCRLogErrors`
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

## Destination queries

Every Log Analytics query sends `Cache-Control: no-cache`, so polling sees current
destination state rather than a cached empty result. A query answered with HTTP 200
and any non-null `error` (partial results) is a failed query with code
`query-incomplete`: its rows are never used as evidence and the error details are not
recorded. A 2xx answer is a failed query with code `query-invalid-response`, never an
empty result, when its body is empty (including `204 No Content`), not JSON, not a JSON
object, nested more than 64 levels deep or has a duplicate key anywhere, or when it has
no usable first table: `tables` missing, not an array or empty, a first table that is not
an object, `columns` or `rows` that are not arrays, a column that is not an object with
a string `name`, a repeated column name, a row that is not an array, or a row whose cell
count differs from the column count, or when a string cannot be decoded. Log Analytics
always returns at least the `PrimaryResult` table, so a real zero-row answer (one table
with columns and an empty `rows` array) is still a clean empty result. The body, its keys and any parser
message are not recorded. The C# and Rust clients behave the same.

An invalid or incomplete answer (and, for parser probes, a timeout or transport
failure) does not end polling: a later valid answer can still verify delivery. Two
failures do end it: a parser probe stops at once on a permission error
(`destination-permission-denied`), and a transport failure ends a generic canary run.
If the last query is invalid or incomplete the run is `failed` and the parser
probe reports `destination-query-failed` with that query error, even if an earlier
query answered cleanly, because the bad answer may have hidden the probe row. The
generic canary always reports the last query's error (or `not-found-before-timeout`),
so a last invalid answer fails it the same way and the setup wizard shows
`destination-query-failed`. A last transport error or timeout after a clean answer still
reports the row missing for parser probes (`destination-row-missing`).

## Parser probes (opt-in)

The generic probe proves `/v1/events` and nothing else. A working generic probe can
coexist with a broken source parser, so `--probe-profile parser:PACK:INDEX` probes a
signed pack parser's HTTP intake instead. The default stays `generic`: its canary, claim
and bundle bytes are unchanged.

```bash
bower evidence run --probe-profile parser:linux-ssh-gateway:0 \
  --collector-url https://collector.example.org:4319 \
  --workspace-id <log-analytics-workspace-guid> --signing-key ./keys/bower-signing.key.pem
```

Supported profiles (repo-owned, synthetic fixtures; anything else fails before a request
is sent):

| Profile | Fixture | Expected event |
|---|---|---|
| `parser:linux-ssh-gateway:0` | `linux-ssh-gateway/sshd-json/authentication-failure@1`: `{"id":"bower-probe-…","timestamp":…,"user":"bower-evidence-probe","source_ip":"192.0.2.10","result":"failure"}` | `authentication_failure` |

The fixture holds no secrets or production samples: a fixed probe username (pseudonymised
by the pack's privacy profile like any other) and a documentation (TEST-NET-1) address.
Its `id` is a fresh `bower-probe-<uuid7>`, so the destination query matches exactly that
event.

What a parser probe does:

1. Reads `GET /v1/status` with the ingest token and records the collector policy hash,
   pack version, pack hash and parser state. A missing pack or a parser that is not
   `active-local-json` is `parser-inactive`, and the fixture is not sent.
2. Posts the fixture to `POST /v1/packs/PACK/parsers/INDEX/events`: the normal
   authentication, parser, privacy, policy, queue and delivery path.
   An accepted probe that the collector did not queue (`queued: false`, `duplicate` or
   `suppressed`) is `probe-not-queued`, and the destination is not queried.
3. Queries the destination for the probe id and projects `EventType` and `PolicyHash`.
   Only a row with the exact probe `EventId`, the expected event type and the policy hash
   the collector returned for the probe (`eventPolicyHash`) verifies. Collector acceptance
   alone never does.

The pack version, pack hash, parser state and `collectorPolicyHash` come from the
separate `/v1/status` read, not from the intake response. Behind a load balancer with
several collector replicas, the status read and the intake post can reach different
replicas. A replica running a different policy shows up as `configuration-mismatch`
(the row's policy hash differs from `eventPolicyHash`), but a replica with the same
policy and a different pack build does not. Probe a single replica directly when the
pack hash must be tied to the exact instance.

The bundle adds a `probe` object (additive; generic bundles omit it; signed as before):
`profile`, `testedPath`, `fixture`, `packId`, `parserIndex`, `packVersion`, `packHash`,
`parserStatus`, `collectorPolicyHash`, `eventId`, `expectedEventType`, `eventPolicyId`,
`eventPolicyVersion`, `eventPolicyHash`, `destinationWorkspaceId`, `destinationTable`,
`queriedAt`, `outcome` and `untestedPaths`. `canary.collectorStatus` is `0` when the
fixture was not sent.

| Outcome | Meaning |
|---|---|
| `verified` | The exact probe row, with the expected event type, was returned from the intended workspace and table. |
| `accepted-not-verified` | The collector accepted the probe but no destination query ran (`simulated`). |
| `parser-inactive` | The pack is not loaded or the parser has no active runtime (status, or HTTP 404). |
| `parser-not-selected` | The parser source filter no longer selects the fixture (422 `pack-record-not-selected`). |
| `parser-record-rejected` | The parser refused the fixture (400, 413 or 415): a mapping or field regression. |
| `parser-wrong-event` | Accepted, but the collector reports a different event id: a mapping regression. |
| `probe-not-queued` | Accepted but not queued (duplicate or suppressed), so it can never arrive; no query runs. |
| `policy-not-selected` | The parser mapped the fixture but policy (or redaction) rejected or quarantined it. |
| `collector-permission-denied` | The collector refused the ingest token or producer scope (401/403). |
| `collector-status-unreadable` | `/v1/status` could not be read, so the tested configuration is unknown. |
| `collector-output-not-sentinel` | `/v1/status` reports an `output` outside the Sentinel allowlist (`azure-logs-ingestion`, `ama-spool`, `relay`), for example `s3`, `http` or any future output. No probe is sent and a `NOT SENTINEL` limitation is added. The generic canary does the same, with this code in `arrival.queryError`. A missing `output` field, an allowlisted value or unreadable status proceeds, and only the Sentinel query can verify. See [S3 output](../deployment/s3-output.md#evidence) and [HTTP output](../deployment/http-splunk-hec-output.md#status-health-and-evidence). |
| `collector-rejected` | Any other refusal (capacity, rate limit, identity conflict). |
| `destination-permission-denied` | The verifier identity may not query the workspace (stops at once). |
| `destination-row-missing` | At least one query answered, and none returned the probe row before the timeout (later queries may have failed or timed out, but the last one was not `query-incomplete` or `query-invalid-response`). |
| `destination-wrong-event` | A row came back but it is not the exact probe event. |
| `configuration-mismatch` | The exact probe row arrived, but its policy hash differs from the one the collector reported for the probe. |
| `destination-timeout` | No query was ever answered: they timed out (including gateway 408/504 with any body). |
| `destination-query-failed` | No query was ever answered: they failed with another error. Also reported, with that query error, when the last query was `query-incomplete` (partial results) or `query-invalid-response` (unusable body), even after an earlier clean answer, because the bad answer may have hidden the probe row. |

Every parser bundle lists what it did not test: generic intake, other packs and parsers,
other event types and privacy rules of the pack, upstream agents and readers, and any
event other than the probe. A probe row is a real `authentication_failure` row in the
table; filter `EventId startswith "bower-probe-"` out of analytics if needed. Probes run
only when someone runs the command, or when an administrator chooses **Send test event**
in the console's setup wizard (audited, one at a time; see
[console onboarding](console-onboarding.md)): there is no automatic scheduling. The C# and Rust CLIs implement the same profiles, fixture bytes and outcomes.

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
