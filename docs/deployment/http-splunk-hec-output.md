# HTTP output: Splunk HEC and NDJSON

`BOWER_OUTPUT=http` delivers queued events to **Splunk HTTP Event Collector** (HEC) or to
a **generic HTTPS endpoint that accepts NDJSON**. Both the C# collector
(`src/Bower.Output.Http`) and the Rust collector (`rust/crates/bower-output-http`)
implement it, with shared request and response vectors.

It is a delivery sink for the same security events Bower already selected, redacted and
queued. It is not a generic log forwarder: only events that passed policy and redaction
reach it, exactly as they would reach Sentinel.

!!! warning "Acceptance is not indexing, and it is not Sentinel"
    An event counts as delivered when the endpoint **accepted** its request: HTTP 2xx and,
    for HEC, a response `code` of `0`, `24` or `25`. That is what HEC's response means: the event was
    received, not that an indexer has written it. Bower does not implement HEC indexer
    acknowledgement (`useACK`) yet, so it cannot tell you an event was indexed. Nothing
    about this output is Sentinel delivery: status, acknowledgements and evidence say
    `endpoint-accepted`, never Sentinel or indexed.

## When to use it

- A team runs Splunk (or another SIEM with an HTTPS NDJSON intake) and wants Bower's
  selected, redacted security events there.
- One collector has one output. To feed Sentinel and Splunk at the same time, run two
  collectors (or a relay for Sentinel and a second collector for HEC). The HTTP output
  does not fan out.

## Configure

| Variable | Default | Meaning |
|---|---|---|
| `BOWER_OUTPUT` | `none` | `http` selects this output. |
| `BOWER_HTTP_URL` | required | Full request URL, for example `https://splunk.example.com:8088/services/collector/event`. HTTPS, a host, no credentials, query or fragment (a query could carry a token). |
| `BOWER_HTTP_FORMAT` | `splunk-hec` | `splunk-hec` or `ndjson`. |
| `BOWER_HTTP_TOKEN_FILE` | — | File holding the token (preferred). A trailing newline is ignored. Read at start-up. |
| `BOWER_HTTP_TOKEN` | — | The token itself, when a file is not possible. Exactly one of the two is required. |
| `BOWER_HTTP_AUTH_HEADER` | `Authorization` | `ndjson` only. `Authorization` sends `Authorization: Bearer <token>`; any other header name (for example `X-Api-Key`) carries the token as is. Refused: hop-by-hop and framing headers (`Host`, `Connection`, `Transfer-Encoding`, `TE`, `Upgrade`, ...), proxy credentials, content headers (`Content-Type`, `Content-Length`, `Content-Disposition`, `Content-Range`, `Content-Language`, `Allow`, `Expires`, ...) and response-only headers (`Server`, `Location`, `Retry-After`, ...). The full list is in `tests/fixtures/http-output/vectors.json`; the collector also refuses to start if the header cannot be added to a request. |
| `BOWER_HTTP_CA_BUNDLE` | — | PEM **self-signed root** CA certificates added to the system roots, for a private CA. Certificate and host name verification are never disabled. Put only roots in the bundle: the C# collector anchors trust at self-signed roots only, so an intermediate would be trusted by the Rust collector but not the C# one. Start-up refuses a bundle holding a certificate whose subject differs from its issuer. Servers must send their intermediates. |
| `BOWER_HTTP_ALLOW_INSECURE_LOOPBACK` | `false` | Allows `http://` only to a loopback IP literal (`127.0.0.0/8` or `::1`), for a local test endpoint. Host names, `localhost` included, and every other address are refused. Plain HTTP never goes through a proxy. |
| `BOWER_HTTP_HEC_INDEX` | token default | HEC `index` (lowercase letters, digits, `_`, `-`). Omitted when unset, so the token's default index applies. |
| `BOWER_HTTP_HEC_SOURCETYPE` | `bower:security` | HEC `sourcetype`. |
| `BOWER_HTTP_HEC_SOURCE` | `bower` | HEC `source`. |
| `BOWER_HTTP_HEC_HOST` | collector id | HEC `host`. |
| `BOWER_HTTP_HEC_CHANNEL` | — | A GUID sent as `X-Splunk-Request-Channel`. |
| `BOWER_HTTP_MAX_BATCH_BYTES` | `1000000` | Uncompressed request body cap (1024–16777216), newlines included. HEC's default `max_content_length` is about 1 MB on many deployments; raise both together. |
| `BOWER_HTTP_MAX_BATCH_EVENTS` | `500` | Events per request (1–10000). The delivery worker leases at most 500 at a time. |
| `BOWER_HTTP_TIMEOUT_SECONDS` | `30` | One request, from connect to the end of the response read (1–300). |
| `BOWER_HTTP_GZIP` | `false` | `true` sends `Content-Encoding: gzip`. The byte cap still applies to the uncompressed body. |

`BOWER_HTTP_HEC_*` settings are refused with `BOWER_HTTP_FORMAT=ndjson`, and every
`BOWER_HTTP_*` setting is refused unless `BOWER_OUTPUT=http`, so a half-configured output
stops start-up instead of going unnoticed.

### Splunk HEC

1. In Splunk, create an HEC token for Bower. Give it an allowed index (for example
   `security`) and **leave indexer acknowledgement off**: Bower does not poll
   `/services/collector/ack`, and an acknowledgement-enabled token would make Splunk keep
   pending acknowledgements for it.
2. Put the token in a file readable only by the collector account.
3. Configure the collector:

```text
BOWER_OUTPUT=http
BOWER_HTTP_URL=https://splunk.example.com:8088/services/collector/event
BOWER_HTTP_TOKEN_FILE=/etc/bower/secrets/hec-token
BOWER_HTTP_HEC_INDEX=security
BOWER_HTTP_CA_BUNDLE=/etc/bower/splunk-ca.pem   # only for a private CA
```

### Generic NDJSON endpoint

```text
BOWER_OUTPUT=http
BOWER_HTTP_FORMAT=ndjson
BOWER_HTTP_URL=https://intake.example.com/v1/bower
BOWER_HTTP_TOKEN_FILE=/etc/bower/secrets/intake-token
BOWER_HTTP_AUTH_HEADER=X-Api-Key                # omit for Authorization: Bearer
```

The endpoint must answer 2xx only after it has taken responsibility for every line in
the request. Bower does not read the response body of a 2xx for NDJSON.

## What is sent

Each request is a `POST` of records, each followed by `\n`.

**HEC** (`Content-Type: application/json; charset=utf-8`): one event envelope per record.
`event` is the Bower event exactly as the queue stores it (already redacted). `time`
comes from the event's `timeGenerated` (Unix seconds, milliseconds truncated) when it is
a strict ISO 8601 timestamp from 1970 on; otherwise it is omitted and Splunk uses receipt
time. `index` is omitted unless configured.

```json
{"time":1793840523.456,"host":"edge-01","source":"bower","sourcetype":"bower:security","index":"security","event":{"schemaVersion":"1.0","eventId":"evt-0101","timeGenerated":"2026-11-05T01:02:03.4567891+00:00","eventCategory":"authentication","eventType":"login_failed","...":"..."},"fields":{"bower_event_id":"evt-0101","bower_fingerprint":"sha256:..."}}
```

`fields` is a small fixed set of indexed fields: `bower_event_id` (Bower's stable event
id) and `bower_fingerprint`. Nothing else is added.

**NDJSON** (`Content-Type: application/x-ndjson; charset=utf-8`): one Bower event per
line, as the queue stores it.

In both formats raw carriage returns and line feeds are removed from the stored payload
(valid JSON holds them only as whitespace), so one event is always one line. The exact
bytes are pinned by `tests/fixtures/http-output/vectors.json`.

### Duplicates and deduplication

Delivery is at least once. A request that times out after the endpoint accepted it, or
a crash between acceptance and the queue's acknowledgement, sends the same event again.
The Rust collector has one more window: on shutdown its delivery worker aborts the
output task and discards its partial result, so batches the endpoint already accepted in
that delivery stay leased and are sent again after the lease expires (C# waits for the
output and settles what it accepted).
Every copy carries the same `bower_event_id`, so deduplicate downstream, for example:

```spl
index=security sourcetype="bower:security" | dedup bower_event_id
```

## Delivery and failure handling

Requests go one at a time, in queue order. The queue marks an event delivered only
after the endpoint accepted it; nothing is deleted before then. A response is never
taken as proof that an event is bad unless the same request also proved that its
siblings are good.

| Response | Outcome | Failure code |
|---|---|---|
| 2xx (HEC: JSON body with `code` 0) | Delivered (`http:<format>:endpoint-accepted`). | — |
| 2xx from HEC with `code` 24 or 25 (near capacity) | Delivered and never resent; the acknowledgement records the code (see below). | — |
| 2xx from HEC with any other `code`, or without one (a proxy page, a captive portal, malformed or over 64 KiB) | Held and retried, indefinitely. | `destination-http-response-invalid` |
| 401, 403 | Held; raises the `destination-credential` health problem (C#). | `destination-http-401`, `destination-http-403` |
| 400 with a HEC configuration code (see below) | Held: a destination or token setting is wrong, not the events. | `destination-http-400:hec-<n>` |
| 3xx (redirects are never followed), 404, 405, 408, 410, 415, 421, 429, 5xx, and any other status not listed here | Held, honouring `Retry-After` up to one hour. | `destination-http-<status>` |
| Connection, TLS or certificate failure | Held. | `destination-http-unavailable` |
| Timeout | Held. | `destination-http-timeout` |
| Other 400, 422 or 413 | The batch is bisected and resent (16 bisections per delivery). A single event is dead-lettered only when an event from the same original batch was accepted; otherwise it is held. Batches left when the budget runs out are held and bisected again on the next delivery. | dead letter: `http-<status>[:hec-<n>]`; held: `destination-http-<status>[:hec-<n>]` |
| Payload is not one JSON object, or its `eventId` differs from the queue's | That event alone is dead-lettered. | `payload-invalid-json`, `payload-event-id-mismatch` |
| One event larger than `BOWER_HTTP_MAX_BATCH_BYTES` (newline included) | That event alone is dead-lettered. | `payload-too-large` |

Held failures (`destination-*`) keep events queued without spending their attempt budget.
An endpoint-wide one (anything but the bisection cases) also stops the rest of the
delivery, so later batches are not sent into the same failure. For HEC, the response's
numeric `code` (0–99) is appended as metadata, for example `destination-http-400:hec-7`
(incorrect index) or `http-400:hec-6` (invalid data format, isolated). Response text is
never stored or logged.

HEC configuration codes (all HTTP 400, from Splunk's "Troubleshoot HTTP Event Collector"
table): 7 incorrect index, 10 data channel is missing, 11 invalid data channel,
14 ACK is disabled, 16 query string authorization is not enabled, 21 invalid token,
22 token disabled. 405 (method not allowed), 410 (gone), 415 (unsupported media type,
for example gzip not accepted) and 421 (misdirected request) mean the URL, host or
encoding is wrong for this endpoint, so they are held too.

!!! warning "Alarm on the destination backlog"
    Held failures retry until the endpoint or its configuration is fixed. Alert on a
    growing retrying backlog with `destination-*` failure codes (`/v1/status`
    `queue.retrying` and `deliveryActivity.lastFailureCode`, the C# `collector_health`
    record, or the `Output adapter did not deliver events` log line). In particular a
    2xx from HEC whose `code` is neither 0, 24 nor 25 is retried indefinitely
    (`destination-http-response-invalid`).

### HEC near capacity (codes 24 and 25)

Splunk's "Troubleshoot HTTP Event Collector" table documents two success-with-warning
codes, both returned with **200 OK**: 24 "HEC queue is approaching its capacity limit"
and 25 "HEC ACK is approaching its capacity limit". The request was accepted, so Bower
acknowledges its events and never resends them (resending would duplicate events and add
load exactly when HEC is short of room). Every other non-zero code on a 2xx is still not
acceptance.

The condition is kept as metadata only, in the queue acknowledgement of every event the
delivery acknowledged: `http:splunk-hec:endpoint-accepted:near-capacity:hec-24` (or
`:hec-25`, or both as `:near-capacity:hec-24:hec-25`). The acknowledgement covers the
whole delivery, so it marks events from every batch of that delivery, not only the one
whose response carried the code. No response text is kept. Treat a rising share of
`near-capacity` acknowledgements as an early warning that HEC needs more capacity, before
it starts answering 503 (code 9) or 429 (codes 26 and 27).

## Security

- The token is held in memory only. It never appears in logs, `/v1/status`, failure
  codes, the queue, error messages or the configuration hash. The hash records only
  where the token comes from (`file:<path>` or `environment`).
- HTTPS only, with system roots plus the optional CA bundle; host names are always
  checked. Redirects are never followed, so the token is never sent to a second host.
- Response bodies are read up to 64 KiB, and only for HEC.
- For `https://`, the standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` variables
  apply, as for the Azure output. Plain `http://` (loopback only) never uses a proxy.
- Rotating the token or the CA bundle needs a collector restart.

## Status, health and evidence

- `/v1/status` reports `"output":"http"`; C# also reports the last failure code under
  `deliveryActivity.lastFailureCode`.
- `bower evidence run` reads `/v1/status` **before** sending anything. Only
  `azure-logs-ingestion` and `ama-spool` are known to deliver to Sentinel; `relay`, a
  missing `output` or an unreadable status proceed, with the Sentinel query still the
  only proof. For an `http` output no canary or probe is sent and Sentinel is not
  queried: the bundle is `failed` with code `collector-output-not-sentinel` (or
  `simulated` without a workspace) and a `NOT SENTINEL` limitation. A Sentinel-verified
  bundle is impossible for this output by design.

## Qualification

- Unit and integration tests in both runtimes: shared request vectors (HEC and NDJSON
  bytes, headers, poison records, batch caps with byte-exact boundaries, gzip), shared
  response classification vectors (2xx, 3xx, 4xx, 5xx, `Retry-After`, HEC error-code
  bodies, malformed, deep and oversize bodies), shared isolation scenarios (mid-stream
  poison, configuration errors, 413 splitting and budget exhaustion), header-name and
  endpoint-policy vectors, a 500-event multi-pass delivery to a single-event endpoint, TLS policy against a private CA (untrusted, trusted, host name
  mismatch), 413 splitting and its budget, timeouts, cancellation (C#), queue
  settlement, the configuration hash (pinned identically in both) and token redaction in
  logs and status.
- A real Splunk container run was **not** performed for this change: no local Docker
  daemon was available. Request bytes follow Splunk's documented HEC event format, but a
  live HEC qualification is still outstanding.

## Not yet supported

- HEC indexer acknowledgement (`useACK`, `/services/collector/ack`). A follow-up could
  poll acknowledgements and only then acknowledge the queue. Until then a 200 is
  acceptance, not indexing.
- One output per collector, no fan-out.
- One request at a time; no adaptive concurrency.
