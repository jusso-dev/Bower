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
    for HEC, a response `code` of `0`. That is what HEC's response means: the event was
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
| `BOWER_HTTP_AUTH_HEADER` | `Authorization` | `ndjson` only. `Authorization` sends `Authorization: Bearer <token>`; any other header name (for example `X-Api-Key`) carries the token as is. Connection, content and proxy headers are refused. |
| `BOWER_HTTP_CA_BUNDLE` | — | PEM roots added to the system roots, for a private CA. Certificate and host name verification are never disabled. |
| `BOWER_HTTP_ALLOW_INSECURE_LOOPBACK` | `false` | Allows `http://` only to a loopback host (`localhost`, `127.0.0.0/8`, `::1`), for a local test endpoint. Plain HTTP to any other host is refused. |
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
Every copy carries the same `bower_event_id`, so deduplicate downstream, for example:

```spl
index=security sourcetype="bower:security" | dedup bower_event_id
```

## Delivery and failure handling

Requests go one at a time, in queue order. The queue marks an event delivered only
after the endpoint accepted it; nothing is deleted before then.

| Response | Outcome | Failure code |
|---|---|---|
| 2xx (HEC: JSON body with `code` 0) | Delivered (`http:<format>:endpoint-accepted`). | — |
| 2xx from HEC without `code` 0 (a proxy page, a captive portal, malformed or over 64 KiB) | Retried behind the destination circuit. | `destination-http-response-invalid` |
| 401, 403 | Retried behind the destination circuit; raises the `destination-credential` health problem (C#). | `destination-http-401`, `destination-http-403` |
| 404, 3xx (redirects are never followed), 408, 429, 5xx | Retried behind the destination circuit, honouring `Retry-After` up to one hour. | `destination-http-<status>` |
| Connection, TLS or certificate failure | Retried behind the destination circuit. | `destination-http-unavailable` |
| Timeout | Retried behind the destination circuit. | `destination-http-timeout` |
| 413 | The batch is split in half and resent (at most 16 splits per delivery). A single event the endpoint still refuses is dead-lettered. | `http-413` |
| Other 4xx (400, 405, 415, ...) | The whole batch is dead-lettered. | `http-<status>` |
| Payload is not one JSON object, or its `eventId` differs from the queue's | That event alone is dead-lettered. | `payload-invalid-json`, `payload-event-id-mismatch` |
| One event larger than `BOWER_HTTP_MAX_BATCH_BYTES` | That event alone is dead-lettered. | `payload-too-large` |

Destination failures (`destination-*`) keep events queued without spending their
attempt budget, and stop the rest of the delivery so they are not sent into the same
failure. For HEC, the response's numeric `code` (0–99) is appended as metadata, for
example `http-400:hec-7` (incorrect index) or `destination-http-403:hec-4` (invalid
token). Response text is never stored or logged.

A configuration error such as a wrong index dead-letters each batch it affects. Fix the
setting, then replay: `bower queue replay --code http-400`.

## Security

- The token is held in memory only. It never appears in logs, `/v1/status`, failure
  codes, the queue, error messages or the configuration hash. The hash records only
  where the token comes from (`file:<path>` or `environment`).
- HTTPS only, with system roots plus the optional CA bundle; host names are always
  checked. Redirects are never followed, so the token is never sent to a second host.
- Response bodies are read up to 64 KiB, and only for HEC.
- The standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` variables apply, as for other
  outbound .NET and reqwest clients.
- Rotating the token or the CA bundle needs a collector restart.

## Status, health and evidence

- `/v1/status` reports `"output":"http"`; C# also reports the last failure code under
  `deliveryActivity.lastFailureCode`.
- `bower evidence run` reads `/v1/status` first. For an `http` output it does **not**
  query Sentinel: the bundle mode is `failed` with arrival error `output-not-sentinel`
  (or `simulated` without a workspace), and the limitations say why. A Sentinel-verified
  bundle is impossible for this output by design.

## Qualification

- Unit and integration tests in both runtimes: shared request vectors (HEC and NDJSON
  bytes, headers, poison records, batch caps, gzip), shared response classification
  vectors (2xx, 3xx, 4xx, 5xx, `Retry-After`, HEC error-code bodies, malformed, deep and
  oversize bodies), TLS policy against a private CA (untrusted, trusted, host name
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
- No per-event isolation of a 400: the whole batch is dead-lettered and can be replayed.
- One request at a time; no adaptive concurrency.
