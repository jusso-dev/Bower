# HTTP output instructions

`BOWER_OUTPUT=http`: bounded HTTPS delivery of queued, already-redacted Bower events to
Splunk HTTP Event Collector (`splunk-hec`) or a generic NDJSON endpoint (`ndjson`). Rust
port: `rust/crates/bower-output-http`; request and response vectors in
`tests/fixtures/http-output` are shared and must pass in both runtimes.

- Delivery means "accepted by the endpoint" (2xx; HEC also `code` 0, or the near-capacity
  codes 24/25, which are recorded only as `:near-capacity:hec-<n>` on the acknowledgement;
  every other non-zero code on a 2xx is not acceptance). Never call it
  Sentinel delivery or indexing. HEC indexer acknowledgement (`useACK`) is not
  implemented; a 200 is acceptance only.
- HTTPS only, certificate and host name verification always on. Plain `http://` only to
  a loopback IP address with `BOWER_HTTP_ALLOW_INSECURE_LOOPBACK=true`. No redirects.
- The token is held in memory only: never in logs, status, errors, failure codes, the
  configuration hash or the queue.
- Send each payload as the queue stores it (CR and LF removed); never re-serialize it.
  Records follow the vectors byte for byte.
- Classification: 2xx accepted. Nothing else is event poison by itself: every failure is
  held as `destination-http-*` (retryable, no attempt budget). Endpoint-wide failures
  (3xx, 401, 403, 404, 405, 408, 410, 415, 421, 429, 5xx, other statuses, and 400 with
  HEC configuration codes 7, 10, 11, 14, 16, 21, 22) stop the delivery. Ambiguous 400,
  422 and 413 bisect within the budget; a single event becomes `http-<status>` poison
  only when a sibling from the same original batch was accepted. HEC codes are metadata
  only (`:hec-<n>`). Shared scenarios in the vectors pin this.
- The byte cap counts every record's newline.
- `BOWER_HTTP_AUTH_HEADER` never names a header .NET refuses on requests (content,
  response-only) or a hop-by-hop/framing/proxy header; adding it must succeed or fail closed.
- `http://` only to loopback IP literals, never through a proxy. CA bundles hold only
  self-signed roots.
- Rust only: on shutdown the worker aborts the output task and discards a partial
  result, so batches already accepted in that delivery are resent after lease expiry.
- Bound everything: batch bytes and events, 64 KiB response reads, request timeout,
  Retry-After capped at one hour.
