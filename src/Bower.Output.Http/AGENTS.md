# HTTP output instructions

`BOWER_OUTPUT=http`: bounded HTTPS delivery of queued, already-redacted Bower events to
Splunk HTTP Event Collector (`splunk-hec`) or a generic NDJSON endpoint (`ndjson`). Rust
port: `rust/crates/bower-output-http`; request and response vectors in
`tests/fixtures/http-output` are shared and must pass in both runtimes.

- Delivery means "accepted by the endpoint" (2xx; HEC also `code` 0). Never call it
  Sentinel delivery or indexing. HEC indexer acknowledgement (`useACK`) is not
  implemented; a 200 is acceptance only.
- HTTPS only, certificate and host name verification always on. Plain `http://` only to
  a loopback host with `BOWER_HTTP_ALLOW_INSECURE_LOOPBACK=true`. No redirects.
- The token is held in memory only: never in logs, status, errors, failure codes, the
  configuration hash or the queue.
- Send each payload as the queue stores it (CR and LF removed); never re-serialize it.
  Records follow the vectors byte for byte.
- Classification: 2xx accepted; 401, 403, 404, 408, 429, 3xx and 5xx are
  `destination-http-*` (retryable, stream held); 413 splits the batch (budgeted), a
  single record then dead-letters; other 4xx dead-letter the batch as `http-<status>`.
  HEC error codes are metadata only (`:hec-<n>`). Stop sending after a destination failure.
- Bound everything: batch bytes and events, 64 KiB response reads, request timeout,
  Retry-After capped at one hour.
