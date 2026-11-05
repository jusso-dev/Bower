# bower-output-http instructions

Rust port of `src/Bower.Output.Http` (the specification), `BOWER_OUTPUT=http`: Splunk HTTP
Event Collector (`splunk-hec`) or a generic NDJSON endpoint (`ndjson`).

- `tests/fixtures/http-output/vectors.json` (repo root) is shared with the C# tests: request
  bytes, headers and outcomes, and response classification. Keep it passing in both.
- Delivery is acceptance by the endpoint (2xx; HEC `code` 0), never Sentinel delivery or
  indexing. HEC indexer acknowledgement is not implemented.
- HTTPS only with verification on (platform roots plus `BOWER_HTTP_CA_BUNDLE`, self-signed
  roots only); `http://` only to loopback IP literals with the opt-in, never through a
  proxy. No redirects.
- The token stays in memory as a sensitive header value: never in logs, errors, failure
  codes, status or the configuration hash.
- Records embed the payload as stored (CR and LF removed) and use
  `bower_contracts::json` for strings, so bytes match C#. Never re-serialize payloads.
- Response reads are bounded (64 KiB, depth 64 like C# `JsonDocument`); Retry-After is
  capped at one hour. Only an isolated single event whose original batch had an accepted
  sibling is poison; every other failure is held as `destination-http-*` (see
  `src/Bower.Output.Http/AGENTS.md`). Endpoint-wide failures stop later batches.
- Duplicate window: the collector's delivery worker aborts the output task on shutdown
  and discards its partial `DeliveryResult`, so batches already accepted in that delivery
  stay leased and are resent after lease expiry. Pre-existing worker behaviour; do not
  rely on partial results surviving shutdown.
