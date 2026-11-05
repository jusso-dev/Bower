# bower-output-http instructions

Rust port of `src/Bower.Output.Http` (the specification), `BOWER_OUTPUT=http`: Splunk HTTP
Event Collector (`splunk-hec`) or a generic NDJSON endpoint (`ndjson`).

- `tests/fixtures/http-output/vectors.json` (repo root) is shared with the C# tests: request
  bytes, headers and outcomes, and response classification. Keep it passing in both.
- Delivery is acceptance by the endpoint (2xx; HEC `code` 0), never Sentinel delivery or
  indexing. HEC indexer acknowledgement is not implemented.
- HTTPS only with verification on (platform roots plus `BOWER_HTTP_CA_BUNDLE`); `http://`
  only to loopback with the opt-in. No redirects.
- The token stays in memory as a sensitive header value: never in logs, errors, failure
  codes, status or the configuration hash.
- Records embed the payload as stored (CR and LF removed) and use
  `bower_contracts::json` for strings, so bytes match C#. Never re-serialize payloads.
- Response reads are bounded (64 KiB, depth 64 like C# `JsonDocument`); Retry-After is
  capped at one hour; 413 splits are budgeted; a destination failure stops later batches.
