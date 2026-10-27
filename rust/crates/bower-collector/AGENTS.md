# bower-collector instructions

Rust port of `src/Bower.Collector` (the specification). Composition lives in
`host.rs`; `main.rs` stays a thin entry point so tests host the app in-process.

- Settings come from the same `BOWER_*` variables, defaults and validation messages
  as `CollectorSettings.cs`. Never weaken `validate` or log the ingest token.
- Ingest is authenticated whenever the listener is not loopback. Every ingest request
  passes the rate limiter, authentication and the 1 MiB body limit before parsing.
- `/health` returns status only; queue, ledger and job metadata stay behind the token.
- Delivery stays in `worker.rs` (lease based, never a scheduled job). The loop never
  exits on storage or adapter errors and settles every leased event exactly once.
- `jobs.rs` runs only idempotent maintenance/reporting jobs.
- Store calls are synchronous: run them with `spawn_blocking`.
- Port `CollectorHostTests` / `QueueDeliveryWorkerTests` changes into `tests/`.
- Relay mode lives in `relay/` (C# `Bower.Collector.Relay`, `Bower.Forwarding.RelayOutput`).
  The relay stores downstream payload bytes unchanged, never redacts or parses raw data
  again, and answers `accepted`/`duplicate` only after the queue commit. Pins are checked
  at the TLS handshake. The management tunnel goes only to the relay's own management
  endpoint, and TLS to management must stay layered inside it (end to end); keep the
  HTTPS-only tunnel test. Port `RelayTests` changes into `tests/relay.rs`.
