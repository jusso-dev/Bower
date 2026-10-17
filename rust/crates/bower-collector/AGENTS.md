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
