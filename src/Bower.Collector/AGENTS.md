# Bower.Collector instructions

Local HTTP collector host. Composition lives in `CollectorApplication`; `Program`
stays a thin entry point so integration tests can host the app in-process.

- Ingest is authenticated with a shared bearer token whenever the listener is not
  loopback. Never weaken `CollectorSettings.Validate` or log the token.
- Every request passes the rate limiter and the 1 MiB body limit before parsing.
- `/health` returns status only. Queue and job metadata stay behind the token.
- Event delivery stays in `QueueDeliveryWorker` (low latency, lease based). Hangfire
  runs only idempotent maintenance and reporting jobs (`Jobs/`).
- The delivery loop must never exit on storage or adapter errors. Every leased event
  is settled exactly once: delivered, retrying or dead-lettered.
- Azure credentials come from one explicit source (`BOWER_AZURE_CREDENTIAL`).
