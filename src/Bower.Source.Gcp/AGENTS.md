# GCP source adapter instructions

Parse Google Cloud security telemetry delivered through Pub/Sub: Cloud Audit Logs
`LogEntry` records from a log sink and Security Command Center `NotificationMessage`
findings. Keep parsing pure, bounded and deterministic.

- No Google credentials, no live API calls in this library or its unit tests.
- Never log message data or attributes; report message ids and failure types only.
- Unknown payloads are `Unsupported` (default deny), malformed payloads throw
  `GcpTelemetryMalformedException` so the host can dead-letter them.
- Raw records stay out of envelopes unless `IncludeRawRecord` is explicitly enabled.
- Event ids are `gcp-` plus a hash of source id, record identity and time, so redelivery
  collapses onto one queued event.
