# Bower.Jobs instructions

Shared Hangfire wiring for Bower hosts.

- Jobs scheduled here are recurring, idempotent maintenance or reporting tasks.
- Never move event delivery, acknowledgement or queue state into Hangfire. The SQLite
  queue stays the only durable record of events.
- Job arguments must be empty or non-sensitive identifiers. Never pass payloads,
  tokens or secrets to a job.
- Do not expose the Hangfire dashboard. Report status through `BackgroundJobCatalog`
  (metadata only) and authenticated Bower APIs.
