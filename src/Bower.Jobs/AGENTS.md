# Bower.Jobs instructions

Shared in-process recurring job scheduler for Bower hosts (`RecurringJobScheduler`, a
`BackgroundService` driven by a `PeriodicTimer`). It replaced Hangfire so every host can
be published as Native AOT; keep it reflection-free.

- Jobs scheduled here are recurring, idempotent maintenance or reporting tasks.
- Never move event delivery, acknowledgement or queue state into the scheduler. The
  SQLite queue stays the only durable record of events. Scheduler state is in memory and
  rebuilt on every start; missed occurrences are coalesced, never replayed.
- A job never overlaps itself. Retries are explicit per registration (`retryAttempts`).
- Job arguments must be empty or non-sensitive identifiers. Never pass payloads,
  tokens or secrets to a job. Failures log the job id and exception type only.
- Do not expose a scheduler dashboard. Report status through `BackgroundJobCatalog`
  (metadata only) and authenticated Bower APIs.
