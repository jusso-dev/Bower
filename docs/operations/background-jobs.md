# Background jobs

Bower uses [Hangfire](https://www.hangfire.io/) to schedule recurring maintenance
and health-reporting work. Event delivery is **not** a Hangfire job.

![Background jobs view in the management console](../images/bower-management-jobs.png)

## What runs where

| Host | Job id | Schedule (UTC) | What it does |
|---|---|---|---|
| Collector | `queue-retention` | Hourly | Deletes `delivered` rows older than `BOWER_QUEUE_RETENTION_HOURS` (default 168). Never touches queued, uploading, retrying or dead-lettered events. |
| Collector | `queue-maintenance` | Daily 03:00 | `PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA optimize` on the queue database. |
| Collector | `management-heartbeat` | Every minute | Registers the collector and reports queue, output and job health. Only when `BOWER_MANAGEMENT_ENDPOINT` is set. |
| Management API | `collector-staleness` | Every 5 minutes | Marks approved/active collectors that have not reported for 15 minutes as `stale` and writes one `collector.stale` audit row per transition. |

## Why delivery stays out of Hangfire

Delivery needs sub-second latency and exactly-once settlement of each leased
event. The SQLite queue already provides durable leases, retry times and
acknowledgements, so the hosted `QueueDeliveryWorker` drains it directly. Putting
delivery in a scheduler would add a second source of truth for event state and
weaken the "never delete before acknowledgement" invariant.

## Why in-memory storage

Every job is idempotent and derives its work from Bower's own SQLite stores. If a
process restarts, Hangfire's schedule is rebuilt at start-up and the next run picks
up where the last left off. This avoids a second database, a third-party SQLite
Hangfire provider, or SQL Server/Redis just for scheduling. Run history is kept for
24 hours in memory and is lost on restart; job outcomes that matter (stale
collectors, retention) are recorded in Bower's audit trail or queue state.

With several management API replicas, each replica runs its own staleness sweep.
The sweep is idempotent (it only changes collectors not already `stale`), so
duplicate runs write no extra audit rows.

## Observing jobs

- **Console:** *Jobs* lists management jobs (with *Run now* for
  `Bower.Administrator`) and every collector's reported jobs.
- **Management API:** `GET /api/jobs` (`View` policy) and
  `POST /api/jobs/{id}/trigger` (`Administer` policy, audited as `job.triggered`).
- **Collector:** `GET /v1/status` with the ingest token returns queue counts and
  job states.

The Hangfire dashboard is intentionally not exposed: the management API uses
bearer tokens only, and the dashboard would add a cookie-authenticated surface.
Job status is metadata only — no arguments, payloads or exception text.

## Adding a job

1. Add a class with a `RunAsync(CancellationToken)` method under the host's
   `Jobs/` folder. Keep it idempotent and argument-free.
2. Register it with DI and with `IRecurringJobManager.AddOrUpdate` in the host's
   `InitializeAsync`, using `TimeZoneInfo.Utc`.
3. Set `[AutomaticRetry]` deliberately (reporting jobs use `Attempts = 0`) and add
   `[DisableConcurrentExecution]`.
4. Add a description in `ui/Bower.Management.Web/src/pages/JobsPage.tsx` and a test.
