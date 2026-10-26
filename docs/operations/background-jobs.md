# Background jobs

Bower schedules recurring maintenance and health-reporting work with a small
in-process cron scheduler (`Bower.Jobs`: `RecurringJobRegistry` and a
`PeriodicTimer`-driven hosted service). Event delivery is **not** a scheduled job.
The scheduler replaced Hangfire so every host publishes as Native AOT; the jobs,
ids and UTC schedules are unchanged.

![Background jobs view in the management console](../images/bower-management-jobs.png)

## What runs where

| Host | Job id | Schedule (UTC) | What it does |
|---|---|---|---|
| Collector | `queue-retention` | Hourly | Deletes `delivered` rows older than `BOWER_QUEUE_RETENTION_HOURS` (default 168). Never touches queued, uploading, retrying or dead-lettered events. |
| Collector | `queue-maintenance` | Daily 03:00 | `PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA optimize` on the queue database. |
| Collector | `management-heartbeat` | Every minute | Registers the collector and reports queue, output and job health (heartbeat v2). Verifies signed commands in the response and hands them to the hosted command worker; never runs them itself. Only when `BOWER_MANAGEMENT_ENDPOINT` is set. |
| Collector | `source-activity` | Every minute | Saves per-application last-seen times to the queue database so source silence detection survives restarts. Metadata only. |
| Collector | `queue-archive` | Every minute | Copies newly stored events into the verifiable archive. Only when `BOWER_ARCHIVE_PATH` is set; reads the queue, never changes event state. |
| Management API | `collector-staleness` | Every 5 minutes | Marks approved/active collectors that have not reported for 15 minutes as `stale` and writes one `collector.stale` audit row per transition. Also expires overdue collector commands (`collector.command-expired`) for collectors that are offline, suspended or heartbeating v1. |
| Management API | `collector-inactivity` | Daily 02:00 | Suspends collector identities that have not reported for `BOWER_COLLECTOR_INACTIVE_DAYS` (default 30). |

Schedules are five-field cron expressions evaluated in UTC (`*`, values, ranges,
steps and lists). A job never overlaps itself; occurrences missed while a run was in
progress or the process was stopped are coalesced into one run, never replayed.
Failed runs are retried with a 15 s, 30 s, 60 s … (capped at 10 minutes) delay up to
the job's retry count: `queue-retention` 3, `queue-maintenance` 2,
`collector-staleness` 2, `collector-inactivity` 2, and
`management-heartbeat`, `source-activity` and `queue-archive` 0 (the next minute's
run supersedes a failed one).

With an archive configured, `queue-retention` purges only events covered by a verified
archive of this queue (segments present, digests and chain intact, starting at or below
the oldest stored event, chain equal to the queue ledger). Otherwise it purges nothing
and logs a metadata-only warning (event 1202) with the reason, so a stalled or damaged
archive delays purging rather than losing events. `queue-archive` holds the archive
writer lock for each run; a run that finds the lock held fails and the next minute's run
retries.

Management commands are **not** run by a scheduled job either. A `run-canary` queues an
event, so the hosted `ManagementCommandWorker` (a task beside the delivery worker in
Rust) runs every admitted command.

Closing suppression windows is **not** a scheduled job: it queues summary events,
which is queue state, so it runs in the hosted `SuppressionWindowWorker` loop every
5 seconds beside the delivery worker.

## Why delivery stays out of the scheduler

Delivery needs sub-second latency and exactly-once settlement of each leased
event. The SQLite queue already provides durable leases, retry times and
acknowledgements, so the hosted `QueueDeliveryWorker` drains it directly. Putting
delivery in a scheduler would add a second source of truth for event state and
weaken the "never delete before acknowledgement" invariant.

## Why in-memory storage

Every job is idempotent and derives its work from Bower's own SQLite stores. If a
process restarts, the schedule is rebuilt at start-up and the next run picks up
where the last left off. This avoids a second database just for scheduling. Only the
last run time and state per job are kept, in memory, and are lost on restart; job
outcomes that matter (stale collectors, retention) are recorded in Bower's audit
trail or queue state.

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

There is no scheduler dashboard: the management API uses bearer tokens only, and a
dashboard would add a cookie-authenticated surface. Job status is metadata only — no
arguments, payloads or exception text. A failed attempt logs the job id, attempt and
exception type only.

## Adding a job

1. Add a class with a `RunAsync(CancellationToken)` method under the host's
   `Jobs/` folder. Keep it idempotent and argument-free.
2. Register it with DI and with `RecurringJobRegistry.AddOrUpdate<TJob>(id,
   (job, token) => job.RunAsync(token), cron, retryAttempts)` in the host's
   `InitializeAsync`. Schedules are UTC; use `Cron.Hourly()`, `Cron.Daily(hour)` or a
   five-field expression.
3. Choose `retryAttempts` deliberately (reporting jobs use 0). Overlap protection is
   built in. Keep the job reflection-free (Native AOT).
4. Add a description in `ui/Bower.Management.Web/src/pages/JobsPage.tsx` and a test.
