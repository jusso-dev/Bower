//! Recurring maintenance and reporting jobs (C# `Bower.Jobs` + `Jobs/`), run as tokio
//! tasks on UTC cron-equivalent schedules. Jobs are idempotent and argument-free; their
//! durable state lives in Bower's stores. Event delivery, acknowledgement and queue
//! state never move in here (see `worker`).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_contracts::DurableEventStore;
use bower_contracts::time::{Clock, Timestamp, serde_offset_option, to_utc, truncate_to_ticks};
use chrono::{DurationRound, TimeDelta};
use serde::Serialize;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::shutdown::ShutdownToken;
use crate::worker::{random_unit, store_error_name};

pub const QUEUE_RETENTION_JOB_ID: &str = "queue-retention";
pub const QUEUE_MAINTENANCE_JOB_ID: &str = "queue-maintenance";
pub const MANAGEMENT_HEARTBEAT_JOB_ID: &str = "management-heartbeat";
pub const MANAGED_PRIVACY_PROFILE_JOB_ID: &str = "managed-privacy-profile";
const RETENTION_BATCH_SIZE: usize = 5_000;

/// UTC schedules used by the collector (Hangfire `Cron.*` helpers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// `Cron.Minutely()`.
    Minutely,
    /// `Cron.Hourly()`.
    Hourly,
    /// `Cron.Daily(hour)`.
    Daily(u32),
}

impl Schedule {
    pub fn cron(self) -> String {
        match self {
            Self::Minutely => "* * * * *".into(),
            Self::Hourly => "0 * * * *".into(),
            Self::Daily(hour) => format!("0 {hour} * * *"),
        }
    }

    /// Next occurrence strictly after `now`.
    pub fn next_after(self, now: Timestamp) -> Timestamp {
        let now = to_utc(now);
        let minute =
            now.duration_trunc(TimeDelta::minutes(1)).unwrap_or(now) + TimeDelta::minutes(1);
        match self {
            Self::Minutely => minute,
            Self::Hourly => {
                now.duration_trunc(TimeDelta::hours(1)).unwrap_or(now) + TimeDelta::hours(1)
            }
            Self::Daily(hour) => {
                let midnight = now.duration_trunc(TimeDelta::days(1)).unwrap_or(now);
                let today = midnight + TimeDelta::hours(i64::from(hour));
                if today > now {
                    today
                } else {
                    today + TimeDelta::days(1)
                }
            }
        }
    }
}

/// Status of one recurring job. Metadata only: never exception text or arguments.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundJobStatus {
    pub id: String,
    pub schedule: String,
    #[serde(with = "serde_offset_option")]
    pub last_run_at: Option<Timestamp>,
    pub last_state: Option<String>,
    #[serde(with = "serde_offset_option")]
    pub next_run_at: Option<Timestamp>,
}

/// Recurring job state for health reporting (C# `BackgroundJobCatalog`).
#[derive(Default)]
pub struct JobCatalog {
    jobs: Mutex<BTreeMap<String, BackgroundJobStatus>>,
}

impl JobCatalog {
    /// Ordered by id (ordinal), like the C# catalog.
    pub fn list(&self) -> Vec<BackgroundJobStatus> {
        self.lock().values().cloned().collect()
    }

    pub fn exists(&self, id: &str) -> bool {
        self.lock().contains_key(id)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, BackgroundJobStatus>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn update(&self, id: &str, change: impl FnOnce(&mut BackgroundJobStatus)) {
        if let Some(status) = self.lock().get_mut(id) {
            change(status);
        }
    }
}

pub type JobFuture = Pin<Box<dyn Future<Output = Result<(), &'static str>> + Send>>;
pub type JobFn = Arc<dyn Fn() -> JobFuture + Send + Sync>;

struct RegisteredJob {
    id: &'static str,
    schedule: Schedule,
    retry_attempts: u32,
    run: JobFn,
    /// Run once immediately instead of waiting for the first occurrence.
    triggered: bool,
}

/// Registers jobs and runs each on its own task (one execution at a time per job,
/// like `[DisableConcurrentExecution]`).
pub struct JobScheduler {
    catalog: Arc<JobCatalog>,
    clock: Arc<dyn Clock>,
    jobs: Vec<RegisteredJob>,
}

impl JobScheduler {
    pub fn new(catalog: Arc<JobCatalog>, clock: Arc<dyn Clock>) -> Self {
        Self {
            catalog,
            clock,
            jobs: Vec::new(),
        }
    }

    /// `IRecurringJobManager.AddOrUpdate` with `[AutomaticRetry(Attempts = retry_attempts)]`.
    pub fn add(&mut self, id: &'static str, schedule: Schedule, retry_attempts: u32, run: JobFn) {
        let next = schedule.next_after(self.clock.utc_now());
        self.catalog.lock().insert(
            id.to_string(),
            BackgroundJobStatus {
                id: id.to_string(),
                schedule: schedule.cron(),
                last_run_at: None,
                last_state: None,
                next_run_at: Some(next),
            },
        );
        self.jobs.push(RegisteredJob {
            id,
            schedule,
            retry_attempts,
            run,
            triggered: false,
        });
    }

    /// `RecurringJobRegistry.Trigger`: requests an immediate run. Returns false for an
    /// unknown job id.
    pub fn trigger(&mut self, id: &str) -> bool {
        match self.jobs.iter_mut().find(|job| job.id == id) {
            Some(job) => {
                job.triggered = true;
                true
            }
            None => false,
        }
    }

    pub fn spawn(self, shutdown: &ShutdownToken) -> Vec<JoinHandle<()>> {
        self.jobs
            .into_iter()
            .map(|job| {
                let catalog = Arc::clone(&self.catalog);
                let clock = Arc::clone(&self.clock);
                let shutdown = shutdown.clone();
                tokio::spawn(async move { run_recurring(job, catalog, clock, shutdown).await })
            })
            .collect()
    }
}

async fn run_recurring(
    job: RegisteredJob,
    catalog: Arc<JobCatalog>,
    clock: Arc<dyn Clock>,
    shutdown: ShutdownToken,
) {
    let mut triggered = job.triggered;
    loop {
        // Re-check the wall clock at least every minute so long sleeps track clock changes.
        let next = job.schedule.next_after(clock.utc_now());
        // A triggered job runs once immediately, then follows its schedule.
        if !std::mem::take(&mut triggered) {
            loop {
                let remaining = (next - clock.utc_now()).to_std().unwrap_or(Duration::ZERO);
                if remaining.is_zero() {
                    break;
                }
                if !shutdown.sleep(remaining.min(Duration::from_secs(60))).await {
                    return;
                }
            }
        }

        let started = truncate_to_ticks(clock.utc_now());
        catalog.update(job.id, |status| {
            status.last_run_at = Some(started);
            status.last_state = Some("Processing".into());
            status.next_run_at = Some(job.schedule.next_after(started));
        });

        let mut attempt = 0u32;
        let state = loop {
            let outcome = tokio::select! {
                outcome = (job.run)() => outcome,
                () = shutdown.cancelled() => return,
            };
            match outcome {
                Ok(()) => break "Succeeded",
                Err(failure) if attempt < job.retry_attempts => {
                    attempt += 1;
                    warn!(
                        job = job.id,
                        failure_type = failure,
                        attempt,
                        "Background job failed; retry scheduled."
                    );
                    catalog.update(job.id, |status| {
                        status.last_state = Some("Scheduled".into())
                    });
                    if !shutdown.sleep(hangfire_retry_delay(attempt)).await {
                        return;
                    }
                    catalog.update(job.id, |status| {
                        status.last_state = Some("Processing".into())
                    });
                }
                Err(failure) => {
                    warn!(
                        job = job.id,
                        failure_type = failure,
                        "Background job failed."
                    );
                    break "Failed";
                }
            }
        };
        catalog.update(job.id, |status| status.last_state = Some(state.into()));
    }
}

/// Hangfire `AutomaticRetryAttribute` default back-off:
/// `(attempt - 1)^4 + 15 + random(0..30) * attempt` seconds.
fn hangfire_retry_delay(attempt: u32) -> Duration {
    let attempt = f64::from(attempt);
    let random = (random_unit() * 30.0).floor();
    Duration::from_secs_f64(((attempt - 1.0).powi(4) + 15.0 + random * attempt).round())
}

/// Removes acknowledged events older than the duplicate-detection window
/// (C# `QueueRetentionJob`). Undelivered, retrying and dead-lettered events are
/// never touched.
pub async fn run_queue_retention(
    queue: Arc<dyn DurableEventStore>,
    clock: Arc<dyn Clock>,
    retention: Duration,
) -> Result<usize, &'static str> {
    let cutoff = clock.utc_now() - TimeDelta::from_std(retention).unwrap_or(TimeDelta::MAX);
    let total = tokio::task::spawn_blocking(move || {
        let mut total = 0usize;
        loop {
            let purged = queue.purge_delivered(cutoff, RETENTION_BATCH_SIZE)?;
            total += purged;
            if purged != RETENTION_BATCH_SIZE {
                return Ok(total);
            }
        }
    })
    .await
    .map_err(|_| "JoinError")?
    .map_err(|error| store_error_name(&error))?;
    info!(
        count = total,
        "Queue retention removed acknowledged event(s)."
    );
    Ok(total)
}

/// Checkpoints the WAL and refreshes SQLite statistics (C# `QueueMaintenanceJob`).
pub async fn run_queue_maintenance(queue: Arc<dyn DurableEventStore>) -> Result<(), &'static str> {
    tokio::task::spawn_blocking(move || queue.maintain())
        .await
        .map_err(|_| "JoinError")?
        .map_err(|error| store_error_name(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        bower_contracts::time::parse(text).unwrap()
    }

    #[test]
    fn schedules_match_hangfire_cron() {
        let now = at("2026-10-17T02:59:30.5Z");
        assert_eq!(
            Schedule::Minutely.next_after(now),
            at("2026-10-17T03:00:00Z")
        );
        assert_eq!(Schedule::Hourly.next_after(now), at("2026-10-17T03:00:00Z"));
        assert_eq!(
            Schedule::Daily(3).next_after(now),
            at("2026-10-17T03:00:00Z")
        );
        assert_eq!(
            Schedule::Daily(3).next_after(at("2026-10-17T03:00:00Z")),
            at("2026-10-18T03:00:00Z")
        );
        assert_eq!(
            Schedule::Hourly.next_after(at("2026-10-17T03:00:00+10:00")),
            at("2026-10-16T18:00:00Z")
        );
        assert_eq!(Schedule::Daily(3).cron(), "0 3 * * *");
        assert_eq!(Schedule::Hourly.cron(), "0 * * * *");
    }

    #[test]
    fn retry_delay_follows_hangfire() {
        let first = hangfire_retry_delay(1).as_secs();
        assert!((15..=44).contains(&first));
        let third = hangfire_retry_delay(3).as_secs();
        assert!((31..=31 + 29 * 3).contains(&third));
    }
}
