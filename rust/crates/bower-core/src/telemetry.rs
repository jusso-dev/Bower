//! In-process selection counters and source activity (C# `PipelineTelemetry`).
//!
//! Counters show how many candidates and bytes arrived, which stage and policy decided
//! each, and what was queued, duplicated or suppressed. They reset on restart and never
//! hold payload content. Source activity is loaded from and flushed to the queue so
//! silence detection survives restarts.
//!
//! Intake counters ([`PipelineTelemetry::intake_snapshot`]) count every candidate
//! submitted to processing and every queue-capacity refusal. A `queue-capacity` refusal
//! committed nothing and never reaches the selection counters; a `privacy-alert-capacity`
//! refusal follows a selection outcome that is already recorded. They also reset only on
//! restart; there is no reset.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bower_contracts::time::{self, Clock, Timestamp};
use bower_contracts::{DecisionAction, SourceActivity};

use crate::processor::{ProcessingResult, ProcessingStage};

pub const NO_POLICY: &str = "-";
pub const MAXIMUM_SOURCES: usize = 10_000;
/// Bounded reason code: the queue refused the event itself; nothing was committed.
pub const QUEUE_CAPACITY_REASON: &str = "queue-capacity";
/// Bounded reason code: the queue refused the privacy alert after the event was decided
/// (and, when accepted, committed).
pub const PRIVACY_ALERT_CAPACITY_REASON: &str = "privacy-alert-capacity";
/// `last_refusal` before any refusal.
const NO_REFUSAL: i64 = i64::MIN;

#[derive(Clone, Copy, Debug, Default)]
struct Counter {
    events: i64,
    queued: i64,
    duplicates: i64,
    suppressed: i64,
    bytes_in: i64,
    bytes_queued: i64,
}

#[derive(Default)]
struct State {
    counters: HashMap<(ProcessingStage, String, DecisionAction), Counter>,
    sources: HashMap<(String, String), SourceActivity>,
    dirty: HashSet<(String, String)>,
}

pub struct PipelineTelemetry {
    clock: Arc<dyn Clock>,
    started_at: Timestamp,
    state: Mutex<State>,
    attempted_requests: AtomicI64,
    attempted_bytes: AtomicI64,
    capacity_refusals: AtomicI64,
    capacity_refused_bytes: AtomicI64,
    privacy_alert_refusals: AtomicI64,
    privacy_alert_refused_bytes: AtomicI64,
    /// 100 ns ticks since the Unix epoch * 2 + reason bit (0 queue, 1 privacy alert).
    last_refusal: AtomicI64,
}

impl std::fmt::Debug for PipelineTelemetry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PipelineTelemetry")
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

/// Selection counters since `started_at`. Queued bytes include Bower decision
/// context, so accepted traffic can exceed its input bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineMetricsSnapshot {
    pub started_at: Timestamp,
    pub events_in: i64,
    pub events_queued: i64,
    pub duplicates: i64,
    pub suppressed: i64,
    pub bytes_in: i64,
    pub bytes_queued: i64,
    pub rows: Vec<PipelineMetricsRow>,
}

/// Intake counters since `observed_since` (process start). Attempts are candidates
/// submitted to processing after authentication and authorisation. Capacity refusals
/// are attempts whose event the queue refused: nothing was committed. Privacy alert
/// refusals are attempts whose privacy alert the queue refused after the event's outcome
/// was recorded in the selection counters (an accepted event is then already queued).
/// Metadata only: no payloads, event ids or credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeMetricsSnapshot {
    pub observed_since: Timestamp,
    pub attempted_requests: i64,
    pub attempted_bytes: i64,
    pub capacity_refusals: i64,
    pub capacity_refused_bytes: i64,
    pub privacy_alert_refusals: i64,
    pub privacy_alert_refused_bytes: i64,
    pub last_refusal_at: Option<Timestamp>,
    pub last_refusal_reason: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineMetricsRow {
    pub stage: String,
    pub policy_id: String,
    pub action: String,
    pub events: i64,
    pub queued: i64,
    pub duplicates: i64,
    pub suppressed: i64,
    pub bytes_in: i64,
    pub bytes_queued: i64,
}

fn ordinal(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

impl PipelineTelemetry {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            started_at: clock.utc_now(),
            clock,
            state: Mutex::new(State::default()),
            attempted_requests: AtomicI64::new(0),
            attempted_bytes: AtomicI64::new(0),
            capacity_refusals: AtomicI64::new(0),
            capacity_refused_bytes: AtomicI64::new(0),
            privacy_alert_refusals: AtomicI64::new(0),
            privacy_alert_refused_bytes: AtomicI64::new(0),
            last_refusal: AtomicI64::new(NO_REFUSAL),
        }
    }

    /// Counts one candidate submitted to processing, before any outcome is known.
    pub fn record_attempt(&self, bytes_in: i64) {
        self.attempted_requests.fetch_add(1, Ordering::SeqCst);
        self.attempted_bytes.fetch_add(bytes_in, Ordering::SeqCst);
    }

    /// Counts one attempt whose event the queue refused for capacity (HTTP 503).
    pub fn record_capacity_refusal(&self, bytes_in: i64) {
        self.mark_refusal(0);
        self.capacity_refused_bytes
            .fetch_add(bytes_in, Ordering::SeqCst);
        self.capacity_refusals.fetch_add(1, Ordering::SeqCst);
    }

    /// Counts one attempt whose privacy alert the queue refused for capacity (HTTP 503).
    pub fn record_privacy_alert_refusal(&self, bytes_in: i64) {
        self.mark_refusal(1);
        self.privacy_alert_refused_bytes
            .fetch_add(bytes_in, Ordering::SeqCst);
        self.privacy_alert_refusals.fetch_add(1, Ordering::SeqCst);
    }

    /// Forward only, so concurrent refusals keep the latest time and its reason.
    fn mark_refusal(&self, reason_bit: i64) {
        let ticks = self
            .clock
            .utc_now()
            .timestamp_nanos_opt()
            .map_or(i64::MAX / 2, |nanos| nanos.div_euclid(100));
        self.last_refusal
            .fetch_max((ticks << 1) | reason_bit, Ordering::SeqCst);
    }

    pub fn intake_snapshot(&self) -> IntakeMetricsSnapshot {
        // Read in the reverse of write order. Writers set the last refusal, then bytes,
        // then the count, and count the attempt before any of these, so a snapshot never
        // shows a refusal without its time and reason, or more refusals than attempts.
        let capacity_refusals = self.capacity_refusals.load(Ordering::SeqCst);
        let privacy_alert_refusals = self.privacy_alert_refusals.load(Ordering::SeqCst);
        let capacity_refused_bytes = self.capacity_refused_bytes.load(Ordering::SeqCst);
        let privacy_alert_refused_bytes = self.privacy_alert_refused_bytes.load(Ordering::SeqCst);
        let last = self.last_refusal.load(Ordering::SeqCst);
        let last_refusal_at = (last != NO_REFUSAL).then(|| {
            time::to_utc(chrono::DateTime::from_timestamp_nanos((last >> 1) * 100).fixed_offset())
        });
        IntakeMetricsSnapshot {
            observed_since: self.started_at,
            attempted_requests: self.attempted_requests.load(Ordering::SeqCst),
            attempted_bytes: self.attempted_bytes.load(Ordering::SeqCst),
            capacity_refusals,
            capacity_refused_bytes,
            privacy_alert_refusals,
            privacy_alert_refused_bytes,
            last_refusal_reason: last_refusal_at.map(|_| {
                if last & 1 == 0 {
                    QUEUE_CAPACITY_REASON
                } else {
                    PRIVACY_ALERT_CAPACITY_REASON
                }
            }),
            last_refusal_at,
        }
    }

    pub fn started_at(&self) -> Timestamp {
        self.started_at
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn record(&self, result: &ProcessingResult, bytes_in: i64) {
        let policy = result
            .policy_decision
            .as_ref()
            .map_or(NO_POLICY, |decision| decision.policy_id.as_str())
            .to_owned();
        let mut state = self.lock();
        let counter = state
            .counters
            .entry((result.stage, policy, result.action))
            .or_default();
        counter.events += 1;
        counter.bytes_in += bytes_in;
        counter.bytes_queued += result.queued_bytes;
        counter.queued += i64::from(result.queued);
        counter.duplicates += i64::from(result.duplicate);
        counter.suppressed += i64::from(result.suppressed);

        if let Some(source) = &result.source
            && (result.queued || result.duplicate || result.suppressed)
        {
            let key = (source.application.clone(), source.environment.clone());
            let now = self.clock.utc_now();
            if let Some(seen) = state.sources.get_mut(&key) {
                seen.last_seen_at = now;
                seen.event_count += 1;
                state.dirty.insert(key);
            } else if state.sources.len() < MAXIMUM_SOURCES {
                state.sources.insert(
                    key.clone(),
                    SourceActivity {
                        application: source.application.clone(),
                        environment: source.environment.clone(),
                        last_seen_at: now,
                        event_count: 1,
                    },
                );
                state.dirty.insert(key);
            }
        }
    }

    /// Seeds activity from durable storage at start-up.
    pub fn load(&self, activity: impl IntoIterator<Item = SourceActivity>) {
        let mut state = self.lock();
        for item in activity {
            let key = (item.application.clone(), item.environment.clone());
            let newer = state
                .sources
                .get(&key)
                .is_none_or(|current| current.last_seen_at < item.last_seen_at);
            if newer && (state.sources.len() < MAXIMUM_SOURCES || state.sources.contains_key(&key))
            {
                state.sources.insert(key, item);
            }
        }
    }

    /// Sources changed since the last call, for flushing to storage.
    pub fn take_changed_sources(&self) -> Vec<SourceActivity> {
        let mut state = self.lock();
        let dirty: Vec<(String, String)> = state.dirty.drain().collect();
        dirty
            .iter()
            .filter_map(|key| state.sources.get(key).cloned())
            .collect()
    }

    /// Returns sources to the changed set after a failed flush.
    pub fn mark_changed(&self, activity: &[SourceActivity]) {
        let mut state = self.lock();
        for item in activity {
            state
                .dirty
                .insert((item.application.clone(), item.environment.clone()));
        }
    }

    pub fn sources(&self) -> Vec<SourceActivity> {
        let mut sources: Vec<SourceActivity> = self.lock().sources.values().cloned().collect();
        sources.sort_by(|left, right| {
            ordinal(&left.application, &right.application)
                .then_with(|| ordinal(&left.environment, &right.environment))
        });
        sources
    }

    pub fn snapshot(&self) -> PipelineMetricsSnapshot {
        let mut rows: Vec<PipelineMetricsRow> = self
            .lock()
            .counters
            .iter()
            .map(|((stage, policy, action), counter)| PipelineMetricsRow {
                stage: stage_name(*stage).to_owned(),
                policy_id: policy.clone(),
                action: action_name(*action),
                events: counter.events,
                queued: counter.queued,
                duplicates: counter.duplicates,
                suppressed: counter.suppressed,
                bytes_in: counter.bytes_in,
                bytes_queued: counter.bytes_queued,
            })
            .collect();
        rows.sort_by(|left, right| {
            ordinal(&left.stage, &right.stage)
                .then_with(|| ordinal(&left.policy_id, &right.policy_id))
                .then_with(|| ordinal(&left.action, &right.action))
        });
        let sum = |field: fn(&PipelineMetricsRow) -> i64| rows.iter().map(field).sum::<i64>();
        PipelineMetricsSnapshot {
            started_at: self.started_at,
            events_in: sum(|row| row.events),
            events_queued: sum(|row| row.queued),
            duplicates: sum(|row| row.duplicates),
            suppressed: sum(|row| row.suppressed),
            bytes_in: sum(|row| row.bytes_in),
            bytes_queued: sum(|row| row.bytes_queued),
            rows,
        }
    }
}

pub fn stage_name(stage: ProcessingStage) -> &'static str {
    match stage {
        ProcessingStage::Redaction => "redaction",
        ProcessingStage::Schema => "schema",
        ProcessingStage::Validation => "validation",
        ProcessingStage::Policy => "policy",
        ProcessingStage::Transform => "transform",
    }
}

pub fn action_name(action: DecisionAction) -> String {
    match action {
        DecisionAction::RedactAndAccept => "redact-and-accept".to_owned(),
        DecisionAction::DeadLetter => "dead-letter".to_owned(),
        other => other.pascal_name().to_lowercase(),
    }
}
