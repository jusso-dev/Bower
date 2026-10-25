//! In-process selection counters and source activity (C# `PipelineTelemetry`).
//!
//! Counters show how many candidates and bytes arrived, which stage and policy decided
//! each, and what was queued, duplicated or suppressed. They reset on restart and never
//! hold payload content. Source activity is loaded from and flushed to the queue so
//! silence detection survives restarts.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{DecisionAction, SourceActivity};

use crate::processor::{ProcessingResult, ProcessingStage};

pub const NO_POLICY: &str = "-";
pub const MAXIMUM_SOURCES: usize = 10_000;

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
    }
}

pub fn action_name(action: DecisionAction) -> String {
    match action {
        DecisionAction::RedactAndAccept => "redact-and-accept".to_owned(),
        DecisionAction::DeadLetter => "dead-letter".to_owned(),
        other => other.pascal_name().to_lowercase(),
    }
}
