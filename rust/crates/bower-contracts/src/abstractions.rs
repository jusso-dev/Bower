//! Data-plane seams mirroring `Bower.Abstractions`.
//!
//! The durable store is synchronous (SQLite is local and fast); async callers
//! wrap it in `tokio::task::spawn_blocking`. Output adapters perform network I/O
//! and are async.

use std::future::Future;
use std::time::Duration;

use indexmap::IndexMap;

use crate::envelope::{DecisionAction, SecurityEventEnvelope};
use crate::time::Timestamp;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RedactionResult {
    pub succeeded: bool,
    pub redacted_json: Option<String>,
    pub removed_paths: Vec<String>,
    pub masked_paths: Vec<String>,
    pub failure_code: Option<String>,
    /// Detector ids observed during the privacy scan. Never original values.
    pub privacy_detected: Option<Vec<String>>,
    /// Per-detector action labels. Never original values.
    pub privacy_actions: Option<IndexMap<String, String>>,
}

impl RedactionResult {
    pub fn failed(code: impl Into<String>) -> Self {
        Self {
            succeeded: false,
            failure_code: Some(code.into()),
            ..Self::default()
        }
    }
}

pub trait EventRedactor: Send + Sync {
    fn redact(&self, json: &str) -> RedactionResult;
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyDecision {
    pub action: DecisionAction,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub score: i32,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}

pub trait TelemetryPolicyEvaluator: Send + Sync {
    fn evaluate(&self, candidate: &SecurityEventEnvelope) -> PolicyDecision;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum QueueState {
    #[default]
    Queued,
    Uploading,
    Retrying,
    Delivered,
    DeadLettered,
}

impl QueueState {
    /// Stored integer value (C# enum ordinal).
    pub fn ordinal(self) -> i64 {
        self as i64
    }

    pub fn from_ordinal(value: i64) -> Option<Self> {
        [
            Self::Queued,
            Self::Uploading,
            Self::Retrying,
            Self::Delivered,
            Self::DeadLettered,
        ]
        .get(usize::try_from(value).ok()?)
        .copied()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueuedEvent {
    pub event_id: String,
    pub fingerprint: String,
    pub payload: String,
    pub received_at: Timestamp,
    pub state: QueueState,
    pub delivery_attempts: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnqueueResult {
    pub enqueued: bool,
    pub duplicate: bool,
    pub event_id: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QueueSnapshot {
    pub queued: i64,
    pub retrying: i64,
    pub uploading: i64,
    pub delivered: i64,
    pub dead_lettered: i64,
    pub total_bytes: i64,
    pub oldest_undelivered: Option<Timestamp>,
    pub undelivered_bytes: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeadLetterRecord {
    pub event_id: String,
    pub failure_code: Option<String>,
    pub delivery_attempts: i32,
    pub received_at: Timestamp,
}

/// One failed delivery to settle (C# `FailureSettlement`). `retry_after` set
/// schedules a retry; `None` dead-letters the event with `failure_code`.
#[derive(Clone, Debug, PartialEq)]
pub struct FailureSettlement {
    pub event_id: String,
    pub failure_code: String,
    pub retry_after: Option<Timestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerHead {
    pub sequence: i64,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerIssue {
    pub sequence: i64,
    pub event_id: String,
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerVerification {
    pub intact: bool,
    pub entries: i64,
    pub head_sequence: i64,
    pub head_hash: String,
    pub issues: Vec<LedgerIssue>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("queue storage failure: {0}")]
    Storage(String),
    #[error("queue is full: {0}")]
    Full(String),
    #[error("invalid queue operation: {0}")]
    Invalid(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// `ArgumentException.ThrowIfNullOrWhiteSpace` for batch arguments.
fn require_batch_text(value: &str, name: &str) -> StoreResult<()> {
    if value.chars().all(char::is_whitespace) {
        Err(StoreError::Invalid(format!(
            "{name} cannot be empty or whitespace."
        )))
    } else {
        Ok(())
    }
}

/// Durable, idempotent event queue. Never deletes before acknowledgement.
pub trait DurableEventStore: Send + Sync {
    fn initialize(&self) -> StoreResult<()>;
    fn enqueue(&self, candidate: &QueuedEvent) -> StoreResult<EnqueueResult>;
    fn lease(
        &self,
        maximum_count: usize,
        lease_duration: Duration,
    ) -> StoreResult<Vec<QueuedEvent>>;
    fn mark_delivered(&self, event_id: &str, acknowledgement: &str) -> StoreResult<()>;
    fn mark_retrying(
        &self,
        event_id: &str,
        failure_code: &str,
        retry_after: Timestamp,
    ) -> StoreResult<()>;
    fn mark_dead_lettered(&self, event_id: &str, failure_code: &str) -> StoreResult<()>;
    /// Marks every listed event that is still leased (uploading) as delivered and
    /// returns the ones that were not (for example reclaimed after lease expiry).
    ///
    /// Stores should override this to settle the batch in one transaction; the
    /// default settles event by event and is not atomic.
    fn mark_delivered_batch(
        &self,
        event_ids: &[String],
        acknowledgement: &str,
    ) -> StoreResult<Vec<String>> {
        require_batch_text(acknowledgement, "acknowledgement")?;
        for event_id in event_ids {
            require_batch_text(event_id, "eventId")?;
        }
        let mut not_leased = Vec::new();
        for event_id in event_ids {
            match self.mark_delivered(event_id, acknowledgement) {
                Ok(()) => {}
                Err(StoreError::Invalid(_)) => not_leased.push(event_id.clone()),
                Err(error) => return Err(error),
            }
        }
        Ok(not_leased)
    }
    /// Settles failed deliveries: every listed event still leased becomes retrying
    /// (`retry_after` set) or dead-lettered (`None`); the rest are returned untouched.
    ///
    /// Stores should override this to settle the batch in one transaction (nothing
    /// settled on error); the default settles event by event and is not atomic.
    fn mark_failed_batch(&self, failures: &[FailureSettlement]) -> StoreResult<Vec<String>> {
        for failure in failures {
            require_batch_text(&failure.event_id, "eventId")?;
            require_batch_text(&failure.failure_code, "failureCode")?;
        }
        let mut not_leased = Vec::new();
        for failure in failures {
            let settled = match failure.retry_after {
                Some(retry_after) => {
                    self.mark_retrying(&failure.event_id, &failure.failure_code, retry_after)
                }
                None => self.mark_dead_lettered(&failure.event_id, &failure.failure_code),
            };
            match settled {
                Ok(()) => {}
                Err(StoreError::Invalid(_)) => not_leased.push(failure.event_id.clone()),
                Err(error) => return Err(error),
            }
        }
        Ok(not_leased)
    }
    fn snapshot(&self) -> StoreResult<QueueSnapshot>;
    /// Removes delivered events acknowledged before `delivered_before`. Never removes
    /// undelivered events.
    fn purge_delivered(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
    ) -> StoreResult<usize>;
    /// Checkpoints and optimises storage. Never changes event state.
    fn maintain(&self) -> StoreResult<()>;
    /// Dead-lettered events, metadata only (never payloads).
    fn list_dead_lettered(&self, maximum_count: usize) -> StoreResult<Vec<DeadLetterRecord>>;
    /// Requeues dead letters filtered by failure code prefix and/or ids; with
    /// neither filter nothing is replayed.
    fn replay_dead_lettered(
        &self,
        failure_code_prefix: Option<&str>,
        event_ids: Option<&[String]>,
        maximum_count: usize,
    ) -> StoreResult<usize>;
    fn ledger_head(&self) -> StoreResult<LedgerHead>;
    fn verify_ledger(&self) -> StoreResult<LedgerVerification>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceCursorSnapshot {
    pub value: String,
    pub version: i64,
}

pub trait SourceCursorStore: Send + Sync {
    fn read(&self, source_id: &str) -> StoreResult<Option<SourceCursorSnapshot>>;
    fn try_advance(
        &self,
        source_id: &str,
        expected_version: i64,
        value: &str,
        updated_at: Timestamp,
    ) -> StoreResult<bool>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryFailure {
    pub event_id: String,
    pub code: String,
    pub is_retryable: bool,
    pub retry_after: Option<Timestamp>,
}

impl DeliveryFailure {
    /// Reserved persisted code namespace: destination outages do not spend poison budgets.
    pub fn is_destination_failure(&self) -> bool {
        self.code.starts_with("destination-")
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeliveryResult {
    pub acknowledged_event_ids: Vec<String>,
    pub failures: Vec<DeliveryFailure>,
    pub destination_acknowledgement: Option<String>,
}

/// Bounded delivery adapter. Must honour cancellation by being drop-safe.
pub trait OutputAdapter: Send + Sync {
    fn id(&self) -> &str;
    fn deliver(&self, events: &[QueuedEvent]) -> impl Future<Output = DeliveryResult> + Send;
}
