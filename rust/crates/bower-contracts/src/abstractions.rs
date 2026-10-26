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
    /// Suppression key resolved for an accepted event from its policy.
    pub suppression: Option<SuppressionDirective>,
}

/// Suppression key resolved for one accepted event from its policy (C# `SuppressionDirective`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppressionDirective {
    pub key_fields: Vec<String>,
    pub key_values: Vec<String>,
    pub window_seconds: i32,
    pub allow_per_window: i32,
}

/// Application and environment that produced an accepted event (C# `SourceActivity`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceActivity {
    pub application: String,
    pub environment: String,
    pub last_seen_at: Timestamp,
    pub event_count: i64,
}

/// When the collector began expecting an application and environment (C#
/// `SourceMonitoring`). The silence allowance of a source never seen runs from here,
/// independent of process start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMonitoring {
    pub application: String,
    pub environment: String,
    pub monitoring_since: Timestamp,
}

/// Admission request for an event accepted by a suppressing policy (C#
/// `SuppressionRequest`). Key values come from the redacted envelope and are stored
/// until the window closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppressionRequest {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub key_hash: String,
    pub key_fields: Vec<String>,
    pub key_values: Vec<String>,
    pub window_seconds: i32,
    pub allow_per_window: i32,
    pub event_category: String,
    pub event_type: String,
    pub application: String,
    pub environment: String,
    pub tenant_id: Option<String>,
}

/// One closed (or closing) suppression window (C# `SuppressionWindow`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppressionWindow {
    pub rule: SuppressionRequest,
    pub window_start: Timestamp,
    pub window_end: Timestamp,
    pub admitted: i64,
    pub suppressed: i64,
    pub first_suppressed_at: Option<Timestamp>,
    pub last_suppressed_at: Option<Timestamp>,
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
    pub lease_token: Option<String>,
    /// Set for an event accepted by a suppressing policy; never persisted with the event.
    pub suppression: Option<SuppressionRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnqueueResult {
    pub enqueued: bool,
    pub duplicate: bool,
    pub event_id: String,
    /// Accepted but counted instead of queued: the window allowance was spent.
    pub suppressed: bool,
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
    pub lease_token: Option<String>,
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
    fn mark_delivered(
        &self,
        event_id: &str,
        acknowledgement: &str,
        lease_token: Option<&str>,
    ) -> StoreResult<()>;
    fn mark_retrying(
        &self,
        event_id: &str,
        failure_code: &str,
        retry_after: Timestamp,
        lease_token: Option<&str>,
    ) -> StoreResult<()>;
    fn mark_dead_lettered(
        &self,
        event_id: &str,
        failure_code: &str,
        lease_token: Option<&str>,
    ) -> StoreResult<()>;
    /// Marks every listed event that is still leased (uploading) as delivered and
    /// returns the ones that were not (for example reclaimed after lease expiry).
    ///
    /// Stores should override this to settle the batch in one transaction; the
    /// default settles event by event and is not atomic.
    fn mark_delivered_batch(
        &self,
        event_ids: &[String],
        acknowledgement: &str,
        lease_tokens: &std::collections::HashMap<String, String>,
    ) -> StoreResult<Vec<String>> {
        require_batch_text(acknowledgement, "acknowledgement")?;
        for event_id in event_ids {
            require_batch_text(event_id, "eventId")?;
        }
        let mut not_leased = Vec::new();
        for event_id in event_ids {
            match self.mark_delivered(
                event_id,
                acknowledgement,
                lease_tokens.get(event_id).map(String::as_str),
            ) {
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
                Some(retry_after) => self.mark_retrying(
                    &failure.event_id,
                    &failure.failure_code,
                    retry_after,
                    failure.lease_token.as_deref(),
                ),
                None => self.mark_dead_lettered(
                    &failure.event_id,
                    &failure.failure_code,
                    failure.lease_token.as_deref(),
                ),
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

    /// As [`DurableEventStore::purge_delivered`], but only events whose ledger sequence is
    /// at or below `archived_through_sequence` are eligible, so nothing is purged before
    /// the archive holds it. Stores without a ledger refuse (nothing is purged).
    fn purge_delivered_archived(
        &self,
        _delivered_before: Timestamp,
        _maximum_count: usize,
        _archived_through_sequence: i64,
    ) -> StoreResult<usize> {
        Err(unsupported_store_operation())
    }

    /// Closes every suppression window that ended at or before `now`. A window that
    /// suppressed events is replaced, in the same transaction, by the summary event
    /// `create_summary` builds; if that fails nothing is closed.
    fn close_expired_suppression_windows(
        &self,
        _now: Timestamp,
        _create_summary: &mut dyn FnMut(&SuppressionWindow) -> StoreResult<QueuedEvent>,
    ) -> StoreResult<usize> {
        Err(unsupported_store_operation())
    }

    /// Last accepted event per application and environment.
    fn get_source_activity(&self) -> StoreResult<Vec<SourceActivity>> {
        Err(unsupported_store_operation())
    }

    /// Merges observations: keeps the later time and the larger count per source.
    fn upsert_source_activity(&self, _activity: &[SourceActivity]) -> StoreResult<()> {
        Err(unsupported_store_operation())
    }

    /// Makes `expected` the monitored set. A source already monitored keeps its stored
    /// start; a new one starts at its proposed time; a source no longer expected is
    /// forgotten, so expecting it again starts afresh. Returns the stored starts.
    fn start_source_monitoring(
        &self,
        _expected: &[SourceMonitoring],
    ) -> StoreResult<Vec<SourceMonitoring>> {
        Err(unsupported_store_operation())
    }
}

/// C# `RequestEventBuffer.Unsupported()`: hosts without a durable queue or ledger.
pub fn unsupported_store_operation() -> StoreError {
    StoreError::Invalid("This host has no durable queue or ledger.".into())
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
