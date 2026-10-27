//! `Bower.Core.SecurityEventProcessor`: redact, deserialize, validate, evaluate
//! policy, enqueue. Order is fixed; redaction failure quarantines without persisting.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use bower_contracts::envelope::{
    ActorContext, ActorType, CURRENT_SCHEMA_VERSION, CollectorContext, DecisionAction, EventResult,
    EventSeverity, PrivacyContext, RequestContext, SecurityDecisionContext, SecurityEventEnvelope,
    TargetContext,
};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::types::{event_categories, event_types};
use bower_contracts::{
    DurableEventStore, EventRedactor, PolicyDecision, QueueState, QueuedEvent, RedactionResult,
    StoreError, SuppressionRequest, TelemetryPolicyEvaluator, json,
};
use chrono::{Duration, Months};
use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use crate::telemetry::PipelineTelemetry;
use crate::{fingerprint, privacy, suppression};

/// Identity stamped into `collector` on every queued event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectorIdentity {
    pub id: String,
    pub version: String,
    pub source_adapter: String,
    pub configuration_hash: String,
}

impl CollectorIdentity {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        source_adapter: impl Into<String>,
        configuration_hash: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            source_adapter: source_adapter.into(),
            configuration_hash: configuration_hash.into(),
        }
    }

    fn context(&self, received_at: Timestamp) -> CollectorContext {
        CollectorContext {
            id: self.id.clone(),
            version: self.version.clone(),
            source_adapter: self.source_adapter.clone(),
            configuration_hash: self.configuration_hash.clone(),
            batch_id: None,
            received_at,
        }
    }
}

/// Pipeline stage that decided an event (C# `ProcessingStage`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ProcessingStage {
    Redaction,
    Schema,
    Validation,
    #[default]
    Policy,
    /// A signed pack transform failed before redaction; nothing was persisted.
    Transform,
}

/// Application and environment of an accepted event (C# `SourceKey`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceKey {
    pub application: String,
    pub environment: String,
}

/// Outcome returned to producers. `reasons` never carry payload content.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessingResult {
    pub action: DecisionAction,
    pub event_id: Option<String>,
    pub queued: bool,
    pub duplicate: bool,
    pub reasons: Vec<String>,
    pub policy_decision: Option<PolicyDecision>,
    pub privacy_alert_event_id: Option<String>,
    /// Pipeline stage that decided the event.
    pub stage: ProcessingStage,
    /// Accepted but counted instead of queued (window allowance spent).
    pub suppressed: bool,
    /// Payload bytes queued for this event; 0 when nothing was queued.
    pub queued_bytes: i64,
    /// Application and environment of an accepted event.
    pub source: Option<SourceKey>,
}

impl ProcessingResult {
    pub fn failed(action: DecisionAction, reason: impl Into<String>) -> Self {
        Self::failed_at(action, reason, ProcessingStage::Policy)
    }

    pub fn failed_at(
        action: DecisionAction,
        reason: impl Into<String>,
        stage: ProcessingStage,
    ) -> Self {
        Self {
            action,
            event_id: None,
            queued: false,
            duplicate: false,
            reasons: vec![reason.into()],
            policy_decision: None,
            privacy_alert_event_id: None,
            stage,
            suppressed: false,
            queued_bytes: 0,
            source: None,
        }
    }

    /// Policy-stage result without suppression, bytes or source.
    fn decided(
        action: DecisionAction,
        event_id: String,
        reasons: Vec<String>,
        policy_decision: Option<PolicyDecision>,
        privacy_alert_event_id: Option<String>,
    ) -> Self {
        Self {
            action,
            event_id: Some(event_id),
            queued: false,
            duplicate: false,
            reasons,
            policy_decision,
            privacy_alert_event_id,
            stage: ProcessingStage::Policy,
            suppressed: false,
            queued_bytes: 0,
            source: None,
        }
    }
}

/// Failures of [`SecurityEventProcessor::close_suppression_windows`].
#[derive(Debug, thiserror::Error)]
pub enum SuppressionCloseError {
    /// C# `SuppressionSummaryRejectedException`: the policy set does not accept the
    /// summary, so every window stays open.
    #[error("Suppression summary was not accepted ({policy_id}: {action}); windows stay open.")]
    Rejected {
        policy_id: String,
        action: &'static str,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Failures the C# processor surfaces as exceptions.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// Queue failure; `StoreError::Full` is the capacity case
    /// (C# `QueueCapacityExceededException`).
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("event serialization failed: {0}")]
    Serialization(String),
}

/// Source-to-policy-to-queue orchestration. Synchronous because the durable store
/// is; async hosts call [`SecurityEventProcessor::process`] in `spawn_blocking`.
#[derive(Clone)]
pub struct SecurityEventProcessor {
    redactor: Arc<dyn EventRedactor>,
    policy_evaluator: Arc<dyn TelemetryPolicyEvaluator>,
    queue: Arc<dyn DurableEventStore>,
    clock: Arc<dyn Clock>,
    telemetry: Option<Arc<PipelineTelemetry>>,
}

fn accepts(action: DecisionAction) -> bool {
    matches!(
        action,
        DecisionAction::Accept | DecisionAction::RedactAndAccept
    )
}

impl SecurityEventProcessor {
    pub fn new(
        redactor: Arc<dyn EventRedactor>,
        policy_evaluator: Arc<dyn TelemetryPolicyEvaluator>,
        queue: Arc<dyn DurableEventStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            redactor,
            policy_evaluator,
            queue,
            clock,
            telemetry: None,
        }
    }

    /// Records every processed candidate in `telemetry` (C# optional constructor argument).
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Arc<PipelineTelemetry>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    pub fn process(
        &self,
        candidate_json: &str,
        collector: &CollectorIdentity,
    ) -> Result<ProcessingResult, ProcessError> {
        let bytes_in = i64::try_from(candidate_json.len()).unwrap_or(i64::MAX);
        if let Some(telemetry) = &self.telemetry {
            telemetry.record_attempt(bytes_in);
        }
        self.process_core(candidate_json, collector, bytes_in)
    }

    /// Records the selection outcome once it is final: before any privacy alert enqueue,
    /// so an alert refused for capacity never hides an event that was already decided or
    /// queued.
    fn decided(&self, result: ProcessingResult, bytes_in: i64) -> ProcessingResult {
        if let Some(telemetry) = &self.telemetry {
            telemetry.record(&result, bytes_in);
        }
        result
    }

    /// Closes ended suppression windows and queues one policy-approved summary for each
    /// window that suppressed events. A summary the policy set does not accept aborts
    /// the close, so suppressed counts are never discarded.
    pub fn close_suppression_windows(
        &self,
        collector: &CollectorIdentity,
    ) -> Result<usize, SuppressionCloseError> {
        let now = self.clock.utc_now();
        let mut rejected: Option<SuppressionCloseError> = None;
        let closed = self
            .queue
            .close_expired_suppression_windows(now, &mut |window| {
                let summary = suppression::create_summary(window, collector, now);
                let decision = self.policy_evaluator.evaluate(&summary);
                if !accepts(decision.action) {
                    rejected = Some(SuppressionCloseError::Rejected {
                        policy_id: decision.policy_id.clone(),
                        action: decision.action.pascal_name(),
                    });
                    return Err(StoreError::Invalid("suppression-summary-rejected".into()));
                }
                let mut arranged = summary;
                arranged.security = Some(SecurityDecisionContext {
                    policy_id: decision.policy_id,
                    policy_version: decision.policy_version,
                    value_score: decision.score,
                    decision: DecisionAction::Aggregate,
                    classification_reasons: decision.reasons,
                    policy_hash: decision.policy_hash,
                });
                queued_event(&arranged, now, None)
                    .map(|(queued, _)| queued)
                    .map_err(|_| StoreError::Invalid("suppression-summary-serialization".into()))
            });
        match (closed, rejected) {
            (_, Some(rejected)) => Err(rejected),
            (Ok(count), None) => Ok(count),
            (Err(error), None) => Err(error.into()),
        }
    }

    fn process_core(
        &self,
        candidate_json: &str,
        collector: &CollectorIdentity,
        bytes_in: i64,
    ) -> Result<ProcessingResult, ProcessError> {
        // Redaction failure (including a panic) is a security failure: quarantine
        // without persisting.
        let Ok(redaction) = catch_unwind(AssertUnwindSafe(|| self.redactor.redact(candidate_json)))
        else {
            return Ok(self.decided(
                ProcessingResult::failed_at(
                    DecisionAction::Quarantine,
                    "redaction-failed",
                    ProcessingStage::Redaction,
                ),
                bytes_in,
            ));
        };

        let redacted_json = match (&redaction.succeeded, &redaction.redacted_json) {
            (true, Some(json)) => json,
            _ => {
                return Ok(self.decided(
                    ProcessingResult::failed_at(
                        DecisionAction::Quarantine,
                        redaction
                            .failure_code
                            .clone()
                            .unwrap_or_else(|| "redaction-failed".to_owned()),
                        ProcessingStage::Redaction,
                    ),
                    bytes_in,
                ));
            }
        };

        let Ok(candidate) = json::from_str::<SecurityEventEnvelope>(redacted_json) else {
            return Ok(self.decided(
                ProcessingResult::failed_at(
                    DecisionAction::Quarantine,
                    "schema-invalid",
                    ProcessingStage::Schema,
                ),
                bytes_in,
            ));
        };

        let now = self.clock.utc_now();
        let validation_failures = validate(&candidate, now);
        if !validation_failures.is_empty() {
            let quarantined = self.decided(
                ProcessingResult {
                    stage: ProcessingStage::Validation,
                    ..ProcessingResult::decided(
                        DecisionAction::Quarantine,
                        candidate.event_id.clone(),
                        validation_failures,
                        None,
                        None,
                    )
                },
                bytes_in,
            );
            // Still notify SOC when high-risk secrets/PII were present in invalid payloads.
            let alert_id =
                self.try_enqueue_privacy_alert(&candidate, &redaction, collector, bytes_in)?;
            return Ok(ProcessingResult {
                privacy_alert_event_id: alert_id,
                ..quarantined
            });
        }

        let decision = self.policy_evaluator.evaluate(&candidate);
        if !accepts(decision.action) {
            let reasons = decision
                .reasons
                .iter()
                .chain(&decision.warnings)
                .cloned()
                .collect();
            let rejected = self.decided(
                ProcessingResult::decided(
                    decision.action,
                    candidate.event_id.clone(),
                    reasons,
                    Some(decision),
                    None,
                ),
                bytes_in,
            );
            let alert_id =
                self.try_enqueue_privacy_alert(&candidate, &redaction, collector, bytes_in)?;
            return Ok(ProcessingResult {
                privacy_alert_event_id: alert_id,
                ..rejected
            });
        }

        let redacted = !redaction.removed_paths.is_empty()
            || !redaction.masked_paths.is_empty()
            || redaction
                .privacy_detected
                .as_ref()
                .is_some_and(|detected| !detected.is_empty());
        let mut arranged = candidate;
        arranged.time_observed = Some(arranged.time_observed.unwrap_or(now));
        arranged.security = Some(SecurityDecisionContext {
            policy_id: decision.policy_id.clone(),
            policy_version: decision.policy_version.clone(),
            value_score: decision.score,
            decision: if redacted {
                DecisionAction::RedactAndAccept
            } else {
                DecisionAction::Accept
            },
            classification_reasons: decision.reasons.clone(),
            policy_hash: decision.policy_hash.clone(),
        });
        arranged.collector = Some(collector.context(now));

        let request = decision
            .suppression
            .as_ref()
            .map(|directive| suppression::create_request(&arranged, &decision, directive));
        let (queued, payload_bytes) = queued_event(&arranged, now, request)?;
        let enqueue = match self.queue.enqueue(&queued) {
            Err(StoreError::Invalid(code)) if code == "event-identity-conflict" => {
                return Ok(self.decided(
                    ProcessingResult::decided(
                        DecisionAction::Quarantine,
                        arranged.event_id.clone(),
                        vec![code],
                        Some(decision),
                        None,
                    ),
                    bytes_in,
                ));
            }
            Err(error @ StoreError::Full(_)) => {
                // Nothing was committed for this attempt.
                if let Some(telemetry) = &self.telemetry {
                    telemetry.record_capacity_refusal(bytes_in);
                }
                return Err(error.into());
            }
            other => other?,
        };

        let action = arranged
            .security
            .as_ref()
            .map_or(DecisionAction::Accept, |security| security.decision);
        // The event is committed (or deduplicated or suppressed): record it before the alert.
        let committed = self.decided(
            ProcessingResult {
                action,
                event_id: Some(arranged.event_id.clone()),
                queued: enqueue.enqueued,
                duplicate: enqueue.duplicate,
                reasons: Vec::new(),
                policy_decision: Some(decision.clone()),
                privacy_alert_event_id: None,
                stage: ProcessingStage::Policy,
                suppressed: enqueue.suppressed,
                queued_bytes: if enqueue.enqueued { payload_bytes } else { 0 },
                source: Some(SourceKey {
                    application: arranged.application.name.clone(),
                    environment: arranged.application.environment.clone(),
                }),
            },
            bytes_in,
        );
        if enqueue.enqueued
            && let Some(telemetry) = &self.telemetry
        {
            // Counted once per stored event: a duplicate or suppressed retry adds nothing.
            telemetry.record_redactions(redaction.privacy_detected.as_deref().unwrap_or(&[]));
        }
        let privacy_alert_event_id =
            self.try_enqueue_privacy_alert(&arranged, &redaction, collector, bytes_in)?;

        let mut reasons: Vec<String> = decision
            .reasons
            .iter()
            .chain(&decision.warnings)
            .cloned()
            .collect();
        if !redaction.removed_paths.is_empty() {
            reasons.push(format!(
                "Removed {} prohibited field(s)",
                redaction.removed_paths.len()
            ));
        }
        if !redaction.masked_paths.is_empty() {
            reasons.push(format!(
                "Masked {} personal field(s)",
                redaction.masked_paths.len()
            ));
        }
        if let Some(alert_id) = &privacy_alert_event_id {
            reasons.push(format!("Emitted privacy alert event {alert_id}"));
        }
        if enqueue.duplicate {
            reasons.push("Duplicate fingerprint already present".to_owned());
        }
        if enqueue.suppressed {
            reasons.push(
                "Suppressed: window allowance reached; counted in a summary event".to_owned(),
            );
        }

        Ok(ProcessingResult {
            reasons,
            privacy_alert_event_id,
            ..committed
        })
    }

    fn try_enqueue_privacy_alert(
        &self,
        source: &SecurityEventEnvelope,
        redaction: &RedactionResult,
        collector: &CollectorIdentity,
        bytes_in: i64,
    ) -> Result<Option<String>, ProcessError> {
        let detected: &[String] = redaction.privacy_detected.as_deref().unwrap_or(&[]);
        let empty = IndexMap::new();
        let actions = redaction.privacy_actions.as_ref().unwrap_or(&empty);

        let mut alert_worthy: Vec<String> = Vec::new();
        for id in detected {
            if privacy::is_security_event_worthy(id) && !alert_worthy.contains(id) {
                alert_worthy.push(id.clone());
            }
        }
        alert_worthy.sort_by(|left, right| compare_ordinal(left, right));
        if alert_worthy.is_empty() {
            return Ok(None);
        }

        let mut alert_actions: IndexMap<String, String> = IndexMap::new();
        for id in &alert_worthy {
            let root = privacy::root(id);
            if let Some(label) = actions.get(root) {
                alert_actions.insert(root.to_owned(), label.clone());
            } else if let Some(label) = actions.get(id.as_str()) {
                alert_actions.insert(id.clone(), label.clone());
            }
        }

        let severity = resolve_severity(&alert_worthy);
        let now = self.clock.utc_now();
        // Idempotent: id and time derive from the source event and detector set, so
        // client retries of the same event collapse onto one alert in the queue.
        let detector_fingerprint = alert_worthy.join(",");
        let alert_event_id = create_alert_event_id(&source.event_id, &detector_fingerprint);
        let alert_time = if is_within_accepted_window(source.time_generated, now) {
            source.time_generated
        } else {
            now
        };
        let request = match &source.request {
            None => RequestContext {
                correlation_id: Some(source.event_id.clone()),
                ..RequestContext::default()
            },
            Some(request) => RequestContext {
                correlation_id: Some(
                    request
                        .correlation_id
                        .clone()
                        .unwrap_or_else(|| source.event_id.clone()),
                ),
                ..request.clone()
            },
        };
        let labels: IndexMap<String, String> = [
            ("sourceEventId", source.event_id.clone()),
            ("sourceEventType", source.event_type.clone()),
            ("sourceEventCategory", source.event_category.clone()),
            ("detectorFingerprint", detector_fingerprint.clone()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();

        let alert = SecurityEventEnvelope {
            schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
            event_id: alert_event_id,
            event_original_id: Some(truncate_id(&format!(
                "{}:{}",
                source.event_id, detector_fingerprint
            ))),
            time_generated: alert_time,
            time_observed: Some(alert_time),
            event_category: event_categories::PRIVACY_CONTROL.to_owned(),
            event_type: event_types::SENSITIVE_DATA_DETECTED.to_owned(),
            event_action: "privacy.control.applied".to_owned(),
            event_result: EventResult::Success,
            event_severity: severity,
            event_outcome_reason: Some(format!(
                "Privacy engine applied controls for {} high-risk finding(s)",
                alert_worthy.len()
            )),
            application: source.application.clone(),
            actor: Some(ActorContext {
                actor_type: ActorType::System,
                username: Some("bower.privacy-engine".to_owned()),
                display_name: Some("Bower Privacy & Secret Protection Engine".to_owned()),
                ..ActorContext::default()
            }),
            target: Some(TargetContext {
                target_type: "telemetry_event".to_owned(),
                id: Some(source.event_id.clone()),
                name: Some(source.event_type.clone()),
            }),
            source: source.source.clone(),
            request: Some(request),
            change: None,
            security: None,
            collector: Some(collector.context(now)),
            labels: Some(labels),
            attributes: None,
            privacy: Some(PrivacyContext {
                detected: alert_worthy,
                actions: alert_actions,
            }),
        };

        let alert_decision = self.policy_evaluator.evaluate(&alert);
        if !accepts(alert_decision.action) {
            return Ok(None);
        }

        let mut arranged_alert = alert;
        arranged_alert.security = Some(SecurityDecisionContext {
            policy_id: alert_decision.policy_id,
            policy_version: alert_decision.policy_version,
            value_score: alert_decision.score,
            decision: DecisionAction::Accept,
            classification_reasons: alert_decision.reasons,
            policy_hash: alert_decision.policy_hash,
        });

        let enqueue = match self
            .queue
            .enqueue(&queued_event(&arranged_alert, now, None)?.0)
        {
            Err(error @ StoreError::Full(_)) => {
                // The source outcome is already recorded (and the source event may be queued).
                if let Some(telemetry) = &self.telemetry {
                    telemetry.record_privacy_alert_refusal(bytes_in);
                }
                return Err(error.into());
            }
            other => other?,
        };
        Ok((enqueue.enqueued || enqueue.duplicate).then_some(arranged_alert.event_id))
    }
}

/// The queued event and its UTF-8 payload byte count.
fn queued_event(
    envelope: &SecurityEventEnvelope,
    now: Timestamp,
    suppression: Option<SuppressionRequest>,
) -> Result<(QueuedEvent, i64), ProcessError> {
    let payload = json::to_string(envelope)
        .map_err(|error| ProcessError::Serialization(error.to_string()))?;
    let payload_bytes = i64::try_from(payload.len()).unwrap_or(i64::MAX);
    let queued = QueuedEvent {
        lease_token: None,
        event_id: envelope.event_id.clone(),
        fingerprint: fingerprint::create(envelope),
        payload,
        received_at: now,
        state: QueueState::Queued,
        delivery_attempts: 0,
        suppression,
    };
    Ok((queued, payload_bytes))
}

/// C# `StringComparer.Ordinal`: UTF-16 code unit order.
fn compare_ordinal(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn resolve_severity(detectors: &[String]) -> EventSeverity {
    let high = detectors.iter().any(|id| {
        // C# `id.Split(':')[0]`.
        let root = id.split(':').next().unwrap_or("");
        root.starts_with("secret.")
            || root.starts_with("crypto.")
            || matches!(
                root,
                privacy::CREDIT_CARD | privacy::TFN | privacy::FIELD_NAME_SECRET
            )
    });
    if high {
        EventSeverity::High
    } else {
        EventSeverity::Medium
    }
}

/// First 128 UTF-16 code units (C# `value[..128]`). A surrogate pair straddling the
/// cut is dropped whole because Rust strings cannot hold a lone surrogate.
fn truncate_id(value: &str) -> String {
    let mut units = 0usize;
    let mut end = 0usize;
    for (index, character) in value.char_indices() {
        let width = character.len_utf16();
        if units + width > 128 {
            return value[..index].to_owned();
        }
        units += width;
        end = index + character.len_utf8();
    }
    value[..end].to_owned()
}

fn create_alert_event_id(source_event_id: &str, detector_fingerprint: &str) -> String {
    let digest =
        Sha256::digest(format!("{source_event_id}\u{1f}{detector_fingerprint}").as_bytes());
    format!("privacy-{}", &hex::encode(digest)[..32])
}

/// `DateTimeOffset.MinValue` (C# `default`).
fn is_default(value: Timestamp) -> bool {
    chrono::NaiveDate::from_ymd_opt(1, 1, 1)
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .is_some_and(|minimum| value.naive_utc() == minimum)
}

fn is_within_accepted_window(value: Timestamp, now: Timestamp) -> bool {
    let upper = now + Duration::minutes(5);
    // DateTimeOffset.AddYears(-5): calendar years, Feb 29 clamps to Feb 28.
    let lower = now.checked_sub_months(Months::new(60)).unwrap_or(now);
    !is_default(value) && value <= upper && value >= lower
}

fn validate(candidate: &SecurityEventEnvelope, now: Timestamp) -> Vec<String> {
    let mut failures = Vec::new();
    if candidate.schema_version != CURRENT_SCHEMA_VERSION {
        failures.push("Unsupported schemaVersion".to_owned());
    }
    if is_null_or_white_space(&candidate.event_id)
        || candidate.event_id.encode_utf16().count() > 128
    {
        failures.push("eventId is required and must not exceed 128 characters".to_owned());
    }
    if is_null_or_white_space(&candidate.event_type)
        || is_null_or_white_space(&candidate.event_category)
        || is_null_or_white_space(&candidate.event_action)
    {
        failures.push("eventType, eventCategory and eventAction are required".to_owned());
    }
    if is_null_or_white_space(&candidate.application.name)
        || is_null_or_white_space(&candidate.application.environment)
    {
        failures.push("application.name and application.environment are required".to_owned());
    }
    if !is_within_accepted_window(candidate.time_generated, now) {
        failures.push("timeGenerated is outside allowed range".to_owned());
    }
    failures
}

/// `string.IsNullOrWhiteSpace` (Unicode `White_Space`, as `char.IsWhiteSpace`).
fn is_null_or_white_space(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_by_utf16_units() {
        assert_eq!(truncate_id(&"a".repeat(130)).len(), 128);
        let value = format!("{}\u{1F600}", "a".repeat(127));
        assert_eq!(truncate_id(&value), "a".repeat(127));
    }

    #[test]
    fn default_offset_is_outside_window() {
        let now = bower_contracts::time::parse("2026-07-26T02:14:19Z").unwrap();
        let min = bower_contracts::time::parse("0001-01-01T00:00:00Z").unwrap();
        assert!(!is_within_accepted_window(min, now));
        assert!(is_within_accepted_window(now, now));
        assert!(is_within_accepted_window(now + Duration::minutes(5), now));
        assert!(!is_within_accepted_window(
            now + Duration::minutes(5) + Duration::nanoseconds(100),
            now
        ));
        let leap = bower_contracts::time::parse("2028-02-29T00:00:00Z").unwrap();
        let five_years = bower_contracts::time::parse("2023-02-28T00:00:00Z").unwrap();
        assert!(is_within_accepted_window(five_years, leap));
        assert!(!is_within_accepted_window(
            five_years - Duration::nanoseconds(100),
            leap
        ));
    }
}
