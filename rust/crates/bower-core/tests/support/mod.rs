//! Test doubles for the contracts traits.
#![allow(dead_code)]

use std::sync::Mutex;
use std::time::Duration;

use bower_contracts::envelope::DecisionAction;
use bower_contracts::time::Timestamp;
use bower_contracts::types::event_types;
use bower_contracts::{
    DeadLetterRecord, DurableEventStore, EnqueueResult, EventRedactor, LedgerHead,
    LedgerVerification, PolicyDecision, QueueSnapshot, QueuedEvent, RedactionResult,
    SecurityEventEnvelope, StoreError, StoreResult, TelemetryPolicyEvaluator,
};
use indexmap::IndexMap;

pub fn now() -> Timestamp {
    bower_contracts::time::parse("2026-07-26T02:14:19Z").unwrap()
}

/// Returns the input unchanged with fixed redaction metadata.
pub struct MetadataRedactor(pub RedactionResult);

impl EventRedactor for MetadataRedactor {
    fn redact(&self, json: &str) -> RedactionResult {
        RedactionResult {
            redacted_json: Some(json.to_owned()),
            ..self.0.clone()
        }
    }
}

/// Removes `attributes.<field>` values and reports detectors, like the privacy engine
/// would for the scenarios in the C# tests.
pub struct FieldRedactor {
    pub remove: Vec<&'static str>,
    pub mask: Vec<(&'static str, &'static str)>,
    pub detected: Vec<&'static str>,
}

impl EventRedactor for FieldRedactor {
    fn redact(&self, json: &str) -> RedactionResult {
        let mut document: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut removed = Vec::new();
        let mut masked = Vec::new();
        if let Some(attributes) = document
            .get_mut("attributes")
            .and_then(|value| value.as_object_mut())
        {
            for field in &self.remove {
                if attributes.shift_remove(*field).is_some() {
                    removed.push(format!("attributes.{field}"));
                }
            }
            for (field, mask) in &self.mask {
                if let Some(value) = attributes.get_mut(*field) {
                    *value = serde_json::Value::String((*mask).to_owned());
                    masked.push(format!("attributes.{field}"));
                }
            }
        }
        let actions: IndexMap<String, String> = self
            .detected
            .iter()
            .map(|id| ((*id).to_owned(), "Removed".to_owned()))
            .collect();
        RedactionResult {
            succeeded: true,
            redacted_json: Some(bower_contracts::json::to_string(&document).unwrap()),
            removed_paths: removed,
            masked_paths: masked,
            failure_code: None,
            privacy_detected: Some(self.detected.iter().map(|id| (*id).to_owned()).collect()),
            privacy_actions: Some(actions),
        }
    }
}

/// Returns the result unchanged (no redacted JSON unless provided).
pub struct FixedRedactor(pub RedactionResult);

impl EventRedactor for FixedRedactor {
    fn redact(&self, _json: &str) -> RedactionResult {
        self.0.clone()
    }
}

pub struct PanickingRedactor;

impl EventRedactor for PanickingRedactor {
    fn redact(&self, _json: &str) -> RedactionResult {
        panic!("detector crashed");
    }
}

/// Accepts authentication failures and privacy alerts, rejects everything else.
pub struct TestPolicy;

impl TelemetryPolicyEvaluator for TestPolicy {
    fn evaluate(&self, candidate: &SecurityEventEnvelope) -> PolicyDecision {
        let decision =
            |action, id: &str, hash: &str, score, reasons: Vec<&str>, warnings: Vec<&str>| {
                PolicyDecision {
                    action,
                    policy_id: id.to_owned(),
                    policy_version: "1.0.0".to_owned(),
                    policy_hash: hash.to_owned(),
                    score,
                    reasons: reasons.into_iter().map(str::to_owned).collect(),
                    warnings: warnings.into_iter().map(str::to_owned).collect(),
                    suppression: None,
                }
            };
        if candidate.event_type == event_types::SENSITIVE_DATA_DETECTED {
            decision(
                DecisionAction::Accept,
                "BWR-POL-PRIVACY-DETECT",
                "sha256:privacy",
                80,
                vec!["privacy reason"],
                vec![],
            )
        } else if candidate.event_id == "rejected" {
            decision(
                DecisionAction::Reject,
                "BWR-POL-AUTH-FAILURE",
                "sha256:auth",
                10,
                vec!["low value"],
                vec!["warn 1"],
            )
        } else if candidate.event_type == event_types::AUTHENTICATION_FAILURE {
            decision(
                DecisionAction::Accept,
                "BWR-POL-AUTH-FAILURE",
                "sha256:auth",
                90,
                vec!["reason 1", "reason 2"],
                vec!["warn 1"],
            )
        } else {
            decision(
                DecisionAction::Reject,
                "default-deny",
                "sha256:none",
                0,
                vec!["No policy matched"],
                vec![],
            )
        }
    }
}

/// In-memory queue: idempotent on fingerprint or event id, like the C# test double.
#[derive(Default)]
pub struct MemoryStore {
    pub items: Mutex<Vec<QueuedEvent>>,
    pub full: bool,
    /// Refuses new rows (as `StoreError::Full`) once this many are held.
    pub capacity: Option<usize>,
}

impl MemoryStore {
    pub fn items(&self) -> Vec<QueuedEvent> {
        self.items.lock().unwrap().clone()
    }
}

impl DurableEventStore for MemoryStore {
    fn initialize(&self) -> StoreResult<()> {
        Ok(())
    }

    fn enqueue(&self, candidate: &QueuedEvent) -> StoreResult<EnqueueResult> {
        if self.full {
            return Err(StoreError::Full("Queue capacity exceeded.".to_owned()));
        }
        let mut items = self.items.lock().unwrap();
        let duplicate = items.iter().any(|item| {
            item.fingerprint == candidate.fingerprint || item.event_id == candidate.event_id
        });
        if !duplicate {
            if self
                .capacity
                .is_some_and(|capacity| items.len() >= capacity)
            {
                return Err(StoreError::Full("Queue capacity exceeded.".to_owned()));
            }
            items.push(candidate.clone());
        }
        Ok(EnqueueResult {
            enqueued: !duplicate,
            duplicate,
            event_id: candidate.event_id.clone(),
            suppressed: false,
        })
    }

    fn lease(&self, _: usize, _: Duration) -> StoreResult<Vec<QueuedEvent>> {
        unimplemented!()
    }
    fn mark_delivered(&self, _: &str, _: &str, _: Option<&str>) -> StoreResult<()> {
        unimplemented!()
    }
    fn mark_retrying(&self, _: &str, _: &str, _: Timestamp, _: Option<&str>) -> StoreResult<()> {
        unimplemented!()
    }
    fn mark_dead_lettered(&self, _: &str, _: &str, _: Option<&str>) -> StoreResult<()> {
        unimplemented!()
    }
    fn snapshot(&self) -> StoreResult<QueueSnapshot> {
        unimplemented!()
    }
    fn purge_delivered(&self, _: Timestamp, _: usize) -> StoreResult<usize> {
        unimplemented!()
    }
    fn maintain(&self) -> StoreResult<()> {
        unimplemented!()
    }
    fn list_dead_lettered(&self, _: usize) -> StoreResult<Vec<DeadLetterRecord>> {
        unimplemented!()
    }
    fn replay_dead_lettered(
        &self,
        _: Option<&str>,
        _: Option<&[String]>,
        _: usize,
    ) -> StoreResult<usize> {
        unimplemented!()
    }
    fn ledger_head(&self) -> StoreResult<LedgerHead> {
        unimplemented!()
    }
    fn verify_ledger(&self) -> StoreResult<LedgerVerification> {
        unimplemented!()
    }
}

/// `TestEvents.AuthenticationFailure(now)` serialized with Bower JSON.
pub fn authentication_failure_json(attributes: &str) -> String {
    let attributes = if attributes.is_empty() {
        String::new()
    } else {
        format!(",\"attributes\":{attributes}")
    };
    format!(
        concat!(
            "{{\"schemaVersion\":\"1.0.0\",\"eventId\":\"event-1\",\"eventOriginalId\":\"source-1\",",
            "\"timeGenerated\":\"2026-07-26T02:14:19+00:00\",\"eventCategory\":\"authentication\",",
            "\"eventType\":\"authentication_failure\",\"eventAction\":\"authentication.attempt\",",
            "\"eventResult\":\"failure\",\"eventSeverity\":\"medium\",\"eventOutcomeReason\":\"InvalidPassword\",",
            "\"application\":{{\"name\":\"TestApplication\",\"environment\":\"test\"}},",
            "\"actor\":{{\"username\":\"test-user\",\"type\":\"human\"}},",
            "\"source\":{{\"ipAddress\":\"192.0.2.10\"}},\"request\":{{\"correlationId\":\"correlation-1\"}}{}}}"
        ),
        attributes
    )
}
