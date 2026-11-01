//! Real pack-detection wrapper preserves retryable identity and privacy failures.

use std::sync::Arc;

use bower_contracts::{
    DurableEventStore, EventRedactor, RedactionResult, TelemetryPolicyEvaluator,
};
use bower_core::{CollectorIdentity, ProcessError, SecurityEventProcessor};
use bower_packs::runtime::PackDetectionRedactor;
use bower_persistence::SqliteEventStore;
use bower_policy::DeterministicPolicyEvaluator;

struct Fixed(RedactionResult);

#[test]
fn duplicate_nested_input_is_quarantined_without_retry_or_queueing() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteEventStore::new(directory.path().join("queue.db"), 1_048_576, None).unwrap(),
    );
    store.initialize().unwrap();
    let evaluator: Arc<dyn TelemetryPolicyEvaluator> =
        Arc::new(DeterministicPolicyEvaluator::new([]));
    let wrapper = PackDetectionRedactor {
        inner: Arc::new(bower_redaction::JsonEventRedactor::new()),
        evaluator: evaluator.clone(),
        rules: vec![],
    };
    let processor = SecurityEventProcessor::new(
        Arc::new(wrapper),
        evaluator,
        store.clone(),
        Arc::new(bower_contracts::time::SystemClock),
    );
    let input = r#"{"schemaVersion":"1.0.0","eventId":"synthetic-id","timeGenerated":"2026-10-31T00:00:00Z","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","application":{"name":"test","environment":"test"},"attributes":{"duplicate":1,"duplicate":2}}"#;
    let result = processor
        .process(input, &CollectorIdentity::new("c", "1", "test", "h"))
        .unwrap();
    assert_eq!(result.action, bower_contracts::DecisionAction::Quarantine);
    assert_eq!(result.reasons, ["redaction-invalid-input"]);
    assert_eq!(store.snapshot().unwrap().queued, 0);
}

struct Panics;
impl EventRedactor for Panics {
    fn redact(&self, _: &str) -> RedactionResult {
        panic!("collector-sensitive-panic-4621");
    }
}

#[test]
fn collector_pack_redactor_panic_is_private_and_not_queued() {
    const CHILD: &str = "BOWER_COLLECTOR_PANIC_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "collector_pack_redactor_panic_is_private_and_not_queued",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("collector-sensitive-panic-4621")
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteEventStore::new(directory.path().join("queue.db"), 1_048_576, None).unwrap(),
    );
    store.initialize().unwrap();
    let evaluator: Arc<dyn TelemetryPolicyEvaluator> =
        Arc::new(DeterministicPolicyEvaluator::new([]));
    let wrapper = PackDetectionRedactor {
        inner: Arc::new(Panics),
        evaluator: evaluator.clone(),
        rules: vec![],
    };
    let processor = SecurityEventProcessor::new(
        Arc::new(wrapper),
        evaluator,
        store.clone(),
        Arc::new(bower_contracts::time::SystemClock),
    );
    let input = r#"{"schemaVersion":"1.0.0","eventId":"private-marker","timeGenerated":"2026-10-31T00:00:00Z","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","application":{"name":"test","environment":"test"}}"#;
    assert!(matches!(
        processor.process(input, &CollectorIdentity::new("c", "1", "test", "hash")),
        Err(ProcessError::RedactionUnavailable)
    ));
    assert_eq!(store.snapshot().unwrap().queued, 0);
}

impl EventRedactor for Fixed {
    fn redact(&self, _: &str) -> RedactionResult {
        self.0.clone()
    }
}

#[test]
fn pack_wrapper_preserves_retryable_identity_and_redaction_failures() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteEventStore::new(directory.path().join("queue.db"), 1_048_576, None).unwrap(),
    );
    store.initialize().unwrap();
    let input = r#"{"schemaVersion":"1.0.0","eventId":"private-marker","timeGenerated":"2026-10-31T00:00:00Z","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","application":{"name":"test","environment":"test"}}"#;
    let outputs = [
        input.replace("\"eventId\":\"private-marker\",", ""),
        input.replace("\"eventId\":\"private-marker\"", "\"eventId\":null"),
        input.replace(
            "\"eventId\":\"private-marker\"",
            "\"eventId\":\"private-marker\",\"eventId\":\"other\"",
        ),
        "{invalid".to_owned(),
    ];
    for output in outputs {
        let evaluator: Arc<dyn TelemetryPolicyEvaluator> =
            Arc::new(DeterministicPolicyEvaluator::new([]));
        let wrapper = PackDetectionRedactor {
            inner: Arc::new(Fixed(RedactionResult {
                succeeded: true,
                redacted_json: Some(output),
                ..RedactionResult::default()
            })),
            evaluator: evaluator.clone(),
            rules: vec![],
        };
        let processor = SecurityEventProcessor::new(
            Arc::new(wrapper),
            evaluator,
            store.clone(),
            Arc::new(bower_contracts::time::SystemClock),
        );
        let error = processor
            .process(input, &CollectorIdentity::new("c", "1", "test", "h"))
            .unwrap_err();
        assert!(matches!(error, ProcessError::EventIdRedacted));
        assert_eq!(error.to_string(), "event-id-redacted");
        assert_eq!(store.snapshot().unwrap().queued, 0);
    }

    for failure in [
        RedactionResult::failed("secret-marker"),
        RedactionResult {
            succeeded: true,
            ..RedactionResult::default()
        },
        RedactionResult {
            succeeded: true,
            redacted_json: Some(
                input.replace("\"eventResult\":\"failure\"", "\"eventResult\":123"),
            ),
            ..RedactionResult::default()
        },
    ] {
        let evaluator: Arc<dyn TelemetryPolicyEvaluator> =
            Arc::new(DeterministicPolicyEvaluator::new([]));
        let wrapper = PackDetectionRedactor {
            inner: Arc::new(Fixed(failure)),
            evaluator: evaluator.clone(),
            rules: vec![],
        };
        let processor = SecurityEventProcessor::new(
            Arc::new(wrapper),
            evaluator,
            store.clone(),
            Arc::new(bower_contracts::time::SystemClock),
        );
        let error = processor
            .process(input, &CollectorIdentity::new("c", "1", "test", "h"))
            .unwrap_err();
        assert!(matches!(error, ProcessError::RedactionUnavailable));
        assert_eq!(error.to_string(), "redaction-unavailable");
        assert_eq!(store.snapshot().unwrap().queued, 0);
    }
}
