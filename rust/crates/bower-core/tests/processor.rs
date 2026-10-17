//! Port of `SecurityEventProcessorTests` (with test doubles for redaction, policy
//! and queue) plus failure-path coverage.

mod support;

use std::sync::Arc;

use bower_contracts::envelope::DecisionAction;
use bower_contracts::types::event_types;
use bower_contracts::{RedactionResult, StoreError};
use bower_core::{CollectorIdentity, ProcessError, SecurityEventProcessor};
use support::*;

fn identity() -> CollectorIdentity {
    CollectorIdentity::new("collector-1", "0.1.0", "test", "sha256:configuration")
}

fn processor(
    redactor: impl bower_contracts::EventRedactor + 'static,
    store: &Arc<MemoryStore>,
) -> SecurityEventProcessor {
    SecurityEventProcessor::new(
        Arc::new(redactor),
        Arc::new(TestPolicy),
        store.clone(),
        Arc::new(now),
    )
}

#[test]
fn process_redacts_before_persistence_and_explains_acceptance() {
    let store = Arc::new(MemoryStore::default());
    let redactor = FieldRedactor {
        remove: vec!["password"],
        mask: vec![],
        detected: vec!["field-name-secret"],
    };
    let json = authentication_failure_json(r#"{"password":"never-persist"}"#);

    let result = processor(redactor, &store)
        .process(&json, &identity())
        .unwrap();
    let queued = store.items();

    assert_eq!(result.action, DecisionAction::RedactAndAccept);
    assert!(result.queued);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.starts_with("Removed 1"))
    );
    let alert_id = result
        .privacy_alert_event_id
        .clone()
        .expect("privacy alert");
    assert_eq!(queued.len(), 2);
    let original = queued
        .iter()
        .find(|item| item.event_id == "event-1")
        .unwrap();
    assert!(!original.payload.contains("never-persist"));
    assert!(!original.payload.contains("\"password\""));
    assert!(
        original
            .payload
            .contains("\"policyId\":\"BWR-POL-AUTH-FAILURE\"")
    );
    let alert = queued
        .iter()
        .find(|item| item.event_id == alert_id)
        .unwrap();
    assert!(alert.payload.contains(event_types::SENSITIVE_DATA_DETECTED));
    assert!(alert.payload.contains("field-name-secret"));
    assert!(!alert.payload.contains("never-persist"));
}

#[test]
fn process_emits_privacy_alert_for_regulated_identifier() {
    let store = Arc::new(MemoryStore::default());
    let redactor = FieldRedactor {
        remove: vec![],
        mask: vec![("note", "TFN [REDACTED]")],
        detected: vec!["au.tfn"],
    };
    let json = authentication_failure_json(r#"{"note":"TFN 100000001"}"#);

    let result = processor(redactor, &store)
        .process(&json, &identity())
        .unwrap();

    assert!(result.queued);
    let alert_id = result.privacy_alert_event_id.expect("privacy alert");
    let queued = store.items();
    let alert = queued
        .iter()
        .find(|item| item.event_id == alert_id)
        .unwrap();
    assert!(alert.payload.contains("au.tfn"));
    assert!(!alert.payload.contains("100000001"));
    assert!(alert.payload.contains("privacy-control"));
}

#[test]
fn process_does_not_emit_privacy_alert_for_email_only() {
    let store = Arc::new(MemoryStore::default());
    let redactor = FieldRedactor {
        remove: vec![],
        mask: vec![("contact", "[EMAIL]")],
        detected: vec!["id.email"],
    };
    let json = authentication_failure_json(r#"{"contact":"alice@example.test"}"#);

    let result = processor(redactor, &store)
        .process(&json, &identity())
        .unwrap();

    assert!(result.queued);
    assert!(result.privacy_alert_event_id.is_none());
    assert_eq!(store.items().len(), 1);
}

#[test]
fn process_deduplicates_stable_source_event() {
    let store = Arc::new(MemoryStore::default());
    let processor = processor(
        FieldRedactor {
            remove: vec![],
            mask: vec![],
            detected: vec![],
        },
        &store,
    );
    let json = authentication_failure_json("");

    let first = processor.process(&json, &identity()).unwrap();
    let second = processor.process(&json, &identity()).unwrap();

    assert!(first.queued);
    assert_eq!(first.action, DecisionAction::Accept);
    assert!(second.duplicate);
    assert!(!second.queued);
    assert_eq!(
        second.reasons.last().unwrap(),
        "Duplicate fingerprint already present"
    );
}

#[test]
fn redaction_failure_or_panic_quarantines_without_persisting() {
    let store = Arc::new(MemoryStore::default());
    let json = authentication_failure_json("");

    let failed = processor(
        FixedRedactor(RedactionResult::failed("depth-exceeded")),
        &store,
    )
    .process(&json, &identity())
    .unwrap();
    assert_eq!(failed.action, DecisionAction::Quarantine);
    assert_eq!(failed.reasons, ["depth-exceeded"]);
    assert!(failed.event_id.is_none());

    let no_json = RedactionResult {
        succeeded: true,
        ..RedactionResult::default()
    };
    let missing = processor(FixedRedactor(no_json), &store)
        .process(&json, &identity())
        .unwrap();
    assert_eq!(missing.reasons, ["redaction-failed"]);

    let panicked = processor(PanickingRedactor, &store)
        .process(&json, &identity())
        .unwrap();
    assert_eq!(panicked.action, DecisionAction::Quarantine);
    assert_eq!(panicked.reasons, ["redaction-failed"]);
    assert!(store.items().is_empty());
}

#[test]
fn invalid_json_and_missing_fields_are_schema_invalid() {
    let store = Arc::new(MemoryStore::default());
    let accept = || {
        MetadataRedactor(RedactionResult {
            succeeded: true,
            ..RedactionResult::default()
        })
    };
    for input in ["{not json", "null", "{\"eventId\":\"x\"}"] {
        let result = processor(accept(), &store)
            .process(input, &identity())
            .unwrap();
        assert_eq!(result.action, DecisionAction::Quarantine);
        assert_eq!(result.reasons, ["schema-invalid"]);
    }
    assert!(store.items().is_empty());
}

#[test]
fn undefined_enum_values_are_schema_invalid() {
    // C# `DefinedEnumConverter` rejects these as invalid JSON (default deny).
    let store = Arc::new(MemoryStore::default());
    let json = authentication_failure_json("");
    for (from, to) in [
        (r#""eventResult":"failure""#, r#""eventResult":7"#),
        (r#""eventResult":"failure""#, r#""eventResult":"7""#),
        (r#""eventResult":"failure""#, r#""eventResult":-1"#),
        (r#""eventSeverity":"medium""#, r#""eventSeverity":5"#),
        (r#""type":"human""#, r#""type":9"#),
    ] {
        let input = json.replace(from, to);
        assert_ne!(input, json);
        let result = processor(
            MetadataRedactor(RedactionResult {
                succeeded: true,
                ..RedactionResult::default()
            }),
            &store,
        )
        .process(&input, &identity())
        .unwrap();
        assert_eq!(result.action, DecisionAction::Quarantine, "{to}");
        assert_eq!(result.reasons, ["schema-invalid"], "{to}");
    }
    assert!(store.items().is_empty());
}

#[test]
fn null_application_quarantines_with_validation_reason_and_alert_has_empty_application() {
    // C# binds `"application":null`, quarantines with the validation reason and (since
    // the fix) builds the privacy alert with an empty application instead of throwing.
    let store = Arc::new(MemoryStore::default());
    let json = authentication_failure_json("").replace(
        r#""application":{"name":"TestApplication","environment":"test"}"#,
        r#""application":null"#,
    );
    let result = processor(
        MetadataRedactor(RedactionResult {
            succeeded: true,
            privacy_detected: Some(vec!["secret.jwt".to_owned()]),
            ..RedactionResult::default()
        }),
        &store,
    )
    .process(&json, &identity())
    .unwrap();

    assert_eq!(result.action, DecisionAction::Quarantine);
    assert!(!result.queued);
    assert_eq!(
        result.reasons,
        ["application.name and application.environment are required"]
    );
    let items = store.items();
    assert_eq!(items.len(), 1);
    assert_eq!(
        Some(items[0].event_id.as_str()),
        result.privacy_alert_event_id.as_deref()
    );
    assert!(
        items[0]
            .payload
            .contains(r#""application":{"name":"","environment":""}"#)
    );
}

#[test]
fn validation_failures_quarantine_with_explained_reasons() {
    let store = Arc::new(MemoryStore::default());
    let json = authentication_failure_json("")
        .replace("\"1.0.0\"", "\"2.0.0\"")
        .replace("\"event-1\"", "\" \"")
        .replace("\"authentication.attempt\"", "\"\"")
        .replace("\"TestApplication\"", "\"\\t\"")
        .replace("2026-07-26T02:14:19+00:00", "2026-07-26T02:19:20+00:00");

    let result = processor(
        MetadataRedactor(RedactionResult {
            succeeded: true,
            ..RedactionResult::default()
        }),
        &store,
    )
    .process(&json, &identity())
    .unwrap();

    assert_eq!(result.action, DecisionAction::Quarantine);
    assert_eq!(result.event_id.as_deref(), Some(" "));
    assert_eq!(
        result.reasons,
        [
            "Unsupported schemaVersion",
            "eventId is required and must not exceed 128 characters",
            "eventType, eventCategory and eventAction are required",
            "application.name and application.environment are required",
            "timeGenerated is outside allowed range",
        ]
    );
    assert!(store.items().is_empty());
}

#[test]
fn rejected_events_report_reasons_and_warnings_and_still_alert() {
    let store = Arc::new(MemoryStore::default());
    let json = authentication_failure_json("").replace("\"event-1\"", "\"rejected\"");
    let redactor = MetadataRedactor(RedactionResult {
        succeeded: true,
        privacy_detected: Some(vec!["secret.jwt".to_owned()]),
        ..RedactionResult::default()
    });

    let result = processor(redactor, &store)
        .process(&json, &identity())
        .unwrap();

    assert_eq!(result.action, DecisionAction::Reject);
    assert!(!result.queued);
    assert_eq!(result.reasons, ["low value", "warn 1"]);
    assert!(result.policy_decision.is_some());
    let queued = store.items();
    assert_eq!(queued.len(), 1);
    assert_eq!(
        Some(&queued[0].event_id),
        result.privacy_alert_event_id.as_ref()
    );
}

#[test]
fn queue_capacity_errors_propagate() {
    let store = Arc::new(MemoryStore {
        full: true,
        ..MemoryStore::default()
    });
    let error = processor(
        FieldRedactor {
            remove: vec![],
            mask: vec![],
            detected: vec![],
        },
        &store,
    )
    .process(&authentication_failure_json(""), &identity())
    .unwrap_err();
    assert!(matches!(error, ProcessError::Store(StoreError::Full(_))));
}
