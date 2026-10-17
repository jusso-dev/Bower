//! Cross-implementation vectors produced by `Bower.Core` (C#).
//!
//! `fixtures/csharp-vectors.json` was written by a temporary xunit test against the
//! C# HEAD: `EventFingerprint.Create` over envelopes deserialized with
//! `BowerJson.Options`, and full `SecurityEventProcessor.ProcessAsync` runs (twice
//! each, to cover duplicates) with the same redactor and policy doubles as
//! `support` and the real `SqliteEventStore`. Queued payloads, fingerprints,
//! privacy alert ids and processing results must be byte-identical.

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use bower_contracts::{RedactionResult, SecurityEventEnvelope, json};
use bower_core::{CollectorIdentity, ProcessingResult, SecurityEventProcessor, event_fingerprint};
use indexmap::IndexMap;
use serde_json::Value;
use support::{MemoryStore, MetadataRedactor, TestPolicy, now};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csharp-vectors.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn fingerprints_match_csharp() {
    let vectors = vectors();
    for case in vectors["fingerprints"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let expected = case["fingerprint"].as_str().unwrap();
        let parsed = json::from_str::<SecurityEventEnvelope>(input);
        if input.contains(r#""eventResult":7"#) {
            // Known divergence (bower-contracts): C# accepts an undefined enum ordinal
            // and fingerprints it as "7"; the Rust envelope rejects it (schema-invalid).
            assert!(expected.starts_with("sha256:"));
            assert!(parsed.is_err());
            continue;
        }
        if expected.starts_with("throws:") {
            assert!(parsed.is_err(), "C# rejected {input}");
            continue;
        }
        assert_eq!(event_fingerprint(&parsed.unwrap()), expected, "{input}");
    }
}

fn result_json(result: &ProcessingResult) -> Value {
    serde_json::json!({
        "action": result.action.pascal_name(),
        "eventId": result.event_id,
        "queued": result.queued,
        "duplicate": result.duplicate,
        "reasons": result.reasons,
        "privacyAlertEventId": result.privacy_alert_event_id,
    })
}

#[test]
fn processor_output_matches_csharp_byte_for_byte() {
    let vectors = vectors();
    let scenarios = vectors["processor"].as_array().unwrap();
    assert_eq!(scenarios.len(), 8);
    for case in scenarios {
        let scenario = &case["scenario"];
        let name = scenario["name"].as_str().unwrap();
        let null_application = name.starts_with("null-application");
        let actions: Option<IndexMap<String, String>> =
            scenario["actions"].as_object().map(|actions| {
                actions
                    .iter()
                    .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
                    .collect()
            });
        let template = RedactionResult {
            succeeded: true,
            redacted_json: None,
            removed_paths: strings(&scenario["removed"]),
            masked_paths: strings(&scenario["masked"]),
            failure_code: None,
            privacy_detected: scenario["detected"]
                .as_array()
                .map(|_| strings(&scenario["detected"])),
            privacy_actions: actions,
        };
        let store = Arc::new(MemoryStore::default());
        let processor = SecurityEventProcessor::new(
            Arc::new(MetadataRedactor(template)),
            Arc::new(TestPolicy),
            store.clone(),
            Arc::new(now),
        );
        let identity =
            CollectorIdentity::new("collector-1", "0.1.0", "test", "sha256:configuration");
        let input = scenario["input"].as_str().unwrap();

        let first = processor.process(input, &identity).unwrap();
        let second = processor.process(input, &identity).unwrap();

        if null_application {
            // Known divergences: C# binds `"application":null` and quarantines with a
            // validation reason, or throws NullReferenceException from
            // EventFingerprint when a privacy alert is due (C# bug). The Rust
            // envelope requires `application`, so both are schema-invalid and nothing
            // is queued.
            assert!(
                case["first"]["reasons"]
                    == serde_json::json!([
                        "application.name and application.environment are required"
                    ])
                    || case["first"] == "throws:NullReferenceException",
                "{name}"
            );
            assert!(case["queued"].as_array().unwrap().is_empty());
            assert_eq!(first.reasons, ["schema-invalid"], "{name}");
            assert!(store.items().is_empty(), "{name}");
            continue;
        }
        assert_eq!(result_json(&first), case["first"], "{name}: first result");
        assert_eq!(
            result_json(&second),
            case["second"],
            "{name}: second result"
        );
        let mut queued = store.items();
        queued.sort_by(|left, right| {
            left.event_id
                .encode_utf16()
                .cmp(right.event_id.encode_utf16())
        });
        let expected = case["queued"].as_array().unwrap();
        assert_eq!(queued.len(), expected.len(), "{name}: queued count");
        for (actual, expected) in queued.iter().zip(expected) {
            assert_eq!(
                actual.event_id,
                expected["eventId"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                actual.fingerprint,
                expected["fingerprint"].as_str().unwrap(),
                "{name}: fingerprint of {}",
                actual.event_id
            );
            assert_eq!(
                actual.payload,
                expected["payload"].as_str().unwrap(),
                "{name}: payload of {}",
                actual.event_id
            );
            assert_eq!(actual.received_at, now(), "{name}");
        }
    }
}
