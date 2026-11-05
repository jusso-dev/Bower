//! Shared C#/Rust vectors: `tests/fixtures/s3-output/vectors.json` (C# `S3OutputTests`).

use bower_contracts::abstractions::{QueueState, QueuedEvent};
use bower_output_s3::{layout, options, output};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/s3-output/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
fn layout_matches_shared_vectors() {
    let vectors = vectors();
    for case in vectors["cases"].as_array().unwrap() {
        let events: Vec<QueuedEvent> = case["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| QueuedEvent {
                event_id: text(&item["eventId"]).into(),
                fingerprint: "sha256:x".into(),
                payload: text(&item["payload"]).into(),
                received_at: chrono::DateTime::parse_from_rfc3339(text(&item["receivedAt"]))
                    .unwrap(),
                state: QueueState::Queued,
                delivery_attempts: 0,
                lease_token: None,
                suppression: None,
            })
            .collect();
        let (objects, rejected) = layout::plan(
            &events,
            text(&case["prefix"]),
            text(&case["collectorId"]),
            i32::try_from(case["maximumObjectBytes"].as_i64().unwrap()).unwrap(),
            i32::try_from(case["maximumObjectEvents"].as_i64().unwrap()).unwrap(),
            case["gzip"].as_bool().unwrap(),
        );

        let expected = case["expected"]["objects"].as_array().unwrap();
        assert_eq!(expected.len(), objects.len(), "{}", case["name"]);
        for (object, expected) in objects.iter().zip(expected) {
            assert_eq!(text(&expected["key"]), object.key);
            let ids: Vec<&str> = expected["eventIds"]
                .as_array()
                .unwrap()
                .iter()
                .map(text)
                .collect();
            assert_eq!(ids, object.event_ids);
            assert_eq!(
                expected["bodyBytes"].as_u64().unwrap(),
                object.body.len() as u64
            );
            assert_eq!(
                text(&expected["bodySha256"]),
                hex::encode(Sha256::digest(&object.body))
            );
        }
        let expected_rejected: Vec<(&str, &str)> = case["expected"]["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| (text(&item["eventId"]), text(&item["code"])))
            .collect();
        let actual_rejected: Vec<(&str, &str)> = rejected
            .iter()
            .map(|failure| (failure.event_id.as_str(), failure.code.as_str()))
            .collect();
        assert_eq!(expected_rejected, actual_rejected, "{}", case["name"]);
        assert!(rejected.iter().all(|failure| !failure.is_retryable));
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| text(item).to_string())
        .collect()
}

/// C# `ObjectHashAndKeys_SeparateAmbiguousIdsBodiesAndCollectors`.
#[test]
fn object_hash_and_keys_separate_ambiguous_ids_bodies_and_collectors() {
    let vectors = vectors();
    let mut hashes = std::collections::HashSet::new();
    for item in vectors["objectHash"].as_array().unwrap() {
        let hash = layout::object_hash(&strings(&item["eventIds"]), text(&item["body"]).as_bytes());
        assert_eq!(text(&item["sha256"]), hash, "{}", item["name"]);
        assert!(hashes.insert(hash), "{}", item["name"]);
    }

    let mut keys = std::collections::HashSet::new();
    for item in vectors["adversarialKeys"].as_array().unwrap() {
        let key = layout::key(
            text(&item["prefix"]),
            text(&item["collectorId"]),
            chrono::DateTime::parse_from_rfc3339(text(&item["receivedAt"])).unwrap(),
            &strings(&item["eventIds"]),
            text(&item["body"]).as_bytes(),
            item["gzip"].as_bool().unwrap(),
        );
        assert_eq!(text(&item["key"]), key, "{}", item["name"]);
        assert!(keys.insert(key), "{}", item["name"]);
    }

    let validation = &vectors["validation"];
    for prefix in strings(&validation["validPrefixes"]) {
        assert!(options::is_valid_prefix(&prefix), "{prefix}");
    }
    for prefix in strings(&validation["invalidPrefixes"]) {
        assert!(!options::is_valid_prefix(&prefix), "{prefix}");
    }
    for id in strings(&validation["validCollectorIds"]) {
        assert!(options::is_valid_collector_id(&id), "{id}");
    }
    for id in strings(&validation["invalidCollectorIds"]) {
        assert!(!options::is_valid_collector_id(&id), "{id}");
    }
}

#[test]
fn classification_and_acknowledgement_match_shared_vectors() {
    let vectors = vectors();
    for item in vectors["classification"].as_array().unwrap() {
        let code = output::classify(
            u16::try_from(item["status"].as_u64().unwrap()).unwrap(),
            item["errorCode"].as_str(),
            item["messageNamesKms"].as_bool().unwrap(),
        );
        assert_eq!(item["expected"].as_str(), code.as_deref(), "{item}");
    }
    for item in vectors["acknowledgement"].as_array().unwrap() {
        assert_eq!(
            text(&item["expected"]),
            output::acknowledgement(text(&item["bucket"]), text(&item["key"]))
        );
    }
}
