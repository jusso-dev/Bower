//! Port of tests/Bower.UnitTests/GeneratedEventIdRedactionTests.cs: Bower-generated record
//! ids skip content detectors only with proof; source text is always scanned.

use bower_contracts::{EventRedactor, RedactionContext, generated_event_ids};
use bower_redaction::{
    JsonEventRedactor, PrivacyAction, PrivacyEngine, PrivacyFieldRule, PrivacyPolicy,
    load_privacy_profile,
};
use serde_json::{Value, json};

// Passes the IBAN mod-97 check: the native pilot false positive.
const IBAN_LIKE_ID: &str = "winevt-dd97c1d25d12d2e202c1e010d70d55f4";
const OTHER_IBAN_LIKE_ID: &str = "syslog-ef23e985944885bb7eee3f74b9a4872f";

/// Operators add detectors like this for generic hex API keys; it matches every record id.
fn hex_policy() -> PrivacyPolicy {
    load_privacy_profile(
        "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: hex-digest-test\n  version: 1.0.0\n\
         customDetectors:\n  - id: custom.hex-digest\n    pattern: '[0-9a-f]{32}'\n    action: mask\n\
         \x20   tests:\n      match: ['0123456789abcdef0123456789abcdef']\n",
        Some(&[0u8; 32]),
        Some("k1"),
    )
    .unwrap()
    .policy
}

fn hex_engine() -> PrivacyEngine {
    PrivacyEngine::new(hex_policy()).unwrap()
}

fn ctx(generated_event_id: Option<&str>) -> RedactionContext<'_> {
    RedactionContext { generated_event_id }
}

fn redact(json: &str, generated: Option<&str>) -> Value {
    let result = hex_engine().redact_json_with(json, &ctx(generated));
    assert!(result.succeeded);
    serde_json::from_str(result.redacted_json.as_deref().unwrap()).unwrap()
}

#[test]
fn without_proof_a_hex_detector_masks_the_generated_id() {
    let custom_only_id = "winevt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let redacted = redact(&json!({ "eventId": custom_only_id }).to_string(), None);
    assert_ne!(redacted["eventId"], custom_only_id);
    assert!(
        redacted["privacy"]["detected"]
            .as_array()
            .unwrap()
            .contains(&json!("custom.hex-digest"))
    );
}

#[test]
fn default_policy_retains_conservative_iban_detection() {
    let engine = PrivacyEngine::with_default_policy();
    for iban in [
        "GB82WEST12345698765432",
        "gb82west12345698765432",
        "DE89370400440532013000",
        "FR1420041010050500013M02606",
        "NL91ABNA0417164300",
        "MT84MALT011000012345MTLCAST001S",
        "XX57WEST12345698765432",
        "GB04WEST123456987654",
    ] {
        let text = json!({ "note": format!("pay {iban} today") }).to_string();
        assert!(
            !engine
                .redact_json(&text)
                .redacted_json
                .unwrap()
                .contains(iban),
            "{iban}"
        );
    }
}

#[test]
fn generated_id_keeps_both_identity_fields_while_every_source_field_is_still_redacted() {
    let input = json!({
        "eventId": IBAN_LIKE_ID,
        "eventOriginalId": IBAN_LIKE_ID,
        "request": { "correlationId": IBAN_LIKE_ID },
        "attributes": {
            "eventId": IBAN_LIKE_ID,
            "card": "4111111111111111",
            "iban": "GB82WEST12345698765432",
            "note": "key AKIAIOSFODNN7EXAMPLE"
        },
        "labels": { "ids": [IBAN_LIKE_ID] }
    });
    let redacted = redact(&input.to_string(), Some(IBAN_LIKE_ID));
    assert_eq!(redacted["eventId"], IBAN_LIKE_ID);
    assert_eq!(redacted["eventOriginalId"], IBAN_LIKE_ID);
    assert_ne!(redacted["request"]["correlationId"], IBAN_LIKE_ID);
    assert_ne!(redacted["attributes"]["eventId"], IBAN_LIKE_ID);
    assert_ne!(redacted["labels"]["ids"][0], IBAN_LIKE_ID);
    let text = redacted.to_string();
    for secret in [
        "4111111111111111",
        "GB82WEST12345698765432",
        "AKIAIOSFODNN7EXAMPLE",
    ] {
        assert!(!text.contains(secret), "{secret} survived");
    }
}

#[test]
fn a_different_value_in_the_identity_field_is_scanned_even_when_well_formed() {
    let input = json!({ "eventId": OTHER_IBAN_LIKE_ID, "eventOriginalId": IBAN_LIKE_ID });
    let redacted = redact(&input.to_string(), Some(IBAN_LIKE_ID));
    assert_ne!(redacted["eventId"], OTHER_IBAN_LIKE_ID);
    assert_eq!(redacted["eventOriginalId"], IBAN_LIKE_ID);
}

#[test]
fn malformed_claims_exempt_nothing() {
    let engine = hex_engine();
    for claimed in [
        "4111111111111111",
        "syslog-4111111111111111",
        "syslog-4111 1111 1111 1111 0000 0000 0000 0000",
        "AKIAIOSFODNN7EXAMPLE",
        "GB82WEST12345698765432",
        "WINEVT-dd97c1d25d12d2e202c1e010d70d55f4",
        "winevt-DD97C1D25D12D2E202C1E010D70D55F4",
        "winevt-dd97c1d25d12d2e202c1e010d70d55f",
        "winevt-dd97c1d25d12d2e202c1e010d70d55f4a",
        "winevt-dd97c1d25d12d2e202c1e010d70d55g4",
        "-dd97c1d25d12d2e202c1e010d70d55f4",
        "abcdefghijklmnopq-dd97c1d25d12d2e202c1e010d70d55f4",
        "win-evt-dd97c1d25d12d2e202c1e010d70d55f",
        "",
    ] {
        assert!(!generated_event_ids::is_well_formed(claimed), "{claimed}");
        let input = json!({ "eventId": claimed, "eventOriginalId": IBAN_LIKE_ID }).to_string();
        assert_eq!(
            engine.redact_json(&input).redacted_json,
            engine
                .redact_json_with(&input, &ctx(Some(claimed)))
                .redacted_json,
            "{claimed}"
        );
    }
}

#[test]
fn is_well_formed_accepts_only_a_prefix_and_thirty_two_lowercase_hex_characters() {
    for id in [
        IBAN_LIKE_ID,
        OTHER_IBAN_LIKE_ID,
        "aws-0123456789abcdef0123456789abcdef",
    ] {
        assert!(generated_event_ids::is_well_formed(id), "{id}");
    }
}

#[test]
fn field_rules_still_apply_to_a_generated_id() {
    let policy = PrivacyPolicy {
        field_rules: vec![PrivacyFieldRule::new(
            "eventId",
            PrivacyAction::Sha256,
            None,
        )],
        ..PrivacyPolicy::default()
    };
    let result = PrivacyEngine::new(policy).unwrap().redact_json_with(
        &json!({ "eventId": IBAN_LIKE_ID }).to_string(),
        &ctx(Some(IBAN_LIKE_ID)),
    );
    assert!(!result.redacted_json.unwrap().contains(IBAN_LIKE_ID));
}

#[test]
fn wrappers_forward_the_proof_and_default_to_scanning() {
    struct ScanEverything;
    impl EventRedactor for ScanEverything {
        fn redact(&self, json: &str) -> bower_contracts::RedactionResult {
            hex_engine().redact(json)
        }
    }
    let input = json!({ "eventId": IBAN_LIKE_ID }).to_string();
    let wrapped = JsonEventRedactor::with_policy(hex_policy()).unwrap();
    assert!(
        wrapped
            .redact_with(&input, &ctx(Some(IBAN_LIKE_ID)))
            .redacted_json
            .unwrap()
            .contains(IBAN_LIKE_ID)
    );
    assert!(
        !wrapped
            .redact(&input)
            .redacted_json
            .unwrap()
            .contains(IBAN_LIKE_ID)
    );
    assert!(
        !ScanEverything
            .redact_with(&input, &ctx(Some(IBAN_LIKE_ID)))
            .redacted_json
            .unwrap()
            .contains(IBAN_LIKE_ID)
    );
}

#[test]
fn from_source_record_reads_only_the_leading_well_formed_id() {
    let id = "syslog-0123456789abcdef0123456789abcdef";
    assert_eq!(
        generated_event_ids::from_source_record(&format!(r#"{{"id":"{id}","message":"x"}}"#)),
        Some(id)
    );
    for record in [
        format!(r#"{{"message":"x","id":"{id}"}}"#),
        r#"{"id":"syslog-0123456789ABCDEF0123456789ABCDEF"}"#.to_owned(),
        r#"{"id":"4111111111111111"}"#.to_owned(),
        r#"{"id":17}"#.to_owned(),
        format!(r#"[{{"id":"{id}"}}]"#),
        "not json".to_owned(),
    ] {
        assert_eq!(
            generated_event_ids::from_source_record(&record),
            None,
            "{record}"
        );
    }
}

#[test]
fn generated_id_does_not_exempt_numbers_or_strings_from_detectors() {
    let record = r#"{"eventId":"health-0123456789abcdef0123456789abcdef","attributes":{"queue":{"queued":14804099,
        "bytes":2693848688944172,"ratio":323600851.5},"counts":[4111111111111111,3605917251],
        "label":"4111111111111111","note":"card 4111 1111 1111 1111"}}"#;
    let engine = PrivacyEngine::with_default_policy();
    let id = "health-0123456789abcdef0123456789abcdef";
    let context = RedactionContext {
        generated_event_id: Some(id),
    };
    let redacted: Value = serde_json::from_str(
        &engine
            .redact_json_with(record, &context)
            .redacted_json
            .unwrap(),
    )
    .unwrap();
    assert_eq!(redacted["eventId"], id);
    let attributes = &redacted["attributes"];
    assert!(attributes["counts"][0].is_string());
    assert_ne!(attributes["label"], "4111111111111111");
    assert!(!redacted.to_string().contains("4111 1111 1111 1111"));
}
