//! Ports of tests/Bower.UnitTests: RedactionTests, SensitiveDataDetectorTests,
//! ChecksumAlgorithmsTests, PrivacyEngineTests, PrivacyBypassTests and the privacy
//! parts of PrivacyProfileAndLedgerTests and CloudPackTests, plus extra adversarial cases.

use aes_gcm::aead::{AeadInOut, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bower_contracts::EventRedactor;
use bower_redaction::{
    DetectionMatch, FieldNameSecretDetector, JsonEventRedactor, MAXIMUM_PAYLOAD_BYTES,
    PrivacyAction, PrivacyEngine, PrivacyError, PrivacyFieldRule, PrivacyPolicy, ScanText,
    SensitiveDataDetector, SensitiveDetector, SensitiveFindingKind, checksum,
    default_value_detectors, detector_ids as ids, load_privacy_profile,
};
use serde_json::Value;

fn engine() -> PrivacyEngine {
    PrivacyEngine::with_default_policy()
}

fn parse(json: &str) -> Value {
    serde_json::from_str(json).expect("redacted JSON parses")
}

fn repo_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

// ------------------------------------------------------------------ RedactionTests

#[test]
fn redact_removes_dangerous_fields_and_masks_email() {
    let json = r#"
        {
          "actor": {
            "email": "alice@example.test",
            "password": "do-not-store"
          },
          "http": {
            "request": {
              "headers": {
                "Authorization": "Bearer secret"
              }
            }
          }
        }"#;

    let result = JsonEventRedactor::new().redact(json);

    assert!(result.succeeded);
    assert!(
        result
            .removed_paths
            .contains(&"$.actor.password".to_owned())
    );
    assert!(
        result
            .removed_paths
            .contains(&"$.http.request.headers".to_owned())
    );
    assert!(result.masked_paths.contains(&"$.actor.email".to_owned()));
    let document = parse(result.redacted_json.as_deref().unwrap());
    assert_eq!(document["actor"]["email"], "a***@example.test");
    assert!(document["actor"].get("password").is_none());
}

#[test]
fn redact_rejects_unsafe_document() {
    for json in ["", "[]", "{ invalid"] {
        let result = JsonEventRedactor::new().redact(json);
        assert!(!result.succeeded, "{json}");
        assert!(result.redacted_json.is_none());
    }
}

// ------------------------------------------------------------------ SensitiveDataDetectorTests

#[test]
fn scan_and_redact_detects_aws_key_jwt_and_email() {
    let json = r#"
        {
          "awsKey": "AKIAIOSFODNN7EXAMPLE",
          "detail": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
          "owner": "alice@example.test",
          "password": "do-not-store"
        }"#;

    let result = SensitiveDataDetector::new().scan_and_redact(json);

    assert!(result.succeeded);
    let kinds: Vec<SensitiveFindingKind> =
        result.findings.iter().map(|finding| finding.kind).collect();
    for kind in [
        SensitiveFindingKind::AwsAccessKey,
        SensitiveFindingKind::Jwt,
        SensitiveFindingKind::Email,
        SensitiveFindingKind::GenericSecret,
    ] {
        assert!(kinds.contains(&kind), "{kind:?}");
    }
    let redacted = result.redacted_json.unwrap();
    assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!redacted.contains("do-not-store"));
    assert!(redacted.contains("a***@example.test"));
}

#[test]
fn scan_and_redact_detects_valid_credit_card() {
    let result = SensitiveDataDetector::new().scan_and_redact(r#"{ "pan": "4111111111111111" }"#);

    assert!(result.succeeded);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.kind == SensitiveFindingKind::CreditCard)
    );
    assert!(!result.redacted_json.unwrap().contains("4111111111111111"));
}

#[test]
fn scan_and_redact_can_mask_credit_card_with_policy() {
    let policy = PrivacyPolicy {
        default_action: PrivacyAction::Mask,
        detector_actions: [(ids::CREDIT_CARD.to_owned(), PrivacyAction::Mask)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::default()
    };
    let result = SensitiveDataDetector::with_policy(policy)
        .unwrap()
        .scan_and_redact(r#"{ "pan": "4111111111111111" }"#);

    assert!(
        result
            .redacted_json
            .unwrap()
            .contains("****-****-****-1111")
    );
}

// ------------------------------------------------------------------ ChecksumAlgorithmsTests

#[test]
fn checksum_algorithms() {
    for (digits, expected) in [("100000001", true), ("123456789", false)] {
        assert_eq!(checksum::is_valid_tfn(digits), expected);
    }
    for (digits, expected) in [("51824753556", true), ("51824753557", false)] {
        assert_eq!(checksum::is_valid_abn(digits), expected);
    }
    for (digits, expected) in [("000000019", true), ("000000018", false)] {
        assert_eq!(checksum::is_valid_acn(digits), expected);
    }
    for (digits, expected) in [("2123456701", true), ("2123456711", false)] {
        assert_eq!(checksum::is_valid_medicare(digits), expected);
    }
    for (digits, expected) in [("8003600000000007", true), ("8003600000000008", false)] {
        assert_eq!(checksum::is_valid_ihi(digits), expected);
    }
    assert!(checksum::luhn("4111111111111111"));
    assert!(!checksum::luhn("4111111111111112"));
}

// ------------------------------------------------------------------ PrivacyEngineTests

#[test]
fn redact_json_detects_australian_identifiers_with_checksum() {
    let json = r#"
        {
          "tfn": "100000001",
          "abn": "51 824 753 556",
          "medicare": "2123 45670 1",
          "ihi": "8003600000000007",
          "crn": "123 456 789A"
        }"#;

    let result = engine().redact_json(json);

    assert!(result.succeeded);
    for id in [ids::TFN, ids::ABN, ids::MEDICARE, ids::IHI] {
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.detector_id == id && f.validated),
            "{id}"
        );
    }
    assert!(result.findings.iter().any(|f| f.detector_id == ids::CRN));
    let redacted = result.redacted_json.unwrap();
    assert!(!redacted.contains("100000001"));
    assert!(redacted.contains("*****0001"));
    assert!(result.metadata.has_findings());
    // An unkeyed hash of a TFN is reversible by enumeration, so the default masks.
    assert_eq!(result.metadata.actions[ids::TFN], "Masked");
    assert_eq!(result.metadata.actions[ids::ABN], "Allow");
}

#[test]
fn redact_json_rejects_invalid_tfn_checksum() {
    let result = engine().redact_json(r#"{ "tfn": "123456789" }"#);

    assert!(result.succeeded);
    assert!(!result.findings.iter().any(|f| f.detector_id == ids::TFN));
    assert!(result.redacted_json.unwrap().contains("123456789"));
}

#[test]
fn redact_json_removes_secrets_and_jwt() {
    let json = r#"
        {
          "awsKey": "AKIAIOSFODNN7EXAMPLE",
          "detail": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
          "password": "do-not-store",
          "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
        }"#;

    let result = engine().redact_json(json);

    assert!(result.succeeded);
    let redacted = result.redacted_json.as_deref().unwrap();
    for secret in [
        "AKIAIOSFODNN7EXAMPLE",
        "do-not-store",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "BEGIN RSA PRIVATE KEY",
    ] {
        assert!(!redacted.contains(secret), "{secret}");
    }
    let has = |id: &str| result.findings.iter().any(|f| f.detector_id == id);
    assert!(has(ids::AWS));
    assert!(has(ids::JWT) || has(ids::ENTRA));
    assert!(has(ids::CRYPTO_MATERIAL));
    assert!(has(ids::FIELD_NAME_SECRET));
}

#[test]
fn redact_json_removes_credit_card_by_default() {
    let result = engine().redact_json(r#"{ "pan": "4111111111111111" }"#);

    assert!(result.succeeded);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.detector_id == ids::CREDIT_CARD && f.validated)
    );
    assert!(!result.redacted_json.unwrap().contains("4111111111111111"));
    assert_eq!(result.metadata.actions[ids::CREDIT_CARD], "Removed");
}

#[test]
fn redact_json_masks_credit_card_when_configured() {
    let mut policy = PrivacyPolicy::create_default();
    policy
        .detector_actions
        .insert(ids::CREDIT_CARD.to_owned(), PrivacyAction::Mask);

    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(r#"{ "pan": "4111111111111111" }"#);

    assert!(
        result
            .redacted_json
            .unwrap()
            .contains("****-****-****-1111")
    );
}

#[test]
fn redact_json_masks_email() {
    let result = engine().redact_json(r#"{ "owner": "alice@example.test" }"#);

    assert!(result.findings.iter().any(|f| f.detector_id == ids::EMAIL));
    assert!(result.redacted_json.unwrap().contains("a***@example.test"));
}

#[test]
fn redact_json_detects_api_keys_by_provider() {
    let json = r#"
        {
          "openai": "sk-abcdefghijklmnopqrstuvwxyz12",
          "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
          "stripe": "sk_live_abcdefghijklmnopqrstuv"
        }"#;

    let result = engine().redact_json(json);

    for provider in ["OpenAI", "GitHub", "Stripe"] {
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.detector_id == ids::API_KEY && f.sub_kind.as_deref() == Some(provider)),
            "{provider}"
        );
    }
}

#[test]
fn redact_json_respects_disabled_detector() {
    let policy = PrivacyPolicy {
        disabled_detectors: [ids::EMAIL.to_owned()].into_iter().collect(),
        ..PrivacyPolicy::create_default()
    };

    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(r#"{ "owner": "alice@example.test" }"#);

    assert!(!result.findings.iter().any(|f| f.detector_id == ids::EMAIL));
    assert!(result.redacted_json.unwrap().contains("alice@example.test"));
}

#[test]
fn redact_json_emits_privacy_metadata_without_originals() {
    let result = engine().redact_json(r#"{ "tfn": "100000001", "email": "bob@example.test" }"#);

    let redacted = result.redacted_json.unwrap();
    let document = parse(&redacted);
    let privacy = &document["privacy"];
    assert!(privacy.get("detected").is_some());
    assert!(privacy.get("actions").is_some());
    assert!(!redacted.contains("100000001"));
    let privacy_json = privacy.to_string();
    assert!(!privacy_json.contains("100000001"));
    assert!(!privacy_json.contains("bob@example.test"));
}

#[test]
fn redact_text_works_for_non_json_sources() {
    let result = engine().redact_text("user email alice@example.test pan 4111111111111111");

    assert!(result.succeeded);
    let text = result.redacted_text.unwrap();
    assert!(!text.contains("4111111111111111"));
    assert!(text.contains("a***@example.test"));
}

#[test]
fn json_event_redactor_still_implements_event_redactor() {
    let redactor: Box<dyn EventRedactor> = Box::new(JsonEventRedactor::new());
    let result =
        redactor.redact(r#"{ "actor": { "email": "alice@example.test", "password": "x" } }"#);

    assert!(result.succeeded);
    assert!(
        result
            .removed_paths
            .contains(&"$.actor.password".to_owned())
    );
    assert!(result.redacted_json.unwrap().contains("a***@example.test"));
}

#[test]
fn detector_catalog_registers_all_modules() {
    let detectors = default_value_detectors();
    assert!(detectors.len() >= 30);
    for id in [ids::TFN, ids::API_KEY, ids::CRYPTO_MATERIAL] {
        assert!(detectors.iter().any(|detector| detector.id() == id), "{id}");
    }
}

// ------------------------------------------------------------------ PrivacyBypassTests

#[test]
fn redact_json_removes_card_numbers_in_numbers_and_keys() {
    for json in [
        r#"{ "attributes": { "card": 4111111111111111 } }"#,
        r#"{ "attributes": { "values": [[4111111111111111]] } }"#,
        r#"{ "attributes": { "4111111111111111": "x" } }"#,
        r#"{ "attributes": { "nested": { "4111111111111111": { "ok": true } } } }"#,
    ] {
        let result = engine().redact_json(json);
        assert!(result.succeeded, "{json}");
        assert!(
            !result.redacted_json.unwrap().contains("4111111111111111"),
            "{json}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.detector_id == ids::CREDIT_CARD),
            "{json}"
        );
    }
}

#[test]
fn redact_json_masks_sensitive_key_and_keeps_its_value() {
    let result = engine().redact_json(r#"{ "alice@example.test": "member" }"#);

    assert!(result.succeeded);
    let redacted = result.redacted_json.unwrap();
    assert!(!redacted.contains("alice@example.test"));
    assert!(redacted.contains(r#""a***@example.test":"member""#));
}

#[test]
fn redact_json_renames_removed_keys_without_collisions() {
    let result = engine().redact_json(r#"{ "4111111111111111": 1, "5555555555554444": 2 }"#);

    assert!(result.succeeded);
    let document = parse(result.redacted_json.as_deref().unwrap());
    assert_eq!(document["redacted-key-1"], 1);
    assert_eq!(document["redacted-key-2"], 2);
}

#[test]
fn redact_json_leaves_ordinary_numbers_untouched() {
    let result = engine().redact_json(r#"{ "statusCode": 401, "port": 443, "score": 87.5 }"#);

    assert!(result.succeeded);
    assert_eq!(
        result.redacted_json.unwrap(),
        r#"{"statusCode":401,"port":443,"score":87.5}"#
    );
}

#[test]
fn redact_json_removes_secret_field_name_variants() {
    for field_name in [
        "dbPassword",
        "sessionToken",
        "idToken",
        "setCookie",
        "pwd",
        "xApiKey",
        "client_secret",
        "userPass",
        "mfa_otp",
        "AWS_SECRET_ACCESS_KEY",
    ] {
        let json = serde_json::json!({ field_name: "plain-secret-value" }).to_string();
        let result = engine().redact_json(&json);
        assert!(result.succeeded, "{field_name}");
        assert!(
            !result.redacted_json.unwrap().contains("plain-secret-value"),
            "{field_name}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.detector_id == ids::FIELD_NAME_SECRET),
            "{field_name}"
        );
    }
}

#[test]
fn redact_json_keeps_secret_metadata_field_names() {
    for field_name in [
        "tokenType",
        "passwordLastChanged",
        "bypass",
        "eventType",
        "sessionId",
    ] {
        let json = serde_json::json!({ field_name: "kept" }).to_string();
        let result = engine().redact_json(&json);
        assert!(result.succeeded, "{field_name}");
        assert!(
            result.redacted_json.unwrap().contains("kept"),
            "{field_name}"
        );
    }
}

#[test]
fn privacy_engine_refuses_hmac_without_key() {
    let policy = PrivacyPolicy {
        detector_actions: [(ids::TFN.to_owned(), PrivacyAction::Hmac)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::default()
    };

    assert!(matches!(
        PrivacyEngine::new(policy),
        Err(PrivacyError::InvalidOperation(_))
    ));
}

#[test]
fn privacy_engine_refuses_short_hmac_key() {
    let policy = PrivacyPolicy {
        hmac_key: Some(vec![1; 31]),
        detector_actions: [(ids::TFN.to_owned(), PrivacyAction::Hmac)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::default()
    };

    assert!(matches!(
        PrivacyEngine::new(policy),
        Err(PrivacyError::InvalidOperation(_))
    ));
}

#[test]
fn privacy_engine_uses_keyed_hash_when_hmac_key_configured() {
    let policy = PrivacyPolicy {
        hmac_key: Some(vec![0; 32]),
        detector_actions: [(ids::TFN.to_owned(), PrivacyAction::Hmac)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::default()
    };

    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(r#"{ "tfn": "100000001" }"#);

    assert!(result.succeeded);
    let redacted = result.redacted_json.unwrap();
    assert!(redacted.contains("hmac-sha256:"));
    assert!(!redacted.replace("hmac-sha256:", "").contains("sha256:"));
}

#[test]
fn redact_json_quarantines_duplicate_keys_instead_of_throwing() {
    let result = engine().redact_json(r#"{ "a": "1", "a": "2" }"#);

    assert!(!result.succeeded);
    assert!(matches!(
        result.failure_code.as_deref(),
        Some("redaction-failed" | "invalid-json")
    ));
}

// ------------------------------------------------------------------ PrivacyProfileAndLedgerTests (privacy)

const PSEUDONYM_PROFILE: &str = "apiVersion: bower.security/v1
kind: PrivacyProfile
metadata:
  id: test
  version: 1.0.0
fields:
  - path: actor.username
    action: hmac
  - path: request.userAgent
    action: truncate
    maxLength: 10
maximumFieldLength: 1024
";

fn key(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

#[test]
fn hmac_pseudonymises_deterministically_with_key_id() {
    let profile = load_privacy_profile(PSEUDONYM_PROFILE, Some(&key(1)), Some("k2026")).unwrap();
    let engine = PrivacyEngine::new(profile.policy).unwrap();
    let json =
        r#"{"actor":{"username":"alice"},"request":{"userAgent":"Mozilla/5.0 something long"}}"#;

    let first = engine.redact_json(json).redacted_json.unwrap();
    let second = engine.redact_json(json).redacted_json.unwrap();
    let node = parse(&first);

    assert_eq!(first, second);
    assert!(
        node["actor"]["username"]
            .as_str()
            .unwrap()
            .starts_with("hmac-sha256:k2026:")
    );
    assert!(!first.contains("alice"));
    assert_eq!(node["request"]["userAgent"], "Mozilla/5.");
}

#[test]
fn hmac_differs_across_keys_so_pseudonyms_are_tenant_scoped() {
    let json = r#"{"actor":{"username":"alice"}}"#;
    let redact = |seed| {
        let profile = load_privacy_profile(PSEUDONYM_PROFILE, Some(&key(seed)), None).unwrap();
        PrivacyEngine::new(profile.policy)
            .unwrap()
            .redact_json(json)
            .redacted_json
            .unwrap()
    };

    assert_ne!(redact(1), redact(2));
}

#[test]
fn profile_fails_closed_without_hmac_key() {
    assert!(matches!(
        load_privacy_profile(PSEUDONYM_PROFILE, None, None),
        Err(PrivacyError::InvalidOperation(_))
    ));
}

#[test]
fn profile_rejects_unknown_or_unsafe_settings() {
    for extra in [
        "detectors:\n  not.a.detector: mask",
        "fields:\n  - path: actor.username\n    action: obliterate",
        "unexpectedKey: true",
        "maximumFieldLength: 10",
    ] {
        let yaml = format!(
            "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n{extra}\n"
        );
        assert!(
            matches!(
                load_privacy_profile(&yaml, None, None),
                Err(PrivacyError::InvalidData(_))
            ),
            "{extra}"
        );
    }
}

#[test]
fn maximum_field_length_truncates_every_long_string() {
    let engine = PrivacyEngine::new(PrivacyPolicy {
        maximum_field_length: 300,
        ..PrivacyPolicy::default()
    })
    .unwrap();
    let json = format!(
        r#"{{"a":"{}","list":["{}"]}}"#,
        "y".repeat(1_000),
        "z".repeat(500)
    );

    let result = engine.redact_json(&json);
    let node = parse(result.redacted_json.as_deref().unwrap());

    assert_eq!(node["a"].as_str().unwrap().len(), 300);
    assert_eq!(node["list"][0].as_str().unwrap().len(), 300);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.detector_id == ids::FIELD_LENGTH)
    );
}

// ------------------------------------------------------------------ repository profiles

#[test]
fn repository_privacy_profiles_load_and_pseudonymise_principals() {
    for (relative, expected_id) in [
        (
            "deploy/privacy/cloud-identities.yaml",
            "cloud-identities-pseudonymised",
        ),
        (
            "packs/linux-ssh-gateway/privacy.yaml",
            "ssh-gateway-pseudonymised",
        ),
    ] {
        let profile =
            load_privacy_profile(&repo_file(relative), Some(&[0; 32]), Some("k1")).unwrap();
        assert_eq!(profile.id.as_deref(), Some(expected_id));
        assert_eq!(profile.policy.maximum_field_length, 16_384);
        let engine = PrivacyEngine::new(profile.policy).unwrap();
        let redacted = engine
            .redact_json(r#"{"actor":{"username":"alice@example.com","userId":"arn:aws:iam::123456789012:user/alice"}}"#)
            .redacted_json
            .unwrap();
        assert!(!redacted.contains("alice@example.com"), "{relative}");
        assert!(!redacted.contains("user/alice"), "{relative}");
        assert!(redacted.contains("hmac-sha256:k1:"), "{relative}");
    }
}

// ------------------------------------------------------------------ additional adversarial cases

#[test]
fn payload_limits_and_failure_codes() {
    let at_limit = format!(r#"{{"a":"{}"}}"#, "y".repeat(MAXIMUM_PAYLOAD_BYTES - 8));
    assert_eq!(at_limit.len(), MAXIMUM_PAYLOAD_BYTES);
    let result = engine().redact_json(&at_limit);
    assert!(result.succeeded);
    assert_eq!(
        parse(result.redacted_json.as_deref().unwrap())["a"]
            .as_str()
            .unwrap()
            .len(),
        32_768
    );

    let over = format!(r#"{{"a":"{}"}}"#, "y".repeat(MAXIMUM_PAYLOAD_BYTES - 7));
    assert_eq!(
        engine().redact_json(&over).failure_code.as_deref(),
        Some("payload-too-large")
    );
    assert_eq!(
        engine()
            .redact_text(&"y".repeat(MAXIMUM_PAYLOAD_BYTES + 1))
            .failure_code
            .as_deref(),
        Some("payload-too-large")
    );
    assert_eq!(
        engine()
            .redact_json(" \u{A0}\u{3000} ")
            .failure_code
            .as_deref(),
        Some("empty-payload")
    );
    assert_eq!(
        engine().redact_json("[1]").failure_code.as_deref(),
        Some("root-must-be-object")
    );
    assert_eq!(
        engine().redact_json("{\"a\":1,}").failure_code.as_deref(),
        Some("invalid-json")
    );
}

#[test]
fn malformed_structures_fail_closed_unless_removed_unread() {
    // Unpaired surrogates and duplicate names are redaction failures wherever C# reads them...
    for json in [
        r#"{"a":"\uD800"}"#,
        r#"{"\uDC00":1}"#,
        r#"{"x":[{"b":1,"b":2}]}"#,
    ] {
        let result = engine().redact_json(json);
        assert_eq!(
            result.failure_code.as_deref(),
            Some("redaction-failed"),
            "{json}"
        );
        assert!(result.to_redaction_result().redacted_json.is_none());
    }

    // ...but a removed secret property is never read, so it cannot fail the event.
    let result = engine().redact_json(r#"{"password":{"\uD800":1,"a":1,"a":2},"ok":1}"#);
    assert!(result.succeeded);
    assert!(result.redacted_json.unwrap().starts_with(r#"{"ok":1,"#));

    // With field-name secrets only alerted, the property stays and must be readable.
    let alert = PrivacyPolicy {
        detector_actions: [(ids::FIELD_NAME_SECRET.to_owned(), PrivacyAction::AlertOnly)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::create_default()
    };
    let result = PrivacyEngine::new(alert)
        .unwrap()
        .redact_json(r#"{"password":{"a":1,"a":2}}"#);
    assert_eq!(result.failure_code.as_deref(), Some("redaction-failed"));
}

#[test]
fn whitespace_value_under_hmac_rule_fails_closed() {
    let policy = PrivacyPolicy {
        hmac_key: Some(vec![3; 32]),
        field_rules: vec![PrivacyFieldRule::new(
            "actor.username",
            PrivacyAction::Hmac,
            None,
        )],
        ..PrivacyPolicy::create_default()
    };
    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(r#"{"actor":{"username":"  "}}"#);
    assert_eq!(result.failure_code.as_deref(), Some("redaction-failed"));
}

#[test]
fn empty_field_rule_path_fails_closed() {
    let policy = PrivacyPolicy {
        field_rules: vec![PrivacyFieldRule::new("..", PrivacyAction::Remove, None)],
        ..PrivacyPolicy::create_default()
    };
    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(r#"{"a":1}"#);
    assert_eq!(result.failure_code.as_deref(), Some("redaction-failed"));
}

#[test]
fn opt_in_detectors_stay_off_unless_enabled() {
    let text =
        "host 192.168.1.10 db.internal username: bob 12 Smith Street -33.8688, 151.2093 PROTECTED";
    let result = engine().redact_text(text);
    assert_eq!(result.redacted_text.as_deref(), Some(text));
    assert!(result.findings.is_empty());

    let enabled = PrivacyPolicy {
        enabled_opt_in_detectors: [ids::IP_ADDRESS, ids::SECURITY_MARKING]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ..PrivacyPolicy::create_default()
    };
    let result = PrivacyEngine::new(enabled).unwrap().redact_text(text);
    let found: Vec<&str> = result
        .findings
        .iter()
        .map(|f| f.detector_id.as_str())
        .collect();
    assert!(found.contains(&ids::IP_ADDRESS));
    // Markings are AlertOnly: detected but content unchanged.
    assert!(found.contains(&ids::SECURITY_MARKING));
    assert!(result.redacted_text.unwrap().contains("PROTECTED"));
}

#[test]
fn unicode_lookalikes_follow_dotnet_semantics() {
    // .NET treats supplementary letters, combining spacing marks and circled
    // letters as non-word characters, so the card still has a word boundary.
    for prefix in ["\u{1D400}", "\u{93E}", "\u{24B6}", "\u{2160}"] {
        let text = format!("{prefix}4111111111111111");
        let result = engine().redact_text(&text);
        assert_eq!(result.redacted_text.as_deref(), Some(prefix), "{prefix:?}");
    }

    // Letters and ZWJ are word characters: no boundary, no match (as in C#).
    for prefix in ["\u{E9}", "\u{200D}"] {
        let text = format!("{prefix}4111111111111111");
        assert_eq!(
            engine().redact_text(&text).redacted_text.as_deref(),
            Some(text.as_str())
        );
    }

    // .NET case-insensitive matching includes the Kelvin sign but not long s.
    assert_eq!(
        engine()
            .redact_text("\u{212A}ubeconfig")
            .redacted_text
            .as_deref(),
        Some("")
    );
    assert_eq!(
        engine()
            .redact_text("aws_\u{17F}ecret_key=x")
            .findings
            .len(),
        0
    );

    // Field names: .NET drops combining marks and counts the Kelvin sign as k.
    for name in ["pass\u{93E}word", "to\u{212A}en", "PASS\u{2160}WORD"] {
        let json = serde_json::json!({ name: "secret-value" }).to_string();
        let result = engine().redact_json(&json);
        assert!(
            !result.redacted_json.unwrap().contains("secret-value"),
            "{name:?}"
        );
    }
}

#[test]
fn encrypt_action_round_trips_and_removes_without_key() {
    let key = [5u8; 32];
    let policy = PrivacyPolicy {
        detector_actions: [(ids::EMAIL.to_owned(), PrivacyAction::Encrypt)]
            .into_iter()
            .collect(),
        encryption_key: Some(key.to_vec()),
        field_rules: vec![PrivacyFieldRule::new(
            "opaque",
            PrivacyAction::Encrypt,
            None,
        )],
        ..PrivacyPolicy::create_default()
    };
    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(r#"{"owner":"alice@example.test","opaque":"v"}"#);
    let document = parse(result.redacted_json.as_deref().unwrap());
    assert_eq!(result.metadata.actions[ids::EMAIL], "Encrypted");

    let decrypt = |value: &str| {
        let parts: Vec<&str> = value
            .strip_prefix("enc:aesgcm:")
            .unwrap()
            .split(':')
            .collect();
        let nonce: [u8; 12] = STANDARD.decode(parts[0]).unwrap().try_into().unwrap();
        let tag = STANDARD.decode(parts[1]).unwrap();
        let mut buffer = STANDARD.decode(parts[2]).unwrap();
        Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt_inout_detached(
                &Nonce::<Aes256Gcm>::from(nonce),
                &[],
                buffer.as_mut_slice().into(),
                tag.as_slice().try_into().unwrap(),
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    assert_eq!(
        decrypt(document["owner"].as_str().unwrap()),
        "alice@example.test"
    );
    assert_eq!(decrypt(document["opaque"].as_str().unwrap()), "v");
    assert!(result.masked_paths.contains(&"$.owner".to_owned()));

    // Without a key, Encrypt falls back to removing the span / value.
    let no_key = PrivacyPolicy {
        detector_actions: [(ids::EMAIL.to_owned(), PrivacyAction::Encrypt)]
            .into_iter()
            .collect(),
        field_rules: vec![PrivacyFieldRule::new(
            "opaque",
            PrivacyAction::Encrypt,
            None,
        )],
        ..PrivacyPolicy::create_default()
    };
    let redacted = PrivacyEngine::new(no_key)
        .unwrap()
        .redact_json(r#"{"owner":"alice@example.test","opaque":"v"}"#);
    let document = parse(redacted.redacted_json.as_deref().unwrap());
    assert_eq!(document["owner"], "");
    assert!(document.get("opaque").is_none());
}

#[test]
fn custom_detectors_plug_in_without_engine_changes() {
    struct Employee;
    impl SensitiveDetector for Employee {
        fn id(&self) -> &str {
            "custom.employee"
        }
        fn category(&self) -> &str {
            "custom"
        }
        fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
            if let Some(start) = text.text().find("EMP-") {
                let end = (start + 8).min(text.text().len());
                matches.push(DetectionMatch::new(
                    self.id(),
                    self.category(),
                    text.text(),
                    start,
                    end,
                    true,
                    None,
                ));
            }
        }
    }

    let mut detectors = default_value_detectors();
    detectors.push(Box::new(Employee));
    let policy = PrivacyPolicy {
        detector_actions: [("custom.employee".to_owned(), PrivacyAction::Remove)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::create_default()
    };
    let engine =
        PrivacyEngine::with_detectors(policy, detectors, Box::new(FieldNameSecretDetector))
            .unwrap();
    let result = engine.redact_text("id EMP-1234 ok");
    assert_eq!(result.redacted_text.as_deref(), Some("id  ok"));
    assert_eq!(result.metadata.actions["custom.employee"], "Removed");
}

#[test]
fn security_event_worthiness() {
    assert!(PrivacyEngine::is_security_event_worthy(
        "secret.api-key:OpenAI"
    ));
    assert!(PrivacyEngine::is_security_event_worthy(
        ids::FIELD_NAME_SECRET
    ));
    assert!(PrivacyEngine::is_security_event_worthy(
        ids::SECURITY_MARKING
    ));
    assert!(!PrivacyEngine::is_security_event_worthy(ids::EMAIL));
    assert!(!PrivacyEngine::is_security_event_worthy(ids::ABN));
    assert!(!PrivacyEngine::is_security_event_worthy(":secret.aws"));
    assert!(!PrivacyEngine::is_security_event_worthy(""));
}

#[test]
fn failed_redaction_reports_empty_privacy_lists_like_csharp() {
    let result = engine().redact("[]");
    assert!(!result.succeeded);
    assert_eq!(result.failure_code.as_deref(), Some("root-must-be-object"));
    assert_eq!(result.privacy_detected, Some(Vec::new()));
}

#[test]
fn metadata_never_contains_original_values() {
    let secrets = [
        "100000001",
        "alice@example.test",
        "4111111111111111",
        "AKIAIOSFODNN7EXAMPLE",
        "hunter2",
    ];
    let json = serde_json::json!({
        "note": "TFN 100000001 alice@example.test 4111111111111111 AKIAIOSFODNN7EXAMPLE PASSWORD=hunter2"
    })
    .to_string();
    let result = engine().redact_json(&json);
    let redacted = result.redacted_json.unwrap();
    for secret in secrets {
        assert!(!redacted.contains(secret), "{secret}");
        assert!(
            !result
                .metadata
                .detected
                .iter()
                .any(|id| id.contains(secret))
        );
    }
}

/// Deterministic xorshift generator so the fuzz corpus is reproducible.
struct Fuzz(u64);

impl Fuzz {
    fn next(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }
}

#[test]
fn unicode_fuzz_never_panics_and_keeps_offsets_on_char_boundaries() {
    // Characters the regex haystack rewrites (supplementary, long s, non-.NET word
    // characters) next to every detector's anchors. A match boundary inside a
    // rewritten character would panic when slicing the original text.
    let pieces = [
        "\u{1F600}",
        "\u{1D400}",
        "\u{1D7CE}",
        "\u{17F}",
        "\u{212A}",
        "\u{93E}",
        "\u{488}",
        "\u{2160}",
        "\u{24B6}",
        "\u{200C}",
        "\u{200D}",
        "\u{3000}",
        "\u{A0}",
        "\u{661}",
        "é",
        "İ",
        " ",
        "-",
        ":",
        "=",
        ";",
        ".",
        "@",
        "/",
        "\n",
        "4111111111111111",
        "100000001",
        "PayID: ",
        "passport N1234567",
        "driver ",
        "DVA ",
        "AKIA",
        "IOSFODNN7EXAMPLE",
        "eyJ",
        "abcdefghij",
        "secret_key=",
        "kind: Config",
        "users:",
        "registry",
        "password=",
        "Server=a;",
        "Pwd=",
        "mongodb://",
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "alice@example.test",
        "TOP SECRET",
        "12 Smith Street",
        "192.168.1.10",
        "username: ",
    ];
    let mut policy = PrivacyPolicy::create_default();
    policy.enabled_opt_in_detectors = policy.opt_in_detectors.clone();
    policy.maximum_field_length = 256;
    let engines = [
        PrivacyEngine::new(policy).unwrap(),
        PrivacyEngine::new(PrivacyPolicy {
            enabled_opt_in_detectors: PrivacyPolicy::default().opt_in_detectors,
            ..PrivacyPolicy::default()
        })
        .unwrap(),
    ];
    let mut fuzz = Fuzz(0x9E37_79B9_7F4A_7C15);
    for _ in 0..1_000 {
        let count = 1 + fuzz.next(24);
        let text: String = (0..count)
            .map(|_| pieces[fuzz.next(pieces.len())])
            .collect();
        for engine in &engines {
            let result = engine.redact_text(&text);
            assert!(result.succeeded, "{text:?}");
            let json = serde_json::json!({ text.clone(): text, "n": [text] }).to_string();
            let result = engine.redact_json(&json);
            assert!(result.succeeded, "{text:?}");
            assert!(
                serde_json::from_str::<Value>(&result.redacted_json.unwrap()).is_ok(),
                "{text:?}"
            );
        }
    }
}

#[test]
fn unpaired_surrogates_from_masking_never_produce_duplicate_keys() {
    // C# masks both keys to names that differ only in an unpaired high surrogate
    // and then serialises both as "PayID: a<U+FFFD>*bc" (duplicate keys). Rust renames
    // the colliding key; see tests/parity.rs `expected_redacted_json`.
    let result = engine().redact_json("{\"PayID: a\u{1F600}bc\":1,\"PayID: a\u{1F300}bc\":2}");
    let redacted = result.redacted_json.unwrap();
    assert!(redacted.starts_with("{\"PayID: a\u{5C}uFFFD*bc\":1,\"redacted-key-1\":2,"));
    assert!(!redacted.contains('\u{1F600}') && !redacted.contains("\\uD83D"));
}
