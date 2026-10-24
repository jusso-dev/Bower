//! Council round 1 engine findings (A1-A6): ports of
//! tests/Bower.UnitTests/CustomRedactionHardeningTests.cs. Byte parity with C# is proven
//! by `parity.rs` over the generated vectors.

use bower_redaction::custom_pattern;
use bower_redaction::detectors::custom::{MAXIMUM_MATCHES_PER_EVENT, MAXIMUM_SCANNED_LENGTH};
use bower_redaction::{
    CustomDetectorDefinition, CustomPatternDetector, FieldNameSecretDetector, LoadedPrivacyProfile,
    PrivacyAction, PrivacyEngine, PrivacyError, PrivacyPolicy, SensitiveDetector,
    load_privacy_profile,
};
use serde_json::Value;

const HEADER: &str =
    "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n";
const TRACE_SAMPLE: &str =
    r#"{"msg":"trace: card 4111111111111111 key AKIAIOSFODNN7EXAMPLE mail alice@example.test"}"#;
const KEY: [u8; 32] = [7; 32];

fn detector(id: &str, pattern: &str, action: &str, extra: &str, tests: &str) -> String {
    format!(
        "customDetectors:\n  - id: {id}\n    pattern: '{pattern}'\n    action: {action}\n{extra}    tests:\n      match: {tests}\n"
    )
}

fn load(yaml: &str) -> Result<LoadedPrivacyProfile, PrivacyError> {
    load_privacy_profile(yaml, Some(&KEY), Some("k1"))
}

fn engine(body: &str) -> PrivacyEngine {
    PrivacyEngine::new(
        load(&format!("{HEADER}{body}"))
            .expect("profile loads")
            .policy,
    )
    .expect("engine builds")
}

fn custom_only(policy: PrivacyPolicy) -> PrivacyEngine {
    let detectors: Vec<Box<dyn SensitiveDetector>> = policy
        .custom_detectors
        .iter()
        .map(|definition| {
            Box::new(CustomPatternDetector::new(definition.clone())) as Box<dyn SensitiveDetector>
        })
        .collect();
    PrivacyEngine::with_detectors(policy, detectors, Box::new(FieldNameSecretDetector)).unwrap()
}

fn load_error(yaml: &str) -> String {
    match load(yaml) {
        Ok(_) => panic!("loaded: {yaml:?}"),
        Err(error) => {
            assert_eq!(error.dotnet_type(), "InvalidDataException", "{error}");
            error.to_string()
        }
    }
}

fn message(json: Option<&str>) -> String {
    let node: Value = serde_json::from_str(json.expect("redacted")).unwrap();
    node["msg"].as_str().unwrap().to_owned()
}

fn defaults_with(entries: &[(&str, PrivacyAction)]) -> indexmap::IndexMap<String, PrivacyAction> {
    let mut actions = PrivacyPolicy::create_default().detector_actions;
    for (id, action) in entries {
        actions.insert((*id).to_owned(), *action);
    }
    actions
}

// ------------------------------------------------------------------ A1

#[test]
fn alert_only_custom_detector_does_not_suppress_other_detectors() {
    let engine = engine(&detector(
        "custom.trace-line",
        "trace: .+",
        "alert-only",
        "",
        "['trace: x']",
    ));
    let result = engine.redact_json(TRACE_SAMPLE);
    assert_eq!(
        message(result.redacted_json.as_deref()),
        "trace: card  key  mail a***@example.test"
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.detector_id == "custom.trace-line"
                && finding.action == PrivacyAction::AlertOnly)
    );
    assert!(
        result
            .metadata
            .detected
            .contains(&"fin.credit-card:Visa".to_owned())
    );
    assert!(
        result
            .metadata
            .detected
            .iter()
            .any(|id| PrivacyEngine::is_security_event_worthy(id))
    );
    assert_eq!(result.metadata.actions["custom.trace-line"], "AlertOnly");
}

#[test]
fn custom_detector_allow_override_does_not_claim_spans() {
    let trace = CustomDetectorDefinition::create(
        "custom.trace-line",
        "trace: .+",
        PrivacyAction::Mask,
        false,
        false,
        None,
    )
    .unwrap();
    let policy = PrivacyPolicy {
        detector_actions: defaults_with(&[("custom.trace-line", PrivacyAction::Allow)]),
        custom_detectors: vec![trace],
        ..PrivacyPolicy::default()
    };
    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_json(TRACE_SAMPLE);
    assert_eq!(
        message(result.redacted_json.as_deref()),
        "trace: card  key  mail a***@example.test"
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.detector_id == "custom.trace-line"
                && finding.action == PrivacyAction::Allow)
    );
}

#[test]
fn load_rejects_allow_for_custom_detectors() {
    assert_eq!(
        load_error(&format!(
            "{HEADER}{}",
            detector("custom.d", "x", "Allow", "", "[x]")
        )),
        "Custom detector 'custom.d' cannot use action allow; use alert-only to record matches without redacting."
    );
}

#[test]
fn redacting_custom_detectors_still_claim_their_spans() {
    let engine = engine(&detector(
        "custom.trace-line",
        "trace: .+",
        "replace",
        "",
        "['trace: x']",
    ));
    assert_eq!(
        message(engine.redact_json(TRACE_SAMPLE).redacted_json.as_deref()),
        "***REDACTED***"
    );
}

// ------------------------------------------------------------------ A2

#[test]
fn values_longer_than_the_scan_limit_quarantine_while_custom_detectors_are_enabled() {
    let body = detector("custom.d", r"EMP-\d{6}", "mask", "", "[EMP-123456]");
    let at_limit = format!("{{\"a\":\"{}\"}}", "x".repeat(MAXIMUM_SCANNED_LENGTH));
    let over_limit = format!("{{\"a\":\"{}\"}}", "x".repeat(MAXIMUM_SCANNED_LENGTH + 1));
    let long_key = format!("{{\"{}\":1}}", "k".repeat(MAXIMUM_SCANNED_LENGTH + 1));
    assert!(engine(&body).redact_json(&at_limit).succeeded);
    for json in [&over_limit, &long_key] {
        assert_eq!(
            engine(&body).redact_json(json).failure_code.as_deref(),
            Some("redaction-failed")
        );
    }
    assert!(
        engine(&format!("{body}disabled: [custom.d]\n"))
            .redact_json(&over_limit)
            .succeeded
    );
    assert!(
        PrivacyEngine::with_default_policy()
            .redact_json(&over_limit)
            .succeeded
    );
}

#[test]
fn more_custom_matches_than_the_per_event_limit_quarantine() {
    let engine = engine(&detector("custom.d", "a+z|a", "mask", "", "[a]"));
    let at_limit = "a".repeat(MAXIMUM_MATCHES_PER_EVENT);
    let half = "a".repeat(MAXIMUM_MATCHES_PER_EVENT / 2);
    assert!(engine.redact_text(&at_limit).succeeded);
    assert_eq!(
        engine
            .redact_text(&format!("{at_limit}a"))
            .failure_code
            .as_deref(),
        Some("redaction-failed")
    );
    // The limit is per event, across values (and keys, which are scanned too).
    assert!(
        engine
            .redact_json(&format!(r#"{{"x":"{half}","y":"{half}"}}"#))
            .succeeded
    );
    assert_eq!(
        engine
            .redact_json(&format!(r#"{{"x":"{half}","y":"{half}","a":1}}"#))
            .failure_code
            .as_deref(),
        Some("redaction-failed")
    );
}

#[test]
fn quadratic_patterns_are_bounded_and_deterministic() {
    let engine = engine(&detector("custom.d", "a+z|a", "mask", "", "[a]"));
    let json = format!("{{\"a\":\"{}\"}}", "a".repeat(5_000));
    for _ in 0..50 {
        assert_eq!(
            engine.redact_json(&json).failure_code.as_deref(),
            Some("redaction-failed")
        );
    }
}

#[test]
fn same_event_redacts_identically_fifty_times() {
    let policy = load(&format!(
        "{HEADER}{}  - id: custom.word\n    pattern: 'x.+x'\n    wholeWord: true\n    action: sha256\n    tests:\n      match: ['xax']\n",
        detector("custom.token", "token=.+", "mask", "", "['token=x']")
    ))
    .unwrap()
    .policy;
    let engine = custom_only(policy);
    let json = format!("{{\"a\":\"{}\"}}", "token=a x\u{1F600}x ".repeat(2_000));
    let first = engine.redact_json(&json).redacted_json;
    assert!(first.is_some());
    for _ in 0..49 {
        assert_eq!(engine.redact_json(&json).redacted_json, first);
    }
}

// ------------------------------------------------------------------ A3

#[test]
fn whole_word_is_an_ascii_boundary_on_both_ends() {
    for (pattern, tests, input, expected) in [
        (
            "TKN-[A-Z0-9]+?",
            "[TKN-A1]",
            "issued TKN-ABC123 today",
            "issued TK******23 today",
        ),
        (
            r"ORD-\d{4}|ORD-\d{4}[A-Z]",
            "[ORD-1234]",
            "ORD-1234X",
            "OR*****4X",
        ),
        (r"EMP-\d", "[EMP-1]", "EMP-1 EMP-2", "EM*-1 EM*-2"),
        (r"-\d-", "[-1-]", "-1--2-", "********"),
        (
            r"EMP-\d{6}",
            "[EMP-123456]",
            "XEMP-111111 EMP-222222_ (EMP-333333) EMP-4444445 EMP-555555",
            "XEMP-111111 EMP-222222_ (EM******33) EMP-4444445 EM******55",
        ),
    ] {
        let engine = engine(&detector(
            "custom.d",
            pattern,
            "mask",
            "    wholeWord: true\n",
            tests,
        ));
        assert_eq!(
            engine.redact_text(input).redacted_text.as_deref(),
            Some(expected),
            "{pattern}"
        );
    }
}

#[test]
fn whole_word_negated_classes_exclude_the_sentinel() {
    for (pattern, canonical) in [
        (
            r"[^a].\D\W\S",
            "[^a\u{FFFE}][^\\n\u{FFFE}][^0-9\u{FFFE}][^0-9A-Z_a-z\u{FFFE}][^\\t\\n\\x0B\\f\\r \u{FFFE}]",
        ),
        (r"[a-z]\d\w\s", "[a-z][0-9][0-9A-Z_a-z][\\t\\n\\x0B\\f\\r ]"),
    ] {
        assert_eq!(
            custom_pattern::translate_with(pattern, false, true)
                .unwrap()
                .canonical_pattern,
            canonical
        );
        assert_eq!(
            CustomDetectorDefinition::create(
                "custom.d",
                pattern,
                PrivacyAction::Mask,
                false,
                true,
                None
            )
            .unwrap()
            .canonical_pattern(),
            format!("[^0-9A-Z_a-z](?:{canonical})[^0-9A-Z_a-z]")
        );
    }
}

#[test]
fn whole_word_rejects_anchors() {
    for (pattern, position) in [("^EMP", 0), ("EMP$", 3), ("(a|^b)", 3)] {
        assert_eq!(
            load_error(&format!(
                "{HEADER}{}",
                detector(
                    "custom.d",
                    pattern,
                    "mask",
                    "    wholeWord: true\n",
                    "[EMP]"
                )
            )),
            format!(
                "Custom detector 'custom.d' pattern has unsupported syntax at position {position}: ^ and $ are not supported with wholeWord."
            )
        );
    }
}

#[test]
fn patterns_reject_the_sentinel_character() {
    for pattern in ["a\u{FFFE}", "[a-\u{FFFE}]", "\u{FFFF}"] {
        let message = CustomDetectorDefinition::create(
            "custom.d",
            pattern,
            PrivacyAction::Mask,
            false,
            false,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            message.ends_with(": characters U+FFFE and U+FFFF are not supported."),
            "{message}"
        );
    }
}

// ------------------------------------------------------------------ A4

#[test]
fn custom_detectors_redact_through_a_split_emoji() {
    let engine = engine(&detector(
        "custom.d",
        "key=.{8}",
        "replace",
        "",
        "[key=12345678]",
    ));
    assert_eq!(
        engine
            .redact_text("key=s3cr3tk\u{1F600} rest")
            .redacted_text
            .as_deref(),
        Some("***REDACTED*** rest")
    );
}

// ------------------------------------------------------------------ A5

#[test]
fn load_rejects_unsupported_raw_characters() {
    // Lone surrogates (C# only) cannot occur in Rust strings.
    for code_point in [
        0x0000u32, 0x0008, 0x000B, 0x000C, 0x001F, 0x007F, 0x0085, 0x009F, 0x2028, 0x2029,
    ] {
        let character = char::from_u32(code_point).unwrap();
        let expected =
            format!("Privacy profile contains unsupported character U+{code_point:04X}.");
        assert_eq!(
            load_error(&format!("{HEADER}# comment {character}\n")),
            expected
        );
        assert_eq!(
            load_error(&format!(
                "{HEADER}{}",
                detector("custom.d", &format!("a{character}b"), "mask", "", "[x]")
            )),
            expected
        );
    }
}

#[test]
fn load_rejects_unsupported_characters_from_escapes() {
    for (scalar, code_point) in [
        (r#""a\x0Cb""#, "U+000C"),
        (r#""a\Lb""#, "U+2028"),
        (r#""a\Nb""#, "U+0085"),
        (r#""a\0b""#, "U+0000"),
        (r#""\uD83D\uDE00""#, "U+D83D"),
        (r#""\U0000DE00""#, "U+DE00"),
    ] {
        assert_eq!(
            load_error(&format!("{HEADER}secretFieldNames: [{scalar}]\n")),
            format!("Privacy profile contains unsupported character {code_point}."),
            "{scalar}"
        );
    }
}

#[test]
fn load_accepts_tabs_line_endings_and_supplementary_characters() {
    let profile = load(&format!(
        "{}secretFieldNames: [\"a\\tb\", \"\\U0001F600x\", \"\u{1F600}y\"]\r\n# tab\there\n",
        HEADER.replace('\n', "\r\n")
    ))
    .unwrap();
    assert_eq!(profile.policy.secret_field_names, ["ab", "x", "y"]);
}

// ------------------------------------------------------------------ A6

#[test]
fn programmatic_custom_detector_actions_are_honoured() {
    let remove = CustomDetectorDefinition::create(
        "custom.d",
        r"secret-\d+",
        PrivacyAction::Remove,
        false,
        false,
        None,
    )
    .unwrap();
    let policy = PrivacyPolicy {
        default_action: PrivacyAction::Allow,
        custom_detectors: vec![remove],
        ..PrivacyPolicy::default()
    };
    assert_eq!(policy.resolve_action("custom.d"), PrivacyAction::Remove);
    assert!(policy.uses_action(PrivacyAction::Remove));
    let result = PrivacyEngine::new(policy)
        .unwrap()
        .redact_text("x secret-42 y");
    assert_eq!(result.redacted_text.as_deref(), Some("x  y"));
}

#[test]
fn programmatic_hmac_custom_detector_needs_a_key() {
    let hmac = CustomDetectorDefinition::create(
        "custom.d",
        r"secret-\d+",
        PrivacyAction::Hmac,
        false,
        false,
        None,
    )
    .unwrap();
    let unkeyed = PrivacyPolicy {
        custom_detectors: vec![hmac.clone()],
        ..PrivacyPolicy::default()
    };
    assert_eq!(
        PrivacyEngine::new(unkeyed).unwrap_err().dotnet_type(),
        "InvalidOperationException"
    );
    let keyed = PrivacyPolicy {
        custom_detectors: vec![hmac],
        hmac_key: Some(KEY.to_vec()),
        hmac_key_id: "k1".to_owned(),
        ..PrivacyPolicy::default()
    };
    let redacted = PrivacyEngine::new(keyed)
        .unwrap()
        .redact_text("secret-42")
        .redacted_text
        .unwrap();
    assert!(redacted.starts_with("hmac-sha256:k1:"), "{redacted}");
}

#[test]
fn detector_actions_override_the_definition_action() {
    let remove = CustomDetectorDefinition::create(
        "custom.d",
        r"secret-\d+",
        PrivacyAction::Remove,
        false,
        false,
        None,
    )
    .unwrap();
    let policy = PrivacyPolicy {
        custom_detectors: vec![remove],
        detector_actions: [("custom.d".to_owned(), PrivacyAction::Replace)]
            .into_iter()
            .collect(),
        ..PrivacyPolicy::default()
    };
    assert!(!policy.uses_action(PrivacyAction::Remove));
    assert_eq!(
        PrivacyEngine::new(policy)
            .unwrap()
            .redact_text("secret-42")
            .redacted_text
            .as_deref(),
        Some("***REDACTED***")
    );
}

#[test]
fn yaml_and_programmatic_policies_redact_identically() {
    let yaml = load(&format!(
        "{HEADER}defaultAction: allow\ndetectors: {{}}\n{}",
        detector("custom.d", r"secret-\d+", "remove", "", "[secret-1]")
    ))
    .unwrap()
    .policy;
    let programmatic = PrivacyPolicy {
        default_action: PrivacyAction::Allow,
        detector_actions: PrivacyPolicy::create_default().detector_actions,
        custom_detectors: vec![
            CustomDetectorDefinition::create(
                "custom.d",
                r"secret-\d+",
                PrivacyAction::Remove,
                false,
                false,
                None,
            )
            .unwrap(),
        ],
        ..PrivacyPolicy::default()
    };
    let json = r#"{"a":"x secret-42 y alice@example.test 4111111111111111"}"#;
    assert_eq!(
        PrivacyEngine::new(yaml)
            .unwrap()
            .redact_json(json)
            .redacted_json,
        PrivacyEngine::new(programmatic)
            .unwrap()
            .redact_json(json)
            .redacted_json
    );
}
