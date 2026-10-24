//! Custom detectors (custom redaction rules) and secret field names: ports of
//! tests/Bower.UnitTests/CustomRedactionTests.cs. Byte parity with C# is proven by
//! `parity.rs` over the generated vectors.

use bower_contracts::EventRedactor;
use bower_redaction::custom_pattern::{self, reasons};
use bower_redaction::detectors::custom::is_valid_id;
use bower_redaction::text::normalize_field_name;
use bower_redaction::{
    CompositeFieldNameDetector, CustomDetectorDefinition, DetectionMatch, FieldNameDetector,
    FieldNameSecretDetector, JsonEventRedactor, LoadedPrivacyProfile, PrivacyAction, PrivacyEngine,
    PrivacyError, PrivacyPolicy, ScanText, SensitiveDetector, default_value_detectors,
    detector_categories as categories, detector_ids as ids, load_privacy_profile,
    value_detectors_for,
};
use serde_json::Value;

const HEADER: &str =
    "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n";
const KEY: [u8; 32] = [7; 32];

fn detector(id: &str, pattern: &str, action: &str, extra: &str, tests: &str) -> String {
    format!(
        "customDetectors:\n  - id: {id}\n    pattern: '{pattern}'\n    action: {action}\n{extra}    tests:\n      match: {tests}\n"
    )
}

fn simple(pattern: &str, tests: &str) -> String {
    detector("custom.d", pattern, "mask", "", tests)
}

fn load(yaml: &str) -> Result<LoadedPrivacyProfile, PrivacyError> {
    load_privacy_profile(yaml, Some(&KEY), Some("k1"))
}

fn load_error(yaml: &str) -> String {
    match load(yaml) {
        Ok(_) => panic!("loaded: {yaml}"),
        Err(error) => {
            assert_eq!(error.dotnet_type(), "InvalidDataException", "{error}");
            error.to_string()
        }
    }
}

fn engine(body: &str) -> PrivacyEngine {
    PrivacyEngine::new(
        load(&format!("{HEADER}{body}"))
            .expect("profile loads")
            .policy,
    )
    .expect("engine builds")
}

fn redact_text(engine: &PrivacyEngine, text: &str) -> String {
    engine.redact_text(text).redacted_text.expect("redacted")
}

fn example_profile() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../deploy/privacy/custom-redaction-example.yaml"
    );
    std::fs::read_to_string(path).expect("example profile exists")
}

// ------------------------------------------------------------------ translator

#[test]
fn translate_emits_canonical_patterns() {
    for (pattern, ignore_case, canonical) in [
        (r"EMP-\d{6}", false, "EMP-[0-9]{6}"),
        (r"EMP-\d{6}", true, "[Ee][Mm][Pp]-[0-9]{6}"),
        (r"^\w+$", false, r"\A[0-9A-Z_a-z]+\z"),
        (
            r"\s\S\D\W",
            false,
            r"[\t\n\x0B\f\r ][^\t\n\x0B\f\r ][^0-9][^0-9A-Z_a-z]",
        ),
        (r"[\d\w\s.-]", false, r"[0-90-9A-Z_a-z\t\n\x0B\f\r .\-]"),
        ("(a|b)(?:c)x()", false, "(?:a|b)(?:c)x(?:)"),
        ("a.b", false, r"a[^\n]b"),
        (r"x}]\.\#\ \-\/", false, r"x\}\]\.# -/"),
        (r"[\]\[\^\\&~]", false, r"[\]\[\^\\\&\~]"),
        ("a{01}b{2,}c{3,5}?d+?", false, "a{1}b{2,}c{3,5}?d+?"),
        ("[a-fX]", true, "[a-fA-FXx]"),
        ("[Z-b]", true, "[Z-bzA-B]"),
        ("[^q]", true, "[^qQ]"),
        ("café ſK", true, "[cC][aA][fF]é ſ[Kk]"),
        (
            "[\u{4E00}-\u{FFFC}]",
            false,
            "[\u{4E00}-\u{D7FF}\u{E000}-\u{FFFC}]",
        ),
    ] {
        let translation = custom_pattern::translate(pattern, ignore_case)
            .unwrap_or_else(|error| panic!("{pattern}: {error:?}"));
        assert_eq!(translation.canonical_pattern, canonical, "{pattern}");
    }
}

#[test]
fn translate_rejects_unsupported_syntax_with_position() {
    for (pattern, position, reason) in [
        ("a(?=b)", 1, reasons::LOOKAROUND),
        ("(?<!a)b", 0, reasons::LOOKAROUND),
        (r"(a)\1", 3, reasons::BACK_REFERENCE),
        (r"\k<n>", 0, reasons::BACK_REFERENCE),
        (r"\p{L}", 0, reasons::UNICODE_PROPERTY),
        ("(?i)a", 0, reasons::INLINE_FLAGS),
        ("(?-i:a)", 0, reasons::INLINE_FLAGS),
        ("(?<n>a)", 0, reasons::NAMED_GROUP),
        ("(?P<n>a)", 0, reasons::NAMED_GROUP),
        ("(?>a)", 0, reasons::UNSUPPORTED_GROUP),
        ("(?#c)", 0, reasons::UNSUPPORTED_GROUP),
        ("a(b", 1, reasons::UNBALANCED_PARENTHESIS),
        ("ab)", 2, reasons::UNBALANCED_PARENTHESIS),
        ("x[ab", 1, reasons::UNTERMINATED_CLASS),
        ("[]a]", 0, reasons::EMPTY_CLASS),
        ("[a[b]]", 2, reasons::NESTED_CLASS),
        ("[[:alpha:]]", 1, reasons::POSIX_CLASS),
        ("[a&&b]", 2, reasons::SET_OPERATION),
        ("[a-z-[aeiou]]", 4, reasons::SET_OPERATION),
        ("[a~~b]", 2, reasons::SET_OPERATION),
        ("[z-a]", 1, reasons::INVALID_RANGE),
        (r"[a-\d]", 1, reasons::INVALID_RANGE),
        (r"[\W]", 1, reasons::NEGATED_SHORTHAND_IN_CLASS),
        ("a{2,1}", 1, reasons::INVALID_QUANTIFIER),
        ("a{x}", 1, reasons::INVALID_QUANTIFIER),
        ("a{,2}", 1, reasons::INVALID_QUANTIFIER),
        ("a{1001}", 1, reasons::QUANTIFIER_BOUND),
        ("a{1,99999999999}", 1, reasons::QUANTIFIER_BOUND),
        ("*a", 0, reasons::NOTHING_TO_REPEAT),
        ("a|+", 2, reasons::NOTHING_TO_REPEAT),
        ("^*", 1, reasons::NOTHING_TO_REPEAT),
        ("{2}", 0, reasons::NOTHING_TO_REPEAT),
        ("a**", 2, reasons::REPEATED_QUANTIFIER),
        ("a*??", 3, reasons::REPEATED_QUANTIFIER),
        ("a{2}{3}", 4, reasons::REPEATED_QUANTIFIER),
        (r"\bx", 0, reasons::WORD_BOUNDARY),
        (r"x\>", 1, reasons::WORD_BOUNDARY),
        (r"\Ax", 0, reasons::ANCHOR_ESCAPE),
        (r"x\Z", 1, reasons::ANCHOR_ESCAPE),
        (r"\x41", 0, reasons::UNSUPPORTED_ESCAPE),
        (r"\u0041", 0, reasons::UNSUPPORTED_ESCAPE),
        (r"\0", 0, reasons::UNSUPPORTED_ESCAPE),
        (r"\é", 0, reasons::UNSUPPORTED_ESCAPE),
        ("ab\\", 2, reasons::TRAILING_BACKSLASH),
        ("a\u{1F600}", 1, reasons::SUPPLEMENTARY_CHARACTER),
        ("[a-\u{FFFF}]", 3, reasons::RESERVED_CHARACTER),
    ] {
        let error = custom_pattern::translate(pattern, false).expect_err(pattern);
        assert_eq!(
            (error.position, error.reason),
            (position, reason),
            "{pattern}"
        );
        assert!(reasons::ALL.contains(&reason));
    }
}

#[test]
fn translate_estimates_complexity_and_empty_matches() {
    for (pattern, complexity, matches_empty) in [
        (r"EMP-\d{6}", 10, false),
        ("(a{64}){8}", 512, false),
        ("(a{64}){9}", 513, false),
        ("((((a{1000}){1000}){1000}){1000})", 513, false),
        ("a|b|c", 3, false),
        ("a*", 1, true),
        ("x(a|)", 2, false),
        ("(a|)", 1, true),
        ("^$", 2, true),
        ("a{0}", 1, true),
    ] {
        let translation = custom_pattern::translate(pattern, false).unwrap();
        assert_eq!(
            (translation.complexity, translation.matches_empty),
            (complexity, matches_empty),
            "{pattern}"
        );
    }
}

#[test]
fn reasons_are_distinct() {
    let mut sorted = reasons::ALL.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), reasons::ALL.len());
}

// ------------------------------------------------------------------ definitions

#[test]
fn valid_ids_follow_the_custom_name_rule() {
    for (id, valid) in [
        ("custom.employee-id", true),
        ("custom.a1-b2-c3", true),
        ("custom.", false),
        ("custom", false),
        ("Custom.x", false),
        ("custom.A", false),
        ("custom.a--b", false),
        ("custom.-a", false),
        ("custom.a-", false),
        ("custom.a_b", false),
        ("custom.a.b", false),
        ("au.tfn", false),
    ] {
        assert_eq!(is_valid_id(id), valid, "{id}");
    }
    assert!(is_valid_id(&format!("custom.{}", "a".repeat(57))));
    assert!(!is_valid_id(&format!("custom.{}", "a".repeat(58))));
}

#[test]
fn create_validates_like_the_loader() {
    let definition = CustomDetectorDefinition::create(
        "custom.d",
        r"emp-\d{6}",
        PrivacyAction::Hmac,
        true,
        true,
        Some("d"),
    )
    .unwrap();
    assert_eq!(definition.canonical_pattern(), "[eE][mM][pP]-[0-9]{6}");
    assert_eq!(definition.pattern(), r"emp-\d{6}");
    assert!(definition.whole_word());
    assert_eq!(definition.action(), PrivacyAction::Hmac);
    let error = |pattern: &str| {
        CustomDetectorDefinition::create(
            "custom.d",
            pattern,
            PrivacyAction::Mask,
            false,
            false,
            None,
        )
        .unwrap_err()
        .to_string()
    };
    assert_eq!(
        error("a?"),
        "Custom detector 'custom.d' pattern must not match an empty string."
    );
    assert_eq!(
        error("(a{100}){11}"),
        "Custom detector 'custom.d' pattern is too complex."
    );
    assert!(
        CustomDetectorDefinition::create("bad", "x", PrivacyAction::Mask, false, false, None)
            .unwrap_err()
            .to_string()
            .starts_with("Custom detector id 'bad'")
    );
}

// ------------------------------------------------------------------ loader errors

#[test]
fn load_rejects_invalid_custom_detectors_and_secret_field_names() {
    let valid = |id: &str| {
        format!("  - id: {id}\n    pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n")
    };
    let samples_error = "Custom detector 'custom.d' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters.";
    let names_error = "Privacy profile may list at most 64 secretFieldNames of 1-128 characters.";
    let cases: Vec<(String, String)> = vec![
        (
            format!(
                "{HEADER}customDetectors:\n{}",
                (0..33).map(|i| valid(&format!("custom.d{i}"))).collect::<String>()
            ),
            "Privacy profile may define at most 32 custom detectors.".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors: ~\n"),
            "Privacy profile 'customDetectors' must not be null.".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors:\n  - ~\n"),
            "Privacy profile custom detector must not be null.".to_owned(),
        ),
        (
            format!("{HEADER}{}", detector("custom.Bad", "x", "mask", "", "[x]")),
            "Custom detector id 'custom.Bad' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters).".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors:\n  - pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n"),
            "Custom detector id '' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters).".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors:\n{}{}", valid("custom.a"), valid("custom.a")),
            "Custom detector id 'custom.a' is defined more than once.".to_owned(),
        ),
        (
            format!(
                "{HEADER}{}",
                detector("custom.d", "x", "mask", &format!("    description: {}\n", "d".repeat(257)), "[x]")
            ),
            "Custom detector 'custom.d' description must be at most 256 characters.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("", "[x]")),
            "Custom detector 'custom.d' pattern must be 1-512 characters.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple(&"x".repeat(513), "[x]")),
            "Custom detector 'custom.d' pattern must be 1-512 characters.".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors:\n  - id: custom.d\n    action: mask\n    tests:\n      match: [x]\n"),
            "Custom detector 'custom.d' pattern must be 1-512 characters.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x(?<=y)", "[x]")),
            "Custom detector 'custom.d' pattern has unsupported syntax at position 1: lookaround is not supported.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("(x{100}){11}", "[x]")),
            "Custom detector 'custom.d' pattern is too complex.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x*", "[x]")),
            "Custom detector 'custom.d' pattern must not match an empty string.".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    tests:\n      match: [x]\n"),
            "Custom detector 'custom.d' requires an action.".to_owned(),
        ),
        (
            format!("{HEADER}{}", detector("custom.d", "x", "~", "", "[x]")),
            "Custom detector 'custom.d' requires an action.".to_owned(),
        ),
        (
            format!("{HEADER}{}", detector("custom.d", "x", "obliterate", "", "[x]")),
            "Unknown privacy action 'obliterate'.".to_owned(),
        ),
        (
            format!("{HEADER}customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: mask\n"),
            "Custom detector 'custom.d' requires at least one tests.match sample.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x", "[]")),
            "Custom detector 'custom.d' requires at least one tests.match sample.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x", "~")),
            "Custom detector 'custom.d' requires at least one tests.match sample.".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x", &format!("[{}]", vec!["x"; 17].join(", ")))),
            samples_error.to_owned(),
        ),
        (
            format!(
                "{HEADER}{}",
                simple("x", &format!("[x]\n      noMatch: [{}]", vec!["y"; 17].join(", ")))
            ),
            samples_error.to_owned(),
        ),
        (format!("{HEADER}{}", simple("x", "[x, '']")), samples_error.to_owned()),
        (
            format!("{HEADER}{}", simple("x", &format!("[{}]", "x".repeat(1025)))),
            samples_error.to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x", "[x]\n      noMatch: ~")),
            samples_error.to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x", "[x, y]")),
            "Custom detector 'custom.d' did not match tests.match[1].".to_owned(),
        ),
        (
            format!("{HEADER}{}", simple("x", "[x]\n      noMatch: [y, axb]")),
            "Custom detector 'custom.d' matched tests.noMatch[1].".to_owned(),
        ),
        (
            format!("{HEADER}{}detectors:\n  custom.d: remove\n", simple("x", "[x]")),
            "Custom detector 'custom.d' sets its action in customDetectors, not detectors.".to_owned(),
        ),
        (
            format!("{HEADER}{}detectors:\n  custom.other: remove\n", simple("x", "[x]")),
            "Unknown detector id 'custom.other'.".to_owned(),
        ),
        (
            format!("{HEADER}{}disabled: [custom.other]\n", simple("x", "[x]")),
            "Unknown detector id 'custom.other'.".to_owned(),
        ),
        (
            format!("{HEADER}{}enableOptIn: [custom.d]\n", simple("x", "[x]")),
            "Unknown detector id 'custom.d'.".to_owned(),
        ),
        (
            format!("{HEADER}secretFieldNames: ~\n"),
            "Privacy profile 'secretFieldNames' must not be null.".to_owned(),
        ),
        (
            format!(
                "{HEADER}secretFieldNames: [{}]\n",
                (0..65).map(|i| format!("n{i}")).collect::<Vec<_>>().join(", ")
            ),
            names_error.to_owned(),
        ),
        (format!("{HEADER}secretFieldNames: [ok, '']\n"), names_error.to_owned()),
        (format!("{HEADER}secretFieldNames: [ok, ~]\n"), names_error.to_owned()),
        (
            format!("{HEADER}secretFieldNames: [{}]\n", "a".repeat(129)),
            names_error.to_owned(),
        ),
        (
            format!("{HEADER}secretFieldNames: [ok, '---']\n"),
            "Secret field name '---' has no letters or digits.".to_owned(),
        ),
    ];
    for (yaml, message) in cases {
        assert_eq!(load_error(&yaml), message, "{yaml}");
    }
}

#[test]
fn load_rejects_unknown_keys_and_bad_scalars_as_yaml_errors() {
    for extra in ["    unknownKey: 1\n", "    ignoreCase: maybe\n"] {
        let message = load_error(&format!(
            "{HEADER}{}",
            detector("custom.d", "x", "mask", extra, "[x]")
        ));
        assert!(
            message.starts_with("Privacy profile is invalid at line"),
            "{message}"
        );
    }
}

#[test]
fn load_hmac_custom_action_needs_a_key() {
    let yaml = format!("{HEADER}{}", detector("custom.d", "x", "hmac", "", "[x]"));
    let error = load_privacy_profile(&yaml, None, None).unwrap_err();
    assert_eq!(error.dotnet_type(), "InvalidOperationException");
    assert_eq!(
        load(&yaml).unwrap().policy.resolve_action("custom.d"),
        PrivacyAction::Hmac
    );
}

#[test]
fn load_accepts_limits_exactly() {
    let valid = |id: &str| {
        format!("  - id: {id}\n    pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n")
    };
    let yaml = format!(
        "{HEADER}customDetectors:\n{}secretFieldNames: [{}]\n",
        (0..32)
            .map(|i| valid(&format!("custom.d{i}")))
            .collect::<String>(),
        (0..64)
            .map(|i| format!("n{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let profile = load(&yaml).unwrap();
    assert_eq!(profile.policy.custom_detectors.len(), 32);
    assert_eq!(profile.policy.secret_field_names.len(), 64);
    assert_eq!(profile.custom_detector_tests, 32);
    load(&format!(
        "{HEADER}{}",
        simple(&"x".repeat(512), &format!("[{}]", "x".repeat(512)))
    ))
    .unwrap();
    load(&format!(
        "{HEADER}{}",
        simple("x", &format!("[{}]", "x".repeat(1024)))
    ))
    .unwrap();
    load(&format!(
        "{HEADER}{}",
        detector(
            "custom.d",
            "x",
            "mask",
            &format!("    description: {}\n", "d".repeat(256)),
            "[x]"
        )
    ))
    .unwrap();
}

// ------------------------------------------------------------------ loaded policy

#[test]
fn load_puts_definitions_and_normalised_names_on_the_policy() {
    let profile = load(&format!(
        "{HEADER}customDetectors:\n  - id: custom.ref\n    description: refs\n    pattern: 'ref-\\d+'\n    ignoreCase: yes\n    wholeWord: on\n    action: Alert-Only\n    tests:\n      match: [REF-1, 'x ref-22 y']\n      noMatch: [xref-1]\nsecretFieldNames: [sessionKey, SESSION_KEY, Session-Key, 'Пароль', ÜberSecret, a1]\ndisabled: [custom.ref]\n"
    ))
    .unwrap();
    let policy = &profile.policy;
    assert_eq!(policy.custom_detectors.len(), 1);
    let definition = &policy.custom_detectors[0];
    assert_eq!(definition.id(), "custom.ref");
    assert_eq!(definition.description(), Some("refs"));
    assert_eq!(definition.canonical_pattern(), "[rR][eE][fF]-[0-9]+");
    assert!(definition.ignore_case());
    assert!(definition.whole_word());
    assert_eq!(definition.action(), PrivacyAction::AlertOnly);
    assert_eq!(
        policy.resolve_action("custom.ref"),
        PrivacyAction::AlertOnly
    );
    assert!(!policy.is_detector_enabled("custom.ref"));
    assert_eq!(
        policy.secret_field_names,
        ["sessionkey", "пароль", "übersecret", "a1"]
    );
    assert_eq!(profile.custom_detector_tests, 3);
}

#[test]
fn load_hash_covers_the_new_sections() {
    let a = load(&format!("{HEADER}{}", simple("x", "[x]")))
        .unwrap()
        .hash;
    let b = load(&format!(
        "{HEADER}{}",
        detector("custom.d", "x", "mask", "    wholeWord: false\n", "[x]")
    ))
    .unwrap()
    .hash;
    let c = load(&format!("{HEADER}secretFieldNames: [a]\n"))
        .unwrap()
        .hash;
    assert_ne!(a, b);
    assert_ne!(a, c);
}

// ------------------------------------------------------------------ engine

#[test]
fn example_profile_loads_and_redacts_the_sample() {
    let profile = load(&example_profile()).unwrap();
    assert_eq!(profile.id.as_deref(), Some("contoso-custom-redaction"));
    assert_eq!(profile.policy.custom_detectors.len(), 3);
    assert_eq!(profile.custom_detector_tests, 13);
    let redactor = JsonEventRedactor::with_policy(profile.policy).unwrap();
    let result = redactor.redact(
        r#"{"actor":{"username":"alice"},"msg":"EMP-123456 opened CUST-ab1234 see INC0012345, not XEMP-000001","sessionKey":"s","webhook_nonce":"n"}"#,
    );
    assert!(result.succeeded);
    let node: Value = serde_json::from_str(result.redacted_json.as_deref().unwrap()).unwrap();
    let message = node["msg"].as_str().unwrap();
    assert!(
        message.starts_with("EM******56 opened hmac-sha256:k1:"),
        "{message}"
    );
    assert!(
        message.ends_with(" see ***REDACTED***, not XEMP-000001"),
        "{message}"
    );
    assert!(node.get("sessionKey").is_none());
    assert!(node.get("webhook_nonce").is_none());
    assert!(
        node["actor"]["username"]
            .as_str()
            .unwrap()
            .starts_with("hmac-sha256:k1:")
    );
    assert!(
        result
            .privacy_detected
            .unwrap()
            .contains(&"custom.employee-id".to_owned())
    );
    assert_eq!(
        result.privacy_actions.unwrap()["custom.customer-ref"],
        "HMAC"
    );
}

#[test]
fn whole_word_skips_adjacent_matches_and_keeps_scanning() {
    let engine = engine(&detector(
        "custom.d",
        r"EMP-\d{6}",
        "mask",
        "    wholeWord: true\n",
        "[EMP-123456]",
    ));
    let result = engine.redact_text("XEMP-111111 EMP-222222_ (EMP-333333) EMP-4444445 EMP-555555");
    assert_eq!(
        result.redacted_text.as_deref(),
        Some("XEMP-111111 EMP-222222_ (EM******33) EMP-4444445 EM******55")
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.category == categories::CUSTOM)
    );
}

#[test]
fn whole_word_resumes_after_a_skipped_match() {
    let engine = engine(&detector(
        "custom.d",
        "a+b",
        "mask",
        "    wholeWord: true\n",
        "[ab]",
    ));
    assert_eq!(redact_text(&engine, "xaab aaab"), "xaab ****");
}

#[test]
fn custom_detectors_join_longest_first_overlap_resolution() {
    let engine = engine(
        "customDetectors:\n  - id: custom.mail\n    pattern: '[a-z]+@example\\.test'\n    action: remove\n    tests:\n      match: [a@example.test]\n  - id: custom.long\n    pattern: 'card \\d{16}'\n    action: replace\n    tests:\n      match: [card 4111111111111111]\n",
    );
    let result = engine.redact_text("alice@example.test card 4111111111111111");
    assert_eq!(
        result.redacted_text.as_deref(),
        Some("a***@example.test ***REDACTED***")
    );
    let mut found: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.detector_id.as_str())
        .collect();
    found.sort_unstable();
    assert_eq!(found, ["custom.long", ids::EMAIL]);
}

#[test]
fn custom_detectors_scan_property_names_numbers_and_arrays() {
    let engine = engine(&detector(
        "custom.d",
        r"\d{12}",
        "sha256",
        "",
        "['123456789012']",
    ));
    let result =
        engine.redact_json(r#"{"123456789012":"k","n":123456789012,"list":["x 123456789012"]}"#);
    assert!(result.succeeded);
    let redacted = result.redacted_json.unwrap();
    assert!(!redacted.contains("123456789012"), "{redacted}");
    let node: Value = serde_json::from_str(&redacted).unwrap();
    assert!(node["n"].as_str().unwrap().starts_with("sha256:"));
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.path == "$.[key]")
    );
}

#[test]
fn custom_detectors_never_split_surrogate_pairs() {
    let engine = engine(
        "customDetectors:\n  - id: custom.one\n    pattern: 'P[^a]Q'\n    action: remove\n    tests:\n      match: [PxQ]\n  - id: custom.two\n    pattern: 'R[^a][^a]S'\n    action: remove\n    tests:\n      match: [RxyS]\n  - id: custom.dot\n    pattern: 'x.'\n    action: remove\n    tests:\n      match: [xy]\n",
    );
    assert_eq!(
        redact_text(&engine, "P\u{1F600}Q R\u{1F600}S x\u{1F600} xy"),
        "P\u{1F600}Q  x\u{1F600} "
    );
}

#[test]
fn utf16_haystack_maps_matches_back_to_the_text() {
    let definition = CustomDetectorDefinition::create(
        "custom.d",
        "[^a]b",
        PrivacyAction::Mask,
        false,
        false,
        None,
    )
    .unwrap();
    let detector = bower_redaction::CustomPatternDetector::new(definition);
    let text = "\u{1F600}b \u{E9}b xb";
    let mut matches: Vec<DetectionMatch> = Vec::new();
    detector.detect(&ScanText::new(text), "$", &mut matches);
    let spans: Vec<&str> = matches
        .iter()
        .map(|found| &text[found.start..found.end])
        .collect();
    // The first candidate is the emoji's low surrogate plus "b": it splits the pair.
    assert_eq!(spans, ["\u{E9}b", "xb"]);
    assert_eq!(matches[0].length_utf16, 2);
}

#[test]
fn secret_field_names_are_handled_like_field_name_secrets() {
    let engine = engine("secretFieldNames: [sessionKey, 'Пароль']\n");
    let result = engine
        .redact_json(r#"{"SESSION_KEY":"s","session-key":"s","ПАРОЛЬ":"s","sessionKeys":"kept"}"#);
    let node: Value = serde_json::from_str(result.redacted_json.as_deref().unwrap()).unwrap();
    let mut keys: Vec<&String> = node.as_object().unwrap().keys().collect();
    keys.sort_unstable();
    assert_eq!(keys, ["privacy", "sessionKeys"]);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.detector_id == ids::FIELD_NAME_SECRET)
    );
    assert_eq!(result.findings.len(), 3);
}

#[test]
fn secret_field_names_follow_the_field_name_secret_action_and_switch() {
    let names = "secretFieldNames: [sessionKey]\n";
    let json = r#"{"sessionKey":"s"}"#;
    let alert = engine(&format!(
        "{names}detectors:\n  field-name-secret: alert-only\n"
    ))
    .redact_json(json);
    let disabled = engine(&format!("{names}disabled: [field-name-secret]\n")).redact_json(json);
    let node: Value = serde_json::from_str(alert.redacted_json.as_deref().unwrap()).unwrap();
    assert_eq!(node["sessionKey"], "s");
    assert_eq!(alert.findings.len(), 1);
    assert_eq!(alert.findings[0].action, PrivacyAction::AlertOnly);
    assert_eq!(disabled.redacted_json.as_deref(), Some(json));
}

#[test]
fn composite_field_name_detector_keeps_the_inner_identity() {
    let detector = CompositeFieldNameDetector::new(
        Box::new(FieldNameSecretDetector),
        &["sessionkey".to_owned()],
    );
    assert_eq!(detector.id(), ids::FIELD_NAME_SECRET);
    assert!(detector.matches_field_name("sessionkey"));
    assert!(detector.matches_field_name("password"));
    assert!(!detector.matches_field_name("sessionkeys"));
    assert!(!detector.matches_field_name(""));
}

#[test]
fn custom_detectors_do_not_raise_sensitive_data_events() {
    assert!(!PrivacyEngine::is_security_event_worthy(
        "custom.employee-id"
    ));
}

#[test]
fn explicit_detector_lists_are_used_as_given() {
    let policy = load(&format!("{HEADER}{}", simple("secret-x", "[secret-x]")))
        .unwrap()
        .policy;
    let with_custom = PrivacyEngine::new(policy.clone()).unwrap();
    assert!(with_custom.detectors().iter().any(|d| d.id() == "custom.d"));
    let explicit = PrivacyEngine::with_detectors(
        policy,
        default_value_detectors(),
        Box::new(FieldNameSecretDetector),
    )
    .unwrap();
    assert!(!explicit.detectors().iter().any(|d| d.id() == "custom.d"));
}

#[test]
fn field_name_normalizer_lowers_letters_and_drops_the_rest() {
    assert_eq!(
        normalize_field_name("x-Contoso_Signature"),
        "xcontososignature"
    );
    assert_eq!(normalize_field_name("ПАРОЛЬ"), "пароль");
    assert_eq!(normalize_field_name("pass\u{1F600}word"), "password");
}

// ------------------------------------------------------------------ adversarial

#[test]
fn catastrophic_backtracking_shapes_run_in_linear_time() {
    let engine = engine(&simple("(a+)+b", "[ab]"));
    let result = engine.redact_text(&format!("{}!", "a".repeat(100_000)));
    assert!(result.succeeded);
    assert!(result.findings.is_empty());
}

struct ThrowingDetector;

impl SensitiveDetector for ThrowingDetector {
    fn id(&self) -> &str {
        "custom.throwing"
    }

    fn category(&self) -> &str {
        categories::CUSTOM
    }

    fn detect(&self, _: &ScanText<'_>, _: &str, _: &mut Vec<DetectionMatch>) {
        panic!("detector failure");
    }
}

#[test]
fn redaction_failure_still_quarantines_with_custom_detectors() {
    let policy = load(&format!(
        "{HEADER}{}secretFieldNames: [sessionKey]\n",
        simple(r"EMP-\d{6}", "[EMP-123456]")
    ))
    .unwrap()
    .policy;
    let mut detectors = value_detectors_for(&policy);
    detectors.push(Box::new(ThrowingDetector));
    let failing =
        PrivacyEngine::with_detectors(policy.clone(), detectors, Box::new(FieldNameSecretDetector))
            .unwrap();
    let engine = PrivacyEngine::new(policy).unwrap();

    let thrown = failing.redact_json(r#"{"a":"EMP-123456"}"#);
    let duplicate = engine.redact_json(r#"{"a":"EMP-123456","a":"x"}"#);
    let text = failing.redact_text("EMP-123456");
    for (code, redacted) in [
        (thrown.failure_code, thrown.redacted_json),
        (duplicate.failure_code, duplicate.redacted_json),
        (text.failure_code, text.redacted_text),
    ] {
        assert_eq!(code.as_deref(), Some("redaction-failed"));
        assert!(redacted.is_none());
    }
}

#[test]
fn long_single_matches_stay_bounded_and_succeed() {
    let engine = engine(&simple("(?:.+){8}", "[xxxxxxxx]"));
    let result = engine.redact_json(&format!("{{\"a\":\"{}\"}}", "x".repeat(200_000)));
    assert!(result.succeeded);
    let node: Value = serde_json::from_str(result.redacted_json.as_deref().unwrap()).unwrap();
    assert!(node["a"].as_str().unwrap().starts_with("xx***"));
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.detector_id == "custom.d")
    );
}

#[test]
fn attacker_controlled_values_cannot_escape_anchors_or_newlines() {
    let engine = engine(&simple("^secret$", "[secret]"));
    assert_eq!(redact_text(&engine, "secret\n"), "secret\n");
    assert_eq!(redact_text(&engine, "secret"), "se**et");
    assert_eq!(redact_text(&engine, "x secret"), "x secret");
}

#[test]
fn policies_compare_custom_detectors_by_definition() {
    let a = load(&format!("{HEADER}{}", simple("x", "[x]")))
        .unwrap()
        .policy;
    let b = load(&format!("{HEADER}{}", simple("x", "[x]")))
        .unwrap()
        .policy;
    let c = load(&format!("{HEADER}{}", simple("y", "[y]")))
        .unwrap()
        .policy;
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, PrivacyPolicy::create_default());
}
