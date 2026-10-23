//! Byte-for-byte parity with the C# implementation.
//!
//! `tests/vectors/csharp.json.gz` is produced by `tests/vectors/generate.fsx` running the
//! C# `Bower.Redaction` assembly. Every expected value here comes from C#.

use std::collections::HashSet;
use std::io::BufReader;
use std::sync::LazyLock;

use base64::Engine as _;
use bower_redaction::text::normalize_field_name;
use bower_redaction::{
    AppliedFinding, CustomDetectorDefinition, KeyedFieldHasher, PrivacyAction, PrivacyEngine,
    PrivacyFieldRule, PrivacyPolicy, SensitiveDataDetector, checksum, custom_pattern,
    detector_ids as ids, load_privacy_profile, read_key_file,
};
use flate2::read::GzDecoder;
use serde_json::Value;

/// Gzipped so synthetic fuzzed credentials in the corpus do not trip secret scanning.
static VECTORS: LazyLock<Value> = LazyLock::new(|| {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/csharp.json.gz");
    let file = std::fs::File::open(path).expect("vectors exist");
    serde_json::from_reader(BufReader::new(GzDecoder::new(file))).expect("vectors parse")
});

fn vectors(name: &str) -> &'static Vec<Value> {
    VECTORS[name].as_array().expect("vector list")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_owned())
        .collect()
}

fn opt_str(value: &Value) -> Option<&str> {
    value.as_str()
}

fn opt_in() -> HashSet<String> {
    [
        ids::IP_ADDRESS,
        ids::HOSTNAME,
        ids::USERNAME,
        ids::ADDRESS,
        ids::GPS,
        ids::SECURITY_MARKING,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn bare(default_action: PrivacyAction) -> PrivacyPolicy {
    PrivacyPolicy {
        default_action,
        ..PrivacyPolicy::default()
    }
}

/// Mirrors the policies in generate.fsx.
fn policy(name: &str) -> PrivacyPolicy {
    let defaults = PrivacyPolicy::create_default();
    match name {
        "default" => defaults,
        "optin" => PrivacyPolicy {
            enabled_opt_in_detectors: opt_in(),
            ..defaults
        },
        "maskall" => PrivacyPolicy {
            enabled_opt_in_detectors: opt_in(),
            ..bare(PrivacyAction::Mask)
        },
        "sha256" => PrivacyPolicy {
            enabled_opt_in_detectors: opt_in(),
            ..bare(PrivacyAction::Sha256)
        },
        "hmac" => PrivacyPolicy {
            hmac_key: Some(vec![7; 32]),
            hmac_key_id: "k9".to_owned(),
            ..bare(PrivacyAction::Hmac)
        },
        "replace" => PrivacyPolicy {
            replacement_text: "[x]".to_owned(),
            ..bare(PrivacyAction::Replace)
        },
        "alert" => bare(PrivacyAction::AlertOnly),
        "truncact" => bare(PrivacyAction::Truncate),
        "encnokey" => bare(PrivacyAction::Encrypt),
        "short" => PrivacyPolicy {
            maximum_field_length: 10,
            ..defaults
        },
        "nometa" => PrivacyPolicy {
            emit_metadata: false,
            ..defaults
        },
        "disabled" => PrivacyPolicy {
            disabled_detectors: [ids::EMAIL, ids::FIELD_NAME_SECRET]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ..defaults
        },
        "rules" => PrivacyPolicy {
            hmac_key: Some(vec![7; 32]),
            hmac_key_id: "k9".to_owned(),
            field_rules: vec![
                PrivacyFieldRule::new("actor.username", PrivacyAction::Hmac, None),
                PrivacyFieldRule::new("request.userAgent", PrivacyAction::Truncate, Some(10)),
                PrivacyFieldRule::new("*.code", PrivacyAction::Sha256, None),
                PrivacyFieldRule::new("meta.*", PrivacyAction::Mask, None),
                PrivacyFieldRule::new("drop", PrivacyAction::Remove, None),
                PrivacyFieldRule::new("rep", PrivacyAction::Replace, None),
                PrivacyFieldRule::new("keep", PrivacyAction::Allow, None),
                PrivacyFieldRule::new("enc", PrivacyAction::Encrypt, None),
                PrivacyFieldRule::new("trunc", PrivacyAction::Truncate, None),
                PrivacyFieldRule::new("num", PrivacyAction::Mask, None),
            ],
            ..defaults
        },
        other => panic!("unknown policy {other}"),
    }
}

fn finding_text(finding: &AppliedFinding) -> String {
    [
        finding.detector_id.as_str(),
        finding.category.as_str(),
        finding.path.as_str(),
        finding.action.name(),
        if finding.validated { "true" } else { "false" },
        finding.sub_kind.as_deref().unwrap_or(""),
    ]
    .join("|")
}

fn preview(input: &str) -> String {
    input.chars().take(160).collect()
}

#[test]
fn redact_json_matches_csharp() {
    let mut engines = std::collections::HashMap::new();
    let mut failures = Vec::new();
    let all = vectors("engine");
    for vector in all {
        let name = vector["policy"].as_str().unwrap();
        let engine = engines
            .entry(name.to_owned())
            .or_insert_with(|| PrivacyEngine::new(policy(name)).expect("policy is valid"));
        let input = vector["input"].as_str().unwrap();
        let result = engine.redact_json(input);
        let actions: Vec<Vec<String>> = result
            .metadata
            .actions
            .iter()
            .map(|(key, value)| vec![key.clone(), value.clone()])
            .collect();
        let expected_actions: Vec<Vec<String>> = vector["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(strings)
            .collect();
        let checks = [
            (
                "succeeded",
                result.succeeded == vector["succeeded"].as_bool().unwrap(),
            ),
            (
                "failureCode",
                result.failure_code.as_deref() == opt_str(&vector["failureCode"]),
            ),
            (
                "redactedJson",
                result.redacted_json.as_deref() == opt_str(&vector["redactedJson"]),
            ),
            (
                "removedPaths",
                result.removed_paths == strings(&vector["removedPaths"]),
            ),
            (
                "maskedPaths",
                result.masked_paths == strings(&vector["maskedPaths"]),
            ),
            (
                "detected",
                result.metadata.detected == strings(&vector["detected"]),
            ),
            ("actions", actions == expected_actions),
            (
                "findings",
                result.findings.iter().map(finding_text).collect::<Vec<_>>()
                    == strings(&vector["findings"]),
            ),
        ];
        for (field, ok) in checks {
            if !ok {
                failures.push(format!(
                    "[{name}] {field} differs for {}\n  rust:   {:?} / {:?}\n  csharp: {:?} / {:?}",
                    preview(input),
                    result.redacted_json.as_deref().map(preview),
                    result.findings.iter().map(finding_text).collect::<Vec<_>>(),
                    vector["redactedJson"].as_str().map(preview),
                    vector["findings"],
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors differ:\n{}",
        failures.len(),
        all.len(),
        failures.join("\n")
    );
}

#[test]
fn redact_text_matches_csharp() {
    let engines: Vec<(&str, PrivacyEngine)> = ["optin", "maskall"]
        .into_iter()
        .map(|name| (name, PrivacyEngine::new(policy(name)).unwrap()))
        .collect();
    let mut failures = Vec::new();
    let all = vectors("text");
    for vector in all {
        let name = vector["policy"].as_str().unwrap();
        let engine = &engines
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .unwrap()
            .1;
        let input = vector["input"].as_str().unwrap();
        let result = engine.redact_text(input);
        let findings: Vec<String> = result.findings.iter().map(finding_text).collect();
        if result.succeeded != vector["succeeded"].as_bool().unwrap()
            || result.redacted_text.as_deref() != opt_str(&vector["redactedText"])
            || findings != strings(&vector["findings"])
        {
            failures.push(format!(
                "[{name}] {input:?}\n  rust:   {:?} {findings:?}\n  csharp: {:?} {}",
                result.redacted_text, vector["redactedText"], vector["findings"]
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors differ:\n{}",
        failures.len(),
        all.len(),
        failures.join("\n")
    );
}

#[test]
fn checksums_match_csharp() {
    type Check = fn(&str) -> bool;
    let checks: [(&str, Check); 6] = [
        ("tfn", checksum::is_valid_tfn),
        ("abn", checksum::is_valid_abn),
        ("acn", checksum::is_valid_acn),
        ("medicare", checksum::is_valid_medicare),
        ("ihi", checksum::is_valid_ihi),
        ("luhn", checksum::luhn),
    ];
    let mut valid = 0;
    for vector in vectors("checksums") {
        let input = vector["input"].as_str().unwrap();
        for (name, check) in checks {
            let expected = vector[name].as_bool().unwrap();
            valid += usize::from(expected);
            assert_eq!(check(input), expected, "{name}({input:?})");
        }
    }
    assert!(valid > 100, "vectors include valid identifiers");
}

#[test]
fn keyed_hasher_matches_csharp() {
    let key: Vec<u8> = (0..32).collect();
    let hasher = KeyedFieldHasher::new(&key).unwrap();
    for vector in vectors("hasher") {
        let value = vector["value"].as_str().unwrap();
        let key_id = opt_str(&vector["keyId"]);
        assert_eq!(
            hasher.hash(value, key_id).unwrap(),
            vector["hash"].as_str().unwrap(),
            "{value:?} {key_id:?}"
        );
    }
    assert!(KeyedFieldHasher::new(&key[..31]).is_err());
    assert!(hasher.hash(" \t", None).is_err());
}

#[test]
fn privacy_profiles_match_csharp() {
    let mut failures = Vec::new();
    for vector in vectors("profiles") {
        let yaml = vector["yaml"].as_str().unwrap();
        let result = load_privacy_profile(yaml, Some(&[9; 32]), Some("kp"));
        match (result, vector["ok"].as_bool().unwrap()) {
            (Ok(loaded), true) => {
                let policy = &loaded.policy;
                let actions: Vec<Vec<String>> = policy
                    .detector_actions
                    .iter()
                    .map(|(id, action)| vec![id.clone(), action.name().to_owned()])
                    .collect();
                let mut disabled: Vec<String> = policy.disabled_detectors.iter().cloned().collect();
                disabled.sort();
                let mut enabled: Vec<String> =
                    policy.enabled_opt_in_detectors.iter().cloned().collect();
                enabled.sort();
                let rules: Vec<Vec<String>> = policy
                    .field_rules
                    .iter()
                    .map(|rule| {
                        vec![
                            rule.path.clone(),
                            rule.action.name().to_owned(),
                            rule.max_length
                                .map(|value| value.to_string())
                                .unwrap_or_default(),
                        ]
                    })
                    .collect();
                let expected_actions: Vec<Vec<String>> = vector["detectorActions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(strings)
                    .collect();
                let expected_rules: Vec<Vec<String>> = vector["fieldRules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(strings)
                    .collect();
                let same = loaded.id.as_deref() == opt_str(&vector["id"])
                    && loaded.version.as_deref() == opt_str(&vector["version"])
                    && loaded.hash == vector["hash"].as_str().unwrap()
                    && policy.default_action.name() == vector["defaultAction"].as_str().unwrap()
                    && actions == expected_actions
                    && disabled == strings(&vector["disabled"])
                    && enabled == strings(&vector["enabledOptIn"])
                    && rules == expected_rules
                    && policy.maximum_field_length as u64
                        == vector["maximumFieldLength"].as_u64().unwrap()
                    && policy.emit_metadata == vector["emitMetadata"].as_bool().unwrap()
                    && policy.hmac_key_id == vector["hmacKeyId"].as_str().unwrap()
                    && custom_detector_vectors(policy) == expected_custom(vector)
                    && policy.secret_field_names == strings(&vector["secretFieldNames"]);
                if !same {
                    failures.push(format!("{yaml:?}: loaded differently: {loaded:?}"));
                }
            }
            (Err(error), false) => {
                let expected_type = vector["error"].as_str().unwrap();
                let message = vector["message"].as_str().unwrap();
                let (rust_type, compare_message) = match expected_type {
                    // YAML parser messages come from different libraries.
                    _ if message.starts_with("Privacy profile is invalid at line") => {
                        (expected_type, false)
                    }
                    _ => (expected_type, true),
                };
                if error.dotnet_type() != rust_type
                    || (compare_message && error.to_string() != message)
                {
                    failures.push(format!(
                        "{yaml:?}: {error:?} ({}) vs {expected_type}: {message}",
                        error.dotnet_type()
                    ));
                }
            }
            (Ok(loaded), false) => failures.push(format!(
                "{yaml:?}: loaded {loaded:?}, C# failed: {}",
                vector["message"]
            )),
            (Err(error), true) => failures.push(format!("{yaml:?}: failed {error:?}, C# loaded")),
        }
    }

    for vector in vectors("profilesWithoutKey") {
        let yaml = vector["yaml"].as_str().unwrap();
        let result = load_privacy_profile(yaml, None, None);
        match (result, vector["ok"].as_bool().unwrap()) {
            (Ok(_), true) => {}
            (Err(error), false) => {
                if error.dotnet_type() != vector["error"].as_str().unwrap()
                    || error.to_string() != vector["message"].as_str().unwrap()
                {
                    failures.push(format!("{yaml:?}: {error:?} vs {}", vector["message"]));
                }
            }
            (other, _) => failures.push(format!("{yaml:?}: {other:?} vs {vector}")),
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn custom_detector_vectors(policy: &PrivacyPolicy) -> Vec<Vec<String>> {
    policy
        .custom_detectors
        .iter()
        .map(|detector| {
            vec![
                detector.id().to_owned(),
                detector.description().unwrap_or_default().to_owned(),
                detector.pattern().to_owned(),
                detector.canonical_pattern().to_owned(),
                detector.ignore_case().to_string(),
                detector.whole_word().to_string(),
                detector.action().name().to_owned(),
            ]
        })
        .collect()
}

fn expected_custom(vector: &Value) -> Vec<Vec<String>> {
    vector["customDetectors"]
        .as_array()
        .expect("customDetectors")
        .iter()
        .map(strings)
        .collect()
}

/// The profile cases include every custom detector and secret field name error.
#[test]
fn custom_profile_vectors_cover_every_message() {
    let messages: Vec<&str> = vectors("profiles")
        .iter()
        .filter_map(|vector| vector["message"].as_str())
        .collect();
    for fragment in [
        "at most 32 custom detectors",
        "must be custom.<name>",
        "is defined more than once",
        "description must be at most 256",
        "pattern must be 1-512",
        "pattern has unsupported syntax at position",
        "pattern is too complex",
        "must not match an empty string",
        "requires an action",
        "Unknown privacy action",
        "requires at least one tests.match",
        "may have at most 16 tests.match",
        "did not match tests.match[",
        "matched tests.noMatch[",
        "sets its action in customDetectors, not detectors",
        "at most 64 secretFieldNames",
        "has no letters or digits",
        "Privacy profile 'customDetectors' must not be null.",
        "Privacy profile 'secretFieldNames' must not be null.",
        "Privacy profile custom detector must not be null.",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(fragment)),
            "no vector for {fragment}"
        );
    }
}

#[test]
fn custom_patterns_match_csharp() {
    let reasons: Vec<String> = strings(&VECTORS["customPatternReasons"]);
    assert_eq!(reasons, custom_pattern::reasons::ALL);
    let mut failures = Vec::new();
    let all = vectors("customPatterns");
    for vector in all {
        let pattern = vector["pattern"].as_str().unwrap();
        let ignore_case = vector["ignoreCase"].as_bool().unwrap();
        let expected = vector["translation"].as_array().unwrap();
        let actual: Vec<Value> = match custom_pattern::translate(pattern, ignore_case) {
            Ok(translation) => vec![
                Value::Bool(true),
                Value::from(translation.canonical_pattern),
                Value::from(translation.complexity),
                Value::Bool(translation.matches_empty),
            ],
            Err(error) => vec![
                Value::Bool(false),
                Value::from(error.position),
                Value::from(error.reason),
            ],
        };
        if &actual != expected {
            failures.push(format!(
                "{pattern:?} ignoreCase={ignore_case}: rust {actual:?} vs C# {expected:?}"
            ));
        }

        let created = match CustomDetectorDefinition::create(
            "custom.t",
            pattern,
            PrivacyAction::Mask,
            ignore_case,
            false,
            None,
        ) {
            Ok(definition) => format!("ok:{}", definition.canonical_pattern()),
            Err(error) => error.to_string(),
        };
        if created != vector["created"].as_str().unwrap() {
            failures.push(format!(
                "{pattern:?} ignoreCase={ignore_case}: created {created:?} vs C# {}",
                vector["created"]
            ));
        }
    }

    assert!(all.len() > 300, "pattern corpus: {}", all.len());
    assert!(
        failures.is_empty(),
        "{} of {} pattern vectors differ:\n{}",
        failures.len(),
        all.len(),
        failures.join("\n")
    );
}

fn custom_engines() -> Vec<(String, PrivacyEngine)> {
    VECTORS["customEngineProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let name = entry[0].as_str().unwrap().to_owned();
            let loaded =
                load_privacy_profile(entry[1].as_str().unwrap(), Some(&[9; 32]), Some("kp"))
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
            (name, PrivacyEngine::new(loaded.policy).unwrap())
        })
        .collect()
}

#[test]
fn custom_detector_redaction_matches_csharp() {
    let engines = custom_engines();
    let engine = |name: &str| {
        &engines
            .iter()
            .find(|(candidate, _)| candidate == name)
            .unwrap()
            .1
    };
    let mut failures = Vec::new();
    for vector in vectors("customEngine") {
        let name = vector["profile"].as_str().unwrap();
        let input = vector["input"].as_str().unwrap();
        let result = engine(name).redact_json(input);
        let actions: Vec<Vec<String>> = result
            .metadata
            .actions
            .iter()
            .map(|(key, value)| vec![key.clone(), value.clone()])
            .collect();
        let expected_actions: Vec<Vec<String>> = vector["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(strings)
            .collect();
        let findings: Vec<String> = result.findings.iter().map(finding_text).collect();
        if result.succeeded != vector["succeeded"].as_bool().unwrap()
            || result.failure_code.as_deref() != opt_str(&vector["failureCode"])
            || result.redacted_json.as_deref() != opt_str(&vector["redactedJson"])
            || result.removed_paths != strings(&vector["removedPaths"])
            || result.masked_paths != strings(&vector["maskedPaths"])
            || result.metadata.detected != strings(&vector["detected"])
            || actions != expected_actions
            || findings != strings(&vector["findings"])
        {
            failures.push(format!(
                "[{name}] {input}\n  rust:   {:?} {findings:?}\n  csharp: {:?} {}",
                result.redacted_json, vector["redactedJson"], vector["findings"]
            ));
        }
    }

    for vector in vectors("customText") {
        let name = vector["profile"].as_str().unwrap();
        let input = vector["input"].as_str().unwrap();
        let result = engine(name).redact_text(input);
        let findings: Vec<String> = result.findings.iter().map(finding_text).collect();
        if result.succeeded != vector["succeeded"].as_bool().unwrap()
            || result.redacted_text.as_deref() != opt_str(&vector["redactedText"])
            || findings != strings(&vector["findings"])
        {
            failures.push(format!(
                "[{name}] text {input:?}\n  rust:   {:?} {findings:?}\n  csharp: {:?} {}",
                result.redacted_text, vector["redactedText"], vector["findings"]
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn field_name_normalization_matches_csharp() {
    let mut failures = Vec::new();
    for vector in vectors("fieldNameNormalization") {
        let input = vector["input"].as_str().unwrap();
        let expected: Vec<char> = vector["normalized"].as_str().unwrap().chars().collect();
        let actual: Vec<char> = normalize_field_name(input).chars().collect();
        if actual != expected {
            let differing: Vec<String> = input
                .chars()
                .map(|c| (c, normalize_field_name(&c.to_string())))
                .filter(|(c, lowered)| {
                    !expected.is_empty()
                        && !lowered.is_empty()
                        && !expected.contains(&lowered.chars().next().unwrap_or(*c))
                })
                .take(20)
                .map(|(c, lowered)| format!("U+{:04X}->{lowered:?}", u32::from(c)))
                .collect();
            failures.push(format!(
                "chunk starting U+{:04X}: {} vs {} chars; suspects {differing:?}",
                input.chars().next().map_or(0, u32::from),
                actual.len(),
                expected.len()
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn key_files_match_csharp() {
    let directory = tempfile::tempdir().unwrap();
    for vector in vectors("keyFiles") {
        let name = vector["name"].as_str().unwrap();
        let path = directory.path().join(name);
        let content = base64::engine::general_purpose::STANDARD
            .decode(vector["content"].as_str().unwrap())
            .unwrap();
        std::fs::write(&path, content).unwrap();
        let result = read_key_file(&path);
        if vector["ok"].as_bool().unwrap() {
            assert_eq!(
                hex::encode(result.unwrap()),
                vector["key"].as_str().unwrap(),
                "{name}"
            );
        } else {
            assert_eq!(
                result.unwrap_err().dotnet_type(),
                vector["error"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}

#[test]
fn facade_matches_csharp() {
    let detector = SensitiveDataDetector::new();
    for vector in vectors("facade") {
        let input = vector["input"].as_str().unwrap();
        let result = detector.scan_and_redact(input);
        assert_eq!(result.succeeded, vector["succeeded"].as_bool().unwrap());
        assert_eq!(
            result.failure_code.as_deref(),
            opt_str(&vector["failureCode"])
        );
        assert_eq!(
            result.redacted_json.as_deref(),
            opt_str(&vector["redactedJson"])
        );
        let findings: Vec<String> = result
            .findings
            .iter()
            .map(|f| format!("{}|{}|{}|{}", f.kind, f.path, f.preview, f.action))
            .collect();
        assert_eq!(findings, strings(&vector["findings"]), "{input}");
    }
}

#[test]
fn policy_validation_matches_csharp() {
    for vector in vectors("policyErrors") {
        let path = vector["path"].as_str().unwrap();
        let policy = PrivacyPolicy {
            field_rules: vec![PrivacyFieldRule::new(path, PrivacyAction::Mask, None)],
            ..PrivacyPolicy::default()
        };
        match (PrivacyEngine::new(policy), vector["ok"].as_bool().unwrap()) {
            (Ok(_), true) => {}
            (Err(error), false) => {
                assert_eq!(
                    error.dotnet_type(),
                    vector["error"].as_str().unwrap(),
                    "{path:?}"
                );
                assert_eq!(
                    error.to_string(),
                    vector["message"].as_str().unwrap(),
                    "{path:?}"
                );
            }
            (result, _) => panic!("{path:?}: {result:?} vs C# {vector}"),
        }
    }
}
