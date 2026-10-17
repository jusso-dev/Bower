//! Byte-for-byte parity with the C# implementation.
//!
//! `tests/vectors/csharp.json.gz` is produced by `tests/vectors/generate.fsx` running the
//! C# `Bower.Redaction` assembly. Every expected value here comes from C#.

use std::collections::HashSet;
use std::sync::LazyLock;

use base64::Engine as _;
use bower_redaction::{
    AppliedFinding, KeyedFieldHasher, PrivacyAction, PrivacyEngine, PrivacyFieldRule,
    PrivacyPolicy, SensitiveDataDetector, checksum, detector_ids as ids, load_privacy_profile,
    read_key_file,
};
use serde_json::Value;

static VECTORS: LazyLock<Value> = LazyLock::new(|| {
    // Gzipped: the vectors are full of synthetic secrets by design, and plain text
    // trips repository secret scanning.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/csharp.json.gz");
    let file = std::fs::File::open(path).expect("vectors exist");
    serde_json::from_reader(std::io::BufReader::new(flate2::read::GzDecoder::new(file)))
        .expect("vectors parse")
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

/// The C# output, adjusted for the two documented divergences. Both come from C#
/// masking slicing a surrogate pair (`value[..2]`), which leaves an unpaired high
/// surrogate in an intermediate .NET string. Rust strings cannot hold one, so the
/// mask writes U+FFFD immediately (System.Text.Json writes the same U+FFFD later):
///
/// * two keys whose masks differ only in that surrogate are distinct in C#, which
///   then serialises both as the same name (duplicate keys in the output). Rust sees
///   the collision and renames the second key `redacted-key-1`;
/// * `PolicyApplicator.Truncate` drops a cut-off unpaired high surrogate; Rust keeps
///   the U+FFFD it already wrote.
///
/// Findings, paths and metadata still match C# exactly for these inputs.
fn expected_redacted_json(policy: &str, input: &str, csharp: Option<&str>) -> Option<String> {
    let csharp = csharp?;
    if input == "{\"PayID: a\u{1F600}bc\":1,\"PayID: a\u{1F300}bc\":2}" {
        let duplicate = "\"PayID: a\u{5C}uFFFD*bc\":2";
        // Only masking policies collide; hashes and replacements keep keys distinct.
        return Some(csharp.replacen(duplicate, r#""redacted-key-1":2"#, 1));
    }

    if policy == "short" && input.starts_with("{\"a\":\" PayID: a\u{1F600}bcdefgh\"") {
        let cut = r#""a":" PayID: a","#;
        assert!(csharp.contains(cut), "C# drops the unpaired surrogate");
        return Some(csharp.replacen(cut, "\"a\":\" PayID: a\u{5C}uFFFD\",", 1));
    }

    Some(csharp.to_owned())
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
                result.redacted_json.as_deref()
                    == expected_redacted_json(name, input, opt_str(&vector["redactedJson"]))
                        .as_deref(),
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
                    && policy.hmac_key_id == vector["hmacKeyId"].as_str().unwrap();
                if !same {
                    failures.push(format!("{yaml:?}: loaded differently: {loaded:?}"));
                }
            }
            (Err(error), false) => {
                let expected_type = vector["error"].as_str().unwrap();
                let message = vector["message"].as_str().unwrap();
                let (rust_type, compare_message) = match expected_type {
                    // C# crashes with a NullReferenceException; Rust fails the load cleanly.
                    "NullReferenceException" => ("InvalidDataException", false),
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
