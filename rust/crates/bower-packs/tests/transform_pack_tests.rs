//! Port of `TransformPackTests` (C#): signed pack transforms run before mapping,
//! redaction and policy, cannot set the security decision or launder sensitive fields,
//! and quarantine with a metadata-only code.

use std::path::{Path, PathBuf};

use bower_contracts::time::parse;
use bower_packs::runtime::{MappingError, map_raw};
use bower_packs::{build, load, run_samples, test_privacy_policy};

const MESSAGE: &str =
    "Failed password for invalid user deploy-admin from 203.0.113.5 port 52144 ssh2";

/// The envelope C# `PackRuntime.Parse` maps from [`raw`] (`TransformPackTests`).
const CSHARP_ENVELOPE: &str = include_str!("fixtures/csharp-vectors/transform-journald-ssh.json");

fn source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs/linux-journald-ssh")
}

fn raw(message: &str) -> String {
    format!(
        r#"{{"__CURSOR":"s=7a1c;i=1f01;b=55aa;m=91;t=63e2;x=c3","__REALTIME_TIMESTAMP":"1792976523000000","SYSLOG_IDENTIFIER":"sshd","_HOSTNAME":"bastion-1","MESSAGE":"{message}"}}"#
    )
}

fn build_and_load(source: &Path) -> Result<bower_packs::LoadedPack, bower_packs::PackError> {
    let output = tempfile::tempdir().unwrap();
    let keys = bower_integrity::generate_key_pair();
    let archive = build(source, &keys.private_key_pem, output.path(), None)?;
    load(&archive, &[keys.public_key_pem.as_str()])
}

fn copy_pack(destination: &Path) {
    fn copy(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    copy(&source(), destination);
}

fn add_transforms(source: &Path, statements: &[&str]) {
    let path = source.join("parsers/sshd-journald.json");
    let mut parser: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let transforms = parser["runtime"]["transforms"].as_array_mut().unwrap();
    transforms.extend(
        statements
            .iter()
            .map(|statement| serde_json::json!(statement)),
    );
    std::fs::write(&path, serde_json::to_string(&parser).unwrap()).unwrap();
}

#[test]
fn journald_pack_signs_and_every_sample_passes_including_transform_quarantine() {
    let pack = build_and_load(&source()).unwrap();
    let privacy = test_privacy_policy(pack.privacy_profile_yaml.as_deref()).unwrap();
    let results = run_samples(&pack, privacy, None).unwrap();
    for result in &results {
        assert!(
            result.passed,
            "{}: {}",
            result.name,
            result.problems.join(" ")
        );
    }
    assert!(
        results
            .iter()
            .any(|result| result.actual_decision == "quarantine")
    );
    assert!(
        results
            .iter()
            .any(|result| result.actual_decision == "redactandaccept")
    );
}

#[test]
fn transform_runs_before_mapping_and_matches_the_csharp_envelope() {
    let pack = build_and_load(&source()).unwrap();
    let at = parse("2026-10-26T01:02:03+00:00").unwrap();
    let envelope = map_raw(&pack.parsers[0], &raw(MESSAGE), &at).unwrap();
    let text = bower_contracts::json::to_string(&envelope).unwrap();
    assert_eq!(text, CSHARP_ENVELOPE.trim_end());
    assert!(envelope.security.is_none());
    assert!(!text.contains("bastion-1"));
    assert!(!text.contains("Failed password"));
    for _ in 0..3 {
        let again = map_raw(&pack.parsers[0], &raw(MESSAGE), &at).unwrap();
        assert_eq!(bower_contracts::json::to_string(&again).unwrap(), text);
    }
}

#[test]
fn transform_failure_is_a_metadata_only_quarantine_code() {
    let directory = tempfile::tempdir().unwrap();
    copy_pack(directory.path());
    add_transforms(
        directory.path(),
        &[".slow = regex_match(.MESSAGE, '(?:a?){100}a{100}$')"],
    );
    let pack = build_and_load(directory.path()).unwrap();
    let at = parse("2026-10-26T01:02:03+00:00").unwrap();
    let pathological = format!("{}b deploy-admin", "a".repeat(5000));
    assert_eq!(
        map_raw(&pack.parsers[0], &raw(&pathological), &at).unwrap_err(),
        MappingError::Transform("transform-budget-exceeded")
    );
    // Duplicate keys are rejected as malformed before the transform runs.
    let duplicate = raw(MESSAGE).replacen("{", r#"{"_HOSTNAME":"x","#, 1);
    assert_eq!(
        map_raw(&pack.parsers[0], &duplicate, &at).unwrap_err(),
        MappingError::Invalid
    );
}

#[test]
fn transform_cannot_set_the_security_decision_or_launder_sensitive_fields() {
    let attacks: [(&[&str], &str); 9] = [
        (
            &[r#"."security.decision" = "accept""#],
            "transform-invalid-target",
        ),
        (&[r#".security = "accept""#], "transform-invalid-target"),
        (
            &[r#".bowerDetections = "forged""#],
            "transform-invalid-target",
        ),
        (
            &[r#".result = "failure""#, "del(.MESSAGE)"],
            "transform-sensitive-field",
        ),
        (&["rename(.MESSAGE, .note)"], "transform-sensitive-field"),
        (&[".__CURSOR = .MESSAGE"], "transform-sensitive-flow"),
        (
            &[r#"if contains(.MESSAGE, "x") { .SYSLOG_IDENTIFIER = "sshd" }"#],
            "transform-sensitive-flow",
        ),
        (&[".password = .MESSAGE"], "transform-invalid-target"),
        (&[".x = .token"], "transform-prohibited-field"),
    ];
    for (statements, code) in attacks {
        let directory = tempfile::tempdir().unwrap();
        copy_pack(directory.path());
        add_transforms(directory.path(), statements);
        let failure = build_and_load(directory.path()).unwrap_err().to_string();
        assert!(failure.contains(code), "{statements:?}: {failure}");
    }
}
