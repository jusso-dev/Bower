//! Port of `PackFieldAssertionTests` (C#): `expectFields` post-redaction field
//! assertions, parser-scoped runs and manifest parser order. Messages match C#.

use std::path::{Path, PathBuf};

use bower_packs::{
    LoadedPack, PackError, PackSampleResult, build, load, run_parser_samples, run_samples,
    test_privacy_policy,
};
use serde_json::{Value, json};

fn packs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

fn build_and_load(source: &Path) -> Result<LoadedPack, PackError> {
    let output = tempfile::tempdir().unwrap();
    let keys = bower_integrity::generate_key_pair();
    let archive = build(source, &keys.private_key_pem, output.path(), None)?;
    load(&archive, &[keys.public_key_pem.as_str()])
}

fn pack(name: &str) -> LoadedPack {
    build_and_load(&packs().join(name)).unwrap()
}

fn copy_pack(name: &str, destination: &Path) {
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
    copy(&packs().join(name), destination);
}

fn run(pack: &LoadedPack, lines: Vec<String>) -> Result<Vec<PackSampleResult>, PackError> {
    let variants = LoadedPack {
        sample_lines: lines,
        ..pack.clone()
    };
    run_samples(
        &variants,
        test_privacy_policy(pack.privacy_profile_yaml.as_deref()).unwrap(),
        None,
    )
}

/// A shipped sample line with `expectFields` replaced.
fn with_fields(pack: &LoadedPack, line: usize, fields: Value) -> String {
    let mut sample: Value = serde_json::from_str(&pack.sample_lines[line]).unwrap();
    sample["expectFields"] = fields;
    serde_json::to_string(&sample).unwrap()
}

#[test]
fn shipped_journald_expectations_pass_after_redaction() {
    let pack = pack("linux-journald-ssh");
    assert!(
        pack.sample_lines
            .iter()
            .any(|line| line.contains("\"expectFields\""))
    );
    let results = run(&pack, pack.sample_lines.clone()).unwrap();
    for result in results {
        assert!(
            result.passed,
            "{}: {}",
            result.name,
            result.problems.join(" ")
        );
    }
}

#[test]
fn failing_expectations_report_path_level_diffs_of_redacted_values() {
    let pack = pack("linux-journald-ssh");
    let line = with_fields(
        &pack,
        0,
        json!({
            "eventOutcomeReason": "PublicKeyRejected",
            "request.correlationId": "present",
            "source.ipAddress": 5,
            "application": "linux-sshd",
            "application.name": true,
            "eventId": "absent",
            "actor.username": "present",
            "labels.missing": "absent"
        }),
    );
    let results = run(&pack, vec![line]).unwrap();
    let [result] = results.as_slice() else {
        panic!("one result")
    };
    assert!(!result.passed);
    assert_eq!(result.actual_decision, "redactandaccept");
    assert_eq!(
        result.problems,
        [
            "Field 'eventOutcomeReason': expected \"PublicKeyRejected\", got \"InvalidCredentials\".",
            "Field 'request.correlationId': expected present, but it is absent.",
            "Field 'source.ipAddress': type mismatch, expected number 5, got string \"203.0.113.5\".",
            "Field 'application': type mismatch, expected string \"linux-sshd\", got object.",
            "Field 'application.name': type mismatch, expected boolean true, got string \"linux-sshd\".",
            "Field 'eventId': expected absent, got string \"s=7a1c;i=1f01;b=55aa;m=91;t=63e2;x=c3\"."
        ]
    );
}

#[test]
fn missing_field_with_a_value_is_reported_as_absent() {
    let pack = pack("linux-ssh-gateway");
    let line = with_fields(
        &pack,
        1,
        json!({"eventOutcomeReason": "AccountLocked", "source.ipAddress": "198.51.100.7"}),
    );
    let results = run(&pack, vec![line]).unwrap();
    assert_eq!(
        results[0].problems,
        ["Field 'eventOutcomeReason': expected \"AccountLocked\", but it is absent."]
    );
}

#[test]
fn raw_sensitive_expectations_fail_without_echoing_the_value() {
    let pack = pack("linux-journald-ssh");
    let line = with_fields(
        &pack,
        0,
        json!({
            "actor.username": "deploy-admin",
            "_HOSTNAME": "bastion-1",
            "eventOutcomeReason": "Failed password for invalid user deploy-admin"
        }),
    );
    let results = run(&pack, vec![line]).unwrap();
    assert!(!results[0].passed);
    assert_eq!(results[0].problems.len(), 3);
    for problem in &results[0].problems {
        assert!(problem.ends_with(
            "the expected value does not survive redaction; expect only post-redaction values."
        ));
        assert!(!problem.contains("deploy-admin") && !problem.contains("bastion-1"));
    }
}

#[test]
fn build_refuses_to_sign_when_a_field_assertion_fails() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    copy_pack("linux-journald-ssh", &source);
    let samples = source.join("samples/journald.jsonl");
    let text = std::fs::read_to_string(&samples).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut first: Value = serde_json::from_str(&lines[0]).unwrap();
    first["expectFields"] = json!({"actor.username": "deploy-admin", "eventOutcomeReason": "Nope"});
    lines[0] = serde_json::to_string(&first).unwrap();
    std::fs::write(&samples, lines.join("\n")).unwrap();
    let output = directory.path().join("out");
    let keys = bower_integrity::generate_key_pair();

    let error = build(&source, &keys.private_key_pem, &output, None)
        .unwrap_err()
        .to_string();

    assert!(
        error
            .contains("Field 'eventOutcomeReason': expected \"Nope\", got \"InvalidCredentials\".")
    );
    assert!(
        error.contains("Field 'actor.username': the expected value does not survive redaction")
    );
    assert!(!error.contains("deploy-admin"));
    assert!(!output.exists());
}

#[test]
fn field_assertions_need_a_redacted_event() {
    let pack = pack("linux-journald-ssh");
    let fields = json!({"eventType": "authentication_failure"});
    let results = run(
        &pack,
        vec![
            with_fields(&pack, 2, fields.clone()),
            with_fields(&pack, 4, fields),
        ],
    )
    .unwrap();
    assert_eq!(
        results[0].problems,
        ["Field assertions need a redacted event; got reject."]
    );
    assert_eq!(
        results[1].problems,
        ["Field assertions need a redacted event; got quarantine."]
    );
}

#[test]
fn invalid_samples_fail_validation() {
    let pack = pack("linux-ssh-gateway");
    let cases = [
        (
            r#""expectFields":[]"#,
            "Sample 's' expectFields must be an object.",
        ),
        (
            r#""expectFields":{}"#,
            "Sample 's' expectFields must have 1 to 64 paths.",
        ),
        (
            r#""expectFields":{"a..b":"present"}"#,
            "Sample 's' expectFields has an invalid path.",
        ),
        (
            r#""expectFields":{"a b":"present"}"#,
            "Sample 's' expectFields has an invalid path.",
        ),
        (
            r#""expectFields":{"a\n":"present"}"#,
            "Sample 's' expectFields has an invalid path.",
        ),
        (
            r#""expectFields":{"a":"present","a":"absent"}"#,
            "Sample 's' expectFields has a duplicate path.",
        ),
        (
            r#""expectFields":{"a":null}"#,
            "Sample 's' expectFields 'a' must be a string, finite number or boolean.",
        ),
        (
            r#""expectFields":{"a":{"b":1}}"#,
            "Sample 's' expectFields 'a' must be a string, finite number or boolean.",
        ),
        (
            r#""expectFields":{"a":1e400}"#,
            "Sample 's' expectFields 'a' must be a string, finite number or boolean.",
        ),
        (
            r#""expectField":{"a":"present"}"#,
            "Sample 1 member 'expectField' is unknown or duplicated.",
        ),
        (
            r#""name":"t""#,
            "Sample 1 member 'name' is unknown or duplicated.",
        ),
    ];
    for (member, message) in cases {
        let line = format!(r#"{{"name":"s","expect":"reject",{member},"event":{{}}}}"#);
        let error = run(&pack, vec![line]).unwrap_err();
        assert_eq!(error.to_string(), message, "{member}");
    }
}

#[test]
fn parser_filter_runs_one_parsers_raw_samples_by_name_or_path() {
    let pack = pack("linux-ssh-gateway");
    let privacy = || test_privacy_policy(pack.privacy_profile_yaml.as_deref()).unwrap();
    assert_eq!(pack.parser_paths, ["parsers/sshd-json.json"]);
    let names = |parser| {
        run_parser_samples(&pack, privacy(), None, Some(parser))
            .unwrap()
            .into_iter()
            .map(|result| {
                assert!(result.passed);
                result.name
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names("sshd-json"),
        [
            "raw failure activates parser and local detection",
            "raw success remains denied by source filter"
        ]
    );
    assert_eq!(names("parsers/sshd-json.json"), names("sshd-json"));
    assert_eq!(
        run_parser_samples(&pack, privacy(), None, Some("nope"))
            .unwrap_err()
            .to_string(),
        "Pack has no parser 'nope'."
    );

    // A raw sample may name its parser instead of using an index.
    let mut named: Value = serde_json::from_str(&pack.sample_lines[5]).unwrap();
    named["parser"] = json!("sshd-json");
    assert!(run(&pack, vec![named.to_string()]).unwrap()[0].passed);
    named["parser"] = json!("sshd");
    assert!(run(&pack, vec![named.to_string()]).is_err());
}

#[test]
fn build_runs_samples_in_manifest_parser_order_so_indexes_match_load() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    copy_pack("linux-ssh-gateway", &source);
    // A second parser that sorts first: pack.yaml lists it last, the manifest first.
    std::fs::copy(
        packs().join("linux-journald-ssh/parsers/sshd-journald.json"),
        source.join("parsers/a-journald.json"),
    )
    .unwrap();
    let yaml = source.join("pack.yaml");
    let text = std::fs::read_to_string(&yaml).unwrap().replace(
        "  - parsers/sshd-json.json\n",
        "  - parsers/sshd-json.json\n  - parsers/a-journald.json\n",
    );
    std::fs::write(&yaml, text).unwrap();
    let samples = source.join("samples/ssh.jsonl");
    let text = std::fs::read_to_string(&samples)
        .unwrap()
        .replace("\"parser\":0", "\"parser\":1");
    std::fs::write(&samples, text).unwrap();

    let pack = build_and_load(&source).unwrap();

    assert_eq!(
        pack.parser_paths,
        ["parsers/a-journald.json", "parsers/sshd-json.json"]
    );
    assert!(
        run(&pack, pack.sample_lines.clone())
            .unwrap()
            .iter()
            .all(|result| result.passed)
    );
}
