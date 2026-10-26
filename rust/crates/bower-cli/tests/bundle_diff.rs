//! `bower policy diff` bundle comparison (C# `PolicyCommands.ComputeBundleDiffAsync` and
//! `PolicyBundleDiffTests`). `tests/fixtures/bundle-diff/expected-*.json` is the C# output
//! for the same fixtures at the same `--at`; this runtime must print the same bytes.

mod common;

use std::path::PathBuf;

use common::{Run, bower_in, repo_root};
use serde_json::Value;

const AT: &str = "2026-10-17T01:02:03Z";
const FIXTURES: [&str; 4] = [
    "root-login.json",
    "access-key.json",
    "page-view.json",
    "future.json",
];

fn fixtures() -> PathBuf {
    repo_root().join("rust/crates/bower-cli/tests/fixtures/bundle-diff")
}

fn pack(name: &str) -> String {
    repo_root()
        .join("rust/crates/bower-packs/tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn aws_policies() -> String {
    repo_root()
        .join("packs/aws-security/policies")
        .to_string_lossy()
        .into_owned()
}

/// Runs `bower policy diff ARGS... FIXTURES...` from the fixture directory.
fn diff(args: &[&str]) -> Run {
    let mut all = vec!["policy", "diff"];
    all.extend_from_slice(args);
    all.extend_from_slice(&FIXTURES);
    bower_in(&fixtures(), &all)
}

fn current_aws() -> Vec<String> {
    vec![
        "--candidate-pack".into(),
        pack("aws-security-1.1.0.bowerpack"),
        "--candidate-trusted-key".into(),
        pack("csharp-current-signing.pub.pem"),
    ]
}

fn detection_args() -> Vec<String> {
    let mut args = vec!["--baseline".into(), aws_policies()];
    args.extend(current_aws());
    args.extend(["--at".into(), AT.into()]);
    args
}

fn privacy_args() -> Vec<String> {
    let mut args = vec![
        "--baseline-pack".into(),
        pack("aws-security-1.1.0.bowerpack"),
        "--baseline-trusted-key".into(),
        pack("csharp-current-signing.pub.pem"),
    ];
    args.extend(current_aws());
    args.extend([
        "--candidate-privacy-profile".into(),
        "mask-aws-keys.privacy.yaml".into(),
        "--at".into(),
        AT.into(),
    ]);
    args
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// The same signed pack on both sides, each with its own privacy profile fixture.
fn field_args(baseline_profile: &str, candidate_profile: &str) -> Vec<String> {
    let mut args = vec![
        "--baseline-pack".into(),
        pack("aws-security-1.1.0.bowerpack"),
        "--baseline-trusted-key".into(),
        pack("csharp-current-signing.pub.pem"),
        "--baseline-privacy-profile".into(),
        format!("{baseline_profile}.privacy.yaml"),
    ];
    args.extend(current_aws());
    args.extend([
        "--candidate-privacy-profile".into(),
        format!("{candidate_profile}.privacy.yaml"),
        "--at".into(),
        AT.into(),
    ]);
    args
}

fn change<'a>(output: &'a Value, file: &str) -> &'a Value {
    output["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["file"] == file)
        .unwrap()
}

#[test]
fn another_field_rule_of_the_same_detector_is_reported() {
    let mut args = field_args("remove-username", "remove-username-and-ip");
    args.push("--fail-on-change".into());
    let run = diff(&refs(&args));
    assert_eq!(run.code, 3, "{}", run.stderr);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(output["changed"], 4);
    let root = change(&output, "root-login.json");
    // One action per detector hides the second field-rule finding; per-finding metadata does not.
    assert_eq!(
        root["baseline"]["privacyActions"],
        root["candidate"]["privacyActions"]
    );
    assert_eq!(
        root["changedFields"],
        serde_json::json!(["privacyFindings", "removedCount"])
    );
    assert_eq!(
        root["candidate"]["privacyFindings"],
        serde_json::json!([
            { "detector": "field-rule", "path": "$.actor.username", "action": "Removed" },
            { "detector": "field-rule", "path": "$.source.ipAddress", "action": "Removed" }
        ])
    );
    assert_eq!(root["baseline"]["removedCount"], 1);
    assert_eq!(root["candidate"]["removedCount"], 2);
    for value in ["203.0.113.10", "198.51.100.7", "visitor", "Admin"] {
        assert!(!run.stdout.contains(value), "{value}");
    }
}

#[test]
fn changed_action_on_a_later_finding_of_the_same_detector_is_reported() {
    let run = diff(&refs(&field_args(
        "remove-username-and-ip",
        "remove-username-mask-ip",
    )));
    assert_eq!(run.code, 0, "{}", run.stderr);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    let root = change(&output, "root-login.json");
    assert_eq!(
        root["baseline"]["privacyActions"],
        root["candidate"]["privacyActions"]
    );
    assert_eq!(
        root["changedFields"],
        serde_json::json!(["privacyFindings", "removedCount", "maskedCount"])
    );
    assert!(
        root["candidate"]["privacyFindings"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(
                { "detector": "field-rule", "path": "$.source.ipAddress", "action": "Masked" }
            ))
    );
}

#[test]
fn explicit_directory_must_exist_even_with_packs() {
    let missing = fixtures().join("no-such-policy-directory");
    let missing = missing.to_str().unwrap();
    let mut args = vec!["--candidate".to_owned(), missing.to_owned()];
    args.extend(current_aws());
    args.extend(["--baseline".into(), aws_policies()]);
    let run = diff(&refs(&args));
    assert_eq!(
        (run.code, run.stderr.as_str(), run.stdout.as_str()),
        (
            1,
            format!("Policy directory does not exist: {missing}\n").as_str(),
            ""
        )
    );
}

#[test]
fn at_refuses_anything_but_iso_8601_with_an_offset() {
    let policies = aws_policies();
    for value in [
        "01:02",
        "2026-10-17",
        "2026-10-17T01:02:03",
        "2026-10-17T01:02:03.123456789Z",
        "10/17/2026",
        "Oct 17 2026",
        "2026-10-17 01:02:03Z",
        "2026-10-17T01:02:60Z",
        "2026-10-17T01:02:03+15:00",
        "2026-10-17t01:02:03z",
        " 2026-10-17T01:02:03Z",
        "2026-02-30T01:02:03Z",
    ] {
        let run = diff(&[
            "--baseline",
            &policies,
            "--candidate",
            &policies,
            "--at",
            value,
        ]);
        assert_eq!(
            (run.code, run.stderr.as_str(), run.stdout.as_str()),
            (
                1,
                "--at must be an ISO 8601 timestamp with Z or an offset: YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM).\n",
                ""
            ),
            "{value}"
        );
    }
    let run = diff(&[
        "--baseline",
        &policies,
        "--candidate",
        &policies,
        "--at",
        "2026-10-17T11:02:03.1234567+10:00",
    ]);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(output["evaluatedAt"], "2026-10-17T01:02:03.1234567+00:00");
}

#[test]
fn bundle_diff_matches_pinned_csharp_output() {
    for (scenario, args) in [
        ("detections", detection_args()),
        ("privacy", privacy_args()),
        (
            "fields",
            field_args("remove-username", "remove-username-and-ip"),
        ),
    ] {
        let run = diff(&refs(&args));
        assert_eq!(run.code, 0, "{scenario}: {}", run.stderr);
        let expected =
            std::fs::read_to_string(fixtures().join(format!("expected-{scenario}.json"))).unwrap();
        assert_eq!(run.stdout, expected.replace("\r\n", "\n"), "{scenario}");
    }
}

#[test]
fn privacy_only_change_is_reported_while_acceptance_is_unchanged() {
    let mut args = privacy_args();
    args.push("--fail-on-change".into());
    let run = diff(&refs(&args));
    assert_eq!(run.code, 3, "{}", run.stderr);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(output["changed"], 1);
    let change = &output["changes"][0];
    assert_eq!(change["file"], "access-key.json");
    assert_eq!(
        change["changedFields"],
        serde_json::json!([
            "privacyActions",
            "privacyFindings",
            "removedCount",
            "maskedCount"
        ])
    );
    assert_eq!(change["baseline"]["accepted"], true);
    assert_eq!(change["candidate"]["accepted"], true);
    assert_eq!(
        change["baseline"]["decision"],
        change["candidate"]["decision"]
    );
    assert_eq!(
        change["candidate"]["privacyActions"],
        serde_json::json!([{ "detector": "secret.aws", "action": "Masked" }])
    );
    assert_eq!(
        output["candidateBundle"]["privacyProfile"]["id"],
        "bundle-diff-mask-aws-keys"
    );
    assert!(!run.stdout.contains("AKIA"));
}

#[test]
fn detection_changes_use_stable_rule_ids_without_matched_values() {
    let run = diff(&refs(&detection_args()));
    assert_eq!(run.code, 0, "{}", run.stderr);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    let root = output["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["file"] == "root-login.json")
        .unwrap();
    assert_eq!(root["changedFields"], serde_json::json!(["detections"]));
    let detections = root["candidate"]["detections"].as_array().unwrap();
    let ids: Vec<&str> = detections
        .iter()
        .map(|detection| detection["ruleId"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "bower-pack-aws-console-login-failure-001",
            "bower-pack-aws-root-activity-001"
        ]
    );
    for detection in detections {
        assert!(!detection["ruleVersion"].as_str().unwrap().is_empty());
        let hash = detection["ruleHash"].as_str().unwrap();
        assert!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{hash}"
        );
    }
    assert_eq!(output["baselineBundle"]["detectionRules"], 0);
    assert_eq!(output["candidateBundle"]["detectionRules"], 4);
    for value in [
        "AKIAIOSFODNN7EXAMPLE",
        "arn:aws",
        "203.0.113.10",
        "123456789012",
        "Failed authentication",
    ] {
        assert!(!run.stdout.contains(value), "{value}");
    }
}

#[test]
fn pack_only_sides_load_without_a_policy_directory() {
    let mut args = vec![
        "--baseline-pack".to_owned(),
        pack("aws-security-1.0.0.bowerpack"),
        "--baseline-trusted-key".into(),
        pack("csharp-signing.pub.pem"),
    ];
    args.extend(current_aws());
    args.extend(["--at".into(), AT.into(), "--fail-on-change".into()]);
    let run = diff(&refs(&args));
    assert_eq!(run.code, 0, "{}", run.stderr);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_ne!(output["baselineBundleHash"], output["candidateBundleHash"]);
    assert_eq!(
        output["baselineBundle"]["bundleHash"],
        output["baselineBundleHash"]
    );
    assert_eq!(output["baselineBundle"]["packs"][0]["version"], "1.0.0");
    assert_eq!(output["candidateBundle"]["packs"][0]["version"], "1.1.0");
    assert_eq!(output["baselineBundle"]["policyCount"], 2);
    assert_eq!(output["candidateBundle"]["policyCount"], 3);
    assert_eq!(output["events"], 4);
    assert_eq!(output["evaluatedAt"], "2026-10-17T01:02:03+00:00");
    let limits = output["notExercisedOffline"].as_array().unwrap();
    assert!(limits.contains(&Value::from("suppression-windows")));
    assert!(limits.contains(&Value::from("source-silence")));
}

#[test]
fn untrusted_or_unsigned_packs_fail_before_any_sample_is_evaluated() {
    let directory = tempfile::tempdir().unwrap();
    let unsigned = directory.path().join("unsigned.bowerpack");
    std::fs::write(&unsigned, b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
    let unsigned = unsigned.to_str().unwrap().to_owned();
    let policies = aws_policies();
    let candidate = pack("aws-security-1.1.0.bowerpack");
    let historical_key = pack("csharp-signing.pub.pem");
    let current_key = pack("csharp-current-signing.pub.pem");
    for args in [
        // Signed by another key than the one trusted.
        vec![
            "--baseline",
            &policies,
            "--candidate-pack",
            &candidate,
            "--candidate-trusted-key",
            &historical_key,
            "--at",
            AT,
        ],
        // No trusted key at all.
        vec!["--baseline", &policies, "--candidate-pack", &candidate],
        // Not a signed pack.
        vec![
            "--baseline-pack",
            &unsigned,
            "--baseline-trusted-key",
            &current_key,
            "--candidate-pack",
            &candidate,
            "--candidate-trusted-key",
            &current_key,
        ],
    ] {
        let run = diff(&args);
        assert_eq!(run.code, 1, "{args:?}");
        assert_eq!(run.stdout, "", "{args:?}");
        assert!(!run.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn bundle_options_are_validated_and_directory_mode_is_unchanged() {
    let policies = aws_policies();
    let missing = diff(&[
        "--baseline",
        &policies,
        "--candidate-privacy-profile",
        "mask-aws-keys.privacy.yaml",
    ]);
    assert_eq!(
        (missing.code, missing.stderr.as_str()),
        (1, "--candidate or --candidate-pack is required.\n")
    );
    let bad_time = diff(&[
        "--baseline",
        &policies,
        "--candidate",
        &policies,
        "--at",
        "soon",
    ]);
    assert_eq!(
        (bad_time.code, bad_time.stderr.as_str()),
        (
            1,
            "--at must be an ISO 8601 timestamp with Z or an offset: YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM).\n"
        )
    );
    // Directory mode: same document shape as before, no bundle fields.
    let legacy = diff(&["--baseline", &policies, "--candidate", &policies]);
    assert_eq!(legacy.code, 0, "{}", legacy.stderr);
    let output: Value = serde_json::from_str(&legacy.stdout).unwrap();
    let keys: Vec<&String> = output.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "baselineBundleHash",
            "candidateBundleHash",
            "events",
            "changed",
            "changes"
        ]
    );
}
