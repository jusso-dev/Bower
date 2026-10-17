//! Ports of the pack half of `PackAndEvidenceTests` and of `CloudPackTests`, plus
//! cross-implementation proof: C#-signed packs verify here, Rust-built manifests are
//! byte-identical to C# ones, and pack content matches the repo `packs/` sources.
//!
//! `tests/fixtures/*.bowerpack` were built and signed by C# `PackArchive.Build` from
//! the repo packs with the clock fixed at 2026-10-17T01:02:03.4567Z;
//! `csharp-signing.pub.pem` is the signer's public key. `tests/fixtures/csharp-vectors`
//! holds C# sample decisions, a C# `PackDiff` and C#-mapped AWS/GCP envelopes.

use std::path::{Path, PathBuf};

use bower_contracts::time::{Clock, Timestamp, parse};
use bower_contracts::{DecisionAction, SecurityEventEnvelope, TelemetryPolicyEvaluator};
use bower_packs::{
    LoadedPack, PackError, build, compare, load, load_bytes, pack_hash, run_samples,
    test_privacy_policy, zip,
};
use bower_policy::DeterministicPolicyEvaluator;
use bower_redaction::PrivacyEngine;

const PACK_IDS: [&str; 3] = ["linux-ssh-gateway", "aws-security", "gcp-security"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    manifest_dir().join("tests/fixtures").join(name)
}

fn repo_pack(id: &str) -> PathBuf {
    manifest_dir().join("../../../packs").join(id)
}

fn csharp_public_key() -> String {
    std::fs::read_to_string(fixture("csharp-signing.pub.pem")).unwrap()
}

fn vector(name: &str) -> String {
    std::fs::read_to_string(fixture("csharp-vectors").join(name)).unwrap()
}

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn utc_now(&self) -> Timestamp {
        self.0
    }
}

fn csharp_clock() -> FixedClock {
    FixedClock(parse("2026-10-17T01:02:03.4567+00:00").unwrap())
}

struct Built {
    _output: tempfile::TempDir,
    archive: PathBuf,
    public_key: String,
    key_id: String,
}

fn build_pack(source: &Path, clock: Option<&dyn Clock>) -> Built {
    let output = tempfile::tempdir().unwrap();
    let keys = bower_integrity::generate_key_pair();
    let archive = build(source, &keys.private_key_pem, output.path(), clock).unwrap();
    Built {
        _output: output,
        archive,
        public_key: keys.public_key_pem.clone(),
        key_id: keys.key_id.clone(),
    }
}

fn copy_directory(source: &Path, destination: &Path) {
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_directory(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn verification_error(result: Result<LoadedPack, PackError>) -> String {
    match result {
        Err(PackError::Verification(message)) => message,
        other => panic!("expected a verification failure, got {other:?}"),
    }
}

// ---------------------------------------------------------------- C# packs

#[test]
fn csharp_signed_packs_verify_and_carry_the_repo_sources() {
    let public_key = csharp_public_key();
    let key_id = bower_integrity::key_id_from_public_key_pem(&public_key).unwrap();
    let dcr =
        bower_dcr::generator::generate_json(&bower_dcr::DcrTemplateOptions::default()).unwrap();
    for id in PACK_IDS {
        let archive = fixture(&format!("{id}-1.0.0.bowerpack"));
        let pack = load(&archive, &[public_key.as_str()]).unwrap();
        let manifest = pack.manifest.as_ref().unwrap();
        assert_eq!(manifest.id, id);
        assert_eq!(pack.signed_by_key_id, key_id);
        assert_eq!(manifest.pack_hash, pack_hash(&manifest.files));

        // The signed content is exactly the repo pack sources, and the embedded DCR
        // template is exactly what the Rust generator writes.
        let entries = zip::read_all(&std::fs::read(&archive).unwrap(), 1_048_576).unwrap();
        for file in &manifest.files {
            let content = &entries
                .iter()
                .find(|(name, _)| *name == format!("content/{}", file.path))
                .unwrap()
                .1;
            if file.role == "dcr" {
                assert_eq!(
                    String::from_utf8(content.clone()).unwrap(),
                    dcr,
                    "{id}: DCR template differs from C#"
                );
            } else {
                assert_eq!(
                    content,
                    &std::fs::read(repo_pack(id).join(&file.path)).unwrap(),
                    "{id}/{}",
                    file.path
                );
            }
        }

        // Its samples pass under the Rust redaction and policy engines.
        let privacy = test_privacy_policy(pack.privacy_profile_yaml.as_deref()).unwrap();
        for result in run_samples(&pack, privacy, None).unwrap() {
            assert!(
                result.passed,
                "{id} {}: {}",
                result.name,
                result.problems.join(" ")
            );
        }
    }
}

#[test]
fn rust_built_manifests_are_byte_identical_to_csharp() {
    let public_key = csharp_public_key();
    let clock = csharp_clock();
    for id in PACK_IDS {
        let csharp = load(
            &fixture(&format!("{id}-1.0.0.bowerpack")),
            &[public_key.as_str()],
        )
        .unwrap();
        let built = build_pack(&repo_pack(id), Some(&clock));
        let rust = load(&built.archive, &[built.public_key.as_str()]).unwrap();
        let (csharp_manifest, rust_manifest) = (csharp.manifest.unwrap(), rust.manifest.unwrap());
        assert_eq!(rust_manifest, csharp_manifest, "{id}");
        assert_eq!(
            rust_manifest.canonical_bytes(),
            csharp_manifest.canonical_bytes(),
            "{id}"
        );

        // The stored manifest bytes are identical too.
        let stored = |path: &Path| {
            zip::read_all(&std::fs::read(path).unwrap(), 1_048_576)
                .unwrap()
                .into_iter()
                .find(|(name, _)| name == "manifest.json")
                .unwrap()
                .1
        };
        assert_eq!(
            stored(&built.archive),
            stored(&fixture(&format!("{id}-1.0.0.bowerpack"))),
            "{id}"
        );
    }
}

#[test]
fn csharp_sample_decisions_match() {
    let clock = csharp_clock();
    let expected: Vec<String> = vector("report.txt")
        .lines()
        .filter(|line| line.starts_with("sample|"))
        .map(|line| {
            // Drop C#'s "True"/"False" casing difference.
            let (head, passed) = line.rsplit_once('|').unwrap();
            format!("{head}|{}", passed.to_lowercase())
        })
        .collect();
    assert!(!expected.is_empty());
    let mut actual = Vec::new();
    for id in PACK_IDS {
        let built = build_pack(&repo_pack(id), Some(&clock));
        let pack = load(&built.archive, &[built.public_key.as_str()]).unwrap();
        let privacy = test_privacy_policy(pack.privacy_profile_yaml.as_deref()).unwrap();
        for result in run_samples(&pack, privacy, Some(&clock)).unwrap() {
            actual.push(format!(
                "sample|{id}|{}|{}|{}|{}",
                result.name, result.expected_decision, result.actual_decision, result.passed
            ));
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn csharp_mapped_cloud_events_pass_pack_policies_and_fire_pack_detections() {
    let aws = load(
        &fixture("aws-security-1.0.0.bowerpack"),
        &[csharp_public_key()],
    )
    .unwrap();
    let gcp = load(
        &fixture("gcp-security-1.0.0.bowerpack"),
        &[csharp_public_key()],
    )
    .unwrap();
    let evaluator =
        DeterministicPolicyEvaluator::new(aws.policies.iter().chain(&gcp.policies).cloned());
    let engine = PrivacyEngine::new(test_privacy_policy(None).unwrap()).unwrap();
    let envelope = |name: &str| -> SecurityEventEnvelope {
        bower_contracts::json::from_str(&vector(&format!("envelope-{name}.json"))).unwrap()
    };

    // `MappedCloudEvents_PassCollectorValidationAndPackPolicies` (policy level).
    for name in [
        "aws-guardduty",
        "aws-root",
        "aws-stop",
        "aws-securityhub",
        "gcp-audit",
        "gcp-scc",
    ] {
        let json = vector(&format!("envelope-{name}.json"));
        let redacted = engine.redact_json(&json);
        assert!(redacted.succeeded, "{name}");
        let event: SecurityEventEnvelope =
            bower_contracts::json::from_str(redacted.redacted_json.as_deref().unwrap()).unwrap();
        let decision = evaluator.evaluate(&event);
        assert!(
            matches!(
                decision.action,
                DecisionAction::Accept | DecisionAction::RedactAndAccept
            ),
            "{name}: {:?} {:?}",
            decision.action,
            decision.reasons
        );
    }

    // `PackDetections_FireOnMappedEvents`.
    let rules: Vec<_> = aws
        .detections
        .iter()
        .chain(&gcp.detections)
        .cloned()
        .collect();
    assert_eq!((aws.detections.len(), gcp.detections.len()), (4, 4));
    let mut detection = bower_detection::DetectionEngine::new(rules, Vec::<String>::new());
    let now = parse("2026-07-26T02:14:19+00:00").unwrap();
    for (name, expected) in [
        (
            "aws-root",
            vec![
                "bower-pack-aws-console-login-failure-001",
                "bower-pack-aws-root-activity-001",
            ],
        ),
        ("aws-stop", vec!["bower-pack-aws-logging-tampering-001"]),
        ("aws-guardduty", vec![]),
        ("gcp-audit", vec!["bower-pack-gcp-sa-key-created-001"]),
        ("gcp-denied", vec!["bower-pack-gcp-permission-denied-001"]),
    ] {
        let mut fired: Vec<String> = detection
            .evaluate(&envelope(name), Some(now))
            .alerts
            .into_iter()
            .map(|alert| alert.rule_id)
            .collect();
        fired.sort();
        assert_eq!(fired, expected, "{name}");
    }
}

/// `CloudIdentityProfile_PseudonymisesPrincipals`: the `deploy/privacy/cloud-identities.yaml`
/// profile HMACs cloud principals. `cloud-identities-gcp-audit.json` is C#
/// `PrivacyEngine.RedactJson` output for the same envelope, key `[0; 32]`, key id `k1`.
#[test]
fn cloud_identity_profile_pseudonymises_principals_like_csharp() {
    let yaml = std::fs::read_to_string(
        manifest_dir().join("../../../deploy/privacy/cloud-identities.yaml"),
    )
    .unwrap();
    let profile =
        bower_redaction::load_privacy_profile(&yaml, Some(&[0u8; 32]), Some("k1")).unwrap();
    let engine = PrivacyEngine::new(profile.policy).unwrap();

    let result = engine.redact_json(&vector("envelope-gcp-audit.json"));
    let redacted = result.redacted_json.as_deref().unwrap();

    assert!(result.succeeded);
    assert!(!redacted.contains("alice@example.com"));
    assert!(redacted.contains("hmac-sha256:k1:"));
    assert_eq!(redacted, vector("cloud-identities-gcp-audit.json"));
}

// ---------------------------------------------------------------- PackAndEvidenceTests

#[test]
fn pack_builds_signs_verifies_and_passes_its_samples() {
    for (id, policies, detections, privacy) in [
        ("linux-ssh-gateway", 1, 1, true),
        ("aws-security", 2, 4, false),
        ("gcp-security", 2, 4, false),
    ] {
        let built = build_pack(&repo_pack(id), None);
        let pack = load(&built.archive, &[built.public_key.as_str()]).unwrap();
        let privacy_policy = test_privacy_policy(pack.privacy_profile_yaml.as_deref()).unwrap();
        let results = run_samples(&pack, privacy_policy, None).unwrap();

        assert_eq!(pack.signed_by_key_id, built.key_id);
        assert_eq!(pack.manifest.as_ref().unwrap().id, id);
        assert_eq!(pack.policies.len(), policies, "{id}");
        assert_eq!(pack.detections.len(), detections, "{id}");
        assert_eq!(pack.privacy_profile_yaml.is_some(), privacy, "{id}");
        assert!(pack.dcr_template_json.is_some());
        assert!(!results.is_empty());
        for result in results {
            assert!(
                result.passed,
                "{id} {}: {}",
                result.name,
                result.problems.join(" ")
            );
        }
        assert_eq!(
            built.archive.file_name().unwrap().to_str().unwrap(),
            format!("{id}-1.0.0.bowerpack")
        );
    }
}

#[test]
fn pack_rejects_untrusted_keys_and_missing_trust() {
    let built = build_pack(&repo_pack("linux-ssh-gateway"), None);
    let other = bower_integrity::generate_key_pair();
    let none: [&str; 0] = [];

    assert_eq!(
        verification_error(load(&built.archive, &[other.public_key_pem.as_str()])),
        "Pack signature is invalid or not from a trusted key."
    );
    assert_eq!(
        verification_error(load(&built.archive, &none)),
        "No trusted public keys configured; refusing to load an unverified pack."
    );
    // The C# fixtures are not trusted under a Rust key either.
    verification_error(load(
        &fixture("aws-security-1.0.0.bowerpack"),
        &[built.public_key.as_str()],
    ));
    // Missing archive.
    verification_error(load(
        Path::new("/nonexistent/pack.bowerpack"),
        &[built.public_key.as_str()],
    ));
}

/// Rewrites an archive's entries and loads the result.
fn tampered(
    archive: &Path,
    trusted: &str,
    edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>),
) -> Result<LoadedPack, PackError> {
    let mut entries = zip::read_all(&std::fs::read(archive).unwrap(), 1_048_576).unwrap();
    edit(&mut entries);
    load_bytes(&zip::write(&entries), &[trusted])
}

fn replace(entries: &mut [(String, Vec<u8>)], name: &str, edit: impl FnOnce(String) -> String) {
    let entry = entries.iter_mut().find(|(entry, _)| entry == name).unwrap();
    entry.1 = edit(String::from_utf8(entry.1.clone()).unwrap()).into_bytes();
}

#[test]
fn pack_detects_tampering() {
    let built = build_pack(&repo_pack("linux-ssh-gateway"), None);
    let key = built.public_key.as_str();
    let policy = "content/policies/ssh-authentication.yaml";

    // Rewriting the archive without changes still loads.
    assert!(tampered(&built.archive, key, |_| {}).is_ok());

    // modify
    let message = verification_error(tampered(&built.archive, key, |entries| {
        replace(entries, policy, |text| {
            text.replace("minimumValueScore: 75", "minimumValueScore: 0")
        });
    }));
    assert_eq!(
        message,
        "Pack file 'policies/ssh-authentication.yaml' is missing or modified."
    );

    // add
    let message = verification_error(tampered(&built.archive, key, |entries| {
        entries.push((
            "content/policies/allow-all.yaml".to_owned(),
            b"extra".to_vec(),
        ));
    }));
    assert_eq!(
        message,
        "Pack contains an unlisted file: content/policies/allow-all.yaml"
    );

    // manifest
    let message = verification_error(tampered(&built.archive, key, |entries| {
        replace(entries, "manifest.json", |text| {
            text.replace("1.0.0", "9.9.9")
        });
    }));
    assert_eq!(
        message,
        "Pack signature is invalid or not from a trusted key."
    );

    // remove a listed file
    let message = verification_error(tampered(&built.archive, key, |entries| {
        entries.retain(|(name, _)| name != policy)
    }));
    assert_eq!(
        message,
        "Pack file 'policies/ssh-authentication.yaml' is missing or modified."
    );

    // unsigned
    let message = verification_error(tampered(&built.archive, key, |entries| {
        entries.retain(|(name, _)| name != "manifest.sig")
    }));
    assert_eq!(message, "Pack is missing its manifest or signature.");

    // signature unreadable
    let message = verification_error(tampered(&built.archive, key, |entries| {
        replace(entries, "manifest.sig", |_| "null".to_owned());
    }));
    assert_eq!(message, "Pack signature is unreadable.");

    // Re-serialized manifest with an extra member is not the signed bytes.
    let message = verification_error(tampered(&built.archive, key, |entries| {
        replace(entries, "manifest.json", |text| {
            text.replacen('{', "{\"extra\":1,", 1)
        });
    }));
    assert_eq!(
        message,
        "Pack signature is invalid or not from a trusted key."
    );

    // Whitespace-only change to the manifest also breaks the canonical check.
    let message = verification_error(tampered(&built.archive, key, |entries| {
        replace(entries, "manifest.json", |text| format!("{text} "));
    }));
    assert_eq!(
        message,
        "Pack signature is invalid or not from a trusted key."
    );

    // Path traversal and unsafe names.
    for name in [
        "content/../manifest.json",
        "content/./x",
        "../evil",
        "content/a b",
        "other/file",
        "/abs",
    ] {
        let message = verification_error(tampered(&built.archive, key, |entries| {
            entries.push((name.to_owned(), b"x".to_vec()))
        }));
        assert_eq!(message, format!("Pack entry '{name}' is not allowed."));
    }

    // Duplicate entry names are refused.
    verification_error(tampered(&built.archive, key, |entries| {
        let copy = entries
            .iter()
            .find(|(name, _)| name == policy)
            .unwrap()
            .clone();
        entries.push(copy);
    }));

    // Oversized entry.
    let message = verification_error(tampered(&built.archive, key, |entries| {
        entries.push(("content/big".to_owned(), vec![b'a'; 1_048_577]));
    }));
    assert_eq!(message, "Pack entry 'content/big' is not allowed.");

    // Too many entries.
    let message = verification_error(tampered(&built.archive, key, |entries| {
        entries.extend((0..500).map(|index| (format!("content/x{index}"), Vec::new())));
    }));
    assert_eq!(message, "Pack archive has too many entries.");

    // Not a zip: the System.IO.Compression message.
    assert!(matches!(
        load_bytes(b"PK not really", &[key]),
        Err(PackError::InvalidData(message)) if message == "End of Central Directory record could not be found."
    ));

    // Directory entries are skipped, as in C#.
    assert!(
        tampered(&built.archive, key, |entries| entries
            .push(("content/dir/".to_owned(), Vec::new())))
        .is_ok()
    );

    // Re-signing a forged manifest with another key does not help.
    let other = bower_integrity::generate_key_pair();
    let message = verification_error(tampered(&built.archive, key, |entries| {
        let manifest = entries
            .iter()
            .find(|(name, _)| name == "manifest.json")
            .unwrap()
            .1
            .clone();
        let signature = bower_integrity::sign(&manifest, &other.private_key_pem).unwrap();
        replace(entries, "manifest.sig", |_| {
            bower_contracts::json::to_string(&signature).unwrap()
        });
    }));
    assert_eq!(
        message,
        "Pack signature is invalid or not from a trusted key."
    );
}

#[test]
fn csharp_pack_tampered_by_rust_is_rejected() {
    let key = csharp_public_key();
    let archive = fixture("gcp-security-1.0.0.bowerpack");
    let message = verification_error(tampered(&archive, &key, |entries| {
        replace(entries, "content/samples/gcp.jsonl", |text| {
            format!("{text}\n")
        });
    }));
    assert_eq!(
        message,
        "Pack file 'samples/gcp.jsonl' is missing or modified."
    );
}

#[test]
fn pack_build_fails_when_a_sample_fails() {
    let source = tempfile::tempdir().unwrap();
    copy_directory(&repo_pack("linux-ssh-gateway"), source.path());
    let samples = source.path().join("samples/ssh.jsonl");
    let mut text = std::fs::read_to_string(&samples).unwrap();
    text.push_str(r#"{"name":"wrong expectation","expect":"reject","event":{"schemaVersion":"1.0.0","eventId":"s9","timeGenerated":"{{now}}","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"a","eventResult":"failure","application":{"name":"x","environment":"y"},"actor":{"username":"u"},"source":{"ipAddress":"192.0.2.1"},"request":{"correlationId":"c"}}}"#);
    text.push('\n');
    std::fs::write(&samples, text).unwrap();
    let keys = bower_integrity::generate_key_pair();

    match build(source.path(), &keys.private_key_pem, source.path(), None) {
        Err(PackError::InvalidData(message)) => {
            assert!(message.starts_with("Pack samples failed: "), "{message}");
            assert!(
                message.contains("wrong expectation: Expected reject, got "),
                "{message}"
            );
        }
        other => panic!("expected InvalidData, got {other:?}"),
    }
}

#[test]
fn pack_build_validates_the_source() {
    let keys = bower_integrity::generate_key_pair();
    let attempt = |edit: &dyn Fn(String) -> String| {
        let source = tempfile::tempdir().unwrap();
        copy_directory(&repo_pack("linux-ssh-gateway"), source.path());
        let yaml = source.path().join("pack.yaml");
        std::fs::write(&yaml, edit(std::fs::read_to_string(&yaml).unwrap())).unwrap();
        build(
            source.path(),
            &keys.private_key_pem,
            &source.path().join("out"),
            None,
        )
    };
    let invalid = |result: Result<PathBuf, PackError>| match result {
        Err(PackError::InvalidData(message)) => message,
        other => panic!("expected InvalidData, got {other:?}"),
    };

    assert_eq!(
        invalid(attempt(
            &|yaml| yaml.replace("id: linux-ssh-gateway", "id: Linux_SSH")
        )),
        "Pack id must be lowercase letters, digits and hyphens (3-64)."
    );
    assert_eq!(
        invalid(attempt(
            &|yaml| yaml.replace("version: 1.0.0", "version: v1")
        )),
        "Pack version must be semantic (for example 1.2.0)."
    );
    assert_eq!(
        invalid(attempt(&|yaml| yaml.replace("kind: Pack", "kind: Other"))),
        "pack.yaml must be apiVersion bower.security/v1, kind Pack."
    );
    assert!(
        invalid(attempt(&|yaml| format!("{yaml}unknownKey: 1\n")))
            .starts_with("pack.yaml is invalid at line")
    );
    assert_eq!(
        invalid(attempt(&|yaml| yaml.replace(
            "privacyProfile: privacy.yaml",
            "privacyProfile: ../../etc/passwd"
        ))),
        "Pack path escapes the pack directory: ../../etc/passwd"
    );
    assert!(matches!(
        attempt(&|yaml| yaml.replace("samples/ssh.jsonl", "samples/missing.jsonl")),
        Err(PackError::NotFound(message)) if message == "Pack file not found: samples/missing.jsonl"
    ));
    assert_eq!(
        invalid(attempt(&|yaml| yaml
            .replace("  - policies/ssh-authentication.yaml\n", "  []\n")
            .replace("policies:\n", "policies:"))),
        "A pack must contain at least one policy."
    );
    assert!(matches!(
        build(
            Path::new("/nonexistent"),
            &keys.private_key_pem,
            Path::new("/nonexistent/out"),
            None
        ),
        Err(PackError::NotFound(_))
    ));
}

#[test]
fn pack_build_rejects_oversized_files_and_bad_keys() {
    let source = tempfile::tempdir().unwrap();
    copy_directory(&repo_pack("linux-ssh-gateway"), source.path());
    let keys = bower_integrity::generate_key_pair();
    assert!(matches!(
        build(source.path(), &keys.public_key_pem, &source.path().join("out"), None),
        Err(PackError::InvalidData(message)) if message.starts_with("Pack signing failed")
    ));
    std::fs::write(
        source.path().join("samples/ssh.jsonl"),
        vec![b' '; 1_048_577],
    )
    .unwrap();
    assert!(matches!(
        build(source.path(), &keys.private_key_pem, &source.path().join("out"), None),
        Err(PackError::InvalidData(message)) if message == "Pack file exceeds 1 MiB: samples/ssh.jsonl"
    ));
}

#[test]
fn pack_diff_reports_population_changes_and_missing_version_bump() {
    let clock = csharp_clock();
    let v1 = tempfile::tempdir().unwrap();
    let v2 = tempfile::tempdir().unwrap();
    copy_directory(&repo_pack("linux-ssh-gateway"), v1.path());
    copy_directory(&repo_pack("linux-ssh-gateway"), v2.path());
    let yaml = v2.path().join("pack.yaml");
    std::fs::write(
        &yaml,
        std::fs::read_to_string(&yaml)
            .unwrap()
            .replace("version: 1.0.0", "version: 1.1.0"),
    )
    .unwrap();
    let policy = v2.path().join("policies/ssh-authentication.yaml");
    std::fs::write(
        &policy,
        std::fs::read_to_string(&policy)
            .unwrap()
            .replace(
                "    - account_lockout\n",
                "    - account_lockout\n    - authentication_success\n",
            )
            .replace("minimumValueScore: 75", "minimumValueScore: 60")
            .replace(
                "    - timeGenerated\n",
                "    - timeGenerated\n    - eventAction\n",
            ),
    )
    .unwrap();

    let before = build_pack(v1.path(), Some(&clock));
    let after = build_pack(v2.path(), Some(&clock));
    let before = load(&before.archive, &[before.public_key.as_str()]).unwrap();
    let after = load(&after.archive, &[after.public_key.as_str()]).unwrap();
    let changes: Vec<String> = compare(&before, &after)
        .unwrap()
        .into_iter()
        .map(|change| {
            format!(
                "diff|{}|{}|{}",
                change.policy_id, change.change, change.detail
            )
        })
        .collect();

    let expected: Vec<String> = vector("report.txt")
        .lines()
        .filter(|line| line.starts_with("diff|"))
        .map(str::to_owned)
        .collect();
    assert_eq!(changes, expected);
    assert!(
        changes
            .iter()
            .any(|line| line.ends_with("|event-type-added|authentication_success"))
    );
    assert!(
        changes
            .iter()
            .any(|line| line.contains("|version-not-bumped|"))
    );
}

#[test]
fn pack_diff_reports_added_removed_and_action_changes() {
    let policy = |id: &str, version: &str, action: &str, types: &str| {
        let yaml = format!(
            "apiVersion: bower.security/v1\nkind: TelemetryPolicy\nmetadata:\n  id: {id}\n  name: n\n  version: {version}\n  owner: o\n\
             match:\n  eventCategories: [authentication]\n  eventTypes: [{types}]\nrequirements:\n  requiredFields: [timeGenerated]\n\
             decision:\n  action: {action}\n  minimumValueScore: 10\n"
        );
        bower_policy::load_yaml(&yaml, "test.yaml").unwrap()
    };
    let pack = |policies| LoadedPack {
        manifest: None,
        signed_by_key_id: "k".to_owned(),
        policies,
        privacy_profile_yaml: None,
        detections: Vec::new(),
        parsers: Vec::new(),
        sample_lines: Vec::new(),
        dcr_template_json: None,
    };
    let before = pack(vec![
        policy("BWR-A", "1.0.0", "accept", "authentication_failure"),
        policy(
            "BWR-B",
            "1.0.0",
            "accept",
            "authentication_failure, account_lockout",
        ),
    ]);
    let after = pack(vec![
        policy(
            "BWR-A",
            "1.0.1",
            "Quarantine",
            "authentication_failure, authentication_failure",
        ),
        policy("BWR-C", "1.0.0", "accept", "authentication_success"),
    ]);
    let changes: Vec<(String, String, String)> = compare(&before, &after)
        .unwrap()
        .into_iter()
        .map(|change| (change.policy_id, change.change, change.detail))
        .collect();
    let owned =
        |id: &str, kind: &str, detail: &str| (id.to_owned(), kind.to_owned(), detail.to_owned());
    assert_eq!(
        changes,
        vec![
            owned("BWR-C", "policy-added", "Accepts authentication_success."),
            owned(
                "BWR-B",
                "policy-removed",
                "Stops accepting authentication_failure, account_lockout."
            ),
            owned("BWR-A", "action-changed", "accept -> Quarantine"),
        ]
    );

    let duplicate = pack(vec![
        policy("BWR-A", "1.0.0", "accept", "x"),
        policy("BWR-A", "1.0.0", "accept", "x"),
    ]);
    assert!(compare(&duplicate, &after).is_err());
}

#[test]
fn rust_and_csharp_archives_round_trip_through_the_rust_zip_writer() {
    // A C# archive rewritten by the Rust writer still verifies: the signature covers
    // the manifest, not the container.
    let key = csharp_public_key();
    for id in PACK_IDS {
        let archive = fixture(&format!("{id}-1.0.0.bowerpack"));
        assert!(
            tampered(&archive, &key, |entries| entries.reverse()).is_ok(),
            "{id}"
        );
    }
}

/// Writes Rust-built packs (and one tampered copy) for the C# cross-check:
/// `RUST_PACKS=<dir> cargo test -p bower-packs -- --ignored emit_rust_packs`, then
/// C# `PackArchive.Load` must accept the packs and reject the tampered one.
#[test]
#[ignore = "writes cross-implementation artifacts; run manually"]
fn emit_rust_packs_for_csharp() {
    let Ok(directory) = std::env::var("RUST_PACKS") else {
        return;
    };
    let directory = PathBuf::from(directory);
    std::fs::create_dir_all(&directory).unwrap();
    // Throwaway test key, scratch directory only.
    let keys = bower_integrity::generate_key_pair();
    std::fs::write(directory.join("rust.pub.pem"), &keys.public_key_pem).unwrap();
    std::fs::write(directory.join("rust.key.pem"), &keys.private_key_pem).unwrap();
    for id in PACK_IDS {
        build(&repo_pack(id), &keys.private_key_pem, &directory, None).unwrap();
    }
    let archive = directory.join("linux-ssh-gateway-1.0.0.bowerpack");
    let mut entries = zip::read_all(&std::fs::read(&archive).unwrap(), 1_048_576).unwrap();
    replace(
        &mut entries,
        "content/policies/ssh-authentication.yaml",
        |text| text.replace("75", "0"),
    );
    std::fs::write(
        directory.join("z-tampered-1.0.0.bowerpack"),
        zip::write(&entries),
    )
    .unwrap();
}
