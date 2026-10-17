//! Port of `PolicyLoaderTests.cs`, plus loader vectors produced by the C#
//! `PolicyLoader` (git HEAD bf15994, YamlDotNet 18.1.0).

mod common;

use std::fs;

use bower_contracts::DecisionAction;
use bower_policy::{
    MAXIMUM_POLICY_BYTES, PolicyError, load_directory, load_file, load_yaml, try_parse_action,
};
use common::{default_policies_dir, fixtures_dir};
use serde_json::Value;

const VALID_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-TEST
  name: Test policy
  version: 1.0.0
  owner: Test
match:
  eventTypes:
    - authentication_failure
requirements:
  requiredFields:
    - eventType
decision:
  action: accept
  minimumValueScore: 1
  neverSample: true
";

/// `VALID_POLICY` hash computed by C# `PolicyLoader.LoadFile`.
const VALID_POLICY_HASH: &str =
    "sha256:664c378a9e14a0b601d8ae8c19ca1dcc25ed1e57d04bba94ff38bf671edf7191";

fn write_policy(directory: &tempfile::TempDir, yaml: &str) -> std::path::PathBuf {
    let path = directory.path().join("policy.yaml");
    fs::write(&path, yaml).unwrap();
    path
}

#[test]
fn load_file_parses_and_hashes_versioned_yaml_deterministically() {
    let directory = tempfile::tempdir().unwrap();
    let path = write_policy(&directory, VALID_POLICY);

    let first = load_file(&path).unwrap();
    let second = load_file(&path).unwrap();

    assert_eq!(first.policy.metadata.id, "BWR-POL-TEST");
    assert_eq!(first.hash, second.hash);
    assert!(first.hash.starts_with("sha256:"));
    assert_eq!(first.hash, VALID_POLICY_HASH);
    assert_eq!(first.source_path, path.to_string_lossy());
    assert!(first.policy.decision.never_sample);
    assert_eq!(first.policy.decision.minimum_value_score, 1);
}

#[test]
fn load_directory_accepts_shipped_default_policies() {
    let policies = load_directory(default_policies_dir()).unwrap();

    assert_eq!(policies.len(), 3);
    // Hashes computed by C# PolicyLoader over the same files.
    let hashes: Vec<(&str, &str)> = policies
        .iter()
        .map(|loaded| (loaded.policy.metadata.id.as_str(), loaded.hash.as_str()))
        .collect();
    assert_eq!(
        hashes,
        [
            (
                "BWR-POL-AUTH-FAILURE",
                "sha256:fe8a90191391c086bef3c1de83d278596777187a773471cdcdd0fb85e8a04f99"
            ),
            (
                "BWR-POL-EVIDENCE-CANARY",
                "sha256:89fd345ecd0730c6f25cb1a5b4a0c07133e5f2d0ffd22dc567ee96b28fcf8bae"
            ),
            (
                "BWR-POL-PRIVACY-DETECT",
                "sha256:df7e78bb696a190bca3405f0d2b75690d48303bbfd8b0913ed98464dc68af146"
            ),
        ]
    );
    let auth = &policies[0].policy;
    assert_eq!(auth.metadata.review_date.unwrap().to_string(), "2027-01-01");
    assert_eq!(
        auth.routing.as_ref().unwrap().destination.as_deref(),
        Some("security-events")
    );
}

#[test]
fn load_file_rejects_misspelt_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = write_policy(
        &directory,
        &VALID_POLICY.replace("requirements:", "requirments:"),
    );

    let error = load_file(&path).unwrap_err();

    assert!(matches!(error, PolicyError::InvalidData(_)));
    assert!(error.to_string().contains("policy.yaml"));
    assert_eq!(
        error.to_string(),
        "Policy 'policy.yaml' is invalid at line 11: Property 'requirments' not found on type 'Bower.PolicyEngine.TelemetryPolicy'."
    );
}

#[test]
fn load_file_rejects_category_only_match() {
    let directory = tempfile::tempdir().unwrap();
    let path = write_policy(
        &directory,
        &VALID_POLICY.replace(
            "  eventTypes:\n    - authentication_failure",
            "  eventCategories:\n    - authentication",
        ),
    );

    let error = load_file(&path).unwrap_err();
    assert!(matches!(error, PolicyError::InvalidData(_)));
    assert_eq!(
        error.to_string(),
        "Policy match must list at least one eventType."
    );
}

#[test]
fn load_file_rejects_numeric_or_unknown_actions() {
    for action in ["1", "-1", "acept"] {
        let directory = tempfile::tempdir().unwrap();
        let path = write_policy(
            &directory,
            &VALID_POLICY.replace("action: accept", &format!("action: \"{action}\"")),
        );

        let error = load_file(&path).unwrap_err();
        assert!(matches!(error, PolicyError::InvalidData(_)), "{action}");
        assert_eq!(
            error.to_string(),
            format!("Unsupported policy action: {action}")
        );
    }
}

#[test]
fn missing_paths_and_limits_fail_like_csharp() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("absent.yaml");
    let error = load_file(&missing).unwrap_err();
    assert!(matches!(error, PolicyError::FileNotFound(_)));
    assert_eq!(error.to_string(), "Policy file does not exist.");
    // A directory is not a policy file.
    assert!(matches!(
        load_file(directory.path()),
        Err(PolicyError::FileNotFound(_))
    ));

    let error = load_directory(directory.path().join("nope")).unwrap_err();
    assert!(matches!(error, PolicyError::DirectoryNotFound(_)));
    assert!(
        error
            .to_string()
            .starts_with("Policy directory does not exist: ")
    );
    assert!(matches!(
        load_directory(" "),
        Err(PolicyError::BlankDirectory)
    ));

    let oversized = format!(
        "{VALID_POLICY}#{}\n",
        "x".repeat(MAXIMUM_POLICY_BYTES - VALID_POLICY.len() - 1)
    );
    assert_eq!(oversized.len(), MAXIMUM_POLICY_BYTES + 1);
    let path = write_policy(&directory, &oversized);
    assert_eq!(
        load_file(&path).unwrap_err().to_string(),
        "Policy exceeds maximum size."
    );
    assert_eq!(
        load_yaml(&oversized, "x").unwrap_err().to_string(),
        "Policy exceeds maximum size."
    );
    let at_limit = &oversized[..MAXIMUM_POLICY_BYTES];
    assert_eq!(at_limit.len(), MAXIMUM_POLICY_BYTES);
    assert_eq!(load_yaml(at_limit, "x").unwrap().hash, VALID_POLICY_HASH);
}

#[test]
fn load_directory_reads_only_top_level_yaml_in_ordinal_order() {
    let directory = tempfile::tempdir().unwrap();
    let with_id = |id: &str| VALID_POLICY.replace("BWR-POL-TEST", id);
    fs::write(directory.path().join("b.yaml"), with_id("B")).unwrap();
    // Upper case sorts first (ordinal); distinct names for case-insensitive file systems.
    fs::write(directory.path().join("Z.yaml"), with_id("UPPER")).unwrap();
    fs::write(directory.path().join("a.yaml"), with_id("A")).unwrap();
    fs::write(directory.path().join("c.yml"), with_id("YML")).unwrap();
    fs::write(directory.path().join("d.yaml.bak"), with_id("BAK")).unwrap();
    fs::create_dir(directory.path().join("nested.yaml")).unwrap();
    fs::write(
        directory.path().join("nested.yaml/e.yaml"),
        with_id("NESTED"),
    )
    .unwrap();

    let ids: Vec<String> = load_directory(directory.path())
        .unwrap()
        .into_iter()
        .map(|loaded| loaded.policy.metadata.id)
        .collect();
    assert_eq!(ids, ["UPPER", "A", "B"]);
}

#[test]
fn load_file_strips_byte_order_mark_and_keeps_hash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bom.yaml");
    fs::write(
        &path,
        [b"\xEF\xBB\xBF".as_slice(), VALID_POLICY.as_bytes()].concat(),
    )
    .unwrap();
    assert_eq!(load_file(&path).unwrap().hash, VALID_POLICY_HASH);

    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(VALID_POLICY.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    fs::write(&path, utf16).unwrap();
    assert_eq!(load_file(&path).unwrap().hash, VALID_POLICY_HASH);
}

#[test]
fn try_parse_action_accepts_names_only() {
    assert_eq!(
        try_parse_action(Some("redact-and-accept")),
        Some(DecisionAction::RedactAndAccept)
    );
    assert_eq!(try_parse_action(Some("4")), None);
}

/// Every vector's YAML was loaded by C# `PolicyLoader.LoadFile`; `csharp` is
/// `OK <hash>` or `ERR <exception message>`. Vectors with a `rust` entry are
/// documented deviations (C# NullReferenceException, culture-dependent dates,
/// mappings for value types, YAML syntax error wording); Rust's outcome is
/// asserted for those.
#[test]
fn loader_vectors_match_csharp() {
    let text = fs::read_to_string(fixtures_dir().join("loader-vectors.json")).unwrap();
    let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
    assert!(vectors.len() > 200);

    let mut deviations = Vec::new();
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        let yaml = vector["yaml"].as_str().unwrap();
        let actual = match load_yaml(yaml, name) {
            Ok(loaded) => format!("OK {}", loaded.hash),
            Err(error) => format!("ERR {error}"),
        };
        let expected = match vector.get("rust") {
            Some(rust) => {
                deviations.push(name);
                rust.as_str().unwrap()
            }
            None => vector["csharp"].as_str().unwrap(),
        };
        assert_eq!(actual, expected, "{name}");
    }

    // Deviations are only the documented classes; every one fails closed.
    for vector in vectors.iter().filter(|vector| vector.get("rust").is_some()) {
        assert!(vector["rust"].as_str().unwrap().starts_with("ERR "));
    }
    assert_eq!(deviations.len(), 22, "{deviations:?}");
}
