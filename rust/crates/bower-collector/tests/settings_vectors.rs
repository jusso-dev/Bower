//! Shared C#/Rust vectors: `tests/fixtures/collector-settings/vectors.json`
//! (C# `CollectorSettingsVectorTests`).

use std::collections::HashMap;
use std::path::Path;

use bower_collector::CollectorSettings;
use serde_json::Value;

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/collector-settings/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn environment(values: &Value) -> HashMap<String, String> {
    values
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
        .collect()
}

fn load(
    environment: &HashMap<String, String>,
) -> Result<CollectorSettings, bower_collector::HostError> {
    CollectorSettings::from_environment(|key| environment.get(key).cloned())
}

#[test]
fn ingest_token_references_are_refused_without_echoing_them() {
    let vectors = vectors();
    let refusal = vectors["referenceRefusal"].as_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    for vector in vectors["ingestTokens"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let value = vector["value"].as_str().unwrap();
        let mut environment = environment(&vectors["environment"]);
        if vector["source"] == "file" {
            let path = directory.path().join(name);
            std::fs::write(&path, value).unwrap();
            environment.insert(
                "BOWER_INGEST_TOKEN_FILE".into(),
                path.to_str().unwrap().into(),
            );
        } else {
            environment.insert("BOWER_INGEST_TOKEN".into(), value.into());
        }

        // from_environment validates, so a refused token never yields settings.
        match load(&environment) {
            Ok(settings) => {
                assert!(vector["accepted"].as_bool().unwrap(), "{name}");
                assert_eq!(
                    settings.ingest_token.as_deref(),
                    Some(value.trim()),
                    "{name}"
                );
            }
            Err(error) => {
                assert!(!vector["accepted"].as_bool().unwrap(), "{name}");
                assert_eq!(error.message, refusal, "{name}");
                assert!(!error.message.to_ascii_lowercase().contains("example"));
            }
        }
    }
}

#[test]
fn producer_scope_sources_are_pinned() {
    for vector in vectors()["producerScopeSources"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let mut environment = environment(&vector["environment"]);
        environment
            .entry("BOWER_COLLECTOR_ID".into())
            .or_insert_with(|| "collector-test".into());
        if !vector["valid"].as_bool().unwrap() {
            assert!(load(&environment).is_err(), "{name}");
            continue;
        }

        let settings = load(&environment).unwrap();
        assert_eq!(
            settings.producer_scopes_json.as_deref(),
            vector["inlineScopes"].as_str(),
            "{name}"
        );
        assert_eq!(
            settings
                .producer_scopes_file
                .as_deref()
                .and_then(Path::to_str),
            vector["scopesFile"].as_str(),
            "{name}"
        );
    }
}

#[test]
fn configuration_hashes_match_csharp_vectors() {
    for vector in vectors()["configurationHashes"].as_array().unwrap() {
        let settings = load(&environment(&vector["environment"])).unwrap();
        assert_eq!(
            settings.configuration_hash(),
            vector["expected"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
}
