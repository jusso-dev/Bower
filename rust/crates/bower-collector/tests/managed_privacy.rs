//! Port of `ManagedPrivacyProfileTests` (C# `Bower.Collector` managed privacy profile
//! mode) plus cross-implementation vectors: deployment documents signed by the C#
//! `ManagedPrivacyProfileCache.SignedBytes` + `DetachedSigner` and C#'s verdict on each
//! (`fixtures/csharp-managed-privacy.json`, produced by
//! `rust/tools/csharp-vectors/ZzManagedPrivacyVectors.cs`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use bower_collector::heartbeat::{AccessTokenSource, ManagementHeartbeat, TokenFuture};
use bower_collector::host::{self, BuildOptions};
use bower_collector::jobs::{JobCatalog, MANAGED_PRIVACY_PROFILE_JOB_ID};
use bower_collector::managed_privacy::{
    self, CACHE_FILE_NAME, MAXIMUM_DOCUMENT_BYTES, ManagedPrivacyProfileJob, RESTART_EXIT_CODE,
};
use bower_collector::settings::{PRIVACY_PROFILE_SOURCE_LOCAL, PRIVACY_PROFILE_SOURCE_MANAGEMENT};
use bower_collector::shutdown::{self, ApplicationLifetime};
use bower_collector::{CollectorSettings, bundle, server};
use bower_contracts::DurableEventStore;
use serde_json::{Value, json};
use tower::ServiceExt;

const COLLECTOR_ID: &str = "collector-test";
const TOKEN: &str = "test-ingest-token-0123456789abcdef0123456789";
const DEPLOYMENT_PATH: &str = "/api/collectors/collector-test/privacy-profile/deployment";
/// Base64 of the 32 zero bytes the C# tests use as the HMAC key.
const HMAC_KEY_BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const HMAC_KEY: [u8; 32] = [0; 32];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

/// `PrivacyProfileApiTests.Profile(version)`.
fn content(version: &str) -> String {
    format!(
        "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: contoso-app\n  version: {version}\n  description: Contoso application telemetry\ndetectors:\n  id.email: remove\nfields:\n  - path: actor.username\n    action: hmac\n\n"
    )
}

fn content_hash(yaml: &str) -> String {
    bower_redaction::load_privacy_profile(yaml, Some(&HMAC_KEY), None)
        .unwrap()
        .hash
}

struct Fixture {
    directory: tempfile::TempDir,
    settings: CollectorSettings,
    private_pem: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pair = bower_integrity::generate_key_pair();
        let trusted = directory.path().join("managed-privacy-trusted.pem");
        std::fs::write(&trusted, &pair.public_key_pem).unwrap();
        let hmac = directory.path().join("hmac.key");
        std::fs::write(&hmac, HMAC_KEY_BASE64).unwrap();
        let mut settings = CollectorSettings::new(
            "http://127.0.0.1:4319",
            directory.path().join("queue.db"),
            repo_root().join("policies/default"),
            COLLECTOR_ID,
        );
        // Discard port: a scheduled run during a test fails fast without a real server.
        settings.management_endpoint = Some("http://127.0.0.1:9".parse().unwrap());
        settings.management_scope = Some("api://bower/.default".into());
        settings.privacy_profile_source = PRIVACY_PROFILE_SOURCE_MANAGEMENT.into();
        settings.managed_privacy_trusted_key_files = vec![trusted.to_string_lossy().into_owned()];
        settings.privacy_hmac_key_file = Some(hmac);
        Self {
            directory,
            settings,
            private_pem: pair.private_key_pem,
        }
    }

    fn cache_path(&self) -> PathBuf {
        managed_privacy::cache_path(&self.settings)
    }

    fn write_cache(&self, document: &[u8]) {
        std::fs::create_dir_all(self.settings.managed_privacy_cache_directory()).unwrap();
        std::fs::write(self.cache_path(), document).unwrap();
    }

    fn cache_files(&self) -> Vec<String> {
        std::fs::read_dir(self.settings.managed_privacy_cache_directory())
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn local(&self) -> CollectorSettings {
        let mut local = self.settings.clone();
        local.privacy_profile_source = PRIVACY_PROFILE_SOURCE_LOCAL.into();
        local.managed_privacy_trusted_key_files.clear();
        local
    }
}

#[derive(Clone)]
struct DocumentSpec {
    content: String,
    collector_id: String,
    content_hash: Option<String>,
    version_id: String,
    issued_at: String,
    profile_id: Option<String>,
    version: Option<String>,
}

impl Default for DocumentSpec {
    fn default() -> Self {
        Self {
            content: content("1.0.0"),
            collector_id: COLLECTOR_ID.into(),
            content_hash: None,
            version_id: "0123456789abcdef0123456789abcdef".into(),
            issued_at: "2026-10-24T00:00:00.0000000Z".into(),
            profile_id: None,
            version: None,
        }
    }
}

/// C# `Document(...)`: a signed deployment document.
fn document(private_pem: &str, spec: &DocumentSpec) -> Vec<u8> {
    serde_json::to_vec(&document_value(private_pem, spec)).unwrap()
}

fn document_value(private_pem: &str, spec: &DocumentSpec) -> Value {
    let loaded = bower_redaction::load_privacy_profile(&spec.content, Some(&HMAC_KEY), None).ok();
    let profile_id = spec.profile_id.clone().unwrap_or_else(|| {
        loaded
            .as_ref()
            .and_then(|profile| profile.id.clone())
            .unwrap_or_else(|| "contoso-app".into())
    });
    let version = spec.version.clone().unwrap_or_else(|| {
        loaded
            .as_ref()
            .and_then(|profile| profile.version.clone())
            .unwrap_or_else(|| "9.9.9".into())
    });
    let hash = spec.content_hash.clone().unwrap_or_else(|| {
        loaded
            .as_ref()
            .map(|profile| profile.hash.clone())
            .unwrap_or_else(|| format!("sha256:{}", "0".repeat(64)))
    });
    let signature = bower_integrity::sign(
        &managed_privacy::signed_bytes(
            &spec.collector_id,
            &spec.version_id,
            &profile_id,
            &version,
            &hash,
            &spec.content,
            &spec.issued_at,
        ),
        private_pem,
    )
    .unwrap();
    json!({
        "collectorId": spec.collector_id,
        "versionId": spec.version_id,
        "profileId": profile_id,
        "version": version,
        "contentHash": hash,
        "content": spec.content,
        "issuedAt": spec.issued_at,
        "signature": {
            "algorithm": signature.algorithm,
            "keyId": signature.key_id,
            "value": signature.value,
        }
    })
}

/// C# `Tampered(tamper, privatePem, content)`.
fn tampered(tamper: &str, private_pem: &str, body: &str) -> Vec<u8> {
    let spec = DocumentSpec {
        content: body.into(),
        ..DocumentSpec::default()
    };
    let valid = document_value(private_pem, &spec);
    let mutate = |change: &dyn Fn(&mut Value)| {
        let mut copy = valid.clone();
        change(&mut copy);
        serde_json::to_vec(&copy).unwrap()
    };
    match tamper {
        "content" => mutate(&|d| d["content"] = json!(body.replace("remove", "allow"))),
        "contentHash" => {
            mutate(&|d| d["contentHash"] = json!(format!("sha256:{}", "a".repeat(64))))
        }
        "signature" => mutate(&|d| {
            d["signature"]["value"] = json!(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
            )
        }),
        "collectorId" => mutate(&|d| d["collectorId"] = json!("collector-other")),
        "missing-field" => mutate(&|d| {
            d.as_object_mut().unwrap().shift_remove("issuedAt");
        }),
        "signed-for-another-collector" => document(
            private_pem,
            &DocumentSpec {
                collector_id: "collector-other".into(),
                ..spec.clone()
            },
        ),
        "signed-wrong-hash" => document(
            private_pem,
            &DocumentSpec {
                content_hash: Some(format!("sha256:{}", "b".repeat(64))),
                ..spec.clone()
            },
        ),
        "signed-invalid-content" => document(
            private_pem,
            &DocumentSpec {
                content: body.replace("id.email", "not-a-detector"),
                ..spec.clone()
            },
        ),
        "untrusted-key" => document(&bower_integrity::generate_key_pair().private_key_pem, &spec),
        "truncated" => {
            let bytes = serde_json::to_vec(&valid).unwrap();
            bytes[..bytes.len() / 2].to_vec()
        }
        other => panic!("unknown tamper {other}"),
    }
}

fn valid_document(fixture: &Fixture) -> Vec<u8> {
    document(&fixture.private_pem, &DocumentSpec::default())
}

// ------------------------------------------------------------------ C# vectors

fn vectors() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csharp-managed-privacy.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes().filter(|byte| *byte != b'=') {
        let value = ALPHABET.iter().position(|c| *c == byte).unwrap() as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    output
}

#[test]
fn csharp_signed_documents_verify_exactly_as_csharp_does() {
    let vectors = vectors();
    assert_eq!(vectors["hmacKey"], HMAC_KEY_BASE64);
    let collector_id = vectors["collectorId"].as_str().unwrap();
    // Non-ASCII and HTML-sensitive characters in the signed collector id.
    assert!(collector_id.contains("<&>'\"+`") && !collector_id.is_ascii());
    let trusted = vec![vectors["publicKey"].as_str().unwrap().to_string()];
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 60, "{} cases", cases.len());
    let (mut accepted, mut yaml_messages) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bytes = base64_decode(case["document"].as_str().unwrap());
        let expected = &case["result"];
        let actual = managed_privacy::verify(&bytes, collector_id, &trusted, Some(&HMAC_KEY), "k1");
        if expected["ok"].as_bool().unwrap() {
            let verified = actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(verified.version_id, expected["versionId"], "{name}");
            assert_eq!(verified.profile_id, expected["profileId"], "{name}");
            assert_eq!(verified.version, expected["version"], "{name}");
            assert_eq!(verified.content_hash, expected["contentHash"], "{name}");
            assert_eq!(verified.profile.hash, expected["contentHash"], "{name}");
            accepted += 1;
        } else {
            assert_eq!(
                expected["type"], "ManagedPrivacyProfileException",
                "{name}: C# threw a different exception type"
            );
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: Rust accepted it"));
            let message = expected["message"].as_str().unwrap();
            // YAML parser messages come from different libraries (YamlDotNet vs
            // serde_yaml), as in bower-redaction's parity tests: compare the
            // Bower-authored prefix up to the parser text.
            const YAML_PREFIX: &str = "failed validation: Privacy profile is invalid at line ";
            match message.find(YAML_PREFIX) {
                Some(at) => {
                    let line_end = message[at + YAML_PREFIX.len()..].find(": ").unwrap();
                    let prefix = &message[..at + YAML_PREFIX.len() + line_end + 2];
                    assert!(
                        error.message().starts_with(prefix),
                        "{name}: {} vs {prefix}",
                        error.message()
                    );
                    yaml_messages += 1;
                }
                None => assert_eq!(error.message(), message, "{name}"),
            }
        }
    }
    assert!(accepted >= 8, "{accepted} accepted");
    assert_eq!(yaml_messages, 1);
}

#[test]
fn signed_bytes_match_csharp_canonical_json() {
    let vectors = vectors();
    let mut compared = 0;
    for case in vectors["cases"].as_array().unwrap() {
        let Some(expected) = case["signedBytes"].as_str() else {
            continue;
        };
        let document: Value =
            serde_json::from_slice(&base64_decode(case["document"].as_str().unwrap())).unwrap();
        let field = |name: &str| document[name].as_str().unwrap().to_string();
        let actual = managed_privacy::signed_bytes(
            &field("collectorId"),
            &field("versionId"),
            &field("profileId"),
            &field("version"),
            &field("contentHash"),
            &field("content"),
            &field("issuedAt"),
        );
        let expected = base64_decode(expected);
        assert_eq!(
            String::from_utf8(actual).unwrap(),
            String::from_utf8(expected).unwrap(),
            "{}",
            case["name"]
        );
        compared += 1;
    }
    assert_eq!(compared, 2);
    // The content really exercises the escaper: non-ASCII, <>&'"+`, CR, LF and tab.
    let content = vectors["content"].as_str().unwrap();
    for needle in [
        "<",
        ">",
        "&",
        "'",
        "\"",
        "+",
        "`",
        "\n",
        "\t",
        "\u{e9}",
        "\u{1f600}",
    ] {
        assert!(content.contains(needle), "{needle:?}");
    }
}

#[test]
fn csharp_signed_cache_loads_at_start_up() {
    let vectors = vectors();
    let fixture = Fixture::new();
    let mut settings = fixture.settings.clone();
    settings.collector_id = vectors["collectorId"].as_str().unwrap().into();
    let public = fixture.directory.path().join("csharp.pem");
    std::fs::write(&public, vectors["publicKey"].as_str().unwrap()).unwrap();
    settings.managed_privacy_trusted_key_files = vec![public.to_string_lossy().into_owned()];
    let case = &vectors["cases"][1];
    assert_eq!(
        case["name"],
        "valid-relaxed-escaping-pascal-case-unknown-fields"
    );
    std::fs::create_dir_all(settings.managed_privacy_cache_directory()).unwrap();
    std::fs::write(
        managed_privacy::cache_path(&settings),
        base64_decode(case["document"].as_str().unwrap()),
    )
    .unwrap();

    let loaded = bundle::load(&settings).unwrap();

    assert_eq!(loaded.info.privacy_profile.as_deref(), Some("contoso-app"));
    assert_eq!(
        loaded.info.privacy_profile_hash.as_deref(),
        vectors["contentHash"].as_str()
    );
}

// ------------------------------------------------------------------ settings

#[test]
fn settings_validate_managed_source() {
    let fixture = Fixture::new();
    let managed = fixture.settings.clone();
    managed.validate().unwrap();
    let message = |change: &dyn Fn(&mut CollectorSettings)| {
        let mut settings = managed.clone();
        change(&mut settings);
        settings.validate().unwrap_err()
    };

    let error = message(&|s| s.privacy_profile_source = "remote".into());
    assert_eq!(error.kind, "InvalidOperationException");
    assert_eq!(
        error.message,
        "BOWER_PRIVACY_PROFILE_SOURCE must be local or management."
    );
    assert_eq!(
        message(&|s| s.management_endpoint = None).message,
        "BOWER_PRIVACY_PROFILE_SOURCE=management requires BOWER_MANAGEMENT_ENDPOINT and BOWER_MANAGEMENT_SCOPE."
    );
    assert_eq!(
        message(&|s| s.managed_privacy_trusted_key_files.clear()).message,
        "BOWER_PRIVACY_PROFILE_SOURCE=management requires BOWER_MANAGED_PRIVACY_TRUSTED_KEYS; \
         managed privacy profiles are never loaded unverified."
    );
    assert_eq!(
        message(&|s| s.privacy_profile_path = Some("profile.yaml".into())).message,
        "BOWER_PRIVACY_PROFILE cannot be combined with BOWER_PRIVACY_PROFILE_SOURCE=management."
    );
    assert_eq!(
        message(&|s| s.management_scope = None).message,
        "BOWER_MANAGEMENT_SCOPE is required when BOWER_MANAGEMENT_ENDPOINT is set."
    );
    // Local mode ignores the managed-only settings.
    let mut local = managed.clone();
    local.privacy_profile_source = PRIVACY_PROFILE_SOURCE_LOCAL.into();
    local.management_endpoint = None;
    local.validate().unwrap();
}

#[test]
fn settings_read_managed_source_from_environment() {
    let directory = tempfile::tempdir().unwrap();
    let queue = directory.path().join("data").join("bower.db");
    let queue_text = queue.to_string_lossy().into_owned();
    let base = move |name: &str| -> Option<String> {
        match name {
            "BOWER_QUEUE_PATH" => Some(queue_text.clone()),
            "BOWER_PRIVACY_PROFILE_SOURCE" => Some(" Management ".into()),
            "BOWER_MANAGEMENT_ENDPOINT" => Some("https://management.example.test".into()),
            "BOWER_MANAGEMENT_SCOPE" => Some("api://bower/.default".into()),
            "BOWER_MANAGED_PRIVACY_TRUSTED_KEYS" => Some("/keys/a.pem, /keys/b.pem".into()),
            _ => None,
        }
    };

    let settings = CollectorSettings::from_environment(&base).unwrap();
    let custom = CollectorSettings::from_environment(|name| {
        if name == "BOWER_MANAGED_PRIVACY_DIRECTORY" {
            Some("/var/lib/bower/privacy".into())
        } else {
            base(name)
        }
    })
    .unwrap();
    let invalid = CollectorSettings::from_environment(|name| {
        if name == "BOWER_PRIVACY_PROFILE_SOURCE" {
            Some("pack".into())
        } else {
            base(name)
        }
    })
    .unwrap_err();
    let local = CollectorSettings::from_environment(|name| {
        if name == "BOWER_PRIVACY_PROFILE_SOURCE" {
            None
        } else {
            base(name)
        }
    })
    .unwrap();

    assert!(settings.uses_managed_privacy_profile());
    assert_eq!(
        settings.managed_privacy_trusted_key_files,
        ["/keys/a.pem", "/keys/b.pem"]
    );
    assert_eq!(
        settings.managed_privacy_cache_directory(),
        directory.path().join("data").join("managed-privacy")
    );
    assert_eq!(
        custom.managed_privacy_cache_directory(),
        PathBuf::from("/var/lib/bower/privacy")
    );
    assert!(invalid.message.contains("BOWER_PRIVACY_PROFILE_SOURCE"));
    assert_eq!(local.privacy_profile_source, PRIVACY_PROFILE_SOURCE_LOCAL);
    // Local configuration hashes are unchanged by the new settings; management differs.
    let mut without_keys = local.clone();
    without_keys.managed_privacy_trusted_key_files.clear();
    assert_eq!(
        local.configuration_hash(),
        without_keys.configuration_hash()
    );
    let mut managed = local.clone();
    managed.privacy_profile_source = PRIVACY_PROFILE_SOURCE_MANAGEMENT.into();
    assert_ne!(local.configuration_hash(), managed.configuration_hash());
}

#[test]
fn configuration_hash_appends_the_management_source_like_csharp() {
    use sha2::{Digest, Sha256};
    let fixture = Fixture::new();
    let local = fixture.local();
    // The C# material is the local material + "\u001fprivacy-source:management".
    let mut managed = local.clone();
    managed.privacy_profile_source = PRIVACY_PROFILE_SOURCE_MANAGEMENT.into();
    let material = format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}\u{1f}\u{1f}ManagedIdentity\u{1f}10737418240\u{1f}168\u{1f}500\u{1f}20\u{1f}False\u{1f}k1\u{1f}False\u{1f}",
        local.listen_url, local.output_type, local.stream_name
    );
    let hash = |text: String| format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())));
    assert_eq!(local.configuration_hash(), hash(material.clone()));
    assert_eq!(
        managed.configuration_hash(),
        hash(material + "\u{1f}privacy-source:management")
    );
}

#[test]
fn relative_queue_path_resolves_like_get_full_path() {
    let mut settings =
        CollectorSettings::new("http://127.0.0.1:4319", "data/../q/./bower.db", ".", "c");
    assert_eq!(
        settings.managed_privacy_cache_directory(),
        std::env::current_dir()
            .unwrap()
            .join("q")
            .join("managed-privacy")
    );
    settings.managed_privacy_directory = Some("relative-cache".into());
    assert_eq!(
        managed_privacy::cache_path(&settings),
        PathBuf::from("relative-cache").join(CACHE_FILE_NAME)
    );
}

// ------------------------------------------------------------------ bundle

#[test]
fn bundle_without_cache_uses_built_in_default_and_keeps_hash_semantics() {
    let fixture = Fixture::new();

    let managed = bundle::load(&fixture.settings).unwrap();
    let local = bundle::load(&fixture.local()).unwrap();

    assert_eq!(managed.info.privacy_profile_hash, None);
    assert_eq!(managed.info.privacy_profile, None);
    assert_eq!(
        managed.info.privacy_profile_source,
        PRIVACY_PROFILE_SOURCE_MANAGEMENT
    );
    assert_eq!(
        local.info.privacy_profile_source,
        PRIVACY_PROFILE_SOURCE_LOCAL
    );
    assert_eq!(managed.info.hash, local.info.hash);
}

#[test]
fn bundle_loads_verified_cache_with_the_same_hash_as_a_local_profile() {
    let fixture = Fixture::new();
    fixture.write_cache(&valid_document(&fixture));
    let profile = fixture.directory.path().join("profile.yaml");
    std::fs::write(&profile, content("1.0.0")).unwrap();
    let mut local_settings = fixture.settings.clone();
    local_settings.privacy_profile_source = PRIVACY_PROFILE_SOURCE_LOCAL.into();
    local_settings.privacy_profile_path = Some(profile);

    let managed = bundle::load(&fixture.settings).unwrap();
    let local = bundle::load(&local_settings).unwrap();

    assert_eq!(managed.info.privacy_profile.as_deref(), Some("contoso-app"));
    assert_eq!(
        managed.info.privacy_profile_version.as_deref(),
        Some("1.0.0")
    );
    assert_eq!(
        managed.info.privacy_profile_hash,
        Some(content_hash(&content("1.0.0")))
    );
    assert_eq!(managed.info.hash, local.info.hash);
    assert_eq!(
        managed.info.privacy_profile_hash,
        local.info.privacy_profile_hash
    );
}

#[test]
fn bundle_tampered_cache_fails_closed() {
    for tamper in [
        "content",
        "contentHash",
        "signature",
        "collectorId",
        "signed-for-another-collector",
        "signed-wrong-hash",
        "untrusted-key",
        "missing-field",
        "truncated",
    ] {
        let fixture = Fixture::new();
        fixture.write_cache(&tampered(tamper, &fixture.private_pem, &content("1.0.0")));

        let error = bundle::load(&fixture.settings).err().unwrap();
        let built = bundle::load(&fixture.settings).and_then(|loaded| {
            host::build(fixture.settings.clone(), loaded, BuildOptions::default())
        });

        assert!(built.is_err(), "{tamper}");
        assert_eq!(error.kind, "ManagedPrivacyProfileException", "{tamper}");
        assert!(
            error.message.starts_with(&format!(
                "Managed privacy profile cache {} failed verification: ",
                fixture.cache_path().display()
            )),
            "{tamper}: {}",
            error.message
        );
        assert!(
            error.message.ends_with(
                " Delete the cache file to start with the built-in default privacy profile."
            ),
            "{tamper}"
        );
        assert!(!error.message.contains("actor.username"), "{tamper}");
    }
}

#[test]
fn bundle_rejects_pack_privacy_profile_in_managed_mode() {
    let fixture = Fixture::new();
    let pair = bower_integrity::generate_key_pair();
    let pack = bower_packs::build(
        &repo_root().join("packs/linux-ssh-gateway"),
        &pair.private_key_pem,
        fixture.directory.path(),
        None,
    )
    .unwrap();
    let key = fixture.directory.path().join("pack.pem");
    std::fs::write(&key, &pair.public_key_pem).unwrap();
    let mut settings = fixture.settings.clone();
    settings.packs = vec![pack.to_string_lossy().into_owned()];
    settings.pack_trusted_key_files = vec![key.to_string_lossy().into_owned()];

    let error = bundle::load(&settings).err().unwrap();

    assert_eq!(error.kind, "InvalidDataException");
    assert_eq!(
        error.message,
        "BOWER_PRIVACY_PROFILE_SOURCE=management cannot be combined with pack privacy profiles."
    );
}

// ------------------------------------------------------------------ host

struct StaticCredential;

impl AccessTokenSource for StaticCredential {
    fn access_token<'a>(&'a self, _: &'a str) -> TokenFuture<'a> {
        Box::pin(async { Ok("test-token".to_string()) })
    }
}

#[tokio::test]
async fn host_reports_managed_privacy_profile_in_status_and_registers_sync_job() {
    let fixture = Fixture::new();
    let mut settings = fixture.settings.clone();
    settings.ingest_token = Some(TOKEN.into());
    fixture.write_cache(&valid_document(&fixture));
    let loaded = bundle::load(&settings).unwrap();
    let mut collector = host::build(
        settings,
        loaded,
        BuildOptions {
            credential: Some(Arc::new(StaticCredential)),
            ..BuildOptions::default()
        },
    )
    .unwrap();
    collector.initialize().await.unwrap();

    let response = collector
        .router
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status = String::from_utf8(body.to_vec()).unwrap();

    let hash = content_hash(&content("1.0.0"));
    assert!(status.contains(&format!(
        "\"privacyProfile\":\"contoso-app\",\"privacyProfileVersion\":\"1.0.0\",\"privacyProfileHash\":\"{hash}\",\"privacyProfileSource\":\"management\"}}"
    )), "{status}");
    assert!(status.contains(&format!("\"id\":\"{MANAGED_PRIVACY_PROFILE_JOB_ID}\"")));
}

#[tokio::test]
async fn local_status_reports_default_privacy_profile_hash() {
    let fixture = Fixture::new();
    let mut settings = fixture.local();
    settings.management_endpoint = None;
    settings.ingest_token = Some(TOKEN.into());
    let loaded = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings, loaded, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();

    let response = collector
        .router
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status = String::from_utf8(body.to_vec()).unwrap();

    assert!(status.contains(
        "\"privacyProfile\":null,\"privacyProfileVersion\":null,\"privacyProfileHash\":\"default\",\"privacyProfileSource\":\"local\"}"
    ), "{status}");
    assert!(!status.contains(MANAGED_PRIVACY_PROFILE_JOB_ID));
}

/// A restart request stops a running host gracefully and is reported for exit code 75.
#[tokio::test]
async fn restart_request_stops_the_host_gracefully() {
    let fixture = Fixture::new();
    let mut settings = fixture.local();
    settings.management_endpoint = None;
    let loaded = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings, loaded, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    let lifetime = collector.lifetime();
    let listeners = server::bind(&["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let address = listeners[0].local_addr().unwrap();
    let running = tokio::spawn(collector.run(listeners, shutdown::ShutdownToken::never()));
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("http://{address}/health"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(!lifetime.restart_requested());

    lifetime.request_restart();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .unwrap()
        .unwrap();

    assert!(lifetime.restart_requested());
    assert_eq!(RESTART_EXIT_CODE, 75);
    assert!(
        client
            .get(format!("http://{address}/health"))
            .send()
            .await
            .is_err()
    );
}

// ------------------------------------------------------------------ sync job

#[derive(Clone, Debug)]
struct Recorded {
    method: Method,
    path: String,
    authorization: Option<String>,
    body: String,
}

type Responder = Arc<dyn Fn() -> Response + Send + Sync>;

/// Fake management API on a loopback listener.
struct MockManagement {
    base: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockManagement {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn mock(respond: impl Fn() -> Response + Send + Sync + 'static) -> MockManagement {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let respond: Responder = Arc::new(respond);
    let recorded = Arc::clone(&requests);
    let router = Router::new().fallback(
        move |method: Method, uri: Uri, headers: HeaderMap, body: String| {
            let (recorded, respond) = (Arc::clone(&recorded), Arc::clone(&respond));
            async move {
                recorded.lock().unwrap().push(Recorded {
                    method,
                    path: uri.path().to_string(),
                    authorization: headers
                        .get(header::AUTHORIZATION)
                        .map(|value| value.to_str().unwrap().to_string()),
                    body,
                });
                respond()
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    MockManagement {
        base: format!("http://{address}/"),
        requests,
        server,
    }
}

fn ok(body: Vec<u8>) -> impl Fn() -> Response + Send + Sync + 'static {
    move || (StatusCode::OK, body.clone()).into_response()
}

fn status(code: StatusCode) -> impl Fn() -> Response + Send + Sync + 'static {
    move || code.into_response()
}

/// C# `Harness`: the job wired to the fake management API and a recording lifetime.
fn harness(fixture: &Fixture, base: &str) -> ManagedPrivacyProfileJob {
    let loaded = bundle::load(&fixture.settings).unwrap();
    ManagedPrivacyProfileJob {
        client: reqwest::Client::new(),
        base: base.parse().unwrap(),
        credential: Arc::new(StaticCredential),
        settings: fixture.settings.clone(),
        active_hash: loaded.info.privacy_profile_hash,
        lifetime: ApplicationLifetime::new(),
    }
}

#[tokio::test]
async fn sync_same_hash_is_a_no_op() {
    let fixture = Fixture::new();
    let current = valid_document(&fixture);
    fixture.write_cache(&current);
    // Different bytes (new issuedAt), same content hash: nothing to apply.
    let reissued = document(
        &fixture.private_pem,
        &DocumentSpec {
            issued_at: "2026-10-24T09:00:00.0000000Z".into(),
            ..DocumentSpec::default()
        },
    );
    let management = mock(ok(reissued)).await;
    let job = harness(&fixture, &management.base);

    job.run().await.unwrap();

    assert_eq!(std::fs::read(fixture.cache_path()).unwrap(), current);
    assert_eq!(job.lifetime.stop_calls(), 0);
    let requests = management.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].path, DEPLOYMENT_PATH);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer test-token")
    );
}

#[tokio::test]
async fn sync_new_version_is_staged_atomically_then_restarts() {
    let fixture = Fixture::new();
    fixture.write_cache(&valid_document(&fixture));
    let next = document(
        &fixture.private_pem,
        &DocumentSpec {
            content: content("1.1.0"),
            version_id: "11111111111111111111111111111111".into(),
            ..DocumentSpec::default()
        },
    );
    let management = mock(ok(next.clone())).await;
    let job = harness(&fixture, &management.base);

    job.run().await.unwrap();

    assert_eq!(std::fs::read(fixture.cache_path()).unwrap(), next);
    assert_eq!(job.lifetime.stop_calls(), 1);
    // Exit 75, not 0, so Restart=on-failure supervisors bring the collector back.
    assert!(job.lifetime.restart_requested());
    assert!(job.lifetime.stopping().is_cancelled());
    assert_eq!(fixture.cache_files(), [CACHE_FILE_NAME]);
    // The staged cache is what the restarted host verifies and loads.
    assert_eq!(
        bundle::load(&fixture.settings)
            .unwrap()
            .info
            .privacy_profile_version
            .as_deref(),
        Some("1.1.0")
    );
}

#[tokio::test]
async fn sync_first_assignment_on_default_profile_is_staged() {
    let fixture = Fixture::new();
    let current = valid_document(&fixture);
    let management = mock(ok(current.clone())).await;
    let job = harness(&fixture, &management.base);

    job.run().await.unwrap();

    assert_eq!(std::fs::read(fixture.cache_path()).unwrap(), current);
    assert_eq!(job.lifetime.stop_calls(), 1);
    assert!(job.lifetime.restart_requested());
}

#[tokio::test]
async fn sync_unverified_content_is_never_written() {
    for tamper in [
        "content",
        "signature",
        "signed-for-another-collector",
        "signed-wrong-hash",
        "signed-invalid-content",
        "untrusted-key",
        "truncated",
    ] {
        let fixture = Fixture::new();
        let current = valid_document(&fixture);
        fixture.write_cache(&current);
        let management = mock(ok(tampered(
            tamper,
            &fixture.private_pem,
            &content("2.0.0"),
        )))
        .await;
        let job = harness(&fixture, &management.base);

        assert_eq!(
            job.run().await,
            Err("ManagedPrivacyProfileException"),
            "{tamper}"
        );

        assert_eq!(
            std::fs::read(fixture.cache_path()).unwrap(),
            current,
            "{tamper}"
        );
        assert_eq!(fixture.cache_files(), [CACHE_FILE_NAME], "{tamper}");
        assert_eq!(job.lifetime.stop_calls(), 0, "{tamper}");
        assert!(!job.lifetime.restart_requested(), "{tamper}");
    }
}

#[tokio::test]
async fn sync_unverified_first_assignment_leaves_no_cache() {
    let fixture = Fixture::new();
    let management = mock(ok(tampered(
        "signature",
        &fixture.private_pem,
        &content("1.0.0"),
    )))
    .await;
    let job = harness(&fixture, &management.base);

    assert_eq!(job.run().await, Err("ManagedPrivacyProfileException"));

    assert!(!fixture.settings.managed_privacy_cache_directory().exists());
    assert_eq!(job.lifetime.stop_calls(), 0);
}

#[tokio::test]
async fn sync_no_content_clears_the_cache_and_restarts() {
    let fixture = Fixture::new();
    fixture.write_cache(&valid_document(&fixture));
    let management = mock(status(StatusCode::NO_CONTENT)).await;
    let cleared = harness(&fixture, &management.base);

    cleared.run().await.unwrap();
    let already_default = harness(&fixture, &management.base);
    already_default.run().await.unwrap();

    assert!(!fixture.cache_path().exists());
    assert_eq!(cleared.lifetime.stop_calls(), 1);
    assert!(cleared.lifetime.restart_requested());
    assert_eq!(already_default.lifetime.stop_calls(), 0);
}

#[tokio::test]
async fn sync_network_and_server_failures_keep_the_current_profile() {
    let fixture = Fixture::new();
    let current = valid_document(&fixture);
    fixture.write_cache(&current);
    let unavailable = mock(status(StatusCode::SERVICE_UNAVAILABLE)).await;
    let unauthorized = mock(status(StatusCode::FORBIDDEN)).await;
    let not_active = mock(status(StatusCode::CONFLICT)).await;
    let oversized = mock(ok(vec![b' '; MAXIMUM_DOCUMENT_BYTES + 1])).await;
    let jobs = [
        harness(&fixture, "http://127.0.0.1:9/"),
        harness(&fixture, &unavailable.base),
        harness(&fixture, &unauthorized.base),
        harness(&fixture, &not_active.base),
        harness(&fixture, &oversized.base),
    ];

    assert_eq!(jobs[0].run().await, Err("HttpRequestException"));
    assert_eq!(jobs[1].run().await, Err("ManagedPrivacyProfileException"));
    assert_eq!(jobs[2].run().await, Err("ManagedPrivacyProfileException"));
    assert_eq!(jobs[3].run().await, Ok(()));
    assert_eq!(jobs[4].run().await, Err("ManagedPrivacyProfileException"));

    assert_eq!(std::fs::read(fixture.cache_path()).unwrap(), current);
    assert_eq!(fixture.cache_files(), [CACHE_FILE_NAME]);
    assert!(jobs.iter().all(|job| job.lifetime.stop_calls() == 0));
}

/// A chunked body without Content-Length is still bounded while it streams.
#[tokio::test]
async fn sync_bounds_chunked_bodies_without_content_length() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let chunk = vec![b' '; 64 * 1024];
        for _ in 0..(MAXIMUM_DOCUMENT_BYTES / chunk.len() + 2) {
            let header = format!("{:x}\r\n", chunk.len());
            if socket.write_all(header.as_bytes()).await.is_err()
                || socket.write_all(&chunk).await.is_err()
                || socket.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    let job = harness(&fixture, &format!("http://{address}/"));

    assert_eq!(job.run().await, Err("ManagedPrivacyProfileException"));

    assert!(!fixture.cache_path().exists());
    assert_eq!(job.lifetime.stop_calls(), 0);
    server.abort();
}

#[tokio::test]
async fn heartbeat_reports_the_active_privacy_profile_hash() {
    let fixture = Fixture::new();
    fixture.write_cache(&valid_document(&fixture));
    let managed = bundle::load(&fixture.settings).unwrap();
    let local = bundle::load(&fixture.local()).unwrap();

    let managed_body = heartbeat_body(&fixture, managed.info.privacy_profile_hash.as_deref()).await;
    let default_body = heartbeat_body(&fixture, local.info.privacy_profile_hash.as_deref()).await;

    let hash = managed.info.privacy_profile_hash.unwrap();
    assert!(
        managed_body.ends_with(&format!(",\"privacyProfileHash\":\"{hash}\"}}")),
        "{managed_body}"
    );
    assert!(
        default_body.ends_with(",\"privacyProfileHash\":\"default\"}"),
        "{default_body}"
    );
}

async fn heartbeat_body(fixture: &Fixture, privacy_profile_hash: Option<&str>) -> String {
    let management = mock(status(StatusCode::OK)).await;
    let mut settings = fixture.settings.clone();
    settings.management_endpoint = Some(management.base.parse().unwrap());
    let store = Arc::new(
        bower_persistence::SqliteEventStore::new(
            &settings.queue_path,
            settings.maximum_queue_bytes,
            None,
        )
        .unwrap(),
    );
    store.initialize().unwrap();
    let heartbeat = ManagementHeartbeat::from_settings(
        &settings,
        "sha256:policy".into(),
        privacy_profile_hash,
        Arc::new(StaticCredential),
        store,
        Arc::new(JobCatalog::default()),
    )
    .unwrap();

    heartbeat.run().await.unwrap();

    let requests = management.requests.lock().unwrap().clone();
    requests
        .into_iter()
        .find(|request| request.path.ends_with("/heartbeat"))
        .expect("no heartbeat was sent")
        .body
}
