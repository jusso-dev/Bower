//! Port of `ManagedPrivacyProfileTests` (C# `Bower.Collector` managed privacy profile
//! mode: signed assignment envelopes with revisions, explicit signed clears, rollback
//! protection and the fail-closed first sync) plus cross-implementation vectors from
//! `fixtures/csharp-managed-privacy.json`, produced by
//! `rust/tools/csharp-vectors/ZzManagedPrivacyVectors.cs`:
//! - `cases`: envelopes signed by the C# code and C#'s `Verify` verdict on each;
//! - `scenarios`: the real C# `ManagedPrivacyProfileJob` run against a cached envelope and
//!   one management response, with the gate state, cache and restart outcome.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use bower_collector::heartbeat::{AccessTokenSource, ManagementHeartbeat, TokenFuture};
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::jobs::{JobCatalog, MANAGED_PRIVACY_PROFILE_JOB_ID};
use bower_collector::managed_privacy::{
    self, ACTION_ASSIGNED, ACTION_CLEARED, CACHE_FILE_NAME, MAXIMUM_DOCUMENT_BYTES,
    ManagedPrivacyProfileJob, ManagedPrivacyState, RESTART_EXIT_CODE, STATE_ASSIGNED,
    STATE_AWAITING_FIRST_SYNC, STATE_CLEARED, STATE_DEFAULT_ALLOWED, STATE_NEVER_ASSIGNED,
    STATE_RESTART_PENDING,
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
const GATE_BODY: &str = "{\"error\":\"Collector is waiting for its managed privacy profile from management; retry later.\"}";

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

/// C# `Settings(directory, trustedKeyFile)` with a generated signing key.
struct Fixture {
    directory: tempfile::TempDir,
    settings: CollectorSettings,
    private_pem: String,
}

impl Fixture {
    fn new() -> Self {
        let pair = bower_integrity::generate_key_pair();
        Self::with_key(COLLECTOR_ID, &pair.public_key_pem, pair.private_key_pem)
    }

    fn with_key(collector_id: &str, public_pem: &str, private_pem: String) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let trusted = directory.path().join("managed-privacy-trusted.pem");
        std::fs::write(&trusted, public_pem).unwrap();
        let hmac = directory.path().join("hmac.key");
        std::fs::write(&hmac, HMAC_KEY_BASE64).unwrap();
        let mut settings = CollectorSettings::new(
            "http://127.0.0.1:4319",
            directory.path().join("queue.db"),
            repo_root().join("policies/default"),
            collector_id,
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
            private_pem,
        }
    }

    fn cache_path(&self) -> PathBuf {
        managed_privacy::cache_path(&self.settings)
    }

    fn write_cache(&self, document: &[u8]) {
        std::fs::create_dir_all(self.settings.managed_privacy_cache_directory()).unwrap();
        std::fs::write(self.cache_path(), document).unwrap();
    }

    fn cache(&self) -> Vec<u8> {
        std::fs::read(self.cache_path()).unwrap()
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

    /// C# `Document(...)`: a signed `assigned` envelope.
    fn assigned(&self, spec: &Spec) -> Vec<u8> {
        serde_json::to_vec(&assigned_value(&self.private_pem, spec)).unwrap()
    }

    /// C# `ClearedDocument(...)`: a signed explicit clear.
    fn cleared(&self, revision: i64) -> Vec<u8> {
        cleared_document(&self.private_pem, revision, COLLECTOR_ID)
    }
}

#[derive(Clone)]
struct Spec {
    content: String,
    collector_id: String,
    content_hash: Option<String>,
    version_id: String,
    issued_at: String,
    revision: i64,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            content: content("1.0.0"),
            collector_id: COLLECTOR_ID.into(),
            content_hash: None,
            version_id: "0123456789abcdef0123456789abcdef".into(),
            issued_at: "2026-10-24T00:00:00.0000000Z".into(),
            revision: 1,
        }
    }
}

fn spec(revision: i64, version: &str) -> Spec {
    Spec {
        content: content(version),
        revision,
        ..Spec::default()
    }
}

fn signature_value(private_pem: &str, payload: &[u8]) -> Value {
    let signature = bower_integrity::sign(payload, private_pem).unwrap();
    json!({"algorithm": signature.algorithm, "keyId": signature.key_id, "value": signature.value})
}

fn assigned_value(private_pem: &str, spec: &Spec) -> Value {
    let loaded = bower_redaction::load_privacy_profile(&spec.content, Some(&HMAC_KEY), None).ok();
    let profile_id = loaded
        .as_ref()
        .and_then(|profile| profile.id.clone())
        .unwrap_or_else(|| "contoso-app".into());
    let version = loaded
        .as_ref()
        .and_then(|profile| profile.version.clone())
        .unwrap_or_else(|| "9.9.9".into());
    let hash = spec.content_hash.clone().unwrap_or_else(|| {
        loaded
            .as_ref()
            .map(|profile| profile.hash.clone())
            .unwrap_or_else(|| format!("sha256:{}", "0".repeat(64)))
    });
    let payload = managed_privacy::signed_bytes(
        &spec.collector_id,
        spec.revision,
        ACTION_ASSIGNED,
        Some(&spec.version_id),
        Some(&profile_id),
        Some(&version),
        Some(&hash),
        Some(&spec.content),
        &spec.issued_at,
    );
    json!({
        "collectorId": spec.collector_id,
        "assignmentRevision": spec.revision,
        "action": ACTION_ASSIGNED,
        "versionId": spec.version_id,
        "profileId": profile_id,
        "version": version,
        "contentHash": hash,
        "content": spec.content,
        "issuedAt": spec.issued_at,
        "signature": signature_value(private_pem, &payload),
    })
}

fn cleared_document(private_pem: &str, revision: i64, collector_id: &str) -> Vec<u8> {
    let issued_at = "2026-10-24T01:00:00.0000000Z";
    let payload = managed_privacy::signed_bytes(
        collector_id,
        revision,
        ACTION_CLEARED,
        None,
        None,
        None,
        None,
        None,
        issued_at,
    );
    serde_json::to_vec(&json!({
        "collectorId": collector_id,
        "assignmentRevision": revision,
        "action": ACTION_CLEARED,
        "issuedAt": issued_at,
        "signature": signature_value(private_pem, &payload),
    }))
    .unwrap()
}

/// C# `Tampered(tamper, privatePem, content, revision)`.
fn tampered(fixture: &Fixture, tamper: &str, body: &str, revision: i64) -> Vec<u8> {
    let spec = Spec {
        content: body.into(),
        revision,
        ..Spec::default()
    };
    let valid = assigned_value(&fixture.private_pem, &spec);
    let mutate = |change: &dyn Fn(&mut Value)| {
        let mut copy = valid.clone();
        change(&mut copy);
        serde_json::to_vec(&copy).unwrap()
    };
    let signed = |change: &dyn Fn(&mut Spec)| {
        let mut changed = spec.clone();
        change(&mut changed);
        fixture.assigned(&changed)
    };
    match tamper {
        "content" => mutate(&|d| d["content"] = json!(body.replace("remove", "allow"))),
        "contentHash" => {
            mutate(&|d| d["contentHash"] = json!(format!("sha256:{}", "a".repeat(64))))
        }
        "signature" => mutate(&|d| {
            d["signature"]["value"] = json!(format!("{}==", "A".repeat(86)));
        }),
        "collectorId" => mutate(&|d| d["collectorId"] = json!("collector-other")),
        "missing-field" => mutate(&|d| {
            d.as_object_mut().unwrap().shift_remove("issuedAt");
        }),
        "revision" => mutate(&|d| d["assignmentRevision"] = json!(revision + 100)),
        "revision-zero" => mutate(&|d| d["assignmentRevision"] = json!(0)),
        "revision-string" => mutate(&|d| d["assignmentRevision"] = json!(revision.to_string())),
        "missing-revision" => mutate(&|d| {
            d.as_object_mut()
                .unwrap()
                .shift_remove("assignmentRevision");
        }),
        "action" => mutate(&|d| d["action"] = json!("cleared")),
        "unknown-action" => mutate(&|d| d["action"] = json!("rollback")),
        "unsigned-extra-field" => mutate(&|d| d["note"] = json!("not signed")),
        "signed-for-another-collector" => signed(&|s| s.collector_id = "collector-other".into()),
        "signed-wrong-hash" => {
            signed(&|s| s.content_hash = Some(format!("sha256:{}", "b".repeat(64))))
        }
        "signed-invalid-content" => {
            signed(&|s| s.content = s.content.replace("id.email", "not-a-detector"))
        }
        "untrusted-key" => serde_json::to_vec(&assigned_value(
            &bower_integrity::generate_key_pair().private_key_pem,
            &spec,
        ))
        .unwrap(),
        "cleared-with-profile-fields" => {
            let mut document: Value = serde_json::from_slice(&fixture.cleared(revision)).unwrap();
            document["content"] = json!(content("9.0.0"));
            serde_json::to_vec(&document).unwrap()
        }
        "cleared-for-another-collector" => {
            cleared_document(&fixture.private_pem, revision, "collector-other")
        }
        "truncated" => {
            let bytes = serde_json::to_vec(&valid).unwrap();
            bytes[..bytes.len() / 2].to_vec()
        }
        other => panic!("unknown tamper {other}"),
    }
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

fn optional_text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

/// YAML parser messages come from different libraries (YamlDotNet vs serde_yaml), as in
/// bower-redaction's parity tests: compare the Bower-authored prefix up to the parser
/// text. Returns whether the message was a YAML parser message.
fn assert_same_message(name: &str, actual: &str, expected: &str) -> bool {
    const YAML_PREFIX: &str = "failed validation: Privacy profile is invalid at line ";
    match expected.find(YAML_PREFIX) {
        Some(at) => {
            let line_end = expected[at + YAML_PREFIX.len()..].find(": ").unwrap();
            let prefix = &expected[..at + YAML_PREFIX.len() + line_end + 2];
            assert!(actual.starts_with(prefix), "{name}: {actual} vs {prefix}");
            true
        }
        None => {
            assert_eq!(actual, expected, "{name}");
            false
        }
    }
}

#[test]
fn csharp_signed_envelopes_verify_exactly_as_csharp_does() {
    let vectors = vectors();
    assert_eq!(vectors["hmacKey"], HMAC_KEY_BASE64);
    let collector_id = vectors["collectorId"].as_str().unwrap();
    // Non-ASCII and HTML-sensitive characters in the signed collector id.
    assert!(collector_id.contains("<&>'\"+`") && !collector_id.is_ascii());
    let trusted = vec![vectors["publicKey"].as_str().unwrap().to_string()];
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 100, "{} cases", cases.len());
    let (mut accepted, mut cleared, mut yaml_messages) = (0, 0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bytes = base64_decode(case["document"].as_str().unwrap());
        let expected = &case["result"];
        let actual = managed_privacy::verify(&bytes, collector_id, &trusted, Some(&HMAC_KEY), "k1");
        if expected["ok"].as_bool().unwrap() {
            let verified = actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(verified.action, expected["action"], "{name}");
            assert_eq!(
                Some(verified.assignment_revision),
                expected["assignmentRevision"].as_i64(),
                "{name}"
            );
            assert_eq!(
                verified.version_id,
                optional_text(&expected["versionId"]),
                "{name}"
            );
            assert_eq!(
                verified.profile_id,
                optional_text(&expected["profileId"]),
                "{name}"
            );
            assert_eq!(
                verified.version,
                optional_text(&expected["version"]),
                "{name}"
            );
            assert_eq!(
                verified.content_hash,
                optional_text(&expected["contentHash"]),
                "{name}"
            );
            assert_eq!(
                verified.profile.map(|profile| profile.hash),
                optional_text(&expected["profileHash"]),
                "{name}"
            );
            assert_eq!(
                verified.signed_payload,
                base64_decode(expected["signedPayload"].as_str().unwrap()),
                "{name}"
            );
            accepted += 1;
            cleared += usize::from(verified.action == ACTION_CLEARED);
        } else {
            assert_eq!(
                expected["type"], "ManagedPrivacyProfileException",
                "{name}: C# threw a different exception type"
            );
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: Rust accepted it"));
            if assert_same_message(name, error.message(), expected["message"].as_str().unwrap()) {
                yaml_messages += 1;
            }
        }
    }
    assert!(
        accepted >= 15 && cleared >= 4,
        "{accepted} accepted, {cleared} cleared"
    );
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
        let field = |name: &str| document[name].as_str();
        let actual = managed_privacy::signed_bytes(
            field("collectorId").unwrap(),
            document["assignmentRevision"].as_i64().unwrap(),
            field("action").unwrap(),
            field("versionId"),
            field("profileId"),
            field("version"),
            field("contentHash"),
            field("content"),
            field("issuedAt").unwrap(),
        );
        assert_eq!(
            String::from_utf8(actual).unwrap(),
            String::from_utf8(base64_decode(expected)).unwrap(),
            "{}",
            case["name"]
        );
        compared += 1;
    }
    assert_eq!(compared, 5);
    // The content really exercises the escaper: non-ASCII, <>&'"+`, LF and tab.
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
fn csharp_management_signed_envelopes_load_at_start_up() {
    let vectors = vectors();
    for (name, expected_hash) in [
        (
            "valid-management-signer-assigned",
            vectors["contentHash"].as_str(),
        ),
        ("valid-management-signer-cleared", None),
    ] {
        let case = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let fixture = Fixture::with_key(
            vectors["collectorId"].as_str().unwrap(),
            vectors["publicKey"].as_str().unwrap(),
            String::new(),
        );
        fixture.write_cache(&base64_decode(case["document"].as_str().unwrap()));

        let loaded = bundle::load(&fixture.settings).unwrap();

        assert_eq!(
            loaded.info.privacy_profile_hash.as_deref(),
            expected_hash,
            "{name}"
        );
        let cached = loaded.managed_privacy.unwrap();
        let state = ManagedPrivacyState::new(Some(&cached), false);
        assert!(state.accepts_events());
        assert_eq!(
            state.revision(),
            case["result"]["assignmentRevision"].as_i64()
        );
    }
}

// ------------------------------------------------------------------ C# job scenarios

type Responder = Arc<dyn Fn() -> Response + Send + Sync>;

#[derive(Clone, Debug)]
struct Recorded {
    method: Method,
    path: String,
    authorization: Option<String>,
    body: String,
}

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

struct StaticCredential;

impl AccessTokenSource for StaticCredential {
    fn access_token<'a>(&'a self, _: &'a str) -> TokenFuture<'a> {
        Box::pin(async { Ok("test-token".to_string()) })
    }
}

/// C# `Harness`: one collector process. The bundle and ingest gate are loaded from the
/// cache as at start-up, so a new harness over the same settings models a restart.
struct Harness {
    job: ManagedPrivacyProfileJob,
    privacy_profile_version: Option<String>,
    privacy_profile_hash: Option<String>,
}

impl Harness {
    fn new(settings: &CollectorSettings, base: &str) -> Self {
        let loaded = bundle::load(settings).unwrap();
        let state = Arc::new(ManagedPrivacyState::new(
            loaded.managed_privacy.as_ref(),
            settings.managed_privacy_allow_default,
        ));
        Self {
            job: ManagedPrivacyProfileJob {
                client: reqwest::Client::new(),
                base: base.parse().unwrap(),
                credential: Arc::new(StaticCredential),
                settings: settings.clone(),
                active_hash: loaded.info.privacy_profile_hash.clone(),
                state,
                lifetime: ApplicationLifetime::new(),
            },
            privacy_profile_version: loaded.info.privacy_profile_version,
            privacy_profile_hash: loaded.info.privacy_profile_hash,
        }
    }

    fn state(&self) -> (&'static str, Option<i64>, bool) {
        let state = &self.job.state;
        (state.state(), state.revision(), state.accepts_events())
    }

    fn stop_calls(&self) -> usize {
        self.job.lifetime.stop_calls()
    }
}

fn state_of(value: &Value) -> (String, Option<i64>, bool) {
    (
        value["state"].as_str().unwrap().to_string(),
        value["revision"].as_i64(),
        value["acceptsEvents"].as_bool().unwrap(),
    )
}

fn owned(state: (&'static str, Option<i64>, bool)) -> (String, Option<i64>, bool) {
    (state.0.to_string(), state.1, state.2)
}

#[tokio::test]
async fn csharp_sync_scenarios_behave_identically() {
    let vectors = vectors();
    let collector_id = vectors["collectorId"].as_str().unwrap();
    let public = vectors["publicKey"].as_str().unwrap();
    let scenarios = vectors["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 35, "{} scenarios", scenarios.len());
    let mut restarts = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let mut fixture = Fixture::with_key(collector_id, public, String::new());
        fixture.settings.managed_privacy_allow_default =
            scenario["allowDefault"].as_bool().unwrap();
        let cache = scenario["cache"].as_str().map(base64_decode);
        if let Some(cache) = &cache {
            fixture.write_cache(cache);
        }
        let body = match (
            scenario["body"].as_str(),
            scenario["zeroBodyLength"].as_u64(),
        ) {
            (Some(body), _) => Some(base64_decode(body)),
            (None, Some(length)) => Some(vec![0u8; usize::try_from(length).unwrap()]),
            (None, None) => None,
        };
        let code =
            StatusCode::from_u16(u16::try_from(scenario["status"].as_u64().unwrap()).unwrap())
                .unwrap();
        let response_body = body.clone();
        let management = mock(move || match &response_body {
            Some(body) => (code, body.clone()).into_response(),
            None => code.into_response(),
        })
        .await;
        let harness = Harness::new(&fixture.settings, &management.base);
        let initial = &scenario["initial"];
        assert_eq!(owned(harness.state()), state_of(initial), "{name}: initial");
        assert_eq!(
            harness.privacy_profile_hash,
            optional_text(&initial["privacyProfileHash"]),
            "{name}"
        );
        if scenario["tamperCacheAfterStart"].as_bool().unwrap() {
            let text = String::from_utf8(cache.clone().unwrap()).unwrap();
            fixture.write_cache(text.replace("remove", "hash").as_bytes());
        }
        let before = std::fs::read(fixture.cache_path()).ok();

        let outcome = harness.job.sync().await;

        match &scenario["error"] {
            Value::Null => assert_eq!(outcome, Ok(()), "{name}"),
            expected => {
                let failure = outcome.expect_err(name);
                assert_eq!(failure.kind, expected["type"], "{name}");
                let message = failure
                    .message
                    .replace(&fixture.cache_path().display().to_string(), "{cachePath}");
                assert_eq!(message, expected["message"], "{name}");
            }
        }
        let after = std::fs::read(fixture.cache_path()).ok();
        let cache_after = match (&after, &before, &body) {
            (None, _, _) => "none",
            (Some(after), Some(before), _) if after == before => "unchanged",
            (Some(after), _, Some(body)) if after == body => "received",
            _ => "other",
        };
        assert_eq!(cache_after, scenario["cacheAfter"], "{name}: cache");
        let last = &scenario["final"];
        assert_eq!(owned(harness.state()), state_of(last), "{name}: final");
        assert_eq!(
            harness.stop_calls() as u64,
            last["stopCalls"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            harness.job.lifetime.restart_requested(),
            harness.stop_calls() > 0,
            "{name}"
        );
        restarts += harness.stop_calls();
        let restarted = match bundle::load(&fixture.settings) {
            Ok(loaded) => loaded
                .info
                .privacy_profile_hash
                .unwrap_or_else(|| "default".into()),
            Err(error) if error.kind == "ManagedPrivacyProfileException" => "start-up-fails".into(),
            Err(error) => panic!("{name}: {error}"),
        };
        assert_eq!(restarted, scenario["restartedPrivacyProfileHash"], "{name}");
        // Only the cache file is ever left in the directory.
        assert!(
            fixture
                .cache_files()
                .iter()
                .all(|file| file == CACHE_FILE_NAME),
            "{name}"
        );
    }
    assert!(restarts >= 6, "{restarts} restarts");
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
    let with = |variable: &'static str, value: Option<&'static str>| {
        let base = base.clone();
        CollectorSettings::from_environment(move |name| {
            if name == variable {
                value.map(str::to_string)
            } else {
                base(name)
            }
        })
    };

    let settings = CollectorSettings::from_environment(&base).unwrap();
    let custom = with(
        "BOWER_MANAGED_PRIVACY_DIRECTORY",
        Some("/var/lib/bower/privacy"),
    )
    .unwrap();
    let invalid = with("BOWER_PRIVACY_PROFILE_SOURCE", Some("pack")).unwrap_err();
    let local = with("BOWER_PRIVACY_PROFILE_SOURCE", None).unwrap();
    let allow = with("BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT", Some("TRUE")).unwrap();
    let padded = with("BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT", Some(" true")).unwrap();
    let yes = with("BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT", Some("yes")).unwrap();

    assert!(settings.uses_managed_privacy_profile());
    assert!(!settings.managed_privacy_allow_default);
    assert!(allow.managed_privacy_allow_default);
    // string.Equals(value, "true", OrdinalIgnoreCase): no trimming, no synonyms.
    assert!(!padded.managed_privacy_allow_default && !yes.managed_privacy_allow_default);
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
    without_keys.managed_privacy_allow_default = true;
    assert_eq!(
        local.configuration_hash(),
        without_keys.configuration_hash()
    );
    assert_ne!(settings.configuration_hash(), allow.configuration_hash());
    assert_ne!(local.configuration_hash(), settings.configuration_hash());
}

#[test]
fn configuration_hash_appends_the_management_settings_like_csharp() {
    use sha2::{Digest, Sha256};
    let fixture = Fixture::new();
    let local = fixture.local();
    let mut managed = local.clone();
    managed.privacy_profile_source = PRIVACY_PROFILE_SOURCE_MANAGEMENT.into();
    let mut allowing = managed.clone();
    allowing.managed_privacy_allow_default = true;
    let material = format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}\u{1f}\u{1f}ManagedIdentity\u{1f}10737418240\u{1f}168\u{1f}500\u{1f}20\u{1f}False\u{1f}k1\u{1f}False\u{1f}",
        local.listen_url, local.output_type, local.stream_name
    );
    let hash = |text: String| format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())));
    assert_eq!(local.configuration_hash(), hash(material.clone()));
    assert_eq!(
        managed.configuration_hash(),
        hash(material.clone() + "\u{1f}privacy-source:management\u{1f}privacy-allow-default:False")
    );
    assert_eq!(
        allowing.configuration_hash(),
        hash(material + "\u{1f}privacy-source:management\u{1f}privacy-allow-default:True")
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
    assert!(managed.managed_privacy.is_none());
    assert_eq!(
        managed.info.privacy_profile_source,
        PRIVACY_PROFILE_SOURCE_MANAGEMENT
    );
    assert_eq!(managed.info.hash, local.info.hash);
}

#[test]
fn bundle_loads_verified_cache_with_the_same_hash_as_a_local_profile() {
    let fixture = Fixture::new();
    fixture.write_cache(&fixture.assigned(&Spec::default()));
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
    assert_eq!(managed.managed_privacy.unwrap().assignment_revision, 1);
}

#[test]
fn bundle_cached_clear_is_the_built_in_default() {
    let fixture = Fixture::new();
    fixture.write_cache(&fixture.cleared(6));

    let managed = bundle::load(&fixture.settings).unwrap();
    let local = bundle::load(&fixture.local()).unwrap();

    assert_eq!(managed.info.privacy_profile_hash, None);
    assert_eq!(managed.info.hash, local.info.hash);
    let cached = managed.managed_privacy.unwrap();
    assert!(cached.is_cleared());
    let state = ManagedPrivacyState::new(Some(&cached), false);
    assert_eq!(
        (state.state(), state.revision(), state.accepts_events()),
        (STATE_CLEARED, Some(6), true)
    );
}

#[test]
fn bundle_tampered_cache_fails_closed() {
    let fixture_for_v1 = Fixture::new();
    let mut v1: Value = serde_json::from_slice(&fixture_for_v1.assigned(&Spec::default())).unwrap();
    v1.as_object_mut()
        .unwrap()
        .shift_remove("assignmentRevision");
    v1.as_object_mut().unwrap().shift_remove("action");
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
        "revision",
        "unsigned-extra-field",
        "cleared-with-profile-fields",
        "v1",
    ] {
        let fixture = Fixture::new();
        let document = if tamper == "v1" {
            serde_json::to_vec(&v1).unwrap()
        } else {
            tampered(&fixture, tamper, &content("1.0.0"), 1)
        };
        fixture.write_cache(&document);

        let error = bundle::load(&fixture.settings).err().unwrap();

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
            error
                .message
                .ends_with(" Delete the cache file to fetch the current assignment again."),
            "{tamper}"
        );
        assert!(!error.message.contains("actor.username"), "{tamper}");
        if tamper == "v1" {
            assert!(error.message.contains("document is incomplete."));
        }
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

async fn build(settings: CollectorSettings) -> Collector {
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
    collector
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

fn authorized(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

fn status_request() -> Request<Body> {
    authorized(Request::get("/v1/status"))
        .body(Body::empty())
        .unwrap()
}

/// `TestEvents.AuthenticationFailure` serialized like `BowerJson.Options`.
fn event_request() -> Request<Body> {
    let now = bower_contracts::time::format_json(&bower_contracts::time::now());
    let event_id = uuid::Uuid::new_v4();
    let json = format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"{event_id}","eventOriginalId":"source-1","timeGenerated":"{now}",
        "eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt",
        "eventResult":"failure","eventOutcomeReason":"InvalidPassword",
        "application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"test-user"}},
        "source":{{"ipAddress":"192.0.2.10"}},"request":{{"correlationId":"correlation-1"}}}}"#
    );
    authorized(Request::post("/v1/events"))
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(json))
        .unwrap()
}

#[tokio::test]
async fn host_reports_managed_privacy_profile_in_status_and_registers_sync_job() {
    let fixture = Fixture::new();
    let mut settings = fixture.settings.clone();
    settings.ingest_token = Some(TOKEN.into());
    fixture.write_cache(&fixture.assigned(&Spec::default()));
    let collector = build(settings).await;

    let (_, _, status) = send(&collector.router, status_request()).await;

    let hash = content_hash(&content("1.0.0"));
    assert!(
        status.contains(&format!(
            "\"privacyProfile\":\"contoso-app\",\"privacyProfileVersion\":\"1.0.0\",\"privacyProfileHash\":\"{hash}\",\"privacyProfileSource\":\"management\",\"managedPrivacyProfileState\":\"assigned\",\"managedPrivacyProfileRevision\":1}}"
        )),
        "{status}"
    );
    assert!(status.contains(&format!("\"id\":\"{MANAGED_PRIVACY_PROFILE_JOB_ID}\"")));
}

#[tokio::test]
async fn local_status_reports_no_managed_state() {
    let fixture = Fixture::new();
    let mut settings = fixture.local();
    settings.management_endpoint = None;
    settings.ingest_token = Some(TOKEN.into());
    let collector = build(settings).await;

    let (_, _, status) = send(&collector.router, status_request()).await;

    assert!(
        status.contains(
            "\"privacyProfile\":null,\"privacyProfileVersion\":null,\"privacyProfileHash\":\"default\",\"privacyProfileSource\":\"local\",\"managedPrivacyProfileState\":null,\"managedPrivacyProfileRevision\":null}"
        ),
        "{status}"
    );
    assert!(!status.contains(MANAGED_PRIVACY_PROFILE_JOB_ID));
}

/// C# `Host_GatesIngestInManagementModeUntilTheProfileResolves`.
#[tokio::test]
async fn host_gates_ingest_in_management_mode_until_the_profile_resolves() {
    for (allow_default, cached) in [(false, false), (true, false), (false, true)] {
        let fixture = Fixture::new();
        let mut settings = fixture.settings.clone();
        settings.ingest_token = Some(TOKEN.into());
        settings.single_trust_domain = true;
        settings.managed_privacy_allow_default = allow_default;
        if cached {
            fixture.write_cache(&fixture.assigned(&Spec {
                revision: 9,
                ..Spec::default()
            }));
        }
        let collector = build(settings).await;
        let case = format!("allow_default={allow_default} cached={cached}");

        let (first, first_headers, first_body) = send(&collector.router, event_request()).await;
        let (pack, pack_headers, _) = send(
            &collector.router,
            authorized(Request::post("/v1/packs/none/parsers/0/events"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        let (unauthenticated, _, _) = send(
            &collector.router,
            Request::post("/v1/events")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        let (_, _, status) = send(&collector.router, status_request()).await;
        collector.managed_privacy.mark_never_assigned();
        let (after_resolution, _, _) = send(&collector.router, event_request()).await;

        assert_eq!(unauthenticated, StatusCode::UNAUTHORIZED, "{case}");
        if allow_default || cached {
            assert_eq!(first, StatusCode::ACCEPTED, "{case}: {first_body}");
            let (state, revision) = if cached {
                ("assigned", "9")
            } else {
                ("default-allowed", "null")
            };
            assert!(
                status.contains(&format!(
                    "\"managedPrivacyProfileState\":\"{state}\",\"managedPrivacyProfileRevision\":{revision}}}"
                )),
                "{case}: {status}"
            );
            continue;
        }

        assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE, "{case}");
        assert_eq!(first_headers[header::RETRY_AFTER], "30");
        assert_eq!(
            first_headers[header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(first_body, GATE_BODY);
        assert_eq!(pack, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(pack_headers[header::RETRY_AFTER], "30");
        assert!(
            status.contains("\"managedPrivacyProfileState\":\"awaiting-first-sync\",\"managedPrivacyProfileRevision\":null}"),
            "{status}"
        );
        assert!(status.contains("\"queued\":0"), "{status}");
        assert_eq!(after_resolution, StatusCode::ACCEPTED);
    }
}

/// C# `Host_RunsTheFirstSyncImmediatelyAtStartup`: the sync job (and the heartbeat) run
/// at start-up instead of waiting for the next minute boundary.
#[tokio::test]
async fn host_runs_the_first_sync_immediately_at_startup() {
    let fixture = Fixture::new();
    let collector = build(fixture.settings.clone()).await;
    let catalog = Arc::clone(&collector.catalog);
    let listeners = server::bind(&["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let (trigger, token) = shutdown::channel();
    let running = tokio::spawn(collector.run(listeners, token));

    // The discard-port endpoint refuses the connection, so the run fails fast; what
    // matters is that it ran without waiting for the next minute boundary.
    let last_run = |id: &str| {
        catalog
            .list()
            .into_iter()
            .find(|job| job.id == id)
            .and_then(|job| job.last_run_at)
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while (last_run(MANAGED_PRIVACY_PROFILE_JOB_ID).is_none()
        || last_run("management-heartbeat").is_none())
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(last_run(MANAGED_PRIVACY_PROFILE_JOB_ID).is_some());
    assert!(last_run("management-heartbeat").is_some());
    trigger.cancel();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .unwrap()
        .unwrap();
}

/// A restart request stops a running host gracefully and is reported for exit code 75.
#[tokio::test]
async fn restart_request_stops_the_host_gracefully() {
    let fixture = Fixture::new();
    let mut settings = fixture.local();
    settings.management_endpoint = None;
    let collector = build(settings).await;
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

#[tokio::test]
async fn sync_same_revision_with_the_same_signed_fields_is_a_no_op() {
    let fixture = Fixture::new();
    let current = fixture.assigned(&Spec::default());
    fixture.write_cache(&current);
    // Refetched with different raw bytes (C# signatures are randomized; here the document
    // is re-serialized) but the same signed fields.
    let refetched =
        serde_json::to_vec_pretty(&assigned_value(&fixture.private_pem, &Spec::default())).unwrap();
    assert_ne!(current, refetched);
    let management = mock(ok(refetched)).await;
    let harness = Harness::new(&fixture.settings, &management.base);

    harness.job.run().await.unwrap();

    assert_eq!(fixture.cache(), current);
    assert_eq!(harness.stop_calls(), 0);
    assert_eq!(harness.state(), (STATE_ASSIGNED, Some(1), true));
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
async fn sync_same_revision_with_different_signed_fields_is_rejected() {
    for difference in ["issuedAt", "content", "cleared"] {
        let fixture = Fixture::new();
        let current = fixture.assigned(&spec(4, "1.0.0"));
        fixture.write_cache(&current);
        let conflicting = match difference {
            "issuedAt" => fixture.assigned(&Spec {
                issued_at: "2026-10-24T09:00:00.0000000Z".into(),
                ..spec(4, "1.0.0")
            }),
            "content" => fixture.assigned(&spec(4, "3.0.0")),
            _ => fixture.cleared(4),
        };
        let management = mock(ok(conflicting)).await;
        let harness = Harness::new(&fixture.settings, &management.base);

        let failure = harness.job.sync().await.unwrap_err();

        assert_eq!(failure.kind, "ManagedPrivacyProfileException");
        assert_eq!(
            failure.message,
            "Managed privacy profile assignment revision 4 does not match the cached document.",
            "{difference}"
        );
        assert_eq!(fixture.cache(), current);
        assert_eq!(harness.stop_calls(), 0);
    }
}

#[tokio::test]
async fn sync_new_version_is_staged_atomically_then_restarts() {
    let fixture = Fixture::new();
    fixture.write_cache(&fixture.assigned(&Spec::default()));
    let next = fixture.assigned(&Spec {
        version_id: "11111111111111111111111111111111".into(),
        ..spec(2, "1.1.0")
    });
    let management = mock(ok(next.clone())).await;
    let harness = Harness::new(&fixture.settings, &management.base);

    harness.job.run().await.unwrap();

    assert_eq!(fixture.cache(), next);
    assert_eq!(harness.stop_calls(), 1);
    assert_eq!(harness.state(), (STATE_RESTART_PENDING, Some(2), true));
    // Exit 75, not 0, so Restart=on-failure supervisors bring the collector back.
    assert!(harness.job.lifetime.restart_requested());
    assert!(harness.job.lifetime.stopping().is_cancelled());
    assert_eq!(fixture.cache_files(), [CACHE_FILE_NAME]);
    // The staged cache is what the restarted host verifies and loads.
    assert_eq!(
        Harness::new(&fixture.settings, &management.base)
            .privacy_profile_version
            .as_deref(),
        Some("1.1.0")
    );
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
        "revision",
        "revision-zero",
        "revision-string",
        "missing-revision",
        "action",
        "unknown-action",
        "unsigned-extra-field",
        "cleared-with-profile-fields",
        "cleared-for-another-collector",
    ] {
        let fixture = Fixture::new();
        let current = fixture.assigned(&Spec::default());
        fixture.write_cache(&current);
        // A newer revision, so only verification (not the high-water mark) can reject it.
        let management = mock(ok(tampered(&fixture, tamper, &content("2.0.0"), 2))).await;
        let harness = Harness::new(&fixture.settings, &management.base);

        assert_eq!(
            harness.job.run().await,
            Err("ManagedPrivacyProfileException"),
            "{tamper}"
        );

        assert_eq!(fixture.cache(), current, "{tamper}");
        assert_eq!(fixture.cache_files(), [CACHE_FILE_NAME], "{tamper}");
        assert_eq!(harness.stop_calls(), 0, "{tamper}");
    }
}

#[tokio::test]
async fn sync_unverified_first_assignment_leaves_no_cache() {
    let fixture = Fixture::new();
    let management = mock(ok(tampered(&fixture, "signature", &content("1.0.0"), 1))).await;
    let harness = Harness::new(&fixture.settings, &management.base);

    assert_eq!(
        harness.job.run().await,
        Err("ManagedPrivacyProfileException")
    );

    assert!(!fixture.settings.managed_privacy_cache_directory().exists());
    assert_eq!(harness.stop_calls(), 0);
}

#[tokio::test]
async fn sync_unsigned_no_content_never_removes_a_verified_cache() {
    for cached_action in [ACTION_ASSIGNED, ACTION_CLEARED] {
        let fixture = Fixture::new();
        let current = if cached_action == ACTION_ASSIGNED {
            fixture.assigned(&spec(3, "1.0.0"))
        } else {
            fixture.cleared(3)
        };
        fixture.write_cache(&current);
        let management = mock(status(StatusCode::NO_CONTENT)).await;
        let unsigned = Harness::new(&fixture.settings, &management.base);

        let failure = unsigned.job.sync().await.unwrap_err();

        assert_eq!(
            failure.message,
            "Management returned 204 although a verified assignment is cached; the cached \
             privacy profile protection stays active."
        );
        assert_eq!(fixture.cache(), current);
        assert_eq!(unsigned.stop_calls(), 0);
        assert!(unsigned.job.state.accepts_events());
        assert_eq!(
            Harness::new(&fixture.settings, &management.base)
                .privacy_profile_version
                .as_deref(),
            (cached_action == ACTION_ASSIGNED).then_some("1.0.0")
        );
    }
}

#[tokio::test]
async fn sync_older_signed_assignment_is_rejected() {
    let fixture = Fixture::new();
    let current = fixture.assigned(&spec(5, "2.0.0"));
    fixture.write_cache(&current);
    // A validly signed older version with a forged-looking issuedAt.
    let rollback = fixture.assigned(&Spec {
        issued_at: "2000-01-01T00:00:00.0000000Z".into(),
        ..spec(4, "1.0.0")
    });
    let management = mock(ok(rollback)).await;
    let harness = Harness::new(&fixture.settings, &management.base);

    let failure = harness.job.sync().await.unwrap_err();

    assert_eq!(
        failure.message,
        "Managed privacy profile assignment revision 4 is older than the cached revision 5."
    );
    assert_eq!(fixture.cache(), current);
    assert_eq!(harness.stop_calls(), 0);
}

#[tokio::test]
async fn sync_replay_after_restart_is_rejected() {
    let fixture = Fixture::new();
    let old = fixture.assigned(&spec(1, "1.0.0"));
    let current = fixture.assigned(&spec(2, "2.0.0"));
    fixture.write_cache(&old);
    let newer = mock(ok(current.clone())).await;
    let first = Harness::new(&fixture.settings, &newer.base);
    first.job.run().await.unwrap();
    assert_eq!(first.stop_calls(), 1);

    // The restarted process loads the high-water mark from the cache.
    let replay = mock(ok(old)).await;
    let restarted = Harness::new(&fixture.settings, &replay.base);
    assert_eq!(
        restarted.job.run().await,
        Err("ManagedPrivacyProfileException")
    );

    assert_eq!(restarted.privacy_profile_version.as_deref(), Some("2.0.0"));
    assert_eq!(fixture.cache(), current);
    assert_eq!(restarted.stop_calls(), 0);
}

#[tokio::test]
async fn sync_signed_clear_is_persisted_and_replay_after_clear_is_rejected() {
    let fixture = Fixture::new();
    let assigned = fixture.assigned(&spec(5, "2.0.0"));
    let cleared = fixture.cleared(6);
    fixture.write_cache(&assigned);

    let clearing_server = mock(ok(cleared.clone())).await;
    let clearing = Harness::new(&fixture.settings, &clearing_server.base);
    clearing.job.run().await.unwrap();
    let replay_server = mock(ok(assigned)).await;
    let restarted = Harness::new(&fixture.settings, &replay_server.base);
    let replay = restarted.job.sync().await.unwrap_err();

    assert_eq!(clearing.stop_calls(), 1);
    assert_eq!(fixture.cache(), cleared);
    // A cached explicit clear means the built-in default privacy profile.
    assert_eq!(restarted.privacy_profile_hash, None);
    assert_eq!(restarted.state(), (STATE_CLEARED, Some(6), true));
    assert!(
        replay
            .message
            .contains("revision 5 is older than the cached revision 6")
    );
    assert_eq!(restarted.stop_calls(), 0);
}

#[tokio::test]
async fn sync_newly_signed_explicit_rollback_is_accepted() {
    let fixture = Fixture::new();
    fixture.write_cache(&fixture.assigned(&spec(5, "2.0.0")));
    // An administrator re-assigns the older version: a new, higher revision.
    let rollback = fixture.assigned(&spec(7, "1.0.0"));
    let management = mock(ok(rollback.clone())).await;
    let harness = Harness::new(&fixture.settings, &management.base);

    harness.job.run().await.unwrap();

    assert_eq!(fixture.cache(), rollback);
    assert_eq!(harness.stop_calls(), 1);
    assert_eq!(
        Harness::new(&fixture.settings, &management.base)
            .privacy_profile_version
            .as_deref(),
        Some("1.0.0")
    );
}

#[tokio::test]
async fn sync_newer_revision_that_keeps_the_active_protection_is_recorded_without_restart() {
    let fixture = Fixture::new();
    fixture.write_cache(&fixture.assigned(&Spec::default()));
    let reassigned = fixture.assigned(&Spec {
        issued_at: "2026-10-24T05:00:00.0000000Z".into(),
        ..spec(3, "1.0.0")
    });
    let management = mock(ok(reassigned.clone())).await;
    let harness = Harness::new(&fixture.settings, &management.base);

    harness.job.run().await.unwrap();

    assert_eq!(fixture.cache(), reassigned);
    assert_eq!(harness.stop_calls(), 0);
    assert_eq!(harness.state(), (STATE_ASSIGNED, Some(3), true));
}

#[tokio::test]
async fn first_sync_without_cache_gates_ingest_until_resolved() {
    let fixture = Fixture::new();

    let unreachable = Harness::new(&fixture.settings, "http://127.0.0.1:9/");
    assert_eq!(unreachable.job.run().await, Err("HttpRequestException"));
    let conflict = mock(status(StatusCode::CONFLICT)).await;
    let not_active = Harness::new(&fixture.settings, &conflict.base);
    not_active.job.run().await.unwrap();
    let no_content = mock(status(StatusCode::NO_CONTENT)).await;
    let never_assigned = Harness::new(&fixture.settings, &no_content.base);
    assert!(!never_assigned.job.state.accepts_events());
    never_assigned.job.run().await.unwrap();
    let clear = mock(ok(fixture.cleared(2))).await;
    let cleared_before_first_sync = Harness::new(&fixture.settings, &clear.base);
    cleared_before_first_sync.job.run().await.unwrap();
    std::fs::remove_file(fixture.cache_path()).unwrap();
    let assignment = mock(ok(fixture.assigned(&Spec::default()))).await;
    let assigned = Harness::new(&fixture.settings, &assignment.base);
    assigned.job.run().await.unwrap();

    assert_eq!(
        unreachable.state(),
        (STATE_AWAITING_FIRST_SYNC, None, false)
    );
    assert_eq!(not_active.state(), (STATE_AWAITING_FIRST_SYNC, None, false));
    assert_eq!(never_assigned.state(), (STATE_NEVER_ASSIGNED, None, true));
    // Cleared before the first sync: the default is already running, no restart needed.
    assert_eq!(
        cleared_before_first_sync.state(),
        (STATE_CLEARED, Some(2), true)
    );
    assert_eq!(cleared_before_first_sync.stop_calls(), 0);
    // A first assignment is staged; ingest stays closed until the restart applies it.
    assert_eq!(assigned.state(), (STATE_RESTART_PENDING, Some(1), false));
    assert_eq!(assigned.stop_calls(), 1);
}

#[tokio::test]
async fn first_sync_allow_default_opt_in_accepts_before_resolution() {
    let mut fixture = Fixture::new();
    fixture.settings.managed_privacy_allow_default = true;
    let conflict = mock(status(StatusCode::CONFLICT)).await;
    let harness = Harness::new(&fixture.settings, &conflict.base);

    harness.job.run().await.unwrap();

    assert_eq!(harness.state(), (STATE_DEFAULT_ALLOWED, None, true));
}

#[tokio::test]
async fn sync_network_and_server_failures_keep_the_current_profile() {
    let fixture = Fixture::new();
    let current = fixture.assigned(&Spec::default());
    fixture.write_cache(&current);
    let unavailable = mock(status(StatusCode::SERVICE_UNAVAILABLE)).await;
    let not_active = mock(status(StatusCode::CONFLICT)).await;
    let oversized = mock(ok(vec![b' '; MAXIMUM_DOCUMENT_BYTES + 1])).await;
    let jobs = [
        Harness::new(&fixture.settings, "http://127.0.0.1:9/"),
        Harness::new(&fixture.settings, &unavailable.base),
        Harness::new(&fixture.settings, &not_active.base),
        Harness::new(&fixture.settings, &oversized.base),
    ];

    assert_eq!(jobs[0].job.run().await, Err("HttpRequestException"));
    assert_eq!(
        jobs[1].job.sync().await.unwrap_err().message,
        "Management returned HTTP 503 for the privacy profile deployment."
    );
    assert_eq!(jobs[2].job.run().await, Ok(()));
    assert_eq!(
        jobs[3].job.sync().await.unwrap_err().message,
        "Managed privacy profile document is too large."
    );

    assert_eq!(fixture.cache(), current);
    assert_eq!(fixture.cache_files(), [CACHE_FILE_NAME]);
    assert!(jobs.iter().all(|harness| harness.stop_calls() == 0));
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
    let harness = Harness::new(&fixture.settings, &format!("http://{address}/"));

    assert_eq!(
        harness.job.sync().await.unwrap_err().message,
        "Managed privacy profile document is too large."
    );

    assert!(!fixture.cache_path().exists());
    assert_eq!(harness.stop_calls(), 0);
    server.abort();
}

#[tokio::test]
async fn heartbeat_reports_the_active_privacy_profile_hash() {
    let fixture = Fixture::new();
    fixture.write_cache(&fixture.assigned(&Spec::default()));
    let managed = bundle::load(&fixture.settings).unwrap();
    let local = bundle::load(&fixture.local()).unwrap();

    let managed_body = heartbeat_body(&fixture, managed.info.privacy_profile_hash.as_deref()).await;
    let default_body = heartbeat_body(&fixture, local.info.privacy_profile_hash.as_deref()).await;

    let hash = managed.info.privacy_profile_hash.unwrap();
    // Heartbeat v2 fields follow the privacy profile hash (C# declaration order).
    assert!(
        managed_body.contains(&format!(
            ",\"privacyProfileHash\":\"{hash}\",\"schemaVersion\":2,"
        )),
        "{managed_body}"
    );
    assert!(
        default_body.contains(",\"privacyProfileHash\":\"default\",\"schemaVersion\":2,"),
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
