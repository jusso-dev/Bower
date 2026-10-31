//! Heartbeat v2 parity with the C# collector: command verification against C#-signed
//! vectors (`fixtures/csharp-management-commands.json`, produced by
//! `rust/tools/csharp-vectors/ZzManagementCommandVectors.cs`), the durable command ledger,
//! management connection settings and the heartbeat exchange end to end.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use bower_collector::CollectorSettings;
use bower_collector::bundle;
use bower_collector::heartbeat::{AccessTokenSource, ManagementHeartbeat, TokenFuture};
use bower_collector::jobs::{JobCatalog, JobTriggers};
use bower_collector::management_commands::{
    self as commands, Admission, CommandLedger, CommandProcessor, CommandWorker, VerifiedCommand,
    results,
};
use bower_collector::shutdown::ApplicationLifetime;
use bower_contracts::DurableEventStore;
use bower_contracts::time::{Clock, Timestamp};
use bower_core::{CollectorIdentity, PipelineTelemetry, SecurityEventProcessor};
use serde_json::{Value, json};

const COLLECTOR_ID: &str = "edge-01";
const BEARER_TOKEN: &str = "management-bearer-token-value";
const PROXY_PASSWORD: &str = "proxy-password-value-never-sent";

fn at(text: &str) -> Timestamp {
    bower_contracts::time::parse(text).unwrap()
}

fn now() -> Timestamp {
    at("2026-10-26T00:00:00Z")
}

/// A settable clock (C# `FakeClock`).
#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl FakeClock {
    fn new(value: Timestamp) -> Self {
        Self(Arc::new(Mutex::new(value)))
    }

    fn advance(&self, by: chrono::TimeDelta) {
        let mut value = self.0.lock().unwrap();
        *value += by;
    }
}

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

#[test]
fn verification_matches_csharp_vectors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csharp-management-commands.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let collector_id = fixture["collectorId"].as_str().unwrap();
    let trusted = vec![fixture["publicKey"].as_str().unwrap().to_string()];
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let document = decode_base64(case["document"].as_str().unwrap());
        let verdict = commands::verify(
            std::str::from_utf8(&document).unwrap(),
            collector_id,
            &trusted,
            commands::parse_timestamp(case["now"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(
            verdict.rejection_code,
            case["rejectionCode"].as_str(),
            "{name}: rejection code"
        );
        assert_eq!(
            verdict.command_id.as_deref(),
            case["commandId"].as_str(),
            "{name}: command id"
        );
        let verified = verdict.command.as_ref();
        assert_eq!(
            verified.map(|command| command.command.as_str()),
            case["command"].as_str(),
            "{name}: command"
        );
        assert_eq!(
            verified.map(|command| command.nonce.as_str()),
            case["nonce"].as_str(),
            "{name}: nonce"
        );
        assert_eq!(
            verified.map(|command| commands::format_timestamp(&command.expires_at)),
            case["expiresAt"].as_str().map(str::to_string),
            "{name}: expiry"
        );
        assert_eq!(
            verified.map(|command| commands::format_timestamp(&command.issued_at)),
            case["issuedAt"].as_str().map(str::to_string),
            "{name}: issue time"
        );
    }
}

/// Standard padded base64 (the fixture stores exact document bytes).
fn decode_base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0;
    let mut bytes = Vec::new();
    for symbol in text.bytes().filter(|byte| *byte != b'=') {
        let value = ALPHABET.iter().position(|item| *item == symbol).unwrap() as u32;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    bytes
}

/// The same vector the C# test `Signer_CanonicalBytesMatchTheCollectorVerifier` pins.
#[test]
fn signed_bytes_match_the_csharp_vector() {
    let bytes = commands::signed_bytes(
        &"1".repeat(32),
        "edge-01",
        "run-canary",
        &"2".repeat(32),
        "2026-10-26T00:00:00.0000000Z",
        "2026-10-26T00:15:00.0000000Z",
    );
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "{\"collectorId\":\"edge-01\",\"command\":\"run-canary\",\"commandId\":\"11111111111111111111111111111111\",\
         \"expiresAt\":\"2026-10-26T00:15:00.0000000Z\",\"issuedAt\":\"2026-10-26T00:00:00.0000000Z\",\
         \"kind\":\"bower.collector-command/v1\",\"nonce\":\"22222222222222222222222222222222\"}"
    );
    assert_eq!(
        commands::format_timestamp(&at("2026-10-26T10:00:00.1234567+10:00")),
        "2026-10-26T00:00:00.1234567Z"
    );
}

fn verified(id: char, nonce: char, command: &str) -> VerifiedCommand {
    VerifiedCommand {
        command_id: id.to_string().repeat(32),
        command: command.into(),
        nonce: nonce.to_string().repeat(32),
        issued_at: now(),
        expires_at: now() + chrono::TimeDelta::minutes(15),
    }
}

/// C# `Ledger_RunsEachCommandAtMostOnceAcrossRestarts`.
#[test]
fn ledger_runs_each_command_at_most_once_across_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now()));
    let ledger = CommandLedger::new(directory.path(), Arc::clone(&clock));
    let canary = verified('1', 'a', commands::RUN_CANARY);
    let reload = verified('2', 'b', commands::RELOAD);

    assert!(ledger.available());
    assert_eq!(ledger.admit(&canary), Admission::Accepted);
    assert_eq!(ledger.admit(&canary), Admission::Duplicate);
    let other_nonce = VerifiedCommand {
        nonce: "9".repeat(32),
        ..canary.clone()
    };
    let other_id = VerifiedCommand {
        command_id: "8".repeat(32),
        ..canary.clone()
    };
    assert_eq!(ledger.admit(&other_nonce), Admission::Rejected);
    assert_eq!(ledger.admit(&other_id), Admission::Rejected);
    assert_eq!(ledger.admit(&reload), Admission::Accepted);
    ledger
        .complete(
            &canary.command_id,
            results::SUCCEEDED,
            results::CANARY_QUEUED,
        )
        .unwrap();

    let restarted = CommandLedger::new(directory.path(), Arc::clone(&clock));
    let pending = restarted.pending_results();
    assert_eq!(restarted.admit(&canary), Admission::Duplicate);
    assert_eq!(restarted.admit(&reload), Admission::Duplicate);
    assert_eq!(pending.len(), 2);
    let interrupted = pending
        .iter()
        .find(|item| item.command_id.as_deref() == Some(reload.command_id.as_str()))
        .unwrap();
    assert_eq!(interrupted.status, results::FAILED);
    assert_eq!(interrupted.code, results::INTERRUPTED);

    restarted.acknowledge(
        &[canary.command_id.clone(), reload.command_id.clone()],
        &pending,
    );
    assert!(restarted.pending_results().is_empty());
    assert!(
        CommandLedger::new(directory.path(), Arc::clone(&clock))
            .pending_results()
            .is_empty()
    );
    assert_eq!(restarted.admit(&canary), Admission::Duplicate);
}

/// C# `Ledger_RejectionsAreReportedOnceAndBounded`.
#[test]
fn ledger_rejections_are_reported_once_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = CommandLedger::new(directory.path(), Arc::new(FakeClock::new(now())));
    ledger.reject(Some("1".repeat(32)), results::UNTRUSTED_SIGNATURE);
    ledger.reject(Some("1".repeat(32)), results::UNTRUSTED_SIGNATURE);
    for _ in 0..41 {
        ledger.reject(None, results::MALFORMED_COMMAND);
    }
    let pending = ledger.pending_results();
    assert_eq!(pending.len(), commands::MAXIMUM_REPORTED_RESULTS);
    assert!(pending.iter().all(|item| item.status == results::REJECTED));
    ledger.acknowledge(&[], &pending);
    assert!(ledger.pending_results().is_empty());
    assert!(!directory.path().join(commands::LEDGER_FILE_NAME).exists());
}

/// C# `Ledger_ThatCannotBeReadRefusesEveryCommand`.
#[test]
fn ledger_that_cannot_be_read_refuses_every_command() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(commands::LEDGER_FILE_NAME),
        "{not json",
    )
    .unwrap();
    let ledger = CommandLedger::new(directory.path(), Arc::new(FakeClock::new(now())));
    assert!(!ledger.available());
    assert_eq!(
        ledger.admit(&verified('1', 'a', commands::RUN_CANARY)),
        Admission::Rejected
    );
    let pending = ledger.pending_results();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].code, results::LEDGER_UNAVAILABLE);
}

/// C# `Ledger_RateLimitsReloads`.
#[test]
fn ledger_rate_limits_reloads() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(now());
    let shared: Arc<dyn Clock> = Arc::new(clock.clone());
    let ledger = CommandLedger::new(directory.path(), Arc::clone(&shared));
    // The peek a reload makes before its pre-check never uses the slot.
    assert!(ledger.reload_allowed());
    assert!(ledger.reload_allowed());
    assert!(ledger.try_begin_reload().unwrap());
    assert!(!ledger.reload_allowed());
    drop(ledger);
    clock.advance(chrono::TimeDelta::minutes(9));
    assert!(
        !CommandLedger::new(directory.path(), Arc::clone(&shared))
            .try_begin_reload()
            .unwrap()
    );
    clock.advance(chrono::TimeDelta::minutes(1));
    assert!(
        CommandLedger::new(directory.path(), shared)
            .try_begin_reload()
            .unwrap()
    );
}

fn base_settings() -> CollectorSettings {
    let mut settings =
        CollectorSettings::new("http://127.0.0.1:4319", "queue.db", "policies", "edge-01");
    settings.management_endpoint = Some("https://management.example.test".parse().unwrap());
    settings.management_scope = Some("api://bower/.default".into());
    settings
}

fn message(settings: &CollectorSettings) -> String {
    settings.validate().unwrap_err().message
}

/// C# `Settings_ValidateProxyCaAndCommandKeys`.
#[test]
fn settings_validate_proxy_ca_and_command_keys() {
    let managed = base_settings();
    let proxy: reqwest::Url = "http://proxy.example.test:3128".parse().unwrap();
    let mut with_proxy = managed.clone();
    with_proxy.management_proxy = Some(proxy.clone());
    with_proxy.validate().unwrap();
    let mut with_credentials = with_proxy.clone();
    with_credentials.management_proxy_username = Some("u".into());
    with_credentials.management_proxy_password_file = Some("p".into());
    with_credentials.validate().unwrap();

    let mut embedded = managed.clone();
    embedded.management_proxy = Some(
        "http://user:hunter2@proxy.example.test:3128"
            .parse()
            .unwrap(),
    );
    assert!(!message(&embedded).contains("hunter2"));
    for invalid in ["socks5://proxy:1080", "http://proxy:3128/path"] {
        let mut settings = managed.clone();
        settings.management_proxy = Some(invalid.parse().unwrap());
        assert!(message(&settings).starts_with("BOWER_MANAGEMENT_PROXY must be"));
    }
    let mut username_only = with_proxy.clone();
    username_only.management_proxy_username = Some("u".into());
    assert_eq!(
        message(&username_only),
        "BOWER_MANAGEMENT_PROXY_USERNAME and BOWER_MANAGEMENT_PROXY_PASSWORD_FILE must be set together."
    );
    let mut no_proxy = managed.clone();
    no_proxy.management_proxy_username = Some("u".into());
    no_proxy.management_proxy_password_file = Some("p".into());
    assert_eq!(
        message(&no_proxy),
        "BOWER_MANAGEMENT_PROXY_USERNAME requires BOWER_MANAGEMENT_PROXY."
    );
    let mut no_endpoint = managed.clone();
    no_endpoint.management_endpoint = None;
    no_endpoint.management_scope = None;
    no_endpoint.management_command_trusted_key_files = vec!["k.pem".into()];
    assert!(message(&no_endpoint).ends_with("require BOWER_MANAGEMENT_ENDPOINT."));

    let read = |name: &str| match name {
        "BOWER_MANAGEMENT_ENDPOINT" => Some("https://management.example.test".to_string()),
        "BOWER_MANAGEMENT_SCOPE" => Some("api://bower/.default".to_string()),
        "BOWER_MANAGEMENT_PROXY" => Some("https://proxy.example.test:8443".to_string()),
        "BOWER_MANAGEMENT_PROXY_USERNAME" => Some("bower".to_string()),
        "BOWER_MANAGEMENT_PROXY_PASSWORD_FILE" => Some("/run/secrets/proxy".to_string()),
        "BOWER_MANAGEMENT_CA_BUNDLE" => Some("/etc/bower/inspection-ca.pem".to_string()),
        "BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS" => {
            Some("/etc/bower/a.pem, /etc/bower/b.pem".to_string())
        }
        _ => None,
    };
    let from_environment = CollectorSettings::from_environment(read).unwrap();
    assert_eq!(
        from_environment.management_command_trusted_key_files,
        ["/etc/bower/a.pem", "/etc/bower/b.pem"]
    );
    assert!(
        CollectorSettings::from_environment(|name| match name {
            "BOWER_MANAGEMENT_PROXY" => Some("not a url".to_string()),
            other => read(other),
        })
        .is_err()
    );
    // Credentials never enter the hash; unset settings leave existing hashes unchanged.
    assert_ne!(
        managed.configuration_hash(),
        from_environment.configuration_hash()
    );
    let mut other_credentials = with_credentials.clone();
    other_credentials.management_proxy_username = Some("v".into());
    other_credentials.management_proxy_password_file = Some("q".into());
    assert_eq!(
        with_credentials.configuration_hash(),
        other_credentials.configuration_hash()
    );
    // Pinned against C# `CollectorSettings.ConfigurationHash` (ManagementProxyTests).
    let mut pinned =
        CollectorSettings::new("http://127.0.0.1:4319", "queue.db", "policies", "edge-01");
    pinned.management_endpoint = from_environment.management_endpoint.clone();
    pinned.management_scope = from_environment.management_scope.clone();
    pinned.management_proxy = from_environment.management_proxy.clone();
    pinned.management_proxy_username = Some("bower".into());
    pinned.management_proxy_password_file = Some("/run/secrets/proxy".into());
    pinned.management_ca_bundle = Some("/etc/bower/inspection-ca.pem".into());
    pinned.management_command_trusted_key_files = vec!["/etc/bower/a.pem".into()];
    assert_eq!(pinned.configuration_hash(), PINNED_CONFIGURATION_HASH);
}

const PINNED_CONFIGURATION_HASH: &str =
    "sha256:a53aa3777ee29ae7496974c8b2328e7b100fa0cd7839de0b835823f09fc091af";

#[test]
fn ca_bundle_that_is_missing_or_empty_fails_startup() {
    let directory = tempfile::tempdir().unwrap();
    let empty = directory.path().join("empty.pem");
    std::fs::write(&empty, "no certificates here").unwrap();
    let mut settings = base_settings();
    settings.management_ca_bundle = Some(directory.path().join("absent.pem"));
    let missing = bower_collector::management_http::client(&settings).unwrap_err();
    settings.management_ca_bundle = Some(empty);
    let invalid = bower_collector::management_http::client(&settings).unwrap_err();
    for error in [missing, invalid] {
        assert_eq!(
            error.message,
            "BOWER_MANAGEMENT_CA_BUNDLE must name a readable PEM file of CA certificates."
        );
    }
}

// ------------------------------------------------------------------ end to end

struct StaticCredential;

impl AccessTokenSource for StaticCredential {
    fn access_token<'a>(&'a self, _: &'a str) -> TokenFuture<'a> {
        Box::pin(async { Ok(BEARER_TOKEN.to_string()) })
    }
}

fn command(private_pem: &str, command_id: &str, issued: Timestamp, expires: Timestamp) -> Value {
    let nonce = hex::encode(uuid::Uuid::new_v4().as_bytes());
    let (issued, expires) = (
        commands::format_timestamp(&issued),
        commands::format_timestamp(&expires),
    );
    let signature = bower_integrity::signer::sign(
        &commands::signed_bytes(
            command_id,
            COLLECTOR_ID,
            commands::RUN_CANARY,
            &nonce,
            &issued,
            &expires,
        ),
        private_pem,
    )
    .unwrap();
    json!({
        "kind": commands::KIND,
        "commandId": command_id,
        "collectorId": COLLECTOR_ID,
        "command": commands::RUN_CANARY,
        "nonce": nonce,
        "issuedAt": issued,
        "expiresAt": expires,
        "signature": { "algorithm": signature.algorithm, "keyId": signature.key_id, "value": signature.value }
    })
}

type Responder = Arc<dyn Fn(&str, &str) -> Response + Send + Sync>;

/// Fake management API recording heartbeat bodies.
async fn mock(respond: Responder) -> (String, tokio::task::JoinHandle<()>) {
    let router = Router::new().fallback(
        move |uri: Uri, headers: axum::http::HeaderMap, body: String| {
            let respond = Arc::clone(&respond);
            async move {
                assert_eq!(
                    headers
                        .get(header::AUTHORIZATION)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    format!("Bearer {BEARER_TOKEN}")
                );
                respond(uri.path(), &body)
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{address}/"), server)
}

fn settings(directory: &Path, base: &str, public_pem: &str) -> CollectorSettings {
    let key = directory.join("command-trusted.pem");
    std::fs::write(&key, public_pem).unwrap();
    let password = directory.join("proxy-password");
    std::fs::write(&password, format!("{PROXY_PASSWORD}\n")).unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("data").join("queue.db"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../policies/default"),
        COLLECTOR_ID,
    );
    settings.management_endpoint = Some(base.parse().unwrap());
    settings.management_scope = Some("api://bower/.default".into());
    settings.management_command_trusted_key_files = vec![key.to_string_lossy().into_owned()];
    settings.management_proxy_username = None;
    settings.management_proxy_password_file = None;
    settings
}

struct Exchange {
    heartbeat: ManagementHeartbeat,
    worker: CommandWorker,
    inbox: tokio::sync::mpsc::Receiver<VerifiedCommand>,
    store: Arc<dyn DurableEventStore>,
}

fn exchange(settings: &CollectorSettings) -> Exchange {
    std::fs::create_dir_all(settings.queue_path.parent().unwrap()).unwrap();
    let sqlite = Arc::new(
        bower_persistence::SqliteEventStore::new(
            &settings.queue_path,
            settings.maximum_queue_bytes,
            None,
        )
        .unwrap(),
    );
    sqlite.initialize().unwrap();
    let store: Arc<dyn DurableEventStore> = sqlite;
    let clock: Arc<dyn Clock> = Arc::new(bower_contracts::time::SystemClock);
    let ledger = Arc::new(CommandLedger::new(
        &settings.management_command_directory(),
        Arc::clone(&clock),
    ));
    let (sender, inbox) = tokio::sync::mpsc::channel(commands::INBOX_CAPACITY);
    let processor = Arc::new(CommandProcessor::new(
        settings,
        Arc::clone(&ledger),
        sender,
        Arc::clone(&clock),
    ));
    let mut heartbeat = ManagementHeartbeat::from_settings(
        settings,
        "sha256:policy".into(),
        None,
        Arc::new(StaticCredential),
        Arc::clone(&store),
        Arc::new(JobCatalog::default()),
    )
    .unwrap();
    heartbeat.commands = Some(processor);
    let loaded = bundle::load(settings).unwrap();
    let worker = CommandWorker {
        ledger,
        triggers: JobTriggers::default(),
        processor: SecurityEventProcessor::new(
            loaded.redactor,
            loaded.evaluator,
            Arc::clone(&store),
            Arc::clone(&clock),
        ),
        identity: CollectorIdentity::new(
            COLLECTOR_ID.to_string(),
            "0.1.0".to_string(),
            "local-http",
            "c".to_string(),
        ),
        environment: "test".into(),
        clock,
        lifetime: ApplicationLifetime::new(),
        enrolment: None,
        settings: Arc::new(settings.clone()),
    };
    Exchange {
        heartbeat,
        worker,
        inbox,
        store,
    }
}

/// C# `Heartbeat_ReportsV2MetadataRunsVerifiedCommandsAndReportsResultsNextTime`.
#[tokio::test]
async fn heartbeat_runs_verified_commands_and_reports_results_next_time() {
    let directory = tempfile::tempdir().unwrap();
    let keys = bower_integrity::signer::generate_key_pair();
    let forger = bower_integrity::signer::generate_key_pair();
    let issued = bower_contracts::time::now();
    let expires = issued + chrono::TimeDelta::minutes(15);
    let canary_id = "c".repeat(32);
    let forged_id = "d".repeat(32);
    let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
    let acknowledge = Arc::new(Mutex::new(None::<String>));
    let (recorded, acknowledged) = (Arc::clone(&bodies), Arc::clone(&acknowledge));
    let (signed, forged) = (
        command(&keys.private_key_pem, &canary_id, issued, expires),
        command(&forger.private_key_pem, &forged_id, issued, expires),
    );
    let forged_ack = forged_id.clone();
    let (base, server) = mock(Arc::new(move |path: &str, body: &str| {
        if path.ends_with("/register") {
            return StatusCode::ACCEPTED.into_response();
        }
        let mut bodies = recorded.lock().unwrap();
        bodies.push(body.to_string());
        let commands = if bodies.len() == 1 {
            json!([signed, forged])
        } else {
            json!([])
        };
        let acks = match acknowledged.lock().unwrap().clone() {
            Some(id) => json!([id, forged_ack]),
            None => json!([]),
        };
        axum::Json(json!({
            "schemaVersion": 2, "collectorId": COLLECTOR_ID, "status": "Active",
            "commands": commands, "acknowledgedResults": acks
        }))
        .into_response()
    }))
    .await;
    let mut exchange = exchange(&settings(directory.path(), &base, &keys.public_key_pem));
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(
        bower_contracts::time::SystemClock,
    )));
    telemetry.record_redactions(&["au.tfn".into(), "secret.aws:access-key".into()]);
    exchange.heartbeat.telemetry = Some(Arc::clone(&telemetry));

    exchange.heartbeat.run().await.unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(5), exchange.inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        exchange.inbox.try_recv().is_err(),
        "the forged command is never queued"
    );
    exchange.worker.execute(&admitted).await;
    *acknowledge.lock().unwrap() = Some(canary_id.clone());
    exchange.heartbeat.run().await.unwrap();
    exchange.heartbeat.run().await.unwrap();
    let snapshot = exchange.store.snapshot().unwrap();

    let bodies = bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 3);
    let first: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(first["schemaVersion"], 2);
    assert_eq!(first["heartbeatIntervalSeconds"], 60);
    assert_eq!(
        first["commandCapabilities"],
        json!(["run-canary", "reload"])
    );
    assert_eq!(first["commandResults"], json!([]));
    // Redaction counts by detector type only: never values.
    assert_eq!(
        first["redactions"]["counts"],
        json!([{"type": "au.tfn", "events": 1}, {"type": "secret.aws", "events": 1}])
    );
    assert!(first["redactions"]["observedSince"].is_string());
    // #81 compatibility: the per-source report keeps its existing shape.
    assert_eq!(first["sources"][0]["status"], "healthy");

    let second: Value = serde_json::from_str(&bodies[1]).unwrap();
    let results = second["commandResults"].as_array().unwrap();
    let find = |id: &str| results.iter().find(|item| item["commandId"] == id).unwrap();
    assert_eq!(find(&canary_id)["status"], "succeeded");
    assert_eq!(find(&canary_id)["code"], "canary-queued");
    // An unverified document never names a command id, even one it claims.
    let forged = results
        .iter()
        .find(|item| item["commandId"].is_null())
        .unwrap();
    assert_eq!(forged["status"], "rejected");
    assert_eq!(forged["code"], "untrusted-signature");
    assert!(!bodies[1].contains(&forged_id));
    assert_eq!(second["lastCanary"]["outcome"], "queued");
    assert_eq!(second["lastCanary"]["commandId"], canary_id.as_str());
    assert_eq!(
        snapshot.queued + snapshot.uploading + snapshot.retrying + snapshot.delivered,
        1
    );

    let third: Value = serde_json::from_str(&bodies[2]).unwrap();
    assert_eq!(third["commandResults"], json!([]));
    assert_eq!(third["lastCanary"]["outcome"], "queued");
    for body in &bodies {
        assert!(!body.contains(BEARER_TOKEN));
        assert!(!body.contains(PROXY_PASSWORD));
    }
    server.abort();
}

/// C# `Heartbeat_AgainstAV1ManagementApiTakesNoCommandsAndKeepsResults`.
#[tokio::test]
async fn heartbeat_against_a_v1_management_api_takes_no_commands() {
    let directory = tempfile::tempdir().unwrap();
    let keys = bower_integrity::signer::generate_key_pair();
    let issued = bower_contracts::time::now();
    let signed = command(
        &keys.private_key_pem,
        &"c".repeat(32),
        issued,
        issued + chrono::TimeDelta::minutes(5),
    );
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&requests);
    let (base, server) = mock(Arc::new(move |_: &str, _: &str| {
        counted.fetch_add(1, Ordering::SeqCst);
        axum::Json(json!({ "id": COLLECTOR_ID, "status": "Active", "commands": [signed] }))
            .into_response()
    }))
    .await;
    let mut exchange = exchange(&settings(directory.path(), &base, &keys.public_key_pem));
    exchange
        .heartbeat
        .commands
        .as_ref()
        .unwrap()
        .ledger()
        .reject(Some("e".repeat(32)), results::EXPIRED);

    exchange.heartbeat.run().await.unwrap();

    assert!(exchange.inbox.try_recv().is_err());
    let pending = exchange
        .heartbeat
        .commands
        .as_ref()
        .unwrap()
        .ledger()
        .pending_results();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].code, results::EXPIRED);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    server.abort();
}

/// C# `Processor_WithTrustedKeysThatAreNotP256PublicKeysAdvertisesNothingAndRefusesCommands`.
#[test]
fn processor_with_invalid_trusted_keys_advertises_nothing_and_refuses_commands() {
    let directory = tempfile::tempdir().unwrap();
    let keys = bower_integrity::signer::generate_key_pair();
    let valid = directory.path().join("valid.pem");
    std::fs::write(&valid, &keys.public_key_pem).unwrap();
    let garbage = directory.path().join("garbage.pem");
    std::fs::write(
        &garbage,
        "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n",
    )
    .unwrap();
    let missing = directory.path().join("missing.pem");
    let issued = bower_contracts::time::now();
    let body = json!({
        "schemaVersion": 2,
        "commands": [command(&keys.private_key_pem, &"c".repeat(32), issued, issued + chrono::TimeDelta::minutes(5))]
    })
    .to_string();
    for files in [vec![valid.clone(), garbage.clone()], vec![missing.clone()]] {
        let mut settings = base_settings();
        settings.management_command_trusted_key_files = files
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let ledger = Arc::new(CommandLedger::new(
            &directory
                .path()
                .join(uuid::Uuid::new_v4().simple().to_string()),
            Arc::new(bower_contracts::time::SystemClock),
        ));
        let (sender, mut inbox) = tokio::sync::mpsc::channel(commands::INBOX_CAPACITY);
        let processor = CommandProcessor::new(
            &settings,
            Arc::clone(&ledger),
            sender,
            Arc::new(bower_contracts::time::SystemClock),
        );

        processor
            .handle_response(Some(body.as_bytes()), &[])
            .unwrap();

        assert!(processor.capabilities().is_empty());
        assert!(inbox.try_recv().is_err());
        let pending = ledger.pending_results();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].code, results::COMMANDS_NOT_CONFIGURED);
    }
}

/// C# `Heartbeat_StalledResponseBodyIsBoundedByTheExchangeTimeout`. reqwest's client timeout
/// covers the response body, so a stalled body ends the run (production budget 15 s).
#[tokio::test]
async fn heartbeat_stalled_response_body_is_bounded_by_the_client_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let directory = tempfile::tempdir().unwrap();
    let keys = bower_integrity::signer::generate_key_pair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    if socket.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    if head.contains("/register ") {
                        let _ = socket
                            .write_all(b"HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        continue;
                    }
                    // Headers, then a body that never arrives.
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{")
                        .await;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            });
        }
    });
    let mut exchange = exchange(&settings(
        directory.path(),
        &format!("http://{address}/"),
        &keys.public_key_pem,
    ));
    exchange.heartbeat.client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .unwrap();

    let run = tokio::time::timeout(Duration::from_secs(10), exchange.heartbeat.run()).await;

    // A timed-out exchange is a logged heartbeat failure, never an error for the scheduler.
    assert_eq!(run.expect("the heartbeat run must not hang"), Ok(()));
    assert_eq!(
        bower_collector::management_http::TIMEOUT,
        Duration::from_secs(15)
    );
    server.abort();
}

/// C# `PackRotationTests`: a reload whose restart could not load its packs, trust keys or
/// privacy key is refused and the running collector keeps its configuration.
#[tokio::test]
async fn reload_is_refused_when_the_restart_could_not_load_its_configuration() {
    let pack_source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/linux-ssh-gateway");
    for fault in [
        "untrusted-key",
        "missing-pack",
        "missing-trusted-key",
        "short-hmac-key",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let keys = bower_integrity::signer::generate_key_pair();
        let other = bower_integrity::signer::generate_key_pair();
        let signer = if fault == "untrusted-key" {
            &other
        } else {
            &keys
        };
        let built = directory.path().join("built");
        std::fs::create_dir_all(&built).unwrap();
        let pack = bower_packs::archive::build(&pack_source, &signer.private_key_pem, &built, None)
            .unwrap();
        let trusted = directory.path().join("pack-trusted.pem");
        std::fs::write(&trusted, &keys.public_key_pem).unwrap();
        let hmac = directory.path().join("privacy-hmac.key");
        std::fs::write(&hmac, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let mut settings = CollectorSettings::new(
            "http://127.0.0.1:4319",
            directory.path().join("data").join("queue.db"),
            directory.path().join("no-local-policies"),
            COLLECTOR_ID,
        );
        settings.packs = vec![pack.to_string_lossy().into_owned()];
        settings.pack_trusted_key_files = vec![trusted.to_string_lossy().into_owned()];
        settings.privacy_hmac_key_file = Some(hmac.clone());
        if fault != "untrusted-key" {
            assert_eq!(commands::reload_refusal(&settings), None, "{fault}");
        }
        match fault {
            "missing-pack" => std::fs::remove_file(&pack).unwrap(),
            "missing-trusted-key" => std::fs::remove_file(&trusted).unwrap(),
            "short-hmac-key" => std::fs::write(&hmac, "AAAAAAAAAAA=").unwrap(),
            _ => {}
        }
        let refusal = commands::reload_refusal(&settings);
        assert!(
            refusal.is_some_and(|kind| kind.chars().all(char::is_alphanumeric)),
            "{fault}: {refusal:?}"
        );
    }
}

/// C# `Reload_IsRefusedForSourceFilesARestartCouldNotLoad`: the pre-check runs the loader
/// start-up runs (`startup::load`), so source files that would stop a restart refuse it.
#[tokio::test]
async fn reload_is_refused_for_source_files_a_restart_could_not_load() {
    let pack_source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/linux-ssh-gateway");
    for fault in [
        "route-to-a-parser-the-pack-no-longer-has",
        "half-written-tls-certificate",
        "tls-key-not-matching",
        "syslog-config-deleted",
        "malformed-source-expectations",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let keys = bower_integrity::signer::generate_key_pair();
        let built = directory.path().join("built");
        std::fs::create_dir_all(&built).unwrap();
        let pack =
            bower_packs::archive::build(&pack_source, &keys.private_key_pem, &built, None).unwrap();
        let trusted = directory.path().join("pack-trusted.pem");
        std::fs::write(&trusted, &keys.public_key_pem).unwrap();
        let hmac = directory.path().join("privacy-hmac.key");
        std::fs::write(&hmac, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&server_key)
            .unwrap();
        let certificate = directory.path().join("syslog-server.pem");
        let key = directory.path().join("syslog-server-key.pem");
        std::fs::write(&certificate, server.pem()).unwrap();
        std::fs::write(&key, server_key.serialize_pem()).unwrap();
        let syslog = directory.path().join("syslog.json");
        let write_syslog = |parser: u32| {
            let quote = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
            std::fs::write(
                &syslog,
                format!(
                    r#"{{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{{
                    "id": "edge", "protocol": "tls", "address": "127.0.0.1", "port": 0, "allowedSenders": ["127.0.0.1"],
                    "tls": {{"certificateFile": {}, "privateKeyFile": {}}},
                    "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": {parser}}}]}}]}}"#,
                    quote(&certificate),
                    quote(&key)
                ),
            )
            .unwrap();
        };
        write_syslog(0);
        let expectations = directory.path().join("expectations.json");
        std::fs::write(
            &expectations,
            r#"{"apiVersion": "bower.security/v1", "kind": "SourceExpectations",
             "sources": [{"application": "ssh-gateway", "environment": "production", "maximumSilenceMinutes": 5}]}"#,
        )
        .unwrap();
        let mut settings = CollectorSettings::new(
            "http://127.0.0.1:4319",
            directory.path().join("data").join("queue.db"),
            directory.path().join("no-local-policies"),
            COLLECTOR_ID,
        );
        settings.packs = vec![pack.to_string_lossy().into_owned()];
        settings.pack_trusted_key_files = vec![trusted.to_string_lossy().into_owned()];
        settings.privacy_hmac_key_file = Some(hmac.clone());
        settings.syslog_config_path = Some(syslog.clone());
        settings.source_expectations_path = Some(expectations.clone());
        assert_eq!(commands::reload_refusal(&settings), None, "{fault}");
        match fault {
            "route-to-a-parser-the-pack-no-longer-has" => write_syslog(7),
            "half-written-tls-certificate" => {
                let text = std::fs::read_to_string(&certificate).unwrap();
                std::fs::write(&certificate, &text[..60]).unwrap();
            }
            "tls-key-not-matching" => {
                std::fs::write(&key, rcgen::KeyPair::generate().unwrap().serialize_pem()).unwrap()
            }
            "syslog-config-deleted" => std::fs::remove_file(&syslog).unwrap(),
            _ => std::fs::write(&expectations, r#"{"kind": "#).unwrap(),
        }
        let refusal = commands::reload_refusal(&settings);
        assert!(
            refusal.is_some_and(|kind| kind.chars().all(char::is_alphanumeric)),
            "{fault}: {refusal:?}"
        );
    }
}
