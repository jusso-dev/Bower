//! Token enrolment and credential rotation parity with the C# collector (#109): the
//! assertion on every management request, the owner-only credential file (shared format),
//! refused and lost enrolment responses, rotation under the current credential, scheduled
//! rotation, the `rotate-credential` command and the settings. C# `EnrolmentTests` covers
//! the management API side, including a Rust-signed assertion vector.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bower_collector::CollectorSettings;
use bower_collector::bundle;
use bower_collector::enrolment::{self, ManagementEnrolment};
use bower_collector::heartbeat::ManagementHeartbeat;
use bower_collector::jobs::{JobCatalog, JobTriggers};
use bower_collector::management_commands::{
    self as commands, CommandLedger, CommandWorker, VerifiedCommand, results,
};
use bower_collector::shutdown::ApplicationLifetime;
use bower_contracts::DurableEventStore;
use bower_contracts::time::{Clock, Timestamp};
use bower_core::{CollectorIdentity, SecurityEventProcessor};
use serde_json::{Value, json};

const COLLECTOR_ID: &str = "edge-onprem-01";
const TOKEN: &str = "bwe1.0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn at(text: &str) -> Timestamp {
    bower_contracts::time::parse(text).unwrap()
}

fn start() -> Timestamp {
    at("2026-10-27T00:00:00Z")
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl FakeClock {
    fn advance(&self, by: chrono::TimeDelta) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

/// A recorded management request: path, Authorization header and body.
#[derive(Clone, Debug)]
struct Request {
    path: String,
    authorization: Option<String>,
    body: Value,
}

/// A fake management API that issues credentials like the C# one and records requests.
#[derive(Default)]
struct Management {
    keys: Mutex<Vec<String>>,
    scripted: Mutex<VecDeque<StatusCode>>,
    requests: Mutex<Vec<Request>>,
    now: Mutex<Option<FakeClock>>,
}

impl Management {
    fn requests(&self, suffix: &str) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path.ends_with(suffix))
            .cloned()
            .collect()
    }

    fn key(&self, index: usize) -> String {
        self.keys.lock().unwrap()[index].clone()
    }

    fn issue(&self, public_key: &str, status: &str) -> Response {
        let id = bower_integrity::key_id_from_public_key_pem(public_key).unwrap();
        self.keys.lock().unwrap().push(public_key.to_string());
        let now = self.now.lock().unwrap().as_ref().unwrap().utc_now();
        let expires = now + chrono::TimeDelta::days(30);
        (
            if status == "Pending" {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            },
            axum::Json(json!({
                "collectorId": COLLECTOR_ID, "credentialId": id, "status": status,
                "issuedAt": now.to_rfc3339(), "expiresAt": expires.to_rfc3339()
            })),
        )
            .into_response()
    }

    fn respond(&self, request: Request) -> Response {
        self.requests.lock().unwrap().push(request.clone());
        if let Some(status) = self.scripted.lock().unwrap().pop_front() {
            return status.into_response();
        }
        let public_key = request.body["publicKey"].as_str().unwrap_or_default();
        if request.path == "/api/collectors/enrol" {
            return self.issue(public_key, "Pending");
        }
        if request.path.ends_with("/credentials/rotate") {
            return self.issue(public_key, "Active");
        }
        if request.path.ends_with("/register") {
            return StatusCode::ACCEPTED.into_response();
        }
        axum::Json(json!({
            "schemaVersion": 2, "collectorId": COLLECTOR_ID, "status": "Active",
            "commands": [], "acknowledgedResults": []
        }))
        .into_response()
    }
}

async fn serve(management: Arc<Management>) -> String {
    let router = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: String| {
        let management = Arc::clone(&management);
        async move {
            management.respond(Request {
                path: uri.path().to_string(),
                authorization: headers
                    .get(header::AUTHORIZATION)
                    .map(|value| value.to_str().unwrap().to_string()),
                body: serde_json::from_str(&body).unwrap_or(Value::Null),
            })
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}/")
}

/// The assertion's collector and credential when `public_key` verifies it (as C# management does).
fn verify(authorization: &str, public_key: &str, now: Timestamp) -> Option<(String, String)> {
    let value = authorization.strip_prefix("Bearer bwc1.")?;
    let (payload, signature) = value.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let fields: Value = serde_json::from_slice(&payload).ok()?;
    let credential = fields["credentialId"].as_str()?.to_string();
    let issued = commands::parse_timestamp(fields["issuedAt"].as_str()?)?;
    let expires = commands::parse_timestamp(fields["expiresAt"].as_str()?)?;
    let canonical = enrolment::signed_bytes(
        fields["collectorId"].as_str()?,
        &credential,
        fields["issuedAt"].as_str()?,
        fields["expiresAt"].as_str()?,
        fields["nonce"].as_str()?,
    );
    let valid = canonical == payload
        && fields["kind"] == enrolment::ASSERTION_KIND
        && issued <= now
        && expires > now
        && expires - issued == chrono::TimeDelta::minutes(5)
        && bower_integrity::verify(
            &payload,
            &bower_integrity::DetachedSignature {
                algorithm: "ES256".into(),
                key_id: credential.clone(),
                value: STANDARD.encode(signature),
            },
            [public_key],
        );
    valid.then(|| {
        (
            fields["collectorId"].as_str().unwrap().to_string(),
            credential,
        )
    })
}

fn settings(directory: &Path, base: &str, token: Option<&str>) -> CollectorSettings {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("data").join("queue.db"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../policies/default"),
        COLLECTOR_ID,
    );
    settings.environment = "production".into();
    settings.management_endpoint = Some(base.parse().unwrap());
    settings.management_authentication = "enrolment".into();
    let file = directory.join("enrolment-token");
    if let Some(token) = token {
        std::fs::write(&file, format!("{token}\n")).unwrap();
    }
    settings.management_enrolment_token_file = Some(file);
    settings
}

struct Harness {
    management: Arc<Management>,
    clock: FakeClock,
    settings: CollectorSettings,
    enrolment: Arc<ManagementEnrolment>,
    heartbeat: ManagementHeartbeat,
    store: Arc<dyn DurableEventStore>,
}

async fn harness(directory: &Path, token: Option<&str>) -> Harness {
    let management = Arc::new(Management::default());
    let clock = FakeClock(Arc::new(Mutex::new(start())));
    *management.now.lock().unwrap() = Some(clock.clone());
    let base = serve(Arc::clone(&management)).await;
    let settings = settings(directory, &base, token);
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
    let shared: Arc<dyn Clock> = Arc::new(clock.clone());
    let enrolment = Arc::new(
        ManagementEnrolment::from_settings(
            &settings,
            "sha256:policy".into(),
            reqwest::Client::new(),
            shared,
        )
        .unwrap(),
    );
    let mut heartbeat = ManagementHeartbeat::from_settings(
        &settings,
        "sha256:policy".into(),
        None,
        enrolment::token_source(Arc::clone(&enrolment)),
        Arc::clone(&store),
        Arc::new(JobCatalog::default()),
    )
    .unwrap();
    heartbeat.enrolment = Some(Arc::clone(&enrolment));
    Harness {
        management,
        clock,
        settings,
        enrolment,
        heartbeat,
        store,
    }
}

/// C# `Collector_EnrolsReportsRotatesAndReEnrolsThroughTheHeartbeatJob` (enrolment part).
#[tokio::test]
async fn enrols_once_then_every_request_carries_a_verifying_assertion() {
    let directory = tempfile::tempdir().unwrap();
    let harness = harness(directory.path(), Some(TOKEN)).await;

    harness.heartbeat.run().await.unwrap();
    harness.clock.advance(chrono::TimeDelta::minutes(1));
    harness.heartbeat.run().await.unwrap();

    let enrolled = harness.management.requests("/enrol");
    let key = harness.management.key(0);
    assert_eq!(enrolled.len(), 1);
    assert!(enrolled[0].authorization.is_none());
    assert_eq!(enrolled[0].body["token"], TOKEN);
    assert_eq!(enrolled[0].body["collectorId"], COLLECTOR_ID);
    assert_eq!(enrolled[0].body["environment"], "production");
    assert_eq!(enrolled[0].body["policyHash"], "sha256:policy");
    assert!(
        enrolled[0].body["publicKey"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
    let reports: Vec<Request> = harness
        .management
        .requests("")
        .into_iter()
        .filter(|request| !request.path.ends_with("/enrol"))
        .collect();
    assert_eq!(reports.len(), 4);
    for request in &reports {
        let (collector, credential) = verify(
            request.authorization.as_deref().unwrap(),
            &key,
            harness.clock.utc_now(),
        )
        .expect("every management request carries a verifying assertion");
        assert_eq!(collector, COLLECTOR_ID);
        assert_eq!(
            credential,
            bower_integrity::key_id_from_public_key_pem(&key).unwrap()
        );
    }
    let body = serde_json::to_string(&reports.last().unwrap().body).unwrap();
    assert!(body.contains("\"commandCapabilities\":[]"));

    // The file holds the key and the token's hash, never the token; owner-only.
    let file = harness
        .settings
        .management_credential_directory()
        .join(enrolment::CREDENTIAL_FILE_NAME);
    let stored = std::fs::read_to_string(&file).unwrap();
    assert!(!stored.contains(TOKEN));
    assert!(stored.contains(&bower_integrity::sha256_hex(TOKEN.as_bytes())));
    assert!(stored.contains("\"pendingPrivateKeyPem\":null"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    drop(harness.store);
}

/// C# `Collector_DoesNotRetryARefusedToken` and the lost-response retry.
#[tokio::test]
async fn lost_responses_reuse_the_key_and_refused_tokens_are_not_retried() {
    let directory = tempfile::tempdir().unwrap();
    let harness = harness(directory.path(), Some(TOKEN)).await;
    harness
        .management
        .scripted
        .lock()
        .unwrap()
        .push_back(StatusCode::INTERNAL_SERVER_ERROR);

    harness.heartbeat.run().await.unwrap();
    let pending = harness.enrolment.state().unwrap();
    harness.heartbeat.run().await.unwrap();
    let attempts = harness.management.requests("/enrol");

    assert!(pending.pending_private_key_pem.is_some());
    assert!(pending.credential_id.is_none());
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].body["publicKey"], attempts[1].body["publicKey"]);
    assert!(harness.enrolment.enrolled());

    // A new token that management refuses: recorded, never retried, old credential kept.
    let second = "bwe1.fedcba9876543210.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    std::fs::write(
        harness
            .settings
            .management_enrolment_token_file
            .as_ref()
            .unwrap(),
        second,
    )
    .unwrap();
    harness
        .management
        .scripted
        .lock()
        .unwrap()
        .push_back(StatusCode::UNAUTHORIZED);
    harness.enrolment.ensure_enrolled().await.unwrap();
    harness.enrolment.ensure_enrolled().await.unwrap();

    let state = harness.enrolment.state().unwrap();
    assert_eq!(harness.management.requests("/enrol").len(), 3);
    assert_eq!(
        state.refused_token_sha256.as_deref(),
        Some(bower_integrity::sha256_hex(second.as_bytes()).as_str())
    );
    assert!(state.pending_private_key_pem.is_none());
    assert!(harness.enrolment.enrolled());
}

/// C# `Collector_RemovesAUsedTokenFileOnlyWhenAskedAndOnlyAfterADefinitiveOutcome`.
#[tokio::test]
async fn removes_a_used_token_file_only_when_asked_and_after_a_definitive_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let management = Arc::new(Management::default());
    let clock = FakeClock(Arc::new(Mutex::new(start())));
    *management.now.lock().unwrap() = Some(clock.clone());
    let base = serve(Arc::clone(&management)).await;
    let kept = settings(directory.path(), &base, Some(TOKEN));
    let mut removing = kept.clone();
    removing.management_enrolment_token_remove_after_use = true;
    let file = kept.management_enrolment_token_file.clone().unwrap();
    let enrolment = |settings: &CollectorSettings| {
        ManagementEnrolment::from_settings(
            settings,
            "sha256:policy".into(),
            reqwest::Client::new(),
            Arc::new(clock.clone()),
        )
        .unwrap()
    };

    // Without the option the token file stays, as before.
    let first = enrolment(&kept);
    first.ensure_enrolled().await.unwrap();
    assert!(first.enrolled());
    assert!(file.exists());

    // An already consumed token still on disk is removed on the next attempt.
    enrolment(&removing).ensure_enrolled().await.unwrap();
    assert!(!file.exists());

    // A transient failure keeps the token for the retry; a refusal removes it.
    let second = "bwe1.fedcba9876543210.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    std::fs::write(&file, second).unwrap();
    management
        .scripted
        .lock()
        .unwrap()
        .push_back(StatusCode::INTERNAL_SERVER_ERROR);
    let retrying = enrolment(&removing);
    assert!(retrying.ensure_enrolled().await.is_err());
    assert!(file.exists());
    management
        .scripted
        .lock()
        .unwrap()
        .push_back(StatusCode::UNAUTHORIZED);
    retrying.ensure_enrolled().await.unwrap();
    assert!(!file.exists());
    assert!(retrying.enrolled());

    let mut invalid = removing.clone();
    invalid.management_enrolment_token_file = None;
    assert!(invalid.validate().is_err());
    assert_eq!(kept.configuration_hash(), removing.configuration_hash());
}

/// C# `Rotation_KeepsTheOldCredentialValidUntilTheNewOneIsUsed` from the collector side.
#[tokio::test]
async fn rotation_switches_keys_under_the_current_credential_and_runs_on_schedule() {
    let directory = tempfile::tempdir().unwrap();
    let harness = harness(directory.path(), Some(TOKEN)).await;
    harness.heartbeat.run().await.unwrap();

    let (status, code) = harness.enrolment.rotate().await;
    let rotation = harness.management.requests("/credentials/rotate");
    let (first, second) = (harness.management.key(0), harness.management.key(1));
    let now = harness.clock.utc_now();

    assert_eq!(
        (status, code),
        (results::SUCCEEDED, enrolment::CREDENTIAL_ROTATED)
    );
    assert_eq!(rotation.len(), 1);
    assert!(verify(rotation[0].authorization.as_deref().unwrap(), &first, now).is_some());
    assert_eq!(rotation[0].body["publicKey"], second);
    let next = format!("Bearer {}", harness.enrolment.create_assertion().unwrap());
    assert!(verify(&next, &second, now).is_some());
    assert!(verify(&next, &first, now).is_none());

    // Refused: the current credential stays and the next attempt uses a fresh key.
    harness
        .management
        .scripted
        .lock()
        .unwrap()
        .push_back(StatusCode::CONFLICT);
    assert_eq!(
        harness.enrolment.rotate().await,
        (results::FAILED, enrolment::ROTATION_REFUSED)
    );
    assert!(
        verify(
            &format!("Bearer {}", harness.enrolment.create_assertion().unwrap()),
            &second,
            now
        )
        .is_some()
    );

    // Not due at 19 days; due once 10 of the 30 days remain.
    harness.clock.advance(chrono::TimeDelta::days(19));
    harness.heartbeat.run().await.unwrap();
    assert_eq!(harness.management.requests("/credentials/rotate").len(), 2);
    harness.clock.advance(chrono::TimeDelta::days(2));
    harness.heartbeat.run().await.unwrap();
    assert_eq!(harness.management.requests("/credentials/rotate").len(), 3);
    let third = harness.management.key(2);
    assert!(
        verify(
            &format!("Bearer {}", harness.enrolment.create_assertion().unwrap()),
            &third,
            harness.clock.utc_now()
        )
        .is_some()
    );

    // An expired credential is never used: nothing is reported until a new token.
    harness.clock.advance(chrono::TimeDelta::days(31));
    let before = harness.management.requests("").len();
    harness.heartbeat.run().await.unwrap();
    assert!(!harness.enrolment.enrolled());
    assert_eq!(
        harness.enrolment.create_assertion(),
        Err("CredentialUnavailableException")
    );
    assert_eq!(harness.management.requests("").len(), before);
}

/// `rotate-credential` runs through the command worker (C# `ManagementCommandWorker`).
#[tokio::test]
async fn rotate_credential_command_rotates_and_reports_its_result() {
    let directory = tempfile::tempdir().unwrap();
    let harness = harness(directory.path(), Some(TOKEN)).await;
    harness.heartbeat.run().await.unwrap();
    let clock: Arc<dyn Clock> = Arc::new(harness.clock.clone());
    let ledger = Arc::new(CommandLedger::new(
        &harness.settings.management_command_directory(),
        Arc::clone(&clock),
    ));
    let loaded = bundle::load(&harness.settings).unwrap();
    let worker = CommandWorker {
        ledger: Arc::clone(&ledger),
        triggers: JobTriggers::default(),
        processor: SecurityEventProcessor::new(
            loaded.redactor,
            loaded.evaluator,
            Arc::clone(&harness.store),
            Arc::clone(&clock),
        ),
        identity: CollectorIdentity::new(
            COLLECTOR_ID.to_string(),
            "0.1.0".to_string(),
            "local-http",
            "c".to_string(),
        ),
        environment: "production".into(),
        clock,
        lifetime: ApplicationLifetime::new(),
        enrolment: Some(Arc::clone(&harness.enrolment)),
    };
    let command = VerifiedCommand {
        command_id: "a".repeat(32),
        command: commands::ROTATE_CREDENTIAL.into(),
        nonce: "b".repeat(32),
        issued_at: start(),
        expires_at: start() + chrono::TimeDelta::minutes(15),
    };
    ledger.admit(&command);

    worker.execute(&command).await;

    let reported = ledger.pending_results();
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0].status, results::SUCCEEDED);
    assert_eq!(reported[0].code, enrolment::CREDENTIAL_ROTATED);
    assert_eq!(harness.management.requests("/credentials/rotate").len(), 1);
}

/// The C# collector's credential file opens unchanged (shared format).
#[test]
fn reads_the_csharp_credential_file() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings(directory.path(), "https://bower-api.example.test/", None);
    let keys = bower_integrity::generate_key_pair();
    let credential_directory = settings.management_credential_directory();
    std::fs::create_dir_all(&credential_directory).unwrap();
    // As System.Text.Json writes ManagementCredentialState (Web defaults).
    let csharp = json!({
        "schemaVersion": 1, "collectorId": COLLECTOR_ID, "credentialId": keys.key_id,
        "privateKeyPem": keys.private_key_pem, "expiresAt": "2026-11-26T00:00:00.0000000Z",
        "pendingPrivateKeyPem": null, "consumedTokenSha256": "ab", "refusedTokenSha256": null
    });
    std::fs::write(
        credential_directory.join(enrolment::CREDENTIAL_FILE_NAME),
        serde_json::to_vec(&csharp).unwrap(),
    )
    .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(FakeClock(Arc::new(Mutex::new(start()))));

    let loaded = ManagementEnrolment::from_settings(
        &settings,
        "sha256:policy".into(),
        reqwest::Client::new(),
        Arc::clone(&clock),
    )
    .unwrap();
    let assertion = format!("Bearer {}", loaded.create_assertion().unwrap());

    assert!(loaded.enrolled());
    assert!(verify(&assertion, &keys.public_key_pem, start()).is_some());
    // Another collector id's credential is never used.
    let mut other = settings.clone();
    other.collector_id = "edge-other".into();
    let foreign =
        ManagementEnrolment::from_settings(&other, "p".into(), reqwest::Client::new(), clock)
            .unwrap();
    assert!(!foreign.enrolled());
}

/// C# `Settings_EnrolmentModeIsValidatedAndAdvertisesRotation`.
#[test]
fn enrolment_settings_match_csharp() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("command.pub.pem");
    std::fs::write(&key, bower_integrity::generate_key_pair().public_key_pem).unwrap();
    let mut entra = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.path().join("queue.db"),
        "policies",
        COLLECTOR_ID,
    );
    entra.management_endpoint = Some("https://bower-api.example.test/".parse().unwrap());
    entra.management_scope = Some("api://bower/.default".into());
    entra.management_command_trusted_key_files = vec![key.to_string_lossy().into_owned()];
    let mut enrolled = entra.clone();
    enrolled.management_authentication = "enrolment".into();
    enrolled.management_scope = None;
    enrolled.management_enrolment_token_file = Some(directory.path().join("token"));

    enrolled.validate().unwrap();
    let mut no_endpoint = enrolled.clone();
    no_endpoint.management_endpoint = None;
    no_endpoint.management_command_trusted_key_files.clear();
    assert!(no_endpoint.validate().is_err());
    let mut stray_token = entra.clone();
    stray_token.management_enrolment_token_file = Some("token".into());
    assert!(stray_token.validate().is_err());
    let mut unknown = entra.clone();
    unknown.management_authentication = "password".into();
    assert!(unknown.validate().is_err());
    let mut no_scope = entra.clone();
    no_scope.management_scope = None;
    assert!(no_scope.validate().is_err());
    assert_eq!(
        commands::supported(&enrolled),
        vec![
            commands::RUN_CANARY,
            commands::RELOAD,
            commands::ROTATE_CREDENTIAL
        ]
    );
    assert!(!commands::supported(&entra).contains(&commands::ROTATE_CREDENTIAL));

    let from_environment = CollectorSettings::from_environment(|name| match name {
        "BOWER_QUEUE_PATH" => Some(directory.path().join("queue.db").to_string_lossy().into()),
        "BOWER_MANAGEMENT_ENDPOINT" => Some("https://bower-api.example.test/".into()),
        "BOWER_MANAGEMENT_AUTH" => Some("Enrolment".into()),
        "BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE" => Some("/etc/bower/enrolment-token".into()),
        _ => None,
    })
    .unwrap();
    assert!(from_environment.uses_enrolment());

    // Pinned against C# `CollectorSettings.ConfigurationHash` (EnrolmentTests).
    let mut pinned =
        CollectorSettings::new("http://127.0.0.1:4319", "queue.db", "policies", "edge-01");
    pinned.management_endpoint = Some("https://bower-api.example.test/".parse().unwrap());
    pinned.management_authentication = "enrolment".into();
    assert_eq!(pinned.configuration_hash(), PINNED_ENROLMENT_HASH);
}

const PINNED_ENROLMENT_HASH: &str =
    "sha256:4e70f9ce806fbabf1922dd1d5b4fe7b753fe00ea9afcbeed18f07882dcb3204a";
