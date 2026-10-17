//! Port of `CollectorHostTests`: the real router, queue, policies and redaction,
//! driven in-process with `tower::ServiceExt::oneshot` (and one real listener).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bower_collector::auth::IngestAuthentication;
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::{AzureCredentialMode, CollectorSettings, bundle, server, shutdown};
use bower_contracts::SecurityEventEnvelope;
use bower_contracts::time::{Clock, Timestamp};
use tower::ServiceExt;

const TOKEN: &str = "test-ingest-token-0123456789abcdef0123456789";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn base_settings(directory: &Path) -> CollectorSettings {
    CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        repo_root().join("policies/default"),
        "collector-test",
    )
}

async fn start(
    directory: &Path,
    token: Option<&str>,
    adjust: impl FnOnce(&mut CollectorSettings),
) -> Collector {
    let mut settings = base_settings(directory);
    settings.ingest_token = token.map(str::to_string);
    adjust(&mut settings);
    let bundle = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings, bundle, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    collector
}

/// `TestEvents.AuthenticationFailure` serialized like `BowerJson.Options`.
fn authentication_failure(event_id: &str) -> SecurityEventEnvelope {
    let now = bower_contracts::time::format_json(&bower_contracts::time::now());
    let json = format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"{event_id}","eventOriginalId":"source-1","timeGenerated":"{now}",
        "eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt",
        "eventResult":"failure","eventOutcomeReason":"InvalidPassword",
        "application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"test-user"}},
        "source":{{"ipAddress":"192.0.2.10"}},"request":{{"correlationId":"correlation-1"}}}}"#
    );
    serde_json::from_str(&json).unwrap()
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn post(candidate: &SecurityEventEnvelope, token: Option<&str>) -> Request<Body> {
    let mut request = Request::post("/v1/events")
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(
            bower_contracts::json::to_vec(candidate).unwrap(),
        ))
        .unwrap();
    if let Some(token) = token {
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
    }
    request
}

async fn send(
    router: &Router,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::get(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn ingest_rejects_missing_and_wrong_tokens() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |_| {}).await;

    let (missing, headers, body) = send(
        &collector.router,
        post(&authentication_failure(&new_id()), None),
    )
    .await;
    let (wrong, _, _) = send(
        &collector.router,
        post(&authentication_failure(&new_id()), Some("wrong-token")),
    )
    .await;

    assert_eq!(missing, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(
        body,
        r#"{"error":"A valid collector ingest token is required."}"#
    );
}

#[tokio::test]
async fn ingest_accepts_valid_token_and_redacts_before_queueing() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |_| {}).await;
    let mut candidate = authentication_failure(&new_id());
    candidate.attributes = Some(
        [(
            "dbPassword".to_string(),
            bower_contracts::JsonElement::from("never-persist"),
        )]
        .into_iter()
        .collect(),
    );

    let (status, headers, body) = send(&collector.router, post(&candidate, Some(TOKEN))).await;
    let (duplicate, _, duplicate_body) =
        send(&collector.router, post(&candidate, Some(TOKEN))).await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    assert!(body.contains("redactandaccept"), "{body}");
    assert!(!body.contains("never-persist"));
    assert!(body.contains(r#""queued":true"#), "{body}");
    assert_eq!(duplicate, StatusCode::OK, "{duplicate_body}");
    assert!(duplicate_body.contains(r#""duplicate":true"#));
    // The secret field also raises a `sensitive_data_detected` privacy alert, as in C#.
    let queued = collector.store.lease(10, Duration::from_secs(60)).unwrap();
    assert!(
        queued
            .iter()
            .all(|event| !event.payload.contains("never-persist"))
    );
    let original: Vec<_> = queued
        .iter()
        .filter(|event| event.event_id == candidate.event_id)
        .collect();
    assert_eq!(original.len(), 1);
    assert!(original[0].payload.contains("local-http:default"));
    assert!(
        queued
            .iter()
            .filter(|event| event.event_id != candidate.event_id)
            .all(|event| event.payload.contains("sensitive_data_detected")),
        "unexpected extra events"
    );
}

#[tokio::test]
async fn ingest_reports_policy_rejection_as_422() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |_| {}).await;
    let mut candidate = authentication_failure(&new_id());
    candidate.event_type = "page_view".into();
    candidate.event_category = "telemetry".into();

    let (status, _, body) = send(&collector.router, post(&candidate, Some(TOKEN))).await;

    assert!(
        status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST,
        "{status} {body}"
    );
    assert!(body.contains(r#""queued":false"#), "{body}");
}

#[tokio::test]
async fn ingest_enforces_content_type_size_and_json() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |_| {}).await;
    let authorized = |body: Body, content_type: &str| {
        Request::post("/v1/events")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_TYPE, content_type)
            .body(body)
            .unwrap()
    };

    let (unsupported, _, _) = send(
        &collector.router,
        authorized(Body::from("{}"), "text/plain"),
    )
    .await;
    let (malformed, _, _) = send(
        &collector.router,
        authorized(Body::from("{\"a\":"), "application/json"),
    )
    .await;
    let (empty, _, _) = send(
        &collector.router,
        authorized(Body::empty(), "application/json"),
    )
    .await;
    let large = format!("{{\"a\":\"{}\"}}", "x".repeat(1_048_576));
    let (too_large, _, _) = send(
        &collector.router,
        authorized(Body::from(large), "application/json"),
    )
    .await;
    let (quarantined, _, body) = send(
        &collector.router,
        authorized(Body::from("[1,2]"), "application/json"),
    )
    .await;

    assert_eq!(unsupported, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(malformed, StatusCode::BAD_REQUEST);
    assert_eq!(empty, StatusCode::BAD_REQUEST);
    assert_eq!(too_large, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(quarantined, StatusCode::BAD_REQUEST);
    assert!(body.contains(r#""decision":"quarantine""#), "{body}");
    assert!(body.contains(r#""eventId":null"#), "{body}");
    assert!(body.contains(r#""policy":null"#), "{body}");
}

#[tokio::test]
async fn health_is_anonymous_but_status_requires_token() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |_| {}).await;

    let (_, _, health) = send(&collector.router, get("/health", None)).await;
    let (anonymous, _, _) = send(&collector.router, get("/v1/status", None)).await;
    let (status, _, body) = send(&collector.router, get("/v1/status", Some(TOKEN))).await;

    assert_eq!(health, r#"{"status":"healthy"}"#);
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("queue-retention"), "{body}");
    assert!(body.contains("queue-maintenance"), "{body}");
    assert!(body.contains(r#""schedule":"0 3 * * *""#), "{body}");
    assert!(body.contains(r#""ledger":{"sequence":"#), "{body}");
    assert!(body.contains(r#""oldestUndelivered":null"#), "{body}");
}

#[tokio::test]
async fn ingest_rate_limits_bursts() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |settings| {
        settings.ingest_requests_per_second = 1
    })
    .await;

    let mut statuses = Vec::new();
    for index in 0..4 {
        let mut candidate = authentication_failure(&format!("burst-{index}"));
        candidate.event_original_id = Some(format!("burst-{index}"));
        statuses.push(
            send(&collector.router, post(&candidate, Some(TOKEN)))
                .await
                .0,
        );
    }

    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

#[test]
fn producer_tokens_are_revocable_without_restart() {
    let directory = tempfile::tempdir().unwrap();
    let sidecar = "sidecar-token-0123456789abcdefghijklmnop";
    let app = "app-token-0123456789abcdefghijklmnopqrstu";
    let tokens_file = directory.path().join("tokens");
    std::fs::write(
        &tokens_file,
        format!(
            "# producer credentials\n{}\n{}\n",
            IngestAuthentication::tokens_file_line("sidecar-01", sidecar),
            IngestAuthentication::tokens_file_line("portal", app)
        ),
    )
    .unwrap();
    let clock = FakeClock(Arc::new(Mutex::new(bower_contracts::time::now())));
    let authentication =
        IngestAuthentication::with_clock(None, Some(&tokens_file), Arc::new(clock.clone()))
            .unwrap();

    let before = authentication.authenticate(Some(&format!("Bearer {sidecar}")));
    std::fs::write(
        &tokens_file,
        format!(
            "{}\n",
            IngestAuthentication::tokens_file_line("portal", app)
        ),
    )
    .unwrap();
    let file = std::fs::File::options()
        .write(true)
        .open(&tokens_file)
        .unwrap();
    file.set_modified(std::time::SystemTime::now() + Duration::from_secs(5))
        .unwrap();
    *clock.0.lock().unwrap() += chrono::TimeDelta::seconds(3);
    let revoked = authentication.authenticate(Some(&format!("Bearer {sidecar}")));
    let kept = authentication.authenticate(Some(&format!("Bearer {app}")));

    assert_eq!(before.as_deref(), Some("sidecar-01"));
    assert_eq!(revoked, None);
    assert_eq!(kept.as_deref(), Some("portal"));
}

#[test]
fn producer_tokens_reject_malformed_file() {
    let directory = tempfile::tempdir().unwrap();
    let tokens_file = directory.path().join("tokens");
    std::fs::write(&tokens_file, "sidecar-01 not-a-hash\n").unwrap();

    let error = IngestAuthentication::new(None, Some(&tokens_file))
        .err()
        .unwrap();

    assert_eq!(error.kind, "FormatException");
}

#[test]
fn settings_refuse_unverified_packs() {
    let mut settings = base_settings(Path::new("unused"));
    settings.packs = vec!["x.bowerpack".into()];

    assert_eq!(
        settings.validate().unwrap_err().kind,
        "InvalidOperationException"
    );
}

#[test]
fn settings_require_token_on_non_loopback_listener() {
    let mut settings = base_settings(Path::new("unused"));
    settings.listen_url = "http://0.0.0.0:4319".into();

    let error = settings.validate().unwrap_err();

    assert!(error.message.contains("BOWER_INGEST_TOKEN"));
}

#[test]
fn settings_allow_explicit_unauthenticated_opt_out() {
    let mut settings = base_settings(Path::new("unused"));
    settings.listen_url = "http://0.0.0.0:4319".into();
    settings.allow_unauthenticated_ingest = true;

    settings.validate().unwrap();
}

#[test]
fn settings_reject_short_token() {
    let mut settings = base_settings(Path::new("unused"));
    settings.ingest_token = Some("short".into());

    assert!(settings.validate().is_err());
}

#[test]
fn settings_require_https_for_remote_management() {
    for (endpoint, valid) in [
        ("http://management.example.test", false),
        ("https://management.example.test", true),
        ("http://127.0.0.1:4320", true),
        ("http://[::1]:4320", true),
        ("http://localhost:4320", true),
    ] {
        let mut settings = base_settings(Path::new("unused"));
        settings.management_endpoint = Some(endpoint.parse().unwrap());
        settings.management_scope = Some("api://bower/.default".into());

        assert_eq!(settings.validate().is_ok(), valid, "{endpoint}");
    }
}

#[test]
fn settings_read_from_environment_with_token_file() {
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let token_path = token_file.to_string_lossy().to_string();
    let environment = [
        ("BOWER_LISTEN_URL", "http://0.0.0.0:4319"),
        ("BOWER_INGEST_TOKEN_FILE", token_path.as_str()),
        ("BOWER_QUEUE_RETENTION_HOURS", "48"),
        ("BOWER_AZURE_CREDENTIAL", "workload-identity"),
        ("BOWER_PACKS", " a.bowerpack ; ,b.bowerpack"),
        ("BOWER_PACK_TRUSTED_KEYS", "k.pem"),
        ("BOWER_OUTPUT", "AMA-Spool"),
    ];
    let read = |name: &str| {
        environment
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_string())
    };

    let settings = CollectorSettings::from_environment(read).unwrap();

    assert_eq!(settings.ingest_token.as_deref(), Some(TOKEN));
    assert_eq!(settings.delivered_retention, Duration::from_secs(48 * 3600));
    assert_eq!(
        settings.azure_credential,
        AzureCredentialMode::WorkloadIdentity
    );
    assert_eq!(settings.packs, ["a.bowerpack", "b.bowerpack"]);
    assert_eq!(settings.output_type, "ama-spool");
    assert_eq!(settings.privacy_hmac_key_id, "k1");
    assert_eq!(settings.stream_name, "Custom-BowerSecurity");
}

/// Environment overrides, expected exception type, expected message fragment.
type SettingsCase = (
    &'static [(&'static str, &'static str)],
    &'static str,
    &'static str,
);

#[test]
fn settings_report_dotnet_style_errors() {
    let cases: [SettingsCase; 6] = [
        (
            &[("BOWER_QUEUE_MAX_BYTES", "ten")],
            "InvalidOperationException",
            "BOWER_QUEUE_MAX_BYTES must be an integer.",
        ),
        (
            &[("BOWER_QUEUE_MAX_BYTES", "1024")],
            "InvalidOperationException",
            "BOWER_QUEUE_MAX_BYTES must be at least 1 MiB.",
        ),
        (
            &[("BOWER_QUEUE_RETENTION_HOURS", "0")],
            "InvalidOperationException",
            "BOWER_QUEUE_RETENTION_HOURS must be between 1 and 2160.",
        ),
        (
            &[("BOWER_OUTPUT", "kafka")],
            "InvalidOperationException",
            "Unsupported BOWER_OUTPUT value: kafka",
        ),
        (
            &[("BOWER_OUTPUT", "azure-logs-ingestion")],
            "InvalidOperationException",
            "BOWER_DCE_ENDPOINT and BOWER_DCR_ID are required for azure-logs-ingestion.",
        ),
        (
            &[("BOWER_MANAGEMENT_ENDPOINT", "https://m.example")],
            "InvalidOperationException",
            "BOWER_MANAGEMENT_SCOPE is required when BOWER_MANAGEMENT_ENDPOINT is set.",
        ),
    ];
    for (environment, kind, message) in cases {
        let read = |name: &str| {
            environment
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        };
        let error = CollectorSettings::from_environment(read).unwrap_err();
        assert_eq!((error.kind, error.message.as_str()), (kind, message));
    }
}

#[test]
fn configuration_hash_excludes_secrets() {
    let mut settings = base_settings(Path::new("unused"));
    settings.ingest_token = Some("a".repeat(40));
    let first = settings.configuration_hash();
    settings.ingest_token = Some("b".repeat(40));

    assert_eq!(first, settings.configuration_hash());
    assert!(first.starts_with("sha256:"));
}

/// Real listener on 127.0.0.1:0: serve, ingest, then a clean shutdown.
#[tokio::test]
async fn serves_on_a_real_listener_and_shuts_down_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let mut collector = start(directory.path(), Some(TOKEN), |settings| {
        settings.output_type = "ama-spool".into();
        settings.ama_spool_path = directory.path().join("spool");
    })
    .await;
    let output = host::create_output(&collector.settings, None).unwrap();
    assert!(output.is_some());
    collector.set_output(output);
    let listeners = server::bind(&["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let address = listeners[0].local_addr().unwrap();
    let (trigger, token) = shutdown::channel();
    let running = tokio::spawn(collector.run(listeners, token));

    let client = reqwest::Client::new();
    let health = client
        .get(format!("http://{address}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    assert!(health.headers().get("server").is_none());
    let response = client
        .post(format!("http://{address}/v1/events"))
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .body(bower_contracts::json::to_vec(&authentication_failure(&new_id())).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    // `healthcheck` is blocking; keep it off the single-threaded test runtime.
    let listen_url = format!("http://{address}");
    assert!(
        tokio::task::spawn_blocking(move || server::healthcheck(&listen_url))
            .await
            .unwrap()
    );

    // The worker drains the queue into the AMA spool.
    let ready = directory.path().join("spool/ready");
    let mut spooled = false;
    for _ in 0..100 {
        if std::fs::read_dir(&ready)
            .map(|entries| entries.count() > 0)
            .unwrap_or(false)
        {
            spooled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(spooled, "event was not delivered to the spool");

    trigger.cancel();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .unwrap()
        .unwrap();
    assert!(
        client
            .get(format!("http://{address}/health"))
            .send()
            .await
            .is_err()
    );
}
