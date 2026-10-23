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

fn signed_ssh_settings(directory: &Path) -> CollectorSettings {
    let keys = bower_integrity::generate_key_pair();
    let archive = bower_packs::build(
        &repo_root().join("packs/linux-ssh-gateway"),
        &keys.private_key_pem,
        directory,
        None,
    )
    .unwrap();
    let public_key = directory.join("trusted.pem");
    std::fs::write(&public_key, keys.public_key_pem).unwrap();
    let privacy_key = directory.join("privacy.key");
    std::fs::write(&privacy_key, [0xabu8; 32]).unwrap();
    let mut settings = base_settings(directory);
    settings.policy_directory = directory.join("no-directory-policies");
    settings.packs = vec![archive.to_string_lossy().into_owned()];
    settings.pack_trusted_key_files = vec![public_key.to_string_lossy().into_owned()];
    settings.privacy_hmac_key_file = Some(privacy_key);
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    settings.ingest_requests_per_second = 1000;
    settings
}

fn raw_ssh(id: &str, result: &str) -> String {
    serde_json::json!({
        "id": id, "timestamp": bower_contracts::time::format_json(&bower_contracts::time::now()),
        "user": "raw-test-user", "source_ip": "203.0.113.5", "result": result,
        "password": "discard-unknown-secret"
    })
    .to_string()
}

fn post_raw(path: &str, body: String, token: Option<&str>) -> Request<Body> {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(Body::from(body)).unwrap()
}

const SSH_RUNTIME_PATH: &str = "/v1/packs/linux-ssh-gateway/parsers/0/events";

#[tokio::test]
async fn signed_pack_raw_events_queue_redacted_detection_evidence_and_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let settings = signed_ssh_settings(directory.path());
    let loaded = bundle::load(&settings).unwrap();
    assert_eq!(loaded.info.packs[0].parser_statuses, ["active-local-json"]);
    assert_eq!(loaded.info.packs[0].detection_status, "active-local");
    assert_eq!(loaded.info.packs[0].dcr_status, "packaged-only");
    let mut collector = host::build(settings.clone(), loaded, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    let raw = raw_ssh("raw-durable", "failure");
    let (status, _, body) = send(
        &collector.router,
        post_raw(SSH_RUNTIME_PATH, raw.clone(), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(!body.contains("raw-test-user"));
    let (status, _, body) = send(
        &collector.router,
        post_raw(SSH_RUNTIME_PATH, raw, Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"duplicate\":true"));

    // Semantic ingest uses exactly the same local rules and cannot forge evidence.
    let mut semantic = authentication_failure("semantic-detection");
    semantic.application.name = "ssh-gateway".into();
    semantic.application.environment = "production".into();
    semantic.attributes = Some(
        [(
            "BOWERDETECTIONS".into(),
            bower_contracts::JsonElement::from("forged-evidence"),
        )]
        .into_iter()
        .collect(),
    );
    let (status, _, body) = send(&collector.router, post(&semantic, Some(TOKEN))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    drop(collector);

    let mut reopened = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    reopened.initialize().await.unwrap();
    let queued = reopened.store.lease(10, Duration::from_secs(60)).unwrap();
    // HMAC redaction may emit existing privacy alerts, but no separate detection event.
    for row in &queued {
        assert!(!row.payload.contains("raw-test-user"));
        assert!(!row.payload.contains("discard-unknown-secret"));
        assert!(!row.payload.contains("forged-evidence"));
    }
    for id in ["raw-durable", "semantic-detection"] {
        let source = queued.iter().find(|row| row.event_id == id).unwrap();
        let event: serde_json::Value = serde_json::from_str(&source.payload).unwrap();
        let evidence = &event["attributes"]["bowerDetections"][0];
        assert_eq!(evidence.as_object().unwrap().len(), 4);
        assert_eq!(evidence["ruleId"], "bower-pack-ssh-auth-failure-001");
        assert_eq!(evidence["ruleVersion"], "1.0.0");
        assert!(evidence["ruleHash"].as_str().unwrap().len() >= 64);
        assert!(
            evidence["mitreTechniques"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item == "T1110")
        );
        if id == "raw-durable" {
            assert_eq!(event["eventOriginalId"], id);
            assert_eq!(
                event["collector"]["sourceAdapter"],
                "pack-http:default:linux-ssh-gateway:0"
            );
        }
    }
    assert_eq!(
        queued
            .iter()
            .filter(|row| row.event_id == "raw-durable")
            .count(),
        1
    );
    assert!(queued.iter().all(|row| row.event_id == "raw-durable"
        || row.event_id == "semantic-detection"
        || row.payload.contains("sensitive_data_detected")));
}

#[tokio::test]
async fn pack_ingest_filters_bounds_and_auth_fail_without_queueing() {
    let directory = tempfile::tempdir().unwrap();
    let settings = signed_ssh_settings(directory.path());
    let mut collector = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    collector.initialize().await.unwrap();
    let valid = raw_ssh("not-queued", "failure");
    let mut cases = vec![
        (valid.clone(), None, StatusCode::UNAUTHORIZED),
        (
            raw_ssh("not-queued", "success"),
            Some(TOKEN),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            raw_ssh("not-queued", "Failure"),
            Some(TOKEN),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("[]".into(), Some(TOKEN), StatusCode::BAD_REQUEST),
        ("{".into(), Some(TOKEN), StatusCode::BAD_REQUEST),
        (
            valid.replacen('{', "{\"id\":\"duplicate\",", 1),
            Some(TOKEN),
            StatusCode::BAD_REQUEST,
        ),
        (
            valid.replace("raw-test-user", &"u".repeat(2049)),
            Some(TOKEN),
            StatusCode::BAD_REQUEST,
        ),
        (
            raw_ssh(&"i".repeat(129), "failure"),
            Some(TOKEN),
            StatusCode::BAD_REQUEST,
        ),
        (
            valid.replace("203.0.113.5", "not-an-address"),
            Some(TOKEN),
            StatusCode::BAD_REQUEST,
        ),
        (
            " ".repeat(32_769),
            Some(TOKEN),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ];
    let mut object: serde_json::Value = serde_json::from_str(&valid).unwrap();
    object["timestamp"] = "2026-10-23T10:00:00".into();
    cases.push((object.to_string(), Some(TOKEN), StatusCode::BAD_REQUEST));
    object["timestamp"] = 123.into();
    cases.push((object.to_string(), Some(TOKEN), StatusCode::BAD_REQUEST));
    let nested = format!("{}0{}", "[".repeat(16), "]".repeat(16));
    cases.push((
        valid.replacen('{', &format!("{{\"deep\":{nested},"), 1),
        Some(TOKEN),
        StatusCode::BAD_REQUEST,
    ));
    for (body, token, expected) in cases {
        let (status, _, response) =
            send(&collector.router, post_raw(SSH_RUNTIME_PATH, body, token)).await;
        assert_eq!(status, expected, "{response}");
        assert!(!response.contains("raw-test-user"));
        assert!(!response.contains("discard-unknown-secret"));
    }
    for path in [
        "/v1/packs/missing/parsers/0/events",
        "/v1/packs/linux-ssh-gateway/parsers/99/events",
        "/v1/packs/linux-ssh-gateway/parsers/-1/events",
    ] {
        assert_eq!(
            send(
                &collector.router,
                post_raw(path, valid.clone(), Some(TOKEN))
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    assert!(
        collector
            .store
            .lease(10, Duration::from_secs(60))
            .unwrap()
            .is_empty()
    );

    // Authorization sees static application and mapped source identity, before processing.
    let scopes = directory.path().join("scopes.json");
    std::fs::write(&scopes, r#"[{"producer":"default","application":{"name":"ssh-gateway","environment":"production"},"source":{"ipAddress":"192.0.2.77"}}]"#).unwrap();
    let mut restricted = settings;
    restricted.single_trust_domain = false;
    restricted.producer_scopes_file = Some(scopes);
    let restricted = host::build(
        restricted.clone(),
        bundle::load(&restricted).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    assert_eq!(
        send(
            &restricted.router,
            post_raw(SSH_RUNTIME_PATH, valid, Some(TOKEN))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(
        restricted
            .store
            .lease(10, Duration::from_secs(60))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn pack_backpressure_preserves_existing_rows_and_retry_can_succeed() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = signed_ssh_settings(directory.path());
    settings.maximum_queue_bytes = 1_048_576;
    let mut collector = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    collector.initialize().await.unwrap();
    collector
        .store
        .enqueue(&bower_contracts::QueuedEvent {
            event_id: "filler".into(),
            fingerprint: "sha256:filler".into(),
            payload: "x".repeat(1_048_000),
            received_at: bower_contracts::time::now(),
            state: bower_contracts::QueueState::Queued,
            delivery_attempts: 0,
        })
        .unwrap();
    let raw = raw_ssh("after-capacity", "failure");
    let (status, _, _) = send(
        &collector.router,
        post_raw(SSH_RUNTIME_PATH, raw.clone(), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let rows = collector.store.lease(10, Duration::from_secs(60)).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_id, "filler");
    collector
        .store
        .mark_delivered("filler", "test-ack", rows[0].lease_token.as_deref())
        .unwrap();
    assert_eq!(
        send(
            &collector.router,
            post_raw(SSH_RUNTIME_PATH, raw, Some(TOKEN))
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        collector.store.lease(10, Duration::from_secs(60)).unwrap()[0].event_id,
        "after-capacity"
    );
}

#[tokio::test]
async fn pack_rate_limit_and_cancelled_body_never_persist_input() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = signed_ssh_settings(directory.path());
    settings.ingest_requests_per_second = 1;
    let mut collector = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    collector.initialize().await.unwrap();
    let (started, received) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let request = Request::post(SSH_RUNTIME_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::new(PendingRawBody {
            started: Some(started),
            dropped: dropped.clone(),
        }))
        .unwrap();
    let router = collector.router.clone();
    let task = tokio::spawn(async move { router.oneshot(request).await });
    tokio::time::timeout(Duration::from_secs(5), received)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            send(
                &collector.router,
                post_raw(SSH_RUNTIME_PATH, "{".into(), Some(TOKEN)),
            )
            .await
            .0,
        );
    }
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
    assert!(
        collector
            .store
            .lease(10, Duration::from_secs(60))
            .unwrap()
            .is_empty()
    );
}

struct PendingRawBody {
    started: Option<tokio::sync::oneshot::Sender<()>>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl hyper::body::Body for PendingRawBody {
    type Data = hyper::body::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        std::task::Poll::Pending
    }
}

impl Drop for PendingRawBody {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn historical_preview_only_parser_is_inactive_and_rejects_raw_ingest() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = signed_ssh_settings(directory.path());
    let fixtures = repo_root().join("rust/crates/bower-packs/tests/fixtures");
    settings.packs = vec![
        fixtures
            .join("linux-ssh-gateway-1.0.0.bowerpack")
            .to_string_lossy()
            .into_owned(),
    ];
    settings.pack_trusted_key_files = vec![
        fixtures
            .join("csharp-signing.pub.pem")
            .to_string_lossy()
            .into_owned(),
    ];
    let loaded = bundle::load(&settings).unwrap();
    assert_eq!(
        loaded.info.packs[0].parser_statuses,
        ["inactive-preview-only"]
    );
    let mut collector = host::build(settings, loaded, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    assert_eq!(
        send(
            &collector.router,
            post_raw(
                SSH_RUNTIME_PATH,
                raw_ssh("inactive", "failure"),
                Some(TOKEN)
            )
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(
        collector
            .store
            .lease(10, Duration::from_secs(60))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn pack_bundle_rejects_duplicate_pack_identity() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = signed_ssh_settings(directory.path());
    settings.packs.push(settings.packs[0].clone());
    assert!(bundle::load(&settings).is_err());
}

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
    settings.single_trust_domain = true;
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

#[tokio::test]
async fn scoped_producer_cannot_impersonate_or_mix_identity_tuples() {
    let directory = tempfile::tempdir().unwrap();
    let scopes = directory.path().join("scopes.json");
    std::fs::write(&scopes, r#"[
      {"producer":"default","application":{"name":"TestApplication","environment":"test","tenantId":"tenant-a","instance":"instance-a"},"source":{"ipAddress":"192.0.2.10","hostname":"host-a","port":123}},
      {"producer":"default","application":{"name":"OtherApplication","environment":"test","tenantId":"tenant-b","instance":"instance-b"},"source":{"ipAddress":"192.0.2.20","hostname":"host-b","port":456}}
    ]"#).unwrap();
    let collector = start(directory.path(), Some(TOKEN), |s| {
        s.single_trust_domain = false;
        s.producer_scopes_file = Some(scopes);
    })
    .await;
    let mut candidate = authentication_failure(&new_id());
    candidate.application.tenant_id = Some("tenant-a".into());
    candidate.application.instance = Some("instance-a".into());
    candidate.source.as_mut().unwrap().hostname = Some("host-a".into());
    candidate.source.as_mut().unwrap().port = Some(123);
    let mut variants = Vec::new();
    for field in 0..8 {
        let mut changed = candidate.clone();
        match field {
            0 => changed.application.name = "OtherApplication".into(),
            1 => changed.application.environment = "production".into(),
            2 => changed.application.tenant_id = Some("tenant-b".into()),
            3 => changed.application.instance = Some("instance-b".into()),
            4 => changed.source.as_mut().unwrap().ip_address = Some("192.0.2.20".into()),
            5 => changed.source.as_mut().unwrap().hostname = Some("host-b".into()),
            6 => changed.source.as_mut().unwrap().port = Some(456),
            _ => changed.application.tenant_id = None,
        }
        variants.push(changed);
    }
    for changed in variants {
        let (status, _, _) = send(&collector.router, post(&changed, Some(TOKEN))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert!(
        collector
            .store
            .lease(100, Duration::from_secs(60))
            .unwrap()
            .is_empty()
    );
    let (status, _, _) = send(&collector.router, post(&candidate, Some(TOKEN))).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn default_without_scopes_denies_authenticated_ingest() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |s| {
        s.single_trust_domain = false
    })
    .await;
    let (status, _, _) = send(
        &collector.router,
        post(&authentication_failure(&new_id()), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        collector
            .store
            .lease(10, Duration::from_secs(60))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn semantic_canaries_absent_from_queue_wal_spool_and_captured_outbound() {
    use axum::{body::Bytes, extract::State, routing::post as route_post};
    use bower_contracts::OutputAdapter;
    use bower_output_ama_spool::{AmaSpoolOptions, AmaSpoolOutput};
    use bower_output_azure::{
        AccessToken, AzureLogsIngestionOptions, AzureLogsIngestionOutput, IngestionClientOptions,
        TokenFuture, TokenProvider,
    };
    use std::io::Read;
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), Some(TOKEN), |_| {}).await;
    let database = directory.path().join("queue.db");
    let reader = rusqlite::Connection::open(&database).unwrap();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM queue_events;")
        .unwrap();
    let mut candidate = authentication_failure(&new_id());
    candidate.change = Some(bower_contracts::ChangeContext {
        field: Some("password".into()),
        previous_value: Some("before-canary".into()),
        new_value: Some("after-canary".into()),
    });
    candidate.request.as_mut().unwrap().path = Some(
        "https://u:userinfo-canary@example.test/login?opaque=query-canary#fragment-canary".into(),
    );
    let (status, _, response) = send(&collector.router, post(&candidate, Some(TOKEN))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    let batch = collector.store.lease(10, Duration::from_secs(60)).unwrap();
    assert!(batch.iter().any(|e| e.event_id == candidate.event_id));
    assert!(batch.iter().all(|e| !e.payload.contains("canary")));
    let wal = directory.path().join("queue.db-wal");
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    for path in [&database, &wal] {
        let bytes = std::fs::read(path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("canary"));
    }
    let ready = directory.path().join("ready");
    let spool = AmaSpoolOutput::new(AmaSpoolOptions::new(
        "test",
        "test",
        "Custom-BowerSecurity",
        directory.path().join("active"),
        &ready,
    ))
    .unwrap();
    let spooled = spool.deliver(&batch).await;
    assert_eq!(spooled.acknowledged_event_ids.len(), batch.len());
    let files: Vec<_> = std::fs::read_dir(&ready).unwrap().collect();
    assert!(!files.is_empty());
    for file in files {
        assert!(
            !std::fs::read_to_string(file.unwrap().path())
                .unwrap()
                .contains("canary")
        );
    }
    struct Credential;
    impl TokenProvider for Credential {
        fn get_token<'a>(&'a self, _: &'a str) -> TokenFuture<'a> {
            Box::pin(async {
                Ok(AccessToken {
                    token: "synthetic-test-token".into(),
                    expires_on: bower_contracts::time::now() + chrono::Duration::hours(1),
                })
            })
        }
    }
    async fn capture(State(bodies): State<Arc<Mutex<Vec<String>>>>, bytes: Bytes) -> StatusCode {
        let mut text = String::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_string(&mut text)
            .unwrap();
        bodies.lock().unwrap().push(text);
        StatusCode::NO_CONTENT
    }
    let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock = Router::new()
        .route(
            "/dataCollectionRules/{rule}/streams/{stream}",
            route_post(capture),
        )
        .with_state(bodies.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let output = AzureLogsIngestionOutput::with_client_options(
        AzureLogsIngestionOptions::new(
            "test",
            "https://simulated.ingest.monitor.azure.com"
                .parse()
                .unwrap(),
            "dcr-test",
            "Custom-BowerSecurity",
        ),
        Arc::new(Credential),
        IngestionClientOptions {
            transport_base_url: Some(format!("http://{address}").parse().unwrap()),
            max_retries: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let delivered = output.deliver(&batch).await;
    assert_eq!(delivered.acknowledged_event_ids.len(), batch.len());
    let recorded = bodies.lock().unwrap();
    assert!(!recorded.is_empty());
    assert!(recorded.iter().all(|body| !body.contains("canary")));
    server.abort();
    reader.execute_batch("ROLLBACK;").unwrap();
}
