//! `BOWER_OUTPUT=http` in the collector (C# `HttpOutputTests`): settings, the
//! configuration hash, bounded failure codes, queue settlement and status. Its own test
//! binary: the captured `tracing` subscriber must not race other tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use bower_collector::host::{self, BuildOptions};
use bower_collector::worker::{QueueDeliveryOptions, QueueDeliveryWorker, is_http_output_code};
use bower_collector::{CollectorSettings, bundle, shutdown};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{DurableEventStore, QueueState, QueuedEvent};
use bower_output_http::{HttpOutput, HttpOutputFormat, HttpOutputOptions};
use bower_persistence::SqliteEventStore;
use tower::ServiceExt;

fn environment(overrides: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let mut values: HashMap<String, String> = [
        ("BOWER_COLLECTOR_ID", "edge-01"),
        ("BOWER_OUTPUT", "http"),
        (
            "BOWER_HTTP_URL",
            "https://splunk.example.test:8088/services/collector/event",
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect();
    for (name, value) in overrides {
        values.insert((*name).to_string(), (*value).to_string());
    }
    move |name| values.get(name).cloned()
}

fn message(result: Result<CollectorSettings, bower_collector::HostError>) -> String {
    result.expect_err("settings must be refused").to_string()
}

#[test]
fn settings_read_validate_and_build_options() {
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("hec-token");
    std::fs::write(&token_file, "11111111-2222-3333-4444-555555555555\n").unwrap();
    let path = token_file.to_string_lossy().into_owned();
    let settings = CollectorSettings::from_environment(environment(&[
        ("BOWER_HTTP_TOKEN_FILE", &path),
        ("BOWER_HTTP_HEC_INDEX", "security"),
        ("BOWER_HTTP_MAX_BATCH_BYTES", "500000"),
        ("BOWER_HTTP_GZIP", "TRUE"),
    ]))
    .unwrap();
    let http = settings.http_output.as_ref().unwrap();
    let options = http.options(&settings.collector_id).unwrap();

    assert_eq!(settings.output_type, "http");
    assert_eq!(options.format, HttpOutputFormat::SplunkHec);
    assert_eq!(options.hec_host, "edge-01");
    assert_eq!(options.hec_index.as_deref(), Some("security"));
    assert_eq!(options.hec_source_type, "bower:security");
    assert_eq!(options.maximum_batch_bytes, 500_000);
    assert!(options.gzip);
    assert_eq!(
        http.read_token().unwrap(),
        "11111111-2222-3333-4444-555555555555"
    );
}

#[test]
fn settings_refuse_invalid_configuration_with_the_csharp_messages() {
    for (name, value, expected) in [
        (
            "BOWER_OUTPUT",
            "none",
            "BOWER_HTTP_* settings require BOWER_OUTPUT=http.",
        ),
        (
            "BOWER_HTTP_URL",
            "http://splunk.example.test/x",
            "BOWER_HTTP_URL must be an absolute https:// URL",
        ),
        (
            "BOWER_HTTP_URL",
            "not a url",
            "BOWER_HTTP_URL must be an absolute https:// URL.",
        ),
        (
            "BOWER_HTTP_TOKEN",
            "also-set",
            "BOWER_OUTPUT=http requires exactly one of BOWER_HTTP_TOKEN_FILE",
        ),
        (
            "BOWER_HTTP_FORMAT",
            "json",
            "BOWER_HTTP_FORMAT must be splunk-hec or ndjson.",
        ),
        (
            "BOWER_HTTP_AUTH_HEADER",
            "X-Api-Key",
            "BOWER_HTTP_AUTH_HEADER applies to BOWER_HTTP_FORMAT=ndjson only",
        ),
        (
            "BOWER_HTTP_HEC_INDEX",
            "Security",
            "BOWER_HTTP_HEC_INDEX must be",
        ),
        (
            "BOWER_HTTP_HEC_CHANNEL",
            "not-a-guid",
            "BOWER_HTTP_HEC_CHANNEL must be a GUID",
        ),
        (
            "BOWER_HTTP_HEC_SOURCETYPE",
            "bower\u{1}",
            "BOWER_HTTP_HEC_SOURCETYPE must be 1 to 256 characters",
        ),
        (
            "BOWER_HTTP_MAX_BATCH_BYTES",
            "100",
            "BOWER_HTTP_MAX_BATCH_BYTES must be between 1024 and 16777216.",
        ),
        (
            "BOWER_HTTP_MAX_BATCH_EVENTS",
            "0",
            "BOWER_HTTP_MAX_BATCH_EVENTS must be between 1 and 10000.",
        ),
        (
            "BOWER_HTTP_TIMEOUT_SECONDS",
            "301",
            "BOWER_HTTP_TIMEOUT_SECONDS must be between 1 and 300.",
        ),
        (
            "BOWER_HTTP_TIMEOUT_SECONDS",
            "ten",
            "BOWER_HTTP_TIMEOUT_SECONDS must be an integer.",
        ),
        (
            "BOWER_HTTP_GZIP",
            "yes",
            "BOWER_HTTP_GZIP must be true or false.",
        ),
    ] {
        let error = message(CollectorSettings::from_environment(environment(&[
            ("BOWER_HTTP_TOKEN_FILE", "/run/secrets/hec-token"),
            (name, value),
        ])));
        assert!(error.contains(expected), "{name}={value:?}: {error}");
    }
    for header in ["Content-Type", "host", "Proxy-Authorization", "X Api"] {
        let error = message(CollectorSettings::from_environment(environment(&[
            ("BOWER_HTTP_TOKEN_FILE", "/run/secrets/token"),
            ("BOWER_HTTP_FORMAT", "ndjson"),
            ("BOWER_HTTP_AUTH_HEADER", header),
        ])));
        assert!(
            error.contains("BOWER_HTTP_AUTH_HEADER must be an HTTP header name"),
            "{header}"
        );
    }
    assert!(
        message(CollectorSettings::from_environment(|name| (name
            == "BOWER_OUTPUT")
            .then(|| "http".to_string())))
        .contains("BOWER_OUTPUT=http requires BOWER_HTTP_URL")
    );
    assert!(
        message(CollectorSettings::from_environment(|name| match name {
            "BOWER_OUTPUT" => Some("http".into()),
            "BOWER_HTTP_URL" => Some("https://hec.example.test/x".into()),
            _ => None,
        }))
        .contains("BOWER_OUTPUT=http requires exactly one of")
    );
    assert!(
        message(CollectorSettings::from_environment(environment(&[
            ("BOWER_HTTP_TOKEN_FILE", "/run/secrets/token"),
            ("BOWER_HTTP_FORMAT", "ndjson"),
            ("BOWER_HTTP_HEC_SOURCE", "bower"),
        ])))
        .contains("BOWER_HTTP_HEC_* settings require BOWER_HTTP_FORMAT=splunk-hec.")
    );
}

#[test]
fn token_is_never_printed_or_hashed() {
    let settings = CollectorSettings::from_environment(environment(&[(
        "BOWER_HTTP_TOKEN",
        "abcdef0123456789",
    )]))
    .unwrap();
    let http = settings.http_output.as_ref().unwrap();
    assert!(!format!("{settings:?}").contains("abcdef0123456789"));
    assert!(!format!("{http:?}").contains("abcdef0123456789"));
    assert!(!http.hash_material().contains("abcdef0123456789"));
    assert_eq!(http.read_token().unwrap(), "abcdef0123456789");
}

/// Pinned against C# `HttpOutputTests.ConfigurationHash_ExcludesTheTokenAndIsPinnedForTheRustPort`.
const PINNED_HTTP_HASH: &str =
    "sha256:667066988faae4ac1c592a085d9c047006642836ff5209297a32b2b85e4e5c56";

#[test]
fn configuration_hash_excludes_the_token_and_matches_csharp() {
    let hash = |overrides: &[(&str, &str)]| {
        CollectorSettings::from_environment(environment(overrides))
            .unwrap()
            .configuration_hash()
    };
    let file = hash(&[("BOWER_HTTP_TOKEN_FILE", "/run/secrets/hec-token")]);
    assert_eq!(
        hash(&[("BOWER_HTTP_TOKEN", "first-token-value")]),
        hash(&[("BOWER_HTTP_TOKEN", "second-token-value")])
    );
    assert_ne!(hash(&[("BOWER_HTTP_TOKEN", "first-token-value")]), file);
    assert_ne!(
        file,
        hash(&[
            ("BOWER_HTTP_TOKEN_FILE", "/run/secrets/hec-token"),
            ("BOWER_HTTP_GZIP", "true")
        ])
    );
    let pinned = hash(&[
        ("BOWER_HTTP_TOKEN_FILE", "/run/secrets/hec-token"),
        ("BOWER_HTTP_HEC_INDEX", "security"),
        ("BOWER_HTTP_HEC_SOURCETYPE", "bower:security"),
        (
            "BOWER_HTTP_HEC_CHANNEL",
            "0aecaf82-3f0c-4c5d-9e2b-7a1f5d9c2b10",
        ),
        ("BOWER_HTTP_CA_BUNDLE", "/etc/bower/splunk-ca.pem"),
        ("BOWER_HTTP_MAX_BATCH_BYTES", "750000"),
        ("BOWER_HTTP_MAX_BATCH_EVENTS", "250"),
        ("BOWER_HTTP_TIMEOUT_SECONDS", "20"),
        ("BOWER_HTTP_GZIP", "true"),
    ]);
    assert_eq!(pinned, PINNED_HTTP_HASH);
}

#[test]
fn worker_persists_only_bounded_http_output_codes() {
    for (code, known) in [
        ("destination-http-unavailable", true),
        ("destination-http-timeout", true),
        ("destination-http-cancelled", true),
        ("destination-http-response-invalid", true),
        ("destination-http-503", true),
        ("destination-http-401:hec-2", true),
        ("http-400:hec-7", true),
        ("http-413:hec-27", true),
        ("http-400:hec-07", false),
        ("http-400:hec-100", false),
        ("http-400:hec-", false),
        ("http-400:hec-7;x", false),
        ("http-4000", false),
        ("http-600", false),
        ("destination-http-other", false),
    ] {
        assert_eq!(is_http_output_code(code), known, "{code}");
    }
}

// ------------------------------------------------------------------ queue integration

#[derive(Clone)]
struct Endpoint {
    replies: Arc<Mutex<(u16, &'static str)>>,
    authorizations: Arc<Mutex<Vec<String>>>,
    port: u16,
}

async fn handle(
    State(endpoint): State<Endpoint>,
    headers: axum::http::HeaderMap,
    _: Bytes,
) -> Response {
    endpoint.authorizations.lock().unwrap().push(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    );
    let (status, body) = *endpoint.replies.lock().unwrap();
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .body(Body::from(body))
        .unwrap()
}

async fn endpoint(status: u16, body: &'static str) -> Endpoint {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        replies: Arc::new(Mutex::new((status, body))),
        authorizations: Arc::default(),
        port: listener.local_addr().unwrap().port(),
    };
    let router = Router::new().fallback(handle).with_state(endpoint.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    endpoint
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn queue_keeps_retryable_failures_and_dead_letters_permanent_ones_without_logging_the_token()
{
    const TOKEN: &str = "hec-token-0123456789abcdef";
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock(Arc::new(Mutex::new(
        bower_contracts::time::parse("2026-11-05T01:02:03Z").unwrap(),
    )));
    let store = Arc::new(
        SqliteEventStore::new(
            directory.path().join("queue.db"),
            10 * 1024 * 1024,
            Some(Arc::new(clock.clone())),
        )
        .unwrap(),
    );
    store.initialize().unwrap();
    store
        .enqueue(&QueuedEvent {
            event_id: "q1".into(),
            fingerprint: "f".into(),
            payload: r#"{"eventId":"q1"}"#.into(),
            received_at: clock.utc_now(),
            state: QueueState::Queued,
            delivery_attempts: 0,
            lease_token: None,
            suppression: None,
        })
        .unwrap();
    let server = endpoint(503, r#"{"text":"Server is busy","code":9}"#).await;
    let mut options = HttpOutputOptions::new(
        reqwest::Url::parse(&format!(
            "http://127.0.0.1:{}/services/collector/event",
            server.port
        ))
        .unwrap(),
        "edge-01",
    );
    options.allow_insecure_loopback = true;
    let output = HttpOutput::new(options, TOKEN)
        .unwrap()
        .with_clock(Arc::new(clock.clone()));
    let worker = QueueDeliveryWorker::new(
        store.clone(),
        Arc::new(output),
        Arc::new(clock.clone()),
        QueueDeliveryOptions::default(),
    );
    let (_owner, shutdown) = shutdown::channel();

    worker.deliver_once(&shutdown).await.unwrap();
    let retrying = store.snapshot().unwrap();
    *clock.0.lock().unwrap() += chrono::TimeDelta::hours(2);
    *server.replies.lock().unwrap() = (400, r#"{"text":"Incorrect index","code":7}"#);
    worker.deliver_once(&shutdown).await.unwrap();
    let dead_lettered = store.snapshot().unwrap();
    let records = store.list_dead_lettered(10).unwrap();

    assert_eq!(retrying.retrying, 1);
    assert_eq!(retrying.delivered, 0);
    assert_eq!(dead_lettered.dead_lettered, 1);
    assert_eq!(records[0].failure_code.as_deref(), Some("http-400:hec-7"));
    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("failure_code=\"destination-http-503:hec-9\""),
        "{logs}"
    );
    assert!(!logs.contains(TOKEN));
    assert!(
        server
            .authorizations
            .lock()
            .unwrap()
            .iter()
            .all(|value| value == &format!("Splunk {TOKEN}"))
    );
}

#[tokio::test]
async fn status_reports_the_http_output_without_the_token() {
    const TOKEN: &str = "hec-token-fedcba9876543210";
    const INGEST: &str = "http-output-ingest-token-0123456789abcdef";
    let directory = tempfile::tempdir().unwrap();
    let server = endpoint(200, r#"{"text":"Success","code":0}"#).await;
    let token_file = directory.path().join("hec-token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.path().join("queue.db"),
        root.join("policies/default"),
        "collector-test",
    );
    settings.ingest_token = Some(INGEST.into());
    settings.single_trust_domain = true;
    settings.output_type = "http".into();
    let mut http = bower_collector::http_output::HttpOutputSettings::new(Some(
        reqwest::Url::parse(&format!(
            "http://127.0.0.1:{}/services/collector/event",
            server.port
        ))
        .unwrap(),
    ));
    http.token_file = Some(token_file);
    http.allow_insecure_loopback = true;
    settings.http_output = Some(http);
    settings.validate().unwrap();
    let loaded = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings.clone(), loaded, BuildOptions::default()).unwrap();
    collector.set_output(host::create_output(&settings, None).unwrap());
    collector.initialize().await.unwrap();

    let response = collector
        .router
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header(header::AUTHORIZATION, format!("Bearer {INGEST}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();

    assert!(body.contains("\"output\":\"http\""), "{body}");
    assert!(!body.contains(TOKEN));
}
