//! Port of `EventTapTests` and `TapHostTests`: tap caps, back-pressure, filters and the
//! `GET /v1/tap` stream, driven in-process with `tower::ServiceExt::oneshot`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bower_collector::auth::IngestAuthentication;
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::tap::{
    EventTap, EventTapOptions, EventTapRecord, EventTapRequest, SESSION_BUFFER_FRAMES, TapPoint,
};
use bower_collector::{CollectorSettings, bundle};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{DecisionAction, SecurityEventEnvelope};
use bower_core::{ProcessingResult, ProcessingStage, TapSink};
use http_body_util::BodyExt;
use tower::ServiceExt;

const TOKEN: &str = "test-ingest-token-0123456789abcdef0123456789";

/// Host tests run one at a time: tracing caches callsite interest process-wide, so a
/// thread-local log capture can miss lines another test's thread registered first.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Known secrets in field names the privacy engine removes and values its detectors mask.
const SECRETS: [&str; 5] = [
    "tap-canary-password-value",
    "AKIAIOSFODNN7EXAMPLE",
    "4111111111111111",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
    "tap-canary-api-token",
];

struct FakeClock(Mutex<Timestamp>);

impl FakeClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            bower_contracts::time::parse("2026-07-26T02:14:19+00:00").unwrap(),
        )))
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += chrono::Duration::from_std(duration).unwrap();
    }
}

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

fn request(limit: i64, sample: i64) -> EventTapRequest {
    EventTapRequest {
        producer: "default".into(),
        point: TapPoint::Redacted,
        application: None,
        event_type: None,
        limit,
        duration: Duration::from_secs(60),
        sample,
    }
}

fn queued() -> ProcessingResult {
    ProcessingResult {
        queued: true,
        event_id: Some("e-1".into()),
        ..ProcessingResult::failed_at(DecisionAction::Accept, "x", ProcessingStage::Policy)
    }
}

fn tap(options: EventTapOptions, clock: Arc<FakeClock>) -> Arc<EventTap> {
    Arc::new(EventTap::new(options, clock))
}

#[test]
fn publish_without_sessions_does_nothing() {
    let tap = tap(EventTapOptions::default(), FakeClock::new());
    assert!(!tap.is_active());
    tap.publish(&queued(), None, Some("{}"));
    let snapshot = tap.snapshot();
    assert_eq!(snapshot.sessions_opened, 0);
    assert_eq!(snapshot.frames_dropped, 0);
}

#[test]
fn publish_never_blocks_on_a_stalled_reader_and_counts_every_drop() {
    let tap = tap(
        EventTapOptions {
            maximum_events_per_second: 1000.0,
            ..EventTapOptions::default()
        },
        FakeClock::new(),
    );
    let session = tap.try_open(request(1000, 1)).unwrap();
    let started = Instant::now();
    for _ in 0..5000 {
        tap.publish(&queued(), None, Some("{}"));
    }
    // Bounded impact: publishing to a reader that never reads stays fast and bounded.
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(session.buffered(), SESSION_BUFFER_FRAMES);
    assert_eq!(session.dropped(), 1000 - SESSION_BUFFER_FRAMES as i64);
    assert_eq!(session.rate_limited(), 4000);
    let snapshot = tap.snapshot();
    assert_eq!(snapshot.frames_dropped, 1000 - SESSION_BUFFER_FRAMES as i64);
    assert_eq!(snapshot.frames_rate_limited, 4000);
}

#[test]
fn session_rate_cap_refills_with_time() {
    let clock = FakeClock::new();
    let tap = tap(
        EventTapOptions {
            maximum_events_per_second: 5.0,
            ..EventTapOptions::default()
        },
        Arc::clone(&clock),
    );
    let session = tap.try_open(request(100, 1)).unwrap();
    for _ in 0..10 {
        tap.publish(&queued(), None, Some("{}"));
    }
    assert_eq!(session.buffered(), 5);
    assert_eq!(session.rate_limited(), 5);
    clock.advance(Duration::from_secs(1));
    for _ in 0..10 {
        tap.publish(&queued(), None, Some("{}"));
    }
    assert_eq!(session.buffered(), 10);
    assert_eq!(session.rate_limited(), 10);
}

#[test]
fn try_open_enforces_concurrent_session_cap_and_clamps_limits() {
    let tap = tap(
        EventTapOptions {
            maximum_sessions: 2,
            maximum_events: 50,
            maximum_duration: Duration::from_secs(30),
            ..EventTapOptions::default()
        },
        FakeClock::new(),
    );
    let first = tap
        .try_open(EventTapRequest {
            duration: Duration::from_secs(3600),
            ..request(5000, 1)
        })
        .unwrap();
    let _second = tap.try_open(request(100, 1)).unwrap();
    assert!(tap.try_open(request(100, 1)).is_none());
    assert_eq!(first.request().limit, 50);
    assert_eq!(first.request().duration, Duration::from_secs(30));
    drop(first);
    let _third = tap.try_open(request(100, 1)).unwrap();
    let snapshot = tap.snapshot();
    assert_eq!(snapshot.active_sessions, 2);
    assert_eq!(snapshot.sessions_opened, 3);
    assert_eq!(snapshot.sessions_refused, 1);
}

#[test]
fn try_open_refuses_when_disabled() {
    let tap = tap(
        EventTapOptions {
            enabled: false,
            ..EventTapOptions::default()
        },
        FakeClock::new(),
    );
    assert!(tap.try_open(request(100, 1)).is_none());
    assert_eq!(tap.snapshot().sessions_refused, 1);
}

#[test]
fn session_samples_and_stops_at_its_limit() {
    let tap = tap(EventTapOptions::default(), FakeClock::new());
    let sampled = tap.try_open(request(100, 3)).unwrap();
    let limited = tap.try_open(request(2, 1)).unwrap();
    for _ in 0..9 {
        tap.publish(&queued(), None, Some("{}"));
    }
    assert_eq!(sampled.buffered(), 3);
    assert_eq!(limited.buffered(), 2);
    assert_eq!(limited.dropped(), 0);
}

#[test]
fn record_matches_tap_points_and_exact_filters() {
    let now = bower_contracts::time::now();
    let queued = EventTapRecord {
        observed_at: now,
        stage: "policy",
        action: "accept".into(),
        queued: true,
        duplicate: false,
        suppressed: false,
        event_type: Some("auth.failure".into()),
        application: Some("TestApplication".into()),
        environment: Some("test".into()),
        policy_id: Some("BWR-POL-AUTH-FAILURE".into()),
        reasons: Vec::new(),
        event: Some("{}".into()),
        event_omitted: None,
    };
    let rejected = EventTapRecord {
        action: "reject".into(),
        queued: false,
        event: None,
        event_omitted: Some("not-accepted"),
        ..queued.clone()
    };
    let invalid = EventTapRecord {
        stage: "validation",
        action: "quarantine".into(),
        ..rejected.clone()
    };
    let at = |point, application: Option<&str>, event_type: Option<&str>| EventTapRequest {
        point,
        application: application.map(str::to_owned),
        event_type: event_type.map(str::to_owned),
        ..request(100, 1)
    };
    assert!(invalid.matches(&at(TapPoint::Redacted, None, None)));
    assert!(!invalid.matches(&at(TapPoint::Decided, None, None)));
    assert!(rejected.matches(&at(TapPoint::Decided, None, None)));
    assert!(!rejected.matches(&at(TapPoint::Queued, None, None)));
    assert!(queued.matches(&at(
        TapPoint::Queued,
        Some("TestApplication"),
        Some("auth.failure")
    )));
    assert!(!queued.matches(&at(TapPoint::Redacted, Some("testapplication"), None)));
    assert!(!queued.matches(&at(TapPoint::Redacted, None, Some("auth"))));
}

#[test]
fn publish_shows_only_accepted_payloads_within_the_size_cap() {
    let tap = tap(
        EventTapOptions {
            maximum_event_bytes: 1024,
            ..EventTapOptions::default()
        },
        FakeClock::new(),
    );
    let mut session = tap.try_open(request(100, 1)).unwrap();
    let mut subject = event(&new_id());
    subject.event_type = "t".repeat(300);
    tap.publish(&queued(), Some(&subject), Some("{\"small\":true}"));
    let large = format!("{{\"large\":\"{}\"}}", "x".repeat(2000));
    tap.publish(&queued(), Some(&subject), Some(&large));
    let rejected =
        ProcessingResult::failed_at(DecisionAction::Reject, "no policy", ProcessingStage::Policy);
    tap.publish(&rejected, Some(&subject), Some("{\"never\":1}"));

    let small = session.try_recv().unwrap();
    assert_eq!(small.event.as_deref(), Some("{\"small\":true}"));
    assert_eq!(small.event_type.as_ref().unwrap().len(), 128);
    let large = session.try_recv().unwrap();
    assert_eq!(large.event, None);
    assert_eq!(large.event_omitted, Some("size-cap"));
    let rejected = session.try_recv().unwrap();
    assert_eq!(rejected.event, None);
    assert_eq!(rejected.event_omitted, Some("not-accepted"));
    assert_eq!(rejected.action, "reject");
}

// ---- GET /v1/tap ----------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

async fn start(directory: &Path, adjust: impl FnOnce(&mut CollectorSettings)) -> Collector {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        repo_root().join("policies/default"),
        "collector-test",
    );
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    adjust(&mut settings);
    let bundle = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings, bundle, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    collector
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn event(event_id: &str) -> SecurityEventEnvelope {
    let now = bower_contracts::time::format_json(&bower_contracts::time::now());
    let json = format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"{event_id}","eventOriginalId":"{}","timeGenerated":"{now}",
        "eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt",
        "eventResult":"failure","eventOutcomeReason":"InvalidPassword",
        "application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"test-user"}},
        "source":{{"ipAddress":"192.0.2.10"}},"request":{{"correlationId":"correlation-1"}}}}"#,
        new_id()
    );
    serde_json::from_str(&json).unwrap()
}

fn with_secrets(mut event: SecurityEventEnvelope) -> SecurityEventEnvelope {
    let names = ["dbPassword", "awsKey", "pan", "detail", "apiToken"];
    event.attributes = Some(
        names
            .iter()
            .zip(SECRETS)
            .map(|(name, secret)| {
                (
                    (*name).to_owned(),
                    bower_contracts::JsonElement::from(secret),
                )
            })
            .collect(),
    );
    event
}

async fn post(router: &Router, candidate: &SecurityEventEnvelope) -> StatusCode {
    let request = Request::post("/v1/events")
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::from(
            bower_contracts::json::to_vec(candidate).unwrap(),
        ))
        .unwrap();
    router.clone().oneshot(request).await.unwrap().status()
}

async fn status_json(router: &Router) -> serde_json::Value {
    let request = Request::get("/v1/status")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// A server-sent event reader over one tap response.
struct TapStream {
    status: StatusCode,
    body: Body,
    pending: Vec<u8>,
    text: String,
}

impl TapStream {
    async fn open(router: &Router, path: &str, token: Option<&str>) -> Self {
        let mut builder = Request::get(path);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        if status == StatusCode::OK {
            assert!(
                response.headers()[header::CONTENT_TYPE]
                    .to_str()
                    .unwrap()
                    .starts_with("text/event-stream")
            );
        }
        let mut stream = Self {
            status,
            body: response.into_body(),
            pending: Vec::new(),
            text: String::new(),
        };
        if status != StatusCode::OK {
            let bytes = axum::body::to_bytes(std::mem::take(&mut stream.body), usize::MAX)
                .await
                .unwrap();
            stream.text = String::from_utf8_lossy(&bytes).into_owned();
        }
        stream
    }

    async fn next(&mut self) -> (String, serde_json::Value) {
        let mut name = String::new();
        loop {
            while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                let line = String::from_utf8(line[..line.len() - 1].to_vec()).unwrap();
                self.text.push_str(&line);
                self.text.push('\n');
                if let Some(value) = line.strip_prefix("event: ") {
                    name = value.to_owned();
                } else if let Some(data) = line.strip_prefix("data: ") {
                    return (name, serde_json::from_str(data).unwrap());
                }
            }
            let frame = tokio::time::timeout(Duration::from_secs(20), self.body.frame())
                .await
                .expect("tap frame within 20 s");
            match frame {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.pending.extend_from_slice(&data);
                    }
                }
                _ => return ("eof".into(), serde_json::Value::Null),
            }
        }
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

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn capture_logs() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    (captured, tracing::subscriber::set_default(subscriber))
}

#[tokio::test]
async fn tap_never_returns_pre_redaction_values_and_audits_the_session() {
    let _serial = SERIAL.lock().await;
    let (logs, _guard) = capture_logs();
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), |_| {}).await;
    let router = &collector.router;
    let mut tap = TapStream::open(router, "/v1/tap?limit=3&durationSeconds=30", Some(TOKEN)).await;
    assert_eq!(tap.status, StatusCode::OK);
    let (name, start) = tap.next().await;
    assert_eq!(name, "start");
    assert_eq!(start["tapPoint"], "redacted");

    let accepted = with_secrets(event(&new_id()));
    let mut rejected = with_secrets(event(&new_id()));
    rejected.event_type = "custom.unlisted".into();
    rejected.event_category = "custom".into();
    let mut invalid = with_secrets(event(&new_id()));
    invalid.time_generated = bower_contracts::time::parse("1970-01-01T00:00:00+00:00").unwrap();
    assert_eq!(post(router, &accepted).await, StatusCode::ACCEPTED);
    assert_eq!(
        post(router, &rejected).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(post(router, &invalid).await, StatusCode::BAD_REQUEST);

    let mut frames = Vec::new();
    let end = loop {
        let (name, data) = tap.next().await;
        if name != "frame" {
            assert_eq!(name, "end");
            break data;
        }
        frames.push(data);
    };
    assert_eq!(end["reason"], "limit");
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0]["action"], "redact-and-accept");
    assert_eq!(frames[0]["event"]["eventId"], accepted.event_id.as_str());
    assert_eq!(frames[1]["action"], "reject");
    assert_eq!(frames[1]["eventOmitted"], "not-accepted");
    assert!(frames[1].get("event").is_none());
    assert_eq!(frames[2]["stage"], "validation");
    assert_eq!(frames[2]["action"], "quarantine");
    assert!(frames[2].get("event").is_none());
    for secret in SECRETS {
        assert!(!tap.text.contains(secret), "tap leaked {secret}");
    }

    let status = status_json(router).await;
    assert_eq!(status["tap"]["sessionsOpened"], 1);
    assert_eq!(status["tap"]["framesSent"], 3);

    let (eof, _) = tap.next().await;
    assert_eq!(eof, "eof");
    let audit = logs.text();
    assert!(audit.contains(
        "opened by producer default: tap point redacted, source -, event type -, limit 3, duration 30 s, sample 1 in 1."
    ), "{audit}");
    assert!(audit.contains("closed (limit) after"), "{audit}");
    assert!(
        audit.contains("3 frames sent, 0 dropped, 0 rate limited."),
        "{audit}"
    );
    assert!(!audit.contains(TOKEN));
    for secret in SECRETS {
        assert!(!audit.contains(secret));
    }
}

#[tokio::test]
async fn tap_is_refused_without_the_operator_credential() {
    let _serial = SERIAL.lock().await;
    const PRODUCER_TOKEN: &str = "producer-token-0123456789abcdef0123456789";
    const OPERATOR_TOKEN: &str = "operator-token-0123456789abcdef0123456789";
    let (logs, _guard) = capture_logs();
    let directory = tempfile::tempdir().unwrap();
    let tokens_file = directory.path().join("tokens");
    std::fs::write(
        &tokens_file,
        format!(
            "{}\n{}\n",
            IngestAuthentication::tokens_file_line("sidecar-01", PRODUCER_TOKEN),
            IngestAuthentication::tokens_file_line("soc-operator", OPERATOR_TOKEN)
        ),
    )
    .unwrap();
    let collector = start(directory.path(), |settings| {
        settings.ingest_tokens_file = Some(tokens_file.clone());
        settings.tap_producers = vec!["soc-operator".into()];
    })
    .await;
    let router = &collector.router;
    assert_eq!(
        TapStream::open(router, "/v1/tap", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        TapStream::open(router, "/v1/tap", Some("wrong-token"))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let producer = TapStream::open(router, "/v1/tap", Some(PRODUCER_TOKEN)).await;
    assert_eq!(producer.status, StatusCode::FORBIDDEN);
    assert!(producer.text.contains("tap-not-authorized"));
    let mut listed = TapStream::open(
        router,
        "/v1/tap?limit=1&durationSeconds=5",
        Some(OPERATOR_TOKEN),
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.next().await.0, "start");
    drop(listed);
    let shared = TapStream::open(router, "/v1/tap?limit=1&durationSeconds=5", Some(TOKEN)).await;
    assert_eq!(shared.status, StatusCode::OK);
    let audit = logs.text();
    assert!(audit.contains("Tap session refused for producer sidecar-01: tap-not-authorized."));
    assert!(audit.contains("opened by producer soc-operator"));
}

#[tokio::test]
async fn tap_without_ingest_authentication_needs_a_loopback_listener() {
    let _serial = SERIAL.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), |settings| {
        settings.ingest_token = None;
        settings.listen_url = "http://0.0.0.0:4319".into();
        settings.allow_unauthenticated_ingest = true;
    })
    .await;
    assert_eq!(
        TapStream::open(&collector.router, "/v1/tap", None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn tap_enforces_session_cap_parameters_and_disablement() {
    let _serial = SERIAL.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), |settings| {
        settings.tap_maximum_sessions = 1
    })
    .await;
    let router = &collector.router;
    let mut first = TapStream::open(router, "/v1/tap?durationSeconds=30", Some(TOKEN)).await;
    assert_eq!(first.next().await.0, "start");
    let second = TapStream::open(router, "/v1/tap", Some(TOKEN)).await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(second.text.contains("tap-session-limit"));
    for (query, error) in [
        ("stage=parsed", "tap-stage-invalid"),
        ("stage=raw", "tap-stage-invalid"),
        ("limit=abc", "tap-parameter-invalid"),
        ("limit=0", "tap-parameter-invalid"),
        ("sample=10001", "tap-parameter-invalid"),
        ("source=bad%20value", "tap-filter-invalid"),
    ] {
        let invalid = TapStream::open(router, &format!("/v1/tap?{query}"), Some(TOKEN)).await;
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST, "{query}");
        assert!(invalid.text.contains(error), "{query}: {}", invalid.text);
    }
    drop(first);

    let other = tempfile::tempdir().unwrap();
    let disabled = start(other.path(), |settings| settings.tap_enabled = false).await;
    assert_eq!(
        TapStream::open(&disabled.router, "/v1/tap", Some(TOKEN))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn tap_duration_cap_ends_the_session() {
    let _serial = SERIAL.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), |settings| {
        settings.tap_maximum_duration_seconds = 1;
        settings.tap_maximum_events = 5;
    })
    .await;
    let mut tap = TapStream::open(
        &collector.router,
        "/v1/tap?durationSeconds=600&limit=900",
        Some(TOKEN),
    )
    .await;
    let (name, start) = tap.next().await;
    assert_eq!(name, "start");
    assert_eq!(start["durationSeconds"], 1);
    assert_eq!(start["limit"], 5);
    let (name, end) = tap.next().await;
    assert_eq!(name, "end");
    assert_eq!(end["reason"], "duration");
}

#[tokio::test]
async fn tap_ends_with_shutdown_when_the_host_stops() {
    let _serial = SERIAL.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), |_| {}).await;
    let mut tap =
        TapStream::open(&collector.router, "/v1/tap?durationSeconds=60", Some(TOKEN)).await;
    assert_eq!(tap.next().await.0, "start");
    collector.tap.stop();
    let (name, end) = tap.next().await;
    assert_eq!(name, "end");
    assert_eq!(end["reason"], "shutdown");
}

#[tokio::test]
async fn stalled_response_releases_session_at_deadline_or_shutdown() {
    let _serial = SERIAL.lock().await;
    for shutdown in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let collector = start(directory.path(), |settings| {
            settings.tap_maximum_duration_seconds = if shutdown { 60 } else { 1 };
        })
        .await;
        // Retain the body without polling it, so the four-frame HTTP channel fills.
        let response = TapStream::open(&collector.router, "/v1/tap", Some(TOKEN)).await;
        assert_eq!(response.status, StatusCode::OK);
        for _ in 0..20 {
            collector.tap.publish(&queued(), None, Some("{}"));
        }
        tokio::task::yield_now().await;
        if shutdown {
            collector.tap.stop();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while collector.tap.is_active() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a stalled response held the tap session past its deadline");
        drop(response);
    }
}

#[tokio::test]
async fn status_lists_activity_and_tap_counters() {
    let _serial = SERIAL.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), |_| {}).await;
    for _ in 0..3 {
        assert_eq!(
            post(&collector.router, &event(&new_id())).await,
            StatusCode::ACCEPTED
        );
    }
    let status = status_json(&collector.router).await;
    assert_eq!(status["activity"][0]["application"], "TestApplication");
    assert_eq!(status["activity"][0]["eventCount"], 3);
    assert_eq!(
        status["tap"],
        serde_json::json!({
            "enabled": true, "activeSessions": 0, "maximumSessions": 2, "sessionsOpened": 0,
            "sessionsRefused": 0, "framesSent": 0, "framesDropped": 0, "framesRateLimited": 0
        })
    );
    assert_eq!(status["pipeline"]["eventsIn"], 3);
}
