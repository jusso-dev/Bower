//! Port of `CollectorHostTests.Ingest_ReportsSuppressionAndStatusShowsPipelineAndExpectedSources`
//! and `SuppressionTests.Bundle_RequiresSummaryPolicyWhenAnyPolicySuppresses`, plus the
//! collector settings and jobs added with suppression, source silence and the archive.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::jobs::{run_queue_archive, run_queue_retention, run_source_activity};
use bower_collector::source_health::SourceHealth;
use bower_collector::{CollectorSettings, bundle};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{DurableEventStore, QueueState, QueuedEvent};
use bower_core::source_expectations;
use bower_persistence::{QueueArchive, SqliteEventStore};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "test-ingest-token-0123456789abcdef0123456789";

const SUPPRESSING_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-AUTH-SUPPRESSED
  name: Authentication failures, suppressed
  version: 1.0.0
  owner: Security Operations
match:
  eventCategories:
    - authentication
  eventTypes:
    - authentication_failure
requirements:
  requiredFields:
    - timeGenerated
    - eventType
  atLeastOne:
    - actor.username
decision:
  action: accept
  minimumValueScore: 50
  neverSample: false
suppression:
  keyFields:
    - actor.username
    - source.ipAddress
  windowSeconds: 60
  allowPerWindow: 2";

const SUMMARY_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-SUPPRESSION-SUMMARY
  name: Suppression summaries
  version: 1.0.0
  owner: Security Operations
match:
  eventTypes:
    - telemetry_aggregation_summary
requirements:
  requiredFields:
    - timeGenerated
    - eventType
    - application.name
    - target.id
decision:
  action: accept
  minimumValueScore: 50
  neverSample: true";

fn settings(directory: &Path, policies: PathBuf) -> CollectorSettings {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        policies,
        "collector-test",
    );
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    settings
}

fn policy_directory(directory: &Path, policies: &[(&str, &str)]) -> PathBuf {
    let path = directory.join("policies");
    std::fs::create_dir_all(&path).unwrap();
    for (name, yaml) in policies {
        std::fs::write(path.join(name), yaml).unwrap();
    }
    path
}

async fn start(settings: CollectorSettings) -> Collector {
    let bundle = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings, bundle, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    collector
}

fn candidate(original_id: &str) -> String {
    candidate_at(original_id, bower_contracts::time::now())
}

fn candidate_at(original_id: &str, at: Timestamp) -> String {
    let now = bower_contracts::time::format_json(&at);
    format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"{}","eventOriginalId":"{original_id}","timeGenerated":"{now}","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","eventOutcomeReason":"InvalidPassword","application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"test-user"}},"source":{{"ipAddress":"192.0.2.10"}},"request":{{"correlationId":"correlation-1"}}}}"#,
        uuid::Uuid::new_v4()
    )
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn post(body: String) -> Request<Body> {
    Request::post("/v1/events")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::from(body))
        .unwrap()
}

fn get(path: &str, token: bool) -> Request<Body> {
    let mut builder = Request::get(path);
    if token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn ingest_reports_suppression_and_status_shows_pipeline_and_expected_sources() {
    let directory = tempfile::tempdir().unwrap();
    let policies = policy_directory(
        directory.path(),
        &[
            ("auth.yaml", SUPPRESSING_POLICY),
            ("summary.yaml", SUMMARY_POLICY),
        ],
    );
    let expectations = directory.path().join("sources.json");
    std::fs::write(
        &expectations,
        r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
  {"application":"TestApplication","environment":"test","maximumSilenceMinutes":5},
  {"application":"Payroll","environment":"production","maximumSilenceMinutes":5}]}"#,
    )
    .unwrap();
    let mut settings = settings(directory.path(), policies);
    settings.source_expectations_path = Some(expectations);
    let collector = start(settings).await;

    let mut bodies = Vec::new();
    for index in 0..3 {
        let (status, body) = send(
            &collector.router,
            post(candidate(&format!("original-{index}"))),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        bodies.push(body);
    }
    let (_, status) = send(&collector.router, get("/v1/status", true)).await;
    let (_, health) = send(&collector.router, get("/health", false)).await;
    let status: Value = serde_json::from_str(&status).unwrap();
    let pipeline = &status["pipeline"];
    let sources = &status["sources"];

    assert!(!bodies[0].contains("\"suppressed\""));
    assert!(bodies[2].contains("\"suppressed\":true"), "{}", bodies[2]);
    assert_eq!(pipeline["eventsIn"].as_i64(), Some(3));
    assert_eq!(pipeline["eventsQueued"].as_i64(), Some(2));
    assert_eq!(pipeline["suppressed"].as_i64(), Some(1));
    assert_eq!(pipeline["rows"][0]["stage"], "policy");
    assert_eq!(pipeline["rows"][0]["action"], "accept");
    assert_eq!(sources.as_array().unwrap().len(), 2);
    assert_eq!(sources[0]["state"], "active");
    assert_eq!(sources[0]["application"], "TestApplication");
    assert!(sources[1]["lastSeenAt"].is_null());
    // Fresh start: never-seen sources are within their grace period.
    assert_eq!(health, r#"{"status":"healthy"}"#);
    let keys: Vec<&str> = status
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "status",
            "policy",
            "ledger",
            "queue",
            "jobs",
            "eventIdentityConflicts",
            "pipeline",
            "sources"
        ]
    );
    let jobs = status["jobs"].to_string();
    assert!(jobs.contains("source-activity"), "{jobs}");
    assert!(!jobs.contains("queue-archive"), "{jobs}");
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl FakeClock {
    fn advance(&self, seconds: i64) {
        *self.0.lock().unwrap() += chrono::Duration::seconds(seconds);
    }
}

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

/// A collector start over an existing queue file: fresh process state, durable store.
async fn start_expecting(directory: &Path, clock: &FakeClock, sources: &[&str]) -> Collector {
    let policies = policy_directory(
        directory,
        &[
            ("auth.yaml", SUPPRESSING_POLICY),
            ("summary.yaml", SUMMARY_POLICY),
        ],
    );
    let expectations = directory.join("sources.json");
    let listed: Vec<String> = sources
        .iter()
        .map(|source| {
            let (application, environment) = source.split_once('/').unwrap();
            format!(
                r#"{{"application":"{application}","environment":"{environment}","maximumSilenceMinutes":1}}"#
            )
        })
        .collect();
    std::fs::write(
        &expectations,
        format!(
            r#"{{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[{}]}}"#,
            listed.join(",")
        ),
    )
    .unwrap();
    let mut settings = settings(directory, policies);
    settings.source_expectations_path = Some(expectations);
    let bundle = bundle::load(&settings).unwrap();
    let options = BuildOptions {
        clock: Some(Arc::new(clock.clone())),
        ..BuildOptions::default()
    };
    let mut collector = host::build(settings, bundle, options).unwrap();
    collector.initialize().await.unwrap();
    collector
}

async fn source_states(collector: &Collector) -> (Vec<(String, i64)>, String) {
    let (_, status) = send(&collector.router, get("/v1/status", true)).await;
    let (_, health) = send(&collector.router, get("/health", false)).await;
    let status: Value = serde_json::from_str(&status).unwrap();
    let health: Value = serde_json::from_str(&health).unwrap();
    let states = status["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| {
            (
                source["state"].as_str().unwrap().to_owned(),
                source["silentSeconds"].as_i64().unwrap(),
            )
        })
        .collect();
    (states, health["status"].as_str().unwrap().to_owned())
}

fn states(expected: &[(&str, i64)], health: &str) -> (Vec<(String, i64)>, String) {
    (
        expected
            .iter()
            .map(|(state, silent)| ((*state).to_owned(), *silent))
            .collect(),
        health.to_owned(),
    )
}

#[tokio::test]
async fn never_seen_deadline_survives_collector_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock(Arc::new(Mutex::new(bower_contracts::time::now())));
    let first_start = clock.utc_now();
    let one = ["TestApplication/test"];
    let two = ["TestApplication/test", "Payroll/production"];

    let collector = start_expecting(directory.path(), &clock, &one).await;
    assert_eq!(
        source_states(&collector).await,
        states(&[("pending", 0)], "healthy")
    );
    clock.advance(120);
    assert_eq!(
        source_states(&collector).await,
        states(&[("never-seen", 120)], "degraded")
    );
    drop(collector);

    // Repeated restarts keep the first monitoring start.
    for restart in 0..3 {
        let collector = start_expecting(directory.path(), &clock, &one).await;
        assert_eq!(
            source_states(&collector).await,
            states(&[("never-seen", 120 + restart * 10)], "degraded")
        );
        clock.advance(10);
    }

    // A newly expected source gets its own grace; the existing deadline stands.
    let collector = start_expecting(directory.path(), &clock, &two).await;
    assert_eq!(
        source_states(&collector).await,
        states(&[("never-seen", 150), ("pending", 0)], "degraded")
    );

    // A valid event updates last-seen and restores activity, also after a restart.
    let (status, body) = send(
        &collector.router,
        post(candidate_at("restored", clock.utc_now())),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        source_states(&collector).await,
        states(&[("active", 0), ("pending", 0)], "healthy")
    );
    run_source_activity(collector.store.clone(), collector.telemetry.clone())
        .await
        .unwrap();
    drop(collector);
    clock.advance(30);
    let collector = start_expecting(directory.path(), &clock, &two).await;
    assert_eq!(
        source_states(&collector).await,
        states(&[("active", 30), ("pending", 30)], "healthy")
    );
    drop(collector);

    // Removing a source forgets its start; expecting it again starts afresh.
    drop(start_expecting(directory.path(), &clock, &one).await);
    clock.advance(300);
    let collector = start_expecting(directory.path(), &clock, &two).await;
    assert_eq!(
        source_states(&collector).await,
        states(&[("silent", 330), ("pending", 0)], "degraded")
    );
    let stored = collector
        .store
        .start_source_monitoring(&[
            bower_contracts::SourceMonitoring {
                application: "TestApplication".into(),
                environment: "test".into(),
                monitoring_since: clock.utc_now(),
            },
            bower_contracts::SourceMonitoring {
                application: "Payroll".into(),
                environment: "production".into(),
                monitoring_since: clock.utc_now(),
            },
        ])
        .unwrap();
    assert_eq!(
        stored
            .iter()
            .map(|item| item.monitoring_since)
            .collect::<Vec<_>>(),
        [first_start, clock.utc_now()]
    );
}

#[tokio::test]
async fn monitoring_start_recorded_while_the_clock_ran_ahead_is_corrected_at_the_next_start() {
    let directory = tempfile::tempdir().unwrap();
    // First start before time synchronisation: the host clock is an hour ahead.
    let clock = FakeClock(Arc::new(Mutex::new(
        bower_contracts::time::now() + chrono::Duration::hours(1),
    )));
    let one = ["TestApplication/test"];

    drop(start_expecting(directory.path(), &clock, &one).await);
    clock.advance(-3600);
    let collector = start_expecting(directory.path(), &clock, &one).await;
    assert_eq!(
        source_states(&collector).await,
        states(&[("pending", 0)], "healthy")
    );
    clock.advance(120);

    assert_eq!(
        source_states(&collector).await,
        states(&[("never-seen", 120)], "degraded")
    );
    drop(collector);
    let collector = start_expecting(directory.path(), &clock, &one).await;
    assert_eq!(
        source_states(&collector).await,
        states(&[("never-seen", 120)], "degraded")
    );
}

#[tokio::test]
async fn initialize_returns_forgotten_monitoring_starts() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock(Arc::new(Mutex::new(bower_contracts::time::now())));
    let collector = start_expecting(
        directory.path(),
        &clock,
        &["TestApplication/test", "Payroll/production"],
    )
    .await;
    let store = collector.store.clone();
    let expectations = source_expectations::parse(
        r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
  {"application":"TestApplication","environment":"test","maximumSilenceMinutes":1}]}"#,
    )
    .unwrap();
    let health = |expectations: Option<source_expectations::SourceExpectations>| {
        SourceHealth::new(
            expectations,
            Arc::new(bower_core::PipelineTelemetry::new(Arc::new(clock.clone()))),
            Arc::new(clock.clone()),
        )
    };
    let keys = |forgotten: Vec<bower_contracts::SourceMonitoring>| -> Vec<(String, String)> {
        forgotten
            .into_iter()
            .map(|item| (item.application, item.environment))
            .collect()
    };

    let removed = health(Some(expectations.clone()))
        .initialize(store.as_ref())
        .unwrap();
    let unchanged = health(Some(expectations))
        .initialize(store.as_ref())
        .unwrap();
    // Starting without expectations forgets every start.
    let unconfigured = health(None).initialize(store.as_ref()).unwrap();

    assert_eq!(
        keys(removed),
        [("Payroll".to_owned(), "production".to_owned())]
    );
    assert!(unchanged.is_empty());
    assert_eq!(
        keys(unconfigured),
        [("TestApplication".to_owned(), "test".to_owned())]
    );
}

#[tokio::test]
async fn status_omits_sources_without_expectations() {
    let directory = tempfile::tempdir().unwrap();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let collector = start(settings(directory.path(), repo.join("policies/default"))).await;
    let (_, status) = send(&collector.router, get("/v1/status", true)).await;
    let status: Value = serde_json::from_str(&status).unwrap();
    assert!(status.get("sources").is_none());
    assert_eq!(status["pipeline"]["eventsIn"].as_i64(), Some(0));
    assert!(status["pipeline"]["rows"].as_array().unwrap().is_empty());
}

#[test]
fn bundle_requires_summary_policy_when_any_policy_suppresses() {
    let directory = tempfile::tempdir().unwrap();
    let policies = policy_directory(directory.path(), &[("suppressed.yaml", SUPPRESSING_POLICY)]);
    let settings = settings(directory.path(), policies.clone());
    let failure = bundle::load(&settings).err().unwrap();
    std::fs::write(policies.join("summary.yaml"), SUMMARY_POLICY).unwrap();
    let loaded = bundle::load(&settings).unwrap();

    assert_eq!(
        failure.to_string(),
        "InvalidDataException: Policies define suppression but none accepts 'telemetry_aggregation_summary'."
    );
    assert_eq!(loaded.info.policies.len(), 2);
}

#[test]
fn invalid_expectations_stop_start_up() {
    let directory = tempfile::tempdir().unwrap();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut settings = settings(directory.path(), repo.join("policies/default"));
    let path = directory.path().join("sources.json");
    std::fs::write(
        &path,
        r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[]}"#,
    )
    .unwrap();
    settings.source_expectations_path = Some(path);
    let bundle = bundle::load(&settings).unwrap();
    let error = host::build(settings.clone(), bundle, BuildOptions::default())
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "InvalidDataException: Source expectations must list 1–1000 sources."
    );

    settings.source_expectations_path = Some(directory.path().join("missing.json"));
    let bundle = bundle::load(&settings).unwrap();
    let error = host::build(settings, bundle, BuildOptions::default())
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "FileNotFoundException: Source expectations file does not exist."
    );
}

#[test]
fn configuration_hash_appends_new_settings_only_when_set() {
    let base = settings(Path::new("unused"), PathBuf::from("policies"));
    let mut expected = base.clone();
    expected.source_expectations_path = Some(PathBuf::from("/etc/bower/sources.json"));
    let mut archived = base.clone();
    archived.archive_path = Some(PathBuf::from("/var/lib/bower/archive"));

    assert_ne!(base.configuration_hash(), expected.configuration_hash());
    assert_ne!(base.configuration_hash(), archived.configuration_hash());
    assert_ne!(expected.configuration_hash(), archived.configuration_hash());
}

fn queued(id: &str, at: bower_contracts::time::Timestamp) -> QueuedEvent {
    QueuedEvent {
        event_id: id.into(),
        fingerprint: format!("sha256:{id}"),
        payload: format!("{{\"eventId\":\"{id}\"}}"),
        received_at: at,
        state: QueueState::Queued,
        delivery_attempts: 0,
        lease_token: None,
        suppression: None,
    }
}

#[tokio::test]
async fn retention_purges_only_archived_events_and_activity_flushes() {
    let directory = tempfile::tempdir().unwrap();
    let past = bower_contracts::time::now() - chrono::Duration::days(30);
    let past_clock: Arc<dyn bower_contracts::time::Clock> = Arc::new(move || past);
    let sqlite = Arc::new(
        SqliteEventStore::new(
            directory.path().join("queue.db"),
            10 * 1024 * 1024,
            Some(past_clock),
        )
        .unwrap(),
    );
    sqlite.initialize().unwrap();
    for id in ["a", "b", "c"] {
        sqlite.enqueue(&queued(id, past)).unwrap();
    }
    let leased = sqlite
        .lease(10, std::time::Duration::from_secs(60))
        .unwrap();
    let tokens = leased
        .iter()
        .map(|item| (item.event_id.clone(), item.lease_token.clone().unwrap()))
        .collect();
    let ids: Vec<String> = leased.iter().map(|item| item.event_id.clone()).collect();
    sqlite.mark_delivered_batch(&ids, "ack", &tokens).unwrap();

    let archive = Arc::new(
        QueueArchive::new(directory.path().join("archive"), "collector-test", None).unwrap(),
    );
    let store: Arc<dyn DurableEventStore> = sqlite.clone();
    let clock: Arc<dyn bower_contracts::time::Clock> = Arc::new(bower_contracts::time::SystemClock);
    let retention = std::time::Duration::from_secs(7 * 24 * 3600);

    // Nothing archived yet: nothing purged.
    let none = run_queue_retention(
        store.clone(),
        clock.clone(),
        retention,
        Some(archive.clone()),
    )
    .await
    .unwrap();
    run_queue_archive(sqlite.clone(), archive.clone())
        .await
        .unwrap();
    let all = run_queue_retention(store.clone(), clock, retention, Some(archive.clone()))
        .await
        .unwrap();
    assert_eq!((none, all), (0, 3));
    assert!(archive.verify(None).unwrap().intact);

    let telemetry = Arc::new(bower_core::PipelineTelemetry::new(Arc::new(
        bower_contracts::time::SystemClock,
    )));
    telemetry.load([bower_contracts::SourceActivity {
        application: "App".into(),
        environment: "prod".into(),
        last_seen_at: past,
        event_count: 1,
    }]);
    telemetry.mark_changed(&telemetry.sources());
    run_source_activity(store.clone(), telemetry.clone())
        .await
        .unwrap();
    assert_eq!(store.get_source_activity().unwrap().len(), 1);
    assert!(telemetry.take_changed_sources().is_empty());
}
