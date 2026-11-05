//! S3 output in the collector (C# `S3OutputTests` queue and settings cases, and
//! `CollectorHostTests.Status_ReportsTheOutputOnlyWhenItIsNotSentinel`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aws_config::BehaviorVersion;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode, Uri, header};
use bower_collector::bundle;
use bower_collector::host::{self, BoxedOutput, BuildOptions};
use bower_collector::settings::CollectorSettings;
use bower_collector::shutdown::ShutdownToken;
use bower_collector::worker::{QueueDeliveryOptions, QueueDeliveryWorker};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{DurableEventStore, QueueState, QueuedEvent};
use bower_output_s3::{S3Output, S3OutputOptions};
use bower_persistence::SqliteEventStore;
use tower::ServiceExt;

const TOKEN: &str = "test-token-with-at-least-thirty-two-characters";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

/// Answers every PUT with the current status (or `fail_index`'s status for that request);
/// counts requests and keeps paths.
#[derive(Clone, Default)]
struct FakeS3 {
    status: Arc<Mutex<u16>>,
    fail_index: Arc<Mutex<Option<(usize, u16)>>>,
    paths: Arc<Mutex<Vec<String>>>,
}

async fn start(fake: FakeS3) -> SocketAddr {
    let state = fake.clone();
    let app = axum::Router::new().fallback(move |uri: Uri, _body: Bytes| {
        let state = state.clone();
        async move {
            let index = {
                let mut paths = state.paths.lock().unwrap();
                paths.push(uri.path().to_string());
                paths.len() - 1
            };
            let status = match *state.fail_index.lock().unwrap() {
                Some((failing, status)) if failing == index => status,
                _ => *state.status.lock().unwrap(),
            };
            let body = match status {
                200 => String::new(),
                503 => "<Error><Code>SlowDown</Code><Message>Reduce your request rate.</Message></Error>".into(),
                _ => "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>".into(),
            };
            (StatusCode::from_u16(status).unwrap(), body)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    address
}

fn output(address: SocketAddr) -> S3Output {
    output_with(address, 1000)
}

fn output_with(address: SocketAddr, maximum_object_events: i32) -> S3Output {
    // Test-only placeholder credentials: the fake endpoint never checks signatures.
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("ap-southeast-2"))
        .endpoint_url(format!("http://{address}"))
        .force_path_style(true)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "fake-test-key-id",
            "fake-test-value",
            None,
            None,
            "bower-test",
        ))
        .retry_config(aws_config::retry::RetryConfig::disabled())
        .build();
    let mut options = S3OutputOptions::new("collector-test", "bower-test-bucket", "ap-southeast-2");
    options.maximum_object_events = maximum_object_events;
    S3Output::with_client(options, aws_sdk_s3::Client::from_conf(config)).unwrap()
}

fn queue(directory: &Path, clock: &FakeClock, count: usize) -> Arc<SqliteEventStore> {
    let store = SqliteEventStore::new(
        directory.join("queue.db"),
        10 * 1024 * 1024,
        Some(Arc::new(clock.clone())),
    )
    .unwrap();
    store.initialize().unwrap();
    for index in 0..count {
        store
            .enqueue(&QueuedEvent {
                event_id: format!("s3-{index}"),
                fingerprint: format!("sha256:{index}"),
                payload: format!("{{\"eventId\":\"s3-{index}\"}}"),
                received_at: clock.utc_now(),
                state: QueueState::Queued,
                delivery_attempts: 0,
                lease_token: None,
                suppression: None,
            })
            .unwrap();
    }
    Arc::new(store)
}

/// C# `Queue_FirstObjectDeliversAndSecondStaysRetrying_InOneLease`.
#[tokio::test]
async fn first_object_delivers_and_second_stays_retrying_in_one_lease() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock(Arc::new(Mutex::new(
        bower_contracts::time::parse("2026-07-26T02:14:19Z").unwrap(),
    )));
    let store = queue(directory.path(), &clock, 4);
    let fake = FakeS3::default();
    *fake.status.lock().unwrap() = 200;
    *fake.fail_index.lock().unwrap() = Some((1, 503));
    let address = start(fake.clone()).await;
    let worker = QueueDeliveryWorker::new(
        store.clone(),
        Arc::new(output_with(address, 2)),
        Arc::new(clock.clone()),
        QueueDeliveryOptions::default(),
    );

    assert_eq!(
        4,
        worker.deliver_once(&ShutdownToken::never()).await.unwrap()
    );

    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        (2, 2, 0, 0),
        (
            snapshot.delivered,
            snapshot.retrying,
            snapshot.uploading,
            snapshot.dead_lettered
        )
    );
    let paths = fake.paths.lock().unwrap().clone();
    assert_eq!(2, paths.len());
    let connection = rusqlite::Connection::open(directory.path().join("queue.db")).unwrap();
    let mut statement = connection
        .prepare("SELECT event_id, acknowledgement, last_failure_code FROM queue_events ORDER BY event_id")
        .unwrap();
    let rows: Vec<(String, Option<String>, Option<String>)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let first_object = format!("s3:/{}", paths[0]);
    let throttled = Some("destination-s3-throttled".to_string());
    assert_eq!(
        vec![
            ("s3-0".to_string(), Some(first_object.clone()), None),
            ("s3-1".to_string(), Some(first_object), None),
            ("s3-2".to_string(), None, throttled.clone()),
            ("s3-3".to_string(), None, throttled),
        ],
        rows
    );
}

#[tokio::test]
async fn destination_failure_keeps_events_queued_then_delivers_once() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock(Arc::new(Mutex::new(
        bower_contracts::time::parse("2026-07-26T02:14:19Z").unwrap(),
    )));
    let store = queue(directory.path(), &clock, 3);
    let fake = FakeS3::default();
    *fake.status.lock().unwrap() = 403;
    let address = start(fake.clone()).await;
    let worker = QueueDeliveryWorker::new(
        store.clone(),
        Arc::new(output(address)),
        Arc::new(clock.clone()),
        QueueDeliveryOptions {
            // Destination faults never spend attempts, so even one allowed attempt holds.
            maximum_delivery_attempts: 1,
            ..QueueDeliveryOptions::default()
        },
    );

    for _ in 0..3 {
        worker.deliver_once(&ShutdownToken::never()).await.unwrap();
        *clock.0.lock().unwrap() += chrono::TimeDelta::minutes(5);
    }
    let held = store.snapshot().unwrap();
    assert_eq!(
        (0, 3, 0, 0),
        (
            held.delivered,
            held.retrying,
            held.dead_lettered,
            held.uploading
        )
    );

    *fake.status.lock().unwrap() = 200;
    worker.deliver_once(&ShutdownToken::never()).await.unwrap();
    let delivered = store.snapshot().unwrap();
    assert_eq!(
        (3, 0, 0),
        (
            delivered.delivered,
            delivered.retrying,
            delivered.dead_lettered
        )
    );
    let paths = fake.paths.lock().unwrap().clone();
    assert_eq!(4, paths.len());
    assert!(paths.iter().all(|path| *path == paths[0]));
}

fn s3_environment() -> Vec<(&'static str, &'static str)> {
    vec![
        ("BOWER_OUTPUT", "s3"),
        ("BOWER_COLLECTOR_ID", "collector-test"),
        ("BOWER_S3_BUCKET", "bower-test-bucket"),
        ("BOWER_S3_REGION", "ap-southeast-2"),
        ("BOWER_S3_PREFIX", "security/bower"),
        ("BOWER_S3_SSE", "aws:kms"),
    ]
}

fn read(pairs: Vec<(&'static str, &'static str)>) -> impl Fn(&str) -> Option<String> {
    move |name| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_string())
    }
}

#[test]
fn settings_match_csharp_and_hash_only_non_secret_settings() {
    let settings = CollectorSettings::from_environment(read(s3_environment())).unwrap();
    let mut expected =
        S3OutputOptions::new("collector-test", "bower-test-bucket", "ap-southeast-2");
    expected.prefix = "security/bower".into();
    expected.server_side_encryption = Some("aws:kms".into());
    assert_eq!(Some(expected), settings.s3_output);
    // C# S3OutputTests pins the same hash for the same environment.
    assert_eq!(
        "sha256:a9429d32a9a415445bb25f4290db2a46c94e1667fb3f089fdc7c88429dd54b45",
        settings.configuration_hash()
    );

    let mut with_chain = s3_environment();
    with_chain.push(("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEEXAMPLE00"));
    with_chain.push((
        "AWS_SECRET_ACCESS_KEY",
        "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY",
    ));
    assert_eq!(
        settings.configuration_hash(),
        CollectorSettings::from_environment(read(with_chain))
            .unwrap()
            .configuration_hash()
    );

    let secret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY";
    let mut static_key = vec![("BOWER_OUTPUT", "none")];
    static_key.push(("BOWER_S3_SECRET_ACCESS_KEY", secret));
    let error = CollectorSettings::from_environment(read(static_key)).unwrap_err();
    assert!(!error.to_string().contains(secret));

    let no_bucket = vec![("BOWER_OUTPUT", "s3")];
    assert!(CollectorSettings::from_environment(read(no_bucket)).is_err());
    let mut wrong_output = s3_environment();
    wrong_output[0] = ("BOWER_OUTPUT", "ama-spool");
    assert!(CollectorSettings::from_environment(read(wrong_output)).is_err());
    let mut bad_collector = s3_environment();
    bad_collector[1] = ("BOWER_COLLECTOR_ID", "host name");
    assert!(CollectorSettings::from_environment(read(bad_collector)).is_err());
    let mut bad_prefix = s3_environment();
    bad_prefix[3] = ("BOWER_S3_PREFIX", "security/*");
    assert!(CollectorSettings::from_environment(read(bad_prefix)).is_err());
    let mut bad_bucket = s3_environment();
    bad_bucket[2] = ("BOWER_S3_BUCKET", "Bad.Bucket");
    assert!(CollectorSettings::from_environment(read(bad_bucket)).is_err());
}

async fn status_body(output: Option<BoxedOutput>) -> String {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.path().join("queue.db"),
        repo_root().join("policies/default"),
        "collector-test",
    );
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    let mut collector = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions {
            output,
            ..BuildOptions::default()
        },
    )
    .unwrap();
    collector.initialize().await.unwrap();
    let request = Request::get("/v1/status")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = collector.router.clone().oneshot(request).await.unwrap();
    assert_eq!(StatusCode::OK, response.status());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn status_reports_the_output_only_when_it_is_not_sentinel() {
    assert!(!status_body(None).await.contains("\"output\":"));
    let s3 = S3Output::new(S3OutputOptions::new(
        "collector-status",
        "bower-status-test",
        "ap-southeast-2",
    ))
    .unwrap();
    let body = status_body(Some(BoxedOutput(Arc::new(s3)))).await;
    assert!(body.contains("\"output\":\"s3\""), "{body}");
    assert!(!body.contains("bower-status-test"));
}
