//! Adaptive request concurrency in the host: `/v1/status` reports it (metadata only)
//! and a throttled stream stays durable in the queue until delivered exactly once.
//! Ports of `CollectorHostTests.Status_*Concurrency*` and
//! `AdaptiveConcurrencyTests.Worker_ThrottledEventsStayDurableAndDeliverOnceWithoutPrematureAck`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;
use bower_collector::host::{self, BoxedOutput, BuildOptions};
use bower_collector::shutdown;
use bower_collector::worker::{QueueDeliveryOptions, QueueDeliveryWorker};
use bower_collector::{CollectorSettings, bundle};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{
    DeliveryFailure, DeliveryResult, DurableEventStore, OutputAdapter, OutputConcurrencySnapshot,
    QueueState, QueuedEvent, time,
};
use bower_output_azure::{
    AccessToken, AzureLogsIngestionOptions, AzureLogsIngestionOutput, IngestionClientOptions,
    TokenFuture, TokenProvider,
};
use bower_persistence::SqliteEventStore;
use reqwest::Url;
use tower::ServiceExt;

const TOKEN: &str = "test-ingest-token-0123456789abcdef0123456789";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn settings(directory: &Path) -> CollectorSettings {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        repo_root().join("policies/default"),
        "collector-test",
    );
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    settings
}

async fn status_body(output: Option<BoxedOutput>) -> String {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings(directory.path());
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

struct ConcurrencyReportingOutput;

impl OutputAdapter for ConcurrencyReportingOutput {
    fn id(&self) -> &str {
        "azure-logs-ingestion"
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        DeliveryResult {
            acknowledged_event_ids: Vec::new(),
            failures: events
                .iter()
                .map(|item| DeliveryFailure {
                    event_id: item.event_id.clone(),
                    code: "destination-test".into(),
                    is_retryable: true,
                    retry_after: None,
                })
                .collect(),
            destination_acknowledgement: None,
        }
    }

    fn concurrency_snapshot(&self) -> Option<OutputConcurrencySnapshot> {
        Some(OutputConcurrencySnapshot {
            output_id: "azure-logs-ingestion".into(),
            limit: 2,
            minimum_limit: 1,
            maximum_limit: 4,
            in_flight: 1,
            latency_ewma_milliseconds: Some(163),
            requests: 9,
            throttles: 3,
            server_errors: 1,
            timeouts: 0,
            latency_spikes: 1,
            decreases: 2,
            increases: 1,
            pauses: 1,
            paused_until: time::parse("2026-07-26T02:16:19Z"),
        })
    }
}

#[tokio::test]
async fn status_reports_adaptive_delivery_concurrency_as_metadata_only() {
    let body = status_body(Some(BoxedOutput(Arc::new(ConcurrencyReportingOutput)))).await;

    // Same text as the C# collector (CollectorHostTests).
    assert!(
        body.contains(
            r#""delivery":{"outputId":"azure-logs-ingestion","limit":2,"minimumLimit":1,"maximumLimit":4,"inFlight":1,"latencyEwmaMilliseconds":163,"requests":9,"throttles":3,"serverErrors":1,"timeouts":0,"latencySpikes":1,"decreases":2,"increases":1,"pauses":1,"pausedUntil":"2026-07-26T02:16:19+00:00"}"#
        ),
        "{body}"
    );
}

#[tokio::test]
async fn status_omits_delivery_when_the_output_does_not_adapt_concurrency() {
    assert!(!status_body(None).await.contains(r#""delivery""#));
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

struct StaticCredential;

impl TokenProvider for StaticCredential {
    fn get_token<'a>(&'a self, _scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            Ok(AccessToken {
                token: "test-token".to_owned(),
                expires_on: time::now() + chrono::Duration::hours(1),
            })
        })
    }
}

#[tokio::test]
async fn worker_throttled_events_stay_durable_and_deliver_once_without_premature_ack() {
    // The output stamps Retry-After from the wall clock, so the fake clock starts there.
    let clock = FakeClock(Arc::new(Mutex::new(time::now())));
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteEventStore::new(
            directory.path().join("queue.db"),
            64 * 1024 * 1024,
            Some(Arc::new(clock.clone())),
        )
        .unwrap(),
    );
    store.initialize().unwrap();
    let padding = "x".repeat(600 * 1024);
    for index in 0..6 {
        let event_id = format!("w-{index}");
        store
            .enqueue(&QueuedEvent {
                lease_token: None,
                payload: format!(
                    r#"{{"eventId":"{event_id}","timeGenerated":"2026-10-08T00:00:00Z","padding":"{padding}"}}"#
                ),
                fingerprint: format!("sha256:{event_id}"),
                event_id,
                received_at: clock.utc_now(),
                state: QueueState::Queued,
                delivery_attempts: 0,
                suppression: None,
            })
            .unwrap();
    }

    // Fake ingestion endpoint: 429 with Retry-After 60 until switched to 204.
    let status = Arc::new(AtomicU16::new(429));
    let count = Arc::new(AtomicUsize::new(0));
    let app = {
        let (status, count) = (Arc::clone(&status), Arc::clone(&count));
        Router::new().route(
            "/dataCollectionRules/{rule}/streams/{stream}",
            post(move || {
                let (status, count) = (Arc::clone(&status), Arc::clone(&count));
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let code = StatusCode::from_u16(status.load(Ordering::SeqCst)).unwrap();
                    ([("retry-after", "60")], (code, "{}")).into_response()
                }
            }),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let output = AzureLogsIngestionOutput::with_client_options(
        AzureLogsIngestionOptions {
            maximum_concurrency: 2,
            ..AzureLogsIngestionOptions::new(
                "azure-logs-ingestion",
                Url::parse("https://example.ingest.monitor.azure.com").unwrap(),
                "dcr-00000000000000000000000000000000",
                "Custom-BowerSecurity",
            )
        },
        Arc::new(StaticCredential),
        IngestionClientOptions {
            max_retries: 0,
            transport_base_url: Some(base),
            ..IngestionClientOptions::default()
        },
    )
    .unwrap();
    let store: Arc<dyn DurableEventStore> = store;
    let worker = QueueDeliveryWorker::new(
        Arc::clone(&store),
        Arc::new(output),
        Arc::new(clock.clone()),
        QueueDeliveryOptions {
            maximum_delivery_attempts: 1,
            ..QueueDeliveryOptions::default()
        },
    );
    let (_trigger, token) = shutdown::channel();

    assert_eq!(worker.deliver_once(&token).await.unwrap(), 6);
    let throttled = store.snapshot().unwrap();
    assert_eq!(
        (
            throttled.retrying,
            throttled.delivered,
            throttled.dead_lettered
        ),
        (6, 0, 0)
    );
    // The durable destination circuit holds the stream for the Retry-After window.
    assert_eq!(worker.deliver_once(&token).await.unwrap(), 0);
    // Up to two requests were in flight before the pause; the rest were never sent.
    let throttled_requests = count.load(Ordering::SeqCst);
    assert!(
        (1..=2).contains(&throttled_requests),
        "{throttled_requests}"
    );

    status.store(204, Ordering::SeqCst);
    *clock.0.lock().unwrap() += chrono::TimeDelta::seconds(120);
    assert_eq!(worker.deliver_once(&token).await.unwrap(), 6);
    let delivered = store.snapshot().unwrap();
    assert_eq!(
        (
            delivered.delivered,
            delivered.dead_lettered,
            delivered.retrying + delivered.queued + delivered.uploading
        ),
        (6, 0, 0)
    );
    assert_eq!(count.load(Ordering::SeqCst), throttled_requests + 6);
}
