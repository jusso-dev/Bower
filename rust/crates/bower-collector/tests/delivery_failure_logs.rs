//! Delivery failure diagnostics. Its own test binary: the captured `tracing` subscriber
//! must not race other tests' callsite registration.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_collector::shutdown;
use bower_collector::worker::{QueueDeliveryOptions, QueueDeliveryWorker};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{
    DeliveryFailure, DeliveryResult, DurableEventStore, OutputAdapter, QueueState, QueuedEvent,
};
use bower_persistence::SqliteEventStore;

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl FakeClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(
            bower_contracts::time::parse("2026-05-01T10:00:00Z").unwrap(),
        )))
    }

    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += chrono::TimeDelta::from_std(by).unwrap();
    }
}

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

type Deliver = dyn Fn(&[QueuedEvent]) -> DeliveryResult + Send + Sync;

struct FakeOutput(Box<Deliver>);

impl OutputAdapter for FakeOutput {
    fn id(&self) -> &str {
        "fake"
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        (self.0)(events)
    }
}

fn failure(event_id: &str, code: &str, retryable: bool) -> DeliveryFailure {
    DeliveryFailure {
        event_id: event_id.into(),
        code: code.into(),
        is_retryable: retryable,
        retry_after: None,
    }
}

fn result(
    acknowledged: &[&str],
    failures: Vec<DeliveryFailure>,
    ack: Option<&str>,
) -> DeliveryResult {
    DeliveryResult {
        acknowledged_event_ids: acknowledged.iter().map(|id| id.to_string()).collect(),
        failures,
        destination_acknowledgement: ack.map(str::to_string),
    }
}

fn create_store(directory: &tempfile::TempDir, clock: &FakeClock) -> Arc<SqliteEventStore> {
    let store = SqliteEventStore::new(
        directory.path().join("queue.db"),
        10 * 1024 * 1024,
        Some(Arc::new(clock.clone())),
    )
    .unwrap();
    store.initialize().unwrap();
    Arc::new(store)
}

fn enqueue(store: &SqliteEventStore, clock: &FakeClock, ids: &[&str]) {
    for id in ids {
        store
            .enqueue(&QueuedEvent {
                lease_token: None,
                event_id: id.to_string(),
                fingerprint: format!("sha256:{id}"),
                payload: format!("{{\"eventId\":\"{id}\"}}"),
                received_at: clock.utc_now(),
                state: QueueState::Queued,
                delivery_attempts: 0,
                suppression: None,
            })
            .unwrap();
    }
}

fn worker(
    store: Arc<dyn DurableEventStore>,
    output: FakeOutput,
    clock: &FakeClock,
    maximum_attempts: i32,
) -> QueueDeliveryWorker<FakeOutput> {
    QueueDeliveryWorker::new(
        store,
        Arc::new(output),
        Arc::new(clock.clone()),
        QueueDeliveryOptions {
            maximum_delivery_attempts: maximum_attempts,
            ..QueueDeliveryOptions::default()
        },
    )
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
async fn credential_failure_keeps_events_queued_and_logs_only_metadata() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["a", "b", "poison"]);
    let repaired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fixed = repaired.clone();
    let output = FakeOutput(Box::new(move |events| {
        if fixed.load(Ordering::SeqCst) {
            let ids: Vec<&str> = events.iter().map(|item| item.event_id.as_str()).collect();
            return result(&ids, Vec::new(), Some("accepted"));
        }
        let failures = events
            .iter()
            .map(|item| {
                if item.event_id == "poison" {
                    failure(&item.event_id, "payload-invalid-json", false)
                } else {
                    failure(
                        &item.event_id,
                        "destination-azure-credential-failed",
                        true,
                    )
                }
            })
            .collect();
        result(&[], failures, None)
    }));
    let worker = worker(store.clone(), output, &clock, 1);
    let (_owner, token) = shutdown::channel();

    worker.deliver_once(&token).await.unwrap();

    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(logs.contains(
        "Output adapter did not deliver events. output_id=\"fake\" count=2 failure_code=\"destination-azure-credential-failed\" disposition=\"retrying\""
    ), "{logs}");
    assert!(logs.contains(
        "count=1 failure_code=\"payload-invalid-json\" disposition=\"dead-lettered\""
    ), "{logs}");
    assert_eq!(store.snapshot().unwrap().retrying, 2);

    // A credential outage never spends the poison budget: after the fix it drains.
    for _ in 0..5 {
        clock.advance(Duration::from_secs(30));
        worker.deliver_once(&token).await.unwrap();
    }
    assert_eq!(store.snapshot().unwrap().retrying, 2);
    repaired.store(true, Ordering::SeqCst);
    clock.advance(Duration::from_secs(30));
    worker.deliver_once(&token).await.unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.delivered, 2);
    assert_eq!(snapshot.dead_lettered, 1);
}
