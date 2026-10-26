//! Port of `QueueDeliveryWorkerTests` against the real SQLite queue.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_collector::shutdown::{self, ShutdownToken};
use bower_collector::worker::{QueueDeliveryOptions, QueueDeliveryWorker};
use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{
    DeadLetterRecord, DeliveryFailure, DeliveryResult, DurableEventStore, EnqueueResult,
    FailureSettlement, LedgerHead, LedgerVerification, OutputAdapter, QueueSnapshot, QueueState,
    QueuedEvent, StoreError, StoreResult,
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

#[tokio::test]
async fn deliver_once_settles_acknowledged_retryable_and_permanent_failures() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["ok", "retry", "bad"]);
    let output = FakeOutput(Box::new(|_| {
        result(
            &["ok"],
            vec![
                failure("retry", "azure-http-503", true),
                failure("bad", "azure-http-400", false),
            ],
            Some("ack-1"),
        )
    }));

    let leased = worker(store.clone(), output, &clock, 20)
        .deliver_once(&ShutdownToken::never())
        .await
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(leased, 3);
    assert_eq!(snapshot.delivered, 1);
    assert_eq!(snapshot.retrying, 1);
    assert_eq!(snapshot.dead_lettered, 1);
    assert_eq!(snapshot.uploading, 0);
}

#[tokio::test]
async fn deliver_once_retries_whole_batch_when_adapter_panics() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["a", "b"]);
    let output = FakeOutput(Box::new(|_| panic!("network down")));

    worker(store.clone(), output, &clock, 20)
        .deliver_once(&ShutdownToken::never())
        .await
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(snapshot.retrying, 2);
    assert_eq!(snapshot.delivered, 0);
}

#[tokio::test]
async fn deliver_once_tolerates_duplicate_unknown_and_missing_results() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["a", "b", "c"]);
    // "a" is both acknowledged and failed, "ghost" was never leased, "c" is missing.
    let output = FakeOutput(Box::new(|_| {
        result(
            &["a", "ghost", "b"],
            vec![failure("a", "azure-http-500", true)],
            Some("ack"),
        )
    }));

    worker(store.clone(), output, &clock, 20)
        .deliver_once(&ShutdownToken::never())
        .await
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(snapshot.delivered, 2);
    assert_eq!(snapshot.retrying, 1);
    assert_eq!(snapshot.uploading, 0);
}

#[tokio::test]
async fn deliver_once_dead_letters_after_maximum_attempts() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["poison"]);
    let output = FakeOutput(Box::new(|events| {
        result(
            &[],
            events
                .iter()
                .map(|item| failure(&item.event_id, "azure-http-500", true))
                .collect(),
            None,
        )
    }));
    let worker = worker(store.clone(), output, &clock, 2);

    worker.deliver_once(&ShutdownToken::never()).await.unwrap();
    clock.advance(Duration::from_secs(3600));
    worker.deliver_once(&ShutdownToken::never()).await.unwrap();
    let snapshot = store.snapshot().unwrap();
    let dead = store.list_dead_lettered(10).unwrap();

    assert_eq!(snapshot.dead_lettered, 1);
    assert_eq!(snapshot.retrying, 0);
    assert_eq!(
        dead[0].failure_code.as_deref(),
        Some("max-attempts-exceeded:azure-http-500")
    );
}

#[tokio::test]
async fn deliver_once_ignores_settlement_of_reclaimed_lease() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["slow"]);
    let (inner_store, inner_clock) = (store.clone(), clock.clone());
    let output = FakeOutput(Box::new(move |_| {
        // Another worker reclaims and delivers the event while this delivery is slow.
        inner_clock.advance(Duration::from_secs(600));
        let reclaimed = inner_store.lease(1, Duration::from_secs(300)).unwrap();
        inner_store
            .mark_delivered(
                &reclaimed[0].event_id,
                "other-worker",
                reclaimed[0].lease_token.as_deref(),
            )
            .unwrap();
        result(&[], vec![failure("slow", "timeout", true)], None)
    }));

    worker(store.clone(), output, &clock, 20)
        .deliver_once(&ShutdownToken::never())
        .await
        .unwrap();

    assert_eq!(store.snapshot().unwrap().delivered, 1);
}

#[tokio::test]
async fn deliver_once_batch_acknowledgement_skips_only_the_reclaimed_event() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["slow", "fast"]);
    let (inner_store, inner_clock) = (store.clone(), clock.clone());
    let output = FakeOutput(Box::new(move |_| {
        // Another worker reclaims "slow" and settles it before this batch acknowledges.
        inner_clock.advance(Duration::from_secs(600));
        let reclaimed = inner_store.lease(1, Duration::from_secs(300)).unwrap();
        inner_store
            .mark_delivered("slow", "other-worker", reclaimed[0].lease_token.as_deref())
            .unwrap();
        result(&["slow", "fast"], Vec::new(), Some("ack-batch"))
    }));

    let leased = worker(store.clone(), output, &clock, 20)
        .deliver_once(&ShutdownToken::never())
        .await
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(leased, 2);
    assert_eq!(snapshot.delivered, 2);
    assert_eq!(snapshot.uploading, 0);
    assert_eq!(snapshot.retrying, 0);
}

#[tokio::test]
async fn deliver_once_settles_all_failures_in_one_batch_all_or_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["ok", "retry", "bad", "missing"]);
    let flaky = Arc::new(FlakyStore::new(store.clone(), 0, 1));
    let output = FakeOutput(Box::new(|events| {
        let acknowledged: Vec<&str> = events
            .iter()
            .map(|item| item.event_id.as_str())
            .filter(|id| *id == "ok")
            .collect();
        let failures = events
            .iter()
            .filter_map(|item| match item.event_id.as_str() {
                "retry" => Some(failure("retry", "azure-http-503", true)),
                "bad" => Some(failure("bad", "azure-http-400", false)),
                _ => None,
            })
            .collect();
        result(&acknowledged, failures, Some("ack-1"))
    }));
    let worker = worker(flaky.clone(), output, &clock, 20);

    // The failure batch fails: acknowledged events stay delivered, every failed event
    // stays leased (none half-settled) and is redelivered once the lease expires.
    assert!(matches!(
        worker.deliver_once(&ShutdownToken::never()).await,
        Err(bower_collector::worker::DeliveryError::Store(
            StoreError::Storage(_)
        ))
    ));
    let after_failure = store.snapshot().unwrap();
    assert_eq!(
        (
            after_failure.delivered,
            after_failure.uploading,
            after_failure.retrying,
            after_failure.dead_lettered
        ),
        (1, 3, 0, 0)
    );

    clock.advance(Duration::from_secs(360));
    let redelivered = worker.deliver_once(&ShutdownToken::never()).await.unwrap();
    let settled = store.snapshot().unwrap();

    assert_eq!(redelivered, 3);
    assert_eq!(flaky.failed_batch_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        (
            settled.delivered,
            settled.uploading,
            settled.retrying,
            settled.dead_lettered
        ),
        (1, 0, 2, 1)
    );
    assert!(store.verify_ledger().unwrap().intact);
}

#[tokio::test]
async fn worker_keeps_running_after_storage_failure() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["a"]);
    let flaky = Arc::new(FlakyStore::new(store.clone(), 2, 0));
    let (delivered_sender, delivered) = tokio::sync::oneshot::channel::<()>();
    let delivered_sender = Mutex::new(Some(delivered_sender));
    let output = FakeOutput(Box::new(move |events| {
        if let Some(sender) = delivered_sender.lock().unwrap().take() {
            let _ = sender.send(());
        }
        let ids: Vec<&str> = events.iter().map(|item| item.event_id.as_str()).collect();
        result(&ids, Vec::new(), Some("ack"))
    }));
    let worker = QueueDeliveryWorker::new(
        flaky.clone() as Arc<dyn DurableEventStore>,
        Arc::new(output),
        Arc::new(bower_contracts::time::SystemClock),
        QueueDeliveryOptions {
            idle_delay: Duration::from_millis(10),
            error_delay: Duration::from_millis(10),
            ..QueueDeliveryOptions::default()
        },
    );
    let (trigger, token) = shutdown::channel();

    let running = tokio::spawn(async move { worker.run(token).await });
    tokio::time::timeout(Duration::from_secs(10), delivered)
        .await
        .unwrap()
        .unwrap();
    trigger.cancel();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(flaky.failures.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn worker_stops_promptly_when_cancelled_while_idle() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    let output = FakeOutput(Box::new(|_| DeliveryResult::default()));
    let worker = worker(store, output, &clock, 20);
    let (trigger, token) = shutdown::channel();

    let running = tokio::spawn(async move { worker.run(token).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    trigger.cancel();

    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
}

struct FlakyStore {
    inner: Arc<SqliteEventStore>,
    failures: AtomicUsize,
    failures_before_success: usize,
    failed_batch_calls: AtomicUsize,
    failed_batch_failures: usize,
}

impl FlakyStore {
    fn new(
        inner: Arc<SqliteEventStore>,
        failures_before_success: usize,
        failed_batch_failures: usize,
    ) -> Self {
        Self {
            inner,
            failures: AtomicUsize::new(0),
            failures_before_success,
            failed_batch_calls: AtomicUsize::new(0),
            failed_batch_failures,
        }
    }
}

impl DurableEventStore for FlakyStore {
    fn mark_delivered_batch(
        &self,
        event_ids: &[String],
        acknowledgement: &str,
        lease_tokens: &std::collections::HashMap<String, String>,
    ) -> StoreResult<Vec<String>> {
        self.inner
            .mark_delivered_batch(event_ids, acknowledgement, lease_tokens)
    }
    fn mark_failed_batch(&self, failures: &[FailureSettlement]) -> StoreResult<Vec<String>> {
        let call = self.failed_batch_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= self.failed_batch_failures {
            return Err(StoreError::Storage("database is locked".into()));
        }
        self.inner.mark_failed_batch(failures)
    }
    fn initialize(&self) -> StoreResult<()> {
        self.inner.initialize()
    }
    fn enqueue(&self, candidate: &QueuedEvent) -> StoreResult<EnqueueResult> {
        self.inner.enqueue(candidate)
    }
    fn lease(
        &self,
        maximum_count: usize,
        lease_duration: Duration,
    ) -> StoreResult<Vec<QueuedEvent>> {
        if self.failures.load(Ordering::SeqCst) < self.failures_before_success {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return Err(StoreError::Storage("database is locked".into()));
        }
        self.inner.lease(maximum_count, lease_duration)
    }
    fn mark_delivered(
        &self,
        event_id: &str,
        acknowledgement: &str,
        lease_token: Option<&str>,
    ) -> StoreResult<()> {
        self.inner
            .mark_delivered(event_id, acknowledgement, lease_token)
    }
    fn mark_retrying(
        &self,
        event_id: &str,
        failure_code: &str,
        retry_after: Timestamp,
        lease_token: Option<&str>,
    ) -> StoreResult<()> {
        self.inner
            .mark_retrying(event_id, failure_code, retry_after, lease_token)
    }
    fn mark_dead_lettered(
        &self,
        event_id: &str,
        failure_code: &str,
        lease_token: Option<&str>,
    ) -> StoreResult<()> {
        self.inner
            .mark_dead_lettered(event_id, failure_code, lease_token)
    }
    fn snapshot(&self) -> StoreResult<QueueSnapshot> {
        self.inner.snapshot()
    }
    fn purge_delivered(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
    ) -> StoreResult<usize> {
        self.inner.purge_delivered(delivered_before, maximum_count)
    }
    fn maintain(&self) -> StoreResult<()> {
        self.inner.maintain()
    }
    fn purge_delivered_archived(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
        archived_through_sequence: i64,
    ) -> StoreResult<usize> {
        self.inner.purge_delivered_archived(
            delivered_before,
            maximum_count,
            archived_through_sequence,
        )
    }
    fn close_expired_suppression_windows(
        &self,
        now: Timestamp,
        create_summary: &mut dyn FnMut(
            &bower_contracts::SuppressionWindow,
        ) -> StoreResult<QueuedEvent>,
    ) -> StoreResult<usize> {
        self.inner
            .close_expired_suppression_windows(now, create_summary)
    }
    fn get_source_activity(&self) -> StoreResult<Vec<bower_contracts::SourceActivity>> {
        self.inner.get_source_activity()
    }
    fn upsert_source_activity(
        &self,
        activity: &[bower_contracts::SourceActivity],
    ) -> StoreResult<()> {
        self.inner.upsert_source_activity(activity)
    }
    fn get_source_monitoring(&self) -> StoreResult<Vec<bower_contracts::SourceMonitoring>> {
        self.inner.get_source_monitoring()
    }
    fn start_source_monitoring(
        &self,
        expected: &[bower_contracts::SourceMonitoring],
    ) -> StoreResult<Vec<bower_contracts::SourceMonitoring>> {
        self.inner.start_source_monitoring(expected)
    }
    fn list_dead_lettered(&self, maximum_count: usize) -> StoreResult<Vec<DeadLetterRecord>> {
        self.inner.list_dead_lettered(maximum_count)
    }
    fn replay_dead_lettered(
        &self,
        failure_code_prefix: Option<&str>,
        event_ids: Option<&[String]>,
        maximum_count: usize,
    ) -> StoreResult<usize> {
        self.inner
            .replay_dead_lettered(failure_code_prefix, event_ids, maximum_count)
    }
    fn ledger_head(&self) -> StoreResult<LedgerHead> {
        self.inner.ledger_head()
    }
    fn verify_ledger(&self) -> StoreResult<LedgerVerification> {
        self.inner.verify_ledger()
    }
}

#[tokio::test]
async fn destination_outages_survive_restart_pause_backlog_and_preserve_budget() {
    for status in [401, 403, 429, 503] {
        let directory = tempfile::tempdir().unwrap();
        let clock = FakeClock::new();
        let store = create_store(&directory, &clock);
        enqueue(&store, &clock, &["valid"]);
        let repaired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let make_output = || {
            let repaired = repaired.clone();
            let clock = clock.clone();
            FakeOutput(Box::new(move |events| {
                assert!(events.iter().all(|item| item.delivery_attempts == 1));
                if repaired.load(Ordering::SeqCst) {
                    DeliveryResult {
                        acknowledged_event_ids: events
                            .iter()
                            .map(|item| item.event_id.clone())
                            .collect(),
                        failures: vec![],
                        destination_acknowledgement: Some("accepted".into()),
                    }
                } else {
                    let failures = events
                        .iter()
                        .map(|item| DeliveryFailure {
                            event_id: item.event_id.clone(),
                            code: format!("destination-azure-http-{status}"),
                            is_retryable: true,
                            retry_after: Some(clock.utc_now() + chrono::Duration::seconds(120)),
                        })
                        .collect();
                    DeliveryResult {
                        acknowledged_event_ids: vec![],
                        failures,
                        destination_acknowledgement: None,
                    }
                }
            }))
        };
        worker(store.clone(), make_output(), &clock, 1)
            .deliver_once(&ShutdownToken::never())
            .await
            .unwrap();
        enqueue(&store, &clock, &["backlog"]);
        drop(store);
        let reopened = create_store(&directory, &clock);
        let restarted = worker(reopened.clone(), make_output(), &clock, 1);
        clock.advance(Duration::from_secs(119));
        assert_eq!(
            restarted
                .deliver_once(&ShutdownToken::never())
                .await
                .unwrap(),
            0
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            restarted
                .deliver_once(&ShutdownToken::never())
                .await
                .unwrap(),
            2
        );
        assert_eq!(reopened.snapshot().unwrap().dead_lettered, 0);
        repaired.store(true, Ordering::SeqCst);
        clock.advance(Duration::from_secs(120));
        assert_eq!(
            restarted
                .deliver_once(&ShutdownToken::never())
                .await
                .unwrap(),
            2
        );
        assert_eq!(reopened.snapshot().unwrap().delivered, 2);
    }
}

#[tokio::test]
async fn excessive_destination_deadline_is_capped_and_recovers_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["valid"]);
    let deadline = clock.utc_now() + chrono::Duration::days(365 * 50);
    let failing = FakeOutput(Box::new(move |_| {
        result(
            &[],
            vec![DeliveryFailure {
                event_id: "valid".into(),
                code: "destination-azure-http-429".into(),
                is_retryable: true,
                retry_after: Some(deadline),
            }],
            None,
        )
    }));
    worker(store.clone(), failing, &clock, 1)
        .deliver_once(&ShutdownToken::never())
        .await
        .unwrap();
    drop(store);
    let reopened = create_store(&directory, &clock);
    let accepting = FakeOutput(Box::new(|_| result(&["valid"], vec![], Some("accepted"))));
    let restarted = worker(reopened.clone(), accepting, &clock, 1);
    clock.advance(Duration::from_secs(3599));
    assert_eq!(
        restarted
            .deliver_once(&ShutdownToken::never())
            .await
            .unwrap(),
        0
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        restarted
            .deliver_once(&ShutdownToken::never())
            .await
            .unwrap(),
        1
    );
    assert_eq!(reopened.snapshot().unwrap().delivered, 1);
}

#[tokio::test]
async fn isolated_bad_record_never_pauses_healthy_backlog() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = create_store(&directory, &clock);
    enqueue(&store, &clock, &["bad", "good"]);
    let output = FakeOutput(Box::new(|events| DeliveryResult {
        acknowledged_event_ids: events
            .iter()
            .filter(|item| item.event_id != "bad")
            .map(|item| item.event_id.clone())
            .collect(),
        failures: events
            .iter()
            .filter(|item| item.event_id == "bad")
            .map(|item| failure(&item.event_id, "azure-http-400-isolated", false))
            .collect(),
        destination_acknowledgement: Some("accepted".into()),
    }));
    let worker = worker(store.clone(), output, &clock, 1);
    assert_eq!(
        worker.deliver_once(&ShutdownToken::never()).await.unwrap(),
        2
    );
    enqueue(&store, &clock, &["backlog"]);
    assert_eq!(
        worker.deliver_once(&ShutdownToken::never()).await.unwrap(),
        1
    );
    assert_eq!(store.snapshot().unwrap().delivered, 2);
    assert_eq!(store.snapshot().unwrap().dead_lettered, 1);
}
