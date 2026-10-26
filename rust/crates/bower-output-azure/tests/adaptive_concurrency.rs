//! Port of `AdaptiveConcurrencyTests`: the AIMD controller, and the output against a
//! fake ingestion endpoint injecting throttling, 5xx bursts, latency and Retry-After.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bower_contracts::time::Timestamp;
use bower_contracts::{OutputAdapter, OutputConcurrencySnapshot, QueueState, QueuedEvent, time};
use bower_output_azure::{
    AccessToken, AdaptiveConcurrencyController, AzureLogsIngestionOptions,
    AzureLogsIngestionOutput, ConcurrencyScope, ConcurrencySignal, IngestionClientOptions,
    TimeSource, TokenFuture, TokenProvider,
};
use reqwest::Url;

const HEALTHY: Duration = Duration::from_millis(100);

fn complete(controller: &AdaptiveConcurrencyController, signal: ConcurrencySignal, rtt: Duration) {
    controller.complete(controller.begin_attempt(), signal, rtt);
}

#[test]
fn controller_starts_at_the_ceiling_and_stays_there_while_healthy() {
    let controller = AdaptiveConcurrencyController::new(4).unwrap();
    for _ in 0..100 {
        complete(&controller, ConcurrencySignal::Healthy, HEALTHY);
    }
    // The fixed setting was maximum_concurrency; the healthy case never runs below it.
    assert_eq!(controller.limit(), 4);
    let snapshot = controller.snapshot("out", time::now());
    assert_eq!(snapshot.decreases, 0);
    assert_eq!(snapshot.latency_ewma_milliseconds, Some(100));
}

#[test]
fn controller_follows_the_shared_aimd_trace() {
    // Same script and expected trace as AdaptiveConcurrencyTests.Controller_FollowsTheSharedAimdTrace.
    let controller = AdaptiveConcurrencyController::new(8).unwrap();
    let mut trace = Vec::new();
    let mut step = |signal, milliseconds: u64| {
        complete(&controller, signal, Duration::from_millis(milliseconds));
        trace.push(controller.limit());
    };
    for _ in 0..8 {
        step(ConcurrencySignal::Healthy, 100);
    }
    step(ConcurrencySignal::Throttled, 100);
    step(ConcurrencySignal::Throttled, 100);
    step(ConcurrencySignal::ServerError, 100);
    step(ConcurrencySignal::Timeout, 100);
    for _ in 0..28 {
        step(ConcurrencySignal::Healthy, 100);
    }
    step(ConcurrencySignal::Healthy, 400);
    step(ConcurrencySignal::Neutral, 100);
    // One window: three attempts started under the same limit fail together.
    let window = [
        controller.begin_attempt(),
        controller.begin_attempt(),
        controller.begin_attempt(),
    ];
    controller.complete(window[0], ConcurrencySignal::Throttled, HEALTHY);
    controller.complete(window[1], ConcurrencySignal::Throttled, HEALTHY);
    controller.complete(window[2], ConcurrencySignal::ServerError, HEALTHY);
    trace.push(controller.limit());

    let expected: Vec<usize> = vec![
        8, 8, 8, 8, 8, 8, 8, 8, //
        4, 2, 1, 1, //
        2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, //
        6, 6, //
        3,
    ];
    assert_eq!(trace, expected);
    assert_eq!(
        controller.snapshot("azure-logs-ingestion", time::now()),
        OutputConcurrencySnapshot {
            output_id: "azure-logs-ingestion".into(),
            limit: 3,
            minimum_limit: 1,
            maximum_limit: 8,
            in_flight: 0,
            latency_ewma_milliseconds: Some(175),
            requests: 45,
            throttles: 4,
            server_errors: 2,
            timeouts: 1,
            latency_spikes: 1,
            decreases: 5,
            increases: 7,
            pauses: 0,
            process_local_paused_until: None,
        }
    );
}

#[test]
fn controller_stale_attempts_neither_decrease_nor_increase_again() {
    let controller = AdaptiveConcurrencyController::new(4).unwrap();
    let stale = controller.begin_attempt();
    let also_stale = controller.begin_attempt();
    complete(&controller, ConcurrencySignal::Throttled, HEALTHY);
    assert_eq!(controller.limit(), 2);

    controller.complete(stale, ConcurrencySignal::ServerError, HEALTHY);
    controller.complete(also_stale, ConcurrencySignal::Healthy, HEALTHY);

    assert_eq!(controller.limit(), 2);
    let snapshot = controller.snapshot("out", time::now());
    assert_eq!((snapshot.decreases, snapshot.increases), (1, 0));
}

#[test]
fn controller_jitter_below_the_floor_is_not_a_spike() {
    let controller = AdaptiveConcurrencyController::new(4).unwrap();
    for _ in 0..4 {
        complete(
            &controller,
            ConcurrencySignal::Healthy,
            Duration::from_millis(2),
        );
    }
    // 100x the EWMA but under the absolute floor: fast-link jitter, not congestion.
    complete(
        &controller,
        ConcurrencySignal::Healthy,
        Duration::from_millis(200),
    );
    assert_eq!(controller.limit(), 4);
    assert_eq!(controller.snapshot("out", time::now()).latency_spikes, 0);
}

#[test]
fn controller_persistent_latency_raises_the_baseline_and_recovers() {
    let controller = AdaptiveConcurrencyController::new(4).unwrap();
    for _ in 0..4 {
        complete(&controller, ConcurrencySignal::Healthy, HEALTHY);
    }
    let slow = Duration::from_millis(500);
    complete(&controller, ConcurrencySignal::Healthy, slow);
    assert_eq!(controller.limit(), 3);
    for _ in 0..20 {
        complete(&controller, ConcurrencySignal::Healthy, slow);
    }
    // A fivefold step is two spikes (EWMA 100 then 200), then the new baseline is healthy.
    assert_eq!(controller.limit(), 4);
    assert_eq!(controller.snapshot("out", time::now()).latency_spikes, 2);
}

#[test]
fn controller_never_leaves_its_bounds() {
    let controller = AdaptiveConcurrencyController::new(32).unwrap();
    for _ in 0..50 {
        complete(&controller, ConcurrencySignal::ServerError, HEALTHY);
        assert!((1..=32).contains(&controller.limit()));
    }
    assert_eq!(controller.limit(), 1);
    for _ in 0..5000 {
        complete(&controller, ConcurrencySignal::Healthy, HEALTHY);
        assert!((1..=32).contains(&controller.limit()));
    }
    assert_eq!(controller.limit(), 32);
    assert!(AdaptiveConcurrencyController::new(0).is_err());
    assert!(AdaptiveConcurrencyController::new(33).is_err());
}

#[test]
fn controller_classifies_statuses() {
    for (status, expected) in [
        (200, ConcurrencySignal::Healthy),
        (204, ConcurrencySignal::Healthy),
        (429, ConcurrencySignal::Throttled),
        (500, ConcurrencySignal::ServerError),
        (503, ConcurrencySignal::ServerError),
        (408, ConcurrencySignal::Timeout),
        (0, ConcurrencySignal::Timeout),
        (400, ConcurrencySignal::Neutral),
        (401, ConcurrencySignal::Neutral),
        (413, ConcurrencySignal::Neutral),
    ] {
        assert_eq!(ConcurrencySignal::classify(status), expected, "{status}");
    }
}

#[test]
fn controller_pause_is_bounded_visible_and_expires_on_the_clock() {
    let controller = AdaptiveConcurrencyController::new(4).unwrap();
    let now = time::parse("2026-07-26T02:14:19Z").unwrap();
    let seconds = |value: i64| now + chrono::TimeDelta::seconds(value);

    controller.pause(seconds(-1), now);
    assert_eq!(controller.paused_until(now), None);
    controller.pause(seconds(30), now);
    controller.pause(seconds(10), now);

    assert_eq!(controller.paused_until(now), Some(seconds(30)));
    assert_eq!(
        controller.snapshot("out", now).process_local_paused_until,
        Some(seconds(30))
    );
    assert_eq!(controller.paused_until(seconds(30)), None);
    let snapshot = controller.snapshot("out", seconds(30));
    assert_eq!(
        (snapshot.process_local_paused_until, snapshot.pauses),
        (None, 1)
    );
}

#[tokio::test]
async fn controller_acquire_waits_for_a_slot_and_cancellation_leaks_nothing() {
    let controller = Arc::new(AdaptiveConcurrencyController::new(2).unwrap());
    complete(&controller, ConcurrencySignal::Throttled, HEALTHY);
    let held = controller.acquire().await;

    // A dropped wait (cancellation) takes no slot.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), controller.acquire())
            .await
            .is_err()
    );
    assert_eq!(controller.snapshot("out", time::now()).in_flight, 1);

    let waiting = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move { controller.acquire().await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiting.is_finished());
    drop(held);
    let next = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    drop(next);
    assert_eq!(controller.snapshot("out", time::now()).in_flight, 0);
}

type Respond = Arc<dyn Fn(usize) -> (u16, Option<&'static str>) + Send + Sync>;
type Latency = Arc<dyn Fn(usize) -> Duration + Send + Sync>;

/// C# `ManualTimestamps` / `FakeClock`: wall time pinned, monotonic time moves only
/// when the endpoint says a request took that long. Real scheduling never shows up.
#[derive(Debug)]
struct ManualTime {
    wall: Timestamp,
    nanos: AtomicU64,
}

impl ManualTime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wall: time::parse("2026-07-26T02:14:19Z").unwrap(),
            nanos: AtomicU64::new(0),
        })
    }

    fn advance(&self, by: Duration) {
        self.nanos
            .fetch_add(u64::try_from(by.as_nanos()).unwrap(), Ordering::SeqCst);
    }
}

impl TimeSource for ManualTime {
    fn utc_now(&self) -> Timestamp {
        self.wall
    }

    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

/// Fake ingestion endpoint: scripted status and Retry-After, delay and peak concurrency.
#[derive(Clone)]
struct Endpoint {
    respond: Arc<Mutex<Respond>>,
    delay: Arc<Mutex<Duration>>,
    /// Simulated RTT per request number, applied to `time`.
    latency: Arc<Mutex<Latency>>,
    time: Arc<ManualTime>,
    retry_after_header: &'static str,
    hold_until_concurrent: usize,
    concurrent: Arc<tokio::sync::Notify>,
    released: Arc<std::sync::atomic::AtomicBool>,
    /// Signalled (permit stored) every time a request reaches the endpoint.
    entered: Arc<tokio::sync::Notify>,
    count: Arc<AtomicUsize>,
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Endpoint {
    fn new(respond: Respond) -> Self {
        Self {
            respond: Arc::new(Mutex::new(respond)),
            delay: Arc::default(),
            latency: Arc::new(Mutex::new(Arc::new(|_| Duration::ZERO))),
            time: ManualTime::new(),
            retry_after_header: "retry-after",
            hold_until_concurrent: 0,
            concurrent: Arc::default(),
            released: Arc::default(),
            entered: Arc::default(),
            count: Arc::default(),
            in_flight: Arc::default(),
            peak: Arc::default(),
        }
    }

    fn set(&self, respond: Respond) {
        *self.respond.lock().unwrap() = respond;
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn reset_peak(&self) {
        self.peak.store(0, Ordering::SeqCst);
    }

    async fn start(self) -> (Url, Self) {
        let app = Router::new()
            .route("/dataCollectionRules/{rule}/streams/{stream}", post(ingest))
            .with_state(self.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (Url::parse(&format!("http://{address}")).unwrap(), self)
    }
}

async fn ingest(State(endpoint): State<Endpoint>, _body: Bytes) -> Response {
    // Registered before counting, so the request that completes the set wakes it.
    let notified = endpoint.concurrent.notified();
    let number = endpoint.count.fetch_add(1, Ordering::SeqCst) + 1;
    endpoint.entered.notify_one();
    let current = endpoint.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    endpoint.peak.fetch_max(current, Ordering::SeqCst);
    if endpoint.hold_until_concurrent > 0 && !endpoint.released.load(Ordering::SeqCst) {
        if current >= endpoint.hold_until_concurrent {
            endpoint.released.store(true, Ordering::SeqCst);
            endpoint.concurrent.notify_waiters();
        } else {
            let _ = tokio::time::timeout(Duration::from_secs(10), notified).await;
        }
    }
    let delay = *endpoint.delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let latency = endpoint.latency.lock().unwrap().clone();
    endpoint.time.advance(latency(number));
    let respond = endpoint.respond.lock().unwrap().clone();
    let (status, retry_after) = respond(number);
    endpoint.in_flight.fetch_sub(1, Ordering::SeqCst);
    let mut response = (StatusCode::from_u16(status).unwrap(), "{}").into_response();
    if let Some(value) = retry_after {
        response
            .headers_mut()
            .insert(endpoint.retry_after_header, value.parse().unwrap());
    }
    response
}

fn status(code: u16) -> Respond {
    Arc::new(move |_| (code, None))
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

fn output(endpoint: &Endpoint, base: &Url, maximum_concurrency: usize) -> AzureLogsIngestionOutput {
    output_with(
        endpoint,
        base,
        maximum_concurrency,
        0,
        ConcurrencyScope::Output,
    )
}

fn output_with(
    endpoint: &Endpoint,
    base: &Url,
    maximum_concurrency: usize,
    max_retries: u32,
    concurrency_scope: ConcurrencyScope,
) -> AzureLogsIngestionOutput {
    let options = AzureLogsIngestionOptions {
        maximum_concurrency,
        concurrency_scope,
        ..AzureLogsIngestionOptions::new(
            "azure-logs-ingestion",
            Url::parse("https://example.ingest.monitor.azure.com").unwrap(),
            "dcr-00000000000000000000000000000000",
            "Custom-BowerSecurity",
        )
    };
    AzureLogsIngestionOutput::with_client_options(
        options,
        Arc::new(StaticCredential),
        IngestionClientOptions {
            max_retries,
            retry_delay: Duration::from_millis(1),
            max_retry_delay: Duration::from_millis(10),
            transport_base_url: Some(base.clone()),
            time: endpoint.time.clone(),
            ..IngestionClientOptions::default()
        },
    )
    .unwrap()
}

/// Every event carries one ~600 KB record so each is its own upload request.
fn events(prefix: &str, count: usize) -> Vec<QueuedEvent> {
    let padding = "x".repeat(600 * 1024);
    (0..count)
        .map(|index| {
            let event_id = format!("{prefix}-{index}");
            QueuedEvent {
                lease_token: None,
                payload: format!(
                    r#"{{"eventId":"{event_id}","timeGenerated":"2026-10-08T00:00:00Z","padding":"{padding}"}}"#
                ),
                fingerprint: format!("sha256:{event_id}"),
                event_id,
                received_at: time::now(),
                state: QueueState::Queued,
                delivery_attempts: 0,
                suppression: None,
            }
        })
        .collect()
}

fn snapshot(output: &AzureLogsIngestionOutput) -> OutputConcurrencySnapshot {
    output.concurrency_snapshot().unwrap()
}

#[tokio::test]
async fn output_throttling_drops_concurrency_and_recovers_without_losing_events() {
    let (base, endpoint) = Endpoint::new(status(429)).start().await;
    let output = output(&endpoint, &base, 8);

    let throttled = output.deliver(&events("t", 8)).await;

    assert!(throttled.acknowledged_event_ids.is_empty());
    assert_eq!(throttled.failures.len(), 8);
    assert!(
        throttled
            .failures
            .iter()
            .all(|failure| failure.is_retryable && failure.is_destination_failure())
    );
    let after = snapshot(&output);
    assert!((1..=4).contains(&after.limit), "{after:?}");
    assert_eq!((after.throttles, after.in_flight), (8, 0));

    endpoint.set(status(204));
    endpoint.reset_peak();
    let mut acknowledged = std::collections::HashSet::new();
    for round in 0..12 {
        let result = output.deliver(&events(&format!("r{round}"), 8)).await;
        assert!(result.failures.is_empty(), "{:?}", result.failures);
        acknowledged.extend(result.acknowledged_event_ids);
    }
    assert_eq!(acknowledged.len(), 96);
    assert_eq!(snapshot(&output).limit, 8);
    assert!((1..=8).contains(&endpoint.peak()));
}

#[tokio::test]
async fn output_healthy_throughput_uses_the_full_fixed_setting() {
    let mut endpoint = Endpoint::new(status(204));
    endpoint.hold_until_concurrent = 4;
    let (base, endpoint) = endpoint.start().await;
    let output = output(&endpoint, &base, 4);

    let result = tokio::time::timeout(Duration::from_secs(20), output.deliver(&events("h", 8)))
        .await
        .unwrap();

    assert_eq!(result.acknowledged_event_ids.len(), 8);
    assert_eq!(endpoint.peak(), 4);
    assert_eq!(snapshot(&output).limit, 4);
}

#[tokio::test]
async fn output_concurrency_gate_bounds_requests_in_flight_after_a_throttle() {
    let (base, endpoint) = Endpoint::new(status(503)).start().await;
    let output = output(&endpoint, &base, 8);
    for name in ["burst", "burst-2", "burst-3"] {
        output.deliver(&events(name, 1)).await;
    }
    assert_eq!(snapshot(&output).limit, 1);

    endpoint.set(status(204));
    *endpoint.delay.lock().unwrap() = Duration::from_millis(20);
    endpoint.reset_peak();
    let result = output.deliver(&events("gated", 3)).await;

    assert_eq!(result.acknowledged_event_ids.len(), 3);
    // Limit 1 lets one request out; it then grows to 2 after one healthy attempt.
    assert!((1..=2).contains(&endpoint.peak()), "{}", endpoint.peak());
    assert_eq!(snapshot(&output).server_errors, 3);
}

#[tokio::test]
async fn output_retry_after_pauses_the_stream_and_is_visible_in_metrics() {
    let (base, endpoint) = Endpoint::new(Arc::new(|number| {
        if number == 1 {
            (429, Some("120"))
        } else {
            (204, None)
        }
    }))
    .start()
    .await;
    let output = output(&endpoint, &base, 1);
    let deadline = endpoint.time.utc_now() + chrono::TimeDelta::seconds(120);

    let result = output.deliver(&events("p", 4)).await;

    // The first request was throttled; the rest of the batch was never sent.
    assert_eq!(endpoint.count(), 1);
    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), 4);
    for failure in &result.failures {
        assert!(failure.is_retryable && failure.is_destination_failure());
        assert_eq!(failure.retry_after, Some(deadline));
    }
    assert_eq!(
        result
            .failures
            .iter()
            .filter(|failure| failure.code == "destination-azure-paused")
            .count(),
        3
    );
    let snapshot = snapshot(&output);
    assert_eq!(snapshot.process_local_paused_until, Some(deadline));
    assert_eq!(snapshot.pauses, 1);
    // Across deliveries the durable destination circuit holds the stream, not the output.
    assert_eq!(
        output
            .deliver(&events("p", 4))
            .await
            .acknowledged_event_ids
            .len(),
        4
    );
}

#[tokio::test]
async fn output_latency_spike_reduces_concurrency() {
    let (base, endpoint) = Endpoint::new(status(204)).start().await;
    *endpoint.latency.lock().unwrap() =
        Arc::new(|number| Duration::from_millis(if number <= 4 { 50 } else { 500 }));
    let output = output(&endpoint, &base, 4);

    for index in 0..5 {
        output.deliver(&events(&format!("l{index}"), 1)).await;
    }

    // Same numbers as C# Output_LatencySpikeReducesConcurrency: EWMA 50, then 162.5.
    let snapshot = snapshot(&output);
    assert_eq!(
        (
            snapshot.limit,
            snapshot.latency_spikes,
            snapshot.latency_ewma_milliseconds
        ),
        (3, 1, Some(163)),
        "{snapshot:?}"
    );
}

#[tokio::test]
async fn output_short_retry_after_during_sdk_retries_pauses_the_stream() {
    // The common Azure case: a short Retry-After the retry loop honours in memory.
    let mut endpoint = Endpoint::new(Arc::new(|number| {
        if number == 1 {
            (429, Some("1"))
        } else {
            (204, None)
        }
    }));
    endpoint.retry_after_header = "retry-after-ms";
    let (base, endpoint) = endpoint.start().await;
    let output = output_with(&endpoint, &base, 1, 2, ConcurrencyScope::Output);
    let deadline = endpoint.time.utc_now() + chrono::TimeDelta::milliseconds(1);

    let result = output.deliver(&events("s", 3)).await;

    // The throttled batch succeeded on its retry; the paused rest was never sent.
    assert_eq!(endpoint.count(), 2);
    assert_eq!(result.acknowledged_event_ids, ["s-0"]);
    let mut paused: Vec<_> = result
        .failures
        .iter()
        .map(|failure| failure.event_id.as_str())
        .collect();
    paused.sort_unstable();
    assert_eq!(paused, ["s-1", "s-2"]);
    for failure in &result.failures {
        assert_eq!(failure.code, "destination-azure-paused");
        assert!(failure.is_retryable);
        assert_eq!(failure.retry_after, Some(deadline));
    }
    let snapshot = snapshot(&output);
    assert_eq!((snapshot.pauses, snapshot.throttles), (1, 1));
    assert_eq!(snapshot.process_local_paused_until, Some(deadline));
}

#[tokio::test]
async fn output_delivery_scope_bounds_each_delivery_not_the_whole_output() {
    // Eight concurrent single-event deliveries must all be in flight together.
    let mut endpoint = Endpoint::new(status(204));
    endpoint.hold_until_concurrent = 8;
    let (base, endpoint) = endpoint.start().await;
    let output = output_with(&endpoint, &base, 4, 0, ConcurrencyScope::Delivery);
    let batches: Vec<_> = (0..8)
        .map(|index| events(&format!("d{index}"), 1))
        .collect();

    let results = tokio::time::timeout(
        Duration::from_secs(20),
        futures_join_all(batches.iter().map(|batch| output.deliver(batch))),
    )
    .await
    .unwrap();

    assert!(
        results
            .iter()
            .all(|result| result.acknowledged_event_ids.len() == 1)
    );
    assert_eq!(endpoint.peak(), 8);
    // No shared controller: nothing output-wide to report.
    assert!(output.concurrency_snapshot().is_none());
}

/// Polls every future on this task until all complete (no extra dependency).
async fn futures_join_all<F: std::future::Future>(
    futures: impl Iterator<Item = F>,
) -> Vec<F::Output> {
    let mut pending: Vec<_> = futures.map(Box::pin).map(Some).collect();
    let mut results: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|context| {
        let mut done = true;
        for (slot, result) in pending.iter_mut().zip(results.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(context) {
                    std::task::Poll::Ready(value) => {
                        *result = Some(value);
                        *slot = None;
                    }
                    std::task::Poll::Pending => done = false,
                }
            }
        }
        if done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    results.into_iter().map(Option::unwrap).collect()
}

#[tokio::test]
async fn output_cancellation_while_waiting_for_a_slot_never_acknowledges() {
    let (base, endpoint) = Endpoint::new(status(204)).start().await;
    // The first request never completes on its own; the other two wait for its slot.
    *endpoint.delay.lock().unwrap() = Duration::from_secs(3600);
    let output = output(&endpoint, &base, 1);

    // Cancel only once the first request has reached the endpoint: dropping the
    // delivery future is cancellation (the worker aborts its task). No timer races
    // batch preparation, which is slow on loaded runners.
    let batch = events("c", 3);
    let delivery = output.deliver(&batch);
    tokio::select! {
        result = delivery => panic!("delivery finished despite a held request: {result:?}"),
        () = endpoint.entered.notified() => {}
    }

    assert_eq!(endpoint.count(), 1);
    // Aborted upload tasks drop their permits when the runtime next polls them. The
    // timeout only guards against a hang; release does not depend on elapsed time.
    tokio::time::timeout(Duration::from_secs(60), async {
        while snapshot(&output).in_flight != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("aborted uploads release their slots");
    assert_eq!(snapshot(&output).in_flight, 0);
    // Nothing else was sent after cancellation, so nothing could be acknowledged.
    tokio::task::yield_now().await;
    assert_eq!(endpoint.count(), 1);
}
