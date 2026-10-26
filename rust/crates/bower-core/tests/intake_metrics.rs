//! Port of `IntakeMetricsTests`: queue-capacity refusals are counted as intake
//! attempts, apart from selection decisions and committed events.

mod support;

use std::sync::Arc;
use std::time::Duration;

use bower_contracts::{DurableEventStore, QueueState, QueuedEvent, StoreError};
use bower_core::{
    CollectorIdentity, IntakeMetricsSnapshot, PipelineTelemetry, ProcessError,
    SecurityEventProcessor,
};
use support::*;

fn identity() -> CollectorIdentity {
    CollectorIdentity::new("collector-1", "0.1.0", "test", "sha256:configuration")
}

#[test]
fn full_queue_counts_each_attempt_as_refusal_and_retry_counts_independently() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        bower_persistence::SqliteEventStore::new(
            directory.path().join("queue.db"),
            1_048_576,
            None,
        )
        .unwrap(),
    );
    store.initialize().unwrap();
    store
        .enqueue(&QueuedEvent {
            lease_token: None,
            event_id: "filler".into(),
            fingerprint: "sha256:filler".into(),
            payload: "x".repeat(1_048_000),
            received_at: now(),
            state: QueueState::Queued,
            delivery_attempts: 0,
            suppression: None,
        })
        .unwrap();
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(now)));
    let processor = SecurityEventProcessor::new(
        Arc::new(FieldRedactor {
            remove: vec![],
            mask: vec![],
            detected: vec![],
        }),
        Arc::new(TestPolicy),
        store.clone(),
        Arc::new(now),
    )
    .with_telemetry(Arc::clone(&telemetry));
    let json = authentication_failure_json("");
    let bytes = i64::try_from(json.len()).unwrap();

    let attempts = 3;
    for _ in 0..attempts {
        let error = processor.process(&json, &identity()).unwrap_err();
        assert!(matches!(error, ProcessError::Store(StoreError::Full(_))));
    }

    let refused = telemetry.intake_snapshot();
    assert_eq!(refused.observed_since, now());
    assert_eq!(refused.attempted_requests, attempts);
    assert_eq!(refused.attempted_bytes, attempts * bytes);
    assert_eq!(refused.capacity_refusals, attempts);
    assert_eq!(refused.capacity_refused_bytes, attempts * bytes);
    assert_eq!(refused.last_refusal_at, Some(now()));
    assert_eq!(refused.last_refusal_reason, Some("queue-capacity"));
    // Refusals are not selection decisions and never count as committed events.
    let pipeline = telemetry.snapshot();
    assert_eq!(pipeline.events_in, 0);
    assert_eq!(pipeline.events_queued, 0);
    assert!(pipeline.rows.is_empty());
    assert_eq!(store.snapshot().unwrap().queued, 1);
    assert!(telemetry.sources().is_empty());

    let leased = store.lease(10, Duration::from_secs(60)).unwrap();
    assert_eq!(leased.len(), 1);
    store
        .mark_delivered("filler", "test-ack", leased[0].lease_token.as_deref())
        .unwrap();
    let retried = processor.process(&json, &identity()).unwrap();
    let repeated = processor.process(&json, &identity()).unwrap();

    assert!(retried.queued && !retried.duplicate);
    assert!(!repeated.queued && repeated.duplicate);
    let after = telemetry.intake_snapshot();
    assert_eq!(after.attempted_requests, attempts + 2);
    assert_eq!(after.attempted_bytes, (attempts + 2) * bytes);
    assert_eq!(after.capacity_refusals, attempts);
    assert_eq!(after.capacity_refused_bytes, attempts * bytes);
    let pipeline = telemetry.snapshot();
    assert_eq!(pipeline.events_in, 2);
    assert_eq!(pipeline.events_queued, 1);
    assert_eq!(pipeline.duplicates, 1);
    assert_eq!(pipeline.bytes_in, 2 * bytes);
}

#[test]
fn intake_starts_empty_for_the_process_lifetime() {
    assert_eq!(
        PipelineTelemetry::new(Arc::new(now)).intake_snapshot(),
        IntakeMetricsSnapshot {
            observed_since: now(),
            attempted_requests: 0,
            attempted_bytes: 0,
            capacity_refusals: 0,
            capacity_refused_bytes: 0,
            last_refusal_at: None,
            last_refusal_reason: None,
        }
    );
}

#[test]
fn intake_concurrent_updates_lose_nothing() {
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(now)));
    let workers = 8;
    let per_worker = 5_000;
    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let telemetry = Arc::clone(&telemetry);
            std::thread::spawn(move || {
                for index in 0..per_worker {
                    telemetry.record_attempt(3);
                    if index % 2 == 0 {
                        telemetry.record_capacity_refusal(3);
                    }
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    let snapshot = telemetry.intake_snapshot();
    assert_eq!(snapshot.attempted_requests, workers * per_worker);
    assert_eq!(snapshot.attempted_bytes, workers * per_worker * 3);
    assert_eq!(snapshot.capacity_refusals, workers * per_worker / 2);
    assert_eq!(
        snapshot.capacity_refused_bytes,
        workers * per_worker / 2 * 3
    );
    assert_eq!(snapshot.last_refusal_at, Some(now()));
}
