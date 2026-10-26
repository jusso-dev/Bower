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

fn tfn_processor(
    store: &Arc<MemoryStore>,
    telemetry: &Arc<PipelineTelemetry>,
) -> SecurityEventProcessor {
    SecurityEventProcessor::new(
        Arc::new(FieldRedactor {
            remove: vec![],
            mask: vec![("note", "TFN [REDACTED]")],
            detected: vec!["au.tfn"],
        }),
        Arc::new(TestPolicy),
        store.clone(),
        Arc::new(now),
    )
    .with_telemetry(Arc::clone(telemetry))
}

#[test]
fn alert_refused_after_commit_records_the_event_and_a_distinct_reason() {
    // Room for the event, not its privacy alert.
    let store = Arc::new(MemoryStore {
        capacity: Some(1),
        ..MemoryStore::default()
    });
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(now)));
    let processor = tfn_processor(&store, &telemetry);
    let json = authentication_failure_json(r#"{"note":"TFN 100000001"}"#);
    let bytes = i64::try_from(json.len()).unwrap();

    // Status code unchanged: the alert refusal still surfaces as backpressure (503).
    let error = processor.process(&json, &identity()).unwrap_err();
    assert!(matches!(error, ProcessError::Store(StoreError::Full(_))));

    let rows = store.items();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_id, "event-1");
    let intake = telemetry.intake_snapshot();
    assert_eq!(intake.attempted_requests, 1);
    assert_eq!(intake.capacity_refusals, 0);
    assert_eq!(intake.capacity_refused_bytes, 0);
    assert_eq!(intake.privacy_alert_refusals, 1);
    assert_eq!(intake.privacy_alert_refused_bytes, bytes);
    assert_eq!(intake.last_refusal_reason, Some("privacy-alert-capacity"));
    assert_eq!(intake.last_refusal_at, Some(now()));
    let pipeline = telemetry.snapshot();
    assert_eq!(pipeline.events_in, 1);
    assert_eq!(pipeline.events_queued, 1);
    assert_eq!(
        pipeline.bytes_queued,
        i64::try_from(rows[0].payload.len()).unwrap()
    );
    let sources = telemetry.sources();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].application, "TestApplication");
}

#[test]
fn alert_refused_for_invalid_or_rejected_event_keeps_their_selection_outcome() {
    let store = Arc::new(MemoryStore {
        capacity: Some(0),
        ..MemoryStore::default()
    });
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(now)));
    let processor = tfn_processor(&store, &telemetry);
    let json = authentication_failure_json(r#"{"note":"TFN 100000001"}"#);
    let invalid = json.replace(r#""schemaVersion":"1.0.0""#, r#""schemaVersion":"9.9.9""#);
    let rejected = json.replace(r#""eventId":"event-1""#, r#""eventId":"rejected""#);

    for candidate in [&invalid, &rejected] {
        let error = processor.process(candidate, &identity()).unwrap_err();
        assert!(matches!(error, ProcessError::Store(StoreError::Full(_))));
    }

    let intake = telemetry.intake_snapshot();
    assert_eq!(intake.attempted_requests, 2);
    assert_eq!(intake.capacity_refusals, 0);
    assert_eq!(intake.privacy_alert_refusals, 2);
    let pipeline = telemetry.snapshot();
    assert_eq!(pipeline.events_in, 2);
    assert_eq!(pipeline.events_queued, 0);
    assert_eq!(
        pipeline
            .rows
            .iter()
            .map(|row| (row.stage.as_str(), row.action.as_str()))
            .collect::<Vec<_>>(),
        [("policy", "reject"), ("validation", "quarantine")]
    );
    assert!(telemetry.sources().is_empty());
    assert!(store.items().is_empty());
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
            privacy_alert_refusals: 0,
            privacy_alert_refused_bytes: 0,
            last_refusal_at: None,
            last_refusal_reason: None,
        }
    );
}

#[test]
fn intake_last_refusal_moves_forward_only_and_keeps_its_reason() {
    let clock = Arc::new(std::sync::Mutex::new(now() + chrono::Duration::seconds(2)));
    let source = Arc::clone(&clock);
    let telemetry = PipelineTelemetry::new(Arc::new(move || *source.lock().unwrap()));
    telemetry.record_privacy_alert_refusal(1);
    *clock.lock().unwrap() = now() + chrono::Duration::seconds(1);
    telemetry.record_capacity_refusal(1);

    let snapshot = telemetry.intake_snapshot();
    assert_eq!(
        snapshot.last_refusal_at,
        Some(now() + chrono::Duration::seconds(2))
    );
    assert_eq!(snapshot.last_refusal_reason, Some("privacy-alert-capacity"));
}

#[test]
fn intake_concurrent_updates_lose_nothing_and_never_tear() {
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(now)));
    let workers = 8;
    let per_worker = 5_000;
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (telemetry, done) = (Arc::clone(&telemetry), Arc::clone(&done));
        std::thread::spawn(move || {
            let mut torn = 0;
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                let seen = telemetry.intake_snapshot();
                let refusals = seen.capacity_refusals + seen.privacy_alert_refusals;
                if (refusals > 0 && seen.last_refusal_at.is_none())
                    || refusals > seen.attempted_requests
                {
                    torn += 1;
                }
            }
            torn
        })
    };
    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let telemetry = Arc::clone(&telemetry);
            std::thread::spawn(move || {
                for index in 0..per_worker {
                    telemetry.record_attempt(3);
                    if index % 2 == 0 {
                        telemetry.record_capacity_refusal(3);
                    } else if index % 5 == 0 {
                        telemetry.record_privacy_alert_refusal(3);
                    }
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    done.store(true, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(reader.join().unwrap(), 0);
    let snapshot = telemetry.intake_snapshot();
    assert_eq!(snapshot.attempted_requests, workers * per_worker);
    assert_eq!(snapshot.attempted_bytes, workers * per_worker * 3);
    assert_eq!(snapshot.capacity_refusals, workers * per_worker / 2);
    assert_eq!(
        snapshot.capacity_refused_bytes,
        workers * per_worker / 2 * 3
    );
    assert_eq!(snapshot.privacy_alert_refusals, workers * (per_worker / 10));
    assert_eq!(
        snapshot.privacy_alert_refused_bytes,
        workers * (per_worker / 10) * 3
    );
    assert_eq!(snapshot.last_refusal_at, Some(now()));
}
