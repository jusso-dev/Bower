mod common;

use bower_contracts::{DurableEventStore, FailureSettlement, StoreError};
use bower_persistence::SqliteEventStore;
use chrono::Duration as Span;
use common::*;
use std::time::Duration;

#[test]
fn expired_owner_cannot_settle_new_lease_or_replayed_incarnation() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    let item = event("one", "fp", "{}", clock.now());
    store.enqueue(&item).unwrap();
    let old = store.lease(1, Duration::from_secs(1)).unwrap().remove(0);
    clock.advance(Span::seconds(2));
    let current = store.lease(1, Duration::from_secs(60)).unwrap().remove(0);
    assert_ne!(old.lease_token, current.lease_token);
    assert!(
        store
            .mark_delivered("one", "stale", old.lease_token.as_deref())
            .is_err()
    );
    assert!(
        store
            .mark_retrying("one", "stale", clock.now(), old.lease_token.as_deref())
            .is_err()
    );
    assert!(
        store
            .mark_dead_lettered("one", "stale", old.lease_token.as_deref())
            .is_err()
    );
    let claims = [(old.event_id.clone(), old.lease_token.clone().unwrap())]
        .into_iter()
        .collect();
    assert_eq!(
        store
            .mark_delivered_batch(&["one".into()], "stale", &claims)
            .unwrap(),
        ["one"]
    );
    assert_eq!(
        store
            .mark_failed_batch(&[FailureSettlement {
                event_id: "one".into(),
                failure_code: "stale".into(),
                retry_after: None,
                lease_token: old.lease_token.clone(),
            }])
            .unwrap(),
        ["one"]
    );
    assert_eq!(store.snapshot().unwrap().uploading, 1);
    store
        .mark_delivered("one", "ack", current.lease_token.as_deref())
        .unwrap();
    store
        .purge_delivered(clock.now() + Span::seconds(1), 10)
        .unwrap();
    store.enqueue(&item).unwrap();
    let replayed = store.lease(1, Duration::from_secs(60)).unwrap().remove(0);
    assert_ne!(old.lease_token, replayed.lease_token);
    assert!(
        store
            .mark_dead_lettered("one", "stale", old.lease_token.as_deref())
            .is_err()
    );
    assert!(store.verify_ledger().unwrap().intact);
}

#[test]
fn exact_replay_normalizes_order_but_changed_content_conflicts_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let first = store(directory.path(), ONE_MEBIBYTE, &clock);
    let item = event(
        "one",
        "fp",
        r#"{"schemaVersion":"1.0.0","eventType":"test","eventId":"one","value":1,"timeObserved":"old"}"#,
        clock.now(),
    );
    first.enqueue(&item).unwrap();
    let restarted = store(directory.path(), ONE_MEBIBYTE, &clock);
    let replay = event(
        "one",
        "fp",
        r#"{"value":1,"eventId":"one","eventType":"test","schemaVersion":"1.0.0","timeObserved":"new"}"#,
        clock.now(),
    );
    assert!(restarted.enqueue(&replay).unwrap().duplicate);
    let changed = event(
        "one",
        "fp",
        &item.payload.replace("\"value\":1", "\"value\":2"),
        clock.now(),
    );
    assert!(
        matches!(restarted.enqueue(&changed), Err(StoreError::Invalid(message)) if message == "event-identity-conflict")
    );
    let other_scope = event("one", "different-source", &item.payload, clock.now());
    assert!(
        matches!(restarted.enqueue(&other_scope), Err(StoreError::Invalid(message)) if message == "event-identity-conflict")
    );
    assert_eq!(
        restarted.lease(1, Duration::from_secs(60)).unwrap()[0].payload,
        item.payload
    );
}

#[test]
fn unresolved_row_does_not_pin_history_and_retention_replay_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let first = store(directory.path(), ONE_MEBIBYTE, &clock);
    enqueue(&first, &clock, "unresolved");
    let lease = first.lease(1, Duration::from_secs(60)).unwrap().remove(0);
    first
        .mark_dead_lettered("unresolved", "test", lease.lease_token.as_deref())
        .unwrap();
    let item = event("replayed", "replayed", &"x".repeat(8192), clock.now());
    for _ in 0..300 {
        first.enqueue(&item).unwrap();
        let lease = first.lease(1, Duration::from_secs(60)).unwrap().remove(0);
        first
            .mark_delivered("replayed", "ack", lease.lease_token.as_deref())
            .unwrap();
        first
            .purge_delivered(clock.now() + Span::seconds(1), 10)
            .unwrap();
    }
    first.enqueue(&item).unwrap();
    let restarted = store(directory.path(), ONE_MEBIBYTE, &clock);
    assert!(restarted.verify_ledger().unwrap().intact);
    assert_eq!(restarted.snapshot().unwrap().dead_lettered, 1);
    let connection = raw(first.database_path());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM queue_ledger_segments", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM queue_ledger", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert!(storage_bytes(first.database_path()) <= first.maximum_storage_bytes() as u64);
    connection.execute("INSERT INTO queue_events_v5(event_id,fingerprint,payload,payload_bytes,received_at,state,enqueue_sequence) SELECT 'injected','injected','{}',2,received_at,0,(SELECT MIN(start_sequence) FROM queue_ledger_segments) FROM queue_events_v5 WHERE event_id='replayed'", []).unwrap();
    assert!(!restarted.verify_ledger().unwrap().intact);
    connection
        .execute("DELETE FROM queue_events_v5 WHERE event_id='injected'", [])
        .unwrap();
    assert!(restarted.verify_ledger().unwrap().intact);
    connection
        .execute(
            "UPDATE queue_ledger_segments SET checkpoint_hash = 'corrupt'",
            [],
        )
        .unwrap();
    assert!(!restarted.verify_ledger().unwrap().intact);
    assert!(
        restarted
            .purge_delivered(clock.now() + Span::days(1), 10)
            .is_err()
    );
}

#[test]
fn populated_old_migration_rollback_restart_and_old_writer_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-queue.db", directory.path());
    let connection = raw(&path);
    let before: i64 = connection
        .query_row("SELECT COUNT(*) FROM queue_events", [], |row| row.get(0))
        .unwrap();
    connection.execute_batch("CREATE TRIGGER interrupt_v5 BEFORE INSERT ON schema_history WHEN NEW.version=5 BEGIN SELECT RAISE(ROLLBACK, 'interrupted'); END;").unwrap();
    let store = SqliteEventStore::new(&path, 10 * ONE_MEBIBYTE, None).unwrap();
    assert!(store.initialize().is_err());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM queue_events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='queue_events_v5'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    connection
        .execute_batch("DROP TRIGGER interrupt_v5;")
        .unwrap();
    store.initialize().unwrap();
    assert!(store.verify_ledger().unwrap().intact);
    assert!(
        connection
            .execute("UPDATE queue_events SET state=4 WHERE state=1", [])
            .is_err()
    );
    store.initialize().unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM queue_events_v5", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        before
    );
}

#[test]
fn csharp_v5_checkpoint_and_incarnation_are_interchangeable() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-queue-v5.db", directory.path());
    let store = SqliteEventStore::new(&path, 10 * ONE_MEBIBYTE, None).unwrap();
    store.initialize().unwrap();
    assert!(store.verify_ledger().unwrap().intact);
    let lease = store.lease(10, Duration::from_secs(60)).unwrap().remove(0);
    assert_eq!(lease.event_id, "replayed");
    assert_eq!(lease.lease_token.as_deref(), Some("3:1"));
    assert!(
        store
            .mark_delivered("replayed", "stale-csharp", Some("2:1"))
            .is_err()
    );
    store
        .mark_delivered("replayed", "rust", lease.lease_token.as_deref())
        .unwrap();
    assert!(store.verify_ledger().unwrap().intact);
}

#[test]
fn pinned_wal_reader_backpressures_before_physical_budget_and_preserves_event() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "retained");
    let mut connection = raw(store.database_path());
    let transaction = connection.transaction().unwrap();
    transaction
        .query_row("SELECT COUNT(*) FROM queue_events_v5", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    let mut blocked = false;
    for _ in 0..2000 {
        let result = store.lease(1, Duration::from_secs(60)).and_then(|leases| {
            let lease = &leases[0];
            store.mark_retrying(
                "retained",
                "temporary",
                clock.now(),
                lease.lease_token.as_deref(),
            )
        });
        if matches!(result, Err(StoreError::Full(_))) {
            blocked = true;
            break;
        }
        result.unwrap();
    }
    assert!(blocked);
    assert!(storage_bytes(store.database_path()) <= store.maximum_storage_bytes() as u64);
    drop(transaction);
    store.maintain().unwrap();
    assert!(storage_bytes(store.database_path()) <= store.maximum_storage_bytes() as u64);
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.retrying + snapshot.uploading, 1);
    assert!(
        store
            .enqueue(&event("recovered", "recovered", "{}", clock.now()))
            .unwrap()
            .enqueued
    );
    assert!(store.verify_ledger().unwrap().intact);
}

fn storage_bytes(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
        + std::fs::metadata(format!("{}-wal", path.display())).map_or(0, |value| value.len())
}

#[test]
fn corrupt_legacy_ledger_refuses_migration_without_rewriting_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-queue.db", directory.path());
    let connection = raw(&path);
    connection
        .execute(
            "UPDATE queue_ledger SET chain_hash='corrupt' WHERE sequence=3",
            [],
        )
        .unwrap();
    let store = SqliteEventStore::new(&path, 10 * ONE_MEBIBYTE, None).unwrap();
    assert!(store.initialize().is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='queue_events_v5'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM queue_events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        4
    );
}

#[test]
fn replay_ignores_local_detection_changes_but_preserves_source_attributes() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    let plain = r#"{"schemaVersion":"1.0.0","eventType":"test","attributes":{"sourceFact":1}}"#;
    let item = event("detection", "fp", plain, clock.now());
    store.enqueue(&item).unwrap();
    for version in ["1", "2"] {
        let enriched = plain.replace(
            r#""sourceFact":1"#,
            &format!(r#""sourceFact":1,"bowerDetections":[{{"ruleVersion":"{version}"}}]"#),
        );
        assert!(
            store
                .enqueue(&event("detection", "fp", &enriched, clock.now()))
                .unwrap()
                .duplicate
        );
    }
    assert!(
        store
            .enqueue(&event(
                "detection",
                "fp",
                &plain.replace("sourceFact\":1", "sourceFact\":2"),
                clock.now()
            ))
            .is_err()
    );
    store
        .enqueue(&event(
            "only-evidence",
            "fp-two",
            r#"{"schemaVersion":"1.0.0","eventType":"test"}"#,
            clock.now(),
        ))
        .unwrap();
    assert!(store.enqueue(&event("only-evidence", "fp-two", r#"{"schemaVersion":"1.0.0","eventType":"test","attributes":{"bowerDetections":[]}}"#, clock.now())).unwrap().duplicate);
    assert_eq!(
        store
            .lease(2, Duration::from_secs(60))
            .unwrap()
            .into_iter()
            .find(|row| row.event_id == "detection")
            .unwrap()
            .payload,
        plain
    );
}
