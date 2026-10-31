mod common;

use bower_contracts::{
    DurableEventStore, FailureSettlement, QueuedEvent, StoreError, SuppressionRequest,
};
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

/// SQLite WAL format: every frame is this header followed by one page.
const WAL_FRAME_HEADER_BYTES: i64 = 24;

#[test]
fn pinned_wal_reader_backpressures_suppression_counters_within_physical_budget() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    let suppressible = |id: &str| QueuedEvent {
        suppression: Some(SuppressionRequest {
            policy_id: "BWR-POL-X".into(),
            policy_version: "1.0.0".into(),
            policy_hash: "sha256:p".into(),
            key_hash: "abc".into(),
            key_fields: vec!["source.ipAddress".into()],
            key_values: vec!["192.0.2.1".into()],
            window_seconds: 60,
            allow_per_window: 1,
            event_category: "authentication".into(),
            event_type: "authentication_failure".into(),
            application: "App".into(),
            environment: "prod".into(),
            tenant_id: None,
        }),
        ..event(
            id,
            &format!("sha256:{id}"),
            &format!("{{\"eventId\":\"{id}\"}}"),
            clock.now(),
        )
    };
    let suppressed_count = || -> i64 {
        raw(store.database_path())
            .query_row("SELECT suppressed FROM suppression_windows", [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    assert!(store.enqueue(&suppressible("admitted")).unwrap().enqueued);
    let mut connection = raw(store.database_path());
    let transaction = connection.transaction().unwrap();
    transaction
        .query_row("SELECT COUNT(*) FROM queue_events_v5", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();

    // Allowance is spent: every unique event only updates the window counters, and
    // each commit grows the WAL the pinned reader keeps from being reset.
    let mut counted = 0;
    let mut blocked = false;
    for index in 0..6000 {
        match store.enqueue(&suppressible(&format!("unique-{index}"))) {
            Err(StoreError::Full(_)) => {
                blocked = true;
                break;
            }
            result => assert!(result.unwrap().suppressed),
        }
        counted += 1;
    }
    assert!(blocked);
    assert!(counted > 0);
    // Refusal starts at the ceiling minus the reserve; the last admitted commit can
    // add one WAL frame for the counter page it changed.
    let page_size: i64 = raw(store.database_path())
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap();
    let admission_bound = store.maximum_storage_bytes() - store.storage_reserve_bytes()
        + WAL_FRAME_HEADER_BYTES
        + page_size;
    let storage = storage_bytes(store.database_path());
    assert!(storage <= admission_bound as u64);
    for index in 0..3 {
        assert!(matches!(
            store.enqueue(&suppressible(&format!("refused-{index}"))),
            Err(StoreError::Full(_))
        ));
    }

    // Refusals leave the counters and the files untouched; exact replay still wins.
    assert_eq!(storage_bytes(store.database_path()), storage);
    assert_eq!(suppressed_count(), counted);
    assert!(store.enqueue(&suppressible("admitted")).unwrap().duplicate);

    drop(transaction);
    store.maintain().unwrap();
    assert!(storage_bytes(store.database_path()) <= store.maximum_storage_bytes() as u64);
    drop(store);
    let restarted = common::store(directory.path(), ONE_MEBIBYTE, &clock);
    assert!(
        restarted
            .enqueue(&suppressible("recovered"))
            .unwrap()
            .suppressed
    );
    clock.advance(Span::minutes(2));
    let mut closed = None;
    let summaries = restarted
        .close_expired_suppression_windows(clock.now(), &mut |window| {
            closed = Some((window.admitted, window.suppressed));
            Ok(event(
                "summary",
                "sha256:summary",
                "{\"eventId\":\"summary\"}",
                clock.now(),
            ))
        })
        .unwrap();
    assert_eq!(summaries, 1);
    assert_eq!(closed, Some((1, counted + 1)));
    assert_eq!(restarted.snapshot().unwrap().queued, 2);
    assert!(restarted.verify_ledger().unwrap().intact);
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

/// Mirrors C# `QueueBackupTests.NewerSchema_FailsClosedWithoutChangingTheDatabase`.
#[test]
fn newer_schema_fails_closed_without_changing_the_database() {
    use sha2::{Digest, Sha256};
    for renamed_queue_table in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let clock = FakeClock::new(test_now());
        {
            let store = store(directory.path(), ONE_MEBIBYTE, &clock);
            store
                .enqueue(&event("one", "fp", "{}", clock.now()))
                .unwrap();
        }
        let path = queue_path(directory.path());
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            let rename = if renamed_queue_table {
                "DROP VIEW queue_events; ALTER TABLE queue_events_v5 RENAME TO queue_events_v6;"
            } else {
                ""
            };
            connection
                .execute_batch(&format!(
                    "{rename} INSERT INTO schema_history(version, applied_at, hash) VALUES (6, '2027-01-01T00:00:00Z', 'future'); PRAGMA wal_checkpoint(TRUNCATE);"
                ))
                .unwrap();
        }
        let digest = || Sha256::digest(std::fs::read(&path).unwrap());
        let objects = || -> i64 {
            rusqlite::Connection::open(&path)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM sqlite_master;", [], |row| row.get(0))
                .unwrap()
        };
        let (before, count) = (digest(), objects());

        let store = SqliteEventStore::new(&path, ONE_MEBIBYTE, Some(clock.clone())).unwrap();
        let Err(StoreError::Invalid(message)) = store.initialize() else {
            panic!("a newer schema must be refused");
        };
        drop(store);
        assert!(
            message.contains("newer than this Bower build supports (5)"),
            "{message}"
        );
        assert!(
            bower_persistence::SqliteSourceCursorStore::new(&path)
                .unwrap()
                .initialize()
                .is_err()
        );
        assert_eq!(count, objects());
        assert_eq!(before, digest());
        assert_eq!(bower_persistence::SCHEMA_VERSION, 5);
    }
}
