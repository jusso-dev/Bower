//! Suppression windows and source activity in the SQLite store (C#
//! `SqliteEventStore.Suppression.cs`): admission under the enqueue write lock,
//! atomic close, crash safety and the additive auxiliary schema.

mod common;

use bower_contracts::{
    DurableEventStore, QueuedEvent, SourceActivity, StoreError, SuppressionRequest,
};
use common::{FakeClock, ONE_MEBIBYTE, event, queue_path, store, test_now};

fn rule() -> SuppressionRequest {
    SuppressionRequest {
        policy_id: "BWR-POL-X".into(),
        policy_version: "1.0.0".into(),
        policy_hash: "sha256:p".into(),
        key_hash: "abc".into(),
        key_fields: vec!["actor.username".into()],
        key_values: vec!["zo\u{eb}".into()],
        window_seconds: 60,
        allow_per_window: 1,
        event_category: "authentication".into(),
        event_type: "authentication_failure".into(),
        application: "App".into(),
        environment: "prod".into(),
        tenant_id: None,
    }
}

fn suppressible(id: &str, clock: &FakeClock) -> QueuedEvent {
    QueuedEvent {
        suppression: Some(rule()),
        ..event(
            id,
            &format!("sha256:{id}"),
            &format!("{{\"eventId\":\"{id}\"}}"),
            clock.now(),
        )
    }
}

fn summary(id: &str, clock: &FakeClock) -> QueuedEvent {
    event(
        id,
        &format!("sha256:{id}"),
        &format!("{{\"eventId\":\"{id}\"}}"),
        clock.now(),
    )
}

#[test]
fn auxiliary_tables_keep_schema_version_five() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    // A second start re-runs the idempotent DDL.
    store(directory.path(), 10 * ONE_MEBIBYTE, &clock);

    let connection = rusqlite::Connection::open(queue_path(directory.path())).unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_history;", [], |row| {
            row.get(0)
        })
        .unwrap();
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE name IN ('suppression_windows', 'source_activity', 'ix_suppression_windows_end') ORDER BY name;")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(version, 5);
    assert_eq!(
        tables,
        [
            "ix_suppression_windows_end",
            "source_activity",
            "suppression_windows"
        ]
    );
}

#[test]
fn suppressed_events_are_counted_without_queue_or_ledger_entries() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);

    let admitted = store.enqueue(&suppressible("e1", &clock)).unwrap();
    let suppressed = store.enqueue(&suppressible("e2", &clock)).unwrap();
    // A retried admitted event is a duplicate and never consumes allowance.
    let retried = store.enqueue(&suppressible("e1", &clock)).unwrap();
    clock.advance(chrono::Duration::seconds(5));
    store.enqueue(&suppressible("e3", &clock)).unwrap();

    assert!(admitted.enqueued && !admitted.suppressed);
    assert!(!suppressed.enqueued && !suppressed.duplicate && suppressed.suppressed);
    assert!(retried.duplicate && !retried.suppressed);
    assert_eq!(store.snapshot().unwrap().queued, 1);
    assert_eq!(store.ledger_head().unwrap().sequence, 1);
    assert!(store.verify_ledger().unwrap().intact);

    let connection = rusqlite::Connection::open(queue_path(directory.path())).unwrap();
    let row: (i64, i64, i64, i64, String, String, String, String) = connection
        .query_row(
            "SELECT window_start, window_end, admitted, suppressed, first_suppressed_at, last_suppressed_at, key_fields, key_values FROM suppression_windows;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .unwrap();
    assert_eq!(row.0, 1_785_032_040);
    assert_eq!(row.1, 1_785_032_100);
    assert_eq!((row.2, row.3), (1, 2));
    assert_eq!(row.4, "2026-07-26T02:14:19.0000000+00:00");
    assert_eq!(row.5, "2026-07-26T02:14:24.0000000+00:00");
    assert_eq!(row.6, r#"["actor.username"]"#);
    assert_eq!(row.7, "[\"zo\\u00EB\"]");
}

#[test]
fn close_is_atomic_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    store.enqueue(&suppressible("e1", &clock)).unwrap();
    store.enqueue(&suppressible("e2", &clock)).unwrap();

    // Not yet ended.
    let mut calls = 0;
    assert_eq!(
        store
            .close_expired_suppression_windows(clock.now(), &mut |_| {
                calls += 1;
                Ok(summary("s1", &clock))
            })
            .unwrap(),
        0
    );
    assert_eq!(calls, 0);

    clock.advance(chrono::Duration::minutes(2));
    // A failing summary closes nothing.
    let failed = store.close_expired_suppression_windows(clock.now(), &mut |_| {
        Err(StoreError::Invalid("rejected".into()))
    });
    assert!(failed.is_err());

    // The window survives a restart and closes once.
    drop(store);
    let store = common::store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let mut seen = Vec::new();
    let closed = store
        .close_expired_suppression_windows(clock.now(), &mut |window| {
            seen.push((
                window.admitted,
                window.suppressed,
                window.rule.key_values.clone(),
            ));
            Ok(summary("s1", &clock))
        })
        .unwrap();
    let again = store
        .close_expired_suppression_windows(clock.now(), &mut |_| Ok(summary("s1", &clock)))
        .unwrap();

    assert_eq!(closed, 1);
    assert_eq!(again, 0);
    assert_eq!(seen, [(1, 1, vec!["zo\u{eb}".to_owned()])]);
    assert_eq!(store.snapshot().unwrap().queued, 2);
    assert!(store.verify_ledger().unwrap().intact);
}

#[test]
fn quiet_windows_close_without_summaries() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    store.enqueue(&suppressible("e1", &clock)).unwrap();
    clock.advance(chrono::Duration::minutes(2));
    let mut calls = 0;
    let closed = store
        .close_expired_suppression_windows(clock.now(), &mut |_| {
            calls += 1;
            Ok(summary("s1", &clock))
        })
        .unwrap();
    assert_eq!((closed, calls), (0, 0));
    // The next window starts afresh.
    assert!(store.enqueue(&suppressible("e2", &clock)).unwrap().enqueued);
}

#[test]
fn source_activity_keeps_latest_time_and_largest_count() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let activity = |at: chrono::Duration, count: i64| SourceActivity {
        application: "App".into(),
        environment: "prod".into(),
        last_seen_at: test_now() + at,
        event_count: count,
    };
    store.upsert_source_activity(&[]).unwrap();
    store
        .upsert_source_activity(&[activity(chrono::Duration::minutes(3), 2)])
        .unwrap();
    store
        .upsert_source_activity(&[activity(chrono::Duration::zero(), 5)])
        .unwrap();

    let stored = store.get_source_activity().unwrap();
    assert_eq!(stored, [activity(chrono::Duration::minutes(3), 5)]);
}
