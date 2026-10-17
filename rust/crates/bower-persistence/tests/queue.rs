//! Ports of `SqliteEventStoreTests`, `QueueRetentionTests` and the dead-letter
//! parts of `PrivacyProfileAndLedgerTests`, plus crash/recovery and limit tests.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::Timestamp;
use bower_contracts::{DurableEventStore, FailureSettlement, QueueState, StoreError};
use bower_persistence::SqliteEventStore;
use chrono::Duration as Span;
use common::*;

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn settlement(event_id: &str, code: &str, retry_after: Option<Timestamp>) -> FailureSettlement {
    FailureSettlement {
        event_id: event_id.into(),
        failure_code: code.into(),
        retry_after,
    }
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn store_is_send_and_sync() {
    assert_send_sync::<SqliteEventStore>();
    assert_send_sync::<bower_persistence::SqliteSourceCursorStore>();
}

// ---- SqliteEventStoreTests ----

#[test]
fn enqueue_deduplicates_fingerprint_and_keeps_original() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);

    let first = store
        .enqueue(&event(
            "event-1",
            "sha256:same",
            r#"{"eventId":"event-1"}"#,
            clock.now(),
        ))
        .unwrap();
    let duplicate = store
        .enqueue(&event(
            "event-2",
            "sha256:same",
            r#"{"eventId":"event-2"}"#,
            clock.now(),
        ))
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert!(first.enqueued);
    assert!(duplicate.duplicate);
    assert!(!duplicate.enqueued);
    assert_eq!(duplicate.event_id, "event-2");
    assert_eq!(snapshot.queued, 1);
    let leased = store.lease(10, Duration::from_secs(60)).unwrap();
    assert_eq!(leased[0].payload, r#"{"eventId":"event-1"}"#);
}

#[test]
fn enqueue_deduplicates_event_id() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    assert!(
        store
            .enqueue(&event("same", "f1", "{}", clock.now()))
            .unwrap()
            .enqueued
    );
    let again = store
        .enqueue(&event("same", "f2", r#"{"x":1}"#, clock.now()))
        .unwrap();
    assert!(again.duplicate);
    assert_eq!(store.snapshot().unwrap().queued, 1);
    assert_eq!(store.ledger_head().unwrap().sequence, 1);
}

#[test]
fn lease_survives_restart_and_expires_for_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let first_store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    first_store
        .enqueue(&event(
            "event-1",
            "sha256:one",
            r#"{"eventId":"event-1"}"#,
            clock.now(),
        ))
        .unwrap();

    let first_lease = first_store.lease(10, Duration::from_secs(10)).unwrap();
    // Crash: the process dies while the event is leased.
    drop(first_store);
    clock.advance(Span::seconds(11));

    let restarted = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let recovered = restarted.lease(10, Duration::from_secs(10)).unwrap();

    assert_eq!(first_lease.len(), 1);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].event_id, "event-1");
    assert_eq!(recovered[0].delivery_attempts, 2);
    assert_eq!(recovered[0].state, QueueState::Uploading);
}

#[test]
fn active_lease_is_not_released_before_expiry_even_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let first = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&first, &clock, "e1");
    assert_eq!(first.lease(10, Duration::from_secs(30)).unwrap().len(), 1);
    drop(first);

    let restarted = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    clock.advance(Span::seconds(29));
    assert!(
        restarted
            .lease(10, Duration::from_secs(30))
            .unwrap()
            .is_empty()
    );
    clock.advance(Span::seconds(1));
    // lease_until <= now: boundary is inclusive.
    assert_eq!(
        restarted.lease(10, Duration::from_secs(30)).unwrap().len(),
        1
    );
    let snapshot = restarted.snapshot().unwrap();
    assert_eq!(snapshot.uploading, 1);
    assert!(restarted.verify_ledger().unwrap().intact);
}

#[test]
fn uncommitted_write_is_rolled_back_after_crash() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "committed");
    {
        // A writer that dies mid-transaction (no commit) must leave no trace.
        let mut connection = raw(&queue_path(directory.path()));
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO queue_events (event_id, fingerprint, payload, payload_bytes, received_at, state) VALUES ('ghost','ghost','{}',2,'2026-01-01T00:00:00.0000000+00:00',0);",
                [],
            )
            .unwrap();
        drop(transaction);
    }
    drop(store);
    let reopened = common::store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    assert_eq!(reopened.snapshot().unwrap().queued, 1);
    let verification = reopened.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(verification.entries, 1);
}

#[test]
fn mark_delivered_requires_lease_and_retains_acknowledged_record() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    store
        .enqueue(&event(
            "event-1",
            "sha256:one",
            r#"{"eventId":"event-1"}"#,
            clock.now(),
        ))
        .unwrap();

    let error = store.mark_delivered("event-1", "not-leased").unwrap_err();
    assert!(
        matches!(&error, StoreError::Invalid(message) if message == "Event 'event-1' is not in required state 'uploading' for transition to 'delivered'."),
        "{error}"
    );
    store.lease(1, Duration::from_secs(60)).unwrap();
    store.mark_delivered("event-1", "ama-spool:file-1").unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(snapshot.queued, 0);
    assert_eq!(snapshot.delivered, 1);
    // Delivered events are never re-leased.
    clock.advance(Span::days(1));
    assert!(store.lease(10, Duration::from_secs(60)).unwrap().is_empty());
}

#[test]
fn transitions_require_uploading_state() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "e1");
    let retry = store.mark_retrying("e1", "busy", clock.now()).unwrap_err();
    assert_eq!(
        retry.to_string(),
        "invalid queue operation: Event 'e1' is not in required state 'uploading' for transition to 'retrying'."
    );
    let dead = store.mark_dead_lettered("missing", "bad").unwrap_err();
    assert_eq!(
        dead.to_string(),
        "invalid queue operation: Event 'missing' is not in required state 'uploading' for transition to 'dead-lettered'."
    );
    store.lease(1, Duration::from_secs(60)).unwrap();
    store.mark_delivered("e1", "ack").unwrap();
    // Already delivered: a second acknowledgement is a transition error, not a silent success.
    assert!(matches!(
        store.mark_delivered("e1", "ack"),
        Err(StoreError::Invalid(_))
    ));
}

#[test]
fn retrying_waits_for_next_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "e1");
    store.lease(1, Duration::from_secs(60)).unwrap();
    // Offset timestamps are normalised to UTC text so comparisons stay lexical.
    let retry_after = bower_contracts::time::parse("2026-07-26T12:19:19+10:00").unwrap();
    store.mark_retrying("e1", "busy", retry_after).unwrap();
    assert_eq!(store.snapshot().unwrap().retrying, 1);
    clock.advance(Span::minutes(4));
    assert!(store.lease(1, Duration::from_secs(60)).unwrap().is_empty());
    clock.advance(Span::minutes(1));
    let leased = store.lease(1, Duration::from_secs(60)).unwrap();
    assert_eq!(leased[0].delivery_attempts, 2);
    let stored: String = raw(&queue_path(directory.path()))
        .query_row(
            "SELECT last_failure_code FROM queue_events WHERE event_id='e1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, "busy");
}

#[test]
fn initialize_restricts_database_permissions_on_unix() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let clock = FakeClock::new(test_now());
        let _store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
        let mode = std::fs::metadata(queue_path(directory.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn validates_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    assert!(matches!(
        SqliteEventStore::new(queue_path(directory.path()), ONE_MEBIBYTE - 1, None),
        Err(StoreError::Invalid(message)) if message == "Queue maximum must be at least 1 MiB."
    ));
    assert!(matches!(
        SqliteEventStore::new("  ", ONE_MEBIBYTE, None),
        Err(StoreError::Invalid(_))
    ));
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    assert!(matches!(
        store.lease(0, Duration::from_secs(1)),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.lease(10_001, Duration::from_secs(1)),
        Err(StoreError::Invalid(_))
    ));
    assert!(store.lease(10_000, Duration::from_secs(1)).is_ok());
    assert!(matches!(
        store.lease(1, Duration::ZERO),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.purge_delivered(clock.now(), 0),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.purge_delivered(clock.now(), 100_001),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.list_dead_lettered(0),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.replay_dead_lettered(Some("x"), None, 0),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.mark_delivered(" ", "ack"),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.mark_delivered("e", "\t"),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.mark_retrying("e", "", clock.now()),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.mark_dead_lettered("e", " "),
        Err(StoreError::Invalid(_))
    ));
}

/// `Enqueue_RejectsInvalidInputInsteadOfReportingDuplicate`. `INSERT OR IGNORE`
/// used to swallow CHECK violations and report them as duplicates (C# and Rust).
#[test]
fn enqueue_rejects_invalid_input_instead_of_reporting_duplicate() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let long_id = "x".repeat(129);
    let astral_129 = "\u{1F600}".repeat(129);
    for (id, fingerprint, payload) in [
        ("", "sha256:empty-id", "{}"),
        (" \t", "sha256:blank-id", "{}"),
        (long_id.as_str(), "sha256:long-id", "{}"),
        ("nul\0id", "sha256:nul-id", "{}"),
        ("\0", "sha256:nul-only", "{}"),
        ("blank-fingerprint", " ", "{}"),
        ("empty-fingerprint", "", "{}"),
        ("empty-payload", "sha256:empty-payload", ""),
        (astral_129.as_str(), "sha256:astral-129", "{}"),
    ] {
        let outcome = store.enqueue(&event(id, fingerprint, payload, clock.now()));
        assert!(
            matches!(outcome, Err(StoreError::Invalid(_))),
            "{fingerprint}: {outcome:?}"
        );
    }

    // The limit mirrors SQLite length(): 128 characters, not 128 UTF-16 units.
    assert!(
        store
            .enqueue(&event(&"x".repeat(128), "sha256:x128", "{}", clock.now()))
            .unwrap()
            .enqueued
    );
    assert!(
        store
            .enqueue(&event(
                &"\u{1F600}".repeat(128),
                "sha256:astral",
                "{}",
                clock.now()
            ))
            .unwrap()
            .enqueued
    );
    let verification = store.verify_ledger().unwrap();
    assert_eq!(store.snapshot().unwrap().queued, 2);
    assert!(verification.intact);
    assert_eq!(verification.entries, 2);
}

/// `Enqueue_ConcurrentDuplicatesInsertExactlyOnce`.
#[test]
fn enqueue_concurrent_duplicates_insert_exactly_once() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = Arc::new(store(directory.path(), 10 * ONE_MEBIBYTE, &clock));
    // Half the writers reuse the event id, half reuse the fingerprint under a new id.
    let handles: Vec<_> = (0..24)
        .map(|index| {
            let store = store.clone();
            let now = clock.now();
            std::thread::spawn(move || {
                let id = if index % 2 == 0 {
                    "same".to_owned()
                } else {
                    format!("other-{index}")
                };
                store
                    .enqueue(&event(&id, "sha256:same", r#"{"eventId":"same"}"#, now))
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let verification = store.verify_ledger().unwrap();

    assert_eq!(results.iter().filter(|result| result.enqueued).count(), 1);
    assert_eq!(results.iter().filter(|result| result.duplicate).count(), 23);
    assert!(
        results
            .iter()
            .all(|result| result.enqueued != result.duplicate)
    );
    assert!(verification.intact);
    assert_eq!(verification.entries, 1);
}

/// `MarkDeliveredBatch_SettlesLeasedEventsAndReturnsTheRest`.
#[test]
fn mark_delivered_batch_settles_leased_events_and_returns_the_rest() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["leased-1", "leased-2", "queued"] {
        enqueue(&store, &clock, id);
    }
    let leased = store.lease(3, Duration::from_secs(300)).unwrap();
    store
        .mark_retrying("queued", "test", clock.now() + Span::hours(1))
        .unwrap();

    let not_leased = store
        .mark_delivered_batch(
            &ids(&["leased-1", "leased-2", "queued", "missing"]),
            "ack-batch",
        )
        .unwrap();
    let empty = store.mark_delivered_batch(&[], "ack-batch").unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(leased.len(), 3);
    assert_eq!(not_leased, ["queued", "missing"]);
    assert!(empty.is_empty());
    assert_eq!(
        (snapshot.delivered, snapshot.retrying, snapshot.uploading),
        (2, 1, 0)
    );
    let acknowledgement: String = raw(&queue_path(directory.path()))
        .query_row(
            "SELECT acknowledgement FROM queue_events WHERE event_id = 'leased-2'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(acknowledgement, "ack-batch");
    assert!(matches!(
        store.mark_delivered_batch(&ids(&["ok", " "]), "ack"),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.mark_delivered_batch(&ids(&["ok"]), " "),
        Err(StoreError::Invalid(_))
    ));
    assert!(store.verify_ledger().unwrap().intact);
}

/// `MarkDeliveredBatch_IsDurableAcrossRestartAndIdempotentOnReplay`.
#[test]
fn mark_delivered_batch_is_durable_across_restart_and_idempotent_on_replay() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let first = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&first, &clock, "event-1");
    enqueue(&first, &clock, "event-2");
    first.lease(2, Duration::from_secs(300)).unwrap();
    assert!(
        first
            .mark_delivered_batch(&ids(&["event-1", "event-2"]), "ack-1")
            .unwrap()
            .is_empty()
    );
    drop(first);

    let restarted = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let replay = restarted
        .mark_delivered_batch(&ids(&["event-1", "event-2"]), "ack-2")
        .unwrap();
    clock.advance(Span::minutes(10));
    let releasable = restarted.lease(10, Duration::from_secs(300)).unwrap();
    let snapshot = restarted.snapshot().unwrap();

    assert_eq!(replay, ["event-1", "event-2"]);
    assert!(releasable.is_empty());
    assert_eq!((snapshot.delivered, snapshot.uploading), (2, 0));
    assert!(restarted.verify_ledger().unwrap().intact);
}

/// `MarkFailedBatch_SettlesLeasedEventsAndReturnsTheRest`.
#[test]
fn mark_failed_batch_settles_leased_events_and_returns_the_rest() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["retry", "dead", "delivered"] {
        enqueue(&store, &clock, id);
    }
    store.lease(3, Duration::from_secs(300)).unwrap();
    store.mark_delivered("delivered", "ack").unwrap();
    let retry_at = bower_contracts::time::parse("2026-08-30T09:00:00+05:30").unwrap();

    let not_leased = store
        .mark_failed_batch(&[
            settlement("retry", "busy", Some(retry_at)),
            settlement("dead", "azure-http-400", None),
            settlement("delivered", "late", None),
            settlement("missing", "late", Some(retry_at)),
            settlement("retry", "twice", None),
        ])
        .unwrap();
    let empty = store.mark_failed_batch(&[]).unwrap();
    let snapshot = store.snapshot().unwrap();
    let dead = store.list_dead_lettered(10).unwrap();

    assert_eq!(not_leased, ["delivered", "missing", "retry"]);
    assert!(empty.is_empty());
    assert_eq!(
        (
            snapshot.retrying,
            snapshot.dead_lettered,
            snapshot.delivered,
            snapshot.uploading
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].failure_code.as_deref(), Some("azure-http-400"));
    let (next_attempt_at, code, lease_until): (String, String, Option<String>) =
        raw(&queue_path(directory.path()))
            .query_row(
                "SELECT next_attempt_at, last_failure_code, lease_until FROM queue_events WHERE event_id = 'retry'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(next_attempt_at, "2026-08-30T03:30:00.0000000+00:00");
    assert_eq!(code, "busy");
    assert_eq!(lease_until, None);

    assert!(matches!(
        store.mark_failed_batch(&[settlement(" ", "code", None)]),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.mark_failed_batch(&[settlement("retry", "", Some(retry_at))]),
        Err(StoreError::Invalid(_))
    ));
    assert!(store.verify_ledger().unwrap().intact);
}

/// `SettlementBatches_RollBackCompletelyOnErrorAndRecoverAfterRestart`.
#[test]
fn settlement_batches_roll_back_completely_on_error_and_recover_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = queue_path(directory.path());
    let clock = FakeClock::new(test_now());
    let first = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b", "poison"] {
        enqueue(&first, &clock, id);
    }
    first.lease(3, Duration::from_secs(300)).unwrap();

    // Adversarial storage failure on the last row of each batch.
    raw(&path)
        .execute_batch(
            "CREATE TRIGGER fail_poison BEFORE UPDATE OF state ON queue_events
WHEN NEW.event_id = 'poison'
BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let retry_at = clock.now() + Span::minutes(1);
    assert!(matches!(
        first.mark_failed_batch(&[
            settlement("a", "busy", Some(retry_at)),
            settlement("b", "bad", None),
            settlement("poison", "bad", None),
        ]),
        Err(StoreError::Storage(_))
    ));
    assert!(matches!(
        first.mark_delivered_batch(&ids(&["a", "b", "poison"]), "ack"),
        Err(StoreError::Storage(_))
    ));
    let after_failure = first.snapshot().unwrap();
    assert_eq!(
        (
            after_failure.uploading,
            after_failure.retrying,
            after_failure.dead_lettered,
            after_failure.delivered
        ),
        (3, 0, 0, 0)
    );
    drop(first);

    // Restart: nothing was half-settled, every lease is reclaimed once it expires
    // (at-least-once) and the reclaimed events settle normally.
    raw(&path)
        .execute_batch("DROP TRIGGER fail_poison;")
        .unwrap();
    let restarted = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    assert!(
        restarted
            .lease(10, Duration::from_secs(300))
            .unwrap()
            .is_empty()
    );
    clock.advance(Span::minutes(6));
    let mut reclaimed = restarted.lease(10, Duration::from_secs(300)).unwrap();
    reclaimed.sort_by(|left, right| left.event_id.cmp(&right.event_id));
    let summary: Vec<(&str, i32)> = reclaimed
        .iter()
        .map(|item| (item.event_id.as_str(), item.delivery_attempts))
        .collect();
    assert_eq!(summary, [("a", 2), ("b", 2), ("poison", 2)]);
    assert!(
        restarted
            .mark_failed_batch(&[
                settlement("a", "busy", Some(clock.now() + Span::minutes(1))),
                settlement("b", "bad", None),
            ])
            .unwrap()
            .is_empty()
    );
    assert!(
        restarted
            .mark_delivered_batch(&ids(&["poison"]), "ack")
            .unwrap()
            .is_empty()
    );
    let settled = restarted.snapshot().unwrap();
    assert_eq!(
        (
            settled.uploading,
            settled.retrying,
            settled.dead_lettered,
            settled.delivered
        ),
        (0, 1, 1, 1)
    );
    assert!(restarted.verify_ledger().unwrap().intact);
}

/// The trait's default (non-transactional) batch methods keep the same contract
/// for stores that do not override them.
#[test]
fn default_batch_methods_follow_the_same_contract() {
    struct Plain(SqliteEventStore);
    impl DurableEventStore for Plain {
        fn initialize(&self) -> bower_contracts::StoreResult<()> {
            self.0.initialize()
        }
        fn enqueue(
            &self,
            candidate: &bower_contracts::QueuedEvent,
        ) -> bower_contracts::StoreResult<bower_contracts::EnqueueResult> {
            self.0.enqueue(candidate)
        }
        fn lease(
            &self,
            maximum_count: usize,
            lease_duration: Duration,
        ) -> bower_contracts::StoreResult<Vec<bower_contracts::QueuedEvent>> {
            self.0.lease(maximum_count, lease_duration)
        }
        fn mark_delivered(&self, event_id: &str, ack: &str) -> bower_contracts::StoreResult<()> {
            self.0.mark_delivered(event_id, ack)
        }
        fn mark_retrying(
            &self,
            event_id: &str,
            code: &str,
            retry_after: bower_contracts::time::Timestamp,
        ) -> bower_contracts::StoreResult<()> {
            self.0.mark_retrying(event_id, code, retry_after)
        }
        fn mark_dead_lettered(
            &self,
            event_id: &str,
            code: &str,
        ) -> bower_contracts::StoreResult<()> {
            self.0.mark_dead_lettered(event_id, code)
        }
        fn snapshot(&self) -> bower_contracts::StoreResult<bower_contracts::QueueSnapshot> {
            self.0.snapshot()
        }
        fn purge_delivered(
            &self,
            before: bower_contracts::time::Timestamp,
            maximum_count: usize,
        ) -> bower_contracts::StoreResult<usize> {
            self.0.purge_delivered(before, maximum_count)
        }
        fn maintain(&self) -> bower_contracts::StoreResult<()> {
            self.0.maintain()
        }
        fn list_dead_lettered(
            &self,
            maximum_count: usize,
        ) -> bower_contracts::StoreResult<Vec<bower_contracts::DeadLetterRecord>> {
            self.0.list_dead_lettered(maximum_count)
        }
        fn replay_dead_lettered(
            &self,
            prefix: Option<&str>,
            event_ids: Option<&[String]>,
            maximum_count: usize,
        ) -> bower_contracts::StoreResult<usize> {
            self.0
                .replay_dead_lettered(prefix, event_ids, maximum_count)
        }
        fn ledger_head(&self) -> bower_contracts::StoreResult<bower_contracts::LedgerHead> {
            self.0.ledger_head()
        }
        fn verify_ledger(
            &self,
        ) -> bower_contracts::StoreResult<bower_contracts::LedgerVerification> {
            self.0.verify_ledger()
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let plain = Plain(store(directory.path(), 10 * ONE_MEBIBYTE, &clock));
    for id in ["ok", "retry", "dead"] {
        enqueue(&plain.0, &clock, id);
    }
    plain.lease(3, Duration::from_secs(300)).unwrap();

    assert_eq!(
        plain
            .mark_delivered_batch(&ids(&["ok", "missing"]), "ack")
            .unwrap(),
        ["missing"]
    );
    assert_eq!(
        plain
            .mark_failed_batch(&[
                settlement("retry", "busy", Some(clock.now())),
                settlement("dead", "bad", None),
                settlement("ok", "late", None),
            ])
            .unwrap(),
        ["ok"]
    );
    assert!(matches!(
        plain.mark_delivered_batch(&ids(&["ok", ""]), "ack"),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        plain.mark_failed_batch(&[settlement("retry", " ", None)]),
        Err(StoreError::Invalid(_))
    ));
    let snapshot = plain.snapshot().unwrap();
    assert_eq!(
        (
            snapshot.delivered,
            snapshot.retrying,
            snapshot.dead_lettered
        ),
        (1, 1, 1)
    );
}

/// `VerifyLedger_ReadsOneSnapshotWhileEnqueuesCommit`.
#[test]
fn verify_ledger_reads_one_snapshot_while_enqueues_commit() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = Arc::new(store(directory.path(), 10 * ONE_MEBIBYTE, &clock));
    enqueue(&store, &clock, "seed");
    let writer = {
        let store = store.clone();
        let now = clock.now();
        std::thread::spawn(move || {
            for index in 0..400 {
                store
                    .enqueue(&event(
                        &format!("e{index}"),
                        &format!("sha256:e{index}"),
                        &format!("{{\"n\":{index}}}"),
                        now,
                    ))
                    .unwrap();
            }
        })
    };
    let mut issues = Vec::new();
    while !writer.is_finished() {
        issues.extend(store.verify_ledger().unwrap().issues);
    }
    writer.join().unwrap();
    let last = store.verify_ledger().unwrap();

    assert!(issues.is_empty(), "{issues:?}");
    assert!(last.intact);
    assert_eq!(last.entries, 401);
}

#[test]
fn received_at_is_stored_as_utc_round_trip_text() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let received = bower_contracts::time::parse("2026-07-26T12:14:19.1234567+10:00").unwrap();
    store.enqueue(&event("e1", "f1", "{}", received)).unwrap();
    let text: String = raw(&queue_path(directory.path()))
        .query_row("SELECT received_at FROM queue_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(text, "2026-07-26T02:14:19.1234567+00:00");
    let leased = store.lease(1, Duration::from_secs(60)).unwrap();
    assert_eq!(leased[0].received_at, received);
}

// ---- QueueRetentionTests ----

#[test]
fn purge_removes_only_acknowledged_events_past_retention() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "delivered-old");
    enqueue(&store, &clock, "dead-lettered");
    enqueue(&store, &clock, "retrying");
    store.lease(10, Duration::from_secs(60)).unwrap();
    store.mark_delivered("delivered-old", "ack-1").unwrap();
    store.mark_dead_lettered("dead-lettered", "bad").unwrap();
    store
        .mark_retrying("retrying", "busy", clock.now() + Span::days(30))
        .unwrap();
    clock.advance(Span::days(8));
    enqueue(&store, &clock, "queued");
    store.lease(1, Duration::from_secs(60)).unwrap();
    store.mark_delivered("queued", "ack-2").unwrap();

    let purged = store
        .purge_delivered(clock.now() - Span::days(7), 100)
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(purged, 1);
    assert_eq!(snapshot.delivered, 1);
    assert_eq!(snapshot.dead_lettered, 1);
    assert_eq!(snapshot.retrying, 1);
}

#[test]
fn purge_never_removes_undelivered_events() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "queued");
    enqueue(&store, &clock, "uploading");
    store.lease(1, Duration::from_secs(60)).unwrap();
    clock.advance(Span::days(365));

    let purged = store.purge_delivered(clock.now(), 100).unwrap();
    let snapshot = store.snapshot().unwrap();

    assert_eq!(purged, 0);
    assert_eq!(snapshot.queued, 1);
    assert_eq!(snapshot.uploading, 1);
}

#[test]
fn purge_honours_maximum_count_oldest_first() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b", "c"] {
        enqueue(&store, &clock, id);
        store.lease(1, Duration::from_secs(60)).unwrap();
        store.mark_delivered(id, "ack").unwrap();
        clock.advance(Span::seconds(1));
    }
    clock.advance(Span::days(10));
    assert_eq!(store.purge_delivered(clock.now(), 2).unwrap(), 2);
    let remaining: String = raw(&queue_path(directory.path()))
        .query_row("SELECT event_id FROM queue_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(remaining, "c");
    assert!(store.verify_ledger().unwrap().intact);
}

#[test]
fn capacity_ignores_delivered_history() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    let large = "x".repeat(600 * 1024);
    store
        .enqueue(&event(
            "delivered",
            "sha256:delivered",
            &format!("{{\"v\":\"{large}\"}}"),
            clock.now(),
        ))
        .unwrap();
    store.lease(1, Duration::from_secs(60)).unwrap();
    store.mark_delivered("delivered", "ack").unwrap();

    let second = store
        .enqueue(&event(
            "next",
            "sha256:next",
            &format!("{{\"v\":\"{large}\"}}"),
            clock.now(),
        ))
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert!(second.enqueued);
    assert!(snapshot.total_bytes > ONE_MEBIBYTE);
    assert!(snapshot.undelivered_bytes < ONE_MEBIBYTE);
}

#[test]
fn capacity_rejects_when_undelivered_bytes_would_exceed_limit() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), ONE_MEBIBYTE, &clock);
    let large = "x".repeat(600 * 1024);
    let payload = format!("{{\"v\":\"{large}\"}}");
    store
        .enqueue(&event("first", "sha256:first", &payload, clock.now()))
        .unwrap();

    let error = store
        .enqueue(&event("second", "sha256:second", &payload, clock.now()))
        .unwrap_err();
    let bytes = payload.len();
    assert!(
        matches!(&error, StoreError::Full(message) if *message == format!("Queue capacity exceeded. Maximum=1048576, Current={bytes}, Attempted={bytes}.")),
        "{error}"
    );
    // Rejected enqueue leaves no row and no ledger entry.
    assert_eq!(store.ledger_head().unwrap().sequence, 1);
}

/// `Capacity_FullQueueStillReportsDuplicates`: idempotency wins over backpressure.
/// The capacity check used to run first, so a re-sent event got `Full` (C# and Rust).
#[test]
fn capacity_full_queue_still_reports_duplicates() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let first = store(directory.path(), ONE_MEBIBYTE, &clock);
    let payload = format!("{{\"v\":\"{}\"}}", "x".repeat(600 * 1024));
    first
        .enqueue(&event("first", "sha256:first", &payload, clock.now()))
        .unwrap();

    let same_id = first
        .enqueue(&event("first", "sha256:first", &payload, clock.now()))
        .unwrap();
    let same_fingerprint = first
        .enqueue(&event("first-again", "sha256:first", &payload, clock.now()))
        .unwrap();
    assert!(matches!(
        first.enqueue(&event("second", "sha256:second", &payload, clock.now())),
        Err(StoreError::Full(_))
    ));
    drop(first);

    // Also after a restart, and for a duplicate that has since been delivered.
    let restarted = store(directory.path(), ONE_MEBIBYTE, &clock);
    restarted.lease(1, Duration::from_secs(60)).unwrap();
    restarted.mark_delivered("first", "ack").unwrap();
    restarted
        .enqueue(&event("filler", "sha256:filler", &payload, clock.now()))
        .unwrap();
    let delivered = restarted
        .enqueue(&event("first", "sha256:first", &payload, clock.now()))
        .unwrap();
    let verification = restarted.verify_ledger().unwrap();

    assert!(same_id.duplicate && !same_id.enqueued);
    assert!(same_fingerprint.duplicate);
    assert_eq!(same_fingerprint.event_id, "first-again");
    assert!(delivered.duplicate);
    assert!(verification.intact);
    assert_eq!(verification.entries, 2);
}

#[test]
fn capacity_counts_utf8_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    store
        .enqueue(&event("e", "f", "\u{1F600}é", clock.now()))
        .unwrap();
    assert_eq!(store.snapshot().unwrap().total_bytes, 6);
}

#[test]
fn capacity_holds_under_concurrent_enqueue() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = Arc::new(store(directory.path(), ONE_MEBIBYTE, &clock));
    let chunk = "x".repeat(100 * 1024);

    let handles: Vec<_> = (0..24)
        .map(|index| {
            let store = store.clone();
            let payload = format!("{{\"v\":\"{chunk}\"}}");
            let now = clock.now();
            std::thread::spawn(move || {
                match store.enqueue(&event(
                    &format!("event-{index}"),
                    &format!("sha256:{index}"),
                    &payload,
                    now,
                )) {
                    Ok(_) => true,
                    Err(StoreError::Full(_)) => false,
                    Err(other) => panic!("unexpected error: {other}"),
                }
            })
        })
        .collect();
    let results: Vec<bool> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let snapshot = store.snapshot().unwrap();

    assert!(snapshot.undelivered_bytes <= ONE_MEBIBYTE);
    assert!(results.iter().any(|accepted| !accepted));
    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(
        verification.entries,
        results.iter().filter(|accepted| **accepted).count() as i64
    );
}

#[test]
fn concurrent_lease_never_hands_out_an_event_twice() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = Arc::new(store(directory.path(), 10 * ONE_MEBIBYTE, &clock));
    for index in 0..200 {
        enqueue(&store, &clock, &format!("e{index:03}"));
    }
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || {
                let mut ids = Vec::new();
                loop {
                    let batch = store.lease(7, Duration::from_secs(60)).unwrap();
                    if batch.is_empty() {
                        break ids;
                    }
                    ids.extend(batch.into_iter().map(|item| item.event_id));
                }
            })
        })
        .collect();
    let mut all: Vec<String> = handles
        .into_iter()
        .flat_map(|handle| handle.join().unwrap())
        .collect();
    all.sort();
    let total = all.len();
    all.dedup();
    assert_eq!(total, 200);
    assert_eq!(all.len(), 200);
}

#[test]
fn maintain_preserves_event_state() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue(&store, &clock, "queued");

    store.maintain().unwrap();
    let restarted = common::store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let snapshot = restarted.snapshot().unwrap();

    assert_eq!(snapshot.queued, 1);
}

#[test]
fn snapshot_reports_oldest_undelivered_and_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    assert_eq!(
        store.snapshot().unwrap(),
        bower_contracts::QueueSnapshot::default()
    );
    enqueue(&store, &clock, "a");
    clock.advance(Span::seconds(5));
    enqueue(&store, &clock, "b");
    store.lease(1, Duration::from_secs(60)).unwrap();
    store.mark_delivered("a", "ack").unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.oldest_undelivered, Some(clock.now()));
    assert_eq!(snapshot.delivered, 1);
    assert_eq!(snapshot.queued, 1);
    assert_eq!(snapshot.total_bytes, 2 * r#"{"eventId":"a"}"#.len() as i64);
    assert_eq!(
        snapshot.undelivered_bytes,
        r#"{"eventId":"b"}"#.len() as i64
    );
}

// ---- Dead letters (PrivacyProfileAndLedgerTests) ----

#[test]
fn dead_letters_are_listed_without_payloads_and_replayed_by_code() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["x", "y"] {
        store
            .enqueue(&event(id, id, r#"{"secret-free":true}"#, clock.now()))
            .unwrap();
    }
    store.lease(2, Duration::from_secs(60)).unwrap();
    store.mark_dead_lettered("x", "azure-http-400").unwrap();
    store
        .mark_dead_lettered("y", "preflight-field-too-large")
        .unwrap();

    let listed = store.list_dead_lettered(10).unwrap();
    let none = store.replay_dead_lettered(None, None, 10).unwrap();
    let replayed = store
        .replay_dead_lettered(Some("azure-http-"), None, 10)
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let leased = store.lease(10, Duration::from_secs(60)).unwrap();

    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].delivery_attempts, 1);
    assert!(
        listed
            .iter()
            .any(|record| record.failure_code.as_deref() == Some("azure-http-400"))
    );
    assert_eq!(none, 0);
    assert_eq!(replayed, 1);
    assert_eq!(snapshot.dead_lettered, 1);
    assert_eq!(leased.len(), 1);
    assert_eq!(leased[0].event_id, "x");
    assert_eq!(leased[0].delivery_attempts, 1);
}

#[test]
fn replay_filters_by_ids_prefix_and_maximum() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b", "c", "d"] {
        enqueue(&store, &clock, id);
        clock.advance(Span::seconds(1));
    }
    store.lease(4, Duration::from_secs(60)).unwrap();
    for id in ["a", "b", "c"] {
        store.mark_dead_lettered(id, "http-500").unwrap();
    }
    store.mark_dead_lettered("d", "schema").unwrap();

    // Whitespace prefix and empty id list count as "no filter".
    assert_eq!(
        store
            .replay_dead_lettered(Some("  "), Some(&[]), 10)
            .unwrap(),
        0
    );
    let ids = vec!["b".to_owned(), "d".to_owned()];
    assert_eq!(
        store
            .replay_dead_lettered(Some("http-"), Some(&ids), 10)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .replay_dead_lettered(None, Some(&["d".to_owned()]), 10)
            .unwrap(),
        1
    );
    assert_eq!(
        store.replay_dead_lettered(Some("http"), None, 1).unwrap(),
        1
    );
    let remaining: Vec<String> = store
        .list_dead_lettered(10)
        .unwrap()
        .into_iter()
        .map(|record| record.event_id)
        .collect();
    assert_eq!(remaining, ["c"]);
    assert_eq!(store.snapshot().unwrap().queued, 3);
}
