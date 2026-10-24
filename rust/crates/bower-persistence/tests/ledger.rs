//! Ports of the ledger parts of `PrivacyProfileAndLedgerTests` plus upgrade,
//! compaction and corruption-path tests.

mod common;

use std::time::Duration;

use bower_contracts::{DurableEventStore, StoreError};
use bower_persistence::{SqliteEventStore, chain_hash, genesis_hash, payload_hash};
use chrono::Duration as Span;
use common::*;

fn codes(store: &SqliteEventStore) -> Vec<String> {
    store
        .verify_ledger()
        .unwrap()
        .issues
        .into_iter()
        .map(|issue| issue.code)
        .collect()
}

#[test]
fn ledger_is_intact_through_normal_lifecycle_including_purge() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for index in 0..5 {
        store
            .enqueue(&event(
                &format!("e{index}"),
                &format!("f{index}"),
                &format!("{{\"n\":{index}}}"),
                clock.now(),
            ))
            .unwrap();
    }
    store.lease(3, Duration::from_secs(60)).unwrap();
    for id in ["e0", "e1", "e2"] {
        store
            .mark_delivered(id, "ack", claim(&store, id).as_deref())
            .unwrap();
    }

    clock.advance(Span::days(10));
    let purged = store
        .purge_delivered(clock.now() - Span::days(7), 100)
        .unwrap();
    let verification = store.verify_ledger().unwrap();
    let head = store.ledger_head().unwrap();

    assert_eq!(purged, 3);
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(head.sequence, 5);
    assert_eq!(verification.entries, 2);
    assert_eq!(verification.head_sequence, 5);
    assert_eq!(verification.head_hash, head.hash);
}

#[test]
fn ledger_detects_modified_payload_deleted_row_and_injected_event() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b", "c"] {
        store
            .enqueue(&event(id, id, &format!("{{\"id\":\"{id}\"}}"), test_now()))
            .unwrap();
    }
    raw(&queue_path(directory.path()))
        .execute_batch(
            r#"UPDATE queue_events_v5 SET payload = '{"id":"a","attacker":true}' WHERE event_id = 'a';
DELETE FROM queue_events_v5 WHERE event_id = 'b';
INSERT INTO queue_events_v5 (event_id, fingerprint, payload, payload_bytes, received_at, state)
VALUES ('forged', 'forged', '{}', 2, '2026-01-01T00:00:00Z', 0);"#,
        )
        .unwrap();

    let verification = store.verify_ledger().unwrap();
    let codes: Vec<&str> = verification
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect();

    assert!(!verification.intact);
    assert!(codes.contains(&"payload-modified"));
    assert!(codes.contains(&"event-missing"));
    assert!(codes.contains(&"unledgered-event"));
    let forged = verification
        .issues
        .iter()
        .find(|issue| issue.code == "unledgered-event")
        .unwrap();
    assert_eq!((forged.sequence, forged.event_id.as_str()), (0, "forged"));
    assert_eq!(forged.detail, "Event is stored without a ledger entry.");
    // Issues carry ids and codes only, never payload text.
    assert!(
        verification
            .issues
            .iter()
            .all(|issue| !issue.detail.contains("attacker"))
    );
}

#[test]
fn ledger_detects_rewritten_chain() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    store.enqueue(&event("a", "a", "{}", test_now())).unwrap();
    store.enqueue(&event("b", "b", "{}", test_now())).unwrap();
    raw(&queue_path(directory.path()))
        .execute(
            "UPDATE queue_ledger SET received_at = '2020-01-01T00:00:00Z' WHERE sequence = 1;",
            [],
        )
        .unwrap();

    assert!(codes(&store).contains(&"chain-broken".to_owned()));
}

#[test]
fn ledger_detects_sequence_gap_and_purge_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b", "c"] {
        enqueue(&store, &clock, id);
    }
    let connection = raw(&queue_path(directory.path()));
    connection
        .execute(
            "UPDATE queue_ledger SET purged_at = 'x' WHERE event_id = 'a';",
            [],
        )
        .unwrap();
    connection
        .execute("DELETE FROM queue_ledger WHERE sequence = 2;", [])
        .unwrap();
    connection
        .execute("DELETE FROM queue_events_v5 WHERE event_id = 'b';", [])
        .unwrap();
    let found = codes(&store);
    assert!(found.contains(&"purge-mismatch".to_owned()), "{found:?}");
    assert!(found.contains(&"sequence-gap".to_owned()), "{found:?}");
    let gap = store
        .verify_ledger()
        .unwrap()
        .issues
        .into_iter()
        .find(|issue| issue.code == "sequence-gap")
        .unwrap();
    assert_eq!(gap.detail, "Expected sequence 2, found 3.");
}

#[test]
fn empty_ledger_head_is_genesis() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let head = store.ledger_head().unwrap();
    assert_eq!(
        (head.sequence, head.hash.as_str()),
        (0, genesis_hash().as_str())
    );
    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact);
    assert_eq!((verification.entries, verification.head_sequence), (0, 0));
}

#[test]
fn chain_matches_independent_recomputation() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    store
        .enqueue(&event("e1", "f1", r#"{"n":1}"#, clock.now()))
        .unwrap();
    let expected = chain_hash(
        &genesis_hash(),
        1,
        "e1",
        &payload_hash(r#"{"n":1}"#),
        "2026-07-26T02:14:19.0000000+00:00",
    );
    assert_eq!(store.ledger_head().unwrap().hash, expected);
}

#[test]
fn full_purge_compacts_into_anchor_and_chain_continues() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b"] {
        enqueue(&store, &clock, id);
    }
    store.lease(2, Duration::from_secs(60)).unwrap();
    store
        .mark_delivered("a", "ack", claim(&store, "a").as_deref())
        .unwrap();
    store
        .mark_delivered("b", "ack", claim(&store, "b").as_deref())
        .unwrap();
    let head_before = store.ledger_head().unwrap();
    clock.advance(Span::days(10));
    assert_eq!(store.purge_delivered(clock.now(), 100).unwrap(), 2);

    let connection = raw(&queue_path(directory.path()));
    let ledger_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM queue_ledger", [], |row| row.get(0))
        .unwrap();
    let anchor: (i64, String) = connection
        .query_row(
            "SELECT end_sequence, chain_hash FROM queue_ledger_segments ORDER BY end_sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(ledger_rows, 0);
    assert_eq!(
        (anchor.0, anchor.1.as_str()),
        (2, head_before.hash.as_str())
    );
    assert_eq!(store.ledger_head().unwrap(), head_before);

    enqueue(&store, &clock, "c");
    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!((verification.entries, verification.head_sequence), (1, 3));
}

/// Purge and compaction are separate transactions (as in C#). A crash after the
/// purge commit leaves purged-but-uncompacted ledger rows; that state verifies
/// intact after restart and the next purge run finishes compaction.
#[test]
fn crash_between_purge_and_compaction_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for id in ["a", "b", "c"] {
        enqueue(&store, &clock, id);
    }
    store.lease(3, Duration::from_secs(60)).unwrap();
    store
        .mark_delivered("a", "ack", claim(&store, "a").as_deref())
        .unwrap();
    store
        .mark_delivered("b", "ack", claim(&store, "b").as_deref())
        .unwrap();
    let head_before = store.ledger_head().unwrap();
    drop(store);
    {
        // Exactly the purge transaction's writes, then "crash" before compaction.
        let mut connection = raw(&queue_path(directory.path()));
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute_batch(
                "DELETE FROM queue_events_v5 WHERE event_id IN ('a', 'b') AND state = 3;
UPDATE queue_ledger SET purged_at = '2026-08-05T02:14:19.0000000+00:00'
WHERE event_id IN ('a', 'b') AND purged_at IS NULL;",
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    let reopened = common::store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let verification = reopened.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(verification.entries, 3);
    assert_eq!(reopened.ledger_head().unwrap(), head_before);

    clock.advance(Span::days(10));
    assert_eq!(reopened.purge_delivered(clock.now(), 100).unwrap(), 0);
    let verification = reopened.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(verification.entries, 1);
    let anchor: i64 = raw(&queue_path(directory.path()))
        .query_row(
            "SELECT end_sequence FROM queue_ledger_segments ORDER BY end_sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(anchor, 2);
    assert_eq!(reopened.ledger_head().unwrap(), head_before);
    // The undelivered event survives both the crash and the follow-up purge.
    assert_eq!(reopened.snapshot().unwrap().uploading, 1);
}

/// Pre-ledger (schema v2) databases are backfilled in `received_at, event_id`
/// order on initialize, exactly like C# `QueueLedger.BackfillAsync`.
#[test]
fn upgrade_from_pre_ledger_schema_backfills_in_receive_order() {
    let directory = tempfile::tempdir().unwrap();
    let path = queue_path(directory.path());
    {
        let connection = raw(&path);
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
CREATE TABLE queue_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL,
    received_at TEXT NOT NULL,
    state INTEGER NOT NULL,
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    lease_until TEXT NULL,
    next_attempt_at TEXT NULL,
    last_failure_code TEXT NULL,
    acknowledgement TEXT NULL,
    delivered_at TEXT NULL,
    CHECK (length(event_id) BETWEEN 1 AND 128),
    CHECK (payload_bytes > 0)
);
CREATE TABLE schema_history (version INTEGER PRIMARY KEY NOT NULL, applied_at TEXT NOT NULL, hash TEXT NOT NULL);
INSERT INTO schema_history VALUES (1, '2026-01-01T00:00:00.000Z', 'bower-queue-v1');
INSERT INTO queue_events (event_id, fingerprint, payload, payload_bytes, received_at, state)
VALUES ('z', 'fz', '{\"z\":1}', 7, '2026-01-01T00:00:01.0000000+00:00', 0),
       ('b', 'fb', '{\"b\":1}', 7, '2026-01-01T00:00:00.0000000+00:00', 0),
       ('a', 'fa', '{\"a\":1}', 7, '2026-01-01T00:00:00.0000000+00:00', 3);",
            )
            .unwrap();
    }
    let clock = FakeClock::new(test_now());
    let store = common::store(directory.path(), 10 * ONE_MEBIBYTE, &clock);

    let order: Vec<String> = {
        let connection = raw(&path);
        let mut statement = connection
            .prepare("SELECT event_id FROM queue_ledger ORDER BY sequence")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(order, ["a", "b", "z"]);
    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    let mut previous = genesis_hash();
    for (index, (id, payload, received)) in [
        ("a", "{\"a\":1}", "2026-01-01T00:00:00.0000000+00:00"),
        ("b", "{\"b\":1}", "2026-01-01T00:00:00.0000000+00:00"),
        ("z", "{\"z\":1}", "2026-01-01T00:00:01.0000000+00:00"),
    ]
    .into_iter()
    .enumerate()
    {
        previous = chain_hash(
            &previous,
            index as i64 + 1,
            id,
            &payload_hash(payload),
            received,
        );
    }
    assert_eq!(verification.head_hash, previous);
    let versions: i64 = raw(&path)
        .query_row("SELECT COUNT(*) FROM schema_history", [], |row| row.get(0))
        .unwrap();
    assert_eq!(versions, 5);

    // Re-initialising is idempotent: no duplicate ledger entries.
    drop(store);
    let again = common::store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    assert_eq!(again.verify_ledger().unwrap().entries, 3);
}

#[test]
fn corrupt_database_fails_initialize_with_storage_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = queue_path(directory.path());
    std::fs::write(
        &path,
        b"this is not a sqlite database, just garbage bytes padding padding padding",
    )
    .unwrap();
    let store = SqliteEventStore::new(&path, 10 * ONE_MEBIBYTE, None).unwrap();
    assert!(matches!(store.initialize(), Err(StoreError::Storage(_))));
}

#[test]
fn truncated_database_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    for index in 0..50 {
        enqueue(&store, &clock, &format!("event-{index}"));
    }
    store.maintain().unwrap();
    drop(store);
    let path = queue_path(directory.path());
    let bytes = std::fs::read(&path).unwrap();
    // Keep the header but corrupt every page after the first.
    let mut corrupted = bytes[..4096].to_vec();
    corrupted.extend(std::iter::repeat_n(0xA5_u8, bytes.len() - 4096));
    std::fs::write(&path, corrupted).unwrap();
    let reopened = SqliteEventStore::new(&path, 10 * ONE_MEBIBYTE, Some(clock.clone())).unwrap();
    let outcome = reopened
        .initialize()
        .and_then(|()| reopened.snapshot().map(|_| ()));
    assert!(
        matches!(outcome, Err(StoreError::Storage(_))),
        "{outcome:?}"
    );
}
