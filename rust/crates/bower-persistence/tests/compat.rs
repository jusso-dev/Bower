//! Cross-implementation compatibility with `src/Bower.Persistence`.
//!
//! `tests/fixtures/csharp-queue.db` and `csharp-cursors.db` were written by the
//! C# `SqliteEventStore` / `EfSourceCursorStore` running the scenario below
//! (temporary xunit test, `FakeClock(TestEvents.Now)`). Rust runs the identical
//! scenario and must produce byte-identical schema, rows and ledger hashes.
//!
//! Generated from commit bf15994 (EF Core `EnsureCreated` cursor store). The same
//! temporary C# test also opened the databases from
//! `export_rust_databases_for_csharp`, verified the ledger, leased, delivered,
//! purged and advanced cursors on them (reverse direction). It was not committed.
//! The current C# cursor store (Microsoft.Data.Sqlite, `CREATE TABLE IF NOT EXISTS`)
//! stores the same DDL text, so the cursor fixture still matches.

mod common;

use std::path::Path;
use std::time::Duration;

use bower_contracts::time::{self, Timestamp};
use bower_contracts::{DurableEventStore, QueuedEvent, SourceCursorStore};
use bower_persistence::{SqliteEventStore, SqliteSourceCursorStore, chain_hash, genesis_hash};
use chrono::Duration as Span;
use common::*;

/// Ledger head written by the C# scenario.
const CSHARP_HEAD_SEQUENCE: i64 = 6;
const CSHARP_HEAD_HASH: &str = "a8d0b005d8f459aa7a2ba54f75e4ddb74736c2197c9e2255ed8530a240a7cf27";

fn ticks(count: i64) -> Span {
    Span::nanoseconds(count * 100)
}

fn offset_time() -> Timestamp {
    time::parse("2026-07-26T12:14:19+10:00").unwrap() + ticks(1_234_567)
}

/// Mirrors `ZzRustPersistenceParityTemp.Generate` (queue part).
fn queue_scenario(path: &Path) {
    let clock = FakeClock::new(test_now());
    let store = SqliteEventStore::new(path, 10 * ONE_MEBIBYTE, Some(clock.clone())).unwrap();
    store.initialize().unwrap();
    let now = clock.now();
    let enqueue = |id: &str, fingerprint: &str, payload: &str, at: Timestamp, attempts: i32| {
        store
            .enqueue(&QueuedEvent {
                delivery_attempts: attempts,
                ..event(id, fingerprint, payload, at)
            })
            .unwrap()
    };
    assert!(enqueue("e1", "sha256:e1", r#"{"n":1}"#, now, 0).enqueued);
    assert!(
        enqueue(
            "e2",
            "sha256:e2",
            "{\"msg\":\"h\u{e9}llo \u{2713} \u{1F600}\"}",
            now + ticks(1),
            0
        )
        .enqueued
    );
    assert!(enqueue("e3", "sha256:e3", r#"{"n":3}"#, offset_time(), 0).enqueued);
    assert!(enqueue("e4", "sha256:e4", r#"{"n":4}"#, now + Span::seconds(2), 2).enqueued);
    assert!(enqueue("e5", "sha256:e5", r#"{"n":5}"#, now + Span::seconds(3), 0).enqueued);
    assert!(enqueue("e6", "sha256:e5", r#"{"n":6}"#, now, 0).duplicate);
    assert!(enqueue("e5", "sha256:other", r#"{"n":6}"#, now, 0).duplicate);
    // The C# fixture run reported these as duplicates (INSERT OR IGNORE swallowed the
    // CHECK failures); both implementations now reject them. Neither wrote a row, so
    // the fixture is unaffected.
    for (id, fingerprint, payload) in [
        (String::new(), "sha256:bad0", "{}"),
        ("x".repeat(129), "sha256:bad129", "{}"),
        ("empty".to_owned(), "sha256:empty", ""),
    ] {
        assert!(matches!(
            store.enqueue(&event(&id, fingerprint, payload, now)),
            Err(bower_contracts::StoreError::Invalid(_))
        ));
    }

    let leased = store.lease(3, Duration::from_secs(60)).unwrap();
    let summary: Vec<String> = leased
        .iter()
        .map(|item| {
            format!(
                "{}:{}:{}",
                item.event_id,
                item.delivery_attempts,
                time::format_round_trip(&item.received_at)
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            "e1:1:2026-07-26T02:14:19.0000000+00:00",
            "e2:1:2026-07-26T02:14:19.0000001+00:00",
            "e3:1:2026-07-26T02:14:19.1234567+00:00"
        ]
    );
    store.mark_delivered("e1", "ack-1").unwrap();
    store.mark_delivered("e2", "ack-2").unwrap();
    store.mark_dead_lettered("e3", "azure-http-400").unwrap();
    clock.advance(Span::seconds(1));
    let leased = store.lease(1, Duration::from_secs(60)).unwrap();
    assert_eq!(
        (leased[0].event_id.as_str(), leased[0].delivery_attempts),
        ("e4", 3)
    );
    let retry_after = time::parse("2026-08-30T09:00:00+05:30").unwrap() + ticks(50);
    store.mark_retrying("e4", "busy", retry_after).unwrap();
    clock.advance(Span::days(10));
    assert_eq!(
        store
            .purge_delivered(clock.now() - Span::days(7), 100)
            .unwrap(),
        2
    );
    assert!(enqueue("e7", "sha256:e7", r#"{"n":7}"#, clock.now(), 0).enqueued);
    let leased = store.lease(1, Duration::from_secs(300)).unwrap();
    assert_eq!(
        (leased[0].event_id.as_str(), leased[0].delivery_attempts),
        ("e5", 1)
    );
    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    store.maintain().unwrap();
    store.close_idle_connections();
}

/// Mirrors the cursor part of the C# scenario.
fn cursor_scenario(path: &Path) {
    let store = SqliteSourceCursorStore::new(path).unwrap();
    store.initialize().unwrap();
    assert!(
        store
            .try_advance("finance-audit", 0, r#"{"sequence":100}"#, test_now())
            .unwrap()
    );
    assert!(
        store
            .try_advance("finance-audit", 1, r#"{"sequence":200}"#, offset_time())
            .unwrap()
    );
    assert!(
        store
            .try_advance("other", 0, "v", test_now() + ticks(1_000_000))
            .unwrap()
    );
    assert!(
        !store
            .try_advance("finance-audit", 1, "x", test_now())
            .unwrap()
    );
    assert!(!store.try_advance("missing", 3, "x", test_now()).unwrap());
    store.close_idle_connections();
}

fn pragmas(path: &Path) -> Vec<String> {
    let connection = raw(path);
    [
        "journal_mode",
        "user_version",
        "page_size",
        "auto_vacuum",
        "encoding",
        "application_id",
    ]
    .iter()
    .map(|pragma| {
        let value: rusqlite::types::Value = connection
            .query_row(&format!("PRAGMA {pragma};"), [], |row| row.get(0))
            .unwrap();
        format!("{pragma}={value:?}")
    })
    .collect()
}

/// Every row as `column=value(typeof)`; `schema_history.applied_at` is wall-clock and skipped.
fn rows(path: &Path, table: &str) -> Vec<String> {
    let connection = raw(path);
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1;"))
        .unwrap();
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    statement
        .query_map([], |row| {
            let mut cells = Vec::new();
            for (index, name) in names.iter().enumerate() {
                if table == "schema_history" && name == "applied_at" {
                    continue;
                }
                let value: rusqlite::types::Value = row.get(index)?;
                cells.push(format!("{name}={value:?}"));
            }
            Ok(cells.join("|"))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn upgrade(path: &Path) {
    let store = SqliteEventStore::new(path, 10 * ONE_MEBIBYTE, None).unwrap();
    store.initialize().unwrap();
    store.close_idle_connections();
}

#[test]
fn v3_database_upgrades_to_v4_idempotently() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-queue.db", directory.path());
    let index = |path: &Path| -> Option<String> {
        raw(path)
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'ix_queue_events_state_bytes';",
                [],
                |row| row.get(0),
            )
            .ok()
    };
    let versions = |path: &Path| -> Vec<i64> {
        let connection = raw(path);
        let mut statement = connection
            .prepare("SELECT version FROM schema_history ORDER BY version;")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(index(&path), None);
    assert_eq!(versions(&path), [1, 2, 3]);

    upgrade(&path);
    upgrade(&path);
    assert_eq!(
        index(&path).as_deref(),
        Some(
            "CREATE INDEX ix_queue_events_state_bytes\n    ON queue_events(state, payload_bytes, received_at)"
        )
    );
    assert_eq!(versions(&path), [1, 2, 3, 4]);

    // v4 recorded but index lost: the next start recreates it.
    raw(&path)
        .execute_batch("DROP INDEX ix_queue_events_state_bytes;")
        .unwrap();
    upgrade(&path);
    assert!(index(&path).is_some());
    let rows_before = rows(&path, "queue_events");
    upgrade(&path);
    assert_eq!(rows(&path, "queue_events"), rows_before);
}

#[test]
fn rust_queue_matches_csharp_database_byte_for_byte() {
    let directory = tempfile::tempdir().unwrap();
    let rust_path = directory.path().join("rust-queue.db");
    queue_scenario(&rust_path);
    let csharp_path = copy_fixture("csharp-queue.db", directory.path());
    // The fixture predates schema v4 (capacity index, bf15994). Upgrade it the way a
    // C# or Rust collector does on start before comparing.
    upgrade(&csharp_path);

    assert_eq!(schema(&rust_path), schema(&csharp_path));
    assert_eq!(pragmas(&rust_path), pragmas(&csharp_path));
    assert!(pragmas(&rust_path).contains(&"journal_mode=Text(\"wal\")".to_owned()));
    for table in [
        "queue_events",
        "queue_ledger",
        "queue_ledger_anchor",
        "schema_history",
    ] {
        assert_eq!(
            rows(&rust_path, table),
            rows(&csharp_path, table),
            "table {table}"
        );
    }
}

#[test]
fn csharp_ledger_hashes_recompute_in_rust() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-queue.db", directory.path());
    let connection = raw(&path);
    let (mut previous, anchor_sequence): (String, i64) = connection
        .query_row(
            "SELECT chain_hash, sequence FROM queue_ledger_anchor WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    // The anchor is the C# hash of entry 2; recompute entries 1..=2 from the known payloads.
    let first = chain_hash(
        &genesis_hash(),
        1,
        "e1",
        &bower_persistence::payload_hash(r#"{"n":1}"#),
        "2026-07-26T02:14:19.0000000+00:00",
    );
    let second = chain_hash(
        &first,
        2,
        "e2",
        &bower_persistence::payload_hash("{\"msg\":\"h\u{e9}llo \u{2713} \u{1F600}\"}"),
        "2026-07-26T02:14:19.0000001+00:00",
    );
    assert_eq!((anchor_sequence, previous.as_str()), (2, second.as_str()));

    let mut statement = connection
        .prepare("SELECT sequence, event_id, payload_sha256, received_at, chain_hash FROM queue_ledger ORDER BY sequence")
        .unwrap();
    let entries: Vec<(i64, String, String, String, String)> = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(entries.len(), 4);
    for (sequence, event_id, payload_sha256, received_at, stored) in entries {
        let recomputed = chain_hash(
            &previous,
            sequence,
            &event_id,
            &payload_sha256,
            &received_at,
        );
        assert_eq!(recomputed, stored, "sequence {sequence}");
        previous = stored;
    }
    assert_eq!(previous, CSHARP_HEAD_HASH);
}

#[test]
fn csharp_queue_opens_verifies_and_operates_in_rust() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-queue.db", directory.path());
    let clock = FakeClock::new(test_now() + Span::days(40));
    let store = SqliteEventStore::new(&path, 10 * ONE_MEBIBYTE, Some(clock.clone())).unwrap();
    store.initialize().unwrap();

    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(verification.entries, 4);
    let head = store.ledger_head().unwrap();
    assert_eq!(
        (head.sequence, head.hash.as_str()),
        (CSHARP_HEAD_SEQUENCE, CSHARP_HEAD_HASH)
    );
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        (
            snapshot.queued,
            snapshot.uploading,
            snapshot.retrying,
            snapshot.delivered,
            snapshot.dead_lettered
        ),
        (1, 1, 1, 0, 1)
    );

    let dead = store.list_dead_lettered(10).unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].failure_code.as_deref(), Some("azure-http-400"));
    assert_eq!(dead[0].received_at, offset_time());

    // e4 (retry due), e5 (expired lease) and e7 (queued) are all leasable 40 days later.
    let leased = store.lease(10, Duration::from_secs(60)).unwrap();
    let ids: Vec<(&str, i32)> = leased
        .iter()
        .map(|item| (item.event_id.as_str(), item.delivery_attempts))
        .collect();
    assert_eq!(ids, [("e4", 4), ("e5", 2), ("e7", 1)]);
    for item in &leased {
        store.mark_delivered(&item.event_id, "rust-ack").unwrap();
    }
    assert!(
        store
            .enqueue(&event("from-rust", "sha256:from-rust", "{}", clock.now()))
            .unwrap()
            .enqueued
    );
    clock.advance(Span::days(10));
    assert_eq!(
        store
            .purge_delivered(clock.now() - Span::days(7), 100)
            .unwrap(),
        3
    );
    let verification = store.verify_ledger().unwrap();
    assert!(verification.intact, "{:?}", verification.issues);
    assert_eq!(verification.head_sequence, CSHARP_HEAD_SEQUENCE + 1);
}

#[test]
fn rust_cursors_match_csharp_database() {
    let directory = tempfile::tempdir().unwrap();
    let rust_path = directory.path().join("rust-cursors.db");
    cursor_scenario(&rust_path);
    let csharp_path = copy_fixture("csharp-cursors.db", directory.path());

    assert_eq!(schema(&rust_path), schema(&csharp_path));
    assert_eq!(pragmas(&rust_path), pragmas(&csharp_path));
    assert_eq!(
        rows(&rust_path, "source_cursors"),
        rows(&csharp_path, "source_cursors")
    );
}

#[test]
fn csharp_cursors_open_and_advance_in_rust() {
    let directory = tempfile::tempdir().unwrap();
    let path = copy_fixture("csharp-cursors.db", directory.path());
    let store = SqliteSourceCursorStore::new(&path).unwrap();
    store.initialize().unwrap();
    let snapshot = store.read("finance-audit").unwrap().unwrap();
    assert_eq!(
        (snapshot.value.as_str(), snapshot.version),
        (r#"{"sequence":200}"#, 2)
    );
    assert!(
        !store
            .try_advance("finance-audit", 1, "stale", test_now())
            .unwrap()
    );
    assert!(
        store
            .try_advance("finance-audit", 2, "by-rust", test_now())
            .unwrap()
    );
    assert_eq!(store.read("finance-audit").unwrap().unwrap().version, 3);
}

/// Writes Rust-produced databases for the C# side to verify:
/// `BOWER_PARITY_DIR=/path cargo test -p bower-persistence --test compat -- --ignored`.
#[test]
#[ignore = "exports databases for the C# reverse-direction check"]
fn export_rust_databases_for_csharp() {
    let directory =
        std::path::PathBuf::from(std::env::var("BOWER_PARITY_DIR").expect("BOWER_PARITY_DIR"));
    std::fs::create_dir_all(&directory).unwrap();
    for name in ["rust-queue.db", "rust-cursors.db"] {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(directory.join(format!("{name}{suffix}")));
        }
    }
    queue_scenario(&directory.join("rust-queue.db"));
    cursor_scenario(&directory.join("rust-cursors.db"));
}
