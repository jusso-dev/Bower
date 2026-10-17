//! Ports of the `EfSourceCursorStore` tests in `SqlServerSourceAdapterTests`.

mod common;

use std::sync::Arc;

use bower_contracts::{SourceCursorStore, StoreError};
use bower_persistence::SqliteSourceCursorStore;
use chrono::Duration as Span;
use common::*;

fn open(path: &std::path::Path) -> SqliteSourceCursorStore {
    let store = SqliteSourceCursorStore::new(path).unwrap();
    store.initialize().unwrap();
    store
}

#[test]
fn cursor_store_survives_restart_and_rejects_stale_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source-cursors.db");
    let first = open(&path);

    let created = first
        .try_advance("finance-audit", 0, r#"{"sequence":100}"#, test_now())
        .unwrap();

    let restarted = open(&path);
    let snapshot = restarted.read("finance-audit").unwrap().unwrap();
    let advanced = restarted
        .try_advance(
            "finance-audit",
            snapshot.version,
            r#"{"sequence":200}"#,
            test_now() + Span::minutes(1),
        )
        .unwrap();
    let stale = first
        .try_advance(
            "finance-audit",
            snapshot.version,
            r#"{"sequence":150}"#,
            test_now() + Span::minutes(2),
        )
        .unwrap();
    let current = first.read("finance-audit").unwrap().unwrap();

    assert!(created);
    assert!(advanced);
    assert!(!stale);
    assert_eq!(current.version, 2);
    assert_eq!(current.value, r#"{"sequence":200}"#);
}

#[test]
fn cursor_store_restricts_database_permissions_on_unix() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source-cursors.db");
        let _store = open(&path);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn missing_cursor_requires_version_zero_and_rejects_duplicates() {
    let directory = tempfile::tempdir().unwrap();
    let store = open(&directory.path().join("cursors.db"));
    assert_eq!(store.read("absent").unwrap(), None);
    assert!(!store.try_advance("absent", 3, "x", test_now()).unwrap());
    assert!(store.try_advance("absent", 0, "x", test_now()).unwrap());
    // A second create with version 0 is stale, not an error.
    assert!(!store.try_advance("absent", 0, "y", test_now()).unwrap());
    assert_eq!(store.read("absent").unwrap().unwrap().value, "x");
}

#[test]
fn validates_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let store = open(&directory.path().join("cursors.db"));
    assert!(matches!(store.read(" "), Err(StoreError::Invalid(_))));
    assert!(matches!(
        store.read(&"s".repeat(129)),
        Err(StoreError::Invalid(_))
    ));
    assert!(store.read(&"s".repeat(128)).unwrap().is_none());
    assert!(matches!(
        store.try_advance("s", 0, " ", test_now()),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.try_advance("s", -1, "v", test_now()),
        Err(StoreError::Invalid(_))
    ));
}

/// C# catches every `SqliteException` from the write: a failed write is a lost race
/// (`false`), never an error, and nothing is committed.
#[test]
fn any_sqlite_write_failure_returns_false() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cursors.db");
    let store = open(&path);
    assert!(store.try_advance("existing", 0, "v1", test_now()).unwrap());
    raw(&path)
        .execute_batch(
            "CREATE TRIGGER reject_insert BEFORE INSERT ON source_cursors BEGIN SELECT RAISE(ABORT, 'injected'); END;
             CREATE TRIGGER reject_update BEFORE UPDATE ON source_cursors BEGIN SELECT RAISE(FAIL, 'injected'); END;",
        )
        .unwrap();

    assert!(!store.try_advance("new", 0, "v", test_now()).unwrap());
    assert!(!store.try_advance("existing", 1, "v2", test_now()).unwrap());
    assert_eq!(store.read("new").unwrap(), None);
    let existing = store.read("existing").unwrap().unwrap();
    assert_eq!((existing.value.as_str(), existing.version), ("v1", 1));

    raw(&path)
        .execute_batch("DROP TRIGGER reject_insert; DROP TRIGGER reject_update;")
        .unwrap();
    assert!(store.try_advance("existing", 1, "v2", test_now()).unwrap());
}

#[test]
fn updated_at_uses_ef_core_text_in_utc() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cursors.db");
    let store = open(&path);
    let local = bower_contracts::time::parse("2026-07-26T12:14:19.1234567+10:00").unwrap();
    store.try_advance("s", 0, "v", local).unwrap();
    let text: String = raw(&path)
        .query_row("SELECT \"UpdatedAt\" FROM source_cursors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(text, "2026-07-26 02:14:19.1234567+00:00");
}

#[test]
fn concurrent_advances_have_exactly_one_winner_per_version() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(open(&directory.path().join("cursors.db")));
    store.try_advance("src", 0, "v0", test_now()).unwrap();
    let handles: Vec<_> = (0..12)
        .map(|index| {
            let store = store.clone();
            std::thread::spawn(move || {
                store
                    .try_advance("src", 1, &format!("v{index}"), test_now())
                    .unwrap()
            })
        })
        .collect();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);
    assert_eq!(store.read("src").unwrap().unwrap().version, 2);
}

/// C# `InitializeAsync` (Microsoft.Data.Sqlite): `CREATE TABLE IF NOT EXISTS` on
/// every start, WAL only for a newly created file. The old EF Core `EnsureCreated`
/// rule left an existing database with unrelated tables without `source_cursors`.
#[test]
fn initialize_creates_table_if_missing_on_every_start() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cursors.db");
    raw(&path)
        .execute_batch("CREATE TABLE unrelated (id INTEGER); INSERT INTO unrelated VALUES (7);")
        .unwrap();
    let store = open(&path);
    assert_eq!(store.read("s").unwrap(), None);
    assert!(store.try_advance("s", 0, "v", test_now()).unwrap());
    let mode: String = raw(&path)
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let unrelated: i64 = raw(&path)
        .query_row("SELECT id FROM unrelated", [], |row| row.get(0))
        .unwrap();
    assert_eq!(unrelated, 7);

    // Restart is idempotent and keeps data; a dropped table is recreated.
    let restarted = open(&path);
    assert_eq!(restarted.read("s").unwrap().unwrap().version, 1);
    restarted.close_idle_connections();
    store.close_idle_connections();
    raw(&path)
        .execute_batch("DROP TABLE source_cursors;")
        .unwrap();
    let recreated = open(&path);
    assert_eq!(recreated.read("s").unwrap(), None);
    let sql: String = raw(&path)
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'source_cursors'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        sql,
        "CREATE TABLE \"source_cursors\" (\n    \"SourceId\" TEXT NOT NULL CONSTRAINT \"PK_source_cursors\" PRIMARY KEY,\n    \"Value\" TEXT NOT NULL,\n    \"Version\" INTEGER NOT NULL,\n    \"UpdatedAt\" TEXT NOT NULL\n)"
    );

    let fresh_path = directory.path().join("fresh.db");
    let _fresh = open(&fresh_path);
    let mode: String = raw(&fresh_path)
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}
