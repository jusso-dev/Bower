#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bower_contracts::time::{self, Clock, Timestamp};
use bower_contracts::{DurableEventStore, EnqueueResult, QueueState, QueuedEvent};
use bower_persistence::SqliteEventStore;

pub const ONE_MEBIBYTE: i64 = 1024 * 1024;

/// `TestEvents.Now` from the C# tests.
pub fn test_now() -> Timestamp {
    time::parse("2026-07-26T02:14:19+00:00").unwrap()
}

pub struct FakeClock(Mutex<Timestamp>);

impl FakeClock {
    pub fn new(value: Timestamp) -> Arc<Self> {
        Arc::new(Self(Mutex::new(value)))
    }

    pub fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }

    pub fn advance(&self, duration: chrono::Duration) {
        let mut value = self.0.lock().unwrap();
        *value += duration;
    }
}

impl Clock for FakeClock {
    fn utc_now(&self) -> Timestamp {
        self.now()
    }
}

pub fn queue_path(directory: &Path) -> PathBuf {
    directory.join("queue.db")
}

pub fn store(directory: &Path, maximum_bytes: i64, clock: &Arc<FakeClock>) -> SqliteEventStore {
    let store =
        SqliteEventStore::new(queue_path(directory), maximum_bytes, Some(clock.clone())).unwrap();
    store.initialize().unwrap();
    store
}

pub fn event(
    event_id: &str,
    fingerprint: &str,
    payload: &str,
    received_at: Timestamp,
) -> QueuedEvent {
    QueuedEvent {
        lease_token: None,
        event_id: event_id.into(),
        fingerprint: fingerprint.into(),
        payload: payload.into(),
        received_at,
        state: QueueState::Queued,
        delivery_attempts: 0,
        suppression: None,
    }
}

/// `QueueRetentionTests.EnqueueAsync` helper.
pub fn enqueue(store: &SqliteEventStore, clock: &FakeClock, event_id: &str) -> EnqueueResult {
    store
        .enqueue(&event(
            event_id,
            &format!("sha256:{event_id}"),
            &format!("{{\"eventId\":\"{event_id}\"}}"),
            clock.now(),
        ))
        .unwrap()
}

pub fn raw(path: &Path) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    connection
}

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Copies a fixture database into a scratch directory so tests never mutate it.
pub fn copy_fixture(name: &str, directory: &Path) -> PathBuf {
    let target = directory.join(name);
    std::fs::copy(fixture(name), &target).unwrap();
    target
}

/// `sqlite_master` rows as `type|name|tbl_name|sql`, ordered by name.
///
/// `sqlite_stat4` is excluded: rusqlite's bundled SQLite is built with
/// `SQLITE_ENABLE_STAT4`, so `PRAGMA optimize` (maintain) adds that ANALYZE table,
/// while `SQLitePCLRaw.bundle_e_sqlite3` only writes `sqlite_stat1`. Builds
/// without STAT4 ignore the table, so it does not affect compatibility.
pub fn schema(path: &Path) -> Vec<String> {
    let connection = raw(path);
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name <> 'sqlite_stat4' ORDER BY name;")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok(format!(
                "{}|{}|{}|{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| "<null>".into())
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

pub fn claims(
    store: &bower_persistence::SqliteEventStore,
) -> std::collections::HashMap<String, String> {
    let connection = raw(store.database_path());
    let mut query = connection.prepare("SELECT event_id, CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) FROM queue_events_v5;").unwrap();
    query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

pub fn claim(store: &bower_persistence::SqliteEventStore, id: &str) -> Option<String> {
    claims(store).get(id).cloned()
}
