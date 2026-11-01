//! Durable SQLite event queue (C# `SqliteEventStore`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::{self, Timestamp};
use bower_contracts::{
    DeadLetterRecord, DurableEventStore, EnqueueResult, FailureSettlement, LedgerHead,
    LedgerVerification, QueueSnapshot, QueueState, QueuedEvent, SourceActivity, SourceMonitoring,
    StoreError, StoreResult, SuppressionWindow,
};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, named_params, params};

use crate::ledger;
use crate::pool::{
    ConnectionPool, is_blank, prepare_path, require_text, restrict_permissions, storage,
};
use bower_contracts::time::{Clock, SystemClock};

/// Smallest accepted `maximum_bytes` (1 MiB).
pub const MINIMUM_QUEUE_BYTES: i64 = 1_048_576;
pub const MAXIMUM_LEASE_COUNT: usize = 10_000;
pub const MAXIMUM_PURGE_COUNT: usize = 100_000;
/// `CHECK (length(event_id) BETWEEN 1 AND 128)`: SQLite counts characters.
pub const MAXIMUM_EVENT_ID_LENGTH: usize = 128;

/// Connection-scoped settings applied to every pooled connection.
const CONNECTION_PRAGMAS: &str = "PRAGMA busy_timeout = 5000;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA wal_autocheckpoint = 1;
PRAGMA journal_size_limit = 0;
PRAGMA cache_spill = OFF;";

/// DDL identical to the C# batch (after raw-literal de-indentation) so
/// `sqlite_master.sql` matches byte for byte. `PRAGMA journal_mode = WAL` runs first.
const QUEUE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS queue_events (
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

CREATE INDEX IF NOT EXISTS ix_queue_events_delivery
    ON queue_events(state, next_attempt_at, received_at);

CREATE INDEX IF NOT EXISTS ix_queue_events_delivered_at
    ON queue_events(state, delivered_at);

CREATE INDEX IF NOT EXISTS ix_queue_events_state_bytes
    ON queue_events(state, payload_bytes, received_at);

CREATE TABLE IF NOT EXISTS schema_history (
    version INTEGER PRIMARY KEY NOT NULL,
    applied_at TEXT NOT NULL,
    hash TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v1');

INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v2-retention');";

const QUEUED: i64 = QueueState::Queued as i64;
const UPLOADING: i64 = QueueState::Uploading as i64;
const RETRYING: i64 = QueueState::Retrying as i64;
const DELIVERED: i64 = QueueState::Delivered as i64;
const DEAD_LETTERED: i64 = QueueState::DeadLettered as i64;

/// Schema v4 (covering index for the capacity and snapshot sums). Recorded after the
/// v3 ledger schema, as in C#; the index itself is created by `QUEUE_SCHEMA`.
const QUEUE_SCHEMA_V4: &str = "INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
VALUES (4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v4-capacity-index');";

/// Durable, idempotent SQLite queue with a tamper-evident ledger.
///
/// `Send + Sync`: every call borrows its own pooled connection (WAL, private
/// cache, `busy_timeout = 5000`); write paths use `BEGIN IMMEDIATE`.
pub struct SqliteEventStore {
    pool: ConnectionPool,
    maximum_bytes: i64,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SqliteEventStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteEventStore")
            .field("database_path", &self.pool.path())
            .field("maximum_bytes", &self.maximum_bytes)
            .finish_non_exhaustive()
    }
}

/// `DateTimeOffset.ToUniversalTime().ToString("O")`.
pub(crate) fn stored(value: &Timestamp) -> String {
    time::format_round_trip(&time::to_utc(time::truncate_to_ticks(*value)))
}

pub(crate) fn parse_stored(text: &str, column: usize) -> rusqlite::Result<Timestamp> {
    time::parse(text).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Text,
            "stored timestamp is not ISO 8601".into(),
        )
    })
}

fn sql_limit(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

fn transition_error(event_id: &str, expected: &str, requested: &str) -> StoreError {
    StoreError::Invalid(format!(
        "Event '{event_id}' is not in required state '{expected}' for transition to '{requested}'."
    ))
}

/// Mirrors the table constraints (C# `ValidateCandidate`): event id 1 to 128
/// characters without NUL (SQLite `length()` stops at NUL), non-blank fingerprint
/// and non-empty payload. Blank ids are rejected too: they could never be settled.
fn validate_candidate(candidate: &QueuedEvent) -> StoreResult<()> {
    let message = if is_blank(&candidate.event_id) {
        "Event identifier cannot be empty or whitespace."
    } else if candidate.event_id.contains('\0') {
        "Event identifier cannot contain NUL characters."
    } else if candidate.event_id.chars().count() > MAXIMUM_EVENT_ID_LENGTH {
        "Event identifier cannot exceed 128 characters."
    } else if is_blank(&candidate.fingerprint) {
        "Event fingerprint cannot be empty or whitespace."
    } else if candidate.payload.is_empty() {
        "Event payload cannot be empty."
    } else {
        return Ok(());
    };
    Err(StoreError::Invalid(message.into()))
}

fn capacity_error(maximum: i64, current: i64, attempted: i64) -> StoreError {
    StoreError::Full(format!(
        "Queue capacity exceeded. Maximum={maximum}, Current={current}, Attempted={attempted}."
    ))
}

impl SqliteEventStore {
    /// `maximum_bytes` bounds undelivered payload bytes (backpressure); at least 1 MiB.
    pub fn new(
        database_path: impl AsRef<Path>,
        maximum_bytes: i64,
        clock: Option<Arc<dyn Clock>>,
    ) -> StoreResult<Self> {
        if maximum_bytes < MINIMUM_QUEUE_BYTES {
            return Err(StoreError::Invalid(
                "Queue maximum must be at least 1 MiB.".into(),
            ));
        }
        let full_path = prepare_path(database_path.as_ref())?;
        Ok(Self {
            pool: ConnectionPool::new(full_path, CONNECTION_PRAGMAS),
            maximum_bytes,
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
        })
    }

    pub fn maximum_storage_bytes(&self) -> i64 {
        self.maximum_bytes
            .saturating_mul(4)
            .saturating_add(16_777_216)
    }

    /// Physical headroom a write must leave below `maximum_storage_bytes` before it
    /// starts: one full WAL transaction plus database growth during checkpoint.
    pub fn storage_reserve_bytes(&self) -> i64 {
        let maximum = self.maximum_storage_bytes();
        maximum / 2 + maximum / 128 + 65_536
    }

    fn configure_budget(&self, connection: &Connection) -> StoreResult<()> {
        let page_size: i64 = connection
            .query_row("PRAGMA page_size;", [], |row| row.get(0))
            .map_err(storage)?;
        let requested = self.maximum_storage_bytes() / 4 / page_size;
        let actual: i64 = connection
            .query_row(
                &format!("PRAGMA max_page_count = {requested};"),
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if actual > requested {
            return Err(capacity_error(
                self.maximum_storage_bytes(),
                actual.saturating_mul(page_size),
                0,
            ));
        }
        Ok(())
    }

    fn check_storage(&self) -> StoreResult<()> {
        let file_size = |path: &Path| -> StoreResult<i64> {
            match std::fs::metadata(path) {
                Ok(value) => Ok(i64::try_from(value.len()).unwrap_or(i64::MAX)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
                Err(_) => Err(StoreError::Storage("storage-size-unavailable".into())),
            }
        };
        let wal = PathBuf::from(format!("{}-wal", self.pool.path().display()));
        let current = file_size(self.pool.path())?.saturating_add(file_size(&wal)?);
        let maximum = self.maximum_storage_bytes();
        let reserve = self.storage_reserve_bytes();
        if current > maximum - reserve {
            return Err(capacity_error(maximum, current, reserve));
        }
        Ok(())
    }

    pub fn database_path(&self) -> &Path {
        self.pool.path()
    }

    pub fn maximum_bytes(&self) -> i64 {
        self.maximum_bytes
    }

    /// Closes idle pooled connections; the last close checkpoints the WAL.
    pub fn close_idle_connections(&self) {
        self.pool.clear();
    }

    fn now_text(&self) -> String {
        stored(&self.clock.utc_now())
    }

    fn undelivered_bytes(connection: &Connection) -> StoreResult<i64> {
        // Delivered rows are retained for idempotency only and are purged by
        // retention, so they do not count against the backpressure limit.
        connection
            .query_row(
                "SELECT COALESCE(SUM(payload_bytes), 0)
FROM queue_events_v5
WHERE state IN (?1, ?2, ?3, ?4);",
                params![QUEUED, UPLOADING, RETRYING, DEAD_LETTERED],
                |row| row.get(0),
            )
            .map_err(storage)
    }

    fn exists(connection: &Connection, candidate: &QueuedEvent) -> StoreResult<bool> {
        let mut select = connection
            .prepare("SELECT payload, fingerprint FROM queue_events_v5 WHERE event_id = ?1 OR fingerprint = ?2;")
            .map_err(storage)?;
        let rows = select
            .query_map(params![candidate.event_id, candidate.fingerprint], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        let mut found = false;
        for row in rows {
            found = true;
            let (payload, fingerprint) = row.map_err(storage)?;
            if fingerprint != candidate.fingerprint
                || replay_content(&payload) != replay_content(&candidate.payload)
            {
                return Err(StoreError::Invalid("event-identity-conflict".into()));
            }
        }
        Ok(found)
    }

    /// Capacity check, insert and ledger append for a candidate already proven new
    /// under the caller's write transaction (C# `InsertAsync`).
    pub(crate) fn insert(
        &self,
        transaction: &Connection,
        candidate: &QueuedEvent,
    ) -> StoreResult<()> {
        let payload_bytes = i64::try_from(candidate.payload.len()).unwrap_or(i64::MAX);
        let received_at = stored(&candidate.received_at);
        self.check_storage()?;
        let current = Self::undelivered_bytes(transaction)?;
        if current.saturating_add(payload_bytes) > self.maximum_bytes {
            return Err(capacity_error(self.maximum_bytes, current, payload_bytes));
        }
        // Plain INSERT: duplicates were ruled out under the write lock, so any
        // constraint failure is an error instead of being silently ignored.
        transaction
            .execute(
                "INSERT INTO queue_events_v5 (
    event_id, fingerprint, payload, payload_bytes, received_at, state,
    delivery_attempts)
VALUES (
    :event_id, :fingerprint, :payload, :payload_bytes, :received_at,
    :state, :delivery_attempts);",
                named_params! {
                    ":event_id": candidate.event_id,
                    ":fingerprint": candidate.fingerprint,
                    ":payload": candidate.payload,
                    ":payload_bytes": payload_bytes,
                    ":received_at": received_at,
                    ":state": QUEUED,
                    ":delivery_attempts": candidate.delivery_attempts,
                },
            )
            .map_err(storage)?;
        ledger::append(
            transaction,
            &candidate.event_id,
            &candidate.payload,
            &received_at,
        )?;
        transaction.execute("UPDATE queue_events_v5 SET enqueue_sequence = (SELECT MAX(sequence) FROM queue_ledger) WHERE event_id = ?1;", params![candidate.event_id]).map_err(storage)?;
        Ok(())
    }

    pub(crate) fn validate(candidate: &QueuedEvent) -> StoreResult<()> {
        validate_candidate(candidate)
    }

    pub(crate) fn exists_in(connection: &Connection, candidate: &QueuedEvent) -> StoreResult<bool> {
        Self::exists(connection, candidate)
    }

    pub(crate) fn pool(&self) -> &ConnectionPool {
        &self.pool
    }

    pub(crate) fn budget(&self, connection: &Connection) -> StoreResult<()> {
        self.configure_budget(connection)
    }

    pub(crate) fn storage_check(&self) -> StoreResult<()> {
        self.check_storage()
    }

    /// Ledger sequences of the events the archive-bounded purge would remove next with the
    /// same arguments: same filter, order and limit (C# `ReadPurgeCandidateSequencesAsync`).
    pub fn read_purge_candidate_sequences(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
        archived_through_sequence: i64,
    ) -> StoreResult<Vec<i64>> {
        if !(1..=MAXIMUM_PURGE_COUNT).contains(&maximum_count) {
            return Err(StoreError::Invalid(
                "maximumCount must be between 1 and 100000.".into(),
            ));
        }
        let before = stored(&delivered_before);
        self.pool.with(|connection| {
            let mut select = connection
                .prepare(
                    "SELECT enqueue_sequence
FROM queue_events_v5
WHERE state = ?1
  AND acknowledgement IS NOT NULL
  AND delivered_at IS NOT NULL
  AND delivered_at < ?2
  AND enqueue_sequence <= ?4
ORDER BY delivered_at ASC
LIMIT ?3;",
                )
                .map_err(storage)?;
            let rows = select
                .query_map(
                    params![
                        DELIVERED,
                        before,
                        sql_limit(maximum_count),
                        archived_through_sequence
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(storage)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage)
        })
    }

    fn purge_delivered_core(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
        archived_through_sequence: Option<i64>,
    ) -> StoreResult<usize> {
        if !(1..=MAXIMUM_PURGE_COUNT).contains(&maximum_count) {
            return Err(StoreError::Invalid(
                "maximumCount must be between 1 and 100000.".into(),
            ));
        }
        let before = stored(&delivered_before);
        self.pool.with(|connection| {
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.check_storage()?;
            // Only acknowledged rows are eligible. Undelivered, retrying and
            // dead-lettered events are never deleted here, nor (with an archive)
            // events the archive does not hold yet.
            let event_ids = {
                let mut select = transaction
                    .prepare(
                        "SELECT event_id
FROM queue_events_v5
WHERE state = ?1
  AND acknowledgement IS NOT NULL
  AND delivered_at IS NOT NULL
  AND delivered_at < ?2
  AND (?4 IS NULL OR enqueue_sequence <= ?4)
ORDER BY delivered_at ASC
LIMIT ?3;",
                    )
                    .map_err(storage)?;
                let rows = select
                    .query_map(
                        params![
                            DELIVERED,
                            before,
                            sql_limit(maximum_count),
                            archived_through_sequence
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(storage)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(storage)?
            };
            {
                let mut delete = transaction
                    .prepare("DELETE FROM queue_events_v5 WHERE event_id = ?1 AND state = ?2;")
                    .map_err(storage)?;
                for event_id in &event_ids {
                    delete
                        .execute(params![event_id, DELIVERED])
                        .map_err(storage)?;
                }
            }
            // Record the purge in the ledger in the same transaction so
            // verification can tell retention from tampering.
            ledger::mark_purged(&transaction, &event_ids, &self.now_text())?;
            ledger::compact(&transaction, &self.now_text())?;
            transaction.commit().map_err(storage)?;
            Ok(event_ids.len())
        })
    }

    fn transition(
        &self,
        sql: &str,
        event_id: &str,
        extra: &[(&str, &dyn rusqlite::ToSql)],
    ) -> StoreResult<usize> {
        self.pool.with(|connection| {
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.check_storage()?;
            let mut statement = transaction.prepare(sql).map_err(storage)?;
            let mut bound: Vec<(&str, &dyn rusqlite::ToSql)> =
                vec![(":event_id", &event_id), (":uploading", &UPLOADING)];
            bound.extend_from_slice(extra);
            let affected = statement.execute(bound.as_slice()).map_err(storage)?;
            drop(statement);
            transaction.commit().map_err(storage)?;
            Ok(affected)
        })
    }
}

/// Queue schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 5;

/// Read-only check mirroring C# `SqliteEventStore.RefuseNewerSchemaAsync`.
pub(crate) fn refuse_newer_schema(connection: &rusqlite::Connection) -> StoreResult<()> {
    let has_history: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_history');",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if !has_history {
        return Ok(());
    }
    let version: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_history;",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::Invalid(format!(
            "Queue schema version {version} is newer than this Bower build supports ({SCHEMA_VERSION}). \
             The database was not modified. Run the newer Bower version or restore a backup taken before the upgrade."
        )));
    }
    Ok(())
}

fn read_queued(row: &Row<'_>) -> rusqlite::Result<QueuedEvent> {
    let received_at: String = row.get(3)?;
    let state: i64 = row.get(4)?;
    Ok(QueuedEvent {
        event_id: row.get(0)?,
        fingerprint: row.get(1)?,
        payload: row.get(2)?,
        received_at: parse_stored(&received_at, 3)?,
        state: QueueState::from_ordinal(state)
            .ok_or_else(|| rusqlite::Error::IntegralValueOutOfRange(4, state))?,
        delivery_attempts: row.get(5)?,
        lease_token: Some(row.get(6)?),
        suppression: None,
    })
}

impl DurableEventStore for SqliteEventStore {
    fn initialize(&self) -> StoreResult<()> {
        self.pool.with(|connection| {
            // Before any DDL or journal change: never create, migrate or repair tables in a
            // database a newer build has already moved to a schema this one does not know.
            refuse_newer_schema(connection)?;
            let _mode: String = connection
                .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
                .map_err(storage)?;
            let migrated: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='queue_events_v5');", [], |row| row.get(0)
            ).map_err(storage)?;
            if !migrated {
                self.configure_budget(connection)?;
                let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
                self.check_storage()?;
                let already_migrated: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='queue_events_v5');", [], |row| row.get(0)).map_err(storage)?;
                if !already_migrated {
                let has_ledger: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='queue_ledger');", [], |row| row.get(0)).map_err(storage)?;
                transaction.execute_batch(QUEUE_SCHEMA).map_err(storage)?;
                transaction.execute_batch(ledger::SCHEMA).map_err(storage)?;
                transaction.execute_batch(QUEUE_SCHEMA_V4).map_err(storage)?;
                if !has_ledger { ledger::backfill(&transaction)?; }
                transaction.execute_batch(MIGRATION_V5).map_err(storage)?;
                let mut last: Option<String> = None;
                loop {
                    let row = transaction.query_row("SELECT event_id, payload FROM queue_events_v5 WHERE ?1 IS NULL OR event_id > ?1 ORDER BY event_id LIMIT 1;", params![last], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).optional().map_err(storage)?;
                    let Some((id, payload)) = row else { break; };
                    last = Some(id.clone());
                    if let Ok(envelope) = bower_contracts::json::from_str::<bower_contracts::SecurityEventEnvelope>(&payload) {
                        transaction.execute("UPDATE queue_events_v5 SET fingerprint = ?1 WHERE event_id = ?2;", params![crate::event_identity(&envelope), id]).map_err(storage)?;
                    }
                }
                if !ledger::verify_snapshot(&transaction)?.intact { return Err(StoreError::Invalid("Cannot migrate a corrupt queue ledger.".into())); }
                }
                transaction.commit().map_err(storage)?;
            }
            let version: i64 = connection.query_row("SELECT MAX(version) FROM schema_history;", [], |row| row.get(0)).map_err(storage)?;
            if version != SCHEMA_VERSION { return Err(StoreError::Invalid("Unsupported queue schema version.".into())); }
            self.configure_budget(connection)?;
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            self.check_storage()?;
            transaction.execute_batch("CREATE INDEX IF NOT EXISTS ix_queue_events_state_bytes ON queue_events_v5(state, payload_bytes, received_at);").map_err(storage)?;
            // Additive auxiliary tables, created on every start without a schema version.
            transaction.execute_batch(crate::suppression::AUXILIARY_SCHEMA).map_err(storage)?;
            transaction.commit().map_err(storage)

        })?;
        let path = self.pool.path();
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        restrict_permissions(&[path.to_path_buf(), wal, shm])
    }

    fn enqueue(&self, candidate: &QueuedEvent) -> StoreResult<EnqueueResult> {
        // Reject what the NOT NULL and CHECK constraints would refuse, so invalid
        // input is an error and never mistaken for a duplicate.
        validate_candidate(candidate)?;
        self.pool.with(|connection| {
            // BEGIN IMMEDIATE takes the write lock before the duplicate and capacity
            // checks so concurrent enqueues cannot both pass them.
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            // Idempotency wins over backpressure: a re-sent event is a duplicate even
            // when the queue is full. Dropping the read-only transaction rolls back.
            if Self::exists(&transaction, candidate)? {
                return Ok(EnqueueResult {
                    enqueued: false,
                    duplicate: true,
                    event_id: candidate.event_id.clone(),
                    suppressed: false,
                });
            }
            // Suppression is decided under the same write lock, after the duplicate
            // check so a retried event never consumes allowance, and committed with
            // the count it changed.
            if let Some(rule) = &candidate.suppression {
                // A suppressed event commits a counter change, so it needs the same
                // physical budget as an insert; refusing here leaves the counters
                // untouched.
                self.check_storage()?;
                if !crate::suppression::admit(&transaction, rule, &candidate.received_at)? {
                    transaction.commit().map_err(storage)?;
                    return Ok(EnqueueResult {
                        enqueued: false,
                        duplicate: false,
                        event_id: candidate.event_id.clone(),
                        suppressed: true,
                    });
                }
            }
            self.insert(&transaction, candidate)?;
            transaction.commit().map_err(storage)?;
            Ok(EnqueueResult {
                enqueued: true,
                duplicate: false,
                event_id: candidate.event_id.clone(),
                suppressed: false,
            })
        })
    }

    fn lease(
        &self,
        maximum_count: usize,
        lease_duration: Duration,
    ) -> StoreResult<Vec<QueuedEvent>> {
        if !(1..=MAXIMUM_LEASE_COUNT).contains(&maximum_count) {
            return Err(StoreError::Invalid(
                "maximumCount must be between 1 and 10000.".into(),
            ));
        }
        if lease_duration.is_zero() {
            return Err(StoreError::Invalid(
                "leaseDuration must be greater than zero.".into(),
            ));
        }
        let now = time::to_utc(time::truncate_to_ticks(self.clock.utc_now()));
        let until = chrono::Duration::from_std(lease_duration)
            .ok()
            .and_then(|duration| now.checked_add_signed(duration))
            .filter(|value| chrono::Datelike::year(value) <= 9999)
            .ok_or_else(|| StoreError::Invalid("leaseDuration is out of range.".into()))?;
        let now_value = time::format_round_trip(&now);
        let lease_value = stored(&until);

        self.pool.with(|connection| {
            self.configure_budget(connection)?;
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            self.check_storage()?;
            let selected = {
                let mut select = transaction
                    .prepare(
                        "SELECT event_id, fingerprint, payload, received_at, state, delivery_attempts,
CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation + 1 AS TEXT)
FROM queue_events_v5
WHERE (
        state = :queued
        OR (state = :retrying AND (next_attempt_at IS NULL OR next_attempt_at <= :now))
        OR (state = :uploading AND lease_until <= :now)
      )
  AND NOT EXISTS (
      SELECT 1 FROM queue_events AS outage
      WHERE outage.state = :retrying
        AND outage.last_failure_code GLOB 'destination-*'
        AND outage.next_attempt_at > :now)
ORDER BY received_at ASC
LIMIT :maximum_count;",
                    )
                    .map_err(storage)?;
                let rows = select
                    .query_map(
                        named_params! {
                            ":queued": QUEUED,
                            ":retrying": RETRYING,
                            ":uploading": UPLOADING,
                            ":now": now_value,
                            ":maximum_count": sql_limit(maximum_count),
                        },
                        read_queued,
                    )
                    .map_err(storage)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(storage)?
            };
            {
                let mut update = transaction
                    .prepare(
                        "UPDATE queue_events_v5
SET state = ?1,
    lease_until = ?2,
    delivery_attempts = delivery_attempts + 1,
    lease_generation = lease_generation + 1
WHERE event_id = ?3;",
                    )
                    .map_err(storage)?;
                for item in &selected {
                    update.execute(params![UPLOADING, lease_value, item.event_id]).map_err(storage)?;
                }
            }
            transaction.commit().map_err(storage)?;
            Ok(selected
                .into_iter()
                .map(|item| QueuedEvent {
                    state: QueueState::Uploading,
                    delivery_attempts: item.delivery_attempts + 1,
                    ..item
                })
                .collect())
        })
    }

    fn mark_delivered(
        &self,
        event_id: &str,
        acknowledgement: &str,
        lease_token: Option<&str>,
    ) -> StoreResult<()> {
        require_text(event_id, "eventId")?;
        require_text(acknowledgement, "acknowledgement")?;
        let delivered_at = self.now_text();
        let affected = self.transition(
            "UPDATE queue_events_v5
SET state = :delivered,
    acknowledgement = :acknowledgement,
    delivered_at = :delivered_at,
    lease_until = NULL,
    next_attempt_at = NULL,
    last_failure_code = NULL
WHERE event_id = :event_id AND state = :uploading
AND CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) = :lease_token;",
            event_id,
            &[
                (":lease_token", &lease_token),
                (":delivered", &DELIVERED),
                (":acknowledgement", &acknowledgement),
                (":delivered_at", &delivered_at),
            ],
        )?;
        if affected == 1 {
            Ok(())
        } else {
            Err(transition_error(event_id, "uploading", "delivered"))
        }
    }

    fn mark_retrying(
        &self,
        event_id: &str,
        failure_code: &str,
        retry_after: Timestamp,
        lease_token: Option<&str>,
    ) -> StoreResult<()> {
        require_text(event_id, "eventId")?;
        require_text(failure_code, "failureCode")?;
        let next_attempt_at = stored(&retry_after);
        let affected = self.transition(
            "UPDATE queue_events_v5
SET state = :retrying,
    next_attempt_at = :next_attempt_at,
    last_failure_code = :failure_code,
    lease_until = NULL
WHERE event_id = :event_id AND state = :uploading
AND CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) = :lease_token;",
            event_id,
            &[
                (":lease_token", &lease_token),
                (":retrying", &RETRYING),
                (":next_attempt_at", &next_attempt_at),
                (":failure_code", &failure_code),
            ],
        )?;
        if affected == 1 {
            Ok(())
        } else {
            Err(transition_error(event_id, "uploading", "retrying"))
        }
    }

    fn mark_dead_lettered(
        &self,
        event_id: &str,
        failure_code: &str,
        lease_token: Option<&str>,
    ) -> StoreResult<()> {
        require_text(event_id, "eventId")?;
        require_text(failure_code, "failureCode")?;
        let affected = self.transition(
            "UPDATE queue_events_v5
SET state = :dead_lettered,
    last_failure_code = :failure_code,
    lease_until = NULL,
    next_attempt_at = NULL
WHERE event_id = :event_id AND state = :uploading
AND CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) = :lease_token;",
            event_id,
            &[
                (":lease_token", &lease_token),
                (":dead_lettered", &DEAD_LETTERED),
                (":failure_code", &failure_code),
            ],
        )?;
        if affected == 1 {
            Ok(())
        } else {
            Err(transition_error(event_id, "uploading", "dead-lettered"))
        }
    }

    fn mark_delivered_batch(
        &self,
        event_ids: &[String],
        acknowledgement: &str,
        lease_tokens: &std::collections::HashMap<String, String>,
    ) -> StoreResult<Vec<String>> {
        require_text(acknowledgement, "acknowledgement")?;
        for event_id in event_ids {
            require_text(event_id, "eventId")?;
        }
        if event_ids.is_empty() {
            return Ok(Vec::new());
        }
        let delivered_at = self.now_text();
        // One transaction (one WAL commit and sync) for the whole batch. Same guarded
        // transition as `mark_delivered`: only uploading rows change. On error the
        // transaction is dropped and nothing is settled.
        self.pool.with(|connection| {
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.check_storage()?;
            let mut not_leased = Vec::new();
            {
                let mut update = transaction
                    .prepare(
                        "UPDATE queue_events_v5
SET state = :delivered,
    acknowledgement = :acknowledgement,
    delivered_at = :delivered_at,
    lease_until = NULL,
    next_attempt_at = NULL,
    last_failure_code = NULL
WHERE event_id = :event_id AND state = :uploading
AND CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) = :lease_token;",
                    )
                    .map_err(storage)?;
                for event_id in event_ids {
                    let affected = update
                        .execute(named_params! {
                            ":delivered": DELIVERED,
                            ":uploading": UPLOADING,
                            ":acknowledgement": acknowledgement,
                            ":delivered_at": delivered_at,
                            ":event_id": event_id,
                            ":lease_token": lease_tokens.get(event_id).map(String::as_str),
                        })
                        .map_err(storage)?;
                    if affected != 1 {
                        not_leased.push(event_id.clone());
                    }
                }
            }
            transaction.commit().map_err(storage)?;
            Ok(not_leased)
        })
    }

    fn mark_failed_batch(&self, failures: &[FailureSettlement]) -> StoreResult<Vec<String>> {
        for failure in failures {
            require_text(&failure.event_id, "eventId")?;
            require_text(&failure.failure_code, "failureCode")?;
        }
        if failures.is_empty() {
            return Ok(Vec::new());
        }
        // One transaction for every failure in the batch, with the same guarded
        // transitions as `mark_retrying` and `mark_dead_lettered`. Any error drops the
        // transaction, so the events stay leased and are redelivered after the lease
        // expires.
        self.pool.with(|connection| {
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.check_storage()?;
            let mut not_leased = Vec::new();
            {
                let mut retry = transaction
                    .prepare(
                        "UPDATE queue_events_v5
SET state = :retrying,
    next_attempt_at = :next_attempt_at,
    delivery_attempts = MAX(0, delivery_attempts - CASE WHEN :failure_code GLOB 'destination-*' THEN 1 ELSE 0 END),
    last_failure_code = :failure_code,
    lease_until = NULL
WHERE event_id = :event_id AND state = :uploading
AND CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) = :lease_token;",
                    )
                    .map_err(storage)?;
                let mut dead_letter = transaction
                    .prepare(
                        "UPDATE queue_events_v5
SET state = :dead_lettered,
    last_failure_code = :failure_code,
    lease_until = NULL,
    next_attempt_at = NULL
WHERE event_id = :event_id AND state = :uploading
AND CAST(enqueue_sequence AS TEXT) || ':' || CAST(lease_generation AS TEXT) = :lease_token;",
                    )
                    .map_err(storage)?;
                for failure in failures {
                    let affected = match &failure.retry_after {
                        Some(retry_after) => retry.execute(named_params! {
                            ":retrying": RETRYING,
                            ":uploading": UPLOADING,
                            ":next_attempt_at": stored(retry_after),
                            ":failure_code": failure.failure_code,
                            ":event_id": failure.event_id,
                            ":lease_token": failure.lease_token,
                        }),
                        None => dead_letter.execute(named_params! {
                            ":dead_lettered": DEAD_LETTERED,
                            ":uploading": UPLOADING,
                            ":failure_code": failure.failure_code,
                            ":event_id": failure.event_id,
                            ":lease_token": failure.lease_token,
                        }),
                    }
                    .map_err(storage)?;
                    if affected != 1 {
                        not_leased.push(failure.event_id.clone());
                    }
                }
            }
            transaction.commit().map_err(storage)?;
            Ok(not_leased)
        })
    }

    fn snapshot(&self) -> StoreResult<QueueSnapshot> {
        self.pool.with(|connection| {
            connection
                .query_row(
                    "SELECT
    SUM(CASE WHEN state = 0 THEN 1 ELSE 0 END),
    SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END),
    SUM(CASE WHEN state = 1 THEN 1 ELSE 0 END),
    SUM(CASE WHEN state = 3 THEN 1 ELSE 0 END),
    SUM(CASE WHEN state = 4 THEN 1 ELSE 0 END),
    COALESCE(SUM(payload_bytes), 0),
    MIN(CASE WHEN state IN (0, 1, 2) THEN received_at END),
    COALESCE(SUM(CASE WHEN state <> 3 THEN payload_bytes ELSE 0 END), 0)
FROM queue_events_v5;",
                    [],
                    |row| {
                        let count = |index: usize| {
                            row.get::<_, Option<i64>>(index)
                                .map(Option::unwrap_or_default)
                        };
                        let oldest = row
                            .get::<_, Option<String>>(6)?
                            .map(|text| parse_stored(&text, 6))
                            .transpose()?;
                        Ok(QueueSnapshot {
                            queued: count(0)?,
                            retrying: count(1)?,
                            uploading: count(2)?,
                            delivered: count(3)?,
                            dead_lettered: count(4)?,
                            total_bytes: count(5)?,
                            oldest_undelivered: oldest,
                            undelivered_bytes: count(7)?,
                        })
                    },
                )
                .map_err(storage)
        })
    }

    fn purge_delivered(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
    ) -> StoreResult<usize> {
        self.purge_delivered_core(delivered_before, maximum_count, None)
    }

    fn purge_delivered_archived(
        &self,
        delivered_before: Timestamp,
        maximum_count: usize,
        archived_through_sequence: i64,
    ) -> StoreResult<usize> {
        self.purge_delivered_core(
            delivered_before,
            maximum_count,
            Some(archived_through_sequence),
        )
    }

    fn close_expired_suppression_windows(
        &self,
        now: Timestamp,
        create_summary: &mut dyn FnMut(&SuppressionWindow) -> StoreResult<QueuedEvent>,
    ) -> StoreResult<usize> {
        crate::suppression::close_expired(self, now, create_summary)
    }

    fn get_source_activity(&self) -> StoreResult<Vec<SourceActivity>> {
        crate::suppression::get_source_activity(self)
    }

    fn upsert_source_activity(&self, activity: &[SourceActivity]) -> StoreResult<()> {
        crate::suppression::upsert_source_activity(self, activity)
    }

    fn get_source_monitoring(&self) -> StoreResult<Vec<SourceMonitoring>> {
        crate::suppression::get_source_monitoring(self)
    }

    fn start_source_monitoring(
        &self,
        expected: &[SourceMonitoring],
    ) -> StoreResult<Vec<SourceMonitoring>> {
        crate::suppression::start_source_monitoring(self, expected)
    }

    fn maintain(&self) -> StoreResult<()> {
        self.pool.with(|connection| {
            connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |_| Ok(()))
                .optional()
                .map_err(storage)?;
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.check_storage()?;
            transaction
                .execute_batch("PRAGMA optimize;")
                .map_err(storage)?;
            transaction.commit().map_err(storage)
        })
    }

    fn list_dead_lettered(&self, maximum_count: usize) -> StoreResult<Vec<DeadLetterRecord>> {
        if maximum_count < 1 {
            return Err(StoreError::Invalid(
                "maximumCount must be at least 1.".into(),
            ));
        }
        self.pool.with(|connection| {
            let mut select = connection
                .prepare(
                    "SELECT event_id, last_failure_code, delivery_attempts, received_at
FROM queue_events_v5
WHERE state = ?1
ORDER BY received_at ASC
LIMIT ?2;",
                )
                .map_err(storage)?;
            let rows = select
                .query_map(params![DEAD_LETTERED, sql_limit(maximum_count)], |row| {
                    let received_at: String = row.get(3)?;
                    Ok(DeadLetterRecord {
                        event_id: row.get(0)?,
                        failure_code: row.get(1)?,
                        delivery_attempts: row.get(2)?,
                        received_at: parse_stored(&received_at, 3)?,
                    })
                })
                .map_err(storage)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage)
        })
    }

    fn replay_dead_lettered(
        &self,
        failure_code_prefix: Option<&str>,
        event_ids: Option<&[String]>,
        maximum_count: usize,
    ) -> StoreResult<usize> {
        if maximum_count < 1 {
            return Err(StoreError::Invalid(
                "maximumCount must be at least 1.".into(),
            ));
        }
        let prefix = failure_code_prefix.filter(|value| !is_blank(value));
        let ids: Option<HashSet<&str>> =
            event_ids.map(|ids| ids.iter().map(String::as_str).collect());
        let id_filter = ids.as_ref().filter(|ids| !ids.is_empty());
        if prefix.is_none() && id_filter.is_none() {
            return Ok(0);
        }
        self.pool.with(|connection| {
            self.configure_budget(connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.check_storage()?;
            let mut selected = Vec::new();
            {
                let mut select = transaction
                    .prepare(
                        "SELECT event_id, last_failure_code FROM queue_events_v5
WHERE state = ?1
ORDER BY received_at ASC;",
                    )
                    .map_err(storage)?;
                let mut rows = select.query(params![DEAD_LETTERED]).map_err(storage)?;
                while selected.len() < maximum_count {
                    let Some(row) = rows.next().map_err(storage)? else {
                        break;
                    };
                    let event_id: String = row.get(0).map_err(storage)?;
                    let code: Option<String> = row.get(1).map_err(storage)?;
                    let id_match = id_filter.is_none_or(|ids| ids.contains(event_id.as_str()));
                    let code_match = prefix.is_none_or(|prefix| {
                        code.as_deref().unwrap_or_default().starts_with(prefix)
                    });
                    if id_match && code_match {
                        selected.push(event_id);
                    }
                }
            }
            {
                let mut update = transaction
                    .prepare(
                        "UPDATE queue_events_v5
SET state = ?1, delivery_attempts = 0, next_attempt_at = NULL, lease_until = NULL
WHERE event_id = ?2 AND state = ?3;",
                    )
                    .map_err(storage)?;
                for event_id in &selected {
                    update
                        .execute(params![QUEUED, event_id, DEAD_LETTERED])
                        .map_err(storage)?;
                }
            }
            transaction.commit().map_err(storage)?;
            Ok(selected.len())
        })
    }

    fn ledger_head(&self) -> StoreResult<LedgerHead> {
        self.pool.with(|connection| {
            let (sequence, hash) = ledger::head(connection)?;
            Ok(LedgerHead { sequence, hash })
        })
    }

    fn verify_ledger(&self) -> StoreResult<LedgerVerification> {
        self.pool.with(ledger::verify)
    }
}

const MIGRATION_V5: &str = r#"
            ALTER TABLE queue_events RENAME TO queue_events_v5;
            ALTER TABLE queue_events_v5 ADD COLUMN enqueue_sequence INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE queue_events_v5 ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0;
            UPDATE queue_events_v5 SET enqueue_sequence = (
                SELECT MAX(sequence) FROM queue_ledger l
                WHERE l.event_id = queue_events_v5.event_id AND l.purged_at IS NULL);
            CREATE UNIQUE INDEX ix_queue_events_incarnation ON queue_events_v5(enqueue_sequence);
            CREATE VIEW queue_events AS SELECT event_id, fingerprint, payload, payload_bytes,
                received_at, state, delivery_attempts, lease_until, next_attempt_at,
                last_failure_code, acknowledgement, delivered_at FROM queue_events_v5;
            CREATE TABLE IF NOT EXISTS queue_ledger_segments (
                start_sequence INTEGER PRIMARY KEY NOT NULL,
                end_sequence INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                checkpoint_hash TEXT NOT NULL,
                CHECK(end_sequence >= start_sequence)
            );
            INSERT INTO schema_history(version, applied_at, hash)
            VALUES (5, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v5-fencing-segments');
            "#;

/// Payload content that decides duplicate versus identity conflict: collector,
/// security and `timeObserved` removed, `eventId` removed when an original id
/// exists, keys sorted. Shared with hosts that mirror the queue's identity rules.
pub fn replay_content(payload: &str) -> String {
    use bower_contracts::JsonElement;
    fn sort(value: &mut JsonElement) {
        match value {
            JsonElement::Object(properties) => {
                properties.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
                for (_, value) in properties {
                    sort(value);
                }
            }
            JsonElement::Array(items) => {
                for value in items {
                    sort(value);
                }
            }
            _ => {}
        }
    }
    let Ok(mut value) = JsonElement::parse(payload) else {
        return payload.to_owned();
    };
    let envelope = value.get("schemaVersion").is_some() && value.get("eventType").is_some();
    let original = match &value {
        JsonElement::Object(properties) => properties
            .iter()
            .rev()
            .find(|(key, _)| key == "eventOriginalId")
            .and_then(|(_, value)| value.as_str())
            .is_some_and(|id| !id.is_empty()),
        _ => false,
    };
    if envelope && let JsonElement::Object(properties) = &mut value {
        for (key, value) in properties.iter_mut() {
            if key == "attributes"
                && let JsonElement::Object(attributes) = value
            {
                attributes.retain(|(name, _)| !name.eq_ignore_ascii_case("bowerDetections"));
            }
        }
        properties.retain(|(key, value)| {
            if key == "attributes"
                && (matches!(value, JsonElement::Null)
                    || matches!(value, JsonElement::Object(attributes) if attributes.is_empty()))
            {
                return false;
            }
            !matches!(key.as_str(), "collector" | "security" | "timeObserved")
                && !(original && key == "eventId")
        });
    }
    sort(&mut value);
    bower_contracts::json::to_string(&value).unwrap_or_else(|_| payload.to_owned())
}
