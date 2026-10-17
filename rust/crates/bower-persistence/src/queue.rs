//! Durable SQLite event queue (C# `SqliteEventStore`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::{self, Timestamp};
use bower_contracts::{
    DeadLetterRecord, DurableEventStore, EnqueueResult, LedgerHead, LedgerVerification,
    QueueSnapshot, QueueState, QueuedEvent, StoreError, StoreResult,
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

/// Connection-scoped settings applied to every pooled connection.
const CONNECTION_PRAGMAS: &str = "PRAGMA busy_timeout = 5000;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;";

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
fn stored(value: &Timestamp) -> String {
    time::format_round_trip(&time::to_utc(time::truncate_to_ticks(*value)))
}

fn parse_stored(text: &str, column: usize) -> rusqlite::Result<Timestamp> {
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
FROM queue_events
WHERE state IN (?1, ?2, ?3, ?4);",
                params![QUEUED, UPLOADING, RETRYING, DEAD_LETTERED],
                |row| row.get(0),
            )
            .map_err(storage)
    }

    fn transition(
        &self,
        sql: &str,
        event_id: &str,
        extra: &[(&str, &dyn rusqlite::ToSql)],
    ) -> StoreResult<usize> {
        self.pool.with(|connection| {
            let mut statement = connection.prepare(sql).map_err(storage)?;
            let mut bound: Vec<(&str, &dyn rusqlite::ToSql)> =
                vec![(":event_id", &event_id), (":uploading", &UPLOADING)];
            bound.extend_from_slice(extra);
            statement.execute(bound.as_slice()).map_err(storage)
        })
    }
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
    })
}

impl DurableEventStore for SqliteEventStore {
    fn initialize(&self) -> StoreResult<()> {
        self.pool.with(|connection| {
            let _mode: String = connection
                .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
                .map_err(storage)?;
            connection.execute_batch(QUEUE_SCHEMA).map_err(storage)?;
            connection.execute_batch(ledger::SCHEMA).map_err(storage)?;
            connection.execute_batch(QUEUE_SCHEMA_V4).map_err(storage)?;
            ledger::backfill(connection)
        })?;
        let path = self.pool.path();
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        restrict_permissions(&[path.to_path_buf(), wal, shm])
    }

    fn enqueue(&self, candidate: &QueuedEvent) -> StoreResult<EnqueueResult> {
        let payload_bytes = i64::try_from(candidate.payload.len()).unwrap_or(i64::MAX);
        let received_at = stored(&candidate.received_at);
        self.pool.with(|connection| {
            // BEGIN IMMEDIATE takes the write lock before the capacity check so
            // concurrent enqueues cannot both pass the check and overshoot.
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let current = Self::undelivered_bytes(&transaction)?;
            if current.saturating_add(payload_bytes) > self.maximum_bytes {
                return Err(capacity_error(self.maximum_bytes, current, payload_bytes));
            }
            // OR IGNORE: duplicate event id or fingerprint keeps the original row.
            let affected = transaction
                .execute(
                    "INSERT OR IGNORE INTO queue_events (
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
            if affected == 1 {
                ledger::append(
                    &transaction,
                    &candidate.event_id,
                    &candidate.payload,
                    &received_at,
                )?;
            }
            transaction.commit().map_err(storage)?;
            Ok(EnqueueResult {
                enqueued: affected == 1,
                duplicate: affected == 0,
                event_id: candidate.event_id.clone(),
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
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let selected = {
                let mut select = transaction
                    .prepare(
                        "SELECT event_id, fingerprint, payload, received_at, state, delivery_attempts
FROM queue_events
WHERE (
        state = :queued
        OR (state = :retrying AND (next_attempt_at IS NULL OR next_attempt_at <= :now))
        OR (state = :uploading AND lease_until <= :now)
      )
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
                        "UPDATE queue_events
SET state = ?1,
    lease_until = ?2,
    delivery_attempts = delivery_attempts + 1
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

    fn mark_delivered(&self, event_id: &str, acknowledgement: &str) -> StoreResult<()> {
        require_text(event_id, "eventId")?;
        require_text(acknowledgement, "acknowledgement")?;
        let delivered_at = self.now_text();
        let affected = self.transition(
            "UPDATE queue_events
SET state = :delivered,
    acknowledgement = :acknowledgement,
    delivered_at = :delivered_at,
    lease_until = NULL,
    next_attempt_at = NULL,
    last_failure_code = NULL
WHERE event_id = :event_id AND state = :uploading;",
            event_id,
            &[
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
    ) -> StoreResult<()> {
        require_text(event_id, "eventId")?;
        require_text(failure_code, "failureCode")?;
        let next_attempt_at = stored(&retry_after);
        let affected = self.transition(
            "UPDATE queue_events
SET state = :retrying,
    next_attempt_at = :next_attempt_at,
    last_failure_code = :failure_code,
    lease_until = NULL
WHERE event_id = :event_id AND state = :uploading;",
            event_id,
            &[
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

    fn mark_dead_lettered(&self, event_id: &str, failure_code: &str) -> StoreResult<()> {
        require_text(event_id, "eventId")?;
        require_text(failure_code, "failureCode")?;
        let affected = self.transition(
            "UPDATE queue_events
SET state = :dead_lettered,
    last_failure_code = :failure_code,
    lease_until = NULL,
    next_attempt_at = NULL
WHERE event_id = :event_id AND state = :uploading;",
            event_id,
            &[
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
FROM queue_events;",
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
        if !(1..=MAXIMUM_PURGE_COUNT).contains(&maximum_count) {
            return Err(StoreError::Invalid(
                "maximumCount must be between 1 and 100000.".into(),
            ));
        }
        let before = stored(&delivered_before);
        self.pool.with(|connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            // Only acknowledged rows are eligible. Undelivered, retrying and
            // dead-lettered events are never deleted here.
            let event_ids = {
                let mut select = transaction
                    .prepare(
                        "SELECT event_id
FROM queue_events
WHERE state = ?1
  AND acknowledgement IS NOT NULL
  AND delivered_at IS NOT NULL
  AND delivered_at < ?2
ORDER BY delivered_at ASC
LIMIT ?3;",
                    )
                    .map_err(storage)?;
                let rows = select
                    .query_map(
                        params![DELIVERED, before, sql_limit(maximum_count)],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(storage)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(storage)?
            };
            {
                let mut delete = transaction
                    .prepare("DELETE FROM queue_events WHERE event_id = ?1 AND state = ?2;")
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
            transaction.commit().map_err(storage)?;
            ledger::compact(connection, &self.now_text())?;
            Ok(event_ids.len())
        })
    }

    fn maintain(&self) -> StoreResult<()> {
        self.pool.with(|connection| {
            connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |_| Ok(()))
                .optional()
                .map_err(storage)?;
            connection
                .execute_batch("PRAGMA optimize;")
                .map_err(storage)
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
FROM queue_events
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
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let mut selected = Vec::new();
            {
                let mut select = transaction
                    .prepare(
                        "SELECT event_id, last_failure_code FROM queue_events
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
                        "UPDATE queue_events
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
