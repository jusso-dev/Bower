//! Source cursor checkpoints (C# `EfSourceCursorStore`).
//!
//! The C# store (Microsoft.Data.Sqlite since EF Core was removed for Native AOT)
//! keeps the DDL and `DateTimeOffset` text EF Core created; this mirrors it so
//! either implementation can open the other's database.

use std::path::{Path, PathBuf};

use bower_contracts::time::{self, Timestamp};
use bower_contracts::{SourceCursorSnapshot, SourceCursorStore, StoreError, StoreResult};
use chrono::Timelike;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::pool::{ConnectionPool, prepare_path, require_text, restrict_permissions, storage};

/// C# opens with `Default Timeout=5` (busy retry) and no other connection PRAGMAs.
const CONNECTION_PRAGMAS: &str = "PRAGMA busy_timeout = 5000;";

/// C# `CreateTableSql`: the DDL EF Core 10 `EnsureCreated` emitted for
/// `SourceCursorDbContext` (key first, then CLR declaration order), made
/// idempotent. SQLite drops `IF NOT EXISTS` from `sqlite_master.sql`, so the
/// stored schema matches `tests/fixtures/csharp-cursors.db`.
const CURSOR_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS \"source_cursors\" (
    \"SourceId\" TEXT NOT NULL CONSTRAINT \"PK_source_cursors\" PRIMARY KEY,
    \"Value\" TEXT NOT NULL,
    \"Version\" INTEGER NOT NULL,
    \"UpdatedAt\" TEXT NOT NULL
);";

const MAXIMUM_SOURCE_ID_LENGTH: usize = 128;

/// EF Core SQLite `DateTimeOffset` text: `yyyy-MM-dd HH:mm:ss.FFFFFFFzzz`
/// (trailing zero fraction digits trimmed, dot omitted for whole seconds).
pub fn format_ef_date_time_offset(value: &Timestamp) -> String {
    let value = time::truncate_to_ticks(*value);
    let mut text = value.format("%Y-%m-%d %H:%M:%S").to_string();
    let ticks = value.nanosecond() / 100;
    if ticks != 0 {
        text.push('.');
        text.push_str(format!("{ticks:07}").trim_end_matches('0'));
    }
    text.push_str(&value.format("%:z").to_string());
    text
}

fn validate_source_id(source_id: &str) -> StoreResult<()> {
    require_text(source_id, "sourceId")?;
    // .NET string length counts UTF-16 code units.
    if source_id.encode_utf16().count() > MAXIMUM_SOURCE_ID_LENGTH {
        return Err(StoreError::Invalid(
            "Source identifier cannot exceed 128 characters.".into(),
        ));
    }
    Ok(())
}

/// Optimistic-concurrency cursor store over the `source_cursors` table.
pub struct SqliteSourceCursorStore {
    pool: ConnectionPool,
}

impl std::fmt::Debug for SqliteSourceCursorStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteSourceCursorStore")
            .field("database_path", &self.pool.path())
            .finish()
    }
}

impl SqliteSourceCursorStore {
    pub fn new(database_path: impl AsRef<Path>) -> StoreResult<Self> {
        let full_path = prepare_path(database_path.as_ref())?;
        Ok(Self {
            pool: ConnectionPool::new(full_path, CONNECTION_PRAGMAS),
        })
    }

    pub fn database_path(&self) -> &Path {
        self.pool.path()
    }

    /// Closes idle pooled connections; the last close checkpoints the WAL.
    pub fn close_idle_connections(&self) {
        self.pool.clear();
    }

    /// C# `InitializeAsync`: a new file is switched to WAL (as EF Core did), then
    /// `CREATE TABLE IF NOT EXISTS` runs on every start, so an existing file that
    /// lacks the table (for example one holding unrelated tables) gets it.
    pub fn initialize(&self) -> StoreResult<()> {
        let created = !self.pool.path().exists();
        self.pool.with(|connection| {
            // The cursor table shares the queue database: never add it to a newer queue schema.
            crate::queue::refuse_newer_schema(connection)?;
            if created {
                let _mode: String = connection
                    .query_row("PRAGMA journal_mode = 'wal';", [], |row| row.get(0))
                    .map_err(storage)?;
            }
            connection.execute_batch(CURSOR_SCHEMA).map_err(storage)
        })?;
        restrict_permissions(&[PathBuf::from(self.pool.path())])
    }
}

impl SourceCursorStore for SqliteSourceCursorStore {
    fn read(&self, source_id: &str) -> StoreResult<Option<SourceCursorSnapshot>> {
        validate_source_id(source_id)?;
        self.pool.with(|connection| {
            connection
                .query_row(
                    "SELECT \"Value\", \"Version\" FROM \"source_cursors\" WHERE \"SourceId\" = ?1 LIMIT 2;",
                    params![source_id],
                    |row| Ok(SourceCursorSnapshot { value: row.get(0)?, version: row.get(1)? }),
                )
                .optional()
                .map_err(storage)
        })
    }

    fn try_advance(
        &self,
        source_id: &str,
        expected_version: i64,
        value: &str,
        updated_at: Timestamp,
    ) -> StoreResult<bool> {
        validate_source_id(source_id)?;
        require_text(value, "value")?;
        if expected_version < 0 {
            return Err(StoreError::Invalid(
                "expectedVersion cannot be negative.".into(),
            ));
        }
        let updated_text = format_ef_date_time_offset(&time::to_utc(updated_at));
        self.pool.with(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let current: Option<i64> = transaction
                .query_row(
                    "SELECT \"Version\" FROM \"source_cursors\" WHERE \"SourceId\" = ?1;",
                    params![source_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            // Any failed write (constraint, concurrent creator) and a version
            // predicate that matched nothing are a lost race: `false`, matching the
            // C# `SqliteException` handler.
            let written = match current {
                None if expected_version != 0 => return Ok(false),
                None => transaction.execute(
                    "INSERT INTO \"source_cursors\" (\"SourceId\", \"Value\", \"Version\", \"UpdatedAt\") VALUES (?1, ?2, 1, ?3);",
                    params![source_id, value, updated_text],
                ),
                Some(version) if version != expected_version => return Ok(false),
                Some(version) => transaction.execute(
                    "UPDATE \"source_cursors\" SET \"Value\" = ?1, \"Version\" = ?2, \"UpdatedAt\" = ?3 WHERE \"SourceId\" = ?4 AND \"Version\" = ?5;",
                    params![value, version + 1, updated_text, source_id, version],
                ),
            };
            match written {
                Ok(1) => {
                    transaction.commit().map_err(storage)?;
                    Ok(true)
                }
                Ok(_) | Err(_) => Ok(false),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ef_format_trims_fraction() {
        let whole = time::parse("2026-07-26T02:14:19Z").unwrap();
        assert_eq!(
            format_ef_date_time_offset(&whole),
            "2026-07-26 02:14:19+00:00"
        );
        let fraction = time::parse("2026-07-26T02:14:19.1234500+10:00").unwrap();
        assert_eq!(
            format_ef_date_time_offset(&fraction),
            "2026-07-26 02:14:19.12345+10:00"
        );
    }

    #[test]
    fn source_id_length_counts_utf16_units() {
        assert!(validate_source_id(&"a".repeat(128)).is_ok());
        assert!(validate_source_id(&"a".repeat(129)).is_err());
        assert!(validate_source_id(&"\u{1F600}".repeat(65)).is_err());
        assert!(validate_source_id(" ").is_err());
    }
}
