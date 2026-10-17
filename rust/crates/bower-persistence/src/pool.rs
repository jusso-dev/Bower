//! Small connection pool mirroring Microsoft.Data.Sqlite pooling: each call
//! borrows a private-cache connection with connection-scoped PRAGMAs applied.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bower_contracts::{StoreError, StoreResult};
use rusqlite::{Connection, OpenFlags};

const MAXIMUM_IDLE: usize = 16;

pub(crate) struct ConnectionPool {
    path: PathBuf,
    pragmas: &'static str,
    idle: Mutex<Vec<Connection>>,
}

impl ConnectionPool {
    pub(crate) fn new(path: PathBuf, pragmas: &'static str) -> Self {
        Self {
            path,
            pragmas,
            idle: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn open(&self) -> StoreResult<Connection> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(&self.path, flags).map_err(storage)?;
        connection.execute_batch(self.pragmas).map_err(storage)?;
        Ok(connection)
    }

    /// Runs `work` on a pooled connection. A connection is only returned to the
    /// pool after success with no open transaction; failures discard it.
    pub(crate) fn with<T>(
        &self,
        work: impl FnOnce(&mut Connection) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let pooled = self
            .idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .pop();
        let mut connection = match pooled {
            Some(connection) => connection,
            None => self.open()?,
        };
        let result = work(&mut connection);
        if result.is_ok() && connection.is_autocommit() {
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if idle.len() < MAXIMUM_IDLE {
                idle.push(connection);
            }
        }
        result
    }

    /// Closes idle connections (C# `SqliteConnection.ClearAllPools`).
    pub(crate) fn clear(&self) {
        self.idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }
}

pub(crate) fn storage(error: rusqlite::Error) -> StoreError {
    // rusqlite messages carry SQLite codes and constraint names, never bound values.
    StoreError::Storage(error.to_string())
}

#[cfg(unix)]
pub(crate) fn restrict_permissions(paths: &[PathBuf]) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    for path in paths {
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| StoreError::Storage(format!("cannot restrict permissions: {error}")),
            )?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_permissions(_paths: &[PathBuf]) -> StoreResult<()> {
    Ok(())
}

/// `Path.GetFullPath` plus `Directory.CreateDirectory` for the parent.
pub(crate) fn prepare_path(database_path: &Path) -> StoreResult<PathBuf> {
    if database_path
        .as_os_str()
        .to_string_lossy()
        .trim()
        .is_empty()
    {
        return Err(StoreError::Invalid("databasePath cannot be empty.".into()));
    }
    let full = std::path::absolute(database_path)
        .map_err(|error| StoreError::Invalid(format!("invalid database path: {error}")))?;
    if let Some(directory) = full
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(directory).map_err(|error| {
            StoreError::Storage(format!("cannot create database directory: {error}"))
        })?;
    }
    Ok(full)
}

pub(crate) fn is_blank(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

pub(crate) fn require_text(value: &str, name: &str) -> StoreResult<()> {
    if is_blank(value) {
        Err(StoreError::Invalid(format!(
            "{name} cannot be empty or whitespace."
        )))
    } else {
        Ok(())
    }
}
