//! `bower queue inspect|dead-letters|replay|verify` (C# `InspectQueueAsync`,
//! `QueueCommands`). Metadata only: payloads are never read or printed.

use std::path::Path;

use bower_contracts::{
    DeadLetterRecord, DurableEventStore, LedgerVerification, QueueSnapshot, StoreError,
};
use bower_persistence::SqliteEventStore;

use crate::cli::{DatabaseArgs, DeadLettersArgs, QueueVerifyArgs, ReplayArgs};
use crate::output::{Json, pad};
use crate::support::{
    CliError, CliResult, QUEUE_MAXIMUM_BYTES, default_database, int_or, parse_long,
};

pub fn store_error(error: StoreError) -> CliError {
    match error {
        StoreError::Storage(message) | StoreError::Full(message) | StoreError::Invalid(message) => {
            CliError(message)
        }
    }
}

/// Opens (creating if needed) and initialises the store, like `new SqliteEventStore` + `InitializeAsync`.
pub fn open_store(path: &str) -> CliResult<SqliteEventStore> {
    if path.trim().is_empty() {
        // `ArgumentException.ThrowIfNullOrWhiteSpace(databasePath)` text.
        return Err(CliError::new(
            "The value cannot be an empty string or composed entirely of whitespace. (Parameter 'databasePath')",
        ));
    }
    let store = SqliteEventStore::new(path, QUEUE_MAXIMUM_BYTES, None).map_err(store_error)?;
    store.initialize().map_err(store_error)?;
    Ok(store)
}

/// `QueueCommands.OpenAsync`: the database must already exist.
fn open_existing(args: &DatabaseArgs) -> CliResult<SqliteEventStore> {
    let path = args.database.clone().unwrap_or_else(default_database);
    if !Path::new(&path).is_file() {
        return Err(CliError(format!("Queue database not found: {path}")));
    }
    open_store(&path)
}

fn count(value: i32) -> usize {
    usize::try_from(value).unwrap_or(0)
}

pub fn snapshot_json(snapshot: &QueueSnapshot) -> Json {
    Json::object([
        ("Queued", Json::Int(snapshot.queued)),
        ("Retrying", Json::Int(snapshot.retrying)),
        ("Uploading", Json::Int(snapshot.uploading)),
        ("Delivered", Json::Int(snapshot.delivered)),
        ("DeadLettered", Json::Int(snapshot.dead_lettered)),
        ("TotalBytes", Json::Int(snapshot.total_bytes)),
        (
            "OldestUndelivered",
            snapshot.oldest_undelivered.map_or(Json::Null, Json::Time),
        ),
        ("UndeliveredBytes", Json::Int(snapshot.undelivered_bytes)),
    ])
}

pub fn dead_letters_json(records: &[DeadLetterRecord]) -> Json {
    Json::Array(
        records
            .iter()
            .map(|record| {
                Json::object([
                    ("EventId", Json::str(record.event_id.clone())),
                    ("FailureCode", Json::opt_str(record.failure_code.clone())),
                    (
                        "DeliveryAttempts",
                        Json::Int(i64::from(record.delivery_attempts)),
                    ),
                    ("ReceivedAt", Json::Time(record.received_at)),
                ])
            })
            .collect(),
    )
}

/// `bower queue inspect [--database PATH]`. Like C#, creates the database if absent.
pub fn inspect(args: &DatabaseArgs) -> CliResult {
    let path = args.database.clone().unwrap_or_else(default_database);
    let store = open_store(&path)?;
    let snapshot = store.snapshot().map_err(store_error)?;
    println!("{}", snapshot_json(&snapshot).to_indented());
    Ok(0)
}

/// `bower queue dead-letters --database FILE [--max N]`.
pub fn dead_letters(args: &DeadLettersArgs) -> CliResult {
    let store = open_existing(&args.database)?;
    let maximum = int_or(args.max.as_deref(), 100)?;
    let records = store
        .list_dead_lettered(count(maximum))
        .map_err(store_error)?;
    println!("{}", dead_letters_json(&records).to_indented());
    Ok(0)
}

/// `bower queue replay --database FILE (--code PREFIX | --event ID ...) [--max N]`.
pub fn replay(args: &ReplayArgs) -> CliResult {
    if args.code.is_none() && args.events.is_empty() {
        return Err(CliError::new(
            "Choose what to replay with --code PREFIX or --event ID.",
        ));
    }
    let store = open_existing(&args.database)?;
    let maximum = int_or(args.max.as_deref(), 1000)?;
    let replayed = store
        .replay_dead_lettered(args.code.as_deref(), Some(&args.events), count(maximum))
        .map_err(store_error)?;
    println!("Returned {replayed} dead-lettered event(s) to the queue.");
    Ok(0)
}

/// Lines printed by `queue verify` plus whether the ledger and witnessed head pass.
pub fn verify_report(
    result: &LedgerVerification,
    expect_head: Option<&str>,
) -> CliResult<(Vec<String>, bool)> {
    let mut lines = vec![format!(
        "Ledger entries: {}; head {}:{}",
        result.entries, result.head_sequence, result.head_hash
    )];
    for issue in result.issues.iter().take(50) {
        lines.push(format!(
            "  {} seq {} {} {}",
            pad(&issue.code, 18),
            pad(&issue.sequence.to_string(), 8),
            issue.event_id,
            issue.detail
        ));
    }

    let mut head_ok = true;
    if let Some(expected) = expect_head {
        let (sequence_text, hash) = match expected.split_once(':') {
            Some((sequence, hash)) => (sequence, Some(hash)),
            None => (expected, None),
        };
        let sequence = parse_long(sequence_text)?;
        head_ok = result.head_sequence > sequence
            || (result.head_sequence == sequence && hash == Some(result.head_hash.as_str()));
        if !head_ok {
            lines.push(
                "  head-regression    The ledger is behind or differs from the witnessed head."
                    .to_owned(),
            );
        }
    }

    let passed = result.intact && head_ok;
    lines.push(
        if passed {
            "Ledger intact."
        } else {
            "Ledger verification FAILED."
        }
        .to_owned(),
    );
    Ok((lines, passed))
}

/// `bower queue verify --database FILE [--expect-head SEQUENCE:HASH]`.
pub fn verify(args: &QueueVerifyArgs) -> CliResult {
    let store = open_existing(&args.database)?;
    let result = store.verify_ledger().map_err(store_error)?;
    let (lines, passed) = verify_report(&result, args.expect_head.as_deref())?;
    for line in lines {
        println!("{line}");
    }
    Ok(if passed { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bower_contracts::LedgerIssue;

    fn ledger(intact: bool) -> LedgerVerification {
        LedgerVerification {
            intact,
            entries: 3,
            head_sequence: 3,
            head_hash: "abc".to_owned(),
            issues: if intact {
                vec![]
            } else {
                vec![LedgerIssue {
                    sequence: 2,
                    event_id: "e2".to_owned(),
                    code: "hash-mismatch".to_owned(),
                    detail: "Stored hash differs.".to_owned(),
                }]
            },
        }
    }

    #[test]
    fn verify_formats_like_csharp() {
        let (lines, passed) = verify_report(&ledger(false), None).unwrap();
        assert!(!passed);
        assert_eq!(lines[0], "Ledger entries: 3; head 3:abc");
        assert_eq!(
            lines[1],
            "  hash-mismatch      seq 2        e2 Stored hash differs."
        );
        assert_eq!(lines[2], "Ledger verification FAILED.");
    }

    #[test]
    fn expect_head_detects_regression() {
        assert!(verify_report(&ledger(true), Some("3:abc")).unwrap().1);
        assert!(verify_report(&ledger(true), Some("2")).unwrap().1);
        let (lines, passed) = verify_report(&ledger(true), Some("3:other")).unwrap();
        assert!(!passed);
        assert!(lines.iter().any(|line| line.contains("head-regression")));
        assert!(!verify_report(&ledger(true), Some("4:abc")).unwrap().1);
        assert_eq!(
            verify_report(&ledger(true), Some("x:abc")).unwrap_err().0,
            "The input string 'x' was not in a correct format."
        );
    }
}
