//! Append-only hash chain over every accepted event (C# `QueueLedger`).
//!
//! Each entry commits to the previous entry, the event id, a SHA-256 of the
//! stored payload and the receive time, so edited payloads, deleted rows and
//! re-ordering are detectable. Retention marks entries purged instead of
//! deleting them; compaction folds a fully purged prefix into an anchor.

use std::collections::HashSet;

use bower_contracts::{LedgerIssue, LedgerVerification, StoreResult};
use indexmap::IndexMap;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::pool::storage;

pub const GENESIS: &str = "bower-queue-ledger-v1";

/// Appended to the queue DDL batch; text identical to C# `QueueLedger.Schema`.
pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS queue_ledger (
    sequence INTEGER PRIMARY KEY NOT NULL,
    event_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    received_at TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    purged_at TEXT NULL
);

CREATE INDEX IF NOT EXISTS ix_queue_ledger_event ON queue_ledger(event_id);

CREATE TABLE IF NOT EXISTS queue_ledger_anchor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    sequence INTEGER NOT NULL,
    chain_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v3-ledger');";

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Lower-case hex SHA-256 of the UTF-8 payload.
pub fn payload_hash(payload: &str) -> String {
    sha256_hex(payload)
}

/// SHA-256 over `previous ␟ sequence ␟ event_id ␟ payload_hash ␟ received_at`.
pub fn chain_hash(
    previous: &str,
    sequence: i64,
    event_id: &str,
    payload_hash: &str,
    received_at: &str,
) -> String {
    sha256_hex(
        &[
            previous,
            &sequence.to_string(),
            event_id,
            payload_hash,
            received_at,
        ]
        .join("\u{1f}"),
    )
}

pub fn genesis_hash() -> String {
    sha256_hex(GENESIS)
}

pub(crate) fn head(connection: &Connection) -> StoreResult<(i64, String)> {
    let latest = connection
        .query_row(
            "SELECT sequence, chain_hash FROM queue_ledger ORDER BY sequence DESC LIMIT 1;",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    match latest {
        Some(value) => Ok(value),
        None => anchor(connection),
    }
}

pub(crate) fn anchor(connection: &Connection) -> StoreResult<(i64, String)> {
    let stored = connection
        .query_row(
            "SELECT sequence, chain_hash FROM queue_ledger_anchor WHERE id = 1;",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    Ok(stored.unwrap_or_else(|| (0, genesis_hash())))
}

/// Must run inside the caller's write transaction.
pub(crate) fn append(
    connection: &Connection,
    event_id: &str,
    payload: &str,
    received_at: &str,
) -> StoreResult<()> {
    let (sequence, previous) = head(connection)?;
    let next = sequence + 1;
    let payload_sha256 = payload_hash(payload);
    let chain = chain_hash(&previous, next, event_id, &payload_sha256, received_at);
    connection
        .execute(
            "INSERT INTO queue_ledger (sequence, event_id, payload_sha256, received_at, chain_hash)
VALUES (?1, ?2, ?3, ?4, ?5);",
            params![next, event_id, payload_sha256, received_at, chain],
        )
        .map_err(storage)?;
    Ok(())
}

/// Adds ledger entries for events stored before the ledger existed.
pub(crate) fn backfill(connection: &mut Connection) -> StoreResult<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    let missing = {
        let mut select = transaction
            .prepare(
                "SELECT e.event_id, e.payload, e.received_at
FROM queue_events e
WHERE NOT EXISTS (SELECT 1 FROM queue_ledger l WHERE l.event_id = e.event_id)
ORDER BY e.received_at ASC, e.event_id ASC;",
            )
            .map_err(storage)?;
        let rows = select
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage)?
    };
    for (event_id, payload, received_at) in &missing {
        append(&transaction, event_id, payload, received_at)?;
    }
    transaction.commit().map_err(storage)
}

/// Must run inside the purge transaction so retention is distinguishable from tampering.
pub(crate) fn mark_purged(
    connection: &Connection,
    event_ids: &[String],
    purged_at: &str,
) -> StoreResult<()> {
    let mut update = connection
        .prepare(
            "UPDATE queue_ledger SET purged_at = ?1 WHERE event_id = ?2 AND purged_at IS NULL;",
        )
        .map_err(storage)?;
    for event_id in event_ids {
        update
            .execute(params![purged_at, event_id])
            .map_err(storage)?;
    }
    Ok(())
}

/// Folds the longest fully purged prefix into the anchor and deletes it.
pub(crate) fn compact(connection: &mut Connection, now: &str) -> StoreResult<usize> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    let boundary = transaction
        .query_row(
            "SELECT sequence, chain_hash FROM queue_ledger
WHERE sequence < COALESCE((SELECT MIN(sequence) FROM queue_ledger WHERE purged_at IS NULL), 9223372036854775807)
ORDER BY sequence DESC LIMIT 1;",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let Some((sequence, hash)) = boundary else {
        // Read-only: nothing to fold. Dropping the transaction rolls back.
        return Ok(0);
    };
    transaction
        .execute(
            "INSERT INTO queue_ledger_anchor (id, sequence, chain_hash, created_at)
VALUES (1, ?1, ?2, ?3)
ON CONFLICT(id) DO UPDATE SET sequence = excluded.sequence, chain_hash = excluded.chain_hash, created_at = excluded.created_at;",
            params![sequence, hash, now],
        )
        .map_err(storage)?;
    let removed = transaction
        .execute(
            "DELETE FROM queue_ledger WHERE sequence <= ?1;",
            params![sequence],
        )
        .map_err(storage)?;
    transaction.commit().map_err(storage)?;
    Ok(removed)
}

fn issue(sequence: i64, event_id: &str, code: &str, detail: impl Into<String>) -> LedgerIssue {
    LedgerIssue {
        sequence,
        event_id: event_id.to_owned(),
        code: code.to_owned(),
        detail: detail.into(),
    }
}

struct LedgerRow {
    sequence: i64,
    event_id: String,
    payload_sha256: String,
    received_at: String,
    chain_hash: String,
    purged: bool,
}

/// Recomputes the chain and cross-checks stored events. Reads run in one
/// deferred (read) transaction: in WAL mode the anchor, event and ledger reads all
/// see one snapshot, so a concurrent enqueue cannot produce a false issue.
pub(crate) fn verify(connection: &mut Connection) -> StoreResult<LedgerVerification> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(storage)?;
    let mut issues = Vec::new();
    let (anchor_sequence, mut previous) = anchor(&transaction)?;
    let mut expected = anchor_sequence + 1;
    let mut entries = 0_i64;
    let mut head_sequence = anchor_sequence;
    let mut head_hash = previous.clone();

    let payloads: IndexMap<String, String> = {
        let mut select = transaction
            .prepare("SELECT event_id, payload FROM queue_events;")
            .map_err(storage)?;
        let rows = select
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        rows.collect::<Result<_, _>>().map_err(storage)?
    };

    let rows: Vec<LedgerRow> = {
        let mut select = transaction
            .prepare(
                "SELECT sequence, event_id, payload_sha256, received_at, chain_hash, purged_at FROM queue_ledger ORDER BY sequence;",
            )
            .map_err(storage)?;
        let mapped = select
            .query_map([], |row| {
                Ok(LedgerRow {
                    sequence: row.get(0)?,
                    event_id: row.get(1)?,
                    payload_sha256: row.get(2)?,
                    received_at: row.get(3)?,
                    chain_hash: row.get(4)?,
                    purged: row.get_ref(5)?.data_type() != rusqlite::types::Type::Null,
                })
            })
            .map_err(storage)?;
        mapped.collect::<Result<_, _>>().map_err(storage)?
    };
    drop(transaction);

    let mut ledgered = HashSet::new();
    for row in rows {
        entries += 1;
        ledgered.insert(row.event_id.clone());
        let sequence = row.sequence;
        let event_id = row.event_id.as_str();

        if sequence != expected {
            issues.push(issue(
                sequence,
                event_id,
                "sequence-gap",
                format!("Expected sequence {expected}, found {sequence}."),
            ));
        }

        let recomputed = chain_hash(
            &previous,
            sequence,
            event_id,
            &row.payload_sha256,
            &row.received_at,
        );
        if recomputed != row.chain_hash {
            issues.push(issue(
                sequence,
                event_id,
                "chain-broken",
                "Ledger entry does not chain from its predecessor.",
            ));
        }

        if !row.purged {
            match payloads.get(event_id) {
                None => issues.push(issue(
                    sequence,
                    event_id,
                    "event-missing",
                    "Event was removed without a purge record.",
                )),
                Some(payload) if payload_hash(payload) != row.payload_sha256 => {
                    issues.push(issue(
                        sequence,
                        event_id,
                        "payload-modified",
                        "Stored payload no longer matches the ledger.",
                    ));
                }
                Some(_) => {}
            }
        } else if payloads.contains_key(event_id) {
            issues.push(issue(
                sequence,
                event_id,
                "purge-mismatch",
                "Ledger marks the event purged but it is still stored.",
            ));
        }

        previous = row.chain_hash.clone();
        head_sequence = sequence;
        head_hash = row.chain_hash;
        expected = sequence + 1;
    }

    for event_id in payloads.keys().filter(|id| !ledgered.contains(*id)) {
        issues.push(issue(
            0,
            event_id,
            "unledgered-event",
            "Event is stored without a ledger entry.",
        ));
    }

    Ok(LedgerVerification {
        intact: issues.is_empty(),
        entries,
        head_sequence,
        head_hash,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_sha256_of_label() {
        assert_eq!(genesis_hash(), sha256_hex("bower-queue-ledger-v1"));
        assert_eq!(genesis_hash().len(), 64);
    }

    #[test]
    fn chain_uses_unit_separator() {
        let manual = sha256_hex("p\u{1f}7\u{1f}e\u{1f}h\u{1f}r");
        assert_eq!(chain_hash("p", 7, "e", "h", "r"), manual);
    }
}
