//! Suppression windows, source activity and source monitoring starts (C# `SqliteEventStore.Suppression.cs`).
//!
//! Auxiliary tables are additive and created on every start without a schema
//! version, so a queue stays at version 5 and either runtime can open the other's
//! file. Windows are fixed and aligned to the Unix epoch, so every collector and
//! runtime computes the same boundaries and a restart continues an open window
//! from its durable counts.

use std::collections::{HashMap, HashSet};

use bower_contracts::time::Timestamp;
use bower_contracts::{
    JsonElement, QueuedEvent, SourceActivity, SourceMonitoring, StoreError, StoreResult,
    SuppressionRequest, SuppressionWindow,
};
use rusqlite::{Connection, TransactionBehavior, named_params, params};

use crate::pool::storage;
use crate::queue::{SqliteEventStore, parse_stored, stored};

/// DDL identical to C# `AuxiliarySchema` (after raw-literal de-indentation).
pub(crate) const AUXILIARY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS suppression_windows (
    policy_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    window_end INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    allow_per_window INTEGER NOT NULL,
    admitted INTEGER NOT NULL,
    suppressed INTEGER NOT NULL,
    first_suppressed_at TEXT NULL,
    last_suppressed_at TEXT NULL,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    event_category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    application TEXT NOT NULL,
    environment TEXT NOT NULL,
    tenant_id TEXT NULL,
    key_fields TEXT NOT NULL,
    key_values TEXT NOT NULL,
    PRIMARY KEY (policy_id, key_hash, window_start)
);

CREATE INDEX IF NOT EXISTS ix_suppression_windows_end ON suppression_windows(window_end);

CREATE TABLE IF NOT EXISTS source_activity (
    application TEXT NOT NULL,
    environment TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    PRIMARY KEY (application, environment)
);

CREATE TABLE IF NOT EXISTS source_monitoring (
    application TEXT NOT NULL,
    environment TEXT NOT NULL,
    monitoring_since TEXT NOT NULL,
    PRIMARY KEY (application, environment)
);";

const MAXIMUM_WINDOWS_PER_CLOSE: i64 = 1_000;

/// Epoch-aligned window start (floor) for `received_at` (`ToUnixTimeSeconds`).
pub fn window_start(received_at: &Timestamp, window_seconds: i32) -> i64 {
    let now = received_at.timestamp();
    let seconds = i64::from(window_seconds);
    now - (((now % seconds) + seconds) % seconds)
}

/// Decides admission for one accepted event inside the caller's write transaction.
/// Returns false when the allowance is spent and the event was only counted.
pub(crate) fn admit(
    transaction: &Connection,
    rule: &SuppressionRequest,
    received_at: &Timestamp,
) -> StoreResult<bool> {
    if rule.window_seconds < 1 {
        // C# divides by zero here; never admit a malformed rule silently.
        return Err(StoreError::Invalid(
            "Suppression windowSeconds must be positive.".into(),
        ));
    }
    let start = window_start(received_at, rule.window_seconds);
    let end = start + i64::from(rule.window_seconds);
    transaction
        .execute(
            "INSERT INTO suppression_windows (
    policy_id, key_hash, window_start, window_end, window_seconds, allow_per_window,
    admitted, suppressed, policy_version, policy_hash, event_category, event_type,
    application, environment, tenant_id, key_fields, key_values)
VALUES (
    :policy, :key, :start, :end, :seconds, :allow, 0, 0, :version, :hash, :category,
    :type, :application, :environment, :tenant, :fields, :values)
ON CONFLICT (policy_id, key_hash, window_start) DO NOTHING;",
            named_params! {
                ":policy": rule.policy_id,
                ":key": rule.key_hash,
                ":start": start,
                ":end": end,
                ":seconds": rule.window_seconds,
                ":allow": rule.allow_per_window,
                ":version": rule.policy_version,
                ":hash": rule.policy_hash,
                ":category": rule.event_category,
                ":type": rule.event_type,
                ":application": rule.application,
                ":environment": rule.environment,
                ":tenant": rule.tenant_id,
                ":fields": write_strings(&rule.key_fields)?,
                ":values": write_strings(&rule.key_values)?,
            },
        )
        .map_err(storage)?;

    let admit: i64 = transaction
        .query_row(
            "SELECT admitted < allow_per_window FROM suppression_windows
WHERE policy_id = ?1 AND key_hash = ?2 AND window_start = ?3;",
            params![rule.policy_id, rule.key_hash, start],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let admit = admit == 1;
    if admit {
        transaction
            .execute(
                "UPDATE suppression_windows SET admitted = admitted + 1
WHERE policy_id = ?1 AND key_hash = ?2 AND window_start = ?3;",
                params![rule.policy_id, rule.key_hash, start],
            )
            .map_err(storage)?;
    } else {
        transaction
            .execute(
                "UPDATE suppression_windows SET
    suppressed = suppressed + 1,
    first_suppressed_at = COALESCE(first_suppressed_at, ?4),
    last_suppressed_at = ?4
WHERE policy_id = ?1 AND key_hash = ?2 AND window_start = ?3;",
                params![rule.policy_id, rule.key_hash, start, stored(received_at)],
            )
            .map_err(storage)?;
    }
    Ok(admit)
}

fn from_unix_seconds(seconds: i64, column: usize) -> rusqlite::Result<Timestamp> {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|value| value.fixed_offset())
        .ok_or(rusqlite::Error::IntegralValueOutOfRange(column, seconds))
}

pub(crate) fn close_expired(
    store: &SqliteEventStore,
    now: Timestamp,
    create_summary: &mut dyn FnMut(&SuppressionWindow) -> StoreResult<QueuedEvent>,
) -> StoreResult<usize> {
    let now_seconds = now.timestamp();
    store.pool().with(|connection| {
        store.budget(connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let expired: Vec<SuppressionWindow> = {
            let mut select = transaction
                .prepare(
                    "SELECT policy_id, key_hash, window_start, window_end, window_seconds,
    allow_per_window, admitted, suppressed, first_suppressed_at,
    last_suppressed_at, policy_version, policy_hash, event_category,
    event_type, application, environment, tenant_id, key_fields, key_values
FROM suppression_windows
WHERE window_end <= ?1
ORDER BY window_end, policy_id, key_hash
LIMIT ?2;",
                )
                .map_err(storage)?;
            let rows = select
                .query_map(params![now_seconds, MAXIMUM_WINDOWS_PER_CLOSE], |row| {
                    let optional_time = |index: usize| -> rusqlite::Result<Option<Timestamp>> {
                        row.get::<_, Option<String>>(index)?
                            .map(|text| parse_stored(&text, index))
                            .transpose()
                    };
                    let strings = |index: usize| -> rusqlite::Result<Vec<String>> {
                        read_strings(&row.get::<_, String>(index)?).ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                index,
                                rusqlite::types::Type::Text,
                                "Suppression key value is not a string.".into(),
                            )
                        })
                    };
                    Ok(SuppressionWindow {
                        rule: SuppressionRequest {
                            policy_id: row.get(0)?,
                            policy_version: row.get(10)?,
                            policy_hash: row.get(11)?,
                            key_hash: row.get(1)?,
                            key_fields: strings(17)?,
                            key_values: strings(18)?,
                            window_seconds: row.get(4)?,
                            allow_per_window: row.get(5)?,
                            event_category: row.get(12)?,
                            event_type: row.get(13)?,
                            application: row.get(14)?,
                            environment: row.get(15)?,
                            tenant_id: row.get(16)?,
                        },
                        window_start: from_unix_seconds(row.get(2)?, 2)?,
                        window_end: from_unix_seconds(row.get(3)?, 3)?,
                        admitted: row.get(6)?,
                        suppressed: row.get(7)?,
                        first_suppressed_at: optional_time(8)?,
                        last_suppressed_at: optional_time(9)?,
                    })
                })
                .map_err(storage)?;
            rows.collect::<Result<_, _>>().map_err(storage)?
        };

        let mut summaries = 0;
        for window in &expired {
            if window.suppressed > 0 {
                // A failing summary drops the transaction: nothing is closed.
                let summary = create_summary(window)?;
                SqliteEventStore::validate(&summary)?;
                if !SqliteEventStore::exists_in(&transaction, &summary)? {
                    store.insert(&transaction, &summary)?;
                    summaries += 1;
                }
            }
            transaction
                .execute(
                    "DELETE FROM suppression_windows
WHERE policy_id = ?1 AND key_hash = ?2 AND window_start = ?3;",
                    params![
                        window.rule.policy_id,
                        window.rule.key_hash,
                        window.window_start.timestamp()
                    ],
                )
                .map_err(storage)?;
        }
        transaction.commit().map_err(storage)?;
        Ok(summaries)
    })
}

pub(crate) fn get_source_activity(store: &SqliteEventStore) -> StoreResult<Vec<SourceActivity>> {
    store.pool().with(|connection| {
        let mut select = connection
            .prepare(
                "SELECT application, environment, last_seen_at, event_count
FROM source_activity
ORDER BY application, environment;",
            )
            .map_err(storage)?;
        let rows = select
            .query_map([], |row| {
                Ok(SourceActivity {
                    application: row.get(0)?,
                    environment: row.get(1)?,
                    last_seen_at: parse_stored(&row.get::<_, String>(2)?, 2)?,
                    event_count: row.get(3)?,
                })
            })
            .map_err(storage)?;
        rows.collect::<Result<_, _>>().map_err(storage)
    })
}

pub(crate) fn upsert_source_activity(
    store: &SqliteEventStore,
    activity: &[SourceActivity],
) -> StoreResult<()> {
    if activity.is_empty() {
        return Ok(());
    }
    store.pool().with(|connection| {
        store.budget(connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        store.storage_check()?;
        {
            let mut upsert = transaction
                .prepare(
                    "INSERT INTO source_activity (application, environment, last_seen_at, event_count)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT (application, environment) DO UPDATE SET
    last_seen_at = MAX(last_seen_at, excluded.last_seen_at),
    event_count = MAX(event_count, excluded.event_count);",
                )
                .map_err(storage)?;
            for item in activity {
                upsert
                    .execute(params![
                        item.application,
                        item.environment,
                        stored(&item.last_seen_at),
                        item.event_count
                    ])
                    .map_err(storage)?;
            }
        }
        transaction.commit().map_err(storage)
    })
}

/// C# `StartSourceMonitoringAsync`: keeps stored starts, records new sources at their
/// proposed start and forgets sources no longer expected, in one write transaction.
pub(crate) fn start_source_monitoring(
    store: &SqliteEventStore,
    expected: &[SourceMonitoring],
) -> StoreResult<Vec<SourceMonitoring>> {
    let keys: HashSet<(&str, &str)> = expected
        .iter()
        .map(|item| (item.application.as_str(), item.environment.as_str()))
        .collect();
    store.pool().with(|connection| {
        store.budget(connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        store.storage_check()?;
        let mut known: HashMap<(String, String), Timestamp> = HashMap::new();
        {
            let mut select = transaction
                .prepare("SELECT application, environment, monitoring_since FROM source_monitoring;")
                .map_err(storage)?;
            let rows = select
                .query_map([], |row| {
                    Ok((
                        (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                        parse_stored(&row.get::<_, String>(2)?, 2)?,
                    ))
                })
                .map_err(storage)?;
            for row in rows {
                let (key, since) = row.map_err(storage)?;
                known.insert(key, since);
            }
        }
        let forgotten: Vec<(String, String)> = known
            .keys()
            .filter(|(application, environment)| {
                !keys.contains(&(application.as_str(), environment.as_str()))
            })
            .cloned()
            .collect();
        for key in forgotten {
            transaction
                .execute(
                    "DELETE FROM source_monitoring WHERE application = ?1 AND environment = ?2;",
                    params![key.0, key.1],
                )
                .map_err(storage)?;
            known.remove(&key);
        }
        let mut monitoring = Vec::with_capacity(expected.len());
        for item in expected {
            let key = (item.application.clone(), item.environment.clone());
            let since = match known.get(&key) {
                Some(since) => *since,
                None => {
                    transaction
                        .execute(
                            "INSERT INTO source_monitoring (application, environment, monitoring_since)
VALUES (?1, ?2, ?3);",
                            params![item.application, item.environment, stored(&item.monitoring_since)],
                        )
                        .map_err(storage)?;
                    known.insert(key, item.monitoring_since);
                    item.monitoring_since
                }
            };
            monitoring.push(SourceMonitoring {
                monitoring_since: since,
                ..item.clone()
            });
        }
        transaction.commit().map_err(storage)?;
        Ok(monitoring)
    })
}

/// `Utf8JsonWriter` array of strings (default encoder escaping).
fn write_strings(values: &[String]) -> StoreResult<String> {
    let array = JsonElement::Array(values.iter().cloned().map(JsonElement::String).collect());
    bower_contracts::json::to_string(&array)
        .map_err(|_| StoreError::Invalid("Suppression key could not be serialized.".into()))
}

fn read_strings(json: &str) -> Option<Vec<String>> {
    match JsonElement::parse(json).ok()? {
        JsonElement::Array(items) => items
            .into_iter()
            .map(|item| match item {
                JsonElement::String(text) => Some(text),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bower_contracts::time;

    #[test]
    fn windows_align_to_the_epoch() {
        let at = |text: &str| time::parse(text).unwrap();
        assert_eq!(
            window_start(&at("2026-07-26T02:14:19.1234567+00:00"), 60),
            1_785_032_040
        );
        assert_eq!(window_start(&at("1970-01-01T00:00:00+00:00"), 60), 0);
        assert_eq!(window_start(&at("1969-12-31T23:59:59+00:00"), 60), -60);
    }

    #[test]
    fn key_lists_round_trip_as_json_arrays() {
        let values = vec!["zo\u{eb} \"q\"".to_owned(), String::new()];
        let text = write_strings(&values).unwrap();
        assert_eq!(text, "[\"zo\\u00EB \\u0022q\\u0022\",\"\"]");
        assert_eq!(read_strings(&text).unwrap(), values);
        assert!(read_strings("[1]").is_none());
    }
}
