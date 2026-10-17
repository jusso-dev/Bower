//! Logs Ingestion API limits checked before upload (`IngestionPreflight`).
//!
//! Azure truncates over-long fields and drops malformed rows without a per-record
//! error, so Bower catches them first and dead-letters with an explicit reason.

use serde_json::{Map, Value};

use crate::json_text::{kind_name, to_compact_string};
use crate::schema::SentinelSchema;

/// Azure truncates any single field value above this size.
pub const MAXIMUM_FIELD_BYTES: usize = 64 * 1024;

/// A single API call is limited to 1 MB; one record must fit.
pub const MAXIMUM_RECORD_BYTES: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightIssue {
    pub code: String,
    pub field: String,
    pub detail: String,
}

impl PreflightIssue {
    fn new(code: &str, field: &str, detail: String) -> Self {
        Self {
            code: code.to_owned(),
            field: field.to_owned(),
            detail,
        }
    }
}

/// Checks one record (the JSON object that would be uploaded) against `schema`.
pub fn check(record: &Map<String, Value>, schema: &SentinelSchema) -> Vec<PreflightIssue> {
    let mut issues = Vec::new();

    let record_bytes = bower_contracts::json::to_vec(record)
        .expect("JSON values always serialize")
        .len();
    if record_bytes > MAXIMUM_RECORD_BYTES {
        issues.push(PreflightIssue::new(
            "record-too-large",
            "$",
            format!("Record is {record_bytes} bytes; the API limit is {MAXIMUM_RECORD_BYTES}."),
        ));
    }

    for column in &schema.stream_columns {
        let value = match record.get(&column.name) {
            None | Some(Value::Null) => continue,
            Some(value) => value,
        };

        let bytes = to_compact_string(value).len();
        if bytes > MAXIMUM_FIELD_BYTES {
            issues.push(PreflightIssue::new(
                "field-too-large",
                &column.name,
                format!("Field is {bytes} bytes; Azure silently truncates values above {MAXIMUM_FIELD_BYTES}."),
            ));
        }

        let type_ok = match column.column_type.as_str() {
            "string" => value.is_string(),
            "datetime" => value.as_str().is_some_and(is_date_time_offset),
            "int" | "long" | "real" => value.is_number(),
            "boolean" => value.is_boolean(),
            _ => true,
        };
        if !type_ok {
            issues.push(PreflightIssue::new(
                "type-mismatch",
                &column.name,
                format!(
                    "Expected {}, got {}; Azure would store an empty or stringified value.",
                    column.column_type,
                    kind_name(value)
                ),
            ));
        }
    }

    if !record.contains_key("timeGenerated") {
        issues.push(PreflightIssue::new(
            "time-generated-missing",
            "timeGenerated",
            "Rows without timeGenerated cannot be placed in time.".to_owned(),
        ));
    }

    issues
}

/// `DateTimeOffset.TryParse(text, InvariantCulture, RoundtripKind)` for the formats
/// Bower and Azure emit: ISO 8601 / RFC 3339 dates and times (offset optional),
/// RFC 1123 and the invariant `MM/dd/yyyy HH:mm:ss` form. .NET accepts more free-form
/// text than this; anything else is reported as a type mismatch.
fn is_date_time_offset(text: &str) -> bool {
    let text = text.trim();
    if bower_contracts::time::parse(text).is_some() {
        return true;
    }
    if chrono::DateTime::parse_from_rfc2822(text).is_ok() {
        return true;
    }
    const NAIVE: &[&str] = &[
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y/%m/%d %H:%M:%S",
    ];
    const WITH_OFFSET: &[&str] = &[
        "%Y-%m-%d %H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M%:z",
    ];
    NAIVE
        .iter()
        .any(|format| chrono::NaiveDateTime::parse_from_str(text, format).is_ok())
        || WITH_OFFSET
            .iter()
            .any(|format| chrono::DateTime::parse_from_str(text, format).is_ok())
        || ["%m/%d/%Y", "%Y/%m/%d"]
            .iter()
            .any(|format| chrono::NaiveDate::parse_from_str(text, format).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_iso_and_rejects_free_text() {
        assert!(is_date_time_offset("2026-10-08T00:00:00Z"));
        assert!(is_date_time_offset("2026-10-08T00:00:00.1234567+10:00"));
        assert!(is_date_time_offset("2026-10-08"));
        assert!(!is_date_time_offset("not a date"));
    }
}
