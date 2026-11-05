//! Deterministic object layout (C# `S3ObjectLayout`), pinned by
//! `tests/fixtures/s3-output/vectors.json`. Keys are
//! `<prefix>/yyyy/MM/dd/HH/<sha256 of ordered event ids>.jsonl[.gz]`, partitioned by the
//! first event's queue receive time (UTC): it never changes, so a retry of the same batch
//! rewrites the same key.

use bower_contracts::abstractions::{DeliveryFailure, QueuedEvent};
use bower_contracts::time::Timestamp;
use sha2::{Digest, Sha256};

pub const INVALID_JSON_CODE: &str = "payload-invalid-json";
pub const TOO_LARGE_CODE: &str = "payload-too-large";

/// One planned object: its events in queue order, key and uncompressed NDJSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedObject {
    pub key: String,
    pub event_ids: Vec<String>,
    pub body: Vec<u8>,
}

/// Splits events, in order, into objects under the byte and count caps. A payload that
/// can never be written (invalid JSON, a line break, larger than one object) fails alone
/// and permanently.
pub fn plan(
    events: &[QueuedEvent],
    prefix: &str,
    maximum_object_bytes: i32,
    maximum_object_events: i32,
    gzip: bool,
) -> (Vec<PlannedObject>, Vec<DeliveryFailure>) {
    let maximum_bytes = i64::from(maximum_object_bytes);
    let maximum_events = usize::try_from(maximum_object_events).unwrap_or(0);
    let mut objects = Vec::new();
    let mut rejected = Vec::new();
    let mut current: Vec<&QueuedEvent> = Vec::new();
    let mut current_bytes = 0i64;
    for item in events {
        if !is_single_line_json(&item.payload) {
            rejected.push(permanent(&item.event_id, INVALID_JSON_CODE));
            continue;
        }
        let record_bytes = i64::try_from(item.payload.len()).unwrap_or(i64::MAX) + 1;
        if record_bytes > maximum_bytes {
            rejected.push(permanent(&item.event_id, TOO_LARGE_CODE));
            continue;
        }
        if !current.is_empty()
            && (current_bytes + record_bytes > maximum_bytes || current.len() >= maximum_events)
        {
            objects.push(build(&current, prefix, gzip));
            current.clear();
            current_bytes = 0;
        }
        current.push(item);
        current_bytes += record_bytes;
    }
    if !current.is_empty() {
        objects.push(build(&current, prefix, gzip));
    }
    (objects, rejected)
}

/// Object key for events in this order whose first event was received at `first_received_at`.
pub fn key(prefix: &str, first_received_at: Timestamp, event_ids: &[String], gzip: bool) -> String {
    let utc = first_received_at.naive_utc();
    format!(
        "{prefix}/{}/{}{}",
        utc.format("%Y/%m/%d/%H"),
        event_ids_hash(event_ids),
        if gzip { ".jsonl.gz" } else { ".jsonl" }
    )
}

/// Lowercase hex SHA-256 of the UTF-8 event ids joined by line feeds.
pub fn event_ids_hash(event_ids: &[String]) -> String {
    hex::encode(Sha256::digest(event_ids.join("\n").as_bytes()))
}

fn build(events: &[&QueuedEvent], prefix: &str, gzip: bool) -> PlannedObject {
    let mut body = Vec::with_capacity(events.iter().map(|item| item.payload.len() + 1).sum());
    for item in events {
        body.extend_from_slice(item.payload.as_bytes());
        body.push(b'\n');
    }
    let event_ids: Vec<String> = events.iter().map(|item| item.event_id.clone()).collect();
    PlannedObject {
        key: key(prefix, events[0].received_at, &event_ids, gzip),
        event_ids,
        body,
    }
}

fn permanent(event_id: &str, code: &str) -> DeliveryFailure {
    DeliveryFailure {
        event_id: event_id.to_string(),
        code: code.to_string(),
        is_retryable: false,
        retry_after: None,
    }
}

/// One JSON object with no raw line break, so it is exactly one NDJSON line. Validation
/// only: the payload bytes are written unchanged.
fn is_single_line_json(payload: &str) -> bool {
    if payload.contains(['\n', '\r']) || !payload.trim_start_matches([' ', '\t']).starts_with('{') {
        return false;
    }
    serde_json::from_str::<Box<serde_json::value::RawValue>>(payload).is_ok()
}
