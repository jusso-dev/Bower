//! Bower envelope to CloudTrail Lake audit event (`PutAuditEvents` `AuditEvent`).
//!
//! `eventData` follows the CloudTrail Lake integration event schema: `version`,
//! `userIdentity`, `eventSource`, `eventName`, `eventTime`, `UID`,
//! `recipientAccountId` and optional `errorCode`, `errorMessage`,
//! `sourceIPAddress` and `additionalEventData`. Field length limits are applied by
//! truncation (UTF-8 safe, counted in bytes so the character limit also holds).
//! `additionalEventData` (limit 28 kB) carries the redacted envelope exactly as
//! the collector would queue it plus its privacy metadata. When it does not fit,
//! the free-form `attributes` bag is omitted and listed in `omittedFields`; when it
//! still does not fit the event is refused locally, never sent truncated.
//!
//! Every value written here comes from the envelope after redaction and policy:
//! the mapper never sees the unredacted candidate.

use bower_contracts::envelope::{EventResult, PrivacyContext, SecurityEventEnvelope};
use bower_contracts::{QueuedEvent, json};
use chrono::Utc;
use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

/// `PutAuditEvents`: at most 100 audit events per call.
pub const MAXIMUM_EVENTS_PER_CALL: usize = 100;
/// `PutAuditEvents`: at most 1 MB per call. Kept below 1,048,576 for headroom.
pub const MAXIMUM_REQUEST_BYTES: usize = 1_000_000;
/// `additionalEventData` limit (28 kB), counted conservatively as 28,000 bytes.
pub const MAXIMUM_ADDITIONAL_EVENT_DATA_BYTES: usize = 28_000;
/// Fixed request envelope (`{"auditEvents":[...]}`) and per-entry JSON overhead.
const REQUEST_OVERHEAD_BYTES: usize = 64;
const ENTRY_OVERHEAD_BYTES: usize = 64;

/// One audit event ready for `PutAuditEvents`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// `AuditEvent.id`: the Bower event id when it fits `[-_A-Za-z0-9]{1,128}`,
    /// else a stable digest of it. Retries send the same id.
    pub id: String,
    /// The Bower `eventId` (also `eventData.UID`).
    pub bower_event_id: String,
    pub event_data: String,
    /// `eventDataChecksum`: base64 SHA-256 of `event_data`.
    pub checksum: String,
    /// Envelope fields left out to respect the `additionalEventData` limit.
    pub omitted_fields: Vec<&'static str>,
}

impl AuditRecord {
    /// Bytes this record adds to a `PutAuditEvents` JSON body (`eventData` is a JSON
    /// string, so its quotes and backslashes are escaped once more).
    pub fn request_bytes(&self) -> usize {
        let escapes = self
            .event_data
            .bytes()
            .filter(|byte| matches!(byte, b'"' | b'\\'))
            .count();
        self.event_data.len() + escapes + self.id.len() + self.checksum.len() + ENTRY_OVERHEAD_BYTES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    /// The redacted envelope does not fit `additionalEventData` even without
    /// `attributes`. Definitive: resending the same event cannot succeed.
    #[error("cloudtrail-lake-event-too-large")]
    TooLarge,
    /// The queued payload is not an envelope (never expected after processing).
    #[error("cloudtrail-lake-mapping-failed")]
    Invalid,
}

impl MappingError {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "cloudtrail-lake-event-too-large",
            Self::Invalid => "cloudtrail-lake-mapping-failed",
        }
    }
}

/// Context the mapper adds to every event.
#[derive(Clone, Copy, Debug)]
pub struct MappingContext<'a> {
    pub recipient_account_id: &'a str,
    pub producer: &'a str,
}

/// `AuditEvent.id` for a Bower event id.
pub fn audit_id(event_id: &str) -> String {
    let valid = (1..=128).contains(&event_id.len())
        && event_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if valid {
        event_id.to_string()
    } else {
        format!("bower-{}", hex::encode(Sha256::digest(event_id.as_bytes())))
    }
}

#[derive(Serialize)]
struct UserIdentity<'a> {
    #[serde(rename = "type")]
    identity_type: String,
    #[serde(rename = "principalId")]
    principal_id: String,
    details: IdentityDetails<'a>,
}

#[derive(Serialize)]
struct IdentityDetails<'a> {
    producer: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdditionalEventData<'a> {
    envelope: &'a RawValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy: Option<&'a PrivacyContext>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    omitted_fields: &'a [&'static str],
}

#[derive(Serialize)]
struct EventData<'a> {
    version: String,
    #[serde(rename = "userIdentity")]
    user_identity: UserIdentity<'a>,
    #[serde(rename = "eventSource")]
    event_source: String,
    #[serde(rename = "eventName")]
    event_name: String,
    #[serde(rename = "eventTime")]
    event_time: String,
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(rename = "sourceIPAddress", skip_serializing_if = "Option::is_none")]
    source_ip_address: Option<String>,
    #[serde(rename = "recipientAccountId")]
    recipient_account_id: &'a str,
    #[serde(rename = "additionalEventData")]
    additional_event_data: &'a RawValue,
}

/// Longest prefix of `value` within `maximum` bytes, cut on a character boundary.
pub fn bounded(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_string();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// `bower.<application>` with characters outside `[A-Za-z0-9._-]` replaced by `-`.
fn event_source(application: &str) -> String {
    let name: String = application
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect();
    bounded(&format!("bower.{name}"), 1024)
}

fn raw(text: String) -> Result<Box<RawValue>, MappingError> {
    RawValue::from_string(text).map_err(|_| MappingError::Invalid)
}

fn additional_event_data(
    envelope_json: &str,
    privacy: Option<&PrivacyContext>,
    omitted_fields: &[&'static str],
) -> Result<String, MappingError> {
    let envelope = raw(envelope_json.to_string())?;
    json::to_string(&AdditionalEventData {
        envelope: &envelope,
        privacy,
        omitted_fields,
    })
    .map_err(|_| MappingError::Invalid)
}

/// Maps one queued (redacted, policy-accepted or privacy alert) event.
pub fn map(queued: &QueuedEvent, context: MappingContext<'_>) -> Result<AuditRecord, MappingError> {
    let envelope: SecurityEventEnvelope =
        json::from_str(&queued.payload).map_err(|_| MappingError::Invalid)?;

    let mut omitted_fields: Vec<&'static str> = Vec::new();
    let mut additional =
        additional_event_data(&queued.payload, envelope.privacy.as_ref(), &omitted_fields)?;
    if additional.len() > MAXIMUM_ADDITIONAL_EVENT_DATA_BYTES && envelope.attributes.is_some() {
        let mut reduced = envelope.clone();
        reduced.attributes = None;
        let reduced_json = json::to_string(&reduced).map_err(|_| MappingError::Invalid)?;
        omitted_fields.push("attributes");
        additional =
            additional_event_data(&reduced_json, envelope.privacy.as_ref(), &omitted_fields)?;
    }
    if additional.len() > MAXIMUM_ADDITIONAL_EVENT_DATA_BYTES {
        return Err(MappingError::TooLarge);
    }
    let additional = raw(additional)?;

    let actor = envelope.actor.as_ref();
    let principal_id = actor
        .and_then(|actor| actor.user_id.as_deref().or(actor.username.as_deref()))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unknown");
    let failed = matches!(
        envelope.event_result,
        EventResult::Failure | EventResult::Denied
    );
    let source_ip_address = envelope
        .source
        .as_ref()
        .and_then(|source| source.ip_address.as_deref())
        .filter(|address| address.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string);

    let data = EventData {
        version: bounded(&envelope.schema_version, 256),
        user_identity: UserIdentity {
            identity_type: bounded(
                actor.map_or("unknown", |actor| actor.actor_type.as_str()),
                128,
            ),
            principal_id: bounded(principal_id, 1024),
            details: IdentityDetails {
                producer: context.producer,
            },
        },
        event_source: event_source(&envelope.application.name),
        event_name: bounded(&envelope.event_type, 1024),
        event_time: envelope
            .time_generated
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
        uid: bounded(&envelope.event_id, 1024),
        error_code: failed.then(|| envelope.event_result.as_str().to_string()),
        error_message: if failed {
            envelope
                .event_outcome_reason
                .as_deref()
                .map(|reason| bounded(reason, 256))
        } else {
            None
        },
        source_ip_address,
        recipient_account_id: context.recipient_account_id,
        additional_event_data: &additional,
    };
    let event_data = json::to_string(&data).map_err(|_| MappingError::Invalid)?;
    let checksum = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(event_data.as_bytes()))
    };
    Ok(AuditRecord {
        id: audit_id(&envelope.event_id),
        bower_event_id: envelope.event_id,
        event_data,
        checksum,
        omitted_fields,
    })
}

/// Splits records into `PutAuditEvents` calls of at most 100 events and 1 MB.
/// Returns index ranges into `records`, in order.
pub fn batches(records: &[AuditRecord]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut bytes = REQUEST_OVERHEAD_BYTES;
    for (index, record) in records.iter().enumerate() {
        let size = record.request_bytes();
        let full = index - start == MAXIMUM_EVENTS_PER_CALL
            || (index > start && bytes + size > MAXIMUM_REQUEST_BYTES);
        if full {
            ranges.push(start..index);
            start = index;
            bytes = REQUEST_OVERHEAD_BYTES;
        }
        bytes += size;
    }
    if start < records.len() {
        ranges.push(start..records.len());
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_ids_keep_valid_event_ids_and_digest_the_rest() {
        assert_eq!(audit_id("0b9c-4f_A"), "0b9c-4f_A");
        let hashed = audit_id("orders:42");
        assert!(hashed.starts_with("bower-"));
        assert_eq!(hashed.len(), 70);
        assert_eq!(hashed, audit_id("orders:42"));
        assert_ne!(audit_id(&"a".repeat(129)), "a".repeat(129));
        assert!(audit_id("é").starts_with("bower-"));
    }

    #[test]
    fn bounded_cuts_on_character_boundaries() {
        assert_eq!(bounded("abc", 5), "abc");
        assert_eq!(bounded("ab\u{e9}", 3), "ab");
        assert_eq!(bounded(&"x".repeat(300), 256).len(), 256);
    }

    #[test]
    fn event_source_is_sanitised() {
        assert_eq!(event_source("Orders API/v2"), "bower.Orders-API-v2");
        assert_eq!(event_source(&"a".repeat(2000)).len(), 1024);
    }

    fn record(id: usize, data_bytes: usize) -> AuditRecord {
        AuditRecord {
            id: format!("id-{id}"),
            bower_event_id: format!("id-{id}"),
            event_data: "x".repeat(data_bytes),
            checksum: "c".repeat(44),
            omitted_fields: Vec::new(),
        }
    }

    #[test]
    fn batches_respect_count_and_byte_limits() {
        let small: Vec<_> = (0..250).map(|index| record(index, 100)).collect();
        assert_eq!(batches(&small), vec![0..100, 100..200, 200..250]);
        let large: Vec<_> = (0..40).map(|index| record(index, 60_000)).collect();
        let ranges = batches(&large);
        assert!(ranges.len() >= 3);
        for range in &ranges {
            let bytes: usize = large[range.clone()]
                .iter()
                .map(AuditRecord::request_bytes)
                .sum();
            assert!(bytes + REQUEST_OVERHEAD_BYTES <= MAXIMUM_REQUEST_BYTES);
            assert!(range.len() <= MAXIMUM_EVENTS_PER_CALL);
        }
        assert_eq!(ranges.last().unwrap().end, 40);
        assert!(batches(&[]).is_empty());
        let escaped = AuditRecord {
            event_data: "\"\\".into(),
            ..record(0, 0)
        };
        assert_eq!(escaped.request_bytes(), 4 + 4 + 44 + ENTRY_OVERHEAD_BYTES);
    }
}
