//! Wire contract between a downstream collector and a relay (C# `Bower.Forwarding.RelayProtocol`).
//! The downstream posts already redacted, policy-decided envelopes exactly as its queue
//! stores them; the relay answers only after each event is committed to its own queue.

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;

pub const SCHEMA_VERSION: i32 = 1;
/// Batch intake, relative to `BOWER_RELAY_URL`.
pub const BATCH_PATH: &str = "v1/relay/batches";
/// Management tunnel (HTTP/1.1 Upgrade), relative to `BOWER_RELAY_URL`.
pub const TUNNEL_PATH: &str = "v1/relay/management-tunnel";
/// Upgrade token for the management tunnel.
pub const TUNNEL_UPGRADE: &str = "bower-management-tunnel/1";
pub const MAXIMUM_BATCH_EVENTS: usize = 500;
/// Relay request body limit.
pub const MAXIMUM_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Downstream batches stop adding events at this many payload bytes.
pub const TARGET_BATCH_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// One stored payload; the collector's ingest limit.
pub const MAXIMUM_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Relay response body limit.
pub const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAXIMUM_IDENTIFIER_LENGTH: usize = 128;

/// Per-event outcome on the relay (C# `RelayEventStatuses`).
pub const STATUS_ACCEPTED: &str = "accepted";
pub const STATUS_DUPLICATE: &str = "duplicate";
pub const STATUS_REJECTED: &str = "rejected";

/// Relay reject codes (C# `RelayRejectCodes`, closed set).
pub const REJECT_PAYLOAD_INVALID: &str = "payload-invalid";
pub const REJECT_PAYLOAD_TOO_LARGE: &str = "payload-too-large";
pub const REJECT_EVENT_ID_MISMATCH: &str = "event-id-mismatch";
pub const REJECT_COLLECTOR_MISMATCH: &str = "collector-mismatch";
pub const REJECT_FINGERPRINT_MISMATCH: &str = "fingerprint-mismatch";
pub const REJECT_POLICY_DECISION_MISSING: &str = "policy-decision-missing";
pub const REJECT_IDENTITY_CONFLICT: &str = "event-identity-conflict";

/// Ids that may appear in acknowledgements and status: printable ASCII, no spaces.
pub fn is_valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTIFIER_LENGTH
        && value
            .chars()
            .all(|character| character > ' ' && character < '\u{7f}')
}

/// Reject codes are short lowercase tokens so they are safe to persist.
pub fn is_valid_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayBatchResponse {
    pub schema_version: i32,
    pub relay_id: String,
    pub ledger: RelayLedgerHead,
    pub results: Vec<RelayEventResult>,
}

/// The relay's queue ledger head after the batch: it commits to every event accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLedgerHead {
    pub sequence: i64,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayEventResult {
    pub event_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// A JSON object as ordered `(name, raw value)` pairs: repeated names are kept, so callers
/// can refuse them instead of last-wins, and raw values keep their exact source text
/// (C# `JsonElement.GetRawText`).
pub struct RawObject(pub Vec<(String, Box<RawValue>)>);

impl RawObject {
    /// The value of exactly one property with this name.
    pub fn single(&self, name: &str) -> Option<&RawValue> {
        let mut found = self
            .0
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_ref());
        let first = found.next()?;
        found.next().is_none().then_some(first)
    }
}

impl<'de> Deserialize<'de> for RawObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawObject, A::Error> {
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    entries.push((key, map.next_value::<Box<RawValue>>()?));
                }
                Ok(RawObject(entries))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

/// The JSON kind of a raw value from its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonKind {
    Object,
    Array,
    String,
    Number,
    Other,
}

pub fn kind(value: &RawValue) -> JsonKind {
    match value.get().as_bytes().first() {
        Some(b'{') => JsonKind::Object,
        Some(b'[') => JsonKind::Array,
        Some(b'"') => JsonKind::String,
        Some(b'-' | b'0'..=b'9') => JsonKind::Number,
        _ => JsonKind::Other,
    }
}

pub fn as_string(value: &RawValue) -> Option<String> {
    (kind(value) == JsonKind::String)
        .then(|| serde_json::from_str::<String>(value.get()).ok())
        .flatten()
}

pub fn as_object(value: &RawValue) -> Option<RawObject> {
    (kind(value) == JsonKind::Object)
        .then(|| serde_json::from_str::<RawObject>(value.get()).ok())
        .flatten()
}

pub fn as_array(value: &RawValue) -> Option<Vec<Box<RawValue>>> {
    (kind(value) == JsonKind::Array)
        .then(|| serde_json::from_str::<Vec<Box<RawValue>>>(value.get()).ok())
        .flatten()
}

/// `JsonElement.TryGetInt32`: an integer token in the `i32` range (no fraction or exponent).
pub fn as_i32(value: &RawValue) -> Option<i32> {
    (kind(value) == JsonKind::Number)
        .then(|| value.get().parse::<i32>().ok())
        .flatten()
}

/// `JsonDocumentOptions.MaxDepth`: refuses documents nested deeper than `maximum`.
pub fn within_depth(text: &[u8], maximum: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in text {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > maximum {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_codes() {
        assert!(is_valid_identifier("relay-01"));
        assert!(!is_valid_identifier("relay 01"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier(&"a".repeat(129)));
        assert!(is_valid_code("collector-mismatch"));
        assert!(!is_valid_code("Not A Code"));
    }

    #[test]
    fn raw_object_keeps_repeated_names_and_exact_text() {
        let object: RawObject = serde_json::from_str(r#"{"a":1,"a":2,"b":{ "x" : 1 }}"#).unwrap();
        assert!(object.single("a").is_none());
        assert_eq!(object.single("b").unwrap().get(), r#"{ "x" : 1 }"#);
        assert_eq!(
            as_i32(&serde_json::from_str::<Box<RawValue>>("1.0").unwrap()),
            None
        );
        assert_eq!(
            as_i32(&serde_json::from_str::<Box<RawValue>>("1").unwrap()),
            Some(1)
        );
    }
}
