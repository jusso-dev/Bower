//! Flat JSON record for a signed pack parser (C# `SyslogRecord`). In memory only; never
//! logged or persisted.

use bower_contracts::time::Timestamp;
use bower_contracts::{JsonElement, json};
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::parser::{SyslogFormat, SyslogMessage, failures};

pub const MAXIMUM_FIELDS: usize = 64;
/// A pack parser cannot read longer values (UTF-16 code units), so they are left out.
pub const MAXIMUM_VALUE_LENGTH: usize = 2048;

pub fn build(
    message: &SyslogMessage,
    frame: &[u8],
    listener_id: &str,
    protocol: &str,
    sender_address: &str,
    received_at: &Timestamp,
) -> Result<String, &'static str> {
    let received = format(received_at);
    let id = event_id(
        listener_id,
        sender_address,
        frame,
        message.timestamp.is_none().then_some(received.as_str()),
    );
    let mut fields: Vec<(String, JsonElement)> = vec![
        ("id".into(), id.into()),
        ("listener".into(), listener_id.into()),
        ("protocol".into(), protocol.into()),
        ("senderAddress".into(), sender_address.into()),
        ("receivedAt".into(), received.clone().into()),
        (
            "format".into(),
            match message.format {
                SyslogFormat::Rfc5424 => "rfc5424",
                SyslogFormat::Rfc3164 => "rfc3164",
            }
            .into(),
        ),
        ("facility".into(), message.facility.to_string().into()),
        ("severity".into(), message.severity.to_string().into()),
        (
            "timestamp".into(),
            message.timestamp.as_ref().map_or(received, format).into(),
        ),
    ];
    let mut add = |name: String, value: Option<&String>| {
        if let Some(value) = value
            && value.encode_utf16().count() <= MAXIMUM_VALUE_LENGTH
        {
            fields.push((name, value.as_str().into()));
        }
    };
    add("hostname".into(), message.hostname.as_ref());
    add("appName".into(), message.app_name.as_ref());
    add("procId".into(), message.proc_id.as_ref());
    add("msgId".into(), message.message_id.as_ref());
    add("message".into(), message.message.as_ref());
    for element in &message.structured_data {
        for (name, value) in &element.parameters {
            add(format!("sd.{}.{name}", element.id), Some(value));
        }
    }
    if fields.len() > MAXIMUM_FIELDS {
        return Err(failures::RECORD_TOO_LARGE);
    }
    json::to_string(&JsonElement::Object(fields)).map_err(|_| failures::RECORD_TOO_LARGE)
}

/// `syslog-` + 32 hex characters of SHA-256 over listener, sender and the exact frame
/// bytes (plus the receive time when the message has no timestamp).
pub fn event_id(
    listener_id: &str,
    sender_address: &str,
    frame: &[u8],
    received_at: Option<&str>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(listener_id.as_bytes());
    hash.update([0x1f]);
    hash.update(sender_address.as_bytes());
    hash.update([0x1f]);
    hash.update(frame);
    if let Some(received_at) = received_at {
        hash.update([0x1f]);
        hash.update(received_at.as_bytes());
    }
    format!("syslog-{}", &hex::encode(hash.finalize())[..32])
}

/// UTC, microsecond precision (truncated), like C# `SyslogRecord.Format`.
pub fn format(value: &Timestamp) -> String {
    value
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}
