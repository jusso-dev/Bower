//! `Bower.Core.EventFingerprint`: stable dedup key over source identity fields.

use bower_contracts::SecurityEventEnvelope;
use bower_contracts::time::{format_round_trip, to_utc};
use sha2::{Digest, Sha256};

/// `sha256:` + lower-case hex SHA-256 of the unit-separator joined stable fields.
/// Byte-identical to the C# implementation.
pub fn create(value: &SecurityEventEnvelope) -> String {
    let actor = value
        .actor
        .as_ref()
        .and_then(|actor| actor.user_id.as_deref().or(actor.username.as_deref()))
        .unwrap_or("");
    let target_type = value
        .target
        .as_ref()
        .map_or("", |target| target.target_type.as_str());
    let target_id = value
        .target
        .as_ref()
        .and_then(|target| target.id.as_deref())
        .unwrap_or("");
    let time_generated = format_round_trip(&to_utc(value.time_generated));
    let parts: [&str; 11] = [
        value.event_original_id.as_deref().unwrap_or(""),
        &value.event_type,
        &value.event_action,
        &value.application.name,
        &value.application.environment,
        value.application.tenant_id.as_deref().unwrap_or(""),
        actor,
        target_type,
        target_id,
        value.event_result.pascal_name(),
        &time_generated,
    ];
    let material = parts.join("\u{1f}");
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}
