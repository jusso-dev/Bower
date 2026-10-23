//! Source-scoped stable identity, byte-identical to C# EventFingerprint v2.
use bower_contracts::SecurityEventEnvelope;
use sha2::{Digest, Sha256};

pub fn create(value: &SecurityEventEnvelope) -> String {
    let original = value
        .event_original_id
        .as_deref()
        .filter(|id| !id.is_empty());
    let parts = [
        "bower-identity-v2",
        value.collector.as_ref().map_or("", |v| v.id.as_str()),
        value
            .collector
            .as_ref()
            .map_or("", |v| v.source_adapter.as_str()),
        value.application.name.as_str(),
        value.application.environment.as_str(),
        value.application.tenant_id.as_deref().unwrap_or(""),
        value.application.instance.as_deref().unwrap_or(""),
        value
            .source
            .as_ref()
            .and_then(|v| v.hostname.as_deref())
            .unwrap_or(""),
        if original.is_some() {
            "original"
        } else {
            "event"
        },
        original.unwrap_or(&value.event_id),
    ];
    let material: String = parts
        .iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect();
    format!(
        "sha256:v2:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}
