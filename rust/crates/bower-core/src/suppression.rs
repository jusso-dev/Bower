//! Suppression key and summary event construction (C# `Bower.Core.Suppression`).
//!
//! Both are pure functions of their inputs, so every runtime derives the same key
//! hash, event id and fingerprint.

use bower_contracts::envelope::{
    ActorContext, ActorType, ApplicationContext, CURRENT_SCHEMA_VERSION, CollectorContext,
    EventResult, EventSeverity, RequestContext, SecurityEventEnvelope, TargetContext,
};
use bower_contracts::time::{self, Timestamp};
use bower_contracts::types::event_types;
use bower_contracts::{
    JsonElement, PolicyDecision, SuppressionDirective, SuppressionRequest, SuppressionWindow,
};
use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use crate::CollectorIdentity;

pub const SUMMARY_ACTION: &str = "telemetry.suppressed";
pub const SUMMARY_SOURCE_ADAPTER: &str = "suppression";

/// Length-framed SHA-256 (as `EventIdentity`), lower-case hex.
fn framed_hash<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let material: String = parts
        .into_iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect();
    hex::encode(Sha256::digest(material.as_bytes()))
}

/// `yyyy-MM-dd'T'HH:mm:ss'Z'` in UTC.
fn seconds(value: &Timestamp) -> String {
    time::to_utc(*value)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Admission request for an accepted event (C# `Suppression.CreateRequest`).
pub fn create_request(
    arranged: &SecurityEventEnvelope,
    decision: &PolicyDecision,
    directive: &SuppressionDirective,
) -> SuppressionRequest {
    let tenant = arranged
        .application
        .tenant_id
        .as_deref()
        .unwrap_or_default();
    let mut parts: Vec<&str> = vec![
        "bower-suppression-v1",
        &decision.policy_id,
        &arranged.application.name,
        &arranged.application.environment,
        tenant,
        &arranged.event_type,
    ];
    for (field, value) in directive.key_fields.iter().zip(&directive.key_values) {
        parts.push(field);
        parts.push(value);
    }
    SuppressionRequest {
        policy_id: decision.policy_id.clone(),
        policy_version: decision.policy_version.clone(),
        policy_hash: decision.policy_hash.clone(),
        key_hash: framed_hash(parts),
        key_fields: directive.key_fields.clone(),
        key_values: directive.key_values.clone(),
        window_seconds: directive.window_seconds,
        allow_per_window: directive.allow_per_window,
        event_category: arranged.event_category.clone(),
        event_type: arranged.event_type.clone(),
        application: arranged.application.name.clone(),
        environment: arranged.application.environment.clone(),
        tenant_id: arranged.application.tenant_id.clone(),
    }
}

/// Summary for a closed window, before policy evaluation (C# `Suppression.CreateSummary`).
/// Ids and times derive from the window, so a retried close cannot create a second
/// summary.
pub fn create_summary(
    window: &SuppressionWindow,
    collector: &CollectorIdentity,
    now: Timestamp,
) -> SecurityEventEnvelope {
    let rule = &window.rule;
    let window_start = seconds(&window.window_start);
    // The first suppressed time distinguishes a window recreated after the host clock
    // stepped back from the one already summarised; a retried close keeps the same id.
    let first_suppressed = window
        .first_suppressed_at
        .map(|value| time::format_round_trip(&time::to_utc(value)))
        .unwrap_or_default();
    let hash = framed_hash([
        "bower-suppression-summary-v1",
        rule.policy_id.as_str(),
        rule.key_hash.as_str(),
        window_start.as_str(),
        first_suppressed.as_str(),
    ]);
    let event_id = format!("suppression-{}", &hash[..32]);

    let labels: IndexMap<String, String> = [
        ("suppressedEventType", rule.event_type.clone()),
        ("suppressionPolicyId", rule.policy_id.clone()),
        ("suppressionKeyHash", rule.key_hash.clone()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();

    SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: event_id.clone(),
        event_original_id: None,
        time_generated: window.window_end,
        time_observed: Some(window.window_end),
        event_category: rule.event_category.clone(),
        event_type: event_types::TELEMETRY_AGGREGATION_SUMMARY.to_owned(),
        event_action: SUMMARY_ACTION.to_owned(),
        event_result: EventResult::Success,
        event_severity: EventSeverity::Medium,
        event_outcome_reason: Some(format!(
            "{} {} event(s) beyond {} per {}s",
            window.suppressed, rule.event_type, rule.allow_per_window, rule.window_seconds
        )),
        application: ApplicationContext {
            name: rule.application.clone(),
            version: None,
            environment: rule.environment.clone(),
            instance: None,
            tenant_id: rule.tenant_id.clone(),
        },
        actor: Some(ActorContext {
            actor_type: ActorType::System,
            username: Some("bower.suppression".to_owned()),
            display_name: Some("Bower suppression".to_owned()),
            ..ActorContext::default()
        }),
        target: Some(TargetContext {
            target_type: "telemetry_event_type".to_owned(),
            id: Some(rule.event_type.clone()),
            name: Some(rule.policy_id.clone()),
        }),
        source: None,
        request: Some(RequestContext {
            correlation_id: Some(event_id),
            ..RequestContext::default()
        }),
        change: None,
        security: None,
        collector: Some(CollectorContext {
            id: collector.id.clone(),
            version: collector.version.clone(),
            source_adapter: SUMMARY_SOURCE_ADAPTER.to_owned(),
            configuration_hash: collector.configuration_hash.clone(),
            batch_id: None,
            received_at: now,
        }),
        labels: Some(labels),
        attributes: Some(summary_attributes(window)),
        privacy: None,
    }
}

fn summary_attributes(window: &SuppressionWindow) -> IndexMap<String, JsonElement> {
    let rule = &window.rule;
    let time = |value: &Option<Timestamp>| {
        value.as_ref().map_or(JsonElement::Null, |value| {
            JsonElement::String(time::format_round_trip(&time::to_utc(*value)))
        })
    };
    let key = rule
        .key_fields
        .iter()
        .zip(&rule.key_values)
        .map(|(field, value)| (field.clone(), JsonElement::String(value.clone())))
        .collect();
    [
        (
            "suppressedCount",
            JsonElement::Number(window.suppressed.to_string()),
        ),
        (
            "admittedCount",
            JsonElement::Number(window.admitted.to_string()),
        ),
        (
            "allowPerWindow",
            JsonElement::Number(rule.allow_per_window.to_string()),
        ),
        (
            "windowSeconds",
            JsonElement::Number(rule.window_seconds.to_string()),
        ),
        (
            "windowStart",
            JsonElement::String(seconds(&window.window_start)),
        ),
        (
            "windowEnd",
            JsonElement::String(seconds(&window.window_end)),
        ),
        ("firstSuppressedAt", time(&window.first_suppressed_at)),
        ("lastSuppressedAt", time(&window.last_suppressed_at)),
        ("suppressionKey", JsonElement::Object(key)),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}
