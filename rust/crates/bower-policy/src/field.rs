//! Port of `EventFieldReader`: a closed allow-list of envelope paths a policy
//! may require. Unknown paths are never present.

use bower_contracts::{EventResult, JsonElement, SecurityEventEnvelope};
use chrono::DateTime;

/// `string.IsNullOrWhiteSpace` negated. Rust `char::is_whitespace` (Unicode
/// `White_Space`) is the same set as .NET `char.IsWhiteSpace`.
pub(crate) fn present(value: Option<&str>) -> bool {
    value.is_some_and(|text| !text.trim().is_empty())
}

/// `DateTimeOffset != default`: equality compares UTC instants, so any
/// offset whose instant is 0001-01-01T00:00:00Z counts as default.
fn is_default_time(value: &bower_contracts::time::Timestamp) -> bool {
    // 0001-01-01T00:00:00Z as Unix seconds.
    const DOTNET_MIN_UNIX_SECONDS: i64 = -62_135_596_800;
    DateTime::from_timestamp(DOTNET_MIN_UNIX_SECONDS, 0).is_some_and(|min| *value == min)
}

/// JSON null is absent and a string must be non-blank; numbers, booleans,
/// objects and arrays are present.
fn present_element(value: &JsonElement) -> bool {
    match value {
        JsonElement::Null => false,
        JsonElement::String(text) => present(Some(text)),
        _ => true,
    }
}

/// Returns whether `path` names a populated envelope field.
///
/// `labels.<key>` and `attributes.<key>` name one top-level entry; the key is
/// the rest of the path, matched exactly (it may itself contain dots).
pub fn has_value(value: &SecurityEventEnvelope, path: &str) -> bool {
    if let Some(key) = path.strip_prefix("labels.") {
        return value
            .labels
            .as_ref()
            .and_then(|labels| labels.get(key))
            .is_some_and(|label| present(Some(label)));
    }
    if let Some(key) = path.strip_prefix("attributes.") {
        return value
            .attributes
            .as_ref()
            .and_then(|attributes| attributes.get(key))
            .is_some_and(present_element);
    }
    match path {
        "schemaVersion" => present(Some(&value.schema_version)),
        "eventId" => present(Some(&value.event_id)),
        "eventOriginalId" => present(value.event_original_id.as_deref()),
        "timeGenerated" => !is_default_time(&value.time_generated),
        "eventCategory" => present(Some(&value.event_category)),
        "eventType" => present(Some(&value.event_type)),
        "eventAction" => present(Some(&value.event_action)),
        "eventResult" => value.event_result != EventResult::Unknown,
        "application.name" => present(Some(&value.application.name)),
        "application.environment" => present(Some(&value.application.environment)),
        "application.tenantId" => present(value.application.tenant_id.as_deref()),
        "actor.userId" => present(value.actor.as_ref().and_then(|a| a.user_id.as_deref())),
        "actor.username" => present(value.actor.as_ref().and_then(|a| a.username.as_deref())),
        "target.id" => present(value.target.as_ref().and_then(|t| t.id.as_deref())),
        "target.type" => present(value.target.as_ref().map(|t| t.target_type.as_str())),
        "target.name" => present(value.target.as_ref().and_then(|t| t.name.as_deref())),
        "change.field" => present(value.change.as_ref().and_then(|c| c.field.as_deref())),
        "change.previousValue" => present(
            value
                .change
                .as_ref()
                .and_then(|c| c.previous_value.as_deref()),
        ),
        "change.newValue" => present(value.change.as_ref().and_then(|c| c.new_value.as_deref())),
        "source.ipAddress" => present(value.source.as_ref().and_then(|s| s.ip_address.as_deref())),
        "request.correlationId" => present(
            value
                .request
                .as_ref()
                .and_then(|r| r.correlation_id.as_deref()),
        ),
        "request.traceId" => present(value.request.as_ref().and_then(|r| r.trace_id.as_deref())),
        "eventOutcomeReason" => present(value.event_outcome_reason.as_deref()),
        _ => false,
    }
}

/// String-valued paths a suppression key may use: identity and context fields plus
/// `labels.<key>`. Times, results, ids and change values are excluded.
const SUPPRESSION_KEY_PATHS: &[&str] = &[
    "eventCategory",
    "eventType",
    "eventAction",
    "eventOutcomeReason",
    "application.name",
    "application.environment",
    "application.tenantId",
    "actor.userId",
    "actor.username",
    "target.id",
    "target.type",
    "target.name",
    "change.field",
    "source.ipAddress",
    "request.correlationId",
    "request.traceId",
];

/// C# `EventFieldReader.IsSuppressionKey`.
pub fn is_suppression_key(path: Option<&str>) -> bool {
    path.is_some_and(|path| {
        SUPPRESSION_KEY_PATHS.contains(&path)
            || path
                .strip_prefix("labels.")
                .is_some_and(|key| !key.is_empty())
    })
}

/// Value of a suppression key path; an absent value is the empty string.
pub fn get_suppression_key_value(value: &SecurityEventEnvelope, path: &str) -> String {
    if let Some(key) = path.strip_prefix("labels.") {
        return value
            .labels
            .as_ref()
            .and_then(|labels| labels.get(key))
            .cloned()
            .unwrap_or_default();
    }
    let text: Option<&str> = match path {
        "eventCategory" => Some(&value.event_category),
        "eventType" => Some(&value.event_type),
        "eventAction" => Some(&value.event_action),
        "eventOutcomeReason" => value.event_outcome_reason.as_deref(),
        "application.name" => Some(&value.application.name),
        "application.environment" => Some(&value.application.environment),
        "application.tenantId" => value.application.tenant_id.as_deref(),
        "actor.userId" => value.actor.as_ref().and_then(|a| a.user_id.as_deref()),
        "actor.username" => value.actor.as_ref().and_then(|a| a.username.as_deref()),
        "target.id" => value.target.as_ref().and_then(|t| t.id.as_deref()),
        "target.type" => value.target.as_ref().map(|t| t.target_type.as_str()),
        "target.name" => value.target.as_ref().and_then(|t| t.name.as_deref()),
        "change.field" => value.change.as_ref().and_then(|c| c.field.as_deref()),
        "source.ipAddress" => value.source.as_ref().and_then(|s| s.ip_address.as_deref()),
        "request.correlationId" => value
            .request
            .as_ref()
            .and_then(|r| r.correlation_id.as_deref()),
        "request.traceId" => value.request.as_ref().and_then(|r| r.trace_id.as_deref()),
        _ => None,
    };
    text.unwrap_or_default().to_owned()
}
