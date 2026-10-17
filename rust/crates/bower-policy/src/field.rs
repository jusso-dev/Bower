//! Port of `EventFieldReader`: a closed allow-list of envelope paths a policy
//! may require. Unknown paths are never present.

use bower_contracts::{EventResult, SecurityEventEnvelope};
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

/// Returns whether `path` names a populated envelope field.
pub fn has_value(value: &SecurityEventEnvelope, path: &str) -> bool {
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
