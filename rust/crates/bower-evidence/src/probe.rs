//! Opt-in parser probes (`ParserProbe.cs`): a trusted synthetic raw record goes
//! through a signed pack parser's HTTP intake instead of the generic `/v1/events`
//! canary. Only repo-owned fixtures can be probed.

use bower_contracts::time::Timestamp;
use serde_json::{Map, Value};

use crate::EvidenceError;

/// The default profile: the canary envelope to `/v1/events`.
pub const GENERIC: &str = "generic";
pub const PARSER_PREFIX: &str = "parser:";

/// A bounded synthetic raw record for one shipped parser: a fixed probe username and
/// a documentation (TEST-NET-1) address. The record id is the unique probe event id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParserProbeFixture {
    pub id: &'static str,
    pub pack_id: &'static str,
    pub parser_index: i32,
    pub expected_event_type: &'static str,
}

pub const LINUX_SSH_GATEWAY: ParserProbeFixture = ParserProbeFixture {
    id: "linux-ssh-gateway/sshd-json/authentication-failure@1",
    pack_id: "linux-ssh-gateway",
    parser_index: 0,
    expected_event_type: "authentication_failure",
};

pub const FIXTURES: &[ParserProbeFixture] = &[LINUX_SSH_GATEWAY];

impl ParserProbeFixture {
    pub fn profile(&self) -> String {
        format!("{PARSER_PREFIX}{}:{}", self.pack_id, self.parser_index)
    }

    pub fn path(&self) -> String {
        format!(
            "/v1/packs/{}/parsers/{}/events",
            self.pack_id, self.parser_index
        )
    }

    /// The raw record JSON; byte-identical with C# `ParserProbeFixture.Render`.
    pub fn render(&self, event_id: &str, sent_at: Timestamp) -> String {
        let mut record = Map::new();
        record.insert("id".to_owned(), Value::String(event_id.to_owned()));
        record.insert("timestamp".to_owned(), Value::String(timestamp(sent_at)));
        record.insert(
            "user".to_owned(),
            Value::String("bower-evidence-probe".to_owned()),
        );
        record.insert(
            "source_ip".to_owned(),
            Value::String("192.0.2.10".to_owned()),
        );
        record.insert("result".to_owned(), Value::String("failure".to_owned()));
        bower_contracts::json::to_string(&Value::Object(record))
            .expect("JSON values always serialize")
    }
}

/// UTC with seven fractional digits, which every parser runtime accepts.
pub fn timestamp(value: Timestamp) -> String {
    use chrono::Timelike;
    let utc = value.with_timezone(&chrono::Utc);
    format!(
        "{}.{:07}Z",
        utc.format("%Y-%m-%dT%H:%M:%S"),
        (utc.nanosecond() % 1_000_000_000) / 100
    )
}

/// The trusted fixture for a `parser:PACK:INDEX` profile; anything else fails before
/// anything is sent.
pub fn resolve_parser(profile: &str) -> Result<ParserProbeFixture, EvidenceError> {
    FIXTURES
        .iter()
        .find(|fixture| fixture.profile() == profile)
        .copied()
        .ok_or_else(|| {
            EvidenceError::InvalidArgument(format!(
                "--probe-profile must be {GENERIC} or one of: {}.",
                FIXTURES
                    .iter()
                    .map(ParserProbeFixture::profile)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// Parser probe results (C# `ProbeOutcomes`). Only [`outcomes::VERIFIED`] is evidence.
pub mod outcomes {
    pub const VERIFIED: &str = "verified";
    pub const ACCEPTED_NOT_VERIFIED: &str = "accepted-not-verified";
    pub const PARSER_INACTIVE: &str = "parser-inactive";
    pub const PARSER_RECORD_REJECTED: &str = "parser-record-rejected";
    pub const PARSER_NOT_SELECTED: &str = "parser-not-selected";
    pub const PARSER_WRONG_EVENT: &str = "parser-wrong-event";
    pub const POLICY_NOT_SELECTED: &str = "policy-not-selected";
    /// Accepted but not queued (duplicate or suppressed): nothing reaches the destination.
    pub const PROBE_NOT_QUEUED: &str = "probe-not-queued";
    /// The exact probe row arrived with a policy hash other than the collector reported.
    pub const CONFIGURATION_MISMATCH: &str = "configuration-mismatch";
    pub const COLLECTOR_PERMISSION_DENIED: &str = "collector-permission-denied";
    pub const COLLECTOR_STATUS_UNREADABLE: &str = "collector-status-unreadable";
    pub const COLLECTOR_REJECTED: &str = "collector-rejected";
    pub const DESTINATION_PERMISSION_DENIED: &str = "destination-permission-denied";
    pub const DESTINATION_ROW_MISSING: &str = "destination-row-missing";
    pub const DESTINATION_WRONG_EVENT: &str = "destination-wrong-event";
    pub const DESTINATION_TIMEOUT: &str = "destination-timeout";
    pub const DESTINATION_QUERY_FAILED: &str = "destination-query-failed";
    /// Query error code when the query call itself timed out.
    pub const QUERY_TIMEOUT_CODE: &str = "query-timeout";
    /// Query error code when the query call failed in transport.
    pub const QUERY_TRANSPORT_CODE: &str = "query-transport-failed";
}

/// Paths a parser probe never exercises; every parser bundle lists them.
pub const UNTESTED_PATHS: &[&str] = &[
    "Generic event intake (POST /v1/events).",
    "Other packs and parsers loaded by the collector.",
    "Other event types, selection branches and privacy rules of this pack.",
    "Agents, forwarders and log readers upstream of collector HTTP intake.",
    "Delivery of any event other than this probe.",
];

fn contains_ignore_case(text: &str, needle: &str) -> bool {
    text.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Log Analytics error codes that mean the verifier identity lacks access.
pub fn is_permission_error(code: &str) -> bool {
    matches!(code, "http-401" | "http-403")
        || [
            "InsufficientAccess",
            "Authorization",
            "Authentication",
            "Forbidden",
            "Unauthorized",
        ]
        .iter()
        .any(|needle| contains_ignore_case(code, needle))
}

/// Query error codes that mean the destination did not answer in time.
pub fn is_timeout_error(code: &str) -> bool {
    matches!(code, outcomes::QUERY_TIMEOUT_CODE | "http-408" | "http-504")
        || contains_ignore_case(code, "Timeout")
}

pub(crate) fn text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

/// Classifies a collector parser intake response; `None` means accepted.
pub fn classify(
    status: u16,
    body: Option<&Map<String, Value>>,
    expected_event_id: &str,
) -> Option<&'static str> {
    if matches!(status, 200 | 202) {
        let event_id = text(body.and_then(|body| body.get("eventId")));
        if event_id.as_deref() != Some(expected_event_id) {
            return Some(outcomes::PARSER_WRONG_EVENT);
        }
        // Accepted but counted, deduplicated or not queued: nothing will reach the destination.
        let flag = |name: &str| {
            body.and_then(|body| body.get(name))
                .and_then(Value::as_bool)
        };
        return (flag("duplicate") == Some(true)
            || flag("suppressed") == Some(true)
            || flag("queued") == Some(false))
        .then_some(outcomes::PROBE_NOT_QUEUED);
    }
    let error = text(body.and_then(|body| body.get("error")));
    let has_decision = body
        .and_then(|body| body.get("decision"))
        .is_some_and(|decision| !decision.is_null());
    Some(match status {
        401 | 403 => outcomes::COLLECTOR_PERMISSION_DENIED,
        404 => outcomes::PARSER_INACTIVE,
        422 if error.as_deref() == Some("pack-record-not-selected") => {
            outcomes::PARSER_NOT_SELECTED
        }
        400 | 422 if has_decision => outcomes::POLICY_NOT_SELECTED,
        400 | 413 | 415 => outcomes::PARSER_RECORD_REJECTED,
        _ => outcomes::COLLECTOR_REJECTED,
    })
}
