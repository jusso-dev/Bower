//! Evidence bundle records (`EvidenceBundle.cs`). Metadata only: no event payloads,
//! tokens or query response bodies.

use bower_contracts::time::{Timestamp, format_json};
use bower_integrity::DetachedSignature;
use serde_json::{Map, Number, Value, json};

/// Bundle modes. Only [`VERIFIED`] is delivery evidence.
pub mod modes {
    /// The canary was found in Sentinel by query.
    pub const VERIFIED: &str = "verified";
    /// The canary was not found before the timeout, or a check failed.
    pub const FAILED: &str = "failed";
    /// No destination query was run. Never counts as delivery proof.
    pub const SIMULATED: &str = "simulated";
}

pub const CURRENT_SCHEMA: &str = "bower.evidence/v1";

#[derive(Clone, Debug, PartialEq)]
pub struct CanaryRecord {
    pub event_id: String,
    pub sent_at: Timestamp,
    pub collector_host: String,
    pub collector_status: i32,
    pub collector_decision: Option<String>,
    pub policy_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ArrivalRecord {
    pub found: bool,
    pub workspace_id: Option<String>,
    pub table: String,
    pub query: Option<String>,
    pub attempts: i32,
    pub time_generated: Option<Timestamp>,
    pub ingestion_time: Option<Timestamp>,
    pub latency_seconds: Option<f64>,
    pub row_policy_hash: Option<String>,
    pub query_error: Option<String>,
}

impl ArrivalRecord {
    /// A not-yet-found arrival for `table`.
    pub fn not_found(workspace_id: Option<String>, table: impl Into<String>) -> Self {
        Self {
            found: false,
            workspace_id,
            table: table.into(),
            query: None,
            attempts: 0,
            time_generated: None,
            ingestion_time: None,
            latency_seconds: None,
            row_policy_hash: None,
            query_error: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionRecord {
    pub plan: Option<String>,
    pub interactive_days: Option<i32>,
    pub total_days: Option<i32>,
    pub workspace_region: Option<String>,
}

/// An evidence statement for an assessor, not a compliance determination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRecord {
    pub framework: String,
    pub id: String,
    pub requirement: String,
    pub status: String,
    pub evidence: String,
}

/// What a parser probe tested (C# `ProbeRecord`): path, collector configuration
/// (pack version and hash, parser state, policy hash), exact event identity, intended
/// destination, outcome and the paths it did not test. Metadata only.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeRecord {
    pub profile: String,
    pub tested_path: String,
    pub fixture: String,
    pub pack_id: String,
    pub parser_index: i32,
    pub pack_version: Option<String>,
    pub pack_hash: Option<String>,
    pub parser_status: Option<String>,
    pub collector_policy_hash: Option<String>,
    pub event_id: String,
    pub expected_event_type: String,
    pub event_policy_id: Option<String>,
    pub event_policy_version: Option<String>,
    pub event_policy_hash: Option<String>,
    pub destination_workspace_id: Option<String>,
    pub destination_table: String,
    pub queried_at: Option<Timestamp>,
    pub outcome: String,
    pub untested_paths: Vec<String>,
}

/// A metadata-only record that Bower delivery was proven (or not).
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceBundle {
    pub schema: String,
    pub mode: String,
    pub generated_at: Timestamp,
    pub tool: String,
    pub canary: CanaryRecord,
    pub arrival: ArrivalRecord,
    pub retention: Option<RetentionRecord>,
    pub ingestion_errors_last_hour: Option<i64>,
    pub controls: Vec<ControlRecord>,
    pub limitations: Vec<String>,
    /// Parser probe record; `None` (and omitted from JSON) for the generic probe.
    pub probe: Option<ProbeRecord>,
}

/// `double.ToString(CultureInfo.InvariantCulture)` / System.Text.Json number text:
/// shortest round-trip digits, no `.0` on whole numbers, `E+XX` exponents.
pub fn format_double(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0".to_owned()
        } else {
            "0".to_owned()
        };
    }
    let magnitude = value.abs();
    if (1e-5..1e15).contains(&magnitude) {
        return format!("{value}");
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific notation");
    let exponent: i32 = exponent.parse().expect("exponent");
    format!(
        "{mantissa}E{}{:02}",
        if exponent < 0 { '-' } else { '+' },
        exponent.abs()
    )
}

fn number(value: f64) -> Value {
    serde_json::from_str::<Number>(&format_double(value))
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn timestamp(value: &Timestamp) -> Value {
    Value::String(format_json(value))
}

fn optional<T>(value: Option<T>, map: impl FnOnce(T) -> Value) -> Value {
    value.map_or(Value::Null, map)
}

impl EvidenceBundle {
    /// The bundle as `JsonSerializer.SerializeToNode(bundle)` produces it: C# property
    /// order, nulls written, `DateTimeOffset` text.
    pub fn to_json(&self) -> Value {
        let canary = &self.canary;
        let arrival = &self.arrival;
        let mut bundle = json!({
            "schema": self.schema,
            "mode": self.mode,
            "generatedAt": timestamp(&self.generated_at),
            "tool": self.tool,
            "canary": {
                "eventId": canary.event_id,
                "sentAt": timestamp(&canary.sent_at),
                "collectorHost": canary.collector_host,
                "collectorStatus": canary.collector_status,
                "collectorDecision": canary.collector_decision,
                "policyId": canary.policy_id,
            },
            "arrival": {
                "found": arrival.found,
                "workspaceId": arrival.workspace_id,
                "table": arrival.table,
                "query": arrival.query,
                "attempts": arrival.attempts,
                "timeGenerated": optional(arrival.time_generated.as_ref(), timestamp),
                "ingestionTime": optional(arrival.ingestion_time.as_ref(), timestamp),
                "latencySeconds": optional(arrival.latency_seconds, number),
                "rowPolicyHash": arrival.row_policy_hash,
                "queryError": arrival.query_error,
            },
            "retention": optional(self.retention.as_ref(), |retention| json!({
                "plan": retention.plan,
                "interactiveDays": retention.interactive_days,
                "totalDays": retention.total_days,
                "workspaceRegion": retention.workspace_region,
            })),
            "ingestionErrorsLastHour": self.ingestion_errors_last_hour,
            "controls": self.controls.iter().map(|control| json!({
                "framework": control.framework,
                "id": control.id,
                "requirement": control.requirement,
                "status": control.status,
                "evidence": control.evidence,
            })).collect::<Vec<_>>(),
            "limitations": self.limitations,
        });
        // Additive: written only for parser probes, so generic bundles are unchanged.
        if let (Some(probe), Value::Object(bundle)) = (&self.probe, &mut bundle) {
            bundle.insert(
                "probe".to_owned(),
                json!({
                    "profile": probe.profile,
                    "testedPath": probe.tested_path,
                    "fixture": probe.fixture,
                    "packId": probe.pack_id,
                    "parserIndex": probe.parser_index,
                    "packVersion": probe.pack_version,
                    "packHash": probe.pack_hash,
                    "parserStatus": probe.parser_status,
                    "collectorPolicyHash": probe.collector_policy_hash,
                    "eventId": probe.event_id,
                    "expectedEventType": probe.expected_event_type,
                    "eventPolicyId": probe.event_policy_id,
                    "eventPolicyVersion": probe.event_policy_version,
                    "eventPolicyHash": probe.event_policy_hash,
                    "destinationWorkspaceId": probe.destination_workspace_id,
                    "destinationTable": probe.destination_table,
                    "queriedAt": optional(probe.queried_at.as_ref(), timestamp),
                    "outcome": probe.outcome,
                    "untestedPaths": probe.untested_paths,
                }),
            );
        }
        bundle
    }
}

/// The bundle plus a detached signature over its canonical JSON.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedEvidence {
    pub bundle: Map<String, Value>,
    pub signature: Option<DetachedSignature>,
}

impl SignedEvidence {
    /// The bundle's `mode`, or `unknown`.
    pub fn mode(&self) -> &str {
        self.bundle
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    }

    pub fn to_value(&self) -> Value {
        json!({
            "bundle": Value::Object(self.bundle.clone()),
            "signature": optional(self.signature.as_ref(), |signature| json!({
                "Algorithm": signature.algorithm,
                "KeyId": signature.key_id,
                "Value": signature.value,
            })),
        })
    }

    /// Indented JSON as `bower evidence run` writes the bundle file.
    pub fn to_json_indented(&self) -> String {
        bower_dcr::json_text::to_indented_string(&self.to_value())
            .expect("JSON values always serialize")
    }

    /// Reads a bundle file. Number text is preserved so the canonical bytes, and
    /// therefore the signature check, match the signer's.
    pub fn from_json(text: &str) -> Result<Self, crate::EvidenceError> {
        let unreadable =
            || crate::EvidenceError::InvalidData("Evidence bundle is unreadable.".to_owned());
        let value: Value = bower_contracts::json::from_str(text).map_err(|_| unreadable())?;
        let Value::Object(mut root) = value else {
            return Err(unreadable());
        };
        let bundle = match root.remove("bundle") {
            Some(Value::Object(bundle)) => bundle,
            _ => return Err(unreadable()),
        };
        let signature = match root.remove("signature") {
            None | Some(Value::Null) => None,
            Some(value) => Some(serde_json::from_value(value).map_err(|_| unreadable())?),
        };
        Ok(Self { bundle, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::format_double;

    #[test]
    fn doubles_format_like_dotnet() {
        assert_eq!(format_double(12.3), "12.3");
        assert_eq!(format_double(120.0), "120");
        assert_eq!(format_double(0.1), "0.1");
        assert_eq!(format_double(1e15), "1E+15");
        assert_eq!(format_double(1.5e-7), "1.5E-07");
    }
}
