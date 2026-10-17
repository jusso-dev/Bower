//! `PackTester`: runs a pack's samples through redaction and policy exactly as a
//! collector would, and checks the expected decision and that listed sensitive
//! strings never survive redaction.
//!
//! Sample lines: `{"name": "...", "expect": "accept", "mustNotContain": ["..."], "event": {...}}`.
//! `{{now}}` in the event is replaced with the current UTC time (`"O"` format).

use bower_contracts::time::{Clock, SystemClock, format_round_trip};
use bower_contracts::{DecisionAction, SecurityEventEnvelope, TelemetryPolicyEvaluator};
use bower_policy::DeterministicPolicyEvaluator;
use bower_redaction::{PrivacyEngine, PrivacyPolicy};
use serde_json::Value;

use crate::archive::{LoadedPack, PackError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackSampleResult {
    pub name: String,
    pub passed: bool,
    pub expected_decision: String,
    pub actual_decision: String,
    pub problems: Vec<String>,
}

fn invalid(message: String) -> PackError {
    PackError::InvalidData(message)
}

/// `JsonNode.GetValue<string>()` on an optional member: absent or `null` is `None`,
/// any other kind is an error as in C#.
fn optional_string<'a>(
    sample: &'a serde_json::Map<String, Value>,
    name: &str,
    label: &str,
) -> Result<Option<&'a str>, PackError> {
    match sample.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(invalid(format!(
            "Sample '{label}' member '{name}' must be a string."
        ))),
    }
}

pub fn run(
    pack: &LoadedPack,
    privacy: PrivacyPolicy,
    clock: Option<&dyn Clock>,
) -> Result<Vec<PackSampleResult>, PackError> {
    let now = clock.unwrap_or(&SystemClock).utc_now();
    let now_text = format_round_trip(&now);
    let engine = PrivacyEngine::new(privacy).map_err(|error| invalid(error.to_string()))?;
    let evaluator = DeterministicPolicyEvaluator::new(pack.policies.iter().cloned());
    let mut results = Vec::new();
    for (position, line) in pack.sample_lines.iter().enumerate() {
        let index = position + 1;
        let sample = match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(sample)) => sample,
            _ => return Err(invalid(format!("Sample {index} is not a JSON object."))),
        };
        let fallback = format!("sample-{index}");
        let name =
            optional_string(&sample, "name", &fallback)?.map_or(fallback.clone(), str::to_owned);
        let expected = optional_string(&sample, "expect", &name)?
            .unwrap_or("accept")
            .replace('-', "");
        let event = match sample.get("event") {
            None | Some(Value::Null) => {
                return Err(invalid(format!("Sample '{name}' has no event.")));
            }
            Some(event) => event,
        };
        // `JsonNode.ToJsonString()` uses System.Text.Json escaping.
        let event_json = bower_contracts::json::to_string(event)
            .map_err(|_| invalid(format!("Sample '{name}' event cannot be serialized.")))?
            .replace("{{now}}", &now_text);
        let mut problems = Vec::new();

        let redaction = engine.redact_json(&event_json);
        let actual = match (&redaction.redacted_json, redaction.succeeded) {
            (Some(redacted), true) => {
                let envelope: SecurityEventEnvelope = bower_contracts::json::from_str(redacted)
                    .map_err(|_| {
                        invalid(format!("Sample '{name}' is not a valid security event."))
                    })?;
                let decision = evaluator.evaluate(&envelope);
                let actual = match decision.action {
                    DecisionAction::Accept if !redaction.findings.is_empty() => {
                        "redactandaccept".to_owned()
                    }
                    action => action.pascal_name().to_lowercase(),
                };

                if let Some(Value::Array(forbidden)) = sample.get("mustNotContain") {
                    for item in forbidden {
                        let Value::String(forbidden) = item else {
                            return Err(invalid(format!(
                                "Sample '{name}' mustNotContain entries must be strings."
                            )));
                        };
                        if redacted.contains(forbidden.as_str()) {
                            problems.push(format!(
                                "Redacted event still contains a forbidden value ({} characters).",
                                forbidden.encode_utf16().count()
                            ));
                        }
                    }
                }
                actual
            }
            _ => "quarantine".to_owned(),
        };

        let decision_matches = expected.eq_ignore_ascii_case(&actual)
            || (expected.eq_ignore_ascii_case("accept") && actual == "redactandaccept");
        if !decision_matches {
            problems.push(format!("Expected {expected}, got {actual}."));
        }

        results.push(PackSampleResult {
            name,
            passed: problems.is_empty(),
            expected_decision: expected,
            actual_decision: actual,
            problems,
        });
    }
    Ok(results)
}
