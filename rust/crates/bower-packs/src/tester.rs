//! `PackTester`: runs a pack's samples through redaction and policy exactly as a
//! collector would, and checks the expected decision and that listed sensitive
//! strings never survive redaction.
//!
//! Sample lines: `{"name": "...", "expect": "accept", "mustNotContain": ["..."], "event": {...}}`.
//! `{{now}}` in the event is replaced with the current UTC time (`"O"` format). Raw
//! samples run the parser's transform program with that same time as its evaluation
//! time; a transform failure is decision `quarantine` (never redacted, selected or kept).
//!
//! Expectations: `accept` passes for accept and for redact-and-accept, because the
//! event is delivered either way (prove the redaction with `mustNotContain`);
//! `redact-and-accept` requires that redaction happened; every other expectation
//! must match exactly. `expectFields` asserts paths of the redacted event
//! ([`crate::assertions`]). `parser` is a zero-based index or a parser name (file name
//! without extension, or its pack path). Unknown or duplicated sample members fail, so
//! a mistyped assertion cannot silently pass. Line format:
//! `schemas/packs/pack-sample.schema.json` (v2).

use bower_contracts::time::{Clock, SystemClock, format_round_trip};
use std::sync::Arc;

use bower_contracts::{
    DecisionAction, EventRedactor, JsonElement, SecurityEventEnvelope, TelemetryPolicyEvaluator,
};
use bower_policy::DeterministicPolicyEvaluator;
use bower_redaction::{JsonEventRedactor, PrivacyPolicy};

use crate::assertions;
use crate::runtime::{MappingError, PackDetectionRedactor, map_raw};
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

const MEMBERS: [&str; 8] = [
    "name",
    "expect",
    "event",
    "raw",
    "parser",
    "mustNotContain",
    "expectedDetections",
    "expectFields",
];

/// Index of a parser by name (file name without extension) or pack path; `None` when
/// no parser or more than one parser has that name.
pub fn parser_index(pack: &LoadedPack, name: &str) -> Option<usize> {
    let mut matches = pack
        .parser_paths
        .iter()
        .enumerate()
        .filter(|(_, path)| {
            path.as_str() == name
                || std::path::Path::new(path.as_str())
                    .file_stem()
                    .is_some_and(|stem| stem == name)
        })
        .map(|(index, _)| index);
    match (matches.next(), matches.next()) {
        (Some(index), None) => Some(index),
        _ => None,
    }
}

/// The parser a raw sample names: a string is a parser name, otherwise an index.
fn sample_parser(
    pack: &LoadedPack,
    parser: Option<&Value>,
    name: &str,
) -> Result<usize, PackError> {
    match parser {
        Some(Value::String(parser)) => parser_index(pack, parser)
            .ok_or_else(|| invalid(format!("Sample '{name}' parser is invalid."))),
        other => other
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < pack.parsers.len())
            .ok_or_else(|| invalid(format!("Sample '{name}' parser is invalid."))),
    }
}

pub fn run(
    pack: &LoadedPack,
    privacy: PrivacyPolicy,
    clock: Option<&dyn Clock>,
) -> Result<Vec<PackSampleResult>, PackError> {
    run_parser(pack, privacy, clock, None)
}

/// [`run`] limited to one parser's raw samples (`parser` is a name or pack path).
pub fn run_parser(
    pack: &LoadedPack,
    privacy: PrivacyPolicy,
    clock: Option<&dyn Clock>,
    parser: Option<&str>,
) -> Result<Vec<PackSampleResult>, PackError> {
    let only = match parser {
        None => None,
        Some(parser) => Some(
            parser_index(pack, parser)
                .ok_or_else(|| invalid(format!("Pack has no parser '{parser}'.")))?,
        ),
    };
    let now = clock.unwrap_or(&SystemClock).utc_now();
    let now_text = format_round_trip(&now);
    let evaluator: Arc<dyn TelemetryPolicyEvaluator> = Arc::new(DeterministicPolicyEvaluator::new(
        pack.policies.iter().cloned(),
    ));
    let engine = PackDetectionRedactor {
        inner: Arc::new(
            JsonEventRedactor::with_policy(privacy).map_err(|error| invalid(error.to_string()))?,
        ),
        evaluator: Arc::clone(&evaluator),
        rules: pack.detections.clone(),
    };
    let mut results = Vec::new();
    for (position, line) in pack.sample_lines.iter().enumerate() {
        let index = position + 1;
        let sample = match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(sample)) => sample,
            _ => return Err(invalid(format!("Sample {index} is not a JSON object."))),
        };
        // Keeps duplicate members, which `serde_json` would collapse.
        let document = JsonElement::parse(line)
            .map_err(|_| invalid(format!("Sample {index} is not a JSON object.")))?;
        if let JsonElement::Object(members) = &document {
            let mut seen = std::collections::HashSet::new();
            if let Some((member, _)) = members
                .iter()
                .find(|(member, _)| !MEMBERS.contains(&member.as_str()) || !seen.insert(member))
            {
                return Err(invalid(format!(
                    "Sample {index} member '{member}' is unknown or duplicated."
                )));
            }
        }
        let fallback = format!("sample-{index}");
        let name =
            optional_string(&sample, "name", &fallback)?.map_or(fallback.clone(), str::to_owned);
        let parser_position = if sample.contains_key("raw") {
            Some(sample_parser(pack, sample.get("parser"), &name)?)
        } else {
            None
        };
        if only.is_some() && parser_position != only {
            continue;
        }
        let expectations = assertions::parse(&document, &name)?;
        let expected = optional_string(&sample, "expect", &name)?
            .unwrap_or("accept")
            .replace('-', "");
        let mut problems = Vec::new();
        let expected_detections = match sample.get("expectedDetections") {
            None => None,
            Some(Value::Array(ids)) if ids.iter().all(Value::is_string) => Some(
                ids.iter()
                    .map(|id| id.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>(),
            ),
            _ => {
                return Err(invalid(format!(
                    "Sample '{name}' expectedDetections must be a string array."
                )));
            }
        };
        let mut mapping_decision = None;
        let mut transform_failure = None;
        let mut raw_json = None;
        let event_json = if let Some(parser) = parser_position {
            let parser = &pack.parsers[parser];
            // Preserve duplicate raw keys so the same runtime rejects them here and at HTTP ingest.
            let raw = bower_contracts::json::to_string(document.get("raw").unwrap())
                .map_err(|_| invalid(format!("Sample '{name}' raw cannot be serialized.")))?
                .replace("{{now}}", &now_text);
            let mapped = map_raw(parser, &raw, &now);
            raw_json = Some(raw);
            match mapped {
                Ok(envelope) => bower_contracts::json::to_string(&envelope)
                    .map_err(|_| invalid(format!("Sample '{name}' event cannot be serialized.")))?,
                Err(MappingError::NoMatch) => {
                    mapping_decision = Some("reject");
                    String::new()
                }
                Err(MappingError::Transform(code)) => {
                    // Quarantined before redaction, as a collector does; only the code is kept.
                    mapping_decision = Some("quarantine");
                    transform_failure = Some(code);
                    String::new()
                }
                Err(_) => return Err(invalid(format!("Sample '{name}' raw event is invalid."))),
            }
        } else {
            let event = sample
                .get("event")
                .filter(|value| !value.is_null())
                .ok_or_else(|| invalid(format!("Sample '{name}' has no event.")))?;
            bower_contracts::json::to_string(event)
                .map_err(|_| invalid(format!("Sample '{name}' event cannot be serialized.")))?
                .replace("{{now}}", &now_text)
        };
        let redaction = engine.redact(&event_json);
        let mut detected = Vec::new();
        let actual = match (&redaction.redacted_json, redaction.succeeded) {
            (Some(redacted), true) => {
                let envelope: SecurityEventEnvelope = bower_contracts::json::from_str(redacted)
                    .map_err(|_| {
                        invalid(format!("Sample '{name}' is not a valid security event."))
                    })?;
                if let Some(JsonElement::Array(alerts)) = envelope
                    .attributes
                    .as_ref()
                    .and_then(|attributes| attributes.get("bowerDetections"))
                {
                    for alert in alerts {
                        if let Some(id) = alert.get("ruleId").and_then(JsonElement::as_str) {
                            detected.push(id.to_owned());
                        }
                    }
                }
                let decision = evaluator.evaluate(&envelope);
                let actual = match decision.action {
                    DecisionAction::Accept
                        if !redaction.removed_paths.is_empty()
                            || !redaction.masked_paths.is_empty()
                            || redaction
                                .privacy_detected
                                .as_ref()
                                .is_some_and(|ids| !ids.is_empty()) =>
                    {
                        "redactandaccept".to_owned()
                    }
                    action => action.pascal_name().to_lowercase(),
                };

                let mut forbidden_values = Vec::new();
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
                        forbidden_values.push(forbidden.as_str());
                    }
                }
                if let Some(expectations) = &expectations {
                    // Pre-redaction inputs only identify withheld values; they are never echoed.
                    let mut inputs = Vec::new();
                    inputs.extend(raw_json.as_deref());
                    inputs.push(event_json.as_str());
                    problems.extend(assertions::check(
                        expectations,
                        redacted,
                        &inputs,
                        &forbidden_values,
                    )?);
                }
                actual
            }
            _ => "quarantine".to_owned(),
        };

        let actual = mapping_decision.map(str::to_owned).unwrap_or(actual);
        let redacted_event =
            mapping_decision.is_none() && redaction.succeeded && redaction.redacted_json.is_some();
        if expectations.is_some() && !redacted_event {
            problems.push(format!(
                "Field assertions need a redacted event; got {actual}."
            ));
        }
        if expected_detections.is_some_and(|mut expected| {
            expected.sort();
            detected.sort();
            expected != detected
        }) {
            problems.push("Expected detection rule ids do not match local execution.".into());
        }

        // `accept` also covers redact-and-accept; the reverse does not hold.
        let decision_matches = expected.eq_ignore_ascii_case(&actual)
            || (expected.eq_ignore_ascii_case("accept") && actual == "redactandaccept");
        if !decision_matches {
            problems.push(format!("Expected {expected}, got {actual}."));
            if let Some(code) = transform_failure {
                problems.push(format!("Transform failed: {code}."));
            }
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
