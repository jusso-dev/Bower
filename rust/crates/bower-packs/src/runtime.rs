//! Signed, bounded JSON-to-semantic mappings and local detection enrichment.
//! Raw source fields never pass through to arbitrary envelope attributes.

use std::collections::HashSet;
use std::sync::Arc;

use bower_contracts::{
    DecisionAction, EventRedactor, JsonElement, RedactionResult, SecurityEventEnvelope,
    TelemetryPolicyEvaluator, json,
};
use bower_detection::{DetectionEngine, DetectionRule};
use bower_pipeline::custom_log::{
    CustomLogParserConfiguration, CustomLogValueType, validate_configuration,
};

pub const MAXIMUM_RAW_BYTES: usize = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingError {
    Inactive,
    Invalid,
    TooLarge,
    NoMatch,
}

pub fn parser_status(parser: &CustomLogParserConfiguration) -> &'static str {
    if parser.runtime.is_some() {
        "active-local-json"
    } else {
        "inactive-preview-only"
    }
}

fn bounded_tree(value: &JsonElement, depth: usize) -> bool {
    match value {
        JsonElement::Object(fields) => {
            let mut seen = HashSet::new();
            depth <= 16
                && fields
                    .iter()
                    .all(|(key, value)| seen.insert(key) && bounded_tree(value, depth + 1))
        }
        JsonElement::Array(values) => {
            depth <= 16 && values.iter().all(|value| bounded_tree(value, depth + 1))
        }
        _ => true,
    }
}

fn offset_timestamp(text: &str) -> bool {
    let offset = text.ends_with('Z')
        || (text.len() >= 6
            && matches!(text.as_bytes()[text.len() - 6], b'+' | b'-')
            && text.as_bytes()[text.len() - 3] == b':');
    text.contains('T') && offset && bower_contracts::time::parse(text).is_some()
}

fn valid_type(value: &str, kind: CustomLogValueType) -> bool {
    match kind {
        CustomLogValueType::Text => true,
        CustomLogValueType::DateTime => offset_timestamp(value),
        CustomLogValueType::IpAddress => value.parse::<std::net::IpAddr>().is_ok(),
        CustomLogValueType::WholeNumber => value.trim().parse::<i64>().is_ok(),
        CustomLogValueType::Boolean => matches!(value, "true" | "false"),
    }
}

pub fn map_raw(
    parser: &CustomLogParserConfiguration,
    raw: &str,
) -> Result<SecurityEventEnvelope, MappingError> {
    let runtime = parser.runtime.as_ref().ok_or(MappingError::Inactive)?;
    if !validate_configuration(parser).is_empty() {
        return Err(MappingError::Invalid);
    }
    if raw.len() > MAXIMUM_RAW_BYTES {
        return Err(MappingError::TooLarge);
    }
    let value = JsonElement::parse(raw).map_err(|_| MappingError::Invalid)?;
    let JsonElement::Object(fields) = &value else {
        return Err(MappingError::Invalid);
    };
    if fields.len() > 64 || !bounded_tree(&value, 1) {
        return Err(MappingError::Invalid);
    }
    let read = |source: &str| -> Result<&str, MappingError> {
        let text = value
            .get(source)
            .and_then(JsonElement::as_str)
            .ok_or(MappingError::Invalid)?;
        let declared = parser
            .fields
            .iter()
            .find(|field| field.source_name == source)
            .ok_or(MappingError::Invalid)?;
        if text.trim().is_empty()
            || text.encode_utf16().count() > 2048
            || !valid_type(text, declared.value_type)
        {
            return Err(MappingError::Invalid);
        }
        Ok(text)
    };
    for (source, expected) in &runtime.match_fields {
        if read(source)? != expected {
            return Err(MappingError::NoMatch);
        }
    }
    let mapped = |target: &str| -> Result<&str, MappingError> {
        read(runtime.fields.get(target).ok_or(MappingError::Invalid)?)
    };
    let id = mapped("eventId")?;
    let timestamp = mapped("timeGenerated")?;
    if id.trim().is_empty() || id.encode_utf16().count() > 128 || !offset_timestamp(timestamp) {
        return Err(MappingError::Invalid);
    }
    let mut envelope = vec![
        ("schemaVersion".into(), JsonElement::from("1.0.0")),
        ("eventId".into(), id.into()),
        ("eventOriginalId".into(), id.into()),
        ("timeGenerated".into(), timestamp.into()),
        (
            "eventCategory".into(),
            runtime.event_category.clone().into(),
        ),
        ("eventType".into(), runtime.event_type.clone().into()),
        ("eventAction".into(), runtime.event_action.clone().into()),
        ("eventResult".into(), runtime.event_result.clone().into()),
        (
            "application".into(),
            JsonElement::Object(vec![
                ("name".into(), runtime.application_name.clone().into()),
                ("environment".into(), runtime.environment.clone().into()),
            ]),
        ),
    ];
    for (context, targets) in [
        ("actor", &["username", "userId"][..]),
        ("source", &["ipAddress"][..]),
        ("request", &["correlationId"][..]),
    ] {
        let mut values = Vec::new();
        for target in targets {
            let key = format!("{context}.{target}");
            if runtime.fields.contains_key(&key) {
                let value = mapped(&key)?;
                if key == "source.ipAddress" && value.parse::<std::net::IpAddr>().is_err() {
                    return Err(MappingError::Invalid);
                }
                values.push(((*target).into(), value.into()));
            }
        }
        if !values.is_empty() {
            envelope.push((context.into(), JsonElement::Object(values)));
        }
    }
    if runtime.fields.contains_key("eventOutcomeReason") {
        envelope.push((
            "eventOutcomeReason".into(),
            mapped("eventOutcomeReason")?.into(),
        ));
    }
    let text =
        json::to_string(&JsonElement::Object(envelope)).map_err(|_| MappingError::Invalid)?;
    json::from_str(&text).map_err(|_| MappingError::Invalid)
}

/// Runs after privacy redaction, before core selection and its single source-event
/// enqueue. Caller-supplied evidence is always removed; rule evaluation is fresh
/// per event so retries carry identical metadata (no alert IDs or clock state).
pub struct PackDetectionRedactor {
    pub inner: Arc<dyn EventRedactor>,
    pub evaluator: Arc<dyn TelemetryPolicyEvaluator>,
    pub rules: Vec<DetectionRule>,
}

impl EventRedactor for PackDetectionRedactor {
    fn redact(&self, candidate: &str) -> RedactionResult {
        let mut result = self.inner.redact(candidate);
        if !result.succeeded {
            return result;
        }
        let Some(text) = result.redacted_json.as_deref() else {
            return result;
        };
        let Ok(mut envelope) = json::from_str::<SecurityEventEnvelope>(text) else {
            return RedactionResult::failed("pack-detection-failed");
        };
        if let Some(attributes) = envelope.attributes.as_mut() {
            attributes.retain(|key, _| !key.eq_ignore_ascii_case("bowerDetections"));
            if attributes.is_empty() {
                envelope.attributes = None;
            }
        }
        if !self.rules.is_empty()
            && matches!(
                self.evaluator.evaluate(&envelope).action,
                DecisionAction::Accept | DecisionAction::RedactAndAccept
            )
        {
            let mut engine = DetectionEngine::new(self.rules.clone(), []);
            let Ok(evaluation) = engine.evaluate(&envelope, Some(envelope.time_generated)) else {
                return RedactionResult::failed("pack-detection-failed");
            };
            let mut alerts = evaluation.alerts;
            alerts.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
            if !alerts.is_empty() {
                let values = alerts
                    .into_iter()
                    .map(|alert| {
                        JsonElement::Object(vec![
                            ("ruleId".into(), alert.rule_id.into()),
                            ("ruleVersion".into(), alert.rule_version.into()),
                            ("ruleHash".into(), alert.rule_hash.into()),
                            (
                                "mitreTechniques".into(),
                                JsonElement::Array(
                                    alert
                                        .mitre_techniques
                                        .into_iter()
                                        .map(JsonElement::from)
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect();
                envelope
                    .attributes
                    .get_or_insert_default()
                    .insert("bowerDetections".into(), JsonElement::Array(values));
            }
        }
        match json::to_string(&envelope) {
            Ok(text) => result.redacted_json = Some(text),
            Err(_) => return RedactionResult::failed("pack-detection-failed"),
        }
        result
    }
}
