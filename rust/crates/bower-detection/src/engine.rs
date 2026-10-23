//! Deterministic, bounded Sigma-style matching (`DetectionEngine`).

use std::collections::{HashSet, VecDeque};
use std::path::Path;

use bower_contracts::SecurityEventEnvelope;
use bower_contracts::time::Timestamp;

use crate::DetectionError;
use crate::loader;
use crate::model::{DetectionAlert, DetectionEvaluationResult, DetectionRule};
use crate::ordinal::eq_ignore_case;
use crate::semantics::Semantics;

pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
    suppressed_rule_ids: Vec<String>,
    seen_fingerprints: HashSet<String>,
    fingerprint_order: VecDeque<String>,
    semantics: Vec<Option<Semantics>>,
}

/// Event values keyed case-insensitively, in insertion order.
struct Haystack {
    entries: Vec<(String, String)>,
}

impl Haystack {
    fn set(&mut self, key: &str, value: String) {
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| eq_ignore_case(existing, key))
        {
            Some(_) => {}
            None => self.entries.push((key.to_owned(), value)),
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(existing, _)| eq_ignore_case(existing, key))
            .map(|(_, value)| value.as_str())
    }
}

impl DetectionEngine {
    pub fn new(
        rules: Vec<DetectionRule>,
        suppressed_rule_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        let semantics = rules
            .iter()
            .map(|r| Semantics::new(&r.detection_fields, &r.condition).ok())
            .collect();
        Self {
            semantics,
            fingerprint_order: VecDeque::new(),
            rules,
            suppressed_rule_ids: suppressed_rule_ids.into_iter().collect(),
            seen_fingerprints: HashSet::new(),
        }
    }

    pub fn from_directory(
        directory: &Path,
        suppressed_rule_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, DetectionError> {
        Ok(Self::new(
            loader::load_directory(directory)?,
            suppressed_rule_ids,
        ))
    }

    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    /// Evaluates every rule. An alert fires once per rule, event id and rule hash.
    /// Ambiguous or over-limit event fields fail before any fingerprint is consumed.
    pub fn evaluate(
        &mut self,
        envelope: &SecurityEventEnvelope,
        now: Option<Timestamp>,
    ) -> Result<DetectionEvaluationResult, DetectionError> {
        let detected_at = now.unwrap_or_else(bower_contracts::time::now);
        let mut alerts = Vec::new();
        let mut suppressed: Vec<String> = Vec::new();

        if envelope
            .labels
            .as_ref()
            .is_some_and(|labels| labels.len() > 256)
            || envelope
                .attributes
                .as_ref()
                .is_some_and(|attributes| attributes.len() > 256)
        {
            return Err(invalid_event());
        }
        let duplicates = |keys: Vec<&str>| {
            keys.iter()
                .enumerate()
                .any(|(index, key)| keys[..index].iter().any(|other| eq_ignore_case(key, other)))
        };
        if envelope
            .labels
            .as_ref()
            .is_some_and(|values| duplicates(values.keys().map(String::as_str).collect()))
            || envelope
                .attributes
                .as_ref()
                .is_some_and(|values| duplicates(values.keys().map(String::as_str).collect()))
        {
            return Err(invalid_event());
        }
        let haystack = build_haystack(envelope);
        if haystack.entries.iter().any(|(key, value)| {
            key.encode_utf16().count() > 128 || value.encode_utf16().count() > 65538
        }) {
            return Err(invalid_event());
        }
        for (index, rule) in self.rules.iter().enumerate() {
            if self
                .suppressed_rule_ids
                .iter()
                .any(|id| eq_ignore_case(id, &rule.id))
            {
                suppressed.push(rule.id.clone());
                continue;
            }

            let Some(matched_fields) = self.semantics[index]
                .as_ref()
                .and_then(|s| s.matches(|field| haystack.get(field).map(str::to_owned)))
            else {
                continue;
            };

            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            for value in [&rule.id, &envelope.event_id, &rule.rule_hash] {
                hash.update((value.len() as u32).to_le_bytes());
                hash.update(value.as_bytes());
            }
            let fingerprint = hex::encode(hash.finalize());
            if !self.seen_fingerprints.insert(fingerprint.clone()) {
                continue;
            }

            self.fingerprint_order.push_back(fingerprint);
            if self.fingerprint_order.len() > 4096
                && let Some(old) = self.fingerprint_order.pop_front()
            {
                self.seen_fingerprints.remove(&old);
            }

            let actor = envelope
                .actor
                .as_ref()
                .and_then(|actor| actor.username.clone().or_else(|| actor.user_id.clone()));
            alerts.push(DetectionAlert {
                alert_id: uuid::Uuid::now_v7().to_string(),
                rule_id: rule.id.clone(),
                rule_title: rule.title.clone(),
                rule_version: rule.version.clone(),
                rule_hash: rule.rule_hash.clone(),
                level: rule.level.clone(),
                risk_score: risk_score(&rule.level),
                detected_at,
                event_id: envelope.event_id.clone(),
                event_type: Some(envelope.event_type.clone()),
                actor,
                source_ip: envelope
                    .source
                    .as_ref()
                    .and_then(|source| source.ip_address.clone()),
                mitre_techniques: rule.mitre_techniques.clone(),
                matched_fields,
                summary: format!(
                    "{} matched event {} ({})",
                    rule.title, envelope.event_type, envelope.event_action
                ),
            });
        }

        let mut distinct: Vec<String> = Vec::new();
        for id in suppressed {
            if !distinct
                .iter()
                .any(|existing| eq_ignore_case(existing, &id))
            {
                distinct.push(id);
            }
        }
        Ok(DetectionEvaluationResult {
            alerts,
            suppressed_rule_ids: distinct,
        })
    }

    /// Deserializes a Bower envelope (System.Text.Json rules) and evaluates it.
    pub fn evaluate_json(
        &mut self,
        event_json: &str,
        now: Option<Timestamp>,
    ) -> Result<DetectionEvaluationResult, DetectionError> {
        if event_json.len() > 1024 * 1024 {
            return Err(crate::semantics::invalid());
        }
        let envelope: SecurityEventEnvelope =
            bower_contracts::json::from_str(event_json).map_err(|_| {
                DetectionError::InvalidData(
                    "Event JSON did not deserialize to SecurityEventEnvelope.".to_owned(),
                )
            })?;
        self.evaluate(&envelope, now)
    }
}

fn invalid_event() -> DetectionError {
    DetectionError::InvalidData("Ambiguous or over-limit detection event fields.".into())
}

fn build_haystack(envelope: &SecurityEventEnvelope) -> Haystack {
    let actor = envelope.actor.as_ref();
    let target = envelope.target.as_ref();
    let mut haystack = Haystack {
        entries: vec![
            ("EventType".to_owned(), envelope.event_type.clone()),
            ("EventAction".to_owned(), envelope.event_action.clone()),
            ("EventCategory".to_owned(), envelope.event_category.clone()),
            ("EventResult".to_owned(), envelope.event_result.to_string()),
            (
                "EventOutcomeReason".to_owned(),
                envelope.event_outcome_reason.clone().unwrap_or_default(),
            ),
            (
                "ActorUsername".to_owned(),
                actor
                    .and_then(|actor| actor.username.clone())
                    .unwrap_or_default(),
            ),
            (
                "ActorUserId".to_owned(),
                actor
                    .and_then(|actor| actor.user_id.clone())
                    .unwrap_or_default(),
            ),
            (
                "SourceIp".to_owned(),
                envelope
                    .source
                    .as_ref()
                    .and_then(|source| source.ip_address.clone())
                    .unwrap_or_default(),
            ),
            (
                "TargetName".to_owned(),
                target
                    .and_then(|target| target.name.clone())
                    .unwrap_or_default(),
            ),
            (
                "TargetType".to_owned(),
                target
                    .map(|target| target.target_type.clone())
                    .unwrap_or_default(),
            ),
            ("Application".to_owned(), envelope.application.name.clone()),
        ],
    };
    if let Some(labels) = &envelope.labels {
        for (key, value) in labels {
            if !key.to_ascii_lowercase().starts_with("attributes.") {
                haystack.set(key, value.clone());
            }
        }
    }
    for (_, value) in &mut haystack.entries {
        *value = format!("s:{value}");
    }
    if let Some(attributes) = &envelope.attributes {
        for (key, value) in attributes {
            use bower_contracts::JsonElement;
            let scalar = match value {
                JsonElement::String(text) => Some(format!("s:{text}")),
                JsonElement::Bool(value) => Some(format!("b:{value}")),
                JsonElement::Number(value) => value.parse::<i64>().ok().map(|n| format!("n:{n}")),
                _ => None,
            };
            if let Some(scalar) = scalar {
                haystack.set(&format!("attributes.{key}"), scalar);
            }
        }
    }
    haystack
}

fn risk_score(level: &str) -> i32 {
    match level.to_lowercase().as_str() {
        "informational" => 10,
        "low" => 25,
        "medium" => 50,
        "high" => 75,
        "critical" => 95,
        _ => 40,
    }
}
