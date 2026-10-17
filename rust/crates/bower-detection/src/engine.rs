//! Deterministic, bounded Sigma-style matching (`DetectionEngine`).

use std::collections::HashSet;
use std::path::Path;

use bower_contracts::SecurityEventEnvelope;
use bower_contracts::time::Timestamp;

use crate::DetectionError;
use crate::loader;
use crate::model::{DetectionAlert, DetectionEvaluationResult, DetectionRule};
use crate::ordinal::{contains_ignore_case, ends_with_ignore_case, eq_ignore_case};

pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
    suppressed_rule_ids: Vec<String>,
    seen_fingerprints: HashSet<String>,
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
            Some(entry) => entry.1 = value,
            None => self.entries.push((key.to_owned(), value)),
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(existing, _)| eq_ignore_case(existing, key))
            .map(|(_, value)| value.as_str())
    }

    fn joined_values(&self) -> String {
        self.entries
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl DetectionEngine {
    pub fn new(
        rules: Vec<DetectionRule>,
        suppressed_rule_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
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
    pub fn evaluate(
        &mut self,
        envelope: &SecurityEventEnvelope,
        now: Option<Timestamp>,
    ) -> DetectionEvaluationResult {
        let detected_at = now.unwrap_or_else(bower_contracts::time::now);
        let mut alerts = Vec::new();
        let mut suppressed: Vec<String> = Vec::new();

        for rule in &self.rules {
            if self
                .suppressed_rule_ids
                .iter()
                .any(|id| eq_ignore_case(id, &rule.id))
            {
                suppressed.push(rule.id.clone());
                continue;
            }

            let Some(matched_fields) = matches(rule, envelope) else {
                continue;
            };

            let fingerprint = format!("{}:{}:{}", rule.id, envelope.event_id, rule.rule_hash);
            if !self.seen_fingerprints.insert(fingerprint) {
                continue;
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
        DetectionEvaluationResult {
            alerts,
            suppressed_rule_ids: distinct,
        }
    }

    /// Deserializes a Bower envelope (System.Text.Json rules) and evaluates it.
    pub fn evaluate_json(
        &mut self,
        event_json: &str,
        now: Option<Timestamp>,
    ) -> Result<DetectionEvaluationResult, DetectionError> {
        let envelope: SecurityEventEnvelope =
            bower_contracts::json::from_str(event_json).map_err(|_| {
                DetectionError::InvalidData(
                    "Event JSON did not deserialize to SecurityEventEnvelope.".to_owned(),
                )
            })?;
        Ok(self.evaluate(&envelope, now))
    }
}

const CONDITION_KEYWORDS: &[&str] = &["or", "and", "not", "of", "them"];

/// Returns the matched field names, or `None` when the rule does not match.
fn matches(rule: &DetectionRule, envelope: &SecurityEventEnvelope) -> Option<Vec<String>> {
    let mut matched_fields = Vec::new();
    let haystack = build_haystack(envelope);

    // MVP: condition "selection" or "selection1 or selection2"; all keys under named selection groups.
    let mut groups: Vec<String> = rule
        .condition
        .split([' ', '\t'])
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .filter(|token| {
            *token != "1"
                && !CONDITION_KEYWORDS
                    .iter()
                    .any(|keyword| eq_ignore_case(keyword, token))
        })
        .map(str::to_owned)
        .collect();
    if groups.is_empty() {
        groups = rule.detection_fields.keys().map(str::to_owned).collect();
    }

    let any_group = contains_ignore_case(&rule.condition, " or ")
        || contains_ignore_case(&rule.condition, "1 of them");

    let mut results = Vec::with_capacity(groups.len());
    for group in &groups {
        let result = match rule.detection_fields.get(group) {
            Some(selection) => match_selection(selection, &haystack, &mut matched_fields),
            None => false,
        };
        results.push(result);
    }

    let matched = if any_group {
        results.iter().any(|result| *result)
    } else {
        results.iter().all(|result| *result)
    };
    matched.then_some(matched_fields)
}

fn match_selection(selection: &str, haystack: &Haystack, matched_fields: &mut Vec<String>) -> bool {
    // Selection forms: "field:value|value2;field2:value".
    let clauses: Vec<&str> = selection
        .split(';')
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .collect();
    if clauses.is_empty() {
        return contains_matching(&haystack.joined_values(), selection, matched_fields);
    }

    for clause in clauses {
        let separator = clause.find(':');
        let Some(separator) = separator.filter(|position| *position > 0) else {
            if !contains_matching(&haystack.joined_values(), clause, matched_fields) {
                return false;
            }
            continue;
        };

        let field = clause[..separator].trim().trim_end_matches(['|', '*']);
        let pattern = &clause[separator + 1..];
        let value = match haystack.get(field) {
            Some(value) => value,
            None => {
                // Also try event.* aliases.
                match haystack
                    .entries
                    .iter()
                    .find(|(key, _)| ends_with_ignore_case(key, field))
                {
                    Some((_, alias)) => alias.as_str(),
                    None => return false,
                }
            }
        };

        let matched = pattern
            .split('|')
            .map(str::trim)
            .filter(|option| !option.is_empty())
            .any(|option| contains_ignore_case(value, option));
        if !matched {
            return false;
        }
        matched_fields.push(field.to_owned());
    }
    true
}

fn contains_matching(haystack: &str, needle: &str, matched_fields: &mut Vec<String>) -> bool {
    if contains_ignore_case(haystack, needle) {
        matched_fields.push("payload".to_owned());
        return true;
    }
    false
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
            haystack.set(key, value.clone());
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
