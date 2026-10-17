//! Detection rule and alert records (`DetectionModels.cs`).

use bower_contracts::time::Timestamp;

use crate::ordinal::eq_ignore_case;

/// Selection name to flattened selection text, looked up case-insensitively (C#
/// `Dictionary` with `StringComparer.OrdinalIgnoreCase`). Insertion order is kept;
/// assigning an existing name (any case) replaces the value in place.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DetectionFields {
    entries: Vec<(String, String)>,
}

impl DetectionFields {
    pub fn insert(&mut self, key: &str, value: String) {
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| eq_ignore_case(existing, key))
        {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key.to_owned(), value)),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(existing, _)| eq_ignore_case(existing, key))
            .map(|(_, value)| value.as_str())
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(key, _)| key.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionRule {
    pub id: String,
    pub title: String,
    pub version: String,
    pub level: String,
    pub status: String,
    pub description: String,
    pub log_sources: Vec<String>,
    pub detection_fields: DetectionFields,
    pub condition: String,
    pub mitre_techniques: Vec<String>,
    pub false_positive_hints: Vec<String>,
    /// Lower-case hex SHA-256 of the rule's YAML text: the rule version identity.
    pub rule_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionAlert {
    pub alert_id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub rule_version: String,
    pub rule_hash: String,
    pub level: String,
    pub risk_score: i32,
    pub detected_at: Timestamp,
    pub event_id: String,
    pub event_type: Option<String>,
    pub actor: Option<String>,
    pub source_ip: Option<String>,
    pub mitre_techniques: Vec<String>,
    pub matched_fields: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionEvaluationResult {
    pub alerts: Vec<DetectionAlert>,
    pub suppressed_rule_ids: Vec<String>,
}
