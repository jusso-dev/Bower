//! Applications that must keep sending security events (C# `SourceExpectations`,
//! `SourceExpectationsLoader`, `SourceSilenceEvaluator`). A silent source means the
//! SIEM is blind to it.
//!
//! Parsing mirrors the C# source-generated context: Web defaults (camelCase,
//! case-insensitive names), strict numbers, unknown members rejected, required and
//! non-null members enforced. Rejection cases match C#; the detail after
//! `Source expectations are invalid: ` is this port's wording, not System.Text.Json's.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use bower_contracts::time::Timestamp;
use bower_contracts::{JsonElement, SourceActivity, SourceMonitoring};

pub const MAXIMUM_SOURCES: usize = 1_000;
pub const MAXIMUM_SILENCE_MINUTES_LIMIT: i32 = 10_080;
const MAXIMUM_BYTES: u64 = 262_144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceExpectations {
    pub api_version: String,
    pub kind: String,
    pub sources: Vec<SourceExpectation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceExpectation {
    pub application: String,
    pub environment: String,
    pub maximum_silence_minutes: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceExpectationsError {
    /// `FileNotFoundException`.
    #[error("Source expectations file does not exist.")]
    FileNotFound,
    /// `InvalidDataException`.
    #[error("{0}")]
    InvalidData(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn invalid(message: impl Into<String>) -> SourceExpectationsError {
    SourceExpectationsError::InvalidData(message.into())
}

fn json_error(detail: &str) -> SourceExpectationsError {
    invalid(format!("Source expectations are invalid: {detail}"))
}

pub fn load_file(path: impl AsRef<Path>) -> Result<SourceExpectations, SourceExpectationsError> {
    let path = path.as_ref();
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return Err(SourceExpectationsError::FileNotFound),
    };
    if metadata.len() > MAXIMUM_BYTES {
        return Err(invalid("Source expectations file exceeds 256 KiB."));
    }
    let bytes = std::fs::read(path)?;
    // File.ReadAllText: a UTF-8 BOM is removed, invalid sequences become U+FFFD.
    let text = String::from_utf8_lossy(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes));
    parse(&text)
}

/// Last property whose name matches case-insensitively (later duplicates win).
fn members<'a>(
    properties: &'a [(String, JsonElement)],
    known: &[&str],
    type_name: &str,
) -> Result<HashMap<&'static str, &'a JsonElement>, SourceExpectationsError> {
    let mut found: HashMap<&'static str, &'a JsonElement> = HashMap::new();
    for (name, value) in properties {
        let Some(member) = known
            .iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(name))
        else {
            return Err(json_error(&format!(
                "The JSON property '{name}' could not be mapped to any .NET member contained in type '{type_name}'."
            )));
        };
        found.insert(static_name(member), value);
    }
    Ok(found)
}

fn static_name(name: &str) -> &'static str {
    match name {
        "apiVersion" => "apiVersion",
        "kind" => "kind",
        "sources" => "sources",
        "application" => "application",
        "environment" => "environment",
        _ => "maximumSilenceMinutes",
    }
}

fn required<'a>(
    found: &HashMap<&'static str, &'a JsonElement>,
    name: &'static str,
    type_name: &str,
) -> Result<&'a JsonElement, SourceExpectationsError> {
    found.get(name).copied().ok_or_else(|| {
        json_error(&format!(
            "JSON deserialization for type '{type_name}' was missing required properties including: '{name}'."
        ))
    })
}

fn string(value: &JsonElement, name: &str) -> Result<String, SourceExpectationsError> {
    match value {
        JsonElement::String(text) => Ok(text.clone()),
        JsonElement::Null => Err(json_error(&format!(
            "The constructor parameter '{name}' does not allow null values."
        ))),
        _ => Err(json_error(&format!(
            "The JSON value of '{name}' could not be converted to System.String."
        ))),
    }
}

pub fn parse(json: &str) -> Result<SourceExpectations, SourceExpectationsError> {
    const ROOT: &str = "Bower.Core.SourceExpectations";
    const ITEM: &str = "Bower.Core.SourceExpectation";
    let element = JsonElement::parse(json).map_err(|error| json_error(&error))?;
    let properties = match &element {
        JsonElement::Null => {
            return Err(invalid(
                "Source expectations need apiVersion bower.security/v1 and kind SourceExpectations.",
            ));
        }
        JsonElement::Object(properties) => properties,
        _ => {
            return Err(json_error(
                "The JSON value could not be converted to Bower.Core.SourceExpectations.",
            ));
        }
    };
    let found = members(properties, &["apiVersion", "kind", "sources"], ROOT)?;
    let api_version = string(required(&found, "apiVersion", ROOT)?, "apiVersion")?;
    let kind = string(required(&found, "kind", ROOT)?, "kind")?;
    let items = match required(&found, "sources", ROOT)? {
        JsonElement::Array(items) => items,
        JsonElement::Null => {
            return Err(json_error(
                "The constructor parameter 'sources' does not allow null values.",
            ));
        }
        _ => {
            return Err(json_error(
                "The JSON value of 'sources' could not be converted to a list.",
            ));
        }
    };
    let mut sources: Vec<Option<SourceExpectation>> = Vec::with_capacity(items.len());
    for item in items {
        let properties = match item {
            JsonElement::Null => {
                sources.push(None);
                continue;
            }
            JsonElement::Object(properties) => properties,
            _ => {
                return Err(json_error(
                    "The JSON value could not be converted to Bower.Core.SourceExpectation.",
                ));
            }
        };
        let found = members(
            properties,
            &["application", "environment", "maximumSilenceMinutes"],
            ITEM,
        )?;
        let application = string(required(&found, "application", ITEM)?, "application")?;
        let environment = string(required(&found, "environment", ITEM)?, "environment")?;
        let maximum_silence_minutes = match required(&found, "maximumSilenceMinutes", ITEM)? {
            // Strict: an integral JSON number within Int32; never a string.
            JsonElement::Number(text) => text.parse::<i32>().map_err(|_| {
                json_error("The JSON value of 'maximumSilenceMinutes' could not be converted to System.Int32.")
            })?,
            _ => {
                return Err(json_error(
                    "The JSON value of 'maximumSilenceMinutes' could not be converted to System.Int32.",
                ));
            }
        };
        sources.push(Some(SourceExpectation {
            application,
            environment,
            maximum_silence_minutes,
        }));
    }

    if api_version != "bower.security/v1" || kind != "SourceExpectations" {
        return Err(invalid(
            "Source expectations need apiVersion bower.security/v1 and kind SourceExpectations.",
        ));
    }
    if !(1..=MAXIMUM_SOURCES).contains(&sources.len()) {
        return Err(invalid(format!(
            "Source expectations must list 1–{MAXIMUM_SOURCES} sources."
        )));
    }
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(sources.len());
    for source in sources {
        let Some(source) = source
            .filter(|source| !is_blank(&source.application) && !is_blank(&source.environment))
        else {
            return Err(invalid(
                "Each expected source needs an application and an environment.",
            ));
        };
        if !(1..=MAXIMUM_SILENCE_MINUTES_LIMIT).contains(&source.maximum_silence_minutes) {
            return Err(invalid(format!(
                "maximumSilenceMinutes must be between 1 and {MAXIMUM_SILENCE_MINUTES_LIMIT}."
            )));
        }
        if !seen.insert((source.application.clone(), source.environment.clone())) {
            return Err(invalid(format!(
                "Expected source {}/{} is listed more than once.",
                source.application, source.environment
            )));
        }
        validated.push(source);
    }
    Ok(SourceExpectations {
        api_version,
        kind,
        sources: validated,
    })
}

fn is_blank(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

/// `active` (seen within the allowance), `pending` (not yet seen, still within the
/// allowance from its monitoring start), `silent` or `never-seen` (overdue) for one
/// expected source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSilenceStatus {
    pub application: String,
    pub environment: String,
    pub state: String,
    pub last_seen_at: Option<Timestamp>,
    pub silent_seconds: i64,
    pub allowed_silence_seconds: i64,
}

impl SourceSilenceStatus {
    /// Seen within its allowance. A `pending` source is not active: it has no evidence yet.
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }

    /// Past its allowance: `silent` or `never-seen`.
    pub fn is_overdue(&self) -> bool {
        matches!(self.state.as_str(), "silent" | "never-seen")
    }
}

/// Compares expected sources with observed activity (C# `SourceSilenceEvaluator`). A
/// source never seen runs its allowance from its durable monitoring start in
/// `monitoring`, or from `monitoring_since` when it has none: `pending` while inside
/// the allowance, then `never-seen`. A restart therefore cannot extend the deadline.
pub fn evaluate(
    expectations: &SourceExpectations,
    activity: &[SourceActivity],
    monitoring: &[SourceMonitoring],
    monitoring_since: Timestamp,
    now: Timestamp,
) -> Vec<SourceSilenceStatus> {
    let mut by_key: HashMap<(&str, &str), &SourceActivity> = HashMap::new();
    for item in activity {
        by_key.insert((&item.application, &item.environment), item);
    }
    let mut started: HashMap<(&str, &str), Timestamp> = HashMap::new();
    for item in monitoring {
        started.insert(
            (&item.application, &item.environment),
            item.monitoring_since,
        );
    }
    expectations
        .sources
        .iter()
        .map(|expected| {
            let allowed = i64::from(expected.maximum_silence_minutes) * 60;
            let key = (expected.application.as_str(), expected.environment.as_str());
            let seen = by_key.get(&key).copied();
            let reference = seen.map_or_else(
                || started.get(&key).copied().unwrap_or(monitoring_since),
                |seen| seen.last_seen_at,
            );
            // Math.Floor(TotalSeconds), clamped at zero.
            let elapsed = now.signed_duration_since(reference);
            let mut silent = elapsed.num_seconds();
            if elapsed.subsec_nanos() < 0 {
                silent -= 1;
            }
            let silent = silent.max(0);
            let state = match (silent <= allowed, seen.is_none()) {
                (true, false) => "active",
                (true, true) => "pending",
                (false, true) => "never-seen",
                (false, false) => "silent",
            };
            SourceSilenceStatus {
                application: expected.application.clone(),
                environment: expected.environment.clone(),
                state: state.to_owned(),
                last_seen_at: seen.map(|seen| seen.last_seen_at),
                silent_seconds: silent,
                allowed_silence_seconds: allowed,
            }
        })
        .collect()
}
