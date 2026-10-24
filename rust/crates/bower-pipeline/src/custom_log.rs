//! Custom log parser configuration and its validation (`CustomLogParser`).
//!
//! Only the configuration model and `ValidateConfiguration` are ported: packs ship
//! parser configurations and must validate them at build and load time. Sample-driven
//! generation and preview (`Generate`, `Preview`) are used only by the C# management
//! API and are not ported.

use indexmap::IndexMap;

use regex::Regex;
use serde_json::{Map, Value};

use crate::PipelineError;

pub const CONFIGURATION_VERSION: &str = "1.0";
pub const MAXIMUM_FIELDS: usize = 64;
const MAXIMUM_PATTERN_LENGTH: usize = 2048;

const PROHIBITED_FIELD_NAMES: &[&str] = &[
    "authorization",
    "authorizationheader",
    "body",
    "cookie",
    "credentials",
    "password",
    "payload",
    "rawpayload",
    "secret",
    "token",
];

macro_rules! named_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// C# enum name.
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => stringify!($variant)),+ }
            }

            /// `JsonStringEnumConverter` read: a name (case-insensitive) or a defined
            /// ordinal.
            fn from_json(value: &Value) -> Option<Self> {
                match value {
                    Value::String(text) => Self::ALL.iter().copied().find(|item| item.as_str().eq_ignore_ascii_case(text.trim())),
                    Value::Number(number) => number.as_u64().and_then(|index| Self::ALL.get(usize::try_from(index).ok()?).copied()),
                    _ => None,
                }
            }
        }
    };
}

named_enum!(CustomLogFormat {
    Json,
    Csv,
    KeyValue,
    Regex
});
named_enum!(CustomLogValueType {
    Text,
    DateTime,
    IpAddress,
    WholeNumber,
    Boolean
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomLogField {
    pub source_name: String,
    pub value_type: CustomLogValueType,
    pub ocsf_path: Option<String>,
    pub asim_field: Option<String>,
    pub sensitive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomLogRuntimeMapping {
    pub application_name: String,
    pub environment: String,
    pub event_category: String,
    pub event_type: String,
    pub event_action: String,
    pub event_result: String,
    pub match_fields: IndexMap<String, String>,
    pub fields: IndexMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomLogParserConfiguration {
    pub version: String,
    pub format: CustomLogFormat,
    pub fields: Vec<CustomLogField>,
    pub delimiter: Option<String>,
    pub key_value_separator: Option<String>,
    pub pattern: Option<String>,
    pub runtime: Option<CustomLogRuntimeMapping>,
}

/// Case-insensitive property lookup (`PropertyNameCaseInsensitive = true`); the last
/// matching property wins.
fn property<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .rev()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn optional_string(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, PipelineError> {
    match property(object, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(PipelineError::InvalidData(format!(
            "Parser property '{name}' must be a string."
        ))),
    }
}

fn read_enum<T>(
    object: &Map<String, Value>,
    name: &str,
    parse: fn(&Value) -> Option<T>,
    default: T,
) -> Result<T, PipelineError> {
    match property(object, name) {
        None => Ok(default),
        Some(value) => parse(value).ok_or_else(|| {
            PipelineError::InvalidData(format!("Parser property '{name}' has an unknown value."))
        }),
    }
}

impl CustomLogParserConfiguration {
    /// Reads a configuration as `JsonSerializer.Deserialize` with Bower's pack options
    /// does: camelCase or any-case property names, enum names or ordinals, missing
    /// members defaulted.
    pub fn from_json(text: &str) -> Result<Self, PipelineError> {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| PipelineError::InvalidData(error.to_string()))?;
        let object = match value {
            Value::Object(object) => object,
            Value::Null => {
                return Err(PipelineError::InvalidData(
                    "Parser configuration is empty.".to_owned(),
                ));
            }
            _ => {
                return Err(PipelineError::InvalidData(
                    "Parser configuration must be a JSON object.".to_owned(),
                ));
            }
        };

        let mut fields = Vec::new();
        match property(&object, "fields") {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    let Value::Object(field) = item else {
                        return Err(PipelineError::InvalidData(
                            "Parser fields must be objects.".to_owned(),
                        ));
                    };
                    fields.push(CustomLogField {
                        source_name: optional_string(field, "sourceName")?.unwrap_or_default(),
                        value_type: read_enum(
                            field,
                            "type",
                            CustomLogValueType::from_json,
                            CustomLogValueType::Text,
                        )?,
                        ocsf_path: optional_string(field, "ocsfPath")?,
                        asim_field: optional_string(field, "asimField")?,
                        sensitive: match property(field, "sensitive") {
                            None => false,
                            Some(Value::Bool(value)) => *value,
                            Some(_) => {
                                return Err(PipelineError::InvalidData(
                                    "Parser property 'sensitive' must be a boolean.".to_owned(),
                                ));
                            }
                        },
                    });
                }
            }
            Some(_) => {
                return Err(PipelineError::InvalidData(
                    "Parser property 'fields' must be an array.".to_owned(),
                ));
            }
        }

        Ok(Self {
            version: optional_string(&object, "version")?.unwrap_or_default(),
            format: read_enum(
                &object,
                "format",
                CustomLogFormat::from_json,
                CustomLogFormat::Json,
            )?,
            fields,
            delimiter: optional_string(&object, "delimiter")?,
            key_value_separator: optional_string(&object, "keyValueSeparator")?,
            pattern: optional_string(&object, "pattern")?,
            runtime: match property(&object, "runtime") {
                None | Some(Value::Null) => None,
                Some(Value::Object(runtime)) => Some(read_runtime(runtime)?),
                _ => {
                    return Err(PipelineError::InvalidData(
                        "Runtime mapping must be an object.".into(),
                    ));
                }
            },
        })
    }
}

fn read_runtime(object: &Map<String, Value>) -> Result<CustomLogRuntimeMapping, PipelineError> {
    let known = [
        "applicationName",
        "environment",
        "eventCategory",
        "eventType",
        "eventAction",
        "eventResult",
        "match",
        "fields",
    ];
    if object
        .keys()
        .any(|key| !known.iter().any(|name| key.eq_ignore_ascii_case(name)))
    {
        return Err(PipelineError::InvalidData(
            "Unknown runtime mapping member.".into(),
        ));
    }
    let dictionary = |name| -> Result<IndexMap<String, String>, PipelineError> {
        let Some(Value::Object(values)) = property(object, name) else {
            return Err(PipelineError::InvalidData(
                "Runtime mapping requires string dictionaries.".into(),
            ));
        };
        values
            .iter()
            .map(|(key, value)| match value {
                Value::String(value) => Ok((key.clone(), value.clone())),
                _ => Err(PipelineError::InvalidData(
                    "Runtime mapping requires string dictionaries.".into(),
                )),
            })
            .collect()
    };
    Ok(CustomLogRuntimeMapping {
        application_name: optional_string(object, "applicationName")?.unwrap_or_default(),
        environment: optional_string(object, "environment")?.unwrap_or_default(),
        event_category: optional_string(object, "eventCategory")?.unwrap_or_default(),
        event_type: optional_string(object, "eventType")?.unwrap_or_default(),
        event_action: optional_string(object, "eventAction")?.unwrap_or_default(),
        event_result: optional_string(object, "eventResult")?.unwrap_or_default(),
        match_fields: dictionary("match")?,
        fields: dictionary("fields")?,
    })
}

/// `CustomLogParser.ValidateConfiguration`: every issue, in C# order.
pub fn validate_configuration(configuration: &CustomLogParserConfiguration) -> Vec<String> {
    let mut issues = Vec::new();
    if configuration.version != CONFIGURATION_VERSION {
        issues.push(format!(
            "Unsupported parser configuration version '{}'.",
            configuration.version
        ));
    }
    if configuration.fields.is_empty() || configuration.fields.len() > MAXIMUM_FIELDS {
        issues.push(format!(
            "Parser configuration needs 1 to {MAXIMUM_FIELDS} fields."
        ));
    }

    let mut names = std::collections::HashSet::new();
    for field in &configuration.fields {
        if !is_valid_field_name(&field.source_name) {
            issues.push(format!(
                "Invalid source field name '{}'.",
                field.source_name
            ));
        } else if !names.insert(field.source_name.as_str()) {
            issues.push(format!(
                "Duplicate source field name '{}'.",
                field.source_name
            ));
        }
        if is_prohibited(&field.source_name) {
            issues.push(format!(
                "Prohibited source field name '{}'.",
                field.source_name
            ));
        }
    }

    match configuration.format {
        CustomLogFormat::Csv
            if !matches!(configuration.delimiter.as_deref(), Some("," | "\t" | ";")) =>
        {
            issues.push("CSV delimiter must be comma, tab or semicolon.".to_owned());
        }
        CustomLogFormat::KeyValue
            if !matches!(
                configuration.key_value_separator.as_deref(),
                Some("=" | ":")
            ) =>
        {
            issues.push("Key/value separator must be '=' or ':'.".to_owned());
        }
        CustomLogFormat::Regex => validate_regex(configuration, &mut issues),
        _ => {}
    }

    if let Some(runtime) = &configuration.runtime {
        let metadata = [
            &runtime.application_name,
            &runtime.environment,
            &runtime.event_category,
            &runtime.event_type,
            &runtime.event_action,
        ];
        let targets = [
            "eventId",
            "timeGenerated",
            "actor.username",
            "actor.userId",
            "source.ipAddress",
            "request.correlationId",
            "eventOutcomeReason",
        ];
        if configuration.format != CustomLogFormat::Json
            || metadata
                .iter()
                .any(|value| value.trim().is_empty() || value.encode_utf16().count() > 128)
            || !matches!(
                runtime.event_result.as_str(),
                "success" | "failure" | "denied" | "unknown"
            )
            || !(1..=16).contains(&runtime.match_fields.len())
            || !(2..=7).contains(&runtime.fields.len())
            || !runtime.fields.contains_key("eventId")
            || !runtime.fields.contains_key("timeGenerated")
            || runtime
                .fields
                .keys()
                .any(|key| !targets.contains(&key.as_str()))
            || runtime
                .fields
                .values()
                .any(|source| !names.contains(source.as_str()))
            || runtime.match_fields.iter().any(|(source, value)| {
                !names.contains(source.as_str())
                    || value.is_empty()
                    || value.encode_utf16().count() > 2048
            })
        {
            issues.push("Invalid runtime semantic mapping; only bounded, filtered JSON mappings are supported.".into());
        }
    }
    issues
}

fn validate_regex(configuration: &CustomLogParserConfiguration, issues: &mut Vec<String>) {
    let pattern = match configuration.pattern.as_deref() {
        Some(pattern)
            if !pattern.trim().is_empty()
                && pattern.encode_utf16().count() <= MAXIMUM_PATTERN_LENGTH =>
        {
            pattern
        }
        _ => {
            issues.push("Regex pattern is required and cannot exceed 2048 characters.".to_owned());
            return;
        }
    };

    // Rust's `regex` is a finite-automata engine like .NET `RegexOptions.NonBacktracking`:
    // both reject backreferences, lookarounds and atomic groups.
    match Regex::new(pattern) {
        Ok(regex) => {
            let groups: std::collections::HashSet<&str> = regex
                .capture_names()
                .flatten()
                .filter(|name| name.parse::<i64>().is_err())
                .collect();
            for field in &configuration.fields {
                if !groups.contains(field.source_name.as_str()) {
                    issues.push(format!(
                        "Regex has no named capture for field '{}'.",
                        field.source_name
                    ));
                }
            }
        }
        Err(_) => {
            issues.push("Regex pattern is unsupported by the non-backtracking engine.".to_owned())
        }
    }
}

/// 1 to 128 characters of ASCII letters, digits, `_ - . @`.
pub fn is_valid_field_name(value: &str) -> bool {
    let length = value.encode_utf16().count();
    (1..=128).contains(&length)
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '@')
        })
}

fn canonical(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// Field names that must never be parsed (credentials, bodies, cookies).
pub fn is_prohibited(name: &str) -> bool {
    let canonical = canonical(name);
    PROHIBITED_FIELD_NAMES.contains(&canonical.as_str())
        || canonical.contains("password")
        || canonical.contains("secret")
        || canonical.contains("token")
        || canonical.contains("cookie")
}
