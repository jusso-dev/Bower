//! Port of `PolicyLoader`: strict YAML loading, validation and the policy hash.

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

use bower_contracts::DecisionAction;
use sha2::{Digest, Sha256};

use crate::field::present;
use crate::model::{
    LoadedPolicy, PolicyAction, PolicyMatch, PolicyMetadata, PolicyRequirements, PolicyRouting,
    PolicySuppression, TelemetryPolicy,
};
use crate::yaml::{self, Ctx, Failure, RawList, RawPolicy, RawSuppression};
use bower_contracts::types::event_types::TELEMETRY_AGGREGATION_SUMMARY;

pub const MAXIMUM_SUPPRESSION_KEY_FIELDS: usize = 5;

/// Maximum policy size in bytes (file length and UTF-8 text length).
pub const MAXIMUM_POLICY_BYTES: usize = 1_048_576;

pub const SUPPORTED_API_VERSION: &str = "bower.security/v1";
pub const SUPPORTED_KIND: &str = "TelemetryPolicy";

/// Loading failures. `Display` is the C# exception message.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// `InvalidDataException`: malformed, oversized or invalid policy.
    #[error("{0}")]
    InvalidData(String),
    /// `FileNotFoundException`.
    #[error("Policy file does not exist.")]
    FileNotFound(PathBuf),
    /// `DirectoryNotFoundException`.
    #[error("Policy directory does not exist: {}", .0.display())]
    DirectoryNotFound(PathBuf),
    /// `ArgumentException` for a blank directory argument.
    #[error(
        "The value cannot be an empty string or composed entirely of whitespace. (Parameter 'directory')"
    )]
    BlankDirectory,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError::InvalidData(message.into())
}

/// `string.CompareOrdinal`: UTF-16 code unit order.
pub(crate) fn ordinal_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Loads every top-level `*.yaml` file, ordered by path (ordinal).
pub fn load_directory(directory: impl AsRef<Path>) -> Result<Vec<LoadedPolicy>, PolicyError> {
    let directory = directory.as_ref();
    if directory.to_string_lossy().trim().is_empty() {
        return Err(PolicyError::BlankDirectory);
    }
    if !directory.is_dir() {
        return Err(PolicyError::DirectoryNotFound(directory.to_path_buf()));
    }

    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let is_yaml = path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".yaml"));
        if is_yaml && path.is_file() {
            paths.push(path);
        }
    }
    paths.sort_by(|left, right| ordinal_cmp(&left.to_string_lossy(), &right.to_string_lossy()));
    paths.iter().map(load_file).collect()
}

/// Loads one policy file (at most [`MAXIMUM_POLICY_BYTES`]).
pub fn load_file(path: impl AsRef<Path>) -> Result<LoadedPolicy, PolicyError> {
    let path = path.as_ref();
    let Ok(metadata) = fs::metadata(path) else {
        return Err(PolicyError::FileNotFound(path.to_path_buf()));
    };
    if !metadata.is_file() {
        return Err(PolicyError::FileNotFound(path.to_path_buf()));
    }
    if metadata.len() > MAXIMUM_POLICY_BYTES as u64 {
        return Err(invalid("Policy exceeds maximum size."));
    }

    let bytes = fs::read(path)?;
    let yaml = decode_text(&bytes);
    load_yaml(&yaml, &path.to_string_lossy())
}

/// `File.ReadAllText(path, Encoding.UTF8)`: byte-order marks select UTF-8,
/// UTF-16 or UTF-32 and are removed; invalid sequences become U+FFFD.
fn decode_text(bytes: &[u8]) -> String {
    const REPLACEMENT: u32 = char::REPLACEMENT_CHARACTER as u32;
    fn utf16(bytes: &[u8], read: fn([u8; 2]) -> u16) -> String {
        let units = bytes
            .chunks(2)
            .map(|chunk| <[u8; 2]>::try_from(chunk).map_or(0xFFFD, read));
        char::decode_utf16(units)
            .map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }
    fn utf32(bytes: &[u8], read: fn([u8; 4]) -> u32) -> String {
        bytes
            .chunks(4)
            .map(|chunk| <[u8; 4]>::try_from(chunk).map_or(REPLACEMENT, read))
            .map(|unit| char::from_u32(unit).unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    match bytes {
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xFF, 0xFE, 0x00, 0x00, rest @ ..] => utf32(rest, u32::from_le_bytes),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [0x00, 0x00, 0xFE, 0xFF, rest @ ..] => utf32(rest, u32::from_be_bytes),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Loads a policy from YAML text (used for signed packs). `source_name` is
/// kept as [`LoadedPolicy::source_path`] and its file name appears in errors.
pub fn load_yaml(yaml: &str, source_name: &str) -> Result<LoadedPolicy, PolicyError> {
    if yaml.len() > MAXIMUM_POLICY_BYTES {
        return Err(invalid("Policy exceeds maximum size."));
    }
    let text = yaml.strip_prefix('\u{feff}').unwrap_or(yaml);

    let raw = parse(text, source_name)?.ok_or_else(|| invalid("Policy is empty."))?;
    let policy = validate(&raw)?;
    let canonical = bower_contracts::json::to_vec(&raw)
        .map_err(|_| invalid("Policy could not be serialized."))?;
    let hash = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    Ok(LoadedPolicy {
        policy,
        hash,
        source_path: source_name.to_owned(),
    })
}

/// `Path.GetFileName` (Unix separators).
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn parse(text: &str, source_name: &str) -> Result<Option<RawPolicy>, PolicyError> {
    let ctx = Ctx::default();
    let yaml_error = |line: usize, message: &str| {
        invalid(format!(
            "Policy '{}' is invalid at line {line}: {message}",
            file_name(source_name)
        ))
    };

    let mut documents = serde_yaml_ng::Deserializer::from_str(text);
    let Some(first) = documents.next() else {
        return Ok(None);
    };
    let raw = yaml::read_policy(first, &ctx).map_err(|error| {
        let location = error.location();
        let line = location.as_ref().map_or(0, serde_yaml_ng::Location::line);
        let index = location.as_ref().map_or(0, serde_yaml_ng::Location::index);
        match ctx.take() {
            Some(Failure::Message(message)) => yaml_error(line, &message),
            Some(Failure::Expected { expected, got }) => yaml_error(
                line,
                &format!(
                    "Expected '{expected}', got '{got}' {}.",
                    position(text, line, index)
                ),
            ),
            // Scanner/parser errors: YamlDotNet's wording is not reproduced.
            None => yaml_error(line, &error.to_string()),
        }
    })?;

    if documents.next().is_some() {
        let (line, index) = second_document_start(text);
        return Err(yaml_error(
            line,
            &format!(
                "Expected 'StreamEnd', got 'DocumentStart' {}.",
                position(text, line, index)
            ),
        ));
    }
    Ok(raw)
}

/// YamlDotNet mark text: column and index count UTF-16 code units.
fn position(text: &str, line: usize, byte_index: usize) -> String {
    let before = text.get(..byte_index).unwrap_or(text);
    let line_start = before.rfind(['\n', '\r']).map_or(0, |found| found + 1);
    let column = before[line_start..].encode_utf16().count() + 1;
    let index = before.encode_utf16().count();
    format!("(at Line: {line}, Col: {column}, Idx: {index})")
}

/// Line (1-based) and byte offset of the second document: the first `---`
/// marker after document content, or the first content after a `...` marker.
fn second_document_start(text: &str) -> (usize, usize) {
    let mut offset = 0;
    let mut seen_content = false;
    let mut after_end_marker = false;
    for (number, line) in text.split_inclusive('\n').enumerate() {
        let body = line.trim_end_matches(['\n', '\r']);
        let is_marker = |marker: &str| {
            body.strip_prefix(marker)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
        };
        let is_content = !body.trim().is_empty() && !body.trim_start().starts_with('#');
        if is_marker("---") && seen_content {
            return (number + 1, offset);
        }
        if is_marker("...") {
            after_end_marker = true;
        } else if is_content {
            if after_end_marker && !body.starts_with('%') {
                return (number + 1, offset);
            }
            seen_content = true;
        }
        offset += line.len();
    }
    (0, 0)
}

/// `PolicyLoader.Validate` (same checks, order and messages), then conversion
/// to the non-null public model. Missing or null sections, lists and list
/// items are rejected, as are blank event categories and field paths.
fn validate(raw: &RawPolicy) -> Result<TelemetryPolicy, PolicyError> {
    if raw.api_version.as_deref() != Some(SUPPORTED_API_VERSION)
        || raw.kind.as_deref() != Some(SUPPORTED_KIND)
    {
        return Err(invalid("Unsupported policy apiVersion or kind."));
    }

    let metadata = raw
        .metadata
        .as_ref()
        .filter(|metadata| present(metadata.id.as_deref()) && present(metadata.version.as_deref()))
        .ok_or_else(|| invalid("Policy metadata id and version are required."))?;

    let rule = raw.r#match.as_ref();
    let event_types = rule
        .and_then(|rule| rule.event_types.as_ref())
        .filter(|types| !types.is_empty() && all_present(types))
        .ok_or_else(|| invalid("Policy match must list at least one eventType."))?;

    let decision = raw
        .decision
        .as_ref()
        .ok_or_else(|| invalid("Policy decision section is required."))?;
    if try_parse_action(decision.action.as_deref()).is_none() {
        return Err(invalid(format!(
            "Unsupported policy action: {}",
            decision.action.as_deref().unwrap_or_default()
        )));
    }
    if !(0..=100).contains(&decision.minimum_value_score) {
        return Err(invalid("minimumValueScore must be between 0 and 100."));
    }

    let event_categories = rule
        .and_then(|rule| rule.event_categories.as_ref())
        .filter(|categories| all_present(categories))
        .ok_or_else(|| {
            invalid("Policy match eventCategories must be a list of non-blank values.")
        })?;
    let requirements = raw
        .requirements
        .as_ref()
        .ok_or_else(|| invalid("Policy requirements section is required."))?;
    // A null or blank path can never be present: as a required field it would
    // quarantine every matching event with "Missing required field: ".
    let field_paths = |list: &RawList, name: &str| {
        list.as_ref()
            .filter(|items| all_present(items))
            .map(|items| strings(items))
            .ok_or_else(|| {
                invalid(format!(
                    "Policy requirements {name} must be a list of non-blank field paths."
                ))
            })
    };
    let required_fields = field_paths(&requirements.required_fields, "requiredFields")?;
    let at_least_one = field_paths(&requirements.at_least_one, "atLeastOne")?;
    let recommended_fields = field_paths(&requirements.recommended_fields, "recommendedFields")?;

    let predicate = |values: &RawList,
                     name: &str,
                     allowed: &[&str]|
     -> Result<Option<Vec<String>>, PolicyError> {
        match values {
            None => Ok(None),
            Some(items)
                if !items.is_empty()
                    && items.len() <= 256
                    && all_present(items)
                    && items.iter().all(|item| {
                        item.as_ref().is_some_and(|value| {
                            value.encode_utf16().count() <= 256
                                && (allowed.is_empty() || allowed.contains(&value.as_str()))
                        })
                    }) =>
            {
                Ok(Some(strings(items)))
            }
            _ => Err(invalid(format!(
                "Policy match {name} must contain 1–256 approved non-blank values."
            ))),
        }
    };
    let rule = rule.expect("event types already validated");
    let event_actions = predicate(&rule.event_actions, "eventActions", &[])?;
    let event_results = predicate(
        &rule.event_results,
        "eventResults",
        &["unknown", "success", "failure", "denied"],
    )?;
    let event_severities = predicate(
        &rule.event_severities,
        "eventSeverities",
        &["informational", "low", "medium", "high", "critical"],
    )?;
    let event_types = strings(event_types);
    let suppression = raw
        .suppression
        .as_ref()
        .map(|suppression| validate_suppression(decision, &event_types, suppression))
        .transpose()?;

    Ok(TelemetryPolicy {
        api_version: SUPPORTED_API_VERSION.to_owned(),
        kind: SUPPORTED_KIND.to_owned(),
        metadata: PolicyMetadata {
            id: metadata.id.clone().unwrap_or_default(),
            name: metadata.name.clone().unwrap_or_default(),
            version: metadata.version.clone().unwrap_or_default(),
            owner: metadata.owner.clone().unwrap_or_default(),
            review_date: metadata.review_date,
        },
        r#match: PolicyMatch {
            event_categories: strings(event_categories),
            event_types,
            event_actions,
            event_results,
            event_severities,
        },
        requirements: PolicyRequirements {
            required_fields,
            at_least_one,
            recommended_fields,
        },
        decision: PolicyAction {
            action: decision.action.clone().unwrap_or_default(),
            minimum_value_score: decision.minimum_value_score,
            never_sample: decision.never_sample,
        },
        routing: raw.routing.as_ref().map(|routing| PolicyRouting {
            profile: routing.profile.clone(),
            destination: routing.destination.clone(),
        }),
        suppression,
    })
}

/// C# `PolicyLoader.ValidateSuppression` (same checks, order and messages).
fn validate_suppression(
    decision: &yaml::RawAction,
    event_types: &[String],
    suppression: &RawSuppression,
) -> Result<PolicySuppression, PolicyError> {
    if decision.never_sample {
        return Err(invalid("A neverSample policy cannot define suppression."));
    }
    if !matches!(
        try_parse_action(decision.action.as_deref()),
        Some(DecisionAction::Accept | DecisionAction::RedactAndAccept)
    ) {
        return Err(invalid(
            "Suppression applies only to accept or redact-and-accept policies.",
        ));
    }
    if event_types
        .iter()
        .any(|item| item == TELEMETRY_AGGREGATION_SUMMARY)
    {
        return Err(invalid(
            "Suppression summaries cannot themselves be suppressed.",
        ));
    }
    let key_fields = suppression
        .key_fields
        .as_ref()
        .filter(|fields| {
            (1..=MAXIMUM_SUPPRESSION_KEY_FIELDS).contains(&fields.len())
                && fields
                    .iter()
                    .enumerate()
                    .all(|(index, field)| !fields[..index].contains(field))
                && fields
                    .iter()
                    .all(|field| crate::field::is_suppression_key(field.as_deref()))
        })
        .ok_or_else(|| {
            invalid(format!(
                "Policy suppression keyFields must list 1–{MAXIMUM_SUPPRESSION_KEY_FIELDS} distinct string field paths."
            ))
        })?;
    if !(1..=86_400).contains(&suppression.window_seconds) {
        return Err(invalid(
            "Policy suppression windowSeconds must be between 1 and 86400.",
        ));
    }
    if !(1..=100_000).contains(&suppression.allow_per_window) {
        return Err(invalid(
            "Policy suppression allowPerWindow must be between 1 and 100000.",
        ));
    }
    Ok(PolicySuppression {
        key_fields: strings(key_fields),
        window_seconds: suppression.window_seconds,
        allow_per_window: suppression.allow_per_window,
    })
}

/// C# `PolicyLoader.ValidateSet`: a set that suppresses must also accept the summary
/// event, so suppressed counts are always delivered. Checked when a bundle is
/// assembled from directories and packs.
pub fn validate_set(policies: &[LoadedPolicy]) -> Result<(), PolicyError> {
    if !policies
        .iter()
        .any(|item| item.policy.suppression.is_some())
    {
        return Ok(());
    }
    let summary_accepted = policies.iter().any(|item| {
        item.policy
            .r#match
            .event_types
            .iter()
            .any(|value| value == TELEMETRY_AGGREGATION_SUMMARY)
            && matches!(
                try_parse_action(Some(&item.policy.decision.action)),
                Some(DecisionAction::Accept | DecisionAction::RedactAndAccept)
            )
    });
    if summary_accepted {
        Ok(())
    } else {
        Err(invalid(format!(
            "Policies define suppression but none accepts '{TELEMETRY_AGGREGATION_SUMMARY}'."
        )))
    }
}

/// No null, empty or white-space item (`string.IsNullOrWhiteSpace`).
fn all_present(items: &[Option<String>]) -> bool {
    items.iter().all(|item| present(item.as_deref()))
}

/// Items already checked by [`all_present`] (event types and categories,
/// field paths), so none is null.
fn strings(items: &[Option<String>]) -> Vec<String> {
    items
        .iter()
        .map(|item| item.clone().unwrap_or_default())
        .collect()
}

/// Parses a named action (`PolicyLoader.TryParseAction`): hyphens are ignored
/// and names compare case-insensitively. Numeric values are rejected.
pub fn try_parse_action(value: Option<&str>) -> Option<DecisionAction> {
    let value = value.filter(|text| present(Some(text)))?;
    let normalized = value.replace('-', "");
    DecisionAction::ALL
        .iter()
        .copied()
        .find(|action| action.pascal_name().eq_ignore_ascii_case(&normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_order_uses_utf16_code_units() {
        // U+FF5E sorts after U+1F600 in UTF-16 (0xFF5E > 0xD83D) but before it
        // by scalar value.
        assert_eq!(ordinal_cmp("\u{ff5e}", "\u{1f600}"), Ordering::Greater);
        assert_eq!(ordinal_cmp("a", "b"), Ordering::Less);
        assert_eq!(ordinal_cmp("B", "a"), Ordering::Less);
    }

    #[test]
    fn actions_parse_like_csharp() {
        let accepted = [
            ("accept", DecisionAction::Accept),
            ("Accept", DecisionAction::Accept),
            ("-accept", DecisionAction::Accept),
            ("redact-and-accept", DecisionAction::RedactAndAccept),
            ("redact--and-accept", DecisionAction::RedactAndAccept),
            ("REDACTANDACCEPT", DecisionAction::RedactAndAccept),
            ("dead-letter", DecisionAction::DeadLetter),
            ("Re-ject", DecisionAction::Reject),
            ("quarantine", DecisionAction::Quarantine),
            ("sample", DecisionAction::Sample),
            ("aggregate", DecisionAction::Aggregate),
        ];
        for (text, action) in accepted {
            assert_eq!(try_parse_action(Some(text)), Some(action), "{text}");
        }
        for text in [
            "1",
            "-1",
            "acept",
            " accept",
            "accept ",
            "",
            "redact_and_accept",
            "\u{17f}ample",
            "quarant\u{131}ne",
            "-",
        ] {
            assert_eq!(try_parse_action(Some(text)), None, "{text:?}");
        }
        assert_eq!(try_parse_action(None), None);
    }

    #[test]
    fn decodes_byte_order_marks() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFab"), "ab");
        assert_eq!(decode_text(b"\xFF\xFEa\x00b\x00"), "ab");
        assert_eq!(decode_text(b"\xFE\xFF\x00a\x00b"), "ab");
        assert_eq!(decode_text(b"\xFF\xFE\x00\x00a\x00\x00\x00"), "a");
        assert_eq!(decode_text(b"a\xFFb"), "a\u{fffd}b");
    }
}
