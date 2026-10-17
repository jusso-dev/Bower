//! Privacy profile YAML (`kind: PrivacyProfile`) loader (`PrivacyProfileLoader`).
//!
//! Strict: unknown keys, unknown detector ids and unknown actions fail the load.
//! The HMAC key comes from the host, never from YAML. Scalars follow YamlDotNet
//! conversion rules (`yes`/`off` booleans, `0x`/`0b`/leading-zero octal integers).

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use base64::Engine as _;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use indexmap::IndexMap;
use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use sha2::{Digest, Sha256};

use crate::applicator::PolicyApplicator;
use crate::error::PrivacyError;
use crate::ids::detector_ids;
use crate::policy::{PrivacyAction, PrivacyFieldRule, PrivacyPolicy};
use crate::text::{is_null_or_whitespace, utf16_len};

const MAXIMUM_PROFILE_BYTES: usize = 262_144;

/// A loaded profile: the policy plus identity and a hash of the normalised YAML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedPrivacyProfile {
    pub policy: PrivacyPolicy,
    /// `metadata.id` (`None` when absent, as C# leaves it null).
    pub id: Option<String>,
    /// `metadata.version` (`None` when absent, as C# leaves it null).
    pub version: Option<String>,
    /// `sha256:<hex>` of the YAML with line endings normalised to `\n`.
    pub hash: String,
}

// ------------------------------------------------------------------ document model

/// `Option<Option<T>>`: outer `None` = key absent, inner `None` = YAML null.
type Present<T> = Option<Option<T>>;

#[derive(Default)]
struct ProfileDocument {
    api_version: Present<String>,
    kind: Present<String>,
    metadata: Present<MetadataDocument>,
    default_action: Present<String>,
    detectors: Present<IndexMap<String, Option<String>>>,
    disabled: Present<Vec<Option<String>>>,
    enable_opt_in: Present<Vec<Option<String>>>,
    fields: Present<Vec<Option<FieldRuleDocument>>>,
    maximum_field_length: Present<DotnetInt>,
    emit_metadata: Present<DotnetBool>,
}

#[derive(Default)]
struct MetadataDocument {
    id: Option<String>,
    version: Option<String>,
}

#[derive(Default)]
struct FieldRuleDocument {
    path: Option<String>,
    action: Option<String>,
    max_length: Option<DotnetInt>,
}

fn unknown_property<E: de::Error>(name: &str, type_name: &str) -> E {
    E::custom(format!(
        "Property '{name}' not found on type 'Bower.Redaction.Privacy.{type_name}'."
    ))
}

/// Visits a mapping with YamlDotNet semantics: duplicate keys overwrite, unknown keys fail.
macro_rules! mapping_visitor {
    ($visitor:ident, $target:ident, $type_name:literal, |$map:ident, $doc:ident, $key:ident| $body:block) => {
        struct $visitor;

        impl<'de> Visitor<'de> for $visitor {
            type Value = $target;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!("a ", $type_name, " mapping"))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut $map: A) -> Result<Self::Value, A::Error> {
                let mut $doc = $target::default();
                while let Some($key) = $map.next_key::<String>()? {
                    $body
                }
                Ok($doc)
            }
        }

        impl<'de> Deserialize<'de> for $target {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_map($visitor)
            }
        }
    };
}

mapping_visitor!(
    ProfileVisitor,
    ProfileDocument,
    "PrivacyProfileDocument",
    |map, doc, key| {
        match key.as_str() {
            "apiVersion" => doc.api_version = Some(map.next_value()?),
            "kind" => doc.kind = Some(map.next_value()?),
            "metadata" => doc.metadata = Some(map.next_value()?),
            "defaultAction" => doc.default_action = Some(map.next_value()?),
            "detectors" => doc.detectors = Some(map.next_value()?),
            "disabled" => doc.disabled = Some(map.next_value()?),
            "enableOptIn" => doc.enable_opt_in = Some(map.next_value()?),
            "fields" => doc.fields = Some(map.next_value()?),
            "maximumFieldLength" => doc.maximum_field_length = Some(map.next_value()?),
            "emitMetadata" => doc.emit_metadata = Some(map.next_value()?),
            other => {
                let _: IgnoredAny = map.next_value()?;
                return Err(unknown_property(other, "PrivacyProfileDocument"));
            }
        }
    }
);

mapping_visitor!(
    MetadataVisitor,
    MetadataDocument,
    "PrivacyProfileMetadata",
    |map, doc, key| {
        match key.as_str() {
            "id" => doc.id = map.next_value()?,
            "version" => doc.version = map.next_value()?,
            "description" => {
                let _: Option<String> = map.next_value()?;
            }
            other => {
                let _: IgnoredAny = map.next_value()?;
                return Err(unknown_property(other, "PrivacyProfileMetadata"));
            }
        }
    }
);

mapping_visitor!(
    FieldRuleVisitor,
    FieldRuleDocument,
    "PrivacyFieldRuleDocument",
    |map, doc, key| {
        match key.as_str() {
            "path" => doc.path = map.next_value()?,
            "action" => doc.action = map.next_value()?,
            "maxLength" => doc.max_length = map.next_value()?,
            other => {
                let _: IgnoredAny = map.next_value()?;
                return Err(unknown_property(other, "PrivacyFieldRuleDocument"));
            }
        }
    }
);

/// YamlDotNet `Int32` scalar conversion.
struct DotnetInt(i32);

impl<'de> Deserialize<'de> for DotnetInt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse_dotnet_int(&text)
            .map(DotnetInt)
            .ok_or_else(|| de::Error::custom("Exception during deserialization"))
    }
}

/// YamlDotNet `Boolean` scalar conversion.
struct DotnetBool(bool);

impl<'de> Deserialize<'de> for DotnetBool {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value = if ["true", "y", "yes", "on"]
            .iter()
            .any(|word| text.eq_ignore_ascii_case(word))
        {
            true
        } else if ["false", "n", "no", "off"]
            .iter()
            .any(|word| text.eq_ignore_ascii_case(word))
        {
            false
        } else {
            return Err(de::Error::custom("Exception during deserialization"));
        };
        Ok(DotnetBool(value))
    }
}

/// `ulong.Parse(text, NumberStyles.Integer)`.
fn parse_dotnet_ulong(text: &str) -> Option<u64> {
    let trimmed =
        text.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\u{B}' | '\u{C}' | '\r'));
    let (negative, digits) = match trimmed.as_bytes().first()? {
        b'+' => (false, &trimmed[1..]),
        b'-' => (true, &trimmed[1..]),
        _ => (false, trimmed),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let value: u64 = digits.parse().ok()?;
    (!negative || value == 0).then_some(value)
}

/// YamlDotNet `DeserializeIntegerHelper` for `Int32`: sign, `0b`/`0x`/leading-zero
/// octal, `_` separators and base-60 `a:b` groups.
fn parse_dotnet_int(value: &str) -> Option<i32> {
    let bytes = value.as_bytes();
    let mut index = 0;
    let negative = match bytes.first()? {
        b'-' => {
            index += 1;
            true
        }
        b'+' => {
            index += 1;
            false
        }
        _ => false,
    };

    let result: u64 = if *bytes.get(index)? == b'0' {
        if index == bytes.len() - 1 {
            0
        } else {
            index += 1;
            let base = match bytes[index] {
                b'b' => {
                    index += 1;
                    2
                }
                b'x' => {
                    index += 1;
                    16
                }
                _ => 8,
            };
            let digits: String = value[index..].chars().filter(|c| *c != '_').collect();
            if base == 16 {
                let trimmed = digits.trim_matches(|c: char| {
                    matches!(c, ' ' | '\t' | '\n' | '\u{B}' | '\u{C}' | '\r')
                });
                if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return None;
                }
                u64::from_str_radix(trimmed, 16).ok()?
            } else {
                let radix_digits = if base == 2 { b'0'..=b'1' } else { b'0'..=b'7' };
                if digits.is_empty() || !digits.bytes().all(|byte| radix_digits.contains(&byte)) {
                    return None;
                }
                u64::from_str_radix(&digits, base).ok()?
            }
        }
    } else {
        let mut total: u64 = 0;
        for chunk in value[index..].split(':') {
            total = total.checked_mul(60)?;
            total = total.checked_add(parse_dotnet_ulong(&chunk.replace('_', ""))?)?;
        }
        total
    };

    if negative {
        let signed = -(i64::try_from(result).ok()?);
        i32::try_from(signed).ok()
    } else {
        i32::try_from(result).ok()
    }
}

// ------------------------------------------------------------------ loader

fn invalid(message: impl Into<String>) -> PrivacyError {
    PrivacyError::InvalidData(message.into())
}

/// `PrivacyProfileLoader.ParseAction`: hyphens removed, ASCII case-insensitive enum name.
pub fn parse_action(value: &str) -> Result<PrivacyAction, PrivacyError> {
    let normalised = value.replace('-', "");
    PrivacyAction::ALL
        .into_iter()
        .find(|action| action.name().eq_ignore_ascii_case(&normalised))
        .ok_or_else(|| invalid(format!("Unknown privacy action '{value}'.")))
}

fn require_known(known: &HashSet<&str>, detector: Option<&str>) -> Result<(), PrivacyError> {
    match detector {
        Some(detector) if known.contains(detector) => Ok(()),
        other => Err(invalid(format!(
            "Unknown detector id '{}'.",
            other.unwrap_or_default()
        ))),
    }
}

/// C# throws `NullReferenceException` for YAML nulls in these positions; fail the
/// load with a descriptive `InvalidData` error instead.
fn required_collection<T: Default>(value: Present<T>, name: &str) -> Result<T, PrivacyError> {
    match value {
        None => Ok(T::default()),
        Some(Some(value)) => Ok(value),
        Some(None) => Err(invalid(format!(
            "Privacy profile '{name}' must not be null."
        ))),
    }
}

/// `string.ReplaceLineEndings("\n")`: CRLF, CR, LF, NEL, LS, FF and PS become `\n`.
fn replace_line_endings(text: &str) -> String {
    let mut normalised = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                normalised.push('\n');
            }
            '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{C}' => normalised.push('\n'),
            other => normalised.push(other),
        }
    }
    normalised
}

/// Loads a deterministic privacy profile. `hmac_key` comes from the host.
pub fn load(
    yaml: &str,
    hmac_key: Option<&[u8]>,
    hmac_key_id: Option<&str>,
) -> Result<LoadedPrivacyProfile, PrivacyError> {
    if is_null_or_whitespace(yaml) {
        return Err(PrivacyError::Argument(
            "The value cannot be an empty string or composed entirely of whitespace. (Parameter 'yaml')"
                .to_owned(),
        ));
    }

    if yaml.len() > MAXIMUM_PROFILE_BYTES {
        return Err(invalid("Privacy profile exceeds 256 KiB."));
    }

    let document = match serde_yaml_ng::from_str::<Option<ProfileDocument>>(yaml) {
        Ok(Some(document)) => document,
        Ok(None) => return Err(invalid("Privacy profile is empty.")),
        Err(error) => {
            let line = error.location().map_or(0, |location| location.line());
            return Err(invalid(format!(
                "Privacy profile is invalid at line {line}: {error}"
            )));
        }
    };

    if document.api_version.flatten().as_deref() != Some("bower.security/v1")
        || document.kind.flatten().as_deref() != Some("PrivacyProfile")
    {
        return Err(invalid(
            "Privacy profile must be apiVersion bower.security/v1, kind PrivacyProfile.",
        ));
    }

    let known: HashSet<&str> = detector_ids::ALL.iter().copied().collect();
    let defaults = PrivacyPolicy::create_default();
    let mut actions = defaults.detector_actions.clone();
    for (detector, action) in required_collection(document.detectors, "detectors")? {
        require_known(&known, Some(&detector))?;
        let action = action.ok_or_else(|| {
            invalid(format!(
                "Privacy profile action for '{detector}' must not be null."
            ))
        })?;
        actions.insert(detector, parse_action(&action)?);
    }

    let disabled = required_collection(document.disabled, "disabled")?;
    let enable_opt_in = required_collection(document.enable_opt_in, "enableOptIn")?;
    for detector in disabled.iter().chain(&enable_opt_in) {
        require_known(&known, detector.as_deref())?;
    }

    let mut rules = Vec::new();
    for rule in required_collection(document.fields, "fields")? {
        let rule = rule.ok_or_else(|| invalid("Privacy profile field rule must not be null."))?;
        let path = rule.path.unwrap_or_default();
        if is_null_or_whitespace(&path)
            || path
                .split('.')
                .any(|segment| segment.is_empty() || utf16_len(segment) > 64)
        {
            return Err(invalid(format!("Field rule path '{path}' is invalid.")));
        }

        let action = rule
            .action
            .ok_or_else(|| invalid(format!("Field rule '{path}' needs an action.")))?;
        let action = parse_action(&action)?;
        let max_length = rule.max_length.map(|DotnetInt(value)| value);
        if action == PrivacyAction::Truncate && !matches!(max_length, Some(1..=65_536)) {
            return Err(invalid(format!(
                "Field rule '{path}' needs maxLength between 1 and 65536 for truncate."
            )));
        }

        // Negative lengths only reach non-truncate rules, which ignore them.
        let max_length = max_length.and_then(|value| usize::try_from(value).ok());
        rules.push(PrivacyFieldRule::new(path, action, max_length));
    }

    let maximum_field_length = match document.maximum_field_length.flatten() {
        Some(DotnetInt(value)) => value,
        None => defaults.maximum_field_length as i32,
    };
    if !(256..=65_536).contains(&maximum_field_length) {
        return Err(invalid("maximumFieldLength must be between 256 and 65536."));
    }

    let default_action = match document.default_action.flatten() {
        Some(action) => parse_action(&action)?,
        None => defaults.default_action,
    };

    let policy = PrivacyPolicy {
        default_action,
        detector_actions: actions,
        disabled_detectors: disabled.into_iter().flatten().collect(),
        enabled_opt_in_detectors: enable_opt_in.into_iter().flatten().collect(),
        field_rules: rules,
        maximum_field_length: maximum_field_length as usize,
        emit_metadata: document
            .emit_metadata
            .flatten()
            .is_none_or(|DotnetBool(value)| value),
        hmac_key: hmac_key.map(<[u8]>::to_vec),
        hmac_key_id: match hmac_key_id {
            Some(key_id) if !is_null_or_whitespace(key_id) => key_id.to_owned(),
            _ => "k1".to_owned(),
        },
        ..PrivacyPolicy::default()
    };

    // Construct once so a profile that needs an absent key fails at load, not at runtime.
    PolicyApplicator::new(&policy)?;

    let metadata = document
        .metadata
        .flatten()
        .ok_or_else(|| invalid("Privacy profile metadata is required."))?;
    let hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(replace_line_endings(yaml).as_bytes()))
    );
    Ok(LoadedPrivacyProfile {
        policy,
        id: metadata.id,
        version: metadata.version,
        hash,
    })
}

/// Reads a key file holding base64 (preferred) or at least 32 raw bytes.
pub fn read_key_file(path: impl AsRef<Path>) -> Result<Vec<u8>, PrivacyError> {
    let raw =
        std::fs::read(path.as_ref()).map_err(|error| PrivacyError::Io(error.kind().to_string()))?;
    let key = decode_key(&raw);
    if key.len() >= 32 {
        Ok(key)
    } else {
        Err(invalid("HMAC key must be at least 32 bytes."))
    }
}

/// `Convert.FromBase64String(Encoding.UTF8.GetString(raw).Trim())`, falling back to
/// the raw bytes. .NET skips spaces, tabs and line breaks anywhere and ignores
/// non-zero trailing bits, but requires padding.
fn decode_key(raw: &[u8]) -> Vec<u8> {
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );

    let text = String::from_utf8_lossy(raw);
    let compact: String = text
        .trim()
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    LENIENT
        .decode(compact.as_bytes())
        .unwrap_or_else(|_| raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_integers_like_yamldotnet() {
        for (text, expected) in [
            ("300", Some(300)),
            ("+300", Some(300)),
            ("-300", Some(-300)),
            (" 300", Some(300)),
            ("1_000", Some(1000)),
            ("01000", Some(512)),
            ("0x200", Some(512)),
            ("0b100000000", Some(256)),
            ("0", Some(0)),
            ("1:30", Some(90)),
            ("0o1000", None),
            ("300.0", None),
            ("3e2", None),
            ("2147483648", None),
            ("-2147483648", Some(i32::MIN)),
        ] {
            assert_eq!(parse_dotnet_int(text), expected, "{text}");
        }
    }

    #[test]
    fn normalises_every_dotnet_line_ending() {
        assert_eq!(
            replace_line_endings("a\r\nb\rc\nd\u{85}e\u{2028}f\u{2029}g\u{C}h"),
            "a\nb\nc\nd\ne\nf\ng\nh"
        );
    }
}
