//! Sigma rule loading (`SigmaRuleLoader`). Rules are declarative data only.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::DetectionError;
use crate::model::{DetectionFields, DetectionRule};
use crate::yaml_node::YamlNode;

/// Rules larger than this are rejected before parsing.
pub const MAXIMUM_RULE_BYTES: usize = 256 * 1024;

pub fn load_file(path: &Path) -> Result<DetectionRule, DetectionError> {
    let yaml = std::fs::read_to_string(path).map_err(|error| {
        DetectionError::Io(format!("Could not read rule '{}': {error}", path.display()))
    })?;
    load_yaml(&yaml, Some(&path.to_string_lossy()))
}

/// Loads every `*.y*ml` file below `directory`, ordered by ordinal path.
pub fn load_directory(directory: &Path) -> Result<Vec<DetectionRule>, DetectionError> {
    if !directory.is_dir() {
        return Err(DetectionError::Io(format!(
            "Rule directory '{}' was not found.",
            directory.display()
        )));
    }
    let mut files = Vec::new();
    collect(directory, &mut files)?;
    files.sort_by(|left, right| {
        left.to_string_lossy()
            .encode_utf16()
            .cmp(right.to_string_lossy().encode_utf16())
    });
    files.iter().map(|path| load_file(path)).collect()
}

fn collect(directory: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<(), DetectionError> {
    let entries = std::fs::read_dir(directory).map_err(|error| {
        DetectionError::Io(format!("Could not list '{}': {error}", directory.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| DetectionError::Io(error.to_string()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| DetectionError::Io(error.to_string()))?;
        if file_type.is_dir() {
            collect(&path, files)?;
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(matches_y_ml)
        {
            files.push(path);
        }
    }
    Ok(())
}

/// The `*.y*ml` search pattern on the extension: `y`, any characters, `ml`.
fn matches_y_ml(extension: &str) -> bool {
    extension.len() >= 3 && extension.starts_with('y') && extension.ends_with("ml")
}

pub fn load_yaml(yaml: &str, source_name: Option<&str>) -> Result<DetectionRule, DetectionError> {
    if yaml.trim().is_empty() {
        return Err(DetectionError::InvalidArgument(
            "The value cannot be an empty string or composed entirely of whitespace.".to_owned(),
        ));
    }
    if yaml.len() > MAXIMUM_RULE_BYTES {
        return Err(DetectionError::InvalidData(
            "Sigma rule exceeds 256 KiB limit.".to_owned(),
        ));
    }

    // Only the first document is read, as YamlStream.Documents[0].
    let first = serde_yaml_ng::Deserializer::from_str(yaml)
        .next()
        .ok_or_else(|| {
            DetectionError::InvalidData("Sigma rule root must be a mapping.".to_owned())
        })?;
    let root: Option<YamlNode> = serde::Deserialize::deserialize(first).map_err(|error| {
        DetectionError::InvalidData(format!("Sigma rule is not valid YAML: {error}"))
    })?;
    let root = match root {
        Some(root @ YamlNode::Mapping(_)) => root,
        _ => {
            return Err(DetectionError::InvalidData(
                "Sigma rule root must be a mapping.".to_owned(),
            ));
        }
    };

    let id = required_scalar(&root, "id", source_name)?;
    let title = required_scalar(&root, "title", source_name)?;
    let level = optional_scalar(&root, "level").unwrap_or_else(|| "medium".to_owned());
    let status = optional_scalar(&root, "status").unwrap_or_else(|| "experimental".to_owned());
    let description = optional_scalar(&root, "description").unwrap_or_default();
    let version = optional_scalar(&root, "version")
        .or_else(|| optional_scalar(&root, "date"))
        .unwrap_or_else(|| "1.0.0".to_owned());

    let mut log_sources = Vec::new();
    if let Some(log_source @ YamlNode::Mapping(_)) = root.get("logsource") {
        for key in ["product", "service", "category"] {
            if let Some(value) =
                optional_scalar(log_source, key).filter(|value| !value.trim().is_empty())
            {
                log_sources.push(value);
            }
        }
    }

    let mut fields = DetectionFields::default();
    let mut condition = "selection".to_owned();
    if let Some(detection @ YamlNode::Mapping(entries)) = root.get("detection") {
        condition =
            optional_scalar(detection, "condition").unwrap_or_else(|| "selection".to_owned());
        for (key, value) in entries {
            let key = key.text();
            if key.eq_ignore_ascii_case("condition") {
                continue;
            }
            fields.insert(&key, flatten_selection(value));
        }
    }
    if fields.is_empty() {
        return Err(DetectionError::InvalidData(format!(
            "Sigma rule '{id}' has no detection selections."
        )));
    }

    let mut techniques = Vec::new();
    if let Some(YamlNode::Sequence(tags)) = root.get("tags") {
        for tag in tags {
            let value = tag.text();
            if value
                .get(.."attack.t".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("attack.t"))
            {
                techniques.push(value["attack.".len()..].to_uppercase());
            } else if value
                .chars()
                .next()
                .is_some_and(|first| first.eq_ignore_ascii_case(&'t'))
                && value.encode_utf16().count() >= 5
                && value
                    .chars()
                    .skip(1)
                    .all(|character| character.is_ascii_digit())
            {
                techniques.push(value.to_uppercase());
            }
        }
    }

    let mut false_positives = Vec::new();
    if let Some(YamlNode::Sequence(items)) = root.get("falsepositives") {
        false_positives.extend(items.iter().map(YamlNode::text));
    }

    Ok(DetectionRule {
        id,
        title,
        version,
        level: level.to_lowercase(),
        status: status.to_lowercase(),
        description,
        log_sources,
        detection_fields: fields,
        condition,
        mitre_techniques: techniques,
        false_positive_hints: false_positives,
        rule_hash: hex::encode(Sha256::digest(yaml.as_bytes())),
    })
}

fn flatten_selection(node: &YamlNode) -> String {
    match node {
        YamlNode::Scalar(value) => value.clone(),
        YamlNode::Sequence(items) => items
            .iter()
            .map(YamlNode::text)
            .collect::<Vec<_>>()
            .join("|"),
        YamlNode::Mapping(entries) => entries
            .iter()
            .map(|(key, value)| format!("{}:{}", key.text(), flatten_selection(value)))
            .collect::<Vec<_>>()
            .join(";"),
    }
}

fn required_scalar(
    root: &YamlNode,
    name: &str,
    source: Option<&str>,
) -> Result<String, DetectionError> {
    match optional_scalar(root, name) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(DetectionError::InvalidData(format!(
            "Sigma rule{} missing required field '{name}'.",
            source
                .map(|source| format!(" '{source}'"))
                .unwrap_or_default()
        ))),
    }
}

fn optional_scalar(root: &YamlNode, name: &str) -> Option<String> {
    root.get(name).map(YamlNode::text)
}
