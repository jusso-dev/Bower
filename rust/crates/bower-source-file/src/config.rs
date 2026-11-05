//! BOWER_FILE_CONFIG (C# `FileTailSourceConfigurationLoader`): same shape, defaults,
//! bounds and messages. There is no wildcard, directory or "all files" form.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

use crate::paths;

pub const MAXIMUM_INPUTS: usize = 16;
pub const MAXIMUM_ROOTS: usize = 8;
pub const MAXIMUM_PATH_LENGTH: usize = 1_024;
pub const DEFAULT_MAX_LINE_BYTES: i32 = 16_384;
/// A pack parser reads records of at most 32 KiB; this leaves room for the record's
/// metadata fields, so a longer line could never be parsed.
pub const MAXIMUM_MAX_LINE_BYTES: i32 = 30_720;
pub const MINIMUM_MAX_LINE_BYTES: i32 = 256;
const MAXIMUM_BYTES: u64 = 262_144;

pub const FORMAT_TEXT: &str = "text";
pub const FORMAT_JSON_LINES: &str = "json-lines";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("File tail source configuration file does not exist.")]
    FileNotFound,
    #[error("{0}")]
    InvalidData(String),
    #[error("File tail source configuration file could not be read: {0}")]
    Io(String),
}

/// Integers are `i32` like the C# `int` properties, so an out-of-range number fails as a
/// serializer error in both runtimes.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileTailSourceConfiguration {
    pub api_version: String,
    pub kind: String,
    /// Kept as options (C# list elements are not null-checked by the serializer), so a
    /// null entry fails with the same validation message.
    pub allowed_roots: Vec<Option<String>>,
    pub inputs: Vec<Option<InputOptions>>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_milliseconds: i32,
    #[serde(default = "default_max_lines_per_batch")]
    pub max_lines_per_batch: i32,
    #[serde(default = "default_max_bytes_per_batch")]
    pub max_bytes_per_batch: i32,
}

/// One file below an allowed root and the signed pack parser that maps its lines.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputOptions {
    pub id: String,
    pub path: String,
    pub route: Route,
    /// `text` (each line becomes `message`) or `json-lines` (the line's object as `json`).
    #[serde(default = "default_format")]
    pub format: String,
    /// `end` (default) or `beginning`.
    #[serde(default = "default_start_at")]
    pub start_at: String,
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: i32,
    /// Allow the file itself to be one symbolic link whose target passes the same checks.
    #[serde(default)]
    pub allow_symlink: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub pack: String,
    pub parser: i32,
}

impl InputOptions {
    /// Durable cursor key in the queue database's source cursor table.
    pub fn source_id(&self) -> String {
        format!("file:{}", self.id)
    }

    pub fn is_json_lines(&self) -> bool {
        self.format == FORMAT_JSON_LINES
    }
}

impl FileTailSourceConfiguration {
    /// Validated inputs (every entry is present after `parse`).
    pub fn inputs(&self) -> impl Iterator<Item = &InputOptions> {
        self.inputs.iter().flatten()
    }

    pub fn roots(&self) -> Vec<String> {
        self.allowed_roots.iter().flatten().cloned().collect()
    }
}

fn default_poll_interval() -> i32 {
    1_000
}
fn default_max_lines_per_batch() -> i32 {
    256
}
fn default_max_bytes_per_batch() -> i32 {
    1_048_576
}
fn default_format() -> String {
    FORMAT_TEXT.into()
}
fn default_start_at() -> String {
    "end".into()
}
fn default_max_line_bytes() -> i32 {
    DEFAULT_MAX_LINE_BYTES
}

pub fn load_file(path: impl AsRef<Path>) -> Result<FileTailSourceConfiguration, ConfigError> {
    let path = path.as_ref();
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Err(ConfigError::FileNotFound),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::FileNotFound);
        }
        Err(error) => return Err(ConfigError::Io(format!("{:?}", error.kind()))),
    };
    if metadata.len() > MAXIMUM_BYTES {
        return Err(invalid_data(
            "File tail source configuration file exceeds 256 KiB.",
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::Io(format!("{:?}", error.kind())))?;
    parse(&text)
}

pub fn parse(json: &str) -> Result<FileTailSourceConfiguration, ConfigError> {
    let configuration: FileTailSourceConfiguration =
        serde_json::from_str(json).map_err(|error| {
            ConfigError::InvalidData(format!(
                "File tail source configuration is invalid: {error}"
            ))
        })?;
    if configuration.api_version != "bower.security/v1" || configuration.kind != "FileTailSource" {
        return Err(invalid_data(
            "File tail source configuration needs apiVersion bower.security/v1 and kind FileTailSource.",
        ));
    }
    if !(1..=MAXIMUM_ROOTS).contains(&configuration.allowed_roots.len()) {
        return Err(invalid_data(format!(
            "File tail source configuration must list 1–{MAXIMUM_ROOTS} allowedRoots."
        )));
    }
    for root in &configuration.allowed_roots {
        if !root
            .as_deref()
            .is_some_and(|root| paths::is_canonical(root) && !paths::is_file_system_root(root))
        {
            return Err(invalid_data(
                "File tail allowedRoots must be absolute, normalised directories without wildcards, and not the file system root.",
            ));
        }
    }
    if !(1..=MAXIMUM_INPUTS).contains(&configuration.inputs.len()) {
        return Err(invalid_data(format!(
            "File tail source configuration must list 1–{MAXIMUM_INPUTS} inputs."
        )));
    }
    if !(100..=60_000).contains(&configuration.poll_interval_milliseconds) {
        return Err(invalid_data(
            "File tail pollIntervalMilliseconds must be between 100 and 60000.",
        ));
    }
    if !(1..=1_024).contains(&configuration.max_lines_per_batch) {
        return Err(invalid_data(
            "File tail maxLinesPerBatch must be between 1 and 1024.",
        ));
    }
    if !(65_536..=4_194_304).contains(&configuration.max_bytes_per_batch) {
        return Err(invalid_data(
            "File tail maxBytesPerBatch must be between 65536 and 4194304.",
        ));
    }
    let roots = configuration.roots();
    let mut ids = HashSet::new();
    let mut seen_paths = HashSet::new();
    for input in &configuration.inputs {
        let Some(input) = input else {
            return Err(invalid_id());
        };
        validate(input, &roots)?;
        if !ids.insert(input.id.clone()) {
            return Err(invalid_data(format!(
                "File tail input {} is listed more than once.",
                input.id
            )));
        }
        if !seen_paths.insert(input.path.clone()) {
            return Err(fail(&input.id, "path is already read by another input."));
        }
    }
    Ok(configuration)
}

fn validate(input: &InputOptions, roots: &[String]) -> Result<(), ConfigError> {
    if !is_input_id(&input.id) {
        return Err(invalid_id());
    }
    let id = &input.id;
    if !paths::is_canonical(&input.path) {
        return Err(fail(
            id,
            "path must be an absolute, normalised file path without wildcards; there is no directory or glob form.",
        ));
    }
    if paths::root_of(&input.path, roots).is_none() {
        return Err(fail(id, "path is not below an allowed root."));
    }
    if input.route.pack.trim().is_empty() || input.route.parser < 0 {
        return Err(fail(
            id,
            "route needs a pack and a parser index of 0 or more.",
        ));
    }
    if !matches!(input.format.as_str(), FORMAT_TEXT | FORMAT_JSON_LINES) {
        return Err(fail(id, "format must be text or json-lines."));
    }
    if !matches!(input.start_at.as_str(), "end" | "beginning") {
        return Err(fail(id, "startAt must be end or beginning."));
    }
    if !(MINIMUM_MAX_LINE_BYTES..=MAXIMUM_MAX_LINE_BYTES).contains(&input.max_line_bytes) {
        return Err(fail(
            id,
            &format!(
                "maxLineBytes must be between {MINIMUM_MAX_LINE_BYTES} and {MAXIMUM_MAX_LINE_BYTES}."
            ),
        ));
    }
    Ok(())
}

fn is_input_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn invalid_id() -> ConfigError {
    invalid_data(
        "File tail input id must be 1–63 lowercase letters, digits or hyphens and start with a letter or digit.",
    )
}

fn fail(id: &str, message: &str) -> ConfigError {
    invalid_data(format!("File tail input {id}: {message}"))
}

fn invalid_data(message: impl Into<String>) -> ConfigError {
    ConfigError::InvalidData(message.into())
}
