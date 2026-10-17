//! Error type, .NET-compatible file access messages and option parsing shared by
//! commands. The C# CLI catches every exception, prints `exception.Message` to
//! stderr and exits 1; [`CliError`] carries that message.

use std::fmt;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

/// A failure reported as one stderr line with exit code 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError(pub String);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

impl CliError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Wraps a library error using its display text (libraries never put secrets
    /// or payloads in error text).
    pub fn from_display(error: impl fmt::Display) -> Self {
        Self(error.to_string())
    }
}

pub type CliResult<T = i32> = Result<T, CliError>;

/// `Path.GetFullPath`: absolute and lexically normalised, symlinks not resolved.
pub fn full_path(path: &str) -> PathBuf {
    let raw = Path::new(path);
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(raw)
    };
    let mut normalised = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other.as_os_str()),
        }
    }
    normalised
}

fn io_message(path: &str, error: &std::io::Error) -> String {
    let full = full_path(path);
    let shown = full.display();
    match error.kind() {
        ErrorKind::NotFound => {
            let parent_exists = full.parent().is_none_or(Path::exists);
            if parent_exists {
                format!("Could not find file '{shown}'.")
            } else {
                format!("Could not find a part of the path '{shown}'.")
            }
        }
        ErrorKind::PermissionDenied => format!("Access to the path '{shown}' is denied."),
        ErrorKind::IsADirectory => format!("Access to the path '{shown}' is denied."),
        _ => format!("{error} : '{shown}'"),
    }
}

/// `File.ReadAllText`: UTF-8 with the BOM stripped; .NET exception messages.
pub fn read_text(path: &str) -> CliResult<String> {
    if Path::new(path).is_dir() {
        return Err(CliError(format!(
            "Access to the path '{}' is denied.",
            full_path(path).display()
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| CliError(io_message(path, &error)))?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// `File.ReadAllBytes` with .NET exception messages.
pub fn read_bytes(path: &str) -> CliResult<Vec<u8>> {
    std::fs::read(path).map_err(|error| CliError(io_message(path, &error)))
}

/// `File.WriteAllText` (UTF-8, no BOM, overwrite).
pub fn write_text(path: &str, content: &str) -> CliResult<()> {
    std::fs::write(path, content).map_err(|error| CliError(io_message(path, &error)))
}

/// `int.Parse(value, CultureInfo.InvariantCulture)`.
pub fn parse_int(value: &str) -> CliResult<i32> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError(format!(
            "The input string '{value}' was not in a correct format."
        )));
    }
    trimmed
        .strip_prefix('+')
        .unwrap_or(trimmed)
        .parse::<i32>()
        .map_err(|_| CliError::new("Value was either too large or too small for an Int32."))
}

/// `long.Parse(value, CultureInfo.InvariantCulture)`.
pub fn parse_long(value: &str) -> CliResult<i64> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError(format!(
            "The input string '{value}' was not in a correct format."
        )));
    }
    trimmed
        .strip_prefix('+')
        .unwrap_or(trimmed)
        .parse::<i64>()
        .map_err(|_| CliError::new("Value was either too large or too small for an Int64."))
}

/// `CliOptions.Int(args, name, fallback)`.
pub fn int_or(value: Option<&str>, fallback: i32) -> CliResult<i32> {
    value.map_or(Ok(fallback), parse_int)
}

/// `CliOptions.Required(args, name)`.
pub fn required<'a>(value: Option<&'a str>, name: &str) -> CliResult<&'a str> {
    value.ok_or_else(|| CliError(format!("{name} is required.")))
}

/// Reads every `--trusted-key` file (`CliOptions.All(...).Select(File.ReadAllText)`).
pub fn read_all(paths: &[String]) -> CliResult<Vec<String>> {
    paths.iter().map(|path| read_text(path)).collect()
}

/// Appends `/` like `EnsureSlash` so relative request paths resolve under it.
pub fn ensure_slash(value: &str) -> String {
    if value.ends_with('/') {
        value.to_owned()
    } else {
        format!("{value}/")
    }
}

/// Bounded queue size the C# CLI opens stores with (10 GiB).
pub const QUEUE_MAXIMUM_BYTES: i64 = 10 * 1024 * 1024 * 1024;

/// `Path.Combine(Directory.GetCurrentDirectory(), "data", "bower.db")`.
pub fn default_database() -> String {
    std::env::current_dir()
        .unwrap_or_default()
        .join("data")
        .join("bower.db")
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ints_like_invariant_culture() {
        assert_eq!(parse_int(" 42 ").unwrap(), 42);
        assert_eq!(parse_int("+7").unwrap(), 7);
        assert_eq!(parse_int("-3").unwrap(), -3);
        assert_eq!(
            parse_int("abc").unwrap_err().0,
            "The input string 'abc' was not in a correct format."
        );
        assert_eq!(
            parse_int("99999999999").unwrap_err().0,
            "Value was either too large or too small for an Int32."
        );
    }

    #[test]
    fn reports_missing_files_like_dotnet() {
        let message = read_text("/nonexistent-bower-dir/file.pem").unwrap_err().0;
        assert_eq!(
            message,
            "Could not find a part of the path '/nonexistent-bower-dir/file.pem'."
        );
        let dir = std::env::temp_dir();
        let path = dir.join("bower-cli-missing-file.pem");
        let message = read_text(path.to_str().unwrap()).unwrap_err().0;
        assert!(message.starts_with("Could not find file '"), "{message}");
    }

    #[test]
    fn normalises_full_paths() {
        assert_eq!(full_path("/a/b/../c/./d"), PathBuf::from("/a/c/d"));
    }
}
