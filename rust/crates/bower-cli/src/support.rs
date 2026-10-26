//! Error type, .NET-compatible file access messages and option parsing shared by
//! commands. The C# CLI catches every exception, prints `exception.Message` to
//! stderr and exits 1; [`CliError`] carries that message.

use std::fmt;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use bower_contracts::time::{self, Timestamp};

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

/// `File.ReadAllText` decoding: the byte order mark picks UTF-8, UTF-16 LE/BE or UTF-32
/// LE/BE (as `StreamReader` detects them, so `FF FE 00 00` is UTF-32 LE); without one the
/// text is UTF-8. Invalid sequences become U+FFFD, as in .NET.
pub fn decode_text(bytes: &[u8]) -> String {
    fn units<const N: usize>(bytes: &[u8], read: impl Fn([u8; N]) -> u32) -> Vec<u32> {
        let (chunks, remainder) = bytes.as_chunks::<N>();
        let mut units: Vec<u32> = chunks.iter().map(|chunk| read(*chunk)).collect();
        if !remainder.is_empty() {
            units.push(0xFFFD);
        }
        units
    }
    let utf16 = |units: Vec<u32>| {
        let units: Vec<u16> = units
            .into_iter()
            .map(|unit| u16::try_from(unit).unwrap_or(0xFFFD))
            .collect();
        String::from_utf16_lossy(&units)
    };
    let utf32 = |units: Vec<u32>| {
        units
            .into_iter()
            .map(|unit| char::from_u32(unit).unwrap_or('\u{FFFD}'))
            .collect()
    };
    match bytes {
        [0xFF, 0xFE, 0x00, 0x00, rest @ ..] => utf32(units::<4>(rest, u32::from_le_bytes)),
        [0x00, 0x00, 0xFE, 0xFF, rest @ ..] => utf32(units::<4>(rest, u32::from_be_bytes)),
        [0xFF, 0xFE, rest @ ..] => {
            utf16(units::<2>(rest, |pair| u32::from(u16::from_le_bytes(pair))))
        }
        [0xFE, 0xFF, rest @ ..] => {
            utf16(units::<2>(rest, |pair| u32::from(u16::from_be_bytes(pair))))
        }
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// `File.ReadAllText`: BOM-detected encoding (see [`decode_text`]); .NET exception messages.
pub fn read_text(path: &str) -> CliResult<String> {
    if Path::new(path).is_dir() {
        return Err(CliError(format!(
            "Access to the path '{}' is denied.",
            full_path(path).display()
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| CliError(io_message(path, &error)))?;
    Ok(decode_text(&bytes))
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

const TIMESTAMP_SHAPE: &str = "YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM)";

/// C# `CliOptions.Timestamp`: a time option (`--at`, `--from`, `--to`) as UTC; `None`
/// when absent. Only [`TIMESTAMP_SHAPE`] is accepted: an explicit `Z` or offset (at most
/// 14:00), at most 7 fractional digits, no date-only or time-only values, so no input is
/// rounded, truncated or completed with today's date.
pub fn timestamp(value: Option<&str>, name: &str) -> CliResult<Option<Timestamp>> {
    let Some(text) = value else {
        return Ok(None);
    };
    strict_timestamp(text).map(Some).ok_or_else(|| {
        CliError(format!(
            "{name} must be an ISO 8601 timestamp with Z or an offset: {TIMESTAMP_SHAPE}."
        ))
    })
}

fn strict_timestamp(text: &str) -> Option<Timestamp> {
    let bytes = text.as_bytes();
    let number = |start: usize, end: usize| -> Option<u32> {
        let part = bytes.get(start..end)?;
        part.iter().all(u8::is_ascii_digit).then(|| {
            part.iter()
                .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
        })
    };
    if bytes.len() < 17
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
    {
        return None;
    }
    // Month and day are checked by the calendar parse below.
    let (year, hour, minute) = (number(0, 4)?, number(11, 13)?, number(14, 16)?);
    number(5, 7)?;
    number(8, 10)?;
    if year == 0 || hour > 23 || minute > 59 {
        return None;
    }
    let (mut index, mut seconds, mut fraction) = (16, "00", "");
    if bytes[index] == b':' {
        if number(17, 19)? > 59 {
            return None;
        }
        seconds = &text[17..19];
        index = 19;
        if bytes.get(index) == Some(&b'.') {
            let digits = bytes[index + 1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 || digits > 7 {
                return None;
            }
            fraction = &text[index..index + 1 + digits];
            index += 1 + digits;
        }
    }
    let offset = &text[index..];
    if offset != "Z" {
        let [b'+' | b'-', _, _, b':', _, _] = offset.as_bytes() else {
            return None;
        };
        let (hours, minutes) = (number(index + 1, index + 3)?, number(index + 4, index + 6)?);
        if minutes > 59 || hours * 60 + minutes > 14 * 60 {
            return None;
        }
    }
    let utc = time::to_utc(time::parse(&format!(
        "{}:{seconds}{fraction}{offset}",
        &text[..16]
    ))?);
    // DateTimeOffset range: UTC years 0001-9999.
    let round_trip = time::format_round_trip(&utc);
    (round_trip.as_bytes().get(4) == Some(&b'-') && !round_trip.starts_with("0000")).then_some(utc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_strict_iso_8601_with_an_offset() {
        for (value, expected) in [
            ("2026-10-17T01:02Z", "2026-10-17T01:02:00.0000000+00:00"),
            (
                "2026-10-17T11:02:03.1234567+10:00",
                "2026-10-17T01:02:03.1234567+00:00",
            ),
            (
                "2026-10-16T20:02:03.5-05:00",
                "2026-10-17T01:02:03.5000000+00:00",
            ),
            (
                "2026-10-17T01:02:03-00:00",
                "2026-10-17T01:02:03.0000000+00:00",
            ),
        ] {
            let parsed = timestamp(Some(value), "--from").unwrap().unwrap();
            assert_eq!(time::format_round_trip(&parsed), expected, "{value}");
        }
        assert_eq!(timestamp(None, "--from").unwrap(), None);
        for value in [
            "01:02",
            "2026-10-17",
            "2026-10-17T01:02:03",
            "2026-10-17T01:02:03.123456789Z",
            "10/17/2026",
            "Oct 17 2026",
            "2026-10-17 01:02:03Z",
            "2026-10-17T01:02:60Z",
            "2026-10-17T01:02:03+15:00",
            "2026-10-17t01:02:03z",
            " 2026-10-17T01:02:03Z",
            "2026-02-30T01:02:03Z",
            "0000-01-01T00:00:00Z",
            "0001-01-01T00:00:00+01:00",
            "9999-12-31T23:59:59-01:00",
            "2026-10-17T01:02:03.Z",
            "2026-10-17T01:02:03Z\n",
            "",
        ] {
            assert_eq!(
                timestamp(Some(value), "--to").unwrap_err().0,
                "--to must be an ISO 8601 timestamp with Z or an offset: YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM).",
                "{value:?}"
            );
        }
    }

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

#[cfg(test)]
mod decode_tests {
    use super::decode_text;

    fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
        let mut bytes = if big_endian {
            vec![0xFE, 0xFF]
        } else {
            vec![0xFF, 0xFE]
        };
        for unit in text.encode_utf16() {
            bytes.extend(if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            });
        }
        bytes
    }

    fn utf32(text: &str, big_endian: bool) -> Vec<u8> {
        let mut bytes = if big_endian {
            vec![0, 0, 0xFE, 0xFF]
        } else {
            vec![0xFF, 0xFE, 0, 0]
        };
        for character in text.chars() {
            let unit = u32::from(character);
            bytes.extend(if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            });
        }
        bytes
    }

    #[test]
    fn detects_byte_order_marks_like_file_read_all_text() {
        let text = "{\"name\":\"José 😀\"}";
        assert_eq!(decode_text(text.as_bytes()), text);
        assert_eq!(
            decode_text(&[&[0xEF, 0xBB, 0xBF][..], text.as_bytes()].concat()),
            text
        );
        assert_eq!(decode_text(&utf16(text, false)), text);
        assert_eq!(decode_text(&utf16(text, true)), text);
        assert_eq!(decode_text(&utf32(text, false)), text);
        assert_eq!(decode_text(&utf32(text, true)), text);
    }

    #[test]
    fn invalid_sequences_become_replacement_characters() {
        assert_eq!(decode_text(&[0xFF, 0xFE, b'a', 0, b'b']), "a\u{FFFD}");
        assert_eq!(decode_text(&[0xFF, 0xFE, 0x00, 0xD8]), "\u{FFFD}");
        assert_eq!(decode_text(&[0xFF, 0xFE, 0, 0, 0, 0, 0x11, 0]), "\u{FFFD}");
        assert_eq!(decode_text(&[b'a', 0xFF]), "a\u{FFFD}");
    }
}
