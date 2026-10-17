//! System.Text.Json compatible serialization (`BowerJson.Options`).
//!
//! Output escaping matches `JavaScriptEncoder.Default`: everything outside
//! printable ASCII plus `" & ' + < > \` `` ` `` is written as an upper-case
//! `\uXXXX` escape, so payload bytes, fingerprints and ledger hashes agree with
//! the C# collector.

use std::io::{self, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::ser::{CharEscape, Formatter};

/// Maximum nesting depth accepted on read (`JsonSerializerOptions.MaxDepth`).
pub const MAX_DEPTH: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    #[error("JSON nesting exceeds {MAX_DEPTH} levels")]
    TooDeep,
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

/// Compact formatter applying `JavaScriptEncoder.Default` escaping.
#[derive(Clone, Copy, Debug, Default)]
pub struct DotnetFormatter;

fn write_unicode_escape<W: ?Sized + Write>(writer: &mut W, unit: u16) -> io::Result<()> {
    write!(writer, "\\u{unit:04X}")
}

fn must_escape(byte: u8) -> bool {
    !(0x20..0x7F).contains(&byte)
        || matches!(
            byte,
            b'"' | b'&' | b'\'' | b'+' | b'<' | b'>' | b'\\' | b'`'
        )
}

impl Formatter for DotnetFormatter {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let bytes = fragment.as_bytes();
        let mut start = 0;
        for (index, character) in fragment.char_indices() {
            let first = bytes[index];
            if character.is_ascii() && !must_escape(first) {
                continue;
            }
            if start < index {
                writer.write_all(&bytes[start..index])?;
            }
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                write_unicode_escape(writer, *unit)?;
            }
            start = index + character.len_utf8();
        }
        writer.write_all(&bytes[start..])
    }

    fn write_char_escape<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        char_escape: CharEscape,
    ) -> io::Result<()> {
        match char_escape {
            CharEscape::Quote => writer.write_all(b"\\u0022"),
            CharEscape::ReverseSolidus => writer.write_all(b"\\\\"),
            CharEscape::Backspace => writer.write_all(b"\\b"),
            CharEscape::FormFeed => writer.write_all(b"\\f"),
            CharEscape::LineFeed => writer.write_all(b"\\n"),
            CharEscape::CarriageReturn => writer.write_all(b"\\r"),
            CharEscape::Tab => writer.write_all(b"\\t"),
            CharEscape::AsciiControl(byte) => write_unicode_escape(writer, u16::from(byte)),
            _ => Err(io::Error::other("unsupported JSON escape")),
        }
    }
}

/// Serializes like `JsonSerializer.Serialize(value, BowerJson.Options)`.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut buffer = Vec::with_capacity(512);
    let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, DotnetFormatter);
    value.serialize(&mut serializer)?;
    Ok(buffer)
}

pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    // DotnetFormatter only emits ASCII, so the buffer is always valid UTF-8.
    to_vec(value).map(|bytes| String::from_utf8(bytes).expect("escaped JSON is ASCII"))
}

/// Rejects documents nested deeper than [`MAX_DEPTH`] without allocating.
pub fn check_depth(text: &[u8]) -> Result<(), JsonError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in text {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(JsonError::TooDeep);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Deserializes with the `MaxDepth = 32` limit enforced.
pub fn from_slice<T: DeserializeOwned>(text: &[u8]) -> Result<T, JsonError> {
    check_depth(text)?;
    Ok(serde_json::from_slice(text)?)
}

pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, JsonError> {
    from_slice(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_javascript_encoder_default() {
        let text = to_string("a\"b<c>&'+`\\\n\u{1}é😀").unwrap();
        assert_eq!(
            text,
            "\"a\\u0022b\\u003Cc\\u003E\\u0026\\u0027\\u002B\\u0060\\\\\\n\\u0001\\u00E9\\uD83D\\uDE00\""
        );
    }

    #[test]
    fn rejects_deep_documents() {
        let deep = "[".repeat(33) + &"]".repeat(33);
        assert!(matches!(
            check_depth(deep.as_bytes()),
            Err(JsonError::TooDeep)
        ));
        let ok = "[".repeat(32) + &"]".repeat(32);
        assert!(check_depth(ok.as_bytes()).is_ok());
        assert!(check_depth(br#"{"a":"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["}"#).is_ok());
    }
}
