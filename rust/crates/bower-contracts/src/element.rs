//! `JsonElement`-compatible attribute values.
//!
//! System.Text.Json keeps a `JsonElement` as the original token stream: number
//! text is written back verbatim (`1E2` stays `1E2`), duplicate object keys and
//! their order survive, and strings are unescaped then re-escaped by the writer.
//! `serde_json::Value` normalises numbers and collapses duplicate keys, so queued
//! payload bytes would differ from the C# collector. This type preserves both.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::value::RawValue;

use crate::json::MAX_DEPTH;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonElement {
    Null,
    Bool(bool),
    /// Number exactly as written in the source document.
    Number(String),
    String(String),
    Array(Vec<JsonElement>),
    /// Properties in document order; duplicates are kept.
    Object(Vec<(String, JsonElement)>),
}

impl JsonElement {
    /// Parses one JSON value from `text` (surrounding whitespace allowed).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            text,
            position: 0,
        };
        parser.skip_whitespace();
        let value = parser.value(0)?;
        parser.skip_whitespace();
        if parser.position != parser.bytes.len() {
            return Err(parser.error("trailing characters"));
        }
        Ok(value)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// First property named `name`, as `JsonElement.TryGetProperty` does.
    pub fn get(&self, name: &str) -> Option<&JsonElement> {
        match self {
            Self::Object(properties) => properties
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

impl From<&str> for JsonElement {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for JsonElement {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<bool> for JsonElement {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for JsonElement {
    fn from(value: i64) -> Self {
        Self::Number(value.to_string())
    }
}

impl Serialize for JsonElement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(text) => RawValue::from_string(text.clone())
                .map_err(serde::ser::Error::custom)?
                .serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    sequence.serialize_element(item)?;
                }
                sequence.end()
            }
            Self::Object(properties) => {
                let mut map = serializer.serialize_map(Some(properties.len()))?;
                for (key, value) in properties {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for JsonElement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <Box<RawValue>>::deserialize(deserializer)?;
        JsonElement::parse(raw.get()).map_err(de::Error::custom)
    }
}

impl fmt::Display for JsonElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = crate::json::to_string(self).map_err(|_| fmt::Error)?;
        formatter.write_str(&text)
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    position: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        format!("{message} at byte {}", self.position)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect_literal(&mut self, literal: &str, value: JsonElement) -> Result<JsonElement, String> {
        if self.bytes[self.position..].starts_with(literal.as_bytes()) {
            self.position += literal.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<JsonElement, String> {
        match self.peek() {
            Some(b'n') => self.expect_literal("null", JsonElement::Null),
            Some(b't') => self.expect_literal("true", JsonElement::Bool(true)),
            Some(b'f') => self.expect_literal("false", JsonElement::Bool(false)),
            Some(b'"') => self.string().map(JsonElement::String),
            Some(b'[') => self.array(depth + 1),
            Some(b'{') => self.object(depth + 1),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("expected value")),
        }
    }

    fn check_depth(&self, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            Err(self.error("JSON nesting too deep"))
        } else {
            Ok(())
        }
    }

    fn array(&mut self, depth: usize) -> Result<JsonElement, String> {
        self.check_depth(depth)?;
        self.position += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(JsonElement::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(JsonElement::Array(items));
                }
                _ => return Err(self.error("expected , or ]")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonElement, String> {
        self.check_depth(depth)?;
        self.position += 1;
        let mut properties = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(JsonElement::Object(properties));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected property name"));
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.error("expected :"));
            }
            self.position += 1;
            self.skip_whitespace();
            properties.push((key, self.value(depth)?));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(JsonElement::Object(properties));
                }
                _ => return Err(self.error("expected , or }")),
            }
        }
    }

    fn number(&mut self) -> Result<JsonElement, String> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number"));
            }
            self.digits();
        }
        Ok(JsonElement::Number(
            self.text[start..self.position].to_owned(),
        ))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
    }

    fn string(&mut self) -> Result<String, String> {
        // Delegate unescaping (incl. surrogate pairs) to serde_json on the exact token.
        let start = self.position;
        self.position += 1;
        loop {
            match self.peek() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => self.position += 2,
                Some(byte) if byte < 0x20 => return Err(self.error("control character in string")),
                Some(_) => self.position += 1,
            }
        }
        self.position += 1;
        serde_json::from_str(&self.text[start..self.position]).map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn preserves_number_text_and_duplicate_keys() {
        let text = r#"{"a":1E2,"b":-0.10e+05,"a":{"x":1,"x":[2.50,true,null]},"s":"<é>"}"#;
        let value = JsonElement::parse(text).unwrap();
        assert_eq!(
            json::to_string(&value).unwrap(),
            r#"{"a":1E2,"b":-0.10e+05,"a":{"x":1,"x":[2.50,true,null]},"s":"\u003C\u00E9\u003E"}"#
        );
        assert_eq!(value.get("a"), Some(&JsonElement::Number("1E2".into())));
    }

    #[test]
    fn rejects_invalid_and_deep_documents() {
        for bad in [
            "01",
            "1.",
            "-",
            "{\"a\" 1}",
            "[1,]",
            "\"\u{1}\"",
            "nul",
            "1 2",
        ] {
            assert!(JsonElement::parse(bad).is_err(), "{bad}");
        }
        assert!(JsonElement::parse(&("[".repeat(33) + &"]".repeat(33))).is_err());
        assert!(JsonElement::parse(&("[".repeat(32) + &"]".repeat(32))).is_ok());
    }

    #[test]
    fn deserializes_through_serde() {
        let map: indexmap::IndexMap<String, JsonElement> =
            json::from_str(r#"{"k":1.0E-3}"#).unwrap();
        assert_eq!(json::to_string(&map).unwrap(), r#"{"k":1.0E-3}"#);
    }
}
