//! Output helpers reproducing the C# CLI's console formats.
//!
//! The C# commands print `JsonSerializer.Serialize(value, new JsonSerializerOptions
//! { WriteIndented = true })`: two-space indentation, `"name": value`, default
//! `JavaScriptEncoder` escaping, and `DateTimeOffset` written without the encoder
//! (so `+00:00` stays literal). [`Json`] models exactly that writer.

use std::fmt::Write as _;

use bower_contracts::time::{Timestamp, format_json};

/// A JSON tree written like `Utf8JsonWriter` with `Indented = true`.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    /// Escaped with `JavaScriptEncoder.Default`.
    Str(String),
    /// A `DateTimeOffset`; written unescaped like System.Text.Json.
    Time(Timestamp),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn object<K: Into<String>>(fields: impl IntoIterator<Item = (K, Json)>) -> Self {
        Self::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    pub fn str(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn opt_str(value: Option<impl Into<String>>) -> Self {
        value.map_or(Self::Null, |text| Self::Str(text.into()))
    }

    /// Indented text without a trailing newline.
    pub fn to_indented(&self) -> String {
        let mut text = String::new();
        self.write(&mut text, 0);
        text
    }

    fn write(&self, text: &mut String, depth: usize) {
        match self {
            Self::Null => text.push_str("null"),
            Self::Bool(flag) => text.push_str(if *flag { "true" } else { "false" }),
            Self::Int(number) => {
                let _ = write!(text, "{number}");
            }
            Self::Str(value) => text.push_str(&quote(value)),
            Self::Time(value) => {
                text.push('"');
                text.push_str(&format_json(value));
                text.push('"');
            }
            Self::Array(items) if items.is_empty() => text.push_str("[]"),
            Self::Object(fields) if fields.is_empty() => text.push_str("{}"),
            Self::Array(items) => {
                text.push('[');
                for (index, item) in items.iter().enumerate() {
                    text.push_str(if index == 0 { "\n" } else { ",\n" });
                    indent(text, depth + 1);
                    item.write(text, depth + 1);
                }
                text.push('\n');
                indent(text, depth);
                text.push(']');
            }
            Self::Object(fields) => {
                text.push('{');
                for (index, (key, item)) in fields.iter().enumerate() {
                    text.push_str(if index == 0 { "\n" } else { ",\n" });
                    indent(text, depth + 1);
                    text.push_str(&quote(key));
                    text.push_str(": ");
                    item.write(text, depth + 1);
                }
                text.push('\n');
                indent(text, depth);
                text.push('}');
            }
        }
    }
}

fn indent(text: &mut String, depth: usize) {
    for _ in 0..depth {
        text.push_str("  ");
    }
}

/// A JSON string literal with `JavaScriptEncoder.Default` escaping.
pub fn quote(value: &str) -> String {
    bower_contracts::json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// C# `{value,-width}` composite formatting: left-aligned, padded with spaces to
/// `width` UTF-16 code units, never truncated.
pub fn pad(value: &str, width: usize) -> String {
    let length = value.encode_utf16().count();
    let mut text = value.to_owned();
    for _ in length..width {
        text.push(' ');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_indented_like_system_text_json() {
        let json = Json::object([
            ("valid", Json::Bool(true)),
            ("count", Json::Int(2)),
            ("empty", Json::Array(vec![])),
            ("none", Json::Object(vec![])),
            (
                "items",
                Json::Array(vec![Json::object([("Id", Json::str("a+b<c>"))])]),
            ),
        ]);
        assert_eq!(
            json.to_indented(),
            "{\n  \"valid\": true,\n  \"count\": 2,\n  \"empty\": [],\n  \"none\": {},\n  \"items\": [\n    {\n      \"Id\": \"a\\u002Bb\\u003Cc\\u003E\"\n    }\n  ]\n}"
        );
    }

    #[test]
    fn writes_timestamps_unescaped() {
        let time = bower_contracts::time::parse("2026-05-01T10:20:30.1200000+00:00").unwrap();
        assert_eq!(
            Json::Time(time).to_indented(),
            "\"2026-05-01T10:20:30.12+00:00\""
        );
    }

    #[test]
    fn pads_like_composite_format() {
        assert_eq!(pad("PASS", 5), "PASS ");
        assert_eq!(pad("toolongvalue", 4), "toolongvalue");
    }
}
