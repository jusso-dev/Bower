//! Deterministic JSON for signing (`Bower.Integrity.CanonicalJson`).
//!
//! Object keys are sorted ordinally by UTF-16 code units (C# `StringComparer.Ordinal`),
//! there is no insignificant whitespace, strings use `JavaScriptEncoder.Default`
//! escaping and numbers keep their source text, exactly as `Utf8JsonWriter` writes a
//! parsed `JsonNode`. Any change breaks every signed artefact.

use std::cmp::Ordering;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;

/// Canonical UTF-8 bytes of `node`. Numbers are written as `serde_json` holds
/// them, which normalises exponent spelling; see [`bytes_from_str`].
pub fn bytes(node: &Value) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    write(&mut output, node);
    output
}

/// Canonical text of `node`. Always ASCII.
pub fn text(node: &Value) -> String {
    String::from_utf8(bytes(node)).expect("canonical JSON is ASCII")
}

/// Ordinal comparison of the UTF-16 encodings (C# `string.CompareOrdinal`).
pub fn compare_ordinal(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn write_string(output: &mut Vec<u8>, value: &str) {
    let escaped = bower_contracts::json::to_vec(value).expect("strings always serialize");
    output.extend_from_slice(&escaped);
}

fn write(output: &mut Vec<u8>, node: &Value) {
    match node {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        // `arbitrary_precision` keeps digits but normalises exponents (`1E2` ->
        // `1e+2`); `bytes_from_str` keeps the exact source text.
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(text) => write_string(output, text),
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write(output, item);
            }
            output.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // Stable sort, like LINQ OrderBy.
            entries.sort_by(|left, right| compare_ordinal(left.0, right.0));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_string(output, key);
                output.push(b':');
                write(output, value);
            }
            output.push(b'}');
        }
    }
}

/// Canonical bytes of JSON `text`, keeping every number's source text exactly as
/// `JsonNode.Parse` + `CanonicalJson.Bytes` do. Prefer this over [`bytes`] when
/// the input is text: `serde_json` (`arbitrary_precision`) normalises exponents
/// (`1E2` becomes `1e+2`), C# does not. Duplicate property names are an error, as
/// C# `JsonObject` throws on them.
pub fn bytes_from_str(text: &str) -> Result<Vec<u8>, serde_json::Error> {
    let mut output = Vec::with_capacity(text.len());
    write_raw(&mut output, text, true)?;
    Ok(output)
}

/// `JsonNode.Parse(text)` written back by `Utf8JsonWriter` (as the Azure SDK's
/// serializer writes a `JsonObject`): no whitespace, `JavaScriptEncoder.Default`
/// string escaping, number text and property order (including duplicate names)
/// kept as in the source.
pub fn compact_from_str(text: &str) -> Result<Vec<u8>, serde_json::Error> {
    let mut output = Vec::with_capacity(text.len());
    write_raw(&mut output, text, false)?;
    Ok(output)
}

/// Object members in source order, duplicates included.
struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MembersVisitor;
        impl<'de> Visitor<'de> for MembersVisitor {
            type Value = Members;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut members = Vec::new();
                while let Some(entry) = map.next_entry::<String, Box<RawValue>>()? {
                    members.push(entry);
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(MembersVisitor)
    }
}

fn write_raw(output: &mut Vec<u8>, raw: &str, sort: bool) -> Result<(), serde_json::Error> {
    let raw = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    match raw.as_bytes().first() {
        Some(b'{') => {
            let Members(mut members) = serde_json::from_str(raw)?;
            if sort {
                members.sort_by(|left, right| compare_ordinal(&left.0, &right.0));
                if members.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                    return Err(serde::de::Error::custom("duplicate property name"));
                }
            }
            output.push(b'{');
            for (index, (key, value)) in members.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_string(output, key);
                output.push(b':');
                write_raw(output, value.get(), sort)?;
            }
            output.push(b'}');
        }
        Some(b'[') => {
            let items: Vec<Box<RawValue>> = serde_json::from_str(raw)?;
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_raw(output, item.get(), sort)?;
            }
            output.push(b']');
        }
        Some(b'"') => write_string(output, &serde_json::from_str::<String>(raw)?),
        _ => {
            // Literals and numbers: validated, then copied verbatim (source text).
            serde_json::from_str::<serde::de::IgnoredAny>(raw)?;
            output.extend_from_slice(raw.as_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_independent_of_property_order() {
        let a: Value =
            serde_json::from_str(r#"{"b":1,"a":{"d":[1,{"z":2,"y":1}],"c":"x"}}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{ "a": { "c": "x", "d": [1, {"y": 1, "z": 2}] }, "b": 1 }"#)
                .unwrap();
        assert_eq!(text(&a), text(&b));
        assert_eq!(text(&a), r#"{"a":{"c":"x","d":[1,{"y":1,"z":2}]},"b":1}"#);
    }

    #[test]
    fn sorts_by_utf16_code_units_not_utf8_bytes() {
        // U+1F600 encodes as D83D DE00 in UTF-16 (sorts before U+E000) but F0.. in
        // UTF-8 (sorts after EE..).
        let node: Value = serde_json::from_str("{\"\u{E000}\":1,\"\u{1F600}\":2}").unwrap();
        assert_eq!(text(&node), "{\"\\uD83D\\uDE00\":2,\"\\uE000\":1}");
    }
}
