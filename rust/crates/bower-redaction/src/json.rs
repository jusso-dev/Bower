//! Mutable JSON tree mirroring `System.Text.Json.Nodes.JsonNode` as the engine uses it.
//!
//! The parser accepts exactly what `JsonNode.Parse` accepts with the engine's
//! options (no comments, no trailing commas, `MaxDepth = 32`). Two inputs parse in
//! C# but throw later, when the engine touches them:
//!
//! * duplicate property names throw when the object is first enumerated;
//! * escaped unpaired surrogates (`"\uD800"`) throw when the string or property
//!   name is read.
//!
//! Both are kept in the tree (`Object::poisoned`, `JsonString::invalid`) so the
//! engine can fail at the same points as C# — and succeed when the containing
//! property is removed before it is ever read.

use indexmap::IndexMap;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

use bower_contracts::json::MAX_DEPTH;

#[derive(Debug)]
pub enum Node {
    Null,
    Bool(bool),
    /// Original number text (written back verbatim, like `JsonElement`).
    Number(Box<RawValue>),
    String(JsonString),
    Array(Vec<Node>),
    Object(Object),
}

#[derive(Debug)]
pub struct JsonString {
    pub value: String,
    /// The source contained an unpaired surrogate escape; reading it fails in C#.
    pub invalid: bool,
}

impl Node {
    pub fn string(value: String) -> Self {
        Self::String(JsonString {
            value,
            invalid: false,
        })
    }
}

#[derive(Debug, Default)]
pub struct Object {
    pub map: IndexMap<String, Node>,
    /// Duplicate or unreadable property names: enumerating the object fails in C#.
    pub poisoned: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SyntaxError;

pub fn parse(text: &str) -> Result<Node, SyntaxError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        position: 0,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(SyntaxError);
    }

    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), SyntaxError> {
        if self.peek() == Some(byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(SyntaxError)
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), SyntaxError> {
        if self.bytes[self.position..].starts_with(word) {
            self.position += word.len();
            Ok(())
        } else {
            Err(SyntaxError)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Node, SyntaxError> {
        match self.peek().ok_or(SyntaxError)? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Node::String),
            b't' => self.literal(b"true").map(|()| Node::Bool(true)),
            b'f' => self.literal(b"false").map(|()| Node::Bool(false)),
            b'n' => self.literal(b"null").map(|()| Node::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(SyntaxError),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Node, SyntaxError> {
        if depth > MAX_DEPTH {
            return Err(SyntaxError);
        }

        self.expect(b'{')?;
        let mut object = Object::default();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(Node::Object(object));
        }

        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(SyntaxError);
            }

            let name = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(depth)?;
            if name.invalid || object.map.contains_key(&name.value) {
                object.poisoned = true;
            } else {
                object.map.insert(name.value, value);
            }

            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Node::Object(object));
                }
                _ => return Err(SyntaxError),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Node, SyntaxError> {
        if depth > MAX_DEPTH {
            return Err(SyntaxError);
        }

        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(Node::Array(items));
        }

        loop {
            self.skip_whitespace();
            items.push(self.value(depth)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Node::Array(items));
                }
                _ => return Err(SyntaxError),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        self.position - start
    }

    fn number(&mut self) -> Result<Node, SyntaxError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }

        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(SyntaxError),
        }

        if self.peek() == Some(b'.') {
            self.position += 1;
            if self.digits() == 0 {
                return Err(SyntaxError);
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if self.digits() == 0 {
                return Err(SyntaxError);
            }
        }

        // A number must be followed by a delimiter (`01`, `1x` are invalid).
        if !matches!(
            self.peek(),
            None | Some(b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}')
        ) {
            return Err(SyntaxError);
        }

        let raw = &self.text[start..self.position];
        RawValue::from_string(raw.to_owned())
            .map(Node::Number)
            .map_err(|_| SyntaxError)
    }

    fn hex4(&mut self) -> Result<u16, SyntaxError> {
        let digits = self
            .bytes
            .get(self.position..self.position + 4)
            .ok_or(SyntaxError)?;
        let mut value = 0u16;
        for &byte in digits {
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(SyntaxError),
            };
            value = value * 16 + u16::from(nibble);
        }

        self.position += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<JsonString, SyntaxError> {
        self.expect(b'"')?;
        let mut units: Vec<u16> = Vec::new();
        let mut segment_start = self.position;
        let mut has_escape = false;
        loop {
            let byte = self.peek().ok_or(SyntaxError)?;
            match byte {
                b'"' => {
                    let tail = &self.text[segment_start..self.position];
                    self.position += 1;
                    if !has_escape {
                        return Ok(JsonString {
                            value: tail.to_owned(),
                            invalid: false,
                        });
                    }

                    units.extend(tail.encode_utf16());
                    let invalid = String::from_utf16(&units).is_err();
                    return Ok(JsonString {
                        value: String::from_utf16_lossy(&units),
                        invalid,
                    });
                }
                b'\\' => {
                    has_escape = true;
                    units.extend(self.text[segment_start..self.position].encode_utf16());
                    self.position += 1;
                    let escape = self.peek().ok_or(SyntaxError)?;
                    self.position += 1;
                    let unit = match escape {
                        b'"' => u16::from(b'"'),
                        b'\\' => u16::from(b'\\'),
                        b'/' => u16::from(b'/'),
                        b'b' => 0x08,
                        b'f' => 0x0C,
                        b'n' => u16::from(b'\n'),
                        b'r' => u16::from(b'\r'),
                        b't' => u16::from(b'\t'),
                        b'u' => self.hex4()?,
                        _ => return Err(SyntaxError),
                    };
                    units.push(unit);
                    segment_start = self.position;
                }
                0x00..=0x1F => return Err(SyntaxError),
                _ => self.position += 1,
            }
        }
    }
}

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(raw) => raw.serialize(serializer),
            Self::String(text) => serializer.serialize_str(&text.value),
            Self::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    sequence.serialize_element(item)?;
                }
                sequence.end()
            }
            Self::Object(object) => {
                let mut map = serializer.serialize_map(Some(object.map.len()))?;
                for (name, value) in &object.map {
                    map.serialize_entry(name, value)?;
                }
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(text: &str) -> String {
        bower_contracts::json::to_string(&parse(text).expect("valid")).expect("serializes")
    }

    #[test]
    fn writes_numbers_verbatim_and_re_escapes_strings() {
        assert_eq!(
            round_trip(r#"{"a":1.50e+3,"b":-0,"c":"\/\u00e9<"}"#),
            r#"{"a":1.50e+3,"b":-0,"c":"/\u00E9\u003C"}"#
        );
    }

    #[test]
    fn rejects_what_utf8_json_reader_rejects() {
        for text in [
            "{\"a\":1,}",
            "{\"a\":01}",
            "{\"a\":1.}",
            "{\"a\":-}",
            "{\"a\":\"\u{1}\"}",
            "\u{FEFF}{}",
            "{'a':1}",
            "{\"a\":1} x",
        ] {
            assert_eq!(parse(text).err(), Some(SyntaxError), "{text}");
        }
    }

    #[test]
    fn tracks_duplicates_and_lone_surrogates() {
        let Node::Object(object) = parse(r#"{"a":1,"a":2}"#).unwrap() else {
            panic!()
        };
        assert!(object.poisoned);
        let Node::Object(object) = parse(r#"{"a":"\uD800","b":"\uD83D\uDE00"}"#).unwrap() else {
            panic!()
        };
        assert!(matches!(&object.map["a"], Node::String(text) if text.invalid));
        assert!(
            matches!(&object.map["b"], Node::String(text) if !text.invalid && text.value == "\u{1F600}")
        );
    }
}
