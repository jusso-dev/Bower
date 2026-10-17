//! System.Text.Json compatible text helpers.

use std::io;

use bower_contracts::json::DotnetFormatter;
use serde::Serialize;
use serde_json::Value;
use serde_json::ser::{CharEscape, Formatter, PrettyFormatter};

/// `JsonSerializerOptions { WriteIndented = true }` output: two-space indentation,
/// `\n` line breaks (non-Windows `Environment.NewLine`) and `JavaScriptEncoder.Default`
/// escaping.
#[derive(Debug)]
pub struct DotnetPrettyFormatter<'a> {
    pretty: PrettyFormatter<'a>,
}

impl Default for DotnetPrettyFormatter<'_> {
    fn default() -> Self {
        Self {
            pretty: PrettyFormatter::with_indent(b"  "),
        }
    }
}

impl Formatter for DotnetPrettyFormatter<'_> {
    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_array(writer)
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array(writer)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array_value(writer)
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object(writer)
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object(writer)
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_object_key(writer, first)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object_value(writer)
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        DotnetFormatter.write_string_fragment(writer, fragment)
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        char_escape: CharEscape,
    ) -> io::Result<()> {
        DotnetFormatter.write_char_escape(writer, char_escape)
    }
}

/// Serializes like `JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true })`
/// (or `JsonNode.ToJsonString` with the same options).
pub fn to_indented_string<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    let mut buffer = Vec::with_capacity(4096);
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut buffer, DotnetPrettyFormatter::default());
    value.serialize(&mut serializer)?;
    // Every non-ASCII character is escaped, so the output is ASCII.
    Ok(String::from_utf8(buffer).expect("escaped JSON is ASCII"))
}

/// Compact `JsonNode.ToJsonString()` text.
pub fn to_compact_string(value: &Value) -> String {
    bower_contracts::json::to_string(value).expect("JSON values always serialize")
}

/// `JsonValueKind` name of a non-null value, as C# string interpolation prints it.
pub fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "Null",
        Value::Bool(true) => "True",
        Value::Bool(false) => "False",
        Value::Number(_) => "Number",
        Value::String(_) => "String",
        Value::Array(_) => "Array",
        Value::Object(_) => "Object",
    }
}

/// `node?.GetValue<string>()`: `None` for a missing or JSON `null` node, an error for
/// any other non-string value (C# throws `InvalidOperationException`).
pub fn optional_string<'a>(
    value: Option<&'a Value>,
    what: &str,
) -> Result<Option<&'a str>, crate::DcrError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(other) => Err(crate::DcrError::InvalidData(format!(
            "{what} must be a string, not {}.",
            kind_name(other)
        ))),
    }
}

/// `JsonValue.TryGetValue(out int)` on a parsed number: integral and within `Int32`.
pub fn try_get_int32(value: Option<&Value>) -> Option<i32> {
    match value {
        Some(Value::Number(number)) => number.as_i64().and_then(|value| i32::try_from(value).ok()),
        _ => None,
    }
}

/// UTF-16 length (`string.Length`).
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `StringComparison.OrdinalIgnoreCase` containment for ASCII needles.
pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// `double.ToString("0.##", CultureInfo.InvariantCulture)`: the value rounded to 15
/// significant digits, then to two decimals (midpoint away from zero), without
/// trailing zeros.
pub fn format_two_decimals(value: f64) -> String {
    if !value.is_finite() {
        return if value.is_nan() {
            "NaN".to_owned()
        } else if value > 0.0 {
            "Infinity".to_owned()
        } else {
            "-Infinity".to_owned()
        };
    }
    // 15 significant digits, like .NET's custom-format double precision.
    let scientific = format!("{:.14e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific notation");
    let exponent: i32 = exponent.parse().expect("exponent");
    let digits: Vec<u8> = mantissa
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|digit| digit - b'0')
        .collect();
    // digits[0] is the 10^exponent place. Keep places down to 10^-2.
    let keep = exponent + 3; // number of digits at or above 10^-2
    let mut kept: Vec<u8> = if keep <= 0 {
        Vec::new()
    } else {
        digits
            .iter()
            .copied()
            .take(usize::try_from(keep).unwrap_or(0))
            .collect()
    };
    let mut places = keep.max(0) as usize; // digits that represent places >= 10^-2
    while kept.len() < places {
        kept.push(0);
    }
    let round_digit = if keep < 0 {
        0
    } else {
        digits
            .get(usize::try_from(keep).unwrap_or(0))
            .copied()
            .unwrap_or(0)
    };
    if round_digit >= 5 {
        // Add one unit in the last kept place, propagating carries.
        let mut index = kept.len();
        loop {
            if index == 0 {
                kept.insert(0, 1);
                places += 1;
                break;
            }
            index -= 1;
            if kept[index] == 9 {
                kept[index] = 0;
            } else {
                kept[index] += 1;
                break;
            }
        }
    }
    // Split into integer and two fraction digits.
    while kept.len() < 3 {
        kept.insert(0, 0);
        places += 1;
    }
    let _ = places;
    let split = kept.len() - 2;
    let integer: String = kept[..split]
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction: String = kept[split..]
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    let fraction = fraction.trim_end_matches('0');
    let negative = value.is_sign_negative() && (integer != "0" || !fraction.is_empty());
    let mut text = String::new();
    if negative {
        text.push('-');
    }
    text.push_str(integer);
    if !fraction.is_empty() {
        text.push('.');
        text.push_str(fraction);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_dotnet_custom_format() {
        assert_eq!(format_two_decimals(25.0), "25");
        assert_eq!(format_two_decimals(25.5), "25.5");
        assert_eq!(format_two_decimals(0.125), "0.13");
        assert_eq!(format_two_decimals(5.000000000000001), "5");
        assert_eq!(format_two_decimals(99.999), "100");
        assert_eq!(format_two_decimals(0.004), "0");
        assert_eq!(format_two_decimals(-1.005), "-1.01");
        assert_eq!(format_two_decimals(1234567.891), "1234567.89");
        assert_eq!(format_two_decimals(0.0), "0");
    }

    #[test]
    fn indented_output_matches_system_text_json() {
        let value = serde_json::json!({"a": [1, {"b": "x'y"}], "c": {}, "d": []});
        assert_eq!(
            to_indented_string(&value).unwrap(),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": \"x\\u0027y\"\n    }\n  ],\n  \"c\": {},\n  \"d\": []\n}"
        );
    }
}
