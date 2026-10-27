//! Transform values, record import and canonical JSON (`TransformValue.cs`).

use bower_contracts::JsonElement;

use super::{TransformError, codes, limits};

/// One immutable transform value. Integers are signed 64-bit; any other JSON number is an
/// opaque `Number` that keeps its source text. Objects keep key order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Number(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

pub(crate) type Record = Vec<(String, Value)>;

/// UTF-16 length, the unit every Bower length limit uses.
pub(crate) fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `-?(0|[1-9][0-9]*)`: JSON integer text with no fraction or exponent.
fn is_integer_text(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && !(digits.starts_with('0') && digits.len() > 1)
}

fn from_number_text(text: &str) -> Value {
    match text.parse::<i64>() {
        Ok(value) if is_integer_text(text) => Value::Int(value),
        _ => Value::Number(text.to_owned()),
    }
}

fn invalid() -> TransformError {
    TransformError(codes::INPUT_INVALID)
}

/// Converts a parsed record. Duplicate keys and nesting deeper than
/// `MAXIMUM_INPUT_DEPTH` fail with `transform-input-invalid`. (Lone surrogates cannot
/// reach here: the JSON reader rejects them, as the C# runtime does after reading.)
pub(crate) fn record_from(root: &JsonElement) -> Result<Record, TransformError> {
    let JsonElement::Object(_) = root else {
        return Err(invalid());
    };
    let Value::Object(fields) = from(root, 1)? else {
        return Err(invalid());
    };
    if fields.len() > limits::MAXIMUM_RECORD_FIELDS {
        return Err(invalid());
    }
    Ok(fields)
}

fn from(element: &JsonElement, depth: usize) -> Result<Value, TransformError> {
    Ok(match element {
        JsonElement::Object(properties) => {
            if depth > limits::MAXIMUM_INPUT_DEPTH {
                return Err(invalid());
            }
            let mut fields: Record = Vec::with_capacity(properties.len());
            let mut names = std::collections::HashSet::with_capacity(properties.len());
            for (name, value) in properties {
                if !names.insert(name.as_str()) {
                    return Err(invalid());
                }
                fields.push((name.clone(), from(value, depth + 1)?));
            }
            Value::Object(fields)
        }
        JsonElement::Array(items) => {
            if depth > limits::MAXIMUM_INPUT_DEPTH {
                return Err(invalid());
            }
            Value::Array(
                items
                    .iter()
                    .map(|item| from(item, depth + 1))
                    .collect::<Result<_, _>>()?,
            )
        }
        JsonElement::String(text) => Value::Str(text.clone()),
        JsonElement::Number(text) => from_number_text(text),
        JsonElement::Bool(value) => Value::Bool(*value),
        JsonElement::Null => Value::Null,
    })
}

/// Canonical output: no whitespace, keys in record order, integers in decimal, opaque
/// numbers as their source text, and only `"`, `\` and control characters escaped.
pub(crate) fn serialize(record: &[(String, Value)]) -> String {
    let mut text = String::new();
    write_object(&mut text, record);
    text
}

fn write(text: &mut String, value: &Value) {
    match value {
        Value::Null => text.push_str("null"),
        Value::Bool(value) => text.push_str(if *value { "true" } else { "false" }),
        Value::Int(value) => text.push_str(&value.to_string()),
        Value::Number(raw) => text.push_str(raw),
        Value::Str(value) => write_string(text, value),
        Value::Array(items) => {
            text.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    text.push(',');
                }
                write(text, item);
            }
            text.push(']');
        }
        Value::Object(fields) => write_object(text, fields),
    }
}

fn write_object(text: &mut String, fields: &[(String, Value)]) {
    text.push('{');
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            text.push(',');
        }
        write_string(text, key);
        text.push(':');
        write(text, value);
    }
    text.push('}');
}

fn write_string(text: &mut String, value: &str) {
    text.push('"');
    for character in value.chars() {
        match character {
            '"' => text.push_str("\\\""),
            '\\' => text.push_str("\\\\"),
            '\u{8}' => text.push_str("\\b"),
            '\u{c}' => text.push_str("\\f"),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            '\t' => text.push_str("\\t"),
            control if control < ' ' => {
                text.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => text.push(other),
        }
    }
    text.push('"');
}
