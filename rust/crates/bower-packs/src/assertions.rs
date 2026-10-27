//! Port of `PackFieldAssertions`: field-level sample assertions (`expectFields`),
//! checked against the redacted event only.
//!
//! An expectation can never name a value that redaction withheld: an expected string
//! that equals a pre-redaction value missing from the redacted event, or that contains
//! a `mustNotContain` entry, fails without the value being printed. Failure messages
//! name the path and show only post-redaction values (or the expectation, once proven
//! safe).

use std::collections::HashSet;

use bower_contracts::JsonElement;

use crate::archive::PackError;

pub const MAXIMUM_EXPECTATIONS: usize = 64;
pub const MAXIMUM_PATH_LENGTH: usize = 256;
pub const MAXIMUM_SEGMENTS: usize = 16;

#[derive(Clone, Debug, PartialEq)]
pub enum Expectation {
    Present,
    Absent,
    /// A string, finite number or boolean compared with the redacted value.
    Exact(JsonElement),
}

/// One `expectFields` entry: a dotted path and the post-redaction expectation.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldExpectation {
    pub path: String,
    pub segments: Vec<String>,
    pub expectation: Expectation,
}

fn invalid(message: String) -> PackError {
    PackError::InvalidData(message)
}

/// `^[A-Za-z0-9_$@-]{1,128}$`.
fn valid_segment(segment: &str) -> bool {
    (1..=128).contains(&segment.len())
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'@' | b'-'))
}

/// `^(?:0|[1-9][0-9]{0,8})$`.
fn array_index(segment: &str) -> Option<usize> {
    let bytes = segment.as_bytes();
    let canonical = !bytes.is_empty()
        && bytes.len() <= 9
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes[0] != b'0' || bytes.len() == 1);
    if canonical {
        segment.parse().ok()
    } else {
        None
    }
}

fn finite(number: &str) -> Option<f64> {
    number.parse::<f64>().ok().filter(|value| value.is_finite())
}

/// Parses and validates `expectFields`; `None` when the sample has none.
pub fn parse(sample: &JsonElement, name: &str) -> Result<Option<Vec<FieldExpectation>>, PackError> {
    let fields = match sample.get("expectFields") {
        None | Some(JsonElement::Null) => return Ok(None),
        Some(JsonElement::Object(fields)) => fields,
        Some(_) => {
            return Err(invalid(format!(
                "Sample '{name}' expectFields must be an object."
            )));
        }
    };
    let mut expectations = Vec::new();
    let mut paths = HashSet::new();
    for (path, value) in fields {
        let segments: Vec<String> = path.split('.').map(str::to_owned).collect();
        if path.len() > MAXIMUM_PATH_LENGTH
            || segments.len() > MAXIMUM_SEGMENTS
            || !segments.iter().all(|segment| valid_segment(segment))
        {
            return Err(invalid(format!(
                "Sample '{name}' expectFields has an invalid path."
            )));
        }
        if !paths.insert(path.as_str()) {
            return Err(invalid(format!(
                "Sample '{name}' expectFields has a duplicate path."
            )));
        }
        let expectation = match value {
            JsonElement::String(text) if text == "present" => Expectation::Present,
            JsonElement::String(text) if text == "absent" => Expectation::Absent,
            JsonElement::String(_) | JsonElement::Bool(_) => Expectation::Exact(value.clone()),
            JsonElement::Number(text) if finite(text).is_some() => {
                Expectation::Exact(value.clone())
            }
            _ => {
                return Err(invalid(format!(
                    "Sample '{name}' expectFields '{path}' must be a string, finite number or boolean."
                )));
            }
        };
        expectations.push(FieldExpectation {
            path: path.clone(),
            segments,
            expectation,
        });
    }
    if expectations.is_empty() || expectations.len() > MAXIMUM_EXPECTATIONS {
        return Err(invalid(format!(
            "Sample '{name}' expectFields must have 1 to {MAXIMUM_EXPECTATIONS} paths."
        )));
    }
    Ok(Some(expectations))
}

fn collect_strings<'a>(element: &'a JsonElement, values: &mut HashSet<&'a str>) {
    match element {
        JsonElement::String(text) => {
            values.insert(text);
        }
        JsonElement::Object(properties) => {
            for (_, value) in properties {
                collect_strings(value, values);
            }
        }
        JsonElement::Array(items) => {
            for item in items {
                collect_strings(item, values);
            }
        }
        _ => {}
    }
}

/// Follows object members and array indexes. JSON null, and a member name that occurs
/// more than once (ambiguous), are absent.
fn resolve<'a>(root: &'a JsonElement, segments: &[String]) -> Option<&'a JsonElement> {
    let mut current = root;
    for segment in segments {
        current = match current {
            JsonElement::Object(properties) => {
                let mut matches = properties.iter().filter(|(key, _)| key == segment);
                match (matches.next(), matches.next()) {
                    (Some((_, value)), None) => value,
                    _ => return None,
                }
            }
            JsonElement::Array(items) => items.get(array_index(segment)?)?,
            _ => return None,
        };
    }
    (!matches!(current, JsonElement::Null)).then_some(current)
}

fn kind_name(element: &JsonElement) -> &'static str {
    match element {
        JsonElement::String(_) => "string",
        JsonElement::Number(_) => "number",
        JsonElement::Bool(_) => "boolean",
        JsonElement::Object(_) => "object",
        JsonElement::Array(_) => "array",
        JsonElement::Null => "null",
    }
}

/// Scalars as JSON text (strings escaped like `JavaScriptEncoder.Default`); containers by kind.
fn render(element: &JsonElement) -> String {
    match element {
        JsonElement::String(text) => {
            bower_contracts::json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
        }
        JsonElement::Number(text) => text.clone(),
        JsonElement::Bool(flag) => flag.to_string(),
        other => kind_name(other).to_owned(),
    }
}

fn describe(element: &JsonElement) -> String {
    match element {
        JsonElement::Object(_) | JsonElement::Array(_) => kind_name(element).to_owned(),
        other => format!("{} {}", kind_name(other), render(other)),
    }
}

fn matches(expected: &JsonElement, actual: &JsonElement) -> bool {
    match (expected, actual) {
        (JsonElement::String(left), JsonElement::String(right)) => left == right,
        (JsonElement::Number(left), JsonElement::Number(right)) => {
            finite(right).is_some_and(|right| finite(left) == Some(right))
        }
        (JsonElement::Bool(left), JsonElement::Bool(right)) => left == right,
        _ => false,
    }
}

/// Checks expectations against the redacted event. `inputs` are the pre-redaction
/// documents (the sample's raw record or event, and the mapped envelope); they are only
/// used to recognise withheld values and are never echoed.
pub fn check(
    expectations: &[FieldExpectation],
    redacted_json: &str,
    inputs: &[&str],
    forbidden: &[&str],
) -> Result<Vec<String>, PackError> {
    let unreadable = || invalid("Sample field assertions cannot read the event.".to_owned());
    let output = JsonElement::parse(redacted_json).map_err(|_| unreadable())?;
    let mut released = HashSet::new();
    collect_strings(&output, &mut released);
    let documents = inputs
        .iter()
        .map(|input| JsonElement::parse(input).map_err(|_| unreadable()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut withheld = HashSet::new();
    for document in &documents {
        let mut values = HashSet::new();
        collect_strings(document, &mut values);
        withheld.extend(values.into_iter().filter(|value| !released.contains(value)));
    }

    let mut problems = Vec::new();
    for expectation in expectations {
        let actual = resolve(&output, &expectation.segments);
        let path = &expectation.path;
        match &expectation.expectation {
            Expectation::Present => {
                if actual.is_none() {
                    problems.push(format!(
                        "Field '{path}': expected present, but it is absent."
                    ));
                }
            }
            Expectation::Absent => {
                if let Some(value) = actual {
                    problems.push(format!(
                        "Field '{path}': expected absent, got {}.",
                        describe(value)
                    ));
                }
            }
            Expectation::Exact(expected) => {
                if let JsonElement::String(text) = expected
                    && (withheld.contains(text.as_str())
                        || forbidden.iter().any(|item| text.contains(item)))
                {
                    problems.push(format!(
                        "Field '{path}': the expected value does not survive redaction; expect only post-redaction values."
                    ));
                    continue;
                }
                match actual {
                    None => problems.push(format!(
                        "Field '{path}': expected {}, but it is absent.",
                        render(expected)
                    )),
                    Some(found) if kind_name(found) != kind_name(expected) => {
                        problems.push(format!(
                            "Field '{path}': type mismatch, expected {}, got {}.",
                            describe(expected),
                            describe(found)
                        ));
                    }
                    Some(found) if !matches(expected, found) => problems.push(format!(
                        "Field '{path}': expected {}, got {}.",
                        render(expected),
                        render(found)
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    Ok(problems)
}
