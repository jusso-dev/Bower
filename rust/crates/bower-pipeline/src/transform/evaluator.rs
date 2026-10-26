//! Statement and expression execution (`TransformEvaluator.cs`). Every statement and
//! expression node costs one step; regex execution adds its VM steps.

use super::syntax::{Bound, Call, Expr, Stmt};
use super::value::{Record, Value, utf16_len};
use super::{Budget, TransformError, codes, limits, time};

pub(crate) struct Evaluator<'a> {
    pub record: &'a mut Record,
    pub evaluation_ticks: i64,
    pub budget: Budget,
}

fn type_error() -> TransformError {
    TransformError(codes::TYPE_ERROR)
}

fn size_error() -> TransformError {
    TransformError(codes::SIZE_EXCEEDED)
}

fn truthy(value: &Value) -> Result<bool, TransformError> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::Null => Ok(false),
        _ => Err(type_error()),
    }
}

fn require_string(value: &Value) -> Result<&str, TransformError> {
    match value {
        Value::Str(text) => Ok(text),
        _ => Err(type_error()),
    }
}

fn is_composite(value: &Value) -> bool {
    matches!(value, Value::Array(_) | Value::Object(_) | Value::Number(_))
}

fn map_ascii(text: &str, upper: bool) -> String {
    if upper {
        text.to_ascii_uppercase()
    } else {
        text.to_ascii_lowercase()
    }
}

fn parse_int(text: &str) -> Value {
    let digits = text
        .strip_prefix('+')
        .or_else(|| text.strip_prefix('-'))
        .unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Value::Null;
    }
    let normalized = text.strip_prefix('+').unwrap_or(text);
    normalized.parse().map_or(Value::Null, Value::Int)
}

fn compare(operator: &str, left: &Value, right: &Value) -> Result<Value, TransformError> {
    if is_composite(left) || is_composite(right) {
        return Err(type_error());
    }
    if matches!(operator, "==" | "!=") {
        let equal = match (left, right) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(left), Value::Bool(right)) => left == right,
            (Value::Int(left), Value::Int(right)) => left == right,
            (Value::Str(left), Value::Str(right)) => left == right,
            _ => false,
        };
        return Ok(Value::Bool(if operator == "==" { equal } else { !equal }));
    }
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return Ok(Value::Bool(false));
    }
    let (Value::Int(left), Value::Int(right)) = (left, right) else {
        return Err(type_error());
    };
    Ok(Value::Bool(match operator {
        "<" => left < right,
        "<=" => left <= right,
        ">" => left > right,
        _ => left >= right,
    }))
}

impl Evaluator<'_> {
    pub fn execute(&mut self, statement: &Stmt) -> Result<(), TransformError> {
        self.budget.step()?;
        match statement {
            Stmt::Assign { target, value, .. } => {
                let value = self.evaluate(value)?;
                self.set(target, value)?;
            }
            Stmt::Delete { target, .. } => self.remove(target),
            Stmt::Rename { from, to, .. } => {
                if let Some(index) = self.index_of(from) {
                    let (_, value) = self.record.remove(index);
                    self.set(to, value)?;
                }
            }
            Stmt::If {
                condition,
                then,
                otherwise,
                ..
            } => {
                let branch = if truthy(&self.evaluate(condition)?)? {
                    Some(then)
                } else {
                    otherwise.as_ref()
                };
                for item in branch.into_iter().flatten() {
                    self.execute(item)?;
                }
            }
        }
        Ok(())
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.record.iter().position(|(key, _)| key == name)
    }

    fn set(&mut self, name: &str, value: Value) -> Result<(), TransformError> {
        if let Some(index) = self.index_of(name) {
            self.record[index].1 = value;
            return Ok(());
        }
        if self.record.len() >= limits::MAXIMUM_RECORD_FIELDS {
            return Err(size_error());
        }
        self.record.push((name.to_owned(), value));
        Ok(())
    }

    fn remove(&mut self, name: &str) {
        if let Some(index) = self.index_of(name) {
            self.record.remove(index);
        }
    }

    fn read(&self, segments: &[String]) -> Value {
        let mut fields: &[(String, Value)] = self.record;
        let mut current = &Value::Null;
        for segment in segments {
            current = fields
                .iter()
                .find(|(key, _)| key == segment)
                .map_or(&Value::Null, |(_, value)| value);
            fields = match current {
                Value::Object(inner) => inner,
                _ => &[],
            };
        }
        current.clone()
    }

    fn evaluate(&mut self, expression: &Expr) -> Result<Value, TransformError> {
        self.budget.step()?;
        match expression {
            Expr::Literal(_, value) => Ok(value.clone()),
            Expr::Path(_, segments) => Ok(self.read(segments)),
            Expr::Not(_, operand) => Ok(Value::Bool(!truthy(&self.evaluate(operand)?)?)),
            Expr::Binary(_, "&&", left, right) => Ok(Value::Bool(
                truthy(&self.evaluate(left)?)? && truthy(&self.evaluate(right)?)?,
            )),
            Expr::Binary(_, "||", left, right) => Ok(Value::Bool(
                truthy(&self.evaluate(left)?)? || truthy(&self.evaluate(right)?)?,
            )),
            Expr::Binary(_, operator, left, right) => {
                let left = self.evaluate(left)?;
                let right = self.evaluate(right)?;
                compare(operator, &left, &right)
            }
            Expr::Call(_, call) => self.call(call),
        }
    }

    fn call(&mut self, call: &Call) -> Result<Value, TransformError> {
        if call.name == "coalesce" {
            for argument in &call.arguments {
                let value = self.evaluate(argument)?;
                if !matches!(value, Value::Null) {
                    return Ok(value);
                }
            }
            return Ok(Value::Null);
        }
        let values = call
            .arguments
            .iter()
            .map(|argument| self.evaluate(argument))
            .collect::<Result<Vec<_>, _>>()?;
        let first = values.first().cloned().unwrap_or(Value::Null);
        match call.name.as_str() {
            "now" => return Ok(Value::Str(time::format(self.evaluation_ticks))),
            "concat" => {
                if values
                    .iter()
                    .any(|value| !matches!(value, Value::Str(_) | Value::Null))
                {
                    return Err(type_error());
                }
                let mut text = String::new();
                for value in &values {
                    match value {
                        Value::Str(part) => text.push_str(part),
                        _ => return Ok(Value::Null),
                    }
                }
                return if utf16_len(&text) > limits::MAXIMUM_STRING_LENGTH {
                    Err(size_error())
                } else {
                    Ok(Value::Str(text))
                };
            }
            "to_string" => {
                return match first {
                    Value::Null | Value::Str(_) => Ok(first),
                    Value::Int(value) => Ok(Value::Str(value.to_string())),
                    Value::Bool(value) => Ok(Value::Str(value.to_string())),
                    Value::Number(raw) => Ok(Value::Str(raw)),
                    _ => Err(type_error()),
                };
            }
            "to_int" => {
                return match first {
                    Value::Null | Value::Int(_) => Ok(first),
                    Value::Str(text) => Ok(parse_int(&text)),
                    Value::Number(_) => Ok(Value::Null),
                    _ => Err(type_error()),
                };
            }
            "to_bool" => {
                return match first {
                    Value::Null | Value::Bool(_) => Ok(first),
                    Value::Str(text) => Ok(match map_ascii(&text, false).as_str() {
                        "true" => Value::Bool(true),
                        "false" => Value::Bool(false),
                        _ => Value::Null,
                    }),
                    _ => Err(type_error()),
                };
            }
            "at" => {
                let Value::Int(index) = values[1] else {
                    return Err(type_error());
                };
                return match first {
                    Value::Null => Ok(Value::Null),
                    Value::Array(items) => {
                        let length = items.len() as i64;
                        let position = if index < 0 { length + index } else { index };
                        Ok(if (0..length).contains(&position) {
                            items[position as usize].clone()
                        } else {
                            Value::Null
                        })
                    }
                    _ => Err(type_error()),
                };
            }
            "join" => {
                let separator = require_string(&values[1])?;
                return match &first {
                    Value::Null => Ok(Value::Null),
                    Value::Array(items) => {
                        let parts = items
                            .iter()
                            .map(require_string)
                            .collect::<Result<Vec<_>, _>>()?;
                        let total = parts.iter().map(|part| utf16_len(part)).sum::<usize>()
                            + utf16_len(separator) * parts.len().saturating_sub(1);
                        if total > limits::MAXIMUM_STRING_LENGTH {
                            Err(size_error())
                        } else {
                            Ok(Value::Str(parts.join(separator)))
                        }
                    }
                    _ => Err(type_error()),
                };
            }
            "lookup" => {
                let Bound::Table(table) = &call.bound else {
                    return Err(type_error());
                };
                return match &values[1] {
                    Value::Null => Ok(Value::Null),
                    key => Ok(table
                        .get(require_string(key)?)
                        .map_or(Value::Null, |found| Value::Str(found.clone()))),
                };
            }
            "parse_timestamp" => {
                let Bound::Format(format) = call.bound else {
                    return Err(type_error());
                };
                let unix = format.starts_with("unix_");
                return match first {
                    Value::Null => Ok(Value::Null),
                    Value::Str(_) => Ok(self.timestamp(format, &first)),
                    Value::Int(_) if unix => Ok(self.timestamp(format, &first)),
                    _ => Err(type_error()),
                };
            }
            _ => {}
        }

        // The remaining functions take a string subject first; null in gives null out.
        let mut extra = Vec::new();
        for value in &values[1..] {
            extra.push(match value {
                Value::Int(_) if call.name == "split" => None,
                _ => Some(require_string(value)?),
            });
        }
        let subject = match &first {
            Value::Null => return Ok(Value::Null),
            value => require_string(value)?,
        };
        let argument = |index: usize| extra[index].unwrap_or_default();
        Ok(match call.name.as_str() {
            "lower" => Value::Str(map_ascii(subject, false)),
            "upper" => Value::Str(map_ascii(subject, true)),
            "trim" => Value::Str(
                subject
                    .trim_matches(|character| {
                        matches!(character, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
                    })
                    .to_owned(),
            ),
            "contains" => Value::Bool(subject.contains(argument(0))),
            "starts_with" => Value::Bool(subject.starts_with(argument(0))),
            "ends_with" => Value::Bool(subject.ends_with(argument(0))),
            "replace" => {
                let (from, to) = (argument(0), argument(1));
                if from.is_empty() {
                    return Err(type_error());
                }
                let count = subject.matches(from).count() as i64;
                let length = utf16_len(subject) as i64
                    + count * (utf16_len(to) as i64 - utf16_len(from) as i64);
                if length > limits::MAXIMUM_STRING_LENGTH as i64 {
                    return Err(size_error());
                }
                Value::Str(subject.replace(from, to))
            }
            "split" => {
                let separator = argument(0);
                if separator.is_empty() {
                    return Err(type_error());
                }
                let limit = match values.get(2) {
                    Some(Value::Int(limit)) => *limit as usize,
                    _ => limits::MAXIMUM_ARRAY_LENGTH + 1,
                };
                let parts: Vec<Value> = subject
                    .splitn(limit, separator)
                    .map(|part| Value::Str(part.to_owned()))
                    .collect();
                if parts.len() > limits::MAXIMUM_ARRAY_LENGTH {
                    return Err(size_error());
                }
                Value::Array(parts)
            }
            "regex_match" => {
                let Bound::Regex(regex) = &call.bound else {
                    return Err(type_error());
                };
                let text: Vec<char> = subject.chars().collect();
                Value::Bool(regex.is_match(&text, &mut self.budget)?)
            }
            _ => {
                let Bound::Regex(regex) = &call.bound else {
                    return Err(type_error());
                };
                let text: Vec<char> = subject.chars().collect();
                let Some(slots) = regex.search(&text, &mut self.budget)? else {
                    return Ok(Value::Null);
                };
                let mut groups = Vec::with_capacity(regex.group_names.len());
                for (group, name) in regex.group_names.iter().enumerate() {
                    let start = slots[2 * (group + 1)];
                    let end = slots[2 * (group + 1) + 1];
                    let value = if start >= 0 && end >= start {
                        let captured: String = text[start as usize..end as usize].iter().collect();
                        if utf16_len(&captured) > limits::MAXIMUM_STRING_LENGTH {
                            return Err(size_error());
                        }
                        Value::Str(captured)
                    } else {
                        Value::Null
                    };
                    groups.push((name.clone(), value));
                }
                Value::Object(groups)
            }
        })
    }

    fn timestamp(&self, format: &str, value: &Value) -> Value {
        time::parse(format, value, self.evaluation_ticks)
            .map_or(Value::Null, |ticks| Value::Str(time::format(ticks)))
    }
}
