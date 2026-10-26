//! Validation and binding (`TransformCompiler.cs`): syntax, functions, literals, targets,
//! tables and sensitivity flow.

use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;

use super::regex::TransformRegex;
use super::syntax::{Bound, Call, Expr, Parser, Stmt, SyntaxError, fail};
use super::value::{Value, utf16_len};
use super::{TransformDefinition, TransformIssue, codes, limits, time};
use crate::custom_log::{is_prohibited, is_valid_field_name};

/// Allow-listed functions and their arity. Nothing else can be called.
pub const FUNCTIONS: [(&str, usize, usize); 20] = [
    ("lower", 1, 1),
    ("upper", 1, 1),
    ("trim", 1, 1),
    ("replace", 3, 3),
    ("split", 2, 3),
    ("join", 2, 2),
    ("at", 2, 2),
    ("concat", 2, 8),
    ("contains", 2, 2),
    ("starts_with", 2, 2),
    ("ends_with", 2, 2),
    ("coalesce", 2, 8),
    ("lookup", 2, 2),
    ("regex_match", 2, 2),
    ("regex_extract", 2, 2),
    ("parse_timestamp", 2, 2),
    ("to_string", 1, 1),
    ("to_int", 1, 1),
    ("to_bool", 1, 1),
    ("now", 0, 0),
];

type Tables = IndexMap<String, IndexMap<String, String>>;

pub(crate) fn compile(definition: &TransformDefinition<'_>) -> (Vec<TransformIssue>, Vec<Stmt>) {
    let mut compiled = Vec::new();
    let mut issues = Vec::new();
    let statements = match definition.statements {
        Some(statements) if (1..=limits::MAXIMUM_STATEMENTS).contains(&statements.len()) => {
            statements
        }
        _ => {
            issues.push(TransformIssue::program(codes::LIMIT_EXCEEDED));
            return (issues, compiled);
        }
    };
    if definition
        .tables
        .is_some_and(|tables| !valid_tables(tables))
    {
        issues.push(TransformIssue::program(codes::INVALID_TABLE));
    }
    let mut declared: HashMap<&str, bool> = HashMap::new();
    for field in definition.fields {
        let sensitive = declared
            .get(field.source_name.as_str())
            .copied()
            .unwrap_or(false);
        declared.insert(field.source_name.as_str(), sensitive || field.sensitive);
    }
    let shared_tables: HashMap<&str, Arc<IndexMap<String, String>>> = definition
        .tables
        .map(|tables| {
            tables
                .iter()
                .map(|(name, table)| (name.as_str(), Arc::new(table.clone())))
                .collect()
        })
        .unwrap_or_default();
    let mut binder = Binder {
        tables: definition.tables.map(|_| &shared_tables),
        regexes: 0,
    };
    let mut taint: HashMap<String, bool> = HashMap::new();
    for (index, text) in statements.iter().enumerate() {
        let number = index + 1;
        let Some(text) = text.as_deref().filter(|text| !text.trim().is_empty()) else {
            issues.push(TransformIssue::at(number, 1, codes::SYNTAX));
            continue;
        };
        if utf16_len(text) > limits::MAXIMUM_STATEMENT_LENGTH {
            issues.push(TransformIssue::at(number, 1, codes::LIMIT_EXCEEDED));
            continue;
        }
        let result = Parser::parse(text).and_then(|mut statement| {
            binder.statement(&mut statement)?;
            let mut next = taint.clone();
            FlowChecker {
                declared: &declared,
                state: &mut next,
            }
            .statement(&statement, false)?;
            Ok((statement, next))
        });
        match result {
            Ok((statement, next)) => {
                taint = next;
                compiled.push(statement);
            }
            Err(error) => issues.push(TransformIssue::at(number, error.position + 1, error.code)),
        }
    }
    (issues, compiled)
}

fn valid_tables(tables: &Tables) -> bool {
    if tables.len() > limits::MAXIMUM_TABLES {
        return false;
    }
    let mut total = 0;
    for (name, entries) in tables {
        if !is_table_name(name) || entries.len() > limits::MAXIMUM_TABLE_ENTRIES {
            return false;
        }
        total += entries.len();
        if entries.iter().any(|(key, value)| {
            !(1..=limits::MAXIMUM_TABLE_KEY_LENGTH).contains(&utf16_len(key))
                || utf16_len(value) > limits::MAXIMUM_TABLE_VALUE_LENGTH
        }) {
            return false;
        }
    }
    total <= limits::MAXIMUM_TOTAL_TABLE_ENTRIES
}

fn is_table_name(name: &str) -> bool {
    (1..=limits::MAXIMUM_TABLE_NAME_LENGTH).contains(&name.len())
        && name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Write targets: a valid parser field name that is not credential-like and not reserved
/// for Bower or the security decision.
pub fn is_writable(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_valid_field_name(name)
        && !is_prohibited(name)
        && lower != "security"
        && !lower.starts_with("security.")
        && !lower.starts_with("bower")
}

struct Binder<'a> {
    tables: Option<&'a HashMap<&'a str, Arc<IndexMap<String, String>>>>,
    regexes: usize,
}

fn target(name: &str, position: usize) -> Result<(), SyntaxError> {
    if is_writable(name) {
        Ok(())
    } else {
        fail(position, codes::INVALID_TARGET)
    }
}

fn reject_empty_literal(argument: &Expr) -> Result<(), SyntaxError> {
    match argument {
        Expr::Literal(position, Value::Str(text)) if text.is_empty() => {
            fail(*position, codes::INVALID_ARGUMENT)
        }
        _ => Ok(()),
    }
}

fn string_literal(argument: &Expr) -> Result<&str, SyntaxError> {
    match argument {
        Expr::Literal(_, Value::Str(text)) => Ok(text),
        other => fail(other.position(), codes::INVALID_ARGUMENT),
    }
}

impl Binder<'_> {
    fn statement(&mut self, statement: &mut Stmt) -> Result<(), SyntaxError> {
        match statement {
            Stmt::Assign {
                position,
                target: name,
                value,
            } => {
                target(name, *position)?;
                self.expression(value)
            }
            Stmt::Delete {
                position,
                target: name,
            } => target(name, *position),
            Stmt::Rename {
                position,
                from,
                to,
                to_position,
            } => {
                target(from, *position)?;
                target(to, *to_position)?;
                if from == to {
                    return fail(*to_position, codes::INVALID_TARGET);
                }
                Ok(())
            }
            Stmt::If {
                condition,
                then,
                otherwise,
                ..
            } => {
                self.expression(condition)?;
                for item in then {
                    self.statement(item)?;
                }
                for item in otherwise.iter_mut().flatten() {
                    self.statement(item)?;
                }
                Ok(())
            }
        }
    }

    fn expression(&mut self, expression: &mut Expr) -> Result<(), SyntaxError> {
        match expression {
            Expr::Path(position, segments) => {
                if segments.iter().any(|segment| is_prohibited(segment)) {
                    return fail(*position, codes::PROHIBITED_FIELD);
                }
                Ok(())
            }
            Expr::Not(_, operand) => self.expression(operand),
            Expr::Binary(_, _, left, right) => {
                self.expression(left)?;
                self.expression(right)
            }
            Expr::Call(position, call) => {
                self.call(*position, call)?;
                for argument in &mut call.arguments {
                    self.expression(argument)?;
                }
                Ok(())
            }
            Expr::Literal(..) => Ok(()),
        }
    }

    fn call(&mut self, position: usize, call: &mut Call) -> Result<(), SyntaxError> {
        let Some((_, minimum, maximum)) = FUNCTIONS.iter().find(|(name, ..)| *name == call.name)
        else {
            return fail(position, codes::UNKNOWN_FUNCTION);
        };
        if call.arguments.len() < *minimum || call.arguments.len() > *maximum {
            return fail(position, codes::ARITY);
        }
        match call.name.as_str() {
            "replace" => reject_empty_literal(&call.arguments[1])?,
            "split" => {
                reject_empty_literal(&call.arguments[1])?;
                if let Some(limit) = call.arguments.get(2) {
                    let valid = matches!(limit, Expr::Literal(_, Value::Int(value))
                        if (1..=limits::MAXIMUM_ARRAY_LENGTH as i64).contains(value));
                    if !valid {
                        return fail(limit.position(), codes::INVALID_ARGUMENT);
                    }
                }
            }
            "lookup" => {
                let name = string_literal(&call.arguments[0])?;
                let Some(table) = self.tables.and_then(|tables| tables.get(name)) else {
                    return fail(call.arguments[0].position(), codes::UNKNOWN_TABLE);
                };
                call.bound = Bound::Table(Arc::clone(table));
            }
            "regex_match" | "regex_extract" => {
                let pattern = string_literal(&call.arguments[1])?;
                self.regexes += 1;
                if self.regexes > limits::MAXIMUM_REGEXES {
                    return fail(position, codes::LIMIT_EXCEEDED);
                }
                let regex = TransformRegex::compile(pattern)
                    .filter(|regex| call.name == "regex_match" || !regex.group_names.is_empty());
                let Some(regex) = regex else {
                    return fail(call.arguments[1].position(), codes::INVALID_REGEX);
                };
                call.bound = Bound::Regex(Arc::new(regex));
            }
            "parse_timestamp" => {
                let format = string_literal(&call.arguments[1])?;
                let Some(format) = time::FORMATS.iter().find(|known| **known == format) else {
                    return fail(call.arguments[1].position(), codes::INVALID_ARGUMENT);
                };
                call.bound = Bound::Format(format);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Static sensitivity flow; see `TransformCompiler.FlowChecker` in C#.
struct FlowChecker<'a> {
    declared: &'a HashMap<&'a str, bool>,
    state: &'a mut HashMap<String, bool>,
}

impl FlowChecker<'_> {
    fn statement(&mut self, statement: &Stmt, context: bool) -> Result<(), SyntaxError> {
        match statement {
            Stmt::Assign {
                position,
                target,
                value,
            } => {
                let tainted = self.tainted(value) || context;
                self.write(target, tainted, *position)
            }
            Stmt::Delete { position, target } => self.delete(target, context, *position),
            Stmt::Rename {
                position,
                from,
                to,
                to_position,
            } => {
                if self.declared.get(from.as_str()) == Some(&true) {
                    return fail(*position, codes::SENSITIVE_FIELD);
                }
                let tainted = self.is_tainted(from) || context;
                self.write(to, tainted, *to_position)?;
                self.delete(from, context, *position)
            }
            Stmt::If {
                condition,
                then,
                otherwise,
                ..
            } => {
                let inner = context || self.tainted(condition);
                let before = self.state.clone();
                for item in then {
                    self.statement(item, inner)?;
                }
                let after_then = std::mem::replace(self.state, before);
                for item in otherwise.iter().flatten() {
                    self.statement(item, inner)?;
                }
                for (key, value) in after_then {
                    let merged = value || self.is_tainted(&key);
                    self.state.insert(key, merged);
                }
                Ok(())
            }
        }
    }

    fn is_tainted(&self, name: &str) -> bool {
        match self.state.get(name) {
            Some(tainted) => *tainted,
            None => self.declared.get(name).copied().unwrap_or(true),
        }
    }

    fn tainted(&self, expression: &Expr) -> bool {
        match expression {
            Expr::Path(_, segments) => self.is_tainted(&segments[0]),
            Expr::Not(_, operand) => self.tainted(operand),
            Expr::Binary(_, _, left, right) => self.tainted(left) | self.tainted(right),
            Expr::Call(_, call) => call
                .arguments
                .iter()
                .fold(false, |tainted, argument| tainted | self.tainted(argument)),
            Expr::Literal(..) => false,
        }
    }

    fn write(&mut self, target: &str, tainted: bool, position: usize) -> Result<(), SyntaxError> {
        if let Some(sensitive) = self.declared.get(target).copied() {
            if !sensitive && tainted {
                return fail(position, codes::SENSITIVE_FLOW);
            }
            self.state.insert(target.to_owned(), sensitive);
            return Ok(());
        }
        self.state.insert(target.to_owned(), tainted);
        Ok(())
    }

    fn delete(&mut self, target: &str, context: bool, position: usize) -> Result<(), SyntaxError> {
        if let Some(sensitive) = self.declared.get(target).copied() {
            if sensitive {
                return fail(position, codes::SENSITIVE_FIELD);
            }
            if context {
                return fail(position, codes::SENSITIVE_FLOW);
            }
            self.state.insert(target.to_owned(), false);
            return Ok(());
        }
        self.state.insert(target.to_owned(), context);
        Ok(())
    }
}
