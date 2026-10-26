//! Port of `Bower.Pipeline.Transforms`: the safe, deterministic transform language that a
//! signed pack parser can run on a parsed record before semantic mapping, redaction and
//! policy. Total (no loops or recursion), side-effect free and bounded; it reads no clock,
//! randomness, environment, file or network (the evaluation time is an explicit input).
//! Validation issues, canonical output bytes, step counts and error codes match C# exactly;
//! `tests/fixtures/transform-vectors.json` pins them for both runtimes.

mod compiler;
mod evaluator;
mod regex;
mod syntax;
mod time;
mod value;

use std::fmt;

use bower_contracts::JsonElement;
use bower_contracts::time::Timestamp;
use indexmap::IndexMap;

use crate::custom_log::CustomLogField;

pub use compiler::{FUNCTIONS, is_writable};

/// Static and runtime bounds (`TransformLimits`).
pub mod limits {
    pub const MAXIMUM_STATEMENTS: usize = 64;
    pub const MAXIMUM_STATEMENT_LENGTH: usize = 1024;
    pub const MAXIMUM_NODES_PER_STATEMENT: usize = 256;
    pub const MAXIMUM_EXPRESSION_DEPTH: usize = 16;
    pub const MAXIMUM_BLOCK_DEPTH: usize = 4;
    pub const MAXIMUM_ARGUMENTS: usize = 8;
    pub const MAXIMUM_REGEXES: usize = 16;
    pub const MAXIMUM_REGEX_PATTERN_LENGTH: usize = 512;
    pub const MAXIMUM_REGEX_INSTRUCTIONS: usize = 2048;
    pub const MAXIMUM_REGEX_REPEAT: usize = 100;
    pub const MAXIMUM_REGEX_GROUPS: usize = 32;
    pub const MAXIMUM_TABLES: usize = 16;
    pub const MAXIMUM_TABLE_ENTRIES: usize = 1024;
    pub const MAXIMUM_TOTAL_TABLE_ENTRIES: usize = 4096;
    pub const MAXIMUM_TABLE_KEY_LENGTH: usize = 256;
    pub const MAXIMUM_TABLE_VALUE_LENGTH: usize = 1024;
    pub const MAXIMUM_TABLE_NAME_LENGTH: usize = 64;
    pub const STEP_BUDGET: u64 = 1_000_000;
    pub const MAXIMUM_STRING_LENGTH: usize = 32_768;
    pub const MAXIMUM_ARRAY_LENGTH: usize = 256;
    pub const MAXIMUM_RECORD_FIELDS: usize = 128;
    pub const MAXIMUM_OUTPUT_LENGTH: usize = 65_536;
    pub const MAXIMUM_INPUT_DEPTH: usize = 16;
}

/// Stable, metadata-only failure codes (`TransformErrorCodes`).
pub mod codes {
    pub const SYNTAX: &str = "transform-syntax";
    pub const LIMIT_EXCEEDED: &str = "transform-limit-exceeded";
    pub const UNKNOWN_FUNCTION: &str = "transform-unknown-function";
    pub const ARITY: &str = "transform-arity";
    pub const INVALID_ARGUMENT: &str = "transform-invalid-argument";
    pub const INVALID_REGEX: &str = "transform-invalid-regex";
    pub const UNKNOWN_TABLE: &str = "transform-unknown-table";
    pub const INVALID_TABLE: &str = "transform-invalid-table";
    pub const INVALID_TARGET: &str = "transform-invalid-target";
    pub const PROHIBITED_FIELD: &str = "transform-prohibited-field";
    pub const SENSITIVE_FIELD: &str = "transform-sensitive-field";
    pub const SENSITIVE_FLOW: &str = "transform-sensitive-flow";
    pub const TYPE_ERROR: &str = "transform-type-error";
    pub const BUDGET_EXCEEDED: &str = "transform-budget-exceeded";
    pub const SIZE_EXCEEDED: &str = "transform-size-exceeded";
    pub const INPUT_INVALID: &str = "transform-input-invalid";
}

/// A runtime failure carrying only its stable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransformError(pub &'static str);

impl TransformError {
    pub fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TransformError {}

/// One validation issue: statement number (1-based; 0 for the program or its tables),
/// UTF-16 column (1-based) and code. Never contains statement text or values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransformIssue {
    pub statement: usize,
    pub column: usize,
    pub code: &'static str,
}

impl TransformIssue {
    fn program(code: &'static str) -> Self {
        Self {
            statement: 0,
            column: 0,
            code,
        }
    }

    fn at(statement: usize, column: usize, code: &'static str) -> Self {
        Self {
            statement,
            column,
            code,
        }
    }
}

impl fmt::Display for TransformIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.statement == 0 {
            write!(formatter, "Transform program: {}.", self.code)
        } else {
            write!(
                formatter,
                "Transform statement {} column {}: {}.",
                self.statement, self.column, self.code
            )
        }
    }
}

/// A transform program as a pack parser carries it: `runtime.transforms`, optional
/// `runtime.tables`, and the parser's declared fields, which decide what is sensitive.
#[derive(Debug, Clone, Copy)]
pub struct TransformDefinition<'a> {
    pub statements: Option<&'a [Option<String>]>,
    pub tables: Option<&'a IndexMap<String, IndexMap<String, String>>>,
    pub fields: &'a [CustomLogField],
}

/// Canonical output record JSON and the steps it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformOutput {
    pub record_json: String,
    pub steps: u64,
}

/// Per-record step counter shared by statements, expressions and regex execution.
pub(crate) struct Budget {
    steps: u64,
}

impl Budget {
    pub(crate) fn step(&mut self) -> Result<(), TransformError> {
        self.steps += 1;
        if self.steps > limits::STEP_BUDGET {
            return Err(TransformError(codes::BUDGET_EXCEEDED));
        }
        Ok(())
    }
}

/// A validated, compiled transform program.
#[derive(Debug, Clone)]
pub struct TransformProgram {
    statements: Vec<syntax::Stmt>,
}

/// UTC ticks (100 ns since 0001-01-01) of a timestamp, as `DateTimeOffset.UtcTicks`.
fn utc_ticks(time: &Timestamp) -> i64 {
    time.timestamp() * 10_000_000
        + i64::from(time.timestamp_subsec_nanos() / 100)
        + time::UNIX_EPOCH_TICKS
}

impl TransformProgram {
    /// Every issue, at most one per statement, in statement order.
    pub fn validate(definition: &TransformDefinition<'_>) -> Vec<TransformIssue> {
        compiler::compile(definition).0
    }

    /// Compiles a valid program, or returns its issues.
    pub fn compile(definition: &TransformDefinition<'_>) -> Result<Self, Vec<TransformIssue>> {
        let (issues, statements) = compiler::compile(definition);
        if issues.is_empty() {
            Ok(Self { statements })
        } else {
            Err(issues)
        }
    }

    /// Runs the program over one record (a JSON object).
    pub fn execute(
        &self,
        record: &JsonElement,
        evaluation_time: &Timestamp,
    ) -> Result<TransformOutput, TransformError> {
        let mut fields = value::record_from(record)?;
        let mut evaluator = evaluator::Evaluator {
            record: &mut fields,
            evaluation_ticks: utc_ticks(evaluation_time),
            budget: Budget { steps: 0 },
        };
        for statement in &self.statements {
            evaluator.execute(statement)?;
        }
        let steps = evaluator.budget.steps;
        let record_json = value::serialize(&fields);
        if value::utf16_len(&record_json) > limits::MAXIMUM_OUTPUT_LENGTH {
            return Err(TransformError(codes::SIZE_EXCEEDED));
        }
        Ok(TransformOutput { record_json, steps })
    }

    /// Parses `record_json` (a JSON object) and runs the program.
    pub fn execute_json(
        &self,
        record_json: &str,
        evaluation_time: &Timestamp,
    ) -> Result<TransformOutput, TransformError> {
        let record =
            JsonElement::parse(record_json).map_err(|_| TransformError(codes::INPUT_INVALID))?;
        self.execute(&record, evaluation_time)
    }
}
