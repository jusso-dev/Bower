//! Transform language conformance vectors shared with C# (`TransformConformanceTests`).
//! Validation issues, canonical output bytes, step counts and runtime error codes must
//! match the C# expectations in `fixtures/transform-vectors.json` exactly.

use bower_contracts::time;
use bower_pipeline::transform::{TransformDefinition, TransformProgram};
use bower_pipeline::{CustomLogField, CustomLogValueType};
use indexmap::IndexMap;
use serde_json::Value;

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transform-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn transform_vectors_match_csharp_outcomes() {
    let fixture = fixture();
    let default_time = fixture["defaultEvaluationTime"].as_str().unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 50);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let fields: Vec<CustomLogField> = case
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|field| CustomLogField {
                source_name: field["name"].as_str().unwrap().to_owned(),
                value_type: CustomLogValueType::Text,
                ocsf_path: None,
                asim_field: None,
                sensitive: field["sensitive"].as_bool().unwrap(),
            })
            .collect();
        let tables: Option<IndexMap<String, IndexMap<String, String>>> =
            case.get("tables").map(|tables| {
                tables
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(name, table)| {
                        let entries = table
                            .as_object()
                            .unwrap()
                            .iter()
                            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
                            .collect();
                        (name.clone(), entries)
                    })
                    .collect()
            });
        let statements: Vec<Option<String>> = case["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect();
        let definition = TransformDefinition {
            statements: Some(&statements),
            tables: tables.as_ref(),
            fields: &fields,
        };
        let issues: Vec<String> = TransformProgram::validate(&definition)
            .iter()
            .map(ToString::to_string)
            .collect();
        let expected: Vec<String> = case["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|issue| issue.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(issues, expected, "{name}: issues");
        let Some(input) = case.get("input").and_then(Value::as_str) else {
            continue;
        };
        if !issues.is_empty() {
            continue;
        }
        let at = time::parse(
            case.get("evaluationTime")
                .and_then(Value::as_str)
                .unwrap_or(default_time),
        )
        .unwrap();
        let program = TransformProgram::compile(&definition).unwrap();
        match program.execute_json(input, &at) {
            Ok(output) => {
                assert_eq!(
                    Some(output.record_json.as_str()),
                    case.get("output").and_then(Value::as_str),
                    "{name}: output"
                );
                assert_eq!(Some(output.steps), case["steps"].as_u64(), "{name}: steps");
                assert_eq!(
                    program.execute_json(input, &at).unwrap(),
                    output,
                    "{name}: rerun"
                );
            }
            Err(error) => assert_eq!(
                Some(error.code()),
                case.get("error").and_then(Value::as_str),
                "{name}: error"
            ),
        }
    }
}

#[test]
fn statements_absent_is_a_program_limit_issue() {
    let definition = TransformDefinition {
        statements: None,
        tables: None,
        fields: &[],
    };
    assert_eq!(
        TransformProgram::validate(&definition)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["Transform program: transform-limit-exceeded."]
    );
}

/// Same generator as `FuzzGenerator` in C# `TransformConformanceTests`; keep the call
/// order identical.
struct FuzzGenerator {
    state: u64,
}

const FRAGMENTS: [&str; 30] = [
    ".a",
    ".b",
    ".user",
    " = ",
    "lower(",
    ")",
    "(",
    ",",
    "\"x\"",
    "'[a-z]+'",
    "if ",
    " { ",
    " }",
    " else ",
    "&&",
    "||",
    "!",
    "==",
    "<",
    "del(",
    ";",
    "'(?<g>a*)*'",
    ".\"q.r\"",
    " ",
    "\"",
    "'",
    "\\",
    ".",
    "-",
    "{",
];
const PATHS: [&str; 7] = [".a", ".b", ".m", ".m.x", ".missing", ".\"q.r\"", ".user"];
const LITERALS: [&str; 11] = [
    "\"x\"",
    "1",
    "-1",
    "null",
    "true",
    "\",\"",
    "'[a-z]+'",
    "'(?<g>a*)*'",
    "\"rfc3339\"",
    "\"t\"",
    "'^(?<w>\\w+)'",
];
const FUNCTIONS: [&str; 20] = [
    "lower",
    "upper",
    "trim",
    "replace",
    "split",
    "join",
    "at",
    "concat",
    "contains",
    "coalesce",
    "lookup",
    "regex_match",
    "regex_extract",
    "parse_timestamp",
    "to_string",
    "to_int",
    "to_bool",
    "now",
    "starts_with",
    "exec",
];
const OPERATORS: [&str; 5] = [" == ", " != ", " && ", " || ", " < "];
const TARGETS: [&str; 5] = [".a", ".b", ".out", ".user", ".m"];

impl FuzzGenerator {
    fn pick(&mut self, count: usize) -> usize {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.state >> 33) % count as u64) as usize
    }

    fn next_statement(&mut self) -> String {
        if self.pick(4) == 0 {
            let count = 1 + self.pick(12);
            let mut soup = String::new();
            for _ in 0..count {
                soup.push_str(FRAGMENTS[self.pick(FRAGMENTS.len())]);
            }
            return soup;
        }
        let mut statement = self.statement(0);
        if self.pick(3) == 0 {
            let position = self.pick(statement.len() + 1);
            statement.insert_str(position, FRAGMENTS[self.pick(FRAGMENTS.len())]);
        }
        statement
    }

    fn statement(&mut self, depth: usize) -> String {
        match self.pick(if depth >= 2 { 3 } else { 4 }) {
            0 | 1 => {
                let target = TARGETS[self.pick(TARGETS.len())];
                format!("{target} = {}", self.expression(0))
            }
            2 => {
                if self.pick(2) == 0 {
                    return format!("del({})", TARGETS[self.pick(TARGETS.len())]);
                }
                let from = TARGETS[self.pick(TARGETS.len())];
                format!("rename({from}, {})", TARGETS[self.pick(TARGETS.len())])
            }
            _ => {
                let condition = self.expression(1);
                let then = self.statement(depth + 1);
                if self.pick(2) == 0 {
                    format!("if {condition} {{ {then} }}")
                } else {
                    let otherwise = self.statement(depth + 1);
                    format!("if {condition} {{ {then} }} else {{ {otherwise} }}")
                }
            }
        }
    }

    fn expression(&mut self, depth: usize) -> String {
        match self.pick(if depth >= 3 { 2 } else { 4 }) {
            0 => PATHS[self.pick(PATHS.len())].to_owned(),
            1 => LITERALS[self.pick(LITERALS.len())].to_owned(),
            2 => {
                let name = FUNCTIONS[self.pick(FUNCTIONS.len())];
                let count = self.pick(4);
                let arguments: Vec<String> =
                    (0..count).map(|_| self.expression(depth + 1)).collect();
                format!("{name}({})", arguments.join(", "))
            }
            _ => {
                let left = self.expression(depth + 1);
                let operator = OPERATORS[self.pick(OPERATORS.len())];
                format!("{left}{operator}{}", self.expression(depth + 1))
            }
        }
    }
}

/// Port of `TransformConformanceTests.DeterministicFuzz_NeverThrowsAndMatchesRust`.
#[test]
fn deterministic_fuzz_never_panics_and_matches_csharp() {
    let fields = [CustomLogField {
        source_name: "user".into(),
        value_type: CustomLogValueType::Text,
        ocsf_path: None,
        asim_field: None,
        sensitive: true,
    }];
    let tables: IndexMap<String, IndexMap<String, String>> = [(
        "t".to_owned(),
        [("Admin".to_owned(), "x".to_owned())].into_iter().collect(),
    )]
    .into_iter()
    .collect();
    let input = r#"{"a":"Alpha,beta","b":"12","user":"Admin","m":{"x":"y"}}"#;
    let at = time::parse("2026-10-26T01:02:03+00:00").unwrap();
    let mut generator = FuzzGenerator { state: 87 };
    let mut digest: u64 = 14695981039346656037;
    let mut valid = 0;
    for _ in 0..4000 {
        let statements = vec![Some(generator.next_statement())];
        let definition = TransformDefinition {
            statements: Some(&statements),
            tables: Some(&tables),
            fields: &fields,
        };
        let issues = TransformProgram::validate(&definition);
        let mut outcome = issues
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        if issues.is_empty() {
            valid += 1;
            outcome = match TransformProgram::compile(&definition)
                .unwrap()
                .execute_json(input, &at)
            {
                Ok(output) => format!("{}|{}", output.record_json, output.steps),
                Err(error) => error.code().to_owned(),
            };
        }
        for byte in format!("{outcome}\n").bytes() {
            digest = (digest ^ u64::from(byte)).wrapping_mul(1099511628211);
        }
    }
    assert_eq!(valid, 1287);
    assert_eq!(digest, 4304864850446909586);
}
