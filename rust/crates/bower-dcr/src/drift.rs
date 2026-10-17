//! Drift checks for deployed DCRs and tables, and lints for known traps (`DcrDrift`).

use std::sync::LazyLock;

use indexmap_lite::OrderedColumns;
use regex::Regex;
use serde_json::{Map, Value};

use crate::DcrError;
use crate::json_text::{contains_ignore_case, optional_string, try_get_int32, utf16_len};
use crate::schema::SentinelSchema;

/// Azure rejects transformations longer than this (UTF-16 code units).
pub const MAXIMUM_TRANSFORM_LENGTH: usize = 15_360;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingLevel {
    Info,
    Warning,
    Error,
}

impl FindingLevel {
    /// C# enum name (`Info`, `Warning`, `Error`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Error => "Error",
        }
    }
}

impl std::fmt::Display for FindingLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcrFinding {
    pub level: FindingLevel,
    pub code: String,
    pub detail: String,
}

impl DcrFinding {
    fn new(level: FindingLevel, code: &str, detail: impl Into<String>) -> Self {
        Self {
            level,
            code: code.to_owned(),
            detail: detail.into(),
        }
    }
}

const RESERVED_COLUMNS: &[&str] = &[
    "TenantId",
    "Type",
    "SourceSystem",
    "MG",
    "ManagementGroupName",
    "Computer",
    "RawData",
    "_ResourceId",
    "_SubscriptionId",
    "_ItemId",
    "_IsBillable",
    "_BilledSize",
    "_TimeReceived",
];

// .NET `$` also matches before a final `\n`; `\n?` keeps that behaviour.
static COLUMN_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_]{0,44}\n?$").expect("regex"));
static REGEX_PARSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)parse\s+kind\s*=\s*regex").expect("regex"));
static PARSE_STATEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\|\s*parse\b[^|]*").expect("regex"));
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("regex"));

/// Compares a deployed DCR (ARM or `az monitor data-collection rule show` JSON) with
/// what Bower expects.
pub fn compare_rule(
    deployed_rule_json: &str,
    expected: &SentinelSchema,
) -> Result<Vec<DcrFinding>, DcrError> {
    let mut findings = Vec::new();
    let root = parse_object(deployed_rule_json, "DCR")?;
    let properties = match root.get("properties") {
        Some(Value::Object(properties)) => properties,
        _ => &root,
    };

    let kind = optional_string(root.get("kind"), "kind")?;
    if !kind.is_some_and(|kind| kind.eq_ignore_ascii_case("Direct")) {
        findings.push(DcrFinding::new(
            FindingLevel::Info,
            "rule-not-direct",
            format!(
                "DCR kind is '{}'. Bower expects 'Direct' so the rule exposes its own ingestion endpoint; a DCE is then needed only for Private Link.",
                kind.unwrap_or("(none)")
            ),
        ));
    }

    let stream = match properties.get("streamDeclarations") {
        Some(Value::Object(declarations)) => match declarations.get(&expected.stream_name) {
            Some(Value::Object(stream)) => Some(stream),
            _ => None,
        },
        _ => None,
    };
    match stream {
        None => findings.push(DcrFinding::new(
            FindingLevel::Error,
            "stream-missing",
            format!(
                "Stream declaration '{}' is not deployed.",
                expected.stream_name
            ),
        )),
        Some(stream) => {
            let deployed = columns(stream.get("columns"))?;
            for column in &expected.stream_columns {
                match deployed.get(&column.name) {
                    None => findings.push(DcrFinding::new(
                        FindingLevel::Error,
                        "stream-column-missing",
                        format!(
                            "Stream column '{}' is missing; the value is dropped at ingestion.",
                            column.name
                        ),
                    )),
                    Some(kind) if !kind.eq_ignore_ascii_case(&column.column_type) => {
                        findings.push(DcrFinding::new(
                            FindingLevel::Error,
                            "stream-column-type",
                            format!(
                                "Stream column '{}' is '{kind}', expected '{}'.",
                                column.name, column.column_type
                            ),
                        ))
                    }
                    Some(_) => {}
                }
            }

            // `Except` yields distinct keys in first-seen order.
            for extra in deployed.names() {
                if !expected
                    .stream_columns
                    .iter()
                    .any(|column| column.name == *extra)
                {
                    findings.push(DcrFinding::new(
                        FindingLevel::Info,
                        "stream-column-extra",
                        format!("Stream column '{extra}' is deployed but Bower does not send it."),
                    ));
                }
            }
        }
    }

    let mut flow = None;
    if let Some(Value::Array(flows)) = properties.get("dataFlows") {
        for item in flows {
            let Value::Object(item) = item else { continue };
            let consumes = match item.get("streams") {
                Some(Value::Array(streams)) => {
                    let mut found = false;
                    for name in streams {
                        if optional_string(Some(name), "streams")?
                            == Some(expected.stream_name.as_str())
                        {
                            found = true;
                            break;
                        }
                    }
                    found
                }
                _ => false,
            };
            if consumes {
                flow = Some(item);
                break;
            }
        }
    }
    let Some(flow) = flow else {
        findings.push(DcrFinding::new(
            FindingLevel::Error,
            "dataflow-missing",
            format!(
                "No data flow consumes '{}'; ingested events are discarded.",
                expected.stream_name
            ),
        ));
        return Ok(findings);
    };

    let output = optional_string(flow.get("outputStream"), "outputStream")?;
    let expected_output = expected.output_stream();
    if output != Some(expected_output.as_str()) {
        findings.push(DcrFinding::new(
            FindingLevel::Error,
            "output-stream",
            format!(
                "Data flow writes to '{}', expected '{expected_output}'.",
                output.unwrap_or("(none)")
            ),
        ));
    }

    let transform = optional_string(flow.get("transformKql"), "transformKql")?.unwrap_or("source");
    if normalise(transform) != normalise(&expected.transform_kql()) {
        findings.push(DcrFinding::new(
            FindingLevel::Warning,
            "transform-drift",
            "Deployed transformKql differs from the transformation Bower generates. Regenerate with `bower dcr generate` or review the change.",
        ));
    }

    findings.extend(lint_transform(transform));
    Ok(findings)
}

/// Compares a deployed Log Analytics table with the expected columns and retention.
pub fn compare_table(
    deployed_table_json: &str,
    expected: &SentinelSchema,
    minimum_total_retention_days: i32,
) -> Result<Vec<DcrFinding>, DcrError> {
    let mut findings = Vec::new();
    let root = parse_object(deployed_table_json, "table")?;
    let properties = match root.get("properties") {
        Some(Value::Object(properties)) => properties,
        _ => &root,
    };
    let schema_columns = match properties.get("schema") {
        Some(Value::Object(schema)) => schema.get("columns"),
        _ => None,
    };
    let deployed = columns(schema_columns)?;
    for column in &expected.table_columns {
        match deployed.get(&column.name) {
            None => findings.push(DcrFinding::new(
                FindingLevel::Error,
                "table-column-missing",
                format!(
                    "Table column '{}' is missing; the transformation cannot write it.",
                    column.name
                ),
            )),
            Some(kind) if !kind.eq_ignore_ascii_case(&column.column_type) => {
                findings.push(DcrFinding::new(
                    FindingLevel::Error,
                    "table-column-type",
                    format!(
                        "Table column '{}' is '{kind}', expected '{}'.",
                        column.name, column.column_type
                    ),
                ))
            }
            Some(_) => {}
        }
    }

    let total = try_get_int32(properties.get("totalRetentionInDays"))
        .or_else(|| try_get_int32(properties.get("retentionInDays")));
    if total.is_none_or(|total| total < minimum_total_retention_days) {
        findings.push(DcrFinding::new(
            FindingLevel::Warning,
            "retention-short",
            format!(
                "Total retention is {} days; ISM event logging guidance expects at least {minimum_total_retention_days}.",
                total.map_or_else(|| "unknown".to_owned(), |total| total.to_string())
            ),
        ));
    }

    Ok(findings)
}

/// [`compare_table`] with the ISM default of 365 days.
pub fn compare_table_default(
    deployed_table_json: &str,
    expected: &SentinelSchema,
) -> Result<Vec<DcrFinding>, DcrError> {
    compare_table(deployed_table_json, expected, 365)
}

/// Validates table column names against Log Analytics naming rules.
pub fn lint_schema(schema: &SentinelSchema) -> Vec<DcrFinding> {
    let mut findings = Vec::new();
    if !schema.table_name.ends_with("_CL") {
        findings.push(DcrFinding::new(
            FindingLevel::Error,
            "table-name",
            "Custom tables must end in _CL.",
        ));
    }

    let time_generated = schema
        .table_columns
        .iter()
        .find(|column| column.name == "TimeGenerated");
    if !time_generated.is_some_and(|column| column.column_type == "datetime") {
        findings.push(DcrFinding::new(
            FindingLevel::Error,
            "time-generated",
            "Tables need a TimeGenerated datetime column.",
        ));
    }

    for column in &schema.table_columns {
        let reserved = RESERVED_COLUMNS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&column.name));
        if !COLUMN_NAME.is_match(&column.name) || reserved {
            findings.push(DcrFinding::new(
                FindingLevel::Error,
                "column-name",
                format!(
                    "Column '{}' is reserved or invalid (start with a letter; letters, digits, underscore; 45 characters max).",
                    column.name
                ),
            ));
        }
    }

    findings
}

/// Flags transformation patterns that silently lose data.
pub fn lint_transform(transform_kql: &str) -> Vec<DcrFinding> {
    let mut findings = Vec::new();
    let length = utf16_len(transform_kql);
    if length > MAXIMUM_TRANSFORM_LENGTH {
        findings.push(DcrFinding::new(
            FindingLevel::Error,
            "transform-too-long",
            format!(
                "transformKql is {length} characters; Azure's limit is {MAXIMUM_TRANSFORM_LENGTH}."
            ),
        ));
    }

    if REGEX_PARSE.is_match(transform_kql) {
        findings.push(DcrFinding::new(
            FindingLevel::Warning,
            "parse-regex-full-match",
            "`parse kind=regex` must match the whole value; a partial match leaves every extracted column empty without an error.",
        ));
    }

    for statement in PARSE_STATEMENT.find_iter(transform_kql) {
        if statement.as_str().matches(':').count() > 10 {
            findings.push(DcrFinding::new(
                FindingLevel::Warning,
                "parse-too-many-columns",
                "A `parse` statement extracts more than 10 columns; transformations support at most 10 per parse.",
            ));
        }
    }

    if contains_ignore_case(transform_kql, "| where") && !transform_kql.contains("schemaVersion") {
        findings.push(DcrFinding::new(
            FindingLevel::Info,
            "filter-present",
            "The transformation filters rows. Filtered rows are dropped without an error; confirm the filter matches Bower's policy.",
        ));
    }

    findings
}

fn columns(columns: Option<&Value>) -> Result<OrderedColumns, DcrError> {
    let mut result = OrderedColumns::default();
    if let Some(Value::Array(columns)) = columns {
        for column in columns {
            let Value::Object(column) = column else {
                continue;
            };
            let name = optional_string(column.get("name"), "column name")?;
            let kind = optional_string(column.get("type"), "column type")?;
            if let (Some(name), Some(kind)) = (name, kind) {
                result.insert(name, kind);
            }
        }
    }
    Ok(result)
}

fn normalise(kql: &str) -> String {
    WHITESPACE.replace_all(kql, " ").trim().to_owned()
}

fn parse_object(json: &str, what: &str) -> Result<Map<String, Value>, DcrError> {
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(DcrError::InvalidData(format!(
            "Deployed {what} JSON must be an object."
        ))),
        Err(_) => Err(DcrError::InvalidData(format!(
            "Deployed {what} JSON is invalid."
        ))),
    }
}

mod indexmap_lite {
    /// A `Dictionary<string, string>`: later duplicates overwrite the value but keep
    /// the first insertion position, as C# dictionary indexer assignment does.
    #[derive(Default)]
    pub struct OrderedColumns {
        entries: Vec<(String, String)>,
    }

    impl OrderedColumns {
        pub fn insert(&mut self, name: &str, kind: &str) {
            if let Some(entry) = self.entries.iter_mut().find(|entry| entry.0 == name) {
                entry.1 = kind.to_owned();
            } else {
                self.entries.push((name.to_owned(), kind.to_owned()));
            }
        }

        pub fn get(&self, name: &str) -> Option<&str> {
            self.entries
                .iter()
                .find(|entry| entry.0 == name)
                .map(|entry| entry.1.as_str())
        }

        pub fn names(&self) -> impl Iterator<Item = &String> {
            self.entries.iter().map(|entry| &entry.0)
        }
    }
}
