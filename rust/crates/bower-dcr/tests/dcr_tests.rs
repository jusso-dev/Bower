//! Ports of the DCR parts of `IntegrityAndDcrTests` and `DcrOptimiserTests`, plus
//! byte-parity checks against output captured from the C# implementation.

use std::path::PathBuf;

use bower_dcr::optimiser::{assess, export_markdown, parse_document};
use bower_dcr::{
    DcrDataSource, DcrDocument, DcrTemplateOptions, MAXIMUM_TRANSFORM_LENGTH, SentinelSchema,
    TableColumn, drift, generator, preflight,
};
use regex::Regex;
use serde_json::{Map, Value, json};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn repo_file(relative: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(relative),
    )
    .unwrap()
}

fn resource<'a>(template: &'a mut Value, kind: &str) -> &'a mut Value {
    template["resources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["type"] == kind)
        .unwrap()
}

fn compact(value: &Value) -> String {
    bower_contracts::json::to_string(value).unwrap()
}

#[test]
fn generated_template_is_byte_identical_to_csharp() {
    assert_eq!(
        generator::generate_json(&DcrTemplateOptions::default()).unwrap(),
        fixture("dcr-default.json")
    );
    let custom = DcrTemplateOptions {
        rule_name: "x-rule's".to_owned(),
        plan: "Basic".to_owned(),
        retention_in_days: 30,
        total_retention_in_days: 400,
        ..DcrTemplateOptions::default()
    };
    assert_eq!(
        generator::generate_json(&custom).unwrap(),
        fixture("dcr-custom.json")
    );
}

#[test]
fn generator_rejects_total_retention_shorter_than_interactive() {
    let options = DcrTemplateOptions {
        retention_in_days: 90,
        total_retention_in_days: 30,
        ..DcrTemplateOptions::default()
    };
    assert!(generator::generate(&options).is_err());
}

#[test]
fn generator_produces_direct_rule_and_table_matching_schema() {
    let mut template = generator::generate(&DcrTemplateOptions::default()).unwrap();
    let rule = resource(&mut template, "Microsoft.Insights/dataCollectionRules").clone();
    let table = resource(
        &mut template,
        "Microsoft.OperationalInsights/workspaces/tables",
    )
    .clone();

    assert_eq!(rule["kind"], "Direct");
    assert!(
        drift::compare_rule(&compact(&rule), SentinelSchema::default_schema())
            .unwrap()
            .is_empty()
    );
    assert!(
        drift::compare_table_default(&compact(&table), SentinelSchema::default_schema())
            .unwrap()
            .is_empty()
    );
    assert_eq!(table["properties"]["totalRetentionInDays"], 365);
}

#[test]
fn drift_flags_missing_columns_wrong_output_and_short_retention() {
    let options = DcrTemplateOptions {
        total_retention_in_days: 90,
        retention_in_days: 30,
        ..DcrTemplateOptions::default()
    };
    let mut template = generator::generate(&options).unwrap();
    let mut rule = resource(&mut template, "Microsoft.Insights/dataCollectionRules").clone();
    let mut table = resource(
        &mut template,
        "Microsoft.OperationalInsights/workspaces/tables",
    )
    .clone();
    rule["properties"]["streamDeclarations"]["Custom-BowerSecurity"]["columns"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    rule["properties"]["dataFlows"][0]["outputStream"] = json!("Custom-Other_CL");
    table["properties"]["schema"]["columns"]
        .as_array_mut()
        .unwrap()
        .remove(1);

    let rule_codes: Vec<String> =
        drift::compare_rule(&compact(&rule), SentinelSchema::default_schema())
            .unwrap()
            .into_iter()
            .map(|finding| finding.code)
            .collect();
    let table_codes: Vec<String> =
        drift::compare_table_default(&compact(&table), SentinelSchema::default_schema())
            .unwrap()
            .into_iter()
            .map(|finding| finding.code)
            .collect();

    assert!(rule_codes.contains(&"stream-column-missing".to_owned()));
    assert!(rule_codes.contains(&"output-stream".to_owned()));
    assert!(table_codes.contains(&"table-column-missing".to_owned()));
    assert!(table_codes.contains(&"retention-short".to_owned()));
}

#[test]
fn drift_reports_missing_stream_and_dataflow_and_invalid_json() {
    let findings = drift::compare_rule(
        r#"{"kind":"AgentDirectToStore","properties":{}}"#,
        SentinelSchema::default_schema(),
    )
    .unwrap();
    let codes: Vec<&str> = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert_eq!(
        codes,
        ["rule-not-direct", "stream-missing", "dataflow-missing"]
    );
    assert!(findings[0].detail.contains("'AgentDirectToStore'"));
    assert!(drift::compare_rule("not json", SentinelSchema::default_schema()).is_err());
    assert!(drift::compare_rule("[]", SentinelSchema::default_schema()).is_err());
}

#[test]
fn lint_flags_transform_traps() {
    let too_long = format!("source | {}", "x".repeat(MAXIMUM_TRANSFORM_LENGTH));
    let regex = "source | parse kind=regex RawData with @'(\\d+)' Id:int";

    assert!(
        drift::lint_transform(&too_long)
            .iter()
            .any(|finding| finding.code == "transform-too-long")
    );
    assert!(
        drift::lint_transform(regex)
            .iter()
            .any(|finding| finding.code == "parse-regex-full-match")
    );
    let many = format!(
        "source | parse RawData with {}",
        (0..11)
            .map(|index| format!("c{index}:string "))
            .collect::<String>()
    );
    assert!(
        drift::lint_transform(&many)
            .iter()
            .any(|finding| finding.code == "parse-too-many-columns")
    );
    assert!(
        drift::lint_transform("source | WHERE x == 1")
            .iter()
            .any(|finding| finding.code == "filter-present")
    );
    assert!(drift::lint_transform(&SentinelSchema::default_schema().transform_kql()).is_empty());
}

#[test]
fn lint_rejects_reserved_and_invalid_column_names() {
    let mut schema = SentinelSchema::default();
    schema
        .table_columns
        .push(TableColumn::new("TenantId", "string", "x"));
    schema
        .table_columns
        .push(TableColumn::new("1bad", "string", "x"));

    assert_eq!(
        drift::lint_schema(&schema)
            .iter()
            .filter(|finding| finding.code == "column-name")
            .count(),
        2
    );
    assert!(drift::lint_schema(SentinelSchema::default_schema()).is_empty());
}

#[test]
fn preflight_catches_what_azure_would_silently_truncate_or_coerce() {
    let record: Map<String, Value> = json!({
        "eventId": "e1",
        "timeGenerated": "not a date",
        "eventType": {},
        "actor": { "username": "x".repeat(70_000) }
    })
    .as_object()
    .unwrap()
    .clone();

    let codes: Vec<String> = preflight::check(&record, SentinelSchema::default_schema())
        .into_iter()
        .map(|issue| issue.code)
        .collect();

    assert!(codes.contains(&"field-too-large".to_owned()));
    assert!(codes.contains(&"type-mismatch".to_owned()));
    let ok = json!({ "timeGenerated": "2026-10-08T00:00:00Z" })
        .as_object()
        .unwrap()
        .clone();
    assert!(preflight::check(&ok, SentinelSchema::default_schema()).is_empty());
    let missing = preflight::check(&Map::new(), SentinelSchema::default_schema());
    assert_eq!(missing[0].code, "time-generated-missing");
    let object_type = preflight::check(&record, SentinelSchema::default_schema());
    assert!(
        object_type
            .iter()
            .any(|issue| issue.field == "eventType" && issue.detail.contains("got Object"))
    );
}

#[test]
fn preflight_requires_dynamic_columns_to_be_objects_or_arrays() {
    let record = json!({
        "timeGenerated": "2026-10-08T00:00:00Z",
        "labels": "team=red",
        "application": { "name": "a" },
        "privacy": []
    })
    .as_object()
    .unwrap()
    .clone();
    let issues = preflight::check(&record, SentinelSchema::default_schema());
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(
        (
            issues[0].code.as_str(),
            issues[0].field.as_str(),
            issues[0].detail.as_str()
        ),
        (
            "type-mismatch",
            "labels",
            "Expected dynamic, got String; Azure would store an empty or stringified value."
        )
    );
}

/// C# `ArmApiVersions_ArePinnedPerResourceProviderInTemplateAndBicep`.
#[test]
fn arm_api_versions_are_pinned_per_resource_provider() {
    assert_eq!(bower_dcr::LOG_ANALYTICS_API_VERSION, "2025-07-01");
    assert_eq!(bower_dcr::DATA_COLLECTION_RULES_API_VERSION, "2024-03-11");
    let mut template = generator::generate(&DcrTemplateOptions::default()).unwrap();
    assert_eq!(
        resource(
            &mut template,
            "Microsoft.OperationalInsights/workspaces/tables"
        )["apiVersion"],
        bower_dcr::LOG_ANALYTICS_API_VERSION
    );
    assert_eq!(
        resource(&mut template, "Microsoft.Insights/dataCollectionRules")["apiVersion"],
        bower_dcr::DATA_COLLECTION_RULES_API_VERSION
    );
    let bicep = repo_file("deploy/bicep/main.bicep");
    for expected in [
        format!(
            "'Microsoft.OperationalInsights/workspaces@{}'",
            bower_dcr::LOG_ANALYTICS_API_VERSION
        ),
        format!(
            "'Microsoft.OperationalInsights/workspaces/tables@{}'",
            bower_dcr::LOG_ANALYTICS_API_VERSION
        ),
        format!(
            "'Microsoft.Insights/dataCollectionRules@{}'",
            bower_dcr::DATA_COLLECTION_RULES_API_VERSION
        ),
    ] {
        assert!(bicep.contains(&expected), "{expected}");
    }
}

fn bicep_columns(bicep: &str, start_marker: &str) -> Vec<String> {
    let start = bicep.find(start_marker).unwrap();
    let end = start + bicep[start..].find(']').unwrap();
    let pattern = Regex::new(r"name: '(?<name>[^']+)', type: '(?<type>[^']+)'").unwrap();
    pattern
        .captures_iter(&bicep[start..end])
        .map(|captures| format!("{}:{}", &captures["name"], &captures["type"]).to_lowercase())
        .collect()
}

fn normalise(kql: &str) -> String {
    Regex::new(r"\s+")
        .unwrap()
        .replace_all(kql, " ")
        .trim()
        .to_owned()
}

#[test]
fn bicep_matches_the_schema_model() {
    let bicep = repo_file("deploy/bicep/main.bicep");
    let schema = SentinelSchema::default_schema();

    let table: Vec<String> = schema
        .table_columns
        .iter()
        .map(|column| format!("{}:{}", column.name, column.column_type).to_lowercase())
        .collect();
    let stream: Vec<String> = schema
        .stream_columns
        .iter()
        .map(|column| format!("{}:{}", column.name, column.column_type).to_lowercase())
        .collect();
    let transform = Regex::new(r"(?s)transformKql: '''(?<kql>.*?)'''")
        .unwrap()
        .captures(&bicep)
        .unwrap()["kql"]
        .to_owned();

    assert_eq!(bicep_columns(&bicep, "schema: {"), table);
    assert_eq!(bicep_columns(&bicep, "'Custom-BowerSecurity': {"), stream);
    assert_eq!(normalise(&schema.transform_kql()), normalise(&transform));
}

/// `SentinelSchema::default`, `deploy/bicep/main.bicep` and the generated template agree
/// column for column and on the transform (the template is the C# bytes, see above).
#[test]
fn generated_template_matches_bicep() {
    let bicep = repo_file("deploy/bicep/main.bicep");
    let mut template = generator::generate(&DcrTemplateOptions::default()).unwrap();
    let columns = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|column| {
                format!(
                    "{}:{}",
                    column["name"].as_str().unwrap(),
                    column["type"].as_str().unwrap()
                )
                .to_lowercase()
            })
            .collect()
    };
    let table = resource(
        &mut template,
        "Microsoft.OperationalInsights/workspaces/tables",
    )
    .clone();
    let rule = resource(&mut template, "Microsoft.Insights/dataCollectionRules").clone();
    let transform = Regex::new(r"(?s)transformKql: '''(?<kql>.*?)'''")
        .unwrap()
        .captures(&bicep)
        .unwrap()["kql"]
        .to_owned();

    assert_eq!(
        columns(&table["properties"]["schema"]["columns"]),
        bicep_columns(&bicep, "schema: {")
    );
    assert_eq!(
        columns(&rule["properties"]["streamDeclarations"]["Custom-BowerSecurity"]["columns"]),
        bicep_columns(&bicep, "'Custom-BowerSecurity': {")
    );
    assert_eq!(
        normalise(
            rule["properties"]["dataFlows"][0]["transformKql"]
                .as_str()
                .unwrap()
        ),
        normalise(&transform)
    );
}

#[test]
fn assess_flags_broad_security_and_missing_sysmon() {
    let json = r#"
        {
          "id": "dcr-1",
          "name": "servers",
          "workspaceId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
          "dataSources": [
            {
              "name": "windows-security",
              "kind": "windowsEventLogs",
              "streams": ["Microsoft-WindowsEvent"],
              "xPathQueries": ["Security!*"]
            }
          ],
          "destinations": [{ "name": "law" }]
        }"#;

    let document = parse_document(json).unwrap();
    let report = assess(&document, Some(100.0), None);

    assert!(
        report
            .recommendations
            .iter()
            .any(|item| item.code == "broad-security-events")
    );
    assert!(
        report
            .recommendations
            .iter()
            .any(|item| item.code == "missing-sysmon")
    );
    assert!(
        report
            .estimated_monthly_savings_gb
            .is_some_and(|value| value > 0.0)
    );
    assert!(report.health_score < 100);
    assert!(export_markdown(&report).contains("DCR Assessment"));
}

#[test]
fn assess_healthy_dcr_scores_high() {
    let source = |name: &str, kind: &str, stream: &str, xpath: &[&str]| DcrDataSource {
        name: name.to_owned(),
        kind: kind.to_owned(),
        streams: vec![stream.to_owned()],
        xpath_queries: xpath.iter().map(|item| (*item).to_owned()).collect(),
        enabled: true,
    };
    let document = DcrDocument {
        id: "dcr-good".to_owned(),
        name: "good".to_owned(),
        workspace_id: Some("law".to_owned()),
        data_sources: vec![
            source(
                "security",
                "windowsEventLogs",
                "Microsoft-WindowsEvent",
                &["Security!*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]"],
            ),
            source(
                "sysmon",
                "windowsEventLogs",
                "Microsoft-WindowsEvent",
                &[
                    "Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=3 or EventID=11)]]",
                ],
            ),
            source(
                "defender",
                "windowsEventLogs",
                "Microsoft-Windows-Windows Defender/Operational",
                &[],
            ),
            source("iis", "iisLogs", "Microsoft-IIS", &[]),
        ],
        destinations: vec!["law".to_owned()],
    };

    let report = assess(&document, None, None);

    assert!(report.coverage_score >= 90);
    assert!(
        !report
            .recommendations
            .iter()
            .any(|item| item.code == "missing-sysmon")
    );
}

fn document_json(document: &DcrDocument) -> Value {
    json!({
        "Id": document.id,
        "Name": document.name,
        "WorkspaceId": document.workspace_id,
        "DataSources": document.data_sources.iter().map(|source| json!({
            "Name": source.name,
            "Kind": source.kind,
            "Streams": source.streams,
            "XPathQueries": source.xpath_queries,
            "Enabled": source.enabled,
        })).collect::<Vec<_>>(),
        "Destinations": document.destinations,
    })
}

#[test]
fn parser_and_markdown_match_csharp_output() {
    let now = bower_contracts::time::parse("2026-01-01T00:00:00Z");
    for (name, gb) in [("dcr1", Some(123.456)), ("dcr2", None)] {
        let document = parse_document(&fixture(&format!("{name}.json"))).unwrap();
        assert_eq!(
            compact(&document_json(&document)),
            fixture(&format!("{name}.document.json")),
            "{name}"
        );
        let report = assess(&document, gb, now);
        assert_eq!(
            export_markdown(&report),
            fixture(&format!("{name}.md")),
            "{name}"
        );
    }
}

#[test]
fn parser_rejects_shapes_csharp_throws_on() {
    assert!(parse_document("  ").is_err());
    assert!(parse_document("[]").is_err());
    assert!(parse_document(r#"{"destinations":["law"]}"#).is_err());
    assert!(parse_document(r#"{"dataSources":[{"streams":[1]}]}"#).is_err());
}

/// `fixtures/csharp-findings.txt` is C# `DcrDrift`/`IngestionPreflight` output (temporary
/// xunit emitter): level, code and full detail text for drifted rule/table, a non-Direct
/// rule, every transform lint, reserved column names and preflight type/size checks.
#[test]
fn findings_text_matches_csharp() {
    let schema = SentinelSchema::default_schema();
    let mut actual = Vec::new();
    let mut findings = |name: &str, items: Vec<drift::DcrFinding>| {
        for item in items {
            actual.push(format!(
                "finding|{name}|{}|{}|{}",
                item.level, item.code, item.detail
            ));
        }
    };

    let options = DcrTemplateOptions {
        total_retention_in_days: 90,
        retention_in_days: 30,
        ..DcrTemplateOptions::default()
    };
    let mut template = generator::generate(&options).unwrap();
    let mut rule = resource(&mut template, "Microsoft.Insights/dataCollectionRules").clone();
    let mut table = resource(
        &mut template,
        "Microsoft.OperationalInsights/workspaces/tables",
    )
    .clone();
    let stream = &mut rule["properties"]["streamDeclarations"]["Custom-BowerSecurity"]["columns"];
    stream.as_array_mut().unwrap().remove(1);
    stream[2]["type"] = json!("int");
    rule["properties"]["dataFlows"][0]["outputStream"] = json!("Custom-Other_CL");
    rule["properties"]["dataFlows"][0]["transformKql"] = json!("source | where x == 1");
    let columns = &mut table["properties"]["schema"]["columns"];
    columns.as_array_mut().unwrap().remove(1);
    columns[3]["type"] = json!("int");
    table["properties"]["plan"] = json!("Basic");

    findings(
        "drift-rule",
        drift::compare_rule(&compact(&rule), schema).unwrap(),
    );
    findings(
        "drift-table",
        drift::compare_table_default(&compact(&table), schema).unwrap(),
    );
    findings(
        "drift-table-400",
        drift::compare_table(&compact(&table), schema, 400).unwrap(),
    );
    findings(
        "drift-agent",
        drift::compare_rule(r#"{"kind":"AgentDirectToStore","properties":{}}"#, schema).unwrap(),
    );
    findings(
        "lint-long",
        drift::lint_transform(&format!(
            "source | {}",
            "x".repeat(MAXIMUM_TRANSFORM_LENGTH)
        )),
    );
    findings(
        "lint-regex",
        drift::lint_transform("source | parse kind=regex RawData with @'(\\d+)' Id:int"),
    );
    findings(
        "lint-many",
        drift::lint_transform(&format!(
            "source | parse RawData with {}",
            (0..11)
                .map(|index| format!("c{index}:string "))
                .collect::<String>()
        )),
    );
    findings("lint-where", drift::lint_transform("source | WHERE x == 1"));
    let mut reserved = SentinelSchema::default();
    reserved
        .table_columns
        .push(TableColumn::new("TenantId", "string", "x"));
    reserved
        .table_columns
        .push(TableColumn::new("1bad", "string", "x"));
    findings("lint-schema", drift::lint_schema(&reserved));

    let record = json!({
        "eventId": "e1",
        "timeGenerated": "not a date",
        "eventType": {},
        "eventSeverity": 3,
        "labels": "text",
        "actor": { "username": "x".repeat(70_000) }
    })
    .as_object()
    .unwrap()
    .clone();
    for issue in preflight::check(&record, schema)
        .into_iter()
        .chain(preflight::check(&Map::new(), schema))
    {
        actual.push(format!(
            "preflight|{}|{}|{}",
            issue.code, issue.field, issue.detail
        ));
    }

    assert_eq!(
        actual,
        fixture("csharp-findings.txt").lines().collect::<Vec<_>>()
    );
}
