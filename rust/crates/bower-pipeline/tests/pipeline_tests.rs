//! Ports of `PipelineValidatorTests` plus YAML byte-parity against YamlDotNet output
//! and custom log parser configuration validation.

use std::path::PathBuf;

use bower_pipeline::custom_log::{
    CustomLogField, CustomLogFormat, CustomLogParserConfiguration, CustomLogValueType,
};
use bower_pipeline::{
    PipelineEdge, PipelineNode, PipelineNodeKind, TelemetryPipeline, create_template, estimate,
    parse_yaml, to_yaml, validate, validate_configuration,
};
use indexmap::IndexMap;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn template_sentinel_app_is_valid() {
    let pipeline = create_template("sentinel-app").unwrap();
    let result = validate(&pipeline);

    assert!(result.is_valid, "{:?}", result.issues);
    assert_eq!(result.topological_order.len(), 4);
    assert_eq!(result.topological_order[0], "source");
    assert_eq!(result.estimated_stage_count, 4);
    assert!(create_template("SENTINEL-APP").is_ok());
    assert!(create_template("nope").is_err());
}

#[test]
fn validate_rejects_cycle_and_secrets() {
    let mut config = IndexMap::new();
    config.insert("apiKey".to_owned(), "super-secret".to_owned());
    let pipeline = TelemetryPipeline {
        id: "bad".to_owned(),
        name: "Bad".to_owned(),
        version: "1.0.0".to_owned(),
        description: "cycle".to_owned(),
        nodes: vec![
            PipelineNode::new("a", PipelineNodeKind::Source, "http-collector"),
            PipelineNode::new("b", PipelineNodeKind::Output, "http").with_config(config),
        ],
        edges: vec![PipelineEdge::new("a", "b"), PipelineEdge::new("b", "a")],
        tags: None,
    };

    let result = validate(&pipeline);

    assert!(!result.is_valid);
    assert!(result.issues.iter().any(|issue| issue.code == "cycle"));
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == "secret-in-config")
    );
}

#[test]
fn validate_reports_structure_problems() {
    let mut config = IndexMap::new();
    config.insert("Connection_String".to_owned(), "x".repeat(4_097));
    let pipeline = TelemetryPipeline {
        id: " ".to_owned(),
        name: String::new(),
        version: String::new(),
        description: String::new(),
        nodes: vec![
            PipelineNode::new("a", PipelineNodeKind::Source, "carrier-pigeon"),
            PipelineNode::new("a", PipelineNodeKind::Filter, "x"),
            PipelineNode::new("c", PipelineNodeKind::Output, "").with_config(config),
        ],
        edges: vec![PipelineEdge::new("a", "zzz"), PipelineEdge::new("c", "c")],
        tags: None,
    };

    let codes: Vec<String> = validate(&pipeline)
        .issues
        .into_iter()
        .map(|issue| issue.code)
        .collect();

    assert_eq!(
        codes,
        [
            "pipeline-id",
            "pipeline-name",
            "pipeline-version",
            "source-type",
            "node-id",
            "node-type",
            "output-type",
            "secret-in-config",
            "config-too-large",
            "edge-unknown-node",
            "edge-self",
        ]
    );
    assert_eq!(
        estimate(&pipeline).unwrap_err().to_string(),
        "Duplicate node id 'a'; no estimate."
    );
}

fn pipeline(nodes: Vec<PipelineNode>, edges: Vec<PipelineEdge>) -> TelemetryPipeline {
    TelemetryPipeline {
        id: "p".to_owned(),
        name: "P".to_owned(),
        version: "1".to_owned(),
        description: String::new(),
        nodes,
        edges,
        tags: None,
    }
}

#[test]
fn validate_flags_nodes_with_no_edges_and_explains_unknown_output_types() {
    let orphan = pipeline(
        vec![
            PipelineNode::new("s", PipelineNodeKind::Source, "http-collector"),
            PipelineNode::new("lonely", PipelineNodeKind::Enrich, "geo"),
            PipelineNode::new("o", PipelineNodeKind::Output, "azure-monitor"),
        ],
        vec![PipelineEdge::new("s", "o")],
    );
    let result = validate(&orphan);
    assert!(!result.is_valid);
    let issues: Vec<(&str, &str, Option<&str>)> = result
        .issues
        .iter()
        .map(|issue| {
            (
                issue.code.as_str(),
                issue.message.as_str(),
                issue.node_id.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        issues,
        [
            (
                "output-type",
                "Unknown output type 'azure-monitor'. Supported: azure-logs-ingestion, ama-spool, http, kafka, syslog, security-lake, opensearch.",
                Some("o")
            ),
            (
                "node-disconnected",
                "Node 'lonely' has no edges; connect it to the pipeline or remove it.",
                Some("lonely")
            ),
        ]
    );
    assert!(validate(&create_template("aws-security").unwrap()).is_valid);
}

#[test]
fn estimate_refuses_cycles_and_measures_longest_path_in_any_edge_order() {
    let cycle = pipeline(
        vec![
            PipelineNode::new("a", PipelineNodeKind::Source, "http-collector"),
            PipelineNode::new("b", PipelineNodeKind::Output, "http"),
        ],
        vec![PipelineEdge::new("a", "b"), PipelineEdge::new("b", "a")],
    );
    assert_eq!(
        estimate(&cycle).unwrap_err().to_string(),
        "Pipeline graph contains a cycle; no estimate."
    );

    // Edges listed back to front: a single pass would report depth 1.
    let chain = pipeline(
        vec![
            PipelineNode::new("a", PipelineNodeKind::Source, "http-collector"),
            PipelineNode::new("b", PipelineNodeKind::Redact, "privacy"),
            PipelineNode::new("c", PipelineNodeKind::Filter, "policy-engine"),
            PipelineNode::new("d", PipelineNodeKind::Output, "http"),
        ],
        vec![
            PipelineEdge::new("c", "d"),
            PipelineEdge::new("b", "c"),
            PipelineEdge::new("a", "b"),
            PipelineEdge::new("a", "zzz"),
        ],
    );
    let estimate = estimate(&chain).unwrap();
    assert_eq!(
        (
            estimate.node_count,
            estimate.edge_count,
            estimate.source_count,
            estimate.output_count,
            estimate.max_depth
        ),
        (4, 4, 1, 1, 3)
    );
}

#[test]
fn estimate_counts_sources_outputs_and_depth() {
    let estimate = estimate(&create_template("aws-security").unwrap()).unwrap();
    assert_eq!(
        (
            estimate.node_count,
            estimate.edge_count,
            estimate.source_count,
            estimate.output_count
        ),
        (6, 5, 2, 2)
    );
    assert_eq!(estimate.max_depth, 3);
}

#[test]
fn yaml_round_trips_template() {
    let original = create_template("aws-security").unwrap();
    let yaml = to_yaml(&original);
    let parsed = parse_yaml(&yaml).unwrap();

    assert_eq!(original.id, parsed.id);
    assert_eq!(original.nodes.len(), parsed.nodes.len());
    assert_eq!(original.edges.len(), parsed.edges.len());
    assert!(validate(&parsed).is_valid);
    assert_eq!(parsed, original);
}

#[test]
fn yaml_output_is_byte_identical_to_yamldotnet() {
    assert_eq!(
        to_yaml(&create_template("sentinel-app").unwrap()),
        fixture("sentinel-app.yaml")
    );
    assert_eq!(
        to_yaml(&create_template("aws-security").unwrap()),
        fixture("aws-security.yaml")
    );

    let mut config = IndexMap::new();
    config.insert("k".to_owned(), "v: w".to_owned());
    config.insert("n".to_owned(), "123".to_owned());
    config.insert("e".to_owned(), String::new());
    let quoted = TelemetryPipeline {
        id: "x: y".to_owned(),
        name: "Name with 'quote' and \"dq\"".to_owned(),
        version: "1.0".to_owned(),
        description: String::new(),
        nodes: vec![
            PipelineNode::new("a", PipelineNodeKind::Source, "http-collector").with_config(config),
        ],
        edges: vec![],
        tags: None,
    };
    assert_eq!(to_yaml(&quoted), fixture("quoted.yaml"));
}

#[test]
fn yaml_scalar_quoting_matches_yamldotnet() {
    let values = [
        "true",
        "null",
        "~",
        "-x",
        "- x",
        "a #b",
        "a#b",
        "a: b",
        "a:b",
        "  lead",
        "trail ",
        "multi\nline",
        "x\ty",
        "@at",
        "\u{e9}",
        "[x]",
        "#h",
        "!t",
        "&a",
        "*a",
        "|p",
        ">f",
        "%p",
        "`b",
        "?q",
        "? q",
        ":c",
        ": c",
        "---",
        "...",
        "-",
        "a,b",
        "{x}",
        "x'y",
        "\"q\"",
        "tab\t",
        "\u{1}ctl",
        "a  b",
        "x\r",
        "\u{a0}nb",
        "\u{feff}bom",
        "\u{1F600}",
        "a]",
        "1e3",
        "0x1F",
        ",lead",
        "\\back",
    ];
    let mut config = IndexMap::new();
    for (index, value) in values.iter().enumerate() {
        config.insert(format!("k{index:02}"), (*value).to_owned());
    }
    config.insert("- key".to_owned(), "v".to_owned());
    config.insert("key: x".to_owned(), "v".to_owned());
    config.insert(String::new(), "emptykey".to_owned());
    let pipeline = TelemetryPipeline {
        id: "id".to_owned(),
        name: "n".to_owned(),
        version: "v".to_owned(),
        description: "d".to_owned(),
        nodes: vec![PipelineNode::new("a", PipelineNodeKind::Source, "t").with_config(config)],
        edges: vec![PipelineEdge::new("a", "b")],
        tags: Some(vec!["x y".to_owned(), "-".to_owned()]),
    };

    assert_eq!(to_yaml(&pipeline), fixture("tricky.yaml"));
}

#[test]
fn yaml_long_and_multiline_scalars_match_yamldotnet() {
    let long = vec!["word"; 30].join(" ");
    let mut config = IndexMap::new();
    config.insert("single".to_owned(), format!("{long}: quoted"));
    config.insert("dq".to_owned(), format!("{long} \u{1} x"));
    config.insert("multi".to_owned(), format!("{long}\n{long}\n\nend"));
    config.insert("multi2".to_owned(), "a\n\n\nb\n".to_owned());
    config.insert("lead".to_owned(), " lead\nx".to_owned());
    let pipeline = TelemetryPipeline {
        id: "id".to_owned(),
        name: format!("{long}: quoted"),
        version: "1".to_owned(),
        description: long.clone(),
        nodes: vec![
            PipelineNode::new("a", PipelineNodeKind::Source, "t").with_config(config),
            PipelineNode::new("b", PipelineNodeKind::Output, "t").with_config(IndexMap::new()),
        ],
        edges: vec![],
        tags: Some(vec![]),
    };
    let empty = TelemetryPipeline {
        id: String::new(),
        name: String::new(),
        version: String::new(),
        description: String::new(),
        nodes: vec![],
        edges: vec![],
        tags: None,
    };

    let yaml = to_yaml(&pipeline);
    assert_eq!(format!("{yaml}{}", to_yaml(&empty)), fixture("wrap.yaml"));
    let parsed = parse_yaml(&yaml).unwrap();
    assert_eq!(parsed, pipeline);
}

#[test]
fn yaml_parse_reads_scalars_as_text_and_rejects_bad_documents() {
    let parsed = parse_yaml(
        "id: p\nname: n\nversion: 1.0\nunknown: ignored\nnodes:\n- id: a\n  kind: source\n  type: http-collector\n  config:\n    port: 4319\n",
    )
    .unwrap();
    assert_eq!(parsed.version, "1.0");
    assert_eq!(parsed.nodes[0].kind, PipelineNodeKind::Source);
    assert_eq!(parsed.nodes[0].config.as_ref().unwrap()["port"], "4319");

    assert!(parse_yaml("   ").is_err());
    assert!(parse_yaml("# only a comment\n").is_err());
    assert!(parse_yaml("nodes:\n- id: a\n  kind: teleport\n").is_err());
    assert!(parse_yaml("nodes:\n- id: a\n  kind: 99\n").is_err());
    assert!(parse_yaml("nodes:\n- id: a\n  kind: Source\n  config:\n    k: ~\n").is_err());
    assert!(parse_yaml(&format!("id: {}", "x".repeat(512 * 1024))).is_err());
}

fn regex_configuration(pattern: &str) -> CustomLogParserConfiguration {
    CustomLogParserConfiguration {
        version: "1.0".to_owned(),
        format: CustomLogFormat::Regex,
        fields: vec![CustomLogField {
            source_name: "value".to_owned(),
            value_type: CustomLogValueType::Text,
            ocsf_path: None,
            asim_field: None,
            sensitive: true,
        }],
        delimiter: None,
        key_value_separator: None,
        pattern: Some(pattern.to_owned()),
        runtime: None,
    }
}

#[test]
fn configuration_rejects_unsupported_regex_construct() {
    let issues = validate_configuration(&regex_configuration("^(?=x)(?<value>.*)$"));
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("non-backtracking"))
    );
    assert!(validate_configuration(&regex_configuration("^(?<value>.*)$")).is_empty());
    let missing = validate_configuration(&regex_configuration("^(?<other>.*)$"));
    assert_eq!(missing, ["Regex has no named capture for field 'value'."]);
}

#[test]
fn configuration_validation_reports_every_issue() {
    let field = |name: &str| CustomLogField {
        source_name: name.to_owned(),
        value_type: CustomLogValueType::Text,
        ocsf_path: None,
        asim_field: None,
        sensitive: false,
    };
    let configuration = CustomLogParserConfiguration {
        version: "2.0".to_owned(),
        format: CustomLogFormat::Csv,
        fields: vec![
            field("ok"),
            field("ok"),
            field("bad name"),
            field("user_password"),
        ],
        delimiter: Some("|".to_owned()),
        key_value_separator: None,
        pattern: None,
        runtime: None,
    };

    assert_eq!(
        validate_configuration(&configuration),
        [
            "Unsupported parser configuration version '2.0'.",
            "Duplicate source field name 'ok'.",
            "Invalid source field name 'bad name'.",
            "Prohibited source field name 'user_password'.",
            "CSV delimiter must be comma, tab or semicolon.",
        ]
    );
}

#[test]
fn pack_parser_configuration_reads_and_validates() {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs/linux-ssh-gateway/parsers/sshd-json.json"),
    )
    .unwrap();
    let configuration = CustomLogParserConfiguration::from_json(&text).unwrap();

    assert_eq!(configuration.format, CustomLogFormat::Json);
    assert_eq!(configuration.fields.len(), 4);
    assert_eq!(
        configuration.fields[2].value_type,
        CustomLogValueType::IpAddress
    );
    assert!(validate_configuration(&configuration).is_empty());

    let any_case = CustomLogParserConfiguration::from_json(
        r#"{"VERSION":"1.0","Format":"keyvalue","KeyValueSeparator":"=","Fields":[{"SourceName":"a","Type":3}]}"#,
    )
    .unwrap();
    assert_eq!(any_case.format, CustomLogFormat::KeyValue);
    assert_eq!(
        any_case.fields[0].value_type,
        CustomLogValueType::WholeNumber
    );
    assert!(validate_configuration(&any_case).is_empty());
    assert!(CustomLogParserConfiguration::from_json(r#"{"format":"Xml"}"#).is_err());
}

/// `fixtures/csharp-validation.txt` is C# `PipelineValidator.Validate`/`Estimate` output
/// (temporary xunit emitter, `TryEstimate` null as `error`) for both templates and four
/// broken pipelines: codes,
/// messages, node ids, topological order, stage counts and estimates.
#[test]
fn validation_and_estimates_match_csharp() {
    let node =
        |id: &str, kind: PipelineNodeKind, kind_type: &str| PipelineNode::new(id, kind, kind_type);
    let pipeline = |id: &str,
                    name: &str,
                    version: &str,
                    nodes: Vec<PipelineNode>,
                    edges: Vec<PipelineEdge>| TelemetryPipeline {
        id: id.to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
        description: String::new(),
        nodes,
        edges,
        tags: None,
    };
    let config = |key: &str, value: String| {
        let mut config = IndexMap::new();
        config.insert(key.to_owned(), value);
        config
    };
    let structure = pipeline(
        " ",
        "",
        "",
        vec![
            node("a", PipelineNodeKind::Source, "carrier-pigeon"),
            node("a", PipelineNodeKind::Filter, "x"),
            node("c", PipelineNodeKind::Output, "")
                .with_config(config("Connection_String", "x".repeat(4_097))),
        ],
        vec![PipelineEdge::new("a", "zzz"), PipelineEdge::new("c", "c")],
    );
    let cycle = pipeline(
        "bad",
        "Bad",
        "1.0.0",
        vec![
            node("a", PipelineNodeKind::Source, "http-collector"),
            node("b", PipelineNodeKind::Output, "http")
                .with_config(config("apiKey", "super-secret".to_owned())),
        ],
        vec![PipelineEdge::new("a", "b"), PipelineEdge::new("b", "a")],
    );
    let orphan = pipeline(
        "orphan",
        "Orphan",
        "1.0.0",
        vec![
            node("s", PipelineNodeKind::Source, "http-collector"),
            node("r", PipelineNodeKind::Redact, "privacy"),
            node("lonely", PipelineNodeKind::Enrich, "geo"),
            node("o", PipelineNodeKind::Output, "azure-monitor"),
        ],
        vec![PipelineEdge::new("s", "r"), PipelineEdge::new("r", "o")],
    );
    let no_output = pipeline(
        "n",
        "N",
        "1",
        vec![node("s", PipelineNodeKind::Source, "http-collector")],
        vec![],
    );

    let mut actual = Vec::new();
    for (name, pipeline) in [
        ("sentinel-app", create_template("sentinel-app").unwrap()),
        ("aws-security", create_template("aws-security").unwrap()),
        ("structure", structure),
        ("cycle", cycle),
        ("orphan", orphan),
        ("no-output", no_output),
    ] {
        let result = validate(&pipeline);
        let valid = if result.is_valid { "True" } else { "False" };
        actual.push(format!(
            "result|{name}|{valid}|{}|{}",
            result.topological_order.join(","),
            result.estimated_stage_count
        ));
        for issue in result.issues {
            actual.push(format!(
                "issue|{name}|{}|{}|{}",
                issue.code,
                issue.message,
                issue.node_id.as_deref().unwrap_or("<null>")
            ));
        }
        actual.push(match estimate(&pipeline) {
            Ok(estimate) => format!(
                "estimate|{name}|{}|{}|{}|{}|{}",
                estimate.node_count,
                estimate.edge_count,
                estimate.source_count,
                estimate.output_count,
                estimate.max_depth
            ),
            Err(_) => format!("estimate|{name}|error"),
        });
    }

    assert_eq!(
        actual,
        fixture("csharp-validation.txt").lines().collect::<Vec<_>>()
    );
}
