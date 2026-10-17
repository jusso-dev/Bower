//! `bower pipeline validate|template` (C# `ValidatePipeline`, `PipelineTemplate`).

use std::path::Path;

use bower_pipeline::{PipelinePerformanceEstimate, PipelineValidationIssue};

use crate::cli::{PipelineTemplateArgs, PipelineValidateArgs};
use crate::output::Json;
use crate::support::{CliError, CliResult, read_text};

fn count(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn estimate_json(estimate: &PipelinePerformanceEstimate) -> Json {
    Json::object([
        ("NodeCount", count(estimate.node_count)),
        ("EdgeCount", count(estimate.edge_count)),
        ("SourceCount", count(estimate.source_count)),
        ("OutputCount", count(estimate.output_count)),
        ("MaxDepth", count(estimate.max_depth)),
    ])
}

fn issue_json(issue: &PipelineValidationIssue) -> Json {
    Json::object([
        ("Code", Json::str(issue.code.clone())),
        ("Message", Json::str(issue.message.clone())),
        ("NodeId", Json::opt_str(issue.node_id.clone())),
    ])
}

/// `bower pipeline validate --file PATH` (or the first non-option argument). Exit 2 when invalid.
pub fn validate(args: &PipelineValidateArgs) -> CliResult {
    let path = args.file.as_deref().or(args.path.as_deref());
    let Some(path) = path.filter(|path| !path.trim().is_empty() && Path::new(path).is_file())
    else {
        return Err(CliError::new(
            "Provide an existing pipeline file with --file PATH.",
        ));
    };
    let pipeline = bower_pipeline::parse_yaml(&read_text(path)?).map_err(CliError::from_display)?;
    let validation = bower_pipeline::validate(&pipeline);
    let estimate = bower_pipeline::estimate(&pipeline).map_err(CliError::from_display)?;
    let json = Json::object([
        ("valid", Json::Bool(validation.is_valid)),
        ("Id", Json::str(pipeline.id.clone())),
        ("Name", Json::str(pipeline.name.clone())),
        ("Version", Json::str(pipeline.version.clone())),
        (
            "order",
            Json::Array(
                validation
                    .topological_order
                    .iter()
                    .cloned()
                    .map(Json::Str)
                    .collect(),
            ),
        ),
        ("estimate", estimate_json(&estimate)),
        (
            "issues",
            Json::Array(validation.issues.iter().map(issue_json).collect()),
        ),
    ]);
    println!("{}", json.to_indented());
    Ok(if validation.is_valid { 0 } else { 2 })
}

/// `bower pipeline template [--id sentinel-app|aws-security]` (or the first non-option argument).
pub fn template(args: &PipelineTemplateArgs) -> CliResult {
    let id = args
        .id
        .as_deref()
        .or(args.template.as_deref())
        .unwrap_or("sentinel-app");
    let pipeline = bower_pipeline::create_template(id).map_err(CliError::from_display)?;
    println!("{}", bower_pipeline::to_yaml(&pipeline));
    Ok(0)
}
