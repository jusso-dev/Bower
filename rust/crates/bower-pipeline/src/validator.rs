//! Pipeline validation, estimates and templates (`PipelineValidator`).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::PipelineError;
use crate::model::{
    PipelineEdge, PipelineNode, PipelineNodeKind, PipelinePerformanceEstimate,
    PipelineValidationIssue, PipelineValidationResult, TelemetryPipeline,
};

const ALLOWED_SOURCE_TYPES: &[&str] = &[
    "http-collector",
    "sqlserver",
    "aws-cloudtrail",
    "aws-guardduty",
    "aws-securityhub",
    "aws-cloudwatch",
    "file-tail",
    "ama-companion",
    "ec2-host",
];

// Azure Monitor / Sentinel delivery is the `azure-logs-ingestion` output (Logs
// Ingestion API). There is no separate `azure-monitor` output type.
const ALLOWED_OUTPUT_TYPES: &[&str] = &[
    "azure-logs-ingestion",
    "ama-spool",
    "http",
    "kafka",
    "syslog",
    "security-lake",
    "opensearch",
];

const SECRET_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "apikey",
    "connectionstring",
    "privatekey",
];

const MAXIMUM_NODES: usize = 64;
const MAXIMUM_ID_LENGTH: usize = 128;
const MAXIMUM_CONFIG_VALUE_LENGTH: usize = 4_096;

/// `StringComparison.OrdinalIgnoreCase`: per-character simple upper-case mapping.
pub(crate) fn eq_ordinal_ignore_case(left: &str, right: &str) -> bool {
    fn upper(character: char) -> char {
        let mut mapped = character.to_uppercase();
        match (mapped.next(), mapped.next()) {
            (Some(single), None) => single,
            _ => character,
        }
    }
    left.chars().map(upper).eq(right.chars().map(upper))
}

fn is_null_or_white_space(text: &str) -> bool {
    text.trim().is_empty()
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

pub fn validate(pipeline: &TelemetryPipeline) -> PipelineValidationResult {
    let mut issues = Vec::new();

    if is_null_or_white_space(&pipeline.id) || utf16_len(&pipeline.id) > MAXIMUM_ID_LENGTH {
        issues.push(PipelineValidationIssue::new(
            "pipeline-id",
            "Pipeline id is required and must be <= 128 chars.",
            None,
        ));
    }
    if is_null_or_white_space(&pipeline.name) {
        issues.push(PipelineValidationIssue::new(
            "pipeline-name",
            "Pipeline name is required.",
            None,
        ));
    }
    if is_null_or_white_space(&pipeline.version) {
        issues.push(PipelineValidationIssue::new(
            "pipeline-version",
            "Pipeline version is required.",
            None,
        ));
    }
    if pipeline.nodes.is_empty() {
        issues.push(PipelineValidationIssue::new(
            "nodes-empty",
            "Pipeline must contain at least one node.",
            None,
        ));
    }
    if pipeline.nodes.len() > MAXIMUM_NODES {
        issues.push(PipelineValidationIssue::new(
            "nodes-too-many",
            "Pipeline cannot exceed 64 nodes.",
            None,
        ));
    }

    let mut nodes: HashSet<&str> = HashSet::new();
    for node in &pipeline.nodes {
        if is_null_or_white_space(&node.id) || !nodes.insert(node.id.as_str()) {
            issues.push(PipelineValidationIssue::new(
                "node-id",
                "Node ids must be unique and non-empty.",
                Some(&node.id),
            ));
            continue;
        }
        validate_node(node, &mut issues);
    }

    for edge in &pipeline.edges {
        if !nodes.contains(edge.from.as_str()) || !nodes.contains(edge.to.as_str()) {
            issues.push(PipelineValidationIssue::new(
                "edge-unknown-node",
                format!(
                    "Edge '{}' -> '{}' references unknown node.",
                    edge.from, edge.to
                ),
                None,
            ));
        }
        if edge.from == edge.to {
            issues.push(PipelineValidationIssue::new(
                "edge-self",
                "Self-edges are not allowed.",
                Some(&edge.from),
            ));
        }
    }

    // A node with no edges is never reached and never delivers: flag it instead of
    // silently ignoring it. Duplicate and empty ids are reported above.
    let connected: HashSet<&str> = pipeline
        .edges
        .iter()
        .flat_map(|edge| [edge.from.as_str(), edge.to.as_str()])
        .collect();
    let mut reported: HashSet<&str> = HashSet::new();
    for node in &pipeline.nodes {
        if !is_null_or_white_space(&node.id)
            && !connected.contains(node.id.as_str())
            && reported.insert(node.id.as_str())
        {
            issues.push(PipelineValidationIssue::new(
                "node-disconnected",
                format!(
                    "Node '{}' has no edges; connect it to the pipeline or remove it.",
                    node.id
                ),
                Some(&node.id),
            ));
        }
    }

    let mut order = Vec::new();
    if nodes.len() == pipeline.nodes.len()
        && pipeline
            .edges
            .iter()
            .all(|edge| nodes.contains(edge.from.as_str()) && nodes.contains(edge.to.as_str()))
    {
        let edges: Vec<(&str, &str)> = pipeline
            .edges
            .iter()
            .map(|edge| (edge.from.as_str(), edge.to.as_str()))
            .collect();
        match topological_sort(&pipeline.nodes, &edges) {
            Ok(sorted) => order = sorted,
            Err((partial, cycle_node)) => {
                order = partial;
                issues.push(PipelineValidationIssue::new(
                    "cycle",
                    "Pipeline graph contains a cycle.",
                    Some(&cycle_node),
                ));
            }
        }
    }

    if !pipeline
        .nodes
        .iter()
        .any(|node| node.kind == PipelineNodeKind::Source)
    {
        issues.push(PipelineValidationIssue::new(
            "missing-source",
            "Pipeline needs at least one source node.",
            None,
        ));
    }
    if !pipeline
        .nodes
        .iter()
        .any(|node| node.kind == PipelineNodeKind::Output)
    {
        issues.push(PipelineValidationIssue::new(
            "missing-output",
            "Pipeline needs at least one output node.",
            None,
        ));
    }

    let stage_count = order.len();
    PipelineValidationResult {
        is_valid: issues.is_empty(),
        issues,
        topological_order: order,
        estimated_stage_count: stage_count,
    }
}

/// `PipelineValidator.Estimate`: counts and the longest path through the graph. Edges
/// that reference unknown nodes are ignored. Duplicate node ids are
/// `InvalidArgument`; a cyclic graph has no depth and is `InvalidData`.
pub fn estimate(
    pipeline: &TelemetryPipeline,
) -> Result<PipelinePerformanceEstimate, PipelineError> {
    let mut depth: HashMap<&str, usize> = HashMap::new();
    for node in &pipeline.nodes {
        if depth.insert(node.id.as_str(), 0).is_some() {
            return Err(PipelineError::InvalidArgument(format!(
                "Duplicate node id '{}'; no estimate.",
                node.id
            )));
        }
    }
    let edges: Vec<(&str, &str)> = pipeline
        .edges
        .iter()
        .filter(|edge| {
            depth.contains_key(edge.from.as_str()) && depth.contains_key(edge.to.as_str())
        })
        .map(|edge| (edge.from.as_str(), edge.to.as_str()))
        .collect();
    let order = topological_sort(&pipeline.nodes, &edges).map_err(|_| {
        PipelineError::InvalidData("Pipeline graph contains a cycle; no estimate.".to_owned())
    })?;

    // Longest path: relax each node's outgoing edges in topological order.
    for current in &order {
        let current_depth = depth[current.as_str()];
        for &(from, to) in &edges {
            if from == current {
                let next = depth.get_mut(to).expect("edges reference known nodes");
                *next = (*next).max(current_depth + 1);
            }
        }
    }

    Ok(PipelinePerformanceEstimate {
        node_count: pipeline.nodes.len(),
        edge_count: pipeline.edges.len(),
        source_count: pipeline
            .nodes
            .iter()
            .filter(|node| node.kind == PipelineNodeKind::Source)
            .count(),
        output_count: pipeline
            .nodes
            .iter()
            .filter(|node| node.kind == PipelineNodeKind::Output)
            .count(),
        max_depth: depth.values().copied().max().unwrap_or(0),
    })
}

/// Built-in templates: `sentinel-app` and `aws-security` (case-insensitive).
pub fn create_template(template_id: &str) -> Result<TelemetryPipeline, PipelineError> {
    match template_id.to_lowercase().as_str() {
        "sentinel-app" => Ok(TelemetryPipeline {
            id: "template-sentinel-app".to_owned(),
            name: "Application to Sentinel".to_owned(),
            version: "1.0.0".to_owned(),
            description: "HTTP collector \u{2192} redact \u{2192} policy filter \u{2192} Azure Logs Ingestion".to_owned(),
            nodes: vec![
                PipelineNode::new("source", PipelineNodeKind::Source, "http-collector"),
                PipelineNode::new("redact", PipelineNodeKind::Redact, "json-redactor"),
                PipelineNode::new("filter", PipelineNodeKind::Filter, "policy-engine"),
                PipelineNode::new("out", PipelineNodeKind::Output, "azure-logs-ingestion"),
            ],
            edges: vec![
                PipelineEdge::new("source", "redact"),
                PipelineEdge::new("redact", "filter"),
                PipelineEdge::new("filter", "out"),
            ],
            tags: Some(vec!["template".to_owned(), "sentinel".to_owned()]),
        }),
        "aws-security" => Ok(TelemetryPipeline {
            id: "template-aws-security".to_owned(),
            name: "AWS Security to multi-destination".to_owned(),
            version: "1.0.0".to_owned(),
            description: "AWS sources \u{2192} normalise \u{2192} detect \u{2192} dual output".to_owned(),
            nodes: vec![
                PipelineNode::new("cloudtrail", PipelineNodeKind::Source, "aws-cloudtrail"),
                PipelineNode::new("guardduty", PipelineNodeKind::Source, "aws-guardduty"),
                PipelineNode::new("normalise", PipelineNodeKind::Normalise, "ocsf"),
                PipelineNode::new("detect", PipelineNodeKind::Detect, "sigma"),
                PipelineNode::new("sentinel", PipelineNodeKind::Output, "azure-logs-ingestion"),
                PipelineNode::new("lake", PipelineNodeKind::Output, "security-lake"),
            ],
            edges: vec![
                PipelineEdge::new("cloudtrail", "normalise"),
                PipelineEdge::new("guardduty", "normalise"),
                PipelineEdge::new("normalise", "detect"),
                PipelineEdge::new("detect", "sentinel"),
                PipelineEdge::new("detect", "lake"),
            ],
            tags: Some(vec!["template".to_owned(), "aws".to_owned()]),
        }),
        _ => Err(PipelineError::InvalidArgument(format!("Unknown pipeline template '{template_id}'."))),
    }
}

fn validate_node(node: &PipelineNode, issues: &mut Vec<PipelineValidationIssue>) {
    if is_null_or_white_space(&node.node_type) {
        issues.push(PipelineValidationIssue::new(
            "node-type",
            "Node type is required.",
            Some(&node.id),
        ));
    }
    if node.kind == PipelineNodeKind::Source
        && !ALLOWED_SOURCE_TYPES
            .iter()
            .any(|allowed| eq_ordinal_ignore_case(allowed, &node.node_type))
    {
        issues.push(PipelineValidationIssue::new(
            "source-type",
            format!(
                "Unknown source type '{}'. Supported: {}.",
                node.node_type,
                ALLOWED_SOURCE_TYPES.join(", ")
            ),
            Some(&node.id),
        ));
    }
    if node.kind == PipelineNodeKind::Output
        && !ALLOWED_OUTPUT_TYPES
            .iter()
            .any(|allowed| eq_ordinal_ignore_case(allowed, &node.node_type))
    {
        issues.push(PipelineValidationIssue::new(
            "output-type",
            format!(
                "Unknown output type '{}'. Supported: {}.",
                node.node_type,
                ALLOWED_OUTPUT_TYPES.join(", ")
            ),
            Some(&node.id),
        ));
    }

    let Some(config) = &node.config else { return };
    for (key, value) in config {
        let normalized: String = key
            .chars()
            .filter(|character| character.is_alphanumeric())
            .collect();
        if SECRET_KEYS
            .iter()
            .any(|secret| eq_ordinal_ignore_case(secret, &normalized))
        {
            issues.push(PipelineValidationIssue::new(
                "secret-in-config",
                format!("Node config key '{key}' looks like a secret and is not allowed."),
                Some(&node.id),
            ));
        }
        if utf16_len(value) > MAXIMUM_CONFIG_VALUE_LENGTH {
            issues.push(PipelineValidationIssue::new(
                "config-too-large",
                format!("Config value for '{key}' exceeds 4 KiB."),
                Some(&node.id),
            ));
        }
    }
}

/// Kahn's algorithm in node order. On a cycle returns the partial order and the first
/// node (in node order) that still has incoming edges.
fn topological_sort(
    nodes: &[PipelineNode],
    edges: &[(&str, &str)],
) -> Result<Vec<String>, (Vec<String>, String)> {
    let index: HashMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(position, node)| (node.id.as_str(), position))
        .collect();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    let mut indegree = vec![0usize; nodes.len()];
    for &(from, to) in edges {
        let (from, to) = (index[from], index[to]);
        adjacency[from].push(to);
        indegree[to] += 1;
    }

    let mut queue: VecDeque<usize> = (0..nodes.len())
        .filter(|&position| indegree[position] == 0)
        .collect();
    let mut order = Vec::new();
    while let Some(current) = queue.pop_front() {
        order.push(nodes[current].id.clone());
        for &next in &adjacency[current] {
            indegree[next] -= 1;
            if indegree[next] == 0 {
                queue.push_back(next);
            }
        }
    }

    if order.len() != nodes.len() {
        let cycle = indegree
            .iter()
            .position(|&value| value > 0)
            .expect("a cycle leaves a positive indegree");
        return Err((order, nodes[cycle].id.clone()));
    }
    Ok(order)
}
