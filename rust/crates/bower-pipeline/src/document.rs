//! YAML import/export of pipeline documents (`PipelineDocument`). Pure: no I/O.

use indexmap::IndexMap;
use serde::Deserialize;

use crate::PipelineError;
use crate::model::{PipelineEdge, PipelineNode, PipelineNodeKind, TelemetryPipeline};
use crate::yaml_emit::Writer;

/// Documents above this size are rejected before parsing.
pub const MAXIMUM_DOCUMENT_BYTES: usize = 512 * 1024;

// Scalars are read as strings (`deserialize_str`), so `version: 1.0` stays "1.0"
// exactly as YamlDotNet reads it. Unknown properties are ignored.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct PipelineDto {
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    nodes: Option<Vec<NodeDto>>,
    edges: Option<Vec<EdgeDto>>,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct NodeDto {
    id: Option<String>,
    kind: Option<String>,
    #[serde(rename = "type")]
    node_type: Option<String>,
    config: Option<IndexMap<String, Option<String>>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct EdgeDto {
    from: Option<String>,
    to: Option<String>,
}

/// Parses a YAML pipeline document.
pub fn parse_yaml(yaml: &str) -> Result<TelemetryPipeline, PipelineError> {
    if yaml.trim().is_empty() {
        return Err(PipelineError::InvalidArgument(
            "The value cannot be an empty string or composed entirely of whitespace.".to_owned(),
        ));
    }
    if yaml.len() > MAXIMUM_DOCUMENT_BYTES {
        return Err(PipelineError::InvalidData(
            "Pipeline document exceeds 512 KiB.".to_owned(),
        ));
    }

    let dto: Option<PipelineDto> = serde_yaml_ng::from_str(yaml)
        .map_err(|error| PipelineError::InvalidData(error.to_string()))?;
    let dto =
        dto.ok_or_else(|| PipelineError::InvalidData("Pipeline document was empty.".to_owned()))?;

    let mut nodes = Vec::new();
    for node in dto.nodes.unwrap_or_default() {
        let kind_text = node.kind.unwrap_or_default();
        let kind = PipelineNodeKind::parse(&kind_text).ok_or_else(|| {
            PipelineError::InvalidData(format!(
                "Node '{}' has unknown kind '{kind_text}'. Supported: {}.",
                node.id.as_deref().unwrap_or_default(),
                PipelineNodeKind::supported()
            ))
        })?;
        let config = match node.config {
            None => None,
            Some(config) => {
                let mut values = IndexMap::new();
                for (key, value) in config {
                    // YamlDotNet stores null here and C# validation then fails with a
                    // NullReferenceException; reject it explicitly instead.
                    let value = value.ok_or_else(|| {
                        PipelineError::InvalidData(format!(
                            "Node config value for '{key}' is null."
                        ))
                    })?;
                    values.insert(key, value);
                }
                Some(values)
            }
        };
        nodes.push(PipelineNode {
            id: node.id.unwrap_or_default(),
            kind,
            node_type: node.node_type.unwrap_or_default(),
            config,
        });
    }

    let edges = dto
        .edges
        .unwrap_or_default()
        .into_iter()
        .map(|edge| PipelineEdge {
            from: edge.from.unwrap_or_default(),
            to: edge.to.unwrap_or_default(),
        })
        .collect();

    Ok(TelemetryPipeline {
        id: dto.id.unwrap_or_default(),
        name: dto.name.unwrap_or_default(),
        version: dto.version.unwrap_or_default(),
        description: dto.description.unwrap_or_default(),
        nodes,
        edges,
        tags: dto.tags,
    })
}

/// Writes YAML byte-identical to YamlDotNet's `SerializerBuilder` with camelCase names
/// and `OmitNull` (what `bower pipeline template` prints).
pub fn to_yaml(pipeline: &TelemetryPipeline) -> String {
    let mut writer = Writer::new();
    for (key, value) in [
        ("id", &pipeline.id),
        ("name", &pipeline.name),
        ("version", &pipeline.version),
        ("description", &pipeline.description),
    ] {
        writer.mapping_key(0, key);
        writer.value(0, value);
    }

    writer.mapping_key(0, "nodes");
    if pipeline.nodes.is_empty() {
        writer.flow_token("[]");
    }
    for node in &pipeline.nodes {
        writer.sequence_entry(0);
        writer.mapping_key(2, "id");
        writer.value(2, &node.id);
        writer.mapping_key(2, "kind");
        writer.value(2, node.kind.as_str());
        writer.mapping_key(2, "type");
        writer.value(2, &node.node_type);
        if let Some(config) = &node.config {
            writer.mapping_key(2, "config");
            if config.is_empty() {
                writer.flow_token("{}");
            }
            for (key, value) in config {
                writer.mapping_key(4, key);
                writer.value(4, value);
            }
        }
    }

    writer.mapping_key(0, "edges");
    if pipeline.edges.is_empty() {
        writer.flow_token("[]");
    }
    for edge in &pipeline.edges {
        writer.sequence_entry(0);
        writer.mapping_key(2, "from");
        writer.value(2, &edge.from);
        writer.mapping_key(2, "to");
        writer.value(2, &edge.to);
    }

    if let Some(tags) = &pipeline.tags {
        writer.mapping_key(0, "tags");
        if tags.is_empty() {
            writer.flow_token("[]");
        }
        for tag in tags {
            writer.sequence_entry(0);
            writer.value(0, tag);
        }
    }

    writer.end();
    writer.finish()
}
