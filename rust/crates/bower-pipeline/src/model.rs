//! Declarative pipeline graph model (`PipelineModels.cs`).

use indexmap::IndexMap;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PipelineNodeKind {
    Source,
    Filter,
    Redact,
    Normalise,
    Detect,
    Enrich,
    Output,
}

impl PipelineNodeKind {
    pub const ALL: [PipelineNodeKind; 7] = [
        Self::Source,
        Self::Filter,
        Self::Redact,
        Self::Normalise,
        Self::Detect,
        Self::Enrich,
        Self::Output,
    ];

    /// C# enum name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "Source",
            Self::Filter => "Filter",
            Self::Redact => "Redact",
            Self::Normalise => "Normalise",
            Self::Detect => "Detect",
            Self::Enrich => "Enrich",
            Self::Output => "Output",
        }
    }

    /// `Enum.TryParse(text, ignoreCase: true)` restricted to defined values: a name
    /// (case-insensitive, surrounding whitespace ignored) or a defined ordinal.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Some(kind) = Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str().eq_ignore_ascii_case(text))
        {
            return Some(kind);
        }
        text.parse::<usize>()
            .ok()
            .and_then(|index| Self::ALL.get(index).copied())
    }
}

impl std::fmt::Display for PipelineNodeKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineNode {
    pub id: String,
    pub kind: PipelineNodeKind,
    pub node_type: String,
    pub config: Option<IndexMap<String, String>>,
}

impl PipelineNode {
    pub fn new(
        id: impl Into<String>,
        kind: PipelineNodeKind,
        node_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            node_type: node_type.into(),
            config: None,
        }
    }

    pub fn with_config(mut self, config: IndexMap<String, String>) -> Self {
        self.config = Some(config);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineEdge {
    pub from: String,
    pub to: String,
}

impl PipelineEdge {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelemetryPipeline {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub nodes: Vec<PipelineNode>,
    pub edges: Vec<PipelineEdge>,
    pub tags: Option<Vec<String>>,
}

/// Serialized with the C# property names (PascalCase), as `JsonSerializer.Serialize`
/// writes it in `bower pipeline validate` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PipelineValidationIssue {
    pub code: String,
    pub message: String,
    pub node_id: Option<String>,
}

impl PipelineValidationIssue {
    pub fn new(code: &str, message: impl Into<String>, node_id: Option<&str>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            node_id: node_id.map(str::to_owned),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineValidationResult {
    pub is_valid: bool,
    pub issues: Vec<PipelineValidationIssue>,
    pub topological_order: Vec<String>,
    pub estimated_stage_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PipelinePerformanceEstimate {
    pub node_count: usize,
    pub edge_count: usize,
    pub source_count: usize,
    pub output_count: usize,
    pub max_depth: usize,
}
