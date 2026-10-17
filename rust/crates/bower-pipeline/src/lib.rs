//! Port of `Bower.Pipeline`: declarative pipeline documents (model, YAML import and
//! export, templates, validation) and custom log parser configuration validation.
//!
//! Pipeline documents are declarative graphs only. Validation rejects cycles, unknown
//! node kinds, unbounded fan-out and secret material in node config.

pub mod custom_log;
pub mod document;
pub mod model;
pub mod validator;
mod yaml_emit;

pub use custom_log::{
    CustomLogField, CustomLogFormat, CustomLogParserConfiguration, CustomLogValueType,
    validate_configuration,
};
pub use document::{parse_yaml, to_yaml};
pub use model::{
    PipelineEdge, PipelineNode, PipelineNodeKind, PipelinePerformanceEstimate,
    PipelineValidationIssue, PipelineValidationResult, TelemetryPipeline,
};
pub use validator::{create_template, estimate, validate};

/// Failures that C# reports with `ArgumentException` or `InvalidDataException`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipelineError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    InvalidData(String),
}
