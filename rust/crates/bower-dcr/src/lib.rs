//! Port of `Bower.Dcr`: the Sentinel schema model, the DCR/table ARM template
//! generator, drift checks against deployed resources, ingestion preflight and the
//! offline DCR optimiser.
//!
//! [`SentinelSchema::default_schema`] is the single source of truth for the Bower
//! table. The Bicep template (`deploy/bicep/main.bicep`) and generated DCRs must stay
//! identical to it; generated JSON is byte-identical to the C# generator.

pub mod drift;
pub mod generator;
pub mod json_text;
pub mod optimiser;
pub mod preflight;
pub mod schema;

pub use drift::{DcrFinding, FindingLevel, MAXIMUM_TRANSFORM_LENGTH};
pub use generator::{
    DATA_COLLECTION_RULES_API_VERSION, DcrTemplateOptions, LOG_ANALYTICS_API_VERSION,
};
pub use optimiser::{DcrAssessmentReport, DcrDataSource, DcrDocument, DcrRecommendation};
pub use preflight::{MAXIMUM_FIELD_BYTES, MAXIMUM_RECORD_BYTES, PreflightIssue};
pub use schema::{SentinelSchema, StreamColumn, TableColumn};

/// Failures that C# reports with `ArgumentException` or `InvalidDataException`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DcrError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    InvalidData(String),
}
