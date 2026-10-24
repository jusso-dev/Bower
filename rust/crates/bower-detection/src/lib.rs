//! Port of `Bower.Detection`: Sigma-compatible rule loading and a deterministic,
//! bounded matcher. Rules are declarative only; nothing in a rule is executed.
//! MITRE tags and the rule version identity (`rule_hash`) travel with every alert.

pub mod engine;
pub mod loader;
pub mod model;
mod ordinal;
mod semantics;
pub mod yaml_node;

pub use engine::DetectionEngine;
pub use loader::{load_directory, load_file, load_yaml};
pub use model::{DetectionAlert, DetectionEvaluationResult, DetectionFields, DetectionRule};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectionError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    InvalidData(String),
    #[error("{0}")]
    Io(String),
}
