//! Source-to-policy-to-queue orchestration (port of `Bower.Core`).
//!
//! Order is fixed: redact, deserialize, validate, evaluate policy, enqueue. The
//! processor depends only on the `bower-contracts` traits, so any redactor, policy
//! evaluator and durable store implementation plugs in.

pub mod capture;
pub mod fingerprint;
pub mod privacy;
mod processor;
pub mod source_expectations;
pub mod suppression;
pub mod telemetry;

pub use processor::{
    CollectorIdentity, ProcessError, ProcessingResult, ProcessingStage, SecurityEventProcessor,
    SourceKey, SuppressionCloseError,
};
pub use telemetry::{
    IntakeMetricsSnapshot, MAXIMUM_REDACTION_TYPES, OTHER_REDACTION_TYPE, PipelineMetricsRow,
    PipelineMetricsSnapshot, PipelineTelemetry, RedactionCount, RedactionSnapshot,
};

/// `Bower.Core.EventFingerprint.Create`.
pub use fingerprint::create as event_fingerprint;
