//! Port of `Bower.Evidence`: query-verified delivery evidence for assessors.
//!
//! A synthetic canary goes through the real collector, then a Log Analytics query
//! under a separate read-only identity must return its row. Only that query makes a
//! bundle [`modes::VERIFIED`]; without a workspace the bundle is
//! [`modes::SIMULATED`] and says so in its limitations. Bundles are metadata only and
//! are signed over their canonical JSON with `bower-integrity`.

pub mod bundle;
pub mod clients;
pub mod controls;
pub mod runner;

pub use bundle::{
    ArrivalRecord, CURRENT_SCHEMA, CanaryRecord, ControlRecord, EvidenceBundle, RetentionRecord,
    SignedEvidence, modes,
};
pub use clients::{
    HttpArmReader, HttpCanarySender, LogAnalyticsQueryClient, default_http_client,
    verifier_credential,
};
pub use runner::{
    ArmReader, BoxFuture, CanarySender, CollectorResponse, EvidenceOptions, EvidenceRunner,
    LogAnalyticsQuery, QueryRows,
};

/// Evidence failures. Messages never carry tokens, payloads or response bodies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// C# `ArgumentException`.
    #[error("{0}")]
    InvalidArgument(String),
    /// C# `InvalidDataException` / `JsonException`.
    #[error("{0}")]
    InvalidData(String),
    /// Transport failure, worded like .NET `HttpRequestException` (for example
    /// `Connection refused (127.0.0.1:9)`). Host and port only; no paths or bodies.
    #[error("{0}")]
    Http(String),
    /// The verifier credential could not produce a token.
    #[error("credential: {0}")]
    Credential(String),
    /// Signing failed (bad or missing private key).
    #[error("signing failed: {0}")]
    Signing(String),
}
