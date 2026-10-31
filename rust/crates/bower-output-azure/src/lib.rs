//! Azure Monitor Logs Ingestion output (port of `Bower.Output.AzureLogsIngestion`)
//! and the Microsoft Entra credential sources the collector supports
//! (`AzureCredentialFactory`).
//!
//! Uses the supported Logs Ingestion REST API directly. Tokens are cached in memory
//! only and never logged or persisted.

pub mod concurrency;
pub mod credential;
mod output;

pub use concurrency::{AdaptiveConcurrencyController, ConcurrencyPermit, ConcurrencySignal};
pub use credential::{
    AccessToken, AzureCliCredential, AzureCredentialMode, CachedTokenProvider,
    EnvironmentCredential, ManagedIdentityCredential, ManagedIdentitySource, TokenError,
    TokenFuture, TokenProvider, WorkloadIdentityCredential, WorkloadIdentitySettings,
    credential_from_mode,
};
pub use output::{
    API_VERSION, AzureLogsIngestionOptions, AzureLogsIngestionOutput, AzureOutputError,
    CREDENTIAL_FAILED_CODE, ConcurrencyScope, IngestionClientOptions, MONITOR_SCOPE,
    SINGLE_UPLOAD_THRESHOLD, SystemTimeSource, TimeSource,
};
