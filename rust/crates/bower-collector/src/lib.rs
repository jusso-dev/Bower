//! Bower collector host (C# `Bower.Collector`): settings, ingest authentication,
//! HTTP endpoints, the queue delivery worker and recurring maintenance jobs.

pub mod app;
pub mod auth;
pub mod authorization;
pub mod bundle;
mod conflicts;
pub mod credential;
pub mod error;
pub mod heartbeat;
pub mod host;
pub mod jobs;
pub mod logging;
pub mod managed_privacy;
pub mod rate_limit;
pub mod server;
pub mod settings;
pub mod shutdown;
pub mod source_health;
pub mod suppression_worker;
pub mod worker;

pub use error::HostError;
pub use settings::{AzureCredentialMode, CollectorSettings};
