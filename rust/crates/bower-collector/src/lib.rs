//! Bower collector host (C# `Bower.Collector`): settings, ingest authentication,
//! HTTP endpoints, the queue delivery worker and recurring maintenance jobs.

pub mod app;
pub mod auth;
pub mod authorization;
pub mod bundle;
mod conflicts;
pub mod credential;
pub mod enrolment;
pub mod error;
pub mod heartbeat;
pub mod host;
pub mod jobs;
pub mod logging;
pub mod managed_privacy;
pub mod management_commands;
pub mod management_http;
pub mod rate_limit;
pub mod relay;
pub mod server;
pub mod settings;
pub mod shutdown;
pub mod source_health;
pub mod startup;
pub mod suppression_worker;
pub mod syslog;
pub mod tap;
pub mod tap_http;
pub mod worker;

pub use error::HostError;
pub use settings::{AzureCredentialMode, CollectorSettings};
