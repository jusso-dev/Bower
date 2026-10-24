//! Bower AWS Lambda host: the collector's `/v1/events` contract over a Lambda
//! Function URL (`AuthType: AWS_IAM`) or direct `Invoke`, the same redaction and
//! default-deny policy pipeline, and delivery with only the execution role to
//! Amazon CloudWatch Logs (`logs:PutLogEvents`) or AWS CloudTrail Lake
//! (`cloudtrail-data:PutAuditEvents`).
//!
//! There is no durable queue, ledger or heartbeat: an event is acknowledged only
//! after the destination accepted it, and the caller retries anything else.
//!
//! - [`settings`]: environment configuration, fail closed.
//! - [`principals`]: IAM caller ARN to producer mapping.
//! - [`capture`]: per-invocation in-memory stand-in for the queue (`bower-core`).
//! - [`audit`]: envelope to log event or audit event mapping and batching.
//! - [`sink`]: the destination seam (`PutLogEvents` or `PutAuditEvents`).
//! - [`handler`]: invocation handling, unit-testable without AWS.
//! - [`aws`]: the real CloudWatch Logs, CloudTrail Lake and Secrets Manager clients.

pub mod audit;
pub mod aws;
pub use bower_core::capture;
pub mod handler;
pub mod principals;
pub mod settings;
pub mod sink;

pub use handler::{Handler, Invocation, InvocationKind};
pub use settings::{Destination, Ingress, LambdaSettings, SettingsError};
