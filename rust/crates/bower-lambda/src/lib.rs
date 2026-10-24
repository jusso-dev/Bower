//! Bower AWS Lambda host: the collector's `/v1/events` contract over a Lambda
//! Function URL (`AuthType: AWS_IAM`) or direct `Invoke`, the same redaction and
//! default-deny policy pipeline, and delivery to AWS CloudTrail Lake with
//! `cloudtrail-data:PutAuditEvents` using only the execution role.
//!
//! There is no durable queue, ledger or heartbeat: an event is acknowledged only
//! after CloudTrail Lake accepted it, and the caller retries anything else.
//!
//! - [`settings`]: environment configuration, fail closed.
//! - [`principals`]: IAM caller ARN to producer mapping.
//! - [`capture`]: per-invocation in-memory stand-in for the queue.
//! - [`audit`]: envelope to CloudTrail Lake audit event mapping and batching.
//! - [`sink`]: the destination seam (`PutAuditEvents`).
//! - [`handler`]: invocation handling, unit-testable without AWS.
//! - [`aws`]: the real CloudTrail Lake and Secrets Manager clients.

pub mod audit;
pub mod aws;
pub mod capture;
pub mod handler;
pub mod principals;
pub mod settings;
pub mod sink;

pub use handler::{Handler, Invocation, InvocationKind};
pub use settings::{Ingress, LambdaSettings, SettingsError};
