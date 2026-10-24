//! Destination seam: one `PutLogEvents` or `PutAuditEvents` call. The handler is
//! generic over it so tests use a fake without AWS; `crate::aws::CloudWatchLogsSink`
//! and `crate::aws::CloudTrailLakeSink` are the real ones.

use std::future::Future;

use crate::audit::{AuditRecord, RecordFormat};

/// An event the destination accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedEvent {
    pub id: String,
    /// CloudTrail's `eventID` for the stored event. CloudWatch Logs returns none.
    pub event_id: Option<String>,
}

/// An event the destination refused (CloudTrail Lake `ResultErrorEntry`, or a
/// CloudWatch Logs `rejectedLogEventsInfo` range). The message is dropped: it is not
/// needed to decide on a retry and may echo event content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedEvent {
    pub id: String,
    pub error_code: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PutResult {
    pub successful: Vec<AcceptedEvent>,
    pub failed: Vec<RefusedEvent>,
}

/// The whole call failed (network, throttling after SDK retries, access denied,
/// unknown channel). Every event in the call is retryable. `code` is an AWS error
/// code or a fixed transport label, never a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkFailure {
    pub code: String,
}

impl SinkFailure {
    pub fn new(code: impl Into<String>) -> Self {
        let code: String = code.into();
        // Codes are short identifiers; keep only that shape.
        let code: String = code
            .chars()
            .filter(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
            .take(128)
            .collect();
        Self {
            code: if code.is_empty() {
                "unknown".into()
            } else {
                code
            },
        }
    }
}

pub trait AuditSink: Send + Sync {
    /// The record shape this destination takes; the handler maps and batches with it.
    fn format(&self) -> RecordFormat;

    /// Sends one batch from [`crate::audit::batches`] for [`Self::format`].
    fn put_audit_events(
        &self,
        records: &[&AuditRecord],
    ) -> impl Future<Output = Result<PutResult, SinkFailure>> + Send;
}

/// `ResultErrorEntry.errorCode` values that resending the same event cannot fix.
/// Everything else (`Throttling`, `InternalFailure`, `AccountNotSubscribed`, codes
/// added later, and CloudWatch Logs timestamp rejections, which a retry restamps) is
/// retryable, so an unknown code never loses an event.
pub fn is_retryable(error_code: &str) -> bool {
    !matches!(
        error_code,
        "FieldTooLong"
            | "FieldNotFound"
            | "InvalidChecksum"
            | "InvalidData"
            | "InvalidRecipient"
            | "InvalidEventSource"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_codes_and_sanitises_failures() {
        assert!(is_retryable("Throttling"));
        assert!(is_retryable("InternalFailure"));
        assert!(is_retryable("SomethingNew"));
        assert!(!is_retryable("InvalidData"));
        assert!(!is_retryable("FieldTooLong"));
        assert_eq!(SinkFailure::new("Access Denied: <x>").code, "AccessDeniedx");
        assert_eq!(SinkFailure::new("").code, "unknown");
    }
}
