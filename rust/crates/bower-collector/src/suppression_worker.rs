//! Closes ended suppression windows and queues their summaries (C#
//! `SuppressionWindowWorker`). A hosted loop beside the delivery worker rather than a
//! scheduled job: it writes queue state, and suppressed counts must reach the SIEM
//! promptly even after the noisy source goes quiet.

use std::time::Duration;

use bower_core::{CollectorIdentity, SecurityEventProcessor, SuppressionCloseError};
use tracing::{info, warn};

use crate::shutdown::ShutdownToken;
use crate::worker::store_error_name;

pub const INTERVAL: Duration = Duration::from_secs(5);

/// One close pass on the blocking pool. Windows stay durable on any failure.
pub async fn close_once(
    processor: &SecurityEventProcessor,
    identity: &CollectorIdentity,
) -> Result<usize, &'static str> {
    let (processor, identity) = (processor.clone(), identity.clone());
    match tokio::task::spawn_blocking(move || processor.close_suppression_windows(&identity)).await
    {
        Ok(Ok(count)) => Ok(count),
        Ok(Err(SuppressionCloseError::Rejected { .. })) => {
            Err("SuppressionSummaryRejectedException")
        }
        Ok(Err(SuppressionCloseError::Store(error))) => Err(store_error_name(&error)),
        Err(_) => Err("JoinError"),
    }
}

/// Runs until `shutdown` (C# `ExecuteAsync`).
pub async fn run(
    processor: SecurityEventProcessor,
    identity: CollectorIdentity,
    shutdown: ShutdownToken,
) {
    while !shutdown.is_cancelled() {
        let outcome = tokio::select! {
            outcome = close_once(&processor, &identity) => outcome,
            () = shutdown.cancelled() => break,
        };
        match outcome {
            Ok(0) => {}
            Ok(count) => info!(count, "Queued {count} suppression summary event(s)."),
            // Windows stay durable and are retried; a full queue or a rejected summary
            // must never stop collection.
            Err(exception_type) => warn!(
                exception_type,
                "Closing suppression windows failed with {exception_type}; windows remain and will be retried."
            ),
        }
        if !shutdown.sleep(INTERVAL).await {
            break;
        }
    }
}
