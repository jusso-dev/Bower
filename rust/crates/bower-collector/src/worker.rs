//! Drains the durable queue into the configured output (C# `QueueDeliveryWorker`).
//!
//! A low-latency loop, never a scheduled job: delivery durability lives in the
//! queue's lease/acknowledgement state. Every leased event is settled exactly once
//! (delivered, retrying or dead-lettered), and the loop never exits on storage or
//! adapter errors.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::Clock;
use bower_contracts::{
    DeliveryFailure, DeliveryResult, DurableEventStore, FailureSettlement, OutputAdapter,
    QueuedEvent, StoreError, StoreResult,
};
use tracing::{error, info, warn};

use crate::shutdown::ShutdownToken;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueDeliveryOptions {
    pub batch_size: usize,
    pub lease_duration: Duration,
    pub idle_delay: Duration,
    pub error_delay: Duration,
    /// Retryable failures dead-letter once an event has been leased this many times.
    pub maximum_delivery_attempts: i32,
}

impl Default for QueueDeliveryOptions {
    fn default() -> Self {
        Self {
            batch_size: 500,
            lease_duration: Duration::from_secs(5 * 60),
            idle_delay: Duration::from_secs(1),
            error_delay: Duration::from_secs(5),
            maximum_delivery_attempts: 20,
        }
    }
}

/// Why one delivery pass stopped early.
#[derive(Debug)]
pub enum DeliveryError {
    Cancelled,
    Store(StoreError),
}

impl From<StoreError> for DeliveryError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// When the output last acknowledged an event, for the heartbeat (C# `DeliveryActivity`).
/// In memory, so `None` until the first acknowledgement after start-up.
#[derive(Default)]
pub struct DeliveryActivity {
    last: std::sync::Mutex<Option<bower_contracts::time::Timestamp>>,
}

impl DeliveryActivity {
    pub fn last_successful_delivery_at(&self) -> Option<bower_contracts::time::Timestamp> {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn record_delivery(&self, at: bower_contracts::time::Timestamp) {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(at);
    }
}

pub struct QueueDeliveryWorker<O> {
    queue: Arc<dyn DurableEventStore>,
    output: Arc<O>,
    clock: Arc<dyn Clock>,
    options: QueueDeliveryOptions,
    activity: Option<Arc<DeliveryActivity>>,
}

impl<O: OutputAdapter + 'static> QueueDeliveryWorker<O> {
    pub fn new(
        queue: Arc<dyn DurableEventStore>,
        output: Arc<O>,
        clock: Arc<dyn Clock>,
        options: QueueDeliveryOptions,
    ) -> Self {
        Self {
            queue,
            output,
            clock,
            options,
            activity: None,
        }
    }

    /// Records each acknowledged batch for the heartbeat's last successful delivery.
    pub fn with_activity(mut self, activity: Arc<DeliveryActivity>) -> Self {
        self.activity = Some(activity);
        self
    }

    /// Runs until `shutdown` is cancelled (C# `ExecuteAsync`).
    pub async fn run(&self, shutdown: ShutdownToken) {
        while !shutdown.is_cancelled() {
            match self.deliver_once(&shutdown).await {
                Ok(0) => {
                    shutdown.sleep(self.options.idle_delay).await;
                }
                Ok(_) => {}
                Err(DeliveryError::Cancelled) => break,
                Err(DeliveryError::Store(failure)) => {
                    // Storage errors (for example SQLITE_BUSY) must not stop collection.
                    // Leased events stay leased and are reclaimed when the lease expires.
                    error!(
                        failure_type = store_error_name(&failure),
                        "Delivery loop failed; retrying after back-off."
                    );
                    shutdown.sleep(self.options.error_delay).await;
                }
            }
        }
    }

    /// Leases one batch, delivers it and settles every leased event exactly once.
    pub async fn deliver_once(&self, shutdown: &ShutdownToken) -> Result<usize, DeliveryError> {
        let batch = self.options.batch_size;
        let lease = self.options.lease_duration;
        let events = self
            .blocking(move |queue| queue.lease(batch, lease), shutdown)
            .await?;
        if events.is_empty() {
            return Ok(0);
        }

        let claims: std::collections::HashMap<String, String> = events
            .iter()
            .filter_map(|item| {
                item.lease_token
                    .as_ref()
                    .map(|token| (item.event_id.clone(), token.clone()))
            })
            .collect();
        let failure_claims = claims.clone();
        let count = events.len();
        let order: Vec<String> = events.iter().map(|item| item.event_id.clone()).collect();
        let leased: HashMap<String, i32> = events
            .iter()
            .map(|item| (item.event_id.clone(), item.delivery_attempts))
            .collect();
        let mut settled: HashSet<String> = HashSet::with_capacity(count);
        let output_id = self.output.id().to_string();

        let result = self.deliver(events, &order, shutdown).await?;

        let acknowledgement = result
            .destination_acknowledgement
            .clone()
            .unwrap_or_else(|| format!("adapter:{output_id}:acknowledged"));
        let mut delivered = Vec::with_capacity(result.acknowledged_event_ids.len());
        for event_id in &result.acknowledged_event_ids {
            if !leased.contains_key(event_id) || !settled.insert(event_id.clone()) {
                warn!(
                    output_id,
                    "Output adapter returned a result for an unknown, duplicate or missing event."
                );
                continue;
            }
            delivered.push(event_id.clone());
        }

        if !delivered.is_empty() {
            let count = delivered.len();
            // One queue transaction for every acknowledged event in the batch.
            let reclaimed = self
                .blocking(
                    move |queue| queue.mark_delivered_batch(&delivered, &acknowledgement, &claims),
                    shutdown,
                )
                .await?;
            self.log_stale_leases(reclaimed.len());
            if reclaimed.len() < count
                && let Some(activity) = &self.activity
            {
                activity.record_delivery(self.clock.utc_now());
            }
        }

        let mut failed = Vec::new();
        for failure in &result.failures {
            let Some(&attempts) = leased.get(&failure.event_id) else {
                warn!(
                    output_id,
                    "Output adapter returned a result for an unknown, duplicate or missing event."
                );
                continue;
            };
            if !settled.insert(failure.event_id.clone()) {
                warn!(
                    output_id,
                    "Output adapter returned a result for an unknown, duplicate or missing event."
                );
                continue;
            }
            failed.push(self.to_settlement(attempts, failure.clone()));
        }

        // An adapter that neither acknowledged nor failed an event broke its contract;
        // retry rather than leave the event leased until the lease expires.
        for event_id in order.iter().filter(|id| !settled.contains(*id)) {
            warn!(
                output_id,
                "Output adapter returned a result for an unknown, duplicate or missing event."
            );
            let failure = DeliveryFailure {
                event_id: event_id.clone(),
                code: "output-result-missing".into(),
                is_retryable: true,
                retry_after: None,
            };
            failed.push(self.to_settlement(leased[event_id], failure));
        }

        for failure in &mut failed {
            failure.lease_token = failure_claims.get(&failure.event_id).cloned();
        }
        if !failed.is_empty() {
            // One queue transaction for every retrying and dead-lettered event in the
            // batch. On error nothing is settled and the events are redelivered after
            // the lease expires.
            let reclaimed = self
                .blocking(move |queue| queue.mark_failed_batch(&failed), shutdown)
                .await?;
            self.log_stale_leases(reclaimed.len());
        }

        Ok(count)
    }

    fn log_stale_leases(&self, count: usize) {
        for _ in 0..count {
            // The lease expired and the event was reclaimed; the newer lease owns it now.
            info!(
                output_id = self.output.id(),
                "Output adapter settled an event whose lease had already expired."
            );
        }
    }

    /// Runs the adapter on its own task so a panicking adapter fails the batch
    /// (retryable) instead of killing the loop, and cancellation aborts it.
    async fn deliver(
        &self,
        events: Vec<QueuedEvent>,
        order: &[String],
        shutdown: &ShutdownToken,
    ) -> Result<DeliveryResult, DeliveryError> {
        let output = Arc::clone(&self.output);
        let mut task = tokio::spawn(async move { output.deliver(&events).await });
        let joined = tokio::select! {
            joined = &mut task => joined,
            () = shutdown.cancelled() => {
                task.abort();
                return Err(DeliveryError::Cancelled);
            }
        };
        Ok(joined.unwrap_or_else(|_| {
            warn!(
                output_id = self.output.id(),
                failure_type = "panic",
                "Output adapter failed; batch will retry."
            );
            DeliveryResult {
                acknowledged_event_ids: Vec::new(),
                failures: order
                    .iter()
                    .map(|event_id| DeliveryFailure {
                        event_id: event_id.clone(),
                        code: "output-adapter-failure".into(),
                        is_retryable: true,
                        retry_after: None,
                    })
                    .collect(),
                destination_acknowledgement: None,
            }
        }))
    }

    /// C# `ToSettlement`: dead-letter permanent failures and exhausted retries,
    /// otherwise schedule a retry.
    fn to_settlement(&self, attempts: i32, failure: DeliveryFailure) -> FailureSettlement {
        let destination = failure.is_destination_failure();
        let DeliveryFailure {
            event_id,
            code,
            is_retryable,
            retry_after,
        } = failure;
        if !is_retryable {
            return FailureSettlement {
                lease_token: None,
                event_id,
                failure_code: code,
                retry_after: None,
            };
        }

        if !destination && attempts >= self.options.maximum_delivery_attempts {
            warn!(
                output_id = self.output.id(),
                attempts, "Output adapter exhausted delivery attempts; event dead-lettered."
            );
            return FailureSettlement {
                lease_token: None,
                event_id,
                failure_code: format!("max-attempts-exceeded:{code}"),
                retry_after: None,
            };
        }

        let delay = if destination {
            Duration::from_secs(30)
        } else {
            calculate_retry_delay(attempts)
        };
        let local = self.clock.utc_now()
            + chrono::TimeDelta::from_std(delay).unwrap_or(chrono::TimeDelta::MAX);
        let requested = retry_after.map_or(local, |server| server.max(local));
        let maximum = self.clock.utc_now() + chrono::TimeDelta::hours(1);
        let code = if requested > maximum {
            warn!(
                output_id = self.output.id(),
                "Retry deadline exceeded one hour and was capped."
            );
            format!("{code}:retry-after-capped")
        } else {
            code
        };
        let retry_at = requested.min(maximum);
        FailureSettlement {
            lease_token: None,
            event_id,
            failure_code: code,
            retry_after: Some(retry_at),
        }
    }

    /// Runs a synchronous store call off the async runtime. A started call always
    /// completes (it is not abandoned mid-transaction); cancellation is checked first.
    async fn blocking<T: Send + 'static>(
        &self,
        call: impl FnOnce(&dyn DurableEventStore) -> StoreResult<T> + Send + 'static,
        shutdown: &ShutdownToken,
    ) -> Result<T, DeliveryError> {
        if shutdown.is_cancelled() {
            return Err(DeliveryError::Cancelled);
        }
        let queue = Arc::clone(&self.queue);
        tokio::task::spawn_blocking(move || call(queue.as_ref()))
            .await
            .unwrap_or_else(|_| Err(StoreError::Storage("queue call panicked".into())))
            .map_err(DeliveryError::Store)
    }
}

/// Exponential back-off: `min(300, 2^min(attempt, 8))` seconds plus up to
/// `min(10, 20%)` seconds of jitter.
pub fn calculate_retry_delay(attempt: i32) -> Duration {
    let exponent = attempt.clamp(i32::MIN, 8);
    let seconds = 2f64.powi(exponent).min(300.0);
    let jitter = random_unit() * (seconds * 0.2).min(10.0);
    Duration::from_secs_f64(seconds + jitter)
}

/// Uniform `[0, 1)` from the OS random source (via UUID v4), like `Random.Shared`.
pub(crate) fn random_unit() -> f64 {
    let bits = uuid::Uuid::new_v4().as_u128() as u64 >> 11;
    bits as f64 / (1u64 << 53) as f64
}

pub(crate) fn store_error_name(error: &StoreError) -> &'static str {
    match error {
        StoreError::Storage(_) => "StorageException",
        StoreError::Full(_) => "QueueCapacityExceededException",
        StoreError::Invalid(_) => "InvalidQueueTransitionException",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_bounded() {
        for attempt in [0, 1, 4, 8, 20, 1000] {
            let delay = calculate_retry_delay(attempt).as_secs_f64();
            let base = 2f64.powi(attempt.min(8)).min(300.0);
            assert!(delay >= base && delay <= base + 10.0, "{attempt}: {delay}");
        }
        assert!(calculate_retry_delay(8).as_secs_f64() <= 266.0);
    }
}
