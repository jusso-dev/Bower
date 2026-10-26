//! Port of `AdaptiveConcurrencyController`: AIMD request concurrency for one DCR
//! stream (one output).
//!
//! Starts at the configured maximum, so the healthy case is never slower than the
//! fixed setting. Halves the limit on 429, 5xx, 408 and transport failures; cuts it by
//! a quarter when an RTT exceeds twice the EWMA by at least
//! [`LATENCY_SPIKE_FLOOR_MILLISECONDS`]; adds one slot after `limit` consecutive
//! healthy attempts. One decrease per window: attempts started before the last
//! decrease cannot decrease (or grow) it again. Deterministic: no clock or randomness
//! inside; callers pass RTT and time. Waiting for a slot is the back-pressure: nothing
//! is buffered beyond the leased batch, which stays durable in the queue.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bower_contracts::OutputConcurrencySnapshot;
use bower_contracts::time::Timestamp;
use tokio::sync::Notify;

use crate::output::AzureOutputError;

pub const MINIMUM_LIMIT: usize = 1;
/// Same ceiling as `AzureLogsIngestionOptions::maximum_concurrency`.
pub const MAXIMUM_ALLOWED_LIMIT: usize = 32;
/// Latency spikes are only judged once the EWMA has this many samples.
pub const LATENCY_SAMPLES_BEFORE_SPIKES: i64 = 4;
/// Absolute RTT rise needed for a spike, so jitter on fast links is not congestion.
pub const LATENCY_SPIKE_FLOOR_MILLISECONDS: f64 = 250.0;
const EWMA_WEIGHT: f64 = 0.25;

/// Capacity signal from one upload attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConcurrencySignal {
    /// 2xx: the RTT feeds the EWMA and may grow the limit.
    Healthy,
    /// Other 4xx: not a capacity signal.
    Neutral,
    /// 429.
    Throttled,
    /// 5xx.
    ServerError,
    /// 408, network timeout or transport failure.
    Timeout,
}

impl ConcurrencySignal {
    /// C# `AdaptiveConcurrencyController.Classify`; `0` is no HTTP response.
    pub fn classify(status: u16) -> Self {
        match status {
            200..=299 => Self::Healthy,
            429 => Self::Throttled,
            0 | 408 => Self::Timeout,
            500..=599 => Self::ServerError,
            _ => Self::Neutral,
        }
    }
}

#[derive(Default)]
struct State {
    limit: usize,
    in_flight: usize,
    healthy: usize,
    generation: u64,
    ewma_milliseconds: f64,
    samples: i64,
    requests: i64,
    throttles: i64,
    server_errors: i64,
    timeouts: i64,
    latency_spikes: i64,
    decreases: i64,
    increases: i64,
    pauses: i64,
    paused_until: Option<Timestamp>,
}

impl State {
    fn decrease(&mut self, generation: u64, target: usize) {
        // Attempts from an earlier window already caused (or missed) their decrease.
        if generation != self.generation {
            return;
        }
        self.generation += 1;
        self.healthy = 0;
        let target = target.max(MINIMUM_LIMIT);
        if target < self.limit {
            self.limit = target;
            self.decreases += 1;
        }
    }
}

pub struct AdaptiveConcurrencyController {
    maximum_limit: usize,
    state: Mutex<State>,
    changed: Notify,
}

impl AdaptiveConcurrencyController {
    pub fn new(maximum_limit: usize) -> Result<Self, AzureOutputError> {
        if !(MINIMUM_LIMIT..=MAXIMUM_ALLOWED_LIMIT).contains(&maximum_limit) {
            return Err(AzureOutputError::Invalid(
                "maximum concurrency must be 1..=32".to_owned(),
            ));
        }
        Ok(Self {
            maximum_limit,
            state: Mutex::new(State {
                limit: maximum_limit,
                ..State::default()
            }),
            changed: Notify::new(),
        })
    }

    pub fn maximum_limit(&self) -> usize {
        self.maximum_limit
    }

    pub fn limit(&self) -> usize {
        self.lock().limit
    }

    /// Waits until fewer than `limit` requests are in flight. Drop-safe: a dropped
    /// wait takes no slot, a dropped permit releases its slot.
    pub async fn acquire(self: &Arc<Self>) -> ConcurrencyPermit {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock();
                if state.in_flight < state.limit {
                    state.in_flight += 1;
                    return ConcurrencyPermit(Arc::clone(self));
                }
            }
            notified.await;
        }
    }

    /// Window token for one attempt; pass it back to [`Self::complete`].
    pub fn begin_attempt(&self) -> u64 {
        self.lock().generation
    }

    pub fn complete(&self, generation: u64, signal: ConcurrencySignal, round_trip: Duration) {
        let mut state = self.lock();
        state.requests += 1;
        match signal {
            ConcurrencySignal::Throttled => {
                state.throttles += 1;
                let target = state.limit / 2;
                state.decrease(generation, target);
            }
            ConcurrencySignal::ServerError => {
                state.server_errors += 1;
                let target = state.limit / 2;
                state.decrease(generation, target);
            }
            ConcurrencySignal::Timeout => {
                state.timeouts += 1;
                let target = state.limit / 2;
                state.decrease(generation, target);
            }
            ConcurrencySignal::Healthy => {
                // Integer nanoseconds keep whole-millisecond inputs exact (C# TotalMilliseconds).
                let milliseconds = round_trip.as_nanos() as f64 / 1_000_000.0;
                let spike = state.samples >= LATENCY_SAMPLES_BEFORE_SPIKES
                    && milliseconds > state.ewma_milliseconds * 2.0
                    && milliseconds - state.ewma_milliseconds >= LATENCY_SPIKE_FLOOR_MILLISECONDS;
                state.ewma_milliseconds = if state.samples == 0 {
                    milliseconds
                } else {
                    state.ewma_milliseconds
                        + ((milliseconds - state.ewma_milliseconds) * EWMA_WEIGHT)
                };
                state.samples += 1;
                if spike {
                    state.latency_spikes += 1;
                    let target = state.limit * 3 / 4;
                    state.decrease(generation, target);
                } else if generation == state.generation {
                    state.healthy += 1;
                    if state.healthy >= state.limit {
                        state.healthy = 0;
                        if state.limit < self.maximum_limit {
                            state.limit += 1;
                            state.increases += 1;
                            drop(state);
                            self.changed.notify_waiters();
                        }
                    }
                }
            }
            ConcurrencySignal::Neutral => {}
        }
    }

    /// Records a server-requested pause (Retry-After). Extending one is not a new pause.
    pub fn pause(&self, until: Timestamp, now: Timestamp) {
        if until <= now {
            return;
        }
        let mut state = self.lock();
        if state.paused_until.is_none_or(|paused| paused <= now) {
            state.pauses += 1;
        }
        if state.paused_until.is_none_or(|paused| paused < until) {
            state.paused_until = Some(until);
        }
    }

    pub fn paused_until(&self, now: Timestamp) -> Option<Timestamp> {
        self.lock().paused_until.filter(|paused| *paused > now)
    }

    pub fn snapshot(&self, output_id: &str, now: Timestamp) -> OutputConcurrencySnapshot {
        let state = self.lock();
        let count = |value: usize| i32::try_from(value).unwrap_or(i32::MAX);
        OutputConcurrencySnapshot {
            output_id: output_id.to_owned(),
            limit: count(state.limit),
            minimum_limit: count(MINIMUM_LIMIT),
            maximum_limit: count(self.maximum_limit),
            in_flight: count(state.in_flight),
            latency_ewma_milliseconds: (state.samples > 0)
                .then(|| state.ewma_milliseconds.round() as i64),
            requests: state.requests,
            throttles: state.throttles,
            server_errors: state.server_errors,
            timeouts: state.timeouts,
            latency_spikes: state.latency_spikes,
            decreases: state.decreases,
            increases: state.increases,
            pauses: state.pauses,
            paused_until: state.paused_until.filter(|paused| *paused > now),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Counters stay usable after a panic elsewhere; every update is a single step.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One request slot; released on drop.
pub struct ConcurrencyPermit(Arc<AdaptiveConcurrencyController>);

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.0.lock().in_flight -= 1;
        self.0.changed.notify_waiters();
    }
}
