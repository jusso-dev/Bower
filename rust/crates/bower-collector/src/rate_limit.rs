//! Ingest token bucket (ASP.NET `TokenBucketRateLimiter` as configured by the C#
//! host): `TokenLimit = rps * 2`, `TokensPerPeriod = rps`, one second period,
//! `QueueLimit = 0` so excess requests are rejected immediately with 429.

use std::sync::Mutex;
use std::time::{Duration, Instant};

const PERIOD: Duration = Duration::from_secs(1);

pub struct TokenBucket {
    limit: u64,
    per_period: u64,
    state: Mutex<(u64, Instant)>,
}

impl TokenBucket {
    pub fn new(requests_per_second: u32) -> Self {
        let per_period = u64::from(requests_per_second.max(1));
        let limit = per_period * 2;
        Self {
            limit,
            per_period,
            state: Mutex::new((limit, Instant::now())),
        }
    }

    /// Takes one token; `false` means reject with 429.
    pub fn try_acquire(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tokens, last) = &mut *state;
        // Auto-replenishment adds whole periods' worth of tokens, capped at the limit.
        let periods = (last.elapsed().as_nanos() / PERIOD.as_nanos()) as u64;
        if periods > 0 {
            *tokens = (*tokens)
                .saturating_add(periods.saturating_mul(self.per_period))
                .min(self.limit);
            *last += PERIOD * u32::try_from(periods).unwrap_or(u32::MAX);
        }
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_of_twice_the_rate() {
        let bucket = TokenBucket::new(1);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }
}
