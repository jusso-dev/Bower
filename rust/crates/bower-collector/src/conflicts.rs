//! Process-local counts. Only authenticated credential labels may become keys.
use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::Serialize;

pub(crate) const CONFLICT_REASON: &str = "event-identity-conflict";
pub(crate) const REMEDIATION: &str = "Preserve the upstream event without acknowledging or discarding it. Repair the producer's globally unique, retry-stable event ID mapping before retrying; do not automatically regenerate IDs.";
const MAXIMUM_PRODUCERS: usize = 1024;

#[derive(Default)]
pub(crate) struct EventIdentityConflicts(Mutex<Counts>);

#[derive(Default)]
struct Counts {
    producers: BTreeMap<String, i64>,
    unattributed: i64,
    overflow: i64,
}

#[derive(Serialize)]
pub(crate) struct ConflictSnapshot {
    producers: Vec<ProducerCount>,
    unattributed: i64,
    overflow: i64,
}

#[derive(Serialize)]
struct ProducerCount {
    producer: String,
    count: i64,
}

impl EventIdentityConflicts {
    pub(crate) fn record(&self, producer: &str, authenticated: bool) {
        let mut counts = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if !authenticated {
            counts.unattributed = counts.unattributed.saturating_add(1);
        } else if let Some(count) = counts.producers.get_mut(producer) {
            *count = count.saturating_add(1);
        } else if counts.producers.len() < MAXIMUM_PRODUCERS
            && (1..=64).contains(&producer.encode_utf16().count())
        {
            counts.producers.insert(producer.to_owned(), 1);
        } else {
            counts.overflow = counts.overflow.saturating_add(1);
        }
    }

    pub(crate) fn snapshot(&self) -> ConflictSnapshot {
        let counts = self.0.lock().unwrap_or_else(|error| error.into_inner());
        ConflictSnapshot {
            producers: counts
                .producers
                .iter()
                .map(|(producer, count)| ProducerCount {
                    producer: producer.clone(),
                    count: *count,
                })
                .collect(),
            unattributed: counts.unattributed,
            overflow: counts.overflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_credential_churn_and_never_keys_anonymous_input() {
        let counts = EventIdentityConflicts::default();
        for index in 0..MAXIMUM_PRODUCERS + 10 {
            counts.record(&format!("producer-{index:04}"), true);
            counts.record(&format!("untrusted-{index}"), false);
        }
        counts.record("producer-0000", true);
        counts.record(&"x".repeat(65), true);
        let snapshot = counts.snapshot();
        assert_eq!(snapshot.producers.len(), MAXIMUM_PRODUCERS);
        assert_eq!(snapshot.producers[0].count, 2);
        assert_eq!(snapshot.unattributed, (MAXIMUM_PRODUCERS + 10) as i64);
        assert_eq!(snapshot.overflow, 11);
        let mut inner = counts.0.lock().unwrap();
        inner.overflow = i64::MAX;
        drop(inner);
        counts.record("new-overflow", true);
        assert_eq!(counts.snapshot().overflow, i64::MAX);
    }
}
