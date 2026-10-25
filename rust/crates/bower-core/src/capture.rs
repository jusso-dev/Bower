//! Per-request capture of the events `SecurityEventProcessor` would queue.
//!
//! Hosts without a durable queue run the collector's processor unchanged against
//! this in-memory store: the AWS Lambda host delivers what was "enqueued" before
//! answering, and `bower policy test` only reports it. Identity checks mirror the
//! SQLite queue inside one store (`SqliteEventStore::exists`): an event matching
//! an existing event id or fingerprint is a duplicate when fingerprint and replay
//! content agree, and an `event-identity-conflict` otherwise. Nothing survives the
//! store, so there is no duplicate detection across requests.

use std::sync::Mutex;
use std::time::Duration;

use bower_contracts::{
    DeadLetterRecord, DurableEventStore, EnqueueResult, LedgerHead, LedgerVerification,
    QueueSnapshot, QueuedEvent, StoreError, StoreResult,
};

#[derive(Default)]
pub struct CaptureStore {
    events: Mutex<Vec<QueuedEvent>>,
    /// Index of the first event not yet returned by [`CaptureStore::take_new`].
    taken: Mutex<usize>,
    /// `(duplicate candidate id, original event id)` since the last
    /// [`CaptureStore::take_duplicates`], so a duplicate can inherit the original's
    /// delivery outcome.
    duplicates: Mutex<Vec<(String, String)>>,
}

fn unsupported<T>() -> StoreResult<T> {
    Err(StoreError::Invalid(
        "operation not supported by the in-memory capture store".into(),
    ))
}

impl CaptureStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<QueuedEvent>> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Events enqueued since the previous call, in enqueue order.
    pub fn take_new(&self) -> Vec<QueuedEvent> {
        let events = self.lock();
        let mut taken = self
            .taken
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let new = events[*taken..].to_vec();
        *taken = events.len();
        new
    }

    /// Duplicate associations recorded since the previous call.
    pub fn take_duplicates(&self) -> Vec<(String, String)> {
        std::mem::take(
            &mut *self
                .duplicates
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl DurableEventStore for CaptureStore {
    fn initialize(&self) -> StoreResult<()> {
        Ok(())
    }

    fn enqueue(&self, candidate: &QueuedEvent) -> StoreResult<EnqueueResult> {
        let mut events = self.lock();
        let mut found: Option<String> = None;
        for existing in events.iter().filter(|existing| {
            existing.event_id == candidate.event_id || existing.fingerprint == candidate.fingerprint
        }) {
            if existing.fingerprint != candidate.fingerprint
                || bower_persistence::replay_content(&existing.payload)
                    != bower_persistence::replay_content(&candidate.payload)
            {
                return Err(StoreError::Invalid("event-identity-conflict".into()));
            }
            found.get_or_insert_with(|| existing.event_id.clone());
        }
        if let Some(original) = found {
            self.duplicates
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((candidate.event_id.clone(), original));
            return Ok(EnqueueResult {
                enqueued: false,
                duplicate: true,
                event_id: candidate.event_id.clone(),
                suppressed: false,
            });
        }
        events.push(candidate.clone());
        Ok(EnqueueResult {
            enqueued: true,
            duplicate: false,
            event_id: candidate.event_id.clone(),
            suppressed: false,
        })
    }

    fn lease(&self, _: usize, _: Duration) -> StoreResult<Vec<QueuedEvent>> {
        unsupported()
    }

    fn mark_delivered(&self, _: &str, _: &str, _: Option<&str>) -> StoreResult<()> {
        unsupported()
    }

    fn mark_retrying(
        &self,
        _: &str,
        _: &str,
        _: bower_contracts::time::Timestamp,
        _: Option<&str>,
    ) -> StoreResult<()> {
        unsupported()
    }

    fn mark_dead_lettered(&self, _: &str, _: &str, _: Option<&str>) -> StoreResult<()> {
        unsupported()
    }

    fn snapshot(&self) -> StoreResult<QueueSnapshot> {
        Ok(QueueSnapshot::default())
    }

    fn purge_delivered(&self, _: bower_contracts::time::Timestamp, _: usize) -> StoreResult<usize> {
        Ok(0)
    }

    fn maintain(&self) -> StoreResult<()> {
        Ok(())
    }

    fn list_dead_lettered(&self, _: usize) -> StoreResult<Vec<DeadLetterRecord>> {
        Ok(Vec::new())
    }

    fn replay_dead_lettered(
        &self,
        _: Option<&str>,
        _: Option<&[String]>,
        _: usize,
    ) -> StoreResult<usize> {
        Ok(0)
    }

    fn ledger_head(&self) -> StoreResult<LedgerHead> {
        unsupported()
    }

    fn verify_ledger(&self) -> StoreResult<LedgerVerification> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bower_contracts::QueueState;

    fn event(id: &str, fingerprint: &str) -> QueuedEvent {
        QueuedEvent {
            event_id: id.into(),
            fingerprint: fingerprint.into(),
            payload: "{}".into(),
            received_at: bower_contracts::time::now(),
            state: QueueState::Queued,
            delivery_attempts: 0,
            lease_token: None,
            suppression: None,
        }
    }

    #[test]
    fn duplicates_and_conflicts_like_the_queue() {
        let store = CaptureStore::default();
        assert!(store.enqueue(&event("a", "f1")).unwrap().enqueued);
        assert!(store.enqueue(&event("a", "f1")).unwrap().duplicate);
        assert!(matches!(
            store.enqueue(&event("a", "f2")),
            Err(StoreError::Invalid(code)) if code == "event-identity-conflict"
        ));
        // Same source identity and content under another event id: duplicate.
        assert!(store.enqueue(&event("b", "f1")).unwrap().duplicate);
        assert_eq!(
            store.take_duplicates(),
            [
                ("a".to_string(), "a".to_string()),
                ("b".to_string(), "a".to_string())
            ]
        );
        let mut changed = event("b", "f1");
        changed.payload = r#"{"x":1}"#.into();
        assert!(matches!(
            store.enqueue(&changed),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(store.take_new().len(), 1);
        assert!(store.enqueue(&event("c", "f3")).unwrap().enqueued);
        let new = store.take_new();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].event_id, "c");
        assert!(store.take_new().is_empty());
    }
}
