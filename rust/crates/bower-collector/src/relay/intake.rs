//! Accepts one batch from an authenticated downstream collector into the relay's own
//! durable queue (C# `RelayIntake`). The relay never parses raw source data and never
//! redacts again: each payload is an envelope the downstream already redacted and decided,
//! stored byte for byte so both ledgers hash the same payload. Validation is default deny.
//! An event answers `accepted` or `duplicate` only after its queue transaction committed.
//! Synchronous: call it from async code with `spawn_blocking`.

use std::collections::HashSet;
use std::sync::Arc;

use bower_contracts::time::Clock;
use bower_contracts::{
    DecisionAction, DurableEventStore, QueueState, QueuedEvent, SecurityEventEnvelope, StoreError,
};

use super::protocol::{self, JsonKind, RawObject, RelayBatchResponse, RelayEventResult};
use super::telemetry::RelayTelemetry;

/// HTTP outcome of one batch.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayIntakeOutcome {
    Accepted(RelayBatchResponse),
    Refused { status: u16, message: &'static str },
}

pub struct RelayIntake {
    store: Arc<dyn DurableEventStore>,
    relay_id: String,
    telemetry: Arc<RelayTelemetry>,
    clock: Arc<dyn Clock>,
}

struct Candidate {
    event_id: String,
    fingerprint: String,
    payload: String,
}

fn malformed() -> RelayIntakeOutcome {
    RelayIntakeOutcome::Refused {
        status: 400,
        message: "Relay batch is malformed.",
    }
}

impl RelayIntake {
    pub fn new(
        store: Arc<dyn DurableEventStore>,
        relay_id: impl Into<String>,
        telemetry: Arc<RelayTelemetry>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            relay_id: relay_id.into(),
            telemetry,
            clock,
        }
    }

    /// `Err` is a storage failure (C# exception path): nothing is acknowledged.
    pub fn accept(
        &self,
        downstream_id: &str,
        body: &[u8],
    ) -> Result<RelayIntakeOutcome, StoreError> {
        if body.len() > protocol::MAXIMUM_REQUEST_BYTES {
            return Ok(RelayIntakeOutcome::Refused {
                status: 413,
                message: "Relay batch is too large.",
            });
        }
        // Envelope depth 32 plus the batch wrapper.
        if !protocol::within_depth(body, 40) {
            return Ok(malformed());
        }
        let Ok(root) = serde_json::from_slice::<Box<serde_json::value::RawValue>>(body) else {
            return Ok(malformed());
        };
        let Some(root) = protocol::as_object(&root) else {
            return Ok(malformed());
        };
        let schema_version = root.single("schemaVersion").and_then(protocol::as_i32);
        let collector = root.single("collectorId").and_then(protocol::as_string);
        let events = root.single("events").and_then(protocol::as_array);
        let (Some(protocol::SCHEMA_VERSION), Some(collector), Some(events)) =
            (schema_version, collector, events)
        else {
            return Ok(malformed());
        };
        if !(1..=protocol::MAXIMUM_BATCH_EVENTS).contains(&events.len()) {
            return Ok(malformed());
        }

        // A downstream acts only as the collector its certificate pin names.
        if collector != downstream_id {
            return Ok(RelayIntakeOutcome::Refused {
                status: 403,
                message: "Relay batch names a collector other than the authenticated downstream.",
            });
        }

        let mut candidates = Vec::with_capacity(events.len());
        let mut seen = HashSet::new();
        for item in &events {
            let Some(candidate) = protocol::as_object(item).and_then(|item| candidate(&item))
            else {
                return Ok(malformed());
            };
            if candidate.event_id.is_empty() || !seen.insert(candidate.event_id.clone()) {
                return Ok(malformed());
            }
            candidates.push(candidate);
        }

        let now = self.clock.utc_now();
        let mut results = Vec::with_capacity(candidates.len());
        let (mut accepted, mut duplicates, mut rejected) = (0, 0, 0);
        for candidate in &candidates {
            let result = match self.accept_one(downstream_id, candidate, now) {
                Ok(result) => result,
                Err(StoreError::Full(_)) => {
                    // Events committed before the queue filled answer duplicate on the retry.
                    self.telemetry
                        .record_batch(downstream_id, accepted, duplicates, rejected, now);
                    return Ok(RelayIntakeOutcome::Refused {
                        status: 503,
                        message: "Relay queue is at capacity; retry later.",
                    });
                }
                Err(error) => return Err(error),
            };
            match result.status.as_str() {
                protocol::STATUS_ACCEPTED => accepted += 1,
                protocol::STATUS_DUPLICATE => duplicates += 1,
                _ => rejected += 1,
            }
            results.push(result);
        }

        self.telemetry
            .record_batch(downstream_id, accepted, duplicates, rejected, now);
        let head = self.store.ledger_head()?;
        Ok(RelayIntakeOutcome::Accepted(RelayBatchResponse {
            schema_version: protocol::SCHEMA_VERSION,
            relay_id: self.relay_id.clone(),
            ledger: protocol::RelayLedgerHead {
                sequence: head.sequence,
                hash: head.hash,
            },
            results,
        }))
    }

    fn accept_one(
        &self,
        downstream_id: &str,
        candidate: &Candidate,
        now: bower_contracts::time::Timestamp,
    ) -> Result<RelayEventResult, StoreError> {
        let rejected = |code: &str| {
            Ok(RelayEventResult {
                event_id: candidate.event_id.clone(),
                status: protocol::STATUS_REJECTED.into(),
                code: Some(code.into()),
            })
        };
        if candidate.payload.len() > protocol::MAXIMUM_PAYLOAD_BYTES {
            return rejected(protocol::REJECT_PAYLOAD_TOO_LARGE);
        }
        let Ok(envelope) =
            bower_contracts::json::from_str::<SecurityEventEnvelope>(&candidate.payload)
        else {
            return rejected(protocol::REJECT_PAYLOAD_INVALID);
        };
        if envelope.event_id != candidate.event_id {
            return rejected(protocol::REJECT_EVENT_ID_MISMATCH);
        }
        if envelope
            .collector
            .as_ref()
            .map(|collector| collector.id.as_str())
            != Some(downstream_id)
        {
            return rejected(protocol::REJECT_COLLECTOR_MISMATCH);
        }
        // Only what a collector's policy accepted reaches a queue; anything else is not
        // post-decision data and the relay refuses to carry it.
        if !matches!(
            envelope.security.as_ref().map(|security| security.decision),
            Some(
                DecisionAction::Accept
                    | DecisionAction::RedactAndAccept
                    | DecisionAction::Aggregate
            )
        ) {
            return rejected(protocol::REJECT_POLICY_DECISION_MISSING);
        }
        if bower_persistence::event_identity(&envelope) != candidate.fingerprint {
            return rejected(protocol::REJECT_FINGERPRINT_MISMATCH);
        }
        let queued = QueuedEvent {
            event_id: candidate.event_id.clone(),
            fingerprint: candidate.fingerprint.clone(),
            payload: candidate.payload.clone(),
            received_at: now,
            state: QueueState::Queued,
            delivery_attempts: 0,
            lease_token: None,
            suppression: None,
        };
        match self.store.enqueue(&queued) {
            Ok(result) => Ok(RelayEventResult {
                event_id: candidate.event_id.clone(),
                status: if result.duplicate {
                    protocol::STATUS_DUPLICATE
                } else {
                    protocol::STATUS_ACCEPTED
                }
                .into(),
                code: None,
            }),
            Err(StoreError::Invalid(message)) if message == "event-identity-conflict" => {
                rejected(protocol::REJECT_IDENTITY_CONFLICT)
            }
            // The queue's own constraints (for example an event id over 128 characters).
            Err(StoreError::Invalid(_)) => rejected(protocol::REJECT_PAYLOAD_INVALID),
            Err(error) => Err(error),
        }
    }
}

/// One batch item: exactly one string `eventId`, string `fingerprint` and object `payload`.
fn candidate(item: &RawObject) -> Option<Candidate> {
    let event_id = item.single("eventId").and_then(protocol::as_string)?;
    let fingerprint = item.single("fingerprint").and_then(protocol::as_string)?;
    let payload = item
        .single("payload")
        .filter(|payload| protocol::kind(payload) == JsonKind::Object)?;
    Some(Candidate {
        event_id,
        fingerprint,
        payload: payload.get().to_string(),
    })
}
