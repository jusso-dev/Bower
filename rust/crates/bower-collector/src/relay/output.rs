//! Output for a downstream collector behind a relay (C# `Bower.Forwarding.RelayOutput`,
//! `BOWER_OUTPUT=relay`). Posts leased events, already redacted and decided, to the relay
//! exactly as the queue stores them. At least once across the hop: an event is
//! acknowledged only when the relay reports it committed (`accepted`) or already held
//! (`duplicate`). Everything else stays in this collector's queue.

use std::collections::{HashMap, HashSet};

use bower_contracts::time::{Clock, SystemClock, Timestamp};
use bower_contracts::{DeliveryFailure, DeliveryResult, OutputAdapter, QueuedEvent};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{StatusCode, Url};
use std::sync::Arc;

use super::protocol::{self, RelayBatchResponse};

pub const OUTPUT_ID: &str = "relay";
const MAXIMUM_RETRY_AFTER_SECONDS: i64 = 3600;

pub struct RelayOutput {
    client: reqwest::Client,
    batch_url: Url,
    collector_id: String,
    clock: Arc<dyn Clock>,
}

struct BatchOutcome {
    acknowledged: Vec<String>,
    failures: Vec<DeliveryFailure>,
    acknowledgement: Option<String>,
    destination_failure: Option<DeliveryFailure>,
}

impl RelayOutput {
    /// `client` carries the mutual TLS identity; `relay` is `BOWER_RELAY_URL`.
    pub fn new(client: reqwest::Client, relay: &Url, collector_id: impl Into<String>) -> Self {
        Self {
            client,
            batch_url: relay
                .join(protocol::BATCH_PATH)
                .expect("a relative path joins an https origin"),
            collector_id: collector_id.into(),
            clock: Arc::new(SystemClock),
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    async fn send(&self, batch: &[&QueuedEvent]) -> BatchOutcome {
        let response = self
            .client
            .post(self.batch_url.clone())
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .body(self.serialize(batch))
            .send()
            .await;
        let unavailable = || failed(batch, failure("destination-relay-unavailable", true, None));
        let response = match response {
            Ok(response) => response,
            // Transport and TLS failures. Error text is never kept.
            Err(_) => return unavailable(),
        };
        let status = response.status();
        let retry_after = self.retry_after(response.headers().get(RETRY_AFTER));
        if status != StatusCode::OK {
            let code = status.as_u16();
            let destination = matches!(code, 401 | 403 | 404 | 408 | 429) || code >= 500;
            // A relay-wide refusal holds the stream (no poison budget spent). Any other
            // 4xx means this request was refused: retry with the attempt budget.
            return failed(
                batch,
                failure(
                    &if destination {
                        format!("destination-relay-http-{code}")
                    } else {
                        format!("relay-http-{code}")
                    },
                    true,
                    retry_after,
                ),
            );
        }
        let body = match read_bounded(response).await {
            Ok(body) => body,
            Err(()) => return unavailable(),
        };
        let invalid = || failed(batch, failure("relay-response-invalid", true, None));
        let Some(parsed) = body.as_deref().and_then(parse) else {
            return invalid();
        };
        let sent: HashSet<&str> = batch.iter().map(|item| item.event_id.as_str()).collect();
        let mut results = HashMap::new();
        for result in &parsed.results {
            if !sent.contains(result.event_id.as_str())
                || results.insert(result.event_id.as_str(), result).is_some()
            {
                return invalid();
            }
        }
        let mut acknowledged = Vec::new();
        let mut failures = Vec::new();
        for item in batch {
            match results.get(item.event_id.as_str()) {
                None => failures.push(DeliveryFailure {
                    event_id: item.event_id.clone(),
                    ..failure("relay-result-missing", true, None)
                }),
                Some(result)
                    if result.status == protocol::STATUS_ACCEPTED
                        || result.status == protocol::STATUS_DUPLICATE =>
                {
                    acknowledged.push(item.event_id.clone());
                }
                Some(result) => {
                    // Rejected (or an unknown status): permanent, so it is dead-lettered
                    // here, where the operator who owns the source can see it.
                    let code = result
                        .code
                        .as_deref()
                        .filter(|code| {
                            result.status == protocol::STATUS_REJECTED
                                && protocol::is_valid_code(code)
                        })
                        .unwrap_or("unknown");
                    failures.push(DeliveryFailure {
                        event_id: item.event_id.clone(),
                        ..failure(&format!("relay-rejected:{code}"), false, None)
                    });
                }
            }
        }
        let acknowledgement = (!acknowledged.is_empty()).then(|| {
            format!(
                "relay:{}:ledger:{}",
                parsed.relay_id, parsed.ledger.sequence
            )
        });
        BatchOutcome {
            acknowledged,
            failures,
            acknowledgement,
            destination_failure: None,
        }
    }

    fn serialize(&self, batch: &[&QueuedEvent]) -> Vec<u8> {
        let string = |value: &str| bower_contracts::json::to_string(value).unwrap_or_default();
        let mut body = Vec::with_capacity(batch.iter().map(|item| item.payload.len() + 128).sum());
        body.extend_from_slice(b"{\"schemaVersion\":");
        body.extend_from_slice(protocol::SCHEMA_VERSION.to_string().as_bytes());
        body.extend_from_slice(b",\"collectorId\":");
        body.extend_from_slice(string(&self.collector_id).as_bytes());
        body.extend_from_slice(b",\"events\":[");
        for (index, item) in batch.iter().enumerate() {
            if index > 0 {
                body.push(b',');
            }
            body.extend_from_slice(b"{\"eventId\":");
            body.extend_from_slice(string(&item.event_id).as_bytes());
            body.extend_from_slice(b",\"fingerprint\":");
            body.extend_from_slice(string(&item.fingerprint).as_bytes());
            // The stored bytes, unchanged: the relay's ledger then hashes the same payload.
            body.extend_from_slice(b",\"payload\":");
            body.extend_from_slice(item.payload.as_bytes());
            body.push(b'}');
        }
        body.extend_from_slice(b"]}");
        body
    }

    /// `RetryConditionHeaderValue`: delta seconds or an HTTP date; past values are
    /// ignored and future ones capped at one hour.
    fn retry_after(&self, header: Option<&reqwest::header::HeaderValue>) -> Option<Timestamp> {
        let now = self.clock.utc_now();
        let text = header?.to_str().ok()?.trim();
        let at = if let Ok(seconds) = text.parse::<i64>() {
            now + chrono::Duration::seconds(seconds)
        } else {
            chrono::DateTime::parse_from_rfc2822(text).ok()?
        };
        if at <= now {
            None
        } else {
            Some(at.min(now + chrono::Duration::seconds(MAXIMUM_RETRY_AFTER_SECONDS)))
        }
    }
}

impl OutputAdapter for RelayOutput {
    fn id(&self) -> &str {
        OUTPUT_ID
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        let mut failures = Vec::new();
        let mut batches: Vec<Vec<&QueuedEvent>> = Vec::new();
        let mut current: Vec<&QueuedEvent> = Vec::new();
        let mut bytes = 0usize;
        for item in events {
            let length = item.payload.len();
            if length > protocol::MAXIMUM_PAYLOAD_BYTES {
                failures.push(DeliveryFailure {
                    event_id: item.event_id.clone(),
                    ..failure("payload-too-large", false, None)
                });
                continue;
            }
            if !is_json_object(&item.payload) {
                // Never succeeds anywhere: dead-letter it alone, as the Azure output does.
                failures.push(DeliveryFailure {
                    event_id: item.event_id.clone(),
                    ..failure("payload-invalid-json", false, None)
                });
                continue;
            }
            if !current.is_empty()
                && (current.len() == protocol::MAXIMUM_BATCH_EVENTS
                    || bytes + length > protocol::TARGET_BATCH_PAYLOAD_BYTES)
            {
                batches.push(std::mem::take(&mut current));
                bytes = 0;
            }
            current.push(item);
            bytes += length;
        }
        if !current.is_empty() {
            batches.push(current);
        }

        let mut acknowledged = Vec::new();
        let mut acknowledgement = None;
        for (index, batch) in batches.iter().enumerate() {
            let outcome = self.send(batch).await;
            acknowledged.extend(outcome.acknowledged);
            failures.extend(outcome.failures);
            acknowledgement = outcome.acknowledgement.or(acknowledgement);
            if let Some(stop) = outcome.destination_failure {
                // The relay is unavailable: keep the rest queued behind the destination
                // circuit instead of sending them into the same failure.
                for item in batches[index + 1..].iter().flatten() {
                    failures.push(DeliveryFailure {
                        event_id: item.event_id.clone(),
                        ..stop.clone()
                    });
                }
                break;
            }
        }
        DeliveryResult {
            acknowledged_event_ids: acknowledged,
            failures,
            destination_acknowledgement: acknowledgement,
        }
    }
}

fn failure(code: &str, is_retryable: bool, retry_after: Option<Timestamp>) -> DeliveryFailure {
    DeliveryFailure {
        event_id: String::new(),
        code: code.to_string(),
        is_retryable,
        retry_after,
    }
}

fn failed(batch: &[&QueuedEvent], failure: DeliveryFailure) -> BatchOutcome {
    BatchOutcome {
        acknowledged: Vec::new(),
        failures: batch
            .iter()
            .map(|item| DeliveryFailure {
                event_id: item.event_id.clone(),
                ..failure.clone()
            })
            .collect(),
        acknowledgement: None,
        destination_failure: failure.is_destination_failure().then_some(failure),
    }
}

/// C# `IsJsonObject`: one JSON object (depth 64), whitespace around it allowed.
fn is_json_object(payload: &str) -> bool {
    payload
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .starts_with('{')
        && protocol::within_depth(payload.as_bytes(), 64)
        && serde_json::from_str::<serde::de::IgnoredAny>(payload).is_ok()
}

fn parse(body: &[u8]) -> Option<RelayBatchResponse> {
    let response = serde_json::from_slice::<RelayBatchResponse>(body).ok()?;
    (response.schema_version == protocol::SCHEMA_VERSION
        && protocol::is_valid_identifier(&response.relay_id)
        && response.ledger.sequence >= 0)
        .then_some(response)
}

/// The response body up to [`protocol::MAXIMUM_RESPONSE_BYTES`]; `Ok(None)` when larger.
async fn read_bounded(mut response: reqwest::Response) -> Result<Option<Vec<u8>>, ()> {
    let declared = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > protocol::MAXIMUM_RESPONSE_BYTES) {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() + chunk.len() > protocol::MAXIMUM_RESPONSE_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}
