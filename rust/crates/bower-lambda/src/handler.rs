//! Invocation handling, independent of AWS: classify the Lambda event, identify
//! the producer, run the collector's redaction and policy pipeline, map accepted
//! events to CloudTrail Lake audit events, deliver them and answer per event.
//!
//! Request contract: the collector's `POST /v1/events` body (one envelope, 1 MiB,
//! JSON depth 64). As an additive extension a JSON array of up to 100 envelopes is
//! accepted; each element is handled exactly like its own `/v1/events` request.
//!
//! Status codes per event follow the collector (202 accepted, 422 rejected by
//! policy, 400 quarantined, 403 outside the producer's scope, 409 identity
//! conflict), with delivery folded in: an event counts as accepted only after
//! CloudTrail Lake accepted every audit event it produced (the event and any
//! privacy alert). A retryable CloudTrail failure makes the event 503 and lists it
//! in `retryIndexes`; a definitive refusal makes it 422. A batch answers 207, or
//! 503 when any element should be retried. Only failed elements need resending.

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use base64::Engine;
use bower_collector::app::{MAXIMUM_PAYLOAD_BYTES, PolicyReference, raw_json_text};
use bower_collector::authorization::ProducerAuthorization;
use bower_contracts::time::Clock;
use bower_contracts::{DecisionAction, EventRedactor, QueuedEvent, TelemetryPolicyEvaluator};
use bower_core::{CollectorIdentity, ProcessingResult, SecurityEventProcessor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tracing::{info, warn};

use crate::audit::{self, AuditRecord, MappingContext};
use crate::capture::CaptureStore;
use crate::principals::PrincipalMap;
use crate::settings::{Ingress, LambdaSettings, SettingsError};
use crate::sink::{AuditSink, is_retryable};

/// Elements accepted in one batch body (one `PutAuditEvents` call worth).
pub const MAXIMUM_EVENTS_PER_REQUEST: usize = 100;
/// Collector `ConflictReason`.
const CONFLICT_REASON: &str = "event-identity-conflict";
const EVENTS_PATH: &str = "/v1/events";

/// How the invocation arrived; decides the response shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationKind {
    FunctionUrl,
    Invoke,
}

/// Handler answer: HTTP-like status plus a JSON body (`bower_contracts::json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub kind: InvocationKind,
    pub status: u16,
    pub body: String,
}

impl Invocation {
    /// The Lambda response payload: a Function URL response object, or for a
    /// direct invoke `{"statusCode": <status>, "body": <body>}`.
    pub fn into_payload(self) -> String {
        match self.kind {
            InvocationKind::FunctionUrl => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct UrlResponse<'a> {
                    status_code: u16,
                    headers: UrlHeaders,
                    body: &'a str,
                    is_base64_encoded: bool,
                }
                #[derive(Serialize)]
                struct UrlHeaders {
                    #[serde(rename = "content-type")]
                    content_type: &'static str,
                }
                bower_contracts::json::to_string(&UrlResponse {
                    status_code: self.status,
                    headers: UrlHeaders {
                        content_type: "application/json; charset=utf-8",
                    },
                    body: &self.body,
                    is_base64_encoded: false,
                })
                .unwrap_or_else(|_| r#"{"statusCode":500}"#.into())
            }
            InvocationKind::Invoke => {
                format!(r#"{{"statusCode":{},"body":{}}}"#, self.status, self.body)
            }
        }
    }
}

// ------------------------------------------------------------------ Function URL event

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UrlEvent {
    raw_path: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
    #[serde(default)]
    is_base64_encoded: bool,
    request_context: Option<UrlRequestContext>,
}

#[derive(Deserialize)]
struct UrlRequestContext {
    http: Option<UrlHttp>,
    authorizer: Option<UrlAuthorizer>,
}

#[derive(Deserialize)]
struct UrlHttp {
    method: Option<String>,
}

#[derive(Deserialize)]
struct UrlAuthorizer {
    iam: Option<UrlIam>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UrlIam {
    user_arn: Option<String>,
}

/// A Function URL payload (version 2.0) has `requestContext.http`; a Bower envelope
/// or batch never does.
fn as_url_event(text: &str) -> Option<UrlEvent> {
    let event: UrlEvent = serde_json::from_str(text).ok()?;
    event
        .request_context
        .as_ref()
        .is_some_and(|context| context.http.is_some())
        .then_some(event)
}

/// `HttpRequest.HasJsonContentType`: `application/json` or `application/*+json`.
fn is_json_media_type(value: &str) -> bool {
    let media = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media == "application/json" || (media.starts_with("application/") && media.ends_with("+json"))
}

// ------------------------------------------------------------------ responses

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryReport {
    /// `AuditEvent.id` sent to CloudTrail Lake.
    audit_event_id: String,
    /// The Bower event id (the source event or its privacy alert).
    event_id: String,
    /// `accepted`, `retry` or `refused`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud_trail_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    omitted_fields: Vec<&'static str>,
}

/// One element's answer: the collector's ingest response plus delivery.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    /// This request's event was accepted by CloudTrail Lake (the collector's
    /// "queued"); false for duplicates, as in the collector.
    queued: bool,
    duplicate: bool,
    reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyReference>,
    retryable: bool,
    delivery: Vec<DeliveryReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchResponse {
    results: Vec<EventResponse>,
    retry_indexes: Vec<usize>,
}

fn json_body<T: Serialize>(value: &T) -> String {
    bower_contracts::json::to_string(value)
        .unwrap_or_else(|_| r#"{"error":"serialization"}"#.into())
}

fn error(kind: InvocationKind, status: u16, message: &'static str) -> Invocation {
    Invocation {
        kind,
        status,
        body: json_body(&ErrorBody { error: message }),
    }
}

// ------------------------------------------------------------------ element state

enum Element {
    Forbidden,
    Failed,
    Processed(Box<ProcessedElement>),
}

struct ProcessedElement {
    result: ProcessingResult,
    captured: Vec<QueuedEvent>,
}

/// An audit record, or the local mapping failure code for a Bower event id.
type MappedRecord = Result<AuditRecord, (String, &'static str)>;
type ProcessedBatch = Vec<(Element, Vec<MappedRecord>)>;

#[derive(Clone, Debug)]
enum Delivery {
    Accepted(String),
    Retry(String),
    Refused(String),
}

/// Counts logged per invocation (metadata only).
#[derive(Default)]
struct Summary {
    accepted: usize,
    rejected: usize,
    retry: usize,
    refused: usize,
}

// ------------------------------------------------------------------ handler

pub struct Handler<S> {
    redactor: Arc<dyn EventRedactor>,
    evaluator: Arc<dyn TelemetryPolicyEvaluator>,
    clock: Arc<dyn Clock>,
    identity: CollectorIdentity,
    authorization: ProducerAuthorization,
    principals: PrincipalMap,
    ingress: Ingress,
    invoke_producer: Option<String>,
    recipient_account_id: String,
    sink: S,
}

impl<S: AuditSink> Handler<S> {
    /// Loads policies, packs, privacy profile, producer scopes and principal map
    /// with the collector's loaders. Any failure stops the function (fail closed).
    pub fn new(
        settings: &LambdaSettings,
        hmac_key: Option<&[u8]>,
        sink: S,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, SettingsError> {
        let bundle = bower_collector::bundle::load_with_key(&settings.bundle_settings(), hmac_key)
            .map_err(|error| SettingsError::new(format!("Policy bundle: {}", error.message)))?;
        let redactor: Arc<dyn EventRedactor> =
            Arc::new(bower_packs::runtime::PackDetectionRedactor {
                inner: bundle.redactor,
                evaluator: Arc::clone(&bundle.evaluator),
                rules: bundle
                    .packs
                    .iter()
                    .flat_map(|pack| pack.detections.iter().cloned())
                    .collect(),
            });
        let authorization = ProducerAuthorization::new(
            settings.producer_scopes_file.as_deref(),
            settings.single_trust_domain,
        )
        .map_err(|error| SettingsError::new(format!("Producer scopes: {}", error.message)))?;
        Ok(Self {
            redactor,
            evaluator: bundle.evaluator,
            clock,
            identity: CollectorIdentity::new(
                settings.collector_id.clone(),
                settings.version.clone(),
                "aws-lambda",
                settings.configuration_hash(),
            ),
            authorization,
            principals: PrincipalMap::load(settings.principals_file.as_deref())?,
            ingress: settings.ingress,
            invoke_producer: settings.invoke_producer.clone(),
            recipient_account_id: settings.recipient_account_id.clone(),
            sink,
        })
    }

    /// Handles one Lambda event (its raw JSON text).
    pub async fn invoke(&self, event: &str) -> Invocation {
        if let Some(url) = as_url_event(event) {
            return self.invoke_url(url).await;
        }
        self.invoke_direct(event).await
    }

    async fn invoke_url(&self, event: UrlEvent) -> Invocation {
        let kind = InvocationKind::FunctionUrl;
        if !self.ingress.allows_function_url() {
            return error(kind, 403, "Function URL ingress is disabled.");
        }
        let context = event.request_context.as_ref();
        let method = context
            .and_then(|context| context.http.as_ref())
            .and_then(|http| http.method.as_deref())
            .unwrap_or_default();
        if event.raw_path.as_deref() != Some(EVENTS_PATH) {
            return error(kind, 404, "Not found.");
        }
        if !method.eq_ignore_ascii_case("POST") {
            return error(kind, 405, "Method not allowed.");
        }
        let Some(caller) = context
            .and_then(|context| context.authorizer.as_ref())
            .and_then(|authorizer| authorizer.iam.as_ref())
            .and_then(|iam| iam.user_arn.as_deref())
        else {
            // AuthType NONE (misconfiguration): there is no verified caller.
            return error(kind, 401, "An IAM-signed request is required.");
        };
        let Some(producer) = self.principals.producer_for(caller) else {
            return error(kind, 403, "Caller principal is not mapped to a producer.");
        };
        let content_type = event
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str());
        if !content_type.is_some_and(is_json_media_type) {
            return error(kind, 415, "Content-Type must be application/json.");
        }
        let body = event.body.unwrap_or_default();
        let bytes = if event.is_base64_encoded {
            if body.len() > MAXIMUM_PAYLOAD_BYTES.div_ceil(3) * 4 + 4 {
                return error(kind, 413, "Request body is too large.");
            }
            match base64::engine::general_purpose::STANDARD.decode(body.as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => return error(kind, 400, "Request body is not valid base64."),
            }
        } else {
            body.into_bytes()
        };
        self.ingest(kind, producer, "aws-lambda-url", &bytes).await
    }

    async fn invoke_direct(&self, event: &str) -> Invocation {
        let kind = InvocationKind::Invoke;
        if !self.ingress.allows_invoke() {
            return error(kind, 403, "Direct invoke ingress is disabled.");
        }
        let Some(producer) = self.invoke_producer.as_deref() else {
            return error(
                kind,
                403,
                "No producer is configured for direct invocations.",
            );
        };
        self.ingest(kind, producer, "aws-lambda-invoke", event.as_bytes())
            .await
    }

    async fn ingest(
        &self,
        kind: InvocationKind,
        producer: &str,
        adapter: &str,
        bytes: &[u8],
    ) -> Invocation {
        if bytes.len() > MAXIMUM_PAYLOAD_BYTES {
            return error(kind, 413, "Request body is too large.");
        }
        let Some(text) = raw_json_text(bytes) else {
            return error(kind, 400, "Request body is not valid JSON.");
        };
        let (batch, candidates): (bool, Vec<&str>) = if text.starts_with('[') {
            let Ok(items) = serde_json::from_str::<Vec<&RawValue>>(text) else {
                return error(kind, 400, "Request body is not valid JSON.");
            };
            if items.is_empty() {
                return error(kind, 400, "A batch must hold at least one event.");
            }
            if items.len() > MAXIMUM_EVENTS_PER_REQUEST {
                return error(kind, 413, "A batch holds at most 100 events.");
            }
            (true, items.iter().map(|item| item.get()).collect())
        } else {
            (false, vec![text])
        };

        let elements = self.process(producer, adapter, &candidates);
        let deliveries = self.deliver(&elements).await;
        let mut summary = Summary::default();
        let responses: Vec<(u16, EventResponse)> = elements
            .into_iter()
            .map(|(element, records)| respond(element, &records, &deliveries, &mut summary))
            .collect();
        info!(
            ingress = match kind {
                InvocationKind::FunctionUrl => "function-url",
                InvocationKind::Invoke => "invoke",
            },
            events = candidates.len(),
            accepted = summary.accepted,
            rejected = summary.rejected,
            retry = summary.retry,
            refused = summary.refused,
            "Invocation processed."
        );

        if !batch {
            let (status, response) = responses.into_iter().next().expect("one element");
            return Invocation {
                kind,
                status,
                body: json_body(&response),
            };
        }
        let mut retry_indexes = Vec::new();
        let mut retry = false;
        let results = responses
            .into_iter()
            .enumerate()
            .map(|(index, (status, mut response))| {
                if status >= 500 {
                    retry = true;
                    retry_indexes.push(index);
                }
                response.index = Some(index);
                response.status = Some(status);
                response
            })
            .collect();
        Invocation {
            kind,
            status: if retry { 503 } else { 207 },
            body: json_body(&BatchResponse {
                results,
                retry_indexes,
            }),
        }
    }

    /// Scope check, then the collector's processor against a capture store.
    /// Returns each element with the audit records its events map to (or the
    /// local mapping failure per Bower event id).
    fn process(&self, producer: &str, adapter: &str, candidates: &[&str]) -> ProcessedBatch {
        let store = Arc::new(CaptureStore::default());
        let processor = SecurityEventProcessor::new(
            Arc::clone(&self.redactor),
            Arc::clone(&self.evaluator),
            store.clone(),
            Arc::clone(&self.clock),
        );
        let identity = CollectorIdentity {
            source_adapter: format!("{adapter}:{producer}"),
            ..self.identity.clone()
        };
        let context = MappingContext {
            recipient_account_id: &self.recipient_account_id,
            producer,
        };
        // Redaction is CPU-bound and synchronous; Lambda runs one invocation per
        // execution environment, so it runs inline on the handler task.
        candidates
            .iter()
            .map(|candidate| {
                if !self.authorization.is_authorized(producer, candidate) {
                    return (Element::Forbidden, Vec::new());
                }
                let processed =
                    catch_unwind(AssertUnwindSafe(|| processor.process(candidate, &identity)));
                let result = match processed {
                    Ok(Ok(result)) => result,
                    Ok(Err(_)) | Err(_) => {
                        warn!(failure_type = "processing", "Event processing failed.");
                        // Drop anything a failed element managed to capture.
                        drop(store.take_new());
                        return (Element::Failed, Vec::new());
                    }
                };
                let captured = store.take_new();
                let records = captured
                    .iter()
                    .map(|queued| {
                        audit::map(queued, context)
                            .map_err(|error| (queued.event_id.clone(), error.code()))
                    })
                    .collect();
                (
                    Element::Processed(Box::new(ProcessedElement { result, captured })),
                    records,
                )
            })
            .collect()
    }

    /// Sends every mapped record in `PutAuditEvents` sized calls. Returns the
    /// outcome per audit id.
    async fn deliver(&self, elements: &ProcessedBatch) -> HashMap<String, Delivery> {
        let mut outcomes: HashMap<String, Delivery> = HashMap::new();
        let mut seen = HashSet::new();
        let mut pending: Vec<AuditRecord> = Vec::new();
        for (_, records) in elements {
            for record in records.iter().flatten() {
                if seen.insert(record.id.clone()) {
                    pending.push(record.clone());
                } else {
                    // Two Bower ids mapped to one audit id: CloudTrail would refuse
                    // the whole call (DuplicatedAuditEventId). Refuse the later one.
                    outcomes.insert(
                        format!("{}\u{1f}{}", record.id, record.bower_event_id),
                        Delivery::Refused("audit-id-collision".into()),
                    );
                }
            }
        }
        for range in audit::batches(&pending) {
            let batch: Vec<&AuditRecord> = pending[range].iter().collect();
            match self.sink.put_audit_events(&batch).await {
                Ok(result) => {
                    for accepted in result.successful {
                        outcomes.insert(accepted.id, Delivery::Accepted(accepted.event_id));
                    }
                    for refused in result.failed {
                        let delivery = if is_retryable(&refused.error_code) {
                            Delivery::Retry(refused.error_code)
                        } else {
                            Delivery::Refused(refused.error_code)
                        };
                        outcomes.insert(refused.id, delivery);
                    }
                }
                Err(failure) => {
                    warn!(
                        failure_type = failure.code.as_str(),
                        events = batch.len(),
                        "CloudTrail Lake PutAuditEvents failed; events are retryable."
                    );
                    for record in &batch {
                        outcomes.insert(record.id.clone(), Delivery::Retry(failure.code.clone()));
                    }
                }
            }
            for record in &batch {
                outcomes
                    .entry(record.id.clone())
                    .or_insert_with(|| Delivery::Retry("missing-result".into()));
            }
        }
        outcomes
    }
}

fn delivery_for(record: &AuditRecord, deliveries: &HashMap<String, Delivery>) -> Delivery {
    deliveries
        .get(&format!("{}\u{1f}{}", record.id, record.bower_event_id))
        .or_else(|| deliveries.get(&record.id))
        .cloned()
        .unwrap_or_else(|| Delivery::Retry("missing-result".into()))
}

fn report(
    audit_event_id: String,
    event_id: String,
    delivery: &Delivery,
    omitted: Vec<&'static str>,
) -> DeliveryReport {
    let (status, cloud_trail_event_id, error_code) = match delivery {
        Delivery::Accepted(id) => ("accepted", Some(id.clone()), None),
        Delivery::Retry(code) => ("retry", None, Some(code.clone())),
        Delivery::Refused(code) => ("refused", None, Some(code.clone())),
    };
    DeliveryReport {
        audit_event_id,
        event_id,
        status,
        cloud_trail_event_id,
        error_code,
        omitted_fields: omitted,
    }
}

fn respond(
    element: Element,
    records: &[MappedRecord],
    deliveries: &HashMap<String, Delivery>,
    summary: &mut Summary,
) -> (u16, EventResponse) {
    let empty = |status: u16, error: &'static str| EventResponse {
        index: None,
        status: None,
        error: Some(error),
        event_id: None,
        decision: None,
        queued: false,
        duplicate: false,
        reasons: Vec::new(),
        policy: None,
        retryable: status >= 500,
        delivery: Vec::new(),
    };
    let (result, captured) = match element {
        Element::Forbidden => {
            summary.rejected += 1;
            return (
                403,
                empty(403, "Producer is not authorized for this event identity."),
            );
        }
        Element::Failed => {
            summary.retry += 1;
            return (500, empty(500, "Event processing failed."));
        }
        Element::Processed(processed) => (processed.result, processed.captured),
    };

    let accepted = matches!(
        result.action,
        DecisionAction::Accept | DecisionAction::RedactAndAccept
    );
    let mut status = match result.action {
        DecisionAction::Accept | DecisionAction::RedactAndAccept => {
            if result.duplicate {
                200
            } else {
                202
            }
        }
        DecisionAction::Reject => 422,
        _ => 400,
    };
    if result
        .reasons
        .iter()
        .any(|reason| reason == CONFLICT_REASON)
    {
        status = 409;
    }

    let mut delivery = Vec::new();
    for (queued, record) in captured.iter().zip(records) {
        match record {
            Ok(record) => {
                let outcome = delivery_for(record, deliveries);
                delivery.push(report(
                    record.id.clone(),
                    record.bower_event_id.clone(),
                    &outcome,
                    record.omitted_fields.clone(),
                ));
            }
            Err((event_id, code)) => delivery.push(report(
                audit::audit_id(event_id),
                queued.event_id.clone(),
                &Delivery::Refused((*code).to_string()),
                Vec::new(),
            )),
        }
    }
    // A duplicate inside one batch shares the delivery of the first copy.
    if result.duplicate
        && let Some(event_id) = &result.event_id
    {
        let id = audit::audit_id(event_id);
        if let Some(outcome) = deliveries.get(&id) {
            delivery.push(report(id, event_id.clone(), outcome, Vec::new()));
        }
    }

    let source_event_id = result.event_id.clone().unwrap_or_default();
    let source_outcome = delivery
        .iter()
        .find(|report| report.event_id == source_event_id)
        .map(|report| report.status);
    let any_retry = delivery.iter().any(|report| report.status == "retry");
    let mut reasons = result.reasons;
    // Like the collector, a duplicate is not "queued" again.
    let mut queued = accepted && !result.duplicate && source_outcome == Some("accepted");
    if any_retry {
        status = 503;
        queued = false;
        reasons.push("CloudTrail Lake did not accept every audit event; retry this event.".into());
        summary.retry += 1;
    } else if accepted && source_outcome == Some("refused") {
        status = 422;
        reasons.push("CloudTrail Lake refused the audit event.".into());
        summary.refused += 1;
    } else if accepted {
        summary.accepted += 1;
    } else {
        summary.rejected += 1;
    }
    if accepted && source_outcome.is_none() && !any_retry {
        // Accepted but nothing captured and no prior copy: never claim delivery.
        queued = false;
    }

    (
        status,
        EventResponse {
            index: None,
            status: None,
            error: None,
            event_id: result.event_id,
            decision: Some(result.action.pascal_name().to_lowercase()),
            queued,
            duplicate: result.duplicate,
            reasons,
            policy: result.policy_decision.map(|decision| PolicyReference {
                policy_id: decision.policy_id,
                policy_version: decision.policy_version,
                policy_hash: decision.policy_hash,
                score: decision.score,
            }),
            retryable: status >= 500,
            delivery,
        },
    )
}
