//! HTTP surface (C# `CollectorApplication.MapEndpoints`).
//!
//! - `POST /v1/events`: rate limited (429), bearer authenticated (401), JSON only
//!   (415), 1 MiB body limit (413), then redaction, policy and durable queueing.
//!   202 accepted, 200 duplicate, 422 rejected, 400 quarantined, 409 identity conflict, 503 queue full.
//! - `GET /health`: anonymous, status only.
//! - `GET /v1/status`: bearer authenticated queue, ledger, policy and job metadata.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use bower_contracts::time::{Timestamp, serde_offset_option};
use bower_contracts::{DecisionAction, DurableEventStore, LedgerHead, QueueSnapshot, StoreError};
use http_body_util::BodyExt;
use serde::Serialize;
use tracing::error;

use crate::auth::IngestAuthentication;
use crate::conflicts::{CONFLICT_REASON, ConflictSnapshot, EventIdentityConflicts, REMEDIATION};
use crate::jobs::{BackgroundJobStatus, JobCatalog};
use crate::rate_limit::TokenBucket;
use crate::worker::store_error_name;
use bower_core::source_expectations::SourceSilenceStatus;

/// `JsonEventRedactor.MaximumPayloadBytes` (Kestrel `MaxRequestBodySize`).
pub const MAXIMUM_PAYLOAD_BYTES: usize = 1_048_576;
/// System.Text.Json default `MaxDepth` used by ASP.NET body binding.
const BODY_MAX_DEPTH: usize = 64;
/// Kestrel `MinRequestBodyDataRate`: 240 bytes/s after a 5 s grace period.
const MINIMUM_BODY_RATE: f64 = 240.0;
const BODY_GRACE: Duration = Duration::from_secs(5);

/// The policy decision fields echoed in ingest responses.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReference {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub score: i32,
}

/// Outcome of processing one candidate (C# `ProcessingResult`).
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessingOutcome {
    pub action: DecisionAction,
    pub event_id: Option<String>,
    pub queued: bool,
    pub duplicate: bool,
    pub reasons: Vec<String>,
    pub policy: Option<PolicyReference>,
    /// Accepted, but counted instead of queued (window allowance spent).
    pub suppressed: bool,
}

#[derive(Debug)]
pub enum ProcessFailure {
    /// `QueueCapacityExceededException`: backpressure, producers retry later.
    QueueFull,
    /// Any other failure; the type name only (never payload text).
    Other(&'static str),
}

impl From<StoreError> for ProcessFailure {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Full(_) => Self::QueueFull,
            other => Self::Other(store_error_name(&other)),
        }
    }
}

/// Redact, select and queue one candidate (bower-core `SecurityEventProcessor`).
/// Synchronous; the router calls it on the blocking pool.
pub trait EventProcessor: Send + Sync + 'static {
    fn process(
        &self,
        candidate_json: &str,
        source_adapter: &str,
    ) -> Result<ProcessingOutcome, ProcessFailure>;
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct PolicySummary {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackSummary {
    pub id: String,
    pub version: String,
    pub pack_hash: String,
    pub parser_statuses: Vec<String>,
    pub detection_status: String,
    pub dcr_status: String,
}

/// Status view of the loaded `PolicyBundle`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BundleInfo {
    pub hash: String,
    pub policies: Vec<PolicySummary>,
    pub packs: Vec<PackSummary>,
    pub privacy_profile: Option<String>,
    /// Active privacy profile version; `None` for the built-in default.
    pub privacy_profile_version: Option<String>,
    /// Active privacy profile content hash; `None` for the built-in default.
    pub privacy_profile_hash: Option<String>,
    /// `BOWER_PRIVACY_PROFILE_SOURCE` that produced the active privacy profile.
    pub privacy_profile_source: String,
}

#[derive(Clone)]
pub struct AppState {
    pub processor: Arc<dyn EventProcessor>,
    pub store: Arc<dyn DurableEventStore>,
    pub auth: Arc<IngestAuthentication>,
    pub authorization: Arc<crate::authorization::ProducerAuthorization>,
    pub limiter: Arc<TokenBucket>,
    pub bundle: Arc<BundleInfo>,
    pub packs: Arc<Vec<bower_packs::LoadedPack>>,
    pub catalog: Arc<JobCatalog>,
    /// Management-mode ingest gate (`ManagedPrivacyProfileGateFilter`).
    pub managed_privacy: Arc<crate::managed_privacy::ManagedPrivacyState>,
    /// Selection counters since start (`PipelineTelemetry`).
    pub telemetry: Arc<bower_core::PipelineTelemetry>,
    /// Expected sources (`SourceHealth`).
    pub source_health: Arc<crate::source_health::SourceHealth>,
}

pub fn router(state: AppState) -> Router {
    let ingest = Router::new()
        .route("/v1/events", post(ingest))
        .route(
            "/v1/packs/{pack_id}/parsers/{parser_index}/events",
            post(ingest_pack),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state.limiter),
            rate_limit,
        ));
    Router::new()
        .merge(ingest)
        .route("/health", get(health))
        .route("/v1/status", get(status))
        .layer(Extension(Arc::new(EventIdentityConflicts::default())))
        .with_state(state)
}

async fn rate_limit(
    State(limiter): State<Arc<TokenBucket>>,
    request: Request,
    next: Next,
) -> Response {
    if limiter.try_acquire() {
        next.run(request).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

pub(crate) fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    match bower_contracts::json::to_vec(body) {
        Ok(bytes) => {
            let mut response = (status, bytes).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn unauthorized() -> Response {
    let mut response = json_response(
        StatusCode::UNAUTHORIZED,
        &ErrorBody {
            error: "A valid collector ingest token is required.",
        },
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// `ManagedPrivacyProfileGateFilter`: refuses ingest with 503 + `Retry-After` while a
/// management-mode collector has not resolved its managed privacy profile, so no event is
/// enqueued under an unintended profile.
fn managed_privacy_gate(state: &crate::managed_privacy::ManagedPrivacyState) -> Option<Response> {
    if state.accepts_events() {
        return None;
    }
    let mut response = json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &ErrorBody {
            error: crate::managed_privacy::GATE_MESSAGE,
        },
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(crate::managed_privacy::GATE_RETRY_AFTER_SECONDS),
    );
    Some(response)
}

/// `IngestAuthenticationFilter`: the producer id, or the 401 response.
fn authenticate(auth: &IngestAuthentication, headers: &HeaderMap) -> Result<String, Box<Response>> {
    // Kestrel rejects non-ASCII header bytes; treat them as no credential.
    let values: Vec<&str> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let joined = (!values.is_empty()).then(|| values.join(","));
    auth.authenticate(joined.as_deref())
        .ok_or_else(|| Box::new(unauthorized()))
}

/// `HttpRequest.HasJsonContentType`: `application/json` or `application/*+json`.
fn has_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let media = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media == "application/json" || (media.starts_with("application/") && media.ends_with("+json"))
}

/// Reads at most `limit` bytes, enforcing Kestrel's minimum data rate.
async fn read_body(body: Body, limit: usize) -> Result<Vec<u8>, StatusCode> {
    let mut body = body;
    let start = tokio::time::Instant::now();
    let mut buffer = Vec::new();
    loop {
        let allowed = BODY_GRACE.max(Duration::from_secs_f64(
            buffer.len() as f64 / MINIMUM_BODY_RATE,
        ));
        let frame = match tokio::time::timeout_at(start + allowed, body.frame()).await {
            Err(_) => return Err(StatusCode::REQUEST_TIMEOUT),
            Ok(None) => return Ok(buffer),
            Ok(Some(Err(_))) => return Err(StatusCode::BAD_REQUEST),
            Ok(Some(Ok(frame))) => frame,
        };
        if let Ok(data) = frame.into_data() {
            if buffer.len() + data.len() > limit {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            buffer.extend_from_slice(&data);
        }
    }
}

/// Validates one JSON value like `JsonElement` binding and returns its raw text
/// (`GetRawText`): BOM and surrounding whitespace removed, bytes otherwise untouched.
pub fn raw_json_text(bytes: &[u8]) -> Option<&str> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).ok()?;
    if exceeds_depth(text.as_bytes(), BODY_MAX_DEPTH) {
        return None;
    }
    let raw: &serde_json::value::RawValue = serde_json::from_str(text).ok()?;
    Some(raw.get())
}

pub(crate) fn exceeds_depth(text: &[u8], maximum: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in text {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > maximum {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IngestResponse {
    event_id: Option<String>,
    decision: String,
    queued: bool,
    duplicate: bool,
    reasons: Vec<String>,
    policy: Option<PolicyReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'static str>,
    /// Present only when true: accepted, but counted instead of queued.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    suppressed: bool,
}

async fn ingest(
    State(state): State<AppState>,
    Extension(conflicts): Extension<Arc<EventIdentityConflicts>>,
    request: Request,
) -> Response {
    ingest_candidate(state, conflicts, request, None).await
}

async fn ingest_pack(
    State(state): State<AppState>,
    Extension(conflicts): Extension<Arc<EventIdentityConflicts>>,
    Path((pack_id, parser_index)): Path<(String, String)>,
    request: Request,
) -> Response {
    ingest_candidate(state, conflicts, request, Some((pack_id, parser_index))).await
}

async fn ingest_candidate(
    state: AppState,
    conflicts: Arc<EventIdentityConflicts>,
    request: Request,
    pack_parser: Option<(String, String)>,
) -> Response {
    let (parts, body) = request.into_parts();
    // Record which producer credential sent the event (never the token).
    let producer = match authenticate(&state.auth, &parts.headers) {
        Ok(producer) => producer,
        Err(response) => return *response,
    };
    // After authentication, before any parsing, policy or enqueue.
    if let Some(response) = managed_privacy_gate(&state.managed_privacy) {
        return response;
    }
    if !has_json_content_type(&parts.headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let limit = if pack_parser.is_some() {
        bower_packs::runtime::MAXIMUM_RAW_BYTES
    } else {
        MAXIMUM_PAYLOAD_BYTES
    };
    if declared.is_some_and(|length| length > limit as u64) {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let bytes = match read_body(body, limit).await {
        Ok(bytes) => bytes,
        Err(status) => return status.into_response(),
    };
    let Some(mut candidate) = raw_json_text(&bytes).map(str::to_string) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    drop(bytes);
    let source_adapter = if let Some((pack_id, parser_index)) = pack_parser {
        let parser = parser_index.parse::<usize>().ok().and_then(|index| {
            state
                .packs
                .iter()
                .find(|pack| {
                    pack.manifest
                        .as_ref()
                        .is_some_and(|manifest| manifest.id == pack_id)
                })
                .and_then(|pack| pack.parsers.get(index).map(|parser| (index, parser)))
        });
        let Some((index, parser)) = parser else {
            return json_response(
                StatusCode::NOT_FOUND,
                &ErrorBody {
                    error: "pack-parser-inactive-or-unknown",
                },
            );
        };
        let envelope = match bower_packs::runtime::map_raw(parser, &candidate) {
            Ok(envelope) => envelope,
            Err(error) => {
                use bower_packs::runtime::MappingError;
                let (status, error) = match error {
                    MappingError::Inactive => {
                        (StatusCode::NOT_FOUND, "pack-parser-inactive-or-unknown")
                    }
                    MappingError::Invalid => (StatusCode::BAD_REQUEST, "pack-record-invalid"),
                    MappingError::TooLarge => {
                        (StatusCode::PAYLOAD_TOO_LARGE, "pack-record-too-large")
                    }
                    MappingError::NoMatch => {
                        (StatusCode::UNPROCESSABLE_ENTITY, "pack-record-not-selected")
                    }
                };
                return json_response(status, &ErrorBody { error });
            }
        };
        candidate = match bower_contracts::json::to_string(&envelope) {
            Ok(text) => text,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        format!("pack-http:{producer}:{pack_id}:{index}")
    } else {
        format!("local-http:{producer}")
    };
    if !state.authorization.is_authorized(&producer, &candidate) {
        return json_response(
            StatusCode::FORBIDDEN,
            &ErrorBody {
                error: "Producer is not authorized for this event identity.",
            },
        );
    }

    let processor = Arc::clone(&state.processor);
    let processed =
        tokio::task::spawn_blocking(move || processor.process(&candidate, &source_adapter)).await;
    let result = match processed {
        Ok(Ok(result)) => result,
        Ok(Err(ProcessFailure::QueueFull)) => {
            // Backpressure: producers should buffer and retry.
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &ErrorBody {
                    error: "Collector queue is at capacity; retry later.",
                },
            );
        }
        Ok(Err(ProcessFailure::Other(failure))) => {
            error!(failure_type = failure, "Event processing failed.");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => {
            error!(failure_type = "panic", "Event processing failed.");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut status = match result.action {
        DecisionAction::Accept | DecisionAction::RedactAndAccept => {
            if result.duplicate {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            }
        }
        DecisionAction::Reject => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::BAD_REQUEST,
    };
    let conflict = result
        .reasons
        .iter()
        .any(|reason| reason == CONFLICT_REASON);
    if conflict {
        conflicts.record(&producer, state.auth.required());
        status = StatusCode::CONFLICT;
    }
    json_response(
        status,
        &IngestResponse {
            event_id: result.event_id,
            decision: result.action.pascal_name().to_lowercase(),
            queued: result.queued,
            duplicate: result.duplicate,
            reasons: result.reasons,
            policy: result.policy,
            remediation: conflict.then_some(REMEDIATION),
            suppressed: result.suppressed,
        },
    )
}

fn health_status(snapshot: &QueueSnapshot, sources: &[SourceSilenceStatus]) -> &'static str {
    if snapshot.dead_lettered > 0 || sources.iter().any(|source| !source.is_active()) {
        "degraded"
    } else {
        "healthy"
    }
}

async fn read_store<T: Send + 'static>(
    store: &Arc<dyn DurableEventStore>,
    call: impl FnOnce(&dyn DurableEventStore) -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StatusCode> {
    let store = Arc::clone(store);
    match tokio::task::spawn_blocking(move || call(store.as_ref())).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(failure)) => {
            error!(
                failure_type = store_error_name(&failure),
                "Queue status read failed."
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
}

// Liveness for probes: status only, no queue metadata without a token.
async fn health(State(state): State<AppState>) -> Response {
    match read_store(&state.store, |store| store.snapshot()).await {
        Ok(snapshot) => json_response(
            StatusCode::OK,
            &HealthBody {
                status: health_status(&snapshot, &state.source_health.evaluate()),
            },
        ),
        Err(status) => status.into_response(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusPolicy<'a> {
    hash: &'a str,
    policies: &'a [PolicySummary],
    packs: &'a [PackSummary],
    privacy_profile: Option<&'a str>,
    privacy_profile_version: Option<&'a str>,
    privacy_profile_hash: &'a str,
    privacy_profile_source: &'a str,
    managed_privacy_profile_state: Option<&'static str>,
    managed_privacy_profile_revision: Option<i64>,
}

#[derive(Serialize)]
struct StatusLedger {
    sequence: i64,
    hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusQueue {
    queued: i64,
    retrying: i64,
    uploading: i64,
    delivered: i64,
    dead_lettered: i64,
    total_bytes: i64,
    undelivered_bytes: i64,
    #[serde(with = "serde_offset_option")]
    oldest_undelivered: Option<Timestamp>,
}

#[derive(Serialize)]
struct StatusBody<'a> {
    status: &'static str,
    policy: StatusPolicy<'a>,
    ledger: StatusLedger,
    queue: StatusQueue,
    jobs: Vec<BackgroundJobStatus>,
    #[serde(rename = "eventIdentityConflicts")]
    event_identity_conflicts: ConflictSnapshot,
    /// Selection counters since start. Metadata only.
    pipeline: PipelineBody,
    /// Intake attempts and queue-capacity refusals since start. Metadata only.
    intake: IntakeBody,
    /// Expected sources; omitted when BOWER_SOURCE_EXPECTATIONS is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    sources: Option<Vec<SourceStatusBody>>,
}

/// `PipelineMetricsSnapshot` (Web defaults).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PipelineBody {
    #[serde(with = "bower_contracts::time::serde_offset")]
    started_at: Timestamp,
    events_in: i64,
    events_queued: i64,
    duplicates: i64,
    suppressed: i64,
    bytes_in: i64,
    bytes_queued: i64,
    rows: Vec<PipelineRowBody>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PipelineRowBody {
    stage: String,
    policy_id: String,
    action: String,
    events: i64,
    queued: i64,
    duplicates: i64,
    suppressed: i64,
    bytes_in: i64,
    bytes_queued: i64,
}

impl From<bower_core::PipelineMetricsSnapshot> for PipelineBody {
    fn from(value: bower_core::PipelineMetricsSnapshot) -> Self {
        Self {
            started_at: value.started_at,
            events_in: value.events_in,
            events_queued: value.events_queued,
            duplicates: value.duplicates,
            suppressed: value.suppressed,
            bytes_in: value.bytes_in,
            bytes_queued: value.bytes_queued,
            rows: value
                .rows
                .into_iter()
                .map(|row| PipelineRowBody {
                    stage: row.stage,
                    policy_id: row.policy_id,
                    action: row.action,
                    events: row.events,
                    queued: row.queued,
                    duplicates: row.duplicates,
                    suppressed: row.suppressed,
                    bytes_in: row.bytes_in,
                    bytes_queued: row.bytes_queued,
                })
                .collect(),
        }
    }
}

/// `IntakeMetricsSnapshot` (Web defaults: null written).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntakeBody {
    #[serde(with = "bower_contracts::time::serde_offset")]
    observed_since: Timestamp,
    attempted_requests: i64,
    attempted_bytes: i64,
    capacity_refusals: i64,
    capacity_refused_bytes: i64,
    privacy_alert_refusals: i64,
    privacy_alert_refused_bytes: i64,
    #[serde(with = "serde_offset_option")]
    last_refusal_at: Option<Timestamp>,
    last_refusal_reason: Option<&'static str>,
}

impl From<bower_core::IntakeMetricsSnapshot> for IntakeBody {
    fn from(value: bower_core::IntakeMetricsSnapshot) -> Self {
        Self {
            observed_since: value.observed_since,
            attempted_requests: value.attempted_requests,
            attempted_bytes: value.attempted_bytes,
            capacity_refusals: value.capacity_refusals,
            capacity_refused_bytes: value.capacity_refused_bytes,
            privacy_alert_refusals: value.privacy_alert_refusals,
            privacy_alert_refused_bytes: value.privacy_alert_refused_bytes,
            last_refusal_at: value.last_refusal_at,
            last_refusal_reason: value.last_refusal_reason,
        }
    }
}

/// `SourceSilenceStatus` (Web defaults: null written; `IsActive` ignored).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceStatusBody {
    application: String,
    environment: String,
    state: String,
    #[serde(with = "serde_offset_option")]
    last_seen_at: Option<Timestamp>,
    silent_seconds: i64,
    allowed_silence_seconds: i64,
}

impl From<SourceSilenceStatus> for SourceStatusBody {
    fn from(value: SourceSilenceStatus) -> Self {
        Self {
            application: value.application,
            environment: value.environment,
            state: value.state,
            last_seen_at: value.last_seen_at,
            silent_seconds: value.silent_seconds,
            allowed_silence_seconds: value.allowed_silence_seconds,
        }
    }
}

async fn status(
    State(state): State<AppState>,
    Extension(conflicts): Extension<Arc<EventIdentityConflicts>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticate(&state.auth, &headers) {
        return *response;
    }
    let (snapshot, ledger): (QueueSnapshot, LedgerHead) = match read_store(&state.store, |store| {
        Ok((store.snapshot()?, store.ledger_head()?))
    })
    .await
    {
        Ok(values) => values,
        Err(status) => return status.into_response(),
    };
    let bundle = &state.bundle;
    let sources = state.source_health.evaluate();
    let status = health_status(&snapshot, &sources);
    json_response(
        StatusCode::OK,
        &StatusBody {
            status,
            policy: StatusPolicy {
                hash: &bundle.hash,
                policies: &bundle.policies,
                packs: &bundle.packs,
                privacy_profile: bundle.privacy_profile.as_deref(),
                privacy_profile_version: bundle.privacy_profile_version.as_deref(),
                privacy_profile_hash: bundle.privacy_profile_hash.as_deref().unwrap_or("default"),
                privacy_profile_source: &bundle.privacy_profile_source,
                managed_privacy_profile_state: (!state.managed_privacy.is_local())
                    .then(|| state.managed_privacy.state()),
                managed_privacy_profile_revision: if state.managed_privacy.is_local() {
                    None
                } else {
                    state.managed_privacy.revision()
                },
            },
            ledger: StatusLedger {
                sequence: ledger.sequence,
                hash: ledger.hash,
            },
            queue: StatusQueue {
                queued: snapshot.queued,
                retrying: snapshot.retrying,
                uploading: snapshot.uploading,
                delivered: snapshot.delivered,
                dead_lettered: snapshot.dead_lettered,
                total_bytes: snapshot.total_bytes,
                undelivered_bytes: snapshot.undelivered_bytes,
                oldest_undelivered: snapshot.oldest_undelivered,
            },
            jobs: state.catalog.list(),
            event_identity_conflicts: conflicts.snapshot(),
            pipeline: state.telemetry.snapshot().into(),
            intake: state.telemetry.intake_snapshot().into(),
            sources: state
                .source_health
                .is_configured()
                .then(|| sources.into_iter().map(Into::into).collect()),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_text_matches_get_raw_text() {
        assert_eq!(
            raw_json_text(b"\xEF\xBB\xBF  {\"a\": 1 }\n"),
            Some("{\"a\": 1 }")
        );
        assert_eq!(raw_json_text(b"{\"a\":1} x"), None);
        assert_eq!(raw_json_text(b""), None);
        let deep = "[".repeat(65) + &"]".repeat(65);
        assert_eq!(raw_json_text(deep.as_bytes()), None);
        let ok = "[".repeat(64) + &"]".repeat(64);
        assert!(raw_json_text(ok.as_bytes()).is_some());
    }

    #[test]
    fn json_content_types() {
        let mut headers = HeaderMap::new();
        assert!(!has_json_content_type(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(has_json_content_type(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/cloudevents+json"),
        );
        assert!(has_json_content_type(&headers));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!has_json_content_type(&headers));
    }
}
