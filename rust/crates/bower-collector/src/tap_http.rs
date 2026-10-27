//! `GET /v1/tap` (C# `CollectorApplication.StreamTapAsync`): a bounded server-sent event
//! stream of post-redaction selection outcomes. Requires the operator credential (the
//! shared ingest token or a `BOWER_TAP_PRODUCERS` producer), or a loopback listener when
//! ingest authentication is off. Every session is audited in the collector log: who,
//! filters, caps, duration and frame counts. Nothing is persisted.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use bower_contracts::time::{Timestamp, serde_offset};
use http_body_util::channel::{Channel, Sender};
use serde::Serialize;
use serde_json::value::RawValue;
use tracing::{info, warn};

use crate::app::{AppState, authenticate, json_response};
use crate::tap::{
    DEFAULT_DURATION, DEFAULT_LIMIT, EventTapRecord, EventTapRequest, EventTapSession,
    MAXIMUM_SAMPLE, SCHEMA_VERSION, TapPoint, is_valid_filter,
};

/// Comment written when no frame arrives for this long, so idle streams stay open and
/// dead clients are found.
pub const KEEP_ALIVE: Duration = Duration::from_secs(15);
const SHARED_PRODUCER: &str = "default";

/// Who may tap besides the shared token, and whether an unauthenticated listener is loopback.
#[derive(Clone, Debug, Default)]
pub struct TapAccess {
    pub loopback_listener: bool,
    pub producers: Vec<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn tap_error(status: StatusCode, error: &'static str) -> Response {
    json_response(status, &ErrorBody { error })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartFrame<'a> {
    schema_version: &'static str,
    session_id: &'a str,
    tap_point: &'static str,
    source: Option<&'a str>,
    event_type: Option<&'a str>,
    limit: i64,
    duration_seconds: u64,
    sample: i64,
    maximum_events_per_second: i64,
    maximum_event_bytes: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndFrame<'a> {
    schema_version: &'static str,
    session_id: &'a str,
    reason: &'static str,
    frames_sent: i64,
    frames_dropped: i64,
    frames_rate_limited: i64,
}

/// One tap frame (C# `Frame`). Content appears only for accepted events and is the exact
/// redacted payload that was queued; every other outcome is metadata only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Frame<'a> {
    schema_version: &'static str,
    sequence: i64,
    #[serde(with = "serde_offset")]
    observed_at: Timestamp,
    stage: &'static str,
    action: &'a str,
    queued: bool,
    duplicate: bool,
    suppressed: bool,
    event_type: Option<&'a str>,
    application: Option<&'a str>,
    environment: Option<&'a str>,
    policy_id: Option<&'a str>,
    reasons: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_omitted: Option<&'static str>,
}

pub fn frame_json(record: &EventTapRecord, sequence: i64) -> Option<Vec<u8>> {
    let event = match &record.event {
        Some(payload) => Some(RawValue::from_string(payload.clone()).ok()?),
        None => None,
    };
    bower_contracts::json::to_vec(&Frame {
        schema_version: SCHEMA_VERSION,
        sequence,
        observed_at: record.observed_at,
        stage: record.stage,
        action: &record.action,
        queued: record.queued,
        duplicate: record.duplicate,
        suppressed: record.suppressed,
        event_type: record.event_type.as_deref(),
        application: record.application.as_deref(),
        environment: record.environment.as_deref(),
        policy_id: record.policy_id.as_deref(),
        reasons: &record.reasons,
        event,
        event_omitted: record.event_omitted,
    })
    .ok()
}

/// C# `int.TryParse(value, NumberStyles.None)` and `> 0`; blank is `fallback`.
fn positive(value: Option<&str>, fallback: i64) -> Option<i64> {
    match value {
        None => Some(fallback),
        Some(text) if text.trim().is_empty() => Some(fallback),
        Some(text) => {
            if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            text.parse::<i32>()
                .ok()
                .map(i64::from)
                .filter(|value| *value > 0)
        }
    }
}

fn blank(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

pub(crate) async fn tap(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let producer = match authenticate(&state.auth, &headers) {
        Ok(producer) => producer,
        Err(response) => return *response,
    };
    let tap = Arc::clone(&state.tap);
    if !tap.options().enabled {
        return tap_error(StatusCode::NOT_FOUND, "tap-disabled");
    }
    let authorised = if state.auth.required() {
        producer == SHARED_PRODUCER || state.tap_access.producers.contains(&producer)
    } else {
        // Without ingest authentication, only a loopback listener may tap.
        state.tap_access.loopback_listener
    };
    if !authorised {
        warn!("Tap session refused for producer {producer}: tap-not-authorized.");
        return tap_error(StatusCode::FORBIDDEN, "tap-not-authorized");
    }

    let query = |name: &str| -> Option<String> {
        let url =
            reqwest::Url::parse(&format!("http://tap/?{}", uri.query().unwrap_or(""))).ok()?;
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let Some(point) = TapPoint::parse(query("stage").as_deref()) else {
        // There is no parsed or raw tap point: nothing before the privacy engine is visible.
        return tap_error(StatusCode::BAD_REQUEST, "tap-stage-invalid");
    };
    let source = blank(query("source"));
    let event_type = blank(query("eventType"));
    if source
        .as_deref()
        .is_some_and(|value| !is_valid_filter(value))
        || event_type
            .as_deref()
            .is_some_and(|value| !is_valid_filter(value))
    {
        return tap_error(StatusCode::BAD_REQUEST, "tap-filter-invalid");
    }
    let (Some(limit), Some(duration), Some(sample)) = (
        positive(query("limit").as_deref(), DEFAULT_LIMIT),
        positive(
            query("durationSeconds").as_deref(),
            DEFAULT_DURATION.as_secs() as i64,
        ),
        positive(query("sample").as_deref(), 1),
    ) else {
        return tap_error(StatusCode::BAD_REQUEST, "tap-parameter-invalid");
    };
    if sample > MAXIMUM_SAMPLE {
        return tap_error(StatusCode::BAD_REQUEST, "tap-parameter-invalid");
    }

    let Some(session) = tap.try_open(EventTapRequest {
        producer: producer.clone(),
        point,
        application: source,
        event_type,
        limit,
        duration: Duration::from_secs(duration.unsigned_abs()),
        sample,
    }) else {
        warn!("Tap session refused for producer {producer}: tap-session-limit.");
        let mut response = tap_error(StatusCode::TOO_MANY_REQUESTS, "tap-session-limit");
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return response;
    };
    let effective = session.request().clone();
    info!(
        "Tap session {} opened by producer {producer}: tap point {}, source {}, event type {}, limit {}, duration {} s, sample 1 in {}.",
        session.id(),
        effective.point.name(),
        effective.application.as_deref().unwrap_or("-"),
        effective.event_type.as_deref().unwrap_or("-"),
        effective.limit,
        effective.duration.as_secs(),
        effective.sample
    );

    let (sender, body) = Channel::<Bytes, std::convert::Infallible>::new(4);
    let start = bower_contracts::json::to_vec(&StartFrame {
        schema_version: SCHEMA_VERSION,
        session_id: session.id(),
        tap_point: effective.point.name(),
        source: effective.application.as_deref(),
        event_type: effective.event_type.as_deref(),
        limit: effective.limit,
        duration_seconds: effective.duration.as_secs(),
        sample: effective.sample,
        maximum_events_per_second: tap.options().maximum_events_per_second as i64,
        maximum_event_bytes: tap.options().maximum_event_bytes,
    })
    .unwrap_or_default();
    tokio::spawn(stream(session, sender, start, tap));

    let mut response = Body::new(body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

fn event(name: &str, json: &[u8]) -> Bytes {
    let mut bytes = format!("event: {name}\ndata: ").into_bytes();
    bytes.extend_from_slice(json);
    bytes.extend_from_slice(b"\n\n");
    Bytes::from(bytes)
}

/// Writes the session until its limit, duration, the client leaving or shutdown.
async fn stream(
    mut session: EventTapSession,
    mut sender: Sender<Bytes>,
    start: Vec<u8>,
    tap: Arc<crate::tap::EventTap>,
) {
    let limit = session.request().limit;
    let deadline = tokio::time::Instant::now() + session.request().duration;
    let mut reason = "limit";
    let mut sequence = 0;
    if let Err(ended) = send_until(&mut sender, event("start", &start), deadline, &tap).await {
        reason = ended;
    }
    while reason == "limit" && session.sent() < limit {
        let next = tokio::select! {
            () = tokio::time::sleep_until(deadline) => { reason = "duration"; break; }
            () = tap.stopped() => { reason = "shutdown"; break; }
            next = tokio::time::timeout(KEEP_ALIVE, session.recv()) => next,
        };
        let record = match next {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(_) => {
                if let Err(ended) = send_until(
                    &mut sender,
                    Bytes::from_static(b": keep-alive\n\n"),
                    deadline,
                    &tap,
                )
                .await
                {
                    reason = ended;
                }
                continue;
            }
        };
        sequence += 1;
        let Some(json) = frame_json(&record, sequence) else {
            continue;
        };
        if let Err(ended) = send_until(&mut sender, event("frame", &json), deadline, &tap).await {
            reason = ended;
            break;
        }
        session.mark_sent();
    }
    if reason != "client-closed" {
        let end = bower_contracts::json::to_vec(&EndFrame {
            schema_version: SCHEMA_VERSION,
            session_id: session.id(),
            reason,
            frames_sent: session.sent(),
            frames_dropped: session.dropped(),
            frames_rate_limited: session.rate_limited(),
        })
        .unwrap_or_default();
        // Closing the session must stay bounded even when the body channel is full.
        if !matches!(
            tokio::time::timeout(Duration::from_secs(1), sender.send_data(event("end", &end)))
                .await,
            Ok(Ok(()))
        ) {
            reason = "client-closed";
        }
    }
    let elapsed = (tap.clock().utc_now() - session.opened_at())
        .num_milliseconds()
        .max(0);
    info!(
        "Tap session {} closed ({reason}) after {elapsed} ms: {} frames sent, {} dropped, {} rate limited.",
        session.id(),
        session.sent(),
        session.dropped(),
        session.rate_limited()
    );
}

async fn send_until(
    sender: &mut Sender<Bytes>,
    data: Bytes,
    deadline: tokio::time::Instant,
    tap: &crate::tap::EventTap,
) -> Result<(), &'static str> {
    tokio::select! {
        biased;
        () = tokio::time::sleep_until(deadline) => Err("duration"),
        () = tap.stopped() => Err("shutdown"),
        result = sender.send_data(data) => result.map_err(|_| "client-closed"),
    }
}
