//! Live, bounded view of selection outcomes for `bower tap` (C# `Bower.Core.EventTap`).
//!
//! The earliest tap point is after the privacy engine: a frame never holds a
//! pre-redaction value. Only accepted events carry content, and that content is the
//! exact redacted payload handed to the queue; every other outcome is metadata only.
//! Nothing is persisted. [`EventTap::publish`] never blocks: a session whose buffer is
//! full or whose rate allowance is spent drops the frame and counts it.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use bower_contracts::time::{Clock, Timestamp};
use bower_contracts::{DecisionAction, SecurityEventEnvelope};
use bower_core::telemetry::{action_name, stage_name};
use bower_core::{ProcessingResult, TapSink};
use serde::Serialize;
use tokio::sync::mpsc;

pub const SCHEMA_VERSION: &str = "bower.tap/v1";
/// Frames a session buffers before new frames are dropped.
pub const SESSION_BUFFER_FRAMES: usize = 64;
/// Longest event type, application or environment shown in a frame (UTF-16 units).
pub const MAXIMUM_METADATA_LENGTH: usize = 128;
pub const DEFAULT_LIMIT: i64 = 100;
pub const DEFAULT_DURATION: Duration = Duration::from_secs(60);
pub const MAXIMUM_SAMPLE: i64 = 10_000;
const MAXIMUM_FILTER_LENGTH: usize = 128;
pub const OMITTED_NOT_ACCEPTED: &str = "not-accepted";
pub const OMITTED_SIZE_CAP: &str = "size-cap";

/// Tap limits (`BOWER_TAP_*`, C# `EventTapOptions`).
#[derive(Clone, Debug, PartialEq)]
pub struct EventTapOptions {
    pub enabled: bool,
    pub maximum_sessions: usize,
    /// Frames per second per session; frames over the allowance are dropped and counted.
    pub maximum_events_per_second: f64,
    pub maximum_duration: Duration,
    /// Most frames one session may receive.
    pub maximum_events: i64,
    /// Accepted events whose payload is larger are shown as metadata only.
    pub maximum_event_bytes: usize,
}

impl Default for EventTapOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            maximum_sessions: 2,
            maximum_events_per_second: 20.0,
            maximum_duration: Duration::from_secs(300),
            maximum_events: 1000,
            maximum_event_bytes: 16_384,
        }
    }
}

/// Where a session taps: every outcome, policy decisions only, or queued events only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapPoint {
    Redacted,
    Decided,
    Queued,
}

impl TapPoint {
    pub fn name(self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::Decided => "decided",
            Self::Queued => "queued",
        }
    }

    /// There is deliberately no `parsed` or raw point: nothing before the privacy
    /// engine can be tapped.
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            None | Some("" | "redacted") => Some(Self::Redacted),
            Some("decided") => Some(Self::Decided),
            Some("queued") => Some(Self::Queued),
            Some(_) => None,
        }
    }
}

/// Filter values are matched exactly and written to the audit log, so they are limited
/// to 1-128 characters from a safe set (letters, digits and `. _ : / @ -`).
pub fn is_valid_filter(value: &str) -> bool {
    (1..=MAXIMUM_FILTER_LENGTH).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@-".contains(character))
}

/// One session's filters and caps (clamped to [`EventTapOptions`] on open).
#[derive(Clone, Debug, PartialEq)]
pub struct EventTapRequest {
    pub producer: String,
    pub point: TapPoint,
    pub application: Option<String>,
    pub event_type: Option<String>,
    pub limit: i64,
    pub duration: Duration,
    pub sample: i64,
}

/// A final selection outcome as the tap sees it. Built only after redaction.
#[derive(Clone, Debug, PartialEq)]
pub struct EventTapRecord {
    pub observed_at: Timestamp,
    pub stage: &'static str,
    pub action: String,
    pub queued: bool,
    pub duplicate: bool,
    pub suppressed: bool,
    pub event_type: Option<String>,
    pub application: Option<String>,
    pub environment: Option<String>,
    pub policy_id: Option<String>,
    pub reasons: Vec<String>,
    pub event: Option<String>,
    pub event_omitted: Option<&'static str>,
}

impl EventTapRecord {
    pub fn create(
        result: &ProcessingResult,
        subject: Option<&SecurityEventEnvelope>,
        accepted_payload: Option<&str>,
        maximum_event_bytes: usize,
        now: Timestamp,
    ) -> Self {
        let accepted = matches!(
            result.action,
            DecisionAction::Accept | DecisionAction::RedactAndAccept
        );
        let (event, omitted) = match accepted_payload {
            Some(payload) if accepted && payload.len() <= maximum_event_bytes => {
                (Some(payload.to_owned()), None)
            }
            Some(_) if accepted => (None, Some(OMITTED_SIZE_CAP)),
            _ => (None, Some(OMITTED_NOT_ACCEPTED)),
        };
        Self {
            observed_at: now,
            stage: stage_name(result.stage),
            action: action_name(result.action),
            queued: result.queued,
            duplicate: result.duplicate,
            suppressed: result.suppressed,
            event_type: subject.map(|subject| bounded(&subject.event_type)),
            application: subject.map(|subject| bounded(&subject.application.name)),
            environment: subject.map(|subject| bounded(&subject.application.environment)),
            policy_id: result
                .policy_decision
                .as_ref()
                .map(|decision| decision.policy_id.clone()),
            reasons: result.reasons.clone(),
            event,
            event_omitted: omitted,
        }
    }

    pub fn matches(&self, request: &EventTapRequest) -> bool {
        let point = match request.point {
            TapPoint::Decided => self.stage == "policy",
            TapPoint::Queued => self.queued,
            TapPoint::Redacted => true,
        };
        point
            && request
                .application
                .as_ref()
                .is_none_or(|filter| self.application.as_ref() == Some(filter))
            && request
                .event_type
                .as_ref()
                .is_none_or(|filter| self.event_type.as_ref() == Some(filter))
    }
}

/// C# `value[..128]`: at most 128 UTF-16 units, never splitting a character.
fn bounded(value: &str) -> String {
    let mut units = 0;
    let mut end = value.len();
    for (index, character) in value.char_indices() {
        units += character.len_utf16();
        if units > MAXIMUM_METADATA_LENGTH {
            end = index;
            break;
        }
    }
    value[..end].to_owned()
}

/// Tap counters since start (C# `EventTapSnapshot`). Metadata only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventTapSnapshot {
    pub enabled: bool,
    pub active_sessions: i64,
    pub maximum_sessions: i64,
    pub sessions_opened: i64,
    pub sessions_refused: i64,
    pub frames_sent: i64,
    pub frames_dropped: i64,
    pub frames_rate_limited: i64,
}

struct SessionShared {
    id: String,
    request: EventTapRequest,
    sender: mpsc::Sender<Arc<EventTapRecord>>,
    matched: AtomicI64,
    buffered: AtomicI64,
    sent: AtomicI64,
    dropped: AtomicI64,
    rate_limited: AtomicI64,
    /// Rate allowance and when it was last refilled.
    bucket: Mutex<(f64, Timestamp)>,
}

#[derive(Default)]
struct Registry {
    sessions: Vec<Arc<SessionShared>>,
    opened: i64,
    refused: i64,
}

/// The tap hub (C# `EventTap`).
pub struct EventTap {
    options: EventTapOptions,
    clock: Arc<dyn Clock>,
    registry: RwLock<Registry>,
    frames_sent: AtomicI64,
    frames_dropped: AtomicI64,
    frames_rate_limited: AtomicI64,
    /// `ApplicationStopping` for open streams: set once the host begins shutting down.
    stopping: tokio::sync::watch::Sender<bool>,
}

impl EventTap {
    pub fn new(options: EventTapOptions, clock: Arc<dyn Clock>) -> Self {
        Self {
            options,
            clock,
            registry: RwLock::new(Registry::default()),
            frames_sent: AtomicI64::new(0),
            frames_dropped: AtomicI64::new(0),
            frames_rate_limited: AtomicI64::new(0),
            stopping: tokio::sync::watch::channel(false).0,
        }
    }

    /// Ends every open stream with reason `shutdown` so graceful shutdown never waits on a tap.
    pub fn stop(&self) {
        self.stopping.send_replace(true);
    }

    /// Resolves once [`Self::stop`] is called.
    pub async fn stopped(&self) {
        let mut receiver = self.stopping.subscribe();
        let _ = receiver.wait_for(|stopping| *stopping).await;
    }

    pub fn is_stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn options(&self) -> &EventTapOptions {
        &self.options
    }

    /// True while at least one session is open.
    pub fn is_active(&self) -> bool {
        !self.read().sessions.is_empty()
    }

    /// Opens a session, or `None` when tap is disabled or every slot is in use.
    pub fn try_open(self: &Arc<Self>, request: EventTapRequest) -> Option<EventTapSession> {
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.options.enabled || registry.sessions.len() >= self.options.maximum_sessions {
            registry.refused += 1;
            return None;
        }
        let request = EventTapRequest {
            limit: request.limit.clamp(1, self.options.maximum_events),
            duration: if request.duration.is_zero()
                || request.duration > self.options.maximum_duration
            {
                self.options.maximum_duration
            } else {
                request.duration
            },
            sample: request.sample.clamp(1, MAXIMUM_SAMPLE),
            ..request
        };
        let (sender, receiver) = mpsc::channel(SESSION_BUFFER_FRAMES);
        let now = self.clock.utc_now();
        let shared = Arc::new(SessionShared {
            id: uuid::Uuid::new_v4().simple().to_string()[..16].to_owned(),
            request,
            sender,
            matched: AtomicI64::new(0),
            buffered: AtomicI64::new(0),
            sent: AtomicI64::new(0),
            dropped: AtomicI64::new(0),
            rate_limited: AtomicI64::new(0),
            bucket: Mutex::new((self.options.maximum_events_per_second, now)),
        });
        registry.sessions.push(Arc::clone(&shared));
        registry.opened += 1;
        Some(EventTapSession {
            tap: Arc::clone(self),
            shared,
            receiver,
            opened_at: now,
        })
    }

    fn close(&self, session: &Arc<SessionShared>) {
        self.registry
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .sessions
            .retain(|item| !Arc::ptr_eq(item, session));
    }

    pub fn snapshot(&self) -> EventTapSnapshot {
        let registry = self.read();
        EventTapSnapshot {
            enabled: self.options.enabled,
            active_sessions: registry.sessions.len() as i64,
            maximum_sessions: self.options.maximum_sessions as i64,
            sessions_opened: registry.opened,
            sessions_refused: registry.refused,
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_dropped: self.frames_dropped.load(Ordering::Relaxed),
            frames_rate_limited: self.frames_rate_limited.load(Ordering::Relaxed),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Registry> {
        self.registry.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn offer(&self, session: &SessionShared, record: &Arc<EventTapRecord>) {
        if !record.matches(&session.request) {
            return;
        }
        // Deterministic 1-in-N sampling of matching outcomes.
        let sequence = session.matched.fetch_add(1, Ordering::Relaxed);
        if sequence % session.request.sample != 0
            || session.buffered.load(Ordering::Relaxed) >= session.request.limit
        {
            return;
        }
        if !self.take_token(session) {
            session.rate_limited.fetch_add(1, Ordering::Relaxed);
            self.frames_rate_limited.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Never waits: a full buffer (slow reader) drops the frame.
        if session.sender.try_send(Arc::clone(record)).is_ok() {
            session.buffered.fetch_add(1, Ordering::Relaxed);
        } else {
            session.dropped.fetch_add(1, Ordering::Relaxed);
            self.frames_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn take_token(&self, session: &SessionShared) -> bool {
        let rate = self.options.maximum_events_per_second;
        let mut bucket = session
            .bucket
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.utc_now();
        // A clock step backwards adds nothing.
        let elapsed = (now - bucket.1)
            .num_microseconds()
            .map_or(0.0, |micros| micros.max(0) as f64 / 1_000_000.0);
        bucket.0 = rate.min(bucket.0 + elapsed * rate);
        if now > bucket.1 {
            bucket.1 = now;
        }
        if bucket.0 < 1.0 {
            return false;
        }
        bucket.0 -= 1.0;
        true
    }
}

impl TapSink for EventTap {
    fn publish(
        &self,
        result: &ProcessingResult,
        subject: Option<&SecurityEventEnvelope>,
        accepted_payload: Option<&str>,
    ) {
        let sessions = {
            let registry = self.read();
            if registry.sessions.is_empty() {
                return;
            }
            registry.sessions.clone()
        };
        let record = Arc::new(EventTapRecord::create(
            result,
            subject,
            accepted_payload,
            self.options.maximum_event_bytes,
            self.clock.utc_now(),
        ));
        for session in &sessions {
            self.offer(session, &record);
        }
    }
}

/// One open tap. Drop it to release the slot.
pub struct EventTapSession {
    tap: Arc<EventTap>,
    shared: Arc<SessionShared>,
    receiver: mpsc::Receiver<Arc<EventTapRecord>>,
    opened_at: Timestamp,
}

impl EventTapSession {
    pub fn id(&self) -> &str {
        &self.shared.id
    }

    pub fn request(&self) -> &EventTapRequest {
        &self.shared.request
    }

    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }

    pub fn sent(&self) -> i64 {
        self.shared.sent.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> i64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    pub fn rate_limited(&self) -> i64 {
        self.shared.rate_limited.load(Ordering::Relaxed)
    }

    /// Frames waiting to be read.
    pub fn buffered(&self) -> usize {
        self.receiver.len()
    }

    /// Next buffered frame, waiting until one arrives.
    pub async fn recv(&mut self) -> Option<Arc<EventTapRecord>> {
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Option<Arc<EventTapRecord>> {
        self.receiver.try_recv().ok()
    }

    /// Records one frame written to the client.
    pub fn mark_sent(&self) {
        self.shared.sent.fetch_add(1, Ordering::Relaxed);
        self.tap.frames_sent.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for EventTapSession {
    fn drop(&mut self) {
        self.tap.close(&self.shared);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_counts_utf16_units() {
        assert_eq!(bounded(&"a".repeat(300)).len(), 128);
        assert_eq!(bounded("short"), "short");
        let wide = "\u{1F600}".repeat(100);
        assert_eq!(bounded(&wide).encode_utf16().count(), 128);
    }

    #[test]
    fn filters_and_points() {
        assert_eq!(TapPoint::parse(Some("parsed")), None);
        assert_eq!(TapPoint::parse(Some("raw")), None);
        assert_eq!(TapPoint::parse(None), Some(TapPoint::Redacted));
        assert!(!is_valid_filter("bad value"));
        assert!(!is_valid_filter(&"a".repeat(129)));
        assert!(!is_valid_filter(""));
        assert!(is_valid_filter("auth.failure:v1/x@y-z_1"));
    }
}
