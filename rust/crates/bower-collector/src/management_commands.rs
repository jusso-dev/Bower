//! Outbound-only management commands delivered in the heartbeat v2 response (C#
//! `ManagementCommands.cs` and `ManagementCommandWorker.cs`).
//!
//! The set is closed: `fetch-bundle`, `run-canary`, `reload` and `rotate-credential`. Each
//! command is signed by management (ECDSA P-256 over the canonical JSON of every field but
//! the signature), bound to one collector id, a nonce and an expiry. The heartbeat job
//! verifies and admits commands to a durable ledger, then hands them to a separate worker
//! task: it never executes one itself. Execution is at most once; results are reported on
//! the next heartbeat until management acknowledges them. Metadata only.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bower_contracts::time::{Clock, Timestamp, serde_offset, serde_offset_option};
use bower_contracts::types::{event_categories, event_types};
use bower_contracts::{
    ActorContext, ActorType, ApplicationContext, CURRENT_SCHEMA_VERSION, DecisionAction,
    EventResult, EventSeverity, RequestContext, SecurityEventEnvelope, StoreError,
};
use bower_core::{CollectorIdentity, ProcessError, SecurityEventProcessor};
use bower_integrity::DetachedSignature;
use chrono::{NaiveDateTime, TimeDelta};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::jobs::{JobTriggers, MANAGED_PRIVACY_PROFILE_JOB_ID};
use crate::settings::{CollectorSettings, read_all_text};
use crate::shutdown::{ApplicationLifetime, ShutdownToken};

pub const KIND: &str = "bower.collector-command/v1";

pub const FETCH_BUNDLE: &str = "fetch-bundle";
pub const RUN_CANARY: &str = "run-canary";
pub const RELOAD: &str = "reload";
/// Rotates the key-bound credential of a token-enrolled collector (#109).
pub const ROTATE_CREDENTIAL: &str = "rotate-credential";
pub const ALL: [&str; 4] = [FETCH_BUNDLE, RUN_CANARY, RELOAD, ROTATE_CREDENTIAL];

/// Result statuses and codes (C# `ManagementCommandResults`).
pub mod results {
    pub const SUCCEEDED: &str = "succeeded";
    pub const FAILED: &str = "failed";
    pub const REJECTED: &str = "rejected";

    pub const MALFORMED_COMMAND: &str = "malformed-command";
    pub const UNTRUSTED_SIGNATURE: &str = "untrusted-signature";
    pub const WRONG_COLLECTOR: &str = "wrong-collector";
    pub const UNKNOWN_COMMAND: &str = "unknown-command";
    pub const NOT_YET_VALID: &str = "not-yet-valid";
    pub const EXPIRED: &str = "expired";
    pub const INVALID_LIFETIME: &str = "invalid-lifetime";
    pub const REPLAYED: &str = "replayed";
    pub const UNSUPPORTED_COMMAND: &str = "unsupported-command";
    pub const COMMANDS_NOT_CONFIGURED: &str = "commands-not-configured";
    pub const LEDGER_UNAVAILABLE: &str = "ledger-unavailable";
    pub const LEDGER_FULL: &str = "ledger-full";
    pub const EXECUTOR_BUSY: &str = "executor-busy";
    pub const INTERRUPTED: &str = "interrupted";
    pub const EXECUTION_FAILED: &str = "execution-failed";

    pub const FETCH_TRIGGERED: &str = "fetch-triggered";
    pub const FETCH_UNAVAILABLE: &str = "fetch-unavailable";
    pub const CANARY_QUEUED: &str = "canary-queued";
    pub const RESTART_REQUESTED: &str = "restart-requested";
    pub const RELOAD_RATE_LIMITED: &str = "reload-rate-limited";
    pub const RELOAD_VALIDATION_FAILED: &str = "reload-validation-failed";
}

pub const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAXIMUM_COMMANDS_PER_RESPONSE: usize = 8;
pub const MAXIMUM_LEDGER_ENTRIES: usize = 128;
pub const MAXIMUM_PENDING_REJECTIONS: usize = 32;
pub const MAXIMUM_REPORTED_RESULTS: usize = 32;
pub const INBOX_CAPACITY: usize = 16;
pub const LEDGER_FILE_NAME: &str = "ledger.json";
pub const CANARY_SOURCE_ADAPTER: &str = "management-canary";

const STARTED: &str = "started";

fn maximum_clock_skew() -> TimeDelta {
    TimeDelta::minutes(5)
}

fn maximum_lifetime() -> TimeDelta {
    TimeDelta::hours(1)
}

fn reload_interval() -> TimeDelta {
    TimeDelta::minutes(10)
}

fn unacknowledged_retention() -> TimeDelta {
    TimeDelta::days(7)
}

/// Commands this collector executes, in wire order (C# `ManagementCommandTypes.Supported`).
pub fn supported(settings: &CollectorSettings) -> Vec<&'static str> {
    if settings.management_command_trusted_key_files.is_empty() {
        return Vec::new();
    }
    let mut supported = if settings.uses_managed_privacy_profile() {
        vec![FETCH_BUNDLE, RUN_CANARY, RELOAD]
    } else {
        vec![RUN_CANARY, RELOAD]
    };
    // An Entra identity has nothing to rotate; only a key-bound credential does.
    if settings.uses_enrolment() {
        supported.push(ROTATE_CREDENTIAL);
    }
    supported
}

// ------------------------------------------------------------------ verification

/// A command whose signature, collector binding and validity window verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCommand {
    pub command_id: String,
    pub command: String,
    pub nonce: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

/// Either a verified command or a rejection code (with the command id when readable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub command: Option<VerifiedCommand>,
    pub rejection_code: Option<&'static str>,
    pub command_id: Option<String>,
}

impl Verification {
    fn reject(code: &'static str, command_id: Option<String>) -> Self {
        Self {
            command: None,
            rejection_code: Some(code),
            command_id,
        }
    }
}

/// An object's members in document order, values as raw JSON. Duplicates are kept so the
/// caller applies System.Text.Json's rules (case-insensitive names, last one wins).
struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MembersVisitor;

        impl<'de> Visitor<'de> for MembersVisitor {
            type Value = Members;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut members = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    members.push((key, map.next_value::<Box<RawValue>>()?));
                }
                Ok(Members(members))
            }
        }

        deserializer.deserialize_map(MembersVisitor)
    }
}

fn members(raw: &str) -> Option<Vec<(String, Box<RawValue>)>> {
    serde_json::from_str::<Members>(raw)
        .ok()
        .map(|members| members.0)
}

/// `string?` under System.Text.Json: a string or `null`; anything else is a JsonException.
fn optional_string(raw: &RawValue) -> Result<Option<String>, ()> {
    serde_json::from_str::<Option<String>>(raw.get()).map_err(|_| ())
}

#[derive(Default)]
struct Document {
    kind: Option<String>,
    command_id: Option<String>,
    collector_id: Option<String>,
    command: Option<String>,
    nonce: Option<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    signature: Option<SignatureDocument>,
}

#[derive(Default)]
struct SignatureDocument {
    algorithm: Option<String>,
    key_id: Option<String>,
    value: Option<String>,
}

/// C# `ManagementCommandDocument` with web defaults and `JsonUnmappedMemberHandling.Disallow`.
/// `None` on any JsonException.
fn parse_document(members: &[(String, Box<RawValue>)]) -> Option<Document> {
    let mut document = Document::default();
    for (key, value) in members {
        let is = |name: &str| key.eq_ignore_ascii_case(name);
        let slot = if is("kind") {
            &mut document.kind
        } else if is("commandId") {
            &mut document.command_id
        } else if is("collectorId") {
            &mut document.collector_id
        } else if is("command") {
            &mut document.command
        } else if is("nonce") {
            &mut document.nonce
        } else if is("issuedAt") {
            &mut document.issued_at
        } else if is("expiresAt") {
            &mut document.expires_at
        } else if is("signature") {
            document.signature = if value.get().trim() == "null" {
                None
            } else {
                Some(parse_signature(value.get())?)
            };
            continue;
        } else {
            // Every accepted field is signed.
            return None;
        };
        *slot = optional_string(value).ok()?;
    }
    Some(document)
}

/// `DetachedSignature` (no unmapped-member restriction: unknown members are skipped).
fn parse_signature(raw: &str) -> Option<SignatureDocument> {
    let mut signature = SignatureDocument::default();
    for (key, value) in members(raw)? {
        let is = |name: &str| key.eq_ignore_ascii_case(name);
        let slot = if is("algorithm") {
            &mut signature.algorithm
        } else if is("keyId") {
            &mut signature.key_id
        } else if is("value") {
            &mut signature.value
        } else {
            continue;
        };
        *slot = optional_string(&value).ok()?;
    }
    Some(signature)
}

/// Verifies one command document (C# `ManagementCommandVerifier.Verify`). Order: shape,
/// signature, collector binding, closed command set, validity window.
pub fn verify(
    raw: &str,
    collector_id: &str,
    trusted_public_key_pems: &[String],
    now: Timestamp,
) -> Verification {
    let Some(members) = members(raw) else {
        return Verification::reject(results::MALFORMED_COMMAND, None);
    };
    // Unverified documents never name a command: a tampered copy injected on the path must
    // not be able to mark the real command rejected.
    let malformed = || Verification::reject(results::MALFORMED_COMMAND, None);
    let Some(Document {
        kind: Some(kind),
        command_id: Some(command_id),
        collector_id: Some(document_collector),
        command: Some(command),
        nonce: Some(nonce),
        issued_at: Some(issued_text),
        expires_at: Some(expires_text),
        signature:
            Some(SignatureDocument {
                algorithm: Some(algorithm),
                key_id: Some(key_id),
                value: Some(value),
            }),
    }) = parse_document(&members)
    else {
        return malformed();
    };
    let (Some(issued_at), Some(expires_at)) = (
        parse_timestamp(&issued_text),
        parse_timestamp(&expires_text),
    ) else {
        return malformed();
    };
    let command_length = command.encode_utf16().count();
    if kind != KIND
        || !is_identifier(&command_id)
        || !is_identifier(&nonce)
        || command_length == 0
        || command_length > 64
    {
        return malformed();
    }

    let payload = signed_bytes(
        &command_id,
        &document_collector,
        &command,
        &nonce,
        &issued_text,
        &expires_text,
    );
    let signature = DetachedSignature {
        algorithm,
        key_id,
        value,
    };
    if !bower_integrity::signer::verify(
        &payload,
        &signature,
        trusted_public_key_pems.iter().map(String::as_str),
    ) {
        return Verification::reject(results::UNTRUSTED_SIGNATURE, None);
    }
    if document_collector != collector_id {
        return Verification::reject(results::WRONG_COLLECTOR, Some(command_id));
    }
    if !ALL.contains(&command.as_str()) {
        return Verification::reject(results::UNKNOWN_COMMAND, Some(command_id));
    }
    if issued_at > now + maximum_clock_skew() {
        return Verification::reject(results::NOT_YET_VALID, Some(command_id));
    }
    if expires_at <= now {
        return Verification::reject(results::EXPIRED, Some(command_id));
    }
    if expires_at <= issued_at || expires_at - issued_at > maximum_lifetime() {
        return Verification::reject(results::INVALID_LIFETIME, Some(command_id));
    }

    Verification {
        command: Some(VerifiedCommand {
            command_id: command_id.clone(),
            command,
            nonce,
            issued_at,
            expires_at,
        }),
        rejection_code: None,
        command_id: Some(command_id),
    }
}

/// Canonical JSON of kind, commandId, collectorId, command, nonce, issuedAt and expiresAt
/// (C# `ManagementCommandVerifier.SignedBytes` and the management API's signer).
pub fn signed_bytes(
    command_id: &str,
    collector_id: &str,
    command: &str,
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
) -> Vec<u8> {
    use serde_json::Value;
    let mut fields = serde_json::Map::new();
    for (name, value) in [
        ("kind", KIND),
        ("commandId", command_id),
        ("collectorId", collector_id),
        ("command", command),
        ("nonce", nonce),
        ("issuedAt", issued_at),
        ("expiresAt", expires_at),
    ] {
        fields.insert(name.into(), Value::String(value.into()));
    }
    bower_integrity::canonical_json::bytes(&Value::Object(fields))
}

/// 32 lowercase hex characters (a GUID "N" or 16 random bytes).
pub fn is_identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'`: the only accepted form.
pub fn format_timestamp(value: &Timestamp) -> String {
    let utc = bower_contracts::time::to_utc(*value);
    format!(
        "{}.{:07}Z",
        utc.format("%Y-%m-%dT%H:%M:%S"),
        chrono::Timelike::nanosecond(&utc) / 100
    )
}

/// `DateTimeOffset.TryParseExact` with the format above (UTC).
pub fn parse_timestamp(text: &str) -> Option<Timestamp> {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 28
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'.',
            27 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        });
    if !shape {
        return None;
    }
    // chrono reads `:60` as a leap second; System.Text.Json and DateTimeOffset do not.
    if &text[17..19] == "60" {
        return None;
    }
    NaiveDateTime::parse_from_str(&text[..27], "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|naive| naive.and_utc().fixed_offset())
}

// ------------------------------------------------------------------ ledger

/// One command result as reported on the heartbeat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandResultReport {
    pub command_id: Option<String>,
    pub status: String,
    pub code: String,
    #[serde(with = "serde_offset")]
    pub completed_at: Timestamp,
}

/// The last canary a `run-canary` command ran. `queued` is local admission, never
/// Sentinel proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryReport {
    pub command_id: String,
    pub event_id: Option<String>,
    #[serde(with = "serde_offset")]
    pub ran_at: Timestamp,
    pub outcome: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerEntry {
    command_id: String,
    nonce: String,
    command: String,
    #[serde(with = "serde_offset")]
    expires_at: Timestamp,
    status: String,
    code: Option<String>,
    #[serde(with = "serde_offset_option")]
    completed_at: Option<Timestamp>,
    acknowledged: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerDocument {
    schema_version: i32,
    entries: Option<Vec<LedgerEntry>>,
    last_canary: Option<CanaryReport>,
    #[serde(with = "serde_offset_option", default)]
    last_reload_at: Option<Timestamp>,
}

/// How the ledger admitted a verified command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// New: recorded as started; execute it once.
    Accepted,
    /// Same command id and nonce seen before: never execute again.
    Duplicate,
    /// Not executed; a rejection result is pending.
    Rejected,
}

#[derive(Default)]
struct LedgerState {
    entries: Vec<LedgerEntry>,
    rejections: Vec<CommandResultReport>,
    last_canary: Option<CanaryReport>,
    last_reload_at: Option<Timestamp>,
}

/// Durable record of every admitted command (C# `ManagementCommandLedger`). A ledger that
/// cannot be read refuses every command (`ledger-unavailable`) rather than risk running
/// one twice. Rejections of commands that never ran stay in memory (bounded).
pub struct CommandLedger {
    path: PathBuf,
    clock: Arc<dyn Clock>,
    available: bool,
    state: Mutex<LedgerState>,
}

impl CommandLedger {
    pub fn new(directory: &Path, clock: Arc<dyn Clock>) -> Self {
        let path = directory.join(LEDGER_FILE_NAME);
        let mut state = LedgerState::default();
        let available = if path.is_file() {
            match std::fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<LedgerDocument>(&bytes).ok())
            {
                Some(LedgerDocument {
                    schema_version: 1,
                    entries: Some(entries),
                    last_canary,
                    last_reload_at,
                }) => {
                    // A command still marked started belongs to a previous process that
                    // stopped before finishing it: report it, never run it again.
                    let now = clock.utc_now();
                    state.entries = entries
                        .into_iter()
                        .map(|mut entry| {
                            if entry.status == STARTED {
                                entry.status = results::FAILED.into();
                                entry.code = Some(results::INTERRUPTED.into());
                                entry.completed_at = Some(now);
                            }
                            entry
                        })
                        .collect();
                    state.last_canary = last_canary;
                    state.last_reload_at = last_reload_at;
                    true
                }
                _ => false,
            }
        } else {
            true
        };
        Self {
            path,
            clock,
            available,
            state: Mutex::new(state),
        }
    }

    pub fn available(&self) -> bool {
        self.available
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn last_canary(&self) -> Option<CanaryReport> {
        self.lock().last_canary.clone()
    }

    /// Records a verified command before it runs. Persisted before returning Accepted.
    pub fn admit(&self, command: &VerifiedCommand) -> Admission {
        let mut state = self.lock();
        if !self.available {
            self.add_rejection(
                &mut state,
                Some(command.command_id.clone()),
                results::LEDGER_UNAVAILABLE,
            );
            return Admission::Rejected;
        }
        if state
            .entries
            .iter()
            .any(|entry| entry.command_id == command.command_id && entry.nonce == command.nonce)
        {
            return Admission::Duplicate;
        }
        if state
            .entries
            .iter()
            .any(|entry| entry.command_id == command.command_id || entry.nonce == command.nonce)
        {
            self.add_rejection(
                &mut state,
                Some(command.command_id.clone()),
                results::REPLAYED,
            );
            return Admission::Rejected;
        }
        self.prune(&mut state);
        if state.entries.len() >= MAXIMUM_LEDGER_ENTRIES {
            self.add_rejection(
                &mut state,
                Some(command.command_id.clone()),
                results::LEDGER_FULL,
            );
            return Admission::Rejected;
        }
        state.entries.push(LedgerEntry {
            command_id: command.command_id.clone(),
            nonce: command.nonce.clone(),
            command: command.command.clone(),
            expires_at: command.expires_at,
            status: STARTED.into(),
            code: None,
            completed_at: None,
            acknowledged: false,
        });
        if self.save(&state).is_err() {
            // Not durably recorded, so it must not run: a restart could run it again.
            state.entries.pop();
            self.add_rejection(
                &mut state,
                Some(command.command_id.clone()),
                results::LEDGER_UNAVAILABLE,
            );
            return Admission::Rejected;
        }
        Admission::Accepted
    }

    /// A command refused before admission (never executed).
    pub fn reject(&self, command_id: Option<String>, code: &str) {
        let mut state = self.lock();
        self.add_rejection(&mut state, command_id, code);
    }

    pub fn complete(&self, command_id: &str, status: &str, code: &str) -> std::io::Result<()> {
        let mut state = self.lock();
        let now = self.clock.utc_now();
        let Some(entry) = state
            .entries
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
        else {
            return Ok(());
        };
        entry.status = status.into();
        entry.code = Some(code.into());
        entry.completed_at = Some(now);
        self.save(&state)
    }

    pub fn record_canary(&self, report: CanaryReport) -> std::io::Result<()> {
        let mut state = self.lock();
        state.last_canary = Some(report);
        self.save(&state)
    }

    /// True when no reload ran within the last 10 minutes; records nothing (C# `IsReloadAllowed`).
    pub fn reload_allowed(&self) -> bool {
        let state = self.lock();
        let now = self.clock.utc_now();
        !state
            .last_reload_at
            .is_some_and(|last| now - last < reload_interval() && now >= last)
    }

    /// True (and recorded) when no reload ran within the last 10 minutes.
    pub fn try_begin_reload(&self) -> std::io::Result<bool> {
        let mut state = self.lock();
        let now = self.clock.utc_now();
        if let Some(last) = state.last_reload_at
            && now - last < reload_interval()
            && now >= last
        {
            return Ok(false);
        }
        state.last_reload_at = Some(now);
        self.save(&state)?;
        Ok(true)
    }

    /// Finished, unacknowledged results (oldest first), then pending rejections.
    pub fn pending_results(&self) -> Vec<CommandResultReport> {
        let state = self.lock();
        let now = self.clock.utc_now();
        state
            .entries
            .iter()
            .filter(|entry| !entry.acknowledged && entry.status != STARTED)
            .map(|entry| CommandResultReport {
                command_id: Some(entry.command_id.clone()),
                status: entry.status.clone(),
                code: entry.code.clone().unwrap_or_else(|| entry.status.clone()),
                completed_at: entry.completed_at.unwrap_or(now),
            })
            .chain(state.rejections.iter().cloned())
            .take(MAXIMUM_REPORTED_RESULTS)
            .collect()
    }

    /// Management acknowledged these results. Rejections without a readable command id
    /// can never be acknowledged, so they are dropped once reported.
    pub fn acknowledge(&self, command_ids: &[String], reported: &[CommandResultReport]) {
        let mut state = self.lock();
        state.rejections.retain(|result| match &result.command_id {
            None => !reported.contains(result),
            Some(id) => !command_ids.contains(id),
        });
        let mut changed = false;
        for entry in &mut state.entries {
            if !entry.acknowledged
                && entry.status != STARTED
                && command_ids.contains(&entry.command_id)
            {
                entry.acknowledged = true;
                changed = true;
            }
        }
        if changed {
            self.prune(&mut state);
            if let Err(error) = self.save(&state) {
                warn!(
                    error_kind = ?error.kind(),
                    "Management command ledger could not be saved."
                );
            }
        }
    }

    fn add_rejection(&self, state: &mut LedgerState, command_id: Option<String>, code: &str) {
        if command_id.is_some()
            && state
                .rejections
                .iter()
                .any(|result| result.command_id == command_id)
        {
            return;
        }
        if state.rejections.len() >= MAXIMUM_PENDING_REJECTIONS {
            state.rejections.remove(0);
        }
        state.rejections.push(CommandResultReport {
            command_id,
            status: results::REJECTED.into(),
            code: code.into(),
            completed_at: self.clock.utc_now(),
        });
    }

    /// Drops acknowledged entries whose command expired and unacknowledged results long
    /// past expiry.
    fn prune(&self, state: &mut LedgerState) {
        let now = self.clock.utc_now();
        state.entries.retain(|entry| {
            entry.status == STARTED
                || !((entry.acknowledged && entry.expires_at <= now)
                    || entry.expires_at + unacknowledged_retention() <= now)
        });
    }

    fn save(&self, state: &LedgerState) -> std::io::Result<()> {
        let document = LedgerDocument {
            schema_version: 1,
            entries: Some(state.entries.clone()),
            last_canary: state.last_canary.clone(),
            last_reload_at: state.last_reload_at,
        };
        let bytes = bower_contracts::json::to_vec(&document).map_err(std::io::Error::other)?;
        crate::managed_privacy::write_atomically(&self.path, &bytes)
    }
}

// ------------------------------------------------------------------ response processing

/// C# `ManagementHeartbeatResponse` read with web defaults: case-insensitive names, last
/// duplicate wins, unknown members ignored, numbers allowed from strings.
#[derive(Default)]
struct HeartbeatResponse {
    schema_version: Option<i64>,
    commands: Option<Vec<Box<RawValue>>>,
    acknowledged_results: Option<Vec<Option<String>>>,
}

fn parse_response(body: &[u8]) -> Result<Option<HeartbeatResponse>, ()> {
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    if text.trim() == "null" {
        return Ok(None);
    }
    let mut response = HeartbeatResponse::default();
    for (key, value) in members(text).ok_or(())? {
        let is = |name: &str| key.eq_ignore_ascii_case(name);
        if is("schemaVersion") {
            response.schema_version =
                match serde_json::from_str::<serde_json::Value>(value.get()).map_err(|_| ())? {
                    serde_json::Value::Null => None,
                    serde_json::Value::Number(number) => {
                        Some(number.as_str().parse::<i32>().map_err(|_| ())?.into())
                    }
                    serde_json::Value::String(text) => {
                        Some(text.parse::<i32>().map_err(|_| ())?.into())
                    }
                    _ => return Err(()),
                };
        } else if is("commands") {
            response.commands =
                serde_json::from_str::<Option<Vec<Box<RawValue>>>>(value.get()).map_err(|_| ())?;
        } else if is("acknowledgedResults") {
            response.acknowledged_results =
                serde_json::from_str::<Option<Vec<Option<String>>>>(value.get()).map_err(|_| ())?;
        } else {
            // A v1 collector record and future additive fields.
            serde_json::from_str::<serde::de::IgnoredAny>(value.get()).map_err(|_| ())?;
        }
    }
    Ok(Some(response))
}

/// C# `LoadTrustedKeys`: every configured key must be a readable ECDSA P-256 public key PEM;
/// otherwise no key is trusted (fail closed) and a metadata-only error names the setting.
fn load_trusted_keys(paths: &[String]) -> Vec<String> {
    let mut keys = Vec::with_capacity(paths.len());
    for path in paths {
        let loaded = read_all_text(path)
            .map_err(|error| error.kind)
            .and_then(|pem| {
                bower_integrity::signer::key_id_from_public_key_pem(&pem)
                    .map(|_| pem)
                    .map_err(|_| "CryptographicException")
            });
        match loaded {
            Ok(pem) => keys.push(pem),
            Err(exception_type) => {
                tracing::error!(
                    count = paths.len(),
                    exception_type,
                    "BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS must all be readable ECDSA P-256 public \
                     key PEM files; management commands are disabled."
                );
                return Vec::new();
            }
        }
    }
    keys
}

/// Verifies, admits and queues the commands in a heartbeat v2 response (C#
/// `ManagementCommandProcessor`). Never executes a command.
pub struct CommandProcessor {
    collector_id: String,
    /// Parsed once at start-up: a missing or invalid key disables commands entirely.
    trusted_keys: Vec<String>,
    supported: Vec<&'static str>,
    ledger: Arc<CommandLedger>,
    inbox: mpsc::Sender<VerifiedCommand>,
    clock: Arc<dyn Clock>,
}

impl CommandProcessor {
    pub fn new(
        settings: &CollectorSettings,
        ledger: Arc<CommandLedger>,
        inbox: mpsc::Sender<VerifiedCommand>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            collector_id: settings.collector_id.clone(),
            trusted_keys: load_trusted_keys(&settings.management_command_trusted_key_files),
            supported: supported(settings),
            ledger,
            inbox,
            clock,
        }
    }

    pub fn ledger(&self) -> &Arc<CommandLedger> {
        &self.ledger
    }

    /// Advertised on the heartbeat; empty when commands cannot be run safely.
    pub fn capabilities(&self) -> Vec<&'static str> {
        if self.ledger.available() && !self.trusted_keys.is_empty() {
            self.supported.clone()
        } else {
            Vec::new()
        }
    }

    /// `body` is `None` when the response exceeded [`MAXIMUM_RESPONSE_BYTES`].
    pub fn handle_response(
        &self,
        body: Option<&[u8]>,
        reported: &[CommandResultReport],
    ) -> Result<(), &'static str> {
        let Some(body) = body else {
            warn!(
                "Management heartbeat response exceeded the size limit; its commands were ignored."
            );
            return Ok(());
        };
        let response = if body.is_empty() {
            None
        } else {
            match parse_response(body) {
                Ok(response) => response,
                Err(()) => {
                    warn!(
                        "Management heartbeat response is not valid JSON; its commands were ignored."
                    );
                    return Ok(());
                }
            }
        };
        // A v1 management API answers with its collector record: no commands, no
        // acknowledgements.
        let Some(response) = response.filter(|response| response.schema_version == Some(2)) else {
            return Ok(());
        };

        let acknowledged: Vec<String> = response
            .acknowledged_results
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect();
        self.ledger.acknowledge(&acknowledged, reported);
        let commands = response.commands.unwrap_or_default();
        if commands.is_empty() {
            return Ok(());
        }

        let trusted = &self.trusted_keys;
        let now = self.clock.utc_now();
        let (mut accepted, mut refused) = (0usize, 0usize);
        for raw in commands.iter().take(MAXIMUM_COMMANDS_PER_RESPONSE) {
            let verification = verify(raw.get(), &self.collector_id, trusted, now);
            if trusted.is_empty() {
                self.ledger
                    .reject(verification.command_id, results::COMMANDS_NOT_CONFIGURED);
                refused += 1;
                continue;
            }
            let Some(command) = verification.command else {
                self.ledger.reject(
                    verification.command_id,
                    verification
                        .rejection_code
                        .unwrap_or(results::MALFORMED_COMMAND),
                );
                refused += 1;
                continue;
            };
            if !self.supported.contains(&command.command.as_str()) {
                self.ledger
                    .reject(Some(command.command_id), results::UNSUPPORTED_COMMAND);
                refused += 1;
                continue;
            }
            match self.ledger.admit(&command) {
                Admission::Accepted => {
                    if self.inbox.try_send(command.clone()).is_ok() {
                        accepted += 1;
                    } else {
                        let _ = self.ledger.complete(
                            &command.command_id,
                            results::FAILED,
                            results::EXECUTOR_BUSY,
                        );
                        refused += 1;
                    }
                }
                Admission::Rejected => refused += 1,
                Admission::Duplicate => {}
            }
        }
        info!(
            count = commands.len(),
            accepted, refused, "Management sent command(s)."
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ worker

/// C# `ManagementCommandWorker.ReloadRefusal`: loads everything a restart loads from files,
/// through the same code start-up runs (`bundle::load`, then `startup::load`). `None` when
/// they load; otherwise the failure type only, never its message. Environment changes are
/// not visible here.
pub fn reload_refusal(settings: &CollectorSettings) -> Option<&'static str> {
    let clock: Arc<dyn Clock> = Arc::new(bower_contracts::time::SystemClock);
    match crate::bundle::load(settings) {
        Err(error) => Some(error.kind),
        Ok(bundle) => crate::startup::load(settings, &bundle.packs, clock)
            .err()
            .map(|error| error.kind),
    }
}

/// Executes admitted commands (C# `ManagementCommandWorker`). A task beside the delivery
/// worker, not a scheduled job: a canary is queued through the normal pipeline
/// (redaction and policy first), which is queue state.
pub struct CommandWorker {
    pub ledger: Arc<CommandLedger>,
    pub triggers: JobTriggers,
    pub processor: SecurityEventProcessor,
    pub identity: CollectorIdentity,
    pub environment: String,
    pub clock: Arc<dyn Clock>,
    pub lifetime: ApplicationLifetime,
    /// Token enrolment: performs `rotate-credential`.
    pub enrolment: Option<Arc<crate::enrolment::ManagementEnrolment>>,
    /// The configuration a restart would load, checked before `reload` restarts.
    pub settings: Arc<CollectorSettings>,
}

impl CommandWorker {
    pub async fn run(self, mut inbox: mpsc::Receiver<VerifiedCommand>, shutdown: ShutdownToken) {
        loop {
            let command = tokio::select! {
                command = inbox.recv() => command,
                () = shutdown.cancelled() => return,
            };
            let Some(command) = command else {
                return;
            };
            self.execute(&command).await;
        }
    }

    pub async fn execute(&self, command: &VerifiedCommand) {
        let outcome = match command.command.as_str() {
            FETCH_BUNDLE => Ok(if self.triggers.trigger(MANAGED_PRIVACY_PROFILE_JOB_ID) {
                (results::SUCCEEDED, results::FETCH_TRIGGERED.to_string())
            } else {
                (results::FAILED, results::FETCH_UNAVAILABLE.to_string())
            }),
            RUN_CANARY => self.run_canary(command).await,
            RELOAD => self.reload(command).await,
            ROTATE_CREDENTIAL if self.enrolment.is_some() => {
                let (status, code) = match &self.enrolment {
                    Some(enrolment) => enrolment.rotate().await,
                    None => (results::FAILED, results::UNSUPPORTED_COMMAND),
                };
                Ok((status, code.to_string()))
            }
            _ => Ok((results::FAILED, results::UNSUPPORTED_COMMAND.to_string())),
        };
        match outcome {
            Ok((status, code)) => {
                let recorded = if command.command == RELOAD && status == results::SUCCEEDED {
                    Ok(())
                } else {
                    self.ledger.complete(&command.command_id, status, &code)
                };
                match recorded {
                    Ok(()) => info!(
                        command = command.command.as_str(),
                        status, code, "Management command finished."
                    ),
                    Err(_) => warn!(
                        command = command.command.as_str(),
                        exception_type = "IOException",
                        "Management command failed."
                    ),
                }
            }
            Err(failure) => {
                warn!(
                    command = command.command.as_str(),
                    exception_type = failure,
                    "Management command failed."
                );
                // Still `started` on disk if this fails: a restart reports it as interrupted.
                let _ = self.ledger.complete(
                    &command.command_id,
                    results::FAILED,
                    results::EXECUTION_FAILED,
                );
            }
        }
    }

    async fn reload(
        &self,
        command: &VerifiedCommand,
    ) -> Result<(&'static str, String), &'static str> {
        // The rate limit first, without recording: a refused reload does not use the slot.
        if !self.ledger.reload_allowed() {
            return Ok((results::FAILED, results::RELOAD_RATE_LIMITED.into()));
        }
        let settings = Arc::clone(&self.settings);
        let refusal = tokio::task::spawn_blocking(move || reload_refusal(&settings))
            .await
            .map_err(|_| "TaskCanceledException")?;
        if let Some(failure) = refusal {
            // Keep running with the configuration already loaded: a restart that cannot load
            // its packs, trust keys or privacy key would stop collection altogether.
            error!(
                failure_type = failure,
                "Reload refused: the restarted collector could not load its configuration. The current configuration stays active."
            );
            return Ok((results::FAILED, results::RELOAD_VALIDATION_FAILED.into()));
        }
        if !self.ledger.try_begin_reload().map_err(|_| "IOException")? {
            return Ok((results::FAILED, results::RELOAD_RATE_LIMITED.into()));
        }
        // Recorded before stopping, so the result survives the restart and is reported then.
        self.ledger
            .complete(
                &command.command_id,
                results::SUCCEEDED,
                results::RESTART_REQUESTED,
            )
            .map_err(|_| "IOException")?;
        self.lifetime.request_restart();
        Ok((results::SUCCEEDED, results::RESTART_REQUESTED.into()))
    }

    async fn run_canary(
        &self,
        command: &VerifiedCommand,
    ) -> Result<(&'static str, String), &'static str> {
        let ran_at = self.clock.utc_now();
        let event_id = format!("bower-canary-{}", uuid::Uuid::now_v7().simple());
        let json = canary_json(&event_id, ran_at, &self.environment, &command.command_id)
            .map_err(|_| "JsonException")?;
        let processor = self.processor.clone();
        let identity = CollectorIdentity {
            source_adapter: CANARY_SOURCE_ADAPTER.into(),
            ..self.identity.clone()
        };
        let result = tokio::task::spawn_blocking(move || processor.process(&json, &identity))
            .await
            .map_err(|_| "JoinError")?;
        let outcome = match result {
            Ok(result) if result.duplicate => "duplicate",
            Ok(result) if result.queued => "queued",
            Ok(result) if result.action == DecisionAction::Reject => "rejected",
            Ok(_) => "quarantined",
            Err(ProcessError::Store(StoreError::Full(_))) => "failed",
            Err(ProcessError::Store(_)) => return Err("SqliteException"),
            Err(ProcessError::Serialization(_)) => return Err("JsonException"),
        };
        self.ledger
            .record_canary(CanaryReport {
                command_id: command.command_id.clone(),
                event_id: Some(event_id),
                ran_at,
                outcome: outcome.into(),
            })
            .map_err(|_| "IOException")?;
        Ok(if matches!(outcome, "queued" | "duplicate") {
            (results::SUCCEEDED, results::CANARY_QUEUED.into())
        } else {
            (results::FAILED, format!("canary-{outcome}"))
        })
    }
}

/// A synthetic collector-health canary (C# `ManagementCommandWorker.CanaryJson`). No user
/// data; it goes through the same redaction and policy as any event.
pub fn canary_json(
    event_id: &str,
    at: Timestamp,
    environment: &str,
    command_id: &str,
) -> Result<String, serde_json::Error> {
    let canary = SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: event_id.to_owned(),
        event_original_id: Some(event_id.to_owned()),
        time_generated: at,
        time_observed: None,
        event_category: event_categories::COLLECTOR_HEALTH.to_owned(),
        event_type: event_types::COLLECTOR_CANARY.to_owned(),
        event_action: "management.canary".to_owned(),
        event_result: EventResult::Success,
        event_severity: EventSeverity::Informational,
        event_outcome_reason: Some("Synthetic management canary".to_owned()),
        application: ApplicationContext {
            name: "bower-collector".to_owned(),
            version: None,
            environment: environment.to_owned(),
            instance: None,
            tenant_id: None,
        },
        actor: Some(ActorContext {
            username: Some("bower.management".to_owned()),
            actor_type: ActorType::System,
            ..ActorContext::default()
        }),
        target: None,
        source: None,
        request: Some(RequestContext {
            correlation_id: Some(event_id.to_owned()),
            ..RequestContext::default()
        }),
        change: None,
        security: None,
        collector: None,
        labels: Some(
            [
                ("evidenceType".to_owned(), "canary".to_owned()),
                ("commandId".to_owned(), command_id.to_owned()),
            ]
            .into_iter()
            .collect(),
        ),
        attributes: None,
        privacy: None,
    };
    bower_contracts::json::to_string(&canary)
}
