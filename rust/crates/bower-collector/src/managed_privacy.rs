//! Managed privacy profiles (C# `ManagedPrivacyProfileCache`, `ManagedPrivacyProfileState`,
//! `ManagedPrivacyProfileGateFilter` and `Jobs/ManagedPrivacyProfileJob`), active when
//! `BOWER_PRIVACY_PROFILE_SOURCE=management`.
//!
//! Management serves a signed assignment envelope: `assigned` (collector id, assignment
//! revision, version fields, content, issue time) or an explicit `cleared` (collector id,
//! revision, issue time). An envelope is trusted only when a configured key signed the
//! canonical JSON of exactly those fields, it names this collector and (when assigned) the
//! privacy profile loader accepts its content with the collector's real HMAC key and the
//! content hash matches. The cache holds the last verified envelope and is the revision
//! high-water mark. Unverified content is never written to disk. Messages and logs are
//! metadata only.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_integrity::DetachedSignature;
use bower_redaction::LoadedPrivacyProfile;
use reqwest::{StatusCode, Url};
use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use tracing::{error, info, warn};

use crate::error::HostError;
use crate::heartbeat::{AccessTokenSource, escape_data_string};
use crate::settings::{CollectorSettings, read_all_text};
use crate::shutdown::ApplicationLifetime;

/// Cache file inside the managed privacy directory: the last verified envelope.
pub const CACHE_FILE_NAME: &str = "profile.json";

/// Upper bound for a deployment document (a 256 KiB profile, JSON-escaped).
pub const MAXIMUM_DOCUMENT_BYTES: usize = 1_048_576;

/// EX_TEMPFAIL: the process exit code after a deliberate restart to apply a new (or
/// cleared) privacy profile, so `Restart=on-failure` supervisors also restart it.
pub const RESTART_EXIT_CODE: u8 = 75;

/// `action` of an envelope that assigns a privacy profile version.
pub const ACTION_ASSIGNED: &str = "assigned";
/// `action` of an explicit, signed clear (the built-in default privacy profile).
pub const ACTION_CLEARED: &str = "cleared";

/// `System.Text.Json` default `MaxDepth` for the deployment document.
const MAXIMUM_DOCUMENT_DEPTH: usize = 64;

/// A managed privacy profile that failed verification (C#
/// `ManagedPrivacyProfileException`). Messages are metadata only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedPrivacyProfileError(pub String);

impl ManagedPrivacyProfileError {
    pub const TYPE_NAME: &'static str = "ManagedPrivacyProfileException";

    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManagedPrivacyProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ManagedPrivacyProfileError {}

impl From<ManagedPrivacyProfileError> for HostError {
    fn from(error: ManagedPrivacyProfileError) -> Self {
        HostError::new(ManagedPrivacyProfileError::TYPE_NAME, error.0)
    }
}

/// A signed, collector-bound assignment envelope. `action` is [`ACTION_ASSIGNED`] (with a
/// loader-validated `profile`) or [`ACTION_CLEARED`] (the built-in default; profile fields
/// are `None`). `signed_payload` is the canonical JSON the signature covers, used to
/// compare same-revision documents.
#[derive(Clone, Debug)]
pub struct VerifiedManagedPrivacyProfile {
    pub action: &'static str,
    pub assignment_revision: i64,
    pub profile: Option<LoadedPrivacyProfile>,
    pub version_id: Option<String>,
    pub profile_id: Option<String>,
    pub version: Option<String>,
    pub content_hash: Option<String>,
    pub signed_payload: Vec<u8>,
}

impl VerifiedManagedPrivacyProfile {
    pub fn is_cleared(&self) -> bool {
        self.action == ACTION_CLEARED
    }
}

/// `<managed privacy directory>/profile.json`.
pub fn cache_path(settings: &CollectorSettings) -> PathBuf {
    settings
        .managed_privacy_cache_directory()
        .join(CACHE_FILE_NAME)
}

/// The trusted signing keys (`File.ReadAllText` of each configured PEM file).
pub fn read_trusted_keys(settings: &CollectorSettings) -> Result<Vec<String>, HostError> {
    settings
        .managed_privacy_trusted_key_files
        .iter()
        .map(|path| read_all_text(path))
        .collect()
}

/// The verified cached envelope, or `None` when there is no cache. Any verification
/// failure is a `ManagedPrivacyProfileException` with a metadata-only message (start-up
/// fails closed).
pub fn load_verified(
    settings: &CollectorSettings,
    hmac_key: Option<&[u8]>,
) -> Result<Option<VerifiedManagedPrivacyProfile>, HostError> {
    let path = cache_path(settings);
    if !path.is_file() {
        return Ok(None);
    }

    let document = std::fs::read(&path).map_err(|error| HostError::io(&path, &error))?;
    let trusted = read_trusted_keys(settings)?;
    verify(
        &document,
        &settings.collector_id,
        &trusted,
        hmac_key,
        &settings.privacy_hmac_key_id,
    )
    .map(Some)
    .map_err(|error| {
        HostError::new(
            ManagedPrivacyProfileError::TYPE_NAME,
            format!(
                "Managed privacy profile cache {} failed verification: {} \
                 Delete the cache file to fetch the current assignment again.",
                path.display(),
                error.0
            ),
        )
    })
}

/// Verifies an assignment envelope (C# `ManagedPrivacyProfileCache.Verify`).
pub fn verify(
    json: &[u8],
    collector_id: &str,
    trusted_public_key_pems: &[String],
    hmac_key: Option<&[u8]>,
    hmac_key_id: &str,
) -> Result<VerifiedManagedPrivacyProfile, ManagedPrivacyProfileError> {
    if json.len() > MAXIMUM_DOCUMENT_BYTES {
        return Err(ManagedPrivacyProfileError::new(
            "Managed privacy profile document is too large.",
        ));
    }

    let incomplete =
        || ManagedPrivacyProfileError::new("Managed privacy profile document is incomplete.");
    let document = parse_document(json)
        .ok_or_else(|| {
            ManagedPrivacyProfileError::new("Managed privacy profile document is not valid JSON.")
        })?
        .ok_or_else(incomplete)?;
    let (
        Some(document_collector),
        Some(revision),
        Some(action),
        Some(issued_at),
        Some(SignatureDocument {
            algorithm: Some(algorithm),
            key_id: Some(key_id),
            value: Some(value),
        }),
    ) = (
        document.collector_id,
        document
            .assignment_revision
            .filter(|revision| *revision > 0),
        document.action.as_deref().and_then(|action| match action {
            ACTION_ASSIGNED => Some(ACTION_ASSIGNED),
            ACTION_CLEARED => Some(ACTION_CLEARED),
            _ => None,
        }),
        document.issued_at,
        document.signature,
    )
    else {
        return Err(incomplete());
    };

    let assigned = action == ACTION_ASSIGNED;
    let profile_fields = [
        &document.version_id,
        &document.profile_id,
        &document.version,
        &document.content_hash,
        &document.content,
    ];
    let complete = if assigned {
        profile_fields.iter().all(|field| field.is_some())
    } else {
        profile_fields.iter().all(|field| field.is_none())
    };
    if !complete {
        return Err(incomplete());
    }

    let payload = signed_bytes(
        &document_collector,
        revision,
        action,
        document.version_id.as_deref(),
        document.profile_id.as_deref(),
        document.version.as_deref(),
        document.content_hash.as_deref(),
        document.content.as_deref(),
        &issued_at,
    );
    let signature = DetachedSignature {
        algorithm,
        key_id,
        value,
    };
    if !bower_integrity::verify(
        &payload,
        &signature,
        trusted_public_key_pems.iter().map(String::as_str),
    ) {
        return Err(ManagedPrivacyProfileError::new(
            "Managed privacy profile signature is not trusted.",
        ));
    }

    if document_collector != collector_id {
        return Err(ManagedPrivacyProfileError::new(
            "Managed privacy profile was issued for a different collector.",
        ));
    }

    if !assigned {
        return Ok(VerifiedManagedPrivacyProfile {
            action: ACTION_CLEARED,
            assignment_revision: revision,
            profile: None,
            version_id: None,
            profile_id: None,
            version: None,
            content_hash: None,
            signed_payload: payload,
        });
    }

    let (Some(profile_id), Some(version), Some(content), Some(content_hash)) = (
        document.profile_id,
        document.version,
        document.content,
        document.content_hash,
    ) else {
        return Err(incomplete());
    };
    let profile = bower_redaction::load_privacy_profile(&content, hmac_key, Some(hmac_key_id))
        .map_err(|error| {
            ManagedPrivacyProfileError::new(format!(
                "Managed privacy profile {profile_id}@{version} failed validation: {error}"
            ))
        })?;

    if profile.hash != content_hash {
        return Err(ManagedPrivacyProfileError::new(format!(
            "Managed privacy profile {profile_id}@{version} content hash does not match."
        )));
    }

    if profile.id.as_deref() != Some(profile_id.as_str())
        || profile.version.as_deref() != Some(version.as_str())
    {
        return Err(ManagedPrivacyProfileError::new(format!(
            "Managed privacy profile {profile_id}@{version} metadata does not match its content."
        )));
    }

    Ok(VerifiedManagedPrivacyProfile {
        action: ACTION_ASSIGNED,
        assignment_revision: revision,
        profile: Some(profile),
        version_id: document.version_id,
        profile_id: Some(profile_id),
        version: Some(version),
        content_hash: Some(content_hash),
        signed_payload: payload,
    })
}

/// Canonical JSON of exactly the signed fields. Matches the management API's
/// `ManagedPrivacyProfileSigner.SignedBytes` byte for byte (`bower_integrity` canonical
/// JSON: ordinal key order, `JavaScriptEncoder.Default` escaping, the revision as a JSON
/// integer): `assigned` signs collectorId, assignmentRevision, action, versionId,
/// profileId, version, contentHash, content and issuedAt; `cleared` signs collectorId,
/// assignmentRevision, action and issuedAt.
#[allow(clippy::too_many_arguments)]
pub fn signed_bytes(
    collector_id: &str,
    assignment_revision: i64,
    action: &str,
    version_id: Option<&str>,
    profile_id: Option<&str>,
    version: Option<&str>,
    content_hash: Option<&str>,
    content: Option<&str>,
    issued_at: &str,
) -> Vec<u8> {
    use serde_json::Value;
    let text = |value: &str| Value::String(value.into());
    let mut fields = serde_json::Map::new();
    fields.insert("collectorId".into(), text(collector_id));
    fields.insert(
        "assignmentRevision".into(),
        Value::Number(assignment_revision.into()),
    );
    fields.insert("action".into(), text(action));
    fields.insert("issuedAt".into(), text(issued_at));
    if action == ACTION_ASSIGNED {
        for (name, value) in [
            ("versionId", version_id),
            ("profileId", profile_id),
            ("version", version),
            ("contentHash", content_hash),
            ("content", content),
        ] {
            fields.insert(name.into(), value.map_or(Value::Null, text));
        }
    }
    bower_integrity::canonical_json::bytes(&Value::Object(fields))
}

/// Replaces `path` atomically: write a temporary file in the same directory, flush it to
/// disk, rename it over the target, then flush the directory entry (Unix). A crash
/// leaves either the old or the new complete file, never a partial one.
pub fn write_atomically(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let full = crate::settings::full_path(path);
    let directory = full.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Cache path has no directory.",
        )
    })?;
    std::fs::create_dir_all(directory)?;
    let file_name = full
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = directory.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &full)?;
        sync_directory(directory)
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Makes the rename durable. Divergence from C#, which does not flush the directory.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> std::io::Result<()> {
    Ok(())
}

// ------------------------------------------------------------------ document parsing

/// Wire shape of the signed envelope (C# `ManagedPrivacyProfileDocument`), read like
/// `System.Text.Json` with web defaults plus `JsonUnmappedMemberHandling.Disallow` and
/// `JsonNumberHandling.Strict`: case-insensitive (ASCII) property names, last duplicate
/// wins, unknown top-level members rejected (unknown signature members are skipped),
/// `null` as absent, the revision only as a JSON integer.
#[derive(Default)]
struct Document {
    collector_id: Option<String>,
    assignment_revision: Option<i64>,
    action: Option<String>,
    version_id: Option<String>,
    profile_id: Option<String>,
    version: Option<String>,
    content_hash: Option<String>,
    content: Option<String>,
    issued_at: Option<String>,
    signature: Option<SignatureDocument>,
}

#[derive(Default)]
struct SignatureDocument {
    algorithm: Option<String>,
    key_id: Option<String>,
    value: Option<String>,
}

/// `JsonSerializer.Deserialize`: `None` on any `JsonException`; `Some(None)` for a JSON
/// `null` root.
fn parse_document(json: &[u8]) -> Option<Option<Document>> {
    if crate::app::exceeds_depth(json, MAXIMUM_DOCUMENT_DEPTH) {
        return None;
    }
    serde_json::from_slice::<Option<Document>>(json).ok()
}

/// `Utf8JsonReader.GetInt64` under strict number handling: a JSON number token whose
/// text is an integer in range (`-0` is 0); fractions, exponents and strings fail.
struct Revision(i64);

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let number = serde_json::Number::deserialize(deserializer)?;
        number
            .as_str()
            .parse::<i64>()
            .map(Revision)
            .map_err(|_| de::Error::custom("assignmentRevision is not an Int64"))
    }
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DocumentVisitor;

        impl<'de> Visitor<'de> for DocumentVisitor {
            type Value = Document;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a managed privacy profile object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Document, A::Error> {
                let mut document = Document::default();
                while let Some(key) = map.next_key::<String>()? {
                    let is = |name: &str| key.eq_ignore_ascii_case(name);
                    let slot = if is("collectorId") {
                        &mut document.collector_id
                    } else if is("action") {
                        &mut document.action
                    } else if is("versionId") {
                        &mut document.version_id
                    } else if is("profileId") {
                        &mut document.profile_id
                    } else if is("version") {
                        &mut document.version
                    } else if is("contentHash") {
                        &mut document.content_hash
                    } else if is("content") {
                        &mut document.content
                    } else if is("issuedAt") {
                        &mut document.issued_at
                    } else if is("assignmentRevision") {
                        document.assignment_revision = map
                            .next_value::<Option<Revision>>()?
                            .map(|revision| revision.0);
                        continue;
                    } else if is("signature") {
                        document.signature = map.next_value()?;
                        continue;
                    } else {
                        // JsonUnmappedMemberHandling.Disallow: every accepted field is signed.
                        return Err(de::Error::custom("unmapped member"));
                    };
                    *slot = map.next_value()?;
                }
                Ok(document)
            }
        }

        deserializer.deserialize_map(DocumentVisitor)
    }
}

impl<'de> Deserialize<'de> for SignatureDocument {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = SignatureDocument;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a detached signature object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<SignatureDocument, A::Error> {
                let mut signature = SignatureDocument::default();
                while let Some(key) = map.next_key::<String>()? {
                    let is = |name: &str| key.eq_ignore_ascii_case(name);
                    let slot = if is("algorithm") {
                        &mut signature.algorithm
                    } else if is("keyId") {
                        &mut signature.key_id
                    } else if is("value") {
                        &mut signature.value
                    } else {
                        // `DetachedSignature` keeps the default: unknown members skipped.
                        map.next_value::<IgnoredAny>()?;
                        continue;
                    };
                    *slot = map.next_value()?;
                }
                Ok(signature)
            }
        }

        deserializer.deserialize_map(SignatureVisitor)
    }
}

// ------------------------------------------------------------------ ingest gate state

pub const STATE_AWAITING_FIRST_SYNC: &str = "awaiting-first-sync";
pub const STATE_DEFAULT_ALLOWED: &str = "default-allowed";
pub const STATE_NEVER_ASSIGNED: &str = "never-assigned";
pub const STATE_ASSIGNED: &str = "assigned";
pub const STATE_CLEARED: &str = "cleared";
pub const STATE_RESTART_PENDING: &str = "restart-pending";

/// Fixed 503 body while ingest is gated.
pub const GATE_MESSAGE: &str =
    "Collector is waiting for its managed privacy profile from management; retry later.";
/// `Retry-After` while ingest is gated.
pub const GATE_RETRY_AFTER_SECONDS: &str = "30";

/// Management mode only: whether the collector has resolved its managed privacy profile
/// and may accept events (C# `ManagedPrivacyProfileState`). Without a verified cache it
/// starts `awaiting-first-sync` and refuses ingest (HTTP 503) until a sync returns a
/// verified document or 204 (never assigned, so the built-in default is intended).
/// `BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT=true` starts as `default-allowed` instead.
pub struct ManagedPrivacyState {
    local: bool,
    inner: Mutex<StateInner>,
}

#[derive(Clone, Copy)]
struct StateInner {
    state: &'static str,
    revision: Option<i64>,
    accepts_events: bool,
}

impl ManagedPrivacyState {
    /// Local mode: no managed privacy profile, ingest is never gated.
    pub fn local() -> Self {
        Self {
            local: true,
            inner: Mutex::new(StateInner {
                state: "local",
                revision: None,
                accepts_events: true,
            }),
        }
    }

    /// Start-up state from the verified cached envelope (the one the bundle loaded).
    pub fn new(cached: Option<&VerifiedManagedPrivacyProfile>, allow_default: bool) -> Self {
        let inner = match cached {
            Some(cached) => StateInner {
                state: if cached.is_cleared() {
                    STATE_CLEARED
                } else {
                    STATE_ASSIGNED
                },
                revision: Some(cached.assignment_revision),
                accepts_events: true,
            },
            None => StateInner {
                state: if allow_default {
                    STATE_DEFAULT_ALLOWED
                } else {
                    STATE_AWAITING_FIRST_SYNC
                },
                revision: None,
                accepts_events: allow_default,
            },
        };
        Self {
            local: false,
            inner: Mutex::new(inner),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StateInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// True in local mode (status reports `null` state and revision).
    pub fn is_local(&self) -> bool {
        self.local
    }

    /// One of the `STATE_*` constants (or `local`).
    pub fn state(&self) -> &'static str {
        self.lock().state
    }

    /// Assignment revision of the verified cached or staged envelope; `None` when none.
    pub fn revision(&self) -> Option<i64> {
        self.lock().revision
    }

    pub fn accepts_events(&self) -> bool {
        self.lock().accepts_events
    }

    /// 204 without a cache: never assigned, so the running default is intended.
    pub fn mark_never_assigned(&self) {
        let mut inner = self.lock();
        if matches!(
            inner.state,
            STATE_AWAITING_FIRST_SYNC | STATE_DEFAULT_ALLOWED
        ) {
            inner.state = STATE_NEVER_ASSIGNED;
            inner.accepts_events = true;
        }
    }

    /// A newer verified envelope is cached and already matches the running protection.
    pub fn mark_resolved(&self, verified: &VerifiedManagedPrivacyProfile) {
        let mut inner = self.lock();
        inner.state = if verified.is_cleared() {
            STATE_CLEARED
        } else {
            STATE_ASSIGNED
        };
        inner.revision = Some(verified.assignment_revision);
        inner.accepts_events = true;
    }

    /// A newer verified envelope is staged and the host is restarting to apply it. Ingest
    /// stays as it was: a collector awaiting its first sync keeps refusing events.
    pub fn mark_restart_pending(&self, verified: &VerifiedManagedPrivacyProfile) {
        let mut inner = self.lock();
        inner.state = STATE_RESTART_PENDING;
        inner.revision = Some(verified.assignment_revision);
    }
}

// ------------------------------------------------------------------ sync job

/// A failed sync: the .NET exception type name and its metadata-only message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncFailure {
    pub kind: &'static str,
    pub message: String,
}

impl SyncFailure {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn rejected(message: impl Into<String>) -> Self {
        Self::new(ManagedPrivacyProfileError::TYPE_NAME, message)
    }

    fn of_type(kind: &'static str) -> Self {
        Self::new(kind, kind)
    }
}

impl From<HostError> for SyncFailure {
    fn from(error: HostError) -> Self {
        Self::new(error.kind, error.message)
    }
}

/// Management mode only: fetches this collector's signed assignment envelope (C#
/// `ManagedPrivacyProfileJob`). The cache holds the last verified envelope and is the
/// assignment-revision high-water mark: a lower revision is rejected (rollback/replay) and
/// the same revision must sign exactly the cached fields; a higher revision is verified,
/// written atomically and, when it changes the active protection, applied by a graceful
/// restart (exit [`RESTART_EXIT_CODE`] for the supervisor). An unsigned 204 never removes
/// a verified cache; without a cache it means never assigned. Anything that does not
/// verify keeps the running profile and fails the job. Metadata-only logs.
pub struct ManagedPrivacyProfileJob {
    pub client: reqwest::Client,
    pub base: Url,
    pub credential: Arc<dyn AccessTokenSource>,
    pub settings: CollectorSettings,
    /// Content hash of the running privacy profile; `None` for the built-in default.
    pub active_hash: Option<String>,
    pub state: Arc<ManagedPrivacyState>,
    pub lifetime: ApplicationLifetime,
}

impl ManagedPrivacyProfileJob {
    pub fn from_settings(
        settings: &CollectorSettings,
        active_hash: Option<String>,
        credential: Arc<dyn AccessTokenSource>,
        state: Arc<ManagedPrivacyState>,
        lifetime: ApplicationLifetime,
    ) -> Option<Self> {
        let base = settings.management_endpoint.clone()?;
        // The same client settings as the management heartbeat (15 s timeout).
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .ok()?;
        Some(Self {
            client,
            base,
            credential,
            settings: settings.clone(),
            active_hash,
            state,
            lifetime,
        })
    }

    /// One scheduled run. Errors are .NET exception type names (metadata only).
    pub async fn run(&self) -> Result<(), &'static str> {
        self.sync().await.map_err(|failure| failure.kind)
    }

    /// One run with the failure message (C# exception message).
    pub async fn sync(&self) -> Result<(), SyncFailure> {
        let scope = self.settings.management_scope.clone().unwrap_or_default();
        let token = self
            .credential
            .access_token(&scope)
            .await
            .map_err(SyncFailure::of_type)?;
        let url = self
            .base
            .join(&format!(
                "api/collectors/{}/privacy-profile/deployment",
                escape_data_string(&self.settings.collector_id)
            ))
            .map_err(|_| SyncFailure::of_type("UriFormatException"))?;
        // The bearer token is attached per request, never to shared default headers.
        let mut response = match self.client.get(url).bearer_auth(token).send().await {
            Ok(response) => response,
            Err(failure) => {
                // Collection and delivery continue with the current privacy profile.
                let exception_type = request_error_name(&failure);
                warn!(
                    exception_type,
                    "Managed privacy profile sync failed with {exception_type}; the current privacy profile stays active."
                );
                return Err(SyncFailure::of_type(exception_type));
            }
        };

        match response.status() {
            StatusCode::NO_CONTENT => self.no_content(),
            StatusCode::CONFLICT => {
                info!(
                    "Collector is not active in management; managed privacy profile sync skipped."
                );
                Ok(())
            }
            StatusCode::OK => {
                let document = read_bounded(&mut response).await?;
                self.apply(document).await
            }
            status => {
                let status_code = status.as_u16();
                warn!(
                    status_code,
                    "Management returned HTTP {status_code} for the privacy profile deployment; the current privacy profile stays active."
                );
                Err(SyncFailure::rejected(format!(
                    "Management returned HTTP {status_code} for the privacy profile deployment."
                )))
            }
        }
    }

    async fn apply(&self, document: Vec<u8>) -> Result<(), SyncFailure> {
        let settings = self.settings.clone();
        let active_hash = self.active_hash.clone();
        let state = Arc::clone(&self.state);
        let restart = tokio::task::spawn_blocking(move || {
            apply_document(&settings, active_hash.as_deref(), &state, &document)
        })
        .await
        .map_err(|_| SyncFailure::of_type("JoinError"))??;
        if restart {
            self.lifetime.request_restart();
        }
        Ok(())
    }

    /// 204 is unsigned: it can never remove verified protection. Only a signed, newer
    /// `cleared` envelope returns a collector to the built-in default.
    fn no_content(&self) -> Result<(), SyncFailure> {
        if cache_path(&self.settings).is_file() {
            warn!(
                "Management returned 204 although a verified assignment is cached; the cached privacy profile protection stays active"
            );
            return Err(SyncFailure::rejected(
                "Management returned 204 although a verified assignment is cached; the cached \
                 privacy profile protection stays active.",
            ));
        }
        self.state.mark_never_assigned();
        Ok(())
    }
}

/// Verifies `document` against the cached high-water mark and, when newer, writes it to
/// the cache. Returns whether a restart is needed to apply it.
fn apply_document(
    settings: &CollectorSettings,
    active_hash: Option<&str>,
    state: &ManagedPrivacyState,
    document: &[u8],
) -> Result<bool, SyncFailure> {
    let key = match &settings.privacy_hmac_key_file {
        Some(path) => Some(
            bower_redaction::read_key_file(path)
                .map_err(|error| SyncFailure::new(error.dotnet_type(), error.to_string()))?,
        ),
        None => None,
    };
    let rejected = |message: String| {
        error!(
            reason = message.as_str(),
            "Managed privacy profile rejected: {message} The current privacy profile stays active."
        );
        SyncFailure::rejected(message)
    };
    let cached = match load_verified(settings, key.as_deref()) {
        Ok(cached) => cached,
        Err(error) if error.kind == ManagedPrivacyProfileError::TYPE_NAME => {
            return Err(rejected(error.message));
        }
        Err(error) => return Err(error.into()),
    };
    let trusted = read_trusted_keys(settings)?;
    let verified = verify(
        document,
        &settings.collector_id,
        &trusted,
        key.as_deref(),
        &settings.privacy_hmac_key_id,
    )
    .map_err(|error| rejected(error.0))?;
    if let Some(cached) = &cached {
        require_not_older(&verified, cached).map_err(|error| rejected(error.0))?;
        if verified.assignment_revision == cached.assignment_revision {
            return Ok(false);
        }
    }

    // Only verified bytes reach the disk, and only through an atomic replace. The new
    // envelope becomes the high-water mark even when it needs no restart.
    write_atomically(&cache_path(settings), document)
        .map_err(|error| SyncFailure::of_type(io_error_name(&error)))?;
    let changes_protection = if verified.is_cleared() {
        active_hash.is_some()
    } else {
        verified.content_hash.as_deref() != active_hash
    };
    let revision = verified.assignment_revision;
    if !changes_protection {
        state.mark_resolved(&verified);
        let action = verified.action;
        info!(
            revision,
            action,
            "Managed privacy profile assignment revision {revision} ({action}) recorded; the active protection is unchanged"
        );
        return Ok(false);
    }

    state.mark_restart_pending(&verified);
    if verified.is_cleared() {
        warn!(
            revision,
            "Managed privacy profile assignment cleared (revision {revision}); restarting to apply the built-in default privacy profile"
        );
    } else {
        let profile_id = verified.profile_id.as_deref().unwrap_or_default();
        let version = verified.version.as_deref().unwrap_or_default();
        warn!(
            profile_id,
            version, "privacy profile {profile_id}@{version} staged; restarting to apply"
        );
    }
    Ok(true)
}

/// Lower revisions are replays or rollbacks; the same revision must sign the same fields.
fn require_not_older(
    received: &VerifiedManagedPrivacyProfile,
    cached: &VerifiedManagedPrivacyProfile,
) -> Result<(), ManagedPrivacyProfileError> {
    if received.assignment_revision < cached.assignment_revision {
        return Err(ManagedPrivacyProfileError::new(format!(
            "Managed privacy profile assignment revision {} is older than the cached revision {}.",
            received.assignment_revision, cached.assignment_revision
        )));
    }
    if received.assignment_revision == cached.assignment_revision
        && received.signed_payload != cached.signed_payload
    {
        return Err(ManagedPrivacyProfileError::new(format!(
            "Managed privacy profile assignment revision {} does not match the cached document.",
            received.assignment_revision
        )));
    }
    Ok(())
}

/// Reads the response body, refusing more than [`MAXIMUM_DOCUMENT_BYTES`].
async fn read_bounded(response: &mut reqwest::Response) -> Result<Vec<u8>, SyncFailure> {
    let too_large = || SyncFailure::rejected("Managed privacy profile document is too large.");
    if response
        .content_length()
        .is_some_and(|length| length > MAXIMUM_DOCUMENT_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut buffer = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|failure| SyncFailure::of_type(request_error_name(&failure)))?
    {
        if buffer.len() + chunk.len() > MAXIMUM_DOCUMENT_BYTES {
            return Err(too_large());
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

fn request_error_name(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "TaskCanceledException"
    } else {
        "HttpRequestException"
    }
}

fn io_error_name(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "UnauthorizedAccessException",
        std::io::ErrorKind::NotFound => "DirectoryNotFoundException",
        _ => "IOException",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_the_file_and_leaves_no_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join(CACHE_FILE_NAME);

        write_atomically(&path, b"first").unwrap();
        write_atomically(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[test]
    fn oversized_document_is_rejected_before_parsing() {
        let error = verify(
            &vec![b' '; MAXIMUM_DOCUMENT_BYTES + 1],
            "c",
            &[],
            None,
            "k1",
        )
        .unwrap_err();
        assert_eq!(
            error.message(),
            "Managed privacy profile document is too large."
        );
        let error = verify(&vec![b' '; MAXIMUM_DOCUMENT_BYTES], "c", &[], None, "k1").unwrap_err();
        assert_eq!(
            error.message(),
            "Managed privacy profile document is not valid JSON."
        );
    }

    #[test]
    /// The managed-v2 notes' example with `+` escaped as `\u002B`, as
    /// `JavaScriptEncoder.Default` (and the C#-signed fixture) writes it.
    fn cleared_signed_bytes_match_the_documented_example() {
        assert_eq!(
            String::from_utf8(signed_bytes(
                "edge-01",
                13,
                ACTION_CLEARED,
                None,
                None,
                None,
                None,
                None,
                "2026-10-24T01:00:00.0000000+00:00"
            ))
            .unwrap(),
            r#"{"action":"cleared","assignmentRevision":13,"collectorId":"edge-01","issuedAt":"2026-10-24T01:00:00.0000000\u002B00:00"}"#
        );
    }

    #[test]
    fn gate_state_transitions_match_csharp() {
        let awaiting = ManagedPrivacyState::new(None, false);
        assert_eq!(
            (awaiting.state(), awaiting.accepts_events()),
            (STATE_AWAITING_FIRST_SYNC, false)
        );
        awaiting.mark_never_assigned();
        assert_eq!(
            (awaiting.state(), awaiting.accepts_events()),
            (STATE_NEVER_ASSIGNED, true)
        );
        let allowed = ManagedPrivacyState::new(None, true);
        assert_eq!(
            (allowed.state(), allowed.accepts_events()),
            (STATE_DEFAULT_ALLOWED, true)
        );
        let local = ManagedPrivacyState::local();
        assert!(local.is_local() && local.accepts_events());
    }
}
