//! Managed privacy profiles (C# `ManagedPrivacyProfileCache` and
//! `Jobs/ManagedPrivacyProfileJob`), active when `BOWER_PRIVACY_PROFILE_SOURCE=management`.
//!
//! A deployment document is trusted only when a configured key signed the canonical JSON
//! of its seven fields, it names this collector, the privacy profile loader accepts its
//! content with the collector's real HMAC key, and the content hash matches. Unverified
//! content is never written to disk. Messages and logs are metadata only.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bower_integrity::DetachedSignature;
use bower_redaction::LoadedPrivacyProfile;
use reqwest::{StatusCode, Url};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use tracing::{error, info, warn};

use crate::error::HostError;
use crate::heartbeat::{AccessTokenSource, escape_data_string};
use crate::settings::{CollectorSettings, read_all_text};
use crate::shutdown::ApplicationLifetime;

/// Cache file inside the managed privacy directory: the full signed deployment document.
pub const CACHE_FILE_NAME: &str = "profile.json";

/// Upper bound for a deployment document (a 256 KiB profile, JSON-escaped).
pub const MAXIMUM_DOCUMENT_BYTES: usize = 1_048_576;

/// EX_TEMPFAIL: the process exit code after a deliberate restart to apply a new (or
/// cleared) privacy profile, so `Restart=on-failure` supervisors also restart it.
pub const RESTART_EXIT_CODE: u8 = 75;

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

/// A signed, collector-bound, loader-validated managed privacy profile.
#[derive(Clone, Debug)]
pub struct VerifiedManagedPrivacyProfile {
    pub profile: LoadedPrivacyProfile,
    pub version_id: String,
    pub profile_id: String,
    pub version: String,
    pub content_hash: String,
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

/// Start-up: the verified cached profile, or `None` when there is no cache (the
/// built-in default applies). Any verification failure stops start-up: fail closed.
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
                 Delete the cache file to start with the built-in default privacy profile.",
                path.display(),
                error.0
            ),
        )
    })
}

/// Verifies a deployment document (C# `ManagedPrivacyProfileCache.Verify`).
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

    let document = parse_document(json).ok_or_else(|| {
        ManagedPrivacyProfileError::new("Managed privacy profile document is not valid JSON.")
    })?;
    let Some(Document {
        collector_id: Some(document_collector),
        version_id: Some(version_id),
        profile_id: Some(profile_id),
        version: Some(version),
        content_hash: Some(content_hash),
        content: Some(content),
        issued_at: Some(issued_at),
        signature:
            Some(SignatureDocument {
                algorithm: Some(algorithm),
                key_id: Some(key_id),
                value: Some(value),
            }),
    }) = document
    else {
        return Err(ManagedPrivacyProfileError::new(
            "Managed privacy profile document is incomplete.",
        ));
    };

    let signature = DetachedSignature {
        algorithm,
        key_id,
        value,
    };
    let payload = signed_bytes(
        &document_collector,
        &version_id,
        &profile_id,
        &version,
        &content_hash,
        &content,
        &issued_at,
    );
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
        profile,
        version_id,
        profile_id,
        version,
        content_hash,
    })
}

/// Canonical JSON of exactly the signed fields. Matches the management API's
/// `ManagedPrivacyProfileSigner.SignedBytes` byte for byte (`bower_integrity`
/// canonical JSON: ordinal key order, `JavaScriptEncoder.Default` escaping).
pub fn signed_bytes(
    collector_id: &str,
    version_id: &str,
    profile_id: &str,
    version: &str,
    content_hash: &str,
    content: &str,
    issued_at: &str,
) -> Vec<u8> {
    let mut fields = serde_json::Map::new();
    for (name, value) in [
        ("collectorId", collector_id),
        ("versionId", version_id),
        ("profileId", profile_id),
        ("version", version),
        ("contentHash", content_hash),
        ("content", content),
        ("issuedAt", issued_at),
    ] {
        fields.insert(name.into(), serde_json::Value::String(value.into()));
    }
    bower_integrity::canonical_json::bytes(&serde_json::Value::Object(fields))
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

/// Wire shape of the signed deployment (`ManagedPrivacyProfileDocument`), read like
/// `System.Text.Json` with web defaults: case-insensitive (ASCII) property names, last
/// duplicate wins, unknown properties skipped, `null` as absent, any other type an error.
#[derive(Default)]
struct Document {
    collector_id: Option<String>,
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
                    let slot = match () {
                        () if key.eq_ignore_ascii_case("collectorId") => &mut document.collector_id,
                        () if key.eq_ignore_ascii_case("versionId") => &mut document.version_id,
                        () if key.eq_ignore_ascii_case("profileId") => &mut document.profile_id,
                        () if key.eq_ignore_ascii_case("version") => &mut document.version,
                        () if key.eq_ignore_ascii_case("contentHash") => &mut document.content_hash,
                        () if key.eq_ignore_ascii_case("content") => &mut document.content,
                        () if key.eq_ignore_ascii_case("issuedAt") => &mut document.issued_at,
                        () if key.eq_ignore_ascii_case("signature") => {
                            document.signature = map.next_value()?;
                            continue;
                        }
                        () => {
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
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
                    let slot = match () {
                        () if key.eq_ignore_ascii_case("algorithm") => &mut signature.algorithm,
                        () if key.eq_ignore_ascii_case("keyId") => &mut signature.key_id,
                        () if key.eq_ignore_ascii_case("value") => &mut signature.value,
                        () => {
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    *slot = map.next_value()?;
                }
                Ok(signature)
            }
        }

        deserializer.deserialize_map(SignatureVisitor)
    }
}

// ------------------------------------------------------------------ sync job

/// Management mode only: fetches the privacy profile version assigned to this collector
/// (C# `ManagedPrivacyProfileJob`). A new verified version is staged in the cache
/// atomically and the host stops gracefully so the supervisor (Docker restart policy,
/// systemd `Restart=on-failure`) restarts it with the new profile: the process exits with
/// [`RESTART_EXIT_CODE`]. Anything that does not verify keeps the running profile and
/// fails the job. Metadata-only logs.
pub struct ManagedPrivacyProfileJob {
    pub client: reqwest::Client,
    pub base: Url,
    pub credential: Arc<dyn AccessTokenSource>,
    pub settings: CollectorSettings,
    /// Content hash of the active privacy profile; `None` for the built-in default.
    pub active_hash: Option<String>,
    pub lifetime: ApplicationLifetime,
}

impl ManagedPrivacyProfileJob {
    pub fn from_settings(
        settings: &CollectorSettings,
        active_hash: Option<String>,
        credential: Arc<dyn AccessTokenSource>,
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
            lifetime,
        })
    }

    /// One run. Errors are .NET exception type names (metadata only).
    pub async fn run(&self) -> Result<(), &'static str> {
        let scope = self.settings.management_scope.clone().unwrap_or_default();
        let token = self.credential.access_token(&scope).await?;
        let url = self
            .base
            .join(&format!(
                "api/collectors/{}/privacy-profile/deployment",
                escape_data_string(&self.settings.collector_id)
            ))
            .map_err(|_| "UriFormatException")?;
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
                return Err(exception_type);
            }
        };

        match response.status() {
            StatusCode::NO_CONTENT => self.clear().await,
            StatusCode::CONFLICT => {
                info!(
                    "Collector is not active in management; managed privacy profile sync skipped."
                );
                Ok(())
            }
            StatusCode::OK => {
                let document = read_bounded(&mut response).await?;
                self.stage(document).await
            }
            status => {
                let status_code = status.as_u16();
                warn!(
                    status_code,
                    "Management returned HTTP {status_code} for the privacy profile deployment; the current privacy profile stays active."
                );
                Err(ManagedPrivacyProfileError::TYPE_NAME)
            }
        }
    }

    async fn stage(&self, document: Vec<u8>) -> Result<(), &'static str> {
        let settings = self.settings.clone();
        let active_hash = self.active_hash.clone();
        let staged = tokio::task::spawn_blocking(move || {
            stage_document(&settings, active_hash.as_deref(), &document)
        })
        .await
        .map_err(|_| "JoinError")??;
        if let Some((profile_id, version)) = staged {
            warn!(
                profile_id,
                version, "privacy profile {profile_id}@{version} staged; restarting to apply"
            );
            self.lifetime.request_restart();
        }
        Ok(())
    }

    async fn clear(&self) -> Result<(), &'static str> {
        let path = cache_path(&self.settings);
        let has_profile = self.active_hash.is_some();
        let cleared = tokio::task::spawn_blocking(move || {
            let cached = path.is_file();
            if !cached && !has_profile {
                return Ok::<bool, &'static str>(false);
            }
            if cached {
                std::fs::remove_file(&path).map_err(|error| io_error_name(&error))?;
            }
            Ok(true)
        })
        .await
        .map_err(|_| "JoinError")??;
        if cleared {
            warn!(
                "Managed privacy profile unassigned; cache cleared, restarting to apply the built-in default privacy profile"
            );
            self.lifetime.request_restart();
        }
        Ok(())
    }
}

/// Verifies `document` and, when it differs from the active profile, writes it to the
/// cache. Returns the staged profile id and version; `None` for a no-op.
fn stage_document(
    settings: &CollectorSettings,
    active_hash: Option<&str>,
    document: &[u8],
) -> Result<Option<(String, String)>, &'static str> {
    let key = match &settings.privacy_hmac_key_file {
        Some(path) => {
            Some(bower_redaction::read_key_file(path).map_err(|error| error.dotnet_type())?)
        }
        None => None,
    };
    let trusted = read_trusted_keys(settings).map_err(|error| error.kind)?;
    let verified = match verify(
        document,
        &settings.collector_id,
        &trusted,
        key.as_deref(),
        &settings.privacy_hmac_key_id,
    ) {
        Ok(verified) => verified,
        Err(rejected) => {
            let reason = rejected.message();
            error!(
                reason,
                "Managed privacy profile rejected: {reason} The current privacy profile stays active."
            );
            return Err(ManagedPrivacyProfileError::TYPE_NAME);
        }
    };

    if active_hash == Some(verified.content_hash.as_str()) {
        return Ok(None);
    }

    // Only verified bytes reach the disk, and only through an atomic replace.
    write_atomically(&cache_path(settings), document).map_err(|error| io_error_name(&error))?;
    Ok(Some((verified.profile_id, verified.version)))
}

/// Reads the response body, refusing more than [`MAXIMUM_DOCUMENT_BYTES`].
async fn read_bounded(response: &mut reqwest::Response) -> Result<Vec<u8>, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > MAXIMUM_DOCUMENT_BYTES as u64)
    {
        return Err(ManagedPrivacyProfileError::TYPE_NAME);
    }
    let mut buffer = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|failure| request_error_name(&failure))?
    {
        if buffer.len() + chunk.len() > MAXIMUM_DOCUMENT_BYTES {
            return Err(ManagedPrivacyProfileError::TYPE_NAME);
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
}
