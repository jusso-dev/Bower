//! Token enrolment and credential rotation for collectors without an Azure identity
//! (C# `ManagementEnrolment`, #109). The collector generates a P-256 key, persists it, then
//! exchanges a one-time token and the public key for a key-bound credential; the record
//! waits in Pending for an approver. Every management request then carries a short-lived
//! assertion signed with that key. Rotation registers a new key under the current
//! credential, and management keeps the old one valid until the new one is first used.
//! Never logs or stores a token, key or assertion; the credential file is owner-only and
//! shares its format with the C# collector.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bower_contracts::time::{Clock, Timestamp};
use chrono::TimeDelta;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::heartbeat::{AccessTokenSource, TokenFuture, escape_data_string};
use crate::management_commands::{format_timestamp, parse_timestamp, results};
use crate::settings::CollectorSettings;

pub const ASSERTION_PREFIX: &str = "bwc1.";
pub const ASSERTION_KIND: &str = "bower.collector-assertion/v1";
pub const CREDENTIAL_FILE_NAME: &str = "credential.json";
pub const STATE_SCHEMA_VERSION: i32 = 1;
pub const MAXIMUM_TOKEN_FILE_BYTES: u64 = 1024;
pub const MAXIMUM_RESPONSE_BYTES: usize = 16 * 1024;

pub const CREDENTIAL_ROTATED: &str = "credential-rotated";
pub const ROTATION_REFUSED: &str = "rotation-refused";
pub const ROTATION_FAILED: &str = "rotation-failed";
pub const NOT_ENROLLED: &str = "not-enrolled";

/// Validity window of each assertion. Management accepts at most 10 minutes.
pub fn assertion_lifetime() -> TimeDelta {
    TimeDelta::minutes(5)
}

/// Scheduled rotation: when 10 of the credential's 30 days remain.
pub fn rotate_before() -> TimeDelta {
    TimeDelta::days(10)
}

/// Canonical JSON of exactly the signed assertion fields (C# `ManagementAssertion.SignedBytes`).
pub fn signed_bytes(
    collector_id: &str,
    credential_id: &str,
    issued_at: &str,
    expires_at: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("kind".into(), Value::String(ASSERTION_KIND.into()));
    fields.insert("collectorId".into(), Value::String(collector_id.into()));
    fields.insert("credentialId".into(), Value::String(credential_id.into()));
    fields.insert("issuedAt".into(), Value::String(issued_at.into()));
    fields.insert("expiresAt".into(), Value::String(expires_at.into()));
    fields.insert("nonce".into(), Value::String(nonce.into()));
    bower_integrity::canonical_json::bytes(&Value::Object(fields))
}

/// `bwc1.<base64url canonical payload>.<base64url P1363 signature>` (C# `ManagementAssertion.Create`).
pub fn create_assertion(
    collector_id: &str,
    credential_id: &str,
    private_key_pem: &str,
    now: Timestamp,
) -> Result<String, &'static str> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let payload = signed_bytes(
        collector_id,
        credential_id,
        &format_timestamp(&now),
        &format_timestamp(&(now + assertion_lifetime())),
        &nonce,
    );
    let signature =
        bower_integrity::sign(&payload, private_key_pem).map_err(|_| "CryptographicException")?;
    let raw = STANDARD
        .decode(signature.value.as_bytes())
        .map_err(|_| "CryptographicException")?;
    Ok(format!(
        "{ASSERTION_PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(raw)
    ))
}

/// The persisted credential (C# `ManagementCredentialState`): the private key (never sent)
/// and hashes of tokens already exchanged or refused, never a token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialState {
    pub schema_version: i32,
    pub collector_id: String,
    pub credential_id: Option<String>,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<String>,
    pub pending_private_key_pem: Option<String>,
    pub consumed_token_sha256: Option<String>,
    pub refused_token_sha256: Option<String>,
}

impl CredentialState {
    fn empty(collector_id: &str) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            collector_id: collector_id.to_string(),
            credential_id: None,
            private_key_pem: None,
            expires_at: None,
            pending_private_key_pem: None,
            consumed_token_sha256: None,
            refused_token_sha256: None,
        }
    }

    fn expiry(&self) -> Option<Timestamp> {
        self.expires_at.as_deref().and_then(parse_timestamp)
    }
}

/// Reads `credential.json`; `None` when missing or unreadable (treated as no credential).
pub fn load_state(directory: &Path) -> Option<CredentialState> {
    let bytes = std::fs::read(directory.join(CREDENTIAL_FILE_NAME)).ok()?;
    let state: CredentialState = serde_json::from_slice(&bytes).ok()?;
    (state.schema_version == STATE_SCHEMA_VERSION).then_some(state)
}

/// Atomic, owner-only write (0600 file in a 0700 directory on Unix).
pub fn save_state(directory: &Path, state: &CredentialState) -> std::io::Result<()> {
    use std::io::Write;
    create_private_directory(directory)?;
    let path = directory.join(CREDENTIAL_FILE_NAME);
    let temporary = directory.join(format!(
        ".{CREDENTIAL_FILE_NAME}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let body = bower_contracts::json::to_vec(state).map_err(std::io::Error::other)?;
    let result = (|| {
        let mut file = private_file(&temporary)?;
        file.write_all(&body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &path)
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
}

#[cfg(not(unix))]
fn create_private_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)
}

#[cfg(unix)]
fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrolmentRequest<'a> {
    token: &'a str,
    collector_id: &'a str,
    machine_name: &'a str,
    environment: &'a str,
    version: &'a str,
    configuration_hash: &'a str,
    policy_hash: &'a str,
    public_key: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationRequest<'a> {
    public_key: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuedCredential {
    credential_id: Option<String>,
    status: Option<String>,
    expires_at: Option<String>,
}

/// Enrolment and rotation for one collector (C# `ManagementEnrolment`).
pub struct ManagementEnrolment {
    client: reqwest::Client,
    base: Url,
    collector_id: String,
    machine_name: String,
    environment: String,
    version: String,
    configuration_hash: String,
    policy_hash: String,
    token_file: Option<PathBuf>,
    directory: PathBuf,
    clock: Arc<dyn Clock>,
    state: RwLock<Option<CredentialState>>,
    gate: tokio::sync::Mutex<()>,
}

impl ManagementEnrolment {
    /// `None` unless `BOWER_MANAGEMENT_AUTH=enrolment` with an endpoint.
    pub fn from_settings(
        settings: &CollectorSettings,
        policy_hash: String,
        client: reqwest::Client,
        clock: Arc<dyn Clock>,
    ) -> Option<Self> {
        if !settings.uses_enrolment() {
            return None;
        }
        let directory = settings.management_credential_directory();
        Some(Self {
            client,
            base: settings.management_endpoint.clone()?,
            collector_id: settings.collector_id.clone(),
            machine_name: crate::settings::machine_name(),
            environment: settings.environment.clone(),
            version: settings.version.clone(),
            configuration_hash: settings.configuration_hash(),
            policy_hash,
            token_file: settings.management_enrolment_token_file.clone(),
            state: RwLock::new(load_state(&directory)),
            directory,
            clock,
            gate: tokio::sync::Mutex::new(()),
        })
    }

    pub fn state(&self) -> Option<CredentialState> {
        self.state.read().ok().and_then(|state| state.clone())
    }

    /// An unexpired credential for this collector id is held.
    pub fn enrolled(&self) -> bool {
        self.usable(self.state().as_ref(), self.clock.utc_now())
    }

    /// A fresh assertion for the current credential.
    pub fn create_assertion(&self) -> Result<String, &'static str> {
        let now = self.clock.utc_now();
        let state = self.state();
        match state.as_ref() {
            Some(current) if self.usable(Some(current), now) => create_assertion(
                &current.collector_id,
                current.credential_id.as_deref().unwrap_or_default(),
                current.private_key_pem.as_deref().unwrap_or_default(),
                now,
            ),
            _ => Err("CredentialUnavailableException"),
        }
    }

    /// Enrols when the token file holds a token not yet exchanged or refused (C#
    /// `EnsureEnrolledAsync`). Transient failures keep the generated key pending, so a retry
    /// is the same exchange to management.
    pub async fn ensure_enrolled(&self) -> Result<(), &'static str> {
        let Some(token) = self.read_token() else {
            self.warn_if_not_enrolled();
            return Ok(());
        };
        let token_hash = bower_integrity::sha256_hex(token.as_bytes());
        if let Some(current) = self.mine(self.state())
            && (current.consumed_token_sha256.as_deref() == Some(token_hash.as_str())
                || current.refused_token_sha256.as_deref() == Some(token_hash.as_str()))
        {
            self.warn_if_not_enrolled();
            return Ok(());
        }

        let _guard = self.gate.lock().await;
        let current = self.mine(self.state());
        let pending = current
            .as_ref()
            .and_then(|state| state.pending_private_key_pem.clone())
            .unwrap_or_else(|| bower_integrity::generate_key_pair().private_key_pem);
        let mut prepared = current.unwrap_or_else(|| CredentialState::empty(&self.collector_id));
        prepared.pending_private_key_pem = Some(pending.clone());
        self.save(prepared.clone())?;

        let public_key = bower_integrity::signer::public_key_pem(&pending)
            .map_err(|_| "CryptographicException")?;
        let body = EnrolmentRequest {
            token: &token,
            collector_id: &self.collector_id,
            machine_name: &self.machine_name,
            environment: &self.environment,
            version: &self.version,
            configuration_hash: &self.configuration_hash,
            policy_hash: &self.policy_hash,
            public_key: &public_key,
        };
        let response = self.post("api/collectors/enrol", None, &body).await?;
        let status = response.status();
        if is_definitive_refusal(status) {
            prepared.pending_private_key_pem = None;
            prepared.refused_token_sha256 = Some(token_hash);
            self.save(prepared)?;
            warn!(
                status_code = status.as_u16(),
                "Management refused the enrolment token; supply a new token to enrol."
            );
            return Ok(());
        }
        if !status.is_success() {
            return Err("HttpRequestException");
        }
        let (credential_id, expires_at, record_status) = read_issued(response, &pending).await?;
        prepared.credential_id = Some(credential_id.clone());
        prepared.private_key_pem = Some(pending);
        prepared.expires_at = Some(expires_at);
        prepared.pending_private_key_pem = None;
        prepared.consumed_token_sha256 = Some(token_hash);
        prepared.refused_token_sha256 = None;
        self.save(prepared)?;
        info!(
            credential_id = credential_id.as_str(),
            status = record_status.as_str(),
            "Collector enrolled with a management credential."
        );
        Ok(())
    }

    /// Rotates when the credential is within [`rotate_before`] of expiry.
    pub async fn rotate_if_due(&self) {
        let now = self.clock.utc_now();
        let state = self.state();
        let due = self.usable(state.as_ref(), now)
            && state
                .as_ref()
                .and_then(CredentialState::expiry)
                .is_some_and(|expiry| expiry - now <= rotate_before());
        if due {
            let (status, code) = self.rotate().await;
            if status != results::SUCCEEDED {
                warn!(
                    code,
                    "Scheduled management credential rotation failed; the current credential stays in use."
                );
            }
        }
    }

    /// Registers a new key under the current credential and switches to it (C#
    /// `RotateAsync`). The new key is persisted as pending first.
    pub async fn rotate(&self) -> (&'static str, &'static str) {
        let _guard = self.gate.lock().await;
        let now = self.clock.utc_now();
        let Some(current) = self.mine(self.state()) else {
            return (results::FAILED, NOT_ENROLLED);
        };
        if !self.usable(Some(&current), now) {
            return (results::FAILED, NOT_ENROLLED);
        }
        let pending = current
            .pending_private_key_pem
            .clone()
            .unwrap_or_else(|| bower_integrity::generate_key_pair().private_key_pem);
        let mut prepared = current.clone();
        prepared.pending_private_key_pem = Some(pending.clone());
        if self.save(prepared.clone()).is_err() {
            return (results::FAILED, ROTATION_FAILED);
        }
        let (Ok(public_key), Ok(assertion)) = (
            bower_integrity::signer::public_key_pem(&pending),
            create_assertion(
                &current.collector_id,
                current.credential_id.as_deref().unwrap_or_default(),
                current.private_key_pem.as_deref().unwrap_or_default(),
                now,
            ),
        ) else {
            return (results::FAILED, ROTATION_FAILED);
        };
        let path = format!(
            "api/collectors/{}/credentials/rotate",
            escape_data_string(&self.collector_id)
        );
        let Ok(response) = self
            .post(
                &path,
                Some(&assertion),
                &RotationRequest {
                    public_key: &public_key,
                },
            )
            .await
        else {
            return (results::FAILED, ROTATION_FAILED);
        };
        let status = response.status();
        if is_definitive_refusal(status) {
            // Start again with a fresh key next time; the current credential still works.
            prepared.pending_private_key_pem = None;
            let _ = self.save(prepared);
            return (results::FAILED, ROTATION_REFUSED);
        }
        if !status.is_success() {
            return (results::FAILED, ROTATION_FAILED);
        }
        let Ok((credential_id, expires_at, _)) = read_issued(response, &pending).await else {
            return (results::FAILED, ROTATION_FAILED);
        };
        prepared.credential_id = Some(credential_id.clone());
        prepared.private_key_pem = Some(pending);
        prepared.expires_at = Some(expires_at);
        prepared.pending_private_key_pem = None;
        if self.save(prepared).is_err() {
            return (results::FAILED, ROTATION_FAILED);
        }
        info!(
            credential_id = credential_id.as_str(),
            "Management credential rotated."
        );
        (results::SUCCEEDED, CREDENTIAL_ROTATED)
    }

    fn usable(&self, state: Option<&CredentialState>, now: Timestamp) -> bool {
        state.is_some_and(|state| {
            state.credential_id.is_some()
                && state.private_key_pem.is_some()
                && state.collector_id == self.collector_id
                && state.expiry().is_some_and(|expiry| expiry > now)
        })
    }

    /// Another collector id's credential is never used.
    fn mine(&self, state: Option<CredentialState>) -> Option<CredentialState> {
        state.filter(|state| state.collector_id == self.collector_id)
    }

    fn save(&self, state: CredentialState) -> Result<(), &'static str> {
        save_state(&self.directory, &state).map_err(|_| "IOException")?;
        if let Ok(mut current) = self.state.write() {
            *current = Some(state);
        }
        Ok(())
    }

    fn warn_if_not_enrolled(&self) {
        if !self.enrolled() {
            warn!(
                "Collector has no usable management credential; set BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE to a new enrolment token."
            );
        }
    }

    /// The token, or `None` when unset, missing, unreadable, empty or oversized.
    fn read_token(&self) -> Option<String> {
        let path = self.token_file.as_ref()?;
        let metadata = std::fs::metadata(path).ok()?;
        if metadata.len() == 0 || metadata.len() > MAXIMUM_TOKEN_FILE_BYTES {
            return None;
        }
        let token = std::fs::read_to_string(path).ok()?.trim().to_string();
        (!token.is_empty()).then_some(token)
    }

    async fn post<T: Serialize>(
        &self,
        path: &str,
        assertion: Option<&str>,
        body: &T,
    ) -> Result<reqwest::Response, &'static str> {
        let url = self.base.join(path).map_err(|_| "UriFormatException")?;
        let body = bower_contracts::json::to_vec(body).map_err(|_| "JsonException")?;
        let mut request = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(body);
        if let Some(assertion) = assertion {
            request = request.bearer_auth(assertion);
        }
        request.send().await.map_err(|error| {
            if error.is_timeout() {
                "TaskCanceledException"
            } else {
                "HttpRequestException"
            }
        })
    }
}

fn is_definitive_refusal(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::CONFLICT
    )
}

/// The issued credential, which must name the key this collector generated: its id, the
/// expiry in the stored form, and the collector status.
async fn read_issued(
    mut response: reqwest::Response,
    private_key_pem: &str,
) -> Result<(String, String, String), &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES as u64)
    {
        return Err("InvalidDataException");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "HttpRequestException")? {
        if body.len() + chunk.len() > MAXIMUM_RESPONSE_BYTES {
            return Err("InvalidDataException");
        }
        body.extend_from_slice(&chunk);
    }
    let issued: IssuedCredential =
        serde_json::from_slice(&body).map_err(|_| "InvalidDataException")?;
    let expected = bower_integrity::key_id_from_public_key_pem(private_key_pem)
        .map_err(|_| "CryptographicException")?;
    let expires_at = issued
        .expires_at
        .as_deref()
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .ok_or("InvalidDataException")?;
    match issued.credential_id {
        Some(id) if id == expected => Ok((
            id,
            format_timestamp(&expires_at),
            issued.status.unwrap_or_default(),
        )),
        _ => Err("InvalidDataException"),
    }
}

/// Assertions where the heartbeat and privacy profile jobs expect a bearer token.
struct EnrolledTokenSource(Arc<ManagementEnrolment>);

impl AccessTokenSource for EnrolledTokenSource {
    fn access_token<'a>(&'a self, _scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move { self.0.create_assertion() })
    }
}

pub fn token_source(enrolment: Arc<ManagementEnrolment>) -> Arc<dyn AccessTokenSource> {
    Arc::new(EnrolledTokenSource(enrolment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_bytes_match_the_pinned_csharp_text() {
        // Pinned identically in the C# EnrolmentTests.
        let text = String::from_utf8(signed_bytes(
            "edge-01",
            "0123456789abcdef",
            "2026-10-27T00:00:00.0000000Z",
            "2026-10-27T00:05:00.0000000Z",
            &"a".repeat(32),
        ))
        .unwrap();
        assert_eq!(
            text,
            "{\"collectorId\":\"edge-01\",\"credentialId\":\"0123456789abcdef\",\"expiresAt\":\"2026-10-27T00:05:00.0000000Z\",\
             \"issuedAt\":\"2026-10-27T00:00:00.0000000Z\",\"kind\":\"bower.collector-assertion/v1\",\
             \"nonce\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"
        );
    }

    #[test]
    fn assertions_carry_the_canonical_payload_and_a_verifying_signature() {
        let keys = bower_integrity::generate_key_pair();
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-27T00:00:00Z").unwrap();
        let assertion =
            create_assertion("edge-01", &keys.key_id, &keys.private_key_pem, now).unwrap();
        let parts: Vec<&str> = assertion
            .strip_prefix(ASSERTION_PREFIX)
            .unwrap()
            .split('.')
            .collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let signature = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let fields: Value = serde_json::from_slice(&payload).unwrap();
        let nonce = fields["nonce"].as_str().unwrap();

        assert_eq!(parts.len(), 2);
        assert_eq!(signature.len(), 64);
        assert_eq!(
            payload,
            signed_bytes(
                "edge-01",
                &keys.key_id,
                "2026-10-27T00:00:00.0000000Z",
                "2026-10-27T00:05:00.0000000Z",
                nonce
            )
        );
        assert!(crate::management_commands::is_identifier(nonce));
        assert!(bower_integrity::verify(
            &payload,
            &bower_integrity::DetachedSignature {
                algorithm: "ES256".into(),
                key_id: keys.key_id.clone(),
                value: STANDARD.encode(&signature),
            },
            [keys.public_key_pem.as_str()],
        ));
    }

    /// Prints the cross-runtime vector pasted into `tests/Bower.UnitTests/RustAssertionVector.cs`.
    #[test]
    #[ignore = "generator: run with --ignored --nocapture"]
    fn emit_cross_runtime_vector() {
        let keys = bower_integrity::generate_key_pair();
        let collector = "collector-é<&>'\"+`東😀";
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-27T00:00:00Z").unwrap();
        println!("{}", keys.public_key_pem);
        println!(
            "{}",
            create_assertion(collector, &keys.key_id, &keys.private_key_pem, now).unwrap()
        );
    }
}
