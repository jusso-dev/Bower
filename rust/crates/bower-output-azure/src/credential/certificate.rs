//! `ClientCertificateCredential` as `EnvironmentCredential` builds it from
//! `AZURE_CLIENT_CERTIFICATE_PATH`: a PEM or PKCS#12 RSA certificate signs an
//! MSAL-format client assertion (`PS256`, `x5t#S256`, optional `x5c`).
//!
//! Private keys stay in memory (`rsa` zeroizes them on drop) and never appear in
//! errors or `Debug` output.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest as _, Sha256};
use x509_cert::der::{Decode as _, Encode as _};

use super::{TokenError, TokenFuture, TokenProvider, client_credentials};
use bower_contracts::time;

/// Certificate files are small; refuse anything larger before parsing.
const MAX_CERTIFICATE_FILE_BYTES: u64 = 1024 * 1024;
/// MSAL `JsonWebToken.MaxTokenLength`.
const MAX_ASSERTION_LENGTH: usize = 65_536;
/// MSAL `JsonWebToken.JwtToAadLifetimeInSeconds`.
const ASSERTION_LIFETIME_SECONDS: i64 = 600;

/// An RSA certificate and its private key, loaded once and kept in memory.
pub struct ClientCertificate {
    signing_key: BlindedSigningKey<Sha256>,
    certificate_der: Vec<u8>,
}

impl fmt::Debug for ClientCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCertificate")
            .field("x5t#S256", &self.thumbprint_sha256())
            .field("private_key", &"[redacted]")
            .finish()
    }
}

fn unavailable(message: &str) -> TokenError {
    TokenError::Unavailable(message.to_owned())
}

fn not_rsa() -> TokenError {
    TokenError::Failed("the client certificate must use an RSA key".to_owned())
}

impl ClientCertificate {
    /// `X509Certificate2FromPathProvider`: `.pfx` (optional password) or `.pem`
    /// (unencrypted, certificate plus `PRIVATE KEY` or `RSA PRIVATE KEY`).
    /// Windows certificate store paths (`cert:/StoreLocation/StoreName/Thumbprint`)
    /// are not supported by this collector.
    pub fn load(path: &Path, password: Option<&str>) -> Result<Self, TokenError> {
        let text = path.to_string_lossy();
        if is_certificate_store_path(&text) {
            return Err(unavailable(
                "certificate store paths are not supported; use a .pfx or .pem file",
            ));
        }
        let extension = path
            .extension()
            .map(|value| value.to_string_lossy().to_ascii_lowercase());
        match extension.as_deref() {
            Some("pfx") => Self::from_pkcs12(&read_bounded(path)?, password),
            Some("pem") => {
                if password.is_some() {
                    return Err(unavailable(
                        "password protection for PEM encoded certificates is not supported",
                    ));
                }
                let bytes = read_bounded(path)?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| unavailable("could not load certificate file"))?;
                Self::from_pem(text)
            }
            _ => Err(unavailable(
                "certificate path must be a file path with a .pfx or .pem extension",
            )),
        }
    }

    /// PEM text with the first `CERTIFICATE` block and an unencrypted RSA key.
    pub fn from_pem(text: &str) -> Result<Self, TokenError> {
        let blocks =
            pem_blocks(text).ok_or_else(|| unavailable("could not load certificate file"))?;
        let certificate = blocks
            .iter()
            .find(|(label, _)| label == "CERTIFICATE")
            .map(|(_, der)| der.clone())
            .ok_or_else(|| unavailable("could not load certificate file"))?;
        let key = blocks
            .iter()
            .find_map(|(label, der)| match label.as_str() {
                "PRIVATE KEY" => Some(decode_pkcs8_key(der)),
                "RSA PRIVATE KEY" => Some(
                    RsaPrivateKey::from_pkcs1_der(der)
                        .map_err(|_| unavailable("could not load certificate file")),
                ),
                _ => None,
            })
            .ok_or_else(|| unavailable("could not load certificate file"))??;
        Self::new(key, certificate)
    }

    /// PKCS#12 (`.pfx`): the first private key with its certificate. The MAC is
    /// verified; legacy (3DES / RC2) and PBES2 (AES) encryption are supported.
    pub fn from_pkcs12(data: &[u8], password: Option<&str>) -> Result<Self, TokenError> {
        let store = p12_keystore::KeyStore::from_pkcs12(
            data,
            password.unwrap_or(""),
            p12_keystore::Pkcs12ImportPolicy::Strict,
        )
        .map_err(|_| unavailable("could not load certificate file"))?;
        let (_, chain) = store
            .private_key_chain()
            .ok_or_else(|| unavailable("certificate file has no private key"))?;
        let certificate = chain
            .certs()
            .first()
            .ok_or_else(|| unavailable("certificate file has no certificate"))?
            .as_der()
            .to_vec();
        let key = decode_pkcs8_key(chain.key().as_der())?;
        Self::new(key, certificate)
    }

    /// Pairs the key with the certificate; like `CopyWithPrivateKey`, the
    /// certificate's public key must match.
    fn new(key: RsaPrivateKey, certificate_der: Vec<u8>) -> Result<Self, TokenError> {
        let certificate = x509_cert::Certificate::from_der(&certificate_der)
            .map_err(|_| unavailable("could not load certificate file"))?;
        let spki = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| unavailable("could not load certificate file"))?;
        let public = RsaPublicKey::from_public_key_der(&spki).map_err(|_| not_rsa())?;
        if public != key.to_public_key() {
            return Err(unavailable(
                "the private key does not match the certificate",
            ));
        }
        Ok(Self {
            signing_key: BlindedSigningKey::<Sha256>::new(key),
            certificate_der,
        })
    }

    /// DER of the leaf certificate (sent as `x5c` when requested).
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Base64url SHA-256 of the certificate (`x5t#S256`).
    pub fn thumbprint_sha256(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(&self.certificate_der))
    }

    /// MSAL `JsonWebToken.Sign` with `useSha2AndPss` (Microsoft Entra authorities):
    /// `{"alg":"PS256","typ":"JWT","x5t#S256":..[,"x5c":..]}` and the claims
    /// `aud` (token endpoint), `iss` = `sub` = client id, `nbf`, `exp` (+10 min,
    /// as strings like MSAL) and a random `jti`.
    pub fn assertion(
        &self,
        client_id: &str,
        audience: &str,
        send_certificate_chain: bool,
    ) -> Result<String, TokenError> {
        let header = if send_certificate_chain {
            format!(
                r#"{{"alg":"PS256","typ":"JWT","x5t#S256":"{}","x5c":"{}"}}"#,
                self.thumbprint_sha256(),
                STANDARD.encode(&self.certificate_der)
            )
        } else {
            format!(
                r#"{{"alg":"PS256","typ":"JWT","x5t#S256":"{}"}}"#,
                self.thumbprint_sha256()
            )
        };
        let valid_from = time::now().timestamp();
        let payload = format!(
            r#"{{"aud":{},"iss":{},"sub":{},"nbf":"{}","exp":"{}","jti":"{}"}}"#,
            json_string(audience),
            json_string(client_id),
            json_string(client_id),
            valid_from,
            valid_from + ASSERTION_LIFETIME_SECONDS,
            uuid::Uuid::new_v4()
        );
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        if signing_input.len() > MAX_ASSERTION_LENGTH {
            return Err(TokenError::Failed(
                "client assertion is too long".to_owned(),
            ));
        }
        let signature = self
            .signing_key
            .try_sign_with_rng(&mut SystemRng, signing_input.as_bytes())
            .map_err(|_| TokenError::Failed("client assertion could not be signed".to_owned()))?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_vec())
        ))
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("strings always serialize")
}

fn decode_pkcs8_key(der: &[u8]) -> Result<RsaPrivateKey, TokenError> {
    let info = rsa::pkcs8::PrivateKeyInfoRef::try_from(der)
        .map_err(|_| unavailable("could not load certificate file"))?;
    if info.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
        return Err(not_rsa());
    }
    RsaPrivateKey::from_pkcs8_der(der).map_err(|_| unavailable("could not load certificate file"))
}

/// `cert:[\/]{1,2}(\w+)[\/](\w+)[\/](\w+)` (case-insensitive), anchored.
fn is_certificate_store_path(path: &str) -> bool {
    let Some(rest) = path
        .get(..5)
        .filter(|prefix| prefix.eq_ignore_ascii_case("cert:"))
        .map(|_| &path[5..])
    else {
        return false;
    };
    let rest = rest.trim_start_matches(['/', '\\']);
    let leading = path.len() - 5 - rest.len();
    if !(1..=2).contains(&leading) {
        return false;
    }
    let parts: Vec<&str> = rest.split(['/', '\\']).collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_'))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, TokenError> {
    use std::io::Read as _;
    let file =
        std::fs::File::open(path).map_err(|_| unavailable("could not load certificate file"))?;
    let mut bytes = Vec::new();
    file.take(MAX_CERTIFICATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable("could not load certificate file"))?;
    if bytes.len() as u64 > MAX_CERTIFICATE_FILE_BYTES {
        return Err(unavailable("certificate file is too large"));
    }
    Ok(bytes)
}

/// `-----BEGIN label-----` blocks in order; `None` when a block is malformed.
fn pem_blocks(text: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + "-----BEGIN ".len()..];
        let label_end = after.find("-----")?;
        let label = &after[..label_end];
        let body = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let body_end = body.find(&end_marker)?;
        let encoded: String = body[..body_end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        blocks.push((label.to_owned(), STANDARD.decode(encoded).ok()?));
        rest = &body[body_end + end_marker.len()..];
    }
    Some(blocks)
}

/// Operating system CSPRNG for PSS salts and blinding.
struct SystemRng;

#[derive(Debug, thiserror::Error)]
#[error("the system random number generator failed")]
struct RngError;

impl rsa::rand_core::TryRng for SystemRng {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(destination).map_err(|_| RngError)
    }
}

impl rsa::rand_core::TryCryptoRng for SystemRng {}

/// Client credentials with a certificate-signed client assertion.
pub struct ClientCertificateCredential {
    pub client: reqwest::Client,
    pub tenant_id: String,
    pub client_id: String,
    pub certificate: Arc<ClientCertificate>,
    pub authority_host: String,
    /// `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`: adds `x5c` for subject name / issuer
    /// authentication.
    pub send_certificate_chain: bool,
}

impl TokenProvider for ClientCertificateCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let audience = super::token_endpoint(&self.authority_host, &self.tenant_id)?;
            let assertion = self.certificate.assertion(
                &self.client_id,
                &audience,
                self.send_certificate_chain,
            )?;
            client_credentials(
                &self.client,
                &self.authority_host,
                &self.tenant_id,
                &[
                    ("client_id", &self.client_id),
                    ("scope", scope),
                    ("grant_type", "client_credentials"),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", &assertion),
                ],
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_store_paths_match_azure_identity_pattern() {
        assert!(is_certificate_store_path("cert:/CurrentUser/My/ABC123"));
        assert!(is_certificate_store_path("CERT:\\\\LocalMachine\\My\\abc"));
        assert!(!is_certificate_store_path("cert:///CurrentUser/My/ABC"));
        assert!(!is_certificate_store_path("cert:/CurrentUser/My"));
        assert!(!is_certificate_store_path("/etc/cert.pem"));
    }

    #[test]
    fn pem_blocks_reject_truncated_input() {
        assert!(pem_blocks("-----BEGIN CERTIFICATE-----\nAAAA").is_none());
        assert_eq!(pem_blocks("no pem here").unwrap().len(), 0);
    }
}
