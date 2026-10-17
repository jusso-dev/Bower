//! Detached ECDSA P-256 / SHA-256 signatures (`Bower.Integrity.DetachedSigner`).
//!
//! Wire format matches .NET: IEEE P1363 fixed-field `r || s` (64 bytes) in standard
//! base64, PKCS#8 private and SPKI public PEM, key id = first 16 lower-case hex
//! characters of SHA-256 over the SPKI DER (uncompressed point).

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Algorithm label of every Bower signature.
pub const ECDSA_P256_SHA256: &str = "ES256";

/// `Convert.FromBase64String`: padding required, trailing bits not validated.
const DOTNET_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// A detached signature. Serialized with the C# property names (PascalCase), read
/// case-insensitively for the PascalCase and camelCase spellings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DetachedSignature {
    #[serde(alias = "algorithm")]
    pub algorithm: String,
    #[serde(alias = "keyId")]
    pub key_id: String,
    #[serde(alias = "value")]
    pub value: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IntegrityError {
    #[error("private key PEM is required")]
    MissingKey,
    #[error("no supported PEM-encoded key was found")]
    NoPem,
    #[error("the PEM contains multiple keys")]
    MultiplePem,
    #[error("encrypted private keys are not supported")]
    EncryptedKey,
    /// Unparseable key or a curve other than P-256 (C# `CryptographicException`).
    #[error("Signing keys must be ECDSA P-256.")]
    NotP256,
    #[error("a private key is required to sign")]
    PublicKeyOnly,
}

/// A key imported like `ECDsa.ImportFromPem`.
enum ImportedKey {
    Private(SigningKey),
    Public(VerifyingKey),
}

impl ImportedKey {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Private(key) => *key.verifying_key(),
            Self::Public(key) => *key,
        }
    }
}

const SUPPORTED_LABELS: [&str; 4] = [
    "PUBLIC KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
];

/// Finds PEM blocks; returns (label, DER) for supported labels only, like
/// `ImportFromPem` which ignores unrecognised labels and rejects ambiguity.
fn find_supported_pem(text: &str) -> Result<(String, Vec<u8>), IntegrityError> {
    let mut found: Option<(String, Vec<u8>)> = None;
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after_begin = &rest[start + 11..];
        let Some(label_end) = after_begin.find("-----") else {
            break;
        };
        let label = &after_begin[..label_end];
        let body_start = &after_begin[label_end + 5..];
        let footer = format!("-----END {label}-----");
        let Some(body_end) = body_start.find(&footer) else {
            break;
        };
        let body = &body_start[..body_end];
        rest = &body_start[body_end + footer.len()..];
        if !SUPPORTED_LABELS.contains(&label) {
            continue;
        }
        let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let Ok(der) = DOTNET_BASE64.decode(compact.as_bytes()) else {
            continue;
        };
        if found.is_some() {
            return Err(IntegrityError::MultiplePem);
        }
        found = Some((label.to_owned(), der));
    }
    found.ok_or(IntegrityError::NoPem)
}

fn import_pem(text: &str) -> Result<ImportedKey, IntegrityError> {
    let (label, der) = find_supported_pem(text)?;
    match label.as_str() {
        "PRIVATE KEY" => SigningKey::from_pkcs8_der(&der)
            .map(ImportedKey::Private)
            .map_err(|_| IntegrityError::NotP256),
        "EC PRIVATE KEY" => p256::SecretKey::from_sec1_der(&der)
            .map(|key| ImportedKey::Private(SigningKey::from(key)))
            .map_err(|_| IntegrityError::NotP256),
        "PUBLIC KEY" => VerifyingKey::from_public_key_der(&der)
            .map(ImportedKey::Public)
            .map_err(|_| IntegrityError::NotP256),
        _ => Err(IntegrityError::EncryptedKey),
    }
}

/// Stable key id: first 16 hex characters of SHA-256 over the SPKI bytes.
pub fn key_id(key: &VerifyingKey) -> String {
    let spki = key.to_public_key_der().expect("P-256 SPKI encodes");
    let mut hex = hex::encode(Sha256::digest(spki.as_bytes()));
    hex.truncate(16);
    hex
}

/// Key id of any PEM accepted by `ImportFromPem` (public or private).
pub fn key_id_from_public_key_pem(public_key_pem: &str) -> Result<String, IntegrityError> {
    Ok(key_id(&import_pem(public_key_pem)?.verifying_key()))
}

/// Signs `content` with a P-256 private key PEM (PKCS#8 or SEC1).
pub fn sign(content: &[u8], private_key_pem: &str) -> Result<DetachedSignature, IntegrityError> {
    if private_key_pem.trim().is_empty() {
        return Err(IntegrityError::MissingKey);
    }
    let ImportedKey::Private(key) = import_pem(private_key_pem)? else {
        return Err(IntegrityError::PublicKeyOnly);
    };
    let signature: Signature = key.sign(content);
    Ok(DetachedSignature {
        algorithm: ECDSA_P256_SHA256.to_owned(),
        key_id: key_id(key.verifying_key()),
        value: DOTNET_BASE64.encode(signature.to_bytes()),
    })
}

/// True only when a trusted key with the signature's key id verifies the content.
/// The first trusted key whose id matches decides the result.
pub fn verify<'a, I>(
    content: &[u8],
    signature: &DetachedSignature,
    trusted_public_key_pems: I,
) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    if signature.algorithm != ECDSA_P256_SHA256 {
        return false;
    }
    // `Convert.FromBase64String` skips exactly these four whitespace characters.
    let compact: String = signature
        .value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    let Ok(value) = DOTNET_BASE64.decode(compact.as_bytes()) else {
        return false;
    };
    for pem in trusted_public_key_pems {
        let Ok(key) = import_pem(pem) else { continue };
        let key = key.verifying_key();
        if key_id(&key) != signature.key_id {
            continue;
        }
        return Signature::from_slice(&value)
            .is_ok_and(|parsed| key.verify(content, &parsed).is_ok());
    }
    false
}

/// A freshly generated P-256 key pair.
pub struct GeneratedKeyPair {
    /// PKCS#8 PEM. Secret: never log or persist outside the operator's key store.
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub key_id: String,
}

impl std::fmt::Debug for GeneratedKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeneratedKeyPair")
            .field("private_key_pem", &"[redacted]")
            .field("public_key_pem", &self.public_key_pem)
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Creates a new P-256 key pair as PKCS#8 private and SPKI public PEM (LF line
/// endings, no trailing newline, as .NET `Export*Pem` writes them).
pub fn generate_key_pair() -> GeneratedKeyPair {
    use p256::elliptic_curve::Generate;
    let key = SigningKey::generate();
    let private_key_pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("P-256 PKCS#8 encodes")
        .trim_end()
        .to_owned();
    let public_key_pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("P-256 SPKI encodes")
        .trim_end()
        .to_owned();
    GeneratedKeyPair {
        private_key_pem,
        public_key_pem,
        key_id: key_id(key.verifying_key()),
    }
}

/// Lower-case hex SHA-256 (`Sha256Hex.Of`).
pub fn sha256_hex(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}
