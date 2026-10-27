//! PEM certificate loading and pinning shared by the relay and its downstream collectors
//! (C# `RelayCertificates`).

use std::path::Path;

use bower_contracts::time::Timestamp;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use x509_cert::der::Decode as _;
use x509_cert::der::oid::ObjectIdentifier;

use crate::error::HostError;

const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const CLIENT_AUTHENTICATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// A certificate (the first in the file, as `X509Certificate2.CreateFromPemFile`) and its
/// private key. The message names the settings, never the files' contents.
pub fn load(
    certificate_file: &Path,
    key_file: &Path,
    setting_names: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), HostError> {
    let invalid = || {
        HostError::new(
            "InvalidOperationException",
            format!("{setting_names} must name a readable PEM certificate and its private key."),
        )
    };
    let certificate = std::fs::read(certificate_file)
        .ok()
        .and_then(|bytes| CertificateDer::pem_slice_iter(&bytes).next()?.ok())
        .ok_or_else(invalid)?;
    let key = std::fs::read(key_file)
        .ok()
        .and_then(|bytes| PrivateKeyDer::from_pem_slice(&bytes).ok())
        .ok_or_else(invalid)?;
    // The key must belong to the certificate (CreateFromPemFile refuses a mismatch).
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing = provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|_| invalid())?;
    rustls::sign::CertifiedKey::new(vec![certificate.clone()], signing)
        .keys_match()
        .map_err(|_| invalid())?;
    Ok((certificate, key))
}

/// PEM CA certificates; at least one, else `message`.
pub fn read_bundle(path: &Path, message: &str) -> Result<Vec<CertificateDer<'static>>, HostError> {
    let invalid = || HostError::new("InvalidOperationException", message);
    let bytes = std::fs::read(path).map_err(|_| invalid())?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if certificates.is_empty() {
        return Err(invalid());
    }
    Ok(certificates)
}

/// Lowercase hex SHA-256 of the DER certificate (`openssl x509 -fingerprint -sha256`).
pub fn pin(certificate: &[u8]) -> String {
    hex::encode(Sha256::digest(certificate))
}

/// C# `IsUsableClientCertificate`: inside its validity period and, if it restricts its key
/// usage, allowing client authentication. The pin is the trust anchor, so self-signed
/// certificates are fine. Unparseable certificates are not usable.
pub fn is_usable_client_certificate(certificate: &[u8], now: Timestamp) -> bool {
    let Ok(parsed) = x509_cert::Certificate::from_der(certificate) else {
        return false;
    };
    let tbs = parsed.tbs_certificate();
    let Ok(seconds) = u64::try_from(now.timestamp()) else {
        return false;
    };
    let now = std::time::Duration::new(seconds, now.timestamp_subsec_nanos());
    let validity = tbs.validity();
    if now < validity.not_before.to_unix_duration() || now > validity.not_after.to_unix_duration() {
        return false;
    }
    for extension in tbs.extensions().into_iter().flatten() {
        if extension.extn_id == EXTENDED_KEY_USAGE {
            return x509_cert::ext::pkix::ExtendedKeyUsage::from_der(
                extension.extn_value.as_bytes(),
            )
            .is_ok_and(|usage| usage.0.contains(&CLIENT_AUTHENTICATION));
        }
    }
    true
}
