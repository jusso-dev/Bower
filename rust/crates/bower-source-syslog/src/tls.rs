//! TLS material reloaded when its files change (C# `SyslogTlsSource`, `SyslogTlsMaterial`
//! and `SyslogTlsSession`).
//!
//! New handshakes use the newest valid certificate, key, client CAs and revocation
//! lists; a reload that fails keeps the last good material and is counted. Open
//! mutual-TLS sessions are validated again after a reload, or once something in their
//! chain or a revocation list expires.
//!
//! Revocation is rustls' end-entity check with unknown status denied and list expiry
//! enforced, which C# implements itself. Known divergences, both fail closed: rustls
//! verifies a list's signature when a client of that issuer connects, while C# also
//! refuses unparsable lists at load; C# refuses RSA-PSS and Ed25519 signed lists that
//! rustls accepts.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bower_contracts::time::Timestamp;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;
use x509_cert::der::Decode as _;

use crate::config::{ListenerOptions, TlsOptions};
use crate::source::SourceError;

/// Largest certificate, key, CA bundle or revocation list file read (C# `MaximumFileBytes`).
pub const MAXIMUM_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// One generation of loaded material.
pub(crate) struct TlsMaterial {
    pub generation: i64,
    pub acceptor: TlsAcceptor,
    verifier: Option<Arc<dyn ClientCertVerifier>>,
    pub server_certificate_not_after: Option<Timestamp>,
    pub client_certificate_authority_not_after: Option<Timestamp>,
    pub client_revocation_list_next_update: Option<Timestamp>,
}

struct Current {
    material: Arc<TlsMaterial>,
    stamp: [u8; 32],
    next_check: Instant,
}

pub(crate) struct TlsSource {
    options: ListenerOptions,
    interval: Duration,
    current: Mutex<Current>,
    reloads: AtomicI64,
    reload_failures: AtomicI64,
}

impl TlsSource {
    /// Loads the initial material; any failure stops listener start-up.
    pub fn load(options: &ListenerOptions, interval: Duration) -> Result<Self, SourceError> {
        let tls = options
            .tls
            .as_ref()
            .ok_or_else(|| SourceError::Tls(options.id.clone()))?;
        let stamp = stamp(tls);
        let material = Arc::new(TlsMaterial::load(options, 1)?);
        Ok(Self {
            options: options.clone(),
            interval,
            current: Mutex::new(Current {
                material,
                stamp,
                next_check: Instant::now() + interval,
            }),
            reloads: AtomicI64::new(0),
            reload_failures: AtomicI64::new(0),
        })
    }

    pub fn reloads(&self) -> i64 {
        self.reloads.load(Ordering::SeqCst)
    }

    pub fn reload_failures(&self) -> i64 {
        self.reload_failures.load(Ordering::SeqCst)
    }

    /// The newest valid material, checking the files at most once per interval.
    pub fn current(&self) -> Arc<TlsMaterial> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let now = Instant::now();
        if now < current.next_check {
            return Arc::clone(&current.material);
        }
        current.next_check = now + self.interval;
        let next = stamp(self.options.tls.as_ref().expect("tls listener"));
        if next == current.stamp {
            return Arc::clone(&current.material);
        }
        // Remember the attempted content either way: a bad file is retried when it
        // changes again, not on every connection.
        current.stamp = next;
        match TlsMaterial::load(&self.options, current.material.generation + 1) {
            Ok(material) => {
                current.material = Arc::new(material);
                self.reloads.fetch_add(1, Ordering::SeqCst);
            }
            Err(_) => {
                self.reload_failures.fetch_add(1, Ordering::SeqCst);
            }
        }
        Arc::clone(&current.material)
    }
}

/// Digest of every configured file's bytes; a missing or unreadable file has its own marker.
fn stamp(tls: &TlsOptions) -> [u8; 32] {
    let mut hash = Sha256::new();
    for path in [
        Some(&tls.certificate_file),
        Some(&tls.private_key_file),
        tls.client_certificate_authority_file.as_ref(),
        tls.client_certificate_revocation_list_file.as_ref(),
    ] {
        match path.map(|path| read_bounded(path)) {
            None => hash.update([0u8]),
            Some(Ok(bytes)) => hash.update(Sha256::digest(&bytes)),
            Some(Err(())) => hash.update([1u8]),
        }
    }
    hash.finalize().into()
}

pub(crate) fn read_bounded(path: &str) -> Result<Vec<u8>, ()> {
    let file = std::fs::File::open(path).map_err(|_| ())?;
    let length = file.metadata().map_err(|_| ())?.len();
    if length > MAXIMUM_FILE_BYTES {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| ())?);
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAXIMUM_FILE_BYTES + 1),
        &mut bytes,
    )
    .map_err(|_| ())?;
    if bytes.len() as u64 > MAXIMUM_FILE_BYTES {
        return Err(());
    }
    Ok(bytes)
}

fn not_after(certificate: &[u8]) -> Option<Timestamp> {
    let parsed = x509_cert::Certificate::from_der(certificate).ok()?;
    timestamp(
        parsed
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration(),
    )
}

fn timestamp(since_epoch: Duration) -> Option<Timestamp> {
    chrono::DateTime::from_timestamp(i64::try_from(since_epoch.as_secs()).ok()?, 0)
        .map(|value| value.fixed_offset())
}

impl TlsMaterial {
    fn load(options: &ListenerOptions, generation: i64) -> Result<Self, SourceError> {
        let failed = || SourceError::Tls(options.id.clone());
        let tls = options.tls.as_ref().ok_or_else(failed)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let certificate_bytes = read_bounded(&tls.certificate_file).map_err(|_| failed())?;
        let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| failed())?;
        if certificates.is_empty() {
            return Err(failed());
        }
        let server_certificate_not_after = not_after(&certificates[0]);
        let key_bytes = read_bounded(&tls.private_key_file).map_err(|_| failed())?;
        let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|_| failed())?;
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| failed())?;
        let mut verifier: Option<Arc<dyn ClientCertVerifier>> = None;
        let mut client_certificate_authority_not_after = None;
        let mut client_revocation_list_next_update = None;
        let builder = match &tls.client_certificate_authority_file {
            None => builder.with_no_client_auth(),
            Some(authority) => {
                let bytes = read_bounded(authority).map_err(|_| failed())?;
                let mut roots = rustls::RootCertStore::empty();
                for certificate in CertificateDer::pem_slice_iter(&bytes) {
                    let certificate = certificate.map_err(|_| failed())?;
                    let expiry = not_after(&certificate);
                    client_certificate_authority_not_after =
                        match (client_certificate_authority_not_after, expiry) {
                            (Some(current), Some(next)) => Some(std::cmp::min(current, next)),
                            (current, next) => current.or(next),
                        };
                    roots.add(certificate).map_err(|_| failed())?;
                }
                if roots.is_empty() {
                    return Err(failed());
                }
                let mut client = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                );
                if let Some(path) = &tls.client_certificate_revocation_list_file {
                    let lists = revocation_lists(path).ok_or_else(failed)?;
                    for list in &lists {
                        let parsed: x509_cert::crl::CertificateList =
                            x509_cert::crl::CertificateList::from_der(list)
                                .map_err(|_| failed())?;
                        // RFC 5280 requires nextUpdate; rustls-webpki refuses a list without it.
                        let next = parsed
                            .tbs_cert_list
                            .next_update
                            .and_then(|time| timestamp(time.to_unix_duration()))
                            .ok_or_else(failed)?;
                        client_revocation_list_next_update = Some(
                            client_revocation_list_next_update
                                .map_or(next, |current: Timestamp| current.min(next)),
                        );
                    }
                    client = client
                        .with_crls(lists)
                        .only_check_end_entity_revocation()
                        .enforce_revocation_expiration();
                }
                let built = client.build().map_err(|_| failed())?;
                verifier = Some(built.clone());
                builder.with_client_cert_verifier(built)
            }
        };
        let config = builder
            .with_single_cert(certificates, key)
            .map_err(|_| failed())?;
        Ok(Self {
            generation,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            verifier,
            server_certificate_not_after,
            client_certificate_authority_not_after,
            client_revocation_list_next_update,
        })
    }

    /// Validates an open session's client chain against this material.
    pub fn still_trusted(&self, session: &mut TlsSession) -> bool {
        let Some(verifier) = &self.verifier else {
            return true;
        };
        let Some((end_entity, intermediates)) = session.chain.split_first() else {
            return false;
        };
        if verifier
            .verify_client_cert(end_entity, intermediates, UnixTime::now())
            .is_err()
        {
            return false;
        }
        session.accept(self);
        true
    }
}

/// One or more PEM `X509 CRL` blocks, or a single DER list.
fn revocation_lists(path: &str) -> Option<Vec<CertificateRevocationListDer<'static>>> {
    let bytes = read_bounded(path).ok()?;
    if !bytes.windows(10).any(|window| window == b"-----BEGIN") {
        return Some(vec![CertificateRevocationListDer::from(bytes)]);
    }
    let lists = CertificateRevocationListDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!lists.is_empty() && lists.len() <= 64).then_some(lists)
}

/// Whether a refused handshake was a revocation decision (C# `TlsRevoked`).
pub(crate) fn is_revocation_failure(error: &std::io::Error) -> bool {
    use rustls::{CertificateError, Error};
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Error>()),
        Some(
            Error::InvalidCertificate(
                CertificateError::Revoked
                    | CertificateError::UnknownRevocationStatus
                    | CertificateError::ExpiredRevocationList
                    | CertificateError::ExpiredRevocationListContext { .. }
            ) | Error::InvalidCertRevocationList(_)
        )
    )
}

/// One TLS connection's client chain, kept to validate it again after a reload.
#[derive(Default)]
pub(crate) struct TlsSession {
    chain: Vec<CertificateDer<'static>>,
    pub generation: i64,
    pub revalidate_at: Option<Timestamp>,
}

impl TlsSession {
    pub fn new(material: &TlsMaterial, chain: Vec<CertificateDer<'static>>) -> Self {
        let mut session = Self {
            chain,
            generation: 0,
            revalidate_at: None,
        };
        session.accept(material);
        session
    }

    fn accept(&mut self, material: &TlsMaterial) {
        self.generation = material.generation;
        // The first expiry in the presented chain, the trusted CAs or the lists.
        self.revalidate_at = self
            .chain
            .iter()
            .filter_map(|certificate| not_after(certificate))
            .chain(material.client_certificate_authority_not_after)
            .chain(material.client_revocation_list_next_update)
            .min();
    }
}
