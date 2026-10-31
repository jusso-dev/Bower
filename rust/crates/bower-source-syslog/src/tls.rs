//! TLS material reloaded when its files change (C# `SyslogTlsSource`, `SyslogTlsMaterial`,
//! `SyslogTlsSession` and `CertificateRevocationList`).
//!
//! A per-listener task reads the files on the blocking pool every interval and swaps in new
//! material when their content changed; connection and frame paths only read an atomic
//! generation and clone the current `Arc`, never touching a file or holding a lock across
//! I/O. A change that cannot be loaded keeps the last good material, is counted once per
//! distinct content and is retried every interval. Superseded material is freed when the
//! last handshake holding its `Arc` ends.
//!
//! Client chains are checked by rustls' `WebPkiClientVerifier` (signatures, usage and the
//! validity of the leaf and intermediates), then by [`BowerClientVerifier`], identical to
//! C#: the chain must end at a configured CA that is valid now (rustls trust anchors do not
//! keep `notAfter`), and revocation lists are selected by the key of the CA that actually
//! issued the leaf and by their issuing-distribution-point scope.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use bower_contracts::time::Timestamp;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, SignatureVerificationAlgorithm,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use crate::config::{ListenerOptions, SyslogSourceConfiguration};
use crate::source::SourceError;

/// Largest certificate, key, CA bundle or revocation list file read (C# `MaximumFileBytes`).
pub const MAXIMUM_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_LISTS: usize = 64;
/// Longest chain of intermediates searched between a sender and a configured CA.
const MAXIMUM_PATH_DEPTH: usize = 6;

/// Checks that every TLS listener's files load, as start-up does (C# `SyslogSource.ValidateTls`).
/// The collector's signed reload pre-check calls this too.
pub fn validate(configuration: &SyslogSourceConfiguration) -> Result<(), SourceError> {
    for listener in configuration
        .listeners
        .iter()
        .filter(|listener| listener.protocol == "tls")
    {
        let files = TlsFiles::read(listener).map_err(|()| SourceError::Tls(listener.id.clone()))?;
        TlsMaterial::load(listener, &files, 0)?;
    }
    Ok(())
}

/// Every configured TLS file, read once, and the digest of exactly those bytes.
struct TlsFiles {
    certificate: Vec<u8>,
    key: Vec<u8>,
    authorities: Option<Vec<u8>>,
    lists: Option<Vec<u8>>,
    stamp: [u8; 32],
}

impl TlsFiles {
    fn read(options: &ListenerOptions) -> Result<Self, ()> {
        let tls = options.tls.as_ref().ok_or(())?;
        let certificate = read_bounded(&tls.certificate_file)?;
        // One bundle file may hold both the certificate chain and the key.
        let key = if tls.private_key_file == tls.certificate_file {
            certificate.clone()
        } else {
            read_bounded(&tls.private_key_file)?
        };
        let authorities = tls
            .client_certificate_authority_file
            .as_deref()
            .map(read_bounded)
            .transpose()?;
        let lists = tls
            .client_certificate_revocation_list_file
            .as_deref()
            .map(read_bounded)
            .transpose()?;
        let mut hash = Sha256::new();
        for part in [
            Some(&certificate),
            Some(&key),
            authorities.as_ref(),
            lists.as_ref(),
        ] {
            match part {
                None => hash.update([0u8]),
                Some(bytes) => hash.update(Sha256::digest(bytes)),
            }
        }
        Ok(Self {
            certificate,
            key,
            authorities,
            lists,
            stamp: hash.finalize().into(),
        })
    }
}

/// Reads one TLS file. Refuses anything that is not a non-empty regular file (a FIFO,
/// device, socket or directory is never opened, so a read cannot block).
pub(crate) fn read_bounded(path: &str) -> Result<Vec<u8>, ()> {
    let metadata = std::fs::metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_FILE_BYTES {
        return Err(());
    }
    let file = std::fs::File::open(path).map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| ())?);
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAXIMUM_FILE_BYTES + 1),
        &mut bytes,
    )
    .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_FILE_BYTES {
        return Err(());
    }
    Ok(bytes)
}

struct RefreshState {
    stamp: [u8; 32],
    last_failure: Option<Vec<u8>>,
}

pub(crate) struct TlsSource {
    options: ListenerOptions,
    current: RwLock<Arc<TlsMaterial>>,
    generation: AtomicI64,
    refresh: Mutex<RefreshState>,
    reloads: AtomicI64,
    reload_failures: AtomicI64,
}

impl TlsSource {
    /// Loads the initial material; any failure stops listener start-up.
    pub fn load(options: &ListenerOptions) -> Result<Self, SourceError> {
        let files = TlsFiles::read(options).map_err(|()| SourceError::Tls(options.id.clone()))?;
        let material = TlsMaterial::load(options, &files, 1)?;
        Ok(Self {
            options: options.clone(),
            current: RwLock::new(Arc::new(material)),
            generation: AtomicI64::new(1),
            refresh: Mutex::new(RefreshState {
                stamp: files.stamp,
                last_failure: None,
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

    /// The current generation, lock-free (the per-frame fast path).
    pub fn generation(&self) -> i64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The current material (a read lock held only to clone the `Arc`).
    pub fn current(&self) -> Arc<TlsMaterial> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }

    /// Reads the files once and swaps in new material when their content changed. Runs on
    /// the blocking pool from one refresh task per listener; no lock is held across I/O or
    /// the rustls build.
    pub fn refresh(&self) {
        let Ok(files) = TlsFiles::read(&self.options) else {
            self.failed(b"read".to_vec());
            return;
        };
        if self.state().stamp == files.stamp {
            self.state().last_failure = None;
            return;
        }
        match TlsMaterial::load(&self.options, &files, self.generation() + 1) {
            Ok(material) => {
                let generation = material.generation;
                *self
                    .current
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner()) = Arc::new(material);
                self.generation.store(generation, Ordering::Release);
                let mut state = self.state();
                state.stamp = files.stamp;
                state.last_failure = None;
                self.reloads.fetch_add(1, Ordering::SeqCst);
            }
            // The stamp stays put, so the same files are tried again next interval but
            // counted once.
            Err(_) => self.failed(files.stamp.to_vec()),
        }
    }

    fn state(&self) -> MutexGuard<'_, RefreshState> {
        self.refresh
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn failed(&self, key: Vec<u8>) {
        let mut state = self.state();
        if state.last_failure.as_ref() != Some(&key) {
            state.last_failure = Some(key);
            self.reload_failures.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// One generation of loaded material.
pub(crate) struct TlsMaterial {
    pub generation: i64,
    pub acceptor: TlsAcceptor,
    verifier: Option<Arc<BowerClientVerifier>>,
    pub server_certificate_not_after: Option<Timestamp>,
    pub client_certificate_authority_not_after: Option<Timestamp>,
    pub client_revocation_list_next_update: Option<Timestamp>,
    /// Every trusted CA's expiry: an open session is validated again when one passes.
    authority_expiries: Vec<Timestamp>,
}

fn timestamp(seconds: i64) -> Option<Timestamp> {
    chrono::DateTime::from_timestamp(seconds, 0).map(|value| value.fixed_offset())
}

impl TlsMaterial {
    fn load(
        options: &ListenerOptions,
        files: &TlsFiles,
        generation: i64,
    ) -> Result<Self, SourceError> {
        let failed = || SourceError::Tls(options.id.clone());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let certificates = CertificateDer::pem_slice_iter(&files.certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| failed())?;
        if certificates.is_empty() {
            return Err(failed());
        }
        let server_certificate_not_after = Certificate::parse(&certificates[0])
            .ok()
            .and_then(|certificate| timestamp(certificate.not_after));
        let key = PrivateKeyDer::from_pem_slice(&files.key).map_err(|_| failed())?;
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| failed())?;
        let mut verifier = None;
        let mut authority_expiries = Vec::new();
        let mut client_revocation_list_next_update = None;
        let builder = match &files.authorities {
            None => builder.with_no_client_auth(),
            Some(bytes) => {
                let mut roots = rustls::RootCertStore::empty();
                let mut anchors = Vec::new();
                for certificate in CertificateDer::pem_slice_iter(bytes) {
                    let certificate = certificate.map_err(|_| failed())?;
                    let parsed = Certificate::parse(&certificate).map_err(|()| failed())?;
                    authority_expiries.extend(timestamp(parsed.not_after));
                    anchors.push(parsed);
                    roots.add(certificate).map_err(|_| failed())?;
                }
                if roots.is_empty() {
                    return Err(failed());
                }
                let lists = match &files.lists {
                    None => Vec::new(),
                    Some(bytes) => RevocationList::load(bytes).map_err(|error| match error {
                        ListError::Unsupported(message) => {
                            SourceError::TlsUnsupported(options.id.clone(), message)
                        }
                        ListError::Malformed => failed(),
                    })?,
                };
                client_revocation_list_next_update = lists
                    .iter()
                    .map(|list| list.next_update)
                    .min()
                    .and_then(timestamp);
                let inner = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::clone(&provider),
                )
                .build()
                .map_err(|_| failed())?;
                let built = Arc::new(BowerClientVerifier {
                    inner,
                    anchors,
                    lists,
                    algorithms: provider.signature_verification_algorithms.all,
                });
                verifier = Some(Arc::clone(&built));
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
            client_certificate_authority_not_after: authority_expiries.iter().copied().min(),
            client_revocation_list_next_update,
            authority_expiries,
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

/// Whether a refused handshake was a revocation decision (C# `TlsRevoked`).
pub(crate) fn is_revocation_failure(error: &std::io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidCertificate(
            CertificateError::Revoked
                | CertificateError::UnknownRevocationStatus
                | CertificateError::ExpiredRevocationList
        ))
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
        // The first expiry in the presented chain, the trusted CAs that can still anchor it
        // (an already expired CA in the bundle cannot) or the lists.
        let now = chrono::Utc::now().fixed_offset();
        self.revalidate_at = self
            .chain
            .iter()
            .filter_map(|certificate| Certificate::parse(certificate).ok())
            .filter_map(|certificate| timestamp(certificate.not_after))
            .chain(
                material
                    .authority_expiries
                    .iter()
                    .copied()
                    .filter(|expiry| *expiry > now),
            )
            .chain(material.client_revocation_list_next_update)
            .min();
    }
}

// ------------------------------------------------------------------ client verifier

/// rustls' chain checks, then the configured-CA validity and revocation checks C# makes.
pub(crate) struct BowerClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    anchors: Vec<Certificate>,
    lists: Vec<RevocationList>,
    algorithms: &'static [&'static dyn SignatureVerificationAlgorithm],
}

impl std::fmt::Debug for BowerClientVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BowerClientVerifier")
            .field("anchors", &self.anchors.len())
            .field("lists", &self.lists.len())
            .finish_non_exhaustive()
    }
}

impl BowerClientVerifier {
    fn signed(
        &self,
        algorithm: &[u8],
        issuer: &Certificate,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        self.algorithms.iter().any(|candidate| {
            candidate.signature_alg_id().as_ref() == algorithm
                && candidate.public_key_alg_id().as_ref() == issuer.key_algorithm.as_slice()
                && candidate
                    .verify_signature(&issuer.key, message, signature)
                    .is_ok()
        })
    }

    /// The certificate that issued `certificate` on a path that ends at a configured CA
    /// valid at `now`. Issuers are matched by name and by verifying the signature, so CAs
    /// sharing a subject (a re-keyed CA) are told apart.
    fn issuer<'a>(
        &'a self,
        certificate: &Certificate,
        intermediates: &'a [Certificate],
        now: i64,
        depth: usize,
    ) -> Option<&'a Certificate> {
        let issued = |candidate: &Certificate| {
            candidate.subject == certificate.issuer
                && self.signed(
                    &certificate.signature_algorithm,
                    candidate,
                    &certificate.signed_part,
                    &certificate.signature,
                )
        };
        if let Some(anchor) = self
            .anchors
            .iter()
            .find(|anchor| anchor.not_before <= now && now <= anchor.not_after && issued(anchor))
        {
            return Some(anchor);
        }
        if depth >= MAXIMUM_PATH_DEPTH {
            return None;
        }
        intermediates.iter().find(|intermediate| {
            issued(intermediate)
                && self
                    .issuer(intermediate, intermediates, now, depth + 1)
                    .is_some()
        })
    }

    /// C# `SyslogTlsMaterial.NotRevoked`.
    fn not_revoked(
        &self,
        leaf: &Certificate,
        issuer: &Certificate,
        now: i64,
    ) -> Result<(), CertificateError> {
        if self.lists.is_empty() {
            return Ok(());
        }
        let (mut any, mut current) = (false, false);
        for list in &self.lists {
            if list.issuer != leaf.issuer
                || !list.covers(&leaf.distribution_points)
                || !list.signed_by(self, issuer)
            {
                continue;
            }
            any = true;
            if list.revoked.contains(&serial(&leaf.serial)) {
                return Err(CertificateError::Revoked);
            }
            current |= list.next_update >= now;
        }
        if !any {
            return Err(CertificateError::UnknownRevocationStatus);
        }
        if !current {
            return Err(CertificateError::ExpiredRevocationList);
        }
        Ok(())
    }
}

impl ClientCertVerifier for BowerClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let bad = || rustls::Error::InvalidCertificate(CertificateError::BadEncoding);
        let leaf = Certificate::parse(end_entity).map_err(|()| bad())?;
        let intermediates = intermediates
            .iter()
            .map(|certificate| Certificate::parse(certificate))
            .collect::<Result<Vec<_>, ()>>()
            .map_err(|()| bad())?;
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let issuer = self
            .issuer(&leaf, &intermediates, now, 0)
            .ok_or(rustls::Error::InvalidCertificate(CertificateError::Expired))?;
        self.not_revoked(&leaf, issuer, now)
            .map_err(rustls::Error::InvalidCertificate)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ------------------------------------------------------------------ X.509 and CRL parsing

/// The fields of an X.509 certificate this module needs, with raw DER for comparisons.
pub(crate) struct Certificate {
    signed_part: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature: Vec<u8>,
    serial: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: i64,
    not_after: i64,
    key_algorithm: Vec<u8>,
    key: Vec<u8>,
    crl_sign: bool,
    distribution_points: Vec<Vec<u8>>,
}

impl Certificate {
    fn parse(der: &[u8]) -> Result<Self, ()> {
        let mut outer = Reader::new(der);
        let mut certificate = outer.expect(SEQUENCE)?.reader();
        outer.finish()?;
        let signed = certificate.expect(SEQUENCE)?;
        let signature_algorithm = certificate.expect(SEQUENCE)?.value.to_vec();
        let signature = bit_string(certificate.expect(BIT_STRING)?.value)?;
        let mut tbs = signed.reader();
        if tbs.peek() == Some(0xA0) {
            tbs.next()?;
        }
        let serial = tbs.expect(INTEGER)?.value.to_vec();
        tbs.expect(SEQUENCE)?;
        let issuer = tbs.expect(SEQUENCE)?.raw.to_vec();
        let mut validity = tbs.expect(SEQUENCE)?.reader();
        let not_before = time(&validity.next()?)?;
        let not_after = time(&validity.next()?)?;
        let subject = tbs.expect(SEQUENCE)?.raw.to_vec();
        let mut key_info = tbs.expect(SEQUENCE)?.reader();
        let key_algorithm = key_info.expect(SEQUENCE)?.value.to_vec();
        let key = bit_string(key_info.expect(BIT_STRING)?.value)?;
        let mut crl_sign = true;
        let mut distribution_points = Vec::new();
        while let Some(tag) = tbs.peek() {
            let field = tbs.next()?;
            if tag != 0xA3 {
                continue;
            }
            for (oid, _, value) in extensions(field.reader().expect(SEQUENCE)?.reader())? {
                match oid.as_str() {
                    // keyUsage: cRLSign is bit 6 (0x02 in the first byte).
                    "2.5.29.15" => {
                        let bits =
                            bit_string_with_unused(Reader::new(&value).expect(BIT_STRING)?.value)?;
                        crl_sign = bits.first().is_some_and(|byte| byte & 0x02 != 0);
                    }
                    "2.5.29.31" => distribution_points = certificate_distribution_points(&value),
                    _ => {}
                }
            }
        }
        Ok(Self {
            signed_part: signed.raw.to_vec(),
            signature_algorithm,
            signature,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            key_algorithm,
            key,
            crl_sign,
            distribution_points,
        })
    }
}

/// `fullName` general names of a certificate's CRL distribution points; points with a
/// separate CRL issuer are skipped, and a malformed extension names none (C# `DistributionPoints`).
fn certificate_distribution_points(value: &[u8]) -> Vec<Vec<u8>> {
    let read = || -> Result<Vec<Vec<u8>>, ListError> {
        let mut names = Vec::new();
        let mut points = Reader::new(value).expect(SEQUENCE)?.reader();
        while !points.is_empty() {
            let mut point = points.expect(SEQUENCE)?.reader();
            let (mut point_names, mut indirect) = (Vec::new(), false);
            while let Some(tag) = point.peek() {
                let field = point.next()?;
                if tag == 0xA0 {
                    point_names.extend(distribution_point_name(field.reader(), false)?);
                } else {
                    indirect |= tag == 0x82 || tag == 0xA2;
                }
            }
            if !indirect {
                names.extend(point_names);
            }
        }
        Ok(names)
    };
    read().unwrap_or_default()
}

pub(crate) enum ListError {
    Malformed,
    /// A list Bower cannot apply correctly; the message names the feature, never content.
    Unsupported(String),
}

impl From<()> for ListError {
    fn from((): ()) -> Self {
        Self::Malformed
    }
}

fn unsupported(message: &str) -> ListError {
    ListError::Unsupported(message.to_string())
}

/// An X.509 v2 revocation list, parsed exactly as C# `CertificateRevocationList` does.
pub(crate) struct RevocationList {
    issuer: Vec<u8>,
    next_update: i64,
    revoked: HashSet<Vec<u8>>,
    signed_part: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature: Vec<u8>,
    scope_names: Vec<Vec<u8>>,
    covers_senders: bool,
    verified: Mutex<HashMap<[u8; 32], bool>>,
}

impl RevocationList {
    /// One or more PEM `X509 CRL` blocks, or a single DER list.
    fn load(bytes: &[u8]) -> Result<Vec<Self>, ListError> {
        if !bytes.windows(10).any(|window| window == b"-----BEGIN") {
            return Ok(vec![Self::parse(bytes)?]);
        }
        let ders = CertificateRevocationListDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ListError::Malformed)?;
        if ders.is_empty() || ders.len() > MAXIMUM_LISTS {
            return Err(ListError::Malformed);
        }
        ders.iter().map(|der| Self::parse(der)).collect()
    }

    fn parse(der: &[u8]) -> Result<Self, ListError> {
        let mut outer = Reader::new(der);
        let mut list = outer.expect(SEQUENCE)?.reader();
        outer.finish()?;
        let signed = list.expect(SEQUENCE)?;
        let algorithm_field = list.expect(SEQUENCE)?;
        let signature = bit_string(list.expect(BIT_STRING)?.value)?;
        list.finish()?;
        let algorithm = algorithm_name(algorithm_field.value)?;
        if ![
            "1.2.840.113549.1.1.11",
            "1.2.840.113549.1.1.12",
            "1.2.840.113549.1.1.13",
            "1.2.840.10045.4.3.2",
            "1.2.840.10045.4.3.3",
            "1.2.840.10045.4.3.4",
        ]
        .contains(&algorithm.as_str())
        {
            return Err(unsupported(
                "client revocation list signature algorithm is not supported (RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512).",
            ));
        }
        let mut tbs = signed.reader();
        if tbs.peek() == Some(INTEGER) && tbs.next()?.value != [1] {
            return Err(ListError::Malformed);
        }
        if algorithm_name(tbs.expect(SEQUENCE)?.value)? != algorithm {
            return Err(ListError::Malformed);
        }
        let issuer = tbs.expect(SEQUENCE)?.raw.to_vec();
        time(&tbs.next()?)?;
        // RFC 5280 requires nextUpdate.
        let next_update = match tbs.peek() {
            Some(UTC_TIME | GENERALIZED_TIME) => time(&tbs.next()?)?,
            _ => return Err(ListError::Malformed),
        };
        let mut revoked = HashSet::new();
        if tbs.peek() == Some(SEQUENCE) {
            let mut entries = tbs.next()?.reader();
            while !entries.is_empty() {
                let mut entry = entries.expect(SEQUENCE)?.reader();
                revoked.insert(serial(entry.expect(INTEGER)?.value));
                time(&entry.next()?)?;
                if !entry.is_empty() {
                    for (oid, critical, _) in extensions(entry.expect(SEQUENCE)?.reader())? {
                        if critical {
                            return Err(ListError::Unsupported(format!(
                                "client revocation list entry has an unsupported critical extension ({oid})."
                            )));
                        }
                    }
                }
                entry.finish()?;
            }
        }
        let (mut scope_names, mut covers_senders) = (Vec::new(), true);
        if !tbs.is_empty() {
            let mut explicit = tbs.expect(0xA0)?.reader();
            for (oid, critical, value) in extensions(explicit.expect(SEQUENCE)?.reader())? {
                if oid == "2.5.29.28" {
                    (scope_names, covers_senders) = issuing_distribution_point(&value)?;
                } else if oid == "2.5.29.27" {
                    return Err(unsupported(
                        "delta client revocation lists are not supported.",
                    ));
                } else if critical {
                    return Err(ListError::Unsupported(format!(
                        "client revocation list has an unsupported critical extension ({oid})."
                    )));
                }
            }
            explicit.finish()?;
        }
        tbs.finish()?;
        Ok(Self {
            issuer,
            next_update,
            revoked,
            signed_part: signed.raw.to_vec(),
            signature_algorithm: algorithm_field.value.to_vec(),
            signature,
            scope_names,
            covers_senders,
            verified: Mutex::new(HashMap::new()),
        })
    }

    fn covers(&self, distribution_points: &[Vec<u8>]) -> bool {
        self.covers_senders
            && (self.scope_names.is_empty()
                || distribution_points
                    .iter()
                    .any(|name| self.scope_names.contains(name)))
    }

    /// Signature check against the issuing CA (which must allow CRL signing), cached per CA.
    fn signed_by(&self, verifier: &BowerClientVerifier, issuer: &Certificate) -> bool {
        let key: [u8; 32] = Sha256::digest(&issuer.signed_part).into();
        let mut verified = self
            .verified
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *verified.entry(key).or_insert_with(|| {
            issuer.crl_sign
                && verifier.signed(
                    &self.signature_algorithm,
                    issuer,
                    &self.signed_part,
                    &self.signature,
                )
        })
    }
}

/// IssuingDistributionPoint (RFC 5280 5.2.5): the `fullName` scope and whether end-entity
/// certificates are in scope. Unsupported scopes fail with their name (C# messages).
fn issuing_distribution_point(value: &[u8]) -> Result<(Vec<Vec<u8>>, bool), ListError> {
    let mut outer = Reader::new(value);
    let mut point = outer.expect(SEQUENCE)?.reader();
    outer.finish()?;
    let mut names = Vec::new();
    let mut covers_senders = true;
    if point.peek() == Some(0xA0) {
        names = distribution_point_name(point.next()?.reader(), true)?;
    }
    for tag in 1u8..=5 {
        if point.peek() != Some(0x80 | tag) {
            continue;
        }
        if tag == 3 {
            return Err(unsupported(
                "client revocation lists limited to some revocation reasons are not supported.",
            ));
        }
        let set = boolean(point.next()?.value)?;
        if set && tag == 4 {
            return Err(unsupported(
                "indirect client revocation lists are not supported.",
            ));
        }
        // onlyContainsCACerts or onlyContainsAttributeCerts: never a sender certificate.
        covers_senders &= !(set && (tag == 2 || tag == 5));
    }
    point.finish()?;
    Ok((names, covers_senders))
}

fn distribution_point_name(
    mut name: Reader<'_>,
    refuse_relative: bool,
) -> Result<Vec<Vec<u8>>, ListError> {
    let mut names = Vec::new();
    if name.peek() == Some(0xA0) {
        let mut full = name.next()?.reader();
        while !full.is_empty() {
            names.push(full.next()?.raw.to_vec());
        }
    } else if refuse_relative {
        return Err(unsupported(
            "client revocation list distribution points relative to the issuer are not supported.",
        ));
    } else {
        name.next()?;
    }
    name.finish()?;
    Ok(names)
}

type Extension = (String, bool, Vec<u8>);

fn extensions(mut sequence: Reader<'_>) -> Result<Vec<Extension>, ()> {
    let mut read = Vec::new();
    while !sequence.is_empty() {
        let mut extension = sequence.expect(SEQUENCE)?.reader();
        let oid = oid_string(extension.expect(OID)?.value)?;
        let critical = if extension.peek() == Some(BOOLEAN) {
            boolean(extension.next()?.value)?
        } else {
            false
        };
        let value = extension.expect(OCTET_STRING)?.value.to_vec();
        extension.finish()?;
        read.push((oid, critical, value));
    }
    Ok(read)
}

/// The algorithm OID; supported algorithms carry no parameters other than RSA's NULL.
fn algorithm_name(contents: &[u8]) -> Result<String, ()> {
    let mut algorithm = Reader::new(contents);
    let oid = oid_string(algorithm.expect(OID)?.value)?;
    if algorithm.peek() == Some(NULL) {
        algorithm.next()?;
    }
    Ok(if algorithm.is_empty() {
        oid
    } else {
        format!("{oid}+parameters")
    })
}

/// Serial number without leading zero bytes (sign padding or not), as C# compares it.
fn serial(big_endian: &[u8]) -> Vec<u8> {
    let last = big_endian.len().saturating_sub(1);
    let start = big_endian
        .iter()
        .take(last)
        .position(|byte| *byte != 0)
        .unwrap_or(last);
    big_endian[start..].to_vec()
}

// ------------------------------------------------------------------ minimal DER reader

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const SEQUENCE: u8 = 0x30;

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    fn reader(&self) -> Reader<'a> {
        Reader::new(self.value)
    }
}

/// Definite-length, single-byte-tag DER (all these structures use), minimal lengths only.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn finish(&self) -> Result<(), ()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }

    fn next(&mut self) -> Result<Tlv<'a>, ()> {
        let input = self.rest;
        let (&tag, after) = input.split_first().ok_or(())?;
        if tag & 0x1F == 0x1F {
            return Err(());
        }
        let (&first, after) = after.split_first().ok_or(())?;
        let (length, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7F);
            if count == 0 || count > 4 || after.len() < count || after[0] == 0 {
                return Err(());
            }
            let length = after[..count]
                .iter()
                .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
            if length < 0x80 {
                return Err(());
            }
            (length, 2 + count)
        };
        let end = header.checked_add(length).ok_or(())?;
        if input.len() < end {
            return Err(());
        }
        self.rest = &input[end..];
        Ok(Tlv {
            tag,
            value: &input[header..end],
            raw: &input[..end],
        })
    }

    fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, ()> {
        let tlv = self.next()?;
        if tlv.tag == tag { Ok(tlv) } else { Err(()) }
    }
}

fn bit_string(value: &[u8]) -> Result<Vec<u8>, ()> {
    match value.split_first() {
        Some((0, bits)) => Ok(bits.to_vec()),
        _ => Err(()),
    }
}

fn bit_string_with_unused(value: &[u8]) -> Result<Vec<u8>, ()> {
    value
        .split_first()
        .filter(|(unused, _)| **unused < 8)
        .map(|(_, bits)| bits.to_vec())
        .ok_or(())
}

fn boolean(value: &[u8]) -> Result<bool, ()> {
    match value {
        [0x00] => Ok(false),
        [0xFF] => Ok(true),
        _ => Err(()),
    }
}

fn oid_string(value: &[u8]) -> Result<String, ()> {
    let mut arcs: Vec<u64> = Vec::new();
    let mut current: u64 = 0;
    let mut pending = false;
    for byte in value {
        if !pending && *byte == 0x80 {
            return Err(());
        }
        current = current.checked_mul(128).ok_or(())? | u64::from(byte & 0x7F);
        pending = byte & 0x80 != 0;
        if !pending {
            if arcs.is_empty() {
                let first = (current / 40).min(2);
                arcs.push(first);
                arcs.push(current - first * 40);
            } else {
                arcs.push(current);
            }
            current = 0;
        }
    }
    if pending || arcs.is_empty() {
        return Err(());
    }
    Ok(arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSS[.f]Z`) as Unix seconds.
fn time(tlv: &Tlv<'_>) -> Result<i64, ()> {
    let text = std::str::from_utf8(tlv.value).map_err(|_| ())?;
    let text = text.strip_suffix('Z').ok_or(())?;
    let (year, rest) = match tlv.tag {
        UTC_TIME if text.len() == 12 => {
            let short: i32 = text[..2].parse().map_err(|_| ())?;
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                &text[2..],
            )
        }
        GENERALIZED_TIME if text.len() >= 14 => (text[..4].parse().map_err(|_| ())?, &text[4..]),
        _ => return Err(()),
    };
    if !rest.is_char_boundary(10) || !rest.as_bytes()[..10].iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    let field = |range: std::ops::Range<usize>| rest[range].parse::<u32>().map_err(|_| ());
    let date = chrono::NaiveDate::from_ymd_opt(year, field(0..2)?, field(2..4)?).ok_or(())?;
    let moment = date
        .and_hms_opt(field(4..6)?, field(6..8)?, field(8..10)?)
        .ok_or(())?;
    Ok(moment.and_utc().timestamp())
}
