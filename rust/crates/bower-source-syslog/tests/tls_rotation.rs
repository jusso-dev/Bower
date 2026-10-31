//! Port of C# `SyslogTlsRotationTests`: certificate, client CA and revocation list
//! rotation on a live TLS listener, and the certificates it must refuse.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_source_syslog::config;
use bower_source_syslog::{
    ListenerOptions, ListenerStatus, Route, SinkFailure, SubmitOutcome, SyslogSink, SyslogSource,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams,
    SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

static SERIAL: AtomicU64 = AtomicU64::new(1000);

/// Calendar day `offset` days from today (UTC), as rcgen's date type.
macro_rules! day {
    ($offset:expr) => {{
        use chrono::Datelike as _;
        let date = (chrono::Utc::now() + chrono::Duration::days($offset)).date_naive();
        rcgen::date_time_ymd(
            date.year(),
            u8::try_from(date.month()).unwrap(),
            u8::try_from(date.day()).unwrap(),
        )
    }};
}

struct Authority(CertifiedIssuer<'static, KeyPair>);

struct Issued {
    certificate: String,
    key: String,
    serial: u64,
}

fn authority(name: &str, from: i64, to: i64) -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = day!(from);
    params.not_after = day!(to);
    Authority(CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap())
}

impl Authority {
    fn pem(&self) -> String {
        self.0.pem()
    }

    fn issue(&self, name: &str, client: bool, from: i64, to: i64) -> Issued {
        let key = KeyPair::generate().unwrap();
        let names = if client {
            Vec::new()
        } else {
            vec!["localhost".to_string(), "127.0.0.1".to_string()]
        };
        let mut params = CertificateParams::new(names).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![if client {
            ExtendedKeyUsagePurpose::ClientAuth
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        let serial = SERIAL.fetch_add(1, Ordering::SeqCst);
        params.serial_number = Some(SerialNumber::from(serial));
        params.not_before = day!(from);
        params.not_after = day!(to);
        let certificate = params.signed_by(&key, &self.0).unwrap();
        Issued {
            certificate: certificate.pem(),
            key: key.serialize_pem(),
            serial,
        }
    }

    /// A signed list revoking `revoked`, valid from `this_update` to `next_update` days.
    fn revocation_list(&self, revoked: &[&Issued], this_update: i64, next_update: i64) -> String {
        CertificateRevocationListParams {
            this_update: day!(this_update),
            next_update: day!(next_update),
            crl_number: SerialNumber::from(SERIAL.fetch_add(1, Ordering::SeqCst)),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|issued| RevokedCertParams {
                    serial_number: SerialNumber::from(issued.serial),
                    revocation_time: day!(-1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&self.0)
        .unwrap()
        .pem()
        .unwrap()
    }
}

/// Generated PKI written as PEM files, each replaced by an atomic rename.
struct Files {
    certificate: PathBuf,
    key: PathBuf,
    authorities: PathBuf,
    revocations: PathBuf,
}

impl Files {
    fn new(directory: &Path) -> Self {
        Self {
            certificate: directory.join("server.pem"),
            key: directory.join("server-key.pem"),
            authorities: directory.join("client-ca.pem"),
            revocations: directory.join("client-ca.crl"),
        }
    }

    fn server(&self, issued: &Issued) {
        replace(&self.key, &issued.key);
        replace(&self.certificate, &issued.certificate);
    }

    fn authorities(&self, authorities: &[&Authority]) {
        let pem: Vec<String> = authorities
            .iter()
            .map(|authority| authority.pem())
            .collect();
        replace(&self.authorities, &pem.join("\n"));
    }
}

fn replace(path: &Path, content: &str) {
    let staging = path.with_extension("new");
    std::fs::write(&staging, content).unwrap();
    std::fs::rename(&staging, path).unwrap();
}

#[derive(Default)]
struct Sink(Mutex<Vec<String>>);

impl SyslogSink for Sink {
    fn submit(
        &self,
        _: &ListenerOptions,
        _: &Route,
        record: &str,
    ) -> Result<SubmitOutcome, SinkFailure> {
        self.0.lock().unwrap().push(record.to_string());
        Ok(SubmitOutcome::Queued)
    }
}

impl Sink {
    fn messages(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|record| {
                let value: serde_json::Value = serde_json::from_str(record).unwrap();
                value["message"].as_str().unwrap_or_default().to_string()
            })
            .collect()
    }

    async fn wait_for(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.0.lock().unwrap().len() < count {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("records");
    }
}

struct Running {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    metrics: bower_source_syslog::SyslogMetrics,
    endpoint: std::net::SocketAddr,
    server_ca: String,
}

impl Running {
    fn status(&self) -> ListenerStatus {
        self.metrics.snapshot().remove(0)
    }

    async fn wait_for(&self, condition: impl Fn(&ListenerStatus) -> bool) -> ListenerStatus {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = self.status();
                if condition(&status) {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("status condition")
    }

    async fn stop(self) {
        let _ = self.stop.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("stops promptly")
            .unwrap();
    }
}

fn listener(files: &Files, mutual: bool, revocations: bool) -> String {
    let quote = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
    let mut tls = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}"#,
        quote(&files.certificate),
        quote(&files.key)
    );
    if mutual {
        tls += &format!(
            r#", "clientCertificateAuthorityFile": {}"#,
            quote(&files.authorities)
        );
    }
    if revocations {
        tls += &format!(
            r#", "clientCertificateRevocationListFile": {}"#,
            quote(&files.revocations)
        );
    }
    format!(
        r#"{{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{{
        "id": "edge", "protocol": "tls", "address": "127.0.0.1", "port": 0,
        "allowedSenders": ["127.0.0.1"], "maximumMessageBytes": 512, "idleTimeoutSeconds": 30,
        "tls": {tls}}},
        "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}}]}}]}}"#
    )
}

async fn start(
    files: &Files,
    server_ca: &Authority,
    sink: Arc<Sink>,
    mutual: bool,
    revocations: bool,
) -> Result<Running, String> {
    let configuration =
        config::parse(&listener(files, mutual, revocations)).map_err(|error| error.to_string())?;
    let mut source = SyslogSource::new(configuration, sink, None)
        .with_retry_delay(Duration::from_millis(20))
        .with_tls_reload_interval(Duration::ZERO);
    source.bind().await.map_err(|error| error.to_string())?;
    let endpoint = source.endpoints()["edge"];
    let metrics = source.metrics();
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(source.run(receiver));
    Ok(Running {
        stop,
        task,
        metrics,
        endpoint,
        server_ca: server_ca.pem(),
    })
}

/// A client session; records the SHA-256 of the certificate the server presented.
struct Connection {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    server: String,
}

impl Connection {
    async fn open(running: &Running, client: Option<&Issued>) -> std::io::Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(running.server_ca.as_bytes()) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let config = match client {
            None => builder.with_no_client_auth(),
            Some(issued) => builder
                .with_client_auth_cert(
                    CertificateDer::pem_slice_iter(issued.certificate.as_bytes())
                        .map(Result::unwrap)
                        .collect(),
                    PrivateKeyDer::from_pem_slice(issued.key.as_bytes()).unwrap(),
                )
                .unwrap(),
        };
        let tcp = TcpStream::connect(running.endpoint).await?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        let server = hex::encode(Sha256::digest(
            &stream.get_ref().1.peer_certificates().unwrap()[0],
        ));
        Ok(Self { stream, server })
    }

    async fn send(&mut self, message: &str) -> std::io::Result<()> {
        self.stream
            .write_all(format!("<38>Oct 11 22:14:15 gw01 sshd: {message}\n").as_bytes())
            .await?;
        self.stream.flush().await
    }

    /// True once the server has closed the session.
    async fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(10), self.stream.read(&mut byte)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    /// True when a fresh session accepted the frame and stayed open.
    async fn try_deliver(running: &Running, client: &Issued, message: &str) -> bool {
        let Ok(mut connection) = Self::open(running, Some(client)).await else {
            return false;
        };
        if connection.send(message).await.is_err() {
            return false;
        }
        // TLS 1.3 reports a refused client certificate only on the next read.
        let mut byte = [0u8; 1];
        match tokio::time::timeout(
            Duration::from_millis(500),
            connection.stream.read(&mut byte),
        )
        .await
        {
            Err(_) => true,
            Ok(Ok(read)) => read != 0,
            Ok(Err(_)) => false,
        }
    }
}

fn sha(issued: &Issued) -> String {
    let der = CertificateDer::from_pem_slice(issued.certificate.as_bytes()).unwrap();
    hex::encode(Sha256::digest(&der))
}

#[tokio::test]
async fn server_certificate_rotation_applies_without_restart_or_dropping_open_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let files = Files::new(directory.path());
    let ca = authority("syslog-ca", -30, 30);
    let first = ca.issue("localhost", false, -1, 20);
    let second = ca.issue("localhost", false, -1, 25);
    let sender = ca.issue("firewall-01", true, -1, 20);
    files.server(&first);
    files.authorities(&[&ca]);
    let sink = Arc::new(Sink::default());
    let running = start(&files, &ca, Arc::clone(&sink), true, false)
        .await
        .unwrap();

    let mut open = Connection::open(&running, Some(&sender)).await.unwrap();
    assert_eq!(open.server, sha(&first));
    open.send("before rotation").await.unwrap();
    sink.wait_for(1).await;

    files.server(&second);
    let status = running.wait_for(|status| status.tls_reloads == 1).await;
    assert!(status.server_certificate_not_after.is_some());
    let mut fresh = Connection::open(&running, Some(&sender)).await.unwrap();
    assert_eq!(fresh.server, sha(&second));
    fresh.send("new session").await.unwrap();
    // The session opened before the rotation keeps its connection and its frames.
    open.send("after rotation").await.unwrap();
    sink.wait_for(3).await;
    let status = running.status();
    assert_eq!(status.tls_sessions_closed, 0);
    assert_eq!(status.tls_handshake_failures, 0);
    running.stop().await;
}

#[tokio::test]
async fn failed_reload_keeps_last_good_material_until_the_files_are_valid() {
    let directory = tempfile::tempdir().unwrap();
    let files = Files::new(directory.path());
    let ca = authority("syslog-ca", -30, 30);
    let first = ca.issue("localhost", false, -1, 20);
    let second = ca.issue("localhost", false, -1, 20);
    let unrelated = ca.issue("localhost", false, -1, 20);
    files.server(&first);
    let sink = Arc::new(Sink::default());
    let running = start(&files, &ca, Arc::clone(&sink), false, false)
        .await
        .unwrap();

    // A certificate written before its key: the pair does not match, so nothing changes.
    replace(&files.certificate, &second.certificate);
    replace(&files.key, &unrelated.key);
    running
        .wait_for(|status| status.tls_reload_failures == 1)
        .await;
    assert_eq!(
        Connection::open(&running, None).await.unwrap().server,
        sha(&first)
    );

    replace(&files.key, "-----BEGIN PRIVATE KEY-----\nAAAA");
    running
        .wait_for(|status| status.tls_reload_failures == 2)
        .await;

    files.server(&second);
    running.wait_for(|status| status.tls_reloads == 1).await;
    assert_eq!(
        Connection::open(&running, None).await.unwrap().server,
        sha(&second)
    );
    assert_eq!(running.status().tls_handshake_failures, 0);
    running.stop().await;
}

#[tokio::test]
async fn client_authority_rotation_overlaps_then_closes_sessions_of_the_removed_authority() {
    let directory = tempfile::tempdir().unwrap();
    let files = Files::new(directory.path());
    let old_ca = authority("old-ca", -30, 30);
    let new_ca = authority("new-ca", -30, 30);
    let server = old_ca.issue("localhost", false, -1, 20);
    let old_sender = old_ca.issue("firewall-01", true, -1, 20);
    let new_sender = new_ca.issue("firewall-01", true, -1, 20);
    files.server(&server);
    files.authorities(&[&old_ca]);
    let sink = Arc::new(Sink::default());
    let running = start(&files, &old_ca, Arc::clone(&sink), true, false)
        .await
        .unwrap();

    let mut old = Connection::open(&running, Some(&old_sender)).await.unwrap();
    old.send("old authority").await.unwrap();
    sink.wait_for(1).await;
    assert!(!Connection::try_deliver(&running, &new_sender, "too early").await);
    running
        .wait_for(|status| status.tls_handshake_failures == 1)
        .await;

    // Overlap: both authorities in one bundle; the open session continues.
    files.authorities(&[&old_ca, &new_ca]);
    running.wait_for(|status| status.tls_reloads == 1).await;
    assert!(Connection::try_deliver(&running, &new_sender, "new authority").await);
    old.send("old during overlap").await.unwrap();
    sink.wait_for(3).await;

    // Removal: the old authority's open session is closed before its next frame is used.
    files.authorities(&[&new_ca]);
    running.wait_for(|status| status.tls_reloads == 2).await;
    old.send("old after removal").await.unwrap();
    running
        .wait_for(|status| status.tls_sessions_closed == 1)
        .await;
    assert!(old.closed().await);
    assert!(!Connection::try_deliver(&running, &old_sender, "old reconnect").await);
    assert!(Connection::try_deliver(&running, &new_sender, "new after removal").await);
    sink.wait_for(4).await;
    let messages = sink.messages();
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("old after removal"))
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("old reconnect"))
    );
    running.stop().await;
}

#[tokio::test]
async fn revocation_list_refuses_listed_senders_and_closes_their_open_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let files = Files::new(directory.path());
    let ca = authority("syslog-ca", -30, 30);
    let server = ca.issue("localhost", false, -1, 20);
    let good = ca.issue("firewall-01", true, -1, 20);
    let stolen = ca.issue("firewall-02", true, -1, 20);
    files.server(&server);
    files.authorities(&[&ca]);
    replace(&files.revocations, &ca.revocation_list(&[&stolen], -1, 7));
    let sink = Arc::new(Sink::default());
    let running = start(&files, &ca, Arc::clone(&sink), true, true)
        .await
        .unwrap();
    assert!(
        running
            .status()
            .client_revocation_list_next_update
            .is_some()
    );

    assert!(!Connection::try_deliver(&running, &stolen, "revoked").await);
    let status = running.wait_for(|status| status.tls_revoked == 1).await;
    assert_eq!(status.tls_handshake_failures, 1);
    let mut open = Connection::open(&running, Some(&good)).await.unwrap();
    open.send("good sender").await.unwrap();
    sink.wait_for(1).await;

    // Emergency revocation of a sender that is already connected.
    replace(
        &files.revocations,
        &ca.revocation_list(&[&stolen, &good], -1, 7),
    );
    running.wait_for(|status| status.tls_reloads == 1).await;
    open.send("after revocation").await.unwrap();
    running
        .wait_for(|status| status.tls_sessions_closed == 1)
        .await;
    assert!(!Connection::try_deliver(&running, &good, "reconnect").await);
    assert_eq!(sink.messages(), ["good sender"]);
    running.stop().await;
}

#[tokio::test]
async fn revocation_list_fails_closed_when_revocation_status_cannot_be_established() {
    for kind in ["stale", "forged", "unknown-issuer"] {
        let directory = tempfile::tempdir().unwrap();
        let files = Files::new(directory.path());
        let ca = authority("syslog-ca", -30, 30);
        let other = authority("other-ca", -30, 30);
        let impostor = authority("syslog-ca", -30, 30);
        let server = ca.issue("localhost", false, -1, 20);
        let sender = if kind == "unknown-issuer" {
            &other
        } else {
            &ca
        }
        .issue("firewall-01", true, -1, 20);
        files.server(&server);
        files.authorities(&[&ca, &other]);
        replace(
            &files.revocations,
            &match kind {
                // Past nextUpdate: an attacker could be replaying an old list.
                "stale" => ca.revocation_list(&[], -9, -2),
                // Same issuer name, different key: the signature does not verify.
                "forged" => impostor.revocation_list(&[], -1, 7),
                // The sender's CA has no list at all.
                _ => ca.revocation_list(&[], -1, 7),
            },
        );
        let sink = Arc::new(Sink::default());
        let running = start(&files, &ca, Arc::clone(&sink), true, true)
            .await
            .unwrap();
        assert!(
            !Connection::try_deliver(&running, &sender, "unverifiable").await,
            "{kind}"
        );
        running.wait_for(|status| status.tls_revoked == 1).await;
        assert!(sink.messages().is_empty(), "{kind}");
        running.stop().await;
    }
}

#[tokio::test]
async fn client_certificates_outside_their_validity_or_purpose_are_refused() {
    for kind in [
        "expired",
        "not-yet-valid",
        "server-purpose-only",
        "expired-authority",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let files = Files::new(directory.path());
        let ca = authority("syslog-ca", -30, 30);
        let expired_ca = authority("expired-ca", -30, -1);
        let server = ca.issue("localhost", false, -1, 20);
        let sender = match kind {
            "expired" => ca.issue("firewall-01", true, -10, -1),
            "not-yet-valid" => ca.issue("firewall-01", true, 1, 10),
            "server-purpose-only" => ca.issue("firewall-01", false, -1, 10),
            _ => expired_ca.issue("firewall-01", true, -20, -2),
        };
        files.server(&server);
        files.authorities(&[&ca, &expired_ca]);
        let sink = Arc::new(Sink::default());
        let running = start(&files, &ca, Arc::clone(&sink), true, false)
            .await
            .unwrap();
        assert!(
            !Connection::try_deliver(&running, &sender, "refused").await,
            "{kind}"
        );
        running
            .wait_for(|status| status.tls_handshake_failures == 1)
            .await;
        assert!(sink.messages().is_empty(), "{kind}");
        running.stop().await;
    }
}

#[tokio::test]
async fn revocation_list_requires_an_authority_and_unreadable_lists_stop_start_without_leaking() {
    let directory = tempfile::tempdir().unwrap();
    let files = Files::new(directory.path());
    let ca = authority("syslog-ca", -30, 30);
    files.server(&ca.issue("localhost", false, -1, 20));
    files.authorities(&[&ca]);
    let error = config::parse(&listener(&files, false, true))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("clientCertificateRevocationListFile requires"),
        "{error}"
    );

    replace(
        &files.revocations,
        "-----BEGIN X509 CRL-----\nc2VjcmV0LWxpc3Q=\n-----END X509 CRL-----\n",
    );
    let error = start(&files, &ca, Arc::new(Sink::default()), true, true)
        .await
        .err()
        .unwrap();
    assert_eq!(
        error,
        "Syslog listener edge: TLS certificate or key could not be loaded."
    );
}
