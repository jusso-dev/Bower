//! The management channel through an authenticated CONNECT proxy to an HTTPS endpoint
//! whose certificate chains to a private CA (what a TLS-inspection proxy presents). C#
//! `ManagementProxyTests`. `tests/fixtures/tls` holds TEST-ONLY certificates and the leaf
//! key (`management.bower.test`, issued by "Bower Test Inspection CA"); the CA key was
//! discarded.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bower_collector::CollectorSettings;
use bower_collector::management_http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "bower";
const PASSWORD: &str = "s3cret-proxy-password";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// HTTPS server answering every request with `pong`.
async fn serve_tls() -> u16 {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certificate =
        CertificateDer::from_pem_slice(&std::fs::read(fixture("management.pem")).unwrap()).unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(fixture("management.key")).unwrap()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                if read_head(&mut tls).await.is_some() {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    port
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).ok()
}

/// A minimal CONNECT proxy requiring Basic credentials; every tunnel goes to the test
/// server, so the client never resolves the management host name itself.
struct ConnectProxy {
    port: u16,
    authorized: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
}

async fn connect_proxy(target: u16) -> ConnectProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (authorized, refused) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (counted_ok, counted_refused) = (Arc::clone(&authorized), Arc::clone(&refused));
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let (counted_ok, counted_refused) =
                (Arc::clone(&counted_ok), Arc::clone(&counted_refused));
            tokio::spawn(async move {
                let Some(head) = read_head(&mut client).await else {
                    return;
                };
                let expected = format!("Basic {}", encode_base64(format!("{USER}:{PASSWORD}")));
                let authenticated = head.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("proxy-authorization") && value.trim() == expected
                    })
                });
                if !head.starts_with("CONNECT ") || !authenticated {
                    counted_refused.fetch_add(1, Ordering::SeqCst);
                    let _ = client
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                              proxy-authenticate: Basic realm=\"bower\"\r\ncontent-length: 0\r\n\
                              connection: close\r\n\r\n",
                        )
                        .await;
                    return;
                }
                counted_ok.fetch_add(1, Ordering::SeqCst);
                let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", target)).await else {
                    return;
                };
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });
    ConnectProxy {
        port,
        authorized,
        refused,
    }
}

fn encode_base64(text: String) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(
                    ALPHABET[((value >> (18 - 6 * index)) & 63) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

fn settings(
    directory: &Path,
    host: &str,
    proxy_port: u16,
    ca: Option<&str>,
    password: &str,
) -> CollectorSettings {
    let password_file = directory.join(format!("password-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&password_file, format!("{password}\n")).unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        "policies",
        "edge-01",
    );
    settings.management_endpoint = Some(format!("https://{host}/").parse().unwrap());
    settings.management_scope = Some("api://bower/.default".into());
    settings.management_proxy = Some(format!("http://127.0.0.1:{proxy_port}").parse().unwrap());
    settings.management_proxy_username = Some(USER.into());
    settings.management_proxy_password_file = Some(password_file);
    settings.management_ca_bundle = ca.map(fixture);
    settings.validate().unwrap();
    settings
}

async fn get(settings: &CollectorSettings) -> Result<String, reqwest::Error> {
    let client = management_http::client(settings).unwrap();
    let url = settings
        .management_endpoint
        .clone()
        .unwrap()
        .join("ping")
        .unwrap();
    client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

/// C# `ExplicitProxy_WithCredentialsAndCaBundle_ReachesManagement`. The fixture leaf is
/// long-lived so the test never expires; Apple's platform verifier refuses TLS leaves valid
/// for more than 825 days, so this runs on Linux (CI) and Windows. Verified on macOS with a
/// 397-day leaf from the same CA.
#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "Apple's verifier refuses TLS leaves valid for over 825 days"
)]
async fn explicit_proxy_with_credentials_and_ca_bundle_reaches_management() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = connect_proxy(serve_tls().await).await;

    let body = get(&settings(
        directory.path(),
        "management.bower.test",
        proxy.port,
        Some("inspection-ca.pem"),
        PASSWORD,
    ))
    .await
    .unwrap();

    assert_eq!(body, "pong");
    assert_eq!(proxy.authorized.load(Ordering::SeqCst), 1);
}

/// C# `TlsVerificationIsNeverDisabled`.
#[tokio::test]
async fn tls_verification_is_never_disabled() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = connect_proxy(serve_tls().await).await;

    // The configured CA cannot excuse a host name mismatch.
    let mismatch = settings(
        directory.path(),
        "other.bower.test",
        proxy.port,
        Some("inspection-ca.pem"),
        PASSWORD,
    );
    assert!(get(&mismatch).await.is_err());
    // A CA that did not issue the certificate is not trusted.
    let unrelated = settings(
        directory.path(),
        "management.bower.test",
        proxy.port,
        Some("unrelated-ca.pem"),
        PASSWORD,
    );
    assert!(get(&unrelated).await.is_err());
    // Without the CA bundle the private chain is refused.
    let without = settings(
        directory.path(),
        "management.bower.test",
        proxy.port,
        None,
        PASSWORD,
    );
    assert!(get(&without).await.is_err());
    assert_eq!(proxy.authorized.load(Ordering::SeqCst), 3);
}

/// C# `WrongProxyPassword_FailsWithoutLeakingIt`.
#[tokio::test]
async fn wrong_proxy_password_fails_without_leaking_it() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = connect_proxy(serve_tls().await).await;

    let failure = get(&settings(
        directory.path(),
        "management.bower.test",
        proxy.port,
        Some("inspection-ca.pem"),
        "wrong-password",
    ))
    .await
    .unwrap_err();

    assert_eq!(proxy.authorized.load(Ordering::SeqCst), 0);
    assert!(proxy.refused.load(Ordering::SeqCst) >= 1);
    assert!(!format!("{failure:?}").contains("wrong-password"));
    assert!(!failure.to_string().contains("wrong-password"));
}
