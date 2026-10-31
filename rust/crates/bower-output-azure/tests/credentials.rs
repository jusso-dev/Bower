//! Credential sources against local mocks: Azure Arc challenge, Service Fabric
//! (TLS with thumbprint pinning), Cloud Shell, Machine Learning, the managed
//! identity retry policy, certificate client assertions (signature verified with
//! the certificate's public key) and username/password.
//!
//! `tests/fixtures/credentials` holds TEST-ONLY keys generated for these tests.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bower_output_azure::credential::{
    ClientCertificate, ClientCertificateCredential, ManagedIdentityRetryOptions,
    UsernamePasswordCredential,
};
use bower_output_azure::{
    ManagedIdentityCredential, ManagedIdentitySource, TokenError, TokenProvider,
};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};
use x509_cert::der::{Decode as _, Encode as _};

const SCOPE: &str = "https://monitor.azure.com//.default";
const RESOURCE_QUERY: &str = "resource=https%3A%2F%2Fmonitor.azure.com%2F";
const TOKEN_BODY: &str = r#"{"access_token":"mi-token","expires_on":"1893456000"}"#;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/credentials")
        .join(name)
}

fn fast_retry(max_retries: u32) -> ManagedIdentityRetryOptions {
    ManagedIdentityRetryOptions {
        max_retries,
        delay: Duration::from_millis(1),
        gone_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    }
}

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    query: String,
    headers: HeaderMap,
    body: String,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// Serves `respond(n, request)` on every path and records requests.
async fn serve(
    respond: impl Fn(usize, &Seen) -> Response + Clone + Send + Sync + 'static,
) -> (SocketAddr, Log) {
    let log: Log = Arc::default();
    let record = log.clone();
    let app = Router::new().route(
        "/{*path}",
        any(
            move |method: axum::http::Method, uri: Uri, headers: HeaderMap, body: String| {
                let record = record.clone();
                let respond = respond.clone();
                async move {
                    let seen = Seen {
                        method: method.to_string(),
                        query: uri.query().unwrap_or("").to_owned(),
                        headers,
                        body,
                    };
                    let n = {
                        let mut log = record.lock().unwrap();
                        log.push(seen.clone());
                        log.len()
                    };
                    respond(n, &seen)
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, log)
}

fn ok_token() -> Response {
    TOKEN_BODY.into_response()
}

fn status(code: u16) -> Response {
    (StatusCode::from_u16(code).unwrap(), "{}").into_response()
}

fn credential(client_id: Option<&str>, source: ManagedIdentitySource) -> ManagedIdentityCredential {
    ManagedIdentityCredential::new(reqwest::Client::new(), client_id.map(str::to_owned), source)
        .with_retry_options(fast_retry(0))
}

// ---------------------------------------------------------------- Azure Arc

#[tokio::test]
async fn azure_arc_answers_the_challenge_with_the_key_file() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("abc.key");
    std::fs::write(&key, "arc-secret").unwrap();
    let challenge = format!("Basic realm={}", key.display());
    let (address, log) = serve(move |_, seen| match seen.headers.get("authorization") {
        None => (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", challenge.clone())],
            "",
        )
            .into_response(),
        Some(value) if value == "Basic arc-secret" => ok_token(),
        Some(_) => status(403),
    })
    .await;

    let token = credential(
        None,
        ManagedIdentitySource::AzureArc {
            endpoint: format!("http://{address}/metadata/identity/oauth2/token"),
            token_directory: Some(directory.path().to_path_buf()),
        },
    )
    .get_token(SCOPE)
    .await
    .unwrap();

    assert_eq!(token.token, "mi-token");
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 2);
    for seen in log.iter() {
        assert_eq!(seen.method, "GET");
        assert_eq!(
            seen.query,
            format!("api-version=2019-11-01&{RESOURCE_QUERY}")
        );
        assert_eq!(seen.headers["metadata"], "true");
    }
}

#[tokio::test]
async fn azure_arc_refuses_challenges_outside_the_token_directory() {
    let directory = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let outside = elsewhere.path().join("abc.key");
    std::fs::write(&outside, "stolen").unwrap();
    let traversal = format!(
        "{}/../{}/abc.key",
        directory.path().display(),
        elsewhere.path().file_name().unwrap().to_string_lossy()
    );
    for path in [
        outside.display().to_string(),
        traversal,
        "/etc/passwd".to_owned(),
    ] {
        let challenge = format!("Basic realm={path}");
        let (address, log) = serve(move |_, seen| {
            if seen.headers.contains_key("authorization") {
                ok_token()
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    [("www-authenticate", challenge.clone())],
                    "",
                )
                    .into_response()
            }
        })
        .await;

        let error = credential(
            None,
            ManagedIdentitySource::AzureArc {
                endpoint: format!("http://{address}/token"),
                token_directory: Some(directory.path().to_path_buf()),
            },
        )
        .get_token(SCOPE)
        .await
        .unwrap_err();

        assert!(matches!(error, TokenError::Failed(_)), "{path}: {error}");
        assert!(!error.to_string().contains("stolen"));
        // The key was never sent anywhere.
        assert_eq!(log.lock().unwrap().len(), 1, "{path}");
    }
}

#[tokio::test]
async fn azure_arc_refuses_oversize_and_linked_key_files_and_missing_challenges() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("big.key"), vec![b'a'; 4097]).unwrap();
    let mut names = vec!["big.key"];
    #[cfg(unix)]
    {
        let target = directory.path().join("target.txt");
        std::fs::write(&target, "linked").unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join("link.key")).unwrap();
        names.push("link.key");
    }
    for name in names {
        let challenge = format!("Basic realm={}", directory.path().join(name).display());
        let (address, log) = serve(move |_, _| {
            (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", challenge.clone())],
                "",
            )
                .into_response()
        })
        .await;
        let error = credential(
            None,
            ManagedIdentitySource::AzureArc {
                endpoint: format!("http://{address}/token"),
                token_directory: Some(directory.path().to_path_buf()),
            },
        )
        .get_token(SCOPE)
        .await
        .unwrap_err();
        assert!(matches!(error, TokenError::Failed(_)), "{name}");
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    let (address, _) = serve(|_, _| status(401)).await;
    let error = credential(
        None,
        ManagedIdentitySource::AzureArc {
            endpoint: format!("http://{address}/token"),
            token_directory: Some(directory.path().to_path_buf()),
        },
    )
    .get_token(SCOPE)
    .await
    .unwrap_err();
    assert!(error.to_string().contains("WWW-Authenticate"));

    // User-assigned identities are rejected before any request.
    let (address, log) = serve(|_, _| ok_token()).await;
    let error = credential(
        Some("user-assigned"),
        ManagedIdentitySource::AzureArc {
            endpoint: format!("http://{address}/token"),
            token_directory: Some(directory.path().to_path_buf()),
        },
    )
    .get_token(SCOPE)
    .await
    .unwrap_err();
    assert!(matches!(error, TokenError::Failed(_)));
    assert!(log.lock().unwrap().is_empty());
}

// ----------------------------------------------------------- Service Fabric

fn sha1_hex(der: &[u8]) -> String {
    use sha1::Digest as _;
    sha1::Sha1::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn fixture_certificate_der() -> Vec<u8> {
    use rustls::pki_types::pem::PemObject as _;
    rustls::pki_types::CertificateDer::from_pem_slice(
        &std::fs::read(fixture("rsa-cert.pem")).unwrap(),
    )
    .unwrap()
    .to_vec()
}

/// HTTPS server presenting the self-signed fixture certificate.
async fn serve_tls(log: Arc<Mutex<Vec<Seen>>>) -> SocketAddr {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certificate =
        CertificateDer::from_pem_slice(&std::fs::read(fixture("rsa-cert.pem")).unwrap()).unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(fixture("rsa-key.pem")).unwrap()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let app = Router::new().route(
        "/token",
        get(move |uri: Uri, headers: HeaderMap| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(Seen {
                    method: "GET".to_owned(),
                    query: uri.query().unwrap_or("").to_owned(),
                    headers,
                    body: String::new(),
                });
                r#"{"access_token":"sf-token","expires_on":1893456000}"#
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(tls),
                            hyper_util::service::TowerToHyperService::new(app),
                        )
                        .await;
                }
            });
        }
    });
    address
}

#[tokio::test]
async fn service_fabric_pins_the_endpoint_certificate_thumbprint() {
    let log: Log = Arc::default();
    let address = serve_tls(log.clone()).await;
    let thumbprint = sha1_hex(&fixture_certificate_der());
    let source = |thumbprint: String| ManagedIdentitySource::ServiceFabric {
        endpoint: format!("https://127.0.0.1:{}/token", address.port()),
        header: "sf-secret".to_owned(),
        thumbprint,
    };

    // Thumbprints compare case-insensitively.
    let token = credential(None, source(thumbprint.to_lowercase()))
        .get_token(SCOPE)
        .await
        .unwrap();
    assert_eq!(token.token, "sf-token");
    {
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].query,
            format!("api-version=2020-05-01&{RESOURCE_QUERY}")
        );
        assert_eq!(log[0].headers["secret"], "sf-secret");
    }

    // A self-signed certificate with another thumbprint never sees the request.
    let wrong = "0".repeat(40);
    let error = credential(None, source(wrong))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    // The TLS handshake fails before any answer: the token service is unreachable.
    assert!(matches!(error, TokenError::Transport(_)), "{error}");
    assert_eq!(log.lock().unwrap().len(), 1);

    // Service Fabric identities are configured in the cluster, not at runtime.
    let error = credential(Some("user-assigned"), source(thumbprint))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Failed(_)));
    assert_eq!(log.lock().unwrap().len(), 1);
}

// ------------------------------------------- Cloud Shell, Machine Learning

#[tokio::test]
async fn cloud_shell_posts_the_resource_form() {
    let (address, log) = serve(|_, _| ok_token()).await;
    let source = ManagedIdentitySource::CloudShell {
        endpoint: format!("http://{address}/oauth2/token"),
    };
    let token = credential(None, source.clone())
        .get_token(SCOPE)
        .await
        .unwrap();
    assert_eq!(token.token, "mi-token");
    {
        let log = log.lock().unwrap();
        assert_eq!(log[0].method, "POST");
        assert_eq!(log[0].query, "");
        assert_eq!(log[0].body, RESOURCE_QUERY);
        assert_eq!(log[0].headers["metadata"], "true");
        assert_eq!(
            log[0].headers["content-type"],
            "application/x-www-form-urlencoded"
        );
    }
    let error = credential(Some("user"), source)
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Failed(_)));
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn machine_learning_uses_the_2017_protocol() {
    let (address, log) = serve(|_, _| ok_token()).await;
    let source = |default_client_id: Option<&str>| ManagedIdentitySource::MachineLearning {
        endpoint: format!("http://{address}/msi/token"),
        secret: "ml-secret".to_owned(),
        default_client_id: default_client_id.map(str::to_owned),
    };
    credential(None, source(Some("default-id")))
        .get_token(SCOPE)
        .await
        .unwrap();
    credential(Some("user-id"), source(Some("default-id")))
        .get_token(SCOPE)
        .await
        .unwrap();
    let error = credential(None, source(None))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Failed(_)));

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(
        log[0].query,
        format!("api-version=2017-09-01&{RESOURCE_QUERY}&clientid=default-id")
    );
    assert_eq!(
        log[1].query,
        format!("api-version=2017-09-01&{RESOURCE_QUERY}&clientid=user-id")
    );
    assert_eq!(log[0].headers["secret"], "ml-secret");
    assert_eq!(log[0].headers["metadata"], "true");
}

// --------------------------------------------------------------- IMDS retry

fn imds(address: SocketAddr, retry: ManagedIdentityRetryOptions) -> ManagedIdentityCredential {
    ManagedIdentityCredential::new(
        reqwest::Client::new(),
        None,
        ManagedIdentitySource::Imds {
            endpoint: format!("http://{address}/metadata/identity/oauth2/token"),
        },
    )
    .with_retry_options(retry)
}

#[tokio::test]
async fn imds_retries_gone_throttled_and_server_errors() {
    let (address, log) = serve(|n, _| match n {
        1 => status(410),
        2 => status(404),
        3 => status(429),
        4 => status(503),
        _ => ok_token(),
    })
    .await;
    let token = imds(address, fast_retry(5)).get_token(SCOPE).await.unwrap();
    assert_eq!(token.token, "mi-token");
    assert_eq!(log.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn imds_does_not_retry_bad_gateway_or_client_errors_and_stops_at_max_retries() {
    for (code, attempts) in [(502, 1), (400, 1), (500, 3)] {
        let (address, log) = serve(move |_, _| status(code)).await;
        let error = imds(address, fast_retry(2))
            .get_token(SCOPE)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(&format!("HTTP {code}")),
            "{error}"
        );
        assert_eq!(log.lock().unwrap().len(), attempts, "{code}");
    }
}

#[tokio::test]
async fn imds_honours_retry_after_and_retries_transport_failures() {
    let (address, log) = serve(|n, _| {
        if n == 1 {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after-ms", "150")],
                "",
            )
                .into_response()
        } else {
            ok_token()
        }
    })
    .await;
    let started = Instant::now();
    imds(address, fast_retry(5)).get_token(SCOPE).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert_eq!(log.lock().unwrap().len(), 2);

    // Nothing listens: every attempt fails at the transport and is retried.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let started = Instant::now();
    let error = imds(
        closed,
        ManagedIdentityRetryOptions {
            max_retries: 2,
            delay: Duration::from_millis(40),
            gone_delay: Duration::from_millis(40),
            max_delay: Duration::from_secs(1),
        },
    )
    .get_token(SCOPE)
    .await
    .unwrap_err();
    // Nothing answered: a network outage, not a credential failure.
    assert!(matches!(error, TokenError::Transport(_)), "{error}");
    // 40 ms + 80 ms of backoff, less jitter.
    assert!(started.elapsed() >= Duration::from_millis(96));
}

#[test]
fn default_retry_policy_matches_azure_identity() {
    let options = ManagedIdentityRetryOptions::default();
    assert_eq!(options.max_retries, 5);
    assert_eq!(options.delay, Duration::from_millis(800));
    assert_eq!(options.gone_delay, Duration::from_secs(3));
    assert_eq!(options.max_delay, Duration::from_secs(60));
}

// ------------------------------------------------------ Client certificates

fn token_endpoint_mock() -> impl Fn(usize, &Seen) -> Response + Clone + Send + Sync + 'static {
    |_, _| {
        r#"{"token_type":"Bearer","expires_in":3599,"access_token":"cert-token"}"#.into_response()
    }
}

fn form_value(body: &str, name: &str) -> String {
    body.split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .unwrap()
        .replace('+', " ")
        .replace("%2F", "/")
        .replace("%3A", ":")
}

fn decode_json(part: &str) -> serde_json::Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

#[tokio::test]
async fn certificate_assertion_is_ps256_signed_with_x5t_s256() {
    let (address, log) = serve(token_endpoint_mock()).await;
    let certificate = Arc::new(ClientCertificate::load(&fixture("client.pem"), None).unwrap());
    let certificate_der = fixture_certificate_der();
    let authority = format!("http://{address}/");
    let audience = format!("http://{address}/tenant-1/oauth2/v2.0/token");

    for send_chain in [false, true] {
        let token = ClientCertificateCredential {
            client: reqwest::Client::new(),
            tenant_id: "tenant-1".to_owned(),
            client_id: "client-1".to_owned(),
            certificate: certificate.clone(),
            authority_host: authority.clone(),
            send_certificate_chain: send_chain,
        }
        .get_token(SCOPE)
        .await
        .unwrap();
        assert_eq!(token.token, "cert-token");
    }

    let log = log.lock().unwrap();
    for (index, seen) in log.iter().enumerate() {
        assert_eq!(seen.method, "POST");
        assert_eq!(form_value(&seen.body, "client_id"), "client-1");
        assert_eq!(form_value(&seen.body, "scope"), SCOPE);
        assert_eq!(form_value(&seen.body, "grant_type"), "client_credentials");
        assert_eq!(
            form_value(&seen.body, "client_assertion_type"),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        let assertion = form_value(&seen.body, "client_assertion");
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = decode_json(parts[0]);
        assert_eq!(header["alg"], "PS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(
            header["x5t#S256"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(&certificate_der))
        );
        if index == 1 {
            assert_eq!(header["x5c"], STANDARD.encode(&certificate_der));
        } else {
            assert!(header.get("x5c").is_none());
        }

        let claims = decode_json(parts[1]);
        assert_eq!(claims["aud"], audience.as_str());
        assert_eq!(claims["iss"], "client-1");
        assert_eq!(claims["sub"], "client-1");
        // MSAL writes nbf and exp as strings, ten minutes apart.
        let nbf: i64 = claims["nbf"].as_str().unwrap().parse().unwrap();
        let exp: i64 = claims["exp"].as_str().unwrap().parse().unwrap();
        assert_eq!(exp - nbf, 600);
        assert!((nbf - chrono::Utc::now().timestamp()).abs() < 60);
        uuid::Uuid::parse_str(claims["jti"].as_str().unwrap()).unwrap();

        // Verify RSASSA-PSS (SHA-256, 32-byte salt) with the certificate's key.
        let certificate = x509_cert::Certificate::from_der(&certificate_der).unwrap();
        let spki = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        let public = rsa::RsaPublicKey::from_public_key_der(&spki).unwrap();
        let verifier = rsa::pss::VerifyingKey::<Sha256>::new(public);
        let signature =
            rsa::pss::Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice())
                .unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        verifier
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
        // Tampering breaks it.
        assert!(verifier.verify(b"tampered", &signature).is_err());
    }
}

fn pem_der(path: &Path, label: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap();
    let begin = format!("-----BEGIN {label}-----");
    let start = text.find(&begin).unwrap() + begin.len();
    let end = text.find(&format!("-----END {label}-----")).unwrap();
    let encoded: String = text[start..end].split_whitespace().collect();
    STANDARD.decode(encoded).unwrap()
}

#[test]
fn certificates_load_from_pem_pkcs1_and_legacy_and_aes_pfx() {
    let expected = ClientCertificate::load(&fixture("client.pem"), None)
        .unwrap()
        .thumbprint_sha256();
    let pkcs1 = ClientCertificate::load(&fixture("client-pkcs1.pem"), None).unwrap();
    assert_eq!(pkcs1.thumbprint_sha256(), expected);
    // OpenSSL default: pbeWithSHA1And3-KeyTripleDES-CBC key, RC2-40 certificates.
    let legacy =
        ClientCertificate::load(&fixture("client-legacy.pfx"), Some("bower-test")).unwrap();
    assert_eq!(legacy.thumbprint_sha256(), expected);

    // PBES2 / AES-256 with an HMAC-SHA256 MAC (current Windows and OpenSSL 3).
    let chain = p12_keystore::PrivateKeyChain::new(
        b"bower".to_vec(),
        p12_keystore::PrivateKey::from_der(&pem_der(&fixture("rsa-key.pem"), "PRIVATE KEY"))
            .unwrap(),
        [p12_keystore::Certificate::from_der(&fixture_certificate_der()).unwrap()],
    );
    let mut store = p12_keystore::KeyStore::new();
    store.add_entry("bower", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
    let pfx = store
        .writer("aes-password")
        .encryption_algorithm(p12_keystore::EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .mac_algorithm(p12_keystore::MacAlgorithm::HmacSha256)
        .write()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("Client.PFX");
    std::fs::write(&path, &pfx).unwrap();
    let modern = ClientCertificate::load(&path, Some("aes-password")).unwrap();
    assert_eq!(modern.thumbprint_sha256(), expected);
    // Wrong password: the MAC check fails.
    assert!(matches!(
        ClientCertificate::load(&path, Some("wrong")),
        Err(TokenError::Unavailable(_))
    ));
    assert!(!format!("{modern:?}").contains("PRIVATE"));
}

#[test]
fn certificate_loading_fails_closed() {
    let unavailable = |result: Result<ClientCertificate, TokenError>| {
        matches!(result, Err(TokenError::Unavailable(_)))
    };
    // PEM files cannot carry a password.
    assert!(unavailable(ClientCertificate::load(
        &fixture("client.pem"),
        Some("x")
    )));
    assert!(unavailable(ClientCertificate::load(
        &fixture("client-legacy.pfx"),
        Some("wrong")
    )));
    assert!(unavailable(ClientCertificate::load(
        Path::new("cert:/CurrentUser/My/0123ABCD"),
        None
    )));
    assert!(unavailable(ClientCertificate::load(
        &fixture("rsa-cert.pem"),
        None
    )));
    assert!(unavailable(ClientCertificate::load(
        &fixture("missing.pem"),
        None
    )));

    let directory = tempfile::tempdir().unwrap();
    let crt = directory.path().join("client.crt");
    std::fs::copy(fixture("client.pem"), &crt).unwrap();
    assert!(unavailable(ClientCertificate::load(&crt, None)));

    let mismatched = format!(
        "{}{}",
        std::fs::read_to_string(fixture("rsa-cert.pem")).unwrap(),
        std::fs::read_to_string(fixture("other-rsa-key.pem")).unwrap()
    );
    let error = ClientCertificate::from_pem(&mismatched).unwrap_err();
    assert!(error.to_string().contains("does not match"));

    let big = directory.path().join("big.pem");
    std::fs::write(&big, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    assert!(unavailable(ClientCertificate::load(&big, None)));

    // Microsoft Entra client assertions need RSA keys.
    assert!(matches!(
        ClientCertificate::load(&fixture("ec-client.pem"), None),
        Err(TokenError::Failed(_))
    ));
}

#[tokio::test]
async fn certificate_and_password_credentials_refuse_plain_http_authorities() {
    let certificate = Arc::new(ClientCertificate::load(&fixture("client.pem"), None).unwrap());
    let error = ClientCertificateCredential {
        client: reqwest::Client::new(),
        tenant_id: "t".to_owned(),
        client_id: "c".to_owned(),
        certificate,
        authority_host: "http://login.example.test/".to_owned(),
        send_certificate_chain: false,
    }
    .get_token(SCOPE)
    .await
    .unwrap_err();
    assert_eq!(
        error,
        TokenError::Unavailable("the authority host must use HTTPS".to_owned())
    );
    let error = password_credential("http://login.example.test/".to_owned())
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenError::Unavailable("the authority host must use HTTPS".to_owned())
    );
}

// --------------------------------------------------------- Username/password

fn password_credential(authority_host: String) -> UsernamePasswordCredential {
    UsernamePasswordCredential {
        client: reqwest::Client::new(),
        tenant_id: "tenant-1".to_owned(),
        client_id: "client-1".to_owned(),
        username: "user@contoso.test".to_owned(),
        password: "p@ss word".to_owned(),
        authority_host,
    }
}

#[tokio::test]
async fn username_password_discovers_the_realm_then_uses_the_password_grant() {
    let calls = Arc::new(AtomicUsize::new(0));
    let paths: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = paths.clone();
    let counter = calls.clone();
    let bodies: Arc<Mutex<Vec<String>>> = Arc::default();
    let body_log = bodies.clone();
    let app = Router::new()
        .route(
            "/common/userrealm/{user}",
            get(move |uri: Uri| {
                let record = record.clone();
                async move {
                    record.lock().unwrap().push(uri.to_string());
                    r#"{"ver":"1.0","account_type":"Managed","domain_name":"contoso.test"}"#
                }
            }),
        )
        .route(
            "/{tenant}/oauth2/v2.0/token",
            post(move |body: String| {
                let counter = counter.clone();
                let body_log = body_log.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    body_log.lock().unwrap().push(body);
                    r#"{"token_type":"Bearer","expires_in":3599,"access_token":"user-token","refresh_token":"never-kept"}"#
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let token = password_credential(format!("http://{address}"))
        .get_token(SCOPE)
        .await
        .unwrap();

    assert_eq!(token.token, "user-token");
    assert_eq!(
        paths.lock().unwrap()[0],
        "/common/userrealm/user%40contoso.test?api-version=1.0"
    );
    assert_eq!(
        bodies.lock().unwrap()[0],
        "client_id=client-1&grant_type=password&username=user%40contoso.test&password=p%40ss+word&scope=https%3A%2F%2Fmonitor.azure.com%2F%2F.default+offline_access+openid+profile&client_info=1"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn username_password_refuses_federated_accounts_and_hides_errors() {
    let (address, log) = serve(|_, seen| {
        if seen.method == "GET" {
            r#"{"account_type":"Federated","federation_protocol":"WSTrust"}"#.into_response()
        } else {
            ok_token()
        }
    })
    .await;
    let error = password_credential(format!("http://{address}"))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Failed(_)));
    assert!(error.to_string().contains("WS-Trust"));
    assert_eq!(log.lock().unwrap().len(), 1);

    // MFA-required (and every other) Entra error: status and code, never the
    // password or the description.
    let (address, _) = serve(|_, seen| {
        if seen.method == "GET" {
            r#"{"account_type":"Managed"}"#.into_response()
        } else {
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant","error_description":"AADSTS50076: MFA p@ss word"}"#,
            )
                .into_response()
        }
    })
    .await;
    let error = password_credential(format!("http://{address}"))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("HTTP 400") && text.contains("invalid_grant"),
        "{text}"
    );
    assert!(!text.contains("p@ss") && !text.contains("AADSTS"));
    assert!(!format!("{:?}", password_credential(String::new())).contains("p@ss"));
}

/// C# `Deliver_ClassifiesTokenFailuresByTheirCause`: no answer or a temporary answer from
/// the token service is `Transport` (a network outage); a rejection is `Failed`, even after
/// retried temporary failures.
#[tokio::test]
async fn token_failures_are_classified_by_their_cause() {
    let certificate = Arc::new(ClientCertificate::load(&fixture("client.pem"), None).unwrap());
    let credential = |authority: String| ClientCertificateCredential {
        client: reqwest::Client::new(),
        tenant_id: "tenant-1".to_owned(),
        client_id: "client-1".to_owned(),
        certificate: certificate.clone(),
        authority_host: authority,
        send_certificate_chain: false,
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let error = credential(format!("http://{closed}/"))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Transport(_)), "{error}");

    for (status, expect_transport) in [
        (StatusCode::SERVICE_UNAVAILABLE, true),
        (StatusCode::TOO_MANY_REQUESTS, true),
        (StatusCode::REQUEST_TIMEOUT, true),
        (StatusCode::UNAUTHORIZED, false),
        (StatusCode::BAD_REQUEST, false),
    ] {
        let (address, _) = serve(move |_, _| {
            (
                status,
                r#"{"error":"invalid_client","error_description":"AADSTS7000215 secret"}"#,
            )
                .into_response()
        })
        .await;
        let error = credential(format!("http://{address}/"))
            .get_token(SCOPE)
            .await
            .unwrap_err();
        assert_eq!(error.is_transport(), expect_transport, "{status}: {error}");
        assert!(!error.to_string().contains("AADSTS"), "{error}");
    }

    // Managed identity: a retried server error, then a rejection, is a credential failure.
    let (address, _) = serve(|n, _| {
        if n == 1 {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        } else {
            (StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#).into_response()
        }
    })
    .await;
    let error = imds(address, fast_retry(3))
        .get_token(SCOPE)
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Failed(_)), "{error}");
}
