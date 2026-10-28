//! Downstream side of the relay hop (C# `RelayHttp`). The batch client and the management
//! tunnel both use mutual TLS to `BOWER_RELAY_URL`: the client certificate from
//! `BOWER_RELAY_CLIENT_CERTIFICATE_FILE`, and the relay's server certificate verified by
//! the platform verifier plus `BOWER_RELAY_CA_BUNDLE`, host name included. Verification
//! is never disabled. Environment proxies never apply to the relay hop.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::certificates;
use super::protocol;
use crate::error::HostError;
use crate::settings::CollectorSettings;

const MAXIMUM_RESPONSE_HEAD_BYTES: usize = 8 * 1024;
const TUNNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The relay commits every event (fsync) before it answers.
pub const BATCH_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Mutual TLS to the relay, read once at start-up so a bad file stops it.
#[derive(Clone)]
pub struct RelayTls {
    relay: Url,
    config: Arc<rustls::ClientConfig>,
}

impl RelayTls {
    pub fn from_settings(settings: &CollectorSettings) -> Result<Self, HostError> {
        let relay = settings.relay_url.clone().ok_or_else(|| {
            HostError::new("InvalidOperationException", "BOWER_RELAY_URL is required.")
        })?;
        let (Some(certificate_file), Some(key_file)) = (
            &settings.relay_client_certificate_file,
            &settings.relay_client_key_file,
        ) else {
            return Err(HostError::new(
                "InvalidOperationException",
                "BOWER_RELAY_CLIENT_CERTIFICATE_FILE and BOWER_RELAY_CLIENT_KEY_FILE must name a readable PEM certificate and its private key.",
            ));
        };
        let (certificate, key) = certificates::load(
            certificate_file,
            key_file,
            "BOWER_RELAY_CLIENT_CERTIFICATE_FILE and BOWER_RELAY_CLIENT_KEY_FILE",
        )?;
        let roots = settings
            .relay_ca_bundle
            .as_deref()
            .map(|path| {
                certificates::read_bundle(
                    path,
                    "BOWER_RELAY_CA_BUNDLE must name a readable PEM file of CA certificates.",
                )
            })
            .transpose()?;
        let failed = || {
            HostError::new(
                "InvalidOperationException",
                "The relay TLS client could not be created.",
            )
        };
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = match roots {
            None => rustls_platform_verifier::Verifier::new(Arc::clone(&provider)),
            Some(roots) => rustls_platform_verifier::Verifier::new_with_extra_roots(
                roots,
                Arc::clone(&provider),
            ),
        }
        .map_err(|_| failed())?;
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| failed())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            // The relay pins certificates and sends no acceptable-issuer list: always offer ours.
            .with_client_auth_cert(vec![certificate], key)
            .map_err(|_| failed())?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            relay,
            config: Arc::new(config),
        })
    }

    pub fn relay_url(&self) -> &Url {
        &self.relay
    }

    /// The batch client ([`super::output::RelayOutput`]): mutual TLS, no proxies, 60 s.
    pub fn batch_client(&self) -> Result<reqwest::Client, HostError> {
        reqwest::Client::builder()
            .tls_backend_preconfigured((*self.config).clone())
            .no_proxy()
            .http1_only()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(BATCH_TIMEOUT)
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| {
                HostError::new(
                    "InvalidOperationException",
                    "The relay HTTP client could not be created.",
                )
            })
    }

    /// Opens one management tunnel: mutual TLS to the relay, then an HTTP/1.1 upgrade. The
    /// response head is read byte by byte so no tunnelled byte is consumed. TLS to
    /// management then runs inside the returned stream, end to end.
    pub async fn open_tunnel(&self) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        tokio::time::timeout(TUNNEL_HANDSHAKE_TIMEOUT, self.open_tunnel_inner())
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "relay tunnel timed out")
            })?
    }

    async fn open_tunnel_inner(
        &self,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let host = self.relay.host_str().unwrap_or_default();
        let port = self.relay.port_or_known_default().unwrap_or(443);
        let bare = host.trim_matches(['[', ']']);
        let tcp = TcpStream::connect((bare, port)).await?;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::try_from(bare.to_string())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "relay host"))?;
        let mut tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.config))
            .connect(name, tcp)
            .await?;
        let authority = match self.relay.port() {
            None => host.to_string(),
            Some(port) => format!("{host}:{port}"),
        };
        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
            protocol::TUNNEL_PATH,
            protocol::TUNNEL_UPGRADE
        );
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;
        let head = read_head(&mut tls).await?;
        if !head.starts_with(b"HTTP/1.1 101") {
            return Err(std::io::Error::other(
                "the relay refused the management tunnel",
            ));
        }
        Ok(tls)
    }
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while head.len() < MAXIMUM_RESPONSE_HEAD_BYTES {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(std::io::Error::other(
        "the relay sent no valid tunnel response",
    ))
}

/// The management channel's relay tunnel (`BOWER_MANAGEMENT_VIA_RELAY=true`).
///
/// reqwest cannot take a caller-supplied stream, so it connects to a Unix domain socket
/// (`unix_socket`, TLS still layered for `https`) served by this forwarder: each
/// connection opens one relay tunnel and splices bytes. TLS to management is established
/// by reqwest inside the tunnel, so the relay only ever sees ciphertext. The socket sits in
/// an owner-only directory next to the queue, so other local users cannot reach it.
#[cfg(unix)]
pub mod tunnel {
    use std::path::{Path, PathBuf};

    use tokio::net::UnixListener;
    use tracing::warn;

    use super::RelayTls;
    use crate::error::HostError;
    use crate::settings::{CollectorSettings, full_path};

    /// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux; keep a margin.
    const MAXIMUM_SOCKET_PATH_BYTES: usize = 100;

    /// `<queue directory>/management-relay/t.sock`.
    pub fn socket_path(settings: &CollectorSettings) -> PathBuf {
        full_path(&settings.queue_path)
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("management-relay")
            .join("t.sock")
    }

    /// Serves the socket until dropped; the socket file is removed then.
    pub struct TunnelForwarder {
        path: PathBuf,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TunnelForwarder {
        fn drop(&mut self) {
            self.task.abort();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl TunnelForwarder {
        /// Binds the socket now (a start-up error if that fails) and serves it on the
        /// current Tokio runtime.
        pub fn start(settings: &CollectorSettings, tls: RelayTls) -> Result<Self, HostError> {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let path = socket_path(settings);
            if path.as_os_str().len() > MAXIMUM_SOCKET_PATH_BYTES {
                return Err(HostError::new(
                    "InvalidOperationException",
                    "BOWER_QUEUE_PATH is too deep for the management relay socket; use a shorter queue directory.",
                ));
            }
            let directory = path.parent().unwrap_or(Path::new("."));
            let failed = |_| {
                HostError::new(
                    "InvalidOperationException",
                    "The management relay socket could not be created next to the queue.",
                )
            };
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(failed)?;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(failed)?;
            let _ = std::fs::remove_file(&path);
            let listener = std::os::unix::net::UnixListener::bind(&path).map_err(failed)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(failed)?;
            listener.set_nonblocking(true).map_err(failed)?;
            let handle = tokio::runtime::Handle::try_current().map_err(|_| {
                HostError::new(
                    "InvalidOperationException",
                    "The management relay tunnel needs a running Tokio runtime.",
                )
            })?;
            let task = handle.spawn(async move {
                let Ok(listener) = UnixListener::from_std(listener) else {
                    return;
                };
                loop {
                    let Ok((mut local, _)) = listener.accept().await else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    };
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        match tls.open_tunnel().await {
                            Ok(mut tunnel) => {
                                let _ =
                                    tokio::io::copy_bidirectional(&mut local, &mut tunnel).await;
                            }
                            // The management request fails and is retried by its job.
                            Err(error) => {
                                warn!(error_kind = %error.kind(), "Relay management tunnel failed.")
                            }
                        }
                    });
                }
            });
            Ok(Self { path, task })
        }
    }
}
