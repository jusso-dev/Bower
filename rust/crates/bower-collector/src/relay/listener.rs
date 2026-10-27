//! The relay listener (C# `RelayListener`, `BOWER_RELAY_LISTEN_URL`): a second listener in
//! the collector process, HTTP/1.1 over TLS with a required client certificate pinned in
//! `BOWER_RELAY_DOWNSTREAMS_FILE`. Two endpoints:
//!
//! - `POST /v1/relay/batches`: downstream events into the relay queue ([`RelayIntake`]).
//! - `GET /v1/relay/management-tunnel` with `Upgrade: bower-management-tunnel/1`: a byte
//!   tunnel to this relay's own management endpoint. TLS to management runs inside it, end
//!   to end, so the relay neither reads nor alters management traffic and cannot be
//!   pointed anywhere else.
//!
//! Delivery from the relay queue stays in the queue delivery worker.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bower_contracts::time::Clock;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use reqwest::Url;
use rustls::DigitallySignedStruct;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::downstreams::RelayDownstreams;
use super::intake::{RelayIntake, RelayIntakeOutcome};
use super::protocol;
use super::telemetry::RelayTelemetry;
use crate::error::HostError;
use crate::settings::CollectorSettings;
use crate::shutdown::ShutdownToken;

pub const MAXIMUM_CONCURRENT_BATCHES: usize = 8;
pub const MAXIMUM_TUNNELS: usize = 64;
pub const MAXIMUM_TUNNELS_PER_DOWNSTREAM: usize = 4;
pub const MAXIMUM_CONNECTIONS: usize = 512;
pub const TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
pub const TUNNEL_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// Kestrel `HttpsConnectionAdapterOptions.HandshakeTimeout`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The pinned downstream a connection authenticated as.
#[derive(Clone, Debug)]
struct Downstream(String);

/// Pin check at the handshake: an unknown, expired or wrong-usage certificate fails it
/// before any request is read. Handshake signatures are always verified.
struct PinnedClientVerifier {
    downstreams: Arc<RelayDownstreams>,
    clock: Arc<dyn Clock>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for PinnedClientVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedClientVerifier")
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self
            .downstreams
            .resolve(end_entity, self.clock.utc_now())
            .is_some()
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
struct RelayState {
    intake: Arc<RelayIntake>,
    telemetry: Arc<RelayTelemetry>,
    batch_slots: Arc<Semaphore>,
    tunnels: Arc<TunnelSlots>,
    /// The relay's own management endpoint when the tunnel is enabled.
    management: Option<Url>,
    shutdown: ShutdownToken,
}

/// The relay server: configuration and pins are read at build time so a bad file stops
/// start-up; [`RelayServer::bind`] and [`RelayServer::serve`] run with the host.
pub struct RelayServer {
    listen: Url,
    acceptor: tokio_rustls::TlsAcceptor,
    downstreams: Arc<RelayDownstreams>,
    clock: Arc<dyn Clock>,
    intake: Arc<RelayIntake>,
    telemetry: Arc<RelayTelemetry>,
    management: Option<Url>,
    listeners: Vec<TcpListener>,
}

impl RelayServer {
    pub fn new(
        settings: &CollectorSettings,
        downstreams: Arc<RelayDownstreams>,
        intake: Arc<RelayIntake>,
        telemetry: Arc<RelayTelemetry>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, HostError> {
        let names = "BOWER_RELAY_CERTIFICATE_FILE and BOWER_RELAY_KEY_FILE";
        let (Some(listen), Some(certificate_file), Some(key_file)) = (
            settings.relay_listen_url.clone(),
            &settings.relay_certificate_file,
            &settings.relay_key_file,
        ) else {
            return Err(HostError::new(
                "InvalidOperationException",
                "BOWER_RELAY_LISTEN_URL requires BOWER_RELAY_CERTIFICATE_FILE, BOWER_RELAY_KEY_FILE and BOWER_RELAY_DOWNSTREAMS_FILE.",
            ));
        };
        let (certificate, key) = super::certificates::load(certificate_file, key_file, names)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = PinnedClientVerifier {
            downstreams: Arc::clone(&downstreams),
            clock: Arc::clone(&clock),
            provider: Arc::clone(&provider),
        };
        let invalid = || {
            HostError::new(
                "InvalidOperationException",
                format!("{names} must name a readable PEM certificate and its private key."),
            )
        };
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid())?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(vec![certificate], key)
            .map_err(|_| invalid())?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            listen,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            downstreams,
            clock,
            intake,
            telemetry,
            management: settings
                .relay_management_tunnel
                .then(|| settings.management_endpoint.clone())
                .flatten(),
            listeners: Vec::new(),
        })
    }

    /// Binds the listener (Kestrel semantics: `localhost` both loopbacks, an IP that
    /// address, a host name every interface).
    pub async fn bind(&mut self) -> Result<(), HostError> {
        let port = self.listen.port().unwrap_or(443);
        let host = self.listen.host_str().unwrap_or_default();
        let addresses: Vec<SocketAddr> = if host.eq_ignore_ascii_case("localhost") {
            vec![
                SocketAddr::from(([127, 0, 0, 1], port)),
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
            ]
        } else {
            match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                Ok(address) => vec![SocketAddr::new(address, port)],
                Err(_) => vec![SocketAddr::from(([0, 0, 0, 0], port))],
            }
        };
        self.listeners = crate::server::bind(&addresses).await?;
        Ok(())
    }

    /// Bound addresses (the port is assigned when the URL uses port 0).
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Serves until `shutdown`, then drains connections for at most the shutdown timeout.
    pub async fn serve(self, shutdown: ShutdownToken) {
        info!(
            downstreams = self.downstreams.collector_ids().len(),
            tunnel = self.management.is_some(),
            "Relay listener started."
        );
        let state = RelayState {
            intake: self.intake,
            telemetry: self.telemetry,
            batch_slots: Arc::new(Semaphore::new(MAXIMUM_CONCURRENT_BATCHES)),
            tunnels: Arc::new(TunnelSlots::default()),
            management: self.management,
            shutdown: shutdown.clone(),
        };
        let router = Router::new()
            .route(&format!("/{}", protocol::BATCH_PATH), post(accept_batch))
            .route(&format!("/{}", protocol::TUNNEL_PATH), get(open_tunnel))
            .with_state(state);
        let connections = Arc::new(Semaphore::new(MAXIMUM_CONNECTIONS));
        let mut acceptors = Vec::new();
        for listener in self.listeners {
            let (acceptor, router, downstreams, clock, shutdown, connections) = (
                self.acceptor.clone(),
                router.clone(),
                Arc::clone(&self.downstreams),
                Arc::clone(&self.clock),
                shutdown.clone(),
                Arc::clone(&connections),
            );
            acceptors.push(tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        accepted = listener.accept() => accepted,
                        () = shutdown.cancelled() => return,
                    };
                    let Ok((tcp, _)) = accepted else {
                        if !shutdown.sleep(Duration::from_millis(100)).await {
                            return;
                        }
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                        continue;
                    };
                    let _ = tcp.set_nodelay(true);
                    let (acceptor, router, downstreams, clock, shutdown) = (
                        acceptor.clone(),
                        router.clone(),
                        Arc::clone(&downstreams),
                        Arc::clone(&clock),
                        shutdown.clone(),
                    );
                    tokio::spawn(async move {
                        let _permit = permit;
                        let Ok(Ok(tls)) =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        else {
                            return;
                        };
                        let Some(identity) = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|certificates| certificates.first())
                            .and_then(|certificate| {
                                downstreams.resolve(certificate, clock.utc_now())
                            })
                        else {
                            return;
                        };
                        let service = TowerToHyperService::new(
                            router.layer(axum::Extension(Downstream(identity))),
                        );
                        let mut connection = std::pin::pin!(
                            http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(crate::server::REQUEST_HEADERS_TIMEOUT)
                                .max_headers(100)
                                .serve_connection(TokioIo::new(tls), service)
                                .with_upgrades()
                        );
                        tokio::select! {
                            _ = connection.as_mut() => {}
                            () = shutdown.cancelled() => {
                                // Drain: finish in-flight requests, then close.
                                connection.as_mut().graceful_shutdown();
                                let _ = tokio::time::timeout(
                                    crate::server::SHUTDOWN_TIMEOUT,
                                    connection,
                                )
                                .await;
                            }
                        }
                    });
                }
            }));
        }
        shutdown.cancelled().await;
        for acceptor in acceptors {
            acceptor.abort();
            let _ = acceptor.await;
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn error(status: u16, message: &'static str, retry_after: Option<&'static str>) -> Response {
    let mut response = crate::app::json_response(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
        &ErrorBody { error: message },
    );
    if let Some(seconds) = retry_after {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static(seconds));
    }
    response
}

async fn accept_batch(
    State(state): State<RelayState>,
    Extension(Downstream(downstream)): Extension<Downstream>,
    request: Request,
) -> Response {
    let Ok(_slot) = state.batch_slots.try_acquire() else {
        return error(429, "Relay is busy; retry shortly.", Some("1"));
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > protocol::MAXIMUM_REQUEST_BYTES) {
        return error(413, "Relay batch could not be read.", None);
    }
    let body =
        match axum::body::to_bytes(request.into_body(), protocol::MAXIMUM_REQUEST_BYTES).await {
            Ok(body) => body,
            Err(failure) => {
                let too_large = std::error::Error::source(&failure)
                    .is_some_and(|source| source.is::<http_body_util::LengthLimitError>());
                return error(
                    if too_large { 413 } else { 400 },
                    "Relay batch could not be read.",
                    None,
                );
            }
        };
    let intake = Arc::clone(&state.intake);
    match tokio::task::spawn_blocking(move || intake.accept(&downstream, &body)).await {
        Ok(Ok(RelayIntakeOutcome::Accepted(response))) => {
            crate::app::json_response(StatusCode::OK, &response)
        }
        Ok(Ok(RelayIntakeOutcome::Refused { status, message })) => {
            error(status, message, (status == 503).then_some("30"))
        }
        Ok(Err(failure)) => {
            // Storage errors (for example SQLITE_BUSY): nothing is acknowledged, the
            // downstream keeps the batch and retries.
            warn!(
                failure_type = crate::worker::store_error_name(&failure),
                "Relay batch failed; the downstream will retry."
            );
            error(503, "Relay storage is unavailable; retry later.", Some("5"))
        }
        Err(_) => error(503, "Relay storage is unavailable; retry later.", Some("5")),
    }
}

/// C# `IHttpUpgradeFeature.IsUpgradableRequest` plus the tunnel's upgrade token.
fn is_tunnel_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers.get_all(header::CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    connection_upgrade
        && headers
            .get(header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case(protocol::TUNNEL_UPGRADE))
}

async fn open_tunnel(
    State(state): State<RelayState>,
    Extension(Downstream(downstream)): Extension<Downstream>,
    mut request: Request,
) -> Response {
    let Some(management) = state.management.clone() else {
        return error(
            404,
            "The management tunnel is not enabled on this relay.",
            None,
        );
    };
    if !is_tunnel_upgrade(request.headers())
        || request
            .extensions()
            .get::<hyper::upgrade::OnUpgrade>()
            .is_none()
    {
        return error(
            400,
            "Expected an upgrade to bower-management-tunnel/1.",
            None,
        );
    }
    let Some(slot) = state.tunnels.acquire(&downstream) else {
        state.telemetry.record_tunnel_refused();
        return error(429, "Too many management tunnels.", Some("5"));
    };
    let Some(upstream) = connect(&management, &state.shutdown).await else {
        return error(
            502,
            "Management endpoint is unreachable from the relay.",
            None,
        );
    };
    let upgrade = hyper::upgrade::on(&mut request);
    let (telemetry, shutdown) = (Arc::clone(&state.telemetry), state.shutdown.clone());
    tokio::spawn(async move {
        let _slot = slot;
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        telemetry.record_tunnel_opened();
        splice(
            TokioIo::new(upgraded),
            upstream,
            TUNNEL_IDLE_TIMEOUT,
            TUNNEL_LIFETIME,
            shutdown,
        )
        .await;
        telemetry.record_tunnel_closed();
    });
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    response.headers_mut().insert(
        header::UPGRADE,
        HeaderValue::from_static(protocol::TUNNEL_UPGRADE),
    );
    response.into_response()
}

async fn connect(management: &Url, shutdown: &ShutdownToken) -> Option<TcpStream> {
    let host = management.host_str()?.trim_matches(['[', ']']).to_string();
    let port = management.port_or_known_default()?;
    let attempt = tokio::time::timeout(TUNNEL_CONNECT_TIMEOUT, TcpStream::connect((host, port)));
    let result = tokio::select! {
        result = attempt => result,
        () = shutdown.cancelled() => return None,
    };
    match result {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Some(stream)
        }
        Ok(Err(failure)) => {
            warn!(error_kind = %failure.kind(), "Relay management tunnel could not connect.");
            None
        }
        Err(_) => {
            warn!("Relay management tunnel could not connect (timeout).");
            None
        }
    }
}

/// Copies both directions until either side closes, the tunnel is idle for `idle`, it
/// reaches `lifetime`, or the relay stops.
pub async fn splice<A, B>(
    first: A,
    second: B,
    idle: Duration,
    lifetime: Duration,
    shutdown: ShutdownToken,
) where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Mutex::new(tokio::time::Instant::now());
    let (mut first_read, mut first_write) = tokio::io::split(first);
    let (mut second_read, mut second_write) = tokio::io::split(second);
    let forward = pump(&mut first_read, &mut second_write, &activity);
    let backward = pump(&mut second_read, &mut first_write, &activity);
    let tick = Duration::from_millis(
        u64::try_from((idle / 4).as_millis())
            .unwrap_or(5_000)
            .clamp(10, 5_000),
    );
    let watchdog = async {
        loop {
            tokio::time::sleep(tick).await;
            let last = *activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if last.elapsed() >= idle {
                return;
            }
        }
    };
    tokio::select! {
        () = forward => {}
        () = backward => {}
        () = watchdog => {}
        () = tokio::time::sleep(lifetime) => {}
        () = shutdown.cancelled() => {}
    }
}

async fn pump<R, W>(from: &mut R, to: &mut W, activity: &Mutex<tokio::time::Instant>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = match from.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        *activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tokio::time::Instant::now();
        if to.write_all(&buffer[..read]).await.is_err() || to.flush().await.is_err() {
            return;
        }
    }
}

/// 64 tunnels in total, 4 per downstream.
#[derive(Default)]
struct TunnelSlots(Mutex<(usize, HashMap<String, usize>)>);

struct TunnelSlot {
    slots: Arc<TunnelSlots>,
    downstream: String,
}

impl TunnelSlots {
    fn acquire(self: &Arc<Self>, downstream: &str) -> Option<TunnelSlot> {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (total, by_downstream) = &mut *guard;
        let count = by_downstream.entry(downstream.to_string()).or_default();
        if *total >= MAXIMUM_TUNNELS || *count >= MAXIMUM_TUNNELS_PER_DOWNSTREAM {
            return None;
        }
        *total += 1;
        *count += 1;
        Some(TunnelSlot {
            slots: Arc::clone(self),
            downstream: downstream.to_string(),
        })
    }
}

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        let mut guard = self
            .slots
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (total, by_downstream) = &mut *guard;
        *total = total.saturating_sub(1);
        if let Some(count) = by_downstream.get_mut(&self.downstream) {
            *count = count.saturating_sub(1);
        }
    }
}
