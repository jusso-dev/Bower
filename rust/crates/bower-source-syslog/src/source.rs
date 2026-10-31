//! TCP, TLS and UDP listeners (C# `SyslogSource`).
//!
//! TCP and TLS: each connection handles one frame at a time and reads the next frame only
//! after the sink has durably enqueued (or definitively dropped) the current one, so a
//! full queue stops reading and TCP flow control pushes back on the sender. Plain syslog
//! has no application acknowledgement, so a healthy connection is never reset: an idle
//! timeout or a stop half-closes it (TCP FIN, no TLS close_notify) and keeps reading what
//! the sender already sent. UDP is best effort: datagrams are queued in a bounded buffer
//! and dropped (and counted) when it is full or the queue is at capacity.
//!
//! Known divergence from C#: this listener sends no TLS 1.3 session tickets. .NET on
//! OpenSSL always sends them, and a sender that never reads (rsyslog) keeps them unread,
//! which hides Bower's FIN from rsyslog's pre-send peek and turns the sender's close into
//! a reset. C# has no API to turn them off; see docs/production-readiness.
//!
//! TLS material is reloaded when its files change, without dropping connections (see
//! [`crate::tls`]); an open mutual-TLS session whose client is no longer trusted is closed
//! before its next frame is used.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bower_contracts::time::{Clock, SystemClock, Timestamp, serde_offset_option};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::config::{ListenerOptions, Route, SyslogSourceConfiguration, normalise};
use crate::framing::FrameReader;
use crate::parser::{self, failures};
use crate::record;
use crate::tls::{TlsSession, TlsSource, is_revocation_failure};

/// Datagrams buffered per UDP listener before new ones are dropped.
pub const UDP_QUEUE_CAPACITY: usize = 256;
/// Submissions in flight across all listeners; others wait (and stop reading).
pub const MAXIMUM_CONCURRENT_SUBMISSIONS: usize = 16;
/// TCP keepalive on accepted connections (C# `SyslogSource.KeepAliveTime` and friends):
/// first probe after two minutes of silence, which also keeps load balancer flow state
/// alive; 30 unanswered probes 30 s apart (about 17 minutes) outlast a Linux sender's own
/// retransmission timeout.
pub const KEEPALIVE_TIME: Duration = Duration::from_secs(120);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const KEEPALIVE_PROBES: u32 = 30;

/// What happened to one record handed to the collector (C# `SyslogSubmitOutcome`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Durably enqueued. This is the acknowledgement point.
    Queued,
    Duplicate,
    Suppressed,
    NotSelected,
    Rejected,
    Invalid,
    TooLarge,
    /// Queue at capacity or ingest gated: TCP waits and retries, UDP drops.
    Unavailable,
}

/// The sink failed (storage error); the frame was not durably accepted.
#[derive(Debug)]
pub struct SinkFailure;

/// Collector side of the source. Synchronous: called on the blocking pool.
pub trait SyslogSink: Send + Sync + 'static {
    fn submit(
        &self,
        listener: &ListenerOptions,
        route: &Route,
        record: &str,
    ) -> Result<SubmitOutcome, SinkFailure>;
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("Syslog listener {0}: TLS certificate or key could not be loaded.")]
    Tls(String),
    /// A revocation list Bower cannot apply correctly (C# `UnsupportedRevocationListException`).
    #[error("Syslog listener {0}: {1}")]
    TlsUnsupported(String, String),
    #[error("{0}")]
    Bind(std::io::Error),
}

/// Per-listener counters since start. Metadata only (C# `SyslogListenerStatus`).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    pub id: String,
    pub protocol: String,
    pub endpoint: String,
    pub active_connections: i64,
    pub connections_accepted: i64,
    pub connections_rejected: i64,
    pub senders_denied: i64,
    pub tls_handshake_failures: i64,
    pub frames_received: i64,
    pub bytes_received: i64,
    pub queued: i64,
    pub duplicates: i64,
    pub suppressed: i64,
    pub not_routed: i64,
    pub not_selected: i64,
    pub rejected: i64,
    pub parser_errors: i64,
    pub malformed: i64,
    pub oversized: i64,
    pub framing_errors: i64,
    pub timeouts: i64,
    pub dropped: i64,
    pub retries: i64,
    pub submit_failures: i64,
    pub receive_errors: i64,
    #[serde(with = "serde_offset_option")]
    pub last_frame_at: Option<Timestamp>,
    /// TLS material reloads applied after a file change.
    pub tls_reloads: i64,
    /// Changed TLS files that could not be loaded; the last good material stays in use.
    pub tls_reload_failures: i64,
    /// Handshakes refused by the revocation lists.
    pub tls_revoked: i64,
    /// Open sessions closed because their client certificate is no longer trusted.
    pub tls_sessions_closed: i64,
    #[serde(with = "serde_offset_option")]
    pub server_certificate_not_after: Option<Timestamp>,
    #[serde(with = "serde_offset_option")]
    pub client_certificate_authority_not_after: Option<Timestamp>,
    #[serde(with = "serde_offset_option")]
    pub client_revocation_list_next_update: Option<Timestamp>,
    /// Connections half-closed (idle timeout or stop) instead of reset.
    pub half_closes: i64,
    /// Frames received after their connection was half-closed.
    pub drained_frames: i64,
    /// Connections a sender or middlebox reset; frames in flight may be lost.
    pub peer_resets: i64,
}

#[derive(Default)]
struct Counters {
    active_connections: AtomicI64,
    connections_accepted: AtomicI64,
    connections_rejected: AtomicI64,
    senders_denied: AtomicI64,
    tls_handshake_failures: AtomicI64,
    tls_revoked: AtomicI64,
    tls_sessions_closed: AtomicI64,
    frames_received: AtomicI64,
    bytes_received: AtomicI64,
    queued: AtomicI64,
    duplicates: AtomicI64,
    suppressed: AtomicI64,
    not_routed: AtomicI64,
    not_selected: AtomicI64,
    rejected: AtomicI64,
    parser_errors: AtomicI64,
    malformed: AtomicI64,
    oversized: AtomicI64,
    framing_errors: AtomicI64,
    timeouts: AtomicI64,
    dropped: AtomicI64,
    retries: AtomicI64,
    submit_failures: AtomicI64,
    receive_errors: AtomicI64,
    half_closes: AtomicI64,
    drained_frames: AtomicI64,
    peer_resets: AtomicI64,
}

fn bump(counter: &AtomicI64) {
    counter.fetch_add(1, Ordering::SeqCst);
}

struct ListenerState {
    options: ListenerOptions,
    counters: Counters,
    endpoint: Mutex<String>,
    last_frame: Mutex<Option<Timestamp>>,
    tls: OnceLock<Arc<TlsSource>>,
}

impl ListenerState {
    fn received(&self, bytes: usize, now: Timestamp) {
        bump(&self.counters.frames_received);
        self.counters
            .bytes_received
            .fetch_add(i64::try_from(bytes).unwrap_or(i64::MAX), Ordering::SeqCst);
        *self
            .last_frame
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(now);
    }

    fn snapshot(&self) -> ListenerStatus {
        let read = |counter: &AtomicI64| counter.load(Ordering::SeqCst);
        let counters = &self.counters;
        // Generation and dates only; the refresh task applies file changes.
        let tls = self.tls.get();
        let material = tls.map(|source| source.current());
        ListenerStatus {
            id: self.options.id.clone(),
            protocol: self.options.protocol.clone(),
            endpoint: self
                .endpoint
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone(),
            active_connections: read(&counters.active_connections),
            connections_accepted: read(&counters.connections_accepted),
            connections_rejected: read(&counters.connections_rejected),
            senders_denied: read(&counters.senders_denied),
            tls_handshake_failures: read(&counters.tls_handshake_failures),
            frames_received: read(&counters.frames_received),
            bytes_received: read(&counters.bytes_received),
            queued: read(&counters.queued),
            duplicates: read(&counters.duplicates),
            suppressed: read(&counters.suppressed),
            not_routed: read(&counters.not_routed),
            not_selected: read(&counters.not_selected),
            rejected: read(&counters.rejected),
            parser_errors: read(&counters.parser_errors),
            malformed: read(&counters.malformed),
            oversized: read(&counters.oversized),
            framing_errors: read(&counters.framing_errors),
            timeouts: read(&counters.timeouts),
            dropped: read(&counters.dropped),
            retries: read(&counters.retries),
            submit_failures: read(&counters.submit_failures),
            receive_errors: read(&counters.receive_errors),
            last_frame_at: *self
                .last_frame
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
            tls_reloads: tls.map_or(0, |source| source.reloads()),
            tls_reload_failures: tls.map_or(0, |source| source.reload_failures()),
            tls_revoked: read(&counters.tls_revoked),
            tls_sessions_closed: read(&counters.tls_sessions_closed),
            server_certificate_not_after: material
                .as_ref()
                .and_then(|material| material.server_certificate_not_after),
            client_certificate_authority_not_after: material
                .as_ref()
                .and_then(|material| material.client_certificate_authority_not_after),
            client_revocation_list_next_update: material
                .as_ref()
                .and_then(|material| material.client_revocation_list_next_update),
            half_closes: read(&counters.half_closes),
            drained_frames: read(&counters.drained_frames),
            peer_resets: read(&counters.peer_resets),
        }
    }
}

/// Read-only view of the listener counters, cheap to clone into the status endpoint.
#[derive(Clone)]
pub struct SyslogMetrics(Arc<Vec<Arc<ListenerState>>>);

impl SyslogMetrics {
    pub fn snapshot(&self) -> Vec<ListenerStatus> {
        self.0.iter().map(|listener| listener.snapshot()).collect()
    }
}

enum Bound {
    Stream(TcpListener, Option<Arc<TlsSource>>),
    Datagram(UdpSocket),
}

struct Shared {
    sink: Arc<dyn SyslogSink>,
    clock: Arc<dyn Clock>,
    gate: Semaphore,
    retry_delay: Duration,
    tls_reload_interval: Duration,
    drain_timeout: Duration,
    stop_timeout: Duration,
}

pub struct SyslogSource {
    listeners: Arc<Vec<Arc<ListenerState>>>,
    bound: Vec<Bound>,
    endpoints: HashMap<String, SocketAddr>,
    shared: Arc<Shared>,
}

impl SyslogSource {
    pub fn new(
        configuration: SyslogSourceConfiguration,
        sink: Arc<dyn SyslogSink>,
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        let listeners = configuration
            .listeners
            .into_iter()
            .map(|options| {
                Arc::new(ListenerState {
                    options,
                    counters: Counters::default(),
                    endpoint: Mutex::new(String::new()),
                    last_frame: Mutex::new(None),
                    tls: OnceLock::new(),
                })
            })
            .collect();
        Self {
            listeners: Arc::new(listeners),
            bound: Vec::new(),
            endpoints: HashMap::new(),
            shared: Arc::new(Shared {
                sink,
                clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
                gate: Semaphore::new(MAXIMUM_CONCURRENT_SUBMISSIONS),
                retry_delay: Duration::from_secs(1),
                tls_reload_interval: Duration::from_secs(1),
                drain_timeout: Duration::from_secs(5),
                stop_timeout: Duration::from_secs(20),
            }),
        }
    }

    /// Wait before retrying a frame the queue could not take yet (before `bind`).
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.retry_delay = delay;
        }
        self
    }

    /// How often a background task checks the TLS files for changes, at least 10 ms
    /// (before `bind`; C# `TlsReloadInterval`).
    pub fn with_tls_reload_interval(mut self, interval: Duration) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.tls_reload_interval = interval;
        }
        self
    }

    /// After a half-close, the wait for each further frame (C# `DrainTimeout`). Call before `bind`.
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.drain_timeout = timeout;
        }
        self
    }

    /// Graceful connection-drain timeout (C# `StopTimeout`). Aborting async tasks cannot
    /// stop an already-running `spawn_blocking` sink, which can outlive this source and
    /// delay runtime shutdown. Call before `bind`.
    pub fn with_stop_timeout(mut self, timeout: Duration) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.stop_timeout = timeout;
        }
        self
    }

    pub fn metrics(&self) -> SyslogMetrics {
        SyslogMetrics(Arc::clone(&self.listeners))
    }

    pub fn snapshot(&self) -> Vec<ListenerStatus> {
        self.metrics().snapshot()
    }

    /// Bound endpoints by listener id (after `bind`).
    pub fn endpoints(&self) -> &HashMap<String, SocketAddr> {
        &self.endpoints
    }

    /// Binds every listener; any failure fails start-up and releases what was bound.
    pub async fn bind(&mut self) -> Result<(), SourceError> {
        let mut bound = Vec::new();
        let mut endpoints = HashMap::new();
        for listener in self.listeners.iter() {
            let options = &listener.options;
            let address = SocketAddr::new(
                options.ip_address(),
                u16::try_from(options.port).unwrap_or(0),
            );
            let (socket, local) = if options.protocol == "udp" {
                let socket = UdpSocket::bind(address).await.map_err(SourceError::Bind)?;
                let local = socket.local_addr().map_err(SourceError::Bind)?;
                (Bound::Datagram(socket), local)
            } else {
                let tls = (options.protocol == "tls")
                    .then(|| TlsSource::load(options))
                    .transpose()?
                    .map(Arc::new);
                if let Some(source) = &tls {
                    let _ = listener.tls.set(Arc::clone(source));
                }
                let socket = bind_stream(address, options).map_err(SourceError::Bind)?;
                let local = socket.local_addr().map_err(SourceError::Bind)?;
                (Bound::Stream(socket, tls), local)
            };
            *listener
                .endpoint
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = local.to_string();
            endpoints.insert(options.id.clone(), local);
            bound.push(socket);
        }
        self.bound = bound;
        self.endpoints = endpoints;
        Ok(())
    }

    /// Serves until `stop` turns true, then closes every connection and returns.
    pub async fn run(self, stop: watch::Receiver<bool>) {
        let mut tasks = JoinSet::new();
        let mut refresh_tasks = JoinSet::new();
        let (refresh_stop, refresh_rx) = watch::channel(false);
        for (listener, bound) in self.listeners.iter().zip(self.bound) {
            let (listener, shared, stop) =
                (Arc::clone(listener), Arc::clone(&self.shared), stop.clone());
            match bound {
                Bound::Stream(socket, tls) => {
                    if let Some(source) = &tls {
                        refresh_tasks.spawn(refresh_tls(
                            Arc::clone(source),
                            self.shared.tls_reload_interval,
                            refresh_rx.clone(),
                        ));
                    }
                    tasks.spawn(accept(listener, socket, tls, shared, stop));
                }
                Bound::Datagram(socket) => {
                    tasks.spawn(serve_udp(listener, socket, shared, stop));
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        let _ = refresh_stop.send(true);
        while refresh_tasks.join_next().await.is_some() {}
    }
}

fn bind_stream(address: SocketAddr, options: &ListenerOptions) -> std::io::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.bind(address)?;
    socket.listen(u32::try_from(options.maximum_connections.min(512)).unwrap_or(128))
}

/// Wait after a failed accept or UDP receive: 100 ms, doubling to 1 s, reset by a success
/// (C# `SyslogSource.NextAcceptBackoff`).
pub fn next_accept_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        Duration::from_millis(100)
    } else {
        (current * 2).min(Duration::from_secs(1))
    }
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|value| *value).await;
}

async fn accept(
    listener: Arc<ListenerState>,
    socket: TcpListener,
    tls: Option<Arc<TlsSource>>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    let mut backoff = Duration::ZERO;
    loop {
        let accepted = tokio::select! {
            () = stopped(&mut stop) => break,
            accepted = socket.accept() => accepted,
            // Reap finished connections so the set stays bounded by the limit.
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let Ok((stream, peer)) = accepted else {
            // A reset before accept completed, or descriptor exhaustion: back off instead of
            // spinning, then keep listening.
            backoff = next_accept_backoff(backoff);
            tokio::select! {
                () = stopped(&mut stop) => break,
                () = tokio::time::sleep(backoff) => continue,
            }
        };
        backoff = Duration::ZERO;
        let sender = normalise(peer.ip());
        if !listener.options.allows(sender) {
            bump(&listener.counters.senders_denied);
            continue;
        }
        let counters = &listener.counters;
        if counters.active_connections.fetch_add(1, Ordering::SeqCst)
            >= listener.options.maximum_connections
        {
            counters.active_connections.fetch_sub(1, Ordering::SeqCst);
            bump(&counters.connections_rejected);
            continue;
        }
        bump(&counters.connections_accepted);
        connections.spawn(serve_connection(
            Arc::clone(&listener),
            stream,
            sender,
            tls.clone(),
            Arc::clone(&shared),
            stop.clone(),
        ));
    }
    // Connections observe the same stop signal: they half-close and drain what senders
    // already sent. Whatever is still open after the drain bound is stopped.
    let drained = tokio::time::timeout(shared.stop_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

struct ActiveGuard(Arc<ListenerState>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0
            .counters
            .active_connections
            .fetch_sub(1, Ordering::SeqCst);
    }
}

async fn serve_connection(
    listener: Arc<ListenerState>,
    stream: TcpStream,
    sender: IpAddr,
    tls: Option<Arc<TlsSource>>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let _guard = ActiveGuard(Arc::clone(&listener));
    configure_keepalive(&stream);
    let frame_timeout =
        Duration::from_secs(u64::try_from(listener.options.frame_timeout_seconds).unwrap_or(60));
    match tls {
        None => serve_frames(&listener, stream, sender, &shared, &mut stop, None).await,
        Some(source) => {
            // Bound unauthenticated connections, including peers that never start TLS.
            // This separate limit accommodates senders that start TLS lazily without
            // applying the idle timeout to an already authenticated session.
            let start_timeout = Duration::from_secs(
                u64::try_from(listener.options.handshake_start_timeout_seconds).unwrap_or(60),
            );
            let mut first = [0u8; 1];
            let started = tokio::select! {
                () = stopped(&mut stop) => return,
                peeked = async {
                    tokio::time::timeout(start_timeout, stream.peek(&mut first)).await.ok()
                } => peeked,
            };
            match started {
                None => {
                    bump(&listener.counters.timeouts);
                    return;
                }
                Some(Ok(0) | Err(_)) => return,
                Some(Ok(_)) => {}
            }
            let material = source.current();
            let handshake = tokio::select! {
                () = stopped(&mut stop) => return,
                handshake = tokio::time::timeout(frame_timeout, material.acceptor.accept(stream)) => handshake,
            };
            match handshake {
                Ok(Ok(secure)) => {
                    let chain = secure
                        .get_ref()
                        .1
                        .peer_certificates()
                        .map(|chain| chain.iter().map(|item| item.clone().into_owned()).collect())
                        .unwrap_or_default();
                    let session = TlsSession::new(&material, chain);
                    let trust = Some((source, session));
                    serve_frames(&listener, secure, sender, &shared, &mut stop, trust).await;
                }
                Ok(Err(error)) => {
                    bump(&listener.counters.tls_handshake_failures);
                    if is_revocation_failure(&error) {
                        bump(&listener.counters.tls_revoked);
                    }
                }
                Err(_) => bump(&listener.counters.tls_handshake_failures),
            }
        }
    }
}

/// C# `StillTrusted`: unchanged material and nothing expired (a lock-free generation
/// check), or a fresh validation.
fn still_trusted(source: &TlsSource, session: &mut TlsSession, now: Timestamp) -> bool {
    (source.generation() == session.generation
        && session.revalidate_at.is_none_or(|deadline| now < deadline))
        || source.current().still_trusted(session)
}

/// C# `RefreshTlsAsync`: checks the TLS files every interval on the blocking pool, off the
/// connection and frame paths.
async fn refresh_tls(source: Arc<TlsSource>, interval: Duration, mut stop: watch::Receiver<bool>) {
    let interval = interval.max(Duration::from_millis(10));
    loop {
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(interval) => {}
        }
        let source = Arc::clone(&source);
        let _ = tokio::task::spawn_blocking(move || source.refresh()).await;
    }
}

/// Keepalive with Bower's timing; a platform that refuses per-socket timing keeps its own.
pub fn configure_keepalive(stream: &TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL);
    #[cfg(not(target_os = "windows"))]
    let keepalive = keepalive.with_retries(KEEPALIVE_PROBES);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// The TCP connection under a stream, for a half-close that sends FIN but no TLS
/// close_notify: a sender that never reads would mistake close_notify for data.
pub trait TcpHalf {
    fn tcp(&mut self) -> &mut TcpStream;
}

impl TcpHalf for TcpStream {
    fn tcp(&mut self) -> &mut TcpStream {
        self
    }
}

impl TcpHalf for tokio_rustls::server::TlsStream<TcpStream> {
    fn tcp(&mut self) -> &mut TcpStream {
        self.get_mut().0
    }
}

async fn half_close<S: TcpHalf>(listener: &ListenerState, stream: &mut S) -> bool {
    if stream.tcp().shutdown().await.is_err() {
        return false;
    }
    bump(&listener.counters.half_closes);
    true
}

enum Between {
    Frame(std::io::Result<bool>),
    Idle,
    Stop,
}

async fn serve_frames<S: AsyncRead + AsyncWrite + Unpin + TcpHalf>(
    listener: &Arc<ListenerState>,
    stream: S,
    sender: IpAddr,
    shared: &Arc<Shared>,
    stop: &mut watch::Receiver<bool>,
    mut trust: Option<(Arc<TlsSource>, TlsSession)>,
) {
    let options = &listener.options;
    let idle = (options.idle_timeout_seconds > 0)
        .then(|| Duration::from_secs(u64::try_from(options.idle_timeout_seconds).unwrap_or(0)));
    let frame_timeout =
        Duration::from_secs(u64::try_from(options.frame_timeout_seconds).unwrap_or(60));
    let mut reader = FrameReader::new(
        stream,
        usize::try_from(options.maximum_message_bytes).unwrap_or(65_536),
    );
    let mut half_closed = false;
    loop {
        // Between frames: an idle connection is closed only gracefully, never reset.
        // `wait_for_frame` is cancel-safe, so the timers below never lose buffered bytes.
        let between = if half_closed {
            match tokio::time::timeout(shared.drain_timeout, reader.wait_for_frame()).await {
                Ok(ready) => Between::Frame(ready),
                Err(_) => return,
            }
        } else {
            tokio::select! {
                () = stopped(stop) => Between::Stop,
                ready = async {
                    match idle {
                        Some(limit) => tokio::time::timeout(limit, reader.wait_for_frame()).await.ok(),
                        None => Some(reader.wait_for_frame().await),
                    }
                } => ready.map_or(Between::Idle, Between::Frame),
            }
        };
        match between {
            Between::Stop | Between::Idle => {
                if matches!(between, Between::Idle) {
                    bump(&listener.counters.timeouts);
                }
                half_closed = half_close(listener, reader.get_mut()).await;
                if !half_closed {
                    return;
                }
                continue;
            }
            Between::Frame(Err(error)) => {
                // A reset can discard frames the sender wrote after its last successful
                // send, so it is counted.
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) {
                    bump(&listener.counters.peer_resets);
                }
                return;
            }
            Between::Frame(Ok(false)) => return,
            Between::Frame(Ok(true)) => {}
        }
        // A frame has started: the rest must arrive within the frame timeout, so a sender
        // that trickles bytes (slow loris) is closed.
        let frame = match tokio::time::timeout(frame_timeout, reader.read_frame()).await {
            Err(_) => {
                bump(&listener.counters.timeouts);
                return;
            }
            // A reset while reading an incomplete frame can discard sender data too.
            Ok(Err(error)) => {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) {
                    bump(&listener.counters.peer_resets);
                }
                return;
            }
            Ok(Ok(Ok(None))) => return,
            Ok(Ok(Err(failure))) => {
                bump(if failure == failures::FRAME_TOO_LARGE {
                    &listener.counters.oversized
                } else {
                    &listener.counters.framing_errors
                });
                return;
            }
            Ok(Ok(Ok(Some(frame)))) => frame.to_vec(),
        };
        listener.received(frame.len(), shared.clock.utc_now());
        if let Some((source, session)) = trust.as_mut()
            && !still_trusted(source, session, shared.clock.utc_now())
        {
            // The client CA was removed, the certificate was revoked or something in its
            // chain expired: refuse this frame and end the session.
            bump(&listener.counters.tls_sessions_closed);
            return;
        }
        if half_closed {
            bump(&listener.counters.drained_frames);
        }
        if !handle_frame(listener, sender, &frame, true, shared, trust.as_mut()).await {
            return;
        }
    }
}

async fn serve_udp(
    listener: Arc<ListenerState>,
    socket: UdpSocket,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let (queue, mut datagrams) = mpsc::channel::<(IpAddr, Vec<u8>)>(UDP_QUEUE_CAPACITY);
    let worker = {
        let (listener, shared, mut stop) =
            (Arc::clone(&listener), Arc::clone(&shared), stop.clone());
        tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    () = stopped(&mut stop) => return,
                    next = datagrams.recv() => next,
                };
                let Some((sender, frame)) = next else { return };
                tokio::select! {
                    () = stopped(&mut stop) => return,
                    _ = handle_frame(&listener, sender, &frame, false, &shared, None) => {}
                }
            }
        })
    };
    let mut buffer = vec![0u8; 65_536];
    let maximum = usize::try_from(listener.options.maximum_message_bytes).unwrap_or(65_536);
    let mut backoff = Duration::ZERO;
    loop {
        let received = tokio::select! {
            () = stopped(&mut stop) => break,
            received = socket.recv_from(&mut buffer) => received,
        };
        let (mut length, peer) = match received {
            Ok(received) => received,
            // ICMP port unreachable reported on Windows; not a datagram.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(_) => {
                // Any other receive error: count it, back off as accept does so a persistent
                // error cannot spin, keep listening (C# `ReceiveErrors`).
                bump(&listener.counters.receive_errors);
                backoff = next_accept_backoff(backoff);
                tokio::select! {
                    () = stopped(&mut stop) => break,
                    () = tokio::time::sleep(backoff) => continue,
                }
            }
        };
        backoff = Duration::ZERO;
        let sender = normalise(peer.ip());
        if !listener.options.allows(sender) {
            bump(&listener.counters.senders_denied);
            continue;
        }
        if length > 0 && buffer[length - 1] == b'\n' {
            length -= 1;
            if length > 0 && buffer[length - 1] == b'\r' {
                length -= 1;
            }
        }
        listener.received(length, shared.clock.utc_now());
        if length > maximum {
            bump(&listener.counters.oversized);
            continue;
        }
        if queue.try_send((sender, buffer[..length].to_vec())).is_err() {
            bump(&listener.counters.dropped);
        }
    }
    drop(queue);
    let _ = worker.await;
}

/// Parse, route, build the record and submit. False when the connection should close
/// (the sink failed, so the frame was not durably accepted).
async fn handle_frame(
    listener: &Arc<ListenerState>,
    sender: IpAddr,
    frame: &[u8],
    wait_when_unavailable: bool,
    shared: &Arc<Shared>,
    mut trust: Option<&mut (Arc<TlsSource>, TlsSession)>,
) -> bool {
    let options = &listener.options;
    let counters = &listener.counters;
    let received_at = shared.clock.utc_now();
    let Ok(message) = parser::parse(frame, &received_at) else {
        bump(&counters.malformed);
        return true;
    };
    let Some(route) = options.route(&message, sender).cloned() else {
        bump(&counters.not_routed);
        return true;
    };
    let Ok(record) = record::build(
        &message,
        frame,
        &options.id,
        &options.protocol,
        &sender.to_string(),
        &received_at,
    ) else {
        bump(&counters.oversized);
        return true;
    };
    let record = Arc::new(record);
    loop {
        let outcome = {
            let Ok(_permit) = shared.gate.acquire().await else {
                return false;
            };
            if let Some((source, session)) = trust.as_mut()
                && !still_trusted(source, session, shared.clock.utc_now())
            {
                bump(&counters.tls_sessions_closed);
                return false;
            }
            let (sink, listener, route, record) = (
                Arc::clone(&shared.sink),
                Arc::clone(listener),
                route.clone(),
                Arc::clone(&record),
            );
            tokio::task::spawn_blocking(move || sink.submit(&listener.options, &route, &record))
                .await
        };
        let outcome = match outcome {
            Ok(Ok(outcome)) => outcome,
            _ => {
                bump(&counters.submit_failures);
                return false;
            }
        };
        let counter = match outcome {
            SubmitOutcome::Unavailable if wait_when_unavailable => {
                bump(&counters.retries);
                tokio::time::sleep(shared.retry_delay).await;
                continue;
            }
            SubmitOutcome::Unavailable => &counters.dropped,
            SubmitOutcome::Queued => &counters.queued,
            SubmitOutcome::Duplicate => &counters.duplicates,
            SubmitOutcome::Suppressed => &counters.suppressed,
            SubmitOutcome::NotSelected => &counters.not_selected,
            SubmitOutcome::Invalid => &counters.parser_errors,
            SubmitOutcome::TooLarge => &counters.oversized,
            SubmitOutcome::Rejected => &counters.rejected,
        };
        bump(counter);
        return true;
    }
}

#[cfg(test)]
mod reset_tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    struct NeverSink;
    impl SyslogSink for NeverSink {
        fn submit(
            &self,
            _: &ListenerOptions,
            _: &Route,
            _: &str,
        ) -> Result<SubmitOutcome, SinkFailure> {
            panic!("an incomplete frame must never reach the sink")
        }
    }
    struct PartialThenReset {
        sent: bool,
        error: std::io::ErrorKind,
    }
    impl AsyncRead for PartialThenReset {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.sent {
                self.sent = true;
                buf.put_slice(b"<38>partial");
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(std::io::Error::from(self.error)))
            }
        }
    }
    impl AsyncWrite for PartialThenReset {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl TcpHalf for PartialThenReset {
        fn tcp(&mut self) -> &mut TcpStream {
            panic!("this test does not half-close")
        }
    }
    #[tokio::test]
    async fn reset_while_reading_partial_frame_is_counted() {
        let configuration = crate::config::parse(r#"{"apiVersion":"bower.security/v1","kind":"SyslogSource","listeners":[{"id":"edge","protocol":"tcp","address":"127.0.0.1","port":0,"allowedSenders":["127.0.0.1"],"routes":[{"appName":"sshd","pack":"ssh","parser":0}]}]}"#).unwrap();
        for (error, expected) in [
            (std::io::ErrorKind::ConnectionReset, 1),
            (std::io::ErrorKind::ConnectionAborted, 1),
            (std::io::ErrorKind::BrokenPipe, 0),
        ] {
            let source = SyslogSource::new(configuration.clone(), Arc::new(NeverSink), None);
            let listener = &source.listeners[0];
            let (_sender, mut stop) = watch::channel(false);
            serve_frames(
                listener,
                PartialThenReset { sent: false, error },
                "127.0.0.1".parse().unwrap(),
                &source.shared,
                &mut stop,
                None,
            )
            .await;
            assert_eq!(
                listener.counters.peer_resets.load(Ordering::SeqCst),
                expected
            );
            assert_eq!(listener.counters.frames_received.load(Ordering::SeqCst), 0);
        }
    }
}
