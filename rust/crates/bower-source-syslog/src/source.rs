//! TCP, TLS and UDP listeners (C# `SyslogSource`).
//!
//! TCP and TLS: each connection handles one frame at a time and reads the next frame only
//! after the sink has durably enqueued (or definitively dropped) the current one, so a
//! full queue stops reading and TCP flow control pushes back on the sender. Plain syslog
//! has no application acknowledgement: frames buffered here or in the kernel when the
//! process stops are lost unless the sender retransmits. UDP is best effort: datagrams are
//! queued in a bounded buffer and dropped (and counted) when it is full or the queue is at
//! capacity.

use std::collections::HashMap;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_contracts::time::{Clock, SystemClock, Timestamp, serde_offset_option};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::{ListenerOptions, Route, SyslogSourceConfiguration, normalise};
use crate::framing::FrameReader;
use crate::parser::{self, failures};
use crate::record;

/// Datagrams buffered per UDP listener before new ones are dropped.
pub const UDP_QUEUE_CAPACITY: usize = 256;
/// Submissions in flight across all listeners; others wait (and stop reading).
pub const MAXIMUM_CONCURRENT_SUBMISSIONS: usize = 16;

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
}

#[derive(Default)]
struct Counters {
    active_connections: AtomicI64,
    connections_accepted: AtomicI64,
    connections_rejected: AtomicI64,
    senders_denied: AtomicI64,
    tls_handshake_failures: AtomicI64,
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
}

fn bump(counter: &AtomicI64) {
    counter.fetch_add(1, Ordering::SeqCst);
}

struct ListenerState {
    options: ListenerOptions,
    counters: Counters,
    endpoint: Mutex<String>,
    last_frame: Mutex<Option<Timestamp>>,
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
    Stream(TcpListener, Option<TlsAcceptor>),
    Datagram(UdpSocket),
}

struct Shared {
    sink: Arc<dyn SyslogSink>,
    clock: Arc<dyn Clock>,
    gate: Semaphore,
    retry_delay: Duration,
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
                    .then(|| load_tls(options))
                    .transpose()?;
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
        for (listener, bound) in self.listeners.iter().zip(self.bound) {
            let (listener, shared, stop) =
                (Arc::clone(listener), Arc::clone(&self.shared), stop.clone());
            match bound {
                Bound::Stream(socket, tls) => {
                    tasks.spawn(accept(listener, socket, tls, shared, stop));
                }
                Bound::Datagram(socket) => {
                    tasks.spawn(serve_udp(listener, socket, shared, stop));
                }
            }
        }
        while tasks.join_next().await.is_some() {}
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
    tls: Option<TlsAcceptor>,
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
    // Connections observe the same stop signal; wait for them to close.
    while connections.join_next().await.is_some() {}
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
    tls: Option<TlsAcceptor>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let _guard = ActiveGuard(Arc::clone(&listener));
    let idle =
        Duration::from_secs(u64::try_from(listener.options.idle_timeout_seconds).unwrap_or(60));
    match tls {
        None => serve_frames(&listener, stream, sender, &shared, idle, &mut stop).await,
        Some(acceptor) => {
            let handshake = tokio::select! {
                () = stopped(&mut stop) => return,
                handshake = tokio::time::timeout(idle, acceptor.accept(stream)) => handshake,
            };
            match handshake {
                Ok(Ok(secure)) => {
                    serve_frames(&listener, secure, sender, &shared, idle, &mut stop).await;
                }
                _ => bump(&listener.counters.tls_handshake_failures),
            }
        }
    }
}

async fn serve_frames<S: AsyncRead + AsyncWrite + Unpin>(
    listener: &Arc<ListenerState>,
    stream: S,
    sender: IpAddr,
    shared: &Arc<Shared>,
    idle: Duration,
    stop: &mut watch::Receiver<bool>,
) {
    let mut reader = FrameReader::new(
        stream,
        usize::try_from(listener.options.maximum_message_bytes).unwrap_or(65_536),
    );
    loop {
        // The whole next frame must arrive within the idle timeout: a sender that trickles
        // bytes (slow loris) is closed as surely as an idle one.
        let frame = tokio::select! {
            () = stopped(stop) => return,
            frame = tokio::time::timeout(idle, reader.read_frame()) => frame,
        };
        let frame = match frame {
            Err(_) => {
                bump(&listener.counters.timeouts);
                return;
            }
            // Peer reset or closed socket: the connection simply ends.
            Ok(Err(_)) | Ok(Ok(Ok(None))) => return,
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
        let handled = tokio::select! {
            () = stopped(stop) => return,
            handled = handle_frame(listener, sender, &frame, true, shared) => handled,
        };
        if !handled {
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
                    _ = handle_frame(&listener, sender, &frame, false, &shared) => {}
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

fn load_tls(options: &ListenerOptions) -> Result<TlsAcceptor, SourceError> {
    let failed = || SourceError::Tls(options.id.clone());
    let tls = options.tls.as_ref().ok_or_else(failed)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certificates = CertificateDer::pem_file_iter(&tls.certificate_file)
        .map_err(|_| failed())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| failed())?;
    if certificates.is_empty() {
        return Err(failed());
    }
    let key = PrivateKeyDer::from_pem_file(&tls.private_key_file).map_err(|_| failed())?;
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| failed())?;
    let builder = match &tls.client_certificate_authority_file {
        None => builder.with_no_client_auth(),
        Some(authority) => {
            let file = std::fs::File::open(authority).map_err(|_| failed())?;
            let mut roots = rustls::RootCertStore::empty();
            for certificate in CertificateDer::pem_reader_iter(BufReader::new(file)) {
                roots
                    .add(certificate.map_err(|_| failed())?)
                    .map_err(|_| failed())?;
            }
            if roots.is_empty() {
                return Err(failed());
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|_| failed())?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let config = builder
        .with_single_cert(certificates, key)
        .map_err(|_| failed())?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
