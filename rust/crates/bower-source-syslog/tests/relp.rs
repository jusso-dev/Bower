//! Port of `SyslogRelpTests`: RELP framing and offer vectors shared with C#
//! (`tests/fixtures/relp-vectors.json`), malformed and oversized input, acknowledgement only
//! after a durable decision, bounded backpressure, crash/resend deduplication, stop and
//! mutual TLS. `tests/fixtures/tls` holds TEST-ONLY keys.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bower_source_syslog::config;
use bower_source_syslog::relp::{self, Command, Frame, RelpReader};
use bower_source_syslog::{
    ListenerOptions, ListenerStatus, Route, SinkFailure, SubmitOutcome, SyslogSink, SyslogSource,
    parser, record,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;

const OFFERS: &str =
    "relp_version=0\nrelp_software=librelp,1.12.0,http://librelp.adiscon.com\ncommands=syslog";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join("relp-vectors.json")).unwrap())
        .unwrap()
}

struct Chunked {
    data: Vec<u8>,
    position: usize,
    chunk: usize,
}

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let take = self
            .chunk
            .min(buf.remaining())
            .min(self.data.len() - self.position);
        let from = self.position;
        buf.put_slice(&self.data[from..from + take]);
        self.position += take;
        Poll::Ready(Ok(()))
    }
}

fn name(command: Command) -> &'static str {
    match command {
        Command::Open => "open",
        Command::Syslog => "syslog",
        Command::Close => "close",
        Command::Response => "rsp",
        Command::ServerClose => "serverclose",
        Command::Unknown => "unknown",
    }
}

#[tokio::test]
async fn frame_vectors_parse_like_csharp_across_arbitrary_reads() {
    for chunk in [1 << 20, 1, 7] {
        for vector in vectors()["frames"].as_array().unwrap() {
            let label = vector["name"].as_str().unwrap();
            let mut reader = RelpReader::new(
                Chunked {
                    data: vector["input"].as_str().unwrap().as_bytes().to_vec(),
                    position: 0,
                    chunk,
                },
                usize::try_from(vector["maximum"].as_u64().unwrap()).unwrap(),
            );
            for expected in vector["results"].as_array().unwrap() {
                let result = reader.read_frame().await.unwrap();
                if expected.is_string() {
                    assert_eq!(result, Frame::End, "{label}");
                } else if let Some(failure) = expected.get("failure") {
                    assert_eq!(
                        result,
                        Frame::Failed(match failure.as_str().unwrap() {
                            "relp-frame-invalid" => relp::failures::FRAME_INVALID,
                            "relp-frame-truncated" => relp::failures::FRAME_TRUNCATED,
                            "relp-data-too-large" => relp::failures::DATA_TOO_LARGE,
                            other => panic!("unknown failure {other}"),
                        }),
                        "{label}"
                    );
                } else {
                    let Frame::Frame {
                        transaction,
                        command,
                        data,
                        oversized,
                    } = result
                    else {
                        panic!("{label}: {result:?}");
                    };
                    assert_eq!(transaction, expected["transaction"].as_u64().unwrap());
                    assert_eq!(name(command), expected["command"].as_str().unwrap());
                    assert_eq!(data, expected["data"].as_str().unwrap().as_bytes());
                    assert_eq!(oversized, expected["oversized"].as_bool().unwrap());
                }
            }
        }
    }
}

#[test]
fn offer_and_response_vectors_match_csharp() {
    let vectors = vectors();
    for vector in vectors["offers"].as_array().unwrap() {
        let accepted = relp::accept_offers(vector["data"].as_str().unwrap().as_bytes());
        assert_eq!(
            accepted.is_ok(),
            vector["accepted"].as_bool().unwrap(),
            "{}",
            vector["name"]
        );
        if let Err(failure) = accepted {
            assert_eq!(failure, relp::failures::OFFERS_INVALID);
        }
    }
    for vector in vectors["responses"].as_array().unwrap() {
        let transaction = vector["transaction"].as_u64().unwrap();
        let frame = match vector["kind"].as_str().unwrap() {
            "openAccepted" => relp::open_accepted(transaction),
            "acknowledge" => relp::acknowledge(transaction),
            "openRefused" => relp::open_refused(transaction),
            "closeAccepted" => relp::close_accepted(transaction),
            _ => relp::server_close(),
        };
        assert_eq!(
            String::from_utf8(frame).unwrap(),
            vector["text"].as_str().unwrap()
        );
    }
    for pair in vectors["transactions"].as_array().unwrap() {
        assert_eq!(
            relp::next(pair[0].as_u64().unwrap()),
            pair[1].as_u64().unwrap()
        );
    }
}

#[tokio::test]
async fn frame_reader_random_and_mutated_input_fails_closed_within_its_buffer() {
    // Fuzz-style: arbitrary bytes and single-byte mutations of valid frames never panic,
    // never return data beyond the limit and always end in a frame, a failure or the end.
    let valid = format!(
        "1 open {} {OFFERS}\n2 syslog 13 <13>1 - - - -\n3 close 0\n",
        OFFERS.len()
    )
    .into_bytes();
    let mut state = 5424u64;
    let mut next = move |bound: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % bound
    };
    for round in 0..2_000 {
        let input: Vec<u8> = if round % 2 == 0 {
            (0..next(200)).map(|_| next(256) as u8).collect()
        } else {
            let mut input = valid.clone();
            let index = next(input.len() as u64) as usize;
            input[index] = next(256) as u8;
            input
        };
        let chunk = 1 + next(15) as usize;
        let mut reader = RelpReader::new(
            Chunked {
                data: input,
                position: 0,
                chunk,
            },
            128,
        );
        for _ in 0..8 {
            match reader.read_frame().await.unwrap() {
                Frame::Frame { data, .. } => assert!(data.len() <= 128),
                Frame::End | Frame::Failed(_) => break,
            }
        }
    }
}

fn config_with(listener: &str) -> String {
    format!(
        r#"{{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{{ {listener} }}]}}"#
    )
}

#[test]
fn configuration_relp_needs_tls_beyond_loopback_and_accepts_tls_settings() {
    let listener = |protocol: &str, address: &str, tls: bool| {
        config_with(&format!(
            r#""id": "edge", "protocol": "{protocol}", "address": "{address}", "port": 0, "allowedSenders": ["10.0.0.1"],
            {} "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}}]"#,
            if tls {
                r#""tls": {"certificateFile": "/s.pem", "privateKeyFile": "/k.pem"},"#
            } else {
                ""
            }
        ))
    };
    let error = |json: String| config::parse(&json).unwrap_err().to_string();
    assert!(
        error(listener("relp", "10.0.0.5", false))
            .contains("requires protocol tls (or relp with tls)")
    );
    for (address, tls) in [("10.0.0.5", true), ("127.0.0.1", false)] {
        assert_eq!(
            config::parse(&listener("relp", address, tls))
                .unwrap()
                .listeners[0]
                .protocol,
            "relp"
        );
    }
    assert!(error(listener("tcp", "127.0.0.1", true)).contains("optional for relp"));
    assert!(
        error(listener("RELP", "127.0.0.1", false))
            .contains("protocol must be tcp, tls, udp or relp")
    );
}

#[test]
fn record_relp_ids_ignore_receive_time_so_resends_deduplicate() {
    let frame = b"<38>1 - gw01 sshd - - - no timestamp";
    let first: bower_contracts::time::Timestamp = "2026-11-01T00:00:00+00:00".parse().unwrap();
    let later = first + chrono::Duration::minutes(30);
    let message = parser::parse(frame, &first).unwrap();
    assert!(message.timestamp.is_none());
    let id = |protocol: &str, at| {
        let built = record::build(&message, frame, "edge", protocol, "10.0.0.1", at).unwrap();
        let value: serde_json::Value = serde_json::from_str(&built).unwrap();
        value["id"].as_str().unwrap().to_string()
    };
    assert_eq!(id("relp", &first), id("relp", &later));
    assert_ne!(id("tls", &first), id("tls", &later));
}

/// A sink that queues, refuses, fails or blocks, and (for the crash test) survives a
/// "restart": committed records stay and a resent id is a duplicate.
#[derive(Default)]
struct Sink {
    committed: Mutex<BTreeMap<String, String>>,
    unavailable: AtomicI64,
    attempts: AtomicUsize,
    fail: bool,
    block: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    /// The commit that reaches this count never returns until released.
    commit_limit: AtomicUsize,
    limit_reached: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl SyslogSink for Sink {
    fn submit(
        &self,
        _: &ListenerOptions,
        _: &Route,
        record: &str,
    ) -> Result<SubmitOutcome, SinkFailure> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(block) = self.block.lock().unwrap().as_ref() {
            let _ = block.recv_timeout(Duration::from_secs(10));
        }
        if self.fail {
            return Err(SinkFailure);
        }
        if self.unavailable.fetch_sub(1, Ordering::SeqCst) > 0 {
            return Ok(SubmitOutcome::Unavailable);
        }
        let value: serde_json::Value = serde_json::from_str(record).unwrap();
        let id = value["id"].as_str().unwrap().to_string();
        let count = {
            let mut committed = self.committed.lock().unwrap();
            if committed.contains_key(&id) {
                return Ok(SubmitOutcome::Duplicate);
            }
            committed.insert(id, value["message"].as_str().unwrap().to_string());
            committed.len()
        };
        if count == self.commit_limit.load(Ordering::SeqCst) {
            // Committed, then the process dies before it can answer.
            if let Some(reached) = self.limit_reached.lock().unwrap().take() {
                let _ = reached.send(());
            }
            let (_keep, wait) = std::sync::mpsc::channel::<()>();
            let _ = wait.recv_timeout(Duration::from_secs(3));
        }
        Ok(SubmitOutcome::Queued)
    }
}

impl Sink {
    fn messages(&self) -> Vec<String> {
        self.committed.lock().unwrap().values().cloned().collect()
    }
}

struct Running {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    metrics: bower_source_syslog::SyslogMetrics,
    endpoint: std::net::SocketAddr,
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
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("stops promptly")
            .unwrap();
    }
}

struct Options {
    idle: u32,
    frame: u32,
    handshake_start: u32,
    drain: Duration,
    stop: Duration,
    busy: Duration,
    tls: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            idle: 0,
            frame: 30,
            handshake_start: 60,
            drain: Duration::from_millis(500),
            stop: Duration::from_secs(1),
            busy: Duration::from_secs(30),
            tls: None,
        }
    }
}

async fn start(sink: Arc<Sink>, options: Options) -> Running {
    let tls = options
        .tls
        .map(|tls| format!(r#""tls": {tls},"#))
        .unwrap_or_default();
    let json = config_with(&format!(
        r#""id": "edge", "protocol": "relp", "address": "127.0.0.1", "port": 0,
        "allowedSenders": ["127.0.0.1"], "maximumMessageBytes": 512, "maximumConnections": 8,
        "idleTimeoutSeconds": {}, "frameTimeoutSeconds": {}, "handshakeStartTimeoutSeconds": {}, {tls}
        "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}}]"#,
        options.idle, options.frame, options.handshake_start
    ));
    let mut source = SyslogSource::new(config::parse(&json).unwrap(), sink, None)
        .with_retry_delay(Duration::from_millis(20))
        .with_drain_timeout(options.drain)
        .with_stop_timeout(options.stop)
        .with_relp_busy_timeout(options.busy);
    source.bind().await.unwrap();
    let endpoint = source.endpoints()["edge"];
    let metrics = source.metrics();
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(source.run(receiver));
    Running {
        stop,
        task,
        metrics,
        endpoint,
    }
}

/// A test RELP client: writes frames and reads the server's frames one at a time.
struct Client<S> {
    reader: RelpReader<S>,
}

impl Client<TcpStream> {
    async fn connect(running: &Running) -> Self {
        Self {
            reader: RelpReader::new(TcpStream::connect(running.endpoint).await.unwrap(), 4_096),
        }
    }

    async fn shutdown(&mut self) {
        self.reader.get_mut().shutdown().await.unwrap();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    async fn open(&mut self) -> Option<String> {
        self.send_command(1, "open", OFFERS).await;
        self.read().await
    }

    async fn send(&mut self, transaction: u64, data: &str) {
        self.send_command(transaction, "syslog", data).await;
    }

    async fn send_command(&mut self, transaction: u64, command: &str, data: &str) {
        self.write(&format!("{transaction} {command} {} {data}\n", data.len()))
            .await;
    }

    async fn write(&mut self, text: &str) {
        let stream = self.reader.get_mut();
        stream.write_all(text.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// The next frame as text, or `None` when the server closed or reset the connection.
    async fn read(&mut self) -> Option<String> {
        let frame = tokio::time::timeout(Duration::from_secs(10), self.reader.read_frame())
            .await
            .expect("server answers or closes");
        match frame {
            Ok(Frame::Frame {
                transaction,
                command,
                data,
                ..
            }) => Some(if data.is_empty() {
                format!("{transaction} {} 0\n", name(command))
            } else {
                format!(
                    "{transaction} {} {} {}\n",
                    name(command),
                    data.len(),
                    String::from_utf8_lossy(data)
                )
            }),
            _ => None,
        }
    }
}

#[tokio::test]
async fn session_opens_acknowledges_each_message_after_its_decision_and_closes() {
    let sink = Arc::new(Sink::default());
    let running = start(Arc::clone(&sink), Options::default()).await;
    let mut client = Client::connect(&running).await;
    assert_eq!(
        client.open().await.unwrap(),
        "1 rsp 57 200 OK\nrelp_version=0\nrelp_software=bower\ncommands=syslog\n"
    );
    client
        .send(2, "<38>Oct 11 22:14:15 gw01 sshd: accepted\n")
        .await;
    client
        .send(3, "<38>Oct 11 22:14:15 gw01 cron: not routed")
        .await;
    client.send(4, "not syslog").await;
    for transaction in 2..=4 {
        assert_eq!(
            client.read().await.unwrap(),
            format!("{transaction} rsp 6 200 OK\n")
        );
    }
    client.write("5 close 0\n").await;
    assert_eq!(client.read().await.unwrap(), "5 rsp 0\n");
    assert!(client.read().await.is_none());
    assert_eq!(sink.messages(), ["accepted"]);
    let status = running
        .wait_for(|status| status.active_connections == 0)
        .await;
    assert_eq!(
        (
            status.queued,
            status.not_routed,
            status.malformed,
            status.relp_acknowledged,
            status.framing_errors
        ),
        (1, 1, 1, 3, 0)
    );
    assert_eq!(status.protocol, "relp");
    running.stop().await;
}

#[tokio::test]
async fn session_never_acknowledges_before_the_sink_commits() {
    let (release, block) = std::sync::mpsc::channel();
    let sink = Arc::new(Sink {
        block: Mutex::new(Some(block)),
        ..Sink::default()
    });
    let running = start(Arc::clone(&sink), Options::default()).await;
    let mut client = Client::connect(&running).await;
    client.open().await;
    client.send(2, "<38>Oct 11 22:14:15 gw01 sshd: held").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(running.status().relp_acknowledged, 0);
    assert!(sink.messages().is_empty());
    release.send(()).unwrap();
    assert_eq!(client.read().await.unwrap(), "2 rsp 6 200 OK\n");
    assert_eq!(sink.messages(), ["held"]);
    running.stop().await;
}

#[tokio::test]
async fn session_a_failed_commit_is_never_acknowledged_and_ends_the_session() {
    let sink = Arc::new(Sink {
        fail: true,
        ..Sink::default()
    });
    let running = start(Arc::clone(&sink), Options::default()).await;
    let mut client = Client::connect(&running).await;
    client.open().await;
    client
        .send(2, "<38>Oct 11 22:14:15 gw01 sshd: storage fails")
        .await;
    assert!(client.read().await.is_none());
    let status = running.wait_for(|status| status.submit_failures == 1).await;
    assert_eq!(status.relp_acknowledged, 0);
    running.stop().await;
}

#[tokio::test]
async fn session_a_queue_that_keeps_refusing_ends_the_session_unacknowledged_then_the_resend_is_queued()
 {
    let sink = Arc::new(Sink {
        unavailable: AtomicI64::new(1_000_000),
        ..Sink::default()
    });
    let running = start(
        Arc::clone(&sink),
        Options {
            busy: Duration::from_millis(300),
            ..Options::default()
        },
    )
    .await;
    let message = "<38>1 2026-11-01T00:00:00.000001Z gw01 sshd - - - refused then accepted";
    let mut refused = Client::connect(&running).await;
    refused.open().await;
    refused.send(2, message).await;
    assert_eq!(refused.read().await.unwrap(), "0 serverclose 0\n");
    assert!(refused.read().await.is_none());
    let status = running
        .wait_for(|status| status.relp_busy_closes == 1 && status.active_connections == 0)
        .await;
    assert_eq!(
        (
            status.relp_acknowledged,
            status.relp_server_closes,
            status.queued
        ),
        (0, 1, 0)
    );
    assert!(status.retries > 0);

    // Capacity returns: the sender reconnects and resends; the message is queued exactly once.
    sink.unavailable.store(0, Ordering::SeqCst);
    let mut resend = Client::connect(&running).await;
    resend.open().await;
    resend.send(2, message).await;
    assert_eq!(resend.read().await.unwrap(), "2 rsp 6 200 OK\n");
    assert_eq!(sink.messages(), ["refused then accepted"]);
    running.stop().await;
}

#[tokio::test]
async fn session_crash_after_commit_before_acknowledgement_then_resend_yields_the_exact_set_once() {
    // A durable sink shared by two collector "processes". The first stops answering right
    // after its 37th commit and is then stopped like a crashed process; the client resends
    // everything it has no acknowledgement for.
    let (reached, limit) = std::sync::mpsc::channel();
    let sink = Arc::new(Sink {
        commit_limit: AtomicUsize::new(37),
        limit_reached: Mutex::new(Some(reached)),
        ..Sink::default()
    });
    let messages: Vec<String> = (0..128)
        .map(|index| format!("<38>1 2026-11-01T00:00:00.{index:06}Z gw01 sshd - - - seq={index}"))
        .collect();
    let first = start(
        Arc::clone(&sink),
        Options {
            stop: Duration::from_millis(200),
            ..Options::default()
        },
    )
    .await;
    let mut acknowledged = BTreeSet::new();
    let mut client = Client::connect(&first).await;
    client.open().await;
    for (index, message) in messages.iter().enumerate() {
        client.send(index as u64 + 2, message).await;
    }
    tokio::task::spawn_blocking(move || limit.recv_timeout(Duration::from_secs(10)).unwrap())
        .await
        .unwrap();
    first.stop().await;
    while let Some(frame) = client.read().await {
        assert!(frame.ends_with(" rsp 6 200 OK\n"), "{frame}");
        let transaction: usize = frame[..frame.find(' ').unwrap()].parse().unwrap();
        acknowledged.insert(transaction - 2);
    }
    assert_eq!(sink.committed.lock().unwrap().len(), 37);
    assert_eq!(acknowledged, (0..36).collect());

    sink.commit_limit.store(usize::MAX, Ordering::SeqCst);
    let second = start(Arc::clone(&sink), Options::default()).await;
    let mut again = Client::connect(&second).await;
    again.open().await;
    let mut transaction = 2;
    for (index, message) in messages.iter().enumerate() {
        if !acknowledged.contains(&index) {
            again.send(transaction, message).await;
            transaction += 1;
        }
    }
    for expected in 2..transaction {
        assert_eq!(
            again.read().await.unwrap(),
            format!("{expected} rsp 6 200 OK\n")
        );
    }
    let committed: BTreeSet<String> = sink.messages().into_iter().collect();
    assert_eq!(
        committed,
        (0..128).map(|index| format!("seq={index}")).collect()
    );
    let status = second.status();
    assert_eq!((status.queued, status.duplicates), (91, 1));
    second.stop().await;
}

#[tokio::test]
async fn session_a_full_window_is_acknowledged_in_order_without_reading_ahead() {
    let sink = Arc::new(Sink::default());
    let running = start(Arc::clone(&sink), Options::default()).await;
    let mut client = Client::connect(&running).await;
    client.open().await;
    let mut window = String::new();
    for index in 0..128 {
        let data = format!("<38>Oct 11 22:14:15 gw01 sshd: window {index}");
        window.push_str(&format!("{} syslog {} {data}\n", index + 2, data.len()));
    }
    client.write(&window).await;
    for index in 0..128 {
        assert_eq!(
            client.read().await.unwrap(),
            format!("{} rsp 6 200 OK\n", index + 2)
        );
    }
    assert_eq!(sink.committed.lock().unwrap().len(), 128);
    running.stop().await;
}

#[tokio::test]
async fn session_protocol_errors_end_the_session_without_submitting() {
    for input in [
        "2 syslog 3 abc\n",
        "1 open 14 relp_version=0\n",
        "1 open 30 relp_version=0\ncommands=syslog\n3 syslog 1 x\n",
        "1 open 30 relp_version=0\ncommands=syslog\n2 open 30 relp_version=0\ncommands=syslog\n",
        "1 open 30 relp_version=0\ncommands=syslog\n2 rsp 6 200 OK\n",
        "1 open 30 relp_version=0\ncommands=syslog\n2 starttls 0\n",
        "1 open 30 relp_version=0\ncommands=syslog\n2 syslog 3 abcd\n",
        "1 open 30 relp_version=0\ncommands=syslog\n2 syslog 2000000 x\n",
    ] {
        let sink = Arc::new(Sink::default());
        let running = start(Arc::clone(&sink), Options::default()).await;
        let mut client = Client::connect(&running).await;
        client.write(input).await;
        while let Some(frame) = client.read().await {
            assert!(!frame.contains("rsp 6 200 OK"), "{input}");
        }
        let status = running
            .wait_for(|status| status.active_connections == 0)
            .await;
        assert!(sink.messages().is_empty(), "{input}");
        assert_eq!(status.framing_errors + status.oversized, 1, "{input}");
        running.stop().await;
    }
}

#[tokio::test]
async fn session_an_oversized_message_is_a_final_drop_and_the_session_continues() {
    let sink = Arc::new(Sink::default());
    let running = start(Arc::clone(&sink), Options::default()).await;
    let mut client = Client::connect(&running).await;
    client.open().await;
    let huge = format!("<38>Oct 11 22:14:15 gw01 sshd: {}", "x".repeat(5_000));
    let long = format!("<38>Oct 11 22:14:15 gw01 sshd: {}", "y".repeat(600));
    client.send(2, &huge).await;
    client.send(3, &long).await;
    client.send(4, "<38>Oct 11 22:14:15 gw01 sshd: fits").await;
    for transaction in 2..=4 {
        assert_eq!(
            client.read().await.unwrap(),
            format!("{transaction} rsp 6 200 OK\n")
        );
    }
    assert_eq!(sink.messages(), ["fits"]);
    assert_eq!(running.status().oversized, 2);
    running.stop().await;
}

#[tokio::test]
async fn session_must_open_within_the_handshake_start_timeout() {
    let running = start(
        Arc::new(Sink::default()),
        Options {
            handshake_start: 1,
            ..Options::default()
        },
    )
    .await;
    let mut client = Client::connect(&running).await;
    assert!(client.read().await.is_none());
    let status = running
        .wait_for(|status| status.timeouts == 1 && status.active_connections == 0)
        .await;
    assert_eq!(status.relp_server_closes, 0);
    running.stop().await;
}

#[tokio::test]
async fn session_a_slow_frame_is_closed_by_the_frame_timeout() {
    let sink = Arc::new(Sink::default());
    let running = start(
        Arc::clone(&sink),
        Options {
            frame: 1,
            ..Options::default()
        },
    )
    .await;
    let mut client = Client::connect(&running).await;
    client.open().await;
    client.write("2 syslog 40 <38>Oct").await;
    assert!(client.read().await.is_none());
    running.wait_for(|status| status.timeouts == 1).await;
    assert!(sink.messages().is_empty());
    running.stop().await;
}

#[tokio::test]
async fn stop_sends_server_close_then_enqueues_what_the_sender_already_sent_without_acknowledging()
{
    let sink = Arc::new(Sink::default());
    let running = start(
        Arc::clone(&sink),
        Options {
            drain: Duration::from_secs(2),
            stop: Duration::from_secs(5),
            ..Options::default()
        },
    )
    .await;
    let metrics = running.metrics.clone();
    let mut client = Client::connect(&running).await;
    client.open().await;
    client
        .send(2, "<38>Oct 11 22:14:15 gw01 sshd: before stop")
        .await;
    assert_eq!(client.read().await.unwrap(), "2 rsp 6 200 OK\n");
    let stopping = tokio::spawn(running.stop());
    assert_eq!(client.read().await.unwrap(), "0 serverclose 0\n");
    // A sender writes before it processes the hint; the frame is still committed.
    client
        .send(3, "<38>Oct 11 22:14:15 gw01 sshd: in flight")
        .await;
    assert!(client.read().await.is_none());
    client.shutdown().await;
    stopping.await.unwrap();
    let mut committed: Vec<String> = sink.messages();
    committed.sort();
    assert_eq!(committed, ["before stop", "in flight"]);
    let status = metrics.snapshot().remove(0);
    assert_eq!(
        (
            status.relp_acknowledged,
            status.relp_server_closes,
            status.drained_frames
        ),
        (1, 1, 1)
    );
}

#[tokio::test]
async fn idle_timeout_ends_an_open_session_with_server_close() {
    let running = start(
        Arc::new(Sink::default()),
        Options {
            idle: 1,
            drain: Duration::from_millis(200),
            ..Options::default()
        },
    )
    .await;
    let mut client = Client::connect(&running).await;
    client.open().await;
    assert_eq!(client.read().await.unwrap(), "0 serverclose 0\n");
    assert!(client.read().await.is_none());
    let status = running
        .wait_for(|status| status.active_connections == 0)
        .await;
    assert_eq!(status.relp_server_closes, 1);
    running.stop().await;
}

fn tls_client(client: Option<&str>) -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(fixtures().join("tls/ca.pem")).unwrap() {
        roots.add(certificate.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let config = match client {
        None => builder.with_no_client_auth(),
        Some(name) => builder
            .with_client_auth_cert(
                CertificateDer::pem_file_iter(fixtures().join(format!("tls/{name}.pem")))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect(),
                PrivateKeyDer::from_pem_file(fixtures().join(format!("tls/{name}-key.pem")))
                    .unwrap(),
            )
            .unwrap(),
    };
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn tls_mutual_authentication_is_enforced_for_relp() {
    let sink = Arc::new(Sink::default());
    let tls = fixtures().join("tls");
    let path = |name: &str| serde_json::to_string(&tls.join(name)).unwrap();
    let running = start(
        Arc::clone(&sink),
        Options {
            tls: Some(format!(
                r#"{{"certificateFile": {}, "privateKeyFile": {}, "clientCertificateAuthorityFile": {}}}"#,
                path("server.pem"),
                path("server-key.pem"),
                path("ca.pem")
            )),
            ..Options::default()
        },
    )
    .await;
    let localhost = ServerName::try_from("localhost").unwrap();
    let anonymous = async {
        let tcp = TcpStream::connect(running.endpoint).await.ok()?;
        let stream = tls_client(None)
            .connect(localhost.clone(), tcp)
            .await
            .ok()?;
        let mut client = Client {
            reader: RelpReader::new(stream, 4_096),
        };
        client.open().await
    };
    assert!(anonymous.await.is_none());
    running
        .wait_for(|status| status.tls_handshake_failures == 1)
        .await;
    let tcp = TcpStream::connect(running.endpoint).await.unwrap();
    let stream = tls_client(Some("client"))
        .connect(localhost, tcp)
        .await
        .unwrap();
    let mut client = Client {
        reader: RelpReader::new(stream, 4_096),
    };
    client.open().await.unwrap();
    client
        .send(2, "<38>Oct 11 22:14:15 gw01 sshd: over mutual tls")
        .await;
    assert_eq!(client.read().await.unwrap(), "2 rsp 6 200 OK\n");
    assert_eq!(sink.messages(), ["over mutual tls"]);
    running.stop().await;
}
