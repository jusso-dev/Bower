//! Port of `SyslogSourceTests`: shared RFC vectors, framing bounds, configuration and the
//! TCP, TLS and UDP listeners against a fake sink. `tests/fixtures/tls` holds TEST-ONLY
//! keys generated for these tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bower_source_syslog::config::{self, ConfigError};
use bower_source_syslog::framing::FrameReader;
use bower_source_syslog::source::UDP_QUEUE_CAPACITY;
use bower_source_syslog::{
    ListenerOptions, ListenerStatus, Route, SinkFailure, SubmitOutcome, SyslogSink, SyslogSource,
    parser, record,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn string(value: &serde_json::Value) -> String {
    value.as_str().unwrap().to_string()
}

#[test]
fn shared_vectors_parse_to_the_same_records_and_failure_codes_as_csharp() {
    let text = std::fs::read_to_string(fixtures().join("syslog-vectors.json")).unwrap();
    let root: serde_json::Value = serde_json::from_str(&text).unwrap();
    let (listener, protocol, sender) = (
        string(&root["listener"]),
        string(&root["protocol"]),
        string(&root["sender"]),
    );
    let vectors = root["vectors"].as_array().unwrap();
    assert!(vectors.len() > 80);
    for vector in vectors {
        let name = string(&vector["name"]);
        let frame = match vector.get("frame") {
            Some(frame) => frame.as_str().unwrap().as_bytes().to_vec(),
            None => base64::engine::general_purpose::STANDARD
                .decode(vector["frameBase64"].as_str().unwrap())
                .unwrap(),
        };
        let received =
            bower_contracts::time::parse(vector["receivedAt"].as_str().unwrap()).unwrap();
        let outcome = parser::parse(&frame, &received).and_then(|message| {
            record::build(&message, &frame, &listener, &protocol, &sender, &received)
        });
        match vector.get("failure") {
            Some(expected) => assert_eq!(outcome.err(), expected.as_str(), "{name}"),
            None => {
                let produced = outcome.unwrap_or_else(|failure| panic!("{name}: {failure}"));
                let produced: serde_json::Value = serde_json::from_str(&produced).unwrap();
                let fields = |value: &serde_json::Value| -> Vec<String> {
                    value
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| format!("{key}={}", value.as_str().unwrap()))
                        .collect()
                };
                assert_eq!(fields(&produced), fields(&vector["record"]), "{name}");
            }
        }
    }
}

#[test]
fn record_id_is_stable_for_retransmits_and_distinct_per_sender_and_listener() {
    let frame = b"<13>1 2026-10-26T08:00:00Z h a - - - msg";
    let now = bower_contracts::time::now();
    let message = parser::parse(frame, &now).unwrap();
    let id = |listener: &str, protocol: &str, sender: &str, at| -> String {
        let text = record::build(&message, frame, listener, protocol, sender, &at).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        string(&value["id"])
    };
    let first = id("edge", "tcp", "192.0.2.10", now);
    assert_eq!(
        first,
        id(
            "edge",
            "udp",
            "192.0.2.10",
            now + chrono::Duration::minutes(5)
        )
    );
    assert_ne!(first, id("edge", "tcp", "192.0.2.11", now));
    assert_ne!(first, id("core", "tcp", "192.0.2.10", now));
    assert!(first.starts_with("syslog-"));
    assert_eq!(first.len(), 39);
}

#[test]
fn record_identity_cannot_distinguish_identical_events_from_retransmissions() {
    let now = bower_contracts::time::now();
    for (frame, timestamped) in [
        (b"<13>1 2026-10-26T08:00:00Z h a - - - msg".as_slice(), true),
        (b"<13>1 - h a - - - msg".as_slice(), false),
    ] {
        let message = parser::parse(frame, &now).unwrap();
        let id = |at| {
            let text = record::build(&message, frame, "edge", "tcp", "192.0.2.10", &at).unwrap();
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            string(&value["id"])
        };
        let first = id(now);
        let later = id(now + chrono::Duration::seconds(1));
        if timestamped {
            assert_eq!(first, later);
        } else {
            assert_ne!(first, later);
        }
    }
}

/// Shared with C#: a peer address becomes `senderAddress` and the event id the same way in
/// both runtimes (IPv4-mapped IPv6 to IPv4, IPv6 interface scope dropped).
#[test]
fn sender_vectors_normalise_peers_and_ids_like_csharp() {
    let text = std::fs::read_to_string(fixtures().join("sender-vectors.json")).unwrap();
    let root: serde_json::Value = serde_json::from_str(&text).unwrap();
    let frame = string(&root["frame"]).into_bytes();
    let received = bower_contracts::time::parse(root["receivedAt"].as_str().unwrap()).unwrap();
    let message = parser::parse(&frame, &received).unwrap();
    let vectors = root["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    for vector in vectors {
        let name = string(&vector["name"]);
        let peer: std::net::SocketAddr = string(&vector["peer"]).parse().unwrap();
        let sender = config::normalise(peer.ip()).to_string();
        assert_eq!(sender, string(&vector["senderAddress"]), "{name}");
        let produced = record::build(
            &message,
            &frame,
            &string(&root["listener"]),
            &string(&root["protocol"]),
            &sender,
            &received,
        )
        .unwrap();
        let produced: serde_json::Value = serde_json::from_str(&produced).unwrap();
        assert_eq!(string(&produced["senderAddress"]), sender, "{name}");
        assert_eq!(string(&produced["id"]), string(&vector["id"]), "{name}");
    }
}

/// Returns at most `chunk` bytes per read.
struct Chunked {
    data: Vec<u8>,
    position: usize,
    chunk: usize,
}

impl Chunked {
    fn new(data: &[u8], chunk: usize) -> Self {
        Self {
            data: data.to_vec(),
            position: 0,
            chunk,
        }
    }
}

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let count = self
            .chunk
            .min(buffer.remaining())
            .min(self.data.len() - self.position);
        let start = self.position;
        buffer.put_slice(&self.data[start..start + count]);
        self.position += count;
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn frame_reader_splits_octet_counted_and_line_frames_across_arbitrary_reads() {
    for (input, chunk) in [
        ("17 <13>1 - - - - - -17 <14>1 - - - - - -", 1),
        ("<13>1 - - - - - -\n<14>1 - - - - - -\r\n", 1),
        ("<13>1 - - - - - -\n17 <14>1 - - - - - -\n\n", 1),
        ("17 <13>1 - - - - - -17 <14>1 - - - - - -", 7),
        ("<13>1 - - - - - -\n<14>1 - - - - - -\r\n", 3),
    ] {
        let mut reader = FrameReader::new(Chunked::new(input.as_bytes(), chunk), 480);
        let mut frames = Vec::new();
        while let Some(frame) = reader.read_frame().await.unwrap().unwrap() {
            frames.push(String::from_utf8(frame.to_vec()).unwrap());
        }
        assert_eq!(
            frames,
            ["<13>1 - - - - - -", "<14>1 - - - - - -"],
            "{input:?}"
        );
    }
}

#[tokio::test]
async fn frame_reader_fails_closed_on_bad_framing() {
    for (input, expected) in [
        ("481 <13>1 -", "syslog-frame-too-large"),
        ("99999999 <13>", "syslog-frame-too-large"),
        ("12a <13>1 - - -", "syslog-octet-count-invalid"),
        ("12<13>1 - - -", "syslog-octet-count-invalid"),
        ("0 <13>1 - - -", "syslog-framing-invalid"),
        ("x<13>1 - - -\n", "syslog-framing-invalid"),
        ("\u{0}<13>1\n", "syslog-framing-invalid"),
        ("50 <13>1 - - - - - -", "syslog-frame-truncated"),
        ("20", "syslog-frame-truncated"),
        ("<13>1 - - - - - - no newline", "syslog-frame-truncated"),
    ] {
        let mut reader = FrameReader::new(Chunked::new(input.as_bytes(), 4), 480);
        assert_eq!(
            reader.read_frame().await.unwrap().err(),
            Some(expected),
            "{input:?}"
        );
    }
}

#[tokio::test]
async fn frame_reader_bounds_line_frames_without_buffering_past_the_limit() {
    let oversized = format!("<13>{}\n", "x".repeat(10_000));
    let mut reader = FrameReader::new(Chunked::new(oversized.as_bytes(), 1024), 480);
    assert_eq!(
        reader.read_frame().await.unwrap().err(),
        Some("syslog-frame-too-large")
    );
    assert!(reader.into_inner().position < 2048);
    for suffix in ["\n", "\r\n"] {
        let exact = format!("<13>{}{suffix}", "y".repeat(476));
        let mut reader = FrameReader::new(Chunked::new(exact.as_bytes(), 64), 480);
        assert_eq!(
            reader.read_frame().await.unwrap().unwrap().unwrap().len(),
            480
        );
    }
    let counted = format!("480 <13>{}", "z".repeat(476));
    let mut reader = FrameReader::new(Chunked::new(counted.as_bytes(), 64), 480);
    assert_eq!(
        reader.read_frame().await.unwrap().unwrap().unwrap().len(),
        480
    );
}

fn config_with(listener: &str) -> String {
    format!(
        r#"{{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{{ {listener} }}]}}"#
    )
}

fn invalid(json: &str) -> String {
    match config::parse(json) {
        Err(ConfigError::InvalidData(message)) => message,
        other => panic!("expected invalid data, got {other:?}"),
    }
}

#[test]
fn configuration_refuses_non_loopback_without_tls_unless_overridden() {
    for (protocol, address, allow, expected) in [
        (
            "tcp",
            "0.0.0.0",
            false,
            Some("a non-loopback address requires protocol tls"),
        ),
        (
            "udp",
            "192.0.2.1",
            false,
            Some("a non-loopback address requires protocol tls"),
        ),
        (
            "tcp",
            "::",
            false,
            Some("a non-loopback address requires protocol tls"),
        ),
        ("tcp", "0.0.0.0", true, None),
        ("udp", "0.0.0.0", true, None),
        ("tcp", "127.0.0.1", false, None),
        ("tcp", "::1", false, None),
        ("udp", "127.0.0.1", false, None),
    ] {
        let json = config_with(&format!(
            r#""id": "edge", "protocol": "{protocol}", "address": "{address}", "port": 5514,
            "allowInsecureNonLoopback": {allow}, "allowedSenders": ["127.0.0.1"],
            "routes": [{{"pack": "p", "parser": 0}}]"#
        ));
        match expected {
            None => assert_eq!(config::parse(&json).unwrap().listeners.len(), 1),
            Some(expected) => assert!(invalid(&json).contains(expected), "{protocol} {address}"),
        }
    }
}

#[test]
fn configuration_validates_every_bound() {
    for (overrides, expected) in [
        (
            r#""protocol": "tls", "address": "0.0.0.0""#,
            "tls settings are required for protocol tls",
        ),
        (
            r#""protocol": "tcp", "tls": {"certificateFile": "c", "privateKeyFile": "k"}"#,
            "tls settings are required for protocol tls and not allowed otherwise",
        ),
        (r#""protocol": "sctp""#, "protocol must be tcp, tls or udp"),
        (
            r#""protocol": "tcp", "address": "localhost""#,
            "address must be an IP address",
        ),
        (
            r#""protocol": "tcp", "address": "127.1""#,
            "address must be an IP address",
        ),
        (
            r#""protocol": "tcp", "port": 70000"#,
            "port must be between 0 and 65535",
        ),
        (
            r#""protocol": "tcp", "allowedSenders": []"#,
            "allowedSenders must list 1–64",
        ),
        (
            r#""protocol": "tcp", "allowedSenders": ["10.0.0.1/8"]"#,
            "is not a valid address or CIDR range",
        ),
        (
            r#""protocol": "tcp", "allowedSenders": ["10.0.0.0/33"]"#,
            "is not a valid address or CIDR range",
        ),
        (
            r#""protocol": "tcp", "allowedSenders": ["fe80::1%1"]"#,
            "is not a valid address or CIDR range",
        ),
        (
            r#""protocol": "tcp", "maximumMessageBytes": 65537"#,
            "maximumMessageBytes must be between 480 and 65536",
        ),
        (
            r#""protocol": "tcp", "maximumMessageBytes": 479"#,
            "maximumMessageBytes must be between 480 and 65536",
        ),
        (
            r#""protocol": "tcp", "maximumConnections": 0"#,
            "maximumConnections must be between 1 and 1024",
        ),
        (
            r#""protocol": "tcp", "idleTimeoutSeconds": -1"#,
            "idleTimeoutSeconds must be between 0 and 3600",
        ),
        (
            r#""protocol": "tcp", "idleTimeoutSeconds": 3601"#,
            "idleTimeoutSeconds must be between 0 and 3600",
        ),
        (
            r#""protocol": "tcp", "frameTimeoutSeconds": 0"#,
            "frameTimeoutSeconds must be between 1 and 3600",
        ),
        (
            r#""protocol": "tcp", "frameTimeoutSeconds": 3601"#,
            "frameTimeoutSeconds must be between 1 and 3600",
        ),
        (
            r#""protocol": "tcp", "handshakeStartTimeoutSeconds": 0"#,
            "handshakeStartTimeoutSeconds must be between 1 and 3600",
        ),
        (
            r#""protocol": "tcp", "handshakeStartTimeoutSeconds": 3601"#,
            "handshakeStartTimeoutSeconds must be between 1 and 3600",
        ),
        (
            r#""protocol": "tcp", "routes": []"#,
            "routes must list 1–64 entries",
        ),
        (
            r#""protocol": "tcp", "routes": [{"pack": "", "parser": 0}]"#,
            "each route needs a pack id and a parser index of 0 or more",
        ),
        (
            r#""protocol": "tcp", "routes": [{"pack": "p", "parser": -1}]"#,
            "each route needs a pack id and a parser index of 0 or more",
        ),
        (
            r#""protocol": "tcp", "routes": [{"pack": "p", "parser": 0, "appName": "bad name"}]"#,
            "route hostname and appName must be",
        ),
        (
            r#""protocol": "tcp", "id": "Edge""#,
            "Syslog listener id must be",
        ),
        (
            r#""protocol": "tcp", "unknownSetting": true"#,
            "Syslog source configuration is invalid",
        ),
    ] {
        let mut fields: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{"id": "edge", "address": "127.0.0.1", "port": 5514, "allowedSenders": ["127.0.0.1"], "routes": [{"pack": "p", "parser": 0}]}"#,
        )
        .unwrap();
        let replaced: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&format!("{{{overrides}}}")).unwrap();
        fields.extend(replaced);
        let listener = serde_json::Value::Object(fields).to_string();
        let json = config_with(&listener[1..listener.len() - 1]);
        let message = invalid(&json);
        assert!(message.contains(expected), "{overrides}: {message}");
    }
}

#[test]
fn configuration_rejects_duplicate_listeners_wrong_kind_and_oversized_files() {
    let listener = r#""id": "edge", "protocol": "udp", "port": 5514, "allowedSenders": ["127.0.0.1"], "routes": [{"pack": "p", "parser": 0}]"#;
    let duplicate = format!(
        r#"{{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{{ {listener} }}, {{ {listener} }}]}}"#
    );
    assert!(invalid(&duplicate).contains("is listed more than once"));
    assert!(
        invalid(&config_with(listener).replace("SyslogSource", "Other"))
            .contains("kind SyslogSource")
    );
    assert!(
        invalid(r#"{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": []}"#)
            .contains("1–16 listeners")
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("syslog.json");
    std::fs::write(&path, config_with(listener) + &" ".repeat(262_145)).unwrap();
    assert!(
        matches!(config::load_file(&path), Err(ConfigError::InvalidData(message)) if message.contains("exceeds 256 KiB"))
    );
    assert_eq!(
        config::load_file(directory.path().join("missing.json")).err(),
        Some(ConfigError::FileNotFound)
    );
    let options = &config::parse(&config_with(listener)).unwrap().listeners[0];
    assert_eq!(options.maximum_message_bytes, 65_536);
    assert_eq!(options.maximum_connections, 64);
    assert_eq!(options.idle_timeout_seconds, 0);
    assert_eq!(options.frame_timeout_seconds, 60);
    assert_eq!(options.handshake_start_timeout_seconds, 60);
}

/// `config-vectors.json`, shared with C# `SyslogSourceTests`: non-canonical addresses,
/// wrong-case property names and duplicate keys fail in both runtimes.
#[test]
fn configuration_vectors_fail_closed_like_csharp() {
    let text = std::fs::read_to_string(fixtures().join("config-vectors.json")).unwrap();
    let root: serde_json::Value = serde_json::from_str(&text).unwrap();
    let vectors = root["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 30);
    for vector in vectors {
        let name = string(&vector["name"]);
        let expected = string(&vector["error"]);
        match config::parse(vector["configuration"].as_str().unwrap()) {
            Err(ConfigError::InvalidData(message)) => {
                assert!(message.contains(&expected), "{name}: {message}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn accept_failures_back_off_from_100_milliseconds_to_one_second() {
    let mut current = Duration::ZERO;
    let waits: Vec<u128> = (0..6)
        .map(|_| {
            current = bower_source_syslog::source::next_accept_backoff(current);
            current.as_millis()
        })
        .collect();
    assert_eq!(waits, [100, 200, 400, 800, 1000, 1000]);
}

#[test]
fn routes_match_hostname_and_app_name_in_order() {
    let json = config_with(
        r#""id": "edge", "protocol": "udp", "port": 5514, "allowedSenders": ["127.0.0.0/8", "::1"],
        "routes": [
          {"hostname": "gw01", "appName": "sshd", "pack": "ssh", "parser": 1},
          {"appName": "sshd", "pack": "ssh", "parser": 0},
          {"hostname": "fw01", "pack": "firewall", "parser": 0},
          {"hostname": "core01", "allowedSenders": ["127.0.0.2"], "pack": "core", "parser": 0}
        ]"#,
    );
    let configuration = config::parse(&json).unwrap();
    let listener = &configuration.listeners[0];
    let route_from = |frame: &str, sender: &str| -> Option<Route> {
        let message = parser::parse(frame.as_bytes(), &bower_contracts::time::now()).unwrap();
        listener.route(&message, sender.parse().unwrap()).cloned()
    };
    let route = |frame: &str| route_from(frame, "127.0.0.1");
    // Hostname and app-name are claimed by the sender; a per-route sender restriction pins them.
    assert!(route("<13>1 - core01 kernel - - -").is_none());
    assert_eq!(
        route_from("<13>1 - core01 kernel - - -", "127.0.0.2")
            .unwrap()
            .pack,
        "core"
    );
    assert_eq!(
        route_from("<13>1 - core01 kernel - - -", "::ffff:127.0.0.2")
            .unwrap()
            .pack,
        "core"
    );
    assert_eq!(route("<13>1 - gw01 sshd - - -").unwrap().parser, 1);
    assert_eq!(route("<13>1 - gw02 sshd - - -").unwrap().parser, 0);
    assert_eq!(route("<13>1 - fw01 kernel - - -").unwrap().pack, "firewall");
    assert!(route("<13>1 - fw02 kernel - - -").is_none());
    assert!(route("<13>1 - GW01 SSHD - - -").is_none());
    assert!(listener.allows("127.4.5.6".parse().unwrap()));
    assert!(listener.allows("::ffff:127.0.0.1".parse().unwrap()));
    assert!(listener.allows("::1".parse().unwrap()));
    assert!(!listener.allows("10.0.0.1".parse().unwrap()));
}

#[derive(Default)]
struct FakeSink {
    records: Mutex<Vec<String>>,
    unavailable: AtomicI64,
    attempts: AtomicUsize,
    fail: bool,
    block: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl SyslogSink for FakeSink {
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
        self.records.lock().unwrap().push(record.to_string());
        Ok(SubmitOutcome::Queued)
    }
}

impl FakeSink {
    fn records(&self) -> Vec<String> {
        self.records.lock().unwrap().clone()
    }

    async fn wait_for(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.records.lock().unwrap().len() < count {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("records");
    }
}

fn field(record: &str, name: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(record).unwrap();
    string(&value[name])
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
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("stops promptly")
            .unwrap();
    }
}

struct Options<'a> {
    idle: u32,
    frame: u32,
    handshake_start: u32,
    drain: Duration,
    stop: Duration,
    connections: u32,
    senders: &'a str,
    tls: Option<String>,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            idle: 30,
            frame: 30,
            handshake_start: 60,
            drain: Duration::from_millis(500),
            stop: Duration::from_secs(1),
            connections: 8,
            senders: r#""127.0.0.1", "::1""#,
            tls: None,
        }
    }
}

async fn start(
    protocol: &str,
    sink: Arc<FakeSink>,
    options: Options<'_>,
) -> Result<Running, String> {
    let tls = options
        .tls
        .map(|tls| format!(r#""tls": {tls},"#))
        .unwrap_or_default();
    let json = config_with(&format!(
        r#""id": "edge", "protocol": "{protocol}", "address": "127.0.0.1", "port": 0,
        "allowedSenders": [{}], "maximumMessageBytes": 512,
        "maximumConnections": {}, "idleTimeoutSeconds": {}, "frameTimeoutSeconds": {}, "handshakeStartTimeoutSeconds": {}, {tls}
        "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}}]"#,
        options.senders, options.connections, options.idle, options.frame, options.handshake_start
    ));
    let mut source = SyslogSource::new(config::parse(&json).unwrap(), sink, None)
        .with_retry_delay(Duration::from_millis(20))
        .with_drain_timeout(options.drain)
        .with_stop_timeout(options.stop);
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
    })
}

async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

fn octet(frame: &str) -> String {
    format!("{} {frame}", frame.len())
}

#[tokio::test]
async fn tcp_accepts_both_framings_and_counts_metadata_only() {
    let sink = Arc::new(FakeSink::default());
    let running = start("tcp", Arc::clone(&sink), Options::default())
        .await
        .unwrap();
    let mut client = TcpStream::connect(running.endpoint).await.unwrap();
    let first =
        "<38>1 2026-10-26T08:15:00Z gw01 sshd 1 - [auth@32473 user=\"deploy-admin\"] secret-marker";
    client
        .write_all(
            format!(
                "{}<38>Oct 11 22:14:15 gw01 sshd: line framed\n",
                octet(first)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    sink.wait_for(2).await;
    let records = sink.records();
    assert_eq!(field(&records[0], "appName"), "sshd");
    assert_eq!(field(&records[1], "format"), "rfc3164");
    client
        .write_all(b"<38>Oct 11 22:14:15 gw01 cron: unrouted\n<999>1 - - - - - -\n")
        .await
        .unwrap();
    let status = running
        .wait_for(|status| status.not_routed == 1 && status.malformed == 1)
        .await;
    assert_eq!(status.frames_received, 4);
    assert_eq!(status.queued, 2);
    assert_eq!(status.active_connections, 1);
    let serialized = serde_json::to_string(&running.metrics.snapshot()).unwrap();
    assert!(!serialized.contains("secret-marker") && !serialized.contains("deploy-admin"));
    assert!(serialized.contains("\"framesReceived\":4"));
    running.stop().await;
}

#[tokio::test]
async fn tcp_slowloris_frames_are_closed_by_the_frame_timeout_but_idle_connections_stay_open() {
    let sink = Arc::new(FakeSink::default());
    let running = start(
        "tcp",
        Arc::clone(&sink),
        Options {
            idle: 0,
            frame: 1,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let mut slow = TcpStream::connect(running.endpoint).await.unwrap();
    let trickle = b"<13>1 - - - - - - slow";
    let mut sent = 0;
    for byte in trickle {
        if slow.write_all(&[*byte]).await.is_err() {
            break;
        }
        sent += 1;
        tokio::time::sleep(Duration::from_millis(300)).await;
        if running.status().timeouts == 1 {
            break;
        }
    }
    assert!(
        sent < trickle.len(),
        "connection should close before the trickle completes"
    );
    running
        .wait_for(|status| status.timeouts == 1 && status.active_connections == 0)
        .await;
    // Idle time between frames is not frame time: with idleTimeoutSeconds 0 a quiet sender
    // keeps its connection well past the frame timeout, and its next frame is accepted.
    let mut idle = TcpStream::connect(running.endpoint).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    idle.write_all(b"<38>Oct 11 22:14:15 gw01 sshd: after a quiet spell\n")
        .await
        .unwrap();
    sink.wait_for(1).await;
    let status = running.status();
    assert_eq!(status.timeouts, 1);
    assert_eq!(status.half_closes, 0);
    assert_eq!(status.active_connections, 1);
    running.stop().await;
}

#[tokio::test]
async fn tcp_idle_timeout_half_closes_and_still_accepts_frames_the_sender_already_sent() {
    let sink = Arc::new(FakeSink::default());
    let running = start(
        "tcp",
        Arc::clone(&sink),
        Options {
            idle: 1,
            drain: Duration::from_secs(2),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(running.endpoint).await.unwrap();
    // The listener sends FIN (end of stream), not a reset: the sender can still write.
    assert!(closed(&mut client).await);
    client
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: crossed the close\n")
        .await
        .unwrap();
    sink.wait_for(1).await;
    let status = running.wait_for(|status| status.drained_frames == 1).await;
    assert_eq!(
        (status.timeouts, status.half_closes, status.queued),
        (1, 1, 1)
    );
    client.shutdown().await.unwrap();
    let status = running
        .wait_for(|status| status.active_connections == 0)
        .await;
    assert_eq!(status.peer_resets, 0);
    running.stop().await;
}

#[tokio::test]
async fn tcp_drain_ends_a_quiet_half_closed_connection() {
    let running = start(
        "tcp",
        Arc::new(FakeSink::default()),
        Options {
            idle: 1,
            drain: Duration::from_millis(300),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(running.endpoint).await.unwrap();
    assert!(closed(&mut client).await);
    let status = running
        .wait_for(|status| status.active_connections == 0)
        .await;
    assert_eq!((status.half_closes, status.drained_frames), (1, 0));
    running.stop().await;
}

#[tokio::test]
async fn tcp_a_peer_reset_is_counted() {
    let running = start("tcp", Arc::new(FakeSink::default()), Options::default())
        .await
        .unwrap();
    let client = TcpStream::connect(running.endpoint).await.unwrap();
    running
        .wait_for(|status| status.active_connections == 1)
        .await;
    // Linger 0: close sends RST, as a sender closing with unread data does.
    client.set_zero_linger().unwrap();
    drop(client);
    let status = running
        .wait_for(|status| status.active_connections == 0)
        .await;
    assert_eq!(status.peer_resets, 1);
    running.stop().await;
}

#[tokio::test]
async fn keepalive_is_enabled_with_bower_timing() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    bower_source_syslog::source::configure_keepalive(&stream);
    let socket = socket2::SockRef::from(&stream);
    assert!(socket.keepalive().unwrap());
    assert_eq!(
        socket.tcp_keepalive_time().unwrap(),
        bower_source_syslog::source::KEEPALIVE_TIME
    );
    assert_eq!(
        socket.tcp_keepalive_interval().unwrap(),
        bower_source_syslog::source::KEEPALIVE_INTERVAL
    );
    assert_eq!(
        socket.tcp_keepalive_retries().unwrap(),
        bower_source_syslog::source::KEEPALIVE_PROBES
    );
}

#[tokio::test]
async fn tcp_bad_framing_closes_the_connection_without_submitting() {
    for (input, counter) in [
        ("70000 <13>1 - - - - - -", "oversized"),
        ("12x <13>", "framing"),
        ("hello\n", "framing"),
    ] {
        let sink = Arc::new(FakeSink::default());
        let running = start("tcp", Arc::clone(&sink), Options::default())
            .await
            .unwrap();
        let mut client = TcpStream::connect(running.endpoint).await.unwrap();
        client.write_all(input.as_bytes()).await.unwrap();
        assert!(closed(&mut client).await);
        let status = running
            .wait_for(|status| status.active_connections == 0)
            .await;
        assert_eq!(
            status.oversized,
            i64::from(counter == "oversized"),
            "{input}"
        );
        assert_eq!(
            status.framing_errors,
            i64::from(counter == "framing"),
            "{input}"
        );
        assert!(sink.records().is_empty());
        running.stop().await;
    }
}

#[tokio::test]
async fn tcp_connection_limit_and_sender_allow_list_are_enforced() {
    let sink = Arc::new(FakeSink::default());
    let running = start(
        "tcp",
        Arc::clone(&sink),
        Options {
            connections: 1,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let mut first = TcpStream::connect(running.endpoint).await.unwrap();
    first
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: one\n")
        .await
        .unwrap();
    sink.wait_for(1).await;
    let mut second = TcpStream::connect(running.endpoint).await.unwrap();
    assert!(closed(&mut second).await);
    let status = running
        .wait_for(|status| status.connections_rejected == 1)
        .await;
    assert_eq!(status.connections_accepted, 1);
    running.stop().await;

    let denied = start(
        "tcp",
        Arc::clone(&sink),
        Options {
            senders: r#""192.0.2.0/24""#,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let mut outsider = TcpStream::connect(denied.endpoint).await.unwrap();
    assert!(closed(&mut outsider).await);
    let status = denied.wait_for(|status| status.senders_denied == 1).await;
    assert_eq!(status.connections_accepted, 0);
    denied.stop().await;
}

#[tokio::test]
async fn tcp_queue_backpressure_stops_reading_and_retries_the_same_frame() {
    let sink = Arc::new(FakeSink {
        unavailable: AtomicI64::new(3),
        ..FakeSink::default()
    });
    let running = start("tcp", Arc::clone(&sink), Options::default())
        .await
        .unwrap();
    let mut client = TcpStream::connect(running.endpoint).await.unwrap();
    client
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: first\n<38>Oct 11 22:14:15 gw01 sshd: second\n")
        .await
        .unwrap();
    sink.wait_for(2).await;
    let records = sink.records();
    assert!(field(&records[0], "message").contains("first"));
    assert!(field(&records[1], "message").contains("second"));
    let status = running.status();
    assert_eq!((status.retries, status.dropped, status.queued), (3, 0, 2));
    assert_eq!(sink.attempts.load(Ordering::SeqCst), 5);
    running.stop().await;
}

#[tokio::test]
async fn tcp_sink_failure_closes_the_connection_so_the_sender_sees_it() {
    let sink = Arc::new(FakeSink {
        fail: true,
        ..FakeSink::default()
    });
    let running = start("tcp", Arc::clone(&sink), Options::default())
        .await
        .unwrap();
    let mut client = TcpStream::connect(running.endpoint).await.unwrap();
    client
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: first\n")
        .await
        .unwrap();
    assert!(closed(&mut client).await);
    assert_eq!(
        running
            .wait_for(|status| status.submit_failures == 1)
            .await
            .submit_failures,
        1
    );
    running.stop().await;
}

#[tokio::test]
async fn udp_is_best_effort_and_counts_drops_under_backpressure() {
    let sink = Arc::new(FakeSink {
        unavailable: AtomicI64::new(1),
        ..FakeSink::default()
    });
    let running = start("udp", Arc::clone(&sink), Options::default())
        .await
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(
            b"<38>Oct 11 22:14:15 gw01 sshd: dropped when the queue is full\n",
            running.endpoint,
        )
        .await
        .unwrap();
    client
        .send_to(b"<38>Oct 11 22:14:15 gw01 sshd: accepted", running.endpoint)
        .await
        .unwrap();
    client
        .send_to(
            format!("<38>Oct 11 22:14:15 gw01 sshd: {}", "x".repeat(600)).as_bytes(),
            running.endpoint,
        )
        .await
        .unwrap();
    let status = running
        .wait_for(|status| status.queued == 1 && status.dropped == 1 && status.oversized == 1)
        .await;
    assert_eq!(status.retries, 0);
    assert_eq!(field(&sink.records()[0], "message"), "accepted");

    // A blocked sink fills the bounded datagram queue; further datagrams are dropped.
    let (release, blocked) = std::sync::mpsc::channel();
    *sink.block.lock().unwrap() = Some(blocked);
    for index in 0..UDP_QUEUE_CAPACITY + 64 {
        client
            .send_to(
                format!("<38>Oct 11 22:14:15 gw01 sshd: flood {index}").as_bytes(),
                running.endpoint,
            )
            .await
            .unwrap();
    }
    let status = running.wait_for(|status| status.dropped > 1).await;
    drop(release);
    assert!(status.frames_received <= i64::try_from(UDP_QUEUE_CAPACITY + 64 + 3).unwrap());
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

async fn send_tls(running: &Running, client: Option<&str>, frame: &[u8]) -> std::io::Result<bool> {
    let tcp = TcpStream::connect(running.endpoint).await?;
    let mut stream = tls_client(client)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    stream.write_all(frame).await?;
    stream.flush().await?;
    Ok(closed(&mut stream).await)
}

#[tokio::test]
async fn tls_requires_the_configured_certificate_and_optional_client_certificate() {
    let sink = Arc::new(FakeSink::default());
    let tls = fixtures().join("tls");
    let quote = |name: &str| serde_json::to_string(&tls.join(name).to_string_lossy()).unwrap();
    let server = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}}}"#,
        quote("server.pem"),
        quote("server-key.pem")
    );
    let running = start(
        "tls",
        Arc::clone(&sink),
        Options {
            tls: Some(server.clone()),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    {
        let tcp = TcpStream::connect(running.endpoint).await.unwrap();
        let mut stream = tls_client(None)
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        stream
            .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: over tls\n")
            .await
            .unwrap();
        sink.wait_for(1).await;
        assert_eq!(field(&sink.records()[0], "protocol"), "tls");
    }
    let mut plain = TcpStream::connect(running.endpoint).await.unwrap();
    plain
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: plain\n")
        .await
        .unwrap();
    running
        .wait_for(|status| status.tls_handshake_failures == 1)
        .await;
    assert_eq!(sink.records().len(), 1);
    running.stop().await;

    let mutual = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}, "clientCertificateAuthorityFile": {}}}"#,
        quote("server.pem"),
        quote("server-key.pem"),
        quote("ca.pem")
    );
    let running = start(
        "tls",
        Arc::clone(&sink),
        Options {
            tls: Some(mutual),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    for client in [None, Some("rogue")] {
        // Refused at or right after the handshake; never a frame.
        let _ = send_tls(
            &running,
            client,
            b"<38>Oct 11 22:14:15 gw01 sshd: refused\n",
        )
        .await;
    }
    running
        .wait_for(|status| status.tls_handshake_failures == 2)
        .await;
    let tcp = TcpStream::connect(running.endpoint).await.unwrap();
    let mut stream = tls_client(Some("client"))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: mutual\n")
        .await
        .unwrap();
    sink.wait_for(2).await;
    assert_eq!(field(&sink.records()[1], "message"), "mutual");
    running.stop().await;
}

#[tokio::test]
async fn tls_accepts_a_client_certificate_issued_by_an_intermediate_the_sender_supplies() {
    let sink = Arc::new(FakeSink::default());
    let tls = fixtures().join("tls");
    let quote = |name: &str| serde_json::to_string(&tls.join(name).to_string_lossy()).unwrap();
    let mutual = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}, "clientCertificateAuthorityFile": {}}}"#,
        quote("server.pem"),
        quote("server-key.pem"),
        quote("ca.pem")
    );
    let running = start(
        "tls",
        Arc::clone(&sink),
        Options {
            tls: Some(mutual),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    // chained-client.pem: leaf issued by an intermediate, followed by that intermediate.
    let tcp = TcpStream::connect(running.endpoint).await.unwrap();
    let mut stream = tls_client(Some("chained-client"))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: chained\n")
        .await
        .unwrap();
    sink.wait_for(1).await;
    assert_eq!(field(&sink.records()[0], "message"), "chained");
    assert_eq!(running.status().tls_handshake_failures, 0);
    running.stop().await;
}

#[tokio::test]
async fn tls_unreadable_certificate_stops_start_without_leaking_contents() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key.pem");
    std::fs::write(&key, "not a key").unwrap();
    let path = serde_json::to_string(&key.to_string_lossy()).unwrap();
    let tls = format!(r#"{{"certificateFile": {path}, "privateKeyFile": {path}}}"#);
    let failure = start(
        "tls",
        Arc::new(FakeSink::default()),
        Options {
            tls: Some(tls),
            ..Options::default()
        },
    )
    .await
    .err()
    .unwrap();
    assert!(failure.contains("TLS certificate or key could not be loaded"));
    assert!(!failure.contains("not a key"));
}

#[tokio::test]
async fn stop_cancels_open_connections_and_blocked_submissions_promptly() {
    let sink = Arc::new(FakeSink {
        unavailable: AtomicI64::new(i64::MAX),
        ..FakeSink::default()
    });
    let running = start("tcp", Arc::clone(&sink), Options::default())
        .await
        .unwrap();
    let mut idle = TcpStream::connect(running.endpoint).await.unwrap();
    let mut blocked = TcpStream::connect(running.endpoint).await.unwrap();
    blocked
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: never durable\n")
        .await
        .unwrap();
    running.wait_for(|status| status.retries > 0).await;
    let metrics = running.metrics.clone();
    running.stop().await;
    assert_eq!(metrics.snapshot()[0].queued, 0);
    assert!(closed(&mut idle).await);
}

#[tokio::test]
async fn stop_half_closes_and_enqueues_frames_the_sender_sends_before_it_sees_the_end() {
    let sink = Arc::new(FakeSink::default());
    let running = start(
        "tcp",
        Arc::clone(&sink),
        Options {
            drain: Duration::from_secs(3),
            stop: Duration::from_secs(8),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(running.endpoint).await.unwrap();
    running
        .wait_for(|status| status.active_connections == 1)
        .await;
    let metrics = running.metrics.clone();
    let _ = running.stop.send(true);
    // The sender sees end of stream, but what it writes until then is still accepted.
    assert!(closed(&mut client).await);
    client
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: in flight at stop\n")
        .await
        .unwrap();
    sink.wait_for(1).await;
    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), running.task)
        .await
        .expect("stops within the drain bound")
        .unwrap();
    let status = metrics.snapshot().remove(0);
    assert_eq!(
        (
            status.queued,
            status.half_closes,
            status.drained_frames,
            status.active_connections
        ),
        (1, 1, 1, 0)
    );
}

#[tokio::test]
async fn tls_prehandshake_timeout_releases_exhausted_slot_without_closing_established_idle() {
    let tls_dir = fixtures().join("tls");
    let tls = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}}}"#,
        serde_json::to_string(&tls_dir.join("server.pem")).unwrap(),
        serde_json::to_string(&tls_dir.join("server-key.pem")).unwrap()
    );
    let sink = Arc::new(FakeSink::default());
    let running = start(
        "tls",
        Arc::clone(&sink),
        Options {
            tls: Some(tls),
            idle: 0,
            handshake_start: 1,
            connections: 1,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let _stalled = TcpStream::connect(running.endpoint).await.unwrap();
    running
        .wait_for(|status| status.active_connections == 1)
        .await;
    let _rejected = TcpStream::connect(running.endpoint).await.unwrap();
    running
        .wait_for(|status| status.connections_rejected == 1)
        .await;
    running
        .wait_for(|status| status.timeouts == 1 && status.active_connections == 0)
        .await;
    let tcp = TcpStream::connect(running.endpoint).await.unwrap();
    let mut stream = tls_client(None)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    stream
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: still active\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    sink.wait_for(1).await;
    assert_eq!(running.status().timeouts, 1);
    running.stop().await;
}

#[tokio::test]
async fn tls_a_connection_may_wait_idle_before_its_handshake() {
    let tls_dir = fixtures().join("tls");
    let tls = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}}}"#,
        serde_json::to_string(&tls_dir.join("server.pem")).unwrap(),
        serde_json::to_string(&tls_dir.join("server-key.pem")).unwrap()
    );
    let sink = Arc::new(FakeSink::default());
    let running = start(
        "tls",
        Arc::clone(&sink),
        Options {
            tls: Some(tls),
            idle: 0,
            frame: 1,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    // syslog-ng connects first and starts TLS only when it has a message: that wait is idle
    // time, so it is not cut short by the frame (handshake) timeout or counted as a failure.
    let tcp = TcpStream::connect(running.endpoint).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let mut stream = tls_client(None)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream
        .write_all(b"<38>Oct 11 22:14:15 gw01 sshd: late handshake\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    sink.wait_for(1).await;
    let status = running.status();
    assert_eq!((status.tls_handshake_failures, status.timeouts), (0, 0));
    running.stop().await;
}

#[tokio::test]
async fn tls_listener_sends_no_session_tickets_a_non_reading_sender_would_keep_unread() {
    let tls_dir = fixtures().join("tls");
    let tls = format!(
        r#"{{"certificateFile": {}, "privateKeyFile": {}, "clientCertificateAuthorityFile": {}}}"#,
        serde_json::to_string(&tls_dir.join("server.pem")).unwrap(),
        serde_json::to_string(&tls_dir.join("server-key.pem")).unwrap(),
        serde_json::to_string(&tls_dir.join("ca.pem")).unwrap()
    );
    let running = start(
        "tls",
        Arc::new(FakeSink::default()),
        Options {
            tls: Some(tls),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    let tcp = TcpStream::connect(running.endpoint).await.unwrap();
    let stream = tls_client(Some("client"))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    // rsyslog's pre-send check peeks the TCP socket without reading TLS records. Nothing may
    // be waiting there, or a later FIN from the listener is invisible to it.
    let mut byte = [0u8; 1];
    let pending = tokio::time::timeout(
        Duration::from_millis(500),
        stream.get_ref().0.peek(&mut byte),
    )
    .await;
    assert!(
        pending.is_err(),
        "no bytes may be pending after the handshake"
    );
    running.stop().await;
}
