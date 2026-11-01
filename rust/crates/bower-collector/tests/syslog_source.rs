//! Port of `SyslogCollectorTests`: a frame becomes a durable event only through a signed
//! pack parser, redaction and policy; the queue is the TCP acknowledgement point.

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, header};
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::{CollectorSettings, bundle, shutdown};
use bower_source_syslog::ListenerStatus;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tower::ServiceExt;

const TOKEN: &str = "syslog-collector-test-token-0123456789abcdef";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn syslog_parser(transforms: &[&str], event_type: &str) -> String {
    let field = |name: &str, kind: &str, ocsf: &str, asim: &str, sensitive: bool| serde_json::json!({"sourceName": name, "type": kind, "ocsfPath": ocsf, "asimField": asim, "sensitive": sensitive});
    let mut parser = serde_json::json!({
        "version": "1.0",
        "format": "Json",
        "fields": [
            field("id", "Text", "metadata.uid", "EventOriginalUid", false),
            field("timestamp", "DateTime", "time", "TimeGenerated", false),
            field("appName", "Text", "metadata.product.name", "EventProduct", false),
            field("sd.auth@32473.user", "Text", "actor.user.name", "TargetUsername", true),
            field("sd.auth@32473.src", "IpAddress", "src_endpoint.ip", "SrcIpAddr", false),
            field("sd.auth@32473.result", "Text", "status", "EventResult", false)
        ],
        "runtime": {
            "applicationName": "ssh-gateway",
            "environment": "production",
            "eventCategory": "authentication",
            "eventType": event_type,
            "eventAction": "authentication.attempt",
            "eventResult": "failure",
            "match": {"appName": "sshd", "sd.auth@32473.result": "failure"},
            "fields": {
                "eventId": "id",
                "timeGenerated": "timestamp",
                "actor.username": "sd.auth@32473.user",
                "source.ipAddress": "sd.auth@32473.src"
            }
        }
    });
    if !transforms.is_empty() {
        parser["runtime"]["transforms"] = serde_json::json!(transforms);
    }
    parser.to_string()
}

fn copy_directory(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn settings(directory: &Path, parser: usize, transforms: &[&str]) -> CollectorSettings {
    settings_with_event_type(directory, parser, transforms, "authentication_failure")
}

fn settings_with_event_type(
    directory: &Path,
    parser: usize,
    transforms: &[&str],
    event_type: &str,
) -> CollectorSettings {
    settings_with_options(directory, parser, transforms, event_type, false)
}

fn settings_with_identity_rule(
    directory: &Path,
    parser: usize,
    transforms: &[&str],
    alter_identity: bool,
) -> CollectorSettings {
    settings_with_options(
        directory,
        parser,
        transforms,
        "authentication_failure",
        alter_identity,
    )
}

fn settings_with_options(
    directory: &Path,
    parser: usize,
    transforms: &[&str],
    event_type: &str,
    alter_identity: bool,
) -> CollectorSettings {
    let pack = directory.join("syslog-pack");
    copy_directory(&repo_root().join("packs/linux-ssh-gateway"), &pack);
    std::fs::write(
        pack.join("parsers/sshd-json.json"),
        syslog_parser(transforms, event_type),
    )
    .unwrap();
    // Same test detector as the C# SyslogCollectorTests: it matches every record id.
    let privacy = pack.join("privacy.yaml");
    let mut profile = std::fs::read_to_string(&privacy).unwrap();
    if alter_identity {
        profile = profile.replace(
            "maximumFieldLength:",
            "  - path: eventId\n    action: sha256\nmaximumFieldLength:",
        );
    }
    profile.push_str(
        "customDetectors:\n  - id: custom.hex-digest\n    description: Test detector for 32-character lowercase hex values.\n    pattern: '[0-9a-f]{32}'\n    action: mask\n    tests:\n      match: ['0123456789abcdef0123456789abcdef']\n",
    );
    std::fs::write(&privacy, profile).unwrap();
    let samples = pack.join("samples/ssh.jsonl");
    let kept: Vec<String> = std::fs::read_to_string(&samples)
        .unwrap()
        .lines()
        .filter(|line| !line.contains("\"raw\":"))
        .map(str::to_string)
        .collect();
    std::fs::write(&samples, kept.join("\n") + "\n").unwrap();
    let keys = bower_integrity::generate_key_pair();
    let archive = bower_packs::build(&pack, &keys.private_key_pem, directory, None).unwrap();
    let trust = directory.join("trusted.pem");
    std::fs::write(&trust, keys.public_key_pem).unwrap();
    let hmac = directory.join("hmac.key");
    std::fs::write(&hmac, [0u8; 32]).unwrap();
    let syslog = directory.join("syslog.json");
    std::fs::write(
        &syslog,
        format!(
            r#"{{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [
              {{"id": "edge", "protocol": "tcp", "port": 0, "allowedSenders": ["127.0.0.1"],
               "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": {parser}}}]}},
              {{"id": "edge-udp", "protocol": "udp", "port": 0, "allowedSenders": ["127.0.0.1"],
               "routes": [{{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": {parser}}}]}}
            ]}}"#
        ),
    )
    .unwrap();
    let expectations = directory.join("expectations.json");
    std::fs::write(
        &expectations,
        r#"{"apiVersion": "bower.security/v1", "kind": "SourceExpectations",
         "sources": [{"application": "ssh-gateway", "environment": "production", "maximumSilenceMinutes": 5}]}"#,
    )
    .unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        directory.join("no-defaults"),
        "syslog-collector-test",
    );
    settings.packs = vec![archive.to_string_lossy().into_owned()];
    settings.pack_trusted_key_files = vec![trust.to_string_lossy().into_owned()];
    settings.privacy_hmac_key_file = Some(hmac);
    settings.maximum_queue_bytes = 1_048_576;
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    settings.syslog_config_path = Some(syslog);
    settings.source_expectations_path = Some(expectations);
    settings
}

struct Started {
    collector_router: axum::Router,
    store: std::sync::Arc<dyn bower_contracts::DurableEventStore>,
    endpoints: std::collections::HashMap<String, std::net::SocketAddr>,
    trigger: shutdown::ShutdownTrigger,
    task: tokio::task::JoinHandle<()>,
}

impl Started {
    async fn status(&self) -> serde_json::Value {
        let request = Request::get("/v1/status")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let response = self
            .collector_router
            .clone()
            .oneshot(request)
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn listener(
        &self,
        id: &str,
        condition: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let status = self.status().await;
                let listener = status["syslog"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|listener| listener["id"] == id)
                    .unwrap()
                    .clone();
                if condition(&listener) {
                    return listener;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("syslog status condition")
    }

    async fn stop(self) {
        self.trigger.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

async fn start(directory: &Path) -> Started {
    start_with(directory, &[]).await
}

async fn start_with(directory: &Path, transforms: &[&str]) -> Started {
    let settings = settings(directory, 0, transforms);
    start_settings(settings).await
}

async fn start_settings(settings: CollectorSettings) -> Started {
    let mut collector: Collector = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    collector.set_syslog_retry_delay(Duration::from_millis(50));
    collector.initialize().await.unwrap();
    let endpoints = collector.syslog_endpoints();
    let (collector_router, store) = (collector.router.clone(), collector.store.clone());
    let (trigger, token) = shutdown::channel();
    let task = tokio::spawn(collector.run(Vec::new(), token));
    Started {
        collector_router,
        store,
        endpoints,
        trigger,
        task,
    }
}

fn frame(result: &str, user: &str) -> String {
    let now = bower_contracts::time::now()
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H:%M:%S%.6fZ");
    let frame = format!(
        "<38>1 {now} gw01 sshd 4242 auth [auth@32473 user=\"{user}\" src=\"203.0.113.5\" result=\"{result}\"] Failed password secret-marker"
    );
    format!("{} {frame}", frame.len())
}

fn count(listener: &serde_json::Value, name: &str) -> i64 {
    listener[name].as_i64().unwrap()
}

#[tokio::test]
async fn signed_syslog_parser_cannot_submit_reserved_health_events() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings_with_event_type(directory.path(), 0, &[], "collector_health");
    let started = start_settings(settings).await;
    let mut client = TcpStream::connect(started.endpoints["edge"]).await.unwrap();
    client
        .write_all(frame("failure", "forged-health-source").as_bytes())
        .await
        .unwrap();
    started
        .listener("edge", |listener| count(listener, "rejected") == 1)
        .await;
    assert_eq!(started.store.snapshot().unwrap().queued, 0);
    started.stop().await;
}

#[tokio::test]
async fn selected_frame_is_redacted_durably_queued_deduplicated_and_keeps_the_source_active() {
    let directory = tempfile::tempdir().unwrap();
    let started = start(directory.path()).await;
    let mut client = TcpStream::connect(started.endpoints["edge"]).await.unwrap();
    let selected = frame("failure", "deploy-admin");
    client.write_all(selected.as_bytes()).await.unwrap();
    started
        .listener("edge", |listener| count(listener, "queued") == 1)
        .await;
    // The frame is acknowledged only once durable: the queue already holds it.
    assert_eq!(started.store.snapshot().unwrap().queued, 1);

    client.write_all(selected.as_bytes()).await.unwrap();
    client
        .write_all(frame("success", "deploy-admin").as_bytes())
        .await
        .unwrap();
    client
        .write_all(b"<38>Oct 11 22:14:15 gw01 cron: unrouted secret-marker\n")
        .await
        .unwrap();
    let listener = started
        .listener("edge", |listener| {
            count(listener, "duplicates") == 1
                && count(listener, "notSelected") == 1
                && count(listener, "notRouted") == 1
        })
        .await;
    assert_eq!(count(&listener, "framesReceived"), 4);

    let rows = started.store.lease(10, Duration::from_secs(60)).unwrap();
    let [row] = rows.as_slice() else {
        panic!("expected one queued syslog event")
    };
    let stored: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
    assert_eq!(stored["eventType"], "authentication_failure");
    assert_eq!(
        stored["collector"]["sourceAdapter"],
        "syslog:edge:linux-ssh-gateway:0"
    );
    assert_eq!(stored["source"]["ipAddress"], "203.0.113.5");
    assert!(row.event_id.starts_with("syslog-"));
    assert!(!row.payload.contains("deploy-admin") && !row.payload.contains("secret-marker"));
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("queue.db")
        {
            let bytes = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
            assert!(!bytes.contains("deploy-admin") && !bytes.contains("secret-marker"));
        }
    }

    let status = started.status().await;
    let text = status.to_string();
    assert!(!text.contains("deploy-admin") && !text.contains("secret-marker"));
    let sources = status["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["application"], "ssh-gateway");
    assert_eq!(sources[0]["state"], "active");
    assert!(!sources[0]["lastSeenAt"].is_null());
    started.stop().await;
}

#[tokio::test]
async fn generated_event_id_skips_content_detectors_while_the_same_value_from_a_producer_is_scanned()
 {
    let directory = tempfile::tempdir().unwrap();
    let started = start(directory.path()).await;
    // The test pack's privacy profile adds a custom detector for 32-character hex values,
    // as operators do for generic API keys: it matches every record id.
    let counted = frame("failure", "lab-user-1");
    let payload = counted.split_once(' ').unwrap().1.to_owned();
    let id = bower_source_syslog::record::event_id("edge", "127.0.0.1", payload.as_bytes(), None);

    let mut client = TcpStream::connect(started.endpoints["edge"]).await.unwrap();
    client.write_all(counted.as_bytes()).await.unwrap();
    started
        .listener("edge", |listener| count(listener, "queued") == 1)
        .await;
    let rows = started.store.lease(10, Duration::from_secs(60)).unwrap();
    let [row] = rows.as_slice() else {
        panic!("expected one queued syslog event")
    };
    let stored: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
    assert_eq!(row.event_id, id);
    assert_eq!(stored["eventId"], id.as_str());
    assert_eq!(stored["eventOriginalId"], id.as_str());
    assert!(!row.payload.contains("custom.hex-digest"));
    // Source text in the same record is still redacted.
    assert!(!row.payload.contains("secret-marker") && !row.payload.contains("lab-user-"));

    // The same characters sent by a producer are source data: still scanned and masked.
    let event = serde_json::json!({
        "schemaVersion": "1.0.0", "eventId": id, "timeGenerated": stored["timeGenerated"],
        "eventCategory": "authentication", "eventType": "authentication_failure",
        "eventAction": "authentication.attempt", "eventResult": "failure",
        "application": { "name": "ssh-gateway", "environment": "production" },
        "actor": { "username": "producer" }
    });
    let request = Request::post("/v1/events")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(event.to_string()))
        .unwrap();
    let response = started
        .collector_router
        .clone()
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        answer,
        serde_json::json!({
            "eventId": null, "decision": "quarantine", "queued": false,
            "duplicate": false, "reasons": ["event-id-redacted"], "policy": null
        })
    );
    assert!(!body.windows(id.len()).any(|window| window == id.as_bytes()));
    assert_eq!(started.store.snapshot().unwrap().queued, 0);
    started.stop().await;
}

#[tokio::test]
async fn altered_identity_holds_tcp_frames_and_counts_udp_loss() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings_with_identity_rule(directory.path(), 0, &[], true);
    let started = start_settings(settings).await;
    let selected = frame("failure", "lab-user");
    let mut client = TcpStream::connect(started.endpoints["edge"]).await.unwrap();
    client.write_all(selected.as_bytes()).await.unwrap();
    started
        .listener("edge", |listener| count(listener, "retries") > 0)
        .await;
    assert_eq!(started.store.snapshot().unwrap().queued, 0);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let datagram = selected.split_once(' ').unwrap().1;
    udp.send_to(datagram.as_bytes(), started.endpoints["edge-udp"])
        .await
        .unwrap();
    started
        .listener("edge-udp", |listener| count(listener, "dropped") > 0)
        .await;
    assert_eq!(started.store.snapshot().unwrap().queued, 0);
    // The same signed-pack detection wrapper must not hide an altered identity
    // from HTTP callers either.
    let event = serde_json::json!({
        "schemaVersion": "1.0.0", "eventId": "source-identity-sensitive",
        "timeGenerated": bower_contracts::time::now().to_rfc3339(),
        "eventCategory": "authentication", "eventType": "authentication_failure",
        "eventAction": "authentication.attempt", "eventResult": "failure",
        "application": { "name": "ssh-gateway", "environment": "production" }
    });
    let response = started
        .collector_router
        .clone()
        .oneshot(
            Request::post("/v1/events")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(event.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["reasons"],
        serde_json::json!(["event-id-redacted"])
    );
    assert!(!String::from_utf8_lossy(&body).contains("source-identity-sensitive"));
    assert_eq!(started.store.snapshot().unwrap().queued, 0);
    started.stop().await;
}

#[tokio::test]
async fn full_queue_stops_tcp_until_space_is_freed_and_drops_udp() {
    let directory = tempfile::tempdir().unwrap();
    let started = start(directory.path()).await;
    started
        .store
        .enqueue(&bower_contracts::QueuedEvent {
            lease_token: None,
            event_id: "filler".into(),
            fingerprint: "sha256:filler".into(),
            payload: "x".repeat(1_048_000),
            received_at: bower_contracts::time::now(),
            state: bower_contracts::QueueState::Queued,
            delivery_attempts: 0,
            suppression: None,
        })
        .unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let datagram = frame("failure", "udp-user");
    let datagram = datagram.split_once(' ').unwrap().1;
    udp.send_to(datagram.as_bytes(), started.endpoints["edge-udp"])
        .await
        .unwrap();
    started
        .listener("edge-udp", |listener| count(listener, "dropped") == 1)
        .await;

    let mut client = TcpStream::connect(started.endpoints["edge"]).await.unwrap();
    client
        .write_all(frame("failure", "deploy-admin").as_bytes())
        .await
        .unwrap();
    started
        .listener("edge", |listener| count(listener, "retries") >= 2)
        .await;
    assert_eq!(
        count(&started.listener("edge", |_| true).await, "queued"),
        0
    );
    let rows = started.store.lease(10, Duration::from_secs(60)).unwrap();
    assert_eq!(rows[0].event_id, "filler");
    started
        .store
        .mark_delivered("filler", "test-ack", rows[0].lease_token.as_deref())
        .unwrap();
    started
        .listener("edge", |listener| count(listener, "queued") == 1)
        .await;
    let rows = started.store.lease(10, Duration::from_secs(60)).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].event_id.starts_with("syslog-"));
    started.stop().await;
}

#[tokio::test]
async fn transform_failure_quarantines_without_persisting_and_keeps_the_connection_open() {
    let directory = tempfile::tempdir().unwrap();
    // A string condition is a run-time type error for every sshd frame.
    let started = start_with(directory.path(), &[r#"if .appName { .appName = "sshd" }"#]).await;
    let mut client = TcpStream::connect(started.endpoints["edge"]).await.unwrap();
    client
        .write_all(frame("failure", "deploy-admin").as_bytes())
        .await
        .unwrap();
    client
        .write_all(frame("failure", "second-user").as_bytes())
        .await
        .unwrap();
    // The connection stays open: a deterministic per-record failure is not a sink failure.
    let listener = started
        .listener("edge", |listener| count(listener, "rejected") == 2)
        .await;
    assert_eq!(count(&listener, "submitFailures"), 0);
    assert_eq!(count(&listener, "queued"), 0);
    assert_eq!(started.store.snapshot().unwrap().queued, 0);

    let status = started.status().await;
    let rows = status["pipeline"]["rows"].as_array().unwrap();
    let transform: Vec<_> = rows
        .iter()
        .filter(|row| row["stage"] == "transform")
        .collect();
    let [row] = transform.as_slice() else {
        panic!("expected one transform row")
    };
    assert_eq!(row["action"], "quarantine");
    assert_eq!(row["events"], 2);
    let body = status.to_string();
    assert!(!body.contains("deploy-admin"));
    assert!(!body.contains("secret-marker"));
    started.stop().await;
}

#[test]
fn unknown_or_inactive_route_parser_stops_start_up() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings(directory.path(), 7, &[]);
    let error = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, "InvalidOperationException");
    assert!(
        error
            .message
            .contains("route pack linux-ssh-gateway parser 7 is not an active parser")
    );
}

#[test]
fn settings_read_syslog_config_and_change_the_configuration_hash() {
    let read = |syslog: bool| {
        CollectorSettings::from_environment(|name| match name {
            "BOWER_COLLECTOR_ID" => Some("syslog-settings".into()),
            "BOWER_QUEUE_PATH" => Some("/tmp/bower-syslog-settings.db".into()),
            "BOWER_SYSLOG_CONFIG" if syslog => Some("/etc/bower/syslog.json".into()),
            _ => None,
        })
        .unwrap()
    };
    let (without, with) = (read(false), read(true));
    assert_eq!(without.syslog_config_path, None);
    assert_eq!(
        with.syslog_config_path.as_deref(),
        Some(Path::new("/etc/bower/syslog.json"))
    );
    assert_ne!(without.configuration_hash(), with.configuration_hash());
    // Pinned in C# `SyslogCollectorTests` too: both runtimes report the same hash.
    assert_eq!(
        with.configuration_hash(),
        "sha256:217176a1055394e50f32c294b934ba760dfeac3097cf12b15ac208bf05208ad1"
    );
}

/// The status body carries the syslog counters with C# property names.
#[test]
fn listener_status_serializes_with_csharp_names() {
    let status = ListenerStatus {
        id: "edge".into(),
        protocol: "tcp".into(),
        endpoint: "127.0.0.1:5514".into(),
        active_connections: 0,
        connections_accepted: 0,
        connections_rejected: 0,
        senders_denied: 0,
        tls_handshake_failures: 0,
        frames_received: 0,
        bytes_received: 0,
        queued: 0,
        duplicates: 0,
        suppressed: 0,
        not_routed: 0,
        not_selected: 0,
        rejected: 0,
        parser_errors: 0,
        malformed: 0,
        oversized: 0,
        framing_errors: 0,
        timeouts: 0,
        dropped: 0,
        retries: 0,
        submit_failures: 0,
        receive_errors: 0,
        last_frame_at: None,
        tls_reloads: 0,
        tls_reload_failures: 0,
        tls_revoked: 0,
        tls_sessions_closed: 0,
        server_certificate_not_after: None,
        client_certificate_authority_not_after: None,
        client_revocation_list_next_update: None,
    };
    assert_eq!(
        serde_json::to_string(&status).unwrap(),
        r#"{"id":"edge","protocol":"tcp","endpoint":"127.0.0.1:5514","activeConnections":0,"connectionsAccepted":0,"connectionsRejected":0,"sendersDenied":0,"tlsHandshakeFailures":0,"framesReceived":0,"bytesReceived":0,"queued":0,"duplicates":0,"suppressed":0,"notRouted":0,"notSelected":0,"rejected":0,"parserErrors":0,"malformed":0,"oversized":0,"framingErrors":0,"timeouts":0,"dropped":0,"retries":0,"submitFailures":0,"receiveErrors":0,"lastFrameAt":null,"tlsReloads":0,"tlsReloadFailures":0,"tlsRevoked":0,"tlsSessionsClosed":0,"serverCertificateNotAfter":null,"clientCertificateAuthorityNotAfter":null,"clientRevocationListNextUpdate":null}"#
    );
}
