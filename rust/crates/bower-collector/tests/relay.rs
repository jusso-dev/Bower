//! Relay role and relay output (issue #110). Port of C# `RelayUnitTests` and
//! `RelayEndToEndTests`: settings, pins, intake, the downstream client, and a downstream
//! collector, relay and destination in one process over real mutual TLS. Test
//! certificates are generated per run (short-lived, so Apple's verifier accepts them);
//! no private key is committed.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bower_collector::heartbeat::{AccessTokenSource, TokenFuture};
use bower_collector::host::{self, BoxedOutput, BuildOptions};
use bower_collector::relay::client::RelayTls;
use bower_collector::relay::downstreams::{MAXIMUM_ENTRIES, RelayDownstreams};
use bower_collector::relay::intake::{RelayIntake, RelayIntakeOutcome};
use bower_collector::relay::output::RelayOutput;
use bower_collector::relay::protocol;
use bower_collector::relay::telemetry::RelayTelemetry;
use bower_collector::worker::QueueDeliveryOptions;
use bower_collector::{CollectorSettings, bundle, server, shutdown};
use bower_contracts::time::SystemClock;
use bower_contracts::{
    CollectorContext, DecisionAction, DeliveryResult, DurableEventStore, OutputAdapter,
    QueuedEvent, SecurityDecisionContext, SecurityEventEnvelope,
};
use bower_persistence::SqliteEventStore;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use reqwest::Url;
use tower::ServiceExt;

const QUEUED: i64 = 0;
const DELIVERED: i64 = 3;

// ------------------------------------------------------------------ certificates

/// Validity from `from_days` to `to_days` relative to today (calendar days, UTC).
fn validity(params: &mut CertificateParams, from_days: i64, to_days: i64) {
    use chrono::Datelike as _;
    let day = |offset: i64| {
        let date = (chrono::Utc::now() + chrono::Duration::days(offset)).date_naive();
        rcgen::date_time_ymd(
            date.year(),
            u8::try_from(date.month()).unwrap(),
            u8::try_from(date.day()).unwrap(),
        )
    };
    params.not_before = day(from_days);
    params.not_after = day(to_days);
}

struct Pki {
    directory: PathBuf,
    ca_bundle: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
}

#[derive(Clone)]
struct Client {
    certificate: PathBuf,
    key: PathBuf,
    pin: String,
}

impl Pki {
    fn new(directory: &Path) -> Self {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.distinguished_name
            .push(DnType::CommonName, "Bower Relay Test CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        validity(&mut ca, -1, 30);
        let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
        let ca_bundle = directory.join("relay-ca.pem");
        std::fs::write(&ca_bundle, ca.pem()).unwrap();

        let key = KeyPair::generate().unwrap();
        let mut server =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        server
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        validity(&mut server, -1, 7);
        let certificate = server.signed_by(&key, &ca).unwrap();
        let server_certificate = directory.join("relay-server.crt.pem");
        let server_key = directory.join("relay-server.key.pem");
        std::fs::write(&server_certificate, certificate.pem()).unwrap();
        std::fs::write(&server_key, key.serialize_pem()).unwrap();
        Self {
            directory: directory.to_path_buf(),
            ca_bundle,
            server_certificate,
            server_key,
        }
    }

    /// A self-signed client certificate valid `from_days..to_days` around today.
    fn client(
        &self,
        name: &str,
        from_days: i64,
        to_days: i64,
        usage: ExtendedKeyUsagePurpose,
    ) -> Client {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = vec![usage];
        validity(&mut params, from_days, to_days);
        let certificate = params.self_signed(&key).unwrap();
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let certificate_file = self
            .directory
            .join(format!("client-{name}-{unique}.crt.pem"));
        let key_file = self
            .directory
            .join(format!("client-{name}-{unique}.key.pem"));
        std::fs::write(&certificate_file, certificate.pem()).unwrap();
        std::fs::write(&key_file, key.serialize_pem()).unwrap();
        Client {
            certificate: certificate_file,
            key: key_file,
            pin: bower_collector::relay::certificates::pin(certificate.der()),
        }
    }

    fn valid_client(&self, name: &str) -> Client {
        self.client(name, -1, 7, ExtendedKeyUsagePurpose::ClientAuth)
    }

    fn downstreams(&self, entries: &[(&str, &str)]) -> PathBuf {
        let path = self.directory.join(format!(
            "downstreams-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        let entries: Vec<_> = entries
            .iter()
            .map(|(id, pin)| serde_json::json!({"collectorId": id, "certificateSha256": pin}))
            .collect();
        std::fs::write(
            &path,
            serde_json::json!({"downstreams": entries}).to_string(),
        )
        .unwrap();
        path
    }
}

// ------------------------------------------------------------------ hosts

fn policies() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../policies/default")
}

fn relay_settings(directory: &Path, pki: &Pki, downstreams: &Path, port: u16) -> CollectorSettings {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("relay").join("queue.db"),
        policies(),
        "relay-01",
    );
    settings.single_trust_domain = true;
    settings.relay_listen_url = Some(Url::parse(&format!("https://127.0.0.1:{port}")).unwrap());
    settings.relay_certificate_file = Some(pki.server_certificate.clone());
    settings.relay_key_file = Some(pki.server_key.clone());
    settings.relay_downstreams_file = Some(downstreams.to_path_buf());
    settings
}

fn downstream_settings(
    directory: &Path,
    pki: &Pki,
    client: &Client,
    relay_port: u16,
    collector_id: &str,
) -> CollectorSettings {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join(collector_id).join("queue.db"),
        policies(),
        collector_id,
    );
    settings.single_trust_domain = true;
    settings.output_type = "relay".into();
    settings.relay_url = Some(Url::parse(&format!("https://localhost:{relay_port}")).unwrap());
    settings.relay_client_certificate_file = Some(client.certificate.clone());
    settings.relay_client_key_file = Some(client.key.clone());
    settings.relay_ca_bundle = Some(pki.ca_bundle.clone());
    settings
}

struct StaticCredential;

impl AccessTokenSource for StaticCredential {
    fn access_token<'a>(&'a self, _: &'a str) -> TokenFuture<'a> {
        Box::pin(async { Ok("test-management-token".to_string()) })
    }
}

/// Destination double for the relay: records every delivered payload.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<QueuedEvent>>>);

impl Capture {
    fn delivered(&self) -> Vec<QueuedEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl OutputAdapter for Capture {
    fn id(&self) -> &str {
        "capture"
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        self.0.lock().unwrap().extend(events.iter().cloned());
        DeliveryResult {
            acknowledged_event_ids: events.iter().map(|item| item.event_id.clone()).collect(),
            failures: Vec::new(),
            destination_acknowledgement: Some("capture:accepted".into()),
        }
    }
}

struct Running {
    router: Router,
    relay: Vec<SocketAddr>,
    trigger: shutdown::ShutdownTrigger,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    fn relay_port(&self) -> u16 {
        self.relay[0].port()
    }

    async fn stop(self) {
        self.trigger.cancel();
        self.task.await.unwrap();
    }
}

async fn start(settings: CollectorSettings, output: Option<BoxedOutput>) -> Running {
    let bundle = bundle::load(&settings).unwrap();
    let mut collector = host::build(
        settings,
        bundle,
        BuildOptions {
            output,
            credential: Some(Arc::new(StaticCredential)),
            delivery: Some(QueueDeliveryOptions {
                idle_delay: Duration::from_millis(50),
                ..QueueDeliveryOptions::default()
            }),
            ..BuildOptions::default()
        },
    )
    .unwrap();
    collector.initialize().await.unwrap();
    let relay = collector.relay_addresses();
    let router = collector.router.clone();
    let listeners = server::bind(&[SocketAddr::from(([127, 0, 0, 1], 0))])
        .await
        .unwrap();
    let (trigger, token) = shutdown::channel();
    let task = tokio::spawn(collector.run(listeners, token));
    Running {
        router,
        relay,
        trigger,
        task,
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    for _ in 0..600 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not met in time");
}

fn rows(queue: &Path) -> Vec<(String, i64, Option<String>, String)> {
    let connection =
        rusqlite::Connection::open_with_flags(queue, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = connection
        .prepare("SELECT event_id, state, acknowledgement, payload FROM queue_events_v5 ORDER BY event_id;")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn ledger_hashes(queue: &Path) -> std::collections::HashMap<String, String> {
    let connection =
        rusqlite::Connection::open_with_flags(queue, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = connection
        .prepare("SELECT event_id, payload_sha256 FROM queue_ledger;")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn ledger_intact(queue: &Path) -> bool {
    SqliteEventStore::new(queue, 1024 * 1024 * 1024, None)
        .unwrap()
        .verify_ledger()
        .unwrap()
        .intact
}

fn authentication_failure(event_id: &str) -> SecurityEventEnvelope {
    let now = bower_contracts::time::format_json(&bower_contracts::time::now());
    let json = format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"{event_id}","eventOriginalId":"source-{event_id}","timeGenerated":"{now}",
        "eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt",
        "eventResult":"failure","eventOutcomeReason":"InvalidPassword",
        "application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"test-user"}},
        "source":{{"ipAddress":"192.0.2.10"}},"request":{{"correlationId":"correlation-1"}}}}"#
    );
    serde_json::from_str(&json).unwrap()
}

/// An envelope as a downstream collector queues it: decided, collector-stamped, fingerprinted.
fn arranged(
    event_id: &str,
    collector_id: &str,
    decided: bool,
    padding: Option<&str>,
) -> (String, String) {
    let mut envelope = authentication_failure(event_id);
    envelope.security = decided.then(|| SecurityDecisionContext {
        policy_id: "BWR-POL-AUTH-FAILURE".into(),
        policy_version: "1.0.0".into(),
        policy_hash: "sha256:test".into(),
        value_score: 80,
        decision: DecisionAction::Accept,
        classification_reasons: vec!["authentication-failure".into()],
    });
    envelope.collector = Some(CollectorContext {
        id: collector_id.into(),
        version: "0.1.0".into(),
        source_adapter: "local-http:anonymous".into(),
        configuration_hash: "sha256:test".into(),
        batch_id: None,
        received_at: bower_contracts::time::now(),
    });
    envelope.attributes = padding.map(|padding| {
        [(
            "padding".to_string(),
            bower_contracts::JsonElement::from(padding),
        )]
        .into_iter()
        .collect()
    });
    (
        bower_contracts::json::to_string(&envelope).unwrap(),
        bower_persistence::event_identity(&envelope),
    )
}

fn batch(collector_id: &str, events: &[(String, String, String)]) -> Vec<u8> {
    let items: Vec<String> = events
        .iter()
        .map(|(id, fingerprint, payload)| {
            format!(
                r#"{{"eventId":{},"fingerprint":{},"payload":{payload}}}"#,
                serde_json::to_string(id).unwrap(),
                serde_json::to_string(fingerprint).unwrap()
            )
        })
        .collect();
    format!(
        r#"{{"schemaVersion":1,"collectorId":{},"events":[{}]}}"#,
        serde_json::to_string(collector_id).unwrap(),
        items.join(",")
    )
    .into_bytes()
}

fn queued(event_id: &str, fingerprint: &str, payload: &str) -> QueuedEvent {
    QueuedEvent {
        event_id: event_id.into(),
        fingerprint: fingerprint.into(),
        payload: payload.into(),
        received_at: bower_contracts::time::now(),
        state: bower_contracts::QueueState::Queued,
        delivery_attempts: 0,
        lease_token: None,
        suppression: None,
    }
}

fn relay_output(settings: &CollectorSettings) -> RelayOutput {
    let tls = RelayTls::from_settings(settings).unwrap();
    RelayOutput::new(
        tls.batch_client().unwrap(),
        tls.relay_url(),
        settings.collector_id.clone(),
    )
}

// ------------------------------------------------------------------ settings

fn base() -> CollectorSettings {
    CollectorSettings::new("http://127.0.0.1:4319", "queue.db", "policies", "edge-01")
}

fn url(value: &str) -> Option<Url> {
    Some(Url::parse(value).unwrap())
}

/// C# `Settings_ValidateDownstreamRole`.
#[test]
fn settings_validate_downstream_role() {
    let mut downstream = base();
    downstream.output_type = "relay".into();
    downstream.relay_url = url("https://relay.example.test:4443");
    downstream.relay_client_certificate_file = Some("client.crt".into());
    downstream.relay_client_key_file = Some("client.key".into());
    downstream.validate().unwrap();
    let with = |change: &dyn Fn(&mut CollectorSettings)| {
        let mut settings = downstream.clone();
        change(&mut settings);
        settings.validate()
    };
    with(&|settings| settings.relay_ca_bundle = Some("ca.pem".into())).unwrap();
    assert!(with(&|settings| settings.relay_url = None).is_err());
    assert!(with(&|settings| settings.relay_url = url("http://relay.example.test:4443")).is_err());
    assert!(
        with(&|settings| settings.relay_url = url("https://relay.example.test:4443/path")).is_err()
    );
    let credentials = with(&|settings| {
        settings.relay_url = url("https://user:hunter2@relay.example.test:4443");
    })
    .unwrap_err();
    assert!(!credentials.message.contains("hunter2"));
    assert!(with(&|settings| settings.relay_client_key_file = None).is_err());
    let mut stray = base();
    stray.relay_ca_bundle = Some("ca.pem".into());
    assert!(stray.validate().is_err());

    let mut managed = downstream.clone();
    managed.management_endpoint = url("https://management.example.test");
    managed.management_authentication = "enrolment".into();
    managed.management_via_relay = true;
    managed.validate().unwrap();
    let mut entra = managed.clone();
    entra.management_authentication = "entra".into();
    entra.management_scope = Some("api://bower/.default".into());
    assert_eq!(
        entra.validate().unwrap_err().message,
        "BOWER_MANAGEMENT_VIA_RELAY requires BOWER_MANAGEMENT_AUTH=enrolment."
    );
    let mut proxied = managed.clone();
    proxied.management_proxy = url("http://proxy:3128");
    assert!(proxied.validate().is_err());
    let mut no_output = managed.clone();
    no_output.output_type = "none".into();
    no_output.relay_url = None;
    no_output.relay_client_certificate_file = None;
    no_output.relay_client_key_file = None;
    assert!(no_output.validate().is_err());
}

/// C# `Settings_ValidateRelayRole`.
#[test]
fn settings_validate_relay_role() {
    let mut relay = base();
    relay.relay_listen_url = url("https://0.0.0.0:4443");
    relay.relay_certificate_file = Some("relay.crt".into());
    relay.relay_key_file = Some("relay.key".into());
    relay.relay_downstreams_file = Some("downstreams.json".into());
    relay.validate().unwrap();
    assert!(relay.is_relay());
    let with = |change: &dyn Fn(&mut CollectorSettings)| {
        let mut settings = relay.clone();
        change(&mut settings);
        settings.validate()
    };
    assert!(with(&|settings| settings.relay_downstreams_file = None).is_err());
    assert!(with(&|settings| settings.relay_listen_url = url("http://0.0.0.0:4443")).is_err());
    assert!(with(&|settings| settings.relay_listen_url = url("https://0.0.0.0")).is_err());
    assert!(with(&|settings| settings.relay_listen_url = url("https://0.0.0.0:443")).is_err());
    let mut stray = base();
    stray.relay_downstreams_file = Some("downstreams.json".into());
    assert!(stray.validate().is_err());
    // One hop: a relay never delivers to another relay.
    assert_eq!(
        with(&|settings| {
            settings.output_type = "relay".into();
            settings.relay_url = url("https://upstream.example.test:4443");
            settings.relay_client_certificate_file = Some("c".into());
            settings.relay_client_key_file = Some("k".into());
        })
        .unwrap_err()
        .message,
        "A relay cannot use BOWER_OUTPUT=relay: relays deliver to the destination, one hop only."
    );
    assert!(with(&|settings| settings.relay_management_tunnel = true).is_err());
    let mut tunnel = relay.clone();
    tunnel.relay_management_tunnel = true;
    tunnel.management_endpoint = url("https://management.example.test");
    tunnel.management_scope = Some("api://bower/.default".into());
    tunnel.validate().unwrap();
    tunnel.management_proxy = url("http://proxy:3128");
    assert!(tunnel.validate().is_err());

    let strict = CollectorSettings::from_environment(|name| {
        (name == "BOWER_RELAY_MANAGEMENT_TUNNEL").then(|| "yes".to_string())
    })
    .unwrap_err();
    assert_eq!(
        strict.message,
        "BOWER_RELAY_MANAGEMENT_TUNNEL must be true or false."
    );
    let environment = CollectorSettings::from_environment(|name| {
        match name {
            "BOWER_COLLECTOR_ID" => Some("relay-01"),
            "BOWER_RELAY_LISTEN_URL" => Some("https://0.0.0.0:4443"),
            "BOWER_RELAY_CERTIFICATE_FILE" => Some("/etc/bower/relay.crt"),
            "BOWER_RELAY_KEY_FILE" => Some("/run/secrets/relay.key"),
            "BOWER_RELAY_DOWNSTREAMS_FILE" => Some("/etc/bower/downstreams.json"),
            "BOWER_RELAY_MANAGEMENT_TUNNEL" => Some("TRUE"),
            "BOWER_MANAGEMENT_ENDPOINT" => Some("https://management.example.test"),
            "BOWER_MANAGEMENT_SCOPE" => Some("api://bower/.default"),
            _ => None,
        }
        .map(str::to_string)
    })
    .unwrap();
    assert!(environment.relay_management_tunnel);
    assert_eq!(environment.relay_listen_url, url("https://0.0.0.0:4443"));
}

/// C# `ConfigurationHash_IsUnchangedWithoutRelaySettingsAndPinned`: the same hashes.
#[test]
fn configuration_hash_matches_csharp() {
    let mut relay = base();
    relay.relay_listen_url = url("https://0.0.0.0:4443");
    relay.relay_certificate_file = Some("/etc/bower/relay.crt".into());
    relay.relay_key_file = Some("/run/secrets/relay.key".into());
    relay.relay_downstreams_file = Some("/etc/bower/downstreams.json".into());
    assert_ne!(base().configuration_hash(), relay.configuration_hash());
    let mut moved = relay.clone();
    moved.relay_key_file = Some("/other.key".into());
    moved.relay_certificate_file = Some("/other.crt".into());
    assert_eq!(relay.configuration_hash(), moved.configuration_hash());

    let mut downstream = base();
    downstream.output_type = "relay".into();
    downstream.relay_url = url("https://relay.example.test:4443");
    downstream.relay_client_certificate_file = Some("/etc/bower/client.crt".into());
    downstream.relay_client_key_file = Some("/run/secrets/client.key".into());
    downstream.relay_ca_bundle = Some("/etc/bower/relay-ca.pem".into());
    downstream.management_endpoint = url("https://management.example.test");
    downstream.management_authentication = "enrolment".into();
    downstream.management_via_relay = true;
    assert_eq!(
        relay.configuration_hash(),
        "sha256:f7d49a6ca37ccdb7646c42e142cb809b2559d901b45d5c53572db76a7f95a997"
    );
    assert_eq!(
        downstream.configuration_hash(),
        "sha256:887f9f1f62c825dbe67b4e257a52bdc8c147c56a2dae0c8a80e936bd271b2ab4"
    );
}

/// C# `Downstreams_ParseStrictly`.
#[test]
fn downstreams_parse_strictly() {
    let pin = "a".repeat(64);
    let other = "B".repeat(64);
    let colons = other
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    let parsed = RelayDownstreams::parse(
        format!(
            r#"{{"downstreams":[{{"collectorId":"edge-01","certificateSha256":"{pin}"}},{{"collectorId":"edge-01","certificateSha256":"{colons}"}}]}}"#
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(parsed.collector_ids(), vec!["edge-01".to_string()]);

    let invalid = [
        "[]".to_string(),
        r#"{"downstreams":[]}"#.to_string(),
        format!(
            r#"{{"downstreams":[{{"collectorId":"edge-01","certificateSha256":"{pin}"}},{{"collectorId":"edge-02","certificateSha256":"{pin}"}}]}}"#
        ),
        format!(
            r#"{{"downstreams":[{{"collectorId":"edge-01","certificateSha256":"{}"}}]}}"#,
            &pin[..63]
        ),
        format!(
            r#"{{"downstreams":[{{"collectorId":"edge-01","certificateSha256":"{}"}}]}}"#,
            "g".repeat(64)
        ),
        format!(r#"{{"downstreams":[{{"collectorId":"","certificateSha256":"{pin}"}}]}}"#),
        format!(r#"{{"downstreams":[{{"collectorId":"edge 01","certificateSha256":"{pin}"}}]}}"#),
        format!(
            r#"{{"downstreams":[{{"collectorId":"edge-01","collectorId":"edge-02","certificateSha256":"{pin}"}}]}}"#
        ),
        r#"{"downstreams":[{"collectorId":"edge-01"}]}"#.to_string(),
        "not json".to_string(),
    ];
    for json in invalid {
        assert!(RelayDownstreams::parse(json.as_bytes()).is_err(), "{json}");
    }
    let entries: Vec<_> = (0..=MAXIMUM_ENTRIES)
        .map(|index| serde_json::json!({"collectorId": format!("edge-{index}"), "certificateSha256": format!("{index:064x}")}))
        .collect();
    let too_many = serde_json::json!({"downstreams": entries}).to_string();
    assert!(RelayDownstreams::parse(too_many.as_bytes()).is_err());
    assert!(RelayDownstreams::load(Path::new("/nonexistent/downstreams.json")).is_err());
}

// ------------------------------------------------------------------ intake

fn intake(directory: &Path, maximum_bytes: i64) -> (RelayIntake, Arc<SqliteEventStore>, PathBuf) {
    let path = directory.join("relay.db");
    let store = Arc::new(SqliteEventStore::new(&path, maximum_bytes, None).unwrap());
    store.initialize().unwrap();
    let intake = RelayIntake::new(
        Arc::clone(&store) as Arc<dyn DurableEventStore>,
        "relay-01",
        Arc::new(RelayTelemetry::new(["edge-01".to_string()])),
        Arc::new(SystemClock),
    );
    (intake, store, path)
}

fn accepted(outcome: RelayIntakeOutcome) -> protocol::RelayBatchResponse {
    match outcome {
        RelayIntakeOutcome::Accepted(response) => response,
        other => panic!("expected 200, got {other:?}"),
    }
}

fn refused_status(outcome: RelayIntakeOutcome) -> u16 {
    match outcome {
        RelayIntakeOutcome::Refused { status, .. } => status,
        RelayIntakeOutcome::Accepted(_) => 200,
    }
}

/// C# `Intake_StoresPayloadBytesUnchangedAndIsIdempotent`.
#[test]
fn intake_stores_payload_bytes_unchanged_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let (intake, store, path) = intake(directory.path(), 64 * 1024 * 1024);
    let (payload, fingerprint) = arranged("event-a", "edge-01", true, None);
    let body = batch(
        "edge-01",
        &[("event-a".into(), fingerprint, payload.clone())],
    );

    let first = accepted(intake.accept("edge-01", &body).unwrap());
    let second = accepted(intake.accept("edge-01", &body).unwrap());

    assert_eq!(first.results[0].status, protocol::STATUS_ACCEPTED);
    assert_eq!(second.results[0].status, protocol::STATUS_DUPLICATE);
    assert_eq!(first.relay_id, "relay-01");
    assert_eq!(first.ledger.sequence, 1);
    assert_eq!(first.ledger, second.ledger);
    let stored = rows(&path);
    assert_eq!(stored.len(), 1);
    // Byte for byte: the relay ledger hashes exactly what the downstream stored.
    assert_eq!(stored[0].3, payload);
    assert!(store.verify_ledger().unwrap().intact);
}

/// C# `Intake_RefusesAnythingThatIsNotThisDownstreamsDecidedEnvelope`.
#[test]
fn intake_refuses_anything_that_is_not_this_downstreams_decided_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let (intake, _, path) = intake(directory.path(), 64 * 1024 * 1024);
    let (payload, fingerprint) = arranged("event-a", "edge-01", true, None);
    let (foreign, foreign_fingerprint) = arranged("event-b", "edge-02", true, None);
    let (undecided, undecided_fingerprint) = arranged("event-c", "edge-01", false, None);
    let outcome = accepted(
        intake
            .accept(
                "edge-01",
                &batch(
                    "edge-01",
                    &[
                        (
                            "event-a".into(),
                            format!("sha256:v2:{}", "0".repeat(64)),
                            payload.clone(),
                        ),
                        ("event-b".into(), foreign_fingerprint, foreign),
                        ("event-c".into(), undecided_fingerprint, undecided),
                        ("event-x".into(), fingerprint.clone(), payload.clone()),
                        (
                            "event-d".into(),
                            "f".into(),
                            r#"{"eventId":"event-d"}"#.into(),
                        ),
                    ],
                ),
            )
            .unwrap(),
    );
    assert_eq!(
        outcome
            .results
            .iter()
            .map(|result| result.code.clone().unwrap())
            .collect::<Vec<_>>(),
        [
            protocol::REJECT_FINGERPRINT_MISMATCH,
            protocol::REJECT_COLLECTOR_MISMATCH,
            protocol::REJECT_POLICY_DECISION_MISSING,
            protocol::REJECT_EVENT_ID_MISMATCH,
            protocol::REJECT_PAYLOAD_INVALID,
        ]
    );
    assert!(
        outcome
            .results
            .iter()
            .all(|result| result.status == protocol::STATUS_REJECTED)
    );
    assert!(rows(&path).is_empty());

    // The batch itself must name the authenticated downstream.
    let one = batch(
        "edge-01",
        &[("event-a".into(), fingerprint.clone(), payload.clone())],
    );
    assert_eq!(refused_status(intake.accept("edge-02", &one).unwrap()), 403);

    // Same event id, different content: an identity conflict, never a silent duplicate.
    accepted(intake.accept("edge-01", &one).unwrap());
    let changed = payload.replace("InvalidPassword", "LockedOut");
    let conflict = accepted(
        intake
            .accept(
                "edge-01",
                &batch("edge-01", &[("event-a".into(), fingerprint, changed)]),
            )
            .unwrap(),
    );
    assert_eq!(
        conflict.results[0].code.as_deref(),
        Some(protocol::REJECT_IDENTITY_CONFLICT)
    );
}

/// C# `Intake_RefusesMalformedBatches` and `Intake_RefusesTooManyEvents`.
#[test]
fn intake_refuses_malformed_batches() {
    let directory = tempfile::tempdir().unwrap();
    let (intake, _, _) = intake(directory.path(), 64 * 1024 * 1024);
    let malformed = [
        r#"{"schemaVersion":2,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}}]}"#,
        r#"{"schemaVersion":1,"collectorId":"edge-01","events":[]}"#,
        r#"{"schemaVersion":1,"collectorId":"edge-01","collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}}]}"#,
        r#"{"schemaVersion":1,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}},{"eventId":"a","fingerprint":"f","payload":{}}]}"#,
        r#"{"schemaVersion":1,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":"{}"}]}"#,
        r#"{"schemaVersion":1.0,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}}]}"#,
        "[1,2,3]",
        r#"{"schemaVersion":1"#,
    ];
    for body in malformed {
        assert_eq!(
            refused_status(intake.accept("edge-01", body.as_bytes()).unwrap()),
            400,
            "{body}"
        );
    }
    let (payload, fingerprint) = arranged("event-a", "edge-01", true, None);
    let events: Vec<_> = (0..=protocol::MAXIMUM_BATCH_EVENTS)
        .map(|index| {
            (
                format!("event-{index}"),
                fingerprint.clone(),
                payload.clone(),
            )
        })
        .collect();
    assert_eq!(
        refused_status(
            intake
                .accept("edge-01", &batch("edge-01", &events))
                .unwrap()
        ),
        400
    );
}

/// C# `Intake_FullQueueAnswers503AndKeepsCommittedEventsIdempotent`.
#[test]
fn intake_full_queue_answers_503_and_keeps_committed_events_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let (intake, store, path) = intake(directory.path(), 1_048_576);
    let padding = "x".repeat(300_000);
    let events: Vec<_> = (0..5)
        .map(|index| {
            let id = format!("event-{index}");
            let (payload, fingerprint) = arranged(&id, "edge-01", true, Some(&padding));
            (id, fingerprint, payload)
        })
        .collect();

    assert_eq!(
        refused_status(
            intake
                .accept("edge-01", &batch("edge-01", &events))
                .unwrap()
        ),
        503
    );
    let committed = rows(&path).len();
    assert!((1..=4).contains(&committed), "{committed}");

    // Space frees up (the relay delivered); the downstream retries the whole batch.
    for leased in store.lease(10, Duration::from_secs(60)).unwrap() {
        store
            .mark_delivered(&leased.event_id, "test", leased.lease_token.as_deref())
            .unwrap();
    }
    let retried = accepted(
        intake
            .accept("edge-01", &batch("edge-01", &events[..committed]))
            .unwrap(),
    );
    assert!(
        retried
            .results
            .iter()
            .all(|result| result.status == protocol::STATUS_DUPLICATE)
    );
    assert_eq!(rows(&path).len(), committed);
}

// ------------------------------------------------------------------ output

type Responder = Arc<dyn Fn(String) -> (u16, String, Option<u64>) + Send + Sync>;

/// A plain-HTTP fake relay; returns its base URL and the request bodies it saw.
async fn fake_relay(respond: Responder) -> (Url, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let app = Router::new().route(
        "/v1/relay/batches",
        axum::routing::post(move |body: String| {
            let (respond, recorded) = (Arc::clone(&respond), Arc::clone(&recorded));
            async move {
                recorded.lock().unwrap().push(body.clone());
                let (status, body, retry_after) = respond(body);
                let mut response = axum::response::Response::new(Body::from(body));
                *response.status_mut() = StatusCode::from_u16(status).unwrap();
                if let Some(seconds) = retry_after {
                    response
                        .headers_mut()
                        .insert(header::RETRY_AFTER, seconds.to_string().parse().unwrap());
                }
                response
            }
        }),
    );
    let listeners = server::bind(&[SocketAddr::from(([127, 0, 0, 1], 0))])
        .await
        .unwrap();
    let port = listeners[0].local_addr().unwrap().port();
    tokio::spawn(server::serve(
        listeners,
        app,
        shutdown::ShutdownToken::never(),
    ));
    (
        Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
        seen,
    )
}

fn plain_output(relay: &Url) -> RelayOutput {
    RelayOutput::new(reqwest::Client::new(), relay, "edge-01")
}

/// C# `StalledResponseBodyHoldsEveryBatchForRetryWithoutAcknowledgement`.
#[tokio::test]
async fn stalled_response_body_holds_every_batch_for_retry_without_acknowledgement() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct StalledBody(Arc<AtomicBool>);
    impl hyper::body::Body for StalledBody {
        type Data = hyper::body::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            self.0.store(true, Ordering::SeqCst);
            std::task::Poll::Pending
        }
    }

    let requests = Arc::new(AtomicUsize::new(0));
    let reading = Arc::new(AtomicBool::new(false));
    let (count, started) = (Arc::clone(&requests), Arc::clone(&reading));
    let app = Router::new().route(
        "/v1/relay/batches",
        axum::routing::post(move |_body: String| {
            count.fetch_add(1, Ordering::SeqCst);
            let body = StalledBody(Arc::clone(&started));
            async move { axum::response::Response::new(Body::new(body)) }
        }),
    );
    let listeners = server::bind(&[SocketAddr::from(([127, 0, 0, 1], 0))])
        .await
        .unwrap();
    let port = listeners[0].local_addr().unwrap().port();
    let (stop, token) = shutdown::channel();
    let host = tokio::spawn(server::serve(listeners, app, token));
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(250))
        .build()
        .unwrap();
    let output = RelayOutput::new(
        client,
        &Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
        "edge-01",
    );
    let events: Vec<_> = (0..=protocol::MAXIMUM_BATCH_EVENTS)
        .map(|index| queued(&format!("e{index}"), &format!("f{index}"), "{}"))
        .collect();

    let result = tokio::time::timeout(Duration::from_secs(5), output.deliver(&events))
        .await
        .unwrap();

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), host)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert!(reading.load(Ordering::SeqCst));
    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), events.len());
    assert!(result.failures.iter().all(|failure| {
        failure.code == "destination-relay-unavailable"
            && failure.is_retryable
            && failure.is_destination_failure()
    }));
}

/// C# `Output_AcknowledgesOnlyCommittedEventsAndSendsPayloadsUnchanged`.
#[tokio::test]
async fn output_acknowledges_only_committed_events_and_sends_payloads_unchanged() {
    let (relay, seen) = fake_relay(Arc::new(|body: String| {
        let request: serde_json::Value = serde_json::from_str(&body).unwrap();
        let id = |index: usize| request["events"][index]["eventId"].clone();
        let response = serde_json::json!({
            "schemaVersion": 1, "relayId": "relay-01", "ledger": {"sequence": 41, "hash": "abc"},
            "results": [
                {"eventId": id(0), "status": "accepted"},
                {"eventId": id(1), "status": "duplicate"},
                {"eventId": id(2), "status": "rejected", "code": "collector-mismatch"},
                {"eventId": id(3), "status": "rejected", "code": "Not A Code"}
            ]
        });
        (200, response.to_string(), None)
    }))
    .await;
    let payload = r#"{"eventId":"e1","attributes":{"text":"café \"quoted\""}}"#;
    let events = [
        queued("e1", "f1", payload),
        queued("e2", "f2", r#"{"eventId":"e2"}"#),
        queued("e3", "f3", r#"{"eventId":"e3"}"#),
        queued("e4", "f4", r#"{"eventId":"e4"}"#),
        queued("e5", "f5", r#"{"eventId":"e5"}"#),
        queued("e6", "f6", "not json"),
    ];

    let result = plain_output(&relay).deliver(&events).await;

    assert_eq!(result.acknowledged_event_ids, ["e1", "e2"]);
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        Some("relay:relay-01:ledger:41")
    );
    let failure = |id: &str| {
        result
            .failures
            .iter()
            .find(|failure| failure.event_id == id)
            .unwrap()
    };
    assert_eq!(failure("e3").code, "relay-rejected:collector-mismatch");
    assert!(!failure("e3").is_retryable);
    assert_eq!(failure("e4").code, "relay-rejected:unknown");
    assert_eq!(failure("e5").code, "relay-result-missing");
    assert!(failure("e5").is_retryable);
    assert_eq!(failure("e6").code, "payload-invalid-json");
    assert!(!failure("e6").is_retryable);
    let sent = seen.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let request: serde_json::Value = serde_json::from_str(&sent[0]).unwrap();
    assert_eq!(request["collectorId"], "edge-01");
    assert_eq!(request["schemaVersion"], 1);
    assert_eq!(request["events"].as_array().unwrap().len(), 5);
    // The stored bytes are sent unchanged, never re-serialized.
    assert!(sent[0].contains(&format!(r#""payload":{payload}}}"#)));
}

/// C# `Output_RelayOutageHoldsEveryEventBehindTheDestinationCircuit`.
#[tokio::test]
async fn output_relay_outage_holds_every_event_behind_the_destination_circuit() {
    let (unavailable, seen) =
        fake_relay(Arc::new(|_| (503, r#"{"error":"full"}"#.into(), Some(30)))).await;
    let events: Vec<_> = (0..protocol::MAXIMUM_BATCH_EVENTS + 10)
        .map(|index| {
            queued(
                &format!("e{index}"),
                &format!("f{index}"),
                &format!(r#"{{"eventId":"e{index}"}}"#),
            )
        })
        .collect();

    let result = plain_output(&unavailable).deliver(&events).await;

    // Two batches were due; after the first refusal the second is never sent.
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), events.len());
    assert!(
        result
            .failures
            .iter()
            .all(|failure| failure.code == "destination-relay-http-503"
                && failure.is_retryable
                && failure.is_destination_failure()
                && failure.retry_after.is_some())
    );

    let (refused, _) = fake_relay(Arc::new(|_| (400, "{}".into(), None))).await;
    let bad = plain_output(&refused).deliver(&events[..1]).await;
    assert_eq!(bad.failures[0].code, "relay-http-400");
    assert!(!bad.failures[0].is_destination_failure());

    let (garbage, _) = fake_relay(Arc::new(|_| {
        (
            200,
            r#"{"schemaVersion":1,"relayId":"r","ledger":{"sequence":1,"hash":"h"},"results":[{"eventId":"other","status":"accepted"}]}"#.into(),
            None,
        )
    }))
    .await;
    assert_eq!(
        plain_output(&garbage).deliver(&events[..1]).await.failures[0].code,
        "relay-response-invalid"
    );

    let closed = Url::parse(&format!("http://127.0.0.1:{}/", free_port())).unwrap();
    assert_eq!(
        plain_output(&closed).deliver(&events[..1]).await.failures[0].code,
        "destination-relay-unavailable"
    );
}

// ------------------------------------------------------------------ end to end

fn post_event(envelope: &SecurityEventEnvelope) -> Request<Body> {
    Request::post("/v1/events")
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(bower_contracts::json::to_vec(envelope).unwrap()))
        .unwrap()
}

/// C# `DeliversThroughOneRelay_WithLedgersThatAgreeEndToEnd`.
#[tokio::test]
async fn delivers_through_one_relay_with_ledgers_that_agree_end_to_end() {
    let directory = tempfile::tempdir().unwrap();
    let pki = Pki::new(directory.path());
    let client = pki.valid_client("edge-01");
    let destination = Capture::default();
    let relay_config = relay_settings(
        directory.path(),
        &pki,
        &pki.downstreams(&[("edge-01", &client.pin)]),
        0,
    );
    let relay_queue = relay_config.queue_path.clone();
    let relay = start(
        relay_config,
        Some(BoxedOutput(Arc::new(destination.clone()))),
    )
    .await;
    let edge_settings = downstream_settings(
        directory.path(),
        &pki,
        &client,
        relay.relay_port(),
        "edge-01",
    );
    let edge_queue = edge_settings.queue_path.clone();
    let output = host::create_output(&edge_settings, None).unwrap();
    let edge = start(edge_settings, output).await;

    let ids = ["relay-e2e-1", "relay-e2e-2", "relay-e2e-3"];
    for id in ids {
        let mut envelope = authentication_failure(id);
        envelope.attributes = Some(
            [(
                "dbPassword".to_string(),
                bower_contracts::JsonElement::from("never-leaves-the-edge"),
            )]
            .into_iter()
            .collect(),
        );
        let response = edge
            .router
            .clone()
            .oneshot(post_event(&envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // The edge also queues a privacy alert for each detected secret; it crosses the relay too.
    wait_for(|| {
        let edge_rows = rows(&edge_queue);
        edge_rows.len() > ids.len()
            && destination.delivered().len() == edge_rows.len()
            && edge_rows.iter().all(|row| row.1 == DELIVERED)
    })
    .await;
    let edge_rows = rows(&edge_queue);
    for id in ids {
        assert!(edge_rows.iter().any(|row| row.0 == id));
    }
    assert!(edge_rows.iter().all(|row| {
        row.2
            .as_deref()
            .is_some_and(|ack| ack.starts_with("relay:relay-01:ledger:"))
    }));
    let mut delivered = destination.delivered();
    delivered.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    // The destination gets exactly what the edge stored: redacted at the edge, unchanged by the relay.
    assert_eq!(
        edge_rows
            .iter()
            .map(|row| row.3.clone())
            .collect::<Vec<_>>(),
        delivered
            .iter()
            .map(|item| item.payload.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        delivered
            .iter()
            .all(|item| !item.payload.contains("never-leaves-the-edge")
                && item.payload.contains(r#""id":"edge-01""#))
    );
    // The ledger chain continues across the hop: both ledgers commit to the same payload hashes.
    let (edge_ledger, relay_ledger) = (ledger_hashes(&edge_queue), ledger_hashes(&relay_queue));
    assert_eq!(relay_ledger.len(), edge_rows.len());
    for row in &edge_rows {
        assert_eq!(edge_ledger[&row.0], relay_ledger[&row.0]);
    }
    assert!(ledger_intact(&edge_queue));
    assert!(ledger_intact(&relay_queue));

    // Relay status: counters per pinned downstream, metadata only.
    let response = relay
        .router
        .clone()
        .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let status: serde_json::Value = serde_json::from_str(&body).unwrap();
    let downstreams = status["relay"]["downstreams"].as_array().unwrap();
    assert_eq!(downstreams.len(), 1);
    assert_eq!(downstreams[0]["collectorId"], "edge-01");
    assert_eq!(downstreams[0]["accepted"], edge_rows.len());
    assert!(downstreams[0]["lastBatchAt"].is_string());
    assert_eq!(
        status["relay"]["tunnels"],
        serde_json::json!({"open": 0, "opened": 0, "refused": 0})
    );
    assert!(!body.contains("relay-e2e-1"));
    edge.stop().await;
    relay.stop().await;
}

/// C# `RelayRestart_NeitherDuplicatesNorLosesEvents`.
#[tokio::test]
async fn relay_restart_neither_duplicates_nor_loses_events() {
    let directory = tempfile::tempdir().unwrap();
    let pki = Pki::new(directory.path());
    let client = pki.valid_client("edge-01");
    let port = free_port();
    let relay_config = relay_settings(
        directory.path(),
        &pki,
        &pki.downstreams(&[("edge-01", &client.pin)]),
        port,
    );
    let relay_queue = relay_config.queue_path.clone();
    let edge_settings = downstream_settings(directory.path(), &pki, &client, port, "edge-01");
    let events: Vec<_> = (0..20)
        .map(|index| {
            let id = format!("restart-{index}");
            let (payload, fingerprint) = arranged(&id, "edge-01", true, None);
            queued(&id, &fingerprint, &payload)
        })
        .collect();
    let output = relay_output(&edge_settings);

    // First relay process: commits the batch, then stops before delivering any of it (no
    // output configured), so the events are still in the relay queue.
    let first = start(relay_config.clone(), None).await;
    let delivered = output.deliver(&events).await;
    assert_eq!(delivered.acknowledged_event_ids.len(), events.len());
    first.stop().await;
    assert!(rows(&relay_queue).iter().all(|row| row.1 == QUEUED));

    // The relay is gone: the downstream keeps everything (destination circuit, no ack).
    let offline = output.deliver(&events).await;
    assert!(offline.acknowledged_event_ids.is_empty());
    assert!(
        offline
            .failures
            .iter()
            .all(|failure| failure.code == "destination-relay-unavailable")
    );

    // Second relay process on the same queue. The downstream resends the batch whose
    // response it never saw: every event is a duplicate, nothing is queued twice.
    let destination = Capture::default();
    let second = start(
        relay_config,
        Some(BoxedOutput(Arc::new(destination.clone()))),
    )
    .await;
    let resent = output.deliver(&events).await;
    assert_eq!(resent.acknowledged_event_ids.len(), events.len());
    wait_for(|| {
        destination.delivered().len() >= events.len()
            && rows(&relay_queue).iter().all(|row| row.1 == DELIVERED)
    })
    .await;
    assert_eq!(rows(&relay_queue).len(), events.len());
    let mut ids: Vec<_> = destination
        .delivered()
        .into_iter()
        .map(|item| item.event_id)
        .collect();
    ids.sort();
    let mut expected: Vec<_> = events.iter().map(|item| item.event_id.clone()).collect();
    expected.sort();
    assert_eq!(ids, expected);
    assert!(ledger_intact(&relay_queue));
    second.stop().await;
}

/// C# `MutualTls_RefusesUnpinnedCertificatesImpersonationAndUntrustedRelays`.
#[tokio::test]
async fn mutual_tls_refuses_unpinned_certificates_impersonation_and_untrusted_relays() {
    let directory = tempfile::tempdir().unwrap();
    let pki = Pki::new(directory.path());
    let pinned = pki.valid_client("edge-01");
    let unpinned = pki.valid_client("intruder");
    let expired = pki.client("expired", -14, -1, ExtendedKeyUsagePurpose::ClientAuth);
    let server_only = pki.client("server-usage", -1, 7, ExtendedKeyUsagePurpose::ServerAuth);
    let relay_config = relay_settings(
        directory.path(),
        &pki,
        &pki.downstreams(&[
            ("edge-01", &pinned.pin),
            ("expired", &expired.pin),
            ("server-usage", &server_only.pin),
        ]),
        0,
    );
    let relay_queue = relay_config.queue_path.clone();
    let relay = start(
        relay_config,
        Some(BoxedOutput(Arc::new(Capture::default()))),
    )
    .await;
    let port = relay.relay_port();
    let (payload, fingerprint) = arranged("tls-1", "edge-01", true, None);
    let events = [queued("tls-1", &fingerprint, &payload)];
    let failure = |client: &Client, collector_id: &str, trust: bool| {
        let mut settings = downstream_settings(directory.path(), &pki, client, port, collector_id);
        if !trust {
            settings.relay_ca_bundle = None;
        }
        let events = events.clone();
        async move {
            let result = relay_output(&settings).deliver(&events).await;
            assert!(result.acknowledged_event_ids.is_empty());
            result.failures[0].code.clone()
        }
    };

    assert_eq!(
        failure(&unpinned, "edge-01", true).await,
        "destination-relay-unavailable"
    );
    assert_eq!(
        failure(&expired, "expired", true).await,
        "destination-relay-unavailable"
    );
    assert_eq!(
        failure(&server_only, "server-usage", true).await,
        "destination-relay-unavailable"
    );
    // A pinned downstream cannot submit as another collector.
    assert_eq!(
        failure(&pinned, "edge-02", true).await,
        "destination-relay-http-403"
    );
    // The downstream refuses a relay whose certificate it cannot verify.
    assert_eq!(
        failure(&pinned, "edge-01", false).await,
        "destination-relay-unavailable"
    );
    assert!(rows(&relay_queue).is_empty());
    relay.stop().await;
}

/// An HTTPS-only management server answering `pong` and recording the Authorization
/// header. Plaintext never gets an answer, so `pong` through the tunnel proves TLS to
/// management ran inside it, end to end.
async fn https_management(pki: &Pki, seen: Arc<Mutex<Option<String>>>) -> u16 {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let certificate =
        CertificateDer::from_pem_slice(&std::fs::read(&pki.server_certificate).unwrap()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(&std::fs::read(&pki.server_key).unwrap()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen) = (acceptor.clone(), Arc::clone(&seen));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                *seen.lock().unwrap() = head.lines().find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                        .map(|(_, value)| value.trim().to_string())
                });
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// C# `ManagementTunnel_CarriesManagementTlsEndToEndAndGoesNowhereElse`.
#[cfg(unix)]
#[tokio::test]
async fn management_tunnel_carries_management_tls_end_to_end_and_goes_nowhere_else() {
    use bower_collector::relay::client::tunnel::TunnelForwarder;
    let directory = tempfile::Builder::new()
        .prefix("bwr")
        .tempdir_in("/tmp")
        .unwrap();
    let pki = Pki::new(directory.path());
    let client = pki.valid_client("edge-01");
    let unpinned = pki.valid_client("intruder");
    let seen = Arc::new(Mutex::new(None));
    let management_port = https_management(&pki, Arc::clone(&seen)).await;
    let management = Url::parse(&format!("https://localhost:{management_port}/")).unwrap();
    let mut relay_config = relay_settings(
        directory.path(),
        &pki,
        &pki.downstreams(&[("edge-01", &client.pin)]),
        0,
    );
    relay_config.relay_management_tunnel = true;
    relay_config.management_endpoint = Some(management.clone());
    relay_config.management_scope = Some("api://bower/.default".into());
    let relay = start(
        relay_config,
        Some(BoxedOutput(Arc::new(Capture::default()))),
    )
    .await;

    let through_tunnel = |identity: &Client, port: u16, name: &str| {
        let mut settings = downstream_settings(directory.path(), &pki, identity, port, name);
        settings.management_endpoint = Some(management.clone());
        settings.management_authentication = "enrolment".into();
        settings.management_via_relay = true;
        settings.management_ca_bundle = Some(pki.ca_bundle.clone());
        let management = management.clone();
        async move {
            let _forwarder =
                TunnelForwarder::start(&settings, RelayTls::from_settings(&settings).unwrap())
                    .unwrap();
            let client = bower_collector::management_http::client(&settings).unwrap();
            client
                .get(management.join("ping").unwrap())
                .bearer_auth("downstream-assertion")
                .send()
                .await?
                .text()
                .await
        }
    };

    // TLS to management runs inside the tunnel: the downstream verifies management's own
    // certificate, and the relay forwards only ciphertext.
    assert_eq!(
        through_tunnel(&client, relay.relay_port(), "edge-a")
            .await
            .unwrap(),
        "pong"
    );
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("Bearer downstream-assertion")
    );
    let response = relay
        .router
        .clone()
        .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(status["relay"]["tunnels"]["opened"].as_i64().unwrap() >= 1);

    // Unpinned certificates never reach the tunnel.
    assert!(
        through_tunnel(&unpinned, relay.relay_port(), "edge-b")
            .await
            .is_err()
    );

    // A relay without the tunnel enabled refuses it.
    let other = tempfile::Builder::new()
        .prefix("bwr")
        .tempdir_in("/tmp")
        .unwrap();
    let plain = start(
        relay_settings(
            other.path(),
            &pki,
            &pki.downstreams(&[("edge-01", &client.pin)]),
            0,
        ),
        Some(BoxedOutput(Arc::new(Capture::default()))),
    )
    .await;
    assert!(
        through_tunnel(&client, plain.relay_port(), "edge-c")
            .await
            .is_err()
    );
    plain.stop().await;
    relay.stop().await;
}
