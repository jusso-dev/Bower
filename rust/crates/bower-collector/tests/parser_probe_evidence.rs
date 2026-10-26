//! Port of the real-collector half of C# `ParserProbeEvidenceTests` (issue 74): the
//! Rust evidence runner drives this collector's router in-process, and a destination
//! fake answers from the collector's durable queue, only for its own workspace and only
//! for the exact EventId in the query.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::{CollectorSettings, bundle};
use bower_contracts::abstractions::DurableEventStore;
use bower_evidence::probe::outcomes;
use bower_evidence::{
    BoxFuture, CanarySender, CollectorResponse, EvidenceBundle, EvidenceError, EvidenceOptions,
    EvidenceRunner, LogAnalyticsQuery, ParserProbeSender, QueryRows, modes,
};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const TOKEN: &str = "parser-probe-test-token-0123456789abcdef";
const PROFILE: &str = "parser:linux-ssh-gateway:0";
const WORKSPACE: &str = "workspace-1";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn copy_dir(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &destination);
        } else {
            std::fs::copy(entry.path(), destination).unwrap();
        }
    }
}

/// The shipped pack, optionally regressed like the C# test variants.
async fn start(directory: &Path, variant: &str) -> Collector {
    let source = directory.join("pack");
    copy_dir(&repo_root().join("packs/linux-ssh-gateway"), &source);
    if variant != "active" {
        let parser_path = source.join("parsers/sshd-json.json");
        let mut parser: Value =
            serde_json::from_str(&std::fs::read_to_string(&parser_path).unwrap()).unwrap();
        let root = parser.as_object_mut().unwrap();
        match variant {
            "inactive" => {
                root.remove("runtime");
            }
            "not-selected" => root["runtime"]["match"] = json!({"result": "denied"}),
            "policy" => root["runtime"]["eventType"] = json!("authentication_success"),
            "wrong-event" => root["runtime"]["fields"]["eventId"] = json!("user"),
            _ => unreachable!(),
        }
        std::fs::write(&parser_path, parser.to_string()).unwrap();
        // Raw samples would fail signing for the regressed parser; envelope samples still run.
        let samples = source.join("samples/ssh.jsonl");
        let kept: Vec<String> = std::fs::read_to_string(&samples)
            .unwrap()
            .lines()
            .filter(|line| !line.contains("\"raw\":"))
            .map(str::to_owned)
            .collect();
        std::fs::write(&samples, kept.join("\n") + "\n").unwrap();
    }
    let keys = bower_integrity::generate_key_pair();
    let archive = bower_packs::build(&source, &keys.private_key_pem, directory, None).unwrap();
    let public_key = directory.join("trusted.pem");
    std::fs::write(&public_key, keys.public_key_pem).unwrap();
    let privacy_key = directory.join("privacy.key");
    std::fs::write(&privacy_key, [0u8; 32]).unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        repo_root().join("policies/default"),
        "parser-probe-test",
    );
    settings.packs = vec![archive.to_string_lossy().into_owned()];
    settings.pack_trusted_key_files = vec![public_key.to_string_lossy().into_owned()];
    settings.privacy_hmac_key_file = Some(privacy_key);
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    settings.ingest_requests_per_second = 1000;
    let loaded = bundle::load(&settings).unwrap();
    let mut collector = host::build(settings, loaded, BuildOptions::default()).unwrap();
    collector.initialize().await.unwrap();
    collector
}

/// The runner's collector client, served by the real router instead of a socket.
struct RouterCollector(Router);

impl RouterCollector {
    async fn call(
        &self,
        method: &str,
        path: String,
        token: Option<&str>,
        json: Option<String>,
    ) -> Result<CollectorResponse, EvidenceError> {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match json {
            Some(json) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json)),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.0.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        Ok((
            status,
            match serde_json::from_slice(&bytes) {
                Ok(Value::Object(body)) => Some(body),
                _ => None,
            },
        ))
    }
}

impl CanarySender for RouterCollector {
    fn send<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        token: Option<&'a str>,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        Box::pin(self.call("POST", "/v1/events".to_owned(), token, Some(json)))
    }
}

impl ParserProbeSender for RouterCollector {
    fn get_status<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        Box::pin(self.call("GET", "/v1/status".to_owned(), token, None))
    }

    fn send_record<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        token: Option<&'a str>,
        pack_id: &'a str,
        parser_index: i32,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        Box::pin(self.call(
            "POST",
            format!("/v1/packs/{pack_id}/parsers/{parser_index}/events"),
            token,
            Some(json),
        ))
    }
}

struct QueueDestination {
    store: Arc<dyn DurableEventStore>,
    workspace: &'static str,
    delivered: Mutex<HashMap<String, Value>>,
    queries: Mutex<Vec<String>>,
    payloads: Mutex<String>,
}

impl QueueDestination {
    fn new(collector: &Collector, workspace: &'static str) -> Arc<Self> {
        Arc::new(Self {
            store: collector.store.clone(),
            workspace,
            delivered: Mutex::new(HashMap::new()),
            queries: Mutex::new(Vec::new()),
            payloads: Mutex::new(String::new()),
        })
    }
}

impl LogAnalyticsQuery for QueueDestination {
    fn query<'a>(
        &'a self,
        workspace_id: &'a str,
        kql: &'a str,
        _timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        self.queries.lock().unwrap().push(kql.to_owned());
        let mut delivered = self.delivered.lock().unwrap();
        for queued in self.store.lease(100, Duration::from_secs(3_600)).unwrap() {
            self.payloads.lock().unwrap().push_str(&queued.payload);
            delivered.insert(
                queued.event_id.clone(),
                serde_json::from_str(&queued.payload).unwrap(),
            );
        }
        let id = kql
            .split("EventId == \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next());
        let rows = match id.and_then(|id| delivered.get(id)) {
            Some(event) if workspace_id == self.workspace => {
                let Value::Object(row) = json!({
                    "TimeGenerated": event["timeGenerated"],
                    "IngestionTime": bower_contracts::time::format_json(&bower_contracts::time::now()),
                    "EventId": event["eventId"],
                    "EventType": event["eventType"],
                    "PolicyHash": event["security"]["policyHash"],
                }) else {
                    unreachable!()
                };
                vec![row]
            }
            _ => Vec::<Map<String, Value>>::new(),
        };
        Box::pin(async move { Ok(QueryRows { rows, error: None }) })
    }
}

fn runner(collector: &Collector, destination: Option<Arc<QueueDestination>>) -> EvidenceRunner {
    let sender = Arc::new(RouterCollector(collector.router.clone()));
    EvidenceRunner::new(
        sender.clone(),
        destination.map(|destination| destination as Arc<dyn LogAnalyticsQuery>),
        None,
    )
    .with_parser_sender(sender)
}

fn options(workspace: Option<&str>, profile: &str) -> EvidenceOptions {
    let mut options = EvidenceOptions::new("http://localhost/".parse().unwrap());
    options.ingest_token = Some(TOKEN.to_owned());
    options.workspace_id = workspace.map(str::to_owned);
    options.timeout = Duration::from_millis(30);
    options.poll_interval = Duration::from_millis(10);
    options.probe_profile = profile.to_owned();
    options
}

async fn run(runner: &EvidenceRunner, workspace: Option<&str>, profile: &str) -> EvidenceBundle {
    runner.run(&options(workspace, profile)).await.unwrap()
}

#[tokio::test]
async fn parser_probe_fails_clearly_when_parser_is_inactive_while_generic_intake_works() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), "inactive").await;
    let destination = QueueDestination::new(&collector, WORKSPACE);
    let runner = runner(&collector, Some(destination.clone()));

    let generic = run(&runner, Some(WORKSPACE), "generic").await;
    let parser = run(&runner, Some(WORKSPACE), PROFILE).await;

    assert_eq!(generic.mode, modes::VERIFIED);
    assert!(generic.probe.is_none());
    assert_eq!(parser.mode, modes::FAILED);
    let probe = parser.probe.unwrap();
    assert_eq!(probe.outcome, outcomes::PARSER_INACTIVE);
    assert_eq!(
        probe.parser_status.as_deref(),
        Some("inactive-preview-only")
    );
    assert_eq!(probe.pack_version.as_deref(), Some("1.1.0"));
    assert!(probe.collector_policy_hash.unwrap().starts_with("sha256:"));
    assert!(probe.pack_hash.is_some_and(|hash| !hash.is_empty()));
    assert_eq!(parser.canary.collector_status, 0);
    assert_eq!(
        parser.arrival.query_error.as_deref(),
        Some(outcomes::PARSER_INACTIVE)
    );
    assert!(
        !destination
            .queries
            .lock()
            .unwrap()
            .iter()
            .any(|kql| kql.contains(&probe.event_id))
    );
}

#[tokio::test]
async fn parser_mapping_or_selection_regression_fails_while_generic_intake_works() {
    for (variant, outcome, status) in [
        ("not-selected", outcomes::PARSER_NOT_SELECTED, 422),
        ("policy", outcomes::POLICY_NOT_SELECTED, 422),
        ("wrong-event", outcomes::PARSER_WRONG_EVENT, 202),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let collector = start(directory.path(), variant).await;
        let destination = QueueDestination::new(&collector, WORKSPACE);
        let runner = runner(&collector, Some(destination.clone()));

        let generic = run(&runner, Some(WORKSPACE), "generic").await;
        let parser = run(&runner, Some(WORKSPACE), PROFILE).await;

        assert_eq!(generic.mode, modes::VERIFIED, "{variant}");
        assert_eq!(parser.mode, modes::FAILED, "{variant}");
        let probe = parser.probe.unwrap();
        assert_eq!(probe.outcome, outcome, "{variant}");
        assert_eq!(probe.parser_status.as_deref(), Some("active-local-json"));
        assert_eq!(parser.canary.collector_status, status, "{variant}");
        assert!(!parser.arrival.found);
        assert!(
            !destination
                .queries
                .lock()
                .unwrap()
                .iter()
                .any(|kql| kql.contains(&probe.event_id))
        );
    }
}

#[tokio::test]
async fn parser_probe_verifies_only_the_exact_event_from_the_intended_destination() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), "active").await;
    let destination = QueueDestination::new(&collector, WORKSPACE);

    let bundle = run(
        &runner(&collector, Some(destination.clone())),
        Some(WORKSPACE),
        PROFILE,
    )
    .await;

    assert_eq!(bundle.mode, modes::VERIFIED);
    let probe = bundle.probe.unwrap();
    assert_eq!(probe.outcome, outcomes::VERIFIED);
    assert_eq!(probe.profile, PROFILE);
    assert_eq!(probe.pack_version.as_deref(), Some("1.1.0"));
    assert_eq!(probe.parser_status.as_deref(), Some("active-local-json"));
    assert!(probe.event_id.starts_with("bower-probe-"));
    assert_eq!(probe.event_id, bundle.canary.event_id);
    assert_eq!(probe.destination_workspace_id.as_deref(), Some(WORKSPACE));
    assert!(probe.queried_at.is_some());
    assert!(
        probe
            .event_policy_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert_eq!(probe.event_policy_hash, bundle.arrival.row_policy_hash);
    assert!(
        probe
            .untested_paths
            .iter()
            .any(|path| path.contains("/v1/events"))
    );
    // The normal privacy path ran: the fixture username never reached the queue.
    assert!(
        !destination
            .payloads
            .lock()
            .unwrap()
            .contains("bower-evidence-probe")
    );

    // The same event in another workspace never verifies.
    let other = tempfile::tempdir().unwrap();
    let elsewhere = start(other.path(), "active").await;
    let wrong_workspace = run(
        &runner(
            &elsewhere,
            Some(QueueDestination::new(&elsewhere, "workspace-2")),
        ),
        Some(WORKSPACE),
        PROFILE,
    )
    .await;
    assert_eq!(wrong_workspace.mode, modes::FAILED);
    assert_eq!(
        wrong_workspace.probe.unwrap().outcome,
        outcomes::DESTINATION_ROW_MISSING
    );
}

#[tokio::test]
async fn parser_probe_acceptance_alone_never_verifies() {
    let directory = tempfile::tempdir().unwrap();
    let collector = start(directory.path(), "active").await;

    let simulated = run(&runner(&collector, None), None, PROFILE).await;

    assert_eq!(simulated.canary.collector_status, 202);
    assert_eq!(simulated.mode, modes::SIMULATED);
    assert_eq!(
        simulated.probe.unwrap().outcome,
        outcomes::ACCEPTED_NOT_VERIFIED
    );
    assert!(
        simulated
            .limitations
            .iter()
            .any(|item| item.starts_with("SIMULATED"))
    );
}
