//! Port of the fake-based half of C# `ParserProbeEvidenceTests` (issue 74). The
//! real-collector cases live in `bower-collector/tests/parser_probe_evidence.rs`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use bower_contracts::time::{Clock, Timestamp, parse};
use bower_evidence::probe::{self, outcomes};
use bower_evidence::{
    BoxFuture, CanarySender, CollectorResponse, EvidenceError, EvidenceOptions, EvidenceRunner,
    HttpCanarySender, LogAnalyticsQuery, ParserProbeSender, QueryRows, modes,
};
use serde_json::{Map, Value, json};

const PROFILE: &str = "parser:linux-ssh-gateway:0";
const WORKSPACE: &str = "workspace-1";
const TOKEN: &str = "parser-probe-test-token-0123456789abcdef";

struct SteppingClock(Mutex<Timestamp>);

impl SteppingClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            parse("2026-10-08T00:00:00+00:00").unwrap(),
        )))
    }

    fn advance(&self, seconds: i64) {
        let mut now = self.0.lock().unwrap();
        *now += chrono::TimeDelta::seconds(seconds);
    }
}

impl Clock for SteppingClock {
    fn utc_now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        unreachable!()
    };
    map
}

/// A collector reporting an active linux-ssh-gateway parser that accepts the probe.
struct FakeCollector {
    status_code: u16,
    status_reads: Mutex<usize>,
    records: Mutex<usize>,
}

impl FakeCollector {
    fn new(status_code: u16) -> Arc<Self> {
        Arc::new(Self {
            status_code,
            status_reads: Mutex::new(0),
            records: Mutex::new(0),
        })
    }
}

impl CanarySender for FakeCollector {
    fn send<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        let event: Value = serde_json::from_str(&json).unwrap();
        let body = object(json!({"eventId": event["eventId"], "decision": "accept"}));
        Box::pin(async move { Ok((202, Some(body))) })
    }
}

impl ParserProbeSender for FakeCollector {
    fn get_status<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        *self.status_reads.lock().unwrap() += 1;
        let status = self.status_code;
        let body = (status == 200).then(|| {
            object(json!({"policy": {"hash": "sha256:bundle", "packs": [{
                "id": "linux-ssh-gateway", "version": "1.1.0", "packHash": "sha256:pack",
                "parserStatuses": ["active-local-json"]
            }]}}))
        });
        Box::pin(async move { Ok((status, body)) })
    }

    fn send_record<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
        _pack_id: &'a str,
        _parser_index: i32,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        *self.records.lock().unwrap() += 1;
        let record: Value = serde_json::from_str(&json).unwrap();
        let body = object(json!({
            "eventId": record["id"], "decision": "redactandaccept",
            "policy": {"policyId": "BWR-PACK-SSH-AUTH", "policyVersion": "1.0.0", "policyHash": "sha256:policy"}
        }));
        Box::pin(async move { Ok((202, Some(body))) })
    }
}

fn event_id_in(kql: &str) -> Option<String> {
    let start = kql.find("EventId == \"")? + "EventId == \"".len();
    let end = kql[start..].find('"')? + start;
    Some(kql[start..end].to_owned())
}

/// Returns the probe row for whatever EventId is queried.
struct EchoDestination;

impl LogAnalyticsQuery for EchoDestination {
    fn query<'a>(
        &'a self,
        _workspace_id: &'a str,
        kql: &'a str,
        _timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        let rows = event_id_in(kql)
            .map(|id| {
                vec![object(json!({
                    "EventId": id,
                    "EventType": if kql.contains("EventType") { Value::from("authentication_failure") } else { Value::Null },
                    "IngestionTime": "2026-07-26T02:16:19Z",
                    "PolicyHash": "sha256:policy"
                }))]
            })
            .unwrap_or_default();
        Box::pin(async move { Ok(QueryRows { rows, error: None }) })
    }
}

struct FixedRowDestination(&'static str);

impl LogAnalyticsQuery for FixedRowDestination {
    fn query<'a>(
        &'a self,
        _workspace_id: &'a str,
        _kql: &'a str,
        _timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        let rows = vec![object(json!({
            "EventId": self.0, "EventType": "authentication_failure", "IngestionTime": "2026-07-26T02:16:19Z"
        }))];
        Box::pin(async move { Ok(QueryRows { rows, error: None }) })
    }
}

struct FailingDestination {
    failure: &'static str,
    clock: Arc<SteppingClock>,
}

impl LogAnalyticsQuery for FailingDestination {
    fn query<'a>(
        &'a self,
        _workspace_id: &'a str,
        kql: &'a str,
        _timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        let result = if kql.starts_with("DCRLogErrors") {
            Ok(QueryRows::default())
        } else {
            // Each probe query takes 30 seconds, so three queries cover the one-minute window.
            self.clock.advance(30);
            let error = |code: &str| {
                Ok(QueryRows {
                    rows: Vec::new(),
                    error: Some(code.to_owned()),
                })
            };
            match self.failure {
                "permission" => error("InsufficientAccessError"),
                "missing" => Ok(QueryRows::default()),
                "timeout" => Err(EvidenceError::Http(
                    "The request was canceled due to the configured HttpClient.Timeout of 30 seconds elapsing."
                        .to_owned(),
                )),
                "gateway" => error("GatewayTimeout"),
                _ => error("BadArgumentError"),
            }
        };
        Box::pin(async move { result })
    }
}

fn options(workspace: Option<&str>) -> EvidenceOptions {
    let mut options = EvidenceOptions::new("http://collector.test:4319/".parse().unwrap());
    options.workspace_id = workspace.map(str::to_owned);
    options.ingest_token = Some(TOKEN.to_owned());
    options.probe_profile = PROFILE.to_owned();
    options.poll_interval = Duration::ZERO;
    options
}

fn runner(
    collector: Arc<FakeCollector>,
    destination: Option<Arc<dyn LogAnalyticsQuery>>,
) -> EvidenceRunner {
    EvidenceRunner::new(collector.clone(), destination, None).with_parser_sender(collector)
}

#[tokio::test]
async fn destination_failures_stay_distinct() {
    for (failure, outcome, attempts) in [
        ("permission", outcomes::DESTINATION_PERMISSION_DENIED, 1),
        ("missing", outcomes::DESTINATION_ROW_MISSING, 3),
        ("timeout", outcomes::DESTINATION_TIMEOUT, 3),
        ("gateway", outcomes::DESTINATION_TIMEOUT, 3),
        ("other", outcomes::DESTINATION_QUERY_FAILED, 3),
    ] {
        let clock = SteppingClock::new();
        let destination = Arc::new(FailingDestination {
            failure,
            clock: clock.clone(),
        });
        let mut options = options(Some(WORKSPACE));
        options.timeout = Duration::from_secs(60);
        let bundle = runner(FakeCollector::new(200), Some(destination))
            .with_clock(clock)
            .run(&options)
            .await
            .unwrap();
        assert_eq!(bundle.mode, modes::FAILED, "{failure}");
        assert_eq!(bundle.probe.unwrap().outcome, outcome, "{failure}");
        assert_eq!(bundle.arrival.attempts, attempts, "{failure}");
        assert!(!bundle.arrival.found);
    }
}

#[tokio::test]
async fn collector_status_failures_never_send_the_fixture() {
    for (status, outcome) in [
        (401, outcomes::COLLECTOR_PERMISSION_DENIED),
        (500, outcomes::COLLECTOR_STATUS_UNREADABLE),
    ] {
        let collector = FakeCollector::new(status);
        let bundle = runner(
            collector.clone(),
            Some(Arc::new(FixedRowDestination("unused"))),
        )
        .run(&options(Some(WORKSPACE)))
        .await
        .unwrap();
        let probe = bundle.probe.unwrap();
        assert_eq!(probe.outcome, outcome);
        assert_eq!(*collector.records.lock().unwrap(), 0);
        assert_eq!(probe.pack_hash, None);
    }
}

#[tokio::test]
async fn unknown_profile_fails_before_anything_is_sent() {
    let collector = FakeCollector::new(200);
    let mut options = options(None);
    options.probe_profile = "parser:linux-ssh-gateway:7".to_owned();
    let error = runner(collector.clone(), None)
        .run(&options)
        .await
        .unwrap_err();
    assert!(error.to_string().contains(PROFILE), "{error}");
    assert_eq!(*collector.status_reads.lock().unwrap(), 0);
    assert_eq!(*collector.records.lock().unwrap(), 0);
}

#[tokio::test]
async fn acceptance_alone_never_verifies() {
    let bundle = runner(FakeCollector::new(200), None)
        .run(&options(None))
        .await
        .unwrap();
    assert_eq!(bundle.canary.collector_status, 202);
    assert_eq!(bundle.mode, modes::SIMULATED);
    assert_eq!(
        bundle.probe.unwrap().outcome,
        outcomes::ACCEPTED_NOT_VERIFIED
    );
    assert!(
        bundle
            .limitations
            .iter()
            .any(|item| item.starts_with("SIMULATED"))
    );
    assert!(
        bundle
            .controls
            .iter()
            .all(|control| control.status != "evidenced")
    );
}

#[tokio::test]
async fn only_the_exact_event_verifies() {
    let stale = runner(
        FakeCollector::new(200),
        Some(Arc::new(FixedRowDestination("bower-probe-0000"))),
    )
    .run(&options(Some(WORKSPACE)))
    .await
    .unwrap();
    assert_eq!(stale.mode, modes::FAILED);
    assert_eq!(
        stale.probe.unwrap().outcome,
        outcomes::DESTINATION_WRONG_EVENT
    );

    let exact = runner(FakeCollector::new(200), Some(Arc::new(EchoDestination)))
        .run(&options(Some(WORKSPACE)))
        .await
        .unwrap();
    assert_eq!(exact.mode, modes::VERIFIED);
    let probe = exact.probe.unwrap();
    assert_eq!(probe.outcome, outcomes::VERIFIED);
    assert_eq!(probe.event_id, exact.canary.event_id);
    assert!(probe.event_id.starts_with("bower-probe-"));
    assert_eq!(probe.pack_version.as_deref(), Some("1.1.0"));
    assert_eq!(probe.parser_status.as_deref(), Some("active-local-json"));
    assert_eq!(probe.event_policy_hash.as_deref(), Some("sha256:policy"));
    assert_eq!(probe.destination_workspace_id.as_deref(), Some(WORKSPACE));
    assert!(probe.queried_at.is_some());
}

#[tokio::test]
async fn bundle_is_signed_additive_and_metadata_only() {
    let runner = runner(FakeCollector::new(200), Some(Arc::new(EchoDestination)));
    let parser = runner.run(&options(Some(WORKSPACE))).await.unwrap();
    let mut generic_options = options(Some(WORKSPACE));
    generic_options.probe_profile = probe::GENERIC.to_owned();
    let generic = runner.run(&generic_options).await.unwrap();
    let keys = bower_integrity::generate_key_pair();

    let signed = EvidenceRunner::sign(&parser, Some(&keys.private_key_pem)).unwrap();
    let json = signed.to_json_indented();

    assert_eq!(parser.mode, modes::VERIFIED);
    let parsed = bower_evidence::SignedEvidence::from_json(&json).unwrap();
    assert!(EvidenceRunner::verify(
        &parsed,
        [keys.public_key_pem.as_str()]
    ));
    let probe = signed.bundle["probe"].as_object().unwrap();
    assert_eq!(probe["packHash"], "sha256:pack");
    assert_eq!(probe["collectorPolicyHash"], "sha256:bundle");
    assert_eq!(
        probe["untestedPaths"].as_array().unwrap().len(),
        probe::UNTESTED_PATHS.len()
    );
    assert!(
        !EvidenceRunner::sign(&generic, None)
            .unwrap()
            .bundle
            .contains_key("probe")
    );
    for forbidden in [TOKEN, "bower-evidence-probe", "192.0.2.10", "\"user\""] {
        assert!(!json.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn fixture_renders_the_csharp_parity_vector() {
    let fixture = probe::resolve_parser(PROFILE).unwrap();
    let raw = fixture.render(
        "bower-probe-0190aaaabbbbccccddddeeeeffff0000",
        parse("2026-10-26T01:02:03.4567891Z").unwrap(),
    );
    // Same vector as C# `ParserProbeFixture_IsSyntheticBoundedAndMatchesTheShippedParser`.
    assert_eq!(
        raw,
        r#"{"id":"bower-probe-0190aaaabbbbccccddddeeeeffff0000","timestamp":"2026-10-26T01:02:03.4567891Z","user":"bower-evidence-probe","source_ip":"192.0.2.10","result":"failure"}"#
    );
    let lower = raw.to_lowercase();
    for secret in ["password", "secret", "token", "key", "cookie"] {
        assert!(!lower.contains(secret), "{secret}");
    }
}

#[derive(Default)]
struct Seen(Mutex<Vec<(String, Option<String>)>>);

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The real HTTP sender reads `/v1/status` and posts to the parser intake path.
#[tokio::test]
async fn http_sender_uses_status_and_parser_intake_endpoints() {
    let seen = Arc::new(Seen::default());
    let app = Router::new()
        .route(
            "/v1/status",
            get(
                |State(seen): State<Arc<Seen>>, headers: HeaderMap| async move {
                    seen.0
                        .lock()
                        .unwrap()
                        .push(("status".to_owned(), bearer(&headers)));
                    axum::Json(json!({"policy": {"hash": "sha256:bundle", "packs": [{
                    "id": "linux-ssh-gateway", "version": "1.1.0", "packHash": "sha256:pack",
                    "parserStatuses": ["active-local-json"]}]}}))
                },
            ),
        )
        .route(
            "/v1/packs/{pack}/parsers/{index}/events",
            post(
                |State(seen): State<Arc<Seen>>,
                 Path((pack, index)): Path<(String, String)>,
                 headers: HeaderMap,
                 body: Bytes| async move {
                    seen.0
                        .lock()
                        .unwrap()
                        .push((format!("{pack}/{index}"), bearer(&headers)));
                    let record: Value = serde_json::from_slice(&body).unwrap();
                    (
                        axum::http::StatusCode::ACCEPTED,
                        axum::Json(json!({"eventId": record["id"], "decision": "redactandaccept"})),
                    )
                },
            ),
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let sender = Arc::new(HttpCanarySender::new(bower_evidence::default_http_client()));
    let mut options = options(None);
    options.collector_url = base.parse().unwrap();
    let bundle = EvidenceRunner::new(sender.clone(), None, None)
        .with_parser_sender(sender)
        .run(&options)
        .await
        .unwrap();

    assert_eq!(
        bundle.probe.unwrap().outcome,
        outcomes::ACCEPTED_NOT_VERIFIED
    );
    let expected = Some(format!("Bearer {TOKEN}"));
    assert_eq!(
        *seen.0.lock().unwrap(),
        [
            ("status".to_owned(), expected.clone()),
            ("linux-ssh-gateway/0".to_owned(), expected)
        ]
    );
}
