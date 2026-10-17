//! Port of the evidence half of `PackAndEvidenceTests`, plus C#-signed fixture
//! parity and a mock Azure/collector HTTP server for the real clients.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bower_contracts::time::{Clock, SystemClock, Timestamp, parse};
use bower_evidence::{
    ArmReader, ArrivalRecord, BoxFuture, CanaryRecord, CanarySender, CollectorResponse,
    EvidenceBundle, EvidenceError, EvidenceOptions, EvidenceRunner, HttpArmReader,
    HttpCanarySender, LogAnalyticsQuery, LogAnalyticsQueryClient, QueryRows, RetentionRecord,
    SignedEvidence, modes,
};
use bower_output_azure::{AccessToken, TokenFuture, TokenProvider};
use serde_json::{Map, Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
}

fn now() -> Timestamp {
    parse("2026-10-08T00:00:00+00:00").unwrap()
}

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn utc_now(&self) -> Timestamp {
        self.0
    }
}

struct FakeSender {
    status: u16,
    sent: Mutex<Vec<String>>,
}

impl FakeSender {
    fn new(status: u16) -> Arc<Self> {
        Arc::new(Self {
            status,
            sent: Mutex::new(Vec::new()),
        })
    }
}

impl CanarySender for FakeSender {
    fn send<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        self.sent.lock().unwrap().push(json);
        let body = (self.status == 202).then(|| {
            let Value::Object(body) =
                json!({"decision": "accept", "policy": {"policyId": "BWR-POL-EVIDENCE-CANARY"}})
            else {
                unreachable!()
            };
            body
        });
        let status = self.status;
        Box::pin(async move { Ok((status, body)) })
    }
}

struct FakeQuery {
    found_after: usize,
    canary_queries: Mutex<usize>,
    queries: Mutex<Vec<String>>,
}

impl FakeQuery {
    fn new(found_after: usize) -> Arc<Self> {
        Arc::new(Self {
            found_after,
            canary_queries: Mutex::new(0),
            queries: Mutex::new(Vec::new()),
        })
    }

    fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

fn row(value: Value) -> Map<String, Value> {
    let Value::Object(row) = value else {
        unreachable!()
    };
    row
}

impl LogAnalyticsQuery for FakeQuery {
    fn query<'a>(
        &'a self,
        _workspace_id: &'a str,
        kql: &'a str,
        _timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        self.queries.lock().unwrap().push(kql.to_owned());
        let result = if kql.starts_with("DCRLogErrors") {
            QueryRows {
                rows: vec![row(json!({"Errors": 0}))],
                error: None,
            }
        } else {
            let mut count = self.canary_queries.lock().unwrap();
            *count += 1;
            if *count < self.found_after {
                QueryRows::default()
            } else {
                QueryRows {
                    rows: vec![row(json!({
                        "TimeGenerated": "2026-07-26T02:14:19Z",
                        "IngestionTime": "2026-07-26T02:16:19Z",
                        "PolicyHash": "sha256:policy"
                    }))],
                    error: None,
                }
            }
        };
        Box::pin(async move { Ok(result) })
    }
}

struct FakeArm {
    total_days: i32,
    region: &'static str,
}

impl ArmReader for FakeArm {
    fn get<'a>(
        &'a self,
        resource_id: &'a str,
        _api_version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Map<String, Value>>, EvidenceError>> {
        let value = if resource_id.contains("/tables/") {
            json!({"properties": {"plan": "Analytics", "retentionInDays": 90, "totalRetentionInDays": self.total_days}})
        } else {
            json!({"location": self.region})
        };
        Box::pin(async move { Ok(Some(row(value))) })
    }
}

fn options(workspace: Option<&str>) -> EvidenceOptions {
    let mut options = EvidenceOptions::new("http://collector.test:4319/".parse().unwrap());
    options.workspace_id = workspace.map(str::to_owned);
    options.workspace_resource_id = workspace.map(|_| {
        "/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w"
            .to_owned()
    });
    options.poll_interval = Duration::ZERO;
    options
}

#[tokio::test]
async fn evidence_verified_when_canary_is_found_and_signature_checks() {
    let query = FakeQuery::new(2);
    let sender = FakeSender::new(202);
    let runner = EvidenceRunner::new(
        sender.clone(),
        Some(query.clone()),
        Some(Arc::new(FakeArm {
            total_days: 400,
            region: "australiaeast",
        })),
    )
    .with_clock(Arc::new(FixedClock(now())));

    let bundle = runner.run(&options(Some("workspace-1"))).await.unwrap();
    let keys = bower_integrity::generate_key_pair();
    let signed = EvidenceRunner::sign(&bundle, Some(&keys.private_key_pem)).unwrap();
    let mut round_tripped = SignedEvidence::from_json(&signed.to_json_indented()).unwrap();

    assert_eq!(bundle.mode, modes::VERIFIED);
    assert!(bundle.arrival.found);
    assert_eq!(bundle.arrival.attempts, 2);
    assert_eq!(
        bundle
            .retention
            .as_ref()
            .and_then(|retention| retention.total_days),
        Some(400)
    );
    assert_eq!(
        bundle
            .retention
            .as_ref()
            .and_then(|retention| retention.workspace_region.as_deref()),
        Some("australiaeast")
    );
    assert_eq!(bundle.ingestion_errors_last_hour, Some(0));
    assert_eq!(bundle.canary.collector_decision.as_deref(), Some("accept"));
    assert_eq!(
        bundle.canary.policy_id.as_deref(),
        Some("BWR-POL-EVIDENCE-CANARY")
    );
    assert_eq!(bundle.canary.collector_host, "collector.test");
    assert_eq!(
        bundle.arrival.row_policy_hash.as_deref(),
        Some("sha256:policy")
    );
    let status = |id: &str| {
        bundle
            .controls
            .iter()
            .find(|control| control.id == id)
            .unwrap()
            .status
            .clone()
    };
    assert_eq!(status("ISM-1988"), "evidenced");
    assert_eq!(status("ISM-0580"), "evidenced");
    assert!(
        query
            .queries()
            .iter()
            .any(|kql| kql.contains(&bundle.canary.event_id))
    );
    assert!(EvidenceRunner::verify(
        &round_tripped,
        [keys.public_key_pem.as_str()]
    ));

    // The canary went through the collector as a real envelope.
    let sent: Value = serde_json::from_str(&sender.sent.lock().unwrap()[0]).unwrap();
    assert_eq!(sent["eventType"], "collector_canary");
    assert_eq!(sent["eventId"], bundle.canary.event_id.as_str());
    assert_eq!(sent["actor"]["type"], "system");
    assert_eq!(sent["labels"]["evidenceType"], "canary");
    assert!(
        bundle.canary.event_id.starts_with("bower-canary-")
            && bundle.canary.event_id.len() == 13 + 32
    );

    round_tripped.bundle.insert(
        "mode".to_owned(),
        Value::String(format!("{}!", modes::VERIFIED)),
    );
    assert!(!EvidenceRunner::verify(
        &round_tripped,
        [keys.public_key_pem.as_str()]
    ));
    let other = bower_integrity::generate_key_pair();
    assert!(!EvidenceRunner::verify(
        &signed,
        [other.public_key_pem.as_str()]
    ));
    let unsigned = EvidenceRunner::sign(&bundle, None).unwrap();
    assert!(!EvidenceRunner::verify(
        &unsigned,
        [keys.public_key_pem.as_str()]
    ));
}

#[tokio::test]
async fn evidence_fails_when_canary_never_arrives() {
    let runner = EvidenceRunner::new(FakeSender::new(202), Some(FakeQuery::new(usize::MAX)), None)
        .with_clock(Arc::new(SystemClock));
    let mut options = options(Some("workspace-1"));
    options.timeout = Duration::from_millis(50);
    options.poll_interval = Duration::from_millis(10);

    let bundle = runner.run(&options).await.unwrap();

    assert_eq!(bundle.mode, modes::FAILED);
    assert!(!bundle.arrival.found);
    assert_eq!(
        bundle.arrival.query_error.as_deref(),
        Some("not-found-before-timeout")
    );
    assert!(bundle.arrival.attempts >= 1);
    let control = bundle
        .controls
        .iter()
        .find(|control| control.id == "ISM-0580")
        .unwrap();
    assert_eq!(control.status, "not-evidenced");
    assert_eq!(
        control.evidence,
        "Canary not found (not-found-before-timeout)."
    );
}

#[tokio::test]
async fn evidence_is_labelled_simulated_without_a_workspace() {
    let runner = EvidenceRunner::new(FakeSender::new(202), None, None)
        .with_clock(Arc::new(FixedClock(now())));

    let bundle = runner.run(&options(None)).await.unwrap();

    assert_eq!(bundle.mode, modes::SIMULATED);
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
    assert_eq!(bundle.ingestion_errors_last_hour, None);
    assert_eq!(bundle.to_json()["mode"], "simulated");
}

#[tokio::test]
async fn evidence_with_query_client_but_no_workspace_is_still_simulated() {
    let query = FakeQuery::new(1);
    let runner = EvidenceRunner::new(FakeSender::new(202), Some(query.clone()), None);

    let bundle = runner.run(&options(None)).await.unwrap();

    assert_eq!(bundle.mode, modes::SIMULATED);
    assert!(query.queries().is_empty());
}

#[tokio::test]
async fn evidence_does_not_query_when_collector_rejects_the_canary() {
    let query = FakeQuery::new(1);
    let runner = EvidenceRunner::new(FakeSender::new(401), Some(query.clone()), None)
        .with_clock(Arc::new(FixedClock(now())));

    let bundle = runner.run(&options(Some("workspace-1"))).await.unwrap();

    assert_eq!(bundle.mode, modes::FAILED);
    assert_eq!(
        bundle.arrival.query_error.as_deref(),
        Some("collector-rejected-canary")
    );
    assert!(!query.queries().iter().any(|kql| kql.contains("EventId")));
    assert_eq!(bundle.canary.collector_decision, None);
}

#[tokio::test]
async fn evidence_rejects_invalid_table_names() {
    let runner = EvidenceRunner::new(FakeSender::new(202), None, None);
    let mut options = options(None);
    options.table = "Bad Table; drop".to_owned();
    assert!(matches!(
        runner.run(&options).await,
        Err(EvidenceError::InvalidArgument(_))
    ));
}

#[test]
fn query_parser_reads_log_analytics_response() {
    let rows = LogAnalyticsQueryClient::parse(
        r#"{"tables":[{"name":"PrimaryResult","columns":[{"name":"EventId","type":"string"},{"name":"IngestionTime","type":"datetime"}],"rows":[["e1","2026-10-08T00:01:00Z"]]}]}"#,
    )
    .unwrap();
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(rows.rows[0]["EventId"], "e1");
    assert_eq!(
        LogAnalyticsQueryClient::parse(r#"{"tables":[]}"#).unwrap(),
        QueryRows::default()
    );
}

/// The bundle that the C# vector generator signed (see `tests/fixtures`).
fn csharp_vector_bundle() -> EvidenceBundle {
    let at = parse("2026-10-17T01:02:03.4567+00:00").unwrap();
    let arrival = ArrivalRecord {
        found: true,
        workspace_id: Some("ws".to_owned()),
        table: "BowerSecurity_CL".to_owned(),
        query: Some("BowerSecurity_CL\n| where EventId == \"x\"".to_owned()),
        attempts: 2,
        time_generated: Some(at),
        ingestion_time: Some(parse("2026-10-17T01:02:15.7567+00:00").unwrap()),
        latency_seconds: Some(12.3),
        row_policy_hash: Some("sha256:policy".to_owned()),
        query_error: None,
    };
    let retention = RetentionRecord {
        plan: Some("Analytics".to_owned()),
        interactive_days: Some(90),
        total_days: Some(400),
        workspace_region: Some("australiaeast".to_owned()),
    };
    EvidenceBundle {
        schema: "bower.evidence/v1".to_owned(),
        mode: modes::VERIFIED.to_owned(),
        generated_at: at,
        tool: "bower".to_owned(),
        canary: CanaryRecord {
            event_id: "bower-canary-x".to_owned(),
            sent_at: at,
            collector_host: "collector.test".to_owned(),
            collector_status: 202,
            collector_decision: Some("accept".to_owned()),
            policy_id: Some("BWR-POL'+<>".to_owned()),
        },
        controls: bower_evidence::controls::map(modes::VERIFIED, &arrival, Some(&retention)),
        arrival,
        retention: Some(retention),
        ingestion_errors_last_hour: Some(0),
        limitations: vec!["l1".to_owned(), "l2 \u{e9}".to_owned()],
    }
}

#[test]
fn csharp_signed_bundle_verifies_and_matches_byte_for_byte() {
    let public_key = fixture("csharp-signing.pub.pem");
    let signed_text = fixture("evidence-signed.json");
    let canonical = fixture("evidence-canonical.json");

    // C# signature verifies under the Rust verifier.
    let signed = SignedEvidence::from_json(&signed_text).unwrap();
    assert!(EvidenceRunner::verify(&signed, [public_key.as_str()]));
    assert_eq!(signed.mode(), "verified");

    // Rust re-serialization is byte-identical to the C# indented file.
    assert_eq!(
        signed.to_json_indented(),
        signed_text.trim_end_matches('\n')
    );

    // A Rust-built bundle has exactly the C# canonical bytes, so the C# signature
    // also covers the Rust serialization.
    let bundle = csharp_vector_bundle();
    let canonical_rust = bower_integrity::canonical_json::text(&bundle.to_json());
    assert_eq!(canonical_rust, canonical.trim_end_matches('\n'));
    let rebuilt = SignedEvidence {
        bundle: signed.bundle.clone(),
        signature: signed.signature.clone(),
    };
    assert_eq!(
        EvidenceRunner::sign(&bundle, None).unwrap().bundle,
        rebuilt.bundle
    );

    // Tampering with any field breaks the C# signature.
    let mut tampered = signed.clone();
    tampered
        .bundle
        .insert("mode".to_owned(), Value::String("simulated".to_owned()));
    assert!(!EvidenceRunner::verify(&tampered, [public_key.as_str()]));
}

// ---- mock HTTP server for the real clients ----

struct StaticToken;

impl TokenProvider for StaticToken {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        let token = format!("token-for-{}", scope.split('/').nth(2).unwrap_or("unknown"));
        Box::pin(async move {
            Ok(AccessToken {
                token,
                expires_on: parse("2099-01-01T00:00:00Z").unwrap(),
            })
        })
    }
}

#[derive(Default)]
struct Recorded {
    requests: Mutex<Vec<(String, Option<String>, String)>>,
    canary_queries: Mutex<usize>,
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn collector(
    State(state): State<Arc<Recorded>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.requests.lock().unwrap().push((
        "collector".to_owned(),
        bearer(&headers),
        String::from_utf8_lossy(&body).into(),
    ));
    (
        StatusCode::ACCEPTED,
        axum::Json(json!({"decision": "accept", "policy": {"policyId": "BWR-POL-CANARY"}})),
    )
        .into_response()
}

async fn query(
    State(state): State<Arc<Recorded>>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let text = String::from_utf8_lossy(&body).to_string();
    state.requests.lock().unwrap().push((
        format!("query:{workspace}"),
        bearer(&headers),
        text.clone(),
    ));
    if workspace == "forbidden" {
        return (StatusCode::FORBIDDEN, axum::Json(json!({"error": {"code": "InsufficientAccessError", "message": "query text echoed"}})))
            .into_response();
    }
    if workspace == "empty-error" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let request: Value = serde_json::from_str(&text).unwrap();
    if request["query"]
        .as_str()
        .unwrap()
        .starts_with("DCRLogErrors")
    {
        return axum::Json(json!({"tables": [{"name": "PrimaryResult", "columns": [{"name": "Errors", "type": "long"}], "rows": [[3]]}]}))
            .into_response();
    }
    let mut count = state.canary_queries.lock().unwrap();
    *count += 1;
    if *count < 2 {
        return axum::Json(
            json!({"tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]}),
        )
        .into_response();
    }
    axum::Json(json!({"tables": [{"name": "PrimaryResult",
        "columns": [{"name": "TimeGenerated", "type": "datetime"}, {"name": "IngestionTime", "type": "datetime"},
                    {"name": "EventId", "type": "string"}, {"name": "PolicyHash", "type": "string"}],
        "rows": [["2026-10-08T00:00:01Z", "2026-10-08T00:00:42.25Z", "e", "sha256:abc"]]}]}))
    .into_response()
}

async fn arm(
    State(state): State<Arc<Recorded>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let path = uri.path().to_owned();
    state
        .requests
        .lock()
        .unwrap()
        .push((format!("arm:{}", uri), bearer(&headers), String::new()));
    if path.ends_with("/tables/BowerSecurity_CL") {
        axum::Json(json!({"properties": {"plan": "Analytics", "retentionInDays": 90, "totalRetentionInDays": 200}})).into_response()
    } else if path.ends_with("/workspaces/w") {
        axum::Json(json!({"location": "australiasoutheast"})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn start_server() -> (String, Arc<Recorded>) {
    let state = Arc::new(Recorded::default());
    let app = Router::new()
        .route("/v1/events", post(collector))
        .route("/v1/workspaces/{workspace}/query", post(query))
        .route("/subscriptions/{*rest}", get(arm))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), state)
}

#[tokio::test]
async fn end_to_end_against_mock_collector_log_analytics_and_arm() {
    let (base, recorded) = start_server().await;
    let http = reqwest::Client::new();
    let credential: Arc<dyn TokenProvider> = Arc::new(StaticToken);
    let runner = EvidenceRunner::new(
        Arc::new(HttpCanarySender::new(http.clone())),
        Some(Arc::new(
            LogAnalyticsQueryClient::new(http.clone(), credential.clone()).with_endpoint(&base),
        )),
        Some(Arc::new(
            HttpArmReader::new(http, credential).with_endpoint(&base),
        )),
    )
    .with_clock(Arc::new(FixedClock(parse("2026-10-08T00:00:00Z").unwrap())));
    let mut options = EvidenceOptions::new(format!("{base}/").parse().unwrap());
    options.ingest_token = Some("ingest-secret".to_owned());
    options.workspace_id = Some("ws 1".to_owned());
    options.workspace_resource_id = Some(
        "/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w"
            .to_owned(),
    );
    options.poll_interval = Duration::ZERO;
    assert!(!format!("{options:?}").contains("ingest-secret"));

    let bundle = runner.run(&options).await.unwrap();

    assert_eq!(bundle.mode, modes::VERIFIED);
    assert_eq!(bundle.arrival.attempts, 2);
    assert_eq!(bundle.arrival.latency_seconds, Some(42.2)); // 42.25 rounds half to even, like Math.Round
    assert_eq!(
        bundle.arrival.row_policy_hash.as_deref(),
        Some("sha256:abc")
    );
    assert_eq!(bundle.ingestion_errors_last_hour, Some(3));
    let retention = bundle.retention.clone().unwrap();
    assert_eq!(
        (retention.total_days, retention.interactive_days),
        (Some(200), Some(90))
    );
    assert_eq!(
        retention.workspace_region.as_deref(),
        Some("australiasoutheast")
    );
    // 200 days is below the ISM 12-month minimum.
    let ism1988 = bundle
        .controls
        .iter()
        .find(|control| control.id == "ISM-1988")
        .unwrap();
    assert_eq!(ism1988.status, "not-evidenced");
    assert_eq!(
        bundle.controls[0].evidence,
        "Canary BowerSecurity_CL row found by KQL after 42.2 s."
    );

    let requests = recorded.requests.lock().unwrap().clone();
    let (_, collector_auth, canary) = &requests[0];
    assert_eq!(collector_auth.as_deref(), Some("Bearer ingest-secret"));
    assert!(canary.contains(&bundle.canary.event_id));
    let queries: Vec<_> = requests
        .iter()
        .filter(|(kind, _, _)| kind.starts_with("query:"))
        .collect();
    assert_eq!(queries.len(), 3);
    assert!(queries.iter().all(|(kind, auth, _)| kind == "query:ws 1"
        && auth.as_deref() == Some("Bearer token-for-api.loganalytics.io")));
    let first: Value = serde_json::from_str(&queries[0].2).unwrap();
    assert_eq!(first["timespan"], "P1D");
    assert!(
        first["query"]
            .as_str()
            .unwrap()
            .contains(&format!("EventId == \"{}\"", bundle.canary.event_id))
    );
    let errors: Value = serde_json::from_str(&queries[2].2).unwrap();
    assert_eq!(errors["timespan"], "PT1H");
    let arm_requests: Vec<_> = requests
        .iter()
        .filter(|(kind, _, _)| kind.starts_with("arm:"))
        .collect();
    assert_eq!(arm_requests.len(), 2);
    assert!(
        arm_requests
            .iter()
            .all(|(kind, auth, _)| kind.ends_with("?api-version=2025-07-01")
                && auth.as_deref() == Some("Bearer token-for-management.azure.com"))
    );

    // No credential or payload leaks into the bundle.
    let text = EvidenceRunner::sign(&bundle, None)
        .unwrap()
        .to_json_indented();
    assert!(!text.contains("ingest-secret") && !text.contains("token-for"));
}

#[tokio::test]
async fn query_client_keeps_only_the_error_code() {
    let (base, _) = start_server().await;
    let client = LogAnalyticsQueryClient::new(reqwest::Client::new(), Arc::new(StaticToken))
        .with_endpoint(&base);

    let forbidden = client
        .query("forbidden", "T | take 1", Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        forbidden,
        QueryRows {
            rows: Vec::new(),
            error: Some("InsufficientAccessError".to_owned())
        }
    );

    let empty = client
        .query("empty-error", "T | take 1", Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(empty.error.as_deref(), Some("http-401"));
}

#[tokio::test]
async fn query_error_is_reported_when_the_canary_is_never_found() {
    let (base, _) = start_server().await;
    let http = reqwest::Client::new();
    let runner = EvidenceRunner::new(
        Arc::new(HttpCanarySender::new(http.clone())),
        Some(Arc::new(
            LogAnalyticsQueryClient::new(http, Arc::new(StaticToken)).with_endpoint(&base),
        )),
        None,
    );
    let mut options = EvidenceOptions::new(format!("{base}/").parse().unwrap());
    options.workspace_id = Some("forbidden".to_owned());
    options.timeout = Duration::ZERO;

    let bundle = runner.run(&options).await.unwrap();

    assert_eq!(bundle.mode, modes::FAILED);
    assert_eq!(
        bundle.arrival.query_error.as_deref(),
        Some("InsufficientAccessError")
    );
    assert_eq!(bundle.ingestion_errors_last_hour, None);
    assert_eq!(bundle.retention, None);
}

#[tokio::test]
async fn arm_reader_rejects_non_subscription_ids_and_reads_missing_as_none() {
    let (base, _) = start_server().await;
    let reader =
        HttpArmReader::new(reqwest::Client::new(), Arc::new(StaticToken)).with_endpoint(&base);
    assert!(matches!(
        reader.get("https://evil.example/x", "2025-07-01").await,
        Err(EvidenceError::InvalidArgument(_))
    ));
    assert_eq!(
        reader
            .get("/subscriptions/s/missing", "2025-07-01")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn transport_errors_read_like_dotnet() {
    // Port 9 (discard) on loopback is closed: the connection is refused.
    let runner = EvidenceRunner::new(
        Arc::new(HttpCanarySender::new(reqwest::Client::new())),
        None,
        None,
    );
    let options = EvidenceOptions::new("http://127.0.0.1:9/".parse().unwrap());
    match runner.run(&options).await {
        Err(EvidenceError::Http(message)) => {
            assert_eq!(message, "Connection refused (127.0.0.1:9)")
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn arm_resource_id_error_names_the_parameter() {
    let reader = HttpArmReader::new(reqwest::Client::new(), Arc::new(StaticToken));
    match reader.get("relative/id", "2025-07-01").await {
        Err(error) => assert_eq!(
            error.to_string(),
            "Resource id must start with /subscriptions/. (Parameter 'resourceId')"
        ),
        Ok(_) => panic!("expected an argument error"),
    }
}

/// Writes a Rust-signed bundle for the C# cross-check (`EvidenceRunner.Verify`):
/// `RUST_PACKS=<dir> cargo test -p bower-evidence -- --ignored emit_rust_evidence`
/// after the bower-packs emitter has written `rust.key.pem` there.
#[test]
#[ignore = "writes cross-implementation artifacts; run manually"]
fn emit_rust_evidence_for_csharp() {
    let Ok(directory) = std::env::var("RUST_PACKS") else {
        return;
    };
    let key = std::fs::read_to_string(format!("{directory}/rust.key.pem")).unwrap();
    let signed = EvidenceRunner::sign(&csharp_vector_bundle(), Some(&key)).unwrap();
    std::fs::write(
        format!("{directory}/evidence.json"),
        signed.to_json_indented(),
    )
    .unwrap();
}
