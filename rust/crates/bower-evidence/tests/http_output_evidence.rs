//! Evidence for a collector whose output is `http` never claims Sentinel delivery (C#
//! `HttpOutputEvidenceTests`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_evidence::probe::outcomes;
use bower_evidence::{
    BoxFuture, CanarySender, CollectorResponse, EvidenceError, EvidenceOptions, EvidenceRunner,
    LogAnalyticsQuery, ParserProbeSender, QueryRows, modes,
};
use serde_json::{Map, Value, json};

const WORKSPACE: &str = "00000000-0000-0000-0000-000000000001";

fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        unreachable!()
    };
    map
}

/// A collector reporting `output` in `/v1/status`, with an active SSH parser.
struct StatusCollector {
    output: &'static str,
    canaries: Mutex<usize>,
    records: Mutex<usize>,
}

impl StatusCollector {
    fn new(output: &'static str) -> Arc<Self> {
        Arc::new(Self {
            output,
            canaries: Mutex::new(0),
            records: Mutex::new(0),
        })
    }
}

impl CanarySender for StatusCollector {
    fn send<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
        _json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        *self.canaries.lock().unwrap() += 1;
        Box::pin(async move { Ok((202, Some(object(json!({"decision": "accept"}))))) })
    }
}

impl ParserProbeSender for StatusCollector {
    fn get_status<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        let body = object(
            json!({"output": self.output, "policy": {"hash": "sha256:bundle", "packs": [{
                "id": "linux-ssh-gateway", "version": "1.1.0", "packHash": "sha256:pack",
                "parserStatuses": ["active-local-json"]
            }]}}),
        );
        Box::pin(async move { Ok((200, Some(body))) })
    }

    fn send_record<'a>(
        &'a self,
        _collector: &'a reqwest::Url,
        _token: Option<&'a str>,
        _pack_id: &'a str,
        _parser_index: i32,
        _json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        *self.records.lock().unwrap() += 1;
        Box::pin(async move { Ok((202, Some(Map::new()))) })
    }
}

/// A destination that returns a row for any canary query.
#[derive(Default)]
struct RowQuery {
    queries: Mutex<Vec<String>>,
}

impl LogAnalyticsQuery for RowQuery {
    fn query<'a>(
        &'a self,
        _workspace_id: &'a str,
        kql: &'a str,
        _timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        self.queries.lock().unwrap().push(kql.to_owned());
        let rows = if kql.starts_with("DCRLogErrors") {
            vec![object(json!({"Errors": 0}))]
        } else {
            vec![object(json!({
                "TimeGenerated": "2026-11-05T01:02:03Z",
                "IngestionTime": "2026-11-05T01:03:03Z",
                "PolicyHash": "sha256:policy"
            }))]
        };
        Box::pin(async move { Ok(QueryRows { rows, error: None }) })
    }
}

fn options(workspace: Option<&str>) -> EvidenceOptions {
    let mut options = EvidenceOptions::new("http://collector.test:4319/".parse().unwrap());
    options.workspace_id = workspace.map(str::to_owned);
    options.poll_interval = Duration::ZERO;
    options.timeout = Duration::from_secs(5);
    options
}

fn runner(collector: &Arc<StatusCollector>, query: Option<Arc<RowQuery>>) -> EvidenceRunner {
    EvidenceRunner::new(
        collector.clone(),
        query.map(|query| query as Arc<dyn LogAnalyticsQuery>),
        None,
    )
    .with_parser_sender(collector.clone())
}

fn not_sentinel(limitations: &[String]) -> bool {
    limitations
        .iter()
        .any(|item| item.starts_with("NOT SENTINEL:"))
}

#[tokio::test]
async fn canary_for_an_http_output_fails_without_querying_sentinel() {
    let collector = StatusCollector::new("http");
    let query = Arc::new(RowQuery::default());

    let bundle = runner(&collector, Some(query.clone()))
        .run(&options(Some(WORKSPACE)))
        .await
        .unwrap();

    assert_eq!(bundle.mode, modes::FAILED);
    assert!(!bundle.arrival.found);
    assert_eq!(
        bundle.arrival.query_error.as_deref(),
        Some(outcomes::OUTPUT_NOT_SENTINEL)
    );
    assert!(not_sentinel(&bundle.limitations));
    // The canary was still sent through the real pipeline, but Sentinel was never asked for it.
    assert_eq!(*collector.canaries.lock().unwrap(), 1);
    assert!(
        query
            .queries
            .lock()
            .unwrap()
            .iter()
            .all(|kql| !kql.contains(&bundle.canary.event_id))
    );
}

#[tokio::test]
async fn simulated_canary_for_an_http_output_says_it_is_not_sentinel() {
    let bundle = runner(&StatusCollector::new("http"), None)
        .run(&options(None))
        .await
        .unwrap();

    assert_eq!(bundle.mode, modes::SIMULATED);
    assert!(not_sentinel(&bundle.limitations));
    assert!(
        bundle
            .limitations
            .iter()
            .any(|item| item.starts_with("SIMULATED:"))
    );
}

#[tokio::test]
async fn sentinel_outputs_still_verify_by_query() {
    let bundle = runner(
        &StatusCollector::new("azure-logs-ingestion"),
        Some(Arc::new(RowQuery::default())),
    )
    .run(&options(Some(WORKSPACE)))
    .await
    .unwrap();

    assert_eq!(bundle.mode, modes::VERIFIED);
    assert!(!not_sentinel(&bundle.limitations));
}

#[tokio::test]
async fn parser_probe_for_an_http_output_is_not_sent_or_queried() {
    let collector = StatusCollector::new("http");
    let query = Arc::new(RowQuery::default());
    let mut options = options(Some(WORKSPACE));
    options.probe_profile = "parser:linux-ssh-gateway:0".into();

    let bundle = runner(&collector, Some(query.clone()))
        .run(&options)
        .await
        .unwrap();

    let probe = bundle.probe.as_ref().unwrap();
    assert_eq!(bundle.mode, modes::FAILED);
    assert_eq!(probe.outcome, outcomes::OUTPUT_NOT_SENTINEL);
    assert_eq!(
        bundle.arrival.query_error.as_deref(),
        Some(outcomes::OUTPUT_NOT_SENTINEL)
    );
    assert_eq!(*collector.records.lock().unwrap(), 0);
    assert!(not_sentinel(&bundle.limitations));
    assert!(
        query
            .queries
            .lock()
            .unwrap()
            .iter()
            .all(|kql| !kql.contains(&probe.event_id))
    );
}
