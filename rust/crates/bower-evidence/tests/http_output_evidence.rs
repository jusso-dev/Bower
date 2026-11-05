//! Evidence never claims Sentinel delivery for an output outside the Sentinel allowlist
//! (C# `HttpOutputEvidenceTests`).

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
    output: Option<&'static str>,
    status_code: u16,
    canaries: Mutex<usize>,
    records: Mutex<usize>,
}

impl StatusCollector {
    fn new(output: Option<&'static str>, status_code: u16) -> Arc<Self> {
        Arc::new(Self {
            output,
            status_code,
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
        let status = self.status_code;
        Box::pin(async move { Ok((status, Some(body))) })
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
async fn non_sentinel_output_is_refused_without_sending_a_canary_or_querying() {
    for (output, profile, label) in [
        ("http", None, "http"),
        ("http", Some("parser:linux-ssh-gateway:0"), "http"),
        ("s3", None, "s3"),
        (
            "future-output",
            Some("parser:linux-ssh-gateway:0"),
            "future-output",
        ),
        ("Not An Id!", None, "unknown"),
    ] {
        let collector = StatusCollector::new(Some(output), 200);
        let query = Arc::new(RowQuery::default());
        let mut options = options(Some(WORKSPACE));
        if let Some(profile) = profile {
            options.probe_profile = profile.into();
        }

        let bundle = runner(&collector, Some(query.clone()))
            .run(&options)
            .await
            .unwrap();
        options.workspace_id = None;
        let simulated = runner(&collector, None).run(&options).await.unwrap();

        assert_eq!(bundle.mode, modes::FAILED, "{output}");
        assert_eq!(simulated.mode, modes::SIMULATED, "{output}");
        assert!(!bundle.arrival.found);
        assert_eq!(
            bundle.arrival.query_error.as_deref(),
            Some(outcomes::COLLECTOR_OUTPUT_NOT_SENTINEL),
            "{output}"
        );
        let limitation = bower_evidence::probe::non_sentinel_limitation(label);
        assert!(bundle.limitations.contains(&limitation), "{output}");
        assert!(simulated.limitations.contains(&limitation), "{output}");
        assert_eq!(*collector.canaries.lock().unwrap(), 0, "{output}");
        assert_eq!(*collector.records.lock().unwrap(), 0, "{output}");
        assert!(
            query
                .queries
                .lock()
                .unwrap()
                .iter()
                .all(|kql| !kql.contains(&bundle.canary.event_id))
        );
        if profile.is_some() {
            assert_eq!(
                bundle.probe.as_ref().unwrap().outcome,
                outcomes::COLLECTOR_OUTPUT_NOT_SENTINEL
            );
        }
    }
}

#[tokio::test]
async fn sentinel_relay_missing_or_unreadable_output_proceeds_and_only_the_query_verifies() {
    for (output, status) in [
        (Some("azure-logs-ingestion"), 200),
        (Some("ama-spool"), 200),
        (Some("relay"), 200),
        (None, 200),
        (Some("http"), 503),
    ] {
        let collector = StatusCollector::new(output, status);
        let bundle = runner(&collector, Some(Arc::new(RowQuery::default())))
            .run(&options(Some(WORKSPACE)))
            .await
            .unwrap();

        assert_eq!(bundle.mode, modes::VERIFIED, "{output:?}");
        assert_eq!(*collector.canaries.lock().unwrap(), 1, "{output:?}");
        assert!(!not_sentinel(&bundle.limitations));
    }
}
