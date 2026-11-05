//! HTTP output (C# `HttpOutputTests`). Request and response vectors in
//! `tests/fixtures/http-output/vectors.json` (repo root) are shared with the C# tests.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use bower_contracts::time::Timestamp;
use bower_contracts::{OutputAdapter, QueueState, QueuedEvent};
use bower_output_http::output::{MAXIMUM_RESPONSE_BYTES, SPLIT_BUDGET, event_time, uses_proxy};
use bower_output_http::{HttpOutput, HttpOutputFormat, HttpOutputOptions};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use reqwest::Url;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn now() -> Timestamp {
    chrono::DateTime::parse_from_rfc3339("2026-11-05T01:02:03+00:00").unwrap()
}

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/http-output/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn event(id: &str, fingerprint: &str, payload: &str) -> QueuedEvent {
    QueuedEvent {
        event_id: id.to_string(),
        fingerprint: fingerprint.to_string(),
        payload: payload.to_string(),
        received_at: now(),
        state: QueueState::Queued,
        delivery_attempts: 0,
        lease_token: None,
        suppression: None,
    }
}

fn events(count: usize) -> Vec<QueuedEvent> {
    (0..count)
        .map(|index| {
            event(
                &format!("e{index}"),
                &format!("f{index}"),
                &format!(r#"{{"eventId":"e{index}","n":{index}}}"#),
            )
        })
        .collect()
}

fn text(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}

// ------------------------------------------------------------------ test endpoint

#[derive(Clone, Debug)]
struct Captured {
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Captured {
    fn lines(&self) -> usize {
        self.body.iter().filter(|byte| **byte == b'\n').count()
    }
}

#[derive(Clone, Default)]
struct Reply {
    status: u16,
    body: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
    stall: bool,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    fn hec_success() -> Self {
        Self::status(200).body(r#"{"text":"Success","code":0}"#)
    }

    fn body(mut self, body: &str) -> Self {
        self.body = Some(body.as_bytes().to_vec());
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

type Responder = Arc<dyn Fn(&Captured) -> Reply + Send + Sync>;

#[derive(Clone)]
struct Endpoint {
    requests: Arc<Mutex<Vec<Captured>>>,
    responder: Arc<Mutex<Responder>>,
    port: u16,
    https: bool,
}

impl Endpoint {
    fn url(&self, host: &str) -> Url {
        let scheme = if self.https { "https" } else { "http" };
        Url::parse(&format!(
            "{scheme}://{host}:{}/services/collector/event",
            self.port
        ))
        .unwrap()
    }

    fn reply(&self, responder: impl Fn(&Captured) -> Reply + Send + Sync + 'static) {
        *self.responder.lock().unwrap() = Arc::new(responder);
    }

    fn requests(&self) -> Vec<Captured> {
        self.requests.lock().unwrap().clone()
    }
}

async fn handle(State(endpoint): State<Endpoint>, headers: HeaderMap, body: Bytes) -> Response {
    let captured = Captured {
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect(),
        body: body.to_vec(),
    };
    endpoint.requests.lock().unwrap().push(captured.clone());
    let responder = Arc::clone(&endpoint.responder.lock().unwrap());
    let reply = responder(&captured);
    if reply.stall {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
    let mut response = Response::builder().status(StatusCode::from_u16(reply.status).unwrap());
    for (name, value) in &reply.headers {
        response = response.header(name, value);
    }
    response
        .body(reply.body.map_or_else(Body::empty, Body::from))
        .unwrap()
}

async fn start(tls: Option<rustls::ServerConfig>) -> Endpoint {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let responder: Responder = Arc::new(|_| Reply::hec_success());
    let endpoint = Endpoint {
        requests: Arc::default(),
        responder: Arc::new(Mutex::new(responder)),
        port: listener.local_addr().unwrap().port(),
        https: tls.is_some(),
    };
    let router = Router::new().fallback(handle).with_state(endpoint.clone());
    match tls {
        None => {
            tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        }
        Some(config) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (acceptor, router) = (acceptor.clone(), router.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let service = hyper_util::service::TowerToHyperService::new(router);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                            .await;
                    });
                }
            });
        }
    }
    endpoint
}

fn hec_options(endpoint: &Endpoint) -> HttpOutputOptions {
    let mut options = HttpOutputOptions::new(endpoint.url("127.0.0.1"), "edge-01");
    options.allow_insecure_loopback = true;
    options
}

// ------------------------------------------------------------------ shared vectors

fn vector_options(options: &Value, endpoint: Url) -> HttpOutputOptions {
    let mut result = HttpOutputOptions::new(
        endpoint,
        text(options, "hecHost").unwrap_or_else(|| "edge-01".into()),
    );
    result.allow_insecure_loopback = true;
    result.format = if text(options, "format").as_deref() == Some("ndjson") {
        HttpOutputFormat::Ndjson
    } else {
        HttpOutputFormat::SplunkHec
    };
    result.authorization_header = text(options, "authorizationHeader");
    result.hec_index = text(options, "hecIndex");
    if let Some(source) = text(options, "hecSource") {
        result.hec_source = source;
    }
    if let Some(source_type) = text(options, "hecSourceType") {
        result.hec_source_type = source_type;
    }
    result.hec_channel = text(options, "hecChannel");
    if let Some(bytes) = options.get("maximumBatchBytes").and_then(Value::as_u64) {
        result.maximum_batch_bytes = usize::try_from(bytes).unwrap();
    }
    if let Some(count) = options.get("maximumBatchEvents").and_then(Value::as_u64) {
        result.maximum_batch_events = usize::try_from(count).unwrap();
    }
    result.gzip = options
        .get("gzip")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    result
}

#[tokio::test]
async fn request_vectors_match_shared_bytes_headers_and_outcomes() {
    let vectors = vectors();
    let token = text(&vectors, "token").unwrap();
    for vector in vectors["requests"].as_array().unwrap() {
        let name = text(vector, "name").unwrap();
        let endpoint = start(None).await;
        let output = HttpOutput::new(
            vector_options(&vector["options"], endpoint.url("127.0.0.1")),
            &token,
        )
        .unwrap();
        let queued: Vec<QueuedEvent> = vector["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                event(
                    &text(item, "eventId").unwrap(),
                    &text(item, "fingerprint").unwrap(),
                    &text(item, "payload").unwrap(),
                )
            })
            .collect();

        let result = output.deliver(&queued).await;

        let expected: Vec<String> = vector["expectedBodies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|body| body.as_str().unwrap().to_string())
            .collect();
        let requests = endpoint.requests();
        assert_eq!(requests.len(), expected.len(), "{name}");
        for (request, expected) in requests.iter().zip(&expected) {
            let body =
                if request.headers.get("content-encoding").map(String::as_str) == Some("gzip") {
                    let mut plain = Vec::new();
                    flate2::read::GzDecoder::new(request.body.as_slice())
                        .read_to_end(&mut plain)
                        .unwrap();
                    plain
                } else {
                    request.body.clone()
                };
            assert_eq!(String::from_utf8(body).unwrap(), *expected, "{name}");
            for (header, value) in vector["expectedHeaders"].as_object().unwrap() {
                assert_eq!(
                    request.headers.get(header).map(String::as_str),
                    value.as_str(),
                    "{name}: {header}"
                );
            }
            // The token travels in exactly one header and nowhere else.
            assert_eq!(
                request
                    .headers
                    .values()
                    .filter(|value| value.contains(&token))
                    .count(),
                1,
                "{name}"
            );
        }
        let failures: Vec<(String, String)> = vector["expectedFailures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| (text(item, "eventId").unwrap(), text(item, "code").unwrap()))
            .collect();
        assert_eq!(
            result
                .failures
                .iter()
                .map(|failure| (failure.event_id.clone(), failure.code.clone()))
                .collect::<Vec<_>>(),
            failures,
            "{name}"
        );
        assert!(result.failures.iter().all(|failure| !failure.is_retryable));
        let failed: Vec<&String> = failures.iter().map(|(id, _)| id).collect();
        assert_eq!(
            result.acknowledged_event_ids,
            queued
                .iter()
                .map(|item| item.event_id.clone())
                .filter(|id| !failed.contains(&id))
                .collect::<Vec<_>>(),
            "{name}"
        );
        assert_eq!(
            result.destination_acknowledgement,
            text(vector, "expectedAcknowledgement"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn response_vectors_classify_as_shared() {
    let vectors = vectors();
    let token = text(&vectors, "token").unwrap();
    for vector in vectors["responses"].as_array().unwrap() {
        let name = text(vector, "name").unwrap();
        let endpoint = start(None).await;
        let mut reply = Reply::status(u16::try_from(vector["status"].as_u64().unwrap()).unwrap());
        if let Some(body) = text(vector, "body") {
            let padding = usize::try_from(vector["bodyPadding"].as_u64().unwrap()).unwrap();
            reply = reply.body(&format!("{body}{}", " ".repeat(padding)));
        }
        if let Some(retry_after) = text(vector, "retryAfter") {
            reply = reply.header("Retry-After", &retry_after);
        }
        if let Some(location) = text(vector, "location") {
            reply = reply.header("Location", &location);
        }
        endpoint.reply(move |_| reply.clone());
        let mut options = hec_options(&endpoint);
        if text(vector, "format").as_deref() == Some("ndjson") {
            options.format = HttpOutputFormat::Ndjson;
        }
        let output = HttpOutput::new(options, &token)
            .unwrap()
            .with_clock(Arc::new(now));

        let result = output
            .deliver(&[event(
                "evt-r",
                "f",
                r#"{"eventId":"evt-r","timeGenerated":"2026-11-05T01:02:03Z"}"#,
            )])
            .await;

        assert_eq!(endpoint.requests().len(), 1, "{name}");
        if vector["accepted"].as_bool().unwrap() {
            assert_eq!(result.acknowledged_event_ids, ["evt-r"], "{name}");
            assert!(result.failures.is_empty(), "{name}");
            continue;
        }
        assert!(result.acknowledged_event_ids.is_empty(), "{name}");
        assert_eq!(result.destination_acknowledgement, None, "{name}");
        assert_eq!(result.failures.len(), 1, "{name}");
        let failure = &result.failures[0];
        assert_eq!(failure.event_id, "evt-r", "{name}");
        assert_eq!(Some(failure.code.clone()), text(vector, "code"), "{name}");
        assert_eq!(
            Some(failure.is_retryable),
            vector["retryable"].as_bool(),
            "{name}"
        );
        assert_eq!(
            failure.is_destination_failure(),
            vector["destination"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            failure.retry_after,
            vector["retryAfterSeconds"]
                .as_i64()
                .map(|seconds| now() + chrono::Duration::seconds(seconds)),
            "{name}"
        );
    }
}

#[test]
fn event_time_follows_the_strict_rules() {
    assert_eq!(
        event_time(Some("2026-11-05T01:02:03.4567891+00:00")).as_deref(),
        Some("1793840523.456")
    );
    assert_eq!(
        event_time(Some("2026-11-05T01:02:03.999-14:00")).as_deref(),
        Some("1793890923.999")
    );
    for refused in [
        "2026-11-05 01:02:03Z",
        "2026-11-05T01:02:60Z",
        "2026-11-05T01:02:03+14:01",
        "2026-11-05T01:02:03+10:60",
        "1969-12-31T23:59:59.999Z",
        "0000-01-01T00:00:00Z",
        "9999-12-31T23:59:59-01:00",
        "2026-11-05T01:02:03.12345678Z",
        "2026-11-05T01:02:03Z\n",
        "２026-11-05T01:02:03Z",
    ] {
        assert_eq!(event_time(Some(refused)), None, "{refused}");
    }
}

// ------------------------------------------------------------------ batching and failures

#[tokio::test]
async fn payload_too_large_for_the_endpoint_splits_the_batch_until_accepted() {
    let endpoint = start(None).await;
    // The endpoint takes at most two records per request.
    endpoint.reply(|request| {
        if request.lines() > 2 {
            Reply::status(413).body(r#"{"text":"Content too large","code":27}"#)
        } else {
            Reply::hec_success()
        }
    });
    let output = HttpOutput::new(hec_options(&endpoint), "token-1").unwrap();
    let queued = events(7);

    let result = output.deliver(&queued).await;

    let ids: Vec<String> = queued.iter().map(|item| item.event_id.clone()).collect();
    assert_eq!(result.acknowledged_event_ids, ids);
    assert!(result.failures.is_empty());
    let accepted: Vec<String> = endpoint
        .requests()
        .iter()
        .filter(|request| request.lines() <= 2)
        .flat_map(|request| {
            String::from_utf8(request.body.clone())
                .unwrap()
                .lines()
                .map(|line| {
                    serde_json::from_str::<Value>(line).unwrap()["fields"]["bower_event_id"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(accepted, ids);
}

#[tokio::test]
async fn always_too_large_endpoint_is_held_within_the_split_budget() {
    let endpoint = start(None).await;
    endpoint.reply(|_| Reply::status(413));
    let output = HttpOutput::new(hec_options(&endpoint), "token-1").unwrap();

    let single = output.deliver(&events(1)).await;
    assert_eq!(single.failures.len(), 1);
    assert_eq!(single.failures[0].code, "destination-http-413");
    assert!(single.failures[0].is_retryable);

    endpoint.requests.lock().unwrap().clear();
    let many = output.deliver(&events(200)).await;

    // One request plus two per split, never more; nothing is poison without a sibling's success.
    assert_eq!(endpoint.requests().len(), 1 + 2 * SPLIT_BUDGET);
    assert!(many.acknowledged_event_ids.is_empty());
    assert_eq!(many.failures.len(), 200);
    assert!(many.failures.iter().all(|failure| {
        failure.code == "destination-http-413" && failure.is_destination_failure()
    }));
}

/// Event ids in a request body (HEC `fields.bower_event_id` or the NDJSON `eventId`).
fn ids(request: &Captured) -> Vec<String> {
    String::from_utf8(request.body.clone())
        .unwrap()
        .lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap();
            value["fields"]["bower_event_id"]
                .as_str()
                .or_else(|| value["eventId"].as_str())
                .unwrap()
                .to_string()
        })
        .collect()
}

/// The shared scenario endpoint: always, then by request number, then a record cap, then
/// rejected ids.
fn scenario_reply(rule: &Value, request: usize, ids: &[String]) -> Reply {
    let reply = |value: &Value| {
        let reply = Reply::status(u16::try_from(value["status"].as_u64().unwrap()).unwrap());
        match value["body"].as_str() {
            Some(body) => reply.body(body),
            None => reply,
        }
    };
    if let Some(always) = rule.get("always") {
        return reply(always);
    }
    if let Some(by_request) = rule
        .get("byRequest")
        .and_then(|by| by.get(request.to_string()))
    {
        return reply(by_request);
    }
    if let Some(maximum) = rule.get("maxRecords").and_then(Value::as_u64)
        && ids.len() > usize::try_from(maximum).unwrap()
    {
        return Reply::status(413);
    }
    match rule.get("reject") {
        Some(reject)
            if ids.iter().any(|id| {
                reject["eventIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item.as_str() == Some(id))
            }) =>
        {
            reply(reject)
        }
        _ => Reply::hec_success(),
    }
}

#[tokio::test]
async fn scenario_vectors_isolate_poison_and_hold_everything_else() {
    for vector in vectors()["scenarios"].as_array().unwrap() {
        let name = text(vector, "name").unwrap();
        let endpoint = start(None).await;
        let rule = vector["endpoint"].clone();
        let counter = Arc::new(Mutex::new(0usize));
        let counted = Arc::clone(&counter);
        endpoint.reply(move |request| {
            let mut count = counted.lock().unwrap();
            *count += 1;
            scenario_reply(&rule, *count, &ids(request))
        });
        let output = HttpOutput::new(
            vector_options(&vector["options"], endpoint.url("127.0.0.1")),
            "token-1",
        )
        .unwrap();
        let queued: Vec<QueuedEvent> = (0..vector["events"].as_u64().unwrap())
            .map(|index| {
                event(
                    &format!("s-{index}"),
                    "f",
                    &format!(r#"{{"eventId":"s-{index}"}}"#),
                )
            })
            .collect();

        let result = output.deliver(&queued).await;

        assert_eq!(
            *counter.lock().unwrap() as u64,
            vector["expectedRequests"].as_u64().unwrap(),
            "{name}"
        );
        let acknowledged: Vec<String> = vector["expectedAcknowledged"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect();
        assert_eq!(result.acknowledged_event_ids, acknowledged, "{name}");
        let expected: Vec<(String, String, bool)> = vector["expectedFailures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    text(item, "eventId").unwrap(),
                    text(item, "code").unwrap(),
                    item["retryable"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            result
                .failures
                .iter()
                .map(|failure| (
                    failure.event_id.clone(),
                    failure.code.clone(),
                    failure.is_retryable
                ))
                .collect::<Vec<_>>(),
            expected,
            "{name}"
        );
        assert!(
            result
                .failures
                .iter()
                .all(|failure| failure.is_retryable == failure.is_destination_failure()),
            "{name}"
        );
    }
}

#[tokio::test]
async fn destination_failure_stops_later_batches_and_keeps_them_retryable() {
    let endpoint = start(None).await;
    let calls = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&calls);
    endpoint.reply(move |_| {
        let mut calls = counted.lock().unwrap();
        *calls += 1;
        if *calls == 1 {
            Reply::hec_success()
        } else {
            Reply::status(503)
                .body(r#"{"text":"Server is busy","code":9}"#)
                .header("Retry-After", "120")
        }
    });
    let mut options = hec_options(&endpoint);
    options.maximum_batch_events = 2;
    let output = HttpOutput::new(options, "token-1")
        .unwrap()
        .with_clock(Arc::new(now));

    let result = output.deliver(&events(7)).await;

    assert_eq!(endpoint.requests().len(), 2);
    assert_eq!(result.acknowledged_event_ids, ["e0", "e1"]);
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        Some("http:splunk-hec:endpoint-accepted")
    );
    assert_eq!(result.failures.len(), 5);
    for failure in &result.failures {
        assert_eq!(failure.code, "destination-http-503:hec-9");
        assert!(failure.is_retryable);
        assert_eq!(
            failure.retry_after,
            Some(now() + chrono::Duration::seconds(120))
        );
    }
}

#[tokio::test]
async fn stalled_endpoint_times_out_as_destination_failure() {
    let endpoint = start(None).await;
    endpoint.reply(|_| Reply {
        stall: true,
        ..Reply::hec_success()
    });
    let mut options = hec_options(&endpoint);
    options.timeout = Duration::from_secs(1);
    let output = HttpOutput::new(options, "token-1").unwrap();

    let result = output.deliver(&events(3)).await;

    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), 3);
    assert!(result.failures.iter().all(|failure| {
        failure.code == "destination-http-timeout" && failure.is_destination_failure()
    }));
}

/// A raw HTTP/1.1 server answering `200` with a chunked body of `size` bytes, no length.
async fn chunked_server(body: Vec<u8>, stall_after: bool) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(body);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tcp.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let length = String::from_utf8_lossy(&head)
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut request = vec![0u8; length];
                let _ = tcp.read_exact(&mut request).await;
                let _ = tcp
                    .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await;
                for chunk in body.chunks(8192) {
                    let _ = tcp
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await;
                    let _ = tcp.write_all(chunk).await;
                    let _ = tcp.write_all(b"\r\n").await;
                }
                if stall_after {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
                let _ = tcp.write_all(b"0\r\n\r\n").await;
            });
        }
    });
    port
}

#[tokio::test]
async fn unbounded_chunked_response_is_not_read_past_the_limit() {
    let mut body = b"{\"code\":0".to_vec();
    body.extend(std::iter::repeat_n(b' ', MAXIMUM_RESPONSE_BYTES));
    body.push(b'}');
    let port = chunked_server(body, false).await;
    let mut options = HttpOutputOptions::new(
        Url::parse(&format!("http://127.0.0.1:{port}/services/collector/event")).unwrap(),
        "h",
    );
    options.allow_insecure_loopback = true;
    let output = HttpOutput::new(options, "token-1").unwrap();

    let result = output.deliver(&events(1)).await;

    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].code, "destination-http-response-invalid");
}

#[tokio::test]
async fn stalled_response_body_is_bounded_by_the_same_deadline() {
    let port = chunked_server(b"{\"code\":0".to_vec(), true).await;
    let mut options = HttpOutputOptions::new(
        Url::parse(&format!("http://127.0.0.1:{port}/services/collector/event")).unwrap(),
        "h",
    );
    options.allow_insecure_loopback = true;
    options.timeout = Duration::from_secs(1);
    let output = HttpOutput::new(options, "token-1").unwrap();

    let result = output.deliver(&events(1)).await;

    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].code, "destination-http-timeout");
}

// ------------------------------------------------------------------ TLS policy

struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
    bundle: PathBuf,
}

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

fn authority(directory: &Path) -> Authority {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.distinguished_name
        .push(DnType::CommonName, "Bower HTTP Output Test CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut ca, -1, 30);
    let issuer = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
    let bundle = directory.join("ca.pem");
    std::fs::write(&bundle, issuer.pem()).unwrap();
    Authority { issuer, bundle }
}

fn server_config(authority: &Authority, names: &[&str]) -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    validity(&mut params, -1, 7);
    let certificate = params.signed_by(&key, &authority.issuer).unwrap();
    rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap()
}

#[tokio::test]
async fn tls_untrusted_certificate_is_refused_and_the_ca_bundle_trusts_it() {
    let directory = tempfile::tempdir().unwrap();
    let authority = authority(directory.path());
    let endpoint = start(Some(server_config(&authority, &["localhost"]))).await;

    let untrusted = HttpOutput::new(
        HttpOutputOptions::new(endpoint.url("localhost"), "h"),
        "token-1",
    )
    .unwrap();
    let refused = untrusted.deliver(&events(1)).await;
    let mut options = HttpOutputOptions::new(endpoint.url("localhost"), "h");
    options.ca_bundle_path = Some(authority.bundle.clone());
    let trusted = HttpOutput::new(options, "token-1").unwrap();
    let accepted = trusted.deliver(&events(1)).await;

    assert_eq!(refused.failures.len(), 1);
    assert_eq!(refused.failures[0].code, "destination-http-unavailable");
    assert_eq!(accepted.acknowledged_event_ids, ["e0"]);
    // The refused handshake never carried the token: only the trusted request arrived.
    assert_eq!(endpoint.requests().len(), 1);
}

#[tokio::test]
async fn tls_ca_bundle_never_overrides_a_host_name_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let authority = authority(directory.path());
    let endpoint = start(Some(server_config(&authority, &["other.example.test"]))).await;
    let mut options = HttpOutputOptions::new(endpoint.url("localhost"), "h");
    options.ca_bundle_path = Some(authority.bundle.clone());
    let output = HttpOutput::new(options, "token-1").unwrap();

    let result = output.deliver(&events(1)).await;

    assert_eq!(result.failures[0].code, "destination-http-unavailable");
    assert!(endpoint.requests().is_empty());
}

#[test]
fn endpoint_vectors_allow_plain_http_only_to_loopback_addresses() {
    for vector in vectors()["endpoints"].as_array().unwrap() {
        let url = text(vector, "url").unwrap();
        let mut options = HttpOutputOptions::new(Url::parse(&url).unwrap(), "h");
        options.allow_insecure_loopback = vector["allowInsecureLoopback"].as_bool().unwrap();
        match options.validate() {
            Ok(()) => assert!(vector["valid"].as_bool().unwrap(), "{url}"),
            Err(error) => {
                assert!(!vector["valid"].as_bool().unwrap(), "{url}");
                assert!(
                    error
                        .0
                        .starts_with("BOWER_HTTP_URL must be an absolute https:// URL"),
                    "{url}"
                );
            }
        }
    }
}

#[test]
fn endpoint_policy_refuses_credentialed_or_odd_urls_without_echoing_them() {
    for url in [
        "https://user:pass@splunk.example.test/services/collector/event",
        "https://splunk.example.test/services/collector/event?token=abc",
        "https://splunk.example.test/services/collector/event#x",
        "ftp://splunk.example.test/",
    ] {
        let mut options = HttpOutputOptions::new(Url::parse(url).unwrap(), "h");
        options.allow_insecure_loopback = true;
        let error = options.validate().unwrap_err().0;
        assert!(!error.contains("pass") && !error.contains("abc"), "{url}");
    }
}

#[test]
fn plain_http_never_uses_a_proxy_and_https_keeps_the_standard_proxy_settings() {
    let mut plain = HttpOutputOptions::new(Url::parse("http://127.0.0.1:8088/x").unwrap(), "h");
    plain.allow_insecure_loopback = true;
    let secure = HttpOutputOptions::new(Url::parse("https://splunk.example.test/x").unwrap(), "h");

    assert!(!uses_proxy(&plain));
    assert!(uses_proxy(&secure));
}

#[test]
fn auth_header_vectors_allow_only_names_that_can_carry_the_token() {
    for vector in vectors()["authHeaderNames"].as_array().unwrap() {
        let name = text(vector, "name").unwrap();
        let mut options =
            HttpOutputOptions::new(Url::parse("https://intake.example.test/x").unwrap(), "h");
        options.format = HttpOutputFormat::Ndjson;
        options.authorization_header = Some(name.clone());
        let result = HttpOutput::new(options, "token-1");
        if vector["allowed"].as_bool().unwrap() {
            assert!(result.is_ok(), "{name:?}");
        } else {
            assert!(
                result
                    .err()
                    .unwrap()
                    .0
                    .starts_with("BOWER_HTTP_AUTH_HEADER must be an HTTP header name"),
                "{name:?}"
            );
        }
    }
}

#[test]
fn tls_ca_bundle_with_an_intermediate_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let authority = authority(directory.path());
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "Bower HTTP Output Test Intermediate");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut params, -1, 7);
    let intermediate = params
        .signed_by(&KeyPair::generate().unwrap(), &authority.issuer)
        .unwrap();
    let bundle = directory.path().join("with-intermediate.pem");
    std::fs::write(
        &bundle,
        format!("{}\n{}", authority.issuer.pem(), intermediate.pem()),
    )
    .unwrap();
    let mut options =
        HttpOutputOptions::new(Url::parse("https://hec.example.test/x").unwrap(), "h");
    options.ca_bundle_path = Some(bundle);

    assert_eq!(
        HttpOutput::new(options, "token-1").err().unwrap().0,
        "BOWER_HTTP_CA_BUNDLE must hold only self-signed root CA certificates, not intermediates."
    );
}

#[test]
fn a_missing_or_empty_ca_bundle_fails_startup() {
    let directory = tempfile::tempdir().unwrap();
    let empty = directory.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    for path in [directory.path().join("missing.pem"), empty] {
        let mut options =
            HttpOutputOptions::new(Url::parse("https://hec.example.test/x").unwrap(), "h");
        options.ca_bundle_path = Some(path);
        assert_eq!(
            HttpOutput::new(options, "token-1").err().unwrap().0,
            "BOWER_HTTP_CA_BUNDLE must name a readable PEM file of CA certificates."
        );
    }
}

#[test]
fn token_is_never_echoed() {
    let options = HttpOutputOptions::new(Url::parse("https://hec.example.test/x").unwrap(), "h");
    let error = HttpOutput::new(options.clone(), "s3cret token with spaces")
        .err()
        .unwrap();
    assert!(!error.0.contains("s3cret"));
    assert!(!format!("{options:?}").contains("abcdef0123456789"));
}
