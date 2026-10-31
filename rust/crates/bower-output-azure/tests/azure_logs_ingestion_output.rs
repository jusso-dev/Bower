//! Port of `AzureLogsIngestionOutputTests` against a local mock of the Logs
//! Ingestion API, plus retry, batching, token and credential coverage.

use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bower_contracts::{OutputAdapter, QueueState, QueuedEvent, time};
use bower_output_azure::{
    AccessToken, AzureLogsIngestionOptions, AzureLogsIngestionOutput, CachedTokenProvider,
    IngestionClientOptions, ManagedIdentityCredential, ManagedIdentitySource, TokenError,
    TokenFuture, TokenProvider, WorkloadIdentityCredential, WorkloadIdentitySettings,
};
use reqwest::Url;

type Responder = Arc<dyn Fn(usize, &[String]) -> (u16, Vec<(&'static str, String)>) + Send + Sync>;

#[derive(Clone)]
struct Mock {
    responder: Responder,
    count: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

#[derive(Clone, Debug)]
struct Recorded {
    path_and_query: String,
    headers: HeaderMap,
    body: String,
    event_ids: Vec<String>,
}

async fn ingest(
    State(mock): State<Mock>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let n = mock.count.fetch_add(1, Ordering::SeqCst) + 1;
    let mut plain = Vec::new();
    if headers
        .get("content-encoding")
        .is_some_and(|value| value == "gzip")
    {
        flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut plain)
            .unwrap();
    } else {
        plain = body.to_vec();
    }
    let document: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    let event_ids: Vec<String> = document
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["eventId"].as_str().unwrap().to_owned())
        .collect();
    let (status, extra) = (mock.responder)(n, &event_ids);
    mock.requests.lock().unwrap().push(Recorded {
        path_and_query: uri.path_and_query().unwrap().to_string(),
        headers,
        body: String::from_utf8(plain).unwrap(),
        event_ids,
    });
    let mut response = (StatusCode::from_u16(status).unwrap(), "{}").into_response();
    response
        .headers_mut()
        .insert("x-ms-request-id", format!("req-{n}").parse().unwrap());
    for (name, value) in extra {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}

async fn start(responder: Responder) -> (Url, Mock) {
    let mock = Mock {
        responder,
        count: Arc::default(),
        requests: Arc::default(),
    };
    let app = Router::new()
        .route("/dataCollectionRules/{rule}/streams/{stream}", post(ingest))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (Url::parse(&format!("http://{address}")).unwrap(), mock)
}

fn status(code: u16) -> Responder {
    Arc::new(move |_, _| (code, Vec::new()))
}

struct StaticCredential {
    calls: AtomicUsize,
    fail: bool,
}

impl StaticCredential {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            fail: false,
        })
    }
}

impl TokenProvider for StaticCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(scope, "https://monitor.azure.com//.default");
            if self.fail {
                return Err(TokenError::Failed("no token".to_owned()));
            }
            Ok(AccessToken {
                token: "test-token".to_owned(),
                expires_on: time::now() + chrono::Duration::hours(1),
            })
        })
    }
}

fn output_with(
    base: &Url,
    retries: u32,
    credential: Arc<dyn TokenProvider>,
) -> AzureLogsIngestionOutput {
    let options = AzureLogsIngestionOptions {
        maximum_concurrency: 1,
        ..AzureLogsIngestionOptions::new(
            "azure-logs-ingestion",
            Url::parse("https://example.ingest.monitor.azure.com").unwrap(),
            "dcr-00000000000000000000000000000000",
            "Custom-BowerSecurity",
        )
    };
    AzureLogsIngestionOutput::with_client_options(
        options,
        credential,
        IngestionClientOptions {
            max_retries: retries,
            retry_delay: Duration::from_millis(1),
            max_retry_delay: Duration::from_secs(5),
            transport_base_url: Some(base.clone()),
            ..IngestionClientOptions::default()
        },
    )
    .unwrap()
}

fn output(base: &Url) -> AzureLogsIngestionOutput {
    output_with(base, 0, StaticCredential::new())
}

fn queued(event_id: &str, payload: String) -> QueuedEvent {
    QueuedEvent {
        lease_token: None,
        event_id: event_id.to_owned(),
        fingerprint: format!("sha256:{event_id}"),
        payload,
        received_at: time::now(),
        state: QueueState::Queued,
        delivery_attempts: 0,
        suppression: None,
    }
}

fn event(event_id: &str, padding: &str) -> QueuedEvent {
    queued(
        event_id,
        format!(
            r#"{{"eventId":"{event_id}","timeGenerated":"2026-10-08T00:00:00Z","padding":"{padding}"}}"#
        ),
    )
}

#[tokio::test]
async fn deliver_acknowledges_accepted_records_as_ingestion_acceptance_only() {
    let (base, mock) = start(status(204)).await;

    let result = output(&base)
        .deliver(&[event("a", ""), event("b", "")])
        .await;

    let mut acknowledged = result.acknowledged_event_ids.clone();
    acknowledged.sort();
    assert_eq!(acknowledged, ["a", "b"]);
    assert!(result.failures.is_empty());
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        Some("azure-logs-ingestion:accepted:owned-batches")
    );
    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.path_and_query,
        "/dataCollectionRules/dcr-00000000000000000000000000000000/streams/Custom-BowerSecurity?api-version=2023-01-01"
    );
    assert_eq!(request.headers["authorization"], "Bearer test-token");
    assert_eq!(request.headers["content-type"], "application/json");
    assert_eq!(request.headers["content-encoding"], "gzip");
}

#[tokio::test]
async fn deliver_attributes_failed_batch_to_exact_events() {
    // ~600 KB records force one upload request per record.
    let padding = "x".repeat(600 * 1024);
    let (base, mock) = start(Arc::new(|_, ids: &[String]| {
        (
            if ids.iter().any(|id| id == "rejected") {
                400
            } else {
                204
            },
            Vec::new(),
        )
    }))
    .await;

    let result = output(&base)
        .deliver(&[event("accepted", &padding), event("rejected", &padding)])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["accepted"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].event_id, "rejected");
    assert_eq!(result.failures[0].code, "azure-http-400-isolated");
    assert!(!result.failures[0].is_retryable);
    assert_eq!(mock.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn deliver_marks_server_errors_retryable() {
    let (base, _) = start(status(503)).await;

    let result = output(&base).deliver(&[event("a", "")]).await;

    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), 1);
    assert!(result.failures[0].is_retryable);
    assert_eq!(result.failures[0].code, "destination-azure-http-503");
}

#[tokio::test]
async fn deliver_dead_letters_unparseable_payload_without_failing_batch() {
    let (base, _) = start(status(204)).await;

    let result = output(&base)
        .deliver(&[event("good", ""), queued("broken", "{not json".to_owned())])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["good"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].event_id, "broken");
    assert_eq!(result.failures[0].code, "payload-invalid-json");
    assert!(!result.failures[0].is_retryable);
}

#[tokio::test]
async fn deliver_dead_letters_payload_whose_event_id_does_not_match() {
    let (base, mock) = start(status(204)).await;

    let result = output(&base)
        .deliver(&[queued("queued-id", r#"{"eventId":"other"}"#.to_owned())])
        .await;

    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].code, "payload-event-id-mismatch");
    assert!(result.destination_acknowledgement.is_none());
    assert!(mock.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deliver_dead_letters_records_azure_would_truncate() {
    let (base, _) = start(status(204)).await;
    let oversized = format!(
        r#"{{"eventId":"big","timeGenerated":"2026-10-08T00:00:00Z","actor":{{"username":"{}"}}}}"#,
        "x".repeat(70_000)
    );

    let result = output(&base)
        .deliver(&[queued("big", oversized), event("ok", "")])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["ok"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].code, "preflight-field-too-large");
    assert!(!result.failures[0].is_retryable);
}

#[test]
fn options_reject_non_https_endpoint() {
    let options = AzureLogsIngestionOptions::new(
        "azure-logs-ingestion",
        Url::parse("http://example.ingest.monitor.azure.com").unwrap(),
        "dcr-1",
        "Custom-BowerSecurity",
    );
    assert!(AzureLogsIngestionOutput::new(options.clone(), StaticCredential::new()).is_err());
    let concurrency = AzureLogsIngestionOptions {
        endpoint: Url::parse("https://example.ingest.monitor.azure.com").unwrap(),
        maximum_concurrency: 33,
        ..options
    };
    assert!(AzureLogsIngestionOutput::new(concurrency, StaticCredential::new()).is_err());
}

#[tokio::test]
async fn body_is_records_reserialized_with_dotnet_escaping() {
    let (base, mock) = start(status(204)).await;
    let payload = "{ \"eventId\" : \"b\", \"timeGenerated\":\"2026-10-08T00:00:00+00:00\", \"s\": \"x+y \u{e9} <z> \\u00e9\", \"n\": 1.50, \"o\": {\"k\": [1, true, null]} }";

    output(&base)
        .deliver(&[queued("b", payload.to_owned())])
        .await;

    let requests = mock.requests.lock().unwrap();
    assert_eq!(
        requests[0].body,
        "[{\"eventId\":\"b\",\"timeGenerated\":\"2026-10-08T00:00:00\\u002B00:00\",\"s\":\"x\\u002By \\u00E9 \\u003Cz\\u003E \\u00E9\",\"n\":1.50,\"o\":{\"k\":[1,true,null]}}]"
    );
}

#[tokio::test]
async fn retries_retriable_statuses_and_honours_retry_after() {
    let (base, mock) = start(Arc::new(|n, _: &[String]| {
        if n == 1 {
            (429, vec![("retry-after-ms", "300".to_owned())])
        } else {
            (204, Vec::new())
        }
    }))
    .await;
    let started = Instant::now();

    let result = output_with(&base, 2, StaticCredential::new())
        .deliver(&[event("a", "")])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["a"]);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(mock.requests.lock().unwrap().len(), 2);
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        Some("azure-logs-ingestion:accepted:owned-batches")
    );
}

#[tokio::test]
async fn does_not_retry_client_errors_and_stops_after_max_retries() {
    let (base, mock) = start(status(400)).await;
    let result = output_with(&base, 2, StaticCredential::new())
        .deliver(&[event("a", "")])
        .await;
    assert_eq!(result.failures[0].code, "destination-azure-http-400");
    assert_eq!(mock.requests.lock().unwrap().len(), 1);

    let (base, mock) = start(status(500)).await;
    let result = output_with(&base, 2, StaticCredential::new())
        .deliver(&[event("a", "")])
        .await;
    assert_eq!(result.failures[0].code, "destination-azure-http-500");
    assert!(result.failures[0].is_retryable);
    assert_eq!(mock.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn batches_split_exactly_where_the_csharp_sdk_splits() {
    // Boundaries measured against Azure.Monitor.Ingestion 1.2 (C#) by binary search:
    // two records split once their lengths sum to 1_048_574, three once they sum to
    // 1_048_573 (`BytesPending + entry + 1 >= 1 MiB`).
    let cases: [(&[usize], usize); 4] = [
        (&[400_000, 648_573], 1),
        (&[400_000, 648_574], 2),
        (&[300_000, 300_000, 448_572], 1),
        (&[300_000, 300_000, 448_573], 2),
    ];
    for (sizes, expected_requests) in cases {
        let (base, mock) = start(status(204)).await;
        let events: Vec<QueuedEvent> = sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let (id, payload) = sized_record(&format!("r{index}"), *size);
                queued(&id, payload)
            })
            .collect();

        let result = output(&base).deliver(&events).await;

        assert_eq!(result.acknowledged_event_ids.len(), sizes.len());
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.len(), expected_requests, "{sizes:?}");
        assert!(requests.iter().all(|r| r.body.len() <= 1_048_576));
    }
}

#[tokio::test]
async fn token_failure_fails_batch_as_retryable_without_sending() {
    let (base, mock) = start(status(204)).await;
    let credential = Arc::new(StaticCredential {
        calls: AtomicUsize::new(0),
        fail: true,
    });

    let result = output_with(&base, 2, credential)
        .deliver(&[event("a", "")])
        .await;

    assert!(result.acknowledged_event_ids.is_empty());
    // Distinct from a network outage (C# `CredentialFailedCode`), still a retryable
    // destination failure that holds the queue behind the durable circuit.
    assert_eq!(
        result.failures[0].code,
        "destination-azure-credential-failed"
    );
    assert!(result.failures[0].is_retryable);
    assert!(result.failures[0].is_destination_failure());
    assert!(mock.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn token_is_cached_across_batches_and_calls() {
    let (base, _) = start(status(204)).await;
    let credential = StaticCredential::new();
    let output = output_with(&base, 0, credential.clone());
    let padding = "x".repeat(600 * 1024);

    output
        .deliver(&[event("a", &padding), event("b", &padding)])
        .await;
    output.deliver(&[event("c", "")]).await;

    assert_eq!(credential.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn transport_failure_is_retryable_upload_failure() {
    // Nothing listens on this port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    drop(listener);

    let result = output(&base).deliver(&[event("a", "")]).await;

    assert_eq!(result.failures[0].code, "destination-azure-unavailable");
    assert!(result.failures[0].is_retryable);
    assert!(result.destination_acknowledgement.is_none());
}

#[tokio::test]
async fn managed_identity_uses_imds_and_app_service_protocols() {
    let seen: Arc<Mutex<Vec<(String, HeaderMap)>>> = Arc::default();
    let record = seen.clone();
    let app = Router::new().route(
        "/token",
        get(move |uri: axum::http::Uri, headers: HeaderMap| {
            let record = record.clone();
            async move {
                record.lock().unwrap().push((uri.query().unwrap_or("").to_owned(), headers));
                r#"{"access_token":"mi-token","expires_on":"1893456000","resource":"https://monitor.azure.com/"}"#
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let endpoint = format!("http://{address}/token");

    let imds = ManagedIdentityCredential::new(
        reqwest::Client::new(),
        Some("client-1".to_owned()),
        ManagedIdentitySource::Imds {
            endpoint: endpoint.clone(),
        },
    );
    let token = imds
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap();
    assert_eq!(token.token, "mi-token");
    assert_eq!(token.expires_on.timestamp(), 1_893_456_000);

    let app_service = ManagedIdentityCredential::new(
        reqwest::Client::new(),
        None,
        ManagedIdentitySource::AppService {
            endpoint,
            header: "identity-header".to_owned(),
        },
    );
    app_service
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[0].0,
        "api-version=2018-02-01&resource=https%3A%2F%2Fmonitor.azure.com%2F&client_id=client-1"
    );
    assert_eq!(seen[0].1["metadata"], "true");
    assert_eq!(
        seen[1].0,
        "api-version=2019-08-01&resource=https%3A%2F%2Fmonitor.azure.com%2F"
    );
    assert_eq!(seen[1].1["x-identity-header"], "identity-header");
}

#[tokio::test]
async fn workload_identity_exchanges_federated_token() {
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let record = seen.clone();
    let app = Router::new().route(
        "/{tenant}/oauth2/v2.0/token",
        post(move |uri: axum::http::Uri, body: String| {
            let record = record.clone();
            async move {
                record.lock().unwrap().push((uri.path().to_owned(), body));
                r#"{"token_type":"Bearer","expires_in":3599,"access_token":"wi-token"}"#
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let token_file = std::env::temp_dir().join(format!("bower-wi-{}", std::process::id()));
    std::fs::write(&token_file, "federated.jwt\n").unwrap();

    let credential = WorkloadIdentityCredential::new(
        reqwest::Client::new(),
        WorkloadIdentitySettings {
            tenant_id: "tenant-1".to_owned(),
            client_id: "client-1".to_owned(),
            token_file: token_file.clone(),
            authority_host: format!("http://{address}/"),
        },
    );
    let token = credential
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap();
    std::fs::remove_file(token_file).unwrap();

    assert_eq!(token.token, "wi-token");
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].0, "/tenant-1/oauth2/v2.0/token");
    assert_eq!(
        seen[0].1,
        "client_id=client-1&scope=https%3A%2F%2Fmonitor.azure.com%2F%2F.default&grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=federated.jwt"
    );
}

#[tokio::test]
async fn token_endpoint_errors_never_leak_bodies() {
    let app = Router::new().route(
        "/token",
        get(|| async {
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_request","error_description":"secret detail"}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let imds = ManagedIdentityCredential::new(
        reqwest::Client::new(),
        None,
        ManagedIdentitySource::Imds {
            endpoint: format!("http://{address}/token"),
        },
    );

    let error = imds
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap_err();

    let text = error.to_string();
    assert!(text.contains("HTTP 400") && text.contains("invalid_request"));
    assert!(!text.contains("secret detail"));
}

/// Returns a token that is inside the refresh window first, then fails.
struct ExpiringThenFailing {
    calls: AtomicUsize,
    expires_in: chrono::Duration,
}

impl TokenProvider for ExpiringThenFailing {
    fn get_token<'a>(&'a self, _scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(AccessToken {
                    token: "short-lived".to_owned(),
                    expires_on: time::now() + self.expires_in,
                })
            } else {
                Err(TokenError::Unavailable("endpoint down".to_owned()))
            }
        })
    }
}

#[tokio::test]
async fn failed_refresh_keeps_using_unexpired_cached_token() {
    let inner = Arc::new(ExpiringThenFailing {
        calls: AtomicUsize::new(0),
        expires_in: chrono::Duration::minutes(2),
    });
    let cache = CachedTokenProvider::new(inner.clone());
    let scope = "https://monitor.azure.com//.default";

    assert_eq!(cache.get_token(scope).await.unwrap().token, "short-lived");
    // Inside the five-minute refresh window: refresh is attempted, fails, and the
    // still-valid token is used.
    assert_eq!(cache.get_token(scope).await.unwrap().token, "short-lived");
    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);

    let expired = Arc::new(ExpiringThenFailing {
        calls: AtomicUsize::new(0),
        expires_in: chrono::Duration::seconds(-1),
    });
    let cache = CachedTokenProvider::new(expired);
    cache.get_token(scope).await.unwrap();
    assert!(matches!(
        cache.get_token(scope).await,
        Err(TokenError::Unavailable(_))
    ));
}

#[tokio::test]
async fn client_credentials_refuse_plain_http_authority() {
    let token_file = std::env::temp_dir().join(format!("bower-wi-http-{}", std::process::id()));
    std::fs::write(&token_file, "federated.jwt").unwrap();
    let credential = WorkloadIdentityCredential::new(
        reqwest::Client::new(),
        WorkloadIdentitySettings {
            tenant_id: "tenant-1".to_owned(),
            client_id: "client-1".to_owned(),
            token_file: token_file.clone(),
            authority_host: "http://login.example.test/".to_owned(),
        },
    );

    let error = credential
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap_err();
    std::fs::remove_file(token_file).unwrap();

    assert_eq!(
        error,
        TokenError::Unavailable("the authority host must use HTTPS".to_owned())
    );
}

#[tokio::test]
async fn managed_identity_token_exchange_uses_federated_token() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = seen.clone();
    let app = Router::new().route(
        "/{tenant}/oauth2/v2.0/token",
        post(move |body: String| {
            let record = record.clone();
            async move {
                record.lock().unwrap().push(body);
                r#"{"expires_in":3599,"access_token":"mi-wi-token"}"#
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let token_file = std::env::temp_dir().join(format!("bower-mi-wi-{}", std::process::id()));
    std::fs::write(&token_file, "projected.jwt").unwrap();
    let credential = ManagedIdentityCredential::new(
        reqwest::Client::new(),
        Some("user-assigned".to_owned()),
        ManagedIdentitySource::TokenExchange(WorkloadIdentitySettings {
            tenant_id: "tenant-1".to_owned(),
            client_id: "user-assigned".to_owned(),
            token_file: token_file.clone(),
            authority_host: format!("http://{address}"),
        }),
    );

    let token = credential
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap();
    std::fs::remove_file(token_file).unwrap();

    assert_eq!(token.token, "mi-wi-token");
    assert!(seen.lock().unwrap()[0].contains("client_assertion=projected.jwt"));
}

#[cfg(unix)]
#[tokio::test]
async fn azure_cli_credential_reads_token_and_reports_failures_without_output() {
    use std::os::unix::fs::PermissionsExt;
    let directory = std::env::temp_dir().join(format!("bower-az-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let script = |name: &str, body: &str| {
        let path = directory.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    };
    let ok = script(
        "az-ok",
        r#"[ "$5 $6" = "--resource https://monitor.azure.com/" ] || exit 9
echo '{"accessToken":"cli-token","expires_on":1893456000}'"#,
    );
    let failing = script("az-fail", "echo 'secret diagnostics' >&2; exit 1");

    let token = bower_output_azure::AzureCliCredential { program: ok }
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap();
    let error = bower_output_azure::AzureCliCredential { program: failing }
        .get_token("https://monitor.azure.com//.default")
        .await
        .unwrap_err();
    let missing = bower_output_azure::AzureCliCredential {
        program: directory.join("missing"),
    }
    .get_token("https://monitor.azure.com//.default")
    .await
    .unwrap_err();
    std::fs::remove_dir_all(&directory).unwrap();

    assert_eq!(token.token, "cli-token");
    assert_eq!(token.expires_on.timestamp(), 1_893_456_000);
    assert!(!error.to_string().contains("secret"));
    assert!(matches!(missing, TokenError::Unavailable(_)));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let (base, mock) = start(Arc::new(|_, _| {
        (
            307,
            vec![("location", "http://127.0.0.1:9/elsewhere".to_owned())],
        )
    }))
    .await;

    let result = output_with(&base, 3, StaticCredential::new())
        .deliver(&[event("a", "")])
        .await;

    assert_eq!(result.failures[0].code, "destination-azure-http-307");
    assert!(result.failures[0].is_retryable);
    assert_eq!(mock.requests.lock().unwrap().len(), 1);
}

/// `Record(id, length)` from the C# vector emitter: a JSON object of exactly
/// `length` bytes.
fn sized_record(event_id: &str, length: usize) -> (String, String) {
    let shape = |padding: &str| {
        format!(
            r#"{{"eventId":"{event_id}","timeGenerated":"2026-10-08T00:00:00Z","padding":"{padding}"}}"#
        )
    };
    let empty = shape("").len();
    (event_id.to_owned(), shape(&"x".repeat(length - empty)))
}

fn literal(event_id: &str, payload: &str) -> (String, String) {
    (event_id.to_owned(), payload.to_owned())
}

/// Same scenarios, in the same order, as `ZzRustCoreOutputsVectors.Azure` (C#
/// `AzureLogsIngestionOutput` over `Azure.Monitor.Ingestion` 1.2 with a capturing
/// transport). Request grouping, decompressed body bytes and results must match.
#[tokio::test]
async fn upload_requests_and_results_match_csharp_vectors() {
    use sha2::Digest;
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csharp-vectors.json");
    let vectors: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let nested = |id: &str, depth: usize| {
        format!(
            r#"{{"eventId":"{id}","a":{}{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        )
    };
    let scenarios: Vec<(&str, Vec<(String, String)>)> = vec![
        (
            "escapes",
            vec![literal(
                "esc",
                r#"{"eventId":"esc","timeGenerated":"2026-10-08T00:00:00Z","s":"<a>&'+é😀\/\u0001","n":1.0E+2,"big":123456789012345678901234567890,"neg":-0,"o":{"z":1,"a":[true,null]}}"#,
            )],
        ),
        (
            "fits-exactly",
            vec![
                sized_record("a", 500_000),
                sized_record("b", 499_997),
                sized_record("c", 100),
            ],
        ),
        (
            "splits-at-threshold",
            vec![sized_record("a", 500_000), sized_record("b", 499_998)],
        ),
        (
            "oversized-last",
            vec![sized_record("s1", 100), sized_record("big", 1_100_000)],
        ),
        (
            "oversized-middle",
            vec![
                sized_record("s1", 100),
                sized_record("big", 1_100_000),
                sized_record("s2", 100),
            ],
        ),
        (
            "first-at-edge",
            vec![sized_record("edge", 999_998), sized_record("s", 100)],
        ),
        (
            "exactly-threshold",
            vec![sized_record("t", 1_000_000), sized_record("s", 100)],
        ),
        (
            "duplicate-keys",
            vec![literal(
                "dup",
                r#"{"eventId":"dup","timeGenerated":"2026-10-08T00:00:00Z","x":1,"x":2}"#,
            )],
        ),
        (
            "depth",
            vec![
                ("d64".to_owned(), nested("d64", 63)),
                ("d65".to_owned(), nested("d65", 64)),
            ],
        ),
        ("non-string-id", vec![literal("5", r#"{"eventId":5}"#)]),
    ];
    let expected_all = vectors["azure"].as_array().unwrap();
    assert_eq!(expected_all.len(), scenarios.len());

    for ((name, events), expected) in scenarios.into_iter().zip(expected_all) {
        assert_eq!(expected["name"], name);
        let (base, mock) = start(status(204)).await;
        let queued_events: Vec<QueuedEvent> = events
            .into_iter()
            .map(|(id, payload)| queued(&id, payload))
            .collect();

        let result = output(&base).deliver(&queued_events).await;

        let requests = mock.requests.lock().unwrap().clone();
        let actual_requests: Vec<serde_json::Value> = requests
            .iter()
            .map(|request| {
                serde_json::json!({
                    "pathAndQuery": request.path_and_query,
                    "contentType": request.headers["content-type"].to_str().unwrap(),
                    "gzip": request.headers["content-encoding"] == "gzip",
                    "authorization": request.headers["authorization"].to_str().unwrap(),
                    "eventIds": request.event_ids,
                    "length": request.body.len(),
                    "sha256": hex::encode(sha2::Sha256::digest(request.body.as_bytes())),
                    "body": (request.body.len() < 4096).then(|| request.body.clone()),
                })
            })
            .collect();
        let failures: Vec<serde_json::Value> = result
            .failures
            .iter()
            .map(|failure| {
                serde_json::json!({
                    "eventId": failure.event_id,
                    "code": failure.code,
                    "retryable": failure.is_retryable,
                })
            })
            .collect();
        assert_eq!(
            serde_json::Value::Array(actual_requests),
            expected["requests"],
            "{name}: requests"
        );
        assert_eq!(
            serde_json::json!(result.acknowledged_event_ids),
            expected["acknowledged"],
            "{name}: acknowledged"
        );
        assert_eq!(
            serde_json::Value::Array(failures),
            expected["failures"],
            "{name}: failures"
        );
    }
}

/// A repeated top-level property can never be uploaded (C# `JsonObject` cannot hold
/// it): that record alone is dead-lettered and the rest of the batch is delivered, in
/// both implementations (the `duplicate-keys` vector pins the C# result).
#[tokio::test]
async fn top_level_duplicate_property_is_dead_lettered_alone() {
    let (base, mock) = start(status(204)).await;
    let result = output(&base)
        .deliver(&[
            queued(
                "dup",
                r#"{"eventId":"dup","timeGenerated":"2026-10-08T00:00:00Z","x":1,"x":2}"#
                    .to_owned(),
            ),
            event("ok", ""),
        ])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["ok"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].event_id, "dup");
    assert_eq!(result.failures[0].code, "payload-invalid-json");
    assert!(!result.failures[0].is_retryable);
    assert_eq!(mock.requests.lock().unwrap().len(), 1);
}

/// Invalid escapes (a lone surrogate) can never be re-serialized: dead-lettered alone,
/// as in C# (`Deliver_DeadLettersInvalidEscapesInsteadOfFailingTheUpload`).
#[tokio::test]
async fn invalid_escape_is_dead_lettered_alone() {
    let (base, mock) = start(status(204)).await;
    let lone_surrogate = format!("{}uD800", '\\');
    let payload = format!(
        r#"{{"eventId":"bad","timeGenerated":"2026-10-08T00:00:00Z","o":{{"s":"{lone_surrogate}"}}}}"#
    );

    let result = output(&base)
        .deliver(&[queued("bad", payload), event("ok", "")])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["ok"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].event_id, "bad");
    assert_eq!(result.failures[0].code, "payload-invalid-json");
    assert_eq!(mock.requests.lock().unwrap().len(), 1);
}

/// C# writes nested duplicate properties through unchanged (the nested
/// `JsonElement` is copied); measured body from the C# vector run.
#[tokio::test]
async fn nested_duplicate_properties_are_sent_like_csharp() {
    let (base, mock) = start(status(204)).await;
    let payload =
        r#"{"eventId":"nested-dup","timeGenerated":"2026-10-08T00:00:00Z","o":{"x":1,"x":2}}"#;

    let result = output(&base)
        .deliver(&[queued("nested-dup", payload.to_owned())])
        .await;

    assert_eq!(result.acknowledged_event_ids, ["nested-dup"]);
    assert_eq!(
        mock.requests.lock().unwrap()[0].body,
        format!("[{payload}]")
    );
}

// Independent response ordering oracle, not generated from the defective SDK.
#[tokio::test]
async fn default_concurrency_owns_reordered_mixed_outcomes() {
    let started = Arc::new(tokio::sync::Barrier::new(4));
    let completion = Arc::new(Mutex::new(Vec::<String>::new()));
    let completed = completion.clone();
    let app = Router::new().route(
        "/dataCollectionRules/{rule}/streams/{stream}",
        post(move |body: Bytes| {
            let started = started.clone();
            let completed = completed.clone();
            async move {
                let mut plain = Vec::new();
                flate2::read::GzDecoder::new(&body[..])
                    .read_to_end(&mut plain)
                    .unwrap();
                assert!(plain.len() <= 1024 * 1024);
                let values: serde_json::Value = serde_json::from_slice(&plain).unwrap();
                assert_eq!(values.as_array().unwrap().len(), 1);
                let id = values[0]["eventId"].as_str().unwrap().to_owned();
                started.wait().await;
                tokio::time::sleep(Duration::from_millis(match id.as_str() {
                    "one" => 80,
                    "three" => 40,
                    _ => 1,
                }))
                .await;
                completed.lock().unwrap().push(id.clone());
                (
                    match id.as_str() {
                        "one" => StatusCode::BAD_REQUEST,
                        "three" => StatusCode::TOO_MANY_REQUESTS,
                        _ => StatusCode::NO_CONTENT,
                    },
                    "{}",
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let output = AzureLogsIngestionOutput::with_client_options(
        AzureLogsIngestionOptions::new(
            "azure",
            Url::parse("https://example.ingest.monitor.azure.com").unwrap(),
            "dcr-test",
            "Custom-BowerSecurity",
        ),
        StaticCredential::new(),
        IngestionClientOptions {
            max_retries: 0,
            transport_base_url: Some(base),
            ..Default::default()
        },
    )
    .unwrap();
    let padding = "x".repeat(600 * 1024);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        output.deliver(&[
            event("one", &padding),
            event("two", &padding),
            event("three", &padding),
            event("four", &padding),
        ]),
    )
    .await
    .unwrap();
    assert_eq!(result.acknowledged_event_ids, ["two", "four"]);
    let mut failed: Vec<_> = result
        .failures
        .iter()
        .map(|item| item.event_id.as_str())
        .collect();
    failed.sort();
    assert_eq!(failed, ["one", "three"]);
    assert_eq!(
        result
            .failures
            .iter()
            .find(|item| item.event_id == "one")
            .unwrap()
            .code,
        "azure-http-400-isolated"
    );
    assert!(
        result
            .failures
            .iter()
            .find(|item| item.event_id == "three")
            .unwrap()
            .is_destination_failure()
    );
    assert_eq!(completion.lock().unwrap().last().unwrap(), "one");
}

#[tokio::test]
async fn final_retry_deadline_survives_exhaustion_and_outages_recover() {
    for status_code in [401, 403, 429, 503] {
        let repaired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let repair = repaired.clone();
        let (base, _) = start(Arc::new(move |n, _| {
            if repair.load(Ordering::SeqCst) {
                return (204, vec![]);
            }
            // Only the terminal response asks for the long cooldown; inner retries stay fast.
            let seconds = if n >= 3 || status_code == 401 || status_code == 403 {
                "120"
            } else {
                "0"
            };
            (status_code, vec![("retry-after", seconds.to_owned())])
        }))
        .await;
        let output = output_with(&base, 2, StaticCredential::new());
        let before = time::now();
        let result = output.deliver(&[event("valid", "")]).await;
        assert!(result.acknowledged_event_ids.is_empty());
        assert!(result.destination_acknowledgement.is_none());
        assert!(result.failures[0].is_destination_failure());
        assert!(result.failures[0].retry_after.unwrap() >= before + chrono::Duration::seconds(120));
        repaired.store(true, Ordering::SeqCst);
        assert_eq!(
            output
                .deliver(&[event("valid", "")])
                .await
                .acknowledged_event_ids,
            ["valid"]
        );
    }
}

#[tokio::test]
async fn ambiguous_bad_request_isolates_siblings_with_bounded_requests() {
    let (base, mock) = start(Arc::new(|_, ids| {
        (
            if ids.iter().any(|id| id == "bad") {
                400
            } else {
                204
            },
            vec![],
        )
    }))
    .await;
    let result = output(&base)
        .deliver(&[event("a", ""), event("bad", ""), event("b", "")])
        .await;
    assert_eq!(result.acknowledged_event_ids, ["a", "b"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].code, "azure-http-400-isolated");
    assert!(!result.failures[0].is_retryable);
    assert!(mock.count.load(Ordering::SeqCst) <= 17);
}

#[tokio::test]
async fn final_http_date_deadline_and_cancellation_are_preserved() {
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(10);
    let (base, _) = start(Arc::new(move |_, _| {
        (429, vec![("retry-after", deadline.to_rfc2822())])
    }))
    .await;
    let result = output(&base).deliver(&[event("a", "")]).await;
    assert_eq!(
        result.failures[0].retry_after.unwrap().timestamp(),
        deadline.timestamp()
    );

    let (base, mock) = start(Arc::new(|_, _| (429, vec![("retry-after", "1".into())]))).await;
    let client = output_with(&base, 3, StaticCredential::new());
    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        client.deliver(&[event("a", "")]),
    )
    .await;
    assert!(cancelled.is_err());
    assert_eq!(mock.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn configuration_wide_bad_request_has_bounded_isolation() {
    let (base, mock) = start(status(400)).await;
    let events: Vec<_> = (0..64).map(|n| event(&format!("e{n}"), "")).collect();
    let result = output(&base).deliver(&events).await;
    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures.len(), 64);
    assert!(
        result
            .failures
            .iter()
            .all(|item| item.is_destination_failure())
    );
    assert!(mock.count.load(Ordering::SeqCst) <= 17);
}

#[tokio::test]
async fn absurd_retry_headers_return_promptly_with_bounded_durable_deadlines() {
    for (name, value) in [
        ("retry-after", "Fri, 01 Jan 2100 00:00:00 GMT"),
        ("retry-after-ms", "1e300"),
        ("retry-after", "999999999999999999"),
    ] {
        let (base, mock) = start(Arc::new(move |_, _| (429, vec![(name, value.to_owned())]))).await;
        let client = output_with(&base, 3, StaticCredential::new());
        let before = time::now();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.deliver(&[event("valid", "")]),
        )
        .await
        .unwrap();
        assert_eq!(mock.count.load(Ordering::SeqCst), 1);
        let failure = &result.failures[0];
        assert!(failure.code.ends_with(":retry-after-capped"));
        assert!(failure.is_destination_failure());
        let deadline = failure.retry_after.unwrap();
        assert!(deadline >= before + chrono::Duration::minutes(59));
        assert!(deadline <= time::now() + chrono::Duration::hours(1));
    }
}
