//! Port of C# `S3OutputTests` delivery cases against a local fake S3 endpoint.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_config::BehaviorVersion;
use aws_config::retry::RetryConfig;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::future::ProvideCredentials as CredentialsFuture;
use aws_sdk_s3::config::{Credentials, Region};
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use bower_contracts::abstractions::{OutputAdapter, QueueState, QueuedEvent};
use bower_output_s3::output::{ACCESS_DENIED_CODE, CREDENTIAL_FAILED_CODE, UNAVAILABLE_CODE};
use bower_output_s3::{S3Output, S3OutputOptions, layout};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
struct Put {
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Put {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| value.to_str().unwrap())
    }
}

type Respond = dyn Fn(usize) -> (u16, String) + Send + Sync;

#[derive(Clone)]
struct FakeS3 {
    puts: Arc<Mutex<Vec<Put>>>,
    respond: Arc<Mutex<Arc<Respond>>>,
}

impl FakeS3 {
    async fn start() -> (Self, SocketAddr) {
        let fake = Self {
            puts: Arc::default(),
            respond: Arc::new(Mutex::new(Arc::new(|_| (200, String::new())))),
        };
        let state = fake.clone();
        let app = axum::Router::new().fallback(
            move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                let state = state.clone();
                async move { state.handle(method, uri, headers, body) }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (fake, address)
    }

    fn handle(&self, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
        assert_eq!(Method::PUT, method);
        let index = {
            let mut puts = self.puts.lock().unwrap();
            puts.push(Put {
                path: uri.path().to_string(),
                headers,
                body: body.to_vec(),
            });
            puts.len() - 1
        };
        let respond = self.respond.lock().unwrap().clone();
        let (status, body) = respond(index);
        let mut response = (StatusCode::from_u16(status).unwrap(), body).into_response();
        response
            .headers_mut()
            .insert("etag", "\"etag\"".parse().unwrap());
        response
    }

    fn respond(&self, respond: impl Fn(usize) -> (u16, String) + Send + Sync + 'static) {
        *self.respond.lock().unwrap() = Arc::new(respond);
    }

    fn puts(&self) -> Vec<Put> {
        self.puts.lock().unwrap().clone()
    }
}

fn error(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message><RequestId>r</RequestId></Error>"
    )
}

fn options() -> S3OutputOptions {
    S3OutputOptions::new("bower-test-bucket", "ap-southeast-2")
}

fn client(address: SocketAddr) -> aws_sdk_s3::Client {
    // Test-only placeholder credentials: the fake endpoint never checks signatures.
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("ap-southeast-2"))
        .endpoint_url(format!("http://{address}"))
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            "fake-test-key-id",
            "fake-test-value",
            None,
            None,
            "bower-test",
        ))
        .retry_config(RetryConfig::disabled())
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

fn events(count: usize) -> Vec<QueuedEvent> {
    let start = bower_contracts::time::parse("2026-07-26T02:14:19Z").unwrap();
    (0..count)
        .map(|index| QueuedEvent {
            event_id: format!("s3-{index}"),
            fingerprint: format!("sha256:{index}"),
            payload: format!(
                "{{\"eventId\":\"s3-{index}\",\"eventType\":\"authentication_failed\",\"n\":{index}}}"
            ),
            received_at: start + chrono::TimeDelta::seconds(index as i64),
            state: QueueState::Queued,
            delivery_attempts: 0,
            lease_token: None,
            suppression: None,
        })
        .collect()
}

fn gunzip(content: &[u8]) -> String {
    let mut text = String::new();
    flate2::read::GzDecoder::new(content)
        .read_to_string(&mut text)
        .unwrap();
    text
}

fn ndjson(events: &[QueuedEvent]) -> String {
    events
        .iter()
        .map(|item| item.payload.clone() + "\n")
        .collect()
}

#[tokio::test]
async fn deliver_sends_conditional_encrypted_checksummed_gzip_object() {
    let (s3, address) = FakeS3::start().await;
    let mut options = options();
    options.expected_bucket_owner = Some("123456789012".into());
    let output = S3Output::with_client(options, client(address)).unwrap();
    let events = events(3);

    let result = output.deliver(&events).await;

    assert_eq!(vec!["s3-0", "s3-1", "s3-2"], result.acknowledged_event_ids);
    assert!(result.failures.is_empty());
    let puts = s3.puts();
    assert_eq!(1, puts.len());
    let put = &puts[0];
    let ids: Vec<String> = events.iter().map(|item| item.event_id.clone()).collect();
    let key = layout::key("bower", events[0].received_at, &ids, true);
    assert_eq!(format!("/bower-test-bucket/{key}"), put.path);
    assert_eq!(
        Some(format!("s3://bower-test-bucket/{key}")),
        result.destination_acknowledgement
    );
    assert_eq!(Some("*"), put.header("if-none-match"));
    assert_eq!(Some("AES256"), put.header("x-amz-server-side-encryption"));
    assert_eq!(
        None,
        put.header("x-amz-server-side-encryption-aws-kms-key-id")
    );
    assert_eq!(
        Some("123456789012"),
        put.header("x-amz-expected-bucket-owner")
    );
    assert_eq!(Some("gzip"), put.header("content-encoding"));
    assert_eq!(Some("3"), put.header("x-amz-meta-bower-events"));
    assert_eq!(
        Some(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&put.body))),
        put.header("x-amz-checksum-sha256").map(str::to_string)
    );
    assert_eq!(ndjson(&events), gunzip(&put.body));
}

#[tokio::test]
async fn deliver_uses_kms_key_and_plain_ndjson_when_gzip_is_off() {
    let (s3, address) = FakeS3::start().await;
    let mut options = options();
    options.server_side_encryption = "aws:kms".into();
    options.kms_key_id = Some("alias/bower-output".into());
    options.gzip = false;
    let output = S3Output::with_client(options, client(address)).unwrap();
    let events = events(2);

    output.deliver(&events).await;

    let put = &s3.puts()[0];
    assert!(put.path.ends_with(".jsonl"));
    assert_eq!(Some("aws:kms"), put.header("x-amz-server-side-encryption"));
    assert_eq!(
        Some("alias/bower-output"),
        put.header("x-amz-server-side-encryption-aws-kms-key-id")
    );
    assert_eq!(None, put.header("content-encoding"));
    assert_eq!(
        ndjson(&events),
        String::from_utf8(put.body.clone()).unwrap()
    );
}

#[tokio::test]
async fn retry_of_same_batch_rewrites_same_key_and_existing_object_is_success() {
    let (s3, address) = FakeS3::start().await;
    let output = S3Output::with_client(options(), client(address)).unwrap();
    let events = events(4);

    let first = output.deliver(&events).await;
    s3.respond(|_| {
        (
            412,
            error(
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
            ),
        )
    });
    let retry = output.deliver(&events).await;

    let puts = s3.puts();
    assert_eq!(2, puts.len());
    assert_eq!(puts[0].path, puts[1].path);
    assert_eq!(first.acknowledged_event_ids, retry.acknowledged_event_ids);
    assert!(retry.failures.is_empty());
    assert_eq!(
        first.destination_acknowledgement,
        retry.destination_acknowledgement
    );
}

#[tokio::test]
async fn splits_under_count_cap_and_holds_objects_after_first_failure() {
    let (s3, address) = FakeS3::start().await;
    s3.respond(|index| {
        if index == 1 {
            (403, error("AccessDenied", "Access Denied"))
        } else {
            (200, String::new())
        }
    });
    let mut options = options();
    options.maximum_object_events = 2;
    let output = S3Output::with_client(options, client(address)).unwrap();

    let result = output.deliver(&events(5)).await;

    assert_eq!(2, s3.puts().len());
    assert_eq!(vec!["s3-0", "s3-1"], result.acknowledged_event_ids);
    let failed: Vec<&str> = result
        .failures
        .iter()
        .map(|failure| failure.event_id.as_str())
        .collect();
    assert_eq!(vec!["s3-2", "s3-3", "s3-4"], failed);
    assert!(
        result
            .failures
            .iter()
            .all(|failure| failure.code == ACCESS_DENIED_CODE
                && failure.is_retryable
                && failure.is_destination_failure())
    );
}

#[tokio::test]
async fn classifies_service_errors_as_retryable_destination_faults() {
    let cases = [
        (503, "SlowDown", "", "destination-s3-throttled"),
        (500, "InternalError", "", "destination-s3-http-500"),
        (404, "NoSuchBucket", "", "destination-s3-no-such-bucket"),
        (
            403,
            "AccessDenied",
            "not authorized to perform: kms:GenerateDataKey",
            "destination-s3-kms-denied",
        ),
        (
            403,
            "InvalidAccessKeyId",
            "",
            "destination-s3-credential-failed",
        ),
    ];
    for (status, code, message, expected) in cases {
        let (s3, address) = FakeS3::start().await;
        let body = error(code, message);
        s3.respond(move |_| (status, body.clone()));
        let output = S3Output::with_client(options(), client(address)).unwrap();

        let result = output.deliver(&events(2)).await;

        assert!(result.acknowledged_event_ids.is_empty());
        assert_eq!(None, result.destination_acknowledgement);
        assert_eq!(2, result.failures.len());
        assert!(
            result
                .failures
                .iter()
                .all(|failure| failure.code == expected
                    && failure.is_retryable
                    && failure.retry_after.is_none()),
            "{status} {code}: {:?}",
            result.failures
        );
    }
}

#[tokio::test]
async fn network_failure_is_unavailable() {
    // Bind and drop a listener so the port refuses connections.
    let address = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let output = S3Output::with_client(options(), client(address)).unwrap();

    let result = output.deliver(&events(2)).await;

    assert!(
        result
            .failures
            .iter()
            .all(|failure| failure.code == UNAVAILABLE_CODE)
    );
}

#[derive(Debug)]
struct NoCredentials;

impl aws_credential_types::provider::ProvideCredentials for NoCredentials {
    fn provide_credentials<'a>(&'a self) -> CredentialsFuture<'a>
    where
        Self: 'a,
    {
        CredentialsFuture::ready(Err(CredentialsError::not_loaded("no credentials in chain")))
    }
}

#[tokio::test]
async fn missing_default_chain_credentials_are_a_credential_failure() {
    let (s3, address) = FakeS3::start().await;
    let config = client(address)
        .config()
        .to_builder()
        .credentials_provider(NoCredentials)
        .build();
    let output = S3Output::with_client(options(), aws_sdk_s3::Client::from_conf(config)).unwrap();

    let result = output.deliver(&events(1)).await;

    assert!(s3.puts().is_empty());
    assert_eq!(CREDENTIAL_FAILED_CODE, result.failures[0].code);
}

#[tokio::test]
async fn rejects_poison_alone_and_delivers_the_rest() {
    let (_s3, address) = FakeS3::start().await;
    let output = S3Output::with_client(options(), client(address)).unwrap();
    let mut batch = events(2);
    let mut bad = batch[0].clone();
    bad.event_id = "bad".into();
    bad.payload = "{\"eventId\":".into();
    batch.push(bad);

    let result = output.deliver(&batch).await;

    assert_eq!(vec!["s3-0", "s3-1"], result.acknowledged_event_ids);
    assert_eq!(1, result.failures.len());
    assert_eq!(
        ("bad", "payload-invalid-json", false),
        (
            result.failures[0].event_id.as_str(),
            result.failures[0].code.as_str(),
            result.failures[0].is_retryable
        )
    );
}

#[test]
fn production_constructor_resolves_credentials_lazily() {
    // No credential is read at construction: start-up never fails or logs over them.
    let output = S3Output::new(options()).unwrap();
    assert_eq!("s3", output.id());
}

#[test]
fn settings_refuse_static_keys_and_invalid_values_without_echoing_them() {
    const SECRET: &str = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY";
    let base = [
        ("BOWER_S3_BUCKET", "bower-test-bucket"),
        ("BOWER_S3_REGION", "ap-southeast-2"),
    ];
    let read = |pairs: Vec<(&'static str, String)>| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    };
    for name in bower_output_s3::options::REFUSED_CREDENTIAL_SETTINGS {
        let mut pairs: Vec<(&str, String)> =
            base.iter().map(|(k, v)| (*k, v.to_string())).collect();
        pairs.push((name, SECRET.into()));
        let error = S3OutputOptions::from_environment(read(pairs)).unwrap_err();
        assert!(error.0.contains(name));
        assert!(!error.0.contains(SECRET));
    }

    let invalid = [
        ("BOWER_S3_BUCKET", "Bower-Upper"),
        ("BOWER_S3_BUCKET", "bower.dotted"),
        ("BOWER_S3_BUCKET", "ab"),
        ("BOWER_S3_BUCKET", "-bower"),
        ("BOWER_S3_BUCKET", "xn--bower"),
        ("BOWER_S3_BUCKET", "bower-s3alias"),
        ("BOWER_S3_BUCKET", "bower_under"),
        ("BOWER_S3_REGION", "Sydney"),
        ("BOWER_S3_PREFIX", "/bower"),
        ("BOWER_S3_PREFIX", "bower/"),
        ("BOWER_S3_PREFIX", "bower//x"),
        ("BOWER_S3_PREFIX", "bower/../x"),
        ("BOWER_S3_PREFIX", "bower x"),
        ("BOWER_S3_SSE", "aws:kms:dsse"),
        ("BOWER_S3_KMS_KEY_ID", "alias/key"),
        ("BOWER_S3_EXPECTED_BUCKET_OWNER", "12345"),
        ("BOWER_S3_MAX_OBJECT_BYTES", "1024"),
        ("BOWER_S3_MAX_OBJECT_BYTES", "999999999"),
        ("BOWER_S3_MAX_OBJECT_EVENTS", "0"),
        ("BOWER_S3_GZIP", "yes"),
    ];
    for (name, value) in invalid {
        let mut pairs: Vec<(&str, String)> = base
            .iter()
            .filter(|(key, _)| *key != name)
            .map(|(k, v)| (*k, v.to_string()))
            .collect();
        pairs.push((name, value.into()));
        let parsed = S3OutputOptions::from_environment(read(pairs));
        assert!(
            parsed
                .and_then(|options| options.unwrap().validate())
                .is_err(),
            "{name}={value}"
        );
    }

    let none = S3OutputOptions::from_environment(|_| None).unwrap();
    assert_eq!(None, none);
}
