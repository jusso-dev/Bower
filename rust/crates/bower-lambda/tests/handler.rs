//! Handler tests with fake CloudTrail Lake and CloudWatch Logs sinks: IAM principal
//! mapping, producer scopes, policy, redaction before send, batching, partial
//! failures, input bounds and `additionalEventData` limits. Parity with the Rust
//! collector is in `collector_parity.rs`.

mod support;

use base64::Engine;
use bower_lambda::audit::{MAXIMUM_EVENTS_PER_CALL, MAXIMUM_REQUEST_BYTES, RecordFormat};
use bower_lambda::{Handler, InvocationKind};
use serde_json::{Value, json};
use support::*;

const ROLE_SESSION: &str = "arn:aws:sts::123456789012:assumed-role/orders-api/i-0abc123";

fn url_handler(sink: &FakeSink) -> Handler<FakeSink> {
    handler(sink, Config::default())
}

#[tokio::test]
async fn mapped_role_session_is_redacted_mapped_and_delivered() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    let mut event = authentication_failure("evt-0001");
    event["attributes"] =
        json!({"dbPassword": "never-send-this", "contact": "jane.citizen@example.com"});

    let invocation = handler
        .invoke(&url_event(Some(ROLE_SESSION), &event.to_string()))
        .await;

    assert_eq!(invocation.kind, InvocationKind::FunctionUrl);
    assert_eq!(invocation.status, 202, "{}", invocation.body);
    let body: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(body["decision"], "redactandaccept");
    assert_eq!(body["queued"], true);
    assert_eq!(body["retryable"], false);
    assert!(!invocation.body.contains("never-send-this"));

    let sent = sink.sent();
    // The source event plus its privacy alert (secret field detected), as the collector queues.
    assert_eq!(
        sent.len(),
        2,
        "{:?}",
        sent.iter().map(|r| &r.bower_event_id).collect::<Vec<_>>()
    );
    for record in &sent {
        assert!(!record.event_data.contains("never-send-this"));
        assert!(!record.event_data.contains("jane.citizen@example.com"));
        let checksum = base64::engine::general_purpose::STANDARD.encode(sha256(&record.event_data));
        assert_eq!(record.checksum, checksum);
    }
    let source = sent.iter().find(|record| record.id == "evt-0001").unwrap();
    let data: Value = serde_json::from_str(&source.event_data).unwrap();
    assert_eq!(data["version"], "1.0.0");
    assert_eq!(data["eventSource"], "bower.TestApplication");
    assert_eq!(data["eventName"], "authentication_failure");
    assert_eq!(data["eventTime"], "2026-10-24T01:02:03Z");
    assert_eq!(data["UID"], "evt-0001");
    assert_eq!(data["recipientAccountId"], "123456789012");
    assert_eq!(data["errorCode"], "failure");
    assert_eq!(data["errorMessage"], "InvalidPassword");
    assert_eq!(data["sourceIPAddress"], "192.0.2.10");
    assert_eq!(data["userIdentity"]["type"], "human");
    assert_eq!(data["userIdentity"]["details"]["producer"], "orders");
    let envelope = &data["additionalEventData"]["envelope"];
    assert_eq!(envelope["eventId"], "evt-0001");
    assert_eq!(
        envelope["collector"]["sourceAdapter"],
        "aws-lambda-url:orders"
    );
    assert_eq!(envelope["security"]["policyId"], "BWR-POL-AUTH-FAILURE");
    assert_ne!(envelope["attributes"]["dbPassword"], "never-send-this");
    assert!(data["additionalEventData"]["privacy"]["detected"].is_array());
    let alert = sent
        .iter()
        .find(|record| record.id.starts_with("privacy-"))
        .unwrap();
    assert!(alert.event_data.contains("sensitive_data_detected"));
}

#[tokio::test]
async fn unmapped_or_unsigned_callers_and_out_of_scope_events_are_denied_without_sending() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    let event = authentication_failure("evt-0002").to_string();

    let unmapped = handler
        .invoke(&url_event(
            Some("arn:aws:sts::123456789012:assumed-role/someone-else/s"),
            &event,
        ))
        .await;
    assert_eq!(unmapped.status, 403);
    assert!(!unmapped.body.contains("someone-else"), "caller ARN echoed");

    let unsigned = handler.invoke(&url_event(None, &event)).await;
    assert_eq!(unsigned.status, 401);

    // Mapped producer, but the event claims an application outside its scope.
    let mut other = authentication_failure("evt-0003");
    other["application"]["name"] = json!("PayrollApplication");
    let scoped = handler
        .invoke(&url_event(Some(ROLE_SESSION), &other.to_string()))
        .await;
    assert_eq!(scoped.status, 403);
    assert_eq!(
        serde_json::from_str::<Value>(&scoped.body).unwrap()["error"],
        "Producer is not authorized for this event identity."
    );

    // A mapped principal whose producer has no scope at all is denied too.
    let ci = handler
        .invoke(&url_event(
            Some("arn:aws:iam::123456789012:user/ci-forwarder"),
            &event,
        ))
        .await;
    assert_eq!(ci.status, 403);
    assert!(sink.calls().is_empty());
}

#[tokio::test]
async fn policy_rejection_is_reported_and_not_sent() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    let mut event = authentication_failure("evt-0004");
    event["eventType"] = json!("page_view");
    event["eventCategory"] = json!("telemetry");

    let invocation = handler
        .invoke(&url_event(Some(ROLE_SESSION), &event.to_string()))
        .await;

    assert!(
        matches!(invocation.status, 400 | 422),
        "{}",
        invocation.body
    );
    let body: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(body["queued"], false);
    assert!(sink.calls().is_empty());
}

#[tokio::test]
async fn request_bounds_and_malformed_input_fail_before_processing() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    let valid = authentication_failure("evt-0005").to_string();

    let cases = [
        (url_event(Some(ROLE_SESSION), "{not json"), 400),
        (url_event(Some(ROLE_SESSION), ""), 400),
        (url_event(Some(ROLE_SESSION), "[]"), 400),
        (
            url_event(
                Some(ROLE_SESSION),
                &format!("{}{}", "[".repeat(65), "]".repeat(65)),
            ),
            400,
        ),
        (url_event(Some(ROLE_SESSION), &" ".repeat(1_048_577)), 413),
        (
            url_event(
                Some(ROLE_SESSION),
                &format!("[{}]", vec![valid.as_str(); 101].join(",")),
            ),
            413,
        ),
        (
            with(
                &url_event(Some(ROLE_SESSION), &valid),
                "/headers/content-type",
                json!("text/plain"),
            ),
            415,
        ),
        (
            with(
                &url_event(Some(ROLE_SESSION), &valid),
                "/rawPath",
                json!("/v1/status"),
            ),
            404,
        ),
        (
            with(
                &url_event(Some(ROLE_SESSION), &valid),
                "/requestContext/http/method",
                json!("GET"),
            ),
            405,
        ),
        (
            with(
                &with(
                    &url_event(Some(ROLE_SESSION), "!!!"),
                    "/isBase64Encoded",
                    json!(true),
                ),
                "/body",
                json!("***"),
            ),
            400,
        ),
    ];
    for (event, status) in cases {
        let invocation = handler.invoke(&event).await;
        assert_eq!(invocation.status, status, "{}", invocation.body);
    }
    assert!(sink.calls().is_empty());

    // Base64 bodies (Function URLs encode non-text content types) are decoded.
    let encoded = base64::engine::general_purpose::STANDARD.encode(valid.as_bytes());
    let event = with(
        &with(
            &url_event(Some(ROLE_SESSION), &encoded),
            "/isBase64Encoded",
            json!(true),
        ),
        "/headers/content-type",
        json!("application/cloudevents+json"),
    );
    assert_eq!(handler.invoke(&event).await.status, 202);
}

#[tokio::test]
async fn batches_report_per_event_and_respect_put_audit_events_limits() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    // 100 accepted events with ~9 KB of attributes each: more than 1 MB of eventData.
    let events: Vec<String> = (0..100)
        .map(|index| {
            let mut event = authentication_failure(&format!("evt-batch-{index:03}"));
            event["attributes"] = json!({"note": "n".repeat(9_000)});
            event.to_string()
        })
        .collect();
    let mut rejected = authentication_failure("evt-batch-reject");
    rejected["eventType"] = json!("page_view");
    let mut body_events = events[..99].to_vec();
    body_events.push(rejected.to_string());
    let body = format!("[{}]", body_events.join(","));
    assert!(body.len() <= 1_048_576);

    let invocation = handler.invoke(&url_event(Some(ROLE_SESSION), &body)).await;

    assert_eq!(
        invocation.status,
        207,
        "{}",
        &invocation.body[..400.min(invocation.body.len())]
    );
    let response: Value = serde_json::from_str(&invocation.body).unwrap();
    let results = response["results"].as_array().unwrap();
    assert_eq!(results.len(), 100);
    assert_eq!(response["retryIndexes"], json!([]));
    assert!(results[..99].iter().all(|result| result["status"] == 202));
    assert!(matches!(results[99]["status"].as_u64(), Some(400 | 422)));
    assert_eq!(results[42]["index"], 42);

    let calls = sink.calls();
    assert!(calls.len() >= 2, "expected the 1 MB limit to split calls");
    let mut total = 0;
    for call in &calls {
        assert!(call.len() <= MAXIMUM_EVENTS_PER_CALL);
        let bytes: usize = call.iter().map(|record| record.request_bytes()).sum();
        assert!(bytes <= MAXIMUM_REQUEST_BYTES);
        total += call.len();
    }
    assert_eq!(total, 99);
}

#[tokio::test]
async fn partial_failures_are_retryable_per_event_and_definitive_refusals_are_not() {
    let sink = FakeSink::default();
    sink.refuse("evt-pf-1", "Throttling");
    sink.refuse("evt-pf-2", "InvalidData");
    let handler = url_handler(&sink);
    let body = format!(
        "[{},{},{}]",
        authentication_failure("evt-pf-0"),
        authentication_failure("evt-pf-1"),
        authentication_failure("evt-pf-2")
    );

    let invocation = handler.invoke(&url_event(Some(ROLE_SESSION), &body)).await;

    assert_eq!(invocation.status, 503);
    let response: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(response["retryIndexes"], json!([1]));
    let results = response["results"].as_array().unwrap();
    assert_eq!(results[0]["status"], 202);
    assert_eq!(results[0]["queued"], true);
    assert_eq!(results[0]["delivery"][0]["status"], "accepted");
    assert_eq!(results[1]["status"], 503);
    assert_eq!(results[1]["retryable"], true);
    assert_eq!(results[1]["queued"], false);
    assert_eq!(results[1]["delivery"][0]["errorCode"], "Throttling");
    assert_eq!(results[2]["status"], 422);
    assert_eq!(results[2]["delivery"][0]["status"], "refused");

    // Retrying only the failed event succeeds and resends the same audit id.
    sink.clear_refusals();
    let retry = handler
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &authentication_failure("evt-pf-1").to_string(),
        ))
        .await;
    assert_eq!(retry.status, 202);
    assert_eq!(sink.calls().last().unwrap()[0].id, "evt-pf-1");
}

#[tokio::test]
async fn whole_call_failure_and_missing_results_never_claim_delivery() {
    let sink = FakeSink::default();
    sink.fail_calls("AccessDeniedException");
    let handler = url_handler(&sink);
    let invocation = handler
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &authentication_failure("evt-wc").to_string(),
        ))
        .await;
    assert_eq!(invocation.status, 503);
    let body: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(body["retryable"], true);
    assert_eq!(body["delivery"][0]["errorCode"], "AccessDeniedException");

    let silent = FakeSink::default();
    silent.drop_results();
    let handler = url_handler(&silent);
    let invocation = handler
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &authentication_failure("evt-mr").to_string(),
        ))
        .await;
    assert_eq!(invocation.status, 503);
    assert!(invocation.body.contains("missing-result"));
}

#[tokio::test]
async fn additional_event_data_limit_omits_attributes_then_refuses() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    let mut large = authentication_failure("evt-large-attributes");
    large["attributes"] = json!({"note": "a".repeat(15_000), "more": "b".repeat(15_000)});
    let mut huge = authentication_failure("evt-large-labels");
    huge["labels"] = Value::Object(
        (0..400)
            .map(|index| (format!("label{index}"), json!("x".repeat(90))))
            .collect(),
    );
    let body = format!("[{large},{huge}]");

    let invocation = handler.invoke(&url_event(Some(ROLE_SESSION), &body)).await;

    let response: Value = serde_json::from_str(&invocation.body).unwrap();
    let results = response["results"].as_array().unwrap();
    assert_eq!(results[0]["status"], 202, "{}", results[0]);
    assert_eq!(
        results[0]["delivery"][0]["omittedFields"],
        json!(["attributes"])
    );
    assert_eq!(results[1]["status"], 422, "{}", results[1]);
    assert_eq!(
        results[1]["delivery"][0]["errorCode"],
        "cloudtrail-lake-event-too-large"
    );
    let sent = sink.sent();
    assert_eq!(sent.len(), 1);
    let data: Value = serde_json::from_str(&sent[0].event_data).unwrap();
    let additional = data["additionalEventData"].to_string();
    assert!(additional.len() <= 28_000);
    assert!(
        data["additionalEventData"]["envelope"]
            .get("attributes")
            .is_none()
    );
    assert_eq!(
        data["additionalEventData"]["omittedFields"],
        json!(["attributes"])
    );
}

#[tokio::test]
async fn ingress_modes_block_forged_url_events_and_unconfigured_invokes() {
    let event = authentication_failure("evt-ing").to_string();

    // Function URL only (default): direct payloads are refused.
    let sink = FakeSink::default();
    let direct = url_handler(&sink).invoke(&event).await;
    assert_eq!((direct.kind, direct.status), (InvocationKind::Invoke, 403));

    // Invoke only: a URL-shaped payload (forgeable by any invoker) is refused.
    let invoke_only = handler(
        &sink,
        Config {
            ingress: "invoke",
            invoke_producer: Some("orders"),
            ..Config::default()
        },
    );
    let forged = invoke_only
        .invoke(&url_event(Some(ROLE_SESSION), &event))
        .await;
    assert_eq!(forged.status, 403);
    assert!(sink.calls().is_empty());

    let accepted = invoke_only.invoke(&event).await;
    assert_eq!(accepted.status, 202, "{}", accepted.body);
    let payload: Value = serde_json::from_str(&accepted.into_payload()).unwrap();
    assert_eq!(payload["statusCode"], 202);
    assert_eq!(payload["body"]["eventId"], "evt-ing");
    let data: Value = serde_json::from_str(&sink.sent()[0].event_data).unwrap();
    assert_eq!(
        data["additionalEventData"]["envelope"]["collector"]["sourceAdapter"],
        "aws-lambda-invoke:orders"
    );

    // Invoke mode without a producer, and the mixed `both` mode, fail at init.
    for config in [
        Config {
            ingress: "invoke",
            ..Config::default()
        },
        Config {
            ingress: "both",
            invoke_producer: Some("orders"),
            ..Config::default()
        },
    ] {
        assert!(try_handler(&FakeSink::default(), config).is_err());
    }

    // Function URL responses are Lambda URL response objects.
    let url = url_handler(&FakeSink::default())
        .invoke(&url_event(Some(ROLE_SESSION), &event))
        .await;
    let payload: Value = serde_json::from_str(&url.into_payload()).unwrap();
    assert_eq!(payload["statusCode"], 202);
    assert_eq!(
        payload["headers"]["content-type"],
        "application/json; charset=utf-8"
    );
    assert!(payload["body"].is_string());
}

#[tokio::test]
async fn duplicates_and_identity_conflicts_inside_a_batch() {
    let sink = FakeSink::default();
    let handler = url_handler(&sink);
    let event = authentication_failure("evt-dup");
    let mut conflicting = event.clone();
    conflicting["eventOutcomeReason"] = json!("Different");
    let body = format!("[{event},{event},{conflicting}]");

    let invocation = handler.invoke(&url_event(Some(ROLE_SESSION), &body)).await;

    let response: Value = serde_json::from_str(&invocation.body).unwrap();
    let results = response["results"].as_array().unwrap();
    assert_eq!(results[0]["status"], 202);
    assert_eq!(results[1]["status"], 200);
    assert_eq!(results[1]["duplicate"], true);
    assert_eq!(results[1]["queued"], false);
    assert_eq!(results[1]["delivery"][0]["status"], "accepted");
    assert_eq!(results[2]["status"], 409);
    assert_eq!(sink.sent().len(), 1);
}

#[tokio::test]
async fn custom_privacy_profile_pseudonymises_before_send() {
    let sink = FakeSink::default();
    let handler = handler(
        &sink,
        Config {
            privacy_profile: Some(repo_root().join("deploy/privacy/cloud-identities.yaml")),
            hmac_key: Some(vec![0xab; 32]),
            ..Config::default()
        },
    );
    let invocation = handler
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &authentication_failure("evt-hmac").to_string(),
        ))
        .await;
    assert_eq!(invocation.status, 202, "{}", invocation.body);
    let sent = sink.sent();
    let data: Value = serde_json::from_str(&sent[0].event_data).unwrap();
    let username = data["additionalEventData"]["envelope"]["actor"]["username"]
        .as_str()
        .unwrap();
    assert_ne!(username, "test-user");
    assert!(!sent[0].event_data.contains("test-user"));
    assert_eq!(data["userIdentity"]["principalId"], username);
}

#[test]
fn profile_needing_hmac_without_key_fails_closed_at_init() {
    let error = try_handler(
        &FakeSink::default(),
        Config {
            privacy_profile: Some(repo_root().join("deploy/privacy/cloud-identities.yaml")),
            ..Config::default()
        },
    )
    .err()
    .expect("init must fail without the HMAC key");
    assert!(error.0.starts_with("Policy bundle:"), "{}", error.0);
}

#[test]
fn missing_policy_directory_fails_closed_at_init() {
    let error = try_handler(
        &FakeSink::default(),
        Config {
            policy_directory: Some("/nonexistent/policies".into()),
            ..Config::default()
        },
    )
    .err()
    .expect("init must fail");
    assert!(error.0.contains("Policy directory does not exist"));
}

// ------------------------------------------------------------------ council review regressions

/// B1 (Codex 1 / Claude 2): `IngressMode=both` let a direct invoker whose producer has no
/// scope send a URL-shaped payload claiming another mapped producer's ARN. The mixed mode
/// no longer exists.
#[test]
fn mixed_ingress_cannot_be_configured() {
    let error = try_handler(
        &FakeSink::default(),
        Config {
            ingress: "both",
            invoke_producer: Some("ci"),
            ..Config::default()
        },
    )
    .err()
    .expect("ingress both must not start");
    assert!(error.0.contains("BOWER_LAMBDA_INGRESS"), "{}", error.0);
}

/// B1: trust boundary, pinned. The handler cannot tell a Function URL event from a
/// URL-shaped direct `Invoke` payload, so in function-url mode it trusts the caller
/// ARN in it: only IAM (the resource policy plus the shipped SCP / permissions
/// boundary Deny) keeps direct invokers out. Invoke mode refuses the same payload.
#[tokio::test]
async fn url_shaped_direct_payload_is_trusted_in_function_url_mode_and_refused_in_invoke_mode() {
    let event = authentication_failure("evt-trust").to_string();
    let forged = url_event(Some(ROLE_SESSION), &event);

    let sink = FakeSink::default();
    let url_mode = url_handler(&sink).invoke(&forged).await;
    assert_eq!(url_mode.status, 202, "{}", url_mode.body);
    assert_eq!(sink.sent().len(), 1);

    let sink = FakeSink::default();
    let invoke_mode = handler(
        &sink,
        Config {
            ingress: "invoke",
            invoke_producer: Some("orders"),
            ..Config::default()
        },
    )
    .invoke(&forged)
    .await;
    assert_eq!(invoke_mode.status, 403);
    assert!(sink.calls().is_empty());
}

fn secret_event(event_id: &str) -> Value {
    let mut event = authentication_failure(event_id);
    event["attributes"] = json!({"dbPassword": "never-send-this"});
    event
}

/// B2 (Codex 4): source accepted, privacy alert refused for good (`InvalidData`)
/// used to answer 202 queued=true. Every required record must be accepted.
#[tokio::test]
async fn permanently_refused_privacy_alert_prevents_success() {
    let sink = FakeSink::default();
    sink.refuse("privacy-*", "InvalidData");
    let invocation = url_handler(&sink)
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &secret_event("evt-b2").to_string(),
        ))
        .await;

    assert_eq!(invocation.status, 422, "{}", invocation.body);
    let body: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(body["queued"], false);
    assert_eq!(body["retryable"], false);
    let statuses: Vec<&str> = body["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .map(|report| report["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["accepted", "refused"]);
}

/// B2: a retryable record still wins over a permanent refusal so the element converges
/// (retry until nothing is retryable, then the definitive answer).
#[tokio::test]
async fn retryable_source_with_refused_alert_is_retried_first() {
    let sink = FakeSink::default();
    sink.refuse("evt-b2r", "Throttling");
    sink.refuse("privacy-*", "InvalidData");
    let handler = url_handler(&sink);
    let first = handler
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &secret_event("evt-b2r").to_string(),
        ))
        .await;
    assert_eq!(first.status, 503, "{}", first.body);
    sink.clear_refusals();
    sink.refuse("privacy-*", "InvalidData");
    let second = handler
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &secret_event("evt-b2r").to_string(),
        ))
        .await;
    assert_eq!(second.status, 422, "{}", second.body);
}

fn batch_results(body: &str) -> (Vec<Value>, Value) {
    let response: Value = serde_json::from_str(body).unwrap();
    (
        response["results"].as_array().unwrap().clone(),
        response["retryIndexes"].clone(),
    )
}

/// B3 (Codex 5): `[event, event]` with the alert throttled answered `[503, 200]` and
/// `retryIndexes: [0]`. A duplicate inherits the original's complete outcome.
#[tokio::test]
async fn same_id_duplicate_inherits_throttled_alert() {
    let sink = FakeSink::default();
    sink.refuse("privacy-*", "Throttling");
    let event = secret_event("evt-b3");
    let invocation = url_handler(&sink)
        .invoke(&url_event(
            Some(ROLE_SESSION),
            &format!("[{event},{event}]"),
        ))
        .await;

    assert_eq!(invocation.status, 503);
    let (results, retry) = batch_results(&invocation.body);
    assert_eq!(results[0]["status"], 503);
    assert_eq!(results[1]["status"], 503, "{}", results[1]);
    assert_eq!(results[1]["duplicate"], true);
    assert_eq!(results[1]["queued"], false);
    assert_eq!(results[1]["retryable"], true);
    assert_eq!(retry, json!([0, 1]));
}

/// B3: same for a fingerprint alias (same source identity and content, another eventId)
/// against permanent refusal and against a local mapping failure.
#[tokio::test]
async fn fingerprint_alias_duplicate_inherits_refusal_and_mapping_failure() {
    let alias = |id: &str, original: Value| {
        let mut event = original;
        event["eventId"] = json!(id);
        event
    };

    // Alert refused for good.
    let sink = FakeSink::default();
    sink.refuse("privacy-*", "InvalidData");
    let original = secret_event("evt-b3-a");
    let body = format!("[{original},{}]", alias("evt-b3-b", original.clone()));
    let invocation = url_handler(&sink)
        .invoke(&url_event(Some(ROLE_SESSION), &body))
        .await;
    let (results, _) = batch_results(&invocation.body);
    assert_eq!(results[0]["status"], 422, "{}", results[0]);
    assert_eq!(results[1]["duplicate"], true, "{}", results[1]);
    assert_eq!(results[1]["status"], 422, "{}", results[1]);
    assert_eq!(results[1]["queued"], false);

    // Source cannot be mapped (labels larger than additionalEventData allows).
    let sink = FakeSink::default();
    let mut huge = authentication_failure("evt-b3-c");
    huge["labels"] = Value::Object(
        (0..400)
            .map(|index| (format!("label{index}"), json!("x".repeat(90))))
            .collect(),
    );
    let body = format!("[{huge},{}]", alias("evt-b3-d", huge.clone()));
    let invocation = url_handler(&sink)
        .invoke(&url_event(Some(ROLE_SESSION), &body))
        .await;
    let (results, _) = batch_results(&invocation.body);
    assert_eq!(results[0]["status"], 422, "{}", results[0]);
    assert_eq!(results[1]["duplicate"], true, "{}", results[1]);
    assert_eq!(results[1]["status"], 422, "{}", results[1]);
    assert_eq!(
        results[1]["delivery"][0]["errorCode"],
        "cloudtrail-lake-event-too-large"
    );
    assert!(sink.calls().is_empty());

    // And a fully accepted original still acknowledges its alias as a duplicate.
    let sink = FakeSink::default();
    let original = secret_event("evt-b3-e");
    let body = format!("[{original},{}]", alias("evt-b3-f", original.clone()));
    let invocation = url_handler(&sink)
        .invoke(&url_event(Some(ROLE_SESSION), &body))
        .await;
    let (results, retry) = batch_results(&invocation.body);
    assert_eq!(results[0]["status"], 202);
    assert_eq!(results[1]["status"], 200, "{}", results[1]);
    assert_eq!(retry, json!([]));
    // Original source and alert, plus the alias's own alert (its id derives from the
    // alias eventId), exactly as the collector would queue them.
    assert_eq!(sink.sent().len(), 3);
}

/// B4 (Claude 9): serverless hosts cannot use managed privacy profiles; refuse at init
/// instead of silently using the packaged or default profile.
#[test]
fn managed_privacy_profile_source_fails_at_init() {
    let error = try_handler(
        &FakeSink::default(),
        Config {
            extra: vec![("BOWER_PRIVACY_PROFILE_SOURCE", "management")],
            ..Config::default()
        },
    )
    .err()
    .expect("management profile source must not start");
    assert_eq!(
        error.0,
        "BOWER_PRIVACY_PROFILE_SOURCE=management is not supported by the AWS Lambda host; \
         package a reviewed privacy profile."
    );
    assert!(
        try_handler(
            &FakeSink::default(),
            Config {
                extra: vec![("BOWER_PRIVACY_PROFILE_SOURCE", "remote")],
                ..Config::default()
            },
        )
        .is_err()
    );
    assert!(
        try_handler(
            &FakeSink::default(),
            Config {
                extra: vec![("BOWER_PRIVACY_PROFILE_SOURCE", "local")],
                ..Config::default()
            },
        )
        .is_ok()
    );
}

#[tokio::test]
async fn cloudwatch_logs_receives_the_redacted_envelope_stamped_with_receive_time() {
    let sink = FakeSink::cloudwatch_logs();
    let handler = url_handler(&sink);
    let mut event = authentication_failure("evt-cwl-1");
    event["timeGenerated"] = json!("2026-09-01T00:00:00Z");
    event["attributes"] = json!({"dbPassword": "never-send-this"});

    let invocation = handler
        .invoke(&url_event(Some(ROLE_SESSION), &event.to_string()))
        .await;

    assert_eq!(invocation.status, 202, "{}", invocation.body);
    let body: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(body["queued"], true);
    for report in body["delivery"].as_array().unwrap() {
        assert_eq!(report["status"], "accepted");
        assert!(report.get("cloudTrailEventId").is_none(), "{report}");
    }
    let sent = sink.sent();
    assert_eq!(sent.len(), 2, "source event and its privacy alert");
    let now = bower_contracts::time::parse(NOW)
        .unwrap()
        .timestamp_millis();
    for record in &sent {
        assert_eq!(record.format, RecordFormat::CloudWatchLogs);
        assert_eq!(record.timestamp_ms, now, "receive time, not timeGenerated");
        assert!(record.checksum.is_empty());
        assert!(!record.event_data.contains("never-send-this"));
    }
    let source = sent.iter().find(|record| record.id == "evt-cwl-1").unwrap();
    let message: Value = serde_json::from_str(&source.event_data).unwrap();
    // The message is the envelope itself (what the AWS cloud source and Firehose
    // subscription filter on `schemaVersion` read), not a CloudTrail record.
    assert_eq!(message["schemaVersion"], "1.0.0");
    assert_eq!(message["eventId"], "evt-cwl-1");
    assert_eq!(message["timeGenerated"], "2026-09-01T00:00:00+00:00");
    assert_eq!(
        message["collector"]["sourceAdapter"],
        "aws-lambda-url:orders"
    );
    assert_eq!(message["security"]["policyId"], "BWR-POL-AUTH-FAILURE");
    assert!(message.get("UID").is_none());
}

#[tokio::test]
async fn cloudwatch_logs_rejections_and_call_failures_are_retryable() {
    let sink = FakeSink::cloudwatch_logs();
    let handler = url_handler(&sink);
    sink.refuse("evt-cwl-2", "cloudwatch-logs-too-old");
    let event = authentication_failure("evt-cwl-2");

    let invocation = handler
        .invoke(&url_event(Some(ROLE_SESSION), &event.to_string()))
        .await;
    assert_eq!(invocation.status, 503, "{}", invocation.body);
    let body: Value = serde_json::from_str(&invocation.body).unwrap();
    assert_eq!(body["queued"], false);
    assert_eq!(body["retryable"], true);

    sink.clear_refusals();
    sink.fail_calls("ResourceNotFoundException");
    let invocation = handler
        .invoke(&url_event(Some(ROLE_SESSION), &event.to_string()))
        .await;
    assert_eq!(invocation.status, 503, "{}", invocation.body);
    assert!(invocation.body.contains("ResourceNotFoundException"));
}

#[test]
fn cloudwatch_logs_destination_refuses_cloudtrail_settings_at_init() {
    let sink = FakeSink::cloudwatch_logs();
    let error = try_handler(
        &sink,
        Config {
            extra: vec![("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL)],
            ..Config::default()
        },
    )
    .err()
    .unwrap();
    assert!(
        error
            .0
            .contains("is not used with BOWER_LAMBDA_DESTINATION=cloudwatch-logs")
    );
}
