//! Parity: for the same input and clock, the envelope the Lambda sends (the
//! CloudWatch Logs message, or CloudTrail Lake `additionalEventData.envelope`) is
//! byte-identical to what the Rust collector queues, apart from the `collector`
//! context (host id, source adapter, configuration hash). Privacy alerts included.
//! Rust collector to C# redaction parity is proven by
//! `bower-redaction/tests/parity.rs`.

mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bower_collector::host::{self, BuildOptions};
use bower_collector::{CollectorSettings, bundle};
use bower_contracts::SecurityEventEnvelope;
use bower_lambda::audit::RecordFormat;
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;
use support::*;
use tower::ServiceExt;

const TOKEN: &str = "parity-ingest-token-0123456789abcdef0123456789";

#[derive(Deserialize)]
struct EventData {
    #[serde(rename = "additionalEventData")]
    additional: Additional,
}

#[derive(Deserialize)]
struct Additional {
    envelope: Box<RawValue>,
}

/// Queued payloads by event id, from the collector.
async fn collector_payloads(candidate: &str, profile: bool) -> (u16, Vec<(String, String)>) {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.path().join("queue.db"),
        repo_root().join("policies/default"),
        "collector-test",
    );
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    if profile {
        let key = directory.path().join("privacy.key");
        std::fs::write(&key, [0xabu8; 32]).unwrap();
        settings.privacy_profile_path =
            Some(repo_root().join("deploy/privacy/cloud-identities.yaml"));
        settings.privacy_hmac_key_file = Some(key);
    }
    let loaded = bundle::load(&settings).unwrap();
    let mut collector = host::build(
        settings,
        loaded,
        BuildOptions {
            clock: Some(clock()),
            ..BuildOptions::default()
        },
    )
    .unwrap();
    collector.initialize().await.unwrap();
    let request = Request::post("/v1/events")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::from(candidate.to_string()))
        .unwrap();
    let response = collector.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let mut rows: Vec<(String, String)> = collector
        .store
        .lease(100, Duration::from_secs(60))
        .unwrap()
        .into_iter()
        .map(|row| (row.event_id, row.payload))
        .collect();
    rows.sort();
    (status.as_u16(), rows)
}

/// Sent envelopes by event id, from the Lambda (direct invoke, same trust model).
async fn lambda_envelopes(
    candidate: &str,
    profile: bool,
    sink: FakeSink,
) -> (u16, Vec<(String, String)>) {
    let handler = handler(
        &sink,
        Config {
            ingress: "invoke",
            invoke_producer: Some("default"),
            single_trust_domain: true,
            privacy_profile: profile
                .then(|| repo_root().join("deploy/privacy/cloud-identities.yaml")),
            hmac_key: profile.then(|| bower_redaction::decode_key_material(&[0xab; 32]).unwrap()),
            ..Config::default()
        },
    );
    let invocation = handler.invoke(candidate).await;
    let mut envelopes: Vec<(String, String)> = sink
        .sent()
        .into_iter()
        .map(|record| match record.format {
            // The log event message is the envelope itself.
            RecordFormat::CloudWatchLogs => (record.bower_event_id, record.event_data),
            RecordFormat::CloudTrailLake => {
                let data: EventData = serde_json::from_str(&record.event_data).unwrap();
                (
                    record.bower_event_id,
                    data.additional.envelope.get().to_string(),
                )
            }
        })
        .collect();
    envelopes.sort();
    (invocation.status, envelopes)
}

async fn assert_parity(candidate: &str, profile: bool) -> usize {
    let lake = assert_parity_for(candidate, profile, FakeSink::default()).await;
    let logs = assert_parity_for(candidate, profile, FakeSink::cloudwatch_logs()).await;
    assert_eq!(
        lake, logs,
        "both destinations send the same events for {candidate}"
    );
    lake
}

async fn assert_parity_for(candidate: &str, profile: bool, sink: FakeSink) -> usize {
    let (collector_status, collector) = collector_payloads(candidate, profile).await;
    let (lambda_status, lambda) = lambda_envelopes(candidate, profile, sink).await;
    assert_eq!(lambda_status, collector_status, "status for {candidate}");
    assert_eq!(
        lambda.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        collector.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        "event ids for {candidate}"
    );
    for ((_, sent), (_, queued)) in lambda.iter().zip(&collector) {
        let sent_envelope: SecurityEventEnvelope = bower_contracts::json::from_str(sent).unwrap();
        let mut queued_envelope: SecurityEventEnvelope =
            bower_contracts::json::from_str(queued).unwrap();
        let lambda_collector = sent_envelope.collector.clone().unwrap();
        let collector_context = queued_envelope.collector.clone().unwrap();
        assert_eq!(lambda_collector.version, collector_context.version);
        assert_eq!(lambda_collector.received_at, collector_context.received_at);
        assert_eq!(lambda_collector.source_adapter, "aws-lambda-invoke:default");
        assert_eq!(collector_context.source_adapter, "local-http:default");
        queued_envelope.collector = Some(lambda_collector);
        assert_eq!(
            sent,
            &bower_contracts::json::to_string(&queued_envelope).unwrap(),
            "envelope bytes for {candidate}"
        );
    }
    lambda.len()
}

#[tokio::test]
async fn sent_envelopes_match_collector_queue_bytes() {
    let mut secrets = authentication_failure("parity-secrets");
    secrets["attributes"] = json!({
        "dbPassword": "hunter2-never-send",
        "contact": "jane.citizen@example.com",
        "card": "4111 1111 1111 1111",
        "note": "José <admin> & 'ops' + `tick`",
        "nested": {"apiKey": "x", "list": [1, 2.50, "Medicare 2123 45670 1"]}
    });
    secrets["labels"] = json!({"team": "identity"});
    let plain = authentication_failure("parity-plain");
    let mut rejected = authentication_failure("parity-rejected");
    rejected["eventType"] = json!("page_view");
    rejected["eventCategory"] = json!("telemetry");
    rejected["attributes"] = json!({"secret": "never-send"});
    let mut quarantined = authentication_failure("parity-quarantined");
    quarantined["schemaVersion"] = json!("9.9.9");
    quarantined["attributes"] = json!({"password": "never-send"});

    let mut sent = 0;
    for (candidate, profile) in [
        (secrets.to_string(), false),
        (plain.to_string(), false),
        (rejected.to_string(), false),
        (quarantined.to_string(), false),
        (secrets.to_string(), true),
        // Raw text with duplicate keys and number text is processed byte for byte.
        (
            plain
                .to_string()
                .replacen("{", r#"{"attributes":{"n":1.50,"n":2},"#, 1),
            false,
        ),
    ] {
        sent += assert_parity(&candidate, profile).await;
    }
    assert!(sent >= 6, "parity compared {sent} envelopes");
}

#[tokio::test]
async fn collector_and_lambda_agree_on_status_for_invalid_bodies() {
    for body in ["{", "[1,2", "null"] {
        let (collector_status, _) = collector_payloads(body, false).await;
        for sink in [FakeSink::default(), FakeSink::cloudwatch_logs()] {
            let (lambda_status, _) = lambda_envelopes(body, false, sink).await;
            assert_eq!(lambda_status, collector_status, "{body}");
        }
    }
    let (collector_status, _) = collector_payloads("{}", false).await;
    assert_eq!(collector_status, StatusCode::BAD_REQUEST.as_u16());
    let (lambda_status, _) = lambda_envelopes("{}", false, FakeSink::cloudwatch_logs()).await;
    assert_eq!(lambda_status, collector_status);
}
