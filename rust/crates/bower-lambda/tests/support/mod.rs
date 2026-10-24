#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bower_contracts::time::{Clock, Timestamp};
use bower_lambda::audit::{AuditRecord, RecordFormat};
use bower_lambda::sink::{AcceptedEvent, AuditSink, PutResult, RefusedEvent, SinkFailure};
use bower_lambda::{Handler, LambdaSettings, SettingsError};
use serde_json::{Value, json};
use sha2::Digest;

pub const CHANNEL: &str =
    "arn:aws:cloudtrail:ap-southeast-2:123456789012:channel/01234567-89ab-cdef-0123-456789abcdef";
pub const NOW: &str = "2026-10-24T01:02:03Z";
pub const LOG_GROUP: &str = "/bower/events/test";

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

pub fn sha256(text: &str) -> Vec<u8> {
    sha2::Sha256::digest(text.as_bytes()).to_vec()
}

pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn utc_now(&self) -> Timestamp {
        self.0
    }
}

pub fn clock() -> Arc<dyn Clock> {
    Arc::new(FixedClock(bower_contracts::time::parse(NOW).unwrap()))
}

struct SinkState {
    format: RecordFormat,
    calls: Vec<Vec<AuditRecord>>,
    refusals: HashMap<String, String>,
    fail_calls: Option<String>,
    drop_results: bool,
}

impl Default for SinkState {
    fn default() -> Self {
        Self {
            format: RecordFormat::CloudTrailLake,
            calls: Vec::new(),
            refusals: HashMap::new(),
            fail_calls: None,
            drop_results: false,
        }
    }
}

/// Fake `PutAuditEvents` (default) or `PutLogEvents`: records every call, accepts
/// by default.
#[derive(Clone, Default)]
pub struct FakeSink(Arc<Mutex<SinkState>>);

impl FakeSink {
    pub fn cloudwatch_logs() -> Self {
        let sink = Self::default();
        sink.0.lock().unwrap().format = RecordFormat::CloudWatchLogs;
        sink
    }

    pub fn calls(&self) -> Vec<Vec<AuditRecord>> {
        self.0.lock().unwrap().calls.clone()
    }

    pub fn sent(&self) -> Vec<AuditRecord> {
        self.calls().into_iter().flatten().collect()
    }

    /// Refuse the audit event of this Bower event id with `code` (`prefix*` matches a prefix,
    /// for example `privacy-*` for every privacy alert).
    pub fn refuse(&self, bower_event_id: &str, code: &str) {
        self.0
            .lock()
            .unwrap()
            .refusals
            .insert(bower_event_id.into(), code.into());
    }

    pub fn clear_refusals(&self) {
        self.0.lock().unwrap().refusals.clear();
    }

    pub fn fail_calls(&self, code: &str) {
        self.0.lock().unwrap().fail_calls = Some(code.into());
    }

    pub fn drop_results(&self) {
        self.0.lock().unwrap().drop_results = true;
    }
}

impl AuditSink for FakeSink {
    fn format(&self) -> RecordFormat {
        self.0.lock().unwrap().format
    }

    async fn put_audit_events(&self, records: &[&AuditRecord]) -> Result<PutResult, SinkFailure> {
        let mut state = self.0.lock().unwrap();
        state
            .calls
            .push(records.iter().map(|record| (*record).clone()).collect());
        if let Some(code) = &state.fail_calls {
            return Err(SinkFailure::new(code.clone()));
        }
        if state.drop_results {
            return Ok(PutResult::default());
        }
        let mut result = PutResult::default();
        for record in records {
            let refusal = state.refusals.iter().find_map(|(key, code)| {
                let matches = match key.strip_suffix('*') {
                    Some(prefix) => record.bower_event_id.starts_with(prefix),
                    None => *key == record.bower_event_id,
                };
                matches.then_some(code)
            });
            match refusal {
                Some(code) => result.failed.push(RefusedEvent {
                    id: record.id.clone(),
                    error_code: code.clone(),
                }),
                None => result.successful.push(AcceptedEvent {
                    id: record.id.clone(),
                    event_id: (state.format == RecordFormat::CloudTrailLake)
                        .then(|| format!("ct-{}", record.id)),
                }),
            }
        }
        Ok(result)
    }
}

pub struct Config {
    pub ingress: &'static str,
    pub invoke_producer: Option<&'static str>,
    pub privacy_profile: Option<PathBuf>,
    pub hmac_key: Option<Vec<u8>>,
    pub policy_directory: Option<PathBuf>,
    pub single_trust_domain: bool,
    /// Extra environment variables (for init failure tests).
    pub extra: Vec<(&'static str, &'static str)>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ingress: "function-url",
            invoke_producer: None,
            privacy_profile: None,
            hmac_key: None,
            policy_directory: None,
            single_trust_domain: false,
            extra: Vec::new(),
        }
    }
}

/// Principals: the `orders-api` role is producer `orders`, the `ci-forwarder` user
/// is producer `ci` (which has no scope). Scope: `orders` may send the
/// `TestApplication`/`test` identity from `192.0.2.10`.
pub fn try_handler(sink: &FakeSink, config: Config) -> Result<Handler<FakeSink>, SettingsError> {
    let directory = tempfile::tempdir().unwrap().keep();
    let principals = directory.join("principals.json");
    std::fs::write(
        &principals,
        json!([
            {"principalArn": "arn:aws:iam::123456789012:role/apps/orders-api", "producer": "orders"},
            {"principalArn": "arn:aws:iam::123456789012:user/ci-forwarder", "producer": "ci"}
        ])
        .to_string(),
    )
    .unwrap();
    let scopes = directory.join("scopes.json");
    std::fs::write(
        &scopes,
        json!([{
            "producer": "orders",
            "application": {"name": "TestApplication", "environment": "test"},
            "source": {"ipAddress": "192.0.2.10"}
        }])
        .to_string(),
    )
    .unwrap();
    let destination = match sink.format() {
        RecordFormat::CloudTrailLake => [
            ("BOWER_LAMBDA_DESTINATION", "cloudtrail-lake".to_string()),
            ("BOWER_CLOUDTRAIL_CHANNEL_ARN", CHANNEL.to_string()),
        ],
        RecordFormat::CloudWatchLogs => [
            ("BOWER_LAMBDA_DESTINATION", "cloudwatch-logs".to_string()),
            ("BOWER_CLOUDWATCH_LOG_GROUP", LOG_GROUP.to_string()),
        ],
    };
    let mut env: HashMap<&str, String> = HashMap::from([
        ("BOWER_LAMBDA_INGRESS", config.ingress.to_string()),
        (
            "BOWER_POLICY_DIRECTORY",
            path(
                &config
                    .policy_directory
                    .unwrap_or_else(|| repo_root().join("policies/default")),
            ),
        ),
        ("BOWER_COLLECTOR_ID", "lambda-test".to_string()),
    ]);
    env.extend(destination);
    // The principal map belongs to Function URL deployments only.
    if config.ingress != "invoke" {
        env.insert("BOWER_LAMBDA_PRINCIPALS_FILE", path(&principals));
    }
    if config.single_trust_domain {
        env.insert("BOWER_SINGLE_TRUST_DOMAIN", "true".into());
    } else {
        env.insert("BOWER_PRODUCER_SCOPES_FILE", path(&scopes));
    }
    if let Some(producer) = config.invoke_producer {
        env.insert("BOWER_LAMBDA_INVOKE_PRODUCER", producer.into());
    }
    if let Some(profile) = &config.privacy_profile {
        env.insert("BOWER_PRIVACY_PROFILE", path(profile));
    }
    for (name, value) in &config.extra {
        env.insert(name, (*value).to_string());
    }
    let settings = LambdaSettings::from_environment(|name| env.get(name).cloned())?;
    Handler::new(&settings, config.hmac_key.as_deref(), sink.clone(), clock())
}

pub fn handler(sink: &FakeSink, config: Config) -> Handler<FakeSink> {
    try_handler(sink, config).unwrap()
}

fn path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `TestEvents.AuthenticationFailure` at [`NOW`].
pub fn authentication_failure(event_id: &str) -> Value {
    json!({
        "schemaVersion": "1.0.0", "eventId": event_id, "eventOriginalId": format!("source-{event_id}"),
        "timeGenerated": NOW, "eventCategory": "authentication",
        "eventType": "authentication_failure", "eventAction": "authentication.attempt",
        "eventResult": "failure", "eventOutcomeReason": "InvalidPassword",
        "application": {"name": "TestApplication", "environment": "test"},
        "actor": {"username": "test-user"},
        "source": {"ipAddress": "192.0.2.10"},
        "request": {"correlationId": "correlation-1"}
    })
}

/// A Function URL (payload 2.0) event signed by `caller` (`None`: AuthType NONE).
pub fn url_event(caller: Option<&str>, body: &str) -> String {
    let mut context = json!({
        "accountId": "123456789012", "apiId": "abcdefghij",
        "domainName": "abcdefghij.lambda-url.ap-southeast-2.on.aws",
        "http": {"method": "POST", "path": "/v1/events", "protocol": "HTTP/1.1",
                 "sourceIp": "198.51.100.7", "userAgent": "bower-forwarder"},
        "requestId": "r-1", "routeKey": "$default", "stage": "$default",
        "time": "24/Oct/2026:01:02:03 +0000", "timeEpoch": 1_792_803_723_000u64
    });
    if let Some(caller) = caller {
        context["authorizer"] = json!({"iam": {
            "accessKey": "ASIAEXAMPLE", "accountId": "123456789012", "callerId": "AROAEXAMPLE:s",
            "userArn": caller, "userId": "AROAEXAMPLE:s"
        }});
    }
    json!({
        "version": "2.0", "routeKey": "$default", "rawPath": "/v1/events", "rawQueryString": "",
        "headers": {"content-type": "application/json", "host": "abcdefghij.lambda-url.ap-southeast-2.on.aws"},
        "requestContext": context,
        "body": body,
        "isBase64Encoded": false
    })
    .to_string()
}

/// Returns `event` with the JSON pointer `pointer` set to `value`.
pub fn with(event: &str, pointer: &str, value: Value) -> String {
    let mut parsed: Value = serde_json::from_str(event).unwrap();
    *parsed.pointer_mut(pointer).unwrap() = value;
    parsed.to_string()
}
