//! Port of `SuppressionTests.cs` (processor and store), `SuppressionParityVectorTests.cs`
//! (pinned C# vectors) and `SourceSilenceTests.cs`.

mod support;

use std::sync::{Arc, Mutex};

use bower_contracts::envelope::DecisionAction;
use bower_contracts::time::{self, Timestamp};
use bower_contracts::{
    DurableEventStore, RedactionResult, SecurityEventEnvelope, SourceActivity, SuppressionRequest,
    SuppressionWindow, TelemetryPolicyEvaluator, json,
};
use bower_core::source_expectations::{self, SourceExpectationsError};
use bower_core::suppression::{SUMMARY_ACTION, create_request, create_summary};
use bower_core::{
    CollectorIdentity, PipelineTelemetry, SecurityEventProcessor, SuppressionCloseError,
    event_fingerprint,
};
use bower_persistence::SqliteEventStore;
use bower_policy::{DeterministicPolicyEvaluator, LoadedPolicy, load_yaml};
use serde_json::Value;
use support::MetadataRedactor;

const SUPPRESSING_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-AUTH-SUPPRESSED
  name: Authentication failures, suppressed
  version: 1.0.0
  owner: Security Operations
match:
  eventCategories:
    - authentication
  eventTypes:
    - authentication_failure
requirements:
  requiredFields:
    - timeGenerated
    - eventType
  atLeastOne:
    - actor.username
decision:
  action: accept
  minimumValueScore: 50
  neverSample: false
suppression:
  keyFields:
    - actor.username
    - source.ipAddress
  windowSeconds: 60
  allowPerWindow: 2";

const SUMMARY_POLICY: &str = "apiVersion: bower.security/v1
kind: TelemetryPolicy
metadata:
  id: BWR-POL-SUPPRESSION-SUMMARY
  name: Suppression summaries
  version: 1.0.0
  owner: Security Operations
match:
  eventTypes:
    - telemetry_aggregation_summary
requirements:
  requiredFields:
    - timeGenerated
    - eventType
    - application.name
    - target.id
decision:
  action: accept
  minimumValueScore: 50
  neverSample: true";

fn identity() -> CollectorIdentity {
    CollectorIdentity::new("collector-1", "0.1.0", "test", "sha256:configuration")
}

fn start() -> Timestamp {
    time::parse("2026-07-26T02:14:19+00:00").unwrap()
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<Timestamp>>);

impl FakeClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(start())))
    }
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
    fn advance(&self, seconds: i64) {
        let mut now = self.0.lock().unwrap();
        *now += chrono::Duration::seconds(seconds);
    }
    fn clock(&self) -> Arc<dyn bower_contracts::time::Clock> {
        let inner = self.0.clone();
        Arc::new(move || *inner.lock().unwrap())
    }
}

fn policies(yaml: &[&str]) -> Vec<LoadedPolicy> {
    yaml.iter()
        .enumerate()
        .map(|(index, text)| load_yaml(text, &format!("policy-{index}.yaml")).unwrap())
        .collect()
}

fn pass_through() -> MetadataRedactor {
    MetadataRedactor(RedactionResult {
        succeeded: true,
        privacy_detected: Some(Vec::new()),
        ..RedactionResult::default()
    })
}

fn processor(
    store: &Arc<SqliteEventStore>,
    clock: &FakeClock,
    loaded: Vec<LoadedPolicy>,
    telemetry: Option<&Arc<PipelineTelemetry>>,
) -> SecurityEventProcessor {
    let processor = SecurityEventProcessor::new(
        Arc::new(pass_through()),
        Arc::new(DeterministicPolicyEvaluator::new(loaded)),
        store.clone(),
        clock.clock(),
    );
    match telemetry {
        Some(telemetry) => processor.with_telemetry(telemetry.clone()),
        None => processor,
    }
}

fn store(directory: &tempfile::TempDir, clock: &FakeClock) -> Arc<SqliteEventStore> {
    let store = SqliteEventStore::new(
        directory.path().join("queue.db"),
        10 * 1024 * 1024,
        Some(clock.clock()),
    )
    .unwrap();
    store.initialize().unwrap();
    Arc::new(store)
}

/// `TestEvents.AuthenticationFailure(now, eventId, originalId)` with `actor.username`.
fn candidate(clock: &FakeClock, index: u32, username: &str) -> String {
    format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"event-{index}","eventOriginalId":"source-{index}","timeGenerated":"{}","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","eventOutcomeReason":"InvalidPassword","application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"{username}"}},"source":{{"ipAddress":"192.0.2.10"}},"request":{{"correlationId":"correlation-1"}}}}"#,
        time::format_json(&clock.now())
    )
}

#[test]
fn process_admits_allowance_then_counts_durably_and_summarises_once() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let loaded = policies(&[SUPPRESSING_POLICY, SUMMARY_POLICY]);
    let first_store = store(&directory, &clock);
    let telemetry = Arc::new(PipelineTelemetry::new(clock.clock()));
    let mut pipeline = processor(&first_store, &clock, loaded.clone(), Some(&telemetry));

    let mut results = Vec::new();
    for index in 1..=3 {
        results.push(
            pipeline
                .process(&candidate(&clock, index, "test-user"), &identity())
                .unwrap(),
        );
    }
    // Restart mid-window: counts continue from the queue file.
    let restarted = store(&directory, &clock);
    pipeline = processor(&restarted, &clock, loaded, Some(&telemetry));
    for index in 4..=5 {
        results.push(
            pipeline
                .process(&candidate(&clock, index, "test-user"), &identity())
                .unwrap(),
        );
    }
    results.push(
        pipeline
            .process(&candidate(&clock, 1, "test-user"), &identity())
            .unwrap(),
    );

    let queued: Vec<bool> = results.iter().map(|item| item.queued).collect();
    let suppressed: Vec<bool> = results.iter().map(|item| item.suppressed).collect();
    assert_eq!(queued, [true, true, false, false, false, false]);
    assert_eq!(suppressed, [false, false, true, true, true, false]);
    assert!(results[5].duplicate);
    assert!(
        results[2]
            .reasons
            .iter()
            .any(|reason| reason.starts_with("Suppressed:"))
    );
    assert_eq!(telemetry.snapshot().suppressed, 3);

    assert_eq!(pipeline.close_suppression_windows(&identity()).unwrap(), 0);
    clock.advance(120);
    let summaries = pipeline.close_suppression_windows(&identity()).unwrap();
    let repeated = pipeline.close_suppression_windows(&identity()).unwrap();
    let leased = restarted
        .lease(10, std::time::Duration::from_secs(60))
        .unwrap();
    let ledger = restarted.verify_ledger().unwrap();

    assert_eq!(summaries, 1);
    assert_eq!(repeated, 0);
    assert_eq!(leased.len(), 3);
    assert!(ledger.intact);
    let summary = leased
        .iter()
        .find(|item| item.event_id.starts_with("suppression-"))
        .unwrap();
    let root: Value = serde_json::from_str(&summary.payload).unwrap();
    assert_eq!(root["eventType"], "telemetry_aggregation_summary");
    assert_eq!(root["eventAction"], SUMMARY_ACTION);
    assert_eq!(root["security"]["decision"], "aggregate");
    assert_eq!(root["security"]["policyId"], "BWR-POL-SUPPRESSION-SUMMARY");
    assert_eq!(root["timeGenerated"], "2026-07-26T02:15:00+00:00");
    let attributes = &root["attributes"];
    assert_eq!(attributes["suppressedCount"].as_i64(), Some(3));
    assert_eq!(attributes["admittedCount"].as_i64(), Some(2));
    assert_eq!(attributes["windowStart"], "2026-07-26T02:14:00Z");
    assert_eq!(attributes["suppressionKey"]["actor.username"], "test-user");
    assert_eq!(
        attributes["suppressionKey"]["source.ipAddress"],
        "192.0.2.10"
    );
}

#[test]
fn process_keeps_separate_allowance_per_key_and_drops_quiet_windows() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = store(&directory, &clock);
    let pipeline = processor(
        &store,
        &clock,
        policies(&[SUPPRESSING_POLICY, SUMMARY_POLICY]),
        None,
    );
    for index in 1..=3 {
        pipeline
            .process(&candidate(&clock, index, "test-user"), &identity())
            .unwrap();
    }
    let other = pipeline
        .process(&candidate(&clock, 10, "other-user"), &identity())
        .unwrap();
    clock.advance(120);
    let summaries = pipeline.close_suppression_windows(&identity()).unwrap();
    let next_window = pipeline
        .process(&candidate(&clock, 11, "test-user"), &identity())
        .unwrap();

    assert!(other.queued);
    assert_eq!(summaries, 1);
    assert!(next_window.queued);
}

#[test]
fn close_summarises_a_window_recreated_after_the_clock_steps_back() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = store(&directory, &clock);
    let pipeline = processor(
        &store,
        &clock,
        policies(&[SUPPRESSING_POLICY, SUMMARY_POLICY]),
        None,
    );
    for index in 1..=3 {
        pipeline
            .process(&candidate(&clock, index, "test-user"), &identity())
            .unwrap();
    }
    clock.advance(120);
    let first = pipeline.close_suppression_windows(&identity()).unwrap();
    // NTP steps the clock back into the closed window; new events recreate it.
    clock.advance(-115);
    for index in 4..=7 {
        pipeline
            .process(&candidate(&clock, index, "test-user"), &identity())
            .unwrap();
    }
    clock.advance(120);
    let second = pipeline.close_suppression_windows(&identity()).unwrap();

    assert_eq!((first, second), (1, 1));
}

#[test]
fn close_keeps_windows_when_summary_is_not_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = store(&directory, &clock);
    let pipeline = processor(&store, &clock, policies(&[SUPPRESSING_POLICY]), None);
    for index in 1..=3 {
        pipeline
            .process(&candidate(&clock, index, "test-user"), &identity())
            .unwrap();
    }
    clock.advance(120);
    let error = pipeline.close_suppression_windows(&identity()).unwrap_err();
    assert!(matches!(error, SuppressionCloseError::Rejected { .. }));
    assert_eq!(
        error.to_string(),
        "Suppression summary was not accepted (BWR-POL-DEFAULT-DENY: Reject); windows stay open."
    );

    let fixed = processor(
        &store,
        &clock,
        policies(&[SUPPRESSING_POLICY, SUMMARY_POLICY]),
        None,
    );
    assert_eq!(fixed.close_suppression_windows(&identity()).unwrap(), 1);
}

#[test]
fn summary_id_and_fingerprint_are_stable_for_a_window() {
    let start = time::parse("2026-07-26T02:14:00+00:00").unwrap();
    let rule = SuppressionRequest {
        policy_id: "BWR-POL-X".into(),
        policy_version: "1.0.0".into(),
        policy_hash: "sha256:p".into(),
        key_hash: "abc".into(),
        key_fields: vec!["source.ipAddress".into()],
        key_values: vec!["192.0.2.1".into()],
        window_seconds: 60,
        allow_per_window: 2,
        event_category: "authentication".into(),
        event_type: "authentication_failure".into(),
        application: "App".into(),
        environment: "prod".into(),
        tenant_id: None,
    };
    let window = SuppressionWindow {
        rule,
        window_start: start,
        window_end: start + chrono::Duration::seconds(60),
        admitted: 2,
        suppressed: 5,
        first_suppressed_at: Some(start + chrono::Duration::seconds(3)),
        last_suppressed_at: Some(start + chrono::Duration::seconds(9)),
    };
    let first = create_summary(&window, &identity(), start + chrono::Duration::minutes(2));
    let retry = create_summary(&window, &identity(), start + chrono::Duration::minutes(9));
    assert_eq!(first.event_id, retry.event_id);
    assert!(first.event_id.starts_with("suppression-"));
    assert_eq!(first.event_id.len(), "suppression-".len() + 32);
    assert_eq!(event_fingerprint(&first), event_fingerprint(&retry));
}

/// Pinned C# outcomes (`SuppressionParityVectorTests`).
#[test]
fn suppression_vectors_match_csharp() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/suppression-vectors.json"),
    )
    .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let loaded: Vec<LoadedPolicy> = vectors["policies"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, yaml)| {
            load_yaml(yaml.as_str().unwrap(), &format!("policy-{index}.yaml")).unwrap()
        })
        .collect();
    let evaluator = DeterministicPolicyEvaluator::new(loaded);
    let window_seconds = vectors["windowSeconds"].as_i64().unwrap();

    let mut requests = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        let envelope: SecurityEventEnvelope =
            json::from_str(case["event"].as_str().unwrap()).unwrap();
        let decision = evaluator.evaluate(&envelope);
        let request = create_request(&envelope, &decision, decision.suppression.as_ref().unwrap());
        let received = time::parse(case["receivedAt"].as_str().unwrap()).unwrap();
        let expected_values: Vec<&str> = case["keyValues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(request.key_values, expected_values);
        assert_eq!(request.key_hash, case["keyHash"].as_str().unwrap());
        assert_eq!(
            request.window_seconds,
            i32::try_from(window_seconds).unwrap()
        );
        assert_eq!(
            bower_persistence::suppression_window_start(&received, request.window_seconds),
            case["windowStart"].as_i64().unwrap()
        );
        requests.push(request);
    }

    let collector = &vectors["collector"];
    let collector = CollectorIdentity::new(
        collector["id"].as_str().unwrap(),
        collector["version"].as_str().unwrap(),
        collector["sourceAdapter"].as_str().unwrap(),
        collector["configurationHash"].as_str().unwrap(),
    );
    let now = time::parse(vectors["now"].as_str().unwrap()).unwrap();
    let start = chrono::DateTime::from_timestamp(vectors["windowStart"].as_i64().unwrap(), 0)
        .unwrap()
        .fixed_offset();
    let rule = requests[1].clone();
    for summary in vectors["summaries"].as_array().unwrap() {
        let parse_time = |value: &Value| value.as_str().map(|text| time::parse(text).unwrap());
        let window = SuppressionWindow {
            rule: SuppressionRequest {
                tenant_id: summary["tenantId"].as_str().map(str::to_owned),
                key_values: summary["keyValues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect(),
                ..rule.clone()
            },
            window_start: start,
            window_end: start + chrono::Duration::seconds(window_seconds),
            admitted: summary["admitted"].as_i64().unwrap(),
            suppressed: summary["suppressed"].as_i64().unwrap(),
            first_suppressed_at: parse_time(&summary["firstSuppressedAt"]),
            last_suppressed_at: parse_time(&summary["lastSuppressedAt"]),
        };
        let mut arranged = create_summary(&window, &collector, now);
        let decision = evaluator.evaluate(&arranged);
        assert_eq!(
            decision.action.pascal_name(),
            summary["decision"].as_str().unwrap()
        );
        arranged.security = Some(bower_contracts::SecurityDecisionContext {
            policy_id: decision.policy_id,
            policy_version: decision.policy_version,
            value_score: decision.score,
            decision: DecisionAction::Aggregate,
            classification_reasons: decision.reasons,
            policy_hash: decision.policy_hash,
        });
        assert_eq!(arranged.event_id, summary["eventId"].as_str().unwrap());
        assert_eq!(
            event_fingerprint(&arranged),
            summary["fingerprint"].as_str().unwrap()
        );
        assert_eq!(
            json::to_string(&arranged).unwrap(),
            summary["payload"].as_str().unwrap()
        );
    }
}

const EXPECTATIONS: &str = r#"{
  "apiVersion": "bower.security/v1",
  "kind": "SourceExpectations",
  "sources": [
    { "application": "FinanceApi", "environment": "production", "maximumSilenceMinutes": 15 },
    { "application": "Portal", "environment": "production", "maximumSilenceMinutes": 60 },
    { "application": "Payroll", "environment": "production", "maximumSilenceMinutes": 30 }
  ]
}"#;

#[test]
fn evaluate_reports_active_silent_and_never_seen_sources() {
    let expectations = source_expectations::parse(EXPECTATIONS).unwrap();
    let started = start();
    let now = started + chrono::Duration::minutes(45);
    let activity = [
        SourceActivity {
            application: "FinanceApi".into(),
            environment: "production".into(),
            last_seen_at: now - chrono::Duration::minutes(20),
            event_count: 10,
        },
        SourceActivity {
            application: "Portal".into(),
            environment: "production".into(),
            last_seen_at: now - chrono::Duration::minutes(20),
            event_count: 4,
        },
    ];
    let statuses = source_expectations::evaluate(&expectations, &activity, started, now);
    let early = source_expectations::evaluate(
        &expectations,
        &[],
        started,
        started + chrono::Duration::minutes(10),
    );

    let states: Vec<&str> = statuses.iter().map(|item| item.state.as_str()).collect();
    assert_eq!(states, ["silent", "active", "never-seen"]);
    assert_eq!(statuses[0].silent_seconds, 1200);
    assert_eq!(statuses[0].allowed_silence_seconds, 900);
    assert!(early.iter().all(|item| item.is_active()));
}

#[test]
fn parse_rejects_invalid_expectations() {
    let cases = [
        (
            r#""kind": "SourceExpectations""#,
            r#""kind": "TelemetryPolicy""#,
            Some(
                "Source expectations need apiVersion bower.security/v1 and kind SourceExpectations.",
            ),
        ),
        (
            r#""maximumSilenceMinutes": 15"#,
            r#""maximumSilenceMinutes": 0"#,
            Some("maximumSilenceMinutes must be between 1 and 10080."),
        ),
        (
            r#""maximumSilenceMinutes": 15"#,
            r#""maximumSilenceMinutes": 20000"#,
            Some("maximumSilenceMinutes must be between 1 and 10080."),
        ),
        (
            r#""application": "Portal""#,
            r#""application": "FinanceApi""#,
            Some("Expected source FinanceApi/production is listed more than once."),
        ),
        (
            r#""application": "Portal""#,
            r#""application": " ""#,
            Some("Each expected source needs an application and an environment."),
        ),
        // System.Text.Json failures: same rejection, this port's detail text.
        (
            r#""kind": "SourceExpectations","#,
            r#""kind": "SourceExpectations", "script": "x","#,
            None,
        ),
        (
            r#""maximumSilenceMinutes": 15"#,
            r#""maximumSilenceMinutes": "15""#,
            None,
        ),
        (
            r#""maximumSilenceMinutes": 15"#,
            r#""maximumSilenceMinutes": 15.0"#,
            None,
        ),
        (r#""application": "Portal""#, r#""application": null"#, None),
        (r#""apiVersion": "bower.security/v1","#, "", None),
    ];
    for (original, replacement, message) in cases {
        let json = EXPECTATIONS.replace(original, replacement);
        assert_ne!(json, EXPECTATIONS);
        let error = source_expectations::parse(&json).unwrap_err();
        assert!(matches!(error, SourceExpectationsError::InvalidData(_)));
        match message {
            Some(message) => assert_eq!(error.to_string(), message),
            None => assert!(
                error
                    .to_string()
                    .starts_with("Source expectations are invalid: "),
                "{error}"
            ),
        }
    }
    // Web defaults: property names match case-insensitively; a null item is a blank source.
    assert!(source_expectations::parse(&EXPECTATIONS.replace("\"kind\"", "\"KIND\"")).is_ok());
    assert_eq!(
        source_expectations::parse(
            r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[null]}"#
        )
        .unwrap_err()
        .to_string(),
        "Each expected source needs an application and an environment."
    );
    assert_eq!(
        source_expectations::parse(
            r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[]}"#
        )
        .unwrap_err()
        .to_string(),
        "Source expectations must list 1–1000 sources."
    );
}

#[test]
fn activity_is_tracked_from_accepted_events_and_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new();
    let store = store(&directory, &clock);
    let telemetry = Arc::new(PipelineTelemetry::new(clock.clock()));
    let auth = SUPPRESSING_POLICY[..SUPPRESSING_POLICY.find("suppression:").unwrap()].to_owned();
    let pipeline = processor(&store, &clock, policies(&[&auth]), Some(&telemetry));
    let accepted = candidate(&clock, 1, "test-user");
    let rejected =
        candidate(&clock, 2, "test-user").replace("authentication_failure", "unknown_type");
    let identity = CollectorIdentity::new("c", "1", "test", "h");

    pipeline.process(&accepted, &identity).unwrap();
    clock.advance(180);
    pipeline.process(&accepted, &identity).unwrap();
    pipeline.process(&rejected, &identity).unwrap();
    // C# runs the real redactor, which rejects a non-object: redaction stage.
    let failing = SecurityEventProcessor::new(
        Arc::new(support::FixedRedactor(RedactionResult::failed(
            "schema-invalid",
        ))),
        Arc::new(DeterministicPolicyEvaluator::new(policies(&[&auth]))),
        store.clone(),
        clock.clock(),
    )
    .with_telemetry(telemetry.clone());
    failing.process("[]", &identity).unwrap();
    let changed = telemetry.take_changed_sources();
    store.upsert_source_activity(&changed).unwrap();
    store
        .upsert_source_activity(&[SourceActivity {
            application: "TestApplication".into(),
            environment: "test".into(),
            last_seen_at: start(),
            event_count: 1,
        }])
        .unwrap();

    let restarted = PipelineTelemetry::new(clock.clock());
    restarted.load(store.get_source_activity().unwrap());
    let metrics = telemetry.snapshot();

    let sources = restarted.sources();
    assert_eq!(sources.len(), 1);
    assert_eq!(
        (
            sources[0].application.as_str(),
            sources[0].environment.as_str(),
            sources[0].event_count
        ),
        ("TestApplication", "test", 2)
    );
    assert_eq!(
        sources[0].last_seen_at,
        start() + chrono::Duration::minutes(3)
    );
    assert!(telemetry.take_changed_sources().is_empty());
    assert_eq!(
        (metrics.events_in, metrics.events_queued, metrics.duplicates),
        (4, 1, 1)
    );
    assert!(metrics.rows.iter().any(|row| row.stage == "policy"
        && row.policy_id == "BWR-POL-DEFAULT-DENY"
        && row.action == "reject"));
    assert!(
        metrics.rows.iter().any(|row| row.stage == "redaction"
            && row.policy_id == "-"
            && row.action == "quarantine")
    );
    assert!(metrics.bytes_queued > 0);
}

#[test]
fn capture_store_never_suppresses() {
    // Serverless and `bower policy test` buffers stage a suppressing policy's event as
    // accepted (C# `RequestEventBuffer`).
    let clock = FakeClock::new();
    let store = Arc::new(bower_core::capture::CaptureStore::default());
    let pipeline = SecurityEventProcessor::new(
        Arc::new(pass_through()),
        Arc::new(DeterministicPolicyEvaluator::new(policies(&[
            SUPPRESSING_POLICY,
            SUMMARY_POLICY,
        ]))),
        store.clone(),
        clock.clock(),
    );
    for index in 1..=4 {
        let result = pipeline
            .process(&candidate(&clock, index, "test-user"), &identity())
            .unwrap();
        assert!(result.queued && !result.suppressed);
    }
    assert!(pipeline.close_suppression_windows(&identity()).is_err());
}
