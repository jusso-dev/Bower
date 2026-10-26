//! `bower policy diff`, `bower archive create|verify|replay` and `bower sources check`
//! (C# `PolicyCommands.DiffAsync`, `ArchiveCommands`, `SourceCommands`, and
//! `PolicyDiffTests`).

mod common;

use std::path::Path;

use bower_contracts::{
    DurableEventStore, QueueState, QueuedEvent, SourceActivity, SourceMonitoring,
};
use bower_persistence::SqliteEventStore;
use common::{bower, one_shot_server};
use serde_json::Value;

const AUTH_POLICY: &str = "apiVersion: bower.security/v1
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
";

fn now() -> String {
    bower_contracts::time::format_json(&bower_contracts::time::now())
}

fn event(id: &str, kind: &str, request: &str) -> String {
    format!(
        r#"{{"schemaVersion":"1.0.0","eventId":"{id}","eventOriginalId":"source-{id}","timeGenerated":"{}","eventCategory":"authentication","eventType":"{kind}","eventAction":"authentication.attempt","eventResult":"failure","eventOutcomeReason":"InvalidPassword","application":{{"name":"TestApplication","environment":"test"}},"actor":{{"username":"test-user"}},"source":{{"ipAddress":"192.0.2.10"}},"request":{request}}}"#,
        now()
    )
}

fn write(path: &Path, text: &str) -> String {
    std::fs::write(path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

#[test]
fn policy_diff_lists_only_events_whose_decision_or_policy_changes() {
    let directory = tempfile::tempdir().unwrap();
    let baseline = directory.path().join("baseline");
    let candidate = directory.path().join("candidate");
    std::fs::create_dir_all(&baseline).unwrap();
    std::fs::create_dir_all(&candidate).unwrap();
    std::fs::write(baseline.join("auth.yaml"), AUTH_POLICY).unwrap();
    std::fs::write(
        candidate.join("auth.yaml"),
        AUTH_POLICY
            .replace("version: 1.0.0", "version: 1.1.0")
            .replace(
                "    - timeGenerated\n",
                "    - timeGenerated\n    - request.traceId\n",
            ),
    )
    .unwrap();
    let plain = write(
        &directory.path().join("plain.json"),
        &event(
            "event-1",
            "authentication_failure",
            r#"{"correlationId":"correlation-1"}"#,
        ),
    );
    let traced = write(
        &directory.path().join("traced.json"),
        &event(
            "event-2",
            "authentication_failure",
            r#"{"correlationId":"c","traceId":"t"}"#,
        ),
    );
    let unknown = write(
        &directory.path().join("unknown.json"),
        &event(
            "event-3",
            "page_view",
            r#"{"correlationId":"correlation-1"}"#,
        ),
    );
    let (baseline, candidate) = (baseline.to_str().unwrap(), candidate.to_str().unwrap());

    let same = bower(&[
        "policy",
        "diff",
        "--baseline",
        baseline,
        "--candidate",
        baseline,
        &plain,
    ]);
    let diff = bower(&[
        "policy",
        "diff",
        "--baseline",
        baseline,
        "--candidate",
        candidate,
        &plain,
        &traced,
        &unknown,
    ]);
    let failing = bower(&[
        "policy",
        "diff",
        &plain,
        "--baseline",
        baseline,
        "--candidate",
        candidate,
        "--fail-on-change",
    ]);
    // --fail-on-change takes no value, so the file after it is still an event.
    let flag_first = bower(&[
        "policy",
        "diff",
        "--fail-on-change",
        &plain,
        "--baseline",
        baseline,
        "--candidate",
        candidate,
    ]);
    assert_eq!(flag_first.code, 3, "{}", flag_first.stderr);
    let flag_first: Value = serde_json::from_str(&flag_first.stdout).unwrap();
    assert_eq!(flag_first["events"].as_i64(), Some(1));
    let none = bower(&["policy", "diff", "--baseline", baseline]);
    let missing = bower(&["policy", "diff", &plain, "--candidate", candidate]);

    assert_eq!(same.code, 0, "{}", same.stderr);
    let same: Value = serde_json::from_str(&same.stdout).unwrap();
    assert_eq!(same["changed"].as_i64(), Some(0));
    assert_eq!(diff.code, 0, "{}", diff.stderr);
    let output: Value = serde_json::from_str(&diff.stdout).unwrap();
    assert_eq!(output["events"].as_i64(), Some(3));
    assert_eq!(output["changed"].as_i64(), Some(1));
    let change = &output["changes"][0];
    assert_eq!(change["file"], plain.as_str());
    assert_eq!(change["eventId"], "event-1");
    assert_eq!(change["baseline"]["decision"], "accept");
    assert_eq!(change["baseline"]["policyId"], "BWR-POL-AUTH-SUPPRESSED");
    assert_eq!(change["candidate"]["decision"], "quarantine");
    assert_ne!(output["baselineBundleHash"], output["candidateBundleHash"]);
    assert!(
        diff.stdout.starts_with("{\n  \"baselineBundleHash\": "),
        "{}",
        diff.stdout
    );
    assert!(!diff.stdout.contains("test-user"));
    assert_eq!(failing.code, 3, "{}", failing.stderr);
    assert_eq!(none.code, 1);
    assert_eq!(
        none.stderr,
        "Provide 1-1000 event files: bower policy diff --baseline DIR --candidate DIR EVENT.json [EVENT.json ...].\n"
    );
    assert_eq!(
        (missing.code, missing.stderr.as_str()),
        (1, "--baseline is required.\n")
    );
}

fn seeded_queue(path: &Path) {
    let store = SqliteEventStore::new(path, 10 * 1024 * 1024, None).unwrap();
    store.initialize().unwrap();
    for (index, kind) in [
        "authentication_failure",
        "account_lockout",
        "authentication_failure",
    ]
    .iter()
    .enumerate()
    {
        let id = format!("e{index}");
        let payload = format!(
            r#"{{"schemaVersion":"1.0.0","eventId":"{id}","timeGenerated":"2026-05-01T10:2{index}:00+00:00","eventType":"{kind}","labels":{{"team":"a"}},"attributes":{{"secret":"payload-{index}"}}}}"#
        );
        store
            .enqueue(&QueuedEvent {
                event_id: id.clone(),
                fingerprint: format!("fp-{id}"),
                payload,
                received_at: bower_contracts::time::parse("2026-05-01T10:20:30+00:00").unwrap(),
                state: QueueState::Queued,
                delivery_attempts: 0,
                lease_token: None,
                suppression: None,
            })
            .unwrap();
    }
}

#[test]
fn archive_create_verify_and_dry_run_replay() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("queue.db");
    seeded_queue(&database);
    let (database, archive) = (
        database.to_str().unwrap().to_owned(),
        directory
            .path()
            .join("archive")
            .to_str()
            .unwrap()
            .to_owned(),
    );

    let created = bower(&[
        "archive",
        "create",
        "--archive",
        &archive,
        "--database",
        &database,
        "--collector-id",
        "c1",
    ]);
    let idle = bower(&[
        "archive",
        "create",
        "--archive",
        &archive,
        "--database",
        &database,
    ]);
    let head = SqliteEventStore::new(&database, 10 * 1024 * 1024, None)
        .unwrap()
        .ledger_head()
        .unwrap();
    let anchor = format!("{}:{}", head.sequence, head.hash);
    let verified = bower(&[
        "archive",
        "verify",
        "--archive",
        &archive,
        "--anchor",
        &anchor,
    ]);
    let wrong = format!("{}:{}", head.sequence, "0".repeat(64));
    let mismatch = bower(&[
        "archive",
        "verify",
        "--archive",
        &archive,
        "--anchor",
        &wrong,
    ]);
    let bad_anchor = bower(&["archive", "verify", "--archive", &archive, "--anchor", "x"]);
    let dry = bower(&[
        "archive",
        "replay",
        "--archive",
        &archive,
        "--collector-url",
        "http://127.0.0.1:9",
        "--event-type",
        "authentication_failure",
        "--from",
        "2026-05-01T10:21:00Z",
        "--dry-run",
    ]);
    let empty = bower(&[
        "archive",
        "verify",
        "--archive",
        directory.path().join("none").to_str().unwrap(),
    ]);
    let no_queue = bower(&[
        "archive",
        "create",
        "--archive",
        &archive,
        "--database",
        "missing.db",
    ]);

    assert_eq!(created.code, 0, "{}", created.stderr);
    assert_eq!(
        created.stdout,
        format!(
            "{{\n  \"segments\": 1,\n  \"events\": 3,\n  \"headSequence\": 3,\n  \"headHash\": \"{}\"\n}}\n",
            head.hash
        )
    );
    assert!(idle.stdout.contains("\"segments\": 0"), "{}", idle.stdout);
    assert_eq!(verified.code, 0, "{}", verified.stderr);
    assert_eq!(
        verified.stdout,
        format!(
            "{{\n  \"intact\": true,\n  \"segments\": 1,\n  \"verifiedEvents\": 3,\n  \"firstSequence\": 1,\n  \"headSequence\": 3,\n  \"headHash\": \"{}\",\n  \"anchorVerified\": true,\n  \"breakSegment\": null,\n  \"breakReason\": null\n}}\n",
            head.hash
        )
    );
    assert_eq!(mismatch.code, 3);
    assert!(
        mismatch
            .stdout
            .contains("\"breakReason\": \"anchor-mismatch\"")
    );
    assert_eq!(
        (bad_anchor.code, bad_anchor.stderr.as_str()),
        (
            1,
            "--anchor must be SEQUENCE:HASH (64 lower-case hex digits).\n"
        )
    );
    assert_eq!(dry.code, 0, "{}", dry.stderr);
    assert_eq!(
        dry.stdout,
        "{\n  \"selected\": 1,\n  \"dryRun\": true,\n  \"responses\": {}\n}\n"
    );
    // Same strict ISO 8601 parsing as `policy diff --at` (C# `CliOptions.Timestamp`).
    for (option, value) in [
        ("--from", "2026-05-01"),
        ("--to", "05/01/2026"),
        ("--from", "2026-05-01T10:21:00"),
        ("--to", "2026-05-01T10:21:00.123456789Z"),
    ] {
        let refused = bower(&[
            "archive",
            "replay",
            "--archive",
            &archive,
            "--collector-url",
            "http://127.0.0.1:9",
            option,
            value,
            "--dry-run",
        ]);
        assert_eq!(
            (refused.code, refused.stderr),
            (
                1,
                format!(
                    "{option} must be an ISO 8601 timestamp with Z or an offset: YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM).\n"
                )
            ),
            "{option} {value}"
        );
    }
    assert_eq!(empty.code, 3);
    assert!(empty.stdout.contains("\"breakReason\": \"archive-empty\""));
    assert_eq!(no_queue.code, 1);
    assert_eq!(no_queue.stderr, "Queue database not found: missing.db\n");
}

#[test]
fn archive_replay_posts_labelled_events_and_stops_on_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("queue.db");
    seeded_queue(&database);
    let (database, archive) = (
        database.to_str().unwrap().to_owned(),
        directory
            .path()
            .join("archive")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    assert_eq!(
        bower(&[
            "archive",
            "create",
            "--archive",
            &archive,
            "--database",
            &database
        ])
        .code,
        0
    );

    let (address, server) = one_shot_server("401 Unauthorized", "{}");
    let run = bower(&[
        "archive",
        "replay",
        "--archive",
        &archive,
        "--collector-url",
        &address,
    ]);
    let request = server.join().unwrap();

    assert_eq!(run.code, 2, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "{\n  \"selected\": 1,\n  \"dryRun\": false,\n  \"responses\": {\n    \"401\": 1\n  }\n}\n"
    );
    assert!(request.starts_with("POST /v1/events "), "{request}");
    assert!(
        request.contains(r#""labels":{"team":"a","bowerReplay":"archive"}"#),
        "{request}"
    );
    assert!(!run.stdout.contains("payload-"));

    let unreachable = bower(&[
        "archive",
        "replay",
        "--archive",
        &archive,
        "--collector-url",
        "http://127.0.0.1:9",
    ]);
    assert_eq!(unreachable.code, 2);
    assert!(
        unreachable.stdout.contains("\"unreachable\": 1"),
        "{}",
        unreachable.stdout
    );
}

#[test]
fn sources_check_reads_collector_monitoring_starts_without_writing_them() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("queue.db");
    let store = SqliteEventStore::new(&database, 10 * 1024 * 1024, None).unwrap();
    store.initialize().unwrap();
    let started = bower_contracts::time::now();
    store
        .start_source_monitoring(&[SourceMonitoring {
            application: "Payroll".into(),
            environment: "production".into(),
            monitoring_since: started,
        }])
        .unwrap();
    let both = write(
        &directory.path().join("both.json"),
        r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
  {"application":"Payroll","environment":"production","maximumSilenceMinutes":30},
  {"application":"Portal","environment":"production","maximumSilenceMinutes":30}]}"#,
    );
    let payroll = write(
        &directory.path().join("payroll.json"),
        r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
  {"application":"Payroll","environment":"production","maximumSilenceMinutes":30}]}"#,
    );
    let database = database.to_str().unwrap();
    let check = |expectations: &str| {
        bower(&[
            "sources",
            "check",
            "--expectations",
            expectations,
            "--database",
            database,
        ])
    };

    let checked_both = check(&both);
    let checked_payroll = check(&payroll);

    // The collector's pending source is pending here too; one it never monitored has no grace.
    assert_eq!(checked_both.code, 3, "{}", checked_both.stderr);
    let output: Value = serde_json::from_str(&checked_both.stdout).unwrap();
    assert_eq!(output["healthy"], false);
    assert_eq!(output["sources"][0]["state"], "pending");
    assert_eq!(output["sources"][1]["state"], "never-seen");
    assert_eq!(checked_payroll.code, 0, "{}", checked_payroll.stderr);
    let output: Value = serde_json::from_str(&checked_payroll.stdout).unwrap();
    assert_eq!(output["healthy"], true);
    let stored = store.get_source_monitoring().unwrap();
    assert_eq!(
        stored
            .iter()
            .map(|item| (item.application.as_str(), item.monitoring_since))
            .collect::<Vec<_>>(),
        [("Payroll", started)]
    );
}

#[test]
fn sources_check_reports_silent_and_never_seen_sources() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("queue.db");
    let store = SqliteEventStore::new(&database, 10 * 1024 * 1024, None).unwrap();
    store.initialize().unwrap();
    store
        .upsert_source_activity(&[SourceActivity {
            application: "FinanceApi".into(),
            environment: "production".into(),
            last_seen_at: bower_contracts::time::now(),
            event_count: 3,
        }])
        .unwrap();
    let expectations = write(
        &directory.path().join("sources.json"),
        r#"{"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
  {"application":"FinanceApi","environment":"production","maximumSilenceMinutes":15},
  {"application":"Payroll","environment":"production","maximumSilenceMinutes":30}]}"#,
    );
    let database = database.to_str().unwrap();

    let run = bower(&[
        "sources",
        "check",
        "--expectations",
        &expectations,
        "--database",
        database,
    ]);
    let missing = bower(&[
        "sources",
        "check",
        "--expectations",
        "nope.json",
        "--database",
        database,
    ]);

    assert_eq!(run.code, 3, "{}", run.stderr);
    let output: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(output["healthy"], false);
    assert_eq!(output["sources"][0]["state"], "active");
    assert!(output["sources"][0]["silentSeconds"].is_i64());
    assert_eq!(output["sources"][1]["state"], "never-seen");
    assert!(output["sources"][1]["lastSeenAt"].is_null());
    assert!(output["sources"][1]["silentSeconds"].is_null());
    assert_eq!(
        output["sources"][1]["allowedSilenceSeconds"].as_i64(),
        Some(1800)
    );
    assert_eq!(
        (missing.code, missing.stderr.as_str()),
        (1, "Source expectations file does not exist.\n")
    );
}

#[test]
fn help_lists_new_commands() {
    let run = bower(&["--help"]);
    assert!(run.stdout.contains(
        "  bower policy diff --baseline DIR --candidate DIR EVENT.json... [--fail-on-change]\n"
    ));
    assert!(
        run.stdout
            .contains("  bower sources check --expectations FILE [--database FILE]\n")
    );
}
