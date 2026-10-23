//! End-to-end tests of the `bower` binary: command surface, exit codes and
//! output formats of the C# CLI.

mod common;

use std::path::Path;

use bower_contracts::{DurableEventStore, QueueState, QueuedEvent};
use bower_persistence::SqliteEventStore;
use common::{bower, bower_in, one_shot_server};

#[test]
fn help_matches_csharp_text_for_all_entry_forms() {
    for args in [&[][..], &["--help"][..], &["help"][..]] {
        let run = bower(args);
        assert_eq!(run.code, 0, "{args:?}");
        assert!(
            run.stdout
                .starts_with("Bower security telemetry\n\nCommands:\n  bower validate"),
            "{args:?}"
        );
        assert!(run.stdout.ends_with("  bower version\n"));
    }
}

#[test]
fn version_prints_csharp_version() {
    let run = bower(&["version"]);
    assert_eq!((run.code, run.stdout.as_str()), (0, "bower 0.1.0\n"));
}

#[test]
fn unknown_commands_fail_with_csharp_message() {
    for args in [
        &["bogus"][..],
        &["queue"][..],
        &["pipeline", "nope"][..],
        &["pack"][..],
    ] {
        let run = bower(args);
        assert_eq!(run.code, 1, "{args:?}");
        assert_eq!(
            run.stderr, "Unknown command. Run 'bower --help'.\n",
            "{args:?}"
        );
        assert!(run.stdout.is_empty());
    }
}

#[test]
fn every_subcommand_has_help() {
    let commands: &[&[&str]] = &[
        &["version"],
        &["validate"],
        &["pipeline"],
        &["pipeline", "validate"],
        &["pipeline", "template"],
        &["queue"],
        &["queue", "inspect"],
        &["queue", "dead-letters"],
        &["queue", "replay"],
        &["queue", "verify"],
        &["test", "emit"],
        &["token", "generate"],
        &["doctor"],
        &["dcr", "generate"],
        &["dcr", "diff"],
        &["keys", "generate"],
        &["pack", "build"],
        &["pack", "verify"],
        &["pack", "inspect"],
        &["pack", "test"],
        &["pack", "diff"],
        &["evidence", "run"],
        &["evidence", "verify"],
        &["developer", "init"],
    ];
    for command in commands {
        let mut args = command.to_vec();
        args.push("--help");
        let run = bower(&args);
        assert_eq!(run.code, 0, "{args:?}: {}", run.stderr);
        assert!(run.stdout.contains("Usage: bower"), "{args:?}");
    }
}

#[test]
fn token_generate_prints_token_and_tokens_file_line() {
    let run = bower(&["token", "generate"]);
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout.trim_end().len(), 43);
    assert!(run.stderr.is_empty());

    let run = bower(&["token", "generate", "--id", "billing-api"]);
    assert_eq!(run.code, 0);
    let token = run.stdout.trim_end();
    assert_eq!(token.len(), 43);
    assert!(
        run.stderr
            .contains("Give this token to producer 'billing-api' (shown once):")
    );
    let line = run.stderr.lines().last().unwrap();
    assert!(line.starts_with("billing-api sha256:"));
    assert!(!run.stderr.contains(token), "token must only go to stdout");
}

#[test]
fn developer_init_scaffolds_dotnet_repo_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let path = root.to_str().unwrap();

    let run = bower(&["developer", "init", "--path", path]);
    assert_eq!(run.code, 1);
    assert_eq!(
        run.stderr,
        "No .NET project detected. This release supports .NET developer init.\n"
    );

    let missing = root.join("missing");
    let run = bower(&["developer", "init", "--path", missing.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    assert!(run.stderr.starts_with("Target directory does not exist: "));

    std::fs::create_dir_all(root.join("src/App")).unwrap();
    std::fs::write(root.join("src/App/App.csproj"), "<Project />").unwrap();
    std::fs::write(root.join("AGENTS.md"), "# Existing\n\nKeep me.\n").unwrap();
    std::fs::write(root.join("bower.yaml"), "custom: true\n").unwrap();

    let run = bower(&["developer", "init", "--path", path]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let full = std::path::absolute(root).unwrap();
    assert_eq!(
        run.stdout,
        format!(
            "{{\n  \"initialized\": true,\n  \"path\": \"{}\",\n  \"framework\": \"dotnet\",\n  \"note\": \"Package references are documented but not changed automatically in 0.1.0.\"\n}}\n",
            full.display()
        )
    );
    assert_eq!(
        std::fs::read_to_string(root.join("bower.yaml")).unwrap(),
        "custom: true\n"
    );
    assert!(
        std::fs::read_to_string(root.join("telemetry-catalogue.yaml"))
            .unwrap()
            .ends_with("events: []")
    );
    assert!(root.join("docs/security-telemetry.md").is_file());
    let agents = std::fs::read_to_string(root.join("AGENTS.md")).unwrap();
    assert!(agents.starts_with(
        "# Existing\n\nKeep me.\n\n<!-- bower:security-telemetry:start -->\n## Bower"
    ));

    let run = bower(&["developer", "init", "--path", path]);
    assert_eq!(run.code, 0);
    assert_eq!(
        std::fs::read_to_string(root.join("AGENTS.md")).unwrap(),
        agents
    );
}

fn seeded_queue(path: &Path) {
    let store = SqliteEventStore::new(path, 10 * 1024 * 1024, None).unwrap();
    store.initialize().unwrap();
    for (index, id) in ["e1", "e2", "e3"].iter().enumerate() {
        store
            .enqueue(&QueuedEvent {
                lease_token: None,
                event_id: (*id).to_owned(),
                fingerprint: format!("fp-{index}"),
                payload: format!("{{\"secret\":\"payload-{index}\"}}"),
                received_at: bower_contracts::time::parse("2026-05-01T10:20:30+00:00").unwrap(),
                state: QueueState::Queued,
                delivery_attempts: 0,
            })
            .unwrap();
    }
    let leases = store.lease(10, std::time::Duration::from_secs(60)).unwrap();
    store
        .mark_dead_lettered(
            "e1",
            "http-400:bad-row",
            leases
                .iter()
                .find(|v| v.event_id == "e1")
                .unwrap()
                .lease_token
                .as_deref(),
        )
        .unwrap();
    store
        .mark_dead_lettered(
            "e2",
            "dcr-mismatch",
            leases
                .iter()
                .find(|v| v.event_id == "e2")
                .unwrap()
                .lease_token
                .as_deref(),
        )
        .unwrap();
}

#[test]
fn queue_commands_report_metadata_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bower.db");
    seeded_queue(&db);
    let db = db.to_str().unwrap();

    let run = bower(&["queue", "inspect", "--database", db]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.starts_with("{\n  \"Queued\": 0,\n  \"Retrying\": 0,\n  \"Uploading\": 1,\n  \"Delivered\": 0,\n  \"DeadLettered\": 2,"));
    assert!(
        run.stdout
            .contains("\"OldestUndelivered\": \"2026-05-01T10:20:30+00:00\"")
    );

    let run = bower(&["queue", "dead-letters", "--database", db]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("\"EventId\": \"e1\""));
    assert!(run.stdout.contains("\"FailureCode\": \"http-400:bad-row\""));
    assert!(
        run.stdout
            .contains("\"ReceivedAt\": \"2026-05-01T10:20:30+00:00\"")
    );
    assert!(
        !run.stdout.contains("payload-"),
        "dead letters must not print payloads"
    );

    let run = bower(&["queue", "replay", "--database", db]);
    assert_eq!(
        (run.code, run.stderr.as_str()),
        (
            1,
            "Choose what to replay with --code PREFIX or --event ID.\n"
        )
    );

    let run = bower(&["queue", "replay", "--database", db, "--code", "http-400"]);
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (0, "Returned 1 dead-lettered event(s) to the queue.\n")
    );
    let run = bower(&[
        "queue",
        "replay",
        "--database",
        db,
        "--event",
        "e2",
        "--event",
        "e9",
    ]);
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (0, "Returned 1 dead-lettered event(s) to the queue.\n")
    );

    let run = bower(&["queue", "verify", "--database", db]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.starts_with("Ledger entries: 3; head 3:"));
    assert!(run.stdout.ends_with("Ledger intact.\n"));

    let run = bower(&[
        "queue",
        "verify",
        "--database",
        db,
        "--expect-head",
        "9:abc",
    ]);
    assert_eq!(run.code, 1);
    assert!(run.stdout.contains(
        "  head-regression    The ledger is behind or differs from the witnessed head.\n"
    ));
    assert!(run.stdout.ends_with("Ledger verification FAILED.\n"));
}

#[test]
fn queue_commands_require_existing_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("absent.db");
    let db = db.to_str().unwrap();
    for sub in ["dead-letters", "verify"] {
        let run = bower(&["queue", sub, "--database", db]);
        assert_eq!(run.code, 1);
        assert_eq!(run.stderr, format!("Queue database not found: {db}\n"));
    }
    let run = bower(&["queue", "dead-letters", "--database", db, "--max", "x"]);
    assert_eq!(run.code, 1);

    // inspect creates the database, like the C# CLI.
    let run = bower(&["queue", "inspect", "--database", db]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("\"OldestUndelivered\": null"));

    let run = bower_in(dir.path(), &["queue", "verify"]);
    assert_eq!(run.code, 1);
    assert!(run.stderr.starts_with("Queue database not found: "));
    assert!(run.stderr.trim_end().ends_with("data/bower.db"));
}

#[test]
fn test_emit_reports_unreachable_collector() {
    let run = bower(&["test", "emit", "--endpoint", "http://127.0.0.1:9"]);
    assert_eq!(run.code, 1);
    assert!(!run.stderr.is_empty());
}

#[test]
fn test_emit_posts_canary_with_token_and_prints_response() {
    let (address, server) = one_shot_server("202 Accepted", "{\"decision\":\"accept\"}");
    let output = common::command(
        &common::bower_binary(),
        &["test", "emit", "--endpoint", &address],
        &common::repo_root(),
    )
    .env("BOWER_INGEST_TOKEN", "test-token-value")
    .output()
    .unwrap();
    let run = common::Run::from(output);
    let request = server.join().unwrap();
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stdout, "{\"decision\":\"accept\"}\n");
    assert!(request.starts_with("POST /v1/events HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer test-token-value")
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/json; charset=utf-8")
    );
    assert!(request.contains("\"eventType\":\"authentication_failure\""));
    assert!(request.contains("\"labels\":{\"evidenceType\":\"test\"}"));

    let (address, server) = one_shot_server("401 Unauthorized", "{\"error\":\"unauthorized\"}");
    let run = bower(&["test", "emit", "--endpoint", &format!("{address}/")]);
    let request = server.join().unwrap();
    assert_eq!(run.code, 2);
    assert_eq!(run.stdout, "{\"error\":\"unauthorized\"}\n");
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
}

const COLLECTOR_ACCEPT: &str =
    "{\"decision\":\"accept\",\"policy\":{\"policyId\":\"BWR-POL-EVIDENCE-CANARY\"}}";

#[test]
fn evidence_run_writes_simulated_signed_bundle_that_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let keys = root.join("keys");
    let run = bower_in(
        root,
        &["keys", "generate", "--out-dir", keys.to_str().unwrap()],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    let private = keys.join("bower-signing.key.pem");
    let public = keys.join("bower-signing.pub.pem");

    let (address, server) = one_shot_server("202 Accepted", COLLECTOR_ACCEPT);
    let output = common::command(
        &common::bower_binary(),
        &[
            "evidence",
            "run",
            "--collector-url",
            &address,
            "--signing-key",
            private.to_str().unwrap(),
            "--out",
            "bundle.json",
        ],
        root,
    )
    .env("BOWER_INGEST_TOKEN", "evidence-token-value")
    .output()
    .unwrap();
    let run = common::Run::from(output);
    let request = server.join().unwrap();
    assert_eq!(run.code, 2, "simulated is not verified: {}", run.stderr);
    assert!(request.starts_with("POST /v1/events HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer evidence-token-value")
    );
    assert!(request.contains("\"eventType\":\"collector_canary\""));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], "Mode:     simulated");
    assert!(
        lines[1].starts_with("Canary:   bower-canary-"),
        "{}",
        lines[1]
    );
    assert!(lines[1].ends_with(" -> collector HTTP 202 (accept)"));
    assert_eq!(lines[2], "Arrival:  not proven (simulated)");
    assert!(lines[3].starts_with("  ISM-0580         "), "{}", lines[3]);
    assert!(lines[lines.len() - 2].starts_with("Signed:   "));
    assert!(!lines[lines.len() - 2].contains("no (pass"));
    assert_eq!(lines[lines.len() - 1], "Bundle:   bundle.json");
    let text = std::fs::read_to_string(root.join("bundle.json")).unwrap();
    assert!(!text.contains("evidence-token-value"), "no token in bundle");
    assert!(text.contains("\"mode\": \"simulated\""));
    assert!(text.contains("SIMULATED: no Sentinel query was run"));

    let run = bower_in(
        root,
        &[
            "evidence",
            "verify",
            "bundle.json",
            "--trusted-key",
            public.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.starts_with("Signature valid (key "));
    assert!(run.stdout.ends_with("). Mode: simulated.\n"));

    // Tampering breaks the signature.
    std::fs::write(
        root.join("bundle.json"),
        text.replace("\"tool\": \"bower\"", "\"tool\": \"other\""),
    )
    .unwrap();
    let run = bower_in(
        root,
        &[
            "evidence",
            "verify",
            "bundle.json",
            "--trusted-key",
            public.to_str().unwrap(),
        ],
    );
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (1, "Signature INVALID or from an untrusted key.\n")
    );
}

#[test]
fn evidence_run_defaults_bundle_name_and_reports_unsigned() {
    let dir = tempfile::tempdir().unwrap();
    let (address, server) = one_shot_server("503 Service Unavailable", "not json");
    let run = bower_in(
        dir.path(),
        &["evidence", "run", "--collector-url", &address],
    );
    server.join().unwrap();
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(
        run.stdout
            .contains(" -> collector HTTP 503 (no decision)\n")
    );
    assert!(run.stdout.contains("Signed:   no (pass --signing-key)\n"));
    let bundle = run.stdout.lines().last().unwrap();
    let name = bundle.strip_prefix("Bundle:   ").unwrap();
    assert!(
        name.starts_with("bower-evidence-") && name.ends_with("Z.json"),
        "{name}"
    );
    assert_eq!(name.len(), "bower-evidence-20261017T010203Z.json".len());
    assert!(dir.path().join(name).is_file());
}

#[test]
fn validate_lists_default_policies_with_hashes() {
    let run = bower(&["validate"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout
            .starts_with("{\n  \"valid\": true,\n  \"policyCount\": ")
    );
    assert!(run.stdout.contains("\"Id\": \"BWR-POL-AUTH-FAILURE\""));
    assert!(run.stdout.contains("\"Hash\": \"sha256:"));

    let run = bower(&["validate", "--policy-directory", "no-such-dir"]);
    assert_eq!(
        (run.code, run.stderr.as_str()),
        (1, "Policy directory does not exist: no-such-dir\n")
    );
}

#[test]
fn packs_build_verify_inspect_test_and_diff() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let keys = root.join("keys");
    assert_eq!(
        bower_in(
            root,
            &["keys", "generate", "--out-dir", keys.to_str().unwrap()]
        )
        .code,
        0
    );
    let private = keys.join("bower-signing.key.pem");
    let public = keys.join("bower-signing.pub.pem");
    let public = public.to_str().unwrap();
    let source = common::repo_root().join("packs/linux-ssh-gateway");

    let run = bower_in(
        root,
        &[
            "pack",
            "build",
            source.to_str().unwrap(),
            "--key",
            private.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "Built and signed artifacts/packs/linux-ssh-gateway-1.0.0.bowerpack\n"
    );
    let pack = "artifacts/packs/linux-ssh-gateway-1.0.0.bowerpack";

    let run = bower_in(root, &["pack", "verify", pack, "--trusted-key", public]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout
            .starts_with("Verified linux-ssh-gateway@1.0.0 signed by key ")
    );
    assert!(run.stdout.contains(" files, pack hash sha256:"));

    let run = bower_in(root, &["pack", "inspect", pack, "--trusted-key", public]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout
            .starts_with("{\n  \"Id\": \"linux-ssh-gateway\",\n  \"Version\": \"1.0.0\",")
    );
    assert!(run.stdout.contains("\"eventTypes\": ["));
    assert!(run.stdout.contains("\"privacyProfile\": true"));

    let run = bower_in(root, &["pack", "test", pack, "--trusted-key", public]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert!(run.stdout.lines().all(|line| line.starts_with("PASS  ")));

    let run = bower_in(root, &["pack", "diff", pack, pack, "--trusted-key", public]);
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (
            0,
            "linux-ssh-gateway 1.0.0 -> 1.0.0\n  No policy population changes.\n"
        )
    );

    // A pack is never loaded without a trusted key, or under an untrusted one.
    let run = bower_in(root, &["pack", "verify", pack]);
    assert_eq!(
        (run.code, run.stderr.as_str()),
        (1, "Provide at least one --trusted-key PUBLIC.pem.\n")
    );
    let other =
        common::repo_root().join("rust/crates/bower-packs/tests/fixtures/csharp-signing.pub.pem");
    let run = bower_in(
        root,
        &[
            "pack",
            "verify",
            pack,
            "--trusted-key",
            other.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);
    assert_eq!(
        run.stderr,
        "Pack signature is invalid or not from a trusted key.\n"
    );
}

#[test]
fn csharp_style_options_ignore_unknowns_and_take_first_value() {
    let run = bower(&[
        "pipeline",
        "template",
        "--bogus",
        "--id",
        "aws-security",
        "--id",
        "x",
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.starts_with("id: template-aws-security\n"));
    let run = bower(&["keys", "generate", "--out-dir"]);
    assert_eq!(
        (run.code, run.stderr.as_str()),
        (1, "--out-dir is required.\n")
    );
    let run = bower(&["version", "extra"]);
    assert_eq!(run.stderr, "Unknown command. Run 'bower --help'.\n");
}

#[test]
fn positionals_never_take_an_options_value() {
    // `--format` is unknown: it and its value are skipped, so `bar` is not the template.
    let run = bower(&["pipeline", "template", "--format", "bar"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.starts_with("id: template-sentinel-app\n"));
    let run = bower(&["pipeline", "template", "--format", "yaml", "aws-security"]);
    assert!(run.stdout.starts_with("id: template-aws-security\n"));

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.yaml");
    std::fs::write(&file, bower(&["pipeline", "template"]).stdout).unwrap();
    let path = file.to_str().unwrap();
    let run = bower(&["pipeline", "validate", "--format", "json", path]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let run = bower(&["pipeline", "validate", "--format", path]);
    assert_eq!(
        (run.code, run.stderr.as_str()),
        (1, "Provide an existing pipeline file with --file PATH.\n")
    );
}

#[test]
fn pipeline_validate_reports_cycles_without_an_estimate() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("cycle.yaml");
    std::fs::write(
        &file,
        "id: c\nname: C\nversion: 1\ndescription: x\nnodes:\n- id: a\n  kind: Source\n  type: http-collector\n- id: b\n  kind: Output\n  type: http\n- id: lonely\n  kind: Enrich\n  type: geo\nedges:\n- from: a\n  to: b\n- from: b\n  to: a\n",
    )
    .unwrap();
    let run = bower(&["pipeline", "validate", file.to_str().unwrap()]);
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stdout.contains("\"estimate\": null"), "{}", run.stdout);
    assert!(run.stdout.contains("\"Code\": \"cycle\""));
    assert!(run.stdout.contains("\"Code\": \"node-disconnected\""));
}

#[test]
fn evidence_verify_reports_unreadable_bundles() {
    let dir = tempfile::tempdir().unwrap();
    for text in ["{}", "{\"bundle\":null}", "[]", "not json"] {
        let file = dir.path().join("bundle.json");
        std::fs::write(&file, text).unwrap();
        let run = bower(&["evidence", "verify", file.to_str().unwrap()]);
        assert_eq!(
            (run.code, run.stderr.as_str()),
            (1, "Evidence bundle is unreadable.\n"),
            "{text}"
        );
    }
}

#[test]
fn evidence_run_requires_a_positive_bounded_timeout() {
    for minutes in ["0", "-5", "1441"] {
        let run = bower(&[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--timeout-minutes",
            minutes,
        ]);
        assert_eq!(
            (run.code, run.stderr.as_str()),
            (1, "--timeout-minutes must be between 1 and 1440.\n"),
            "{minutes}"
        );
    }
}
