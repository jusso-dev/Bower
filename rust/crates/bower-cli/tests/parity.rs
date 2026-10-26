//! Differential tests: run the C# `bower` (when a built binary exists under
//! `src/Bower.Cli/bin`, or `BOWER_CSHARP_CLI` points at one) and the Rust `bower`
//! on the same inputs and compare exit codes and output. Skips when the C#
//! binary is absent or cannot start.

mod common;

use std::path::{Path, PathBuf};

use common::{Run, bower_binary, command, policy_samples, repo_root};

fn csharp_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BOWER_CSHARP_CLI") {
        return Some(PathBuf::from(path));
    }
    let bin = repo_root().join("src/Bower.Cli/bin");
    let mut candidates = Vec::new();
    for configuration in ["Release", "Debug"] {
        let Ok(frameworks) = std::fs::read_dir(bin.join(configuration)) else {
            continue;
        };
        for framework in frameworks.flatten() {
            candidates.push(framework.path().join("bower"));
            if let Ok(rids) = std::fs::read_dir(framework.path()) {
                candidates.extend(rids.flatten().map(|rid| rid.path().join("bower")));
            }
        }
    }
    candidates.into_iter().find(|path| path.is_file())
}

/// The C# binary if it runs here (`bower version` succeeds).
fn csharp() -> Option<PathBuf> {
    let binary = csharp_binary()?;
    let run: Run = command(&binary, &["version"], &repo_root())
        .output()
        .ok()?
        .into();
    if run.stdout == "bower 0.1.0\n" {
        Some(binary)
    } else {
        eprintln!(
            "skipping: C# bower at {} did not start ({})",
            binary.display(),
            run.stderr.trim()
        );
        None
    }
}

fn both(csharp: &Path, cwd: &Path, args: &[&str]) -> (Run, Run) {
    let expected: Run = command(csharp, args, cwd)
        .output()
        .expect("run C# bower")
        .into();
    let actual: Run = command(&bower_binary(), args, cwd)
        .output()
        .expect("run Rust bower")
        .into();
    (expected, actual)
}

fn assert_same(csharp: &Path, cwd: &Path, args: &[&str]) -> Run {
    let (expected, actual) = both(csharp, cwd, args);
    assert_eq!(
        actual.code, expected.code,
        "exit code for {args:?}\nC# stderr: {}\nRust stderr: {}",
        expected.stderr, actual.stderr
    );
    assert_eq!(actual.stdout, expected.stdout, "stdout for {args:?}");
    assert_eq!(actual.stderr, expected.stderr, "stderr for {args:?}");
    actual
}

#[test]
fn read_only_commands_match_csharp() {
    let Some(cs) = csharp() else {
        eprintln!("skipping: no runnable C# bower binary");
        return;
    };
    let root = repo_root();
    let cases: &[&[&str]] = &[
        &["version"],
        &["--help"],
        &["bogus"],
        &["validate"],
        &["validate", "--policy-directory", "policies/default"],
        &["pipeline", "template"],
        &["pipeline", "template", "aws-security"],
        &["pipeline", "template", "--id", "aws-security"],
        &["pipeline", "validate"],
        &["dcr", "generate"],
        &[
            "dcr",
            "generate",
            "--rule-name",
            "custom-dcr",
            "--plan",
            "Basic",
            "--retention-days",
            "30",
            "--total-retention-days",
            "120",
        ],
        &["doctor"],
        &["doctor", "--json"],
        &["queue", "replay", "--database", "x.db"],
        &["keys", "generate"],
        &["pack", "verify"],
        &["evidence", "verify"],
    ];
    for args in cases {
        assert_same(&cs, &root, args);
    }
}

#[test]
fn pipeline_validate_matches_csharp() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let template = command(&cs, &["pipeline", "template", "aws-security"], &repo_root())
        .output()
        .unwrap();
    let valid = dir.path().join("valid.yaml");
    std::fs::write(&valid, &template.stdout).unwrap();
    let invalid = dir.path().join("invalid.yaml");
    std::fs::write(
        &invalid,
        "id: bad\nname: Bad\nversion: 1.0.0\ndescription: cycle\nnodes:\n- id: a\n  kind: Source\n  type: nope\n- id: b\n  kind: Filter\n  type: policy-engine\nedges:\n- from: a\n  to: b\n- from: b\n  to: a\n",
    )
    .unwrap();
    // A disconnected Enrich node, an unknown `azure-monitor` output and duplicate ids.
    let orphan = dir.path().join("orphan.yaml");
    std::fs::write(
        &orphan,
        "id: o\nname: O\nversion: 1.0.0\ndescription: orphan\nnodes:\n- id: s\n  kind: Source\n  type: http-collector\n- id: lonely\n  kind: Enrich\n  type: geo\n- id: out\n  kind: Output\n  type: azure-monitor\n- id: out\n  kind: Output\n  type: http\nedges:\n- from: s\n  to: out\n",
    )
    .unwrap();
    for file in [&valid, &invalid, &orphan] {
        let path = file.to_str().unwrap();
        assert_same(&cs, &repo_root(), &["pipeline", "validate", "--file", path]);
        assert_same(&cs, &repo_root(), &["pipeline", "validate", path]);
        // An unknown option's value is never taken as the path.
        assert_same(
            &cs,
            &repo_root(),
            &["pipeline", "validate", "--format", path, path],
        );
    }
    let invalid = invalid.to_str().unwrap();
    let run = assert_same(&cs, &repo_root(), &["pipeline", "validate", invalid]);
    assert_eq!(run.code, 2);
    assert!(run.stdout.contains("\"estimate\": null"), "{}", run.stdout);
}

#[test]
fn privacy_validate_matches_csharp() {
    let Some(cs) = csharp() else { return };
    let root = repo_root();
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, content: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_owned()
    };
    // A fixed key so HMAC pseudonyms in the redacted sample are deterministic.
    let key = write("key.b64", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n");
    let short_key = write("short.key", "abc");
    let sample = write(
        "sample.json",
        "{\"actor\":{\"username\":\"alice\"},\"msg\":\"EMP-123456 opened CUST-ab1234 see INC0012345 \u{1F600}x\",\"sessionKey\":\"s\",\"webhook_nonce\":1}",
    );
    let broken_sample = write("broken.json", "{ not json");
    let header = "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n";
    let untested = write(
        "untested.yaml",
        &format!(
            "{header}customDetectors:\n  - id: custom.d\n    pattern: 'EMP-\\d{{6}}'\n    action: mask\n    tests:\n      match: [EMP-12345]\n"
        ),
    );
    let syntax = write(
        "syntax.yaml",
        &format!(
            "{header}customDetectors:\n  - id: custom.d\n    pattern: 'a(?=b)'\n    action: mask\n    tests:\n      match: [ab]\n"
        ),
    );
    let secret = write(
        "secret.yaml",
        &format!("{header}secretFieldNames: ['---']\n"),
    );
    let example = "deploy/privacy/custom-redaction-example.yaml";
    let cases: Vec<Vec<&str>> = vec![
        vec!["privacy", "validate"],
        vec!["privacy", "validate", "missing.yaml"],
        vec!["privacy", "validate", example],
        vec![
            "privacy",
            "validate",
            "deploy/privacy/cloud-identities.yaml",
        ],
        vec![
            "privacy",
            "validate",
            "packs/linux-ssh-gateway/privacy.yaml",
        ],
        vec!["privacy", "validate", example, "--hmac-key-file", &key],
        vec![
            "privacy",
            "validate",
            "--hmac-key-file",
            &key,
            example,
            "--sample",
            &sample,
        ],
        vec![
            "privacy",
            "validate",
            example,
            "--hmac-key-file",
            &key,
            "--sample",
            &broken_sample,
        ],
        vec![
            "privacy",
            "validate",
            example,
            "--hmac-key-file",
            &short_key,
        ],
        vec![
            "privacy",
            "validate",
            example,
            "--hmac-key-file",
            "missing.key",
        ],
        vec![
            "privacy",
            "validate",
            example,
            "--hmac-key-file",
            &key,
            "--sample",
            "missing.json",
        ],
        vec!["privacy", "validate", &untested],
        vec!["privacy", "validate", &syntax],
        vec!["privacy", "validate", &secret],
    ];
    for args in &cases {
        assert_same(&cs, &root, args);
    }

    // Council A5: characters the two YAML parsers treat differently fail identically, raw
    // or escaped; allow is rejected; alert-only never hides other detectors.
    let probes: Vec<String> = [
        format!("{header}# nel \u{85}\n"),
        format!("{header}# line separator \u{2028}\n"),
        format!("{header}# form feed \u{C}\n"),
        format!("{header}secretFieldNames: [\"a\\Lb\"]\n"),
        format!("{header}secretFieldNames: [\"\\uD83D\\uDE00\"]\n"),
        format!("{header}secretFieldNames: [\"\\x0C\"]\n"),
        format!(
            "{header}customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: allow\n    tests:\n      match: [x]\n"
        ),
        format!(
            "{header}customDetectors:\n  - id: custom.trace-line\n    pattern: 'trace: .+'\n    action: alert-only\n    tests:\n      match: ['trace: x']\n"
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, content)| write(&format!("probe-{index}.yaml"), &content))
    .collect();
    let trace_sample = write(
        "trace.json",
        r#"{"msg":"trace: card 4111111111111111 key AKIAIOSFODNN7EXAMPLE mail alice@example.test"}"#,
    );
    for (index, probe) in probes.iter().enumerate() {
        let run = assert_same(
            &cs,
            &root,
            &[
                "privacy",
                "validate",
                probe,
                "--hmac-key-file",
                &key,
                "--sample",
                &trace_sample,
            ],
        );
        assert_eq!(
            run.code,
            if index == 7 { 0 } else { 1 },
            "{probe}: {}",
            run.stderr
        );
    }

    let run = assert_same(&cs, &root, &cases[6]);
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("\"testsPassed\": 13"), "{}", run.stdout);
    assert!(!run.stdout.contains("EMP-123456"), "{}", run.stdout);
    assert_eq!(assert_same(&cs, &root, &cases[7]).code, 2);
    assert_eq!(assert_same(&cs, &root, &cases[11]).code, 1);
}

#[test]
fn dcr_diff_matches_csharp() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let template = dir.path().join("template.json");
    let path = template.to_str().unwrap();
    let run = assert_same(&cs, dir.path(), &["dcr", "generate", "--out", path]);
    assert!(run.stdout.starts_with("Wrote "));

    // Extract the DCR and table resources from the generated ARM template.
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&template).unwrap()).unwrap();
    let resources = document["resources"].as_array().unwrap();
    let find = |kind: &str| {
        resources
            .iter()
            .find(|item| item["type"] == kind)
            .cloned()
            .unwrap()
    };
    let rule = dir.path().join("rule.json");
    std::fs::write(
        &rule,
        find("Microsoft.Insights/dataCollectionRules").to_string(),
    )
    .unwrap();
    let table = dir.path().join("table.json");
    std::fs::write(
        &table,
        find("Microsoft.OperationalInsights/workspaces/tables").to_string(),
    )
    .unwrap();

    let mut drifted = find("Microsoft.Insights/dataCollectionRules");
    drifted["properties"]["streamDeclarations"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .for_each(|stream| {
            stream["columns"].as_array_mut().unwrap().truncate(3);
        });
    let drifted_path = dir.path().join("drifted.json");
    std::fs::write(&drifted_path, drifted.to_string()).unwrap();

    for args in [
        vec!["dcr", "diff"],
        vec!["dcr", "diff", "--rule", rule.to_str().unwrap()],
        vec![
            "dcr",
            "diff",
            "--rule",
            rule.to_str().unwrap(),
            "--table",
            table.to_str().unwrap(),
        ],
        vec!["dcr", "diff", "--rule", drifted_path.to_str().unwrap()],
    ] {
        assert_same(&cs, dir.path(), &args);
    }
}

#[test]
fn queue_commands_match_csharp_on_shared_database() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let rust_db = dir.path().join("rust.db");
    let csharp_db = dir.path().join("csharp.db");
    // Each implementation creates an empty queue; snapshots must agree.
    let rust: Run = command(
        &bower_binary(),
        &["queue", "inspect", "--database", rust_db.to_str().unwrap()],
        dir.path(),
    )
    .output()
    .unwrap()
    .into();
    let csharp: Run = command(
        &cs,
        &[
            "queue",
            "inspect",
            "--database",
            csharp_db.to_str().unwrap(),
        ],
        dir.path(),
    )
    .output()
    .unwrap()
    .into();
    assert_eq!((rust.code, &rust.stdout), (csharp.code, &csharp.stdout));

    // Seed through the Rust store, then let both CLIs read the same file.
    {
        use bower_contracts::{DurableEventStore, QueueState, QueuedEvent};
        let store =
            bower_persistence::SqliteEventStore::new(&rust_db, 10 * 1024 * 1024, None).unwrap();
        store.initialize().unwrap();
        for id in ["a", "b"] {
            store
                .enqueue(&QueuedEvent {
                    lease_token: None,
                    event_id: id.to_owned(),
                    fingerprint: format!("fp-{id}"),
                    payload: "{}".to_owned(),
                    received_at: bower_contracts::time::parse("2026-05-01T10:20:30.5+00:00")
                        .unwrap(),
                    state: QueueState::Queued,
                    delivery_attempts: 0,
                    suppression: None,
                })
                .unwrap();
        }
        let leases = store.lease(1, std::time::Duration::from_secs(60)).unwrap();
        store
            .mark_dead_lettered("a", "http-400", leases[0].lease_token.as_deref())
            .unwrap();
    }
    let db = rust_db.to_str().unwrap();
    for args in [
        vec!["queue", "inspect", "--database", db],
        vec!["queue", "dead-letters", "--database", db],
        vec!["queue", "verify", "--database", db],
        vec!["queue", "verify", "--database", db, "--expect-head", "5:x"],
        vec!["doctor", "--database", db],
    ] {
        assert_same(&cs, dir.path(), &args);
    }
}

#[test]
fn keys_and_packs_interoperate_with_csharp() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let keys_dir = keys.to_str().unwrap();
    let run = |binary: &Path, args: &[&str]| -> Run {
        command(binary, args, &repo_root()).output().unwrap().into()
    };

    // Key generation output shape and overwrite refusal.
    let rust_keys = run(
        &bower_binary(),
        &["keys", "generate", "--out-dir", keys_dir, "--name", "rust"],
    );
    let cs_keys = run(
        &cs,
        &[
            "keys",
            "generate",
            "--out-dir",
            keys_dir,
            "--name",
            "csharp",
        ],
    );
    assert_eq!(rust_keys.code, 0, "{}", rust_keys.stderr);
    assert_eq!(cs_keys.code, 0);
    let shape = |text: &str| {
        text.lines()
            .map(|line| line.split(':').next().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&rust_keys.stdout), shape(&cs_keys.stdout));
    let again = run(
        &bower_binary(),
        &["keys", "generate", "--out-dir", keys_dir, "--name", "rust"],
    );
    let again_cs = run(
        &cs,
        &["keys", "generate", "--out-dir", keys_dir, "--name", "rust"],
    );
    assert_eq!(
        (again.code, &again.stderr),
        (again_cs.code, &again_cs.stderr)
    );

    let key = |name: &str, kind: &str| {
        keys.join(format!("{name}.{kind}.pem"))
            .to_string_lossy()
            .into_owned()
    };
    let out = dir.path().join("out");
    let out_dir = out.to_str().unwrap();
    let source = repo_root().join("packs/linux-ssh-gateway");
    let source = source.to_str().unwrap();

    // Each implementation builds and signs; each verifies the other's pack.
    let built_rs = run(
        &bower_binary(),
        &[
            "pack",
            "build",
            source,
            "--key",
            &key("rust", "key"),
            "--out",
            &format!("{out_dir}/rs"),
        ],
    );
    assert_eq!(built_rs.code, 0, "{}", built_rs.stderr);
    let built_cs = run(
        &cs,
        &[
            "pack",
            "build",
            source,
            "--key",
            &key("csharp", "key"),
            "--out",
            &format!("{out_dir}/cs"),
        ],
    );
    assert_eq!(built_cs.code, 0, "{}", built_cs.stderr);
    let pack_path = |text: &str| {
        text.trim_end()
            .trim_start_matches("Built and signed ")
            .to_owned()
    };
    let rs_pack = pack_path(&built_rs.stdout);
    let cs_pack = pack_path(&built_cs.stdout);

    for (pack, signer) in [(&rs_pack, "rust"), (&cs_pack, "csharp")] {
        let trusted = key(signer, "pub");
        for sub in ["verify", "inspect", "test"] {
            assert_same(
                &cs,
                &repo_root(),
                &["pack", sub, pack, "--trusted-key", &trusted],
            );
        }
        // Untrusted key must fail identically.
        let other = key(if signer == "rust" { "csharp" } else { "rust" }, "pub");
        assert_same(
            &cs,
            &repo_root(),
            &["pack", "verify", pack, "--trusted-key", &other],
        );
    }
    let both_keys = [key("rust", "pub"), key("csharp", "pub")];
    assert_same(
        &cs,
        &repo_root(),
        &[
            "pack",
            "diff",
            &cs_pack,
            &rs_pack,
            "--trusted-key",
            &both_keys[0],
            "--trusted-key",
            &both_keys[1],
        ],
    );
    assert_same(
        &cs,
        &repo_root(),
        &["doctor", "--pack", &rs_pack, "--trusted-key", &both_keys[0]],
    );
}

#[test]
fn evidence_verify_matches_csharp_on_tampered_bundle() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("bundle.json");
    std::fs::write(
        &bundle,
        "{\"bundle\":{\"mode\":\"simulated\"},\"signature\":null}",
    )
    .unwrap();
    let path = bundle.to_str().unwrap();
    assert_same(&cs, dir.path(), &["evidence", "verify", path]);

    // No bundle, a null bundle or invalid JSON: a clean error, never a crash.
    for (name, text) in [
        ("empty.json", "{}"),
        ("null.json", "{\"bundle\":null}"),
        ("text.json", "not json"),
    ] {
        std::fs::write(dir.path().join(name), text).unwrap();
        let run = assert_same(&cs, dir.path(), &["evidence", "verify", name]);
        assert_eq!(
            (run.code, run.stderr.as_str()),
            (1, "Evidence bundle is unreadable.\n")
        );
    }
}

/// Masks per-run values (canary ids, times) so two runs can be compared.
fn mask_canary(text: &str) -> String {
    let mut masked = String::new();
    let mut rest = text;
    while let Some(index) = rest.find("bower-canary-") {
        masked.push_str(&rest[..index]);
        masked.push_str("bower-canary-<id>");
        rest = rest[index + "bower-canary-".len()..]
            .trim_start_matches(|c: char| c.is_ascii_hexdigit());
    }
    masked.push_str(rest);
    masked
}

#[test]
fn evidence_run_matches_csharp_and_bundles_cross_verify() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let keys = root.join("keys");
    let keys_dir = keys.to_str().unwrap();
    let generated: Run = command(
        &bower_binary(),
        &["keys", "generate", "--out-dir", keys_dir],
        root,
    )
    .output()
    .unwrap()
    .into();
    assert_eq!(generated.code, 0, "{}", generated.stderr);
    let private = keys.join("bower-signing.key.pem");
    let public = keys.join("bower-signing.pub.pem");
    let (private, public) = (private.to_str().unwrap(), public.to_str().unwrap());

    let body = "{\"decision\":\"accept\",\"policy\":{\"policyId\":\"BWR-POL-EVIDENCE-CANARY\"}}";
    let mut outputs = Vec::new();
    for (binary, name) in [
        (cs.as_path(), "cs.json"),
        (bower_binary().as_path(), "rs.json"),
    ] {
        let (address, server) = common::one_shot_server("202 Accepted", body);
        let run: Run = command(
            binary,
            &[
                "evidence",
                "run",
                "--collector-url",
                &address,
                "--signing-key",
                private,
                "--out",
                name,
            ],
            root,
        )
        .output()
        .unwrap()
        .into();
        if !run.stdout.starts_with("Mode:") {
            // The binary never reached the server: release it instead of waiting out its timeout.
            drop(std::net::TcpStream::connect(
                address.trim_start_matches("http://"),
            ));
        }
        if server.join().unwrap().is_empty() {
            eprintln!(
                "skipping: {} could not reach the local test collector ({})",
                binary.display(),
                run.stderr.trim()
            );
            return;
        }
        outputs.push(run);
    }
    let (expected, actual) = (&outputs[0], &outputs[1]);
    assert_eq!(
        actual.code, expected.code,
        "C# stderr: {}\nRust stderr: {}",
        expected.stderr, actual.stderr
    );
    assert_eq!(expected.code, 2);
    assert_eq!(
        mask_canary(&actual.stdout).replace("rs.json", "<out>"),
        mask_canary(&expected.stdout).replace("cs.json", "<out>")
    );

    // Same bundle shape once per-run values are masked.
    let shape = |name: &str| {
        let text = std::fs::read_to_string(root.join(name)).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        for pointer in [
            "/bundle/generatedAt",
            "/bundle/canary/eventId",
            "/bundle/canary/sentAt",
            "/signature/Value",
        ] {
            *value.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
        }
        // Key order matters: compare serialized text, not maps.
        value.to_string()
    };
    assert_eq!(shape("rs.json"), shape("cs.json"));

    // Each verifies the other's signed bundle.
    for name in ["cs.json", "rs.json"] {
        assert_same(
            &cs,
            root,
            &["evidence", "verify", name, "--trusted-key", public],
        );
    }
}

/// C# `CliOptions` semantics: unknown options and extra arguments are ignored, the
/// first occurrence wins, a trailing option has no value, values may start with `-`.
#[test]
fn argument_handling_matches_csharp() {
    let Some(cs) = csharp() else { return };
    let dir = tempfile::tempdir().unwrap();
    let cases: &[&[&str]] = &[
        &["version", "extra"],
        &["pipeline"],
        &["pipeline", "template", "--id"],
        &["pipeline", "template", "--bogus"],
        &[
            "pipeline",
            "template",
            "--id",
            "aws-security",
            "--id",
            "sentinel-app",
        ],
        &["pipeline", "validate", "--file"],
        &["pipeline", "validate", "--foo", "bar"],
        &["pipeline", "template", "--foo", "bar"],
        &["pipeline", "template", "--format", "yaml", "aws-security"],
        &["dcr", "generate", "--retention-days"],
        &["dcr", "generate", "--retention-days", "x"],
        &["dcr", "generate", "--plan", "Basic", "--unknown"],
        &["dcr", "diff", "--dcr-resource-id"],
        &[
            "dcr",
            "diff",
            "--credential",
            "bogus",
            "--rule",
            "x.json",
            "--dcr-resource-id",
        ],
        &["queue", "replay", "--database", "x.db", "--event", "-abc"],
        &["queue", "inspect", "--database", " "],
        &["queue", "verify", "--database", "nope.db", "--expect-head"],
        &["keys", "generate", "--out-dir"],
        &["doctor", "--json", "--json"],
        &["pack", "build"],
        &["pack", "build", "src", "--key", "nope.pem"],
        &["pack", "diff", "a.bowerpack"],
        &["pack", "diff", "a.bowerpack", "B.BOWERPACK"],
        &["pack", "verify", "--trusted-key", "k.pem"],
        &["pack", "inspect", "x.bowerpack"],
        &["pack", "test", "x.bowerpack", "--trusted-key", "nope.pem"],
        &["evidence", "run"],
        &["evidence", "run", "--collector-url", "notaurl"],
        &[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--table",
            "bad table",
        ],
        &[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--workspace-id",
            "w",
            "--credential",
            "bogus",
        ],
        &[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--timeout-minutes",
            "x",
        ],
        &["evidence", "run", "--timeout-minutes", "-5"],
        &[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--timeout-minutes",
            "0",
        ],
        &[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--timeout-minutes",
            "1441",
        ],
        &["evidence", "verify", "missing.json"],
        &[
            "evidence",
            "run",
            "--collector-url",
            "http://127.0.0.1:9",
            "--probe-profile",
            "parser:linux-ssh-gateway:7",
        ],
        &["developer", "init", "--path", "/nonexistent-bower-path"],
    ];
    for args in cases {
        assert_same(&cs, dir.path(), args);
    }
}

#[test]
fn pack_fixtures_match_csharp() {
    let Some(cs) = csharp() else { return };
    let fixtures = repo_root().join("rust/crates/bower-packs/tests/fixtures");
    let key = fixtures.join("csharp-signing.pub.pem");
    let key = key.to_str().unwrap();
    let pack = |name: &str| {
        fixtures
            .join(format!("{name}-1.0.0.bowerpack"))
            .to_string_lossy()
            .into_owned()
    };
    let dir = tempfile::tempdir().unwrap();
    let hmac = dir.path().join("hmac.key");
    std::fs::write(&hmac, [7u8; 32]).unwrap();
    let hmac = hmac.to_str().unwrap();
    for name in ["aws-security", "gcp-security", "linux-ssh-gateway"] {
        let file = pack(name);
        for sub in ["verify", "inspect", "test"] {
            assert_same(
                &cs,
                &repo_root(),
                &["pack", sub, &file, "--trusted-key", key],
            );
        }
        assert_same(
            &cs,
            &repo_root(),
            &[
                "pack",
                "test",
                &file,
                "--trusted-key",
                key,
                "--hmac-key-file",
                hmac,
            ],
        );
    }
    let (aws, gcp, ssh) = (
        pack("aws-security"),
        pack("gcp-security"),
        pack("linux-ssh-gateway"),
    );
    for args in [
        &["pack", "diff", &aws, &gcp, "--trusted-key", key][..],
        &["pack", "diff", &aws, &aws, "--trusted-key", key][..],
        &[
            "doctor",
            "--pack",
            &aws,
            "--pack",
            &gcp,
            "--pack",
            &ssh,
            "--trusted-key",
            key,
        ][..],
        &[
            "doctor",
            "--pack",
            &aws,
            "--pack",
            &aws,
            "--trusted-key",
            key,
            "--json",
        ][..],
        &[
            "doctor",
            "--pack",
            &ssh,
            "--trusted-key",
            key,
            "--hmac-key-file",
            hmac,
        ][..],
        &["doctor", "--pack", &ssh][..],
        &[
            "validate",
            "--policy-directory",
            "packs/aws-security/policies",
        ][..],
    ] {
        assert_same(&cs, &repo_root(), args);
    }
}

#[test]
fn policy_test_matches_csharp() {
    let Some(cs) = csharp() else {
        eprintln!("skipping: no runnable C# bower binary");
        return;
    };
    let root = repo_root();
    let dir = tempfile::tempdir().unwrap();
    let (secret, noise, broken) = policy_samples(dir.path());
    let cases: Vec<Vec<&str>> = vec![
        vec!["policy", "test"],
        vec!["policy", "test", "missing.json"],
        vec!["policy", "test", &secret, &noise, &broken],
        vec!["policy", "test", &secret, "--expect", "redact-and-accept"],
        vec!["policy", "test", &noise, "--expect", "accept"],
        vec!["policy", "test", &noise, "--expect", "1"],
        vec!["policy", "test", &noise, "--policy-directory", "missing"],
    ];
    for args in &cases {
        let run = assert_same(&cs, &root, args);
        assert!(!run.stdout.contains("never-print"));
    }

    // File.ReadAllText detects UTF-16 and UTF-32 byte order marks (Windows PowerShell 5.1
    // writes UTF-16 LE); a truncated trailing code unit decodes to U+FFFD on both sides.
    let text = std::fs::read_to_string(&secret).unwrap();
    let encode = |name: &str, bom: &[u8], unit: &dyn Fn(char) -> Vec<u8>, trailing: &[u8]| {
        let mut bytes = bom.to_vec();
        for character in text.chars() {
            bytes.extend(unit(character));
        }
        bytes.extend_from_slice(trailing);
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let utf16 = |big: bool| {
        move |character: char| -> Vec<u8> {
            let mut buffer = [0u16; 2];
            character
                .encode_utf16(&mut buffer)
                .iter()
                .flat_map(|unit| {
                    if big {
                        unit.to_be_bytes()
                    } else {
                        unit.to_le_bytes()
                    }
                })
                .collect()
        }
    };
    let utf32 = |big: bool| {
        move |character: char| -> Vec<u8> {
            let unit = u32::from(character);
            (if big {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            })
            .to_vec()
        }
    };
    let samples = [
        encode("utf16le.json", &[0xFF, 0xFE], &utf16(false), &[]),
        encode("utf16be.json", &[0xFE, 0xFF], &utf16(true), &[]),
        encode("utf32le.json", &[0xFF, 0xFE, 0, 0], &utf32(false), &[]),
        encode("utf32be.json", &[0, 0, 0xFE, 0xFF], &utf32(true), &[]),
        encode("utf16odd.json", &[0xFF, 0xFE], &utf16(false), b" "),
    ];
    for sample in &samples {
        let run = assert_same(&cs, &root, &["policy", "test", sample]);
        assert!(!run.stdout.contains("never-print"));
    }
    let utf16le = assert_same(&cs, &root, &["policy", "test", &samples[0]]);
    assert!(
        utf16le.stdout.contains("\"redactandaccept\""),
        "UTF-16 sample decoded: {}",
        utf16le.stdout
    );
}
