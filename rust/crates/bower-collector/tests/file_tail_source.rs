//! Port of `FileTailCollectorTests`: a plain-text auth.log line becomes a durable event
//! only through the signed `linux-authlog-ssh` parser (transforms, match filter),
//! redaction and policy. Lines the parser does not select are counted and dropped.

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, header};
use bower_collector::host::{self, BuildOptions, Collector};
use bower_collector::{CollectorSettings, bundle, shutdown};
use tower::ServiceExt;

const TOKEN: &str = "file-tail-collector-test-token-0123456789abcdef";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

/// RFC 3339 with an offset, as rsyslog writes by default; recent, so policy accepts it.
fn at() -> chrono::DateTime<chrono::FixedOffset> {
    let now = bower_contracts::time::now() - chrono::Duration::minutes(1);
    let micros = now.timestamp_micros();
    chrono::DateTime::from_timestamp_micros(micros)
        .unwrap()
        .with_timezone(&chrono::FixedOffset::east_opt(11 * 3600).unwrap())
}

fn lines(at: &chrono::DateTime<chrono::FixedOffset>) -> (String, String, String) {
    let time = at.format("%Y-%m-%dT%H:%M:%S%.6f%:z");
    (
        format!(
            "{time} bastion-1 sshd[4242]: Failed password for invalid user deploy-admin from 203.0.113.5 port 52144 ssh2"
        ),
        format!(
            "{time} bastion-1 sshd[4243]: Accepted publickey for deploy-admin from 203.0.113.5 port 52145 ssh2"
        ),
        format!(
            "{time} bastion-1 CRON[4244]: pam_unix(cron:session): session opened for user secret-marker"
        ),
    )
}

fn settings(directory: &Path, log: &Path, start_at: &str, parser: i32) -> CollectorSettings {
    settings_with_pack(
        directory,
        log,
        start_at,
        parser,
        &repo_root().join("packs/linux-authlog-ssh"),
    )
}

fn settings_with_pack(
    directory: &Path,
    log: &Path,
    start_at: &str,
    parser: i32,
    pack: &Path,
) -> CollectorSettings {
    let archive = directory.join("linux-authlog-ssh.bowerpack");
    let trust = directory.join("trusted.pem");
    let hmac = directory.join("hmac.key");
    if !archive.exists() {
        let keys = bower_integrity::generate_key_pair();
        let built = bower_packs::build(pack, &keys.private_key_pem, directory, None).unwrap();
        std::fs::rename(built, &archive).unwrap();
        std::fs::write(&trust, keys.public_key_pem).unwrap();
        std::fs::write(&hmac, [0u8; 32]).unwrap();
    }
    let configuration = directory.join("file.json");
    std::fs::write(
        &configuration,
        serde_json::json!({
            "apiVersion": "bower.security/v1",
            "kind": "FileTailSource",
            "allowedRoots": [log.parent().unwrap().to_str().unwrap()],
            "pollIntervalMilliseconds": 100,
            "inputs": [{
                "id": "auth",
                "path": log.to_str().unwrap(),
                "startAt": start_at,
                "route": {"pack": "linux-authlog-ssh", "parser": parser}
            }]
        })
        .to_string(),
    )
    .unwrap();
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        directory.join("queue.db"),
        directory.join("no-defaults"),
        "file-tail-collector-test",
    );
    settings.packs = vec![archive.to_string_lossy().into_owned()];
    settings.pack_trusted_key_files = vec![trust.to_string_lossy().into_owned()];
    settings.privacy_hmac_key_file = Some(hmac);
    settings.maximum_queue_bytes = 1_048_576;
    settings.ingest_token = Some(TOKEN.into());
    settings.single_trust_domain = true;
    settings.file_tail_config_path = Some(configuration);
    settings
}

struct Started {
    router: axum::Router,
    store: std::sync::Arc<dyn bower_contracts::DurableEventStore>,
    trigger: shutdown::ShutdownTrigger,
    task: tokio::task::JoinHandle<()>,
}

impl Started {
    async fn status(&self) -> serde_json::Value {
        let request = Request::get("/v1/status")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn input(&self, condition: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let status = self.status().await;
                let input = status["fileTail"][0].clone();
                if condition(&input) {
                    return input;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("file tail status condition")
    }

    async fn stop(self) {
        self.trigger.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

async fn start(settings: CollectorSettings) -> Started {
    let mut collector: Collector = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .unwrap();
    collector.initialize().await.unwrap();
    let (router, store) = (collector.router.clone(), collector.store.clone());
    let (trigger, token) = shutdown::channel();
    let task = tokio::spawn(collector.run(Vec::new(), token));
    Started {
        router,
        store,
        trigger,
        task,
    }
}

fn count(input: &serde_json::Value, name: &str) -> i64 {
    input[name].as_i64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_auth_log_line_is_transformed_redacted_queued_and_the_rest_is_counted_and_dropped()
{
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("log").join("auth.log");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let at = at();
    let (failed, accepted, cron) = lines(&at);
    std::fs::write(&log, format!("{cron}\n")).unwrap();
    let started = start(settings(directory.path(), &log, "end", 0)).await;
    // startAt end: the line already in the file is history and is not read.
    started.input(|input| input["offset"].is_i64()).await;

    let mut content = std::fs::read_to_string(&log).unwrap();
    content.push_str(&format!("{failed}\n{accepted}\n{cron}\n"));
    std::fs::write(&log, content).unwrap();
    let input = started
        .input(|input| count(input, "queued") == 1 && count(input, "notSelected") == 2)
        .await;
    assert_eq!(count(&input, "linesRead"), 3);
    assert_eq!(input["state"], "running");

    let rows = started.store.lease(10, Duration::from_secs(60)).unwrap();
    let [row] = rows.as_slice() else {
        panic!("expected one queued event");
    };
    let stored: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
    assert_eq!(stored["eventType"], "authentication_failure");
    assert_eq!(
        stored["collector"]["sourceAdapter"],
        "file:auth:linux-authlog-ssh:0"
    );
    assert_eq!(stored["source"]["ipAddress"], "203.0.113.5");
    assert_eq!(stored["eventOutcomeReason"], "InvalidCredentials");
    assert!(stored["eventId"].as_str().unwrap().starts_with("file-"));
    let generated =
        bower_contracts::time::parse(stored["timeGenerated"].as_str().unwrap()).unwrap();
    assert_eq!(generated, at);
    for text in [
        "deploy-admin",
        "secret-marker",
        "Failed password",
        log.to_str().unwrap(),
    ] {
        assert!(!row.payload.contains(text), "{text}");
    }
    let status = started.status().await.to_string();
    assert!(!status.contains("deploy-admin"));
    assert!(!status.contains("secret-marker"));
    started.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_resumes_from_the_durable_cursor_without_loss_or_duplicates() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("log").join("auth.log");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let (failed, _, _) = lines(&at());
    std::fs::write(&log, format!("{failed}\n")).unwrap();
    let committed = std::fs::metadata(&log).unwrap().len() as i64;
    let first = start(settings(directory.path(), &log, "beginning", 0)).await;
    first
        .input(|input| count(input, "queued") == 1 && input["offset"].as_i64() == Some(committed))
        .await;
    first.stop().await;

    let content = format!("{failed}\n{}\n", failed.replace("4242", "4250"));
    std::fs::write(&log, content).unwrap();
    let second = start(settings(directory.path(), &log, "beginning", 0)).await;
    let input = second.input(|input| count(input, "queued") == 1).await;
    assert_eq!(
        (count(&input, "linesRead"), count(&input, "duplicates")),
        (1, 0)
    );
    assert_eq!(second.store.snapshot().unwrap().queued, 2);
    second.stop().await;
}

/// The shipped pack, but timeGenerated is the read time, so a replay maps differently.
fn read_time_pack(directory: &Path) -> PathBuf {
    let source = repo_root().join("packs/linux-authlog-ssh");
    let target = directory.join("read-time-pack");
    for sub in ["", "parsers", "policies", "samples"] {
        std::fs::create_dir_all(target.join(sub)).unwrap();
    }
    for file in [
        "pack.yaml",
        "privacy.yaml",
        "policies/authlog-ssh-authentication.yaml",
    ] {
        std::fs::copy(source.join(file), target.join(file)).unwrap();
    }
    let mut parser: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(source.join("parsers/sshd-authlog.json")).unwrap(),
    )
    .unwrap();
    let fields = parser["fields"].as_array_mut().unwrap();
    if !fields.iter().any(|field| field["sourceName"] == "readAt") {
        fields.push(serde_json::json!({"sourceName": "readAt", "type": "DateTime", "ocsfPath": null, "asimField": null, "sensitive": false}));
    }
    parser["runtime"]["transforms"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(".timestamp = .readAt"));
    std::fs::write(target.join("parsers/sshd-authlog.json"), parser.to_string()).unwrap();
    let samples: Vec<String> = std::fs::read_to_string(source.join("samples/authlog.jsonl"))
        .unwrap()
        .lines()
        .map(|line| {
            let mut sample: serde_json::Value = serde_json::from_str(line).unwrap();
            sample.as_object_mut().unwrap().remove("expectFields");
            sample.to_string()
        })
        .collect();
    std::fs::write(
        target.join("samples/authlog.jsonl"),
        samples.join("\n") + "\n",
    )
    .unwrap();
    target
}

/// A replayed line whose mapped content differs from the queued event is an
/// event-identity conflict in the real SQLite queue: quarantined, counted, and the cursor
/// moves on (C# `CrashReplayWithAnIdentityConflict_IsCountedAndNeverBlocksTheInput`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_replay_with_an_identity_conflict_is_counted_and_never_blocks_the_input() {
    use bower_contracts::SourceCursorStore;
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("log").join("auth.log");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let (failed, _, _) = lines(&at());
    std::fs::write(&log, format!("{failed}\n")).unwrap();
    let pack = read_time_pack(directory.path());
    let end = std::fs::metadata(&log).unwrap().len() as i64;
    let first = start(settings_with_pack(
        directory.path(),
        &log,
        "beginning",
        0,
        &pack,
    ))
    .await;
    // Wait for the committed cursor, not just the counter (counted before the commit).
    first
        .input(|input| count(input, "queued") == 1 && input["offset"].as_i64() == Some(end))
        .await;
    first.stop().await;

    // Crash before the cursor commit: the stored cursor still points at the line.
    let cursors =
        bower_persistence::SqliteSourceCursorStore::new(directory.path().join("queue.db")).unwrap();
    let stored = cursors.read("file:auth").unwrap().unwrap();
    let mut rewound = bower_source_file::Cursor::deserialize(&stored.value).unwrap();
    rewound.offset = 0;
    assert!(
        cursors
            .try_advance(
                "file:auth",
                stored.version,
                &rewound.serialize(),
                bower_contracts::time::now()
            )
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(5)).await;

    let second = start(settings_with_pack(
        directory.path(),
        &log,
        "beginning",
        0,
        &pack,
    ))
    .await;
    // The poll is complete once the cursor past the line is committed and the state is set.
    let input = second
        .input(|input| {
            count(input, "rejected") == 1
                && input["offset"].as_i64() == Some(end)
                && input["state"] == "running"
        })
        .await;
    assert_eq!(
        (count(&input, "queued"), count(&input, "backpressure")),
        (0, 0)
    );
    let mut content = std::fs::read_to_string(&log).unwrap();
    content.push_str(&format!("{}\n", failed.replace("4242", "4251")));
    std::fs::write(&log, content).unwrap();
    second.input(|input| count(input, "queued") == 1).await;
    assert_eq!(second.store.snapshot().unwrap().queued, 2);
    second.stop().await;
}

#[test]
fn route_to_a_missing_parser_stops_start_up_and_refuses_a_signed_reload() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("log").join("auth.log");
    let settings = settings(directory.path(), &log, "end", 1);
    let error = host::build(
        settings.clone(),
        bundle::load(&settings).unwrap(),
        BuildOptions::default(),
    )
    .err()
    .expect("start-up refused");
    assert_eq!(error.kind, "InvalidOperationException");
    assert!(
        error
            .message
            .contains("File tail input auth: route pack linux-authlog-ssh parser 1"),
        "{}",
        error.message
    );
    assert_eq!(
        bower_collector::management_commands::reload_refusal(&settings),
        Some("InvalidOperationException")
    );
    let valid = self::settings(directory.path(), &log, "end", 0);
    assert_eq!(
        bower_collector::management_commands::reload_refusal(&valid),
        None
    );
    std::fs::write(
        valid.file_tail_config_path.as_ref().unwrap(),
        r#"{"apiVersion":"bower.security/v1","kind":"FileTailSource","allowedRoots":["/var/log"],"inputs":[],"globs":["*"]}"#,
    )
    .unwrap();
    assert_eq!(
        bower_collector::management_commands::reload_refusal(&valid),
        Some("InvalidDataException")
    );
}

#[test]
fn configuration_hash_changes_only_when_the_file_source_is_configured() {
    let plain = CollectorSettings::from_environment(|name| {
        (name == "BOWER_INGEST_TOKEN").then(|| TOKEN.to_owned())
    })
    .unwrap();
    let file = CollectorSettings::from_environment(|name| match name {
        "BOWER_INGEST_TOKEN" => Some(TOKEN.to_owned()),
        "BOWER_FILE_CONFIG" => Some("/etc/bower/file.json".to_owned()),
        _ => None,
    })
    .unwrap();
    assert_eq!(
        file.file_tail_config_path.as_deref(),
        Some(Path::new("/etc/bower/file.json"))
    );
    assert!(plain.file_tail_config_path.is_none());
    assert_ne!(plain.configuration_hash(), file.configuration_hash());

    // C# `ConfigurationHash_ChangesOnlyWhenTheFileSourceIsConfigured` pins the same value.
    let mut pinned =
        CollectorSettings::new("http://127.0.0.1:4319", "queue.db", "policies", "edge-01");
    pinned.syslog_config_path = Some("/etc/bower/syslog.json".into());
    pinned.file_tail_config_path = Some("/etc/bower/file.json".into());
    assert_eq!(
        pinned.configuration_hash(),
        "sha256:71d6a33e0d2c55df95ea9b44bc947d9bf28439afedb36e22f37b96b3d800bcae"
    );
}
