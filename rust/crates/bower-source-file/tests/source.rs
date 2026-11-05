//! The file tail source against a fake sink (C# `FileTailSourceTests`): default deny,
//! backpressure, durable cursor crash/recovery, malformed and oversized lines, bounds,
//! rotation counters, missing files, path guards and stopping.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_contracts::time::Timestamp;
use bower_contracts::{SourceCursorSnapshot, SourceCursorStore, StoreError, StoreResult};
use bower_persistence::SqliteSourceCursorStore;
use bower_source_file::config::{FileTailSourceConfiguration, InputOptions, Route};
use bower_source_file::paths::{self, PathState};
use bower_source_file::reader::Cursor;
use bower_source_file::source::failures;
use bower_source_file::{FileTailSink, FileTailSource, SinkFailure, SubmitOutcome};

fn line(text: &str) -> String {
    format!(
        "{text} {}\n",
        "x".repeat(69usize.saturating_sub(text.len()))
    )
}

fn configuration(
    root: &Path,
    path: &Path,
    start_at: &str,
    format: &str,
    max_line_bytes: i32,
) -> FileTailSourceConfiguration {
    FileTailSourceConfiguration {
        api_version: "bower.security/v1".into(),
        kind: "FileTailSource".into(),
        allowed_roots: vec![Some(root.to_str().unwrap().into())],
        inputs: vec![Some(InputOptions {
            id: "auth".into(),
            path: path.to_str().unwrap().into(),
            route: Route {
                pack: "pack".into(),
                parser: 0,
            },
            format: format.into(),
            start_at: start_at.into(),
            max_line_bytes,
            allow_symlink: false,
        })],
        poll_interval_milliseconds: 100,
        max_lines_per_batch: 256,
        max_bytes_per_batch: 1_048_576,
        rotation_grace_polls: 1,
    }
}

fn text(root: &Path, path: &Path, start_at: &str) -> FileTailSourceConfiguration {
    configuration(root, path, start_at, "text", 16_384)
}

type Decide = dyn Fn(&str) -> Result<SubmitOutcome, SinkFailure> + Send + Sync;

struct FakeSink {
    records: Mutex<Vec<String>>,
    decide: Box<Decide>,
}

impl FakeSink {
    fn new(
        decide: impl Fn(&str) -> Result<SubmitOutcome, SinkFailure> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(Vec::new()),
            decide: Box::new(decide),
        })
    }

    fn records(&self) -> Vec<String> {
        self.records.lock().unwrap().clone()
    }
}

impl FileTailSink for FakeSink {
    fn submit(&self, _: &InputOptions, record: &str) -> Result<SubmitOutcome, SinkFailure> {
        self.records.lock().unwrap().push(record.to_owned());
        (self.decide)(record)
    }
}

#[derive(Default)]
struct MemoryCursors(Mutex<HashMap<String, SourceCursorSnapshot>>);

impl MemoryCursors {
    fn value(&self, id: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .get(id)
            .map(|snapshot| snapshot.value.clone())
    }
}

impl SourceCursorStore for MemoryCursors {
    fn read(&self, source_id: &str) -> StoreResult<Option<SourceCursorSnapshot>> {
        Ok(self.0.lock().unwrap().get(source_id).cloned())
    }

    fn try_advance(
        &self,
        source_id: &str,
        expected: i64,
        value: &str,
        _: Timestamp,
    ) -> StoreResult<bool> {
        let mut values = self.0.lock().unwrap();
        let current = values.get(source_id).map_or(0, |snapshot| snapshot.version);
        if current != expected {
            return Ok(false);
        }
        values.insert(
            source_id.into(),
            SourceCursorSnapshot {
                value: value.into(),
                version: expected + 1,
            },
        );
        Ok(true)
    }
}

/// Simulates a crash after enqueue and before the cursor commit.
struct FailingCommit(Arc<SqliteSourceCursorStore>);

impl SourceCursorStore for FailingCommit {
    fn read(&self, source_id: &str) -> StoreResult<Option<SourceCursorSnapshot>> {
        self.0.read(source_id)
    }

    fn try_advance(&self, _: &str, _: i64, _: &str, _: Timestamp) -> StoreResult<bool> {
        Err(StoreError::Invalid("injected crash before commit".into()))
    }
}

fn field(record: &str, name: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(record).unwrap();
    value[name].as_str().unwrap().to_owned()
}

fn first_word(record: &str) -> String {
    field(record, "message")
        .split(' ')
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn selected_lines_are_submitted_in_order_and_default_deny_counts_the_rest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, line("history")).unwrap();
    let sink = FakeSink::new(|record| {
        Ok(if record.contains("select-me") {
            SubmitOutcome::Queued
        } else {
            SubmitOutcome::NotSelected
        })
    });
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        text(directory.path(), &path, "end"),
        sink.clone(),
        cursors,
        None,
    );

    assert_eq!(source.poll_once("auth").unwrap().lines, 0);
    let appended = format!(
        "{}{}\npartial",
        line("select-me secret-marker"),
        line("other secret-marker")
    );
    std::fs::write(&path, format!("{}{appended}", line("history"))).unwrap();
    let result = source.poll_once("auth").unwrap();

    assert_eq!(result.lines, 3);
    assert_eq!(sink.records().len(), 2);
    let status = &source.snapshot()[0];
    assert_eq!(
        (
            status.queued,
            status.not_selected,
            status.blank,
            status.state.as_str()
        ),
        (1, 1, 1, "running")
    );
    assert!(
        !serde_json::to_string(&source.snapshot())
            .unwrap()
            .contains("secret-marker")
    );
    let first = &sink.records()[0];
    assert_eq!(field(first, "path"), path.to_str().unwrap());
    assert_eq!(field(first, "offset"), line("history").len().to_string());
    assert!(first.starts_with("{\"id\":\"file-"));
}

#[test]
fn full_queue_stops_reading_rewinds_to_the_line_and_loses_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(
        &path,
        format!("{}{}{}", line("one"), line("two"), line("three")),
    )
    .unwrap();
    let full = Arc::new(Mutex::new(true));
    let gate = Arc::clone(&full);
    let sink = FakeSink::new(move |record| {
        Ok(if *gate.lock().unwrap() && record.contains("two") {
            SubmitOutcome::Unavailable
        } else {
            SubmitOutcome::Queued
        })
    });
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        cursors.clone(),
        None,
    );

    let blocked = source.poll_once("auth").unwrap();
    assert!(blocked.backpressure);
    assert_eq!(blocked.lines, 1);
    assert_eq!(source.snapshot()[0].state, "backpressure");
    let stored = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(stored.offset, line("one").len() as i64);

    assert!(source.poll_once("auth").unwrap().backpressure);
    *full.lock().unwrap() = false;
    assert!(!source.poll_once("auth").unwrap().backpressure);

    let mut words: Vec<String> = sink
        .records()
        .iter()
        .map(|record| first_word(record))
        .collect();
    words.dedup();
    assert_eq!(words, ["one", "two", "three"]);
    let status = &source.snapshot()[0];
    assert_eq!(
        (status.queued, status.backpressure, status.state.as_str()),
        (3, 2, "running")
    );
}

#[test]
fn durable_cursor_resumes_after_restart_and_a_crash_before_commit_replays_the_same_ids() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    let queue = directory.path().join("queue.db");
    std::fs::write(&path, format!("{}{}", line("one"), line("two"))).unwrap();
    let store = Arc::new(SqliteSourceCursorStore::new(&queue).unwrap());
    store.initialize().unwrap();

    let first = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let crashed = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        first.clone(),
        Arc::new(FailingCommit(Arc::clone(&store))),
        None,
    );
    assert_eq!(
        crashed.poll_once("auth").unwrap_err().code,
        failures::SOURCE_FAILED
    );
    assert!(store.read("file:auth").unwrap().is_none());

    let first_ids: Vec<String> = first
        .records()
        .iter()
        .map(|record| field(record, "id"))
        .collect();
    let known = first_ids.clone();
    let second = FakeSink::new(move |record| {
        Ok(if known.contains(&field(record, "id")) {
            SubmitOutcome::Duplicate
        } else {
            SubmitOutcome::Queued
        })
    });
    let restarted = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        second.clone(),
        Arc::new(SqliteSourceCursorStore::new(&queue).unwrap()),
        None,
    );
    restarted.poll_once("auth").unwrap();
    let second_ids: Vec<String> = second
        .records()
        .iter()
        .map(|record| field(record, "id"))
        .collect();
    assert_eq!(first_ids, second_ids);
    assert_eq!(restarted.snapshot()[0].duplicates, 2);

    std::fs::write(
        &path,
        format!("{}{}{}", line("one"), line("two"), line("three")),
    )
    .unwrap();
    let third = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let resumed = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        third.clone(),
        Arc::new(SqliteSourceCursorStore::new(&queue).unwrap()),
        None,
    );
    resumed.poll_once("auth").unwrap();
    let records = third.records();
    assert_eq!(records.len(), 1);
    assert_eq!(first_word(&records[0]), "three");
}

#[test]
fn malformed_oversized_and_rejected_lines_are_counted_dropped_and_consumed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("app.jsonl");
    let mut content =
        br#"{"event":"login","pad":"0123456789012345678901234567890123456789012345"}"#.to_vec();
    content.push(b'\n');
    content.extend_from_slice(b"not json\n");
    content.extend_from_slice(b"{\"a\":\"\xff\"}\n");
    content.extend_from_slice(format!("{{\"big\":\"{}\"}}\n", "x".repeat(400)).as_bytes());
    content.extend_from_slice(b"{\"event\":\"other\"}\n");
    std::fs::write(&path, &content).unwrap();
    let sink = FakeSink::new(|record| {
        Ok(if record.contains("login") {
            SubmitOutcome::Rejected
        } else {
            SubmitOutcome::Invalid
        })
    });
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        configuration(directory.path(), &path, "beginning", "json-lines", 256),
        sink.clone(),
        cursors.clone(),
        None,
    );

    source.poll_once("auth").unwrap();

    assert_eq!(sink.records().len(), 2);
    let status = &source.snapshot()[0];
    assert_eq!(
        (
            status.malformed,
            status.oversized,
            status.rejected,
            status.parser_errors
        ),
        (2, 1, 1, 1)
    );
    let stored = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(stored.offset, content.len() as i64);
    let record: serde_json::Value = serde_json::from_str(&sink.records()[0]).unwrap();
    assert_eq!(record["json"]["event"], "login");
}

#[test]
fn bounded_polls_read_at_most_the_line_limit_and_ask_for_more() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(
        &path,
        (0..5)
            .map(|index| line(&format!("line-{index}")))
            .collect::<String>(),
    )
    .unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let mut configuration = text(directory.path(), &path, "beginning");
    configuration.max_lines_per_batch = 2;
    let source = FileTailSource::new(
        configuration,
        sink.clone(),
        Arc::new(MemoryCursors::default()),
        None,
    );

    let shape = |result: bower_source_file::PollResult| (result.lines, result.more);
    assert_eq!(shape(source.poll_once("auth").unwrap()), (2, true));
    assert_eq!(shape(source.poll_once("auth").unwrap()), (2, true));
    assert_eq!(shape(source.poll_once("auth").unwrap()), (1, false));
    assert_eq!(sink.records().len(), 5);
}

#[test]
fn rotation_is_counted_and_a_missed_rotation_is_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    let rotated = directory.path().join("auth.log.1");
    std::fs::write(&path, line("first-1")).unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        Arc::new(MemoryCursors::default()),
        None,
    );
    source.poll_once("auth").unwrap();

    std::fs::write(&path, format!("{}{}", line("first-1"), line("first-2"))).unwrap();
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, line("second-1")).unwrap();
    // Drain path.1, wait one unchanged poll (grace), then move to the new file.
    assert!(!source.poll_once("auth").unwrap().more);
    assert!(source.poll_once("auth").unwrap().more);
    source.poll_once("auth").unwrap();

    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, line("third-1")).unwrap();
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::write(&path, line("fourth-1")).unwrap();
    source.poll_once("auth").unwrap();

    let words: Vec<String> = sink
        .records()
        .iter()
        .map(|record| first_word(record))
        .collect();
    assert_eq!(words, ["first-1", "first-2", "second-1", "fourth-1"]);
    let status = &source.snapshot()[0];
    assert_eq!((status.rotations, status.rotation_gaps), (1, 1));
}

#[test]
fn missing_file_waits_and_is_read_from_its_start_once_created() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("later").join("auth.log");
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let source = FileTailSource::new(
        text(directory.path(), &path, "end"),
        sink.clone(),
        Arc::new(MemoryCursors::default()),
        None,
    );

    source.poll_once("auth").unwrap();
    assert_eq!(source.snapshot()[0].state, "waiting");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, line("created")).unwrap();
    source.poll_once("auth").unwrap();

    assert_eq!(sink.records().len(), 1);
    assert_eq!(source.snapshot()[0].state, "running");
}

#[cfg(unix)]
#[test]
fn path_guards_refuse_links_directories_special_files_and_paths_outside_the_roots() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = directory.path().join("logs");
    std::fs::create_dir_all(root.join("app")).unwrap();
    let secret = outside.path().join("shadow");
    std::fs::write(&secret, line("secret")).unwrap();
    let inside = root.join("app").join("real.log");
    std::fs::write(&inside, line("real")).unwrap();
    symlink(&secret, root.join("escape.log")).unwrap();
    symlink(&inside, root.join("inside.log")).unwrap();
    symlink(root.join("inside.log"), root.join("chain.log")).unwrap();
    symlink(outside.path(), root.join("linked")).unwrap();
    symlink(root.join("app"), root.join("linked-inside")).unwrap();
    let roots = vec![root.to_str().unwrap().to_owned()];
    let at = |path: &Path, allow: bool| paths::resolve(path.to_str().unwrap(), &roots, allow);

    assert_eq!(at(&inside, false).0, PathState::Ready);
    assert_eq!(
        at(&root.join("app").join("none.log"), false).0,
        PathState::Missing
    );
    assert_eq!(
        at(&root.join("none").join("a.log"), false).0,
        PathState::Missing
    );
    assert_eq!(at(&secret, true).0, PathState::Refused);
    assert_eq!(at(&root.join("app"), false).0, PathState::Refused);
    assert_eq!(at(&root.join("inside.log"), false).0, PathState::Refused);
    assert_eq!(
        at(&root.join("inside.log"), true),
        (PathState::Ready, inside.to_str().unwrap().to_owned())
    );
    assert_eq!(at(&root.join("escape.log"), true).0, PathState::Refused);
    assert_eq!(at(&root.join("chain.log"), true).0, PathState::Refused);
    assert_eq!(
        at(&root.join("linked").join("shadow"), true).0,
        PathState::Refused
    );
    assert_eq!(
        at(&root.join("linked-inside").join("real.log"), true).0,
        PathState::Refused
    );
}

/// Rust-only: a FIFO is refused outright. C# cannot tell it from an empty file and never
/// opens it either (shorter than the fingerprint), so neither runtime blocks on it.
#[cfg(unix)]
#[test]
fn fifo_is_refused_and_never_opened() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("pipe.log");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let roots = vec![directory.path().to_str().unwrap().to_owned()];
    assert_eq!(
        paths::resolve(fifo.to_str().unwrap(), &roots, false).0,
        PathState::Refused
    );
    assert_eq!(bower_source_file::reader::fingerprint(&fifo).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn refused_path_is_never_read_and_reports_the_failure_code() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("shadow");
    std::fs::write(&secret, line("root:secret-marker")).unwrap();
    let path = directory.path().join("auth.log");
    std::os::unix::fs::symlink(&secret, &path).unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        cursors.clone(),
        None,
    );

    assert_eq!(
        source.poll_once("auth").unwrap_err().code,
        failures::PATH_REFUSED
    );
    assert!(sink.records().is_empty());
    assert!(cursors.value("file:auth").is_none());
    let status = &source.snapshot()[0];
    assert_eq!(
        (status.state.as_str(), status.read_errors),
        (failures::PATH_REFUSED, 1)
    );
}

#[test]
fn sink_failure_commits_handled_lines_and_retries_the_failed_one() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, format!("{}{}", line("one"), line("fail"))).unwrap();
    let sink = FakeSink::new(|record| {
        if record.contains("fail") {
            Err(SinkFailure)
        } else {
            Ok(SubmitOutcome::Queued)
        }
    });
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink,
        cursors.clone(),
        None,
    );

    assert_eq!(
        source.poll_once("auth").unwrap_err().code,
        failures::SUBMIT_FAILED
    );
    let stored = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(stored.offset, line("one").len() as i64);
    assert_eq!(source.snapshot()[0].submit_failures, 1);
}

#[test]
fn stopping_between_lines_commits_only_handled_lines() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(
        &path,
        format!("{}{}{}", line("one"), line("stop"), line("three")),
    )
    .unwrap();
    let cursors = Arc::new(MemoryCursors::default());
    let holder: Arc<Mutex<Option<Arc<FileTailSource>>>> = Arc::new(Mutex::new(None));
    let trigger = Arc::clone(&holder);
    let sink = FakeSink::new(move |record| {
        if record.contains("stop")
            && let Some(source) = trigger.lock().unwrap().as_ref()
        {
            source.request_stop();
        }
        Ok(SubmitOutcome::Queued)
    });
    let source = Arc::new(FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        cursors.clone(),
        None,
    ));
    *holder.lock().unwrap() = Some(Arc::clone(&source));

    let result = source.poll_once("auth").unwrap();

    assert_eq!((result.lines, result.more), (2, false));
    assert_eq!(sink.records().len(), 2);
    let stored = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(
        stored.offset,
        (line("one").len() + line("stop").len()) as i64
    );
    *holder.lock().unwrap() = None;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_loop_tails_new_lines_until_stopped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, line("history")).unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let source = FileTailSource::new(
        text(directory.path(), &path, "end"),
        sink.clone(),
        Arc::new(MemoryCursors::default()),
        None,
    );
    let metrics = source.metrics();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(source.run(receiver));

    wait_for(|| metrics.snapshot()[0].offset.is_some()).await;
    std::fs::write(&path, format!("{}{}", line("history"), line("live"))).unwrap();
    wait_for(|| !sink.records().is_empty()).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(first_word(&sink.records()[0]), "live");
    assert_eq!(metrics.snapshot()[0].state, "stopped");
}

async fn wait_for(condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn configuration_loads_defaults_and_rejects_oversized_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file.json");
    std::fs::write(
        &path,
        r#"{"apiVersion":"bower.security/v1","kind":"FileTailSource","allowedRoots":["/var/log"],
           "inputs":[{"id":"auth","path":"/var/log/auth.log","route":{"pack":"linux-authlog-ssh","parser":0}}]}"#,
    )
    .unwrap();
    let configuration = bower_source_file::config::load_file(&path).unwrap();
    let input = configuration.inputs().next().unwrap();
    assert_eq!(
        (
            input.format.as_str(),
            input.start_at.as_str(),
            input.max_line_bytes,
            input.allow_symlink
        ),
        ("text", "end", 16_384, false)
    );
    assert_eq!(
        (
            configuration.poll_interval_milliseconds,
            configuration.max_lines_per_batch,
            configuration.max_bytes_per_batch
        ),
        (1_000, 256, 1_048_576)
    );
    assert_eq!(input.source_id(), "file:auth");
    std::fs::write(&path, " ".repeat(262_145)).unwrap();
    assert!(matches!(
        bower_source_file::config::load_file(&path),
        Err(bower_source_file::config::ConfigError::InvalidData(_))
    ));
    assert_eq!(
        bower_source_file::config::load_file(directory.path().join("none.json")).unwrap_err(),
        bower_source_file::config::ConfigError::FileNotFound
    );
}

/// C# `RotatedFileThatBecomesALink_FailsThePollWithoutReadingIt`.
#[cfg(unix)]
#[test]
fn rotated_file_that_becomes_a_link_fails_the_poll_without_reading_it() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, line("first-1")).unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        cursors.clone(),
        None,
    );
    source.poll_once("auth").unwrap();
    let secret = outside.path().join("shadow");
    std::fs::write(&secret, line("root:secret-marker")).unwrap();
    std::fs::rename(&path, outside.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(&secret, directory.path().join("auth.log.1")).unwrap();
    std::fs::write(&path, line("second-1")).unwrap();

    assert_eq!(
        source.poll_once("auth").unwrap_err().code,
        failures::PATH_REFUSED
    );
    assert!(
        !sink
            .records()
            .iter()
            .any(|record| record.contains("secret-marker"))
    );
    let stored = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(stored.offset, line("first-1").len() as i64);
}

/// C# `StopInsideAnOversizedLine_RewindsAndKeepsDiscarding`.
#[test]
fn stop_inside_an_oversized_line_rewinds_and_keeps_discarding() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, format!("{}{}", line("before"), "o".repeat(300))).unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let cursors = Arc::new(MemoryCursors::default());
    let configuration = configuration(directory.path(), &path, "beginning", "text", 256);
    FileTailSource::new(configuration.clone(), sink.clone(), cursors.clone(), None)
        .poll_once("auth")
        .unwrap();
    let discarding = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert!(discarding.discarding);
    let mut content = std::fs::read(&path).unwrap();
    content.extend_from_slice(format!("ooo\n{}", line("after")).as_bytes());
    std::fs::write(&path, content).unwrap();

    let stopping = FileTailSource::new(configuration, sink.clone(), cursors.clone(), None);
    stopping.request_stop();
    let result = stopping.poll_once("auth").unwrap();

    assert_eq!(result.lines, 0);
    let stored = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(
        (stored.offset, stored.discarding),
        (discarding.offset, true)
    );
    assert_eq!(sink.records().len(), 1);
}

/// C# `FullQueueWhileDrainingTheRotatedFile_RewindsIntoItAndLosesNothing`.
#[test]
fn full_queue_while_draining_the_rotated_file_rewinds_into_it_and_loses_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, line("first-1")).unwrap();
    let full = Arc::new(Mutex::new(false));
    let gate = Arc::clone(&full);
    let sink = FakeSink::new(move |record| {
        Ok(if *gate.lock().unwrap() && record.contains("first-3") {
            SubmitOutcome::Unavailable
        } else {
            SubmitOutcome::Queued
        })
    });
    let cursors = Arc::new(MemoryCursors::default());
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        cursors.clone(),
        None,
    );
    source.poll_once("auth").unwrap();
    let generation = Cursor::deserialize(&cursors.value("file:auth").unwrap())
        .unwrap()
        .fingerprint;
    std::fs::write(
        &path,
        format!(
            "{}{}{}{}",
            line("first-1"),
            line("first-2"),
            line("first-3"),
            line("first-4")
        ),
    )
    .unwrap();
    std::fs::rename(&path, directory.path().join("auth.log.1")).unwrap();
    std::fs::write(&path, line("second-1")).unwrap();

    *full.lock().unwrap() = true;
    assert!(source.poll_once("auth").unwrap().backpressure);
    let rewound = Cursor::deserialize(&cursors.value("file:auth").unwrap()).unwrap();
    assert_eq!(
        (rewound.fingerprint, rewound.offset),
        (generation, line("first-1").len() as i64 * 2)
    );
    *full.lock().unwrap() = false;
    for _ in 0..4 {
        source.poll_once("auth").unwrap();
    }
    let mut words: Vec<String> = sink
        .records()
        .iter()
        .map(|record| first_word(record))
        .collect();
    words.dedup();
    assert_eq!(
        words,
        ["first-1", "first-2", "first-3", "first-4", "second-1"]
    );
    let status = &source.snapshot()[0];
    assert_eq!((status.queued, status.rotation_gaps), (5, 0));
}

/// C# `AllowedLinkToAnotherInputsFile_IsRefusedAtLoad`.
#[cfg(unix)]
#[test]
fn allowed_link_to_another_inputs_file_is_refused_at_load() {
    let directory = tempfile::tempdir().unwrap();
    let auth = directory.path().join("auth.log");
    let linked = directory.path().join("alias.log");
    std::fs::write(&auth, line("one")).unwrap();
    std::os::unix::fs::symlink(directory.path().join("auth.log.1"), &linked).unwrap();
    let file = directory.path().join("file.json");
    std::fs::write(
        &file,
        serde_json::json!({
            "apiVersion": "bower.security/v1",
            "kind": "FileTailSource",
            "allowedRoots": [directory.path().to_str().unwrap()],
            "inputs": [
                {"id": "auth", "path": auth.to_str().unwrap(), "route": {"pack": "p", "parser": 0}},
                {"id": "alias", "path": linked.to_str().unwrap(), "allowSymlink": true, "route": {"pack": "p", "parser": 0}}
            ]
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(
        bower_source_file::config::load_file(&file).unwrap_err(),
        bower_source_file::config::ConfigError::InvalidData(
            "File tail input alias: allowSymlink target is another input's file or rotated file."
                .into()
        )
    );
}

/// A busy cursor store is backpressure, retried after the retry delay (C#
/// `IsTransientStorageFailure`), never a source failure.
#[test]
fn busy_cursor_store_is_backpressure_not_a_failure() {
    struct Busy;
    impl SourceCursorStore for Busy {
        fn read(&self, _: &str) -> StoreResult<Option<SourceCursorSnapshot>> {
            Err(StoreError::Storage("busy".into()))
        }
        fn try_advance(&self, _: &str, _: i64, _: &str, _: Timestamp) -> StoreResult<bool> {
            Err(StoreError::Storage("busy".into()))
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.log");
    std::fs::write(&path, line("one")).unwrap();
    let sink = FakeSink::new(|_| Ok(SubmitOutcome::Queued));
    let source = FileTailSource::new(
        text(directory.path(), &path, "beginning"),
        sink.clone(),
        Arc::new(Busy),
        None,
    )
    .with_transient_storage(
        |error| matches!(error, StoreError::Storage(message) if message == "busy"),
    );

    let result = source.poll_once("auth").unwrap();

    assert!(result.backpressure);
    let status = &source.snapshot()[0];
    assert_eq!(
        (status.state.as_str(), status.backpressure),
        ("backpressure", 1)
    );
    assert!(sink.records().is_empty());
}
