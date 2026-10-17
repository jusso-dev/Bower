//! Port of `AmaSpoolOutputTests` plus naming, size-bound and permission checks.

use bower_contracts::{OutputAdapter, QueueState, QueuedEvent, time};
use bower_output_ama_spool::{AmaSpoolOptions, AmaSpoolOutput};

fn event(id: &str, payload: &str) -> QueuedEvent {
    QueuedEvent {
        event_id: id.to_owned(),
        fingerprint: format!("sha256:{id}"),
        payload: payload.to_owned(),
        received_at: time::now(),
        state: QueueState::Queued,
        delivery_attempts: 0,
    }
}

fn files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    entries
}

fn options(root: &std::path::Path, maximum: i64) -> AmaSpoolOptions {
    AmaSpoolOptions {
        maximum_file_bytes: maximum,
        ..AmaSpoolOptions::new(
            "ama",
            "collector-1",
            "Custom-BowerSecurity",
            root.join("active"),
            root.join("ready"),
        )
    }
}

#[tokio::test]
async fn deliver_writes_complete_utf8_json_lines_to_ready_directory() {
    let directory = tempfile::tempdir().unwrap();
    let output = AmaSpoolOutput::new(options(directory.path(), 4_096)).unwrap();
    let events = [
        event("event-1", r#"{"eventId":"event-1"}"#),
        event("event-2", r#"{"eventId":"event-2"}"#),
    ];

    let result = output.deliver(&events).await;

    assert_eq!(result.acknowledged_event_ids.len(), 2);
    assert!(result.failures.is_empty());
    assert!(files(&directory.path().join("active")).is_empty());
    let ready = files(&directory.path().join("ready"));
    assert_eq!(ready.len(), 1);
    assert_eq!(
        ready[0].file_name().unwrap().to_str().unwrap(),
        "collector-1-Custom-BowerSecurity-00000000000000000001.jsonl"
    );
    let text = std::fs::read_to_string(&ready[0]).unwrap();
    assert_eq!(
        text,
        "{\"eventId\":\"event-1\"}\n{\"eventId\":\"event-2\"}\n"
    );
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        Some("ama-spool:collector-1:1")
    );
}

#[tokio::test]
async fn deliver_rolls_files_at_limit_and_rejects_oversized_records() {
    let directory = tempfile::tempdir().unwrap();
    let output = AmaSpoolOutput::new(options(directory.path(), 1_024)).unwrap();
    let half = format!(r#"{{"p":"{}"}}"#, "x".repeat(500));
    let events = [
        event("a", &half),
        event("b", &half),
        event("huge", &"y".repeat(1_024)),
        event("c", &half),
    ];

    let result = output.deliver(&events).await;

    assert_eq!(result.acknowledged_event_ids, ["a", "b", "c"]);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].event_id, "huge");
    assert_eq!(result.failures[0].code, "record-exceeds-ama-file-limit");
    assert!(!result.failures[0].is_retryable);
    let ready = files(&directory.path().join("ready"));
    assert_eq!(ready.len(), 2);
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        Some("ama-spool:collector-1:2")
    );
}

#[tokio::test]
async fn deliver_of_empty_batch_writes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let output = AmaSpoolOutput::new(options(directory.path(), 4_096)).unwrap();
    let result = output.deliver(&[]).await;
    assert!(
        result.acknowledged_event_ids.is_empty() && result.destination_acknowledgement.is_none()
    );
    assert!(files(&directory.path().join("ready")).is_empty());
}

#[tokio::test]
async fn existing_ready_file_is_never_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let output = AmaSpoolOutput::new(options(directory.path(), 4_096)).unwrap();
    let ready = directory
        .path()
        .join("ready")
        .join("collector-1-Custom-BowerSecurity-00000000000000000001.jsonl");
    std::fs::write(&ready, "existing\n").unwrap();

    let result = output.deliver(&[event("a", "{}")]).await;

    assert!(result.acknowledged_event_ids.is_empty());
    assert_eq!(result.failures[0].code, "output-adapter-failure");
    assert!(result.failures[0].is_retryable);
    assert_eq!(std::fs::read_to_string(&ready).unwrap(), "existing\n");
}

#[test]
fn options_are_validated() {
    let directory = tempfile::tempdir().unwrap();
    let same = AmaSpoolOptions::new(
        "ama",
        "c",
        "s",
        directory.path().join("x"),
        directory.path().join("y/../x"),
    );
    assert!(AmaSpoolOutput::new(same).is_err());
    assert!(AmaSpoolOutput::new(options(directory.path(), 1_023)).is_err());
    let blank = AmaSpoolOptions {
        id: " ".to_owned(),
        ..options(directory.path(), 4_096)
    };
    assert!(AmaSpoolOutput::new(blank).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn directories_and_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let output = AmaSpoolOutput::new(options(directory.path(), 4_096)).unwrap();
    output.deliver(&[event("a", "{}")]).await;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&directory.path().join("active")), 0o700);
    assert_eq!(mode(&directory.path().join("ready")), 0o700);
    assert_eq!(mode(&files(&directory.path().join("ready"))[0]), 0o600);
}
