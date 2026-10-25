//! Cross-implementation vector produced by `Bower.Output.AmaSpool` (C#): the same
//! batch (Unicode payload, roll-over at the 1 KiB limit, an oversized record) and
//! the same non-ASCII collector and stream names must yield identical file names,
//! file bytes, acknowledgements and failures.

use std::path::PathBuf;

use bower_contracts::{OutputAdapter, QueueState, QueuedEvent, time};
use bower_output_ama_spool::{AmaSpoolOptions, AmaSpoolOutput};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn event(id: &str, payload: String) -> QueuedEvent {
    QueuedEvent {
        lease_token: None,
        event_id: id.to_owned(),
        fingerprint: format!("sha256:{id}"),
        payload,
        received_at: time::now(),
        state: QueueState::Queued,
        delivery_attempts: 0,
        suppression: None,
    }
}

#[tokio::test]
async fn spool_files_match_csharp() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csharp-vectors.json");
    let vectors: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let expected = &vectors["ama"];
    let directory = tempfile::tempdir().unwrap();
    let output = AmaSpoolOutput::new(AmaSpoolOptions {
        maximum_file_bytes: 1_024,
        ..AmaSpoolOptions::new(
            "ama",
            expected["collectorId"].as_str().unwrap(),
            expected["streamName"].as_str().unwrap(),
            directory.path().join("active"),
            directory.path().join("ready"),
        )
    })
    .unwrap();

    let result = output
        .deliver(&[
            event("a", r#"{"eventId":"é😀"}"#.to_owned()),
            event("b", "y".repeat(600)),
            event("c", "z".repeat(1_023)),
            event("d", "w".repeat(1_024)),
        ])
        .await;

    assert_eq!(
        serde_json::json!(result.acknowledged_event_ids),
        expected["acknowledged"]
    );
    let failures: Vec<String> = result
        .failures
        .iter()
        .map(|failure| {
            // C# formats bool as "True"/"False".
            let retryable = if failure.is_retryable {
                "True"
            } else {
                "False"
            };
            format!("{}:{}:{retryable}", failure.event_id, failure.code)
        })
        .collect();
    assert_eq!(serde_json::json!(failures), expected["failures"]);
    assert_eq!(
        result.destination_acknowledgement.as_deref(),
        expected["acknowledgement"].as_str()
    );

    let mut files: Vec<PathBuf> = std::fs::read_dir(directory.path().join("ready"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let actual: Vec<Value> = files
        .iter()
        .map(|file| {
            serde_json::json!({
                "name": file.file_name().unwrap().to_str().unwrap(),
                "sha256": hex::encode(Sha256::digest(std::fs::read(file).unwrap())),
            })
        })
        .collect();
    assert_eq!(Value::Array(actual), expected["files"]);
}
