//! Shared vectors with C# `FileTailSourceTests` (`tests/fixtures/file-tail-vectors.json`):
//! record shape and ids, rotation and truncation sequences, malformed and oversized lines
//! and configuration errors must match the specification exactly.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use bower_source_file::config::{self, InputOptions, Route};
use bower_source_file::reader::{self, Batch, Cursor, Line, ReaderOptions};
use bower_source_file::record;
use serde_json::Value;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/file-tail-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn records_match_the_csharp_specification() {
    let fixture = fixture();
    let input_id = fixture["input"]["id"].as_str().unwrap();
    let input_path = fixture["input"]["path"].as_str().unwrap();
    let fingerprint = fixture["fingerprint"].as_str().unwrap();
    let read_at = bower_contracts::time::parse(fixture["readAt"].as_str().unwrap()).unwrap();
    let vectors = fixture["records"].as_array().unwrap();
    assert!(vectors.len() >= 15);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let bytes = match vector["line"].as_str() {
            Some(text) => text.as_bytes().to_vec(),
            None => base64::engine::general_purpose::STANDARD
                .decode(vector["lineBase64"].as_str().unwrap())
                .unwrap(),
        };
        let input = InputOptions {
            id: input_id.into(),
            path: input_path.into(),
            route: Route {
                pack: "pack".into(),
                parser: 0,
            },
            format: vector["format"].as_str().unwrap().into(),
            start_at: "end".into(),
            max_line_bytes: config::DEFAULT_MAX_LINE_BYTES,
            allow_symlink: false,
        };
        let offset = vector["offset"].as_i64().unwrap();
        let line = Line {
            end_offset: offset + bytes.len() as i64 + 1,
            bytes,
            fingerprint: fingerprint.into(),
            start_offset: offset,
            oversized: false,
            continues_discard: false,
        };
        let expect = &vector["expect"];
        match record::build(&input, &line, &read_at) {
            Ok(record) => assert_eq!(Some(record.as_str()), expect["record"].as_str(), "{name}"),
            Err(failure) => assert_eq!(Some(failure), expect["failure"].as_str(), "{name}"),
        }
    }
}

#[test]
fn sequences_match_the_csharp_specification() {
    let fixture = fixture();
    let sequences = fixture["sequences"].as_array().unwrap();
    assert!(sequences.len() >= 15);
    for sequence in sequences {
        let name = sequence["name"].as_str().unwrap();
        let options = &sequence["options"];
        let reader = ReaderOptions {
            start_at_end: options["startAtEnd"].as_bool().unwrap(),
            max_line_bytes: options["maxLineBytes"].as_u64().unwrap_or(256) as usize,
            max_lines_per_batch: options["maxLinesPerBatch"].as_u64().unwrap_or(256) as usize,
            max_bytes_per_batch: options["maxBytesPerBatch"].as_u64().unwrap_or(1_048_576),
            rotation_grace_polls: options["rotationGracePolls"].as_i64().unwrap_or(1) as i32,
            rotation_drain_max_polls: options["rotationDrainMaxPolls"]
                .as_i64()
                .unwrap_or(i64::from(config::DEFAULT_ROTATION_DRAIN_MAX_POLLS))
                as i32,
            // Identities alone decide unless the sequence uses device and inode numbers
            // ("fileIds"): real ones here, modelled by the C# harness on every platform.
            use_file_ids: options["fileIds"].as_bool().unwrap_or(false),
        };
        if cfg!(not(unix)) && reader.use_file_ids {
            continue; // No device and inode numbers to compare.
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.log");
        let rotated = directory.path().join("app.log.1");
        // With real device and inode numbers, a file about to be unlinked or overwritten stays
        // hard-linked here, so a later file is never handed its number again (ext4 reuses
        // freed numbers at once): a new file always has a new number, as the C# model assumes.
        let kept = directory.path().join("kept");
        std::fs::create_dir(&kept).unwrap();
        let mut generation = 0;
        let mut keep = |file: &Path| {
            if reader.use_file_ids && file.exists() {
                generation += 1;
                std::fs::hard_link(file, kept.join(generation.to_string())).unwrap();
            }
        };
        let mut cursor: Option<Cursor> = None;
        for (index, step) in sequence["steps"].as_array().unwrap().iter().enumerate() {
            if let Some(text) = step["write"].as_str() {
                // In place (same file), as a writer truncating and rewriting would.
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(false)
                    .open(&path)
                    .unwrap();
                file.set_len(0).unwrap();
                file.write_all(text.as_bytes()).unwrap();
            } else if let Some(text) = step["append"].as_str() {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .unwrap();
                file.write_all(text.as_bytes()).unwrap();
            } else if let Some(text) = step["appendRotated"].as_str() {
                // A writer that has not reopened its file yet keeps writing to path.1.
                let mut file = OpenOptions::new().append(true).open(&rotated).unwrap();
                file.write_all(text.as_bytes()).unwrap();
            } else if step.get("deleteRotated").is_some() {
                keep(&rotated);
                std::fs::remove_file(&rotated).unwrap();
            } else if step.get("rename").is_some() {
                keep(&rotated);
                std::fs::rename(&path, &rotated).unwrap();
            } else if let Some(text) = step["replace"].as_str() {
                // Other content at a new inode (a new generation after a rotation Bower missed).
                keep(&path);
                let replacement = directory.path().join("app.log.replace");
                std::fs::write(&replacement, text).unwrap();
                std::fs::rename(&replacement, &path).unwrap();
            } else if step.get("restore").is_some() {
                // The same content at a new inode, as a restore from backup or a copy leaves it.
                keep(&path);
                let restored = directory.path().join("app.log.restore");
                std::fs::write(&restored, std::fs::read(&path).unwrap()).unwrap();
                std::fs::rename(&restored, &path).unwrap();
            } else if step.get("copytruncate").is_some() {
                keep(&rotated);
                std::fs::copy(&path, &rotated).unwrap();
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
            } else {
                let batch = reader::read(
                    path.exists().then_some(path.as_path()),
                    rotated.exists().then_some(rotated.as_path()),
                    cursor.as_ref(),
                    &reader,
                    None,
                )
                .unwrap();
                assert_eq!(describe(&batch), step["read"], "{name}, step {index}");
                cursor = Some(batch.cursor);
            }
        }
    }
}

fn describe(batch: &Batch) -> Value {
    let lines: Vec<Value> = batch
        .lines
        .iter()
        .map(|line| {
            if line.oversized {
                serde_json::json!({"oversized": true, "start": line.start_offset, "end": line.end_offset})
            } else {
                serde_json::json!({
                    "text": String::from_utf8(line.bytes.clone()).unwrap(),
                    "start": line.start_offset,
                    "end": line.end_offset
                })
            }
        })
        .collect();
    serde_json::json!({
        "lines": lines,
        "provisional": batch.cursor.fingerprint.is_empty(),
        "offset": batch.cursor.offset,
        "discarding": batch.cursor.discarding,
        "drain": batch.cursor.drain,
        "abandoned": batch.cursor.abandoned.is_some(),
        "rotated": batch.rotated,
        "gap": batch.gap,
        "more": batch.more
    })
}

#[test]
fn configuration_errors_match_the_csharp_specification() {
    let fixture = fixture();
    let vectors = fixture["config"].as_array().unwrap();
    assert!(vectors.len() >= 40);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let json = match vector["text"].as_str() {
            Some(text) => text.to_owned(),
            None => vector["config"].to_string(),
        };
        let expect = &vector["expect"];
        match config::parse(&json) {
            Ok(_) => assert_eq!(expect["valid"], Value::Bool(true), "{name}"),
            Err(config::ConfigError::InvalidData(message)) => {
                if let Some(prefix) = expect["errorPrefix"].as_str() {
                    assert!(message.starts_with(prefix), "{name}: {message}");
                } else {
                    assert_eq!(Some(message.as_str()), expect["error"].as_str(), "{name}");
                }
            }
            Err(other) => panic!("{name}: {other}"),
        }
    }
}

#[test]
fn cursor_json_matches_csharp() {
    assert_eq!(
        Cursor::new("", 0).serialize(),
        r#"{"schemaVersion":2,"fingerprint":"","offset":0}"#
    );
    let cursor = Cursor {
        discarding: true,
        ..Cursor::new("a".repeat(64), 42)
    };
    assert_eq!(Cursor::deserialize(&cursor.serialize()), Some(cursor));
    assert_eq!(
        Cursor::deserialize(r#"{"schemaVersion":3,"fingerprint":"","offset":0}"#),
        None
    );
    assert_eq!(
        Cursor::deserialize(r#"{"schemaVersion":2,"fingerprint":"zz","offset":0}"#),
        None
    );
    assert_eq!(
        Cursor::deserialize(r#"{"schemaVersion":2,"fingerprint":"","offset":-1}"#),
        None
    );
    assert_eq!(Cursor::deserialize("not json"), None);
    // Every field, in the order both runtimes write it (C# Cursor_RoundTripsAndRefusesValuesThisVersionDidNotWrite).
    let full = format!(
        r#"{{"schemaVersion":2,"fingerprint":"{}","offset":42,"discarding":true,"fileId":"1:2","drain":"rename","observedLength":10,"observedWriteTime":11,"stablePolls":1,"drainPolls":3,"drainLength":12,"abandoned":"{}","abandonedLength":13}}"#,
        "a".repeat(64),
        "b".repeat(64)
    );
    assert_eq!(Cursor::deserialize(&full).unwrap().serialize(), full);
    // An "anchor" from an earlier pre-release build is ignored, not refused, and dropped on the
    // next commit (C# and Rust both skip unknown members).
    let with_anchor = format!(
        r#"{},"anchor":"{}"}}"#,
        &full[..full.len() - 1],
        "c".repeat(64)
    );
    assert_eq!(Cursor::deserialize(&with_anchor).unwrap().serialize(), full);
    assert_eq!(
        Cursor::deserialize(r#"{"schemaVersion":2,"fingerprint":"","offset":0,"drainLength":5}"#),
        None
    );
}
