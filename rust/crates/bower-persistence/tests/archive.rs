//! Ports of `QueueArchiveTests` and `QueueArchiveParityTests` plus Rust-only checks of
//! the on-disk format and the fail-closed paths.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::Clock;
use bower_contracts::{DurableEventStore, LedgerHead, StoreError};
use bower_persistence::{
    ArchiveError, ArchiveManifest, MANIFEST_KIND, MAXIMUM_EVENTS_PER_SEGMENT, QueueArchive,
    SqliteEventStore, chain_hash, genesis_hash, payload_hash,
};
use chrono::Duration as Span;
use common::*;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};

fn archive_path(directory: &Path) -> PathBuf {
    directory.join("archive")
}

fn new_archive(directory: &Path, clock: &Arc<FakeClock>) -> QueueArchive {
    QueueArchive::new(
        archive_path(directory),
        "collector-1",
        Some(clock.clone() as Arc<dyn Clock>),
    )
    .unwrap()
}

/// `QueueArchiveTests.EnqueueAsync`.
fn enqueue_range(store: &SqliteEventStore, first: i32, last: i32, clock: &FakeClock) {
    for index in first..=last {
        clock.advance(Span::seconds(1));
        store
            .enqueue(&event(
                &format!("event-{index}"),
                &format!("sha256:event-{index}"),
                &format!("{{\"eventId\":\"event-{index}\"}}"),
                clock.now(),
            ))
            .unwrap();
    }
}

fn deliver_all(store: &SqliteEventStore) {
    let leased = store.lease(100, Duration::from_secs(60)).unwrap();
    let ids: Vec<String> = leased.iter().map(|item| item.event_id.clone()).collect();
    let tokens: HashMap<String, String> = leased
        .iter()
        .map(|item| (item.event_id.clone(), item.lease_token.clone().unwrap()))
        .collect();
    store
        .mark_delivered_batch(&ids, "test-ack", &tokens)
        .unwrap();
}

fn read_segment(path: &Path) -> Vec<String> {
    let mut text = String::new();
    MultiGzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    text.split('\n')
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn write_segment(path: &Path, lines: &[String]) {
    let mut gzip = GzEncoder::new(
        std::fs::File::create(path).unwrap(),
        flate2::Compression::best(),
    );
    for line in lines {
        gzip.write_all(line.as_bytes()).unwrap();
        gzip.write_all(b"\n").unwrap();
    }
    gzip.finish().unwrap();
}

fn file_digest(path: &Path) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
    )
}

fn copy_directory(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
    }
}

fn csharp_anchor(directory: &Path) -> LedgerHead {
    let text = std::fs::read_to_string(directory.join("anchor.txt")).unwrap();
    let (sequence, hash) = text.trim().split_once(':').unwrap();
    LedgerHead {
        sequence: sequence.parse().unwrap(),
        hash: hash.to_owned(),
    }
}

#[test]
fn csharp_archive_fixture_verifies() {
    let directory = tempfile::tempdir().unwrap();
    let copy = directory.path().join("archive-csharp");
    copy_directory(&fixture("archive-csharp"), &copy);
    let anchor = csharp_anchor(&copy);
    let archive = QueueArchive::new(&copy, "verifier", None).unwrap();

    let report = archive.verify(Some(&anchor)).unwrap();

    assert_eq!(anchor.sequence, 4);
    assert!(report.intact, "{:?}", report.break_reason);
    assert!(report.anchor_verified);
    assert_eq!(report.segments, 2);
    assert_eq!(report.verified_events, 4);
    assert_eq!(report.first_sequence, 1);
    assert_eq!(report.head_sequence, 4);
    assert_eq!(report.head_hash.as_deref(), Some(anchor.hash.as_str()));
    assert_eq!(archive.archived_through_sequence().unwrap(), 4);
}

#[test]
fn csharp_archive_lines_and_manifest_match_rust_serialization_byte_for_byte() {
    let fixture_directory = fixture("archive-csharp");
    let archive = QueueArchive::new(&fixture_directory, "verifier", None).unwrap();
    let events = archive.read_all().unwrap();
    let mut lines = read_segment(&fixture_directory.join("segment-000000000001.jsonl.gz"));
    lines.extend(read_segment(
        &fixture_directory.join("segment-000000000004.jsonl.gz"),
    ));

    assert_eq!(events.len(), 4);
    assert_eq!(
        events[1].payload,
        "{\"eventId\":\"a2\",\"note\":\"zo\u{eb} \u{7528}\u{6237} \\\"quoted\\\" \\\\ back\"}"
    );
    for (event, line) in events.iter().zip(&lines) {
        assert_eq!(&bower_contracts::json::to_string(event).unwrap(), line);
    }

    let text =
        std::fs::read_to_string(fixture_directory.join("segment-000000000001.manifest.json"))
            .unwrap();
    let manifest = ArchiveManifest {
        api_version: "bower.security/v1".into(),
        kind: MANIFEST_KIND.into(),
        collector_id: "collector-parity".into(),
        segment_file: "segment-000000000001.jsonl.gz".into(),
        segment_sha256: file_digest(&fixture_directory.join("segment-000000000001.jsonl.gz")),
        first_sequence: 1,
        last_sequence: 3,
        event_count: 3,
        previous_chain_hash: genesis_hash(),
        last_chain_hash: events[2].chain_hash.clone(),
        created_at: bower_contracts::time::parse("2026-07-26T02:14:22.7037034+00:00").unwrap(),
    };
    assert_eq!(bower_contracts::json::to_string(&manifest).unwrap(), text);
}

#[test]
fn archive_continues_ledger_chain_across_runs_and_verifies_against_queue_head() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);

    enqueue_range(&store, 1, 3, &clock);
    let first = archive.archive(&store).unwrap();
    let idle = archive.archive(&store).unwrap();
    enqueue_range(&store, 4, 5, &clock);
    let second = archive.archive(&store).unwrap();
    let head = store.ledger_head().unwrap();
    let report = archive.verify(Some(&head)).unwrap();
    let events = archive.read_all().unwrap();

    assert_eq!((first.segments, first.events), (1, 3));
    assert_eq!(idle.segments, 0);
    assert_eq!((second.segments, second.events), (1, 2));
    assert!(report.intact);
    assert!(report.anchor_verified);
    assert_eq!(report.head_hash.as_deref(), Some(head.hash.as_str()));
    assert_eq!(archive.archived_through_sequence().unwrap(), 5);
    assert_eq!(
        events.iter().map(|item| item.sequence).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    assert_eq!(events[1].payload, "{\"eventId\":\"event-2\"}");
    // Idle rerun reports the archived head like C#.
    assert_eq!(idle.head_sequence, 3);
    assert_eq!(idle.head_hash, first.head_hash);
}

#[test]
fn verify_detects_altered_segment_even_when_manifest_digest_is_updated() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 3, &clock);
    archive.archive(&store).unwrap();
    let segment = archive_path(directory.path()).join("segment-000000000001.jsonl.gz");
    let manifest = archive_path(directory.path()).join("segment-000000000001.manifest.json");

    let mut lines = read_segment(&segment);
    let forged = lines[1].replace("event-2", "forged");
    assert_ne!(lines[1], forged);
    lines[1] = forged;
    let original_digest = file_digest(&segment);
    write_segment(&segment, &lines);
    let digest_only = archive.verify(None).unwrap();

    let text = std::fs::read_to_string(&manifest).unwrap();
    let rewritten_text = text.replace(&original_digest, &file_digest(&segment));
    assert_ne!(text, rewritten_text);
    std::fs::write(&manifest, rewritten_text).unwrap();
    let rewritten = archive.verify(None).unwrap();

    assert_eq!(
        digest_only.break_reason.as_deref(),
        Some("segment-digest-mismatch")
    );
    assert_eq!(
        digest_only.break_segment.as_deref(),
        Some("segment-000000000001.jsonl.gz")
    );
    assert_eq!(rewritten.break_reason.as_deref(), Some("chain-broken"));
    assert!(!rewritten.intact);
    assert_eq!(
        (
            rewritten.first_sequence,
            rewritten.head_sequence,
            rewritten.head_hash.clone(),
            rewritten.anchor_verified,
            rewritten.verified_events,
            rewritten.segments
        ),
        (0, 0, None, false, 1, 1)
    );
}

#[test]
fn verify_reports_missing_segments_and_anchor_failures() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    archive.archive(&store).unwrap();
    let head = store.ledger_head().unwrap();

    let wrong_hash = archive
        .verify(Some(&LedgerHead {
            sequence: head.sequence,
            hash: "0".repeat(64),
        }))
        .unwrap();
    let beyond = archive
        .verify(Some(&LedgerHead {
            sequence: head.sequence + 10,
            hash: head.hash.clone(),
        }))
        .unwrap();
    enqueue_range(&store, 3, 3, &clock);
    archive.archive(&store).unwrap();
    std::fs::remove_file(archive_path(directory.path()).join("segment-000000000001.manifest.json"))
        .unwrap();
    let missing_first = archive.verify(None).unwrap();
    std::fs::remove_file(archive_path(directory.path()).join("segment-000000000003.manifest.json"))
        .unwrap();
    let empty = archive.verify(None).unwrap();

    assert_eq!(wrong_hash.break_reason.as_deref(), Some("anchor-mismatch"));
    assert_eq!(beyond.break_reason.as_deref(), Some("anchor-missing"));
    assert_eq!(beyond.break_segment, None);
    // Without the first manifest the archive starts at 3 with an unproven predecessor:
    // the stored previous hash still chains, so only an anchor at 1 or 2 would expose it.
    assert!(missing_first.intact);
    assert_eq!(missing_first.first_sequence, 3);
    assert_eq!(empty.break_reason.as_deref(), Some("archive-empty"));
}

#[test]
fn verify_reports_missing_segment_file() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    archive.archive(&store).unwrap();
    std::fs::remove_file(archive_path(directory.path()).join("segment-000000000001.jsonl.gz"))
        .unwrap();

    let report = archive.verify(None).unwrap();

    assert_eq!(report.break_reason.as_deref(), Some("segment-missing"));
    assert_eq!(report.segments, 1);
}

#[test]
fn archive_rewrites_segment_left_without_manifest_by_crash() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    archive.archive(&store).unwrap();
    std::fs::remove_file(archive_path(directory.path()).join("segment-000000000001.manifest.json"))
        .unwrap();
    enqueue_range(&store, 3, 3, &clock);

    let recovered = archive.archive(&store).unwrap();
    let report = archive.verify(None).unwrap();

    assert_eq!(recovered.events, 3);
    assert!(report.intact);
    assert_eq!(report.verified_events, 3);
}

#[test]
fn retention_purges_only_archived_events_and_archive_resumes_after_compaction() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 4, &clock);
    deliver_all(&store);
    archive.archive(&store).unwrap();
    enqueue_range(&store, 5, 6, &clock);
    deliver_all(&store);
    clock.advance(Span::days(10));

    let purged = store
        .purge_delivered_archived(
            clock.now(),
            100,
            archive.archived_through_sequence().unwrap(),
        )
        .unwrap();
    let resumed = archive.archive(&store).unwrap();
    let rest = store
        .purge_delivered_archived(
            clock.now(),
            100,
            archive.archived_through_sequence().unwrap(),
        )
        .unwrap();
    let ledger = store.verify_ledger().unwrap();
    let report = archive.verify(Some(&store.ledger_head().unwrap())).unwrap();

    assert_eq!(purged, 4);
    assert_eq!(resumed.events, 2);
    assert_eq!(rest, 2);
    assert!(ledger.intact);
    assert!(report.intact);
    assert_eq!(report.verified_events, 6);
}

#[test]
fn archive_starts_after_earlier_purge_from_the_recorded_ledger_hash() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue_range(&store, 1, 3, &clock);
    deliver_all(&store);
    clock.advance(Span::days(10));
    store.purge_delivered(clock.now(), 100).unwrap();
    enqueue_range(&store, 4, 5, &clock);
    let archive = new_archive(directory.path(), &clock);

    let result = archive.archive(&store).unwrap();
    let report = archive.verify(Some(&store.ledger_head().unwrap())).unwrap();

    assert_eq!(result.events, 2);
    assert!(report.intact);
    assert_eq!(report.first_sequence, 4);
}

#[test]
fn rust_written_archive_has_csharp_shape() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    clock.advance(Span::milliseconds(1234) + Span::microseconds(567) + Span::nanoseconds(890));
    store
        .enqueue(&event(
            "a1",
            "sha256:a1",
            "{\"eventId\":\"a1\",\"note\":\"zo\u{eb} <+>\"}",
            clock.now(),
        ))
        .unwrap();
    enqueue_range(&store, 2, 2, &clock);
    let head = store.ledger_head().unwrap();
    archive.archive(&store).unwrap();
    let root = archive_path(directory.path());
    let segment = root.join("segment-000000000001.jsonl.gz");

    let manifest =
        std::fs::read_to_string(root.join("segment-000000000001.manifest.json")).unwrap();
    let expected = format!(
        "{{\"apiVersion\":\"bower.security/v1\",\"kind\":\"BowerArchiveSegment\",\"collectorId\":\"collector-1\",\"segmentFile\":\"segment-000000000001.jsonl.gz\",\"segmentSha256\":\"{}\",\"firstSequence\":1,\"lastSequence\":2,\"eventCount\":2,\"previousChainHash\":\"{}\",\"lastChainHash\":\"{}\",\"createdAt\":\"2026-07-26T02:14:21.2345678+00:00\"}}",
        file_digest(&segment),
        genesis_hash(),
        head.hash
    );
    assert_eq!(manifest, expected);

    let mut raw = Vec::new();
    MultiGzDecoder::new(std::fs::File::open(&segment).unwrap())
        .read_to_end(&mut raw)
        .unwrap();
    let text = String::from_utf8(raw).unwrap();
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    assert_eq!(lines.len(), 2);
    let received = "2026-07-26T02:14:20.2345678\\u002B00:00";
    let first_hash = chain_hash(
        &genesis_hash(),
        1,
        "a1",
        &payload_hash("{\"eventId\":\"a1\",\"note\":\"zo\u{eb} <+>\"}"),
        "2026-07-26T02:14:20.2345678+00:00",
    );
    assert_eq!(
        lines[0],
        format!(
            "{{\"sequence\":1,\"eventId\":\"a1\",\"receivedAt\":\"{received}\",\"chainHash\":\"{first_hash}\",\"payload\":\"{{\\u0022eventId\\u0022:\\u0022a1\\u0022,\\u0022note\\u0022:\\u0022zo\\u00EB \\u003C\\u002B\\u003E\\u0022}}\"}}\n"
        )
    );
    assert!(lines[1].ends_with("\"}\n"));
    assert!(!root.join("segment-000000000001.jsonl.gz.tmp").exists());
    assert!(!root.join("segment-000000000001.manifest.json.tmp").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in [
            "segment-000000000001.jsonl.gz",
            "segment-000000000001.manifest.json",
        ] {
            let mode = std::fs::metadata(root.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }

    // A C#-readable archive written by Rust verifies against the queue head.
    let report = archive.verify(Some(&head)).unwrap();
    assert!(report.intact && report.anchor_verified);
}

/// The final manifest move never overwrites: a collision means two writers share the
/// archive. A directory squatting on the manifest name is skipped by discovery, so the
/// archive starts from scratch and the no-overwrite move collides with it.
#[test]
fn manifest_collision_is_refused_instead_of_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue_range(&store, 1, 2, &clock);
    let root = archive_path(directory.path());
    let planted = root.join("segment-000000000001.manifest.json");
    std::fs::create_dir_all(&planted).unwrap();
    let archive = new_archive(directory.path(), &clock);

    let error = archive.archive(&store).unwrap_err();

    assert!(
        matches!(&error, ArchiveError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
        "{error:?}"
    );
    assert!(planted.is_dir());
    assert_eq!(archive.archived_through_sequence().unwrap(), 0);
}

#[test]
fn unreadable_manifests_report_manifest_invalid_and_block_archiving() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    archive.archive(&store).unwrap();
    let root = archive_path(directory.path());
    let manifest = root.join("segment-000000000001.manifest.json");
    let original = std::fs::read_to_string(&manifest).unwrap();

    let cases: Vec<(String, &str)> = vec![
        (
            "not json".into(),
            "Archive manifest invalid: segment-000000000001.manifest.json",
        ),
        (
            "null".into(),
            "Archive manifest empty: segment-000000000001.manifest.json",
        ),
        (
            original.replace(MANIFEST_KIND, "Other"),
            "Archive manifest invalid: segment-000000000001.manifest.json",
        ),
        (
            original.replace("\"segmentFile\":\"", "\"segmentFile\":\"../"),
            "Archive manifest invalid: segment-000000000001.manifest.json",
        ),
        (
            original.replace("\"eventCount\":2", "\"eventCount\":3"),
            "Archive manifest invalid: segment-000000000001.manifest.json",
        ),
        (
            original.replace("\"firstSequence\":1", "\"firstSequence\":0"),
            "Archive manifest invalid: segment-000000000001.manifest.json",
        ),
        // Case-sensitive names: `Kind` is ignored, so `kind` is missing.
        (
            original.replace("\"kind\"", "\"Kind\""),
            "Archive manifest invalid: segment-000000000001.manifest.json",
        ),
        (
            format!("{original}{}", " ".repeat(65_537)),
            "Archive manifest too large: segment-000000000001.manifest.json",
        ),
    ];
    for (text, message) in cases {
        std::fs::write(&manifest, &text).unwrap();
        let report = archive.verify(None).unwrap();
        assert_eq!(
            report.break_reason.as_deref(),
            Some("manifest-invalid"),
            "{message}"
        );
        assert_eq!((report.segments, report.verified_events), (0, 0));
        match archive.archive(&store) {
            Err(ArchiveError::InvalidData(actual)) => assert_eq!(actual, message),
            other => panic!("expected invalid data, got {other:?}"),
        }
        assert!(archive.archived_through_sequence().is_err());
    }

    // Unknown members, a BOM and a missing createdAt are accepted like System.Text.Json.
    let tolerant = format!(
        "\u{feff}{}",
        original
            .replacen('{', "{\"extra\":{\"nested\":[1,2]},", 1)
            .split(",\"createdAt\"")
            .next()
            .unwrap()
            .to_owned()
            + "}"
    );
    std::fs::write(&manifest, tolerant).unwrap();
    assert!(archive.verify(None).unwrap().intact);
}

#[test]
fn manifests_with_missing_sequences_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 1, &clock);
    archive.archive(&store).unwrap();
    enqueue_range(&store, 2, 2, &clock);
    archive.archive(&store).unwrap();
    enqueue_range(&store, 3, 3, &clock);
    archive.archive(&store).unwrap();
    std::fs::remove_file(archive_path(directory.path()).join("segment-000000000002.manifest.json"))
        .unwrap();

    let report = archive.verify(None).unwrap();
    let error = archive.archived_through_sequence().unwrap_err();

    assert_eq!(report.break_reason.as_deref(), Some("manifest-invalid"));
    assert_eq!(error.to_string(), "Archive is missing sequences before 3.");
}

#[test]
fn verify_reports_sequence_gap_and_manifest_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 3, &clock);
    archive.archive(&store).unwrap();
    let root = archive_path(directory.path());
    let segment = root.join("segment-000000000001.jsonl.gz");
    let manifest = root.join("segment-000000000001.manifest.json");
    let original_lines = read_segment(&segment);
    let original_manifest = std::fs::read_to_string(&manifest).unwrap();
    let original_digest = file_digest(&segment);

    let rewrite = |lines: &[String]| {
        write_segment(&segment, lines);
        std::fs::write(
            &manifest,
            original_manifest.replace(&original_digest, &file_digest(&segment)),
        )
        .unwrap();
        archive.verify(None).unwrap()
    };

    let gap = rewrite(&[original_lines[0].clone(), original_lines[2].clone()]);
    let short = rewrite(&original_lines[..2]);

    assert_eq!(gap.break_reason.as_deref(), Some("sequence-gap"));
    assert_eq!(gap.verified_events, 1);
    assert_eq!(short.break_reason.as_deref(), Some("manifest-mismatch"));
    assert_eq!(short.verified_events, 2);
}

#[test]
fn verify_reports_segment_not_contiguous() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 1, &clock);
    archive.archive(&store).unwrap();
    enqueue_range(&store, 2, 2, &clock);
    archive.archive(&store).unwrap();
    let manifest = archive_path(directory.path()).join("segment-000000000002.manifest.json");
    let text = std::fs::read_to_string(&manifest).unwrap();
    let previous = text
        .split("\"previousChainHash\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    std::fs::write(&manifest, text.replace(&previous, &"f".repeat(64))).unwrap();

    let report = archive.verify(None).unwrap();

    assert_eq!(
        report.break_reason.as_deref(),
        Some("segment-not-contiguous")
    );
    assert_eq!(
        report.break_segment.as_deref(),
        Some("segment-000000000002.jsonl.gz")
    );
    assert_eq!(report.verified_events, 1);
}

/// C# throws from `VerifyAsync` (uncaught `InvalidDataException`/`JsonException`) when a
/// segment whose digest matches its manifest is not gzip or holds a bad line; Rust
/// returns an error rather than a verdict, so nothing reads as intact.
#[test]
fn unreadable_segment_content_fails_closed_with_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    archive.archive(&store).unwrap();
    let root = archive_path(directory.path());
    let segment = root.join("segment-000000000001.jsonl.gz");
    let manifest = root.join("segment-000000000001.manifest.json");
    let original_manifest = std::fs::read_to_string(&manifest).unwrap();
    let original_digest = file_digest(&segment);
    let replace_segment = |bytes: &[u8]| {
        std::fs::write(&segment, bytes).unwrap();
        std::fs::write(
            &manifest,
            original_manifest.replace(&original_digest, &file_digest(&segment)),
        )
        .unwrap();
    };

    replace_segment(b"not gzip at all");
    assert!(matches!(
        archive.verify(None),
        Err(ArchiveError::InvalidData(_))
    ));
    assert!(archive.read_all().is_err());

    let lines = vec!["{\"sequence\":1,".to_owned()];
    write_segment(&segment, &lines);
    std::fs::write(
        &manifest,
        original_manifest.replace(&original_digest, &file_digest(&segment)),
    )
    .unwrap();
    match archive.verify(None) {
        Err(ArchiveError::InvalidData(message)) => {
            assert_eq!(message, "Archived line is not valid JSON.");
        }
        other => panic!("expected invalid data, got {other:?}"),
    }

    write_segment(&segment, &["null".to_owned()]);
    std::fs::write(
        &manifest,
        original_manifest.replace(&original_digest, &file_digest(&segment)),
    )
    .unwrap();
    match archive.verify(None) {
        Err(ArchiveError::InvalidData(message)) => assert_eq!(message, "Archived line is empty."),
        other => panic!("expected invalid data, got {other:?}"),
    }
}

#[test]
fn archive_refuses_when_unarchived_events_were_purged() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    archive.archive(&store).unwrap();
    enqueue_range(&store, 3, 4, &clock);
    deliver_all(&store);
    clock.advance(Span::days(10));
    // Plain retention ignores the archive and purges 3 and 4 before they are archived.
    store.purge_delivered(clock.now(), 100).unwrap();
    enqueue_range(&store, 5, 5, &clock);

    let error = archive.archive(&store).unwrap_err();

    assert_eq!(
        error.to_string(),
        "Events after sequence 2 were purged before they were archived."
    );
}

#[test]
fn ledger_reads_validate_arguments_and_resolve_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue_range(&store, 1, 3, &clock);

    assert!(matches!(
        store.read_ledger_events(-1, 1),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.read_ledger_events(0, 0),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.read_ledger_events(0, 100_001),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.ledger_hash_at(-1),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.ledger_hash_at(0).unwrap(), Some(genesis_hash()));
    assert_eq!(store.ledger_hash_at(99).unwrap(), None);

    let rows = store.read_ledger_events(1, 100_000).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.sequence).collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(rows[0].payload, "{\"eventId\":\"event-2\"}");
    assert_eq!(
        store.ledger_hash_at(3).unwrap().as_deref(),
        Some(rows[1].chain_hash.as_str())
    );
    assert_eq!(MAXIMUM_EVENTS_PER_SEGMENT, 10_000);
}

#[test]
fn constructor_rejects_blank_arguments() {
    assert!(matches!(
        QueueArchive::new(" ", "collector", None),
        Err(ArchiveError::InvalidArgument(_))
    ));
    assert!(matches!(
        QueueArchive::new("archive", " ", None),
        Err(ArchiveError::InvalidArgument(_))
    ));
    let archive = QueueArchive::new("a/./b/../archive", "collector", None).unwrap();
    assert!(archive.directory().is_absolute());
    assert!(archive.directory().ends_with("a/archive"));
    // A missing directory is an empty archive.
    assert_eq!(archive.archived_through_sequence().unwrap(), 0);
}

fn segment_files(root: &Path) -> usize {
    std::fs::read_dir(root)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("segment-")
        })
        .count()
}

/// Issue #67: the exclusive writer lock either runtime holds for a whole run
/// (C# `Archive_RefusesWhileAnotherWriterHoldsTheArchiveLock`).
#[test]
fn archive_refuses_while_another_writer_holds_the_archive_lock() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 2, &clock);
    let root = archive_path(directory.path());
    std::fs::create_dir_all(&root).unwrap();

    {
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("archive.lock"))
            .unwrap();
        held.try_lock().unwrap();
        let error = archive.archive(&store).unwrap_err();
        assert!(
            matches!(&error, ArchiveError::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock),
            "{error:?}"
        );
        assert_eq!(segment_files(&root), 0);
    }

    assert_eq!(archive.archive(&store).unwrap().events, 2);
}

fn archive_delivered(
    store: &SqliteEventStore,
    archive: &QueueArchive,
    first: i32,
    last: i32,
    clock: &FakeClock,
) {
    enqueue_range(store, first, last, clock);
    deliver_all(store);
    archive.archive(store).unwrap();
}

fn segment(directory: &Path, first: i64) -> PathBuf {
    archive_path(directory).join(format!("segment-{first:012}.jsonl.gz"))
}

fn forge_segment(path: &Path, line: usize, from: &str, to: &str) {
    let mut lines = read_segment(path);
    lines[line] = lines[line].replace(from, to);
    write_segment(path, &lines);
}

/// Issue #66 (C# `QueueArchiveRetentionTests`): coverage requires verified segments,
/// a start at or below the oldest stored event and the queue's own ledger chain.
#[test]
fn coverage_refuses_deleted_and_corrupted_segments() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    archive_delivered(&store, &archive, 1, 4, &clock);
    let path = segment(directory.path(), 1);
    let original = std::fs::read(&path).unwrap();

    forge_segment(&path, 0, "event-1", "forged1");
    let corrupted = archive.verify_coverage(&store).unwrap();
    std::fs::remove_file(&path).unwrap();
    let deleted = archive.verify_coverage(&store).unwrap();
    std::fs::write(&path, original).unwrap();
    let restored = archive.verify_coverage(&store).unwrap();

    assert!(!corrupted.verified);
    assert_eq!(corrupted.reason.as_deref(), Some("segment-digest-mismatch"));
    assert_eq!(deleted.reason.as_deref(), Some("segment-missing"));
    assert!(restored.verified, "{restored:?}");
    assert_eq!((restored.first_sequence, restored.through_sequence), (1, 4));
}

#[test]
fn coverage_refuses_a_foreign_archive_with_overlapping_sequences() {
    let directory = tempfile::tempdir().unwrap();
    let foreign_directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let foreign = common::store(foreign_directory.path(), 10 * ONE_MEBIBYTE, &clock);
    enqueue_range(&store, 1, 4, &clock);
    deliver_all(&store);
    enqueue_range(&foreign, 101, 106, &clock);
    let archive = new_archive(directory.path(), &clock);
    archive.archive(&foreign).unwrap();

    let coverage = archive.verify_coverage(&store).unwrap();

    assert!(archive.verify(None).unwrap().intact);
    assert_eq!(coverage.reason.as_deref(), Some("lineage-mismatch"));
    assert_eq!(
        store
            .purge_delivered_archived(clock.now() + Span::days(10), 100, 0)
            .unwrap(),
        0
    );
}

#[test]
fn coverage_protects_rows_below_an_archive_that_lost_its_first_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    archive_delivered(&store, &archive, 1, 2, &clock);
    archive_delivered(&store, &archive, 3, 4, &clock);
    std::fs::remove_file(archive_path(directory.path()).join("segment-000000000001.manifest.json"))
        .unwrap();

    let coverage = archive.verify_coverage(&store).unwrap();

    assert_eq!(
        coverage.reason.as_deref(),
        Some("archive-starts-above-retained")
    );
    assert_eq!(coverage.first_sequence, 3);
}

#[test]
fn coverage_permits_purging_only_verified_acknowledged_rows_and_notices_later_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    enqueue_range(&store, 1, 5, &clock);
    let leased = store.lease(4, Duration::from_secs(60)).unwrap();
    let token = |id: &str| {
        leased
            .iter()
            .find(|item| item.event_id == id)
            .and_then(|item| item.lease_token.clone())
    };
    store
        .mark_delivered("event-1", "ack-1", token("event-1").as_deref())
        .unwrap();
    store
        .mark_delivered("event-2", "ack-2", token("event-2").as_deref())
        .unwrap();
    store
        .mark_dead_lettered("event-3", "bad", token("event-3").as_deref())
        .unwrap();
    store
        .mark_retrying(
            "event-4",
            "busy",
            clock.now() + Span::days(30),
            token("event-4").as_deref(),
        )
        .unwrap();
    archive.archive(&store).unwrap();
    clock.advance(Span::days(10));

    let coverage = archive.verify_coverage(&store).unwrap();
    let purged = store
        .purge_delivered_archived(clock.now(), 100, coverage.through_sequence)
        .unwrap();
    let snapshot = store.snapshot().unwrap();

    assert!(coverage.verified, "{coverage:?}");
    assert_eq!((coverage.first_sequence, coverage.through_sequence), (1, 5));
    assert_eq!(purged, 2);
    assert_eq!(
        (
            snapshot.delivered,
            snapshot.dead_lettered,
            snapshot.retrying,
            snapshot.queued
        ),
        (0, 1, 1, 1)
    );
    assert!(store.verify_ledger().unwrap().intact);

    // The cached verification must notice a segment changed after it was verified.
    archive_delivered(&store, &archive, 6, 7, &clock);
    assert!(archive.verify_coverage(&store).unwrap().verified);
    forge_segment(&segment(directory.path(), 6), 1, "event-7", "forged7");

    assert_eq!(
        archive.verify_coverage(&store).unwrap().reason.as_deref(),
        Some("segment-digest-mismatch")
    );
}

/// Crash after a segment was published, before its manifest, with temporary files of a
/// crashed writer left behind (C# `Retention_AfterCrashBeforeManifest...`).
#[test]
fn coverage_after_crash_before_manifest_is_the_committed_prefix_and_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    let archive = new_archive(directory.path(), &clock);
    archive_delivered(&store, &archive, 1, 2, &clock);
    archive_delivered(&store, &archive, 3, 4, &clock);
    let root = archive_path(directory.path());
    std::fs::remove_file(root.join("segment-000000000003.manifest.json")).unwrap();
    std::fs::write(
        root.join("segment-000000000003.manifest.json.0123.tmp"),
        "{",
    )
    .unwrap();
    std::fs::write(root.join("segment-000000000003.jsonl.gz.tmp"), "partial").unwrap();
    clock.advance(Span::days(10));

    let committed = archive.verify_coverage(&store).unwrap();
    let first_purge = store
        .purge_delivered_archived(clock.now(), 100, committed.through_sequence)
        .unwrap();
    let recovered = archive.archive(&store).unwrap();
    let coverage = archive.verify_coverage(&store).unwrap();
    let second_purge = store
        .purge_delivered_archived(clock.now(), 100, coverage.through_sequence)
        .unwrap();
    let report = archive.verify(Some(&store.ledger_head().unwrap())).unwrap();

    assert_eq!(committed.through_sequence, 2);
    assert_eq!((first_purge, recovered.events, second_purge), (2, 2, 2));
    assert!(report.intact, "{report:?}");
    assert_eq!(report.verified_events, 4);
    let leftovers = std::fs::read_dir(&root)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        })
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn ledger_boundary_at_or_below_resolves_entries_segments_and_validates() {
    let directory = tempfile::tempdir().unwrap();
    let clock = FakeClock::new(test_now());
    let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
    assert_eq!(store.ledger_boundary_at_or_below(5).unwrap(), None);
    enqueue_range(&store, 1, 3, &clock);
    deliver_all(&store);
    enqueue_range(&store, 4, 4, &clock);
    let entry = store.ledger_boundary_at_or_below(10).unwrap().unwrap();
    clock.advance(Span::days(10));
    store.purge_delivered(clock.now(), 100).unwrap();

    // Rows 1-3 are compacted into one segment ending at 3.
    let compacted = store.ledger_boundary_at_or_below(2).unwrap();
    let end = store.ledger_boundary_at_or_below(3).unwrap().unwrap();

    assert_eq!(entry.sequence, 4);
    assert_eq!(Some(entry.hash), store.ledger_hash_at(4).unwrap());
    assert_eq!(compacted, None);
    assert_eq!(end.sequence, 3);
    assert_eq!(Some(end.hash), store.ledger_hash_at(3).unwrap());
    assert!(matches!(
        store.ledger_boundary_at_or_below(-1),
        Err(StoreError::Invalid(_))
    ));
}

fn snapshot_files(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name() != "archive.lock")
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

/// C# `Archive_RefusesToExtendAForeignOrNewerArchiveWithoutWriting`: 8 queue events
/// give sequence 6 a different hash (another queue or a diverged restore); 2 leave the
/// archive ahead of the queue.
#[test]
fn archive_refuses_to_extend_a_foreign_or_newer_archive_without_writing() {
    for queue_events in [8, 2] {
        let directory = tempfile::tempdir().unwrap();
        let foreign_directory = tempfile::tempdir().unwrap();
        let clock = FakeClock::new(test_now());
        let store = store(directory.path(), 10 * ONE_MEBIBYTE, &clock);
        let foreign = common::store(foreign_directory.path(), 10 * ONE_MEBIBYTE, &clock);
        enqueue_range(&foreign, 101, 106, &clock);
        let archive = new_archive(directory.path(), &clock);
        archive.archive(&foreign).unwrap();
        enqueue_range(&store, 1, queue_events, &clock);
        let root = archive_path(directory.path());
        let before = snapshot_files(&root);

        let error = archive.archive(&store).unwrap_err();

        assert!(
            matches!(&error, ArchiveError::InvalidData(message) if message.contains("lineage-mismatch") && !message.contains("eventId")),
            "{error:?}"
        );
        assert_eq!(snapshot_files(&root), before, "{queue_events}");
    }
}
