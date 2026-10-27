//! Redaction counters (C# `PipelineTelemetry.RecordRedactions`): queued events per
//! detector type, counted once per stored event. Type ids only, never values.

mod support;

use std::sync::Arc;

use bower_contracts::DurableEventStore;
use bower_core::{
    CollectorIdentity, MAXIMUM_REDACTION_TYPES, OTHER_REDACTION_TYPE, PipelineTelemetry,
    RedactionCount, SecurityEventProcessor,
};
use support::*;

fn identity() -> CollectorIdentity {
    CollectorIdentity::new("collector-1", "0.1.0", "test", "sha256:configuration")
}

fn counts(telemetry: &PipelineTelemetry) -> Vec<(String, i64)> {
    telemetry
        .redaction_snapshot()
        .counts
        .into_iter()
        .map(|RedactionCount { kind, events }| (kind, events))
        .collect()
}

#[test]
fn redacted_event_counts_once_per_type_and_a_duplicate_retry_adds_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        bower_persistence::SqliteEventStore::new(
            directory.path().join("queue.db"),
            1_048_576,
            None,
        )
        .unwrap(),
    );
    store.initialize().unwrap();
    let telemetry = Arc::new(PipelineTelemetry::new(Arc::new(now)));
    let processor = SecurityEventProcessor::new(
        Arc::new(FieldRedactor {
            remove: vec![],
            mask: vec![],
            detected: vec!["id.email", "au.tfn", "au.tfn"],
        }),
        Arc::new(TestPolicy),
        store,
        Arc::new(now),
    )
    .with_telemetry(Arc::clone(&telemetry));
    let json = authentication_failure_json("");

    let first = processor.process(&json, &identity()).unwrap();
    assert!(first.queued);
    let retry = processor.process(&json, &identity()).unwrap();
    assert!(retry.duplicate);

    let snapshot = telemetry.redaction_snapshot();
    assert_eq!(snapshot.observed_since, now());
    assert_eq!(
        counts(&telemetry),
        vec![("au.tfn".to_owned(), 1), ("id.email".to_owned(), 1)]
    );
}

#[test]
fn sub_kinds_count_under_their_detector_type_once_per_event() {
    let telemetry = PipelineTelemetry::new(Arc::new(now));
    telemetry.record_redactions(&[
        "secret.aws:access-key".to_owned(),
        "secret.aws:secret-key".to_owned(),
        "id.email".to_owned(),
    ]);
    telemetry.record_redactions(&["secret.aws".to_owned()]);
    telemetry.record_redactions(&[]);

    assert_eq!(
        counts(&telemetry),
        vec![("id.email".to_owned(), 1), ("secret.aws".to_owned(), 2)]
    );
}

#[test]
fn types_beyond_the_limit_count_as_other_and_known_types_keep_counting() {
    let telemetry = PipelineTelemetry::new(Arc::new(now));
    for index in 0..MAXIMUM_REDACTION_TYPES - 1 {
        telemetry.record_redactions(&[format!("custom.t{index:02}")]);
    }
    // Two new types in one event fold into one "other" count.
    telemetry.record_redactions(&["custom.new-a".to_owned(), "custom.new-b".to_owned()]);
    telemetry.record_redactions(&["custom.new-c".to_owned(), "custom.t00".to_owned()]);

    let snapshot = counts(&telemetry);
    assert_eq!(snapshot.len(), MAXIMUM_REDACTION_TYPES);
    assert!(snapshot.contains(&(OTHER_REDACTION_TYPE.to_owned(), 2)));
    assert!(snapshot.contains(&("custom.t00".to_owned(), 2)));
    assert!(
        !snapshot
            .iter()
            .any(|(kind, _)| kind.starts_with("custom.new"))
    );
}

#[test]
fn snapshot_orders_types_ordinally() {
    let telemetry = PipelineTelemetry::new(Arc::new(now));
    telemetry.record_redactions(&["id.ip".to_owned(), "au.tfn".to_owned(), "Zeta".to_owned()]);

    let kinds: Vec<String> = counts(&telemetry)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect();
    assert_eq!(kinds, vec!["Zeta", "au.tfn", "id.ip"]);
}
