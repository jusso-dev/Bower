//! Live qualification only: `cargo test -p bower-output-s3 --test live -- --ignored` with
//! `BOWER_S3_LIVE_BUCKET` set. Same fixed batches as C# `S3OutputTests.Live_SameBatchWritesOneObject`,
//! so both runtimes and every retry land on one key per content (later PUTs get 412 and
//! count as delivered) and the same ids with changed content get their own key.

use bower_contracts::abstractions::{OutputAdapter, QueueState, QueuedEvent};
use bower_output_s3::{S3Output, S3OutputOptions};

#[tokio::test]
#[ignore = "needs BOWER_S3_LIVE_BUCKET and AWS default-chain credentials"]
async fn live_same_batch_writes_one_object() {
    let bucket = std::env::var("BOWER_S3_LIVE_BUCKET").expect("BOWER_S3_LIVE_BUCKET");
    let mut options = S3OutputOptions::new(
        "live-idem",
        bucket,
        std::env::var("BOWER_S3_LIVE_REGION").unwrap_or_else(|_| "ap-southeast-2".into()),
    );
    options.prefix =
        std::env::var("BOWER_S3_LIVE_PREFIX").unwrap_or_else(|_| "live/idempotent".into());
    options.expected_bucket_owner = std::env::var("BOWER_S3_LIVE_OWNER").ok();
    let output = S3Output::new(options).unwrap();
    let start = bower_contracts::time::parse("2026-11-05T00:00:00Z").unwrap();
    let events: Vec<QueuedEvent> = (0..5)
        .map(|index| QueuedEvent {
            event_id: format!("live-idem-{index}"),
            fingerprint: format!("sha256:{index}"),
            payload: format!(
                "{{\"eventId\":\"live-idem-{index}\",\"eventType\":\"authentication_failure\",\"live\":true}}"
            ),
            received_at: start + chrono::TimeDelta::seconds(index),
            state: QueueState::Queued,
            delivery_attempts: 0,
            lease_token: None,
            suppression: None,
        })
        .collect();

    let first = output.deliver(&events).await;
    let retry = output.deliver(&events).await;

    assert!(first.failures.is_empty(), "{:?}", first.failures);
    assert!(retry.failures.is_empty(), "{:?}", retry.failures);
    assert_eq!(5, first.acknowledged_event_ids.len());
    assert_eq!(
        first.destination_acknowledgement,
        retry.destination_acknowledgement
    );

    // Same ids, different content: a different key, never a 412 on the first object.
    let changed: Vec<QueuedEvent> = events
        .iter()
        .map(|item| QueuedEvent {
            payload: item.payload.replace("true}", "false}"),
            ..item.clone()
        })
        .collect();
    let other = output.deliver(&changed).await;
    assert!(other.failures.is_empty(), "{:?}", other.failures);
    assert_ne!(
        first.destination_acknowledgement,
        other.destination_acknowledgement
    );
    println!(
        "live acknowledgements: {} {}",
        first.destination_acknowledgement.unwrap_or_default(),
        other.destination_acknowledgement.unwrap_or_default()
    );
}
