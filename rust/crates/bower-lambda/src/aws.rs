//! AWS clients. Credentials come only from the Lambda execution role through the
//! default provider chain (the runtime's `AWS_*` session variables); no keys are
//! stored or configured by Bower.

use std::time::Duration;

use aws_sdk_cloudtraildata::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_cloudtraildata::types::AuditEvent;
use aws_sdk_cloudwatchlogs::types::InputLogEvent;

use crate::audit::{AuditRecord, RecordFormat};
use crate::settings::SettingsError;
use crate::sink::{AcceptedEvent, AuditSink, PutResult, RefusedEvent, SinkFailure};

/// Shared SDK configuration: region and role credentials from the Lambda
/// environment, bounded attempts so a stalled call cannot use the whole timeout.
pub async fn sdk_config() -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .timeout_config(
            aws_config::timeout::TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(3))
                .operation_attempt_timeout(Duration::from_secs(8))
                .operation_timeout(Duration::from_secs(20))
                .build(),
        )
        .load()
        .await
}

fn failure_code<E: ProvideErrorMetadata, R>(error: &SdkError<E, R>) -> String {
    match error {
        SdkError::ServiceError(service) => service.err().code().unwrap_or("service-error").into(),
        SdkError::TimeoutError(_) => "timeout".into(),
        SdkError::DispatchFailure(_) => "dispatch-failure".into(),
        SdkError::ResponseError(_) => "response-error".into(),
        SdkError::ConstructionFailure(_) => "construction-failure".into(),
        _ => "unknown".into(),
    }
}

/// `logs:PutLogEvents` into one stream of one log group. The stream belongs to this
/// execution environment and is created at init (`logs:CreateLogStream`).
pub struct CloudWatchLogsSink {
    client: aws_sdk_cloudwatchlogs::Client,
    log_group: String,
    log_stream: String,
}

impl CloudWatchLogsSink {
    /// Creates the stream if it does not exist. Any other failure stops init: the
    /// function never serves without a writable destination.
    pub async fn new(
        config: &aws_config::SdkConfig,
        log_group: String,
        log_stream: String,
    ) -> Result<Self, SettingsError> {
        let client = aws_sdk_cloudwatchlogs::Client::new(config);
        let created = client
            .create_log_stream()
            .log_group_name(&log_group)
            .log_stream_name(&log_stream)
            .send()
            .await;
        if let Err(error) = created {
            let exists = error
                .as_service_error()
                .is_some_and(|service| service.is_resource_already_exists_exception());
            if !exists {
                return Err(SettingsError::new(format!(
                    "CloudWatch Logs CreateLogStream for BOWER_CLOUDWATCH_LOG_GROUP failed ({}).",
                    SinkFailure::new(failure_code(&error)).code
                )));
            }
        }
        Ok(Self {
            client,
            log_group,
            log_stream,
        })
    }
}

/// Positions (in sent order) that `rejectedLogEventsInfo` refuses, with a code.
///
/// The end indexes are read as inclusive. The SDK documents `tooOldLogEventEndIndex` as
/// exclusive and says nothing for `expiredLogEventEndIndex`; the inclusive reading marks
/// at most one more event retryable than the exclusive one. A wrongly retried event is
/// a duplicate (queries deduplicate on `eventId`); a wrongly accepted one would be lost,
/// so the wider reading is the safe one. `tooNewLogEventStartIndex` is documented as
/// inclusive. Every record in a call carries the same receive-time timestamp, so these
/// ranges are not expected in practice.
fn rejected_log_events(
    count: usize,
    too_new_start: Option<i32>,
    too_old_end: Option<i32>,
    expired_end: Option<i32>,
) -> Vec<(usize, &'static str)> {
    let index = |value: Option<i32>| value.and_then(|value| usize::try_from(value).ok());
    (0..count)
        .filter_map(|position| {
            if index(too_new_start).is_some_and(|start| position >= start) {
                Some((position, "cloudwatch-logs-too-new"))
            } else if index(expired_end).is_some_and(|end| position <= end) {
                Some((position, "cloudwatch-logs-expired"))
            } else if index(too_old_end).is_some_and(|end| position <= end) {
                Some((position, "cloudwatch-logs-too-old"))
            } else {
                None
            }
        })
        .collect()
}

impl AuditSink for CloudWatchLogsSink {
    fn format(&self) -> RecordFormat {
        RecordFormat::CloudWatchLogs
    }

    async fn put_audit_events(&self, records: &[&AuditRecord]) -> Result<PutResult, SinkFailure> {
        // PutLogEvents needs chronological order; rejections index the sent order.
        let mut order: Vec<&AuditRecord> = records.to_vec();
        order.sort_by_key(|record| record.timestamp_ms);
        let events = order
            .iter()
            .map(|record| {
                InputLogEvent::builder()
                    .message(&record.event_data)
                    .timestamp(record.timestamp_ms)
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SinkFailure::new("request-build-failed"))?;
        let output = self
            .client
            .put_log_events()
            .log_group_name(&self.log_group)
            .log_stream_name(&self.log_stream)
            .set_log_events(Some(events))
            .send()
            .await
            .map_err(|error| SinkFailure::new(failure_code(&error)))?;
        let rejected = output
            .rejected_log_events_info()
            .map_or_else(Vec::new, |info| {
                rejected_log_events(
                    order.len(),
                    info.too_new_log_event_start_index(),
                    info.too_old_log_event_end_index(),
                    info.expired_log_event_end_index(),
                )
            });
        let mut result = PutResult::default();
        for (position, record) in order.iter().enumerate() {
            match rejected.iter().find(|(index, _)| *index == position) {
                Some((_, code)) => result.failed.push(RefusedEvent {
                    id: record.id.clone(),
                    error_code: (*code).to_string(),
                }),
                None => result.successful.push(AcceptedEvent {
                    id: record.id.clone(),
                    event_id: None,
                }),
            }
        }
        Ok(result)
    }
}

/// `cloudtrail-data:PutAuditEvents` on one custom integration channel.
pub struct CloudTrailLakeSink {
    client: aws_sdk_cloudtraildata::Client,
    channel_arn: String,
    external_id: Option<String>,
}

impl CloudTrailLakeSink {
    pub fn new(
        config: &aws_config::SdkConfig,
        channel_arn: String,
        external_id: Option<String>,
    ) -> Self {
        Self {
            client: aws_sdk_cloudtraildata::Client::new(config),
            channel_arn,
            external_id,
        }
    }
}

impl AuditSink for CloudTrailLakeSink {
    fn format(&self) -> RecordFormat {
        RecordFormat::CloudTrailLake
    }

    async fn put_audit_events(&self, records: &[&AuditRecord]) -> Result<PutResult, SinkFailure> {
        let events = records
            .iter()
            .map(|record| {
                AuditEvent::builder()
                    .id(&record.id)
                    .event_data(&record.event_data)
                    .event_data_checksum(&record.checksum)
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SinkFailure::new("request-build-failed"))?;
        let output = self
            .client
            .put_audit_events()
            .channel_arn(&self.channel_arn)
            .set_external_id(self.external_id.clone())
            .set_audit_events(Some(events))
            .send()
            .await
            .map_err(|error| SinkFailure::new(failure_code(&error)))?;
        Ok(PutResult {
            successful: output
                .successful()
                .iter()
                .map(|entry| AcceptedEvent {
                    id: entry.id().to_string(),
                    event_id: Some(entry.event_id().to_string()),
                })
                .collect(),
            failed: output
                .failed()
                .iter()
                .map(|entry| RefusedEvent {
                    id: entry.id().to_string(),
                    error_code: SinkFailure::new(entry.error_code()).code,
                })
                .collect(),
        })
    }
}

/// Reads the privacy HMAC key with `secretsmanager:GetSecretValue` on exactly
/// this ARN. The value is decoded like a key file (base64 preferred, else raw
/// bytes, at least 32 bytes) and kept only in memory for the life of the
/// execution environment. Errors carry the AWS error code, never the value.
pub async fn fetch_hmac_key(
    config: &aws_config::SdkConfig,
    secret_arn: &str,
) -> Result<Vec<u8>, SettingsError> {
    let client = aws_sdk_secretsmanager::Client::new(config);
    let output = client
        .get_secret_value()
        .secret_id(secret_arn)
        .send()
        .await
        .map_err(|error| {
            SettingsError::new(format!(
                "Secrets Manager GetSecretValue for the privacy HMAC key failed ({}).",
                SinkFailure::new(failure_code(&error)).code
            ))
        })?;
    let raw: &[u8] = match (output.secret_binary(), output.secret_string()) {
        (Some(binary), _) => binary.as_ref(),
        (None, Some(text)) => text.as_bytes(),
        (None, None) => {
            return Err(SettingsError::new(
                "The privacy HMAC key secret has no value.",
            ));
        }
    };
    bower_redaction::decode_key_material(raw).map_err(|_| {
        SettingsError::new(
            "The privacy HMAC key secret must hold at least 32 bytes (base64 or raw).",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_ranges_map_to_positions() {
        assert!(rejected_log_events(3, None, None, None).is_empty());
        assert_eq!(
            rejected_log_events(5, Some(3), Some(0), None),
            vec![
                (0, "cloudwatch-logs-too-old"),
                (3, "cloudwatch-logs-too-new"),
                (4, "cloudwatch-logs-too-new")
            ]
        );
        assert_eq!(
            rejected_log_events(3, None, Some(1), Some(0)),
            vec![
                (0, "cloudwatch-logs-expired"),
                (1, "cloudwatch-logs-too-old")
            ]
        );
        assert!(rejected_log_events(2, Some(-1), None, None).is_empty());
    }

    /// Whatever the service means by an end index (inclusive or exclusive), every event
    /// it refused is reported as refused: the mapping never claims a rejected event.
    #[test]
    fn rejections_cover_both_readings_of_end_indexes() {
        for count in 0..6usize {
            for end in -1..6i32 {
                for (too_old, expired) in [(Some(end), None), (None, Some(end))] {
                    let marked: Vec<usize> = rejected_log_events(count, None, too_old, expired)
                        .into_iter()
                        .map(|(position, _)| position)
                        .collect();
                    let end = usize::try_from(end).ok();
                    let exclusive: Vec<usize> = (0..count)
                        .filter(|position| end.is_some_and(|end| *position < end))
                        .collect();
                    let inclusive: Vec<usize> = (0..count)
                        .filter(|position| end.is_some_and(|end| *position <= end))
                        .collect();
                    assert!(exclusive.iter().all(|position| marked.contains(position)));
                    assert_eq!(marked, inclusive, "count {count} end {end:?}");
                }
            }
        }
    }
}
