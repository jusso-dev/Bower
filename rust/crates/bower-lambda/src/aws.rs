//! AWS clients. Credentials come only from the Lambda execution role through the
//! default provider chain (the runtime's `AWS_*` session variables); no keys are
//! stored or configured by Bower.

use std::time::Duration;

use aws_sdk_cloudtraildata::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_cloudtraildata::types::AuditEvent;

use crate::audit::AuditRecord;
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
                    event_id: entry.event_id().to_string(),
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
