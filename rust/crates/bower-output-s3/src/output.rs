//! C# `S3Output`: one conditional PUT per planned object (`If-None-Match: *`, SHA-256
//! checksum, server-side encryption). Delivered means S3 accepted the PUT; it is not
//! Sentinel delivery. The first destination failure holds this and every later object.

use std::io::Write;
use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_credential_types::provider::error::CredentialsError;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::{ConnectorError, ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, ServerSideEncryption};
use base64::Engine;
use bower_contracts::abstractions::{DeliveryFailure, DeliveryResult, OutputAdapter, QueuedEvent};
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use crate::layout::{self, PlannedObject};
use crate::options::{S3OutputOptions, S3SettingsError, SSE_KMS};

pub const THROTTLED_CODE: &str = "destination-s3-throttled";
pub const ACCESS_DENIED_CODE: &str = "destination-s3-access-denied";
pub const KMS_DENIED_CODE: &str = "destination-s3-kms-denied";
pub const NO_SUCH_BUCKET_CODE: &str = "destination-s3-no-such-bucket";
pub const WRONG_REGION_CODE: &str = "destination-s3-wrong-region";
pub const CREDENTIAL_FAILED_CODE: &str = "destination-s3-credential-failed";
pub const UNAVAILABLE_CODE: &str = "destination-s3-unavailable";
pub const CANCELLED_CODE: &str = "destination-s3-cancelled";
pub const HTTP_CODE_PREFIX: &str = "destination-s3-http-";

pub struct S3Output {
    options: S3OutputOptions,
    client: OnceCell<aws_sdk_s3::Client>,
}

impl S3Output {
    /// Production client from the AWS default credential chain, built on the first
    /// delivery so start-up never resolves (or logs about) credentials.
    pub fn new(options: S3OutputOptions) -> Result<Self, S3SettingsError> {
        options.validate()?;
        Ok(Self {
            options,
            client: OnceCell::new(),
        })
    }

    /// An output over a prepared client (tests and fakes).
    pub fn with_client(
        options: S3OutputOptions,
        client: aws_sdk_s3::Client,
    ) -> Result<Self, S3SettingsError> {
        options.validate()?;
        Ok(Self {
            options,
            client: OnceCell::new_with(Some(client)),
        })
    }

    async fn client(&self) -> &aws_sdk_s3::Client {
        self.client
            .get_or_init(|| async {
                let config = aws_config::defaults(BehaviorVersion::latest())
                    .region(aws_config::Region::new(self.options.region.clone()))
                    // Three attempts in memory; anything longer waits in the durable queue.
                    .retry_config(RetryConfig::standard().with_max_attempts(3))
                    .timeout_config(
                        TimeoutConfig::builder()
                            .connect_timeout(Duration::from_secs(10))
                            .operation_attempt_timeout(Duration::from_secs(60))
                            .operation_timeout(Duration::from_secs(180))
                            .build(),
                    )
                    .load()
                    .await;
                aws_sdk_s3::Client::new(&config)
            })
            .await
    }

    /// One conditional PUT; `None` on success, otherwise a bounded failure code.
    async fn put(&self, item: &PlannedObject) -> Option<String> {
        let content = if self.options.gzip {
            compress(&item.body)
        } else {
            item.body.clone()
        };
        let checksum = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&content));
        let mut request = self
            .client()
            .await
            .put_object()
            .bucket(&self.options.bucket)
            .key(&item.key)
            .body(ByteStream::from(content))
            .content_type("application/x-ndjson")
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .checksum_sha256(checksum)
            .if_none_match("*")
            .metadata("bower-events", item.event_ids.len().to_string());
        // Unset: no header, so the bucket's default encryption (possibly a KMS key) applies.
        if let Some(sse) = &self.options.server_side_encryption {
            request = request.server_side_encryption(if sse == SSE_KMS {
                ServerSideEncryption::AwsKms
            } else {
                ServerSideEncryption::Aes256
            });
        }
        if let Some(key) = &self.options.kms_key_id {
            request = request.ssekms_key_id(key);
        }
        if let Some(owner) = &self.options.expected_bucket_owner {
            request = request.expected_bucket_owner(owner);
        }
        if self.options.gzip {
            request = request.content_encoding("gzip");
        }
        match request.send().await {
            Ok(_) => None,
            Err(error) => classify_error(&error),
        }
    }
}

impl OutputAdapter for S3Output {
    fn id(&self) -> &str {
        &self.options.id
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        if events.is_empty() {
            return DeliveryResult::default();
        }
        let (objects, rejected) = layout::plan(
            events,
            &self.options.prefix,
            &self.options.collector_id,
            self.options.maximum_object_bytes,
            self.options.maximum_object_events,
            self.options.gzip,
        );
        let mut failures = rejected;
        let mut acknowledged = Vec::new();
        let mut acknowledgements = std::collections::HashMap::new();
        for (index, item) in objects.iter().enumerate() {
            if let Some(code) = self.put(item).await {
                for held in &objects[index..] {
                    failures.extend(held.event_ids.iter().map(|event_id| DeliveryFailure {
                        event_id: event_id.clone(),
                        code: code.clone(),
                        is_retryable: true,
                        retry_after: None,
                    }));
                }
                break;
            }
            acknowledged.extend(item.event_ids.iter().cloned());
            for event_id in &item.event_ids {
                acknowledgements.insert(
                    event_id.clone(),
                    acknowledgement(&self.options.bucket, &item.key),
                );
            }
        }
        // Every event's acknowledgement names its own object; the batch-level value is the
        // first object's, for readers of the batch result only.
        DeliveryResult {
            destination_acknowledgement: acknowledged
                .first()
                .map(|event_id| acknowledgements[event_id].clone()),
            acknowledged_event_ids: acknowledged,
            failures,
            event_acknowledgements: acknowledgements,
        }
    }
}

/// C# `S3Output.Classify`: maps an S3 error response to a destination code. `None` means
/// success: 412 answers `If-None-Match: *` when the key already exists, and the key binds
/// the collector, the exact ids and the uncompressed body, so the stored object holds
/// byte-identical content. Every code is
/// retryable; access, bucket, KMS and region faults wait in the queue for an operator.
pub fn classify(status: u16, error_code: Option<&str>, message_names_kms: bool) -> Option<String> {
    if status == 412 {
        return None;
    }
    let code = match error_code {
        Some(
            "SlowDown"
            | "Throttling"
            | "ThrottlingException"
            | "RequestLimitExceeded"
            | "TooManyRequestsException"
            | "RequestThrottled"
            | "RequestThrottledException",
        ) => THROTTLED_CODE,
        _ if status == 429 || status == 503 => THROTTLED_CODE,
        Some(code) if code.starts_with("KMS.") => KMS_DENIED_CODE,
        Some("AccessDenied") if message_names_kms => KMS_DENIED_CODE,
        Some(
            "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "ExpiredToken"
            | "InvalidToken"
            | "TokenRefreshRequired"
            | "MissingSecurityHeader",
        ) => CREDENTIAL_FAILED_CODE,
        Some("AccessDenied" | "AllAccessDisabled" | "AccountProblem" | "InvalidPayer") => {
            ACCESS_DENIED_CODE
        }
        _ if status == 403 => ACCESS_DENIED_CODE,
        Some("NoSuchBucket") => NO_SUCH_BUCKET_CODE,
        Some(
            "PermanentRedirect"
            | "AuthorizationHeaderMalformed"
            | "IllegalLocationConstraintException",
        ) => WRONG_REGION_CODE,
        _ if status == 301 => WRONG_REGION_CODE,
        _ if (100..=599).contains(&status) => return Some(format!("{HTTP_CODE_PREFIX}{status}")),
        _ => UNAVAILABLE_CODE,
    };
    Some(code.to_string())
}

/// C# `S3Output.Acknowledgement`: persisted with each acknowledged event, the object
/// that holds it.
pub fn acknowledgement(bucket: &str, key: &str) -> String {
    format!("s3://{bucket}/{key}")
}

type PutError = SdkError<PutObjectError, HttpResponse>;

/// Response and transport errors never leave this function as text: only a bounded code.
fn classify_error(error: &PutError) -> Option<String> {
    match error {
        SdkError::ServiceError(context) => {
            // Service messages can carry ARNs; only whether one names KMS is kept.
            let message_names_kms = context
                .err()
                .message()
                .is_some_and(|message| message.to_ascii_lowercase().contains("kms"));
            classify(
                context.raw().status().as_u16(),
                context.err().code(),
                message_names_kms,
            )
        }
        SdkError::ResponseError(context) => classify(context.raw().status().as_u16(), None, false),
        _ if credential_failure(error) => Some(CREDENTIAL_FAILED_CODE.to_string()),
        _ => Some(UNAVAILABLE_CODE.to_string()),
    }
}

/// C# `IsCredentialFailure`: the default chain found no credentials or could not use
/// them. A network fault anywhere in the chain (an I/O error, a connector I/O or timeout
/// error, a provider timeout), such as an unreachable IMDS endpoint wrapped in
/// `CredentialsError::ProviderError`, is an outage like any other.
pub fn credential_failure(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut credentials = false;
    let mut current = Some(error);
    while let Some(item) = current {
        if item.is::<std::io::Error>()
            || item
                .downcast_ref::<ConnectorError>()
                .is_some_and(|connector| connector.is_io() || connector.is_timeout())
            || matches!(
                item.downcast_ref::<CredentialsError>(),
                Some(CredentialsError::ProviderTimedOut(_))
            )
        {
            return false;
        }
        credentials |= item.is::<CredentialsError>();
        current = item.source();
    }
    credentials
}

fn compress(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(body)
        .and_then(|()| encoder.finish())
        .expect("gzip into memory cannot fail")
}
