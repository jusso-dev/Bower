//! Registers the collector and reports queue, output and background-job health to the
//! management API (C# `ManagementHeartbeatJob`). Metadata only: never events, payloads
//! or credentials. Failures are logged by type and superseded by the next run.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bower_contracts::time::{Timestamp, serde_offset, serde_offset_option};
use bower_contracts::{DurableEventStore, LedgerHead, QueueSnapshot};
use bower_core::PipelineTelemetry;
use reqwest::{StatusCode, Url};
use serde::Serialize;
use tracing::{info, warn};

use crate::jobs::{BackgroundJobStatus, JobCatalog};
use crate::management_commands::{CanaryReport, CommandProcessor, CommandResultReport};
use crate::settings::CollectorSettings;
use crate::worker::store_error_name;

pub type TokenFuture<'a> = Pin<Box<dyn Future<Output = Result<String, &'static str>> + Send + 'a>>;

/// Queue observations only; retained acknowledgements are not destination proof.
pub fn delivery_health(
    output: &str,
    snapshot: &QueueSnapshot,
    capacity: i64,
    now: Timestamp,
) -> &'static str {
    if output.eq_ignore_ascii_case("none") {
        return "disabled";
    }
    if snapshot.dead_lettered > 0 {
        return "degraded";
    }
    if snapshot.undelivered_bytes >= capacity - capacity / 10 {
        return "backpressure";
    }
    if snapshot
        .oldest_undelivered
        .is_some_and(|oldest| (now - oldest).num_seconds() > 300)
    {
        return "stalled";
    }
    if snapshot.retrying > 0 {
        return "retrying";
    }
    if snapshot.uploading > 0 || snapshot.queued > 0 {
        return "pending";
    }
    // Historical receipts may belong to a previously configured output.
    if snapshot.delivered > 0 {
        "idle"
    } else {
        "waiting"
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn disabled_stalled_and_full_delivery_is_never_healthy() {
        let now = bower_contracts::time::now();
        let mut snapshot = QueueSnapshot {
            queued: 0,
            retrying: 0,
            uploading: 0,
            delivered: 0,
            dead_lettered: 0,
            total_bytes: 0,
            oldest_undelivered: None,
            undelivered_bytes: 0,
        };
        assert_eq!(delivery_health("none", &snapshot, 1000, now), "disabled");
        assert_eq!(
            delivery_health("azure-logs-ingestion", &snapshot, 1000, now),
            "waiting"
        );
        snapshot.delivered = 1;
        assert_eq!(delivery_health("ama-spool", &snapshot, 1000, now), "idle");
        assert_eq!(
            delivery_health("azure-logs-ingestion", &snapshot, 1000, now),
            "idle"
        );
        snapshot.delivered = 0;
        snapshot.retrying = 1;
        assert_eq!(
            delivery_health("azure-logs-ingestion", &snapshot, 1000, now),
            "retrying"
        );
        snapshot.oldest_undelivered = Some(now - chrono::Duration::minutes(6));
        assert_eq!(
            delivery_health("azure-logs-ingestion", &snapshot, 1000, now),
            "stalled"
        );
        snapshot.undelivered_bytes = 950;
        assert_eq!(
            delivery_health("azure-logs-ingestion", &snapshot, 1000, now),
            "backpressure"
        );
    }
}

/// Bearer token source for the management API (one explicit Azure credential).
/// Errors are type names only.
pub trait AccessTokenSource: Send + Sync {
    fn access_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a>;
}

pub struct ManagementHeartbeat {
    pub client: reqwest::Client,
    pub base: Url,
    pub scope: String,
    pub credential: Arc<dyn AccessTokenSource>,
    pub store: Arc<dyn DurableEventStore>,
    pub catalog: Arc<JobCatalog>,
    pub collector_id: String,
    pub machine_name: String,
    pub environment: String,
    pub version: String,
    pub configuration_hash: String,
    pub policy_hash: String,
    /// Active privacy profile content hash, or `default` for the built-in profile.
    pub privacy_profile_hash: String,
    pub output_type: String,
    pub maximum_queue_bytes: i64,
    /// Expected applications report as sources so silent ones show in the console.
    pub source_health: Option<Arc<crate::source_health::SourceHealth>>,
    /// Heartbeat v2 commands: verified, admitted and handed to the command worker.
    pub commands: Option<Arc<CommandProcessor>>,
    /// Last output acknowledgement for `lastSuccessfulDeliveryAt`.
    pub delivery_activity: Option<Arc<crate::worker::DeliveryActivity>>,
    /// Token enrolment: enrol before reporting, rotate on schedule after.
    pub enrolment: Option<Arc<crate::enrolment::ManagementEnrolment>>,
    /// Redaction counters for `redactions`; `null` when not wired.
    pub telemetry: Option<Arc<PipelineTelemetry>>,
}

/// The job runs every minute; management derives staleness from this interval.
pub const INTERVAL_SECONDS: i32 = 60;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceReport<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    status: &'a str,
    lag_seconds: Option<i64>,
    #[serde(with = "serde_offset_option")]
    last_event_at: Option<Timestamp>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputReport<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    status: &'a str,
    #[serde(with = "serde_offset_option")]
    last_acknowledged_at: Option<Timestamp>,
    last_error_code: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Registration<'a> {
    collector_id: &'a str,
    machine_name: &'a str,
    environment: &'a str,
    version: &'a str,
    configuration_hash: &'a str,
    policy_hash: &'a str,
    sources: &'a [SourceReport<'a>],
    outputs: &'a [OutputReport<'a>],
}

#[derive(Serialize)]
struct LedgerReport<'a> {
    sequence: i64,
    hash: &'a str,
}

/// Queued events per redacted detector type since process start. Counts only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RedactionReport {
    #[serde(with = "serde_offset")]
    observed_since: Timestamp,
    counts: Vec<RedactionCountReport>,
}

#[derive(Serialize)]
struct RedactionCountReport {
    #[serde(rename = "type")]
    kind: String,
    events: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Heartbeat<'a> {
    version: &'a str,
    configuration_hash: &'a str,
    policy_hash: &'a str,
    queue_depth: i64,
    delivery_status: &'a str,
    sources: &'a [SourceReport<'a>],
    outputs: &'a [OutputReport<'a>],
    jobs: &'a [BackgroundJobStatus],
    dead_lettered: i64,
    ledger: LedgerReport<'a>,
    privacy_profile_hash: &'a str,
    // Heartbeat v2: additive. A body without schemaVersion is v1.
    schema_version: i32,
    heartbeat_interval_seconds: i32,
    oldest_undelivered_age_seconds: Option<i64>,
    #[serde(with = "serde_offset_option")]
    last_successful_delivery_at: Option<Timestamp>,
    last_canary: Option<CanaryReport>,
    command_capabilities: Vec<&'static str>,
    command_results: &'a [CommandResultReport],
    redactions: Option<RedactionReport>,
}

impl ManagementHeartbeat {
    pub fn from_settings(
        settings: &CollectorSettings,
        policy_hash: String,
        privacy_profile_hash: Option<&str>,
        credential: Arc<dyn AccessTokenSource>,
        store: Arc<dyn DurableEventStore>,
        catalog: Arc<JobCatalog>,
    ) -> Option<Self> {
        let base = settings.management_endpoint.clone()?;
        let client = crate::management_http::client(settings).ok()?;
        Some(Self {
            client,
            base,
            scope: settings.management_scope.clone().unwrap_or_default(),
            credential,
            store,
            catalog,
            collector_id: settings.collector_id.clone(),
            machine_name: crate::settings::machine_name(),
            environment: settings.environment.clone(),
            version: settings.version.clone(),
            configuration_hash: settings.configuration_hash(),
            policy_hash,
            privacy_profile_hash: privacy_profile_hash.unwrap_or("default").to_string(),
            output_type: settings.output_type.clone(),
            maximum_queue_bytes: settings.maximum_queue_bytes,
            source_health: None,
            commands: None,
            delivery_activity: None,
            enrolment: None,
            telemetry: None,
        })
    }

    /// One run. Collection and delivery continue when management is unreachable, so
    /// failures are logged and swallowed (`[AutomaticRetry(Attempts = 0)]`).
    pub async fn run(&self) -> Result<(), &'static str> {
        if let Err(failure) = self.enrol_and_report().await {
            warn!(
                exception_type = failure,
                "Management heartbeat failed; collection and delivery continue."
            );
        }
        Ok(())
    }

    async fn enrol_and_report(&self) -> Result<(), &'static str> {
        let Some(enrolment) = &self.enrolment else {
            return self.report().await;
        };
        // Token enrolment (no Azure identity): exchange a new token first, and report
        // nothing until a credential is held.
        enrolment.ensure_enrolled().await?;
        if !enrolment.enrolled() {
            return Ok(());
        }
        self.report().await?;
        // Scheduled rotation; the current credential keeps working until the new one is used.
        enrolment.rotate_if_due().await;
        Ok(())
    }

    async fn report(&self) -> Result<(), &'static str> {
        let token = self.credential.access_token(&self.scope).await?;
        let store = Arc::clone(&self.store);
        let (snapshot, ledger): (QueueSnapshot, LedgerHead) =
            tokio::task::spawn_blocking(move || {
                Ok::<_, bower_contracts::StoreError>((store.snapshot()?, store.ledger_head()?))
            })
            .await
            .map_err(|_| "JoinError")?
            .map_err(|error| store_error_name(&error))?;

        let now = bower_contracts::time::now();
        let delivery_status =
            delivery_health(&self.output_type, &snapshot, self.maximum_queue_bytes, now);
        // Finished command results stay pending until management acknowledges them.
        let results = self
            .commands
            .as_ref()
            .map(|commands| commands.ledger().pending_results())
            .unwrap_or_default();
        // Expected applications report as sources so silent ones show in the console.
        let expected: Vec<(String, String, Option<i64>, Option<Timestamp>)> = self
            .source_health
            .as_ref()
            .map(|health| health.evaluate())
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                let status = if item.is_active() {
                    "healthy".to_owned()
                } else {
                    item.state.clone()
                };
                (
                    format!("{}/{}", item.application, item.environment),
                    status,
                    Some(item.silent_seconds),
                    item.last_seen_at,
                )
            })
            .collect();
        let mut sources = vec![SourceReport {
            id: "local-http",
            kind: "local-http",
            status: "healthy",
            lag_seconds: None,
            last_event_at: None,
        }];
        sources.extend(expected.iter().map(|(id, status, lag, last)| SourceReport {
            id,
            kind: "application",
            status,
            lag_seconds: *lag,
            last_event_at: *last,
        }));
        let outputs = [OutputReport {
            id: &self.output_type,
            kind: &self.output_type,
            status: delivery_status,
            last_acknowledged_at: None,
            last_error_code: None,
        }];
        let jobs = self.catalog.list();

        let registration = Registration {
            collector_id: &self.collector_id,
            machine_name: &self.machine_name,
            environment: &self.environment,
            version: &self.version,
            configuration_hash: &self.configuration_hash,
            policy_hash: &self.policy_hash,
            sources: &sources,
            outputs: &outputs,
        };
        let registered = self
            .post("api/collectors/register", &token, &registration)
            .await?;
        if !registered.is_success() {
            warn!(
                status_code = registered.as_u16(),
                "Management registration returned an unsuccessful HTTP status."
            );
            return Ok(());
        }

        let heartbeat = Heartbeat {
            version: &self.version,
            configuration_hash: &self.configuration_hash,
            policy_hash: &self.policy_hash,
            queue_depth: snapshot.queued + snapshot.retrying + snapshot.uploading,
            delivery_status,
            sources: &sources,
            outputs: &outputs,
            jobs: &jobs,
            dead_lettered: snapshot.dead_lettered,
            ledger: LedgerReport {
                sequence: ledger.sequence,
                hash: &ledger.hash,
            },
            privacy_profile_hash: &self.privacy_profile_hash,
            schema_version: 2,
            heartbeat_interval_seconds: INTERVAL_SECONDS,
            oldest_undelivered_age_seconds: snapshot
                .oldest_undelivered
                .map(|oldest| (now - oldest).num_seconds().max(0)),
            last_successful_delivery_at: self
                .delivery_activity
                .as_ref()
                .and_then(|activity| activity.last_successful_delivery_at()),
            last_canary: self
                .commands
                .as_ref()
                .and_then(|commands| commands.ledger().last_canary()),
            command_capabilities: self
                .commands
                .as_ref()
                .map(|commands| commands.capabilities())
                .unwrap_or_default(),
            command_results: &results,
            redactions: self.telemetry.as_ref().map(|telemetry| {
                let snapshot = telemetry.redaction_snapshot();
                RedactionReport {
                    observed_since: snapshot.observed_since,
                    counts: snapshot
                        .counts
                        .into_iter()
                        .map(|count| RedactionCountReport {
                            kind: count.kind,
                            events: count.events,
                        })
                        .collect(),
                }
            }),
        };
        let path = format!(
            "api/collectors/{}/heartbeat",
            escape_data_string(&self.collector_id)
        );
        let mut response = self.send(&path, &token, &heartbeat).await?;
        let status = response.status();
        if status == StatusCode::CONFLICT {
            info!("Collector is awaiting approval or is not permitted to heartbeat.");
            return Ok(());
        }
        if !status.is_success() {
            return Err("HttpRequestException");
        }
        if let Some(commands) = &self.commands {
            // Commands are verified and handed to the command worker; never executed here.
            let body = read_bounded(&mut response).await?;
            commands.handle_response(body.as_deref(), &results)?;
        }
        Ok(())
    }

    async fn post<T: Serialize>(
        &self,
        path: &str,
        token: &str,
        body: &T,
    ) -> Result<StatusCode, &'static str> {
        Ok(self.send(path, token, body).await?.status())
    }

    // The bearer token is attached per request, never to shared default headers.
    async fn send<T: Serialize>(
        &self,
        path: &str,
        token: &str,
        body: &T,
    ) -> Result<reqwest::Response, &'static str> {
        let url = self.base.join(path).map_err(|_| "UriFormatException")?;
        let body = bower_contracts::json::to_vec(body).map_err(|_| "JsonException")?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(body)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    "TaskCanceledException"
                } else {
                    "HttpRequestException"
                }
            })?;
        Ok(response)
    }
}

/// The response body, or `None` once it exceeds the command response bound.
async fn read_bounded(response: &mut reqwest::Response) -> Result<Option<Vec<u8>>, &'static str> {
    let limit = crate::management_commands::MAXIMUM_RESPONSE_BYTES;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            "TaskCanceledException"
        } else {
            "HttpRequestException"
        }
    })? {
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// `Uri.EscapeDataString`: percent-encode everything except RFC 3986 unreserved.
pub fn escape_data_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_dotnet() {
        assert_eq!(escape_data_string("a b/c?é~"), "a%20b%2Fc%3F%C3%A9~");
    }
}
