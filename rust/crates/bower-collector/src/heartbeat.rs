//! Registers the collector and reports queue, output and background-job health to the
//! management API (C# `ManagementHeartbeatJob`). Metadata only: never events, payloads
//! or credentials. Failures are logged by type and superseded by the next run.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::{Timestamp, serde_offset_option};
use bower_contracts::{DurableEventStore, LedgerHead, QueueSnapshot};
use reqwest::{StatusCode, Url};
use serde::Serialize;
use tracing::{info, warn};

use crate::jobs::{BackgroundJobStatus, JobCatalog};
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
    if snapshot.delivered > 0 {
        "api-accepted"
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
    pub output_type: String,
    pub maximum_queue_bytes: i64,
}

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
}

impl ManagementHeartbeat {
    pub fn from_settings(
        settings: &CollectorSettings,
        policy_hash: String,
        credential: Arc<dyn AccessTokenSource>,
        store: Arc<dyn DurableEventStore>,
        catalog: Arc<JobCatalog>,
    ) -> Option<Self> {
        let base = settings.management_endpoint.clone()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .ok()?;
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
            output_type: settings.output_type.clone(),
            maximum_queue_bytes: settings.maximum_queue_bytes,
        })
    }

    /// One run. Collection and delivery continue when management is unreachable, so
    /// failures are logged and swallowed (`[AutomaticRetry(Attempts = 0)]`).
    pub async fn run(&self) -> Result<(), &'static str> {
        if let Err(failure) = self.report().await {
            warn!(
                exception_type = failure,
                "Management heartbeat failed; collection and delivery continue."
            );
        }
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

        let delivery_status = delivery_health(
            &self.output_type,
            &snapshot,
            self.maximum_queue_bytes,
            bower_contracts::time::now(),
        );
        let sources = [SourceReport {
            id: "local-http",
            kind: "local-http",
            status: "healthy",
            lag_seconds: None,
            last_event_at: None,
        }];
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
        };
        let path = format!(
            "api/collectors/{}/heartbeat",
            escape_data_string(&self.collector_id)
        );
        let status = self.post(&path, &token, &heartbeat).await?;
        if status == StatusCode::CONFLICT {
            info!("Collector is awaiting approval or is not permitted to heartbeat.");
            return Ok(());
        }
        if !status.is_success() {
            return Err("HttpRequestException");
        }
        Ok(())
    }

    // The bearer token is attached per request, never to shared default headers.
    async fn post<T: Serialize>(
        &self,
        path: &str,
        token: &str,
        body: &T,
    ) -> Result<StatusCode, &'static str> {
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
        Ok(response.status())
    }
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
