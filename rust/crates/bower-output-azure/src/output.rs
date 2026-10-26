//! `Bower.Output.AzureLogsIngestion`: delivery to a Data Collection Rule stream
//! through the Azure Monitor Logs Ingestion REST API (`api-version=2023-01-01`).
//!
//! Wire behaviour follows `Azure.Monitor.Ingestion` 1.2 with Azure.Core defaults:
//! records re-serialized as a JSON array, 1 MiB batches, gzip bodies, bearer
//! tokens for `https://monitor.azure.com//.default`, exponential retries honouring
//! `Retry-After`. Upload success is ingestion acceptance only, never proof of
//! Sentinel queryability.

use std::collections::HashSet;
use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bower_contracts::time::Timestamp;
use bower_contracts::{
    DeliveryFailure, DeliveryResult, OutputAdapter, OutputConcurrencySnapshot, QueuedEvent,
};
use bower_dcr::SentinelSchema;
use flate2::Compression;
use flate2::write::GzEncoder;
use reqwest::Url;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Map, Value};
use tokio::task::JoinSet;

use crate::concurrency::{AdaptiveConcurrencyController, ConcurrencySignal};
use crate::credential::{CachedTokenProvider, TokenProvider};

/// Token scope used by `LogsIngestionClient` for the public cloud.
pub const MONITOR_SCOPE: &str = "https://monitor.azure.com//.default";
/// Logs Ingestion REST API version used by `Azure.Monitor.Ingestion` 1.2.
pub const API_VERSION: &str = "2023-01-01";
/// Hard uncompressed JSON-array byte limit, including commas and brackets.
pub const SINGLE_UPLOAD_THRESHOLD: usize = 1024 * 1024;
/// `JsonNode.Parse` default maximum depth.
const MAXIMUM_PAYLOAD_DEPTH: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AzureOutputError {
    #[error("invalid Azure Logs Ingestion options: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug)]
pub struct AzureLogsIngestionOptions {
    pub id: String,
    pub endpoint: Url,
    pub dcr_immutable_id: String,
    pub stream_name: String,
    /// Parallel batch uploads (1..=32, default 4): the adaptive controller's ceiling.
    pub maximum_concurrency: usize,
    /// What one adaptive controller bounds (C# `ConcurrencyScope`).
    pub concurrency_scope: ConcurrencyScope,
    /// Stream schema used for preflight checks before upload.
    pub schema: SentinelSchema,
}

/// C# `ConcurrencyScope`: what one adaptive concurrency controller bounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConcurrencyScope {
    /// Every delivery of the output (one DCR stream): the collector's single delivery loop.
    #[default]
    Output,
    /// Each delivery on its own, as the fixed setting did: hosts that deliver many caller
    /// requests concurrently through one output.
    Delivery,
}

/// C# `TimeProvider` for the output: wall time for Retry-After deadlines and pauses,
/// monotonic time for request RTT.
pub trait TimeSource: Send + Sync + std::fmt::Debug {
    fn utc_now(&self) -> Timestamp;
    /// Monotonic reading; only differences are meaningful.
    fn monotonic(&self) -> Duration;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn utc_now(&self) -> Timestamp {
        bower_contracts::time::now()
    }

    fn monotonic(&self) -> Duration {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed()
    }
}

impl AzureLogsIngestionOptions {
    pub fn new(
        id: impl Into<String>,
        endpoint: Url,
        dcr_immutable_id: impl Into<String>,
        stream_name: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            endpoint,
            dcr_immutable_id: dcr_immutable_id.into(),
            stream_name: stream_name.into(),
            maximum_concurrency: 4,
            concurrency_scope: ConcurrencyScope::Output,
            schema: SentinelSchema::default_schema().clone(),
        }
    }

    fn validate(&self) -> Result<(), AzureOutputError> {
        for (name, value) in [
            ("id", &self.id),
            ("dcr_immutable_id", &self.dcr_immutable_id),
            ("stream_name", &self.stream_name),
        ] {
            if value.trim().is_empty() {
                return Err(AzureOutputError::Invalid(format!("{name} is required")));
            }
        }
        if self.endpoint.scheme() != "https" {
            return Err(AzureOutputError::Invalid(
                "Azure ingestion endpoint must use HTTPS.".to_owned(),
            ));
        }
        if !(1..=32).contains(&self.maximum_concurrency) {
            return Err(AzureOutputError::Invalid(
                "maximum_concurrency must be 1..=32".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Pipeline settings (Azure.Core `ClientOptions` defaults).
#[derive(Clone, Debug)]
pub struct IngestionClientOptions {
    /// Retries after the first attempt (`RetryOptions.MaxRetries`, default 3).
    pub max_retries: u32,
    /// Base exponential delay (`RetryOptions.Delay`, default 0.8 s).
    pub retry_delay: Duration,
    /// Cap for computed delays (`RetryOptions.MaxDelay`, default 60 s). A larger
    /// server `Retry-After` still wins, as in Azure.Core.
    pub max_retry_delay: Duration,
    /// Per-attempt timeout (`RetryOptions.NetworkTimeout`, default 100 s).
    pub network_timeout: Duration,
    pub scope: String,
    /// Test transport: send requests to this base URL instead of `endpoint`
    /// (the equivalent of replacing the C# `HttpPipelineTransport`). Validation of
    /// the configured endpoint is unchanged.
    pub transport_base_url: Option<Url>,
    /// Clock for Retry-After deadlines, pauses and RTT (default: system).
    pub time: Arc<dyn TimeSource>,
}

impl Default for IngestionClientOptions {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_millis(800),
            max_retry_delay: Duration::from_secs(60),
            network_timeout: Duration::from_secs(100),
            scope: MONITOR_SCOPE.to_owned(),
            transport_base_url: None,
            time: Arc::new(SystemTimeSource),
        }
    }
}

pub struct AzureLogsIngestionOutput {
    options: AzureLogsIngestionOptions,
    client_options: IngestionClientOptions,
    upload_url: Url,
    http: reqwest::Client,
    credential: Arc<dyn TokenProvider>,
    /// One controller per output: one DCR stream. `maximum_concurrency` is its ceiling.
    concurrency: Arc<AdaptiveConcurrencyController>,
}

impl AzureLogsIngestionOutput {
    pub fn new(
        options: AzureLogsIngestionOptions,
        credential: Arc<dyn TokenProvider>,
    ) -> Result<Self, AzureOutputError> {
        Self::with_client_options(options, credential, IngestionClientOptions::default())
    }

    pub fn with_client_options(
        options: AzureLogsIngestionOptions,
        credential: Arc<dyn TokenProvider>,
        client_options: IngestionClientOptions,
    ) -> Result<Self, AzureOutputError> {
        options.validate()?;
        let base = client_options
            .transport_base_url
            .clone()
            .unwrap_or_else(|| options.endpoint.clone());
        let upload_url = upload_url(&base, &options.dcr_immutable_id, &options.stream_name)?;
        let http = reqwest::Client::builder()
            .timeout(client_options.network_timeout)
            // Azure.Core does not follow redirects; never replay the bearer token.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AzureOutputError::Invalid("HTTP client could not be built".to_owned()))?;
        let concurrency = Arc::new(AdaptiveConcurrencyController::new(
            options.maximum_concurrency,
        )?);
        Ok(Self {
            options,
            client_options,
            upload_url,
            http,
            concurrency,
            // BearerTokenAuthenticationPolicy caches the token in memory and refreshes
            // it five minutes before expiry.
            credential: Arc::new(CachedTokenProvider::new(credential)),
        })
    }
}

/// `{endpoint}/dataCollectionRules/{ruleId}/streams/{stream}?api-version=2023-01-01`
/// with escaped path segments.
fn upload_url(base: &Url, rule_id: &str, stream_name: &str) -> Result<Url, AzureOutputError> {
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| AzureOutputError::Invalid("endpoint cannot be a base URL".to_owned()))?;
        segments
            .pop_if_empty()
            .extend(["dataCollectionRules", rule_id, "streams", stream_name]);
    }
    url.set_query(Some(&format!("api-version={API_VERSION}")));
    Ok(url)
}

fn failure(event_id: &str, code: impl Into<String>, is_retryable: bool) -> DeliveryFailure {
    DeliveryFailure {
        event_id: event_id.to_owned(),
        code: code.into(),
        is_retryable,
        retry_after: None,
    }
}

/// `JsonNode.Parse(payload) as JsonObject` with the default 64-level depth limit.
/// A duplicate top-level property is unparseable too (`JsonObject` cannot hold it);
/// C# dead-letters it as `payload-invalid-json` as well.
fn try_parse_record(payload: &str) -> Option<Map<String, Value>> {
    if exceeds_depth(payload.as_bytes(), MAXIMUM_PAYLOAD_DEPTH) {
        return None;
    }
    if serde_json::from_str::<TopLevelKeys>(payload).is_ok_and(|keys| keys.duplicate) {
        return None;
    }
    match serde_json::from_str::<Value>(payload) {
        Ok(Value::Object(record)) => Some(record),
        _ => None,
    }
}

/// Detects a repeated top-level property name without materialising values.
struct TopLevelKeys {
    duplicate: bool,
}

impl<'de> serde::Deserialize<'de> for TopLevelKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keys;
        impl<'de> serde::de::Visitor<'de> for Keys {
            type Value = TopLevelKeys;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<TopLevelKeys, A::Error> {
                let mut seen = HashSet::new();
                let mut duplicate = false;
                while let Some(key) = map.next_key::<String>()? {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    duplicate |= !seen.insert(key);
                }
                Ok(TopLevelKeys { duplicate })
            }
        }
        deserializer.deserialize_map(Keys)
    }
}

fn exceeds_depth(text: &[u8], maximum: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in text {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > maximum {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn read_event_id(record: &Map<String, Value>) -> Option<&str> {
    record.get("eventId").and_then(Value::as_str)
}

/// One upload request: JSON array body and the events it carries.
struct Batch {
    body: Vec<u8>,
    event_ids: Vec<String>,
}

/// Prepared entries fit within the hard request limit (checked before batching).
fn batch_records(records: Vec<(String, Vec<u8>)>) -> Vec<Batch> {
    let mut batches = Vec::new();
    let mut body: Vec<u8> = vec![b'['];
    let mut event_ids: Vec<String> = Vec::new();
    for (event_id, entry) in records {
        if !event_ids.is_empty() && body.len() + entry.len() + 2 > SINGLE_UPLOAD_THRESHOLD {
            body.push(b']');
            batches.push(Batch {
                body: std::mem::replace(&mut body, vec![b'[']),
                event_ids: std::mem::take(&mut event_ids),
            });
        }
        if !event_ids.is_empty() {
            body.push(b',');
        }
        body.extend_from_slice(&entry);
        event_ids.push(event_id);
    }
    if !event_ids.is_empty() {
        body.push(b']');
        batches.push(Batch { body, event_ids });
    }
    batches
}

/// Outcome of one batch after retries.
enum BatchOutcome {
    Accepted,
    /// `status` 0 means no HTTP response (transport, timeout or token failure).
    Failed {
        status: u16,
        retry_after: Option<bower_contracts::time::Timestamp>,
        retry_capped: bool,
    },
}

/// Azure.Core `ResponseClassifier`: retriable HTTP statuses.
fn is_retriable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Server-requested delay: `retry-after-ms`, `x-ms-retry-after-ms`, then
/// `Retry-After` (seconds or HTTP date).
fn server_delay(headers: &HeaderMap) -> Option<Duration> {
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
    };
    for name in ["retry-after-ms", "x-ms-retry-after-ms"] {
        if let Some(milliseconds) = text(name).and_then(|value| value.parse::<f64>().ok())
            && milliseconds.is_finite()
            && milliseconds >= 0.0
        {
            return Some(Duration::from_secs_f64(
                (milliseconds / 1000.0).min(253_402_300_799.0),
            ));
        }
    }
    let value = text("retry-after")?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds.min(253_402_300_799)));
    }
    let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let remaining = date.signed_duration_since(chrono::Utc::now());
    Some(remaining.to_std().unwrap_or(Duration::ZERO))
}

fn jitter() -> f64 {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return 1.0;
    }
    0.8 + 0.4 * f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX)
}

/// Azure.Core exponential `DelayStrategy`: `max(server, min(base * 2^(n-1) * jitter, max))`.
fn retry_delay(
    options: &IngestionClientOptions,
    retry_number: u32,
    server: Option<Duration>,
) -> Duration {
    let exponent = retry_number.saturating_sub(1).min(30);
    let computed = options
        .retry_delay
        .mul_f64(f64::from(1u32 << exponent) * jitter());
    let capped = computed.min(options.max_retry_delay);
    server.map_or(capped, |server| server.max(capped))
}

#[derive(Clone)]
struct Uploader {
    http: reqwest::Client,
    url: Url,
    credential: Arc<dyn TokenProvider>,
    options: IngestionClientOptions,
    concurrency: Arc<AdaptiveConcurrencyController>,
    /// Retry-After deadline seen by any attempt of this delivery.
    paused: Arc<Mutex<Option<Timestamp>>>,
}

impl Uploader {
    /// C# `DeliveryScope.Pause`: every attempt's Retry-After, including ones the retry
    /// loop sleeps through in memory, holds new batches of this delivery.
    fn pause(&self, until: Timestamp, now: Timestamp) {
        if until <= now {
            return;
        }
        self.concurrency.pause(until, now);
        let mut paused = self
            .paused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if paused.is_none_or(|current| current < until) {
            *paused = Some(until);
        }
    }

    fn paused_until(&self, now: Timestamp) -> Option<Timestamp> {
        self.paused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .filter(|until| *until > now)
    }

    async fn upload(&self, body: Vec<u8>) -> BatchOutcome {
        let mut encoder =
            GzEncoder::new(Vec::with_capacity(body.len() / 4), Compression::default());
        let compressed = match encoder.write_all(&body).and_then(|()| encoder.finish()) {
            Ok(compressed) => compressed,
            Err(_) => {
                return BatchOutcome::Failed {
                    status: 0,
                    retry_after: None,
                    retry_capped: false,
                };
            }
        };
        let client_request_id = uuid::Uuid::new_v4().to_string();
        let mut retry_number = 0u32;
        loop {
            let (retriable, server, outcome) = self.attempt(&compressed, &client_request_id).await;
            if !retriable
                || retry_number >= self.options.max_retries
                || server.is_some_and(|delay| delay > Duration::from_secs(60))
            {
                return outcome;
            }
            retry_number += 1;
            tokio::time::sleep(retry_delay(&self.options, retry_number, server)).await;
        }
    }

    /// One try. Returns (retriable, server delay, outcome).
    async fn attempt(
        &self,
        body: &[u8],
        client_request_id: &str,
    ) -> (bool, Option<Duration>, BatchOutcome) {
        let token = match self.credential.get_token(&self.options.scope).await {
            Ok(token) => token,
            // Credential failures are not retried by the pipeline.
            Err(_) => {
                return (
                    false,
                    None,
                    BatchOutcome::Failed {
                        status: 0,
                        retry_after: None,
                        retry_capped: false,
                    },
                );
            }
        };
        let Ok(authorization) = HeaderValue::from_str(&format!("Bearer {}", token.token)) else {
            return (
                false,
                None,
                BatchOutcome::Failed {
                    status: 0,
                    retry_after: None,
                    retry_capped: false,
                },
            );
        };
        let mut authorization = authorization;
        authorization.set_sensitive(true);
        // C# `ConcurrencyObserverPolicy` runs after the token policy: every attempt,
        // including retries, feeds the controller. A dropped (cancelled) attempt does not.
        let generation = self.concurrency.begin_attempt();
        let started = self.options.time.monotonic();
        let request = self
            .http
            .post(self.url.clone())
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_ENCODING, "gzip")
            .header(reqwest::header::ACCEPT, "application/json")
            .header("x-ms-client-request-id", client_request_id)
            .header("x-ms-return-client-request-id", "true")
            .body(body.to_vec());
        let sent = request.send().await;
        self.concurrency.complete(
            generation,
            sent.as_ref()
                .map_or(ConcurrencySignal::Timeout, |response| {
                    ConcurrencySignal::classify(response.status().as_u16())
                }),
            self.options.time.monotonic().saturating_sub(started),
        );
        match sent {
            Err(_) => (
                true,
                None,
                BatchOutcome::Failed {
                    status: 0,
                    retry_after: None,
                    retry_capped: false,
                },
            ),
            Ok(response) => {
                let status = response.status();
                let server = server_delay(response.headers());
                // Drop untrusted response bodies; never buffer or expose them.
                if status.is_success() {
                    (false, None, BatchOutcome::Accepted)
                } else {
                    let code = status.as_u16();
                    let now = self.options.time.utc_now();
                    let retry_after = server.map(|delay| {
                        now + chrono::Duration::from_std(delay.min(Duration::from_secs(3600)))
                            .expect("bounded retry delay")
                    });
                    if let Some(until) = retry_after {
                        self.pause(until, now);
                    }
                    (
                        is_retriable_status(code),
                        server,
                        BatchOutcome::Failed {
                            status: code,
                            retry_capped: server
                                .is_some_and(|delay| delay > Duration::from_secs(3600)),
                            retry_after,
                        },
                    )
                }
            }
        }
    }
}

impl AzureLogsIngestionOutput {
    /// Uploads `events`. Poison records (unparseable, id mismatch, preflight issue)
    /// fail alone and are not retryable. HTTP/credential/transport failures use the
    /// reserved destination fault namespace and preserve records for repair.
    pub async fn deliver_events(&self, events: &[QueuedEvent]) -> DeliveryResult {
        if events.is_empty() {
            return DeliveryResult::default();
        }

        let mut batch_event_ids: HashSet<&str> = HashSet::new();
        let mut accepted_ids: Vec<&str> = Vec::new();
        let mut records: Vec<(String, Vec<u8>)> = Vec::with_capacity(events.len());
        let mut failures: Vec<DeliveryFailure> = Vec::new();
        for item in events {
            let Some(record) = try_parse_record(&item.payload) else {
                // Never succeeds on retry: dead-letter it alone.
                failures.push(failure(&item.event_id, "payload-invalid-json", false));
                continue;
            };
            if read_event_id(&record) != Some(item.event_id.as_str()) {
                failures.push(failure(&item.event_id, "payload-event-id-mismatch", false));
                continue;
            }
            let issues = bower_dcr::preflight::check(&record, &self.options.schema);
            if let Some(issue) = issues.first() {
                // Azure would truncate, coerce or drop this row silently.
                failures.push(failure(
                    &item.event_id,
                    format!("preflight-{}", issue.code),
                    false,
                ));
                continue;
            }
            // Re-serialized as the SDK's JsonObject serializer writes it: strings
            // re-escaped, number text and property order kept from the payload.
            let Ok(entry) = bower_integrity::canonical_json::compact_from_str(&item.payload) else {
                failures.push(failure(&item.event_id, "payload-invalid-json", false));
                continue;
            };
            if entry.len() + 2 > SINGLE_UPLOAD_THRESHOLD {
                failures.push(failure(&item.event_id, "payload-too-large", false));
                continue;
            }
            records.push((item.event_id.clone(), entry));
            if batch_event_ids.insert(item.event_id.as_str()) {
                accepted_ids.push(item.event_id.as_str());
            }
        }

        if records.is_empty() {
            return DeliveryResult {
                acknowledged_event_ids: Vec::new(),
                failures,
                destination_acknowledgement: None,
            };
        }

        let uploader = Uploader {
            http: self.http.clone(),
            url: self.upload_url.clone(),
            credential: Arc::clone(&self.credential),
            options: self.client_options.clone(),
            concurrency: match self.options.concurrency_scope {
                ConcurrencyScope::Output => Arc::clone(&self.concurrency),
                ConcurrencyScope::Delivery => Arc::new(
                    AdaptiveConcurrencyController::new(self.options.maximum_concurrency)
                        .expect("validated maximum concurrency"),
                ),
            },
            // Server-requested pause seen during this delivery. Across deliveries the
            // durable destination circuit holds the stream instead.
            paused: Arc::default(),
        };
        let time = Arc::clone(&self.client_options.time);
        let budget = Arc::new(AtomicI32::new(16));
        let mut failed: HashSet<String> = HashSet::new();
        // Each task retains its batch IDs through every completion and isolation split.
        // JoinSet aborts in-flight requests on caller cancellation.
        let mut uploads = JoinSet::new();
        let mut batches = batch_records(records).into_iter();
        while let Some(batch) = batches.next() {
            // Back-pressure: wait for a slot under the adaptive limit, in batch order.
            let permit = uploader.concurrency.acquire().await;
            if let Some(until) = uploader.paused_until(time.utc_now()) {
                drop(permit);
                // Never sent: keep the records retryable behind the destination circuit.
                for event_id in std::iter::once(batch)
                    .chain(batches.by_ref())
                    .flat_map(|batch| batch.event_ids)
                {
                    let mut item = failure(&event_id, "destination-azure-paused", true);
                    item.retry_after = Some(until);
                    failures.push(item);
                    failed.insert(event_id);
                }
                break;
            }
            let uploader = uploader.clone();
            let budget = Arc::clone(&budget);
            let time = Arc::clone(&time);
            uploads.spawn(async move {
                let _permit = permit;
                let mut pending = vec![batch];
                let mut results = Vec::new();
                while let Some(batch) = pending.pop() {
                    let outcome = uploader.upload(batch.body.clone()).await;
                    if matches!(outcome, BatchOutcome::Failed { status: 400, retry_after, .. } if retry_after.is_none_or(|deadline| deadline <= time.utc_now()))
                        && batch.event_ids.len() > 1
                        && budget.fetch_sub(2, Ordering::SeqCst) >= 2
                    {
                        // RawValue preserves already prepared number text and escaping.
                        let entries: Vec<Box<serde_json::value::RawValue>> =
                            serde_json::from_slice(&batch.body).expect("owned valid JSON array");
                        let middle = entries.len() / 2;
                        for (entries, ids) in [
                            (&entries[middle..], &batch.event_ids[middle..]),
                            (&entries[..middle], &batch.event_ids[..middle]),
                        ] {
                            let body = format!("[{}]", entries.iter().map(|entry| entry.get()).collect::<Vec<_>>().join(",")).into_bytes();
                            pending.push(Batch { body, event_ids: ids.to_vec() });
                        }
                    } else {
                        results.push((batch.event_ids, outcome));
                    }
                }
                results
            });
        }

        let mut isolated = HashSet::new();
        while let Some(joined) = uploads.join_next().await {
            let Ok(results) = joined else {
                failures.extend(
                    accepted_ids
                        .iter()
                        .map(|id| failure(id, "destination-azure-unattributed", true)),
                );
                return DeliveryResult {
                    acknowledged_event_ids: Vec::new(),
                    failures,
                    destination_acknowledgement: None,
                };
            };
            for (event_ids, outcome) in results {
                if let BatchOutcome::Failed {
                    status,
                    retry_after,
                    retry_capped,
                } = outcome
                {
                    if status == 400
                        && event_ids.len() == 1
                        && retry_after
                            .is_none_or(|deadline| deadline <= self.client_options.time.utc_now())
                    {
                        isolated.insert(event_ids[0].clone());
                    }
                    for event_id in event_ids {
                        let code = if status == 0 {
                            "destination-azure-unavailable".to_owned()
                        } else {
                            format!(
                                "destination-azure-http-{status}{}",
                                if retry_capped {
                                    ":retry-after-capped"
                                } else {
                                    ""
                                }
                            )
                        };
                        let mut item = failure(&event_id, code, true);
                        item.retry_after = retry_after;
                        failures.push(item);
                        failed.insert(event_id);
                    }
                }
            }
        }

        let acknowledged: Vec<String> = accepted_ids
            .iter()
            .filter(|id| !failed.contains(**id))
            .map(|id| (*id).to_owned())
            .collect();
        if !acknowledged.is_empty() {
            for failure in &mut failures {
                if isolated.contains(&failure.event_id) {
                    failure.code = "azure-http-400-isolated".to_owned();
                    failure.is_retryable = false;
                    failure.retry_after = None;
                }
            }
        }
        let acknowledgement = (!acknowledged.is_empty())
            .then(|| "azure-logs-ingestion:accepted:owned-batches".to_owned());
        DeliveryResult {
            acknowledged_event_ids: acknowledged,
            failures,
            destination_acknowledgement: acknowledgement,
        }
    }
}

impl OutputAdapter for AzureLogsIngestionOutput {
    fn id(&self) -> &str {
        &self.options.id
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        self.deliver_events(events).await
    }

    fn concurrency_snapshot(&self) -> Option<OutputConcurrencySnapshot> {
        (self.options.concurrency_scope == ConcurrencyScope::Output).then(|| {
            self.concurrency
                .snapshot(&self.options.id, self.client_options.time.utc_now())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_url_matches_sdk() {
        let base = Url::parse("https://example.ingest.monitor.azure.com").unwrap();
        assert_eq!(
            upload_url(&base, "dcr-1", "Custom-BowerSecurity")
                .unwrap()
                .as_str(),
            "https://example.ingest.monitor.azure.com/dataCollectionRules/dcr-1/streams/Custom-BowerSecurity?api-version=2023-01-01"
        );
    }

    #[test]
    fn server_delay_prefers_milliseconds_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("7"));
        assert_eq!(server_delay(&headers), Some(Duration::from_secs(7)));
        headers.insert("retry-after-ms", HeaderValue::from_static("250"));
        assert_eq!(server_delay(&headers), Some(Duration::from_millis(250)));
    }

    #[test]
    fn computed_delay_is_capped_but_server_delay_wins() {
        let options = IngestionClientOptions::default();
        let first = retry_delay(&options, 1, None);
        assert!(first >= Duration::from_millis(640) && first <= Duration::from_millis(960));
        assert_eq!(retry_delay(&options, 30, None), Duration::from_secs(60));
        assert_eq!(
            retry_delay(&options, 1, Some(Duration::from_secs(120))),
            Duration::from_secs(120)
        );
    }
}
