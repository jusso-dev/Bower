//! C# `HttpOutput`: posts leased events, already redacted and decided, in bounded batches,
//! one at a time. An event is acknowledged only when the endpoint accepted its request
//! (2xx, and for HEC a `code` of 0): acceptance by the endpoint, not Sentinel delivery and
//! not proof of indexing. Everything else stays in the queue or is dead-lettered with a
//! bounded code. The token is held as a sensitive header value and never appears in
//! failures, errors or logs.

use std::io::Write as _;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bower_contracts::time::{Clock, SystemClock, Timestamp};
use bower_contracts::{DeliveryFailure, DeliveryResult, OutputAdapter, QueuedEvent};
use regex::Regex;
use reqwest::header::{
    AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue,
    RETRY_AFTER,
};
use serde::Deserialize;

use crate::options::{ConfigError, HttpOutputFormat, HttpOutputOptions, is_valid_token};

pub const OUTPUT_ID: &str = "http";
/// Largest response body read (HEC replies are a few dozen bytes).
pub const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;
/// 413 splits per delivery, so a hostile endpoint cannot multiply requests.
pub const SPLIT_BUDGET: usize = 16;
pub const SPLUNK_HEC_CONTENT_TYPE: &str = "application/json; charset=utf-8";
pub const NDJSON_CONTENT_TYPE: &str = "application/x-ndjson; charset=utf-8";
pub const CHANNEL_HEADER: &str = "X-Splunk-Request-Channel";
const MAXIMUM_RETRY_AFTER_SECONDS: i64 = 3600;
/// `DateTimeOffset.MaxValue` in Unix milliseconds.
const MAXIMUM_EVENT_MILLISECONDS: i64 = 253_402_300_799_999;

static STRICT_TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?(Z|[+-][0-9]{2}:[0-9]{2})\z",
    )
    .expect("static regex")
});

pub struct HttpOutput {
    options: HttpOutputOptions,
    client: reqwest::Client,
    clock: Arc<dyn Clock>,
    authorization: (HeaderName, HeaderValue),
    hec_metadata: Vec<u8>,
}

impl HttpOutput {
    /// `token` comes from `BOWER_HTTP_TOKEN_FILE` or `BOWER_HTTP_TOKEN` and stays in memory.
    /// The CA bundle is read here, so a bad file stops start-up.
    pub fn new(options: HttpOutputOptions, token: &str) -> Result<Self, ConfigError> {
        options.validate()?;
        if !is_valid_token(token) {
            // Never echo the value.
            return Err(ConfigError(
                "The HTTP output token (BOWER_HTTP_TOKEN_FILE or BOWER_HTTP_TOKEN) must be 1 to 4096 printable \
                 ASCII characters without spaces."
                    .into(),
            ));
        }
        let header_failed = || ConfigError("BOWER_HTTP_AUTH_HEADER could not be used.".into());
        let (name, value) = match (&options.format, options.authorization_header.as_deref()) {
            (HttpOutputFormat::SplunkHec, _) => (AUTHORIZATION, format!("Splunk {token}")),
            (HttpOutputFormat::Ndjson, None) => (AUTHORIZATION, format!("Bearer {token}")),
            (HttpOutputFormat::Ndjson, Some(name))
                if name.eq_ignore_ascii_case("authorization") =>
            {
                (AUTHORIZATION, format!("Bearer {token}"))
            }
            (HttpOutputFormat::Ndjson, Some(name)) => (
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| header_failed())?,
                token.to_string(),
            ),
        };
        let mut value = HeaderValue::from_str(&value).map_err(|_| header_failed())?;
        value.set_sensitive(true);
        let mut builder = reqwest::Client::builder()
            // A redirect is a misconfigured URL; it would also resend the token elsewhere.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(options.timeout.min(Duration::from_secs(10)))
            .timeout(options.timeout)
            .pool_idle_timeout(Duration::from_secs(60));
        if let Some(path) = &options.ca_bundle_path {
            builder = builder.tls_certs_merge(read_ca_bundle(path)?);
        }
        let client = builder
            .build()
            .map_err(|_| ConfigError("The HTTP output client could not be created.".into()))?;
        Ok(Self {
            hec_metadata: hec_metadata(&options),
            options,
            client,
            clock: Arc::new(SystemClock),
            authorization: (name, value),
        })
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Queue acknowledgement text: acceptance by the endpoint, nothing more.
    pub fn acknowledgement(&self) -> &'static str {
        match self.options.format {
            HttpOutputFormat::SplunkHec => "http:splunk-hec:endpoint-accepted",
            HttpOutputFormat::Ndjson => "http:ndjson:endpoint-accepted",
        }
    }

    /// C# `Encode`: one record without its newline, or a poison code. The payload is
    /// embedded as stored (raw CR and LF, which valid JSON holds only as whitespace, are
    /// removed).
    pub fn encode(&self, item: &QueuedEvent) -> Result<Vec<u8>, &'static str> {
        let payload = if item.payload.contains(['\r', '\n']) {
            item.payload.replace(['\r', '\n'], "")
        } else {
            item.payload.clone()
        };
        let head = inspect(&payload).ok_or("payload-invalid-json")?;
        if head.event_id.as_deref() != Some(item.event_id.as_str()) {
            return Err("payload-event-id-mismatch");
        }
        if self.options.format == HttpOutputFormat::Ndjson {
            return Ok(payload.into_bytes());
        }
        let mut record = Vec::with_capacity(payload.len() + self.hec_metadata.len() + 160);
        record.push(b'{');
        if let Some(seconds) = event_time(head.time_generated.as_deref()) {
            record.extend_from_slice(b"\"time\":");
            record.extend_from_slice(seconds.as_bytes());
            record.push(b',');
        }
        record.extend_from_slice(&self.hec_metadata);
        record.extend_from_slice(b",\"event\":");
        record.extend_from_slice(payload.as_bytes());
        record.extend_from_slice(b",\"fields\":{\"bower_event_id\":");
        record.extend_from_slice(json_string(&item.event_id).as_bytes());
        record.extend_from_slice(b",\"bower_fingerprint\":");
        record.extend_from_slice(json_string(&item.fingerprint).as_bytes());
        record.extend_from_slice(b"}}");
        Ok(record)
    }

    async fn send(&self, batch: &[(String, Vec<u8>)]) -> (u16, Option<DeliveryFailure>) {
        let body = join(batch.iter().map(|(_, record)| record.as_slice()));
        let mut request = self
            .client
            .post(self.options.endpoint.clone())
            .header(
                CONTENT_TYPE,
                match self.options.format {
                    HttpOutputFormat::SplunkHec => SPLUNK_HEC_CONTENT_TYPE,
                    HttpOutputFormat::Ndjson => NDJSON_CONTENT_TYPE,
                },
            )
            .header(self.authorization.0.clone(), self.authorization.1.clone());
        if let Some(channel) = &self.options.hec_channel {
            request = request.header(CHANNEL_HEADER, channel);
        }
        request = if self.options.gzip {
            request
                .header(CONTENT_ENCODING, "gzip")
                .body(compress(&body))
        } else {
            request.body(body)
        };
        let failure = |code: &str| {
            (
                0,
                Some(DeliveryFailure {
                    event_id: String::new(),
                    code: code.to_string(),
                    is_retryable: true,
                    retry_after: None,
                }),
            )
        };
        // Transport and TLS failures (an untrusted certificate included). Text is never kept.
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) if error.is_timeout() => return failure("destination-http-timeout"),
            Err(_) => return failure("destination-http-unavailable"),
        };
        let status = response.status().as_u16();
        let retry_after =
            read_retry_after(response.headers().get(RETRY_AFTER), self.clock.utc_now());
        let body = if self.options.format == HttpOutputFormat::SplunkHec {
            match read_bounded(response).await {
                Ok(body) => body,
                Err(timeout) if timeout => return failure("destination-http-timeout"),
                Err(_) => return failure("destination-http-unavailable"),
            }
        } else {
            None
        };
        classify(self.options.format, status, retry_after, body.as_deref())
    }
}

impl OutputAdapter for HttpOutput {
    fn id(&self) -> &str {
        &self.options.id
    }

    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        let mut failures = Vec::new();
        let mut pending: Vec<Vec<(String, Vec<u8>)>> = Vec::new();
        let mut current: Vec<(String, Vec<u8>)> = Vec::new();
        let mut bytes = 0usize;
        for item in events {
            let record = match self.encode(item) {
                Ok(record) => record,
                Err(poison) => {
                    // Never succeeds anywhere: dead-letter it alone, as the other outputs do.
                    failures.push(failure(&item.event_id, poison, false, None));
                    continue;
                }
            };
            let length = record.len() + 1;
            if length > self.options.maximum_batch_bytes {
                failures.push(failure(&item.event_id, "payload-too-large", false, None));
                continue;
            }
            if !current.is_empty()
                && (current.len() == self.options.maximum_batch_events
                    || bytes + length > self.options.maximum_batch_bytes)
            {
                pending.push(std::mem::take(&mut current));
                bytes = 0;
            }
            current.push((item.event_id.clone(), record));
            bytes += length;
        }
        if !current.is_empty() {
            pending.push(current);
        }

        let mut acknowledged = Vec::new();
        let mut splits = SPLIT_BUDGET;
        let mut index = 0;
        while index < pending.len() {
            let (status, outcome) = self.send(&pending[index]).await;
            let Some(outcome) = outcome else {
                acknowledged.extend(pending[index].iter().map(|(id, _)| id.clone()));
                index += 1;
                continue;
            };
            let count = pending[index].len();
            if status == 413 && count > 1 && splits > 0 {
                // Too large for this endpoint: send the halves in order instead.
                splits -= 1;
                let mut first = std::mem::take(&mut pending[index]);
                let second = first.split_off(count / 2);
                pending.splice(index + 1..index + 1, [first, second]);
                index += 1;
                continue;
            }
            // A multi-record 413 past the split budget retries (and splits again) next
            // time; only a single record the endpoint refuses as too large is dead-lettered.
            let outcome = DeliveryFailure {
                is_retryable: outcome.is_retryable || (status == 413 && count > 1),
                ..outcome
            };
            let stop = outcome.is_destination_failure();
            let rest = if stop {
                &pending[index..]
            } else {
                &pending[index..=index]
            };
            // The endpoint is unavailable or refuses this collector: keep the rest queued
            // behind the destination circuit instead of sending them into the same failure.
            for (id, _) in rest.iter().flatten() {
                failures.push(DeliveryFailure {
                    event_id: id.clone(),
                    ..outcome.clone()
                });
            }
            if stop {
                break;
            }
            index += 1;
        }

        DeliveryResult {
            destination_acknowledgement: (!acknowledged.is_empty())
                .then(|| self.acknowledgement().to_string()),
            acknowledged_event_ids: acknowledged,
            failures,
            // One acknowledgement for the whole delivery; no per-event acknowledgements.
            ..DeliveryResult::default()
        }
    }
}

/// C# `Join`: every record followed by a newline.
pub fn join<'a>(records: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    for record in records {
        body.extend_from_slice(record);
        body.push(b'\n');
    }
    body
}

/// C# `EventTime`: HEC `time` as Unix seconds with three decimals (milliseconds,
/// truncated) from a strict ISO 8601 `timeGenerated`. `None` (the field is omitted and
/// Splunk uses receipt time) when missing, not strict, or before 1970. Limits follow
/// `DateTimeOffset.TryParseExact`: seconds 00-59, offsets up to 14:00, year 9999.
pub fn event_time(time_generated: Option<&str>) -> Option<String> {
    let text = time_generated?;
    if !STRICT_TIMESTAMP.is_match(text) || &text[17..19] > "59" {
        return None;
    }
    if !text.ends_with('Z') {
        let offset = &text[text.len() - 5..];
        let hours: i32 = offset[..2].parse().ok()?;
        let minutes: i32 = offset[3..].parse().ok()?;
        if minutes > 59 || hours * 60 + minutes > 14 * 60 {
            return None;
        }
    }
    let milliseconds = chrono::DateTime::parse_from_rfc3339(text)
        .ok()?
        .timestamp_millis();
    if !(0..=MAXIMUM_EVENT_MILLISECONDS).contains(&milliseconds) {
        return None;
    }
    Some(format!(
        "{}.{:03}",
        milliseconds / 1000,
        milliseconds % 1000
    ))
}

/// C# `Classify`: accepted (no failure) or a bounded failure code. HEC error codes are
/// added as `:hec-<n>` metadata; response text never is.
pub fn classify(
    format: HttpOutputFormat,
    status: u16,
    retry_after: Option<Timestamp>,
    body: Option<&[u8]>,
) -> (u16, Option<DeliveryFailure>) {
    let hec = match format {
        HttpOutputFormat::SplunkHec => read_hec_code(body),
        HttpOutputFormat::Ndjson => None,
    };
    if (200..300).contains(&status) {
        return if format == HttpOutputFormat::Ndjson || hec == Some(0) {
            (status, None)
        } else {
            // A 2xx that is not a HEC success (a captive portal, a proxy page) is not acceptance.
            (
                status,
                Some(failure("", "destination-http-response-invalid", true, None)),
            )
        };
    }
    let suffix = hec.map(|code| format!(":hec-{code}")).unwrap_or_default();
    if status == 413 {
        return (
            status,
            Some(failure("", &format!("http-413{suffix}"), false, None)),
        );
    }
    // Endpoint-wide refusals and outages hold the stream without spending poison budgets:
    // a wrong or revoked token (401/403) or path (404) is fixed by the operator, not the event.
    let destination = status < 200
        || (300..400).contains(&status)
        || matches!(status, 401 | 403 | 404 | 408 | 429)
        || status >= 500;
    let failure = if destination {
        failure(
            "",
            &format!("destination-http-{status}{suffix}"),
            true,
            retry_after,
        )
    } else {
        failure("", &format!("http-{status}{suffix}"), false, None)
    };
    (status, Some(failure))
}

/// C# `ReadHecCode`: the integer HEC `code` (0-99) of a JSON object body (depth 64), or
/// `None`. Repeated names: the last wins, as `JsonElement.TryGetProperty`.
pub fn read_hec_code(body: Option<&[u8]>) -> Option<i32> {
    let body = body.filter(|body| !body.is_empty())?;
    if !within_depth(body, 64) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let code = value.as_object()?.get("code")?;
    // Integer text only (`0.0` and `7e0` are not), like `JsonElement.TryGetInt64`.
    let code = code.as_number()?.as_str().parse::<i64>().ok()?;
    (0..=99)
        .contains(&code)
        .then(|| i32::try_from(code).ok())
        .flatten()
}

/// C# `ReadRetryAfter` (`RetryConditionHeaderValue`): delta seconds or an HTTP date; past
/// values are ignored and future ones capped at one hour. Delta seconds must fit i32.
pub fn read_retry_after(header: Option<&HeaderValue>, now: Timestamp) -> Option<Timestamp> {
    let text = header?.to_str().ok()?.trim();
    let at = if let Ok(seconds) = text.parse::<i32>() {
        if seconds <= 0 {
            return None;
        }
        now.checked_add_signed(chrono::Duration::seconds(
            i64::from(seconds).min(MAXIMUM_RETRY_AFTER_SECONDS),
        ))?
    } else {
        chrono::DateTime::parse_from_rfc2822(text).ok()?
    };
    if at <= now {
        None
    } else {
        Some(
            at.min(now.checked_add_signed(chrono::Duration::seconds(MAXIMUM_RETRY_AFTER_SECONDS))?),
        )
    }
}

fn failure(
    event_id: &str,
    code: &str,
    is_retryable: bool,
    retry_after: Option<Timestamp>,
) -> DeliveryFailure {
    DeliveryFailure {
        event_id: event_id.to_string(),
        code: code.to_string(),
        is_retryable,
        retry_after,
    }
}

/// Top-level `eventId` and `timeGenerated` (each a string or null). A repeated one fails
/// to deserialize, as C# `TryInspect` refuses it.
#[derive(Deserialize)]
struct Head {
    #[serde(rename = "eventId")]
    event_id: Option<String>,
    #[serde(rename = "timeGenerated")]
    time_generated: Option<String>,
}

/// C# `TryInspect`: one JSON object within 64 levels and nothing after it.
fn inspect(payload: &str) -> Option<Head> {
    if !payload
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .starts_with('{')
        || !within_depth(payload.as_bytes(), 64)
    {
        return None;
    }
    serde_json::from_str::<Head>(payload).ok()
}

/// Nesting of objects and arrays at most `maximum` (`JsonReaderOptions.MaxDepth`).
fn within_depth(text: &[u8], maximum: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
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
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

fn hec_metadata(options: &HttpOutputOptions) -> Vec<u8> {
    let mut metadata = format!(
        "\"host\":{},\"source\":{},\"sourcetype\":{}",
        json_string(&options.hec_host),
        json_string(&options.hec_source),
        json_string(&options.hec_source_type)
    );
    if let Some(index) = &options.hec_index {
        metadata.push_str(",\"index\":");
        metadata.push_str(&json_string(index));
    }
    metadata.into_bytes()
}

/// A JSON string with System.Text.Json's default escaping.
fn json_string(value: &str) -> String {
    bower_contracts::json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn compress(body: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    // Writing to a Vec cannot fail.
    let _ = encoder.write_all(body);
    encoder.finish().unwrap_or_default()
}

/// The response body up to [`MAXIMUM_RESPONSE_BYTES`]; `Ok(None)` when larger. `Err(true)`
/// is a timeout, `Err(false)` another transport failure.
async fn read_bounded(mut response: reqwest::Response) -> Result<Option<Vec<u8>>, bool> {
    let declared = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES) {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.is_timeout())? {
        if body.len() + chunk.len() > MAXIMUM_RESPONSE_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// C# `ReadCaBundle`: at least one PEM certificate, else a start-up error.
fn read_ca_bundle(path: &std::path::Path) -> Result<Vec<reqwest::Certificate>, ConfigError> {
    let invalid = || {
        ConfigError("BOWER_HTTP_CA_BUNDLE must name a readable PEM file of CA certificates.".into())
    };
    let bytes = std::fs::read(path).map_err(|_| invalid())?;
    let certificates = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|_| invalid())?;
    if certificates.is_empty() {
        return Err(invalid());
    }
    Ok(certificates)
}
