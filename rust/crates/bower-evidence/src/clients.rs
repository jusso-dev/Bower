//! Read-only Azure clients for verification (`AzureClients.cs`): the Log Analytics
//! query REST API and ARM GET. Both use the verifier identity, which is separate from
//! the ingest identity. Response bodies are never logged or kept; only error codes.

use std::sync::Arc;
use std::time::Duration;

use bower_output_azure::{AzureCredentialMode, TokenProvider, credential_from_mode};
use serde_json::{Map, Value, json};

use crate::EvidenceError;
use crate::runner::{
    ArmReader, BoxFuture, CanarySender, CollectorResponse, LogAnalyticsQuery, ParserProbeSender,
    QueryRows,
};

const LOG_ANALYTICS_SCOPE: &str = "https://api.loganalytics.io/.default";
const MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";
const LOG_ANALYTICS_ENDPOINT: &str = "https://api.loganalytics.azure.com";
const MANAGEMENT_ENDPOINT: &str = "https://management.azure.com";

/// `VerifierCredential.Create`: `azure-cli` (default), `managed-identity` (optional
/// user-assigned client id), `workload-identity` or `environment`.
pub fn verifier_credential(
    mode: Option<&str>,
    client_id: Option<&str>,
) -> Result<Arc<dyn TokenProvider>, EvidenceError> {
    let mode = match mode.unwrap_or("azure-cli").to_lowercase().as_str() {
        "azure-cli" => AzureCredentialMode::AzureCli,
        "managed-identity" => AzureCredentialMode::ManagedIdentity,
        "workload-identity" => AzureCredentialMode::WorkloadIdentity,
        "environment" => AzureCredentialMode::Environment,
        _ => {
            return Err(EvidenceError::InvalidArgument(
                "Credential must be azure-cli, managed-identity, workload-identity or environment."
                    .to_owned(),
            ));
        }
    };
    Ok(credential_from_mode(mode, client_id))
}

/// A `reqwest` client with the CLI's 30 second timeout.
pub fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client builds with static configuration")
}

/// `XmlConvert.ToString(TimeSpan)`: an ISO 8601 duration such as `P1D` or `PT1H`.
pub fn iso8601_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    if total == 0 && duration.subsec_nanos() == 0 {
        return "PT0S".to_owned();
    }
    let (days, hours, minutes, seconds) = (
        total / 86_400,
        total / 3_600 % 24,
        total / 60 % 60,
        total % 60,
    );
    let ticks = duration.subsec_nanos() / 100;
    let mut text = String::from("P");
    if days > 0 {
        text.push_str(&format!("{days}D"));
    }
    if hours > 0 || minutes > 0 || seconds > 0 || ticks > 0 {
        text.push('T');
        if hours > 0 {
            text.push_str(&format!("{hours}H"));
        }
        if minutes > 0 {
            text.push_str(&format!("{minutes}M"));
        }
        if seconds > 0 || ticks > 0 {
            if ticks > 0 {
                let fraction = format!("{ticks:07}");
                text.push_str(&format!("{seconds}.{}S", fraction.trim_end_matches('0')));
            } else {
                text.push_str(&format!("{seconds}S"));
            }
        }
    }
    text
}

/// Posts the canary to the collector's `v1/events` endpoint.
pub struct HttpCanarySender {
    http: reqwest::Client,
}

impl HttpCanarySender {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }
}

impl HttpCanarySender {
    async fn request(
        &self,
        method: reqwest::Method,
        collector: &reqwest::Url,
        path: &str,
        token: Option<&str>,
        json: Option<String>,
    ) -> Result<CollectorResponse, EvidenceError> {
        let url = collector
            .join(path)
            .map_err(|_| EvidenceError::InvalidArgument("Collector URL is invalid.".to_owned()))?;
        let mut request = self.http.request(method, url);
        if let Some(json) = json {
            request = request
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )
                .body(json);
        }
        if let Some(token) = token.filter(|token| !token.is_empty()) {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| EvidenceError::Http(transport_error(&error)))?;
        let status = response.status().as_u16();
        let body = response.bytes().await.ok().and_then(|bytes| {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(Value::Object(body)) => Some(body),
                _ => None,
            }
        });
        Ok((status, body))
    }
}

impl CanarySender for HttpCanarySender {
    fn send<'a>(
        &'a self,
        collector: &'a reqwest::Url,
        token: Option<&'a str>,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        Box::pin(self.request(
            reqwest::Method::POST,
            collector,
            "v1/events",
            token,
            Some(json),
        ))
    }
}

impl ParserProbeSender for HttpCanarySender {
    fn get_status<'a>(
        &'a self,
        collector: &'a reqwest::Url,
        token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        Box::pin(self.request(reqwest::Method::GET, collector, "v1/status", token, None))
    }

    fn send_record<'a>(
        &'a self,
        collector: &'a reqwest::Url,
        token: Option<&'a str>,
        pack_id: &'a str,
        parser_index: i32,
        json: String,
    ) -> BoxFuture<'a, Result<CollectorResponse, EvidenceError>> {
        Box::pin(async move {
            let path = format!(
                "v1/packs/{}/parsers/{parser_index}/events",
                escape_data_string(pack_id)
            );
            self.request(reqwest::Method::POST, collector, &path, token, Some(json))
                .await
        })
    }
}

/// Log Analytics query REST API (read-only).
pub struct LogAnalyticsQueryClient {
    http: reqwest::Client,
    credential: Arc<dyn TokenProvider>,
    endpoint: String,
}

impl LogAnalyticsQueryClient {
    pub fn new(http: reqwest::Client, credential: Arc<dyn TokenProvider>) -> Self {
        Self {
            http,
            credential,
            endpoint: LOG_ANALYTICS_ENDPOINT.to_owned(),
        }
    }

    /// Overrides `https://api.loganalytics.azure.com` (sovereign clouds, tests).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Parses a query response into column-name rows (first table only).
    pub fn parse(body: &str) -> Result<QueryRows, EvidenceError> {
        let root: Value = serde_json::from_str(body).map_err(|_| {
            EvidenceError::InvalidData("Query response is not valid JSON.".to_owned())
        })?;
        let table = match root
            .get("tables")
            .and_then(Value::as_array)
            .and_then(|tables| tables.first())
        {
            Some(Value::Object(table)) => table,
            _ => {
                return Ok(QueryRows {
                    rows: Vec::new(),
                    error: None,
                });
            }
        };
        let columns: Vec<String> = table
            .get("columns")
            .and_then(Value::as_array)
            .map(|columns| {
                columns
                    .iter()
                    .map(|column| {
                        column
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut rows = Vec::new();
        for row in table
            .get("rows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Value::Array(values) = row else { continue };
            let mut record = Map::new();
            for (column, value) in columns.iter().zip(values) {
                record.insert(column.clone(), value.clone());
            }
            rows.push(record);
        }
        Ok(QueryRows { rows, error: None })
    }
}

impl LogAnalyticsQuery for LogAnalyticsQueryClient {
    fn query<'a>(
        &'a self,
        workspace_id: &'a str,
        kql: &'a str,
        timespan: Duration,
    ) -> BoxFuture<'a, Result<QueryRows, EvidenceError>> {
        Box::pin(async move {
            let token = self
                .credential
                .get_token(LOG_ANALYTICS_SCOPE)
                .await
                .map_err(|error| EvidenceError::Credential(error.to_string()))?;
            let url = format!(
                "{}/v1/workspaces/{}/query",
                self.endpoint,
                escape_data_string(workspace_id)
            );
            let body = bower_contracts::json::to_string(
                &json!({ "query": kql, "timespan": iso8601_duration(timespan) }),
            )
            .expect("JSON values always serialize");
            let response = self
                .http
                .post(url)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )
                .bearer_auth(&token.token)
                .body(body)
                .send()
                .await
                .map_err(|error| EvidenceError::Http(transport_error(&error)))?;
            let status = response.status();
            let text = response
                .text()
                .await
                .map_err(|error| EvidenceError::Http(transport_error(&error)))?;
            if !status.is_success() {
                // Only the error code is kept; bodies can echo query text.
                let code = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|body| body.get("error")?.get("code")?.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("http-{}", status.as_u16()));
                return Ok(QueryRows {
                    rows: Vec::new(),
                    error: Some(code),
                });
            }
            Self::parse(&text)
        })
    }
}

/// Azure Resource Manager GET (read-only).
pub struct HttpArmReader {
    http: reqwest::Client,
    credential: Arc<dyn TokenProvider>,
    endpoint: String,
}

impl HttpArmReader {
    pub fn new(http: reqwest::Client, credential: Arc<dyn TokenProvider>) -> Self {
        Self {
            http,
            credential,
            endpoint: MANAGEMENT_ENDPOINT.to_owned(),
        }
    }

    /// Overrides `https://management.azure.com` (sovereign clouds, tests).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

impl ArmReader for HttpArmReader {
    fn get<'a>(
        &'a self,
        resource_id: &'a str,
        api_version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Map<String, Value>>, EvidenceError>> {
        Box::pin(async move {
            let prefix = "/subscriptions/";
            if !resource_id
                .get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            {
                return Err(EvidenceError::InvalidArgument(
                    "Resource id must start with /subscriptions/. (Parameter 'resourceId')"
                        .to_owned(),
                ));
            }
            let token = self
                .credential
                .get_token(MANAGEMENT_SCOPE)
                .await
                .map_err(|error| EvidenceError::Credential(error.to_string()))?;
            let url = format!(
                "{}{resource_id}?api-version={}",
                self.endpoint,
                escape_data_string(api_version)
            );
            let response = self
                .http
                .get(url)
                .bearer_auth(&token.token)
                .send()
                .await
                .map_err(|error| EvidenceError::Http(transport_error(&error)))?;
            if !response.status().is_success() {
                return Ok(None);
            }
            let text = response
                .text()
                .await
                .map_err(|error| EvidenceError::Http(transport_error(&error)))?;
            Ok(match serde_json::from_str::<Value>(&text) {
                Ok(Value::Object(object)) => Some(object),
                _ => None,
            })
        })
    }
}

/// `Uri.EscapeDataString`: RFC 3986 unreserved characters stay, everything else is
/// percent-encoded as UTF-8.
pub fn escape_data_string(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

/// .NET `HttpClient` timeout text; parser probes read it as a query timeout.
pub(crate) const TIMEOUT_MESSAGE: &str =
    "The request was canceled due to the configured HttpClient.Timeout of 30 seconds elapsing.";

/// Transport failure text as .NET `HttpClient` reports it, for example
/// `Connection refused (127.0.0.1:9)`. Only the host and port are included: never
/// paths, queries, headers or bodies.
pub(crate) fn transport_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        // The verifier and canary clients use the CLI's 30 second timeout.
        return TIMEOUT_MESSAGE.to_owned();
    }
    if error.is_body() || error.is_decode() {
        return "Error while copying content to a stream.".to_owned();
    }
    let endpoint = error.url().and_then(|url| {
        Some(format!(
            "{}:{}",
            url.host_str()?,
            url.port_or_known_default()?
        ))
    });
    match (socket_error(error), endpoint) {
        (Some(reason), Some(endpoint)) => format!("{reason} ({endpoint})"),
        (Some(reason), None) => reason,
        (None, _) => "An error occurred while sending the request.".to_owned(),
    }
}

/// The socket-level reason in an error chain, worded like .NET `SocketException`.
fn socket_error(error: &reqwest::Error) -> Option<String> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind;
            let text = match io.kind() {
                ErrorKind::ConnectionRefused => "Connection refused".to_owned(),
                ErrorKind::ConnectionReset => "Connection reset by peer".to_owned(),
                ErrorKind::TimedOut => "Operation timed out".to_owned(),
                ErrorKind::HostUnreachable => "No route to host".to_owned(),
                ErrorKind::NetworkUnreachable => "Network is unreachable".to_owned(),
                _ => {
                    let text = io.to_string();
                    let text = text
                        .strip_prefix("failed to lookup address information: ")
                        .unwrap_or(&text);
                    match text.rfind(" (os error ") {
                        Some(index) => text[..index].to_owned(),
                        None => text.to_owned(),
                    }
                }
            };
            return Some(text);
        }
        source = current.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_format_like_xml_convert() {
        assert_eq!(iso8601_duration(Duration::from_secs(86_400)), "P1D");
        assert_eq!(iso8601_duration(Duration::from_secs(3_600)), "PT1H");
        assert_eq!(iso8601_duration(Duration::from_secs(90_061)), "P1DT1H1M1S");
        assert_eq!(iso8601_duration(Duration::from_millis(1_500)), "PT1.5S");
    }

    #[test]
    fn escapes_like_uri_escape_data_string() {
        assert_eq!(escape_data_string("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(escape_data_string("2025-07-01"), "2025-07-01");
    }
}
