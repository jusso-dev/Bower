//! C# `HttpOutputOptions`: non-secret settings of the HTTP output. The token is passed to
//! [`crate::HttpOutput::new`] separately and never held here. Messages name the collector
//! variables because the collector is the only host.

use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;

pub const DEFAULT_SOURCE_TYPE: &str = "bower:security";
pub const DEFAULT_SOURCE: &str = "bower";
pub const DEFAULT_MAXIMUM_BATCH_BYTES: usize = 1_000_000;
pub const DEFAULT_MAXIMUM_BATCH_EVENTS: usize = 500;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A start-up configuration error. The message never holds a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

/// Request body format (`BOWER_HTTP_FORMAT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpOutputFormat {
    /// Splunk HTTP Event Collector envelopes, `Authorization: Splunk <token>`.
    SplunkHec,
    /// One Bower event per line (`application/x-ndjson`), bearer token or a named header.
    Ndjson,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HttpOutputOptions {
    pub id: String,
    /// `BOWER_HTTP_URL`: the full request URL.
    pub endpoint: Url,
    pub format: HttpOutputFormat,
    /// `BOWER_HTTP_ALLOW_INSECURE_LOOPBACK`: permits `http://` to a loopback host only.
    pub allow_insecure_loopback: bool,
    /// `BOWER_HTTP_AUTH_HEADER` (ndjson only). `None` or `Authorization` sends
    /// `Authorization: Bearer <token>`; any other name carries the token as is.
    pub authorization_header: Option<String>,
    /// `BOWER_HTTP_CA_BUNDLE`: PEM roots added to the platform roots.
    pub ca_bundle_path: Option<PathBuf>,
    pub hec_index: Option<String>,
    pub hec_source_type: String,
    pub hec_source: String,
    /// `BOWER_HTTP_HEC_HOST`; the collector id when unset.
    pub hec_host: String,
    /// `BOWER_HTTP_HEC_CHANNEL`: sent as `X-Splunk-Request-Channel`.
    pub hec_channel: Option<String>,
    /// Uncompressed request body cap, newlines included (HEC's default limit is 1 MB).
    pub maximum_batch_bytes: usize,
    pub maximum_batch_events: usize,
    /// One request, from connect to the end of the bounded response read.
    pub timeout: Duration,
    pub gzip: bool,
}

impl HttpOutputOptions {
    /// C# property-initialiser defaults.
    pub fn new(endpoint: Url, hec_host: impl Into<String>) -> Self {
        Self {
            id: crate::OUTPUT_ID.to_string(),
            endpoint,
            format: HttpOutputFormat::SplunkHec,
            allow_insecure_loopback: false,
            authorization_header: None,
            ca_bundle_path: None,
            hec_index: None,
            hec_source_type: DEFAULT_SOURCE_TYPE.to_string(),
            hec_source: DEFAULT_SOURCE.to_string(),
            hec_host: hec_host.into(),
            hec_channel: None,
            maximum_batch_bytes: DEFAULT_MAXIMUM_BATCH_BYTES,
            maximum_batch_events: DEFAULT_MAXIMUM_BATCH_EVENTS,
            timeout: DEFAULT_TIMEOUT,
            gzip: false,
        }
    }

    /// C# `Validate`, with the same messages.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() {
            return Err(invalid("The HTTP output id is required."));
        }
        if !is_valid_endpoint(&self.endpoint, self.allow_insecure_loopback) {
            return Err(invalid(
                "BOWER_HTTP_URL must be an absolute https:// URL with a host and no credentials, query or \
                 fragment; http:// is allowed only to a loopback host with BOWER_HTTP_ALLOW_INSECURE_LOOPBACK=true.",
            ));
        }
        if self.format == HttpOutputFormat::SplunkHec && self.authorization_header.is_some() {
            return Err(invalid(
                "BOWER_HTTP_AUTH_HEADER applies to BOWER_HTTP_FORMAT=ndjson only; Splunk HEC uses Authorization: Splunk.",
            ));
        }
        if self
            .authorization_header
            .as_deref()
            .is_some_and(|name| !is_allowed_header_name(name))
        {
            return Err(invalid(
                "BOWER_HTTP_AUTH_HEADER must be an HTTP header name (letters, digits and !#$%&'*+-.^_`|~, at most \
                 64 characters) other than a connection, content or proxy header.",
            ));
        }
        if self
            .hec_index
            .as_deref()
            .is_some_and(|index| !is_index_name(index))
        {
            return Err(invalid(
                "BOWER_HTTP_HEC_INDEX must be 1 to 80 lowercase letters, digits, '_' or '-', starting with a letter or digit.",
            ));
        }
        require_metadata(&self.hec_source_type, "BOWER_HTTP_HEC_SOURCETYPE")?;
        require_metadata(&self.hec_source, "BOWER_HTTP_HEC_SOURCE")?;
        require_metadata(&self.hec_host, "BOWER_HTTP_HEC_HOST")?;
        if self
            .hec_channel
            .as_deref()
            .is_some_and(|channel| !is_channel(channel))
        {
            return Err(invalid(
                "BOWER_HTTP_HEC_CHANNEL must be a GUID in 8-4-4-4-12 hexadecimal form.",
            ));
        }
        range(
            self.maximum_batch_bytes,
            1_024,
            16 * 1024 * 1024,
            "BOWER_HTTP_MAX_BATCH_BYTES",
        )?;
        range(
            self.maximum_batch_events,
            1,
            10_000,
            "BOWER_HTTP_MAX_BATCH_EVENTS",
        )?;
        if self.timeout < Duration::from_secs(1) || self.timeout > Duration::from_secs(300) {
            return Err(invalid(
                "BOWER_HTTP_TIMEOUT_SECONDS must be between 1 and 300.",
            ));
        }
        Ok(())
    }
}

/// C# `IsValidEndpoint`: HTTPS with a host and no credentials, query or fragment (a query
/// could carry a token, and the URL is hashed and shown). `http://` only to loopback, and
/// only when allowed.
pub fn is_valid_endpoint(endpoint: &Url, allow_insecure_loopback: bool) -> bool {
    let Some(host) = endpoint.host_str().filter(|host| !host.is_empty()) else {
        return false;
    };
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return false;
    }
    match endpoint.scheme() {
        "https" => true,
        "http" => allow_insecure_loopback && is_loopback(host),
        _ => false,
    }
}

/// C# `IsLoopback`: `localhost` or a loopback IP address (brackets trimmed).
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// C# `IsValidToken`: printable ASCII without spaces, at most 4096 characters.
pub fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 4096
        && token.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}

const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "expect",
    "proxy-authorization",
    "proxy-connection",
];

fn is_allowed_header_name(name: &str) -> bool {
    (1..=64).contains(&name.chars().count())
        && !RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

fn is_index_name(index: &str) -> bool {
    let first = index.chars().next();
    (1..=80).contains(&index.chars().count())
        && first.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && index
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_channel(channel: &str) -> bool {
    channel.len() == 36
        && channel.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// C# `RequireMetadata`: 1 to 256 UTF-16 code units, no control characters.
fn require_metadata(value: &str, name: &str) -> Result<(), ConfigError> {
    let length = value.encode_utf16().count();
    if length == 0 || length > 256 || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{name} must be 1 to 256 characters without control characters."
        )));
    }
    Ok(())
}

fn range(value: usize, minimum: usize, maximum: usize, name: &str) -> Result<(), ConfigError> {
    if value < minimum || value > maximum {
        return Err(invalid(format!(
            "{name} must be between {minimum} and {maximum}."
        )));
    }
    Ok(())
}
