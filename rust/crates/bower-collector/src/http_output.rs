//! `BOWER_HTTP_*` settings of the HTTP output (C# `HttpOutputSettings`,
//! `BOWER_OUTPUT=http`). The token read from `BOWER_HTTP_TOKEN` is never printed, hashed,
//! logged or reported; the token file is read when the output is created.

use std::path::PathBuf;
use std::time::Duration;

use bower_output_http::options::{
    DEFAULT_MAXIMUM_BATCH_BYTES, DEFAULT_MAXIMUM_BATCH_EVENTS, DEFAULT_SOURCE, DEFAULT_SOURCE_TYPE,
    DEFAULT_TIMEOUT,
};
use bower_output_http::{HttpOutputFormat, HttpOutputOptions, OUTPUT_ID};
use reqwest::Url;

use crate::error::HostError;
use crate::settings::is_blank;

const NAMES: &[&str] = &[
    "BOWER_HTTP_URL",
    "BOWER_HTTP_FORMAT",
    "BOWER_HTTP_TOKEN_FILE",
    "BOWER_HTTP_TOKEN",
    "BOWER_HTTP_AUTH_HEADER",
    "BOWER_HTTP_CA_BUNDLE",
    "BOWER_HTTP_ALLOW_INSECURE_LOOPBACK",
    "BOWER_HTTP_HEC_INDEX",
    "BOWER_HTTP_HEC_SOURCETYPE",
    "BOWER_HTTP_HEC_SOURCE",
    "BOWER_HTTP_HEC_HOST",
    "BOWER_HTTP_HEC_CHANNEL",
    "BOWER_HTTP_MAX_BATCH_BYTES",
    "BOWER_HTTP_MAX_BATCH_EVENTS",
    "BOWER_HTTP_TIMEOUT_SECONDS",
    "BOWER_HTTP_GZIP",
];

const TOKEN_REQUIRED: &str = "BOWER_OUTPUT=http requires exactly one of BOWER_HTTP_TOKEN_FILE (preferred) or BOWER_HTTP_TOKEN.";

#[derive(Clone, PartialEq)]
pub struct HttpOutputSettings {
    pub endpoint: Option<Url>,
    /// `BOWER_HTTP_FORMAT`: `splunk-hec` (default) or `ndjson`.
    pub format: String,
    /// `BOWER_HTTP_TOKEN_FILE`: file holding the token (preferred). Never logged.
    pub token_file: Option<PathBuf>,
    environment_token: Option<String>,
    pub authorization_header: Option<String>,
    pub ca_bundle: Option<PathBuf>,
    pub allow_insecure_loopback: bool,
    pub hec_index: Option<String>,
    pub hec_source_type: Option<String>,
    pub hec_source: Option<String>,
    pub hec_host: Option<String>,
    pub hec_channel: Option<String>,
    pub maximum_batch_bytes: i32,
    pub maximum_batch_events: i32,
    pub timeout_seconds: i32,
    pub gzip: bool,
}

// Never print the token.
impl std::fmt::Debug for HttpOutputSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpOutputSettings")
            .field("endpoint", &self.endpoint.as_ref().map(Url::as_str))
            .field("format", &self.format)
            .field("token_file", &self.token_file)
            .field("has_environment_token", &self.has_environment_token())
            .finish_non_exhaustive()
    }
}

impl HttpOutputSettings {
    /// Settings with C# property-initialiser defaults.
    pub fn new(endpoint: Option<Url>) -> Self {
        Self {
            endpoint,
            format: "splunk-hec".into(),
            token_file: None,
            environment_token: None,
            authorization_header: None,
            ca_bundle: None,
            allow_insecure_loopback: false,
            hec_index: None,
            hec_source_type: None,
            hec_source: None,
            hec_host: None,
            hec_channel: None,
            maximum_batch_bytes: i32::try_from(DEFAULT_MAXIMUM_BATCH_BYTES).unwrap_or(i32::MAX),
            maximum_batch_events: i32::try_from(DEFAULT_MAXIMUM_BATCH_EVENTS).unwrap_or(i32::MAX),
            timeout_seconds: i32::try_from(DEFAULT_TIMEOUT.as_secs()).unwrap_or(i32::MAX),
            gzip: false,
        }
    }

    /// `BOWER_HTTP_TOKEN` is set (its value stays private).
    pub fn has_environment_token(&self) -> bool {
        self.environment_token.is_some()
    }

    /// Sets the `BOWER_HTTP_TOKEN` value (tests and [`Self::from_environment`]).
    pub fn with_environment_token(mut self, token: Option<&str>) -> Self {
        self.environment_token = token
            .filter(|token| !is_blank(token))
            .map(|token| token.trim().to_string());
        self
    }

    /// C# `FromEnvironment`: `None` when no `BOWER_HTTP_*` variable is set.
    pub fn from_environment(
        read: &impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, HostError> {
        let blank = |name: &str| read(name).filter(|value| !is_blank(value));
        if NAMES.iter().all(|name| blank(name).is_none()) {
            return Ok(None);
        }
        let trimmed = |name: &str| blank(name).map(|value| value.trim().to_string());
        // The value is never echoed: a mistyped URL may hold a credential.
        let endpoint = blank("BOWER_HTTP_URL")
            .map(|url| {
                Url::parse(url.trim())
                    .map_err(|_| invalid("BOWER_HTTP_URL must be an absolute https:// URL."))
            })
            .transpose()?;
        let settings = Self {
            endpoint,
            format: trimmed("BOWER_HTTP_FORMAT")
                .map(|format| format.to_lowercase())
                .unwrap_or_else(|| "splunk-hec".into()),
            token_file: blank("BOWER_HTTP_TOKEN_FILE").map(PathBuf::from),
            environment_token: None,
            authorization_header: trimmed("BOWER_HTTP_AUTH_HEADER"),
            ca_bundle: blank("BOWER_HTTP_CA_BUNDLE").map(PathBuf::from),
            allow_insecure_loopback: read_boolean(read, "BOWER_HTTP_ALLOW_INSECURE_LOOPBACK")?,
            hec_index: trimmed("BOWER_HTTP_HEC_INDEX"),
            hec_source_type: trimmed("BOWER_HTTP_HEC_SOURCETYPE"),
            hec_source: trimmed("BOWER_HTTP_HEC_SOURCE"),
            hec_host: trimmed("BOWER_HTTP_HEC_HOST"),
            hec_channel: trimmed("BOWER_HTTP_HEC_CHANNEL"),
            maximum_batch_bytes: read_i32(
                read,
                "BOWER_HTTP_MAX_BATCH_BYTES",
                DEFAULT_MAXIMUM_BATCH_BYTES,
            )?,
            maximum_batch_events: read_i32(
                read,
                "BOWER_HTTP_MAX_BATCH_EVENTS",
                DEFAULT_MAXIMUM_BATCH_EVENTS,
            )?,
            timeout_seconds: read_i32(
                read,
                "BOWER_HTTP_TIMEOUT_SECONDS",
                usize::try_from(DEFAULT_TIMEOUT.as_secs()).unwrap_or(30),
            )?,
            gzip: read_boolean(read, "BOWER_HTTP_GZIP")?,
        };
        Ok(Some(settings.with_environment_token(
            read("BOWER_HTTP_TOKEN").as_deref(),
        )))
    }

    /// C# `Validate`: `BOWER_OUTPUT=http` needs these settings; any other output refuses
    /// them, so a half-configured HTTP output never goes unnoticed.
    pub fn validate(
        output_type: &str,
        settings: Option<&Self>,
        collector_id: &str,
    ) -> Result<(), HostError> {
        let http_output = output_type == OUTPUT_ID;
        let Some(settings) = settings else {
            return if http_output {
                Err(invalid(
                    "BOWER_OUTPUT=http requires BOWER_HTTP_URL and BOWER_HTTP_TOKEN_FILE (or BOWER_HTTP_TOKEN).",
                ))
            } else {
                Ok(())
            };
        };
        if !http_output {
            return Err(invalid("BOWER_HTTP_* settings require BOWER_OUTPUT=http."));
        }
        if settings.endpoint.is_none() {
            return Err(invalid("BOWER_OUTPUT=http requires BOWER_HTTP_URL."));
        }
        if settings.token_file.is_some() == settings.has_environment_token() {
            return Err(invalid(TOKEN_REQUIRED));
        }
        if !matches!(settings.format.as_str(), "splunk-hec" | "ndjson") {
            return Err(invalid("BOWER_HTTP_FORMAT must be splunk-hec or ndjson."));
        }
        if settings.format == "ndjson"
            && (settings.hec_index.is_some()
                || settings.hec_source_type.is_some()
                || settings.hec_source.is_some()
                || settings.hec_host.is_some()
                || settings.hec_channel.is_some())
        {
            return Err(invalid(
                "BOWER_HTTP_HEC_* settings require BOWER_HTTP_FORMAT=splunk-hec.",
            ));
        }
        settings
            .options(collector_id)?
            .validate()
            .map_err(|error| invalid(error.0))
    }

    /// C# `Options`: the output options; HEC host defaults to the collector id.
    pub fn options(&self, collector_id: &str) -> Result<HttpOutputOptions, HostError> {
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| invalid("BOWER_OUTPUT=http requires BOWER_HTTP_URL."))?;
        let mut options = HttpOutputOptions::new(
            endpoint,
            self.hec_host
                .clone()
                .unwrap_or_else(|| collector_id.to_string()),
        );
        options.format = if self.format == "ndjson" {
            HttpOutputFormat::Ndjson
        } else {
            HttpOutputFormat::SplunkHec
        };
        options.allow_insecure_loopback = self.allow_insecure_loopback;
        options.authorization_header = self.authorization_header.clone();
        options.ca_bundle_path = self.ca_bundle.clone();
        options.hec_index = self.hec_index.clone();
        options.hec_source_type = self
            .hec_source_type
            .clone()
            .unwrap_or_else(|| DEFAULT_SOURCE_TYPE.into());
        options.hec_source = self
            .hec_source
            .clone()
            .unwrap_or_else(|| DEFAULT_SOURCE.into());
        options.hec_channel = self.hec_channel.clone();
        // Negative values become 0 and fail validation with the C# message.
        options.maximum_batch_bytes = usize::try_from(self.maximum_batch_bytes).unwrap_or(0);
        options.maximum_batch_events = usize::try_from(self.maximum_batch_events).unwrap_or(0);
        options.timeout =
            u64::try_from(self.timeout_seconds).map_or(Duration::ZERO, Duration::from_secs);
        options.gzip = self.gzip;
        Ok(options)
    }

    /// C# `ReadToken`: the file (a trailing newline from `echo` or a secret mount is not
    /// part of it) or `BOWER_HTTP_TOKEN`. Messages never include the value.
    pub fn read_token(&self) -> Result<String, HostError> {
        let Some(path) = &self.token_file else {
            return self
                .environment_token
                .clone()
                .ok_or_else(|| invalid(TOKEN_REQUIRED));
        };
        let text = std::fs::read_to_string(path)
            .map_err(|_| invalid("BOWER_HTTP_TOKEN_FILE must name a readable file."))?;
        Ok(text
            .strip_prefix('\u{feff}')
            .unwrap_or(&text)
            .trim()
            .to_string())
    }

    /// C# `HashMaterial`: endpoint scheme, host, port and path, format, where the token
    /// comes from (never the token or a digest of it), and the remaining settings.
    pub fn hash_material(&self) -> String {
        let endpoint = self
            .endpoint
            .as_ref()
            .map(|url| {
                format!(
                    "{}://{}:{}{}",
                    url.scheme(),
                    url.host_str().unwrap_or_default(),
                    url.port_or_known_default().unwrap_or_default(),
                    url.path()
                )
            })
            .unwrap_or_default();
        let token = match (&self.token_file, self.has_environment_token()) {
            (Some(path), _) => format!("file:{}", path.to_string_lossy()),
            (None, true) => "environment".into(),
            (None, false) => "none".into(),
        };
        let text = |value: &Option<String>| value.clone().unwrap_or_default();
        [
            format!("http-url:{endpoint}"),
            format!("http-format:{}", self.format),
            format!("http-token:{token}"),
            format!("http-auth-header:{}", text(&self.authorization_header)),
            format!(
                "http-ca:{}",
                self.ca_bundle
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            format!(
                "http-hec:{},{},{},{},{}",
                text(&self.hec_index),
                text(&self.hec_source_type),
                text(&self.hec_source),
                text(&self.hec_host),
                text(&self.hec_channel)
            ),
            format!(
                "http-limits:{},{},{},{},{}",
                self.maximum_batch_bytes,
                self.maximum_batch_events,
                self.timeout_seconds,
                dotnet_bool(self.gzip),
                dotnet_bool(self.allow_insecure_loopback)
            ),
        ]
        .join("\u{1f}")
    }
}

fn invalid(message: impl Into<String>) -> HostError {
    HostError::new("InvalidOperationException", message)
}

fn dotnet_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// C# `ReadBoolean`: unset or blank is false; otherwise true or false (any case).
fn read_boolean(read: &impl Fn(&str) -> Option<String>, name: &str) -> Result<bool, HostError> {
    match read(name)
        .filter(|value| !is_blank(value))
        .map(|value| value.trim().to_lowercase())
        .as_deref()
    {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(invalid(format!("{name} must be true or false."))),
    }
}

/// C# `ReadInt32` (`int.TryParse`, `NumberStyles.Integer`).
fn read_i32(
    read: &impl Fn(&str) -> Option<String>,
    name: &str,
    fallback: usize,
) -> Result<i32, HostError> {
    let Some(value) = read(name).filter(|value| !is_blank(value)) else {
        return Ok(i32::try_from(fallback).unwrap_or(i32::MAX));
    };
    value
        .trim_matches(|character: char| {
            matches!(character, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
        })
        .parse::<i32>()
        .map_err(|_| invalid(format!("{name} must be an integer.")))
}
