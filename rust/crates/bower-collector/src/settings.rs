//! `CollectorSettings`: read once from `BOWER_*` environment variables and validated
//! before the host starts (C# `Bower.Collector.CollectorSettings`). Variable names,
//! defaults and validation messages match the C# host so deploy assets work unchanged.

use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::error::HostError;

pub const MINIMUM_INGEST_TOKEN_LENGTH: usize = 32;

/// Explicit Azure credential source (C# `AzureCredentialMode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AzureCredentialMode {
    #[default]
    ManagedIdentity,
    WorkloadIdentity,
    Environment,
    AzureCli,
}

impl AzureCredentialMode {
    /// C# `Enum.ToString()` name (used in the configuration hash).
    pub fn pascal_name(self) -> &'static str {
        match self {
            Self::ManagedIdentity => "ManagedIdentity",
            Self::WorkloadIdentity => "WorkloadIdentity",
            Self::Environment => "Environment",
            Self::AzureCli => "AzureCli",
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct CollectorSettings {
    pub listen_url: String,
    pub queue_path: PathBuf,
    pub policy_directory: PathBuf,
    pub collector_id: String,
    pub version: String,
    pub environment: String,
    pub maximum_queue_bytes: i64,
    /// How long acknowledged events stay in the queue for duplicate detection.
    pub delivered_retention: Duration,
    pub ingest_token: Option<String>,
    /// One revocable credential per producer: lines of `<producer> sha256:<hex>`.
    pub ingest_tokens_file: Option<PathBuf>,
    pub packs: Vec<String>,
    pub pack_trusted_key_files: Vec<String>,
    pub privacy_profile_path: Option<PathBuf>,
    pub privacy_hmac_key_file: Option<PathBuf>,
    pub privacy_hmac_key_id: String,
    pub allow_unauthenticated_ingest: bool,
    pub ingest_requests_per_second: i32,
    pub maximum_delivery_attempts: i32,
    pub output_type: String,
    pub ama_spool_path: PathBuf,
    pub stream_name: String,
    pub dce_endpoint: Option<Url>,
    pub dcr_immutable_id: Option<String>,
    pub azure_credential: AzureCredentialMode,
    pub azure_client_id: Option<String>,
    pub management_endpoint: Option<Url>,
    pub management_scope: Option<String>,
}

// Never print the ingest token.
impl std::fmt::Debug for CollectorSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectorSettings")
            .field("listen_url", &self.listen_url)
            .field("collector_id", &self.collector_id)
            .field("output_type", &self.output_type)
            .field(
                "ingest_token",
                &self.ingest_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl CollectorSettings {
    /// Settings with C# property-initialiser defaults for the optional values.
    pub fn new(
        listen_url: impl Into<String>,
        queue_path: impl Into<PathBuf>,
        policy_directory: impl Into<PathBuf>,
        collector_id: impl Into<String>,
    ) -> Self {
        Self {
            listen_url: listen_url.into(),
            queue_path: queue_path.into(),
            policy_directory: policy_directory.into(),
            collector_id: collector_id.into(),
            version: "0.1.0".into(),
            environment: "unknown".into(),
            maximum_queue_bytes: 10 * 1024 * 1024 * 1024,
            delivered_retention: Duration::from_secs(7 * 24 * 3600),
            ingest_token: None,
            ingest_tokens_file: None,
            packs: Vec::new(),
            pack_trusted_key_files: Vec::new(),
            privacy_profile_path: None,
            privacy_hmac_key_file: None,
            privacy_hmac_key_id: "k1".into(),
            allow_unauthenticated_ingest: false,
            ingest_requests_per_second: 500,
            maximum_delivery_attempts: 20,
            output_type: "none".into(),
            ama_spool_path: base_directory().join("spool"),
            stream_name: "Custom-BowerSecurity".into(),
            dce_endpoint: None,
            dcr_immutable_id: None,
            azure_credential: AzureCredentialMode::ManagedIdentity,
            azure_client_id: None,
            management_endpoint: None,
            management_scope: None,
        }
    }

    pub fn from_process_environment() -> Result<Self, HostError> {
        Self::from_environment(|name| std::env::var(name).ok())
    }

    /// C# `FromEnvironment`. `read` returns `None` for unset variables; an empty value
    /// is `Some("")` exactly like `Environment.GetEnvironmentVariable`.
    pub fn from_environment(read: impl Fn(&str) -> Option<String>) -> Result<Self, HostError> {
        let token_file = read("BOWER_INGEST_TOKEN_FILE");
        let mut token = read("BOWER_INGEST_TOKEN");
        if let Some(path) = token_file.as_deref().filter(|value| !is_blank(value)) {
            token = Some(read_all_text(path)?.trim().to_string());
        }

        let management_endpoint = read("BOWER_MANAGEMENT_ENDPOINT");
        let dce_endpoint = read("BOWER_DCE_ENDPOINT");
        let retention_hours = read_i64(&read, "BOWER_QUEUE_RETENTION_HOURS", 7 * 24)?;
        let settings = Self {
            listen_url: read("BOWER_LISTEN_URL").unwrap_or_else(|| "http://127.0.0.1:4319".into()),
            queue_path: read("BOWER_QUEUE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| base_directory().join("data").join("bower.db")),
            policy_directory: read("BOWER_POLICY_DIRECTORY")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join("policies")
                        .join("default")
                }),
            collector_id: read("BOWER_COLLECTOR_ID").unwrap_or_else(machine_name),
            version: "0.1.0".into(),
            environment: read("BOWER_ENVIRONMENT").unwrap_or_else(|| "unknown".into()),
            maximum_queue_bytes: read_i64(&read, "BOWER_QUEUE_MAX_BYTES", 10 * 1024 * 1024 * 1024)?,
            delivered_retention: hours(retention_hours),
            ingest_token: token.filter(|value| !is_blank(value)),
            ingest_tokens_file: blank(read("BOWER_INGEST_TOKENS_FILE")).map(PathBuf::from),
            packs: split_list(read("BOWER_PACKS").as_deref()),
            pack_trusted_key_files: split_list(read("BOWER_PACK_TRUSTED_KEYS").as_deref()),
            privacy_profile_path: blank(read("BOWER_PRIVACY_PROFILE")).map(PathBuf::from),
            privacy_hmac_key_file: blank(read("BOWER_PRIVACY_HMAC_KEY_FILE")).map(PathBuf::from),
            privacy_hmac_key_id: blank(read("BOWER_PRIVACY_HMAC_KEY_ID"))
                .unwrap_or_else(|| "k1".into()),
            allow_unauthenticated_ingest: read("BOWER_ALLOW_UNAUTHENTICATED_INGEST")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            // C# casts with `(int)`: unchecked, so out-of-range values wrap. Kept for parity.
            ingest_requests_per_second: read_i64(&read, "BOWER_INGEST_RATE_PER_SECOND", 500)?
                as i32,
            maximum_delivery_attempts: read_i64(&read, "BOWER_MAX_DELIVERY_ATTEMPTS", 20)? as i32,
            output_type: read("BOWER_OUTPUT")
                .unwrap_or_else(|| "none".into())
                .to_lowercase(),
            ama_spool_path: read("BOWER_AMA_SPOOL_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| base_directory().join("spool")),
            stream_name: read("BOWER_STREAM_NAME").unwrap_or_else(|| "Custom-BowerSecurity".into()),
            dce_endpoint: absolute_uri(dce_endpoint)?,
            dcr_immutable_id: read("BOWER_DCR_ID"),
            azure_credential: parse_credential_mode(read("BOWER_AZURE_CREDENTIAL").as_deref())?,
            azure_client_id: read("BOWER_AZURE_CLIENT_ID"),
            management_endpoint: absolute_uri(management_endpoint)?,
            management_scope: read("BOWER_MANAGEMENT_SCOPE"),
        };
        settings.validate()?;
        Ok(settings)
    }

    /// Parsed listen URL host is loopback (`localhost` or a loopback IP).
    pub fn is_loopback_listener(&self) -> bool {
        Url::parse(&self.listen_url).is_ok_and(|url| url_is_loopback(&url))
    }

    pub fn validate(&self) -> Result<(), HostError> {
        let listen_ok = Url::parse(&self.listen_url)
            .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some());
        if !listen_ok {
            return Err(invalid("BOWER_LISTEN_URL must be an absolute HTTP(S) URL."));
        }

        if is_blank(&self.collector_id) {
            return Err(HostError::new(
                "ArgumentException",
                "The value cannot be an empty string or composed entirely of whitespace. (Parameter 'CollectorId')",
            ));
        }

        if let Some(token) = &self.ingest_token
            && token.encode_utf16().count() < MINIMUM_INGEST_TOKEN_LENGTH
        {
            return Err(invalid(format!(
                "BOWER_INGEST_TOKEN must contain at least {MINIMUM_INGEST_TOKEN_LENGTH} characters."
            )));
        }

        // Fail closed: a collector reachable from other hosts must authenticate producers.
        if self.ingest_token.is_none()
            && self.ingest_tokens_file.is_none()
            && !self.allow_unauthenticated_ingest
            && !self.is_loopback_listener()
        {
            return Err(invalid(
                "BOWER_LISTEN_URL is not loopback, so BOWER_INGEST_TOKEN, BOWER_INGEST_TOKEN_FILE \
                 or BOWER_INGEST_TOKENS_FILE is required. Set BOWER_ALLOW_UNAUTHENTICATED_INGEST=true \
                 only on an isolated network you control.",
            ));
        }

        if !self.packs.is_empty() && self.pack_trusted_key_files.is_empty() {
            return Err(invalid(
                "BOWER_PACKS requires BOWER_PACK_TRUSTED_KEYS; packs are never loaded unverified.",
            ));
        }

        if self.maximum_queue_bytes < 1_048_576 {
            return Err(invalid("BOWER_QUEUE_MAX_BYTES must be at least 1 MiB."));
        }

        if self.delivered_retention < Duration::from_secs(3600)
            || self.delivered_retention > Duration::from_secs(90 * 24 * 3600)
        {
            return Err(invalid(
                "BOWER_QUEUE_RETENTION_HOURS must be between 1 and 2160.",
            ));
        }

        if !(1..=100_000).contains(&self.ingest_requests_per_second) {
            return Err(invalid(
                "BOWER_INGEST_RATE_PER_SECOND must be between 1 and 100000.",
            ));
        }

        if !(1..=1_000).contains(&self.maximum_delivery_attempts) {
            return Err(invalid(
                "BOWER_MAX_DELIVERY_ATTEMPTS must be between 1 and 1000.",
            ));
        }

        if !matches!(
            self.output_type.as_str(),
            "none" | "ama-spool" | "azure-logs-ingestion"
        ) {
            return Err(invalid(format!(
                "Unsupported BOWER_OUTPUT value: {}",
                self.output_type
            )));
        }

        if self.output_type == "azure-logs-ingestion"
            && (self.dce_endpoint.is_none()
                || self.dcr_immutable_id.as_deref().is_none_or(is_blank))
        {
            return Err(invalid(
                "BOWER_DCE_ENDPOINT and BOWER_DCR_ID are required for azure-logs-ingestion.",
            ));
        }

        if let Some(endpoint) = &self.management_endpoint {
            if self.management_scope.as_deref().is_none_or(is_blank) {
                return Err(invalid(
                    "BOWER_MANAGEMENT_SCOPE is required when BOWER_MANAGEMENT_ENDPOINT is set.",
                ));
            }

            // The heartbeat carries an Entra bearer token; never send it in cleartext.
            if endpoint.scheme() != "https" && !url_is_loopback(endpoint) {
                return Err(invalid(
                    "BOWER_MANAGEMENT_ENDPOINT must use HTTPS unless it targets loopback.",
                ));
            }
        }

        Ok(())
    }

    /// Hash of non-secret settings reported to management (C# `ConfigurationHash`).
    pub fn configuration_hash(&self) -> String {
        let retention_hours = self.delivered_retention.as_secs_f64() / 3600.0;
        let material = [
            self.listen_url.clone(),
            self.output_type.clone(),
            self.stream_name.clone(),
            self.dce_endpoint
                .as_ref()
                .map(Url::to_string)
                .unwrap_or_default(),
            self.dcr_immutable_id.clone().unwrap_or_default(),
            self.azure_credential.pascal_name().to_string(),
            self.maximum_queue_bytes.to_string(),
            dotnet_double(retention_hours),
            self.ingest_requests_per_second.to_string(),
            self.maximum_delivery_attempts.to_string(),
            dotnet_bool(self.ingest_token.is_some() || self.ingest_tokens_file.is_some())
                .to_string(),
            self.privacy_hmac_key_id.clone(),
        ]
        .join("\u{1f}");
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(material.as_bytes()))
        )
    }
}

fn invalid(message: impl Into<String>) -> HostError {
    HostError::new("InvalidOperationException", message)
}

fn dotnet_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// `double.ToString(InvariantCulture)` for the values this host produces (whole hours).
fn dotnet_double(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

fn hours(value: i64) -> Duration {
    // Negative or overflowing values fail validation, as TimeSpan.FromHours would.
    u64::try_from(value)
        .ok()
        .and_then(|hours| hours.checked_mul(3600))
        .map_or(Duration::ZERO, Duration::from_secs)
}

/// `string.IsNullOrWhiteSpace` for a present value.
pub(crate) fn is_blank(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

fn blank(value: Option<String>) -> Option<String> {
    value.filter(|value| !is_blank(value))
}

fn split_list(value: Option<&str>) -> Vec<String> {
    match value {
        Some(value) if !is_blank(value) => value
            .split([',', ';'])
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// `long.TryParse(value, NumberStyles.Integer, InvariantCulture)`.
fn read_i64(
    read: &impl Fn(&str) -> Option<String>,
    name: &str,
    fallback: i64,
) -> Result<i64, HostError> {
    let Some(value) = read(name).filter(|value| !is_blank(value)) else {
        return Ok(fallback);
    };
    value
        .trim_matches(|character: char| {
            matches!(character, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
        })
        .parse::<i64>()
        .map_err(|_| invalid(format!("{name} must be an integer.")))
}

fn absolute_uri(value: Option<String>) -> Result<Option<Url>, HostError> {
    match value {
        Some(value) if !is_blank(&value) => Url::parse(&value)
            .ok()
            .filter(|url| url.host().is_some())
            .map(Some)
            .ok_or_else(|| {
                HostError::new(
                    "UriFormatException",
                    "Invalid URI: The format of the URI could not be determined.",
                )
            }),
        _ => Ok(None),
    }
}

fn parse_credential_mode(value: Option<&str>) -> Result<AzureCredentialMode, HostError> {
    match value.map(|value| value.trim().to_lowercase()).as_deref() {
        None | Some("") | Some("managed-identity") => Ok(AzureCredentialMode::ManagedIdentity),
        Some("workload-identity") => Ok(AzureCredentialMode::WorkloadIdentity),
        Some("environment") => Ok(AzureCredentialMode::Environment),
        Some("azure-cli") => Ok(AzureCredentialMode::AzureCli),
        Some(_) => Err(invalid(
            "BOWER_AZURE_CREDENTIAL must be managed-identity, workload-identity, environment or azure-cli.",
        )),
    }
}

/// C# `IsLoopback(host)`: `localhost` or a loopback IP address.
pub fn url_is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(is_loopback_host)
}

/// C# `IsLoopback(host)`: `localhost` or a loopback IP address (brackets trimmed).
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// `File.ReadAllText`: UTF-8 with a leading BOM removed.
pub(crate) fn read_all_text(path: &str) -> Result<String, HostError> {
    let text = std::fs::read_to_string(path).map_err(|error| HostError::io(path, &error))?;
    Ok(text
        .strip_prefix('\u{feff}')
        .map(str::to_string)
        .unwrap_or(text))
}

/// `AppContext.BaseDirectory`: the directory holding the executable.
pub fn base_directory() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .unwrap_or_default()
}

/// `Environment.MachineName` on Unix: the host name up to the first dot.
pub fn machine_name() -> String {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
        })
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "localhost".into());
    let name = raw.trim();
    name.split('.').next().unwrap_or(name).to_string()
}
