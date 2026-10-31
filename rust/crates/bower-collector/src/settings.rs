//! `CollectorSettings`: read once from `BOWER_*` environment variables and validated
//! before the host starts (C# `Bower.Collector.CollectorSettings`). Variable names,
//! defaults and validation messages match the C# host so deploy assets work unchanged.

use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::error::HostError;

pub const MINIMUM_INGEST_TOKEN_LENGTH: usize = 32;

/// `BOWER_PRIVACY_PROFILE_SOURCE=local` (C# `PrivacyProfileSources.Local`).
pub const PRIVACY_PROFILE_SOURCE_LOCAL: &str = "local";
/// `BOWER_PRIVACY_PROFILE_SOURCE=management` (C# `PrivacyProfileSources.Management`).
pub const PRIVACY_PROFILE_SOURCE_MANAGEMENT: &str = "management";

/// `BOWER_MANAGEMENT_AUTH` values (C# `ManagementAuthenticationModes`).
pub const MANAGEMENT_AUTH_ENTRA: &str = "entra";
pub const MANAGEMENT_AUTH_ENROLMENT: &str = "enrolment";

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
    pub producer_scopes_file: Option<PathBuf>,
    pub single_trust_domain: bool,
    pub packs: Vec<String>,
    pub pack_trusted_key_files: Vec<String>,
    pub privacy_profile_path: Option<PathBuf>,
    /// `local` (default): `BOWER_PRIVACY_PROFILE`, one pack profile or the built-in
    /// default. `management`: the signed version assigned in the management API (cached
    /// locally).
    pub privacy_profile_source: String,
    /// PEM public keys trusted to sign managed privacy profiles.
    pub managed_privacy_trusted_key_files: Vec<String>,
    /// Cache directory for the managed privacy profile; `None` means next to the queue
    /// database.
    pub managed_privacy_directory: Option<PathBuf>,
    /// `BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT=true`: accept events under the built-in default
    /// privacy profile before the first managed sync resolves. Off by default: a
    /// management-mode collector without a verified cache refuses ingest (503) until then.
    pub managed_privacy_allow_default: bool,
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
    /// Explicit HTTP(S) proxy for the management channel (BOWER_MANAGEMENT_PROXY). Unset:
    /// the standard HTTPS_PROXY, HTTP_PROXY and NO_PROXY variables apply.
    pub management_proxy: Option<Url>,
    /// Proxy user name (BOWER_MANAGEMENT_PROXY_USERNAME); the password comes from a file.
    pub management_proxy_username: Option<String>,
    /// File holding the proxy password (BOWER_MANAGEMENT_PROXY_PASSWORD_FILE). Never logged.
    pub management_proxy_password_file: Option<PathBuf>,
    /// Extra CA roots for the management channel (BOWER_MANAGEMENT_CA_BUNDLE), merged with
    /// the platform roots. Verification is never disabled.
    pub management_ca_bundle: Option<PathBuf>,
    /// PEM public keys trusted to sign management commands (BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS).
    pub management_command_trusted_key_files: Vec<String>,
    /// How the collector authenticates to management (BOWER_MANAGEMENT_AUTH): `entra`
    /// (default) or `enrolment` (a one-time token exchanged for a key-bound credential).
    pub management_authentication: String,
    /// One-time enrolment token file (BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE). Never logged.
    pub management_enrolment_token_file: Option<PathBuf>,
    /// Delete the token file once management consumed or refused the token
    /// (BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE). Not part of the configuration hash.
    pub management_enrolment_token_remove_after_use: bool,
    /// JSON file of applications that must keep sending events (BOWER_SOURCE_EXPECTATIONS).
    pub source_expectations_path: Option<PathBuf>,
    /// Directory for the verifiable long-term archive (BOWER_ARCHIVE_PATH).
    pub archive_path: Option<PathBuf>,
    /// JSON file of syslog listeners and pack routes (BOWER_SYSLOG_CONFIG).
    pub syslog_config_path: Option<PathBuf>,
    /// Relay this collector delivers to (BOWER_RELAY_URL, BOWER_OUTPUT=relay): an https
    /// URL with no path, credentials or query. The connection uses mutual TLS.
    pub relay_url: Option<Url>,
    /// PEM client certificate presented to the relay (BOWER_RELAY_CLIENT_CERTIFICATE_FILE).
    pub relay_client_certificate_file: Option<PathBuf>,
    /// PEM private key of the client certificate (BOWER_RELAY_CLIENT_KEY_FILE). Never logged.
    pub relay_client_key_file: Option<PathBuf>,
    /// PEM roots trusted for the relay's server certificate (BOWER_RELAY_CA_BUNDLE).
    pub relay_ca_bundle: Option<PathBuf>,
    /// BOWER_MANAGEMENT_VIA_RELAY=true: management traffic goes through the relay's
    /// management tunnel; TLS to management stays end to end.
    pub management_via_relay: bool,
    /// Relay role (BOWER_RELAY_LISTEN_URL): an https listener for downstream collectors,
    /// always mutual TLS.
    pub relay_listen_url: Option<Url>,
    /// PEM server certificate of the relay listener (BOWER_RELAY_CERTIFICATE_FILE).
    pub relay_certificate_file: Option<PathBuf>,
    /// PEM private key of the relay listener certificate (BOWER_RELAY_KEY_FILE). Never logged.
    pub relay_key_file: Option<PathBuf>,
    /// Downstream collector ids and pinned client certificates (BOWER_RELAY_DOWNSTREAMS_FILE).
    pub relay_downstreams_file: Option<PathBuf>,
    /// BOWER_RELAY_MANAGEMENT_TUNNEL=true: downstreams may tunnel to this relay's own
    /// BOWER_MANAGEMENT_ENDPOINT, and nowhere else.
    pub relay_management_tunnel: bool,
    /// BOWER_TAP_ENABLED (default true): serve `GET /v1/tap` for `bower tap`.
    pub tap_enabled: bool,
    /// BOWER_TAP_MAX_SESSIONS: concurrent tap sessions (1-16, default 2).
    pub tap_maximum_sessions: i32,
    /// BOWER_TAP_MAX_EVENTS_PER_SECOND: frames per second per session (1-1000, default 20).
    pub tap_maximum_events_per_second: i32,
    /// BOWER_TAP_MAX_DURATION_SECONDS: longest session (1-3600, default 300).
    pub tap_maximum_duration_seconds: i32,
    /// BOWER_TAP_MAX_EVENTS: most frames per session (1-10000, default 1000).
    pub tap_maximum_events: i32,
    /// BOWER_TAP_MAX_EVENT_BYTES: larger accepted events show metadata only (default 16384).
    pub tap_maximum_event_bytes: i32,
    /// BOWER_TAP_PRODUCERS: tokens-file producer ids allowed to tap besides the shared token.
    pub tap_producers: Vec<String>,
    /// BOWER_WINDOWS_EVENTLOG_CONFIG. Read only to refuse it: the Windows Event Log source
    /// is C#-only (the Rust collector does not run on Windows).
    pub windows_event_log_config_path: Option<PathBuf>,
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
            producer_scopes_file: None,
            single_trust_domain: false,
            packs: Vec::new(),
            pack_trusted_key_files: Vec::new(),
            privacy_profile_path: None,
            privacy_profile_source: PRIVACY_PROFILE_SOURCE_LOCAL.into(),
            managed_privacy_trusted_key_files: Vec::new(),
            managed_privacy_directory: None,
            managed_privacy_allow_default: false,
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
            management_proxy: None,
            management_proxy_username: None,
            management_proxy_password_file: None,
            management_ca_bundle: None,
            management_command_trusted_key_files: Vec::new(),
            management_authentication: MANAGEMENT_AUTH_ENTRA.to_string(),
            management_enrolment_token_file: None,
            management_enrolment_token_remove_after_use: false,
            source_expectations_path: None,
            archive_path: None,
            syslog_config_path: None,
            relay_url: None,
            relay_client_certificate_file: None,
            relay_client_key_file: None,
            relay_ca_bundle: None,
            management_via_relay: false,
            relay_listen_url: None,
            relay_certificate_file: None,
            relay_key_file: None,
            relay_downstreams_file: None,
            relay_management_tunnel: false,
            tap_enabled: true,
            tap_maximum_sessions: 2,
            tap_maximum_events_per_second: 20,
            tap_maximum_duration_seconds: 300,
            tap_maximum_events: 1000,
            tap_maximum_event_bytes: 16_384,
            tap_producers: Vec::new(),
            windows_event_log_config_path: None,
        }
    }

    /// Also resolves the persisted default collector id (`collector_identity`) when
    /// `BOWER_COLLECTOR_ID` is unset; `from_environment` stays free of file writes.
    pub fn from_process_environment() -> Result<Self, HostError> {
        let queue_path = std::env::var("BOWER_QUEUE_PATH")
            .ok()
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| base_directory().join("data").join("bower.db"));
        let (collector_id, _) = crate::collector_identity::resolve(
            std::env::var("BOWER_COLLECTOR_ID").ok(),
            &queue_path,
            machine_name,
        )?;
        Self::from_environment(|name| {
            if name == "BOWER_COLLECTOR_ID" {
                Some(collector_id.clone())
            } else {
                std::env::var(name).ok()
            }
        })
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
            producer_scopes_file: blank(read("BOWER_PRODUCER_SCOPES_FILE")).map(PathBuf::from),
            single_trust_domain: read("BOWER_SINGLE_TRUST_DOMAIN")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            packs: split_list(read("BOWER_PACKS").as_deref()),
            pack_trusted_key_files: split_list(read("BOWER_PACK_TRUSTED_KEYS").as_deref()),
            privacy_profile_path: blank(read("BOWER_PRIVACY_PROFILE")).map(PathBuf::from),
            privacy_profile_source: blank(read("BOWER_PRIVACY_PROFILE_SOURCE")).map_or_else(
                || PRIVACY_PROFILE_SOURCE_LOCAL.into(),
                |value| value.trim().to_lowercase(),
            ),
            managed_privacy_trusted_key_files: split_list(
                read("BOWER_MANAGED_PRIVACY_TRUSTED_KEYS").as_deref(),
            ),
            managed_privacy_directory: blank(read("BOWER_MANAGED_PRIVACY_DIRECTORY"))
                .map(PathBuf::from),
            managed_privacy_allow_default: read("BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
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
            management_proxy: read_proxy(blank(read("BOWER_MANAGEMENT_PROXY")))?,
            management_proxy_username: blank(read("BOWER_MANAGEMENT_PROXY_USERNAME")),
            management_proxy_password_file: blank(read("BOWER_MANAGEMENT_PROXY_PASSWORD_FILE"))
                .map(PathBuf::from),
            management_ca_bundle: blank(read("BOWER_MANAGEMENT_CA_BUNDLE")).map(PathBuf::from),
            management_command_trusted_key_files: split_list(
                read("BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS").as_deref(),
            ),
            management_authentication: blank(read("BOWER_MANAGEMENT_AUTH"))
                .map(|value| value.trim().to_lowercase())
                .unwrap_or_else(|| MANAGEMENT_AUTH_ENTRA.to_string()),
            management_enrolment_token_file: blank(read("BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE"))
                .map(PathBuf::from),
            relay_url: read_url(blank(read("BOWER_RELAY_URL")), "BOWER_RELAY_URL")?,
            relay_client_certificate_file: blank(read("BOWER_RELAY_CLIENT_CERTIFICATE_FILE"))
                .map(PathBuf::from),
            relay_client_key_file: blank(read("BOWER_RELAY_CLIENT_KEY_FILE")).map(PathBuf::from),
            relay_ca_bundle: blank(read("BOWER_RELAY_CA_BUNDLE")).map(PathBuf::from),
            management_via_relay: read_boolean(&read, "BOWER_MANAGEMENT_VIA_RELAY")?,
            relay_listen_url: read_url(
                blank(read("BOWER_RELAY_LISTEN_URL")),
                "BOWER_RELAY_LISTEN_URL",
            )?,
            relay_certificate_file: blank(read("BOWER_RELAY_CERTIFICATE_FILE")).map(PathBuf::from),
            relay_key_file: blank(read("BOWER_RELAY_KEY_FILE")).map(PathBuf::from),
            relay_downstreams_file: blank(read("BOWER_RELAY_DOWNSTREAMS_FILE")).map(PathBuf::from),
            relay_management_tunnel: read_boolean(&read, "BOWER_RELAY_MANAGEMENT_TUNNEL")?,
            management_enrolment_token_remove_after_use: read(
                "BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE",
            )
            .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            source_expectations_path: blank(read("BOWER_SOURCE_EXPECTATIONS")).map(PathBuf::from),
            archive_path: blank(read("BOWER_ARCHIVE_PATH")).map(PathBuf::from),
            syslog_config_path: blank(read("BOWER_SYSLOG_CONFIG")).map(PathBuf::from),
            tap_enabled: read_bool(&read, "BOWER_TAP_ENABLED", true)?,
            tap_maximum_sessions: read_i64(&read, "BOWER_TAP_MAX_SESSIONS", 2)? as i32,
            tap_maximum_events_per_second: read_i64(&read, "BOWER_TAP_MAX_EVENTS_PER_SECOND", 20)?
                as i32,
            tap_maximum_duration_seconds: read_i64(&read, "BOWER_TAP_MAX_DURATION_SECONDS", 300)?
                as i32,
            tap_maximum_events: read_i64(&read, "BOWER_TAP_MAX_EVENTS", 1000)? as i32,
            tap_maximum_event_bytes: read_i64(&read, "BOWER_TAP_MAX_EVENT_BYTES", 16_384)? as i32,
            tap_producers: split_list(read("BOWER_TAP_PRODUCERS").as_deref()),
            windows_event_log_config_path: blank(read("BOWER_WINDOWS_EVENTLOG_CONFIG"))
                .map(PathBuf::from),
        };
        settings.validate()?;
        Ok(settings)
    }

    /// `BOWER_PRIVACY_PROFILE_SOURCE=management` (C# `UsesManagedPrivacyProfile`).
    pub fn uses_managed_privacy_profile(&self) -> bool {
        self.privacy_profile_source == PRIVACY_PROFILE_SOURCE_MANAGEMENT
    }

    /// Resolved managed privacy profile cache directory (C# `ManagedPrivacyCacheDirectory`):
    /// `managed-privacy` next to the queue database unless configured.
    pub fn managed_privacy_cache_directory(&self) -> PathBuf {
        if let Some(directory) = &self.managed_privacy_directory {
            return directory.clone();
        }
        full_path(&self.queue_path)
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("managed-privacy")
    }

    /// `BOWER_MANAGEMENT_AUTH=enrolment` (C# `UsesEnrolment`).
    pub fn uses_enrolment(&self) -> bool {
        self.management_authentication == MANAGEMENT_AUTH_ENROLMENT
    }

    /// Key-bound credential directory (C# `ManagementCredentialDirectory`):
    /// `management-credential` next to the queue database.
    pub fn management_credential_directory(&self) -> PathBuf {
        full_path(&self.queue_path)
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("management-credential")
    }

    /// Durable command ledger directory (C# `ManagementCommandDirectory`):
    /// `management-commands` next to the queue database.
    pub fn management_command_directory(&self) -> PathBuf {
        full_path(&self.queue_path)
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("management-commands")
    }

    /// Relay role: `BOWER_RELAY_LISTEN_URL` is set (C# `IsRelay`).
    pub fn is_relay(&self) -> bool {
        self.relay_listen_url.is_some()
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

        if self.single_trust_domain && self.producer_scopes_file.is_some() {
            return Err(invalid(
                "Producer scopes and single trust domain mode are mutually exclusive.",
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
            "none" | "ama-spool" | "azure-logs-ingestion" | "relay"
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

        if self.management_authentication != MANAGEMENT_AUTH_ENTRA && !self.uses_enrolment() {
            return Err(invalid("BOWER_MANAGEMENT_AUTH must be entra or enrolment."));
        }
        if self.uses_enrolment() && self.management_endpoint.is_none() {
            return Err(invalid(
                "BOWER_MANAGEMENT_AUTH=enrolment requires BOWER_MANAGEMENT_ENDPOINT.",
            ));
        }
        if self.management_enrolment_token_file.is_some() && !self.uses_enrolment() {
            return Err(invalid(
                "BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE requires BOWER_MANAGEMENT_AUTH=enrolment.",
            ));
        }
        if self.management_enrolment_token_remove_after_use
            && self.management_enrolment_token_file.is_none()
        {
            return Err(invalid(
                "BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE requires BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE.",
            ));
        }

        if let Some(endpoint) = &self.management_endpoint {
            if !self.uses_enrolment() && self.management_scope.as_deref().is_none_or(is_blank) {
                return Err(invalid(
                    "BOWER_MANAGEMENT_SCOPE is required when BOWER_MANAGEMENT_ENDPOINT is set.",
                ));
            }

            // The heartbeat carries a bearer token or assertion; never send it in cleartext.
            if endpoint.scheme() != "https" && !url_is_loopback(endpoint) {
                return Err(invalid(
                    "BOWER_MANAGEMENT_ENDPOINT must use HTTPS unless it targets loopback.",
                ));
            }
        }

        // Fail closed rather than run without a source the operator configured.
        if self.windows_event_log_config_path.is_some() {
            return Err(invalid(
                "BOWER_WINDOWS_EVENTLOG_CONFIG is supported only by the C# collector on Windows; \
                 the Rust collector does not read the Windows Event Log.",
            ));
        }

        self.validate_management_connection()?;
        self.validate_privacy_profile_source()?;
        self.validate_relay()?;
        self.validate_tap()
    }

    /// Downstream (`BOWER_OUTPUT=relay`) and relay (`BOWER_RELAY_LISTEN_URL`) settings
    /// (C# `ValidateRelay`). One hop only: a relay never delivers to another relay.
    fn validate_relay(&self) -> Result<(), HostError> {
        let relay_output = self.output_type == "relay";
        let client_settings = self.relay_url.is_some()
            || self.relay_client_certificate_file.is_some()
            || self.relay_client_key_file.is_some()
            || self.relay_ca_bundle.is_some();
        if client_settings && !relay_output {
            return Err(invalid(
                "BOWER_RELAY_URL, BOWER_RELAY_CLIENT_CERTIFICATE_FILE, BOWER_RELAY_CLIENT_KEY_FILE and \
                 BOWER_RELAY_CA_BUNDLE require BOWER_OUTPUT=relay.",
            ));
        }

        if relay_output {
            if !self.relay_url.as_ref().is_some_and(is_valid_https_origin) {
                return Err(invalid(
                    "BOWER_OUTPUT=relay requires BOWER_RELAY_URL: an absolute https:// URL with a host and no \
                     credentials, path or query.",
                ));
            }
            if self.relay_client_certificate_file.is_none() || self.relay_client_key_file.is_none()
            {
                return Err(invalid(
                    "BOWER_OUTPUT=relay requires BOWER_RELAY_CLIENT_CERTIFICATE_FILE and BOWER_RELAY_CLIENT_KEY_FILE: \
                     the relay accepts only pinned client certificates.",
                ));
            }
        }

        if self.management_via_relay {
            if !relay_output || self.management_endpoint.is_none() {
                return Err(invalid(
                    "BOWER_MANAGEMENT_VIA_RELAY requires BOWER_OUTPUT=relay and BOWER_MANAGEMENT_ENDPOINT.",
                ));
            }
            // An Entra token needs a route to Entra ID, which a collector behind a relay lacks.
            if !self.uses_enrolment() {
                return Err(invalid(
                    "BOWER_MANAGEMENT_VIA_RELAY requires BOWER_MANAGEMENT_AUTH=enrolment.",
                ));
            }
            if self.management_proxy.is_some() {
                return Err(invalid(
                    "BOWER_MANAGEMENT_VIA_RELAY cannot be combined with BOWER_MANAGEMENT_PROXY.",
                ));
            }
        }

        let server_settings = self.relay_certificate_file.is_some()
            || self.relay_key_file.is_some()
            || self.relay_downstreams_file.is_some()
            || self.relay_management_tunnel;
        if server_settings && self.relay_listen_url.is_none() {
            return Err(invalid(
                "BOWER_RELAY_CERTIFICATE_FILE, BOWER_RELAY_KEY_FILE, BOWER_RELAY_DOWNSTREAMS_FILE and \
                 BOWER_RELAY_MANAGEMENT_TUNNEL require BOWER_RELAY_LISTEN_URL.",
            ));
        }

        let Some(listen) = &self.relay_listen_url else {
            return Ok(());
        };

        // `Uri.IsDefaultPort`: no port, or the scheme's default written explicitly.
        if !is_valid_https_origin(listen) || listen.port().is_none() {
            return Err(invalid(
                "BOWER_RELAY_LISTEN_URL must be an absolute https:// URL with an explicit port and no \
                 credentials, path or query.",
            ));
        }

        if self.relay_certificate_file.is_none()
            || self.relay_key_file.is_none()
            || self.relay_downstreams_file.is_none()
        {
            return Err(invalid(
                "BOWER_RELAY_LISTEN_URL requires BOWER_RELAY_CERTIFICATE_FILE, BOWER_RELAY_KEY_FILE and \
                 BOWER_RELAY_DOWNSTREAMS_FILE.",
            ));
        }

        if relay_output {
            return Err(invalid(
                "A relay cannot use BOWER_OUTPUT=relay: relays deliver to the destination, one hop only.",
            ));
        }

        if self.relay_management_tunnel && self.management_endpoint.is_none() {
            return Err(invalid(
                "BOWER_RELAY_MANAGEMENT_TUNNEL requires BOWER_MANAGEMENT_ENDPOINT.",
            ));
        }

        // The tunnel opens a direct TCP connection to the management host.
        if self.relay_management_tunnel && self.management_proxy.is_some() {
            return Err(invalid(
                "BOWER_RELAY_MANAGEMENT_TUNNEL connects directly and cannot be combined with BOWER_MANAGEMENT_PROXY.",
            ));
        }

        Ok(())
    }

    /// C# `ValidateTap`.
    fn validate_tap(&self) -> Result<(), HostError> {
        let range = |value: i32, minimum: i32, maximum: i32, name: &str| {
            if (minimum..=maximum).contains(&value) {
                Ok(())
            } else {
                Err(invalid(format!(
                    "{name} must be between {minimum} and {maximum}."
                )))
            }
        };
        range(self.tap_maximum_sessions, 1, 16, "BOWER_TAP_MAX_SESSIONS")?;
        range(
            self.tap_maximum_events_per_second,
            1,
            1_000,
            "BOWER_TAP_MAX_EVENTS_PER_SECOND",
        )?;
        range(
            self.tap_maximum_duration_seconds,
            1,
            3_600,
            "BOWER_TAP_MAX_DURATION_SECONDS",
        )?;
        range(self.tap_maximum_events, 1, 10_000, "BOWER_TAP_MAX_EVENTS")?;
        range(
            self.tap_maximum_event_bytes,
            1_024,
            1_048_576,
            "BOWER_TAP_MAX_EVENT_BYTES",
        )?;
        if self.tap_producers.iter().any(|producer| {
            !(1..=64).contains(&producer.encode_utf16().count()) || producer.contains(' ')
        }) {
            return Err(invalid(
                "BOWER_TAP_PRODUCERS must list producer ids of 1 to 64 characters.",
            ));
        }
        Ok(())
    }

    /// Tap limits for [`crate::tap::EventTap`] (C# `TapOptions`).
    pub fn tap_options(&self) -> crate::tap::EventTapOptions {
        crate::tap::EventTapOptions {
            enabled: self.tap_enabled,
            maximum_sessions: usize::try_from(self.tap_maximum_sessions).unwrap_or(1),
            maximum_events_per_second: f64::from(self.tap_maximum_events_per_second),
            maximum_duration: Duration::from_secs(
                u64::try_from(self.tap_maximum_duration_seconds).unwrap_or(1),
            ),
            maximum_events: i64::from(self.tap_maximum_events),
            maximum_event_bytes: usize::try_from(self.tap_maximum_event_bytes).unwrap_or(1_024),
        }
    }

    /// Proxy, CA bundle and command keys apply to the management channel only (C#
    /// `ValidateManagementConnection`). Messages never echo the proxy URL.
    fn validate_management_connection(&self) -> Result<(), HostError> {
        let connection_settings = self.management_proxy.is_some()
            || self.management_proxy_username.is_some()
            || self.management_proxy_password_file.is_some()
            || self.management_ca_bundle.is_some()
            || !self.management_command_trusted_key_files.is_empty();
        if connection_settings && self.management_endpoint.is_none() {
            return Err(invalid(
                "BOWER_MANAGEMENT_PROXY, BOWER_MANAGEMENT_CA_BUNDLE and BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS \
                 require BOWER_MANAGEMENT_ENDPOINT.",
            ));
        }

        if self
            .management_proxy
            .as_ref()
            .is_some_and(|proxy| !is_valid_proxy(proxy))
        {
            return Err(invalid(
                "BOWER_MANAGEMENT_PROXY must be an absolute http:// or https:// URL with a host and no \
                 credentials, path or query. Put credentials in BOWER_MANAGEMENT_PROXY_USERNAME and \
                 BOWER_MANAGEMENT_PROXY_PASSWORD_FILE.",
            ));
        }

        if self.management_proxy_username.is_none() != self.management_proxy_password_file.is_none()
        {
            return Err(invalid(
                "BOWER_MANAGEMENT_PROXY_USERNAME and BOWER_MANAGEMENT_PROXY_PASSWORD_FILE must be set together.",
            ));
        }

        if self.management_proxy_username.is_some() && self.management_proxy.is_none() {
            return Err(invalid(
                "BOWER_MANAGEMENT_PROXY_USERNAME requires BOWER_MANAGEMENT_PROXY.",
            ));
        }

        Ok(())
    }

    fn validate_privacy_profile_source(&self) -> Result<(), HostError> {
        if self.privacy_profile_source != PRIVACY_PROFILE_SOURCE_LOCAL
            && self.privacy_profile_source != PRIVACY_PROFILE_SOURCE_MANAGEMENT
        {
            return Err(invalid(
                "BOWER_PRIVACY_PROFILE_SOURCE must be local or management.",
            ));
        }

        if !self.uses_managed_privacy_profile() {
            return Ok(());
        }

        if self.management_endpoint.is_none() {
            return Err(invalid(
                "BOWER_PRIVACY_PROFILE_SOURCE=management requires BOWER_MANAGEMENT_ENDPOINT and BOWER_MANAGEMENT_SCOPE.",
            ));
        }

        if self.managed_privacy_trusted_key_files.is_empty() {
            return Err(invalid(
                "BOWER_PRIVACY_PROFILE_SOURCE=management requires BOWER_MANAGED_PRIVACY_TRUSTED_KEYS; \
                 managed privacy profiles are never loaded unverified.",
            ));
        }

        if self.privacy_profile_path.is_some() {
            return Err(invalid(
                "BOWER_PRIVACY_PROFILE cannot be combined with BOWER_PRIVACY_PROFILE_SOURCE=management.",
            ));
        }

        Ok(())
    }

    /// Hash of non-secret settings reported to management (C# `ConfigurationHash`).
    pub fn configuration_hash(&self) -> String {
        let retention_hours = self.delivered_retention.as_secs_f64() / 3600.0;
        let mut material = [
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
            dotnet_bool(self.single_trust_domain).to_string(),
            self.producer_scopes_file
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ]
        .join("\u{1f}");
        // Appended only when set so existing configuration hashes are unchanged.
        if let Some(path) = &self.source_expectations_path {
            material.push('\u{1f}');
            material.push_str("source-expectations:");
            material.push_str(&path.to_string_lossy());
        }
        if let Some(path) = &self.archive_path {
            material.push('\u{1f}');
            material.push_str("archive:");
            material.push_str(&path.to_string_lossy());
        }
        if let Some(path) = &self.syslog_config_path {
            material.push('\u{1f}');
            material.push_str("syslog:");
            material.push_str(&path.to_string_lossy());
        }
        if self.uses_managed_privacy_profile() {
            // Appended only in management mode so existing local configuration hashes
            // are unchanged.
            material.push('\u{1f}');
            material.push_str("privacy-source:");
            material.push_str(&self.privacy_profile_source);
            material.push('\u{1f}');
            material.push_str("privacy-allow-default:");
            material.push_str(dotnet_bool(self.managed_privacy_allow_default));
        }
        // Appended only when set so existing configuration hashes are unchanged. The proxy
        // contributes scheme, host and port only; credentials never enter the hash.
        if let Some(proxy) = &self.management_proxy {
            material.push('\u{1f}');
            material.push_str(&format!(
                "management-proxy:{}://{}:{}",
                proxy.scheme(),
                proxy.host_str().unwrap_or_default(),
                proxy.port_or_known_default().unwrap_or_default()
            ));
            material.push('\u{1f}');
            material.push_str("management-proxy-auth:");
            material.push_str(dotnet_bool(self.management_proxy_username.is_some()));
        }
        if let Some(path) = &self.management_ca_bundle {
            material.push('\u{1f}');
            material.push_str("management-ca:");
            material.push_str(&path.to_string_lossy());
        }
        if !self.management_command_trusted_key_files.is_empty() {
            material.push('\u{1f}');
            material.push_str("management-commands:True");
        }
        if self.uses_enrolment() {
            material.push('\u{1f}');
            material.push_str("management-auth:enrolment");
        }
        // Relay settings, appended only when set. Hosts, ports and paths only, never file
        // contents.
        if let Some(url) = &self.relay_url {
            material.push_str(&format!(
                "\u{1f}relay-url:{}:{}\u{1f}relay-ca:{}",
                url.host_str().unwrap_or_default(),
                url.port_or_known_default().unwrap_or_default(),
                self.relay_ca_bundle
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
        }
        if self.management_via_relay {
            material.push_str("\u{1f}management-via-relay:True");
        }
        if let Some(url) = &self.relay_listen_url {
            material.push_str(&format!(
                "\u{1f}relay-listen:{}:{}\u{1f}relay-downstreams:{}\u{1f}relay-tunnel:{}",
                url.host_str().unwrap_or_default(),
                url.port_or_known_default().unwrap_or_default(),
                self.relay_downstreams_file
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                dotnet_bool(self.relay_management_tunnel)
            ));
        }
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

/// C# `ReadBoolean`: blank is `fallback`; otherwise `true` or `false` in any case.
fn read_bool(
    read: &impl Fn(&str) -> Option<String>,
    name: &str,
    fallback: bool,
) -> Result<bool, HostError> {
    let Some(value) = read(name).filter(|value| !is_blank(value)) else {
        return Ok(fallback);
    };
    match value.trim().to_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(format!("{name} must be true or false."))),
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

/// C# `ReadProxy`: an absolute URI or a start-up error that never echoes the value.
fn read_proxy(value: Option<String>) -> Result<Option<Url>, HostError> {
    match value {
        Some(value) => Url::parse(value.trim()).map(Some).map_err(|_| {
            invalid("BOWER_MANAGEMENT_PROXY must be an absolute http:// or https:// URL.")
        }),
        None => Ok(None),
    }
}

/// C# `ReadUrl`: an absolute URI or a start-up error naming the variable.
fn read_url(value: Option<String>, name: &str) -> Result<Option<Url>, HostError> {
    match value {
        Some(value) => Url::parse(value.trim())
            .map(Some)
            .map_err(|_| invalid(format!("{name} must be an absolute https:// URL."))),
        None => Ok(None),
    }
}

/// C# `ReadBoolean`: unset or blank is false; otherwise exactly true or false (any case).
fn read_boolean(read: &impl Fn(&str) -> Option<String>, name: &str) -> Result<bool, HostError> {
    match blank(read(name))
        .map(|value| value.trim().to_lowercase())
        .as_deref()
    {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(invalid(format!("{name} must be true or false."))),
    }
}

/// C# `IsValidHttpsOrigin`: https, a host, no credentials, no path, query or fragment.
pub fn is_valid_https_origin(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

/// C# `IsValidProxy`: http(s), a host, no credentials, no path, query or fragment.
pub fn is_valid_proxy(proxy: &Url) -> bool {
    matches!(proxy.scheme(), "http" | "https")
        && proxy.host_str().is_some_and(|host| !host.is_empty())
        && proxy.username().is_empty()
        && proxy.password().is_none()
        && proxy.path() == "/"
        && proxy.query().is_none()
        && proxy.fragment().is_none()
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

/// `Path.GetFullPath`: absolute against the current directory, with `.` and `..`
/// segments resolved lexically (symbolic links are not followed).
pub(crate) fn full_path(path: &std::path::Path) -> PathBuf {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    normalized
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
