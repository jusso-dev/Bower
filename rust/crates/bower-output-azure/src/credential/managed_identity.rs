//! `ManagedIdentityCredential` (Azure.Identity 1.21 over MSAL.NET 4.83): source
//! detection, the per-source wire protocols and the Azure.Core retry policy that
//! Azure.Identity installs for managed identity
//! (`DefaultAzureCredentialImdsRetryPolicy`, 5 retries).
//!
//! Bower creates the credential directly, never through `DefaultAzureCredential`,
//! so Azure.Identity's IMDS probe (1 s first-request timeout, no `Metadata`
//! header) is never sent; neither is it here.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, WWW_AUTHENTICATE};

use super::{
    AccessToken, DEFAULT_AUTHORITY_HOST, IMDS_ENDPOINT, NETWORK_TIMEOUT, TokenError, TokenFuture,
    TokenProvider, WorkloadIdentityCredential, WorkloadIdentitySettings, form_encode,
    read_token_response, scope_to_resource, tls,
};

/// MSAL's Azure Arc endpoint when only the agent binary is detected.
pub const ARC_DEFAULT_ENDPOINT: &str = "http://127.0.0.1:40342/metadata/identity/oauth2/token";
/// MSAL rejects Azure Arc challenge files larger than this.
const ARC_MAX_KEY_FILE_BYTES: u64 = 4096;
const SOURCE: &str = "managed identity";

/// Azure.Core retry settings Azure.Identity uses for managed identity requests:
/// `MaxRetries = 5`, `ImdsRetryDelayStrategy` (exponential from 0.8 s, from 3 s for
/// HTTP 410 so IMDS gets 70+ s to recover), ±20 % jitter, 60 s cap, and a larger
/// server `Retry-After` always wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedIdentityRetryOptions {
    pub max_retries: u32,
    pub delay: Duration,
    pub gone_delay: Duration,
    pub max_delay: Duration,
}

impl Default for ManagedIdentityRetryOptions {
    fn default() -> Self {
        Self {
            max_retries: 5,
            delay: Duration::from_millis(800),
            gone_delay: Duration::from_secs(3),
            max_delay: Duration::from_secs(60),
        }
    }
}

impl ManagedIdentityRetryOptions {
    fn delay_for(&self, status: Option<u16>, headers: Option<&HeaderMap>, retry: u32) -> Duration {
        let base = if status == Some(410) {
            self.gone_delay
        } else {
            self.delay
        };
        let exponent = retry.saturating_sub(1).min(30);
        let computed = base
            .mul_f64(f64::from(1u32 << exponent) * jitter())
            .min(self.max_delay);
        headers
            .and_then(server_delay)
            .map_or(computed, |server| server.max(computed))
    }
}

/// `ManagedIdentityResponseClassifier`: 404 and 410 (IMDS warming up) on top of
/// Azure.Core's 408, 429, 500, 503 and 504; 502 is explicitly not retried.
fn is_retriable_status(status: u16) -> bool {
    matches!(status, 404 | 408 | 410 | 429 | 500 | 503 | 504)
}

/// Azure.Core `ResponseHeaders.RetryAfter`: `retry-after-ms`,
/// `x-ms-retry-after-ms`, then `Retry-After` (seconds or HTTP date).
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
            return Some(Duration::from_secs_f64(milliseconds / 1000.0));
        }
    }
    let value = text("retry-after")?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
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

/// Where a managed identity token comes from (MSAL `ManagedIdentitySource`).
#[derive(Clone, PartialEq, Eq)]
pub enum ManagedIdentitySource {
    /// Azure Instance Metadata Service (VMs, scale sets, AKS node identity).
    Imds { endpoint: String },
    /// App Service / Functions / Container Apps (`IDENTITY_ENDPOINT` + `IDENTITY_HEADER`).
    AppService { endpoint: String, header: String },
    /// Service Fabric (`IDENTITY_ENDPOINT` + `IDENTITY_HEADER` +
    /// `IDENTITY_SERVER_THUMBPRINT`): system-assigned only, thumbprint-pinned TLS.
    ServiceFabric {
        endpoint: String,
        header: String,
        thumbprint: String,
    },
    /// Azure Machine Learning (`MSI_ENDPOINT` + `MSI_SECRET`,
    /// `DEFAULT_IDENTITY_CLIENT_ID`).
    MachineLearning {
        endpoint: String,
        secret: String,
        default_client_id: Option<String>,
    },
    /// Azure Cloud Shell (`MSI_ENDPOINT`): system-assigned only.
    CloudShell { endpoint: String },
    /// Azure Arc (`IDENTITY_ENDPOINT` + `IMDS_ENDPOINT`, or the installed agent):
    /// system-assigned only, `WWW-Authenticate` challenge file flow. Challenge
    /// files must sit directly in `token_directory` (`None` where Azure Arc is not
    /// supported).
    AzureArc {
        endpoint: String,
        token_directory: Option<PathBuf>,
    },
    /// AKS workload identity token exchange (`AZURE_FEDERATED_TOKEN_FILE`), which
    /// Azure.Identity prefers over every MSAL source except a misconfigured
    /// Service Fabric.
    TokenExchange(WorkloadIdentitySettings),
}

impl fmt::Debug for ManagedIdentitySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Header and secret values are credentials; endpoints are not.
        match self {
            Self::Imds { endpoint } => formatter
                .debug_struct("Imds")
                .field("endpoint", endpoint)
                .finish(),
            Self::AppService { endpoint, .. } => formatter
                .debug_struct("AppService")
                .field("endpoint", endpoint)
                .finish_non_exhaustive(),
            Self::ServiceFabric {
                endpoint,
                thumbprint,
                ..
            } => formatter
                .debug_struct("ServiceFabric")
                .field("endpoint", endpoint)
                .field("thumbprint", thumbprint)
                .finish_non_exhaustive(),
            Self::MachineLearning { endpoint, .. } => formatter
                .debug_struct("MachineLearning")
                .field("endpoint", endpoint)
                .finish_non_exhaustive(),
            Self::CloudShell { endpoint } => formatter
                .debug_struct("CloudShell")
                .field("endpoint", endpoint)
                .finish(),
            Self::AzureArc {
                endpoint,
                token_directory,
            } => formatter
                .debug_struct("AzureArc")
                .field("endpoint", endpoint)
                .field("token_directory", token_directory)
                .finish(),
            Self::TokenExchange(settings) => formatter
                .debug_tuple("TokenExchange")
                .field(settings)
                .finish(),
        }
    }
}

/// MSAL `AzureArcManagedIdentitySource.IsValidPath` directory.
fn arc_token_directory() -> Option<PathBuf> {
    if cfg!(target_os = "linux") {
        Some(PathBuf::from("/var/opt/azcmagent/tokens/"))
    } else if cfg!(windows) {
        let program_data =
            std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_owned());
        Some(PathBuf::from(format!(
            "{program_data}\\AzureConnectedMachineAgent\\Tokens\\"
        )))
    } else {
        None
    }
}

/// MSAL file-based Azure Arc detection (`himds` agent binary).
fn arc_agent_installed() -> bool {
    if cfg!(target_os = "linux") {
        Path::new("/opt/azcmagent/bin/himds").is_file()
    } else if cfg!(windows) {
        std::env::var("ProgramFiles").is_ok_and(|program_files| {
            Path::new(&format!(
                "{program_files}\\AzureConnectedMachineAgent\\himds.exe"
            ))
            .is_file()
        })
    } else {
        false
    }
}

impl ManagedIdentitySource {
    /// Detects the source from the process environment.
    pub fn from_env(client_id: Option<&str>) -> Self {
        Self::detect(
            |name| std::env::var(name).ok().filter(|value| !value.is_empty()),
            client_id,
            arc_agent_installed(),
        )
    }

    /// MSAL `GetManagedIdentitySourceNoImds` order (Service Fabric, App Service,
    /// Machine Learning, Cloud Shell, Azure Arc), then Azure.Identity's rules:
    /// Service Fabric with a user-assigned id fails, otherwise a configured token
    /// exchange wins, otherwise the MSAL source, otherwise IMDS.
    fn detect(
        var: impl Fn(&str) -> Option<String>,
        client_id: Option<&str>,
        arc_agent_installed: bool,
    ) -> Self {
        let identity_endpoint = var("IDENTITY_ENDPOINT");
        let identity_header = var("IDENTITY_HEADER");
        let msi_endpoint = var("MSI_ENDPOINT");
        let msal = match (identity_endpoint.clone(), identity_header) {
            (Some(endpoint), Some(header)) => Some(match var("IDENTITY_SERVER_THUMBPRINT") {
                Some(thumbprint) => Self::ServiceFabric {
                    endpoint,
                    header,
                    thumbprint,
                },
                None => Self::AppService { endpoint, header },
            }),
            _ => match (msi_endpoint, var("MSI_SECRET")) {
                (Some(endpoint), Some(secret)) => Some(Self::MachineLearning {
                    endpoint,
                    secret,
                    default_client_id: var("DEFAULT_IDENTITY_CLIENT_ID"),
                }),
                (Some(endpoint), None) => Some(Self::CloudShell { endpoint }),
                _ if (identity_endpoint.is_some() && var("IMDS_ENDPOINT").is_some())
                    || arc_agent_installed =>
                {
                    Some(Self::AzureArc {
                        endpoint: identity_endpoint
                            .unwrap_or_else(|| ARC_DEFAULT_ENDPOINT.to_owned()),
                        token_directory: arc_token_directory(),
                    })
                }
                _ => None,
            },
        };
        if let Some(source @ Self::ServiceFabric { .. }) = &msal
            && client_id.is_some()
        {
            return source.clone();
        }
        if let (Some(token_file), Some(tenant_id), Some(exchange_client_id)) = (
            var("AZURE_FEDERATED_TOKEN_FILE"),
            var("AZURE_TENANT_ID"),
            client_id
                .map(str::to_owned)
                .or_else(|| var("AZURE_CLIENT_ID")),
        ) {
            return Self::TokenExchange(WorkloadIdentitySettings {
                tenant_id,
                client_id: exchange_client_id,
                token_file: PathBuf::from(token_file),
                authority_host: var("AZURE_AUTHORITY_HOST")
                    .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_owned()),
            });
        }
        msal.unwrap_or_else(|| Self::Imds {
            endpoint: var("AZURE_POD_IDENTITY_AUTHORITY_HOST")
                .map(|host| {
                    format!(
                        "{}/metadata/identity/oauth2/token",
                        host.trim_end_matches('/')
                    )
                })
                .unwrap_or_else(|| IMDS_ENDPOINT.to_owned()),
        })
    }
}

/// System- or user-assigned (by client id) managed identity.
pub struct ManagedIdentityCredential {
    client: reqwest::Client,
    client_id: Option<String>,
    source: ManagedIdentitySource,
    retry: ManagedIdentityRetryOptions,
    service_fabric_client: OnceLock<Result<reqwest::Client, TokenError>>,
}

impl ManagedIdentityCredential {
    pub fn new(
        client: reqwest::Client,
        client_id: Option<String>,
        source: ManagedIdentitySource,
    ) -> Self {
        Self {
            client,
            client_id,
            source,
            retry: ManagedIdentityRetryOptions::default(),
            service_fabric_client: OnceLock::new(),
        }
    }

    /// Detects the source like Azure.Identity (see [`ManagedIdentitySource`]).
    pub fn from_env(client: reqwest::Client, client_id: Option<String>) -> Self {
        let source = ManagedIdentitySource::from_env(client_id.as_deref());
        Self::new(client, client_id, source)
    }

    /// Overrides the retry policy (tests use short delays).
    pub fn with_retry_options(mut self, retry: ManagedIdentityRetryOptions) -> Self {
        self.retry = retry;
        self
    }

    pub fn source(&self) -> &ManagedIdentitySource {
        &self.source
    }

    fn system_assigned_only(&self, source: &str) -> Result<(), TokenError> {
        match self.client_id {
            Some(_) => Err(TokenError::Failed(format!(
                "{source} managed identity does not support user-assigned identities"
            ))),
            None => Ok(()),
        }
    }

    /// Sends with the managed identity retry policy. Transport failures and
    /// retriable statuses are retried; the last outcome is returned.
    async fn send(
        &self,
        client: &reqwest::Client,
        build: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, TokenError> {
        let mut retry = 0u32;
        loop {
            let outcome = build(client).send().await;
            let (retriable, status, headers) = match &outcome {
                Ok(response) => (
                    is_retriable_status(response.status().as_u16()),
                    Some(response.status().as_u16()),
                    Some(response.headers().clone()),
                ),
                Err(_) => (true, None, None),
            };
            if !retriable || retry >= self.retry.max_retries {
                return outcome
                    .map_err(|_| TokenError::Transport(format!("{SOURCE} endpoint unreachable")));
            }
            drop(outcome);
            retry += 1;
            tokio::time::sleep(self.retry.delay_for(status, headers.as_ref(), retry)).await;
        }
    }

    async fn get(
        &self,
        client: &reqwest::Client,
        url: &reqwest::Url,
        headers: &[(&'static str, &str)],
    ) -> Result<AccessToken, TokenError> {
        let response = self
            .send(client, |client| {
                headers
                    .iter()
                    .fold(client.get(url.clone()), |request, (name, value)| {
                        request.header(*name, *value)
                    })
            })
            .await?;
        read_token_response(response, SOURCE).await
    }

    async fn azure_arc(
        &self,
        endpoint: &str,
        token_directory: Option<&Path>,
        resource: &str,
    ) -> Result<AccessToken, TokenError> {
        self.system_assigned_only("Azure Arc")?;
        let url = request_url(
            endpoint,
            &[("api-version", "2019-11-01"), ("resource", resource)],
        )?;
        let challenge = self
            .send(&self.client, |client| {
                client.get(url.clone()).header("Metadata", "true")
            })
            .await?;
        if challenge.status() != reqwest::StatusCode::UNAUTHORIZED {
            return read_token_response(challenge, SOURCE).await;
        }
        let header = challenge
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| {
                TokenError::Failed(
                    "Azure Arc did not return a WWW-Authenticate challenge".to_owned(),
                )
            })?;
        drop(challenge);
        let key_file = arc_challenge_file(&header, token_directory)?;
        let secret = read_arc_key(&key_file)?;
        let mut authorization = HeaderValue::from_str(&format!("Basic {secret}"))
            .map_err(|_| TokenError::Failed("Azure Arc key file is not valid".to_owned()))?;
        authorization.set_sensitive(true);
        let response = self
            .send(&self.client, |client| {
                client
                    .get(url.clone())
                    .header("Metadata", "true")
                    .header(AUTHORIZATION, authorization.clone())
            })
            .await?;
        read_token_response(response, SOURCE).await
    }

    fn service_fabric_client(&self, thumbprint: &str) -> Result<reqwest::Client, TokenError> {
        self.service_fabric_client
            .get_or_init(|| tls::service_fabric_client(thumbprint, NETWORK_TIMEOUT))
            .clone()
    }
}

/// `endpoint?query`, rejecting endpoints that are not absolute URIs.
fn request_url(endpoint: &str, query: &[(&str, &str)]) -> Result<reqwest::Url, TokenError> {
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    reqwest::Url::parse(&format!("{endpoint}{separator}{}", form_encode(query)))
        .map_err(|_| TokenError::Failed(format!("the {SOURCE} endpoint is not a valid URI")))
}

/// MSAL `ValidateSplitChallenge` + `IsValidPath`: `Basic realm=<path>` must name
/// `<token_directory><file stem>.key` exactly, so the endpoint cannot point the
/// credential at any other file.
fn arc_challenge_file(
    challenge: &str,
    token_directory: Option<&Path>,
) -> Result<PathBuf, TokenError> {
    let parts: Vec<&str> = challenge
        .split('=')
        .filter(|part| !part.is_empty())
        .collect();
    let [_, path] = parts.as_slice() else {
        return Err(TokenError::Failed(
            "Azure Arc challenge is not valid".to_owned(),
        ));
    };
    let directory = token_directory.ok_or_else(|| {
        TokenError::Failed(
            "Azure Arc managed identity is not supported on this platform".to_owned(),
        )
    })?;
    let path = Path::new(path);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| TokenError::Failed("Azure Arc challenge file is not valid".to_owned()))?;
    if path != directory.join(format!("{stem}.key")) {
        return Err(TokenError::Failed(
            "Azure Arc challenge file is not valid".to_owned(),
        ));
    }
    Ok(path.to_path_buf())
}

/// Reads the challenge key: a regular file of at most 4096 bytes (MSAL limit;
/// symbolic links are refused as well). `File.ReadAllText` drops a UTF-8 BOM.
fn read_arc_key(path: &Path) -> Result<String, TokenError> {
    use std::io::Read as _;
    let invalid = || {
        TokenError::Failed(
            "Azure Arc key file does not exist or is larger than 4096 bytes".to_owned(),
        )
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > ARC_MAX_KEY_FILE_BYTES {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| invalid())?
        .take(ARC_MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 > ARC_MAX_KEY_FILE_BYTES {
        return Err(invalid());
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| TokenError::Failed("Azure Arc key file is not valid".to_owned()))?;
    Ok(text
        .strip_prefix('\u{feff}')
        .map(str::to_owned)
        .unwrap_or(text))
}

impl TokenProvider for ManagedIdentityCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let resource = scope_to_resource(scope);
            let client_id = self.client_id.as_deref();
            match &self.source {
                ManagedIdentitySource::TokenExchange(settings) => {
                    WorkloadIdentityCredential::new(self.client.clone(), settings.clone())
                        .get_token(scope)
                        .await
                }
                ManagedIdentitySource::Imds { endpoint } => {
                    let mut query = vec![("api-version", "2018-02-01"), ("resource", resource)];
                    query.extend(client_id.map(|id| ("client_id", id)));
                    let url = request_url(endpoint, &query)?;
                    self.get(&self.client, &url, &[("Metadata", "true")]).await
                }
                ManagedIdentitySource::AppService { endpoint, header } => {
                    let mut query = vec![("api-version", "2019-08-01"), ("resource", resource)];
                    query.extend(client_id.map(|id| ("client_id", id)));
                    let url = request_url(endpoint, &query)?;
                    self.get(&self.client, &url, &[("X-IDENTITY-HEADER", header)])
                        .await
                }
                ManagedIdentitySource::ServiceFabric {
                    endpoint,
                    header,
                    thumbprint,
                } => {
                    // Azure.Identity: the identity is configured in the cluster, not
                    // selectable at runtime.
                    self.system_assigned_only("Service Fabric")?;
                    let url = request_url(
                        endpoint,
                        &[("api-version", "2020-05-01"), ("resource", resource)],
                    )?;
                    let client = self.service_fabric_client(thumbprint)?;
                    self.get(&client, &url, &[("secret", header)]).await
                }
                ManagedIdentitySource::MachineLearning {
                    endpoint,
                    secret,
                    default_client_id,
                } => {
                    let identity = client_id.or(default_client_id.as_deref()).ok_or_else(|| {
                        TokenError::Failed(
                            "the DEFAULT_IDENTITY_CLIENT_ID environment variable is not set"
                                .to_owned(),
                        )
                    })?;
                    let url = request_url(
                        endpoint,
                        &[
                            ("api-version", "2017-09-01"),
                            ("resource", resource),
                            ("clientid", identity),
                        ],
                    )?;
                    self.get(
                        &self.client,
                        &url,
                        &[("Metadata", "true"), ("secret", secret)],
                    )
                    .await
                }
                ManagedIdentitySource::CloudShell { endpoint } => {
                    self.system_assigned_only("Cloud Shell")?;
                    let url = reqwest::Url::parse(endpoint).map_err(|_| {
                        TokenError::Failed(format!("the {SOURCE} endpoint is not a valid URI"))
                    })?;
                    let body = form_encode(&[("resource", resource)]);
                    let response = self
                        .send(&self.client, |client| {
                            client
                                .post(url.clone())
                                .header(
                                    reqwest::header::CONTENT_TYPE,
                                    "application/x-www-form-urlencoded",
                                )
                                .header("Metadata", "true")
                                .body(body.clone())
                        })
                        .await?;
                    read_token_response(response, SOURCE).await
                }
                ManagedIdentitySource::AzureArc {
                    endpoint,
                    token_directory,
                } => {
                    self.azure_arc(endpoint, token_directory.as_deref(), resource)
                        .await
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn detection_follows_msal_order() {
        let detect =
            |pairs, client_id, arc| ManagedIdentitySource::detect(env(pairs), client_id, arc);
        assert!(matches!(
            detect(
                &[
                    ("IDENTITY_ENDPOINT", "https://localhost:2377/token"),
                    ("IDENTITY_HEADER", "h"),
                    ("IDENTITY_SERVER_THUMBPRINT", "AB"),
                ],
                None,
                false
            ),
            ManagedIdentitySource::ServiceFabric { .. }
        ));
        assert!(matches!(
            detect(
                &[("IDENTITY_ENDPOINT", "http://e"), ("IDENTITY_HEADER", "h")],
                None,
                false
            ),
            ManagedIdentitySource::AppService { .. }
        ));
        assert_eq!(
            detect(
                &[
                    ("MSI_ENDPOINT", "http://ml"),
                    ("MSI_SECRET", "s"),
                    ("DEFAULT_IDENTITY_CLIENT_ID", "d")
                ],
                None,
                false
            ),
            ManagedIdentitySource::MachineLearning {
                endpoint: "http://ml".to_owned(),
                secret: "s".to_owned(),
                default_client_id: Some("d".to_owned()),
            }
        );
        assert_eq!(
            detect(&[("MSI_ENDPOINT", "http://shell")], None, false),
            ManagedIdentitySource::CloudShell {
                endpoint: "http://shell".to_owned()
            }
        );
        assert_eq!(
            detect(
                &[
                    ("IDENTITY_ENDPOINT", "http://arc"),
                    ("IMDS_ENDPOINT", "http://imds")
                ],
                None,
                false
            ),
            ManagedIdentitySource::AzureArc {
                endpoint: "http://arc".to_owned(),
                token_directory: arc_token_directory(),
            }
        );
        assert_eq!(
            detect(&[], None, true),
            ManagedIdentitySource::AzureArc {
                endpoint: ARC_DEFAULT_ENDPOINT.to_owned(),
                token_directory: arc_token_directory(),
            }
        );
        // IDENTITY_ENDPOINT alone is not enough for Azure Arc.
        assert!(matches!(
            detect(&[("IDENTITY_ENDPOINT", "http://arc")], None, false),
            ManagedIdentitySource::Imds { .. }
        ));
        assert_eq!(
            detect(
                &[("AZURE_POD_IDENTITY_AUTHORITY_HOST", "http://pod/")],
                None,
                false
            ),
            ManagedIdentitySource::Imds {
                endpoint: "http://pod/metadata/identity/oauth2/token".to_owned()
            }
        );
    }

    #[test]
    fn token_exchange_wins_except_over_misconfigured_service_fabric() {
        const EXCHANGE: &[(&str, &str)] = &[
            ("IDENTITY_ENDPOINT", "http://e"),
            ("IDENTITY_HEADER", "h"),
            ("AZURE_FEDERATED_TOKEN_FILE", "/token"),
            ("AZURE_TENANT_ID", "t"),
            ("AZURE_CLIENT_ID", "env-client"),
        ];
        match ManagedIdentitySource::detect(env(EXCHANGE), Some("configured"), false) {
            ManagedIdentitySource::TokenExchange(settings) => {
                assert_eq!(settings.client_id, "configured");
                assert_eq!(settings.authority_host, DEFAULT_AUTHORITY_HOST);
            }
            other => panic!("unexpected {other:?}"),
        }
        const FABRIC: &[(&str, &str)] = &[
            ("IDENTITY_ENDPOINT", "https://localhost:2377"),
            ("IDENTITY_HEADER", "h"),
            ("IDENTITY_SERVER_THUMBPRINT", "AB"),
            ("AZURE_FEDERATED_TOKEN_FILE", "/token"),
            ("AZURE_TENANT_ID", "t"),
        ];
        assert!(matches!(
            ManagedIdentitySource::detect(env(FABRIC), Some("user"), false),
            ManagedIdentitySource::ServiceFabric { .. }
        ));
        // System-assigned: no client id anywhere, so no token exchange.
        assert!(matches!(
            ManagedIdentitySource::detect(env(FABRIC), None, false),
            ManagedIdentitySource::ServiceFabric { .. }
        ));
    }

    #[test]
    fn source_debug_hides_secrets() {
        let text = format!(
            "{:?}",
            ManagedIdentitySource::MachineLearning {
                endpoint: "http://ml".to_owned(),
                secret: "very-secret".to_owned(),
                default_client_id: None,
            }
        );
        assert!(!text.contains("very-secret"));
        let text = format!(
            "{:?}",
            ManagedIdentitySource::AppService {
                endpoint: "http://e".to_owned(),
                header: "very-secret".to_owned(),
            }
        );
        assert!(!text.contains("very-secret"));
    }

    #[test]
    fn retry_policy_matches_azure_identity() {
        for status in [404, 408, 410, 429, 500, 503, 504] {
            assert!(is_retriable_status(status), "{status}");
        }
        for status in [400, 401, 403, 502, 501] {
            assert!(!is_retriable_status(status), "{status}");
        }
        let options = ManagedIdentityRetryOptions::default();
        for retry in 1..=5u32 {
            let base = 0.8 * f64::from(1u32 << (retry - 1));
            let delay = options.delay_for(Some(500), None, retry).as_secs_f64();
            assert!(
                delay >= base * 0.8 - 1e-9 && delay <= base * 1.2 + 1e-9,
                "{retry}: {delay}"
            );
            let gone = options.delay_for(Some(410), None, retry).as_secs_f64();
            let gone_base = (3.0 * f64::from(1u32 << (retry - 1))).min(60.0);
            assert!(
                gone >= (gone_base * 0.8).min(60.0) - 1e-9
                    && gone <= gone_base.min(60.0) * 1.2 + 1e-9
            );
            assert!(gone <= 60.0 + 1e-9);
        }
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("120"));
        assert_eq!(
            options.delay_for(Some(429), Some(&headers), 1),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn arc_challenge_paths_are_confined_to_the_token_directory() {
        let directory = Path::new("/var/opt/azcmagent/tokens/");
        assert_eq!(
            arc_challenge_file(
                "Basic realm=/var/opt/azcmagent/tokens/abc.key",
                Some(directory)
            )
            .unwrap(),
            PathBuf::from("/var/opt/azcmagent/tokens/abc.key")
        );
        for challenge in [
            "Basic realm=/etc/shadow",
            "Basic realm=/var/opt/azcmagent/tokens/../../../etc/x.key",
            "Basic realm=/var/opt/azcmagent/tokens/sub/abc.key",
            "Basic realm=/var/opt/azcmagent/tokens/abc.txt",
            "Basic realm=/var/opt/azcmagent/tokens/abc",
            "Basic realm=a=b",
            "Basic realm",
        ] {
            assert!(
                arc_challenge_file(challenge, Some(directory)).is_err(),
                "{challenge}"
            );
        }
        assert!(arc_challenge_file("Basic realm=/var/opt/azcmagent/tokens/abc.key", None).is_err());
    }
}
