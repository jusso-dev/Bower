//! Microsoft Entra token acquisition for Azure Monitor (subset of Azure.Identity
//! used by `Bower.Collector.AzureCredentialFactory`).
//!
//! Tokens live only in memory. They are never logged, persisted or included in
//! errors; `AccessToken`'s `Debug` output is redacted.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::{self, Timestamp};
use serde_json::Value;
use tokio::sync::Mutex;

/// Default Microsoft Entra authority (`AzureAuthorityHosts.AzurePublicCloud`).
pub const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com/";
/// IMDS token endpoint used by `ManagedIdentityCredential`.
pub const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Azure.Core `BearerTokenAuthenticationPolicy` refreshes this long before expiry.
pub const TOKEN_REFRESH_OFFSET: Duration = Duration::from_secs(5 * 60);
/// Azure.Identity `AzureCliCredential` process timeout.
const CLI_TIMEOUT: Duration = Duration::from_secs(13);

#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub token: String,
    pub expires_on: Timestamp,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessToken")
            .field("token", &"[redacted]")
            .field("expires_on", &self.expires_on)
            .finish()
    }
}

/// Token failures. Messages carry status codes and error codes only.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The credential source is not configured or not reachable here
    /// (C# `CredentialUnavailableException`).
    #[error("credential unavailable: {0}")]
    Unavailable(String),
    /// The source answered but refused or returned an unusable token
    /// (C# `AuthenticationFailedException`).
    #[error("authentication failed: {0}")]
    Failed(String),
}

pub type TokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AccessToken, TokenError>> + Send + 'a>>;

/// Async token source (C# `TokenCredential`). Object safe.
pub trait TokenProvider: Send + Sync {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a>;
}

/// `BOWER_AZURE_CREDENTIAL` modes (`AzureCredentialMode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AzureCredentialMode {
    ManagedIdentity,
    WorkloadIdentity,
    Environment,
    AzureCli,
}

impl AzureCredentialMode {
    /// Parses the collector setting (`managed-identity` default, `workload-identity`,
    /// `environment`, `azure-cli`).
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value
            .map(|text| text.trim().to_lowercase())
            .as_deref()
            .unwrap_or("")
        {
            "" | "managed-identity" => Some(Self::ManagedIdentity),
            "workload-identity" => Some(Self::WorkloadIdentity),
            "environment" => Some(Self::Environment),
            "azure-cli" => Some(Self::AzureCli),
            _ => None,
        }
    }
}

/// `AzureCredentialFactory.Create`: exactly one configured credential source,
/// wrapped in an in-memory cache. Environment variables are read lazily at token
/// time, as Azure.Identity does.
pub fn credential_from_mode(
    mode: AzureCredentialMode,
    managed_identity_client_id: Option<&str>,
) -> Arc<dyn TokenProvider> {
    let client = default_http_client();
    let inner: Arc<dyn TokenProvider> = match mode {
        AzureCredentialMode::ManagedIdentity => {
            let client_id = managed_identity_client_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            Arc::new(ManagedIdentityCredential::from_env(
                client.clone(),
                client_id,
            ))
        }
        AzureCredentialMode::WorkloadIdentity => {
            Arc::new(WorkloadIdentityCredential::from_env(client))
        }
        AzureCredentialMode::Environment => Arc::new(EnvironmentCredential::new(client)),
        AzureCredentialMode::AzureCli => Arc::new(AzureCliCredential::default()),
    };
    Arc::new(CachedTokenProvider::new(inner))
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(100))
        // Never replay credentials or client secrets to a redirect target.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builds with static configuration")
}

/// Caches one token per scope until [`TOKEN_REFRESH_OFFSET`] before expiry.
/// Acquisition is single-flight per provider.
pub struct CachedTokenProvider {
    inner: Arc<dyn TokenProvider>,
    cache: Mutex<Vec<(String, AccessToken)>>,
}

impl CachedTokenProvider {
    pub fn new(inner: Arc<dyn TokenProvider>) -> Self {
        Self {
            inner,
            cache: Mutex::new(Vec::new()),
        }
    }
}

impl TokenProvider for CachedTokenProvider {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let mut cache = self.cache.lock().await;
            let refresh_at = time::now()
                + chrono::Duration::from_std(TOKEN_REFRESH_OFFSET).expect("offset fits");
            if let Some((_, token)) = cache.iter().find(|(cached, _)| cached == scope)
                && token.expires_on > refresh_at
            {
                return Ok(token.clone());
            }
            let token = match self.inner.get_token(scope).await {
                Ok(token) => token,
                // Like BearerTokenAuthenticationPolicy's background refresh: a failed
                // refresh keeps using the cached token until it actually expires.
                Err(error) => {
                    return cache
                        .iter()
                        .find(|(cached, token)| cached == scope && token.expires_on > time::now())
                        .map(|(_, token)| token.clone())
                        .ok_or(error);
                }
            };
            cache.retain(|(cached, _)| cached != scope);
            cache.push((scope.to_owned(), token.clone()));
            Ok(token)
        })
    }
}

/// `ScopeUtilities.ScopesToResource`: strips the `/.default` suffix.
pub fn scope_to_resource(scope: &str) -> &str {
    scope.strip_suffix("/.default").unwrap_or(scope)
}

/// `application/x-www-form-urlencoded` encoding.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    fn encode(value: &str, output: &mut String) {
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                    output.push(char::from(byte))
                }
                b' ' => output.push('+'),
                other => output.push_str(&format!("%{other:02X}")),
            }
        }
    }
    let mut output = String::new();
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            output.push('&');
        }
        encode(name, &mut output);
        output.push('=');
        encode(value, &mut output);
    }
    output
}

fn now_plus_seconds(seconds: i64) -> Timestamp {
    time::now() + chrono::Duration::seconds(seconds)
}

fn number_or_string(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Parses an OAuth / managed identity token response without echoing it.
fn parse_token_response(body: &[u8]) -> Result<AccessToken, TokenError> {
    let document: Value = serde_json::from_slice(body)
        .map_err(|_| TokenError::Failed("token response is not JSON".to_owned()))?;
    let token = document
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| TokenError::Failed("token response has no access_token".to_owned()))?
        .to_owned();
    let expires_on = if let Some(epoch) = number_or_string(document.get("expires_on")) {
        chrono::DateTime::from_timestamp(epoch, 0)
            .map(|value| value.fixed_offset())
            .ok_or_else(|| TokenError::Failed("token response has invalid expires_on".to_owned()))?
    } else if let Some(seconds) = number_or_string(document.get("expires_in")) {
        now_plus_seconds(seconds)
    } else {
        return Err(TokenError::Failed(
            "token response has no expiry".to_owned(),
        ));
    };
    Ok(AccessToken { token, expires_on })
}

/// Error code from an Entra error body (`error`), never the description.
fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|document| {
            document
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|code| {
            code.len() <= 64 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

async fn send_for_token(
    request: reqwest::RequestBuilder,
    source: &str,
) -> Result<AccessToken, TokenError> {
    let response = request
        .send()
        .await
        .map_err(|_| TokenError::Unavailable(format!("{source} endpoint unreachable")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|_| TokenError::Failed(format!("{source} response could not be read")))?;
    if !status.is_success() {
        return Err(TokenError::Failed(format!(
            "{source} returned HTTP {} ({})",
            status.as_u16(),
            error_code(&body)
        )));
    }
    parse_token_response(&body)
}

/// Where a managed identity token comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagedIdentitySource {
    /// Azure Instance Metadata Service (VMs, VM scale sets, AKS node identity).
    Imds { endpoint: String },
    /// App Service / Functions / Container Apps (`IDENTITY_ENDPOINT` + `IDENTITY_HEADER`).
    AppService { endpoint: String, header: String },
    /// AKS workload identity token exchange (`AZURE_FEDERATED_TOKEN_FILE`), which
    /// Azure.Identity's managed identity credential prefers over IMDS.
    TokenExchange(WorkloadIdentitySettings),
    /// A source this port does not implement (Azure Arc, Service Fabric, Cloud Shell).
    Unsupported(&'static str),
}

/// System- or user-assigned (by client id) managed identity.
pub struct ManagedIdentityCredential {
    client: reqwest::Client,
    client_id: Option<String>,
    source: ManagedIdentitySource,
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
        }
    }

    /// Detects the source like Azure.Identity: Service Fabric / App Service /
    /// Cloud Shell / Azure Arc (only App Service is supported here), then workload
    /// identity token exchange, else IMDS.
    pub fn from_env(client: reqwest::Client, client_id: Option<String>) -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        let source = match (var("IDENTITY_ENDPOINT"), var("IDENTITY_HEADER")) {
            (Some(_), Some(_)) if var("IDENTITY_SERVER_THUMBPRINT").is_some() => {
                ManagedIdentitySource::Unsupported("Service Fabric managed identity")
            }
            (Some(endpoint), Some(header)) => {
                ManagedIdentitySource::AppService { endpoint, header }
            }
            (Some(_), None) if var("IMDS_ENDPOINT").is_some() => {
                ManagedIdentitySource::Unsupported("Azure Arc managed identity")
            }
            _ if var("MSI_ENDPOINT").is_some() => {
                ManagedIdentitySource::Unsupported("Cloud Shell managed identity")
            }
            _ if var("AZURE_FEDERATED_TOKEN_FILE").is_some()
                && var("AZURE_TENANT_ID").is_some()
                && (client_id.is_some() || var("AZURE_CLIENT_ID").is_some()) =>
            {
                ManagedIdentitySource::TokenExchange(WorkloadIdentitySettings {
                    tenant_id: var("AZURE_TENANT_ID").unwrap_or_default(),
                    client_id: client_id
                        .clone()
                        .or_else(|| var("AZURE_CLIENT_ID"))
                        .unwrap_or_default(),
                    token_file: PathBuf::from(
                        var("AZURE_FEDERATED_TOKEN_FILE").unwrap_or_default(),
                    ),
                    authority_host: var("AZURE_AUTHORITY_HOST")
                        .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_owned()),
                })
            }
            _ => {
                let endpoint = var("AZURE_POD_IDENTITY_AUTHORITY_HOST")
                    .map(|host| {
                        format!(
                            "{}/metadata/identity/oauth2/token",
                            host.trim_end_matches('/')
                        )
                    })
                    .unwrap_or_else(|| IMDS_ENDPOINT.to_owned());
                ManagedIdentitySource::Imds { endpoint }
            }
        };
        Self::new(client, client_id, source)
    }
}

impl TokenProvider for ManagedIdentityCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let resource = scope_to_resource(scope);
            let mut query: Vec<(&str, &str)> = Vec::new();
            let request = match &self.source {
                ManagedIdentitySource::Imds { endpoint } => {
                    query.push(("api-version", "2018-02-01"));
                    query.push(("resource", resource));
                    if let Some(client_id) = &self.client_id {
                        query.push(("client_id", client_id));
                    }
                    self.client
                        .get(format!("{endpoint}?{}", form_encode(&query)))
                        .header("Metadata", "true")
                }
                ManagedIdentitySource::AppService { endpoint, header } => {
                    query.push(("api-version", "2019-08-01"));
                    query.push(("resource", resource));
                    if let Some(client_id) = &self.client_id {
                        query.push(("client_id", client_id));
                    }
                    self.client
                        .get(format!("{endpoint}?{}", form_encode(&query)))
                        .header("X-IDENTITY-HEADER", header)
                }
                ManagedIdentitySource::TokenExchange(settings) => {
                    return WorkloadIdentityCredential::new(self.client.clone(), settings.clone())
                        .get_token(scope)
                        .await;
                }
                ManagedIdentitySource::Unsupported(name) => {
                    return Err(TokenError::Unavailable(format!(
                        "{name} is not supported by this collector"
                    )));
                }
            };
            send_for_token(request, "managed identity").await
        })
    }
}

/// Azure.Identity rejects non-HTTPS authority hosts. Plain HTTP is accepted only
/// for loopback hosts (local test doubles), where nothing leaves the machine.
fn is_allowed_authority(authority_host: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(authority_host) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }),
        _ => false,
    }
}

/// OAuth client credentials against `{authority}/{tenant}/oauth2/v2.0/token`.
async fn client_credentials(
    client: &reqwest::Client,
    authority_host: &str,
    tenant_id: &str,
    form: &[(&str, &str)],
) -> Result<AccessToken, TokenError> {
    if !is_allowed_authority(authority_host) {
        return Err(TokenError::Unavailable(
            "the authority host must use HTTPS".to_owned(),
        ));
    }
    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        authority_host.trim_end_matches('/'),
        tenant_id
    );
    let request = client
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_encode(form));
    send_for_token(request, "Microsoft Entra").await
}

/// Workload identity federation (AKS): exchanges the projected service account
/// token for an Entra token. The token file is re-read on every acquisition.
pub struct WorkloadIdentityCredential {
    client: reqwest::Client,
    settings: Option<WorkloadIdentitySettings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadIdentitySettings {
    pub tenant_id: String,
    pub client_id: String,
    pub token_file: PathBuf,
    pub authority_host: String,
}

impl WorkloadIdentityCredential {
    pub fn new(client: reqwest::Client, settings: WorkloadIdentitySettings) -> Self {
        Self {
            client,
            settings: Some(settings),
        }
    }

    /// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`,
    /// `AZURE_AUTHORITY_HOST` (optional).
    pub fn from_env(client: reqwest::Client) -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        let settings = match (
            var("AZURE_TENANT_ID"),
            var("AZURE_CLIENT_ID"),
            var("AZURE_FEDERATED_TOKEN_FILE"),
        ) {
            (Some(tenant_id), Some(client_id), Some(token_file)) => {
                Some(WorkloadIdentitySettings {
                    tenant_id,
                    client_id,
                    token_file: PathBuf::from(token_file),
                    authority_host: var("AZURE_AUTHORITY_HOST")
                        .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_owned()),
                })
            }
            _ => None,
        };
        Self { client, settings }
    }
}

impl TokenProvider for WorkloadIdentityCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let settings = self.settings.as_ref().ok_or_else(|| {
                TokenError::Unavailable(
                    "workload identity needs AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_FEDERATED_TOKEN_FILE".to_owned(),
                )
            })?;
            let assertion = tokio::fs::read_to_string(&settings.token_file)
                .await
                .map_err(|_| {
                    TokenError::Unavailable("federated token file could not be read".to_owned())
                })?;
            client_credentials(
                &self.client,
                &settings.authority_host,
                &settings.tenant_id,
                &[
                    ("client_id", &settings.client_id),
                    ("scope", scope),
                    ("grant_type", "client_credentials"),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", assertion.trim()),
                ],
            )
            .await
        })
    }
}

/// `EnvironmentCredential` with a client secret (`AZURE_TENANT_ID`,
/// `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, optional `AZURE_AUTHORITY_HOST`).
/// Certificate and username/password variants are not supported.
pub struct EnvironmentCredential {
    client: reqwest::Client,
}

impl EnvironmentCredential {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl TokenProvider for EnvironmentCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let var = |name: &str| {
                std::env::var(name)
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            };
            let (Some(tenant_id), Some(client_id)) =
                (var("AZURE_TENANT_ID"), var("AZURE_CLIENT_ID"))
            else {
                return Err(TokenError::Unavailable(
                    "AZURE_TENANT_ID and AZURE_CLIENT_ID are required".to_owned(),
                ));
            };
            let Some(secret) = var("AZURE_CLIENT_SECRET") else {
                return Err(TokenError::Unavailable(
                    "only AZURE_CLIENT_SECRET environment credentials are supported".to_owned(),
                ));
            };
            let authority =
                var("AZURE_AUTHORITY_HOST").unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_owned());
            client_credentials(
                &self.client,
                &authority,
                &tenant_id,
                &[
                    ("client_id", &client_id),
                    ("scope", scope),
                    ("grant_type", "client_credentials"),
                    ("client_secret", &secret),
                ],
            )
            .await
        })
    }
}

/// Developer credential: `az account get-access-token`.
#[derive(Clone, Debug)]
pub struct AzureCliCredential {
    pub program: PathBuf,
}

impl Default for AzureCliCredential {
    fn default() -> Self {
        Self {
            program: PathBuf::from("az"),
        }
    }
}

impl TokenProvider for AzureCliCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let program = self.program.clone();
            let resource = scope_to_resource(scope).to_owned();
            let run = tokio::task::spawn_blocking(move || run_cli(&program, &resource));
            let (status, stdout) = run
                .await
                .map_err(|_| TokenError::Unavailable("Azure CLI could not be started".to_owned()))?
                .map_err(|_| TokenError::Unavailable("Azure CLI not installed".to_owned()))?
                .ok_or_else(|| TokenError::Unavailable("Azure CLI timed out".to_owned()))?;
            if !status.success() {
                return Err(TokenError::Unavailable(
                    "Azure CLI failed; run 'az login'".to_owned(),
                ));
            }
            parse_cli_output(&stdout)
        })
    }
}

/// Runs `az account get-access-token`; kills it after [`CLI_TIMEOUT`] (`None`).
/// stderr is discarded so CLI diagnostics never reach Bower logs.
fn run_cli(
    program: &std::path::Path,
    resource: &str,
) -> std::io::Result<Option<(std::process::ExitStatus, Vec<u8>)>> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args([
            "account",
            "get-access-token",
            "--output",
            "json",
            "--resource",
            resource,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    // Drain stdout concurrently so a large output cannot block the child.
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).map(|_| output)
    });
    let deadline = std::time::Instant::now() + CLI_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = reader
        .join()
        .map_err(|_| std::io::Error::other("Azure CLI output reader failed"))??;
    Ok(status.map(|status| (status, output)))
}

fn parse_cli_output(stdout: &[u8]) -> Result<AccessToken, TokenError> {
    let document: Value = serde_json::from_slice(stdout)
        .map_err(|_| TokenError::Failed("Azure CLI output is not JSON".to_owned()))?;
    let token = document
        .get("accessToken")
        .and_then(Value::as_str)
        .ok_or_else(|| TokenError::Failed("Azure CLI output has no accessToken".to_owned()))?
        .to_owned();
    let expires_on = if let Some(epoch) = number_or_string(document.get("expires_on")) {
        chrono::DateTime::from_timestamp(epoch, 0).map(|value| value.fixed_offset())
    } else {
        // Older CLIs: local time "2026-10-17 15:00:00.000000".
        document
            .get("expiresOn")
            .and_then(Value::as_str)
            .and_then(|text| {
                chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f").ok()
            })
            .and_then(|naive| naive.and_local_timezone(chrono::Local).single())
            .map(|value| value.fixed_offset())
    }
    .ok_or_else(|| TokenError::Failed("Azure CLI output has no expiry".to_owned()))?;
    Ok(AccessToken { token, expires_on })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_and_form_encoding_match_azure_identity() {
        assert_eq!(
            scope_to_resource("https://monitor.azure.com//.default"),
            "https://monitor.azure.com/"
        );
        assert_eq!(form_encode(&[("a b", "x/y+z=")]), "a+b=x%2Fy%2Bz%3D");
    }

    #[test]
    fn token_debug_is_redacted_and_responses_parse() {
        let token = parse_token_response(br#"{"access_token":"secret","expires_on":"1893456000"}"#)
            .unwrap();
        assert!(!format!("{token:?}").contains("secret"));
        assert_eq!(token.expires_on.timestamp(), 1_893_456_000);
        let relative =
            parse_token_response(br#"{"access_token":"secret","expires_in":3599}"#).unwrap();
        assert!(relative.expires_on > time::now());
        assert!(parse_token_response(br#"{"error":"invalid_client"}"#).is_err());
        assert_eq!(
            error_code(br#"{"error":"invalid_client","error_description":"x"}"#),
            "invalid_client"
        );
        let cli = parse_cli_output(br#"{"accessToken":"t","expires_on":1893456000}"#).unwrap();
        assert_eq!(cli.expires_on.timestamp(), 1_893_456_000);
    }

    #[test]
    fn modes_parse_like_collector_settings() {
        assert_eq!(
            AzureCredentialMode::parse(None),
            Some(AzureCredentialMode::ManagedIdentity)
        );
        assert_eq!(
            AzureCredentialMode::parse(Some(" Azure-CLI ")),
            Some(AzureCredentialMode::AzureCli)
        );
        assert_eq!(AzureCredentialMode::parse(Some("other")), None);
    }
}
