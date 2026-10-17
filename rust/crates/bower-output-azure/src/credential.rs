//! Microsoft Entra token acquisition for Azure Monitor (the Azure.Identity 1.21
//! credentials reached by `Bower.Collector.AzureCredentialFactory` and
//! `Bower.Evidence.VerifierCredential`).
//!
//! Tokens, secrets and key material live only in memory. They are never logged,
//! persisted or included in errors; `Debug` output is redacted.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bower_contracts::time::{self, Timestamp};
use serde_json::Value;
use tokio::sync::Mutex;

mod certificate;
mod managed_identity;
mod tls;

pub use certificate::{ClientCertificate, ClientCertificateCredential};
pub use managed_identity::{
    ARC_DEFAULT_ENDPOINT, ManagedIdentityCredential, ManagedIdentityRetryOptions,
    ManagedIdentitySource,
};

/// Default Microsoft Entra authority (`AzureAuthorityHosts.AzurePublicCloud`).
pub const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com/";
/// IMDS token endpoint used by `ManagedIdentityCredential`.
pub const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Azure.Core `BearerTokenAuthenticationPolicy` refreshes this long before expiry.
pub const TOKEN_REFRESH_OFFSET: Duration = Duration::from_secs(5 * 60);
/// Azure.Identity `AzureCliCredential` process timeout.
const CLI_TIMEOUT: Duration = Duration::from_secs(13);
/// Azure.Core `RetryOptions.NetworkTimeout`.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(100);

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
/// wrapped in an in-memory cache.
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
        .timeout(NETWORK_TIMEOUT)
        // Never replay credentials or client secrets to a redirect target.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builds with static configuration")
}

/// Non-empty environment variable (`EnvironmentVariables.GetNonEmptyStringOrNull`).
fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
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
    let mut output = String::new();
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            output.push('&');
        }
        percent_encode(name, &mut output);
        output.push('=');
        percent_encode(value, &mut output);
    }
    output
}

fn percent_encode(value: &str, output: &mut String) {
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

/// `expires_on` as Unix seconds (number or string) or, from older managed identity
/// endpoints, a date string (`DateTimeOffset.TryParse`).
fn parse_expires_on(value: Option<&Value>) -> Option<Timestamp> {
    if let Some(epoch) = number_or_string(value) {
        return chrono::DateTime::from_timestamp(epoch, 0).map(|value| value.fixed_offset());
    }
    let text = value?.as_str()?.trim();
    chrono::DateTime::parse_from_rfc3339(text)
        .or_else(|_| chrono::DateTime::parse_from_str(text, "%m/%d/%Y %H:%M:%S %:z"))
        .or_else(|_| chrono::DateTime::parse_from_str(text, "%m/%d/%Y %I:%M:%S %p %:z"))
        .ok()
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
    let expires_on = if document.get("expires_on").is_some() {
        parse_expires_on(document.get("expires_on"))
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

/// Maps a token endpoint response: success parses, anything else fails with the
/// status and the Entra error code only.
async fn read_token_response(
    response: reqwest::Response,
    source: &str,
) -> Result<AccessToken, TokenError> {
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

async fn send_for_token(
    request: reqwest::RequestBuilder,
    source: &str,
) -> Result<AccessToken, TokenError> {
    let response = request
        .send()
        .await
        .map_err(|_| TokenError::Unavailable(format!("{source} endpoint unreachable")))?;
    read_token_response(response, source).await
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

/// `{authority}/{tenant}/oauth2/v2.0/token`, also the client assertion audience.
fn token_endpoint(authority_host: &str, tenant_id: &str) -> Result<String, TokenError> {
    if !is_allowed_authority(authority_host) {
        return Err(TokenError::Unavailable(
            "the authority host must use HTTPS".to_owned(),
        ));
    }
    Ok(format!(
        "{}/{}/oauth2/v2.0/token",
        authority_host.trim_end_matches('/'),
        tenant_id
    ))
}

/// OAuth token request against `{authority}/{tenant}/oauth2/v2.0/token`.
async fn client_credentials(
    client: &reqwest::Client,
    authority_host: &str,
    tenant_id: &str,
    form: &[(&str, &str)],
) -> Result<AccessToken, TokenError> {
    let url = token_endpoint(authority_host, tenant_id)?;
    post_token_form(client, url, form).await
}

async fn post_token_form(
    client: &reqwest::Client,
    url: String,
    form: &[(&str, &str)],
) -> Result<AccessToken, TokenError> {
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
        let settings = match (
            env_var("AZURE_TENANT_ID"),
            env_var("AZURE_CLIENT_ID"),
            env_var("AZURE_FEDERATED_TOKEN_FILE"),
        ) {
            (Some(tenant_id), Some(client_id), Some(token_file)) => {
                Some(WorkloadIdentitySettings {
                    tenant_id,
                    client_id,
                    token_file: PathBuf::from(token_file),
                    authority_host: env_var("AZURE_AUTHORITY_HOST")
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

/// Which credential `EnvironmentCredential` builds, in Azure.Identity's order:
/// client secret, then client certificate, then username and password.
#[derive(Clone, PartialEq, Eq)]
enum EnvironmentConfig {
    Secret {
        tenant_id: String,
        client_id: String,
        secret: String,
    },
    Certificate {
        tenant_id: String,
        client_id: String,
        path: PathBuf,
        password: Option<String>,
        send_certificate_chain: bool,
    },
    UsernamePassword {
        tenant_id: String,
        client_id: String,
        username: String,
        password: String,
    },
}

impl fmt::Debug for EnvironmentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Secret { .. } => "EnvironmentConfig::Secret",
            Self::Certificate { .. } => "EnvironmentConfig::Certificate",
            Self::UsernamePassword { .. } => "EnvironmentConfig::UsernamePassword",
        })
    }
}

/// `EnvironmentCredential`'s constructor over an environment lookup.
fn resolve_environment(var: impl Fn(&str) -> Option<String>) -> Option<EnvironmentConfig> {
    let tenant_id = var("AZURE_TENANT_ID")?;
    let client_id = var("AZURE_CLIENT_ID")?;
    if let Some(secret) = var("AZURE_CLIENT_SECRET") {
        return Some(EnvironmentConfig::Secret {
            tenant_id,
            client_id,
            secret,
        });
    }
    if let Some(path) = var("AZURE_CLIENT_CERTIFICATE_PATH") {
        let send_certificate_chain = var("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN")
            .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1");
        return Some(EnvironmentConfig::Certificate {
            tenant_id,
            client_id,
            path: PathBuf::from(path),
            password: var("AZURE_CLIENT_CERTIFICATE_PASSWORD"),
            send_certificate_chain,
        });
    }
    match (var("AZURE_USERNAME"), var("AZURE_PASSWORD")) {
        (Some(username), Some(password)) => Some(EnvironmentConfig::UsernamePassword {
            tenant_id,
            client_id,
            username,
            password,
        }),
        _ => None,
    }
}

/// `EnvironmentCredential`: `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` plus one of
/// `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH` (optional
/// `AZURE_CLIENT_CERTIFICATE_PASSWORD`, `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`) or
/// `AZURE_USERNAME` + `AZURE_PASSWORD`; optional `AZURE_AUTHORITY_HOST`.
///
/// Variables are read at token time. A loaded certificate is kept in memory, as
/// Azure.Identity caches it, until the path or password changes.
pub struct EnvironmentCredential {
    client: reqwest::Client,
    certificate: Mutex<Option<LoadedCertificate>>,
}

/// Certificate path, password and the certificate loaded from them.
type LoadedCertificate = (PathBuf, Option<String>, Arc<ClientCertificate>);

impl EnvironmentCredential {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            certificate: Mutex::new(None),
        }
    }

    async fn certificate(
        &self,
        path: &std::path::Path,
        password: Option<&str>,
    ) -> Result<Arc<ClientCertificate>, TokenError> {
        let mut cached = self.certificate.lock().await;
        if let Some((cached_path, cached_password, certificate)) = cached.as_ref()
            && cached_path == path
            && cached_password.as_deref() == password
        {
            return Ok(certificate.clone());
        }
        let owned_path = path.to_path_buf();
        let owned_password = password.map(str::to_owned);
        let certificate = tokio::task::spawn_blocking(move || {
            ClientCertificate::load(&owned_path, owned_password.as_deref())
        })
        .await
        .map_err(|_| TokenError::Unavailable("could not load certificate file".to_owned()))??;
        let certificate = Arc::new(certificate);
        *cached = Some((
            path.to_path_buf(),
            password.map(str::to_owned),
            certificate.clone(),
        ));
        Ok(certificate)
    }
}

impl TokenProvider for EnvironmentCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let config = resolve_environment(env_var).ok_or_else(|| {
                TokenError::Unavailable("environment variables are not fully configured".to_owned())
            })?;
            let authority = env_var("AZURE_AUTHORITY_HOST")
                .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_owned());
            match config {
                EnvironmentConfig::Secret {
                    tenant_id,
                    client_id,
                    secret,
                } => {
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
                }
                EnvironmentConfig::Certificate {
                    tenant_id,
                    client_id,
                    path,
                    password,
                    send_certificate_chain,
                } => {
                    let certificate = self.certificate(&path, password.as_deref()).await?;
                    ClientCertificateCredential {
                        client: self.client.clone(),
                        tenant_id,
                        client_id,
                        certificate,
                        authority_host: authority,
                        send_certificate_chain,
                    }
                    .get_token(scope)
                    .await
                }
                EnvironmentConfig::UsernamePassword {
                    tenant_id,
                    client_id,
                    username,
                    password,
                } => {
                    UsernamePasswordCredential {
                        client: self.client.clone(),
                        tenant_id,
                        client_id,
                        username,
                        password,
                        authority_host: authority,
                    }
                    .get_token(scope)
                    .await
                }
            }
        })
    }
}

/// `UsernamePasswordCredential` (OAuth resource owner password grant), reached by
/// C# Bower through `EnvironmentCredential` when `AZURE_USERNAME` and
/// `AZURE_PASSWORD` are set. Microsoft deprecates it and it cannot satisfy MFA.
/// Like MSAL it runs user realm discovery first; federated (WS-Trust) accounts
/// are refused rather than implemented.
pub struct UsernamePasswordCredential {
    pub client: reqwest::Client,
    pub tenant_id: String,
    pub client_id: String,
    pub username: String,
    pub password: String,
    pub authority_host: String,
}

impl fmt::Debug for UsernamePasswordCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UsernamePasswordCredential")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("authority_host", &self.authority_host)
            .finish_non_exhaustive()
    }
}

impl UsernamePasswordCredential {
    /// MSAL user realm discovery: `{authority}/common/userrealm/{username}`.
    async fn account_type(&self) -> Result<String, TokenError> {
        let mut url = format!(
            "{}/common/userrealm/",
            self.authority_host.trim_end_matches('/')
        );
        percent_encode(&self.username, &mut url);
        url.push_str("?api-version=1.0");
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| {
                TokenError::Unavailable("Microsoft Entra endpoint unreachable".to_owned())
            })?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|_| TokenError::Failed("user realm response could not be read".to_owned()))?;
        if !status.is_success() {
            return Err(TokenError::Failed(format!(
                "user realm discovery returned HTTP {}",
                status.as_u16()
            )));
        }
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|document| {
                document
                    .get("account_type")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or_else(|| TokenError::Failed("user realm response is not valid".to_owned()))
    }
}

impl TokenProvider for UsernamePasswordCredential {
    fn get_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            let url = token_endpoint(&self.authority_host, &self.tenant_id)?;
            let account_type = self.account_type().await?;
            if account_type.eq_ignore_ascii_case("federated") {
                return Err(TokenError::Failed(
                    "federated accounts need WS-Trust, which this collector does not support"
                        .to_owned(),
                ));
            }
            if !account_type.eq_ignore_ascii_case("managed") {
                return Err(TokenError::Failed(
                    "unsupported user account type".to_owned(),
                ));
            }
            // MSAL adds the OIDC reserved scopes to user flows (ordered set).
            let scopes: BTreeSet<&str> = [scope, "openid", "profile", "offline_access"]
                .into_iter()
                .collect();
            let scopes = scopes.into_iter().collect::<Vec<_>>().join(" ");
            post_token_form(
                &self.client,
                url,
                &[
                    ("client_id", &self.client_id),
                    ("grant_type", "password"),
                    ("username", &self.username),
                    ("password", &self.password),
                    ("scope", &scopes),
                    ("client_info", "1"),
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
        let dated = parse_token_response(
            br#"{"access_token":"secret","expires_on":"01/01/2030 00:00:00 +00:00"}"#,
        )
        .unwrap();
        assert_eq!(dated.expires_on.timestamp(), 1_893_456_000);
        assert!(parse_token_response(br#"{"access_token":"t","expires_on":"soon"}"#).is_err());
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

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn environment_credential_prefers_secret_then_certificate_then_password() {
        let all: &'static [(&str, &str)] = &[
            ("AZURE_TENANT_ID", "t"),
            ("AZURE_CLIENT_ID", "c"),
            ("AZURE_CLIENT_SECRET", "s"),
            ("AZURE_CLIENT_CERTIFICATE_PATH", "/cert.pem"),
            ("AZURE_USERNAME", "u"),
            ("AZURE_PASSWORD", "p"),
        ];
        assert!(matches!(
            resolve_environment(lookup(all)),
            Some(EnvironmentConfig::Secret { .. })
        ));
        let certificate: &'static [(&str, &str)] = &[
            ("AZURE_TENANT_ID", "t"),
            ("AZURE_CLIENT_ID", "c"),
            ("AZURE_CLIENT_CERTIFICATE_PATH", "/cert.pfx"),
            ("AZURE_CLIENT_CERTIFICATE_PASSWORD", "pw"),
            ("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", "TRUE"),
            ("AZURE_USERNAME", "u"),
            ("AZURE_PASSWORD", "p"),
        ];
        assert_eq!(
            resolve_environment(lookup(certificate)),
            Some(EnvironmentConfig::Certificate {
                tenant_id: "t".to_owned(),
                client_id: "c".to_owned(),
                path: PathBuf::from("/cert.pfx"),
                password: Some("pw".to_owned()),
                send_certificate_chain: true,
            })
        );
        let password: &'static [(&str, &str)] = &[
            ("AZURE_TENANT_ID", "t"),
            ("AZURE_CLIENT_ID", "c"),
            ("AZURE_USERNAME", "u"),
            ("AZURE_PASSWORD", "p"),
        ];
        assert!(matches!(
            resolve_environment(lookup(password)),
            Some(EnvironmentConfig::UsernamePassword { .. })
        ));
        // Username without password, or no tenant: unavailable.
        let partial: &'static [(&str, &str)] = &[
            ("AZURE_TENANT_ID", "t"),
            ("AZURE_CLIENT_ID", "c"),
            ("AZURE_USERNAME", "u"),
        ];
        assert_eq!(resolve_environment(lookup(partial)), None);
        let no_tenant: &'static [(&str, &str)] = &[("AZURE_CLIENT_SECRET", "s")];
        assert_eq!(resolve_environment(lookup(no_tenant)), None);
        // Debug never prints secrets.
        let debug = format!("{:?}", resolve_environment(lookup(all)).unwrap());
        assert_eq!(debug, "EnvironmentConfig::Secret");
    }
}
