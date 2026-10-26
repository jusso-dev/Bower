//! The management channel's HTTP client (C# `ManagementHttp`). Without explicit settings
//! the standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` variables apply (reqwest's
//! system proxy). `BOWER_MANAGEMENT_PROXY` replaces them for this channel, with optional
//! Basic credentials whose password is read from a file. `BOWER_MANAGEMENT_CA_BUNDLE`
//! merges extra roots (for example a TLS-inspection proxy CA) with the platform roots:
//! certificate and host name verification are never disabled. Credentials stay in memory
//! and are never logged.

use std::time::Duration;

use reqwest::{Certificate, Proxy};

use crate::error::HostError;
use crate::settings::CollectorSettings;

/// Management request timeout (C# `HttpClient.Timeout` of 15 s).
pub const TIMEOUT: Duration = Duration::from_secs(15);

const CA_BUNDLE_MESSAGE: &str =
    "BOWER_MANAGEMENT_CA_BUNDLE must name a readable PEM file of CA certificates.";

/// The client shared by the heartbeat, command and managed privacy profile requests.
pub fn client(settings: &CollectorSettings) -> Result<reqwest::Client, HostError> {
    let mut builder = reqwest::Client::builder().timeout(TIMEOUT);
    if let Some(url) = &settings.management_proxy {
        let mut proxy = Proxy::all(url.as_str()).map_err(|_| {
            HostError::new(
                "InvalidOperationException",
                "BOWER_MANAGEMENT_PROXY must be an absolute http:// or https:// URL.",
            )
        })?;
        if let (Some(username), Some(path)) = (
            &settings.management_proxy_username,
            &settings.management_proxy_password_file,
        ) {
            proxy = proxy.basic_auth(username, &read_password(path)?);
        }
        builder = builder.proxy(proxy);
    }
    if let Some(path) = &settings.management_ca_bundle {
        builder = builder.tls_certs_merge(read_ca_bundle(path)?);
    }
    builder.build().map_err(|_| {
        HostError::new(
            "InvalidOperationException",
            "Management HTTP client could not be created.",
        )
    })
}

/// C# `ReadCaBundle`: at least one PEM certificate, else a start-up error.
pub fn read_ca_bundle(path: &std::path::Path) -> Result<Vec<Certificate>, HostError> {
    let invalid = || HostError::new("InvalidOperationException", CA_BUNDLE_MESSAGE);
    let bytes = std::fs::read(path).map_err(|_| invalid())?;
    let certificates = Certificate::from_pem_bundle(&bytes).map_err(|_| invalid())?;
    if certificates.is_empty() {
        return Err(invalid());
    }
    Ok(certificates)
}

/// A trailing newline from `echo` or a secret mount is not part of the password.
fn read_password(path: &std::path::Path) -> Result<String, HostError> {
    std::fs::read_to_string(path)
        .map(|text| text.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|_| {
            HostError::new(
                "InvalidOperationException",
                "BOWER_MANAGEMENT_PROXY_PASSWORD_FILE must name a readable file.",
            )
        })
}
