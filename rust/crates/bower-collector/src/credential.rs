//! `AzureCredentialFactory`: exactly one configured credential source for least
//! privilege (`BOWER_AZURE_CREDENTIAL`), never a probing chain. Tokens are cached in
//! memory only and never logged.

use std::sync::Arc;

use bower_output_azure::{
    AzureCredentialMode as Mode, TokenError, TokenProvider, credential_from_mode,
};

use crate::heartbeat::{AccessTokenSource, TokenFuture};
use crate::settings::{AzureCredentialMode, CollectorSettings};

/// The configured credential, created only when an Azure output or the management
/// heartbeat needs one.
pub fn create(settings: &CollectorSettings) -> Option<Arc<dyn TokenProvider>> {
    // Token enrolment authenticates management with its own key-bound credential.
    let needed = settings.output_type == "azure-logs-ingestion"
        || (settings.management_endpoint.is_some() && !settings.uses_enrolment());
    needed.then(|| from_settings(settings))
}

pub fn from_settings(settings: &CollectorSettings) -> Arc<dyn TokenProvider> {
    let mode = match settings.azure_credential {
        AzureCredentialMode::ManagedIdentity => Mode::ManagedIdentity,
        AzureCredentialMode::WorkloadIdentity => Mode::WorkloadIdentity,
        AzureCredentialMode::Environment => Mode::Environment,
        AzureCredentialMode::AzureCli => Mode::AzureCli,
    };
    // Azure.Identity: a blank client id selects the system-assigned identity.
    credential_from_mode(mode, settings.azure_client_id.as_deref())
}

struct ManagementTokenSource(Arc<dyn TokenProvider>);

impl AccessTokenSource for ManagementTokenSource {
    fn access_token<'a>(&'a self, scope: &'a str) -> TokenFuture<'a> {
        Box::pin(async move {
            match self.0.get_token(scope).await {
                Ok(token) => Ok(token.token),
                Err(TokenError::Unavailable(_)) => Err("CredentialUnavailableException"),
                Err(TokenError::Failed(_) | TokenError::Transport(_)) => {
                    Err("AuthenticationFailedException")
                }
            }
        })
    }
}

/// Bearer tokens for the management heartbeat from the shared credential.
pub fn management_source(provider: Arc<dyn TokenProvider>) -> Arc<dyn AccessTokenSource> {
    Arc::new(ManagementTokenSource(provider))
}
