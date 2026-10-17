//! Service Fabric managed identity TLS: MSAL's
//! `ServiceFabricManagedIdentitySource.ValidateServerCertificateCallback` accepts
//! the endpoint certificate when normal validation passes or when its SHA-1
//! thumbprint equals `IDENTITY_SERVER_THUMBPRINT` (the cluster's self-signed
//! certificate). Handshake signatures are always verified.

use std::sync::Arc;
use std::time::Duration;

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha1::{Digest as _, Sha1};

use super::TokenError;

#[derive(Debug)]
struct ThumbprintPinnedVerifier {
    /// Upper-case hex SHA-1, as `X509Certificate2.GetCertHashString()`.
    thumbprint: String,
    provider: Arc<CryptoProvider>,
    fallback: Arc<dyn ServerCertVerifier>,
}

/// `X509Certificate2.GetCertHashString()`: upper-case hex SHA-1 of the DER.
pub(super) fn sha1_thumbprint(certificate_der: &[u8]) -> String {
    Sha1::digest(certificate_der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

impl ServerCertVerifier for ThumbprintPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha1_thumbprint(end_entity).eq_ignore_ascii_case(&self.thumbprint) {
            return Ok(ServerCertVerified::assertion());
        }
        self.fallback
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// HTTP client for the Service Fabric endpoint: thumbprint pinning plus the
/// platform verifier, no redirects.
pub(super) fn service_fabric_client(
    thumbprint: &str,
    timeout: Duration,
) -> Result<reqwest::Client, TokenError> {
    let failed =
        || TokenError::Unavailable("Service Fabric TLS could not be configured".to_owned());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let fallback =
        Arc::new(rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|_| failed())?);
    let verifier = ThumbprintPinnedVerifier {
        thumbprint: thumbprint.trim().to_ascii_uppercase(),
        provider: provider.clone(),
        fallback,
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| failed())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| failed())
}
