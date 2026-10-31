//! C# `CollectorStartupSources`: every file a collector start reads besides the policy
//! bundle, loaded and checked the same way by start-up (`host::build`) and by the signed
//! `reload` pre-check (`management_commands::reload_refusal`): source expectations, the
//! syslog configuration and its routes to the loaded packs, the syslog TLS material,
//! producer scopes and ingest tokens, and the relay's pins and certificates. A reload is
//! therefore refused for exactly the files that would stop a restart.
//!
//! Environment variables are read once when the process starts; a changed environment
//! file is not visible to the running process, so apply it with a supervisor restart.

use std::sync::Arc;

use bower_contracts::time::Clock;
use bower_core::source_expectations::{self, SourceExpectations, SourceExpectationsError};
use bower_packs::LoadedPack;
use bower_source_syslog::SyslogSourceConfiguration;

use crate::auth::IngestAuthentication;
use crate::authorization::ProducerAuthorization;
use crate::error::HostError;
use crate::relay::downstreams::RelayDownstreams;
use crate::settings::CollectorSettings;

pub struct StartupSources {
    pub expectations: Option<SourceExpectations>,
    pub syslog: Option<SyslogSourceConfiguration>,
    pub authorization: ProducerAuthorization,
    pub auth: IngestAuthentication,
    pub relay_downstreams: Option<RelayDownstreams>,
}

pub fn load(
    settings: &CollectorSettings,
    packs: &[LoadedPack],
    clock: Arc<dyn Clock>,
) -> Result<StartupSources, HostError> {
    let expectations = settings
        .source_expectations_path
        .as_ref()
        .map(source_expectations::load_file)
        .transpose()
        .map_err(|error| {
            let kind = match &error {
                SourceExpectationsError::FileNotFound => "FileNotFoundException",
                SourceExpectationsError::InvalidData(_) => "InvalidDataException",
                SourceExpectationsError::Io(_) => "IOException",
            };
            HostError::new(kind, error.to_string())
        })?;
    let syslog = settings
        .syslog_config_path
        .as_ref()
        .map(|path| crate::syslog::load(path, packs))
        .transpose()?;
    if let Some(configuration) = &syslog {
        bower_source_syslog::tls::validate(configuration)
            .map_err(|error| HostError::new("InvalidOperationException", error.to_string()))?;
    }
    let relay_downstreams = if settings.is_relay() {
        let downstreams = RelayDownstreams::load(
            settings
                .relay_downstreams_file
                .as_deref()
                .unwrap_or(std::path::Path::new("")),
        )?;
        if let (Some(certificate), Some(key)) =
            (&settings.relay_certificate_file, &settings.relay_key_file)
        {
            crate::relay::certificates::load(
                certificate,
                key,
                "BOWER_RELAY_CERTIFICATE_FILE and BOWER_RELAY_KEY_FILE",
            )?;
        }
        Some(downstreams)
    } else {
        None
    };
    if settings.output_type == "relay" {
        // The client certificate, key and CA bundle the relay output reads at start.
        crate::relay::client::RelayTls::from_settings(settings)?;
    }
    Ok(StartupSources {
        expectations,
        syslog,
        authorization: ProducerAuthorization::new(
            settings.producer_scopes_file.as_deref(),
            settings.single_trust_domain,
        )?,
        auth: IngestAuthentication::with_clock(
            settings.ingest_token.as_deref(),
            settings.ingest_tokens_file.as_deref(),
            clock,
        )?,
        relay_downstreams,
    })
}
