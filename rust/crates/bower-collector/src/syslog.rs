//! Collector side of the syslog source (C# `SyslogIntake`). A record becomes an event
//! only through a signed pack parser whose filter selects it, then redaction, policy and
//! the durable queue, like `/v1/packs/.../events`. `Queued` means durably enqueued: the
//! TCP acknowledgement point.

use std::sync::Arc;

use bower_contracts::time::Clock;
use bower_contracts::{DecisionAction, StoreError, json};
use bower_core::{
    CollectorIdentity, PipelineTelemetry, ProcessError, ProcessingResult, ProcessingStage,
    SecurityEventProcessor,
};
use bower_packs::LoadedPack;
use bower_packs::runtime::{MappingError, map_raw};
use bower_pipeline::custom_log::CustomLogParserConfiguration;
use bower_source_syslog::config::ConfigError;
use bower_source_syslog::{
    ListenerOptions, Route, SinkFailure, SubmitOutcome, SyslogSink, SyslogSourceConfiguration,
};

use crate::error::HostError;
use crate::managed_privacy::ManagedPrivacyState;

pub struct CollectorSyslogSink {
    pub processor: SecurityEventProcessor,
    pub identity: CollectorIdentity,
    pub packs: Arc<Vec<LoadedPack>>,
    pub managed_privacy: Arc<ManagedPrivacyState>,
    /// Evaluation time for pack transforms (C# `TimeProvider`).
    pub clock: Arc<dyn Clock>,
    pub telemetry: Arc<PipelineTelemetry>,
    /// Transform quarantines are shown to the tap as metadata only.
    pub tap: Option<Arc<crate::tap::EventTap>>,
}

impl SyslogSink for CollectorSyslogSink {
    fn submit(
        &self,
        listener: &ListenerOptions,
        route: &Route,
        record: &str,
    ) -> Result<SubmitOutcome, SinkFailure> {
        if !self.managed_privacy.accepts_events() {
            return Ok(SubmitOutcome::Unavailable);
        }
        let Some(parser) = parser(&self.packs, route) else {
            return Ok(SubmitOutcome::Invalid);
        };
        let now = self.clock.utc_now();
        let envelope = match map_raw(parser, record, &now) {
            Ok(envelope) => envelope,
            Err(MappingError::NoMatch) => return Ok(SubmitOutcome::NotSelected),
            Err(MappingError::TooLarge) => return Ok(SubmitOutcome::TooLarge),
            Err(MappingError::Transform(code)) => {
                // Quarantine without persisting, as /v1/packs/.../events does: the record
                // never reaches redaction, policy or the queue; only the code is counted.
                let result = ProcessingResult::failed_at(
                    DecisionAction::Quarantine,
                    code,
                    ProcessingStage::Transform,
                );
                self.telemetry
                    .record(&result, i64::try_from(record.len()).unwrap_or(i64::MAX));
                if let Some(tap) = &self.tap {
                    bower_core::TapSink::publish(tap.as_ref(), &result, None, None);
                }
                return Ok(SubmitOutcome::Rejected);
            }
            Err(MappingError::Invalid | MappingError::Inactive) => {
                return Ok(SubmitOutcome::Invalid);
            }
        };
        let candidate = json::to_string(&envelope).map_err(|_| SinkFailure)?;
        let identity = CollectorIdentity {
            source_adapter: format!("syslog:{}:{}:{}", listener.id, route.pack, route.parser),
            ..self.identity.clone()
        };
        match self.processor.process(&candidate, &identity) {
            Ok(result) => Ok(
                if !matches!(
                    result.action,
                    DecisionAction::Accept | DecisionAction::RedactAndAccept
                ) {
                    SubmitOutcome::Rejected
                } else if result.suppressed {
                    SubmitOutcome::Suppressed
                } else if result.duplicate {
                    SubmitOutcome::Duplicate
                } else {
                    SubmitOutcome::Queued
                },
            ),
            Err(ProcessError::Store(StoreError::Full(_))) => Ok(SubmitOutcome::Unavailable),
            Err(_) => Err(SinkFailure),
        }
    }
}

fn parser<'a>(packs: &'a [LoadedPack], route: &Route) -> Option<&'a CustomLogParserConfiguration> {
    let pack = packs.iter().find(|pack| {
        pack.manifest
            .as_ref()
            .is_some_and(|manifest| manifest.id == route.pack)
    })?;
    usize::try_from(route.parser)
        .ok()
        .and_then(|index| pack.parsers.get(index))
        .filter(|parser| parser.runtime.is_some())
}

/// Loads BOWER_SYSLOG_CONFIG and checks every route names an active parser of a loaded
/// signed pack (C# `SyslogRoutes.Validate`), so a bad file stops start-up.
pub fn load(
    path: &std::path::Path,
    packs: &[LoadedPack],
) -> Result<SyslogSourceConfiguration, HostError> {
    let configuration = bower_source_syslog::config::load_file(path).map_err(|error| {
        let kind = match &error {
            ConfigError::FileNotFound => "FileNotFoundException",
            ConfigError::InvalidData(_) => "InvalidDataException",
            ConfigError::Io(_) => "IOException",
        };
        HostError::new(kind, error.to_string())
    })?;
    for listener in &configuration.listeners {
        for route in listener.routes.iter().flatten() {
            if parser(packs, route).is_none() {
                return Err(HostError::new(
                    "InvalidOperationException",
                    format!(
                        "Syslog listener {}: route pack {} parser {} is not an active parser of a loaded pack.",
                        listener.id, route.pack, route.parser
                    ),
                ));
            }
        }
    }
    Ok(configuration)
}
