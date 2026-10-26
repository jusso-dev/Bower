//! Expected sources and their silence state (C# `SourceHealth`). Empty when no
//! expectations are configured.

use std::sync::{Arc, Mutex, PoisonError};

use bower_contracts::time::Clock;
use bower_contracts::{DurableEventStore, SourceMonitoring, StoreResult};
use bower_core::PipelineTelemetry;
use bower_core::source_expectations::{self, SourceExpectations, SourceSilenceStatus};

pub struct SourceHealth {
    expectations: Option<SourceExpectations>,
    telemetry: Arc<PipelineTelemetry>,
    clock: Arc<dyn Clock>,
    monitoring: Mutex<Vec<SourceMonitoring>>,
}

impl SourceHealth {
    pub fn new(
        expectations: Option<SourceExpectations>,
        telemetry: Arc<PipelineTelemetry>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            expectations,
            telemetry,
            clock,
            monitoring: Mutex::new(Vec::new()),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.expectations.is_some()
    }

    /// Loads each expected source's durable monitoring start, recording now for sources
    /// expected for the first time and forgetting sources no longer expected. A restart
    /// keeps the original start, so it cannot extend a never-seen source's deadline.
    pub fn initialize(&self, store: &dyn DurableEventStore) -> StoreResult<()> {
        let now = self.clock.utc_now();
        let expected: Vec<SourceMonitoring> = self
            .expectations
            .iter()
            .flat_map(|expectations| &expectations.sources)
            .map(|item| SourceMonitoring {
                application: item.application.clone(),
                environment: item.environment.clone(),
                monitoring_since: now,
            })
            .collect();
        let monitoring = store.start_source_monitoring(&expected)?;
        *self
            .monitoring
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = monitoring;
        Ok(())
    }

    pub fn evaluate(&self) -> Vec<SourceSilenceStatus> {
        match &self.expectations {
            None => Vec::new(),
            Some(expectations) => source_expectations::evaluate(
                expectations,
                &self.telemetry.sources(),
                &self
                    .monitoring
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
                self.telemetry.started_at(),
                self.clock.utc_now(),
            ),
        }
    }
}
