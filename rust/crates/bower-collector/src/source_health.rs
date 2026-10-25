//! Expected sources and their silence state (C# `SourceHealth`). Empty when no
//! expectations are configured.

use std::sync::Arc;

use bower_contracts::time::Clock;
use bower_core::PipelineTelemetry;
use bower_core::source_expectations::{self, SourceExpectations, SourceSilenceStatus};

pub struct SourceHealth {
    expectations: Option<SourceExpectations>,
    telemetry: Arc<PipelineTelemetry>,
    clock: Arc<dyn Clock>,
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
        }
    }

    pub fn is_configured(&self) -> bool {
        self.expectations.is_some()
    }

    pub fn evaluate(&self) -> Vec<SourceSilenceStatus> {
        match &self.expectations {
            None => Vec::new(),
            Some(expectations) => source_expectations::evaluate(
                expectations,
                &self.telemetry.sources(),
                self.telemetry.started_at(),
                self.clock.utc_now(),
            ),
        }
    }
}
