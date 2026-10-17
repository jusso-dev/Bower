//! Read-only Azure Resource Manager access for `doctor` and `dcr diff`
//! (C# `new ArmReader(new HttpClient(), VerifierCredential.Create(...))`).

use std::time::Duration;

use bower_evidence::{ArmReader, EvidenceError, HttpArmReader, verifier_credential};
use serde_json::Value;

use crate::support::{CliError, CliResult};

/// `HttpClient` default timeout (the C# commands construct a bare `HttpClient`).
const HTTP_TIMEOUT: Duration = Duration::from_secs(100);

/// Maps evidence-crate failures to the CLI's one-line error.
pub fn evidence_error(error: EvidenceError) -> CliError {
    CliError::from_display(error)
}

/// An ARM reader bound to one verifier credential.
pub struct ArmSession {
    reader: HttpArmReader,
}

impl ArmSession {
    /// `VerifierCredential.Create(mode, clientId)`; fails on an unknown mode.
    pub fn new(mode: Option<&str>, client_id: Option<&str>) -> CliResult<Self> {
        let credential = verifier_credential(mode, client_id).map_err(evidence_error)?;
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(CliError::from_display)?;
        Ok(Self {
            reader: HttpArmReader::new(http, credential),
        })
    }

    /// GETs an ARM resource; `None` when it does not exist or is not readable.
    pub fn get(&self, resource_id: &str, api_version: &str) -> CliResult<Option<Value>> {
        super::block_on(async {
            self.reader
                .get(resource_id, api_version)
                .await
                .map(|resource| resource.map(Value::Object))
                .map_err(evidence_error)
        })
    }
}
