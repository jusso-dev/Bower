//! Read-only Azure Resource Manager access for `doctor` and `dcr diff`
//! (C# `AzureResources`): each resource type is read with its provider's pinned
//! api-version.

use std::time::Duration;

use bower_dcr::{DATA_COLLECTION_RULES_API_VERSION, LOG_ANALYTICS_API_VERSION};
use bower_evidence::{ArmReader, EvidenceError, HttpArmReader, verifier_credential};
use serde_json::Value;

use crate::support::{CliError, CliResult};

/// Per-request timeout for ARM reads (C# `AzureResources.HttpTimeout`, the same as
/// `evidence run`).
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maps evidence-crate failures to the CLI's one-line error.
pub fn evidence_error(error: EvidenceError) -> CliError {
    CliError::from_display(error)
}

/// An ARM reader bound to one verifier credential.
pub struct ArmSession {
    reader: Box<dyn ArmReader>,
}

impl ArmSession {
    /// `VerifierCredential.Create(mode, clientId)`; fails on an unknown mode.
    pub fn new(mode: Option<&str>, client_id: Option<&str>) -> CliResult<Self> {
        let credential = verifier_credential(mode, client_id).map_err(evidence_error)?;
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(CliError::from_display)?;
        Ok(Self::with_reader(Box::new(HttpArmReader::new(
            http, credential,
        ))))
    }

    pub fn with_reader(reader: Box<dyn ArmReader>) -> Self {
        Self { reader }
    }

    /// A `Microsoft.Insights/dataCollectionRules` resource.
    pub fn get_rule(&self, rule_id: &str) -> CliResult<Option<Value>> {
        self.get(rule_id, DATA_COLLECTION_RULES_API_VERSION)
    }

    /// A `Microsoft.OperationalInsights/workspaces` resource.
    pub fn get_workspace(&self, workspace_id: &str) -> CliResult<Option<Value>> {
        self.get(workspace_id, LOG_ANALYTICS_API_VERSION)
    }

    /// A `Microsoft.OperationalInsights/workspaces/tables` resource.
    pub fn get_table(&self, workspace_id: &str, table: &str) -> CliResult<Option<Value>> {
        self.get(
            &format!("{workspace_id}/tables/{table}"),
            LOG_ANALYTICS_API_VERSION,
        )
    }

    /// GETs an ARM resource; `None` when it does not exist or is not readable.
    fn get(&self, resource_id: &str, api_version: &str) -> CliResult<Option<Value>> {
        super::block_on(async {
            self.reader
                .get(resource_id, api_version)
                .await
                .map(|resource| resource.map(Value::Object))
                .map_err(evidence_error)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bower_evidence::BoxFuture;
    use serde_json::Map;

    use super::*;

    #[derive(Default)]
    struct RecordingArm(Arc<Mutex<Vec<(String, String)>>>);

    impl ArmReader for RecordingArm {
        fn get<'a>(
            &'a self,
            resource_id: &'a str,
            api_version: &'a str,
        ) -> BoxFuture<'a, Result<Option<Map<String, Value>>, EvidenceError>> {
            self.0
                .lock()
                .unwrap()
                .push((resource_id.to_owned(), api_version.to_owned()));
            Box::pin(async { Ok(None) })
        }
    }

    #[test]
    fn each_resource_type_uses_its_providers_api_version() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let arm = ArmSession::with_reader(Box::new(RecordingArm(Arc::clone(&calls))));
        let rule =
            "/subscriptions/s/resourceGroups/g/providers/Microsoft.Insights/dataCollectionRules/r";
        let workspace = "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/w";
        arm.get_rule(rule).unwrap();
        arm.get_workspace(workspace).unwrap();
        arm.get_table(workspace, "BowerSecurity_CL").unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                (rule.to_owned(), "2024-03-11".to_owned()),
                (workspace.to_owned(), "2025-07-01".to_owned()),
                (
                    format!("{workspace}/tables/BowerSecurity_CL"),
                    "2025-07-01".to_owned()
                ),
            ]
        );
    }
}
