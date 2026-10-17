//! Policy loading shared by `validate` and `doctor`, plus the C# exception classes
//! `doctor` reports as checks rather than aborting on.

use bower_policy::PolicyError;

use crate::output::Json;
use crate::support::{CliError, CliResult};

/// Policy metadata printed by `validate` and checked for duplicates by `doctor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySummary {
    pub id: String,
    pub version: String,
    pub hash: String,
}

/// `Reported`: an exception class `doctor` turns into a FAIL check
/// (`InvalidDataException`, `IOException` and its subclasses).
/// `Fatal`: anything else, which aborts the command with exit code 1.
#[derive(Debug)]
pub enum ContentError {
    Reported(String),
    Fatal(CliError),
}

impl From<ContentError> for CliError {
    fn from(error: ContentError) -> Self {
        match error {
            ContentError::Reported(message) => CliError(message),
            ContentError::Fatal(error) => error,
        }
    }
}

/// `PolicyLoader.LoadDirectory`.
pub fn load_policy_directory(directory: &str) -> Result<Vec<PolicySummary>, ContentError> {
    match bower_policy::load_directory(directory) {
        Ok(policies) => Ok(policies
            .into_iter()
            .map(|loaded| PolicySummary {
                id: loaded.policy.metadata.id,
                version: loaded.policy.metadata.version,
                hash: loaded.hash,
            })
            .collect()),
        // ArgumentException: not caught by doctor.
        Err(error @ PolicyError::BlankDirectory) => {
            Err(ContentError::Fatal(CliError::from_display(error)))
        }
        Err(error) => Err(ContentError::Reported(error.to_string())),
    }
}

/// `bower validate [--policy-directory PATH]` (default `./policies/default`).
pub fn validate(policy_directory: Option<&str>) -> CliResult {
    let directory = policy_directory.map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_default()
                .join("policies")
                .join("default")
                .to_string_lossy()
                .into_owned()
        },
        str::to_owned,
    );
    let policies = load_policy_directory(&directory)?;
    println!("{}", validate_json(&policies).to_indented());
    Ok(0)
}

pub fn validate_json(policies: &[PolicySummary]) -> Json {
    Json::object([
        ("valid", Json::Bool(true)),
        (
            "policyCount",
            Json::Int(i64::try_from(policies.len()).unwrap_or(i64::MAX)),
        ),
        (
            "policies",
            Json::Array(
                policies
                    .iter()
                    .map(|policy| {
                        Json::object([
                            ("Id", Json::str(policy.id.clone())),
                            ("Version", Json::str(policy.version.clone())),
                            ("Hash", Json::str(policy.hash.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}
