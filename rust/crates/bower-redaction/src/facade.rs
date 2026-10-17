//! Backward-compatible facade (`SensitiveDataDetector`). Prefer [`PrivacyEngine`].

use std::fmt;

use bower_contracts::RedactionResult;

use crate::engine::{AppliedFinding, PrivacyEngine};
use crate::error::PrivacyError;
use crate::ids::detector_ids as ids;
use crate::policy::{PrivacyAction, PrivacyPolicy};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SensitiveFindingKind {
    AwsAccessKey,
    AwsSecretKey,
    PrivateKeyBlock,
    Jwt,
    CreditCard,
    Email,
    IpAddress,
    BearerToken,
    ConnectionString,
    GenericSecret,
}

impl fmt::Display for SensitiveFindingKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensitiveFinding {
    pub kind: SensitiveFindingKind,
    pub path: String,
    pub preview: String,
    pub action: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensitiveScanResult {
    pub succeeded: bool,
    pub redacted_json: Option<String>,
    pub findings: Vec<SensitiveFinding>,
    pub failure_code: Option<String>,
}

#[derive(Debug)]
pub struct SensitiveDataDetector {
    engine: PrivacyEngine,
}

impl SensitiveDataDetector {
    pub const MAXIMUM_PAYLOAD_BYTES: usize = crate::engine::MAXIMUM_PAYLOAD_BYTES;

    pub fn new() -> Self {
        Self {
            engine: PrivacyEngine::with_default_policy(),
        }
    }

    pub fn with_policy(policy: PrivacyPolicy) -> Result<Self, PrivacyError> {
        Ok(Self {
            engine: PrivacyEngine::new(policy)?,
        })
    }

    pub fn scan_and_redact(&self, json: &str) -> SensitiveScanResult {
        let result = self.engine.redact_json(json);
        if !result.succeeded {
            return SensitiveScanResult {
                succeeded: false,
                redacted_json: None,
                findings: Vec::new(),
                failure_code: result.failure_code,
            };
        }

        SensitiveScanResult {
            succeeded: true,
            redacted_json: result.redacted_json,
            findings: result.findings.iter().map(map_finding).collect(),
            failure_code: None,
        }
    }

    pub fn to_redaction_result(&self, json: &str) -> RedactionResult {
        self.engine.redact_json(json).to_redaction_result()
    }
}

impl Default for SensitiveDataDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn map_finding(finding: &AppliedFinding) -> SensitiveFinding {
    let kind = match finding.detector_id.as_str() {
        ids::AWS => SensitiveFindingKind::AwsAccessKey,
        ids::JWT | ids::ENTRA => SensitiveFindingKind::Jwt,
        ids::CRYPTO_MATERIAL => SensitiveFindingKind::PrivateKeyBlock,
        ids::CREDIT_CARD => SensitiveFindingKind::CreditCard,
        ids::EMAIL => SensitiveFindingKind::Email,
        ids::IP_ADDRESS => SensitiveFindingKind::IpAddress,
        ids::DATABASE => SensitiveFindingKind::ConnectionString,
        _ => SensitiveFindingKind::GenericSecret,
    };
    let action = match finding.action {
        PrivacyAction::Remove => "removed",
        PrivacyAction::Allow | PrivacyAction::AlertOnly => "alert",
        _ => "masked",
    };
    SensitiveFinding {
        kind,
        path: finding.path.clone(),
        preview: "***".to_owned(),
        action: action.to_owned(),
    }
}
