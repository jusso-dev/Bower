//! Global and per-detector privacy policy (`PrivacyPolicy`, `PrivacyAction`,
//! `PrivacyFieldRule`). Deterministic; no executable configuration.

use std::collections::HashSet;
use std::fmt;

use indexmap::IndexMap;

use crate::ids::detector_ids as ids;

/// Deterministic action applied to a detected sensitive span. Original values are
/// never written into privacy metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyAction {
    Allow,
    Remove,
    Replace,
    Mask,
    Sha256,
    Hmac,
    Encrypt,
    AlertOnly,
    /// Shorten the value to a configured maximum length.
    Truncate,
}

impl PrivacyAction {
    /// Every action in C# enum declaration order.
    pub const ALL: [PrivacyAction; 9] = [
        Self::Allow,
        Self::Remove,
        Self::Replace,
        Self::Mask,
        Self::Sha256,
        Self::Hmac,
        Self::Encrypt,
        Self::AlertOnly,
        Self::Truncate,
    ];

    /// C# enum member name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Remove => "Remove",
            Self::Replace => "Replace",
            Self::Mask => "Mask",
            Self::Sha256 => "Sha256",
            Self::Hmac => "Hmac",
            Self::Encrypt => "Encrypt",
            Self::AlertOnly => "AlertOnly",
            Self::Truncate => "Truncate",
        }
    }

    /// Metadata label (`PolicyApplicator.ActionLabel`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Remove => "Removed",
            Self::Replace => "Replaced",
            Self::Mask => "Masked",
            Self::Sha256 => "SHA256",
            Self::Hmac => "HMAC",
            Self::Encrypt => "Encrypted",
            Self::AlertOnly => "AlertOnly",
            Self::Truncate => "Truncated",
        }
    }

    /// Allow and AlertOnly leave content unchanged.
    pub fn keeps_content(self) -> bool {
        matches!(self, Self::Allow | Self::AlertOnly)
    }
}

impl fmt::Display for PrivacyAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Deterministic action on a JSON path. Paths are dot-separated names from the
/// envelope root (for example `actor.username`); `*` matches one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyFieldRule {
    pub path: String,
    pub action: PrivacyAction,
    pub max_length: Option<usize>,
    segments: Vec<String>,
}

impl PrivacyFieldRule {
    pub fn new(path: impl Into<String>, action: PrivacyAction, max_length: Option<usize>) -> Self {
        let path = path.into();
        let segments = path
            .split('.')
            .filter(|segment| !segment.is_empty())
            .map(str::to_owned)
            .collect();
        Self {
            path,
            action,
            max_length,
            segments,
        }
    }

    /// Non-empty path segments (`Split('.', RemoveEmptyEntries)`).
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

/// Global and per-detector privacy policy.
///
/// `Default` matches C# `new PrivacyPolicy()` (mask everything, no overrides);
/// [`PrivacyPolicy::create_default`] gives the enterprise defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyPolicy {
    pub default_action: PrivacyAction,
    /// Replacement text used when the action is Replace.
    pub replacement_text: String,
    /// Per-detector action overrides keyed by detector id (insertion ordered).
    pub detector_actions: IndexMap<String, PrivacyAction>,
    /// Disabled detector ids (case-sensitive stable ids).
    pub disabled_detectors: HashSet<String>,
    /// Optional detectors that are off unless explicitly enabled.
    pub opt_in_detectors: HashSet<String>,
    /// Explicitly enabled opt-in detectors.
    pub enabled_opt_in_detectors: HashSet<String>,
    /// HMAC key for the Hmac action (at least 32 bytes). Required when any action
    /// resolves to Hmac; the engine refuses to start without it.
    pub hmac_key: Option<Vec<u8>>,
    /// Identifier embedded in HMAC output (`hmac-sha256:<keyId>:<hex>`).
    pub hmac_key_id: String,
    /// Field-level rules applied after detectors.
    pub field_rules: Vec<PrivacyFieldRule>,
    /// Any string longer than this (UTF-16 units) is truncated after redaction.
    pub maximum_field_length: usize,
    /// AES-256 key for the Encrypt action (exactly 32 bytes). Otherwise Encrypt
    /// removes the value.
    pub encryption_key: Option<Vec<u8>>,
    /// Inject the privacy metadata object into the JSON root.
    pub emit_metadata: bool,
    /// High-risk findings should surface as a separate `sensitive_data_detected`
    /// event. The processor owns enqueue; this flag documents intent.
    pub emit_security_event_on_findings: bool,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self {
            default_action: PrivacyAction::Mask,
            replacement_text: "***REDACTED***".to_owned(),
            detector_actions: IndexMap::new(),
            disabled_detectors: HashSet::new(),
            opt_in_detectors: [
                ids::IP_ADDRESS,
                ids::HOSTNAME,
                ids::USERNAME,
                ids::ADDRESS,
                ids::GPS,
                ids::SECURITY_MARKING,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            enabled_opt_in_detectors: HashSet::new(),
            hmac_key: None,
            hmac_key_id: "k1".to_owned(),
            field_rules: Vec::new(),
            maximum_field_length: 32_768,
            encryption_key: None,
            emit_metadata: true,
            emit_security_event_on_findings: true,
        }
    }
}

impl PrivacyPolicy {
    /// Enterprise-safe defaults for production telemetry gateways.
    pub fn create_default() -> Self {
        use PrivacyAction::{AlertOnly, Allow, Mask, Remove};
        let actions = [
            (ids::FIELD_NAME_SECRET, Remove),
            // TFNs have ~10^8 valid values, so an unkeyed hash is reversible by enumeration.
            (ids::TFN, Mask),
            (ids::CRN, Mask),
            (ids::MEDICARE, Mask),
            (ids::IHI, Mask),
            (ids::PASSPORT, Mask),
            (ids::DRIVER_LICENCE, Mask),
            (ids::ABN, Allow),
            (ids::ACN, Allow),
            (ids::DVA, Mask),
            (ids::CREDIT_CARD, Remove),
            (ids::BSB_ACCOUNT, Mask),
            (ids::IBAN, Mask),
            (ids::SWIFT_BIC, Allow),
            (ids::PAY_ID, Mask),
            (ids::EMAIL, Mask),
            (ids::PHONE_AU, Mask),
            (ids::PHONE_INTERNATIONAL, Mask),
            (ids::DATE_OF_BIRTH, Mask),
            (ids::AWS, Remove),
            (ids::AZURE, Remove),
            (ids::ENTRA, Remove),
            (ids::GCP, Remove),
            (ids::JWT, Remove),
            (ids::OAUTH, Remove),
            (ids::API_KEY, Remove),
            (ids::KUBERNETES, Remove),
            (ids::DOCKER, Remove),
            (ids::DATABASE, Remove),
            (ids::ENV_VAR, Remove),
            (ids::CRYPTO_MATERIAL, Remove),
            (ids::SECURITY_MARKING, AlertOnly),
        ];
        Self {
            default_action: Mask,
            detector_actions: actions
                .into_iter()
                .map(|(id, action)| (id.to_owned(), action))
                .collect(),
            ..Self::default()
        }
    }

    pub fn is_detector_enabled(&self, detector_id: &str) -> bool {
        if self.disabled_detectors.contains(detector_id) {
            return false;
        }

        !(self.opt_in_detectors.contains(detector_id)
            && !self.enabled_opt_in_detectors.contains(detector_id))
    }

    /// True when the default, any per-detector action or any field rule is `action`.
    pub fn uses_action(&self, action: PrivacyAction) -> bool {
        self.default_action == action
            || self.detector_actions.values().any(|value| *value == action)
            || self.field_rules.iter().any(|rule| rule.action == action)
    }

    pub fn resolve_action(&self, detector_id: &str) -> PrivacyAction {
        self.detector_actions
            .get(detector_id)
            .copied()
            .unwrap_or(self.default_action)
    }
}
