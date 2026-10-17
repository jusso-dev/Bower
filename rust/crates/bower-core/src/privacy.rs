//! Detector classification used for privacy alerts. Mirrors
//! `Bower.Redaction.Privacy.PrivacyEngine.IsSecurityEventWorthy` and the
//! `DetectorIds` constants it references, so bower-core does not depend on the
//! redaction crate.

pub const FIELD_NAME_SECRET: &str = "field-name-secret";
pub const TFN: &str = "au.tfn";
pub const CREDIT_CARD: &str = "fin.credit-card";

/// High-risk regulated AU identifiers, secrets and crypto material (never routine
/// email-mask noise).
const SECURITY_EVENT_WORTHY: [&str; 24] = [
    FIELD_NAME_SECRET,
    TFN,
    "au.crn",
    "au.medicare",
    "au.ihi",
    "au.passport",
    "au.driver-licence",
    "au.dva",
    CREDIT_CARD,
    "fin.bsb-account",
    "fin.iban",
    "fin.payid",
    "secret.aws",
    "secret.azure",
    "secret.entra",
    "secret.gcp",
    "secret.jwt",
    "secret.oauth",
    "secret.api-key",
    "secret.kubernetes",
    "secret.docker",
    "secret.database",
    "secret.env-var",
    "crypto.material",
];

const SECURITY_MARKING: &str = "class.security-marking";

/// Root detector id: text before the first `:` when the colon is not leading.
pub fn root(detector_id: &str) -> &str {
    match detector_id.find(':') {
        Some(colon) if colon > 0 => &detector_id[..colon],
        _ => detector_id,
    }
}

pub fn is_security_event_worthy(detector_id: &str) -> bool {
    if detector_id.is_empty() {
        return false;
    }
    let root = root(detector_id);
    root == SECURITY_MARKING || SECURITY_EVENT_WORTHY.contains(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_like_privacy_engine() {
        assert!(is_security_event_worthy("secret.api-key:OpenAI"));
        assert!(is_security_event_worthy("au.tfn"));
        assert!(is_security_event_worthy("class.security-marking"));
        assert!(!is_security_event_worthy("id.email"));
        assert!(!is_security_event_worthy(""));
        assert!(!is_security_event_worthy(":au.tfn"));
    }
}
