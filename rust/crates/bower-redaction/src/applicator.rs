//! Applies a [`PrivacyAction`] to a matched span or a whole value
//! (`PolicyApplicator`). Never logs originals.

use aes_gcm::aead::{AeadInOut, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::checksum::digits_only;
use crate::detectors::DetectionMatch;
use crate::error::PrivacyError;
use crate::hasher::KeyedFieldHasher;
use crate::ids::detector_ids as ids;
use crate::policy::{PrivacyAction, PrivacyPolicy};
use crate::text::{mask_email, mask_generic, truncate_utf16};

#[derive(Debug)]
pub struct PolicyApplicator {
    replacement_text: String,
    hmac_key_id: String,
    maximum_field_length: usize,
    encryption_key: Option<Vec<u8>>,
    hmac_hasher: Option<KeyedFieldHasher>,
}

impl PolicyApplicator {
    /// Fails closed when the policy uses Hmac without a key of at least 32 bytes:
    /// an unkeyed fallback would silently weaken pseudonymisation.
    pub fn new(policy: &PrivacyPolicy) -> Result<Self, PrivacyError> {
        policy.validate()?;
        let hmac_hasher = match &policy.hmac_key {
            Some(key) if key.len() >= 32 => Some(KeyedFieldHasher::new(key)?),
            _ => None,
        };
        if hmac_hasher.is_none() && policy.uses_action(PrivacyAction::Hmac) {
            return Err(PrivacyError::InvalidOperation(
                "Privacy policy uses the Hmac action but no HMAC key of at least 32 bytes is configured."
                    .to_owned(),
            ));
        }

        Ok(Self {
            replacement_text: policy.replacement_text.clone(),
            hmac_key_id: policy.hmac_key_id.clone(),
            maximum_field_length: policy.maximum_field_length,
            encryption_key: policy.encryption_key.clone(),
            hmac_hasher,
        })
    }

    fn hmac(&self, value: &str) -> Result<String, PrivacyError> {
        self.hmac_hasher
            .as_ref()
            .ok_or_else(|| {
                PrivacyError::InvalidOperation("HMAC key is not configured.".to_owned())
            })?
            .hash(value, Some(&self.hmac_key_id))
    }

    /// Replacement for `match` within `original`.
    pub fn apply(
        &self,
        original: &str,
        found: &DetectionMatch,
        action: PrivacyAction,
    ) -> Result<String, PrivacyError> {
        let span = &original[found.start..found.end];
        Ok(match action {
            PrivacyAction::Allow | PrivacyAction::AlertOnly => span.to_owned(),
            PrivacyAction::Remove => String::new(),
            PrivacyAction::Mask => mask(span, &found.detector_id),
            PrivacyAction::Sha256 => sha256(span),
            PrivacyAction::Hmac => self.hmac(span)?,
            PrivacyAction::Encrypt => self.encrypt(span).unwrap_or_default(),
            PrivacyAction::Replace | PrivacyAction::Truncate => self.replacement_text.clone(),
        })
    }

    /// Applies an action to a whole field value (field rules). `None` removes the value.
    pub fn apply_to_value(
        &self,
        value: &str,
        action: PrivacyAction,
        max_length: Option<usize>,
    ) -> Result<Option<String>, PrivacyError> {
        Ok(match action {
            PrivacyAction::Allow | PrivacyAction::AlertOnly => Some(value.to_owned()),
            PrivacyAction::Remove => None,
            PrivacyAction::Replace => Some(self.replacement_text.clone()),
            PrivacyAction::Mask => Some(mask(value, "")),
            PrivacyAction::Sha256 => Some(sha256(value)),
            PrivacyAction::Hmac if value.is_empty() => Some(String::new()),
            PrivacyAction::Hmac => Some(self.hmac(value)?),
            PrivacyAction::Encrypt => self.encrypt(value),
            PrivacyAction::Truncate => Some(
                truncate_utf16(value, max_length.unwrap_or(self.maximum_field_length))
                    .unwrap_or_else(|| value.to_owned()),
            ),
        })
    }

    /// `enc:aesgcm:<nonce>:<tag>:<ciphertext>` (base64), AES-256-GCM with a random
    /// 96-bit nonce. `None` when no 32-byte key is configured.
    fn encrypt(&self, value: &str) -> Option<String> {
        let key = self
            .encryption_key
            .as_deref()
            .filter(|key| key.len() == 32)?;
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let mut nonce = [0u8; 12];
        // An unavailable OS RNG must never produce a predictable nonce: fail to remove.
        getrandom::fill(&mut nonce).ok()?;
        let mut buffer = value.as_bytes().to_vec();
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::<Aes256Gcm>::from(nonce),
                &[],
                buffer.as_mut_slice().into(),
            )
            .ok()?;
        Some(format!(
            "enc:aesgcm:{}:{}:{}",
            STANDARD.encode(nonce),
            STANDARD.encode(tag.as_slice()),
            STANDARD.encode(&buffer)
        ))
    }
}

/// `PolicyApplicator.Truncate`.
pub fn truncate(value: &str, max_length: usize) -> String {
    truncate_utf16(value, max_length).unwrap_or_else(|| value.to_owned())
}

fn sha256(value: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
}

fn mask(value: &str, detector_id: &str) -> String {
    if detector_id == ids::EMAIL
        && let Some(masked) = mask_email(value)
    {
        return masked;
    }

    if detector_id == ids::CREDIT_CARD {
        let digits = digits_only(value);
        if digits.len() >= 4 {
            return format!("****-****-****-{}", &digits[digits.len() - 4..]);
        }
    }

    if matches!(
        detector_id,
        ids::TFN | ids::MEDICARE | ids::IHI | ids::CRN | ids::ABN | ids::ACN | ids::BSB_ACCOUNT
    ) {
        let digits = digits_only(value);
        if digits.len() >= 4 {
            return format!(
                "{}{}",
                "*".repeat(digits.len() - 4),
                &digits[digits.len() - 4..]
            );
        }
    }

    mask_generic(value)
}
