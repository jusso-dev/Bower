//! Keyed HMAC-SHA256 pseudonymisation (`KeyedFieldHasher`).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::PrivacyError;
use crate::text::is_null_or_whitespace;

#[derive(Clone)]
pub struct KeyedFieldHasher {
    key: Vec<u8>,
}

impl std::fmt::Debug for KeyedFieldHasher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyedFieldHasher")
            .finish_non_exhaustive()
    }
}

impl KeyedFieldHasher {
    /// Fails when the key is shorter than 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, PrivacyError> {
        if key.len() < 32 {
            return Err(PrivacyError::Argument(
                "Key must contain at least 32 bytes. (Parameter 'key')".to_owned(),
            ));
        }

        Ok(Self { key: key.to_vec() })
    }

    /// `hmac-sha256:<hex>` or `hmac-sha256:<keyId>:<hex>`. Fails on empty or
    /// whitespace-only values, like `ArgumentException.ThrowIfNullOrWhiteSpace`.
    pub fn hash(&self, value: &str, key_id: Option<&str>) -> Result<String, PrivacyError> {
        if is_null_or_whitespace(value) {
            return Err(PrivacyError::Argument(
                "The value cannot be an empty string or composed entirely of whitespace. (Parameter 'value')"
                    .to_owned(),
            ));
        }

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| PrivacyError::Argument("HMAC key is invalid.".to_owned()))?;
        mac.update(value.as_bytes());
        let digest = hex::encode(mac.finalize().into_bytes());
        Ok(match key_id {
            Some(key_id) if !key_id.is_empty() => format!("hmac-sha256:{key_id}:{digest}"),
            _ => format!("hmac-sha256:{digest}"),
        })
    }
}
