//! Cryptographic material (PEM private keys, certificates, PGP blocks).

use std::sync::LazyLock;

use super::{Pattern, RegexDetector, proxied};
use crate::ids::{detector_categories as categories, detector_ids as ids};

static PEM: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----|-----BEGIN PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----[\s\S]+?-----END PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----|-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
        Some(b'_'),
        b'_',
    )
});

/// Labels the block by its exact `-----BEGIN <label>-----` header, so body text can
/// never change the kind (every alternative of the pattern starts with a header).
fn sub_kind(matched: &str) -> Option<String> {
    let label = matched
        .strip_prefix("-----BEGIN ")
        .map(|rest| rest.find("-----").map_or(rest, |end| &rest[..end]));
    let kind = match label {
        Some("RSA PRIVATE KEY") => "rsa-private",
        Some("EC PRIVATE KEY") => "ecdsa-private",
        Some("DSA PRIVATE KEY") => "dsa-private",
        Some("OPENSSH PRIVATE KEY") => "openssh-private",
        Some("ENCRYPTED PRIVATE KEY") => "encrypted-private",
        Some("PRIVATE KEY") => "pkcs8-private",
        Some("CERTIFICATE") => "x509-certificate",
        Some("PGP PRIVATE KEY BLOCK") => "pgp-private",
        Some("PGP PUBLIC KEY BLOCK") => "pgp-public",
        Some("PGP KEY BLOCK") => "pgp",
        _ => "pem",
    };
    Some(kind.to_owned())
}

pub fn cryptographic_material_detector() -> RegexDetector {
    RegexDetector::new(ids::CRYPTO_MATERIAL, categories::CRYPTO, &PEM).with_sub_kind(sub_kind)
}

/// Every pattern in this module, for the proxy differential test.
#[cfg(test)]
pub(super) fn patterns() -> Vec<(&'static str, &'static Pattern)> {
    #[allow(unused_mut)]
    let mut patterns: Vec<(&'static str, &'static Pattern)> = vec![("PEM", &*PEM)];
    patterns
}
