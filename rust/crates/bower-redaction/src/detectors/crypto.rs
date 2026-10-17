//! Cryptographic material (PEM private keys, certificates, PGP blocks).

use std::sync::LazyLock;

use regex::Regex;

use super::{RegexDetector, compile};
use crate::ids::{detector_categories as categories, detector_ids as ids};

static PEM: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----|-----BEGIN PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----[\s\S]+?-----END PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----|-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    )
});

fn sub_kind(matched: &str) -> Option<String> {
    let kind = if matched.contains("RSA PRIVATE") {
        "rsa-private"
    } else if matched.contains("EC PRIVATE") || matched.contains("ECDSA") {
        "ecdsa-private"
    } else if matched.contains("OPENSSH PRIVATE") {
        "openssh-private"
    } else if matched.contains("PRIVATE KEY") {
        "pkcs8-private"
    } else if matched.contains("CERTIFICATE") {
        "x509-certificate"
    } else if matched.contains("PGP") {
        "pgp"
    } else if matched.contains("BEGIN SSH2") {
        "ssh"
    } else {
        "pem"
    };
    Some(kind.to_owned())
}

pub fn cryptographic_material_detector() -> RegexDetector {
    RegexDetector::new(ids::CRYPTO_MATERIAL, categories::CRYPTO, &PEM).with_sub_kind(sub_kind)
}
