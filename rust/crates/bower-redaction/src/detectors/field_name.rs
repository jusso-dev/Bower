//! Removes whole properties whose names indicate secrets or unrestricted bodies.

use super::FieldNameDetector;
use crate::ids::{detector_categories as categories, detector_ids as ids};

const SECRET_NAMES: &[&str] = &[
    "password",
    "passwordhash",
    "pwd",
    "passwd",
    "accesstoken",
    "refreshtoken",
    "bearertoken",
    "apikeysecret",
    "apikey",
    "clientsecret",
    "privatekey",
    "connectionstring",
    "authorization",
    "authorizationheader",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "secret",
    "requestbody",
    "responsebody",
    "body",
    "headers",
    "payload",
    "filecontents",
];

/// Fragments that mark a value as secret wherever they appear in a normalised name.
const SECRET_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "cookie",
    "credential",
    "connectionstring",
    "authorization",
    "signature",
];

/// Short markers that only count as a suffix, to avoid matching unrelated words.
const SECRET_SUFFIXES: &[&str] = &["pwd", "pass", "pin", "otp"];

/// Names that describe secret metadata rather than carrying the secret itself.
const SAFE_NAMES: &[&str] = &[
    "tokentype",
    "tokenexpiry",
    "tokenexpiresat",
    "tokenexpiresin",
    "tokenissuer",
    "tokenaudience",
    "tokenvalid",
    "tokencount",
    "passwordpolicy",
    "passwordexpired",
    "passwordexpiresat",
    "passwordlastchanged",
    "passwordchanged",
    "passwordresetrequired",
    "secretname",
    "secretversion",
    "credentialtype",
    "credentialid",
    "signaturealgorithm",
    "signaturevalid",
    "cookieconsent",
    "bypass",
    "compass",
    "spin",
];

/// Exact secret names, then secret-bearing fragments and suffixes, minus an
/// allow-list of metadata names that describe a secret without containing it.
pub struct FieldNameSecretDetector;

impl FieldNameDetector for FieldNameSecretDetector {
    fn id(&self) -> &str {
        ids::FIELD_NAME_SECRET
    }

    fn category(&self) -> &str {
        categories::FIELD_NAME
    }

    fn matches_field_name(&self, normalized_field_name: &str) -> bool {
        if normalized_field_name.is_empty() {
            return false;
        }

        if SECRET_NAMES.contains(&normalized_field_name) {
            return true;
        }

        if SAFE_NAMES.contains(&normalized_field_name) {
            return false;
        }

        SECRET_FRAGMENTS
            .iter()
            .any(|fragment| normalized_field_name.contains(fragment))
            || SECRET_SUFFIXES
                .iter()
                .any(|suffix| normalized_field_name.ends_with(suffix))
    }
}
