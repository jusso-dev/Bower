//! Signing and canonicalisation shared by packs and evidence bundles
//! (port of `Bower.Integrity`).
//!
//! ECDSA P-256 with SHA-256 only. Verification trusts only explicitly supplied
//! public keys, matched by key id. Private keys are never logged.

pub mod canonical_json;
pub mod signer;

pub use signer::{
    DetachedSignature, ECDSA_P256_SHA256, GeneratedKeyPair, IntegrityError, generate_key_pair,
    key_id, key_id_from_public_key_pem, sha256_hex, sign, verify,
};
