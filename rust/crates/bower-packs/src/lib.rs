//! Port of `Bower.Packs`: signed, versioned bundles of policy, privacy profile,
//! parsers, Sigma detections, samples and a DCR template for one application type.
//!
//! - Never loads an unsigned pack or a pack signed by an untrusted key. There is no
//!   "skip verification" switch: [`load`] refuses an empty trust list.
//! - Every archive file is listed in the signed manifest with its SHA-256; unlisted
//!   files, path traversal and oversized entries fail verification.
//! - Content is parsed and samples run at build time, so a broken pack cannot be signed.
//! - Privacy profiles never contain keys; hosts supply HMAC keys at load.
//! - Manifests and signatures are byte-compatible with the C# implementation: either
//!   side verifies the other's packs.

pub mod archive;
pub mod diff;
pub mod model;
pub mod runtime;
pub mod tester;
pub mod zip;

pub use archive::{
    LoadedPack, MANIFEST_ENTRY, MAXIMUM_ARCHIVE_BYTES, MAXIMUM_ENTRIES, MAXIMUM_FILE_BYTES,
    PackError, SIGNATURE_ENTRY, build, load, load_bytes, pack_hash, test_privacy_policy,
};
pub use diff::{PolicyChange, compare};
pub use model::{PackFile, PackManifest, PackPolicyEntry, PackSource, PackSourceMetadata, roles};
pub use tester::{PackSampleResult, run as run_samples};
