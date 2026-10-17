//! Bower Privacy & Secret Protection Engine (port of `Bower.Redaction`).
//!
//! Deterministic redaction before persistence: compiled patterns, checksums and
//! structure only — no AI, no network, no executable configuration. Redaction
//! failure is a security failure: the payload must be quarantined, never stored.
//! Privacy metadata lists detector ids and actions only, never original values.
//!
//! Output is byte-identical to the C# implementation: the redacted document is
//! written with [`bower_contracts::json`] and detectors reproduce .NET regex
//! semantics (see [`text`]).

pub mod applicator;
pub mod checksum;
pub mod detectors;
pub mod engine;
pub mod error;
pub mod facade;
pub mod hasher;
pub mod ids;
mod json;
pub mod policy;
pub mod profile;
pub mod text;

pub use applicator::PolicyApplicator;
pub use detectors::{
    DetectionMatch, FieldNameDetector, FieldNameSecretDetector, ScanText, SensitiveDetector,
    default_field_name_detector, default_value_detectors,
};
pub use engine::{
    AppliedFinding, JsonEventRedactor, MAXIMUM_PAYLOAD_BYTES, PrivacyEngine, PrivacyMetadata,
    PrivacyScanResult, PrivacyTextResult,
};
pub use error::PrivacyError;
pub use facade::{
    SensitiveDataDetector, SensitiveFinding, SensitiveFindingKind, SensitiveScanResult,
};
pub use hasher::KeyedFieldHasher;
pub use ids::{detector_categories, detector_ids};
pub use policy::{PrivacyAction, PrivacyFieldRule, PrivacyPolicy};
pub use profile::{LoadedPrivacyProfile, load as load_privacy_profile, read_key_file};
