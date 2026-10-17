//! Pluggable sensitive-data detectors. Runtime stays deterministic: compiled
//! patterns, checksums and structure only.

use std::borrow::Cow;

use regex::{Captures, Match, Regex};

use crate::text::{regex_haystack, utf16_len};

pub mod australian;
pub mod classification;
pub mod crypto;
pub mod field_name;
pub mod financial;
pub mod identity;
pub mod secrets;

pub use field_name::FieldNameSecretDetector;

/// A sensitive span inside a field value.
///
/// `start`/`end` are UTF-8 byte offsets into the scanned text. `length_utf16`
/// is the C# `Length` (UTF-16 code units) used to rank overlapping matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionMatch {
    pub detector_id: String,
    pub category: String,
    pub start: usize,
    pub end: usize,
    pub length_utf16: usize,
    pub validated: bool,
    pub sub_kind: Option<String>,
}

impl DetectionMatch {
    pub fn new(
        detector_id: &str,
        category: &str,
        text: &str,
        start: usize,
        end: usize,
        validated: bool,
        sub_kind: Option<String>,
    ) -> Self {
        Self {
            detector_id: detector_id.to_owned(),
            category: category.to_owned(),
            start,
            end,
            length_utf16: utf16_len(&text[start..end]),
            validated,
            sub_kind,
        }
    }
}

/// Text handed to detectors: the original value plus a regex haystack with
/// .NET-equivalent character classes (see [`crate::text::regex_haystack`]).
/// Both have identical byte offsets.
pub struct ScanText<'a> {
    text: &'a str,
    haystack: Cow<'a, str>,
}

impl<'a> ScanText<'a> {
    pub fn new(text: &'a str) -> Self {
        Self {
            text,
            haystack: regex_haystack(text),
        }
    }

    /// Original text. Use for validation, sub-kinds and context checks.
    pub fn text(&self) -> &'a str {
        self.text
    }

    /// Text to run regexes over. Offsets apply to [`ScanText::text`].
    pub fn haystack(&self) -> &str {
        &self.haystack
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Iterates regex matches with .NET semantics.
    pub fn captures<'s>(&'s self, regex: &'s Regex) -> impl Iterator<Item = Captures<'s>> + 's {
        regex.captures_iter(&self.haystack)
    }

    /// Original text of a match found in the haystack.
    pub fn slice(&self, found: &Match<'_>) -> &'a str {
        &self.text[found.start()..found.end()]
    }

    pub fn detection(
        &self,
        detector_id: &str,
        category: &str,
        found: &Match<'_>,
        validated: bool,
        sub_kind: Option<String>,
    ) -> DetectionMatch {
        DetectionMatch::new(
            detector_id,
            category,
            self.text,
            found.start(),
            found.end(),
            validated,
            sub_kind,
        )
    }
}

/// Pluggable value detector (`ISensitiveDetector`).
pub trait SensitiveDetector: Send + Sync {
    /// Stable id used in policy and metadata (for example `au.tfn`).
    fn id(&self) -> &str;

    /// Module category (australian, financial, secrets, …).
    fn category(&self) -> &str;

    /// Scans `text` and appends matches.
    fn detect(&self, text: &ScanText<'_>, path: &str, matches: &mut Vec<DetectionMatch>);
}

/// Detector that decides whole JSON properties by field name (`IFieldNameDetector`).
pub trait FieldNameDetector: Send + Sync {
    fn id(&self) -> &str;

    fn category(&self) -> &str;

    /// True when the normalised field name should be treated as secret.
    fn matches_field_name(&self, normalized_field_name: &str) -> bool;
}

/// Compiles a pattern that is known valid at build time.
pub(crate) fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|error| panic!("detector pattern is invalid: {error}"))
}

/// `RegexDetectorBase`: whole-match detector with optional validation and sub-kind.
pub struct RegexDetector {
    id: &'static str,
    category: &'static str,
    pattern: &'static std::sync::LazyLock<Regex>,
    validate: Option<fn(&str) -> bool>,
    sub_kind: fn(&str) -> Option<String>,
}

fn no_sub_kind(_: &str) -> Option<String> {
    None
}

impl RegexDetector {
    pub(crate) const fn new(
        id: &'static str,
        category: &'static str,
        pattern: &'static std::sync::LazyLock<Regex>,
    ) -> Self {
        Self {
            id,
            category,
            pattern,
            validate: None,
            sub_kind: no_sub_kind,
        }
    }

    pub(crate) const fn with_validation(mut self, validate: fn(&str) -> bool) -> Self {
        self.validate = Some(validate);
        self
    }

    pub(crate) const fn with_sub_kind(mut self, sub_kind: fn(&str) -> Option<String>) -> Self {
        self.sub_kind = sub_kind;
        self
    }
}

impl SensitiveDetector for RegexDetector {
    fn id(&self) -> &str {
        self.id
    }

    fn category(&self) -> &str {
        self.category
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        for found in self.pattern.find_iter(text.haystack()) {
            let span = text.slice(&found);
            if let Some(validate) = self.validate
                && !validate(span)
            {
                continue;
            }

            matches.push(text.detection(
                self.id,
                self.category,
                &found,
                true,
                (self.sub_kind)(span),
            ));
        }
    }
}

/// Built-in value detectors in catalogue order (`DetectorCatalog.CreateDefaultValueDetectors`).
pub fn default_value_detectors() -> Vec<Box<dyn SensitiveDetector>> {
    vec![
        // Australian
        Box::new(australian::TfnDetector),
        Box::new(australian::CrnDetector),
        Box::new(australian::MedicareDetector),
        Box::new(australian::IhiDetector),
        Box::new(australian::PassportDetector),
        Box::new(australian::DriverLicenceDetector),
        Box::new(australian::AbnDetector),
        Box::new(australian::AcnDetector),
        Box::new(australian::DvaDetector),
        // Financial
        Box::new(financial::CreditCardDetector),
        Box::new(financial::bsb_account_detector()),
        Box::new(financial::iban_detector()),
        Box::new(financial::swift_bic_detector()),
        Box::new(financial::PayIdDetector),
        // Identity
        Box::new(identity::email_detector()),
        Box::new(identity::phone_au_detector()),
        Box::new(identity::phone_international_detector()),
        Box::new(identity::DateOfBirthDetector),
        Box::new(identity::address_detector()),
        Box::new(identity::gps_coordinate_detector()),
        Box::new(identity::ip_address_detector()),
        Box::new(identity::hostname_detector()),
        Box::new(identity::UsernameDetector),
        // Secrets
        Box::new(secrets::aws_secret_detector()),
        Box::new(secrets::azure_secret_detector()),
        Box::new(secrets::entra_token_detector()),
        Box::new(secrets::gcp_secret_detector()),
        Box::new(secrets::jwt_detector()),
        Box::new(secrets::oauth_token_detector()),
        Box::new(secrets::ApiKeyDetector),
        Box::new(secrets::kubernetes_secret_detector()),
        Box::new(secrets::docker_credential_detector()),
        Box::new(secrets::database_credential_detector()),
        Box::new(secrets::environment_variable_secret_detector()),
        // Crypto + classification
        Box::new(crypto::cryptographic_material_detector()),
        Box::new(classification::security_marking_detector()),
    ]
}

/// Built-in field-name detector (`DetectorCatalog.CreateDefaultFieldNameDetector`).
pub fn default_field_name_detector() -> Box<dyn FieldNameDetector> {
    Box::new(FieldNameSecretDetector)
}
