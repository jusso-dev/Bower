//! Australian regulated identifiers (TFN, CRN, Medicare, IHI, passport, driver
//! licence, ABN, ACN, DVA).

use std::sync::LazyLock;

use regex::Regex;

use super::{DetectionMatch, ScanText, SensitiveDetector, compile};
use crate::checksum::{
    digits_only, is_valid_abn, is_valid_acn, is_valid_ihi, is_valid_medicare, is_valid_tfn,
};
use crate::ids::{detector_categories as categories, detector_ids as ids};
use crate::text::{contains_ignore_ascii_case, is_dotnet_whitespace, utf16_len};

// 8–9 digits with optional spaces/hyphens; context labels increase confidence but checksum is required.
static TFN: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:TFN|Tax\s*File\s*Number)?[:\s#-]*(\d{3}[\s-]?\d{3}[\s-]?\d{2,3})\b")
});
static CRN: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:CRN|Customer\s*Reference\s*Number|Centrelink)?[:\s#-]*(\d{3}[\s-]?\d{3}[\s-]?\d{3}[A-Za-z])\b",
    )
});
static MEDICARE: LazyLock<Regex> = LazyLock::new(|| compile(r"\b(\d{4}[\s-]?\d{5}[\s-]?\d)\b"));
static IHI: LazyLock<Regex> = LazyLock::new(|| compile(r"\b(800360\d{10})\b"));
// Common AU passport: letter + 7 digits, or 1–2 letters + 7 digits.
static PASSPORT: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:passport(?:\s*no(?:\.|mber)?)?|australian\s*passport)[:\s#-]*([A-Z]{1,2}\d{7})\b|\b([A-Z]\d{7})\b",
    )
});
static ABN: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b(\d{2}[\s]?\d{3}[\s]?\d{3}[\s]?\d{3})\b"));
static ACN: LazyLock<Regex> = LazyLock::new(|| compile(r"\b(\d{3}[\s]?\d{3}[\s]?\d{3})\b"));
// State letter + 1–8 digits + optional war code letter.
static DVA: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:DVA|Veterans'?\s*Affairs)?[:\s#-]*([NQVSTW][A-Z]?\d{4,8}[A-Z]?)\b")
});
// Broad licence token after contextual keywords only (context gated in detect).
static LICENCE: LazyLock<Regex> = LazyLock::new(|| compile(r"(?i)\b([A-Z]{0,2}\d{6,10}[A-Z]?)\b"));
static STATE_NSW_VIC_QLD: LazyLock<Regex> = LazyLock::new(|| compile(r"^\d{8}$"));
static STATE_SA_TAS_WA: LazyLock<Regex> = LazyLock::new(|| compile(r"^\d{6,7}$"));
static STATE_ACT: LazyLock<Regex> = LazyLock::new(|| compile(r"(?i)^[A-Z]{2}\d{6}$"));
static STATE_NT: LazyLock<Regex> = LazyLock::new(|| compile(r"^\d{10}$"));

/// Pushes group 1 of each match when `accept(group text)` holds.
fn detect_group(
    text: &ScanText<'_>,
    regex: &Regex,
    id: &str,
    category: &str,
    validated: bool,
    accept: impl Fn(&str) -> bool,
    matches: &mut Vec<DetectionMatch>,
) {
    if text.is_empty() {
        return;
    }

    for captures in text.captures(regex) {
        let Some(group) = captures.get(1) else {
            continue;
        };
        if accept(text.slice(&group)) {
            matches.push(text.detection(id, category, &group, validated, None));
        }
    }
}

pub struct TfnDetector;

impl SensitiveDetector for TfnDetector {
    fn id(&self) -> &str {
        ids::TFN
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_group(
            text,
            &TFN,
            ids::TFN,
            categories::AUSTRALIAN,
            true,
            |group| is_valid_tfn(&digits_only(group)),
            matches,
        );
    }
}

pub struct CrnDetector;

impl SensitiveDetector for CrnDetector {
    fn id(&self) -> &str {
        ids::CRN
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_group(
            text,
            &CRN,
            ids::CRN,
            categories::AUSTRALIAN,
            true,
            |_| true,
            matches,
        );
    }
}

pub struct MedicareDetector;

impl SensitiveDetector for MedicareDetector {
    fn id(&self) -> &str {
        ids::MEDICARE
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_group(
            text,
            &MEDICARE,
            ids::MEDICARE,
            categories::AUSTRALIAN,
            true,
            |group| is_valid_medicare(&digits_only(group)),
            matches,
        );
    }
}

pub struct IhiDetector;

impl SensitiveDetector for IhiDetector {
    fn id(&self) -> &str {
        ids::IHI
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        // Group 1 spans the whole match.
        detect_group(
            text,
            &IHI,
            ids::IHI,
            categories::AUSTRALIAN,
            true,
            is_valid_ihi,
            matches,
        );
    }
}

pub struct PassportDetector;

impl SensitiveDetector for PassportDetector {
    fn id(&self) -> &str {
        ids::PASSPORT
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        let has_context = contains_ignore_ascii_case(text.text(), "passport");
        for captures in text.captures(&PASSPORT) {
            let labelled = captures.get(1);
            let bare = captures.get(2);
            // Bare letter+7digits only when a contextual label is present (reduces false positives).
            if !has_context && bare.is_some() && labelled.is_none() {
                continue;
            }

            let Some(group) = labelled.or(bare).or_else(|| captures.get(0)) else {
                continue;
            };
            matches.push(text.detection(
                ids::PASSPORT,
                categories::AUSTRALIAN,
                &group,
                false,
                None,
            ));
        }
    }
}

pub struct AbnDetector;

impl SensitiveDetector for AbnDetector {
    fn id(&self) -> &str {
        ids::ABN
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_group(
            text,
            &ABN,
            ids::ABN,
            categories::AUSTRALIAN,
            true,
            |group| {
                let digits = digits_only(group);
                digits.len() == 11 && is_valid_abn(&digits)
            },
            matches,
        );
    }
}

pub struct AcnDetector;

impl SensitiveDetector for AcnDetector {
    fn id(&self) -> &str {
        ids::ACN
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_group(
            text,
            &ACN,
            ids::ACN,
            categories::AUSTRALIAN,
            true,
            |group| {
                let digits = digits_only(group);
                digits.len() == 9 && is_valid_acn(&digits)
            },
            matches,
        );
    }
}

pub struct DvaDetector;

impl SensitiveDetector for DvaDetector {
    fn id(&self) -> &str {
        ids::DVA
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        let contextual = contains_ignore_ascii_case(text.text(), "DVA")
            || contains_ignore_ascii_case(text.text(), "Veteran");
        for captures in text.captures(&DVA) {
            let whole = captures.get(0).expect("group 0 always participates");
            if !contextual && utf16_len(text.slice(&whole)) < 6 {
                continue;
            }

            let group = captures.get(1).unwrap_or(whole);
            matches.push(text.detection(ids::DVA, categories::AUSTRALIAN, &group, false, None));
        }
    }
}

/// State-specific Australian driver licence format detector (context gated).
pub struct DriverLicenceDetector;

impl DriverLicenceDetector {
    fn infer_state(value: &str) -> &'static str {
        let compact: String = value
            .chars()
            .filter(|c| !is_dotnet_whitespace(*c))
            .collect();
        // Heuristic format buckets — not authoritative registries.
        if STATE_NSW_VIC_QLD.is_match(&compact) {
            "NSW/VIC/QLD-like"
        } else if STATE_SA_TAS_WA.is_match(&compact) {
            "SA/TAS/WA-like"
        } else if STATE_ACT.is_match(&compact) {
            "ACT-like"
        } else if STATE_NT.is_match(&compact) {
            "NT-like"
        } else {
            "unknown"
        }
    }
}

impl SensitiveDetector for DriverLicenceDetector {
    fn id(&self) -> &str {
        ids::DRIVER_LICENCE
    }

    fn category(&self) -> &str {
        categories::AUSTRALIAN
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        let original = text.text();
        let has_context = ["licence", "license", "driver", "DLN"]
            .iter()
            .any(|keyword| contains_ignore_ascii_case(original, keyword));
        if !has_context {
            return;
        }

        for found in LICENCE.find_iter(text.haystack()) {
            // Matches never include supplementary-plane characters (the haystack maps
            // them to symbols), so .NET and Rust `\d` agree on the original slice.
            let state = Self::infer_state(text.slice(&found));
            matches.push(text.detection(
                ids::DRIVER_LICENCE,
                categories::AUSTRALIAN,
                &found,
                false,
                Some(state.to_owned()),
            ));
        }
    }
}
