//! Identity / personal detectors. IP, hostname, username, address and GPS are opt-in.

use std::sync::LazyLock;

use super::{
    DetectionMatch, Pattern, RegexDetector, ScanText, SensitiveDetector, proxied, unicode_only,
};
use crate::ids::{detector_categories as categories, detector_ids as ids};

static EMAIL: LazyLock<Pattern> =
    LazyLock::new(|| unicode_only(r"(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}"));
static PHONE_AU: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"\b(?:\+?61[\s\-]?|0)(?:4\d{2}|[2378]\d)[\s\-]?\d{3}[\s\-]?\d{3}\b",
        Some(b'9'),
        b'_',
    )
});
static PHONE_INTL: LazyLock<Pattern> =
    LazyLock::new(|| proxied(r"\b\+[1-9]\d{6,14}\b", Some(b'0'), b'_'));
static DOB: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"(?i)\b(?:DOB|Date\s*of\s*Birth|born)[:\s#\-]*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})\b",
        Some(b'9'),
        b'k',
    )
});
// Opt-in: Australian-style street address heuristic.
static ADDRESS: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"(?i)\b\d{1,5}\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,3}\s+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Court|Ct|Place|Pl|Lane|Ln|Parade|Pde|Crescent|Cres|Boulevard|Blvd|Highway|Hwy)\b",
        Some(b'9'),
        b'k',
    )
});
static GPS: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"\b-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b",
        Some(b'9'),
        b'_',
    )
});
static IP: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        Some(b'9'),
        b'_',
    )
});
static HOST: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|au|local|internal|corp)\b",
        Some(b'_'),
        b'k',
    )
});
static USERNAME: LazyLock<Pattern> = LazyLock::new(|| {
    unicode_only(r"(?i)\b(?:username|user\s*name|login)[:\s=]+([A-Za-z0-9._\-]{2,64})\b")
});

pub fn email_detector() -> RegexDetector {
    RegexDetector::new(ids::EMAIL, categories::IDENTITY, &EMAIL)
}

pub fn phone_au_detector() -> RegexDetector {
    RegexDetector::new(ids::PHONE_AU, categories::IDENTITY, &PHONE_AU)
}

pub fn phone_international_detector() -> RegexDetector {
    RegexDetector::new(ids::PHONE_INTERNATIONAL, categories::IDENTITY, &PHONE_INTL)
}

pub fn address_detector() -> RegexDetector {
    RegexDetector::new(ids::ADDRESS, categories::IDENTITY, &ADDRESS)
}

pub fn gps_coordinate_detector() -> RegexDetector {
    RegexDetector::new(ids::GPS, categories::IDENTITY, &GPS)
}

pub fn ip_address_detector() -> RegexDetector {
    RegexDetector::new(ids::IP_ADDRESS, categories::IDENTITY, &IP)
}

pub fn hostname_detector() -> RegexDetector {
    RegexDetector::new(ids::HOSTNAME, categories::IDENTITY, &HOST)
}

/// Pushes group 1 (falling back to the whole match) as an unvalidated match.
fn detect_labelled(
    text: &ScanText<'_>,
    pattern: &Pattern,
    id: &str,
    matches: &mut Vec<DetectionMatch>,
) {
    if text.is_empty() {
        return;
    }

    for captures in text.captures(pattern) {
        let group = captures
            .get(1)
            .or_else(|| captures.get(0))
            .expect("group 0 always participates");
        matches.push(text.detection(id, categories::IDENTITY, group, false, None));
    }
}

pub struct DateOfBirthDetector;

impl SensitiveDetector for DateOfBirthDetector {
    fn id(&self) -> &str {
        ids::DATE_OF_BIRTH
    }

    fn category(&self) -> &str {
        categories::IDENTITY
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_labelled(text, &DOB, ids::DATE_OF_BIRTH, matches);
    }
}

pub struct UsernameDetector;

impl SensitiveDetector for UsernameDetector {
    fn id(&self) -> &str {
        ids::USERNAME
    }

    fn category(&self) -> &str {
        categories::IDENTITY
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        detect_labelled(text, &USERNAME, ids::USERNAME, matches);
    }
}

/// Every pattern in this module, for the proxy differential test.
#[cfg(test)]
pub(super) fn patterns() -> Vec<(&'static str, &'static Pattern)> {
    #[allow(unused_mut)]
    let mut patterns: Vec<(&'static str, &'static Pattern)> = vec![
        ("EMAIL", &*EMAIL),
        ("PHONE_AU", &*PHONE_AU),
        ("PHONE_INTL", &*PHONE_INTL),
        ("DOB", &*DOB),
        ("ADDRESS", &*ADDRESS),
        ("GPS", &*GPS),
        ("IP", &*IP),
        ("HOST", &*HOST),
        ("USERNAME", &*USERNAME),
    ];
    patterns
}
