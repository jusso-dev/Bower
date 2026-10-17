//! Identity / personal detectors. IP, hostname, username, address and GPS are opt-in.

use std::sync::LazyLock;

use regex::Regex;

use super::{DetectionMatch, RegexDetector, ScanText, SensitiveDetector, compile};
use crate::ids::{detector_categories as categories, detector_ids as ids};

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}"));
static PHONE_AU: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b(?:\+?61[\s\-]?|0)(?:4\d{2}|[2378]\d)[\s\-]?\d{3}[\s\-]?\d{3}\b"));
static PHONE_INTL: LazyLock<Regex> = LazyLock::new(|| compile(r"\b\+[1-9]\d{6,14}\b"));
static DOB: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:DOB|Date\s*of\s*Birth|born)[:\s#\-]*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})\b")
});
// Opt-in: Australian-style street address heuristic.
static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b\d{1,5}\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,3}\s+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Court|Ct|Place|Pl|Lane|Ln|Parade|Pde|Crescent|Cres|Boulevard|Blvd|Highway|Hwy)\b",
    )
});
static GPS: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b"));
static IP: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
});
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|au|local|internal|corp)\b",
    )
});
static USERNAME: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:username|user\s*name|login)[:\s=]+([A-Za-z0-9._\-]{2,64})\b")
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
    regex: &Regex,
    id: &str,
    matches: &mut Vec<DetectionMatch>,
) {
    if text.is_empty() {
        return;
    }

    for captures in text.captures(regex) {
        let group = captures
            .get(1)
            .or_else(|| captures.get(0))
            .expect("group 0 always participates");
        matches.push(text.detection(id, categories::IDENTITY, &group, false, None));
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
