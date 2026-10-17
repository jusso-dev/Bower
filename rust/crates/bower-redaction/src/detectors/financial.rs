//! Financial detectors (payment cards, BSB/account, IBAN, SWIFT/BIC, PayID).

use std::sync::LazyLock;

use super::{DetectionMatch, Pattern, RegexDetector, ScanText, SensitiveDetector, proxied};
use crate::checksum::{digits_only, luhn};
use crate::ids::{detector_categories as categories, detector_ids as ids};
use crate::text::is_dotnet_whitespace;

static CARD: LazyLock<Pattern> =
    LazyLock::new(|| proxied(r"\b(?:\d[ -]*?){13,19}\b", Some(b'9'), b'_'));
static BSB: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"(?i)\b(\d{3}[-\s]?\d{3})(?:[/\s:]+|[\s]*account[\s#:]*)(\d{4,10})\b",
        Some(b'9'),
        b'k',
    )
});
static IBAN: LazyLock<Pattern> =
    LazyLock::new(|| proxied(r"(?i)\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b", None, b'k'));
static SWIFT: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        Some(b'_'),
        b'_',
    )
});
// PayID is typically email, phone, or ABN — flag explicit PayID labels.
static PAY_ID: LazyLock<Pattern> =
    LazyLock::new(|| proxied(r"(?i)\bPayID[:\s=]+(\S+)", Some(b'_'), b'k'));

pub struct CreditCardDetector;

impl CreditCardDetector {
    fn classify_network(digits: &str) -> Option<&'static str> {
        let bytes = digits.as_bytes();
        let length = bytes.len();
        if bytes[0] == b'4' && matches!(length, 13 | 16 | 19) {
            return Some("Visa");
        }

        if length == 16 {
            let prefix2 = u32::from(bytes[0] - b'0') * 10 + u32::from(bytes[1] - b'0');
            if (51..=55).contains(&prefix2) {
                return Some("Mastercard");
            }

            let prefix4: u32 = digits[..4].parse().unwrap_or(0);
            if (2221..=2720).contains(&prefix4) {
                return Some("Mastercard");
            }

            if digits.starts_with("6011") || digits.starts_with("65") {
                return Some("Discover");
            }

            if digits.starts_with("35") {
                return Some("JCB");
            }
        }

        if length == 15 && (digits.starts_with("34") || digits.starts_with("37")) {
            return Some("Amex");
        }

        if matches!(length, 14 | 16)
            && (digits.starts_with("36") || digits.starts_with("38") || digits.starts_with("300"))
        {
            return Some("Diners");
        }

        None
    }
}

impl SensitiveDetector for CreditCardDetector {
    fn id(&self) -> &str {
        ids::CREDIT_CARD
    }

    fn category(&self) -> &str {
        categories::FINANCIAL
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        for found in text.find_iter(&CARD) {
            let digits = digits_only(text.slice(found));
            if !(13..=19).contains(&digits.len()) || !luhn(&digits) {
                continue;
            }

            let Some(network) = Self::classify_network(&digits) else {
                continue;
            };
            matches.push(text.detection(
                ids::CREDIT_CARD,
                categories::FINANCIAL,
                found,
                true,
                Some(network.to_owned()),
            ));
        }
    }
}

pub fn bsb_account_detector() -> RegexDetector {
    RegexDetector::new(ids::BSB_ACCOUNT, categories::FINANCIAL, &BSB)
}

/// ISO 13616 mod-97 check over the whitespace-stripped, upper-cased match.
fn validate_iban(matched: &str) -> bool {
    let compact: Vec<u8> = matched
        .chars()
        .filter(|c| !is_dotnet_whitespace(*c))
        .map(|c| {
            if c.is_ascii() {
                c.to_ascii_uppercase() as u8
            } else {
                0
            }
        })
        .collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }

    let mut total = 0u32;
    for &byte in compact[4..].iter().chain(&compact[..4]) {
        match byte {
            b'0'..=b'9' => total = (total * 10 + u32::from(byte - b'0')) % 97,
            b'A'..=b'Z' => {
                let value = u32::from(byte - b'A') + 10;
                total = (total * 10 + value / 10) % 97;
                total = (total * 10 + value % 10) % 97;
            }
            // Non-ASCII characters (for example the Kelvin sign, which .NET
            // case-insensitive `[A-Z]` matches) never validate.
            _ => return false,
        }
    }

    total == 1
}

pub fn iban_detector() -> RegexDetector {
    RegexDetector::new(ids::IBAN, categories::FINANCIAL, &IBAN).with_validation(validate_iban)
}

pub fn swift_bic_detector() -> RegexDetector {
    RegexDetector::new(ids::SWIFT_BIC, categories::FINANCIAL, &SWIFT)
}

pub struct PayIdDetector;

impl SensitiveDetector for PayIdDetector {
    fn id(&self) -> &str {
        ids::PAY_ID
    }

    fn category(&self) -> &str {
        categories::FINANCIAL
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        for captures in text.captures(&PAY_ID) {
            if let Some(group) = captures.get(1) {
                matches.push(text.detection(
                    ids::PAY_ID,
                    categories::FINANCIAL,
                    group,
                    false,
                    None,
                ));
            }
        }
    }
}

/// Every pattern in this module, for the proxy differential test.
#[cfg(test)]
pub(super) fn patterns() -> Vec<(&'static str, &'static Pattern)> {
    #[allow(unused_mut)]
    let mut patterns: Vec<(&'static str, &'static Pattern)> = vec![
        ("CARD", &*CARD),
        ("BSB", &*BSB),
        ("IBAN", &*IBAN),
        ("SWIFT", &*SWIFT),
        ("PAY_ID", &*PAY_ID),
    ];
    patterns
}
