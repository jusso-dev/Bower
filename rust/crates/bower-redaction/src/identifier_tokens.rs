//! Canonical identifier tokens (port of `CanonicalIdentifierTokens`).
//!
//! A UUID in 8-4-4-4-12 form or a 32-hex-digit dashless GUID (either case, any
//! version), bounded by the start or end of the value or by a character that is not an
//! ASCII letter, digit, hyphen or underscore. A structured number detector (Australian
//! identifiers, card, bank account, IBAN and SWIFT numbers) cannot claim a span that lies
//! wholly inside one: random identifiers pass those checksums by chance (about 1 in 450
//! UUIDv4 for the TFN check), and no person writes a TFN, card number or IBAN as a UUID.
//! Every other detector, including secrets and custom detectors, still scans the token.

use crate::detectors::DetectionMatch;
use crate::ids::detector_ids as ids;

const GUID_LENGTH: usize = 32;
const UUID_LENGTH: usize = 36;

/// Detectors whose matches are dropped inside a canonical identifier token.
pub const STRUCTURED_NUMBER_DETECTOR_IDS: &[&str] = &[
    ids::TFN,
    ids::CRN,
    ids::MEDICARE,
    ids::IHI,
    ids::PASSPORT,
    ids::DRIVER_LICENCE,
    ids::ABN,
    ids::ACN,
    ids::DVA,
    ids::CREDIT_CARD,
    ids::BSB_ACCOUNT,
    ids::IBAN,
    ids::SWIFT_BIC,
];

/// True when matches of `detector_id` are dropped inside a canonical identifier token.
pub fn applies_to(detector_id: &str) -> bool {
    STRUCTURED_NUMBER_DETECTOR_IDS.contains(&detector_id)
}

/// True when `token` is exactly a canonical UUID or dashless GUID.
pub fn is_canonical_identifier(token: &str) -> bool {
    let bytes = token.as_bytes();
    match bytes.len() {
        GUID_LENGTH => bytes.iter().all(u8::is_ascii_hexdigit),
        UUID_LENGTH => bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    }
}

/// Byte range (start, exclusive end) of every canonical identifier token in `text`.
/// Non-ASCII characters are never token characters, as in C#.
pub fn find(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_token_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_token_byte(bytes[index]) {
            index += 1;
        }
        // Token bytes are ASCII, so `start..index` is a character boundary range.
        if is_canonical_identifier(&text[start..index]) {
            found.push((start, index));
        }
    }
    found
}

/// Removes matches at or after `from` that lie wholly inside a token, keeping order.
/// `tokens` must come from [`find`] (disjoint and in order), so each match costs one binary
/// search, not a scan of every token. Returns the token ranges examined; tests use it to
/// bound the work.
pub fn remove_contained(
    tokens: &[(usize, usize)],
    matches: &mut Vec<DetectionMatch>,
    from: usize,
) -> usize {
    if tokens.is_empty() {
        return 0;
    }
    let mut examined = 0;
    let mut index = 0;
    matches.retain(|found| {
        index += 1;
        if index <= from {
            return true;
        }
        // Only the last token starting at or before the match can contain it.
        let after = tokens.partition_point(|&(start, _)| {
            examined += 1;
            start <= found.start
        });
        after == 0 || found.end > tokens[after - 1].1
    });
    examined
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}
