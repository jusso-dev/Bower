//! Australian Government protective security markings (opt-in, AlertOnly by default).

use std::sync::LazyLock;

use super::{Pattern, RegexDetector, proxied};
use crate::ids::{detector_categories as categories, detector_ids as ids};
use crate::text::is_dotnet_whitespace;

static MARKING: LazyLock<Pattern> = LazyLock::new(|| {
    proxied(
        r"(?i)\b(?:OFFICIAL(?::\s*Sensitive)?|PROTECTED|SECRET|TOP\s*SECRET|CABINET-IN-CONFIDENCE)\b",
        Some(b'_'),
        b'k',
    )
});

/// `matched.Trim().ToUpperInvariant()`. Matches hold ASCII letters, `:`, `-` and
/// whitespace only, so ASCII upper-casing is exact.
fn sub_kind(matched: &str) -> Option<String> {
    Some(
        matched
            .trim_matches(is_dotnet_whitespace)
            .to_ascii_uppercase(),
    )
}

pub fn security_marking_detector() -> RegexDetector {
    RegexDetector::new(ids::SECURITY_MARKING, categories::CLASSIFICATION, &MARKING)
        .with_sub_kind(sub_kind)
}

/// Every pattern in this module, for the proxy differential test.
#[cfg(test)]
pub(super) fn patterns() -> Vec<(&'static str, &'static Pattern)> {
    #[allow(unused_mut)]
    let mut patterns: Vec<(&'static str, &'static Pattern)> = vec![("MARKING", &*MARKING)];
    patterns
}
