//! Australian Government protective security markings (opt-in, AlertOnly by default).

use std::sync::LazyLock;

use regex::Regex;

use super::{RegexDetector, compile};
use crate::ids::{detector_categories as categories, detector_ids as ids};
use crate::text::is_dotnet_whitespace;

static MARKING: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\b(?:OFFICIAL(?::\s*Sensitive)?|PROTECTED|SECRET|TOP\s*SECRET|CABINET-IN-CONFIDENCE)\b",
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
