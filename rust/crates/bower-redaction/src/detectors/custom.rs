//! Custom detectors (custom redaction rules) from a privacy profile
//! (`CustomDetectorDefinition`, `CustomPatternDetector`, `CompositeFieldNameDetector`).

use std::collections::HashSet;
use std::fmt;

use regex::{Regex, RegexBuilder};

use super::{FieldNameDetector, ScanText, SensitiveDetector, Span};
use crate::custom_pattern::{self, MAXIMUM_COMPLEXITY};
use crate::detectors::DetectionMatch;
use crate::error::PrivacyError;
use crate::ids::detector_categories as categories;
use crate::policy::PrivacyAction;
use crate::text::utf16_len;

pub const MAXIMUM_ID_LENGTH: usize = 64;
pub const MAXIMUM_DESCRIPTION_LENGTH: usize = 256;
pub const MAXIMUM_PATTERN_LENGTH: usize = 512;
/// Longest value (UTF-16 units) custom detectors scan; a longer value fails the redaction
/// (quarantine) while any custom detector is enabled.
pub const MAXIMUM_SCANNED_LENGTH: usize = 65_536;
/// Most custom detector matches per event (all custom detectors and values).
pub const MAXIMUM_MATCHES_PER_EVENT: usize = 4_096;

const WHOLE_WORD_PREFIX: &str = "[^0-9A-Z_a-z](?:";
const WHOLE_WORD_SUFFIX: &str = ")[^0-9A-Z_a-z]";

/// Compiled program limit. Patterns within the complexity limit compile far below it;
/// anything above is reported as too complex.
const REGEX_SIZE_LIMIT: usize = 16 * (1 << 20);
/// Lazy DFA cache per regex. Large enough that every pattern within the complexity
/// limit stays in the lazy DFA instead of falling back to the much slower PikeVM.
const DFA_SIZE_LIMIT: usize = 4 * (1 << 20);

fn invalid(message: String) -> PrivacyError {
    PrivacyError::InvalidData(message)
}

/// A validated custom detector. Instances only come from [`CustomDetectorDefinition::create`]
/// (or the profile loader), so the pattern is always restricted syntax, bounded in
/// complexity, never empty-matching and compiled.
#[derive(Clone)]
pub struct CustomDetectorDefinition {
    id: String,
    description: Option<String>,
    pattern: String,
    canonical_pattern: String,
    ignore_case: bool,
    whole_word: bool,
    action: PrivacyAction,
    regex: Regex,
}

impl fmt::Debug for CustomDetectorDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomDetectorDefinition")
            .field("id", &self.id)
            .field("canonical_pattern", &self.canonical_pattern)
            .field("ignore_case", &self.ignore_case)
            .field("whole_word", &self.whole_word)
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CustomDetectorDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.description == other.description
            && self.pattern == other.pattern
            && self.canonical_pattern == other.canonical_pattern
            && self.ignore_case == other.ignore_case
            && self.whole_word == other.whole_word
            && self.action == other.action
    }
}

impl Eq for CustomDetectorDefinition {}

impl CustomDetectorDefinition {
    /// Validates and compiles a custom detector. Error messages are safe to show.
    pub fn create(
        id: &str,
        pattern: &str,
        action: PrivacyAction,
        ignore_case: bool,
        whole_word: bool,
        description: Option<&str>,
    ) -> Result<Self, PrivacyError> {
        require_valid_id(Some(id))?;
        require_valid_description(id, description)?;
        let (canonical, regex) = compile_pattern(id, Some(pattern), ignore_case, whole_word)?;
        require_redacting_action(id, action)?;
        Ok(Self::from_validated(
            id,
            description,
            pattern,
            canonical,
            regex,
            ignore_case,
            whole_word,
            action,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_validated(
        id: &str,
        description: Option<&str>,
        pattern: &str,
        canonical_pattern: String,
        regex: Regex,
        ignore_case: bool,
        whole_word: bool,
        action: PrivacyAction,
    ) -> Self {
        Self {
            id: id.to_owned(),
            description: description.map(str::to_owned),
            pattern: pattern.to_owned(),
            canonical_pattern,
            ignore_case,
            whole_word,
            action,
            regex,
        }
    }

    /// Stable id, `custom.<name>`.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Pattern as written in the profile.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Translated pattern that is compiled (identical in the C# engine).
    pub fn canonical_pattern(&self) -> &str {
        &self.canonical_pattern
    }

    pub fn ignore_case(&self) -> bool {
        self.ignore_case
    }

    /// Keep only matches not adjacent to an ASCII word character.
    pub fn whole_word(&self) -> bool {
        self.whole_word
    }

    pub fn action(&self) -> PrivacyAction {
        self.action
    }
}

/// `^custom\.[a-z0-9]+(-[a-z0-9]+)*$`, at most 64 characters.
pub fn is_valid_id(id: &str) -> bool {
    let Some(name) = id.strip_prefix("custom.") else {
        return false;
    };
    id.len() <= MAXIMUM_ID_LENGTH
        && !name.is_empty()
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

pub(crate) fn require_valid_id(id: Option<&str>) -> Result<(), PrivacyError> {
    match id {
        Some(id) if is_valid_id(id) => Ok(()),
        other => Err(invalid(format!(
            "Custom detector id '{}' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters).",
            other.unwrap_or_default()
        ))),
    }
}

pub(crate) fn require_valid_description(
    id: &str,
    description: Option<&str>,
) -> Result<(), PrivacyError> {
    match description {
        Some(text) if utf16_len(text) > MAXIMUM_DESCRIPTION_LENGTH => Err(invalid(format!(
            "Custom detector '{id}' description must be at most 256 characters."
        ))),
        _ => Ok(()),
    }
}

/// `allow` would let a custom detector's span hide other detectors' matches;
/// `alert-only` records matches without redacting.
pub(crate) fn require_redacting_action(
    id: &str,
    action: PrivacyAction,
) -> Result<(), PrivacyError> {
    if action == PrivacyAction::Allow {
        return Err(invalid(format!(
            "Custom detector '{id}' cannot use action allow; use alert-only to record matches without redacting."
        )));
    }
    Ok(())
}

/// The canonical pattern actually compiled. With `whole_word` the translated pattern sits
/// between two non-word characters (`[^0-9A-Z_a-z](?:P)[^0-9A-Z_a-z]`) and runs over the
/// text wrapped in [`custom_pattern::WHOLE_WORD_SENTINEL`], exactly like C#.
pub(crate) fn compile_pattern(
    id: &str,
    pattern: Option<&str>,
    ignore_case: bool,
    whole_word: bool,
) -> Result<(String, Regex), PrivacyError> {
    let pattern = match pattern {
        Some(pattern) if (1..=MAXIMUM_PATTERN_LENGTH).contains(&utf16_len(pattern)) => pattern,
        _ => {
            return Err(invalid(format!(
                "Custom detector '{id}' pattern must be 1-512 characters."
            )));
        }
    };

    let translation =
        custom_pattern::translate_with(pattern, ignore_case, whole_word).map_err(|error| {
            invalid(format!(
                "Custom detector '{id}' pattern has unsupported syntax at position {}: {}.",
                error.position, error.reason
            ))
        })?;
    let too_complex = || invalid(format!("Custom detector '{id}' pattern is too complex."));
    if translation.complexity > MAXIMUM_COMPLEXITY {
        return Err(too_complex());
    }

    if translation.matches_empty {
        return Err(invalid(format!(
            "Custom detector '{id}' pattern must not match an empty string."
        )));
    }

    let canonical = if whole_word {
        format!(
            "{WHOLE_WORD_PREFIX}{}{WHOLE_WORD_SUFFIX}",
            translation.canonical_pattern
        )
    } else {
        translation.canonical_pattern
    };
    let regex = RegexBuilder::new(&canonical)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map_err(|_| too_complex())?;
    Ok((canonical, regex))
}

/// Value detector for a custom detector (`CustomPatternDetector`). `wholeWord` is part of
/// the compiled pattern (an ASCII boundary on both ends); a match whose start or end falls
/// inside a UTF-16 surrogate pair is widened to the whole pair, exactly like C#.
pub struct CustomPatternDetector {
    definition: CustomDetectorDefinition,
}

impl CustomPatternDetector {
    pub fn new(definition: CustomDetectorDefinition) -> Self {
        Self { definition }
    }

    pub fn definition(&self) -> &CustomDetectorDefinition {
        &self.definition
    }

    /// True when this detector alone finds at least one match (profile tests).
    pub fn matches(&self, sample: &str) -> bool {
        let mut found = Vec::new();
        self.detect(&ScanText::new(sample), "$", &mut found);
        !found.is_empty()
    }
}

impl CustomPatternDetector {
    /// Appends at most `limit` matches. Returns false (having stopped scanning) when the
    /// text holds more (`CustomPatternDetector.Detect(text, matches, limit)`).
    pub fn detect_bounded(
        &self,
        text: &ScanText<'_>,
        matches: &mut Vec<DetectionMatch>,
        limit: usize,
    ) -> bool {
        if text.is_empty() {
            return true;
        }

        let (haystack, offsets) = text.utf16_haystack();
        let mut found = 0usize;
        let mut add = |start: usize, end: usize| {
            let (start, end) = widen(offsets, start, end);
            matches.push(text.detection(
                &self.definition.id,
                categories::CUSTOM,
                Span { start, end },
                true,
                None,
            ));
        };

        let regex = &self.definition.regex;
        if !self.definition.whole_word {
            for candidate in regex.find_iter(haystack) {
                found += 1;
                if found > limit {
                    return false;
                }
                add(candidate.start(), candidate.end());
            }
            return true;
        }

        // The haystack is wrapped in the sentinel, so every match is one boundary character,
        // the redacted span, then one boundary character. The next search starts at the
        // span's last character, so a non-word last character can be the leading boundary
        // of an adjacent match.
        let sentinel = custom_pattern::WHOLE_WORD_SENTINEL;
        let width = sentinel.len_utf8();
        let wrapped = format!("{sentinel}{haystack}{sentinel}");
        let mut start = 0usize;
        while start < wrapped.len() {
            let Some(candidate) = regex.find_at(&wrapped, start) else {
                break;
            };
            found += 1;
            if found > limit {
                return false;
            }

            let first = candidate.as_str().chars().next().map_or(0, char::len_utf8);
            let last = candidate
                .as_str()
                .chars()
                .next_back()
                .map_or(0, char::len_utf8);
            // Wrapped offsets of the span, then haystack offsets (shifted by the sentinel).
            let span_start = candidate.start() + first;
            let span_end = candidate.end() - last;
            add(span_start - width, span_end - width);
            start = wrapped[..span_end]
                .chars()
                .next_back()
                .map_or(span_end, |character| span_end - character.len_utf8());
        }
        true
    }
}

/// Maps a haystack span back to the text, widening an end that falls between the two
/// stand-ins of a surrogate pair outward to the whole character.
fn widen(offsets: Option<&[usize]>, start: usize, end: usize) -> (usize, usize) {
    let Some(offsets) = offsets else {
        return (start, end);
    };
    let stand_in = super::SURROGATE_STAND_IN.len_utf8();
    let start = match offsets[start] {
        super::INSIDE_PAIR => offsets[start - stand_in],
        offset => offset,
    };
    let end = match offsets[end] {
        super::INSIDE_PAIR => offsets[end + stand_in],
        offset => offset,
    };
    (start, end)
}

impl SensitiveDetector for CustomPatternDetector {
    fn id(&self) -> &str {
        &self.definition.id
    }

    fn category(&self) -> &str {
        categories::CUSTOM
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        self.detect_bounded(text, matches, usize::MAX);
    }

    fn as_custom(&self) -> Option<&CustomPatternDetector> {
        Some(self)
    }
}

/// Adds a privacy profile's secret field names to an existing field-name detector
/// (`CompositeFieldNameDetector`): same id, category and action resolution.
pub struct CompositeFieldNameDetector {
    inner: Box<dyn FieldNameDetector>,
    names: HashSet<String>,
}

impl CompositeFieldNameDetector {
    /// `normalized_names` are already normalised with
    /// [`crate::text::normalize_field_name`].
    pub fn new(inner: Box<dyn FieldNameDetector>, normalized_names: &[String]) -> Self {
        Self {
            inner,
            names: normalized_names.iter().cloned().collect(),
        }
    }
}

impl FieldNameDetector for CompositeFieldNameDetector {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn category(&self) -> &str {
        self.inner.category()
    }

    fn matches_field_name(&self, normalized_field_name: &str) -> bool {
        (!normalized_field_name.is_empty() && self.names.contains(normalized_field_name))
            || self.inner.matches_field_name(normalized_field_name)
    }
}
