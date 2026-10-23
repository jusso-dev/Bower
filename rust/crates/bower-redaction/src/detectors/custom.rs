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
        let (canonical, regex) = compile_pattern(id, Some(pattern), ignore_case)?;
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

pub(crate) fn compile_pattern(
    id: &str,
    pattern: Option<&str>,
    ignore_case: bool,
) -> Result<(String, Regex), PrivacyError> {
    let pattern = match pattern {
        Some(pattern) if (1..=MAXIMUM_PATTERN_LENGTH).contains(&utf16_len(pattern)) => pattern,
        _ => {
            return Err(invalid(format!(
                "Custom detector '{id}' pattern must be 1-512 characters."
            )));
        }
    };

    let translation = custom_pattern::translate(pattern, ignore_case).map_err(|error| {
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

    let regex = RegexBuilder::new(&translation.canonical_pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map_err(|_| too_complex())?;
    Ok((translation.canonical_pattern, regex))
}

/// Value detector for a custom detector (`CustomPatternDetector`). Matches that would
/// split a UTF-16 surrogate pair are skipped in both engines (Rust strings cannot hold
/// half a pair), as are, with `wholeWord`, matches next to an ASCII word character.
/// Skipped matches do not stop the scan.
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

fn is_ascii_word(character: Option<char>) -> bool {
    character.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl SensitiveDetector for CustomPatternDetector {
    fn id(&self) -> &str {
        &self.definition.id
    }

    fn category(&self) -> &str {
        categories::CUSTOM
    }

    fn detect(&self, text: &ScanText<'_>, _path: &str, matches: &mut Vec<DetectionMatch>) {
        if text.is_empty() {
            return;
        }

        let (haystack, offsets) = text.utf16_haystack();
        let original = text.text();
        for found in self.definition.regex.find_iter(haystack) {
            let (start, end) = match offsets {
                Some(offsets) => (offsets[found.start()], offsets[found.end()]),
                None => (found.start(), found.end()),
            };
            // Inside a surrogate pair (between its two stand-ins).
            if start == super::INSIDE_PAIR || end == super::INSIDE_PAIR || start == end {
                continue;
            }

            if self.definition.whole_word
                && (is_ascii_word(original[..start].chars().next_back())
                    || is_ascii_word(original[end..].chars().next()))
            {
                continue;
            }

            matches.push(text.detection(
                &self.definition.id,
                categories::CUSTOM,
                Span { start, end },
                true,
                None,
            ));
        }
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
