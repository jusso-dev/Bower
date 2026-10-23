//! Pluggable sensitive-data detectors. Runtime stays deterministic: compiled
//! patterns, checksums and structure only.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::policy::PrivacyPolicy;
use crate::text::{AsciiProxy, ProxyBytes, regex_haystack, utf16_len};

pub mod australian;
pub mod classification;
pub mod crypto;
pub mod custom;
pub mod field_name;
pub mod financial;
pub mod identity;
pub mod secrets;

pub use custom::{CompositeFieldNameDetector, CustomDetectorDefinition, CustomPatternDetector};
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
            // Invalid offsets never panic here; the engine rejects them (fail closed).
            length_utf16: text.get(start..end).map_or(0, utf16_len),
            validated,
            sub_kind,
        }
    }
}

/// Byte range of a match in [`ScanText::text`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Capture groups of one match, as [`Span`]s in [`ScanText::text`].
pub struct Groups<'s> {
    captures: Captures<'s>,
    offsets: Option<&'s [usize]>,
}

impl Groups<'_> {
    pub fn get(&self, index: usize) -> Option<Span> {
        self.captures
            .get(index)
            .map(|found| map_span(self.offsets, found.start(), found.end()))
    }
}

/// Maps a match in the searched text back to the haystack (identity unless the
/// search ran over an [`AsciiProxy`]).
fn map_span(offsets: Option<&[usize]>, start: usize, end: usize) -> Span {
    match offsets {
        Some(offsets) => Span {
            start: offsets[start],
            end: offsets[end],
        },
        None => Span { start, end },
    }
}

/// A detector regex plus the ASCII stand-ins it accepts (see
/// [`crate::text::AsciiProxy`]). `proxy` is `None` for patterns that mention `_` in a
/// literal or class: no ASCII byte then stands in for non-ASCII word characters, so
/// they always scan the Unicode haystack.
pub struct Pattern {
    regex: Regex,
    proxy: Option<ProxyBytes>,
}

impl Pattern {
    /// A custom detector pattern; it always scans the Unicode haystack.
    pub fn new(regex: Regex) -> Self {
        Self { regex, proxy: None }
    }

    pub fn regex(&self) -> &Regex {
        &self.regex
    }
}

/// Text handed to detectors: the original value plus a regex haystack with
/// .NET-equivalent character classes (see [`crate::text::regex_haystack`]).
/// Both have identical byte offsets.
pub struct ScanText<'a> {
    text: &'a str,
    haystack: Cow<'a, str>,
    ascii: bool,
    proxy: OnceCell<Option<AsciiProxy>>,
    /// Proxy texts per stand-in variant, built on first use (see [`proxy_slot`]).
    proxy_texts: [OnceCell<String>; PROXY_SLOTS],
    /// UTF-16 unit haystack for custom detectors, built on first use (see
    /// [`ScanText::utf16_haystack`]); `None` when the text is all BMP.
    utf16: OnceCell<Option<(String, Vec<usize>)>>,
}

/// Offset map entry for the position between the two stand-ins of a surrogate pair.
pub(crate) const INSIDE_PAIR: usize = usize::MAX;

/// Stand-in for each UTF-16 surrogate of a supplementary character. Custom detector
/// patterns can never contain it and character ranges never reach it, so like a .NET
/// surrogate unit it only matches negated classes and `.`.
const SURROGATE_STAND_IN: char = '\u{FFFF}';

/// Replaces each supplementary character by two [`SURROGATE_STAND_IN`]s and maps every
/// haystack byte offset back to the text ([`INSIDE_PAIR`] between the two).
fn build_utf16_haystack(text: &str) -> (String, Vec<usize>) {
    let mut haystack = String::with_capacity(text.len() + text.len() / 2);
    let mut offsets = Vec::with_capacity(text.len() + text.len() / 2 + 1);
    for (offset, character) in text.char_indices() {
        if character.len_utf16() == 2 {
            offsets.push(offset);
            offsets.extend(std::iter::repeat_n(0, SURROGATE_STAND_IN.len_utf8() - 1));
            offsets.push(INSIDE_PAIR);
            offsets.extend(std::iter::repeat_n(0, SURROGATE_STAND_IN.len_utf8() - 1));
            haystack.push(SURROGATE_STAND_IN);
            haystack.push(SURROGATE_STAND_IN);
        } else {
            offsets.push(offset);
            offsets.extend(std::iter::repeat_n(0, character.len_utf8() - 1));
            haystack.push(character);
        }
    }
    offsets.push(text.len());
    (haystack, offsets)
}

/// Digit stand-ins (absent, `9`, `0`, `_`) times Kelvin stand-ins (absent, `k`, `_`).
const PROXY_SLOTS: usize = 12;

fn proxy_slot((digit, kelvin): (u8, u8)) -> Option<usize> {
    let digit = match digit {
        0 => 0,
        b'9' => 1,
        b'0' => 2,
        b'_' => 3,
        _ => return None,
    };
    let kelvin = match kelvin {
        0 => 0,
        b'k' => 1,
        b'_' => 2,
        _ => return None,
    };
    Some(digit * 3 + kelvin)
}

impl<'a> ScanText<'a> {
    pub fn new(text: &'a str) -> Self {
        Self {
            text,
            haystack: regex_haystack(text),
            ascii: text.is_ascii(),
            proxy: OnceCell::new(),
            proxy_texts: Default::default(),
            utf16: OnceCell::new(),
        }
    }

    /// Text for custom detector patterns, which see UTF-16 units like .NET: the text
    /// itself when it is all BMP, otherwise a haystack with two stand-ins per
    /// supplementary character plus the map from its byte offsets to the text's (entries
    /// at non-boundaries are unused).
    pub(crate) fn utf16_haystack(&self) -> (&str, Option<&[usize]>) {
        // Supplementary characters are the only four-byte UTF-8 sequences.
        let built = self.utf16.get_or_init(|| {
            self.text
                .bytes()
                .any(|byte| byte >= 0xF0)
                .then(|| build_utf16_haystack(self.text))
        });
        match built {
            Some((haystack, offsets)) => (haystack, Some(offsets)),
            None => (self.text, None),
        }
    }

    /// Text to search with `pattern` and the map back to haystack offsets: the ASCII
    /// proxy when the haystack is non-ASCII and the pattern has stand-ins for every
    /// class present, otherwise the haystack itself (ASCII text already is fast).
    fn search_text(&self, pattern: &Pattern) -> (&str, Option<&[usize]>) {
        let unicode = (&*self.haystack, None);
        let Some(bytes) = pattern.proxy else {
            return unicode;
        };
        if self.ascii {
            return unicode;
        }

        let Some(proxy) = self.proxy.get_or_init(|| AsciiProxy::new(&self.haystack)) else {
            return unicode;
        };
        let Some(variant) = proxy.variant(bytes) else {
            return unicode;
        };
        let Some(slot) = proxy_slot(variant) else {
            return unicode;
        };
        let text = self.proxy_texts[slot].get_or_init(|| proxy.text(variant));
        (text, Some(proxy.offsets()))
    }

    /// Iterates whole matches with .NET semantics.
    pub fn find_iter<'s>(&'s self, pattern: &'s Pattern) -> impl Iterator<Item = Span> + 's {
        let (searched, offsets) = self.search_text(pattern);
        pattern
            .regex
            .find_iter(searched)
            .map(move |found| map_span(offsets, found.start(), found.end()))
    }

    /// Iterates matches and their capture groups with .NET semantics.
    pub fn captures<'s>(&'s self, pattern: &'s Pattern) -> impl Iterator<Item = Groups<'s>> + 's {
        let (searched, offsets) = self.search_text(pattern);
        pattern
            .regex
            .captures_iter(searched)
            .map(move |captures| Groups { captures, offsets })
    }

    /// Like [`ScanText::captures`] but always over the Unicode haystack (tests compare
    /// both paths).
    #[cfg(test)]
    fn captures_unicode<'s>(
        &'s self,
        pattern: &'s Pattern,
    ) -> impl Iterator<Item = Groups<'s>> + 's {
        pattern
            .regex
            .captures_iter(&self.haystack)
            .map(|captures| Groups {
                captures,
                offsets: None,
            })
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

    /// Original text of a match.
    pub fn slice(&self, found: Span) -> &'a str {
        &self.text[found.start..found.end]
    }

    pub fn detection(
        &self,
        detector_id: &str,
        category: &str,
        found: Span,
        validated: bool,
        sub_kind: Option<String>,
    ) -> DetectionMatch {
        DetectionMatch::new(
            detector_id,
            category,
            self.text,
            found.start,
            found.end,
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

/// Compiles a pattern that is known valid at build time and always scans the Unicode
/// haystack.
pub(crate) fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|error| panic!("detector pattern is invalid: {error}"))
}

/// A pattern that always scans the Unicode haystack (it mentions `_`).
pub(crate) fn unicode_only(pattern: &str) -> Pattern {
    Pattern {
        regex: compile(pattern),
        proxy: None,
    }
}

/// A pattern that may scan the ASCII proxy with these stand-ins. Requirements, checked
/// by hand for each caller and by the differential test below: the pattern never
/// mentions `_` (not in a literal, class or range) and has no non-ASCII literal;
/// `digit` is `_` when the pattern has no `\d`, otherwise an ASCII digit used by no
/// literal, class or range, or `None` if every digit is used; `kelvin` is `k` when the
/// whole pattern is `(?i)`, otherwise `_`.
pub(crate) fn proxied(pattern: &str, digit: Option<u8>, kelvin: u8) -> Pattern {
    Pattern {
        regex: compile(pattern),
        proxy: Some(ProxyBytes { digit, kelvin }),
    }
}

/// `RegexDetectorBase`: whole-match detector with optional validation and sub-kind.
pub struct RegexDetector {
    id: &'static str,
    category: &'static str,
    pattern: &'static LazyLock<Pattern>,
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
        pattern: &'static LazyLock<Pattern>,
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

        for found in text.find_iter(self.pattern) {
            let span = text.slice(found);
            if let Some(validate) = self.validate
                && !validate(span)
            {
                continue;
            }

            matches.push(text.detection(
                self.id,
                self.category,
                found,
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

/// Built-in value detectors followed by the policy's custom detectors, in definition
/// order (`DetectorCatalog.CreateValueDetectors`).
pub fn value_detectors_for(policy: &PrivacyPolicy) -> Vec<Box<dyn SensitiveDetector>> {
    let mut detectors = default_value_detectors();
    detectors.extend(policy.custom_detectors.iter().map(|definition| {
        Box::new(CustomPatternDetector::new(definition.clone())) as Box<dyn SensitiveDetector>
    }));
    detectors
}

/// The built-in field-name detector extended with the policy's secret field names
/// (`DetectorCatalog.CreateFieldNameDetector`).
pub fn field_name_detector_for(policy: &PrivacyPolicy) -> Box<dyn FieldNameDetector> {
    if policy.secret_field_names.is_empty() {
        default_field_name_detector()
    } else {
        Box::new(CompositeFieldNameDetector::new(
            default_field_name_detector(),
            &policy.secret_field_names,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_patterns() -> Vec<(&'static str, &'static Pattern)> {
        [
            australian::patterns(),
            financial::patterns(),
            identity::patterns(),
            secrets::patterns(),
            crypto::patterns(),
            classification::patterns(),
        ]
        .concat()
    }

    /// Fragments covering every class the proxy distinguishes: ASCII stand-in bytes
    /// themselves, digits each pattern names, keywords and literals, non-ASCII letters,
    /// digits (BMP and supplementary), whitespace, joiners, marks, the Kelvin sign and
    /// long s, symbols and surrogate pairs.
    const FRAGMENTS: &[&str] = &[
        "a",
        "Z",
        "k",
        "K",
        "s",
        "S",
        "x",
        "e",
        "_",
        "0",
        "1",
        "2",
        "5",
        "9",
        " ",
        "  ",
        "-",
        ":",
        "#",
        ".",
        "/",
        "@",
        "=",
        ";",
        "+",
        "'",
        "\"",
        "{",
        "}",
        "%",
        "\n",
        "\t",
        "\u{B}",
        "\u{C}",
        "\u{1}",
        "TFN ",
        "CRN ",
        "DVA ",
        "PayID: ",
        "passport ",
        "account ",
        " Street",
        "DOB: ",
        "born ",
        "sk-",
        "xoxb-",
        "SK",
        "mongodb://",
        "Bearer ",
        "-----BEGIN ",
        "RSA PRIVATE KEY-----",
        "-----END ",
        "PGP PUBLIC KEY BLOCK-----",
        "docker login",
        "registry ",
        "password=",
        "Server=",
        ";Pwd=",
        "sv=2020-01-01",
        "&sig=",
        "AccountKey=",
        "OFFICIAL",
        "TOP SECRET",
        ".com",
        ".internal",
        "192.168.1.1",
        "123",
        "456 789",
        "4111111111111111",
        "GB82WEST12345698765432",
        "DEUTDEFF",
        "+61412345678",
        "800360",
        "0123456789abcdef",
        "abcdefghijklmnopqrst",
        "-33.8688, 151.2093",
        "username: ",
        "\u{E9}",
        "\u{5B57}",
        "\u{661}",
        "\u{663}",
        "\u{FF10}",
        "\u{FF21}",
        "\u{212A}",
        "\u{17F}",
        "\u{DF}",
        "\u{131}",
        "\u{130}",
        "\u{B5}",
        "\u{A0}",
        "\u{3000}",
        "\u{2028}",
        "\u{85}",
        "\u{200C}",
        "\u{200D}",
        "\u{93E}",
        "\u{488}",
        "\u{2160}",
        "\u{24B6}",
        "\u{20AC}",
        "\u{1F600}",
        "\u{1D400}",
        "\u{1D7CE}",
    ];

    fn spans(groups: Groups<'_>) -> Vec<Option<Span>> {
        (0..groups.captures.len())
            .map(|index| groups.get(index))
            .collect()
    }

    /// The ASCII proxy must find exactly the matches and groups the Unicode haystack
    /// finds, for every proxied pattern.
    #[test]
    fn ascii_proxy_matches_unicode_haystack_exactly() {
        let patterns: Vec<_> = all_patterns()
            .into_iter()
            .filter(|(_, pattern)| pattern.proxy.is_some())
            .collect();
        assert!(patterns.len() >= 25, "proxied patterns: {}", patterns.len());

        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % bound as u64).expect("bound fits usize")
        };
        let mut proxied_searches = 0;
        for _ in 0..4_000 {
            let mut text = String::new();
            for _ in 0..1 + next(24) {
                text.push_str(FRAGMENTS[next(FRAGMENTS.len())]);
            }
            let scan = ScanText::new(&text);
            for (name, pattern) in &patterns {
                let fast: Vec<_> = scan.captures(pattern).map(spans).collect();
                let unicode: Vec<_> = scan.captures_unicode(pattern).map(spans).collect();
                assert_eq!(fast, unicode, "{name} on {text:?}");
                let whole: Vec<_> = scan.find_iter(pattern).map(Some).collect();
                let unicode_whole: Vec<_> = unicode.iter().map(|groups| groups[0]).collect();
                assert_eq!(whole, unicode_whole, "{name} find_iter on {text:?}");
                if !scan.ascii && scan.search_text(pattern).1.is_some() {
                    proxied_searches += 1;
                }
            }
        }
        assert!(
            proxied_searches > 10_000,
            "proxy used {proxied_searches} times"
        );
    }

    #[test]
    fn proxy_falls_back_when_a_digit_has_no_stand_in() {
        let iban = financial::patterns()
            .into_iter()
            .find(|(name, _)| *name == "IBAN")
            .map(|(_, pattern)| pattern)
            .expect("IBAN pattern");
        let with_digit = ScanText::new("GB82WEST1234569876543\u{661} \u{E9}");
        assert!(with_digit.search_text(iban).1.is_none());
        let without_digit = ScanText::new("GB82WEST12345698765432 \u{E9}");
        assert!(without_digit.search_text(iban).1.is_some());
        assert_eq!(
            without_digit.find_iter(iban).collect::<Vec<_>>(),
            [Span { start: 0, end: 22 }]
        );
    }

    #[test]
    fn proxy_maps_offsets_back_to_the_original_text() {
        let text = "\u{E9}\u{1F600} TFN 123 456 782 \u{5B57}";
        let scan = ScanText::new(text);
        let tfn = australian::patterns()
            .into_iter()
            .find(|(name, _)| *name == "TFN")
            .map(|(_, pattern)| pattern)
            .expect("TFN pattern");
        let groups: Vec<_> = scan.captures(tfn).collect();
        assert_eq!(groups.len(), 1);
        let digits = groups[0].get(1).expect("digits group");
        assert_eq!(scan.slice(digits), "123 456 782");
    }
}
