//! .NET string semantics the C# engine relies on.
//!
//! C# strings are UTF-16 and `System.Text.RegularExpressions` matches UTF-16 code
//! units. The Rust `regex` crate matches Unicode scalar values over UTF-8. The
//! helpers here reproduce the C# behaviour exactly where it is observable:
//! lengths, masking and truncation count UTF-16 units, and [`regex_haystack`]
//! rewrites text so Rust regexes see the same character classes as .NET.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;

/// Characters whose regex behaviour differs between .NET and Rust:
///
/// * any supplementary-plane character (.NET sees two surrogate code units, which
///   are never word characters, never `\d` and count as two for `{m,n}`);
/// * `U+017F` LATIN SMALL LETTER LONG S, which Rust's case-insensitive mode folds
///   to `s` but .NET (`IgnoreCase | CultureInvariant`) does not;
/// * BMP characters Rust treats as word characters for `\b` but .NET does not.
///   .NET's word class is `[\p{L}\p{Mn}\p{Nd}\p{Pc}]` plus ZWJ/ZWNJ for boundaries;
///   Rust adds `\p{Mc}`, `\p{Me}`, `\p{Nl}` and other `Alphabetic` characters.
static REGEX_REMAP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\x{10000}-\x{10FFFF}\x{17F}[\w--[\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]]]")
        .expect("remap pattern is valid")
});

/// `char.IsLetterOrDigit` for a single UTF-16 code unit: BMP letters and decimal digits.
static LETTER_OR_DIGIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\p{L}\p{Nd}]$").expect("letter-or-digit pattern is valid"));

/// Returns text for regex scanning with the same byte length and character
/// boundaries as `text`, in which every character matches the same .NET-equivalent
/// classes (`\b`, `\d`, `\s`, case-insensitive ASCII letters, negated classes and
/// UTF-16 repetition counts). Match offsets therefore apply to the original text.
pub fn regex_haystack(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        return Cow::Borrowed(text);
    }

    REGEX_REMAP.replace_all(text, |captures: &regex::Captures<'_>| {
        let found = &captures[0];
        match found.len() {
            // Two non-word, non-digit, non-space units: like a surrogate pair.
            4 => "\u{D7}\u{D7}",
            // Long s stays a letter (word character) without folding to ASCII.
            _ if found == "\u{17F}" => "\u{DF}",
            2 => "\u{D7}",
            _ => "\u{2022}",
        }
    })
}

/// Regex classes of a non-ASCII haystack character, as the Unicode-mode detector
/// patterns see it. Indexed by BMP code point (the haystack has no other characters).
const CLASS_OTHER: u8 = 0;
const CLASS_WORD: u8 = 1;
const CLASS_DIGIT: u8 = 2;
const CLASS_SPACE: u8 = 3;
const CLASS_KELVIN: u8 = 4;

static BMP_CLASSES: LazyLock<Box<[u8]>> = LazyLock::new(|| {
    let mut classes = vec![CLASS_OTHER; 0x1_0000].into_boxed_slice();
    let all: String = (0x80..0x1_0000).filter_map(char::from_u32).collect();
    // Later classes refine earlier ones: every `\d` is also `\w`.
    for (pattern, class) in [
        (r"\w+", CLASS_WORD),
        (r"\d+", CLASS_DIGIT),
        (r"\s+", CLASS_SPACE),
    ] {
        let regex = Regex::new(pattern).expect("class pattern is valid");
        for found in regex.find_iter(&all) {
            for character in found.as_str().chars() {
                classes[character as usize] = class;
            }
        }
    }
    classes['\u{212A}' as usize] = CLASS_KELVIN;
    classes
});

/// Placeholder bytes in [`AsciiProxy`] for classes whose stand-in depends on the
/// pattern. Never valid in the final (ASCII) proxy text.
const PLACEHOLDER_DIGIT: u8 = 0x80;
const PLACEHOLDER_KELVIN: u8 = 0x81;

/// An all-ASCII stand-in for a non-ASCII regex haystack: one byte per haystack
/// character (that is, per UTF-16 unit of the original text) plus the haystack byte
/// offset of each.
///
/// Rust's lazy DFA cannot evaluate a Unicode `\b` once it sees a non-ASCII byte, so on
/// non-ASCII text every `\b` pattern falls back to the much slower PikeVM over the rest
/// of the value. On ASCII text the DFA handles `\b` exactly. Each non-ASCII character
/// is replaced by an ASCII byte in exactly the same classes *for the pattern being
/// run*: `_` for word characters (a pattern using it must not mention `_`), `\x0C` for
/// whitespace, `\x01` for everything else, and a pattern-chosen byte for decimal digits
/// and the Kelvin sign (see [`ProxyBytes`]). The pattern then matches the same
/// character positions, which [`AsciiProxy::offsets`] maps back.
#[derive(Debug)]
pub(crate) struct AsciiProxy {
    bytes: Vec<u8>,
    offsets: Vec<usize>,
    has_digit: bool,
    has_kelvin: bool,
}

/// Stand-ins a pattern accepts for non-ASCII digits and the Kelvin sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProxyBytes {
    /// Byte matching exactly what a non-ASCII `\d` character matches in this pattern:
    /// an ASCII digit used by no literal or class (patterns with `\d`), `_` (patterns
    /// without `\d`), or `None` when no byte qualifies.
    pub digit: Option<u8>,
    /// `k` in `(?i)` patterns (Rust folds the Kelvin sign to `k`), otherwise `_`.
    pub kelvin: u8,
}

impl AsciiProxy {
    /// `None` when `haystack` holds a character outside the BMP (never produced by
    /// [`regex_haystack`]).
    pub(crate) fn new(haystack: &str) -> Option<Self> {
        let classes = &*BMP_CLASSES;
        let mut bytes = Vec::with_capacity(haystack.len());
        let mut offsets = Vec::with_capacity(haystack.len() + 1);
        let mut has_digit = false;
        let mut has_kelvin = false;
        for (offset, character) in haystack.char_indices() {
            offsets.push(offset);
            let byte = if character.is_ascii() {
                character as u8
            } else {
                match *classes.get(character as usize)? {
                    CLASS_WORD => b'_',
                    CLASS_DIGIT => {
                        has_digit = true;
                        PLACEHOLDER_DIGIT
                    }
                    CLASS_SPACE => 0x0C,
                    CLASS_KELVIN => {
                        has_kelvin = true;
                        PLACEHOLDER_KELVIN
                    }
                    _ => 0x01,
                }
            };
            bytes.push(byte);
        }
        offsets.push(haystack.len());
        Some(Self {
            bytes,
            offsets,
            has_digit,
            has_kelvin,
        })
    }

    /// Haystack byte offset of each proxy byte (and of the end).
    pub(crate) fn offsets(&self) -> &[usize] {
        &self.offsets
    }

    /// Variant key for `proxy`, or `None` when the text holds a non-ASCII digit the
    /// pattern cannot represent. Texts without digits or Kelvin signs share variant 0.
    pub(crate) fn variant(&self, proxy: ProxyBytes) -> Option<(u8, u8)> {
        let digit = if self.has_digit { proxy.digit? } else { 0 };
        let kelvin = if self.has_kelvin { proxy.kelvin } else { 0 };
        Some((digit, kelvin))
    }

    /// ASCII proxy text for a variant from [`AsciiProxy::variant`].
    pub(crate) fn text(&self, (digit, kelvin): (u8, u8)) -> String {
        self.bytes
            .iter()
            .map(|&byte| match byte {
                PLACEHOLDER_DIGIT => char::from(digit),
                PLACEHOLDER_KELVIN => char::from(kelvin),
                other => char::from(other),
            })
            .collect()
    }
}

/// Number of UTF-16 code units (`string.Length`).
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `string.Contains(value, StringComparison.OrdinalIgnoreCase)` for an ASCII needle.
/// .NET ordinal case-insensitivity never maps non-ASCII characters onto ASCII letters
/// (`ı`, `ſ` and the Kelvin sign do not match), so ASCII folding is exact.
pub fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// `string.Concat(value.Where(char.IsLetterOrDigit)).ToLowerInvariant()`.
///
/// Only membership against ASCII names is ever tested, so non-ASCII characters are
/// kept as-is: invariant lowercasing never turns them into ASCII except for the
/// Kelvin sign (U+212A to `k`). `İ` (U+0130) is left unchanged by .NET invariant casing.
pub fn normalize_field_name(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut buffer = [0u8; 4];
    for character in value.chars() {
        let is_letter_or_digit = if character.is_ascii() {
            character.is_ascii_alphanumeric()
        } else {
            character.len_utf16() == 1
                && LETTER_OR_DIGIT.is_match(character.encode_utf8(&mut buffer))
        };
        if !is_letter_or_digit {
            continue;
        }

        normalized.push(match character {
            '\u{212A}' => 'k',
            other => other.to_ascii_lowercase(),
        });
    }

    normalized
}

/// `char.IsWhiteSpace` (identical to the Unicode `White_Space` property).
pub fn is_dotnet_whitespace(character: char) -> bool {
    character.is_whitespace()
}

/// `string.IsNullOrWhiteSpace`.
pub fn is_null_or_whitespace(value: &str) -> bool {
    value.chars().all(is_dotnet_whitespace)
}

/// `StringComparer.Ordinal` comparison (UTF-16 code unit order).
pub fn compare_ordinal(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn is_high_surrogate(unit: u16) -> bool {
    (0xD800..0xDC00).contains(&unit)
}

/// Converts UTF-16 units to a string the way System.Text.Json writes them:
/// unpaired surrogates become U+FFFD.
pub fn from_utf16_lossy(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// `PolicyApplicator.Truncate`: keeps `max_length` UTF-16 units, never splitting a
/// surrogate pair. Returns `None` when no truncation is needed.
pub fn truncate_utf16(value: &str, max_length: usize) -> Option<String> {
    if utf16_len(value) <= max_length {
        return None;
    }

    let units: Vec<u16> = value.encode_utf16().collect();
    let mut cut = max_length;
    if cut > 0 && is_high_surrogate(units[cut - 1]) {
        cut -= 1;
    }

    Some(from_utf16_lossy(&units[..cut]))
}

fn is_low_surrogate(unit: u16) -> bool {
    (0xDC00..0xE000).contains(&unit)
}

/// `PolicyApplicator.Mask` generic form: keeps the first two and last two UTF-16 units
/// and stars the rest; values of four units or fewer become `****`. A kept prefix or
/// suffix that would end inside a surrogate pair shrinks by one unit, so the pair is
/// masked and the output never holds an unpaired surrogate (which C# would serialise as
/// U+FFFD, letting two different masks collide).
pub fn mask_generic(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    let length = units.len();
    if length <= 4 {
        return "****".to_owned();
    }

    let prefix = if is_high_surrogate(units[1]) { 1 } else { 2 };
    let suffix = if is_low_surrogate(units[length - 2]) {
        1
    } else {
        2
    };
    let mut masked = Vec::with_capacity(length);
    masked.extend_from_slice(&units[..prefix]);
    masked.extend(std::iter::repeat_n(
        u16::from(b'*'),
        length - prefix - suffix,
    ));
    masked.extend_from_slice(&units[length - suffix..]);
    from_utf16_lossy(&masked)
}

/// Email mask: first UTF-16 unit + `***` + `value[at..]` when `@` is after the first
/// unit. A leading surrogate pair is dropped rather than split.
pub fn mask_email(value: &str) -> Option<String> {
    let units: Vec<u16> = value.encode_utf16().collect();
    let at = units.iter().position(|unit| *unit == u16::from(b'@'))?;
    if at == 0 {
        return None;
    }

    let mut masked = Vec::with_capacity(units.len() + 3);
    if !is_high_surrogate(units[0]) {
        masked.push(units[0]);
    }
    masked.extend("***".encode_utf16());
    masked.extend_from_slice(&units[at..]);
    Some(from_utf16_lossy(&masked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haystack_preserves_byte_offsets() {
        for text in [
            "a\u{1F600}b",
            "\u{17F}x",
            "\u{93E}4",
            "\u{24B6}\u{2160}\u{488}",
            "é\u{200D}",
        ] {
            let haystack = regex_haystack(text);
            assert_eq!(haystack.len(), text.len());
            for (index, _) in text.char_indices() {
                assert!(haystack.is_char_boundary(index));
            }
        }
    }

    #[test]
    fn haystack_maps_classes_like_dotnet() {
        assert_eq!(regex_haystack("\u{1D400}"), "\u{D7}\u{D7}");
        assert_eq!(regex_haystack("\u{17F}"), "\u{DF}");
        assert_eq!(regex_haystack("\u{93E}"), "\u{2022}");
        assert_eq!(regex_haystack("\u{488}"), "\u{D7}");
        // .NET word characters are kept.
        assert_eq!(
            regex_haystack("é\u{200D}\u{212A}\u{661}"),
            "é\u{200D}\u{212A}\u{661}"
        );
    }

    #[test]
    fn normalizes_field_names_like_dotnet() {
        assert_eq!(
            normalize_field_name("AWS_SECRET_ACCESS_KEY"),
            "awssecretaccesskey"
        );
        assert_eq!(normalize_field_name("pass\u{93E}word"), "password");
        assert_eq!(normalize_field_name("to\u{212A}en"), "token");
        assert_eq!(normalize_field_name("pass\u{1D400}word"), "password");
        assert_eq!(normalize_field_name("pass\u{130}word"), "pass\u{130}word");
        assert_eq!(normalize_field_name("PASS\u{2160}WORD"), "password");
    }

    #[test]
    fn masks_and_truncates_in_utf16_units() {
        // Never splits a surrogate pair at either end.
        assert_eq!(mask_generic("a\u{1F600}bc"), "a**bc");
        assert_eq!(mask_generic("ab\u{1F600}c"), "ab**c");
        assert_eq!(mask_generic("abcd\u{1F600}"), "ab**\u{1F600}");
        assert_eq!(mask_generic("\u{1F600}abc"), "\u{1F600}*bc");
        assert_eq!(mask_generic("\u{1F600}\u{1F600}x"), "\u{1F600}**x");
        assert_eq!(mask_generic("abcd"), "****");
        assert_eq!(
            mask_email("\u{1F600}x@example.test").as_deref(),
            Some("***@example.test")
        );
        assert_eq!(
            mask_email("alice@example.test").as_deref(),
            Some("a***@example.test")
        );
        assert_eq!(mask_email("@x"), None);
        assert_eq!(truncate_utf16("ab\u{1F600}", 3).as_deref(), Some("ab"));
        assert_eq!(truncate_utf16("abc", 3), None);
    }

    #[test]
    fn ordinal_compare_uses_utf16_order() {
        assert_eq!(compare_ordinal("\u{FF61}", "\u{10000}"), Ordering::Greater);
        assert_eq!(compare_ordinal("a", "b"), Ordering::Less);
    }
}
