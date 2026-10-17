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

/// `value[..2] + new string('*', value.Length - 4) + value[^2..]` with C# UTF-16
/// slicing; values of four units or fewer become `****`.
pub fn mask_generic(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    if units.len() <= 4 {
        return "****".to_owned();
    }

    let mut masked = Vec::with_capacity(units.len());
    masked.extend_from_slice(&units[..2]);
    masked.extend(std::iter::repeat_n(u16::from(b'*'), units.len() - 4));
    masked.extend_from_slice(&units[units.len() - 2..]);
    from_utf16_lossy(&masked)
}

/// Email mask: `value[0] + "***" + value[at..]` when `@` is after the first unit.
pub fn mask_email(value: &str) -> Option<String> {
    let units: Vec<u16> = value.encode_utf16().collect();
    let at = units.iter().position(|unit| *unit == u16::from(b'@'))?;
    if at == 0 {
        return None;
    }

    let mut masked = Vec::with_capacity(units.len() + 3);
    masked.push(units[0]);
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
        assert_eq!(mask_generic("a\u{1F600}bc"), "a\u{FFFD}*bc");
        assert_eq!(mask_generic("abcd"), "****");
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
