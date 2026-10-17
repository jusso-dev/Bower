//! `YamlDotNet` scalar conversions for the value types a policy uses.
//!
//! Integers follow `ScalarNodeDeserializer.DeserializeIntegerHelper`: an
//! optional sign, then `0b` binary, `0x` hex, `0…` octal, or decimal with
//! base-60 `:` chunks; `_` separators are dropped. Booleans accept
//! `true|y|yes|on` and `false|n|no|off`, case-insensitively.

use chrono::NaiveDate;

/// `NumberStyles` white space: U+0009–U+000D and U+0020.
fn is_number_white(character: char) -> bool {
    matches!(character, '\u{9}'..='\u{d}' | ' ')
}

/// .NET number parsing trims leading white space and trailing white space or
/// NUL characters.
fn trim_number(text: &str) -> &str {
    text.trim_start_matches(is_number_white)
        .trim_end_matches(|character| is_number_white(character) || character == '\0')
}

/// `ulong.Parse(text)` with `NumberStyles.Integer`.
fn parse_dotnet_u64(text: &str) -> Option<u64> {
    let text = trim_number(text);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: u64 = digits.bytes().try_fold(0u64, |value, byte| {
        value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
    })?;
    // A negative sign is only valid for zero.
    if negative && value != 0 {
        return None;
    }
    Some(value)
}

/// `ulong.Parse(text, NumberStyles.HexNumber)`.
fn parse_dotnet_hex(text: &str) -> Option<u64> {
    let digits = trim_number(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    digits.bytes().try_fold(0u64, |value, byte| {
        let digit = char::from(byte).to_digit(16)?;
        value.checked_mul(16)?.checked_add(u64::from(digit))
    })
}

/// `Convert.ToUInt64(text, radix)` for radix 2 or 8: optional `+`, digits
/// only, no white space.
fn parse_dotnet_radix(text: &str, radix: u32) -> Option<u64> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() {
        return None;
    }
    digits.chars().try_fold(0u64, |value, character| {
        let digit = character.to_digit(radix)?;
        value
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))
    })
}

/// Converts a scalar to `Int32` exactly as `YamlDotNet` does; `None` where it
/// throws.
pub(crate) fn parse_int32(value: &str) -> Option<i32> {
    let chars: Vec<char> = value.chars().collect();
    let mut index = 0;
    let mut negative = false;
    match chars.first()? {
        '-' => {
            index = 1;
            negative = true;
        }
        '+' => index = 1,
        _ => {}
    }

    let result: u64 = if *chars.get(index)? == '0' {
        if index == chars.len() - 1 {
            0
        } else {
            index += 1;
            let radix = match chars[index] {
                'b' => {
                    index += 1;
                    2
                }
                'x' => {
                    index += 1;
                    16
                }
                _ => 8,
            };
            let digits: String = chars[index..].iter().filter(|c| **c != '_').collect();
            if radix == 16 {
                parse_dotnet_hex(&digits)?
            } else {
                parse_dotnet_radix(&digits, radix)?
            }
        }
    } else {
        let rest: String = chars[index..].iter().collect();
        // Unchecked ulong arithmetic in YamlDotNet.
        rest.split(':').try_fold(0u64, |result, chunk| {
            Some(
                result
                    .wrapping_mul(60)
                    .wrapping_add(parse_dotnet_u64(&chunk.replace('_', ""))?),
            )
        })?
    };

    if negative {
        // `-(long)result` in unchecked arithmetic; the `as` cast is the
        // intended two's-complement reinterpretation.
        #[allow(clippy::cast_possible_wrap)]
        let signed = (result as i64).wrapping_neg();
        i32::try_from(signed).ok()
    } else {
        i32::try_from(result).ok()
    }
}

/// Converts a scalar to `Boolean`. The C# patterns are anchored with `$`,
/// which also matches before one final line feed.
pub(crate) fn parse_bool(value: &str) -> Option<bool> {
    let text = value.strip_suffix('\n').unwrap_or(value);
    let any = |words: &[&str]| words.iter().any(|word| word.eq_ignore_ascii_case(text));
    if any(&["true", "y", "yes", "on"]) {
        Some(true)
    } else if any(&["false", "n", "no", "off"]) {
        Some(false)
    } else {
        None
    }
}

/// Converts a scalar to `DateOnly`. C# uses culture-sensitive
/// `DateOnly.Parse`; only the culture-invariant year-first forms
/// `yyyy-M-d` and `yyyy/M/d` are accepted here.
pub(crate) fn parse_date_only(value: &str) -> Option<NaiveDate> {
    let text = value.trim_matches(char::is_whitespace);
    let separator = if text.contains('-') { '-' } else { '/' };
    let mut parts = text.split(separator);
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || year.len() != 4
        || !(1..=2).contains(&month.len())
        || !(1..=2).contains(&day.len())
        || ![year, month, day]
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let year: i32 = year.parse().ok()?;
    if year < 1 {
        return None;
    }
    NaiveDate::from_ymd_opt(year, month.parse().ok()?, day.parse().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Outcomes observed from YamlDotNet 18.1.0 via `PolicyLoader` (None = the
    /// C# load failed with "Exception during deserialization").
    #[test]
    fn integers_match_yamldotnet() {
        let cases: &[(&str, Option<i32>)] = &[
            ("101", Some(101)),
            ("-1", Some(-1)),
            ("0", Some(0)),
            ("60", Some(60)),
            ("070", Some(56)),
            ("0x10", Some(16)),
            ("0b11", Some(3)),
            ("+5", Some(5)),
            ("1_0", Some(10)),
            ("1:30", Some(90)),
            ("70.0", None),
            ("1e2", None),
            ("", None),
            ("abc", None),
            (" 7 ", Some(7)),
            ("-0", Some(0)),
            ("2147483648", None),
            ("-2147483649", None),
            ("0o17", None),
            ("09", None),
            ("00", Some(0)),
            ("1.5", None),
            ("  ", None),
            ("0+7", Some(7)),
            ("1:-5", None),
            ("0b", None),
            ("0x1F", Some(31)),
            ("-0x1", Some(-1)),
            ("\t5", Some(5)),
            ("1_000_000_000_000", None),
            ("-2147483648", Some(i32::MIN)),
            ("0x", None),
            ("+-5", None),
            ("--0", Some(0)),
            ("0:1", None),
            ("1:0x", None),
            ("1:", None),
            ("08_", None),
            ("0 7", None),
            ("\u{a0}7", None),
            ("0x 1F ", Some(31)),
            ("07 ", None),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_int32(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn booleans_match_yamldotnet() {
        let cases: &[(&str, Option<bool>)] = &[
            ("yes", Some(true)),
            ("Y", Some(true)),
            ("on", Some(true)),
            ("ON", Some(true)),
            ("True", Some(true)),
            ("TRUE", Some(true)),
            ("1", None),
            ("true", Some(true)),
            ("no", Some(false)),
            ("off", Some(false)),
            ("False", Some(false)),
            ("nope", None),
            ("y", Some(true)),
            ("n", Some(false)),
            ("OFF", Some(false)),
            ("0", None),
            ("tRuE", Some(true)),
            (" true", None),
            ("maybe", None),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_bool(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn year_first_dates_parse() {
        let date = |y, m, d| NaiveDate::from_ymd_opt(y, m, d);
        assert_eq!(parse_date_only("2027-01-01"), date(2027, 1, 1));
        assert_eq!(parse_date_only("2027-1-1"), date(2027, 1, 1));
        assert_eq!(parse_date_only("2027/01/05"), date(2027, 1, 5));
        assert_eq!(parse_date_only("0001-01-01"), date(1, 1, 1));
        assert_eq!(parse_date_only("9999-12-31"), date(9999, 12, 31));
        assert_eq!(parse_date_only("2027-13-01"), None);
        assert_eq!(parse_date_only("2027-01-01T00:00:00Z"), None);
        assert_eq!(parse_date_only("2027-01-01 10:00"), None);
        assert_eq!(parse_date_only("20270105"), None);
        assert_eq!(parse_date_only("notadate"), None);
    }
}
