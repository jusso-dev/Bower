//! Canonical scalars for the policy value types (`StrictScalarYamlConverter`
//! in `PolicyYaml.cs`).
//!
//! `YamlDotNet`'s defaults follow YAML 1.1 (`yes`/`on`/`y` booleans, `070`
//! read as octal 56, hex, binary, base-60 and `_`-separated integers) and C#
//! `DateOnly.Parse` accepts locale-shaped dates, so the C# loader replaces
//! them with the YAML 1.2 JSON-schema forms only: `true`/`false`, decimal
//! integers without a leading zero or `+`, and ISO 8601 `yyyy-MM-dd` dates.
//! The checks apply to the scalar text whatever its quoting style.

use chrono::NaiveDate;

/// `-?(0|[1-9][0-9]*)` within `i32` range.
pub(crate) fn parse_int32(value: &str) -> Option<i32> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    let canonical = !digits.is_empty()
        && (!digits.starts_with('0') || digits.len() == 1)
        && digits.bytes().all(|byte| byte.is_ascii_digit());
    if canonical { value.parse().ok() } else { None }
}

/// Exactly `true` or `false`.
pub(crate) fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Exactly `yyyy-MM-dd`: four-digit year (0001–9999), two-digit month and day.
pub(crate) fn parse_date_only(value: &str) -> Option<NaiveDate> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !shaped {
        return None;
    }
    let year: i32 = value[0..4].parse().ok()?;
    if year < 1 {
        return None;
    }
    NaiveDate::from_ymd_opt(year, value[5..7].parse().ok()?, value[8..10].parse().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_canonical_decimal_only() {
        let cases: &[(&str, Option<i32>)] = &[
            ("101", Some(101)),
            ("-1", Some(-1)),
            ("0", Some(0)),
            ("-0", Some(0)),
            ("60", Some(60)),
            ("2147483647", Some(i32::MAX)),
            ("-2147483648", Some(i32::MIN)),
            ("070", None),
            ("00", None),
            ("09", None),
            ("0x10", None),
            ("0b11", None),
            ("0o17", None),
            ("+5", None),
            ("1_0", None),
            ("1:30", None),
            ("70.0", None),
            ("1e2", None),
            ("", None),
            ("-", None),
            ("abc", None),
            (" 7 ", None),
            ("\t5", None),
            ("2147483648", None),
            ("-2147483649", None),
            ("--0", None),
            ("\u{0661}", None),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_int32(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn booleans_are_true_or_false_only() {
        let cases: &[(&str, Option<bool>)] = &[
            ("true", Some(true)),
            ("false", Some(false)),
            ("True", None),
            ("TRUE", None),
            ("tRuE", None),
            ("yes", None),
            ("y", None),
            ("on", None),
            ("no", None),
            ("n", None),
            ("off", None),
            ("1", None),
            ("0", None),
            (" true", None),
            ("true\n", None),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_bool(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn dates_are_iso_only() {
        let date = |y, m, d| NaiveDate::from_ymd_opt(y, m, d);
        assert_eq!(parse_date_only("2027-01-02"), date(2027, 1, 2));
        assert_eq!(parse_date_only("0001-01-01"), date(1, 1, 1));
        assert_eq!(parse_date_only("9999-12-31"), date(9999, 12, 31));
        assert_eq!(parse_date_only("2028-02-29"), date(2028, 2, 29));
        for text in [
            "0000-01-01",
            "2027-02-30",
            "2027-13-01",
            "2027-1-1",
            "27-1-2",
            "2027/01/05",
            "01/02/2027",
            "Jan 5, 2027",
            "2027-01-01T00:00:00Z",
            "2027-01-01 10:00",
            " 2027-01-01",
            "2027-01-01 ",
            "20270105",
            "2027-0a-01",
            "+027-01-01",
            "notadate",
        ] {
            assert_eq!(parse_date_only(text), None, "{text:?}");
        }
    }
}
