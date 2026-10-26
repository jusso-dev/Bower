//! `parse_timestamp` formats and canonical UTC text (`TransformTime.cs`): exact grammars
//! and integer tick arithmetic (100 ns since 0001-01-01T00:00:00Z).

use super::value::Value;

pub(crate) const FORMATS: [&str; 6] = [
    "rfc3339",
    "rfc3164",
    "common_log",
    "unix_seconds",
    "unix_milliseconds",
    "unix_microseconds",
];

const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_MINUTE: i64 = 60 * TICKS_PER_SECOND;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
pub(crate) const UNIX_EPOCH_TICKS: i64 = 621_355_968_000_000_000;
const MAXIMUM_TICKS: i64 = 3_155_378_975_999_999_999;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `yyyy-MM-ddTHH:mm:ss[.fffffff]Z`, trailing fraction zeros trimmed.
pub(crate) fn format(ticks: i64) -> String {
    let days = ticks / TICKS_PER_DAY;
    let remainder = ticks % TICKS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let seconds = remainder / TICKS_PER_SECOND;
    let fraction = remainder % TICKS_PER_SECOND;
    let mut text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    );
    if fraction > 0 {
        text.push('.');
        text.push_str(format!("{fraction:07}").trim_end_matches('0'));
    }
    text.push('Z');
    text
}

pub(crate) fn parse(format: &str, value: &Value, evaluation_ticks: i64) -> Option<i64> {
    if format.starts_with("unix_") {
        let count = match value {
            Value::Int(number) => *number,
            Value::Str(text) => unix_text(text)?,
            _ => return None,
        };
        let factor = match format {
            "unix_seconds" => TICKS_PER_SECOND,
            "unix_milliseconds" => 10_000,
            _ => 10,
        };
        if count < -(UNIX_EPOCH_TICKS / factor)
            || count > (MAXIMUM_TICKS - UNIX_EPOCH_TICKS) / factor
        {
            return None;
        }
        return Some(UNIX_EPOCH_TICKS + count * factor);
    }
    let Value::Str(text) = value else {
        return None;
    };
    // Every grammar below is ASCII; anything else cannot match.
    let text = text.as_bytes();
    match format {
        "rfc3339" => rfc3339(text),
        "rfc3164" => rfc3164(text, evaluation_ticks),
        _ => common_log(text),
    }
}

fn unix_text(text: &str) -> Option<i64> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if !(1..=19).contains(&digits.len()) || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn digits(text: &[u8], start: usize, count: usize) -> Option<i64> {
    let slice = text.get(start..start + count)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        slice
            .iter()
            .fold(0, |value, digit| value * 10 + i64::from(digit - b'0')),
    )
}

fn at(text: &[u8], index: usize) -> u8 {
    text.get(index).copied().unwrap_or(0)
}

fn month(name: &[u8]) -> Option<i64> {
    MONTHS
        .iter()
        .position(|month| month.as_bytes() == name)
        .map(|index| index as i64 + 1)
}

fn rfc3339(text: &[u8]) -> Option<i64> {
    if text.len() < 20
        || at(text, 4) != b'-'
        || at(text, 7) != b'-'
        || !matches!(at(text, 10), b'T' | b't' | b' ')
        || at(text, 13) != b':'
        || at(text, 16) != b':'
    {
        return None;
    }
    let year = digits(text, 0, 4)?;
    let month = digits(text, 5, 2)?;
    let day = digits(text, 8, 2)?;
    let hour = digits(text, 11, 2)?;
    let minute = digits(text, 14, 2)?;
    let second = digits(text, 17, 2)?;
    let mut position = 19;
    let mut fraction = 0;
    if text[position] == b'.' {
        position += 1;
        let start = position;
        while position < text.len() && text[position].is_ascii_digit() {
            position += 1;
        }
        let count = position - start;
        if !(1..=9).contains(&count) {
            return None;
        }
        let kept = count.min(7);
        fraction = digits(text, start, kept)? * 10_i64.pow((7 - kept) as u32);
    }
    let offset_minutes = if position + 1 == text.len() && matches!(text[position], b'Z' | b'z') {
        0
    } else if position + 6 == text.len()
        && matches!(text[position], b'+' | b'-')
        && at(text, position + 3) == b':'
    {
        let offset_hour = digits(text, position + 1, 2)?;
        let offset_minute = digits(text, position + 4, 2)?;
        if offset_hour > 23 || offset_minute > 59 {
            return None;
        }
        (offset_hour * 60 + offset_minute) * if text[position] == b'-' { -1 } else { 1 }
    } else {
        return None;
    };
    in_range(
        ticks(year, month, day, hour, minute, second)? + fraction
            - offset_minutes * TICKS_PER_MINUTE,
    )
}

fn rfc3164(text: &[u8], evaluation_ticks: i64) -> Option<i64> {
    if text.len() != 15 || text[3] != b' ' || text[6] != b' ' || text[9] != b':' || text[12] != b':'
    {
        return None;
    }
    let day = if text[4] == b' ' {
        digits(text, 5, 1)?
    } else {
        digits(text, 4, 2)?
    };
    let month = month(&text[..3])?;
    let hour = digits(text, 7, 2)?;
    let minute = digits(text, 10, 2)?;
    let second = digits(text, 13, 2)?;
    let year = civil_from_days(evaluation_ticks / TICKS_PER_DAY).0;
    match ticks(year, month, day, hour, minute, second) {
        Some(candidate) if candidate <= evaluation_ticks + TICKS_PER_DAY => Some(candidate),
        _ => ticks(year - 1, month, day, hour, minute, second),
    }
}

fn common_log(text: &[u8]) -> Option<i64> {
    if text.len() != 26
        || text[2] != b'/'
        || text[6] != b'/'
        || text[11] != b':'
        || text[14] != b':'
        || text[17] != b':'
        || text[20] != b' '
        || !matches!(text[21], b'+' | b'-')
    {
        return None;
    }
    let day = digits(text, 0, 2)?;
    let year = digits(text, 7, 4)?;
    let hour = digits(text, 12, 2)?;
    let minute = digits(text, 15, 2)?;
    let second = digits(text, 18, 2)?;
    let offset_hour = digits(text, 22, 2)?;
    let offset_minute = digits(text, 24, 2)?;
    if offset_hour > 23 || offset_minute > 59 {
        return None;
    }
    let month = month(&text[3..6])?;
    let offset = (offset_hour * 60 + offset_minute) * if text[21] == b'-' { -1 } else { 1 };
    in_range(ticks(year, month, day, hour, minute, second)? - offset * TICKS_PER_MINUTE)
}

fn in_range(ticks: i64) -> Option<i64> {
    (0..=MAXIMUM_TICKS).contains(&ticks).then_some(ticks)
}

fn ticks(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> Option<i64> {
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * TICKS_PER_DAY
            + (hour * 3600 + minute * 60 + second) * TICKS_PER_SECOND,
    )
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 0001-01-01 (proleptic Gregorian), after H. Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 306
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 306;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
