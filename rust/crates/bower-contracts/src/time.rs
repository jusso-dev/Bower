//! `DateTimeOffset` compatible timestamps.
//!
//! .NET stores 100 ns ticks. Values are truncated to tick precision on parse so
//! round trips and hashes match the C# implementation.

use chrono::{DateTime, FixedOffset, SecondsFormat, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Timestamp = DateTime<FixedOffset>;

/// Current UTC time as a `+00:00` offset timestamp truncated to ticks.
pub fn now() -> Timestamp {
    truncate_to_ticks(Utc::now().fixed_offset())
}

/// Time source (C# `TimeProvider`). Tests inject a controllable clock; any
/// `Fn() -> Timestamp` closure is a clock.
pub trait Clock: Send + Sync {
    fn utc_now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn utc_now(&self) -> Timestamp {
        now()
    }
}

impl<F> Clock for F
where
    F: Fn() -> Timestamp + Send + Sync,
{
    fn utc_now(&self) -> Timestamp {
        self()
    }
}

pub fn truncate_to_ticks(value: Timestamp) -> Timestamp {
    let nanos = value.nanosecond();
    value
        .with_nanosecond(nanos - nanos % 100)
        .expect("tick truncation keeps nanoseconds in range")
}

pub fn to_utc(value: Timestamp) -> Timestamp {
    value.with_timezone(&FixedOffset::east_opt(0).expect("zero offset"))
}

fn offset_suffix(value: &Timestamp) -> String {
    let seconds = value.offset().local_minus_utc();
    let sign = if seconds < 0 { '-' } else { '+' };
    let minutes = seconds.unsigned_abs() / 60;
    format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

/// `DateTimeOffset.ToString("O")`: seven fractional digits, `+00:00` style offset.
pub fn format_round_trip(value: &Timestamp) -> String {
    format!(
        "{}.{:07}{}",
        value.format("%Y-%m-%dT%H:%M:%S"),
        value.nanosecond() / 100,
        offset_suffix(value)
    )
}

/// System.Text.Json `DateTimeOffset` text: trailing zero fraction digits trimmed.
pub fn format_json(value: &Timestamp) -> String {
    let ticks = value.nanosecond() / 100;
    let mut text = value.format("%Y-%m-%dT%H:%M:%S").to_string();
    if ticks != 0 {
        let fraction = format!("{ticks:07}");
        text.push('.');
        text.push_str(fraction.trim_end_matches('0'));
    }
    text.push_str(&offset_suffix(value));
    text
}

/// Parses ISO 8601 timestamps accepted by System.Text.Json (offset optional; no
/// offset is read as UTC).
pub fn parse(text: &str) -> Option<Timestamp> {
    if let Ok(value) = DateTime::parse_from_rfc3339(text) {
        return Some(truncate_to_ticks(value));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(text, format) {
            return Some(truncate_to_ticks(naive.and_utc().fixed_offset()));
        }
    }
    chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map(|naive| naive.and_utc().fixed_offset())
}

/// RFC 3339 with `Z`, for logs and HTTP headers only (never hashed).
pub fn format_rfc3339_utc(value: &Timestamp) -> String {
    value
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Utf8JsonWriter writes `DateTimeOffset` without the text encoder, so `+` in the
/// offset stays literal. Emitting a raw JSON string keeps that byte-for-byte.
fn serialize_unescaped<S: Serializer>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    let raw = serde_json::value::RawValue::from_string(format!("\"{}\"", format_json(value)))
        .map_err(serde::ser::Error::custom)?;
    raw.serialize(serializer)
}

pub mod serde_offset {
    use super::*;

    pub fn serialize<S: Serializer>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_unescaped(value, serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| serde::de::Error::custom("invalid DateTimeOffset"))
    }
}

pub mod serde_offset_option {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<Timestamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serialize_unescaped(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        let text = <Option<std::borrow::Cow<'de, str>>>::deserialize(deserializer)?;
        text.map(|text| {
            parse(&text).ok_or_else(|| serde::de::Error::custom("invalid DateTimeOffset"))
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_match_dotnet() {
        let value = parse("2026-05-01T10:20:30.1234500Z").unwrap();
        assert_eq!(format_json(&value), "2026-05-01T10:20:30.12345+00:00");
        assert_eq!(
            format_round_trip(&value),
            "2026-05-01T10:20:30.1234500+00:00"
        );
        let whole = parse("2026-05-01T10:20:30+10:00").unwrap();
        assert_eq!(format_json(&whole), "2026-05-01T10:20:30+10:00");
        assert_eq!(
            format_round_trip(&to_utc(whole)),
            "2026-05-01T00:20:30.0000000+00:00"
        );
    }

    #[test]
    fn truncates_to_ticks() {
        let value = parse("2026-05-01T10:20:30.123456789Z").unwrap();
        assert_eq!(format_json(&value), "2026-05-01T10:20:30.1234567+00:00");
    }
}
