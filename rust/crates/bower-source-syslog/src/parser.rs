//! Strict RFC 5424 and RFC 3164 parser (C# `SyslogParser`). The whole frame must be
//! valid UTF-8; anything ambiguous fails closed with a stable code.

use std::collections::HashSet;

use bower_contracts::time::Timestamp;
use chrono::{Datelike, Duration, FixedOffset, NaiveDate, TimeZone, Utc};

/// Stable failure codes, identical to C# `SyslogFailures`.
pub mod failures {
    pub const EMPTY: &str = "syslog-empty";
    pub const INVALID_UTF8: &str = "syslog-invalid-utf8";
    pub const PRIORITY_INVALID: &str = "syslog-priority-invalid";
    pub const VERSION_UNSUPPORTED: &str = "syslog-version-unsupported";
    pub const TIMESTAMP_INVALID: &str = "syslog-timestamp-invalid";
    pub const HEADER_INVALID: &str = "syslog-header-invalid";
    pub const STRUCTURED_DATA_INVALID: &str = "syslog-structured-data-invalid";
    pub const STRUCTURED_DATA_DUPLICATE: &str = "syslog-structured-data-duplicate";
    pub const RECORD_TOO_LARGE: &str = "syslog-record-too-large";
    pub const FRAME_TOO_LARGE: &str = "syslog-frame-too-large";
    pub const OCTET_COUNT_INVALID: &str = "syslog-octet-count-invalid";
    pub const FRAMING_INVALID: &str = "syslog-framing-invalid";
    pub const FRAME_TRUNCATED: &str = "syslog-frame-truncated";
}

use failures::*;

pub const MAXIMUM_PRIORITY: u32 = 191;
const BOM: char = '\u{FEFF}';
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyslogFormat {
    Rfc5424,
    Rfc3164,
}

/// One RFC 5424 SD-ELEMENT. Parameter names are unique within an element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredElement {
    pub id: String,
    pub parameters: Vec<(String, String)>,
}

/// A parsed syslog message. Absent (NILVALUE) fields are `None`.
#[derive(Clone, Debug, PartialEq)]
pub struct SyslogMessage {
    pub format: SyslogFormat,
    pub facility: u32,
    pub severity: u32,
    pub timestamp: Option<Timestamp>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub message_id: Option<String>,
    pub structured_data: Vec<StructuredElement>,
    pub message: Option<String>,
}

type Parsed<T> = Result<T, &'static str>;

pub fn parse(frame: &[u8], received_at: &Timestamp) -> Parsed<SyslogMessage> {
    if frame.is_empty() {
        return Err(EMPTY);
    }
    let text = std::str::from_utf8(frame).map_err(|_| INVALID_UTF8)?;
    let bytes = text.as_bytes();
    let (priority, position) = read_priority(bytes)?;
    let mut run = position;
    while run < bytes.len() && run - position < 4 && bytes[run].is_ascii_digit() {
        run += 1;
    }
    if (1..=3).contains(&(run - position)) && run < bytes.len() && bytes[run] == b' ' {
        if run - position != 1 || bytes[position] != b'1' {
            return Err(VERSION_UNSUPPORTED);
        }
        return parse_5424(text, run + 1, priority);
    }
    parse_3164(text, position, priority, received_at)
}

fn read_priority(bytes: &[u8]) -> Parsed<(u32, usize)> {
    if bytes[0] != b'<' {
        return Err(PRIORITY_INVALID);
    }
    let mut end = 1;
    while end < bytes.len() && end <= 4 && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let digits = end - 1;
    if digits == 0
        || digits > 3
        || end >= bytes.len()
        || bytes[end] != b'>'
        || (digits > 1 && bytes[1] == b'0')
    {
        return Err(PRIORITY_INVALID);
    }
    let value = bytes[1..end]
        .iter()
        .fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'));
    if value > MAXIMUM_PRIORITY {
        return Err(PRIORITY_INVALID);
    }
    Ok((value, end + 1))
}

fn parse_5424(text: &str, mut position: usize, priority: u32) -> Parsed<SyslogMessage> {
    let bytes = text.as_bytes();
    let timestamp_token = token(text, &mut position, HEADER_INVALID)?;
    let timestamp = if timestamp_token == "-" {
        None
    } else {
        Some(parse_timestamp(timestamp_token).ok_or(TIMESTAMP_INVALID)?)
    };
    let hostname = field(text, &mut position, 255)?;
    let app_name = field(text, &mut position, 48)?;
    let proc_id = field(text, &mut position, 128)?;
    let message_id = field(text, &mut position, 32)?;
    if position >= bytes.len() {
        return Err(HEADER_INVALID);
    }
    let mut elements = Vec::new();
    match bytes[position] {
        b'-' => position += 1,
        b'[' => read_structured_data(text, &mut position, &mut elements)?,
        _ => return Err(STRUCTURED_DATA_INVALID),
    }
    let mut message = None;
    if position < bytes.len() {
        if bytes[position] != b' ' {
            return Err(STRUCTURED_DATA_INVALID);
        }
        message = body(&text[position + 1..]);
    }
    Ok(SyslogMessage {
        format: SyslogFormat::Rfc5424,
        facility: priority / 8,
        severity: priority % 8,
        timestamp,
        hostname,
        app_name,
        proc_id,
        message_id,
        structured_data: elements,
        message,
    })
}

fn parse_3164(
    text: &str,
    mut position: usize,
    priority: u32,
    received_at: &Timestamp,
) -> Parsed<SyslogMessage> {
    let bytes = text.as_bytes();
    let bsd = (position + 15 < bytes.len() && bytes[position + 15] == b' ')
        .then(|| bsd_timestamp(&bytes[position..position + 15], received_at))
        .flatten();
    let timestamp = if let Some(value) = bsd {
        position += 16;
        value.ok_or(TIMESTAMP_INVALID)?
    } else {
        let space = find_space(bytes, position).ok_or(TIMESTAMP_INVALID)?;
        let value = parse_timestamp(&text[position..space]).ok_or(TIMESTAMP_INVALID)?;
        position = space + 1;
        value
    };

    // HOSTNAME is optional in practice: a first token that looks like a tag starts the content.
    let mut hostname = None;
    match find_space(bytes, position) {
        Some(end) if end == position => return Err(HEADER_INVALID),
        Some(end) => {
            let token = &text[position..end];
            if !token.ends_with(':') && !token.contains('[') {
                if !is_printable(token, 255) {
                    return Err(HEADER_INVALID);
                }
                hostname = Some(token.to_string());
                position = end + 1;
            }
        }
        None => {}
    }

    let content = &text[position..];
    let content_bytes = content.as_bytes();
    let (mut app_name, mut proc_id, mut message) = (None, None, content);
    let mut tag = 0;
    while tag < content_bytes.len()
        && tag <= 48
        && printable(content_bytes[tag])
        && !matches!(content_bytes[tag], b'[' | b':')
    {
        tag += 1;
    }
    if (1..=48).contains(&tag) {
        let mut next = Some(tag);
        let mut pid = None;
        if tag < content_bytes.len() && content_bytes[tag] == b'[' {
            let mut close = tag + 1;
            while close < content_bytes.len()
                && close - tag <= 129
                && printable(content_bytes[close])
                && content_bytes[close] != b']'
            {
                close += 1;
            }
            let closed = close < content_bytes.len()
                && content_bytes[close] == b']'
                && (1..=128).contains(&(close - tag - 1));
            pid = closed.then(|| content[tag + 1..close].to_string());
            next = closed.then_some(close + 1);
        }
        if let Some(mut next) = next
            && next < content_bytes.len()
            && content_bytes[next] == b':'
        {
            app_name = Some(content[..tag].to_string());
            proc_id = pid;
            next += 1;
            if next < content_bytes.len() && content_bytes[next] == b' ' {
                next += 1;
            }
            message = &content[next..];
        }
    }

    Ok(SyslogMessage {
        format: SyslogFormat::Rfc3164,
        facility: priority / 8,
        severity: priority % 8,
        timestamp: Some(timestamp),
        hostname,
        app_name,
        proc_id,
        message_id: None,
        structured_data: Vec::new(),
        message: body(message),
    })
}

fn body(message: &str) -> Option<String> {
    let message = message.strip_prefix(BOM).unwrap_or(message);
    (!message.is_empty()).then(|| message.to_string())
}

fn find_space(bytes: &[u8], from: usize) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|byte| *byte == b' ')
        .map(|index| from + index)
}

/// Header token followed by exactly one SP.
fn token<'a>(text: &'a str, position: &mut usize, failure: &'static str) -> Parsed<&'a str> {
    match find_space(text.as_bytes(), *position) {
        Some(end) if end > *position => {
            let value = &text[*position..end];
            *position = end + 1;
            Ok(value)
        }
        _ => Err(failure),
    }
}

fn field(text: &str, position: &mut usize, maximum: usize) -> Parsed<Option<String>> {
    let value = token(text, position, HEADER_INVALID)?;
    if !is_printable(value, maximum) {
        return Err(HEADER_INVALID);
    }
    Ok((value != "-").then(|| value.to_string()))
}

fn read_structured_data(
    text: &str,
    position: &mut usize,
    elements: &mut Vec<StructuredElement>,
) -> Parsed<()> {
    let bytes = text.as_bytes();
    let mut ids = HashSet::new();
    while *position < bytes.len() && bytes[*position] == b'[' {
        *position += 1;
        let id = sd_name(text, position)?;
        if !ids.insert(id.clone()) {
            return Err(STRUCTURED_DATA_DUPLICATE);
        }
        let mut parameters = Vec::new();
        let mut names = HashSet::new();
        loop {
            match bytes.get(*position) {
                None => return Err(STRUCTURED_DATA_INVALID),
                Some(b']') => {
                    *position += 1;
                    break;
                }
                Some(b' ') => *position += 1,
                Some(_) => return Err(STRUCTURED_DATA_INVALID),
            }
            let name = sd_name(text, position)?;
            if *position + 1 >= bytes.len()
                || bytes[*position] != b'='
                || bytes[*position + 1] != b'"'
            {
                return Err(STRUCTURED_DATA_INVALID);
            }
            *position += 2;
            // Removing ASCII escapes from valid UTF-8 keeps it valid UTF-8.
            let mut value = Vec::new();
            loop {
                match bytes.get(*position) {
                    None => return Err(STRUCTURED_DATA_INVALID),
                    Some(b'\\')
                        if matches!(bytes.get(*position + 1), Some(b'"' | b'\\' | b']')) =>
                    {
                        value.push(bytes[*position + 1]);
                        *position += 2;
                    }
                    Some(b'"') => {
                        *position += 1;
                        break;
                    }
                    Some(byte) => {
                        value.push(*byte);
                        *position += 1;
                    }
                }
            }
            if !names.insert(name.clone()) {
                return Err(STRUCTURED_DATA_DUPLICATE);
            }
            let value = String::from_utf8(value).map_err(|_| STRUCTURED_DATA_INVALID)?;
            parameters.push((name, value));
        }
        elements.push(StructuredElement { id, parameters });
    }
    Ok(())
}

/// SD-NAME: 1–32 PRINTUSASCII except '=', SP, ']' and '"'.
fn sd_name(text: &str, position: &mut usize) -> Parsed<String> {
    let bytes = text.as_bytes();
    let start = *position;
    while *position < bytes.len()
        && *position - start <= 32
        && printable(bytes[*position])
        && !matches!(bytes[*position], b'=' | b']' | b'"')
    {
        *position += 1;
    }
    if (1..=32).contains(&(*position - start)) {
        Ok(text[start..*position].to_string())
    } else {
        Err(STRUCTURED_DATA_INVALID)
    }
}

fn printable(byte: u8) -> bool {
    (b'!'..=b'~').contains(&byte)
}

fn is_printable(token: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&token.len()) && token.bytes().all(printable)
}

fn number(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        digits
            .iter()
            .fold(0, |value, digit| value * 10 + u32::from(digit - b'0')),
    )
}

/// RFC 5424 TIMESTAMP: uppercase T and Z, at most six fraction digits, no leap seconds.
pub fn parse_timestamp(token: &str) -> Option<Timestamp> {
    let span = token.as_bytes();
    if span.len() < 20
        || span[4] != b'-'
        || span[7] != b'-'
        || span[10] != b'T'
        || span[13] != b':'
        || span[16] != b':'
    {
        return None;
    }
    let year = number(&span[..4])?;
    let month = number(&span[5..7])?;
    let day = number(&span[8..10])?;
    let hour = number(&span[11..13])?;
    let minute = number(&span[14..16])?;
    let second = number(&span[17..19])?;
    let mut position = 19;
    let mut microseconds = 0i64;
    if span[position] == b'.' {
        position += 1;
        let start = position;
        while position < span.len() && span[position].is_ascii_digit() {
            position += 1;
        }
        let digits = position - start;
        if !(1..=6).contains(&digits) {
            return None;
        }
        microseconds = i64::from(number(&span[start..position])?) * 10i64.pow(6 - digits as u32);
    }
    let zone = &span[position..];
    let offset_seconds = if zone == b"Z" {
        0
    } else if zone.len() == 6 && matches!(zone[0], b'+' | b'-') && zone[3] == b':' {
        let hours = number(&zone[1..3])?;
        let minutes = number(&zone[4..6])?;
        if minutes > 59 || hours * 60 + minutes > 14 * 60 {
            return None;
        }
        let seconds = i32::try_from((hours * 60 + minutes) * 60).ok()?;
        if zone[0] == b'-' { -seconds } else { seconds }
    } else {
        return None;
    };
    if year < 1 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?;
    let local = date.and_hms_opt(hour, minute, second)? + Duration::microseconds(microseconds);
    let value = FixedOffset::east_opt(offset_seconds)?
        .from_local_datetime(&local)
        .single()?;
    (1..=9999)
        .contains(&value.with_timezone(&Utc).year())
        .then_some(value)
}

/// RFC 3164 "Mmm dd hh:mm:ss" read as UTC with the receive year (or the year before, as
/// C# `TryBsdTimestamp`). `None` when the text does not start with a month name;
/// `Some(None)` when it does but is not a valid timestamp.
fn bsd_timestamp(span: &[u8], received_at: &Timestamp) -> Option<Option<Timestamp>> {
    let month = MONTHS
        .iter()
        .position(|name| name.as_bytes() == &span[..3])? as u32
        + 1;
    if span[3] != b' ' || span[6] != b' ' || span[9] != b':' || span[12] != b':' {
        return Some(None);
    }
    let day = if span[4] == b' ' && (b'1'..=b'9').contains(&span[5]) {
        u32::from(span[5] - b'0')
    } else {
        match number(&span[4..6]) {
            Some(day) => day,
            None => return Some(None),
        }
    };
    let (Some(hour), Some(minute), Some(second)) = (
        number(&span[7..9]),
        number(&span[10..12]),
        number(&span[13..15]),
    ) else {
        return Some(None);
    };
    if hour > 23 || minute > 59 || second > 59 || !(1..=31).contains(&day) {
        return Some(None);
    }
    let date = |year: i32| -> Option<Timestamp> {
        if !(1..=9999).contains(&year) {
            return None;
        }
        let value = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
        Some(Utc.from_utc_datetime(&value).fixed_offset())
    };
    let year = received_at.with_timezone(&Utc).year();
    let limit = *received_at + Duration::days(1);
    Some(match date(year) {
        Some(candidate) if candidate <= limit => Some(candidate),
        _ => date(year - 1),
    })
}
