//! Flat JSON record for a signed pack parser (C# `FileTailRecord`): `id`, `input`, `path`,
//! `offset`, `readAt`, then `message` (text) or `json` (json-lines). In memory only;
//! never logged or persisted.

use bower_contracts::time::Timestamp;
use bower_contracts::{JsonElement, json};
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::config::InputOptions;
use crate::reader::Line;

/// Nesting a json-lines object may use (C# `JsonDocumentOptions.MaxDepth = 8`).
pub const MAXIMUM_JSON_DEPTH: usize = 8;

pub const INVALID_UTF8: &str = "file-line-invalid-utf8";
pub const INVALID_JSON: &str = "file-line-invalid-json";
/// The record would exceed `MAXIMUM_RECORD_BYTES` once JSON-escaped (a line within
/// `maxLineBytes` can: a control character becomes six bytes). Counted as oversized.
pub const TOO_LARGE: &str = "file-record-too-large";
/// The largest record a pack parser reads (`bower_packs::runtime::MAXIMUM_RAW_BYTES`; a
/// collector test keeps them equal).
pub const MAXIMUM_RECORD_BYTES: usize = 32 * 1024;

/// The record, or the failure code of a malformed line.
pub fn build(
    input: &InputOptions,
    line: &Line,
    read_at: &Timestamp,
) -> Result<String, &'static str> {
    let text = std::str::from_utf8(&line.bytes).map_err(|_| INVALID_UTF8)?;
    let body = if input.is_json_lines() {
        if too_deep(text.as_bytes()) {
            return Err(INVALID_JSON);
        }
        match JsonElement::parse(text) {
            Ok(object @ JsonElement::Object(_)) => ("json", object),
            _ => return Err(INVALID_JSON),
        }
    } else {
        ("message", JsonElement::from(text))
    };
    let fields = vec![
        (
            "id".to_owned(),
            event_id(&input.id, &line.fingerprint, line.start_offset, &line.bytes).into(),
        ),
        ("input".to_owned(), input.id.as_str().into()),
        ("path".to_owned(), input.path.as_str().into()),
        ("offset".to_owned(), line.start_offset.to_string().into()),
        ("readAt".to_owned(), format(read_at).into()),
        (body.0.to_owned(), body.1),
    ];
    let record = json::to_string(&JsonElement::Object(fields)).map_err(|_| INVALID_JSON)?;
    if record.len() > MAXIMUM_RECORD_BYTES {
        return Err(TOO_LARGE);
    }
    Ok(record)
}

/// Depth beyond [`MAXIMUM_JSON_DEPTH`], counted like `Utf8JsonReader` (the top-level
/// container is depth 1). Malformed text is left to the parser.
fn too_deep(text: &[u8]) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in text {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAXIMUM_JSON_DEPTH {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// `file-` + 32 hex characters of SHA-256 over input id, fingerprint, start offset and
/// the line bytes, so a re-read deduplicates.
pub fn event_id(input_id: &str, fingerprint: &str, start_offset: i64, line: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(input_id.as_bytes());
    hash.update([0x1f]);
    hash.update(fingerprint.as_bytes());
    hash.update([0x1f]);
    hash.update(start_offset.to_string().as_bytes());
    hash.update([0x1f]);
    hash.update(line);
    format!("file-{}", &hex::encode(hash.finalize())[..32])
}

/// UTC, microsecond precision (truncated), like C# `FileTailRecord.Format`.
pub fn format(value: &Timestamp) -> String {
    value
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}
