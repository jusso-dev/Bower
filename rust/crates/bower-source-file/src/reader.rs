//! Bounded, read-only tail of one plain-text file with rename and copytruncate rotation
//! (C# `FileTailReader`). Only complete lines are consumed (except at the end of a rotated
//! file, which no longer grows), an oversized line is skipped without being buffered, and
//! each read is bounded by a line count and a byte budget.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FINGERPRINT_BYTES: u64 = 64;
pub const CURRENT_SCHEMA_VERSION: i32 = 1;

/// Position in one tailed file (C# `FileTailCursor`, same JSON). An empty fingerprint is
/// provisional: the file was missing or too short to identify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    pub schema_version: i32,
    pub fingerprint: String,
    pub offset: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub discarding: bool,
}

/// C# deserializes with default options: missing members take their defaults and
/// unknown members are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCursor {
    #[serde(default)]
    schema_version: i32,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    offset: i64,
    #[serde(default)]
    discarding: bool,
}

impl Cursor {
    pub fn new(fingerprint: impl Into<String>, offset: i64) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            fingerprint: fingerprint.into(),
            offset,
            discarding: false,
        }
    }

    pub fn serialize(&self) -> String {
        bower_contracts::json::to_string(self).expect("cursor serializes")
    }

    /// The cursor, or `None` when the stored value is not a cursor this version wrote.
    pub fn deserialize(value: &str) -> Option<Self> {
        if value.trim().is_empty() {
            return None;
        }
        let stored: StoredCursor = serde_json::from_str(value).ok()?;
        let fingerprint = stored.fingerprint?;
        let valid_fingerprint = fingerprint.is_empty()
            || (fingerprint.len() == 64
                && fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        (stored.schema_version == CURRENT_SCHEMA_VERSION && stored.offset >= 0 && valid_fingerprint)
            .then_some(Self {
                schema_version: stored.schema_version,
                fingerprint,
                offset: stored.offset,
                discarding: stored.discarding,
            })
    }
}

/// One complete line, in file order. `bytes` excludes the newline and one trailing
/// carriage return; an oversized line carries no bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub bytes: Vec<u8>,
    pub fingerprint: String,
    pub start_offset: i64,
    pub end_offset: i64,
    pub oversized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub lines: Vec<Line>,
    /// Position after every line in `lines`.
    pub cursor: Cursor,
    /// `path.1` was drained and the cursor moved to the current file.
    pub rotated: bool,
    /// Lines may have been lost: rotated more than once, or truncated in place.
    pub gap: bool,
    /// A limit stopped the read, or the cursor moved files: read again without waiting.
    pub more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderOptions {
    pub max_line_bytes: usize,
    pub max_lines_per_batch: usize,
    pub max_bytes_per_batch: u64,
    /// When a file is first seen, start after its last complete line.
    pub start_at_end: bool,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_line_bytes: crate::config::DEFAULT_MAX_LINE_BYTES as usize,
            max_lines_per_batch: 256,
            max_bytes_per_batch: 1_048_576,
            start_at_end: true,
        }
    }
}

/// `path` is the current file (already checked by `paths::resolve`), `None` when missing;
/// `rotated` is `path.1` when it can be read.
pub fn read(
    path: Option<&Path>,
    rotated: Option<&Path>,
    cursor: Option<&Cursor>,
    options: &ReaderOptions,
) -> std::io::Result<Batch> {
    let current_fingerprint = match path {
        Some(path) => fingerprint(path)?,
        None => None,
    };
    let Some(cursor) = cursor else {
        let Some(current) = current_fingerprint else {
            return Ok(empty(Cursor::new("", 0)));
        };
        let path = path.expect("fingerprinted file has a path");
        let initial = Cursor::new(
            current,
            if options.start_at_end {
                last_complete_line_end(path)?
            } else {
                0
            },
        );
        return if options.start_at_end {
            Ok(empty(initial))
        } else {
            read_file(path, &initial, options, false, false)
        };
    };

    if cursor.fingerprint.is_empty() {
        return match current_fingerprint {
            None => Ok(empty(cursor.clone())),
            Some(current) => read_file(
                path.expect("fingerprinted file has a path"),
                &Cursor::new(current, 0),
                options,
                false,
                false,
            ),
        };
    }

    if current_fingerprint.as_deref() == Some(cursor.fingerprint.as_str()) {
        let path = path.expect("fingerprinted file has a path");
        if length(path)? < cursor.offset {
            // Truncated in place without a matching copy: restart and flag the gap.
            return read_file(
                path,
                &Cursor {
                    offset: 0,
                    discarding: false,
                    ..cursor.clone()
                },
                options,
                false,
                true,
            );
        }
        return read_file(path, cursor, options, false, false);
    }

    // The current file is another file. Drain the rotated file first if it is ours.
    if let Some(rotated_path) = rotated
        && fingerprint(rotated_path)?.as_deref() == Some(cursor.fingerprint.as_str())
    {
        let batch = read_file(rotated_path, cursor, options, true, false)?;
        let drained = batch.cursor.offset >= length(rotated_path)? && !batch.more;
        return Ok(if drained {
            Batch {
                cursor: Cursor::new(current_fingerprint.unwrap_or_default(), 0),
                rotated: true,
                more: true,
                ..batch
            }
        } else {
            batch
        });
    }

    let Some(current) = current_fingerprint else {
        // Missing or too short to identify, and not rotated to path.1: wait.
        return Ok(empty(cursor.clone()));
    };
    // Rotated more than once since the last read, or replaced: lines were lost.
    read_file(
        path.expect("fingerprinted file has a path"),
        &Cursor::new(current, 0),
        options,
        false,
        true,
    )
}

/// SHA-256 of the first 64 bytes, or `None` when the file is missing, shorter, or not a
/// regular file (which is never opened).
pub fn fingerprint(path: &Path) -> std::io::Result<Option<String>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() < FINGERPRINT_BYTES {
        return Ok(None);
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut prefix = [0u8; FINGERPRINT_BYTES as usize];
    match file.read_exact(&mut prefix) {
        Ok(()) => Ok(Some(hex::encode(Sha256::digest(prefix)))),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

fn length(path: &Path) -> std::io::Result<i64> {
    Ok(i64::try_from(std::fs::metadata(path)?.len()).unwrap_or(i64::MAX))
}

fn read_file(
    path: &Path,
    cursor: &Cursor,
    options: &ReaderOptions,
    eof_ends_line: bool,
    gap: bool,
) -> std::io::Result<Batch> {
    let mut lines = Vec::new();
    let mut committed = cursor.offset;
    let mut discarding = cursor.discarding;
    let mut more = false;

    let mut file = File::open(path)?;
    // A snapshot of the length bounds this read; bytes appended meanwhile wait.
    let length = i64::try_from(file.metadata()?.len()).unwrap_or(i64::MAX);
    if cursor.offset > length {
        return Ok(empty(cursor.clone()));
    }
    file.seek(SeekFrom::Start(cursor.offset as u64))?;
    let budget = i64::try_from(options.max_bytes_per_batch).unwrap_or(i64::MAX);
    let budget_end = length.min(cursor.offset.saturating_add(budget));
    let max_line = options.max_line_bytes;
    let mut buffer = vec![0u8; max_line];
    let mut chunk = vec![0u8; 65_536];
    let (mut chunk_length, mut chunk_index) = (0usize, 0usize);
    let mut position = cursor.offset;

    while position < budget_end {
        if lines.len() >= options.max_lines_per_batch {
            more = true;
            break;
        }
        let line_start = position;
        // A line may run up to its own limit past the byte budget, never past the snapshot.
        let limit = length.min(budget_end.max(line_start + max_line as i64 + 1));
        let mut count = 0usize;
        let mut oversized = discarding;
        let mut terminated = false;
        while position < limit {
            if chunk_index == chunk_length {
                let wanted = (chunk.len() as i64).min(limit - position) as usize;
                chunk_length = file.read(&mut chunk[..wanted])?;
                chunk_index = 0;
                if chunk_length == 0 {
                    break; // Shortened underneath us: treat as the end of the snapshot.
                }
            }
            let value = chunk[chunk_index];
            chunk_index += 1;
            position += 1;
            if value == b'\n' {
                terminated = true;
                break;
            }
            if !oversized {
                if count == buffer.len() {
                    oversized = true;
                } else {
                    buffer[count] = value;
                    count += 1;
                }
            }
        }

        let at_end = position >= length;
        if terminated || (eof_ends_line && at_end && (oversized || count > 0)) {
            lines.push(if oversized {
                Line {
                    bytes: Vec::new(),
                    fingerprint: cursor.fingerprint.clone(),
                    start_offset: line_start,
                    end_offset: position,
                    oversized: true,
                }
            } else {
                let end = if count > 0 && buffer[count - 1] == b'\r' {
                    count - 1
                } else {
                    count
                };
                Line {
                    bytes: buffer[..end].to_vec(),
                    fingerprint: cursor.fingerprint.clone(),
                    start_offset: line_start,
                    end_offset: position,
                    oversized: false,
                }
            });
            committed = position;
            discarding = false;
            continue;
        }
        if oversized {
            // Consume what was scanned so a huge line never pins the cursor across reads.
            committed = position;
            discarding = true;
            more = !at_end;
        }
        // Otherwise the line is still being written: leave it for the next read.
        break;
    }

    if !more && committed < length && position >= budget_end && budget_end < length {
        more = true;
    }
    Ok(Batch {
        lines,
        cursor: Cursor {
            offset: committed,
            discarding,
            ..cursor.clone()
        },
        rotated: false,
        gap,
        more,
    })
}

fn last_complete_line_end(path: &Path) -> std::io::Result<i64> {
    let mut file = File::open(path)?;
    let mut block = [0u8; 4_096];
    let mut end = i64::try_from(file.metadata()?.len()).unwrap_or(i64::MAX);
    while end > 0 {
        let count = (block.len() as i64).min(end) as usize;
        let start = end - count as i64;
        file.seek(SeekFrom::Start(start as u64))?;
        // A concurrent truncation can shorten the read; bytes past EOF are never '\n'.
        let mut read = 0;
        while read < count {
            let got = file.read(&mut block[read..count])?;
            if got == 0 {
                break;
            }
            read += got;
        }
        if let Some(newline) = block[..read].iter().rposition(|&byte| byte == b'\n') {
            return Ok(start + newline as i64 + 1);
        }
        end = start;
    }
    Ok(0)
}

fn empty(cursor: Cursor) -> Batch {
    Batch {
        lines: Vec::new(),
        cursor,
        rotated: false,
        gap: false,
        more: false,
    }
}
