//! Bounded, read-only tail of one plain-text file with rename and copytruncate rotation
//! (C# `FileTailReader`). Only complete lines are consumed, an oversized line is skipped
//! without being buffered, and each read is bounded by a line count and a byte budget. Each
//! file is opened once per read (`handle::open`): its identity and its lines come from the
//! same handle.
//!
//! A writer keeps writing to `path.1` until it reopens its file (rsyslog until HUP), so the
//! cursor leaves `path.1` only once the current file can be identified and `path.1` stayed
//! unchanged for `rotation_grace_polls` polls; only then is its unterminated last line
//! complete. Lines written to it afterwards cannot be read and are reported as a gap.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::handle::{self, Handle, OpenError};

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
/// carriage return; an oversized line carries no bytes. `continues_discard` means it started
/// inside a line already being skipped, so a rewind to its start must keep skipping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub bytes: Vec<u8>,
    pub fingerprint: String,
    pub start_offset: i64,
    pub end_offset: i64,
    pub oversized: bool,
    pub continues_discard: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub lines: Vec<Line>,
    /// Position after every line in `lines`.
    pub cursor: Cursor,
    /// `path.1` was drained and the cursor moved to the current file.
    pub rotated: bool,
    /// Lines may have been lost: rotated more than once, truncated in place, or written to
    /// `path.1` after the cursor moved to the current file.
    pub gap: bool,
    /// A limit stopped the read, or the cursor moved files: read again without waiting.
    pub more: bool,
    /// This read opened `path.1`, so the caller re-checks it.
    pub rotated_opened: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderOptions {
    pub max_line_bytes: usize,
    pub max_lines_per_batch: usize,
    pub max_bytes_per_batch: u64,
    /// When a file is first seen, start after its last complete line.
    pub start_at_end: bool,
    /// Polls `path.1` must stay unchanged (size and write time) before the cursor leaves it.
    pub rotation_grace_polls: i32,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_line_bytes: crate::config::DEFAULT_MAX_LINE_BYTES as usize,
            max_lines_per_batch: 256,
            max_bytes_per_batch: 1_048_576,
            start_at_end: true,
            rotation_grace_polls: crate::config::DEFAULT_ROTATION_GRACE_POLLS,
        }
    }
}

/// What a reader remembers between polls of one input (C# `FileTailRotationState`), in
/// memory only: a restart starts the grace window again and forgets the abandoned generation.
#[derive(Clone, Debug, Default)]
pub struct RotationState {
    observed: Option<(i64, Option<SystemTime>)>,
    stable_polls: i32,
    /// The generation the cursor left, and its length then: later growth is a gap.
    abandoned: Option<(String, i64)>,
}

#[derive(Debug)]
pub enum ReadError {
    /// An opened handle is not the validated regular file.
    Refused,
    Io(std::io::Error),
    /// Stopping: nothing is committed.
    Stopped,
}

impl From<std::io::Error> for ReadError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<OpenError> for ReadError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Refused => Self::Refused,
            OpenError::Io(error) => Self::Io(error),
        }
    }
}

/// `path` is the current file (already checked by `paths::resolve`), `None` when missing;
/// `rotated` is `path.1` when it exists (already checked).
pub fn read(
    path: Option<&Path>,
    rotated: Option<&Path>,
    cursor: Option<&Cursor>,
    options: &ReaderOptions,
    state: &mut RotationState,
    stop: Option<&AtomicBool>,
) -> Result<Batch, ReadError> {
    let mut current = handle::open(path)?;
    let mut previous: Option<Option<Handle>> = None;
    let mut batch = plan(
        &mut current,
        &mut previous,
        rotated,
        cursor,
        options,
        state,
        stop,
    )?;
    let late = late_rotated_lines(&mut previous, rotated, state)?;
    batch.gap |= late;
    batch.rotated_opened = matches!(previous, Some(Some(_)));
    Ok(batch)
}

fn open_rotated<'a>(
    previous: &'a mut Option<Option<Handle>>,
    rotated: Option<&Path>,
) -> Result<Option<&'a mut Handle>, ReadError> {
    if previous.is_none() {
        *previous = Some(handle::open(rotated)?);
    }
    Ok(previous.as_mut().and_then(Option::as_mut))
}

fn late_rotated_lines(
    previous: &mut Option<Option<Handle>>,
    rotated: Option<&Path>,
    state: &mut RotationState,
) -> Result<bool, ReadError> {
    let Some((fingerprint, length)) = state.abandoned.clone() else {
        return Ok(false);
    };
    let file = open_rotated(previous, rotated)?;
    let Some(file) = file.filter(|file| file.fingerprint.as_deref() == Some(fingerprint.as_str()))
    else {
        state.abandoned = None; // Rotated again or removed: nothing more can arrive.
        return Ok(false);
    };
    if file.length <= length {
        return Ok(false);
    }
    state.abandoned = Some((fingerprint, file.length));
    Ok(true)
}

fn plan(
    current: &mut Option<Handle>,
    previous: &mut Option<Option<Handle>>,
    rotated: Option<&Path>,
    cursor: Option<&Cursor>,
    options: &ReaderOptions,
    state: &mut RotationState,
    stop: Option<&AtomicBool>,
) -> Result<Batch, ReadError> {
    let fingerprint = current.as_ref().and_then(|file| file.fingerprint.clone());
    let Some(cursor) = cursor else {
        state.observed = None;
        let Some(fingerprint) = fingerprint else {
            return Ok(empty(Cursor::new("", 0)));
        };
        let file = current.as_mut().expect("identified file is open");
        if !options.start_at_end {
            return read_file(file, &Cursor::new(fingerprint, 0), options, false, false);
        }
        let (offset, discarding) = start_position(file, options.max_bytes_per_batch, stop)?;
        return Ok(empty(Cursor {
            discarding,
            ..Cursor::new(fingerprint, offset)
        }));
    };

    if cursor.fingerprint.is_empty() {
        // Provisional cursor: the file was missing or too short to identify.
        state.observed = None;
        return match fingerprint {
            None => Ok(empty(cursor.clone())),
            Some(fingerprint) => read_file(
                current.as_mut().expect("identified file is open"),
                &Cursor::new(fingerprint, 0),
                options,
                false,
                false,
            ),
        };
    }

    if fingerprint.as_deref() == Some(cursor.fingerprint.as_str()) {
        let length = current.as_ref().expect("identified file is open").length;
        if length >= cursor.offset {
            state.observed = None;
            return read_file(
                current.as_mut().expect("identified file is open"),
                cursor,
                options,
                false,
                false,
            );
        }
        // Shorter than the cursor with the same identity: copytruncate whose new first line
        // repeats the old one. Drain the copy in path.1 first when it is ours.
        if let Some(copy) = open_rotated(previous, rotated)?
            && copy.fingerprint.as_deref() == Some(cursor.fingerprint.as_str())
            && copy.length >= cursor.offset
        {
            return drain(copy, cursor, fingerprint, options, state);
        }
        // Truncated in place without a matching copy: restart and flag the gap.
        state.observed = None;
        return read_file(
            current.as_mut().expect("identified file is open"),
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

    // The current file is another file. Drain the rotated file first if it is ours.
    if let Some(previous) = open_rotated(previous, rotated)?
        && previous.fingerprint.as_deref() == Some(cursor.fingerprint.as_str())
    {
        return drain(previous, cursor, fingerprint, options, state);
    }

    state.observed = None;
    let Some(fingerprint) = fingerprint else {
        // Missing or too short to identify, and not rotated: wait.
        return Ok(empty(cursor.clone()));
    };
    // Rotated more than once since the last read, or replaced: lines were lost.
    read_file(
        current.as_mut().expect("identified file is open"),
        &Cursor::new(fingerprint, 0),
        options,
        false,
        true,
    )
}

fn drain(
    file: &mut Handle,
    cursor: &Cursor,
    current_fingerprint: Option<String>,
    options: &ReaderOptions,
    state: &mut RotationState,
) -> Result<Batch, ReadError> {
    let observed = (file.length, file.write_time);
    if state.observed == Some(observed) {
        state.stable_polls =
            (state.stable_polls + 1).min(crate::config::MAXIMUM_ROTATION_GRACE_POLLS);
    } else {
        state.observed = Some(observed);
        state.stable_polls = 0;
    }
    // Leave path.1 only once the current file is identified and path.1 has settled; until
    // then a writer may still add to it, and its last line may still grow.
    let leave = current_fingerprint.is_some() && state.stable_polls >= options.rotation_grace_polls;
    let batch = read_file(file, cursor, options, leave, false)?;
    if !leave || batch.more || batch.cursor.offset < file.length {
        return Ok(batch);
    }
    state.observed = None;
    state.abandoned = Some((cursor.fingerprint.clone(), file.length));
    Ok(Batch {
        cursor: Cursor::new(current_fingerprint.expect("identified current file"), 0),
        rotated: true,
        more: true,
        ..batch
    })
}

/// The identity of the file at `path` (`None` when it has none yet).
pub fn fingerprint(path: &Path) -> std::io::Result<Option<String>> {
    handle::fingerprint(path)
}

fn read_file(
    file: &mut Handle,
    cursor: &Cursor,
    options: &ReaderOptions,
    eof_ends_line: bool,
    gap: bool,
) -> Result<Batch, ReadError> {
    let mut lines = Vec::new();
    let mut committed = cursor.offset;
    let mut discarding = cursor.discarding;
    let mut more = false;

    // The length when opened bounds this read; bytes appended meanwhile wait.
    let length = file.length;
    if cursor.offset > length {
        return Ok(empty(cursor.clone()));
    }
    let stream = &mut file.file;
    stream.seek(SeekFrom::Start(cursor.offset as u64))?;
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
        let continues_discard = discarding;
        // A line may run up to its own limit past the byte budget, never past the snapshot.
        let limit = length.min(budget_end.max(line_start + max_line as i64 + 1));
        let mut count = 0usize;
        let mut oversized = discarding;
        let mut terminated = false;
        while position < limit {
            if chunk_index == chunk_length {
                let wanted = (chunk.len() as i64).min(limit - position) as usize;
                chunk_length = stream.read(&mut chunk[..wanted])?;
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
                    continues_discard,
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
                    continues_discard: false,
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
        rotated_opened: false,
    })
}

/// After the last complete line, scanning back at most `budget` bytes. Without a newline in
/// that window the read starts at the end, skipping the rest of the line being written; a
/// file with no newline at all starts at 0.
fn start_position(
    file: &mut Handle,
    budget: u64,
    stop: Option<&AtomicBool>,
) -> Result<(i64, bool), ReadError> {
    let mut block = [0u8; 4_096];
    let mut end = file.length;
    let floor = file
        .length
        .saturating_sub(i64::try_from(budget).unwrap_or(i64::MAX))
        .max(0);
    while end > floor {
        if stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            return Err(ReadError::Stopped);
        }
        let count = (block.len() as i64).min(end - floor) as usize;
        let start = end - count as i64;
        file.file.seek(SeekFrom::Start(start as u64))?;
        // A concurrent truncation can shorten the read; bytes past EOF are never '\n'.
        let mut read = 0;
        while read < count {
            let got = file.file.read(&mut block[read..count])?;
            if got == 0 {
                break;
            }
            read += got;
        }
        if let Some(newline) = block[..read].iter().rposition(|&byte| byte == b'\n') {
            return Ok((start + newline as i64 + 1, false));
        }
        end = start;
    }
    Ok(if floor > 0 {
        (file.length, true)
    } else {
        (0, false)
    })
}

fn empty(cursor: Cursor) -> Batch {
    Batch {
        lines: Vec::new(),
        cursor,
        rotated: false,
        gap: false,
        more: false,
        rotated_opened: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> String {
        format!(
            "{text} {}\n",
            "x".repeat(69usize.saturating_sub(text.len()))
        )
    }

    fn options() -> ReaderOptions {
        ReaderOptions {
            start_at_end: false,
            rotation_grace_polls: 1,
            ..ReaderOptions::default()
        }
    }

    /// C# `RotatedFileSwappedForAnOutsideLinkBeforeTheOpen_IsRefusedAndNeverRead`.
    #[cfg(unix)]
    #[test]
    fn rotated_file_swapped_for_an_outside_link_before_the_open_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.log");
        let rotated = directory.path().join("auth.log.1");
        let secret = outside.path().join("shadow");
        std::fs::write(&secret, line("root:secret-marker")).unwrap();
        std::fs::write(&path, line("first-1")).unwrap();
        let mut state = RotationState::default();
        let cursor = read(Some(&path), None, None, &options(), &mut state, None)
            .unwrap()
            .cursor;
        std::fs::write(&path, format!("{}{}", line("first-1"), line("first-2"))).unwrap();
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, line("second-1")).unwrap();
        let (swap, target) = (rotated.clone(), secret.clone());
        handle::BEFORE_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |opening: &Path| {
                if opening == swap {
                    std::fs::remove_file(&swap).unwrap();
                    std::os::unix::fs::symlink(&target, &swap).unwrap();
                }
            }));
        });
        let result = read(
            Some(&path),
            Some(&rotated),
            Some(&cursor),
            &options(),
            &mut state,
            None,
        );
        handle::BEFORE_OPEN.with(|hook| *hook.borrow_mut() = None);
        assert!(matches!(result, Err(ReadError::Refused)));
    }

    /// C# `FileReplacedWhileBeingRead_OnlyItsOwnGenerationMovesTheCursor`.
    #[test]
    fn file_replaced_while_being_read_only_its_own_generation_moves_the_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.log");
        std::fs::write(&path, line("old-1")).unwrap();
        let mut state = RotationState::default();
        let cursor = read(Some(&path), None, None, &options(), &mut state, None)
            .unwrap()
            .cursor;
        let old = cursor.fingerprint.clone();
        std::fs::write(&path, format!("{}{}", line("old-1"), line("old-2"))).unwrap();
        let replacement = directory.path().join("replacement");
        std::fs::write(
            &replacement,
            format!("{}{}{}", line("new-1"), line("new-2"), line("new-3")),
        )
        .unwrap();
        let (target, from) = (path.clone(), replacement.clone());
        handle::AFTER_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |opened: &Path| {
                if opened == target {
                    std::fs::rename(&from, &target).unwrap();
                }
            }));
        });
        let batch = read(
            Some(&path),
            None,
            Some(&cursor),
            &options(),
            &mut state,
            None,
        );
        handle::AFTER_OPEN.with(|hook| *hook.borrow_mut() = None);
        let batch = batch.unwrap();
        assert_eq!(batch.lines.len(), 1);
        assert!(batch.lines[0].bytes.starts_with(b"old-2"));
        assert_eq!(
            (batch.cursor.fingerprint.as_str(), batch.cursor.offset),
            (old.as_str(), line("old-1").len() as i64 * 2)
        );
        let next = read(
            Some(&path),
            None,
            Some(&batch.cursor),
            &options(),
            &mut state,
            None,
        )
        .unwrap();
        assert!(next.gap);
        assert_eq!(next.lines.len(), 3);
        assert_ne!(next.cursor.fingerprint, old);
    }

    /// C# `StartAtEnd_ScanIsBoundedAndCancellable`.
    #[test]
    fn start_at_end_scan_is_bounded_and_stoppable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.log");
        std::fs::write(&path, format!("{}{}", line("first"), "z".repeat(200_000))).unwrap();
        let options = ReaderOptions {
            start_at_end: true,
            max_bytes_per_batch: 65_536,
            ..ReaderOptions::default()
        };
        let mut state = RotationState::default();
        let batch = read(Some(&path), None, None, &options, &mut state, None).unwrap();
        let length = std::fs::metadata(&path).unwrap().len() as i64;
        assert_eq!(
            (batch.cursor.offset, batch.cursor.discarding),
            (length, true)
        );
        let stop = AtomicBool::new(true);
        assert!(matches!(
            read(Some(&path), None, None, &options, &mut state, Some(&stop)),
            Err(ReadError::Stopped)
        ));
    }
}
