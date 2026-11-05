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

use serde::{Deserialize, Serialize};

use crate::handle::{self, Handle, OpenError};

/// 2 since the rotation fields (C# `FileTailCursor.CurrentSchemaVersion`). A stored cursor
/// of any other version is never interpreted: `is_other_schema` lets the source replay the
/// current file from its start instead.
pub const CURRENT_SCHEMA_VERSION: i32 = 2;

/// Position in one tailed file and the rotation state that must survive a restart (C#
/// `FileTailCursor`, same JSON). An empty fingerprint is provisional: the file was missing
/// or could not be identified yet. `drain` (`rename` or `copytruncate`) means the cursor
/// refers to `path.1`; `observed_*` and `stable_polls` track a rename's grace window;
/// `abandoned` is the generation the cursor left after a rename. Optional fields are omitted
/// when unset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    pub schema_version: i32,
    pub fingerprint: String,
    pub offset: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub discarding: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_write_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stable_polls: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_polls: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned_length: Option<i64>,
}

pub const RENAME_DRAIN: &str = "rename";
pub const COPY_DRAIN: &str = "copytruncate";

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
    #[serde(default)]
    file_id: Option<String>,
    #[serde(default)]
    drain: Option<String>,
    #[serde(default)]
    observed_length: Option<i64>,
    #[serde(default)]
    observed_write_time: Option<i64>,
    #[serde(default)]
    stable_polls: Option<i32>,
    #[serde(default)]
    drain_polls: Option<i32>,
    #[serde(default)]
    abandoned: Option<String>,
    #[serde(default)]
    abandoned_length: Option<i64>,
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_file_id(value: &str) -> bool {
    match value.split_once(':') {
        Some((device, inode)) => {
            !device.is_empty()
                && !inode.is_empty()
                && value.len() <= 41
                && device.bytes().all(|byte| byte.is_ascii_digit())
                && inode.bytes().all(|byte| byte.is_ascii_digit())
        }
        None => false,
    }
}

impl Cursor {
    pub fn new(fingerprint: impl Into<String>, offset: i64) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            fingerprint: fingerprint.into(),
            offset,
            discarding: false,
            file_id: None,
            drain: None,
            observed_length: None,
            observed_write_time: None,
            stable_polls: None,
            drain_polls: None,
            abandoned: None,
            abandoned_length: None,
        }
    }

    /// A JSON object with an integer `schemaVersion` other than the current one: a cursor
    /// from another build, whose meaning must not be guessed (C# `IsOtherSchema`).
    pub fn is_other_schema(value: &str) -> bool {
        serde_json::from_str::<serde_json::Value>(value)
            .ok()
            .and_then(|value| {
                value
                    .get("schemaVersion")
                    .and_then(serde_json::Value::as_i64)
            })
            .is_some_and(|version| {
                i32::try_from(version).is_ok_and(|version| version != CURRENT_SCHEMA_VERSION)
            })
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
        let cursor = Self {
            schema_version: stored.schema_version,
            fingerprint: stored.fingerprint?,
            offset: stored.offset,
            discarding: stored.discarding,
            file_id: stored.file_id,
            drain: stored.drain,
            observed_length: stored.observed_length,
            observed_write_time: stored.observed_write_time,
            stable_polls: stored.stable_polls,
            drain_polls: stored.drain_polls,
            abandoned: stored.abandoned,
            abandoned_length: stored.abandoned_length,
        };
        (cursor.schema_version == CURRENT_SCHEMA_VERSION && cursor.offset >= 0 && cursor.is_valid())
            .then_some(cursor)
    }

    fn is_valid(&self) -> bool {
        (self.fingerprint.is_empty() || is_fingerprint(&self.fingerprint))
            && self.file_id.as_deref().is_none_or(is_file_id)
            && self.drain.as_deref().is_none_or(|drain| {
                !self.fingerprint.is_empty() && (drain == RENAME_DRAIN || drain == COPY_DRAIN)
            })
            && self.observed_length.is_none() == self.observed_write_time.is_none()
            && self.observed_length.is_none() == self.stable_polls.is_none()
            && self.observed_length.is_none_or(|length| length >= 0)
            && self.stable_polls.is_none_or(|polls| polls >= 0)
            && (self.observed_length.is_none() || self.drain.as_deref() == Some(RENAME_DRAIN))
            && self
                .drain_polls
                .is_none_or(|polls| self.drain.as_deref() == Some(RENAME_DRAIN) && polls >= 0)
            && self.abandoned.is_none() == self.abandoned_length.is_none()
            && self.abandoned.as_deref().is_none_or(is_fingerprint)
            && self.abandoned_length.is_none_or(|length| length >= 0)
    }

    fn normal(fingerprint: &str, offset: i64, file_id: Option<String>) -> Self {
        Self {
            file_id,
            ..Self::new(fingerprint, offset)
        }
    }

    /// The cursor now refers to path.1; grace and abandoned state start afresh.
    fn start_drain(&self, kind: &str) -> Self {
        Self {
            drain: Some(kind.to_owned()),
            observed_length: None,
            observed_write_time: None,
            stable_polls: None,
            drain_polls: None,
            abandoned: None,
            abandoned_length: None,
            ..self.clone()
        }
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
    /// The cursor moved from a drained `path.1` to the current file.
    pub rotated: bool,
    /// Lines may have been lost: rotated more than once, truncated in place, the generation
    /// being drained disappeared, or lines were written to `path.1` after the cursor left it.
    pub gap: bool,
    /// A limit stopped the read, or the cursor moved files: read again without waiting.
    pub more: bool,
    /// This read opened `path.1`, so the caller re-checks it.
    pub rotated_opened: bool,
    /// The cursor the lines were read under: a rewind to a line's start is this cursor at
    /// that offset, so it never carries a switch the batch did not commit.
    pub origin: Option<Cursor>,
}

impl Batch {
    /// Back to a line's start; inside an oversized line, keep skipping it.
    pub fn rewind_to(&self, line: &Line) -> Cursor {
        Cursor {
            offset: line.start_offset,
            discarding: line.continues_discard,
            ..self.origin.clone().unwrap_or_else(|| self.cursor.clone())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderOptions {
    pub max_line_bytes: usize,
    pub max_lines_per_batch: usize,
    pub max_bytes_per_batch: u64,
    /// When a file is first seen, start after its last complete line.
    pub start_at_end: bool,
    /// Unchanged end-of-file polls of a renamed `path.1` (size and write time) before the
    /// cursor moves to the new file. Copytruncate never waits.
    pub rotation_grace_polls: i32,
    /// Polls a rename drain may take before the cursor moves on anyway, so a `path.1` that
    /// keeps changing cannot starve the current file (C# `RotationDrainMaxPolls`).
    pub rotation_drain_max_polls: i32,
    /// Use device and inode numbers (Unix) to tell rename from copytruncate and to spot a
    /// replaced file. Off, identities alone decide; the shared vectors run this way.
    pub use_file_ids: bool,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_line_bytes: crate::config::DEFAULT_MAX_LINE_BYTES as usize,
            max_lines_per_batch: 256,
            max_bytes_per_batch: 1_048_576,
            start_at_end: true,
            rotation_grace_polls: crate::config::DEFAULT_ROTATION_GRACE_POLLS,
            rotation_drain_max_polls: crate::config::DEFAULT_ROTATION_DRAIN_MAX_POLLS,
            use_file_ids: true,
        }
    }
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
/// `rotated` is `path.1` when it exists (already checked). Rotation state lives in the
/// cursor (C# `FileTailReader.Read`): once a rotation is detected the cursor refers to
/// `path.1` and the current file is not read until it is drained. A copytruncate copy is
/// drained to its end and the cursor moves on at once; a renamed `path.1` is left only once
/// the current file is identified and `path.1` stayed unchanged over
/// `rotation_grace_polls` end-of-file polls, and its later growth is reported as a gap.
pub fn read(
    path: Option<&Path>,
    rotated: Option<&Path>,
    cursor: Option<&Cursor>,
    options: &ReaderOptions,
    stop: Option<&AtomicBool>,
) -> Result<Batch, ReadError> {
    let mut reading = Reading {
        current: handle::open(path)?,
        previous: None,
        rotated,
        options,
        stop,
    };
    let fingerprint = reading
        .current
        .as_ref()
        .and_then(|file| file.fingerprint.clone());
    let file_id = if options.use_file_ids {
        match &reading.current {
            Some(file) => file.file_id.clone(),
            None => path.and_then(handle::file_id_of),
        }
    } else {
        None
    };
    let mut batch = reading.plan(cursor, fingerprint, file_id)?;
    batch.rotated_opened = matches!(reading.previous, Some(Some(_)));
    Ok(batch)
}

struct Reading<'a> {
    current: Option<Handle>,
    /// `path.1`, opened on first use.
    previous: Option<Option<Handle>>,
    rotated: Option<&'a Path>,
    options: &'a ReaderOptions,
    stop: Option<&'a AtomicBool>,
}

impl Reading<'_> {
    fn rotated(&mut self) -> Result<Option<&mut Handle>, ReadError> {
        if self.previous.is_none() {
            self.previous = Some(handle::open(self.rotated)?);
        }
        Ok(self.previous.as_mut().and_then(Option::as_mut))
    }

    /// `path.1` when it carries `fingerprint` (and its length).
    fn previous_matching(&mut self, fingerprint: &str) -> Result<Option<i64>, ReadError> {
        Ok(self
            .rotated()?
            .filter(|file| file.fingerprint.as_deref() == Some(fingerprint))
            .map(|file| file.length))
    }

    fn current(&mut self) -> &mut Handle {
        self.current.as_mut().expect("identified file is open")
    }

    fn scan_current(&mut self, at: Cursor, gap: bool) -> Result<Batch, ReadError> {
        let options = *self.options;
        scan(self.current(), at, &options, false, gap)
    }

    fn plan(
        &mut self,
        cursor: Option<&Cursor>,
        fingerprint: Option<String>,
        file_id: Option<String>,
    ) -> Result<Batch, ReadError> {
        let Some(cursor) = cursor else {
            let Some(fingerprint) = fingerprint else {
                return Ok(empty(Cursor::new("", 0)));
            };
            let initial = Cursor::normal(&fingerprint, 0, file_id);
            if !self.options.start_at_end {
                return self.scan_current(initial, false);
            }
            let (budget, stop) = (self.options.max_bytes_per_batch, self.stop);
            let (offset, discarding) = start_position(self.current(), budget, stop)?;
            return Ok(empty(Cursor {
                offset,
                discarding,
                ..initial
            }));
        };
        if cursor.drain.is_some() {
            return self.drain(cursor.clone(), fingerprint, file_id);
        }
        if cursor.fingerprint.is_empty() {
            // Provisional cursor: the file was missing or could not be identified.
            return match fingerprint {
                None => Ok(empty(cursor.clone())),
                Some(fingerprint) => {
                    self.scan_current(Cursor::normal(&fingerprint, 0, file_id), false)
                }
            };
        }
        let (watched, late) = self.watch_abandoned(cursor)?;
        let mut batch = self.detect(watched, fingerprint, file_id)?;
        batch.gap |= late;
        Ok(batch)
    }

    /// A generation the cursor left after a rename: writes to it now can never be read.
    fn watch_abandoned(&mut self, at: &Cursor) -> Result<(Cursor, bool), ReadError> {
        let (Some(abandoned), Some(length)) = (at.abandoned.clone(), at.abandoned_length) else {
            return Ok((at.clone(), false));
        };
        match self.previous_matching(&abandoned)? {
            // Rotated again or removed: nothing more can arrive.
            None => Ok((
                Cursor {
                    abandoned: None,
                    abandoned_length: None,
                    ..at.clone()
                },
                false,
            )),
            Some(grown) if grown > length => Ok((
                Cursor {
                    abandoned_length: Some(grown),
                    ..at.clone()
                },
                true,
            )),
            Some(_) => Ok((at.clone(), false)),
        }
    }

    fn detect(
        &mut self,
        at: Cursor,
        fingerprint: Option<String>,
        file_id: Option<String>,
    ) -> Result<Batch, ReadError> {
        let same_file = matches!((&file_id, &at.file_id), (Some(now), Some(then)) if now == then);
        let other_file = matches!((&file_id, &at.file_id), (Some(now), Some(then)) if now != then);
        let same_identity = fingerprint.as_deref() == Some(at.fingerprint.as_str());

        if same_identity && !other_file {
            let length = self.current().length;
            if length >= at.offset {
                let file_id = file_id.or_else(|| at.file_id.clone());
                return self.scan_current(Cursor { file_id, ..at }, false);
            }
            // Shorter than the cursor: copytruncate when path.1 is the copy, else truncated.
            if self
                .previous_matching(&at.fingerprint)?
                .is_some_and(|copy| copy >= at.offset)
            {
                return self.drain(at.start_drain(COPY_DRAIN), fingerprint, file_id);
            }
            let fingerprint = fingerprint.expect("identified file");
            return self.scan_current(Cursor::normal(&fingerprint, 0, file_id), true);
        }

        if same_file {
            // The same file rewritten in place (its first line changed): copytruncate.
            if self.previous_matching(&at.fingerprint)?.is_some() {
                return self.drain(at.start_drain(COPY_DRAIN), fingerprint, file_id);
            }
            return match fingerprint {
                None => Ok(Batch {
                    gap: true,
                    ..empty(Cursor::new("", 0))
                }),
                Some(fingerprint) => {
                    self.scan_current(Cursor::normal(&fingerprint, 0, file_id), true)
                }
            };
        }

        // Another file at the path: rename rotation when path.1 is ours.
        if self.previous_matching(&at.fingerprint)?.is_some() {
            return self.drain(at.start_drain(RENAME_DRAIN), fingerprint, file_id);
        }
        // Missing or not identified yet, and not rotated: wait. Otherwise rotated more than
        // once since the last read, or replaced: lines were lost.
        match fingerprint {
            None => Ok(empty(at)),
            Some(fingerprint) => self.scan_current(Cursor::normal(&fingerprint, 0, file_id), true),
        }
    }

    fn drain(
        &mut self,
        at: Cursor,
        fingerprint: Option<String>,
        file_id: Option<String>,
    ) -> Result<Batch, ReadError> {
        let options = *self.options;
        let next = match &fingerprint {
            None => Cursor::new("", 0),
            Some(fingerprint) => Cursor::normal(fingerprint, 0, file_id),
        };
        if self.previous_matching(&at.fingerprint)?.is_none() {
            // The generation being drained is gone (removed or rotated again): lines were lost.
            return match fingerprint {
                None => Ok(Batch {
                    gap: true,
                    ..empty(next)
                }),
                Some(_) => self.scan_current(next, true),
            };
        }
        let file = self.rotated()?.expect("matching rotated file is open");
        if at.drain.as_deref() == Some(COPY_DRAIN) {
            // A static copy: drain it to its end, then move to the truncated original at once.
            let copied = scan(file, at, &options, true, false)?;
            return Ok(if copied.more {
                copied
            } else {
                Batch {
                    cursor: next,
                    rotated: true,
                    more: true,
                    ..copied
                }
            });
        }

        let scanned = scan(file, at.clone(), &options, false, false)?;
        let polls =
            (at.drain_polls.unwrap_or(0) + 1).min(crate::config::MAXIMUM_ROTATION_DRAIN_MAX_POLLS);
        let batch = Batch {
            cursor: Cursor {
                drain_polls: Some(polls),
                ..scanned.cursor.clone()
            },
            ..scanned
        };
        if polls >= options.rotation_drain_max_polls {
            // A path.1 that never settles cannot hold the cursor: move on anyway. What is left
            // unread in it now, and anything written to it later, is a gap.
            let unread = batch.cursor.offset < file.length;
            return Ok(Batch {
                cursor: Cursor {
                    abandoned: Some(at.fingerprint.clone()),
                    abandoned_length: Some(file.length),
                    ..next
                },
                rotated: true,
                more: true,
                gap: batch.gap || unread,
                ..batch
            });
        }
        if batch.more {
            return Ok(batch); // A backlog poll never counts towards the grace window.
        }
        // At the end of path.1 (only an unterminated last line may remain).
        let write_ticks = file.write_ticks();
        let unchanged =
            at.observed_length == Some(file.length) && at.observed_write_time == Some(write_ticks);
        let stable = if unchanged {
            (at.stable_polls.unwrap_or(0) + 1).min(crate::config::MAXIMUM_ROTATION_GRACE_POLLS)
        } else {
            0
        };
        let observed = Cursor {
            observed_length: Some(file.length),
            observed_write_time: Some(write_ticks),
            stable_polls: Some(stable),
            ..batch.cursor.clone()
        };
        if fingerprint.is_none()
            || stable < options.rotation_grace_polls
            || batch.lines.len() >= options.max_lines_per_batch
        {
            return Ok(Batch {
                cursor: observed,
                ..batch
            });
        }
        // Settled: its unterminated last line is complete, then leave it.
        let length = file.length;
        let tail = scan(file, observed, &options, true, false)?;
        let mut lines = batch.lines;
        lines.extend(tail.lines);
        Ok(Batch {
            lines,
            cursor: Cursor {
                abandoned: Some(at.fingerprint.clone()),
                abandoned_length: Some(length),
                ..next
            },
            rotated: true,
            more: true,
            ..batch
        })
    }
}

fn scan(
    file: &mut Handle,
    at: Cursor,
    options: &ReaderOptions,
    eof_ends_line: bool,
    gap: bool,
) -> Result<Batch, ReadError> {
    let batch = read_file(file, &at, options, eof_ends_line, gap)?;
    Ok(Batch {
        origin: Some(at),
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
        origin: None,
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
        origin: None,
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
        let cursor = read(Some(&path), None, None, &options(), None)
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
        let result = read(Some(&path), Some(&rotated), Some(&cursor), &options(), None);
        handle::BEFORE_OPEN.with(|hook| *hook.borrow_mut() = None);
        assert!(matches!(result, Err(ReadError::Refused)));
    }

    /// C# `FileReplacedWhileBeingRead_OnlyItsOwnGenerationMovesTheCursor`.
    #[test]
    fn file_replaced_while_being_read_only_its_own_generation_moves_the_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.log");
        std::fs::write(&path, line("old-1")).unwrap();
        let cursor = read(Some(&path), None, None, &options(), None)
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
        let batch = read(Some(&path), None, Some(&cursor), &options(), None);
        handle::AFTER_OPEN.with(|hook| *hook.borrow_mut() = None);
        let batch = batch.unwrap();
        assert_eq!(batch.lines.len(), 1);
        assert!(batch.lines[0].bytes.starts_with(b"old-2"));
        assert_eq!(
            (batch.cursor.fingerprint.as_str(), batch.cursor.offset),
            (old.as_str(), line("old-1").len() as i64 * 2)
        );
        let next = read(Some(&path), None, Some(&batch.cursor), &options(), None).unwrap();
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
        let batch = read(Some(&path), None, None, &options, None).unwrap();
        let length = std::fs::metadata(&path).unwrap().len() as i64;
        assert_eq!(
            (batch.cursor.offset, batch.cursor.discarding),
            (length, true)
        );
        let stop = AtomicBool::new(true);
        assert!(matches!(
            read(Some(&path), None, None, &options, Some(&stop)),
            Err(ReadError::Stopped)
        ));
    }
}
