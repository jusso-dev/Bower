//! Security-selected local file tail (C# `FileTailSource`). Each configured file is read
//! line by line and every line goes through its route's signed pack parser, then
//! redaction, policy and the durable queue; lines the parser does not select are counted
//! and dropped.
//!
//! The cursor moves past a line only once it is durably enqueued or definitively dropped
//! and is committed after each poll. A full queue stops reading and rewinds to the start
//! of the line it could not take. A crash between enqueue and commit re-reads those lines;
//! their deterministic ids make the queue drop them as duplicates. The sink and cursor
//! store are synchronous: the run loop calls `poll_once` on the blocking pool.
//!
//! Divergence: C# cancels a submission in flight; the synchronous sink cannot be
//! interrupted, so stopping takes effect between lines (the rest of the poll is rewound).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bower_contracts::time::{Clock, SystemClock, Timestamp, serde_offset_option};
use bower_contracts::{SourceCursorStore, StoreError};
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::{self, FileTailSourceConfiguration, InputOptions};
use crate::paths::{self, PathState};
use crate::reader::{self, Batch, Cursor, Line, ReadError, ReaderOptions};
use crate::record;

/// What happened to one record handed to the collector (C# `FileTailSubmitOutcome`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Durably enqueued. Only then can the cursor move past the line.
    Queued,
    Duplicate,
    Suppressed,
    /// The pack parser's filter did not select the record: counted and dropped.
    NotSelected,
    Rejected,
    Invalid,
    TooLarge,
    /// Queue at capacity or ingest gated: stop reading and retry the same line.
    Unavailable,
}

/// The sink failed (storage error); the line was not durably accepted.
#[derive(Debug)]
pub struct SinkFailure;

/// Collector side of the source. Synchronous: called on the blocking pool.
pub trait FileTailSink: Send + Sync + 'static {
    fn submit(&self, input: &InputOptions, record: &str) -> Result<SubmitOutcome, SinkFailure>;
}

/// Stable, metadata-only failure codes (C# `FileTailFailures`).
pub mod failures {
    pub const PATH_REFUSED: &str = "file-path-refused";
    pub const READ_FAILED: &str = "file-read-failed";
    pub const CURSOR_INVALID: &str = "file-cursor-invalid";
    pub const CURSOR_CONFLICT: &str = "file-cursor-conflict";
    pub const SUBMIT_FAILED: &str = "file-submit-failed";
    pub const SOURCE_FAILED: &str = "file-source-failed";
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{code}")]
pub struct FileTailError {
    pub code: &'static str,
}

impl FileTailError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}

/// Per-input counters since start. Metadata only (C# `FileTailInputStatus`, same JSON).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputStatus {
    pub id: String,
    pub path: String,
    /// `starting`, `running`, `waiting`, `backpressure`, `stopped` or a failure code.
    pub state: String,
    pub offset: Option<i64>,
    pub lines_read: i64,
    pub bytes_read: i64,
    pub queued: i64,
    pub duplicates: i64,
    pub suppressed: i64,
    pub not_selected: i64,
    pub rejected: i64,
    pub parser_errors: i64,
    pub too_large: i64,
    pub malformed: i64,
    pub oversized: i64,
    pub blank: i64,
    pub rotations: i64,
    pub rotation_gaps: i64,
    pub backpressure: i64,
    pub read_errors: i64,
    pub submit_failures: i64,
    pub cursor_conflicts: i64,
    #[serde(with = "serde_offset_option")]
    pub last_line_at: Option<Timestamp>,
    #[serde(with = "serde_offset_option")]
    pub last_poll_at: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollResult {
    /// Lines read (including oversized and blank ones).
    pub lines: usize,
    /// The queue could not take a line; it is retried next time.
    pub backpressure: bool,
    /// A limit stopped the read; read again without waiting.
    pub more: bool,
}

#[derive(Default)]
struct Counters {
    lines_read: AtomicI64,
    bytes_read: AtomicI64,
    queued: AtomicI64,
    duplicates: AtomicI64,
    suppressed: AtomicI64,
    not_selected: AtomicI64,
    rejected: AtomicI64,
    parser_errors: AtomicI64,
    too_large: AtomicI64,
    malformed: AtomicI64,
    oversized: AtomicI64,
    blank: AtomicI64,
    rotations: AtomicI64,
    rotation_gaps: AtomicI64,
    backpressure: AtomicI64,
    read_errors: AtomicI64,
    submit_failures: AtomicI64,
    cursor_conflicts: AtomicI64,
}

struct InputState {
    options: InputOptions,
    gate: Mutex<()>,
    counters: Counters,
    state: Mutex<String>,
    offset: AtomicI64,
    last_line_at: Mutex<Option<Timestamp>>,
    last_poll_at: Mutex<Option<Timestamp>>,
}

impl InputState {
    fn set_state(&self, state: &str) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = state.to_owned();
    }

    fn snapshot(&self) -> InputStatus {
        let c = &self.counters;
        let load = |value: &AtomicI64| value.load(Ordering::Relaxed);
        let offset = load(&self.offset);
        InputStatus {
            id: self.options.id.clone(),
            path: self.options.path.clone(),
            state: self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone(),
            offset: (offset >= 0).then_some(offset),
            lines_read: load(&c.lines_read),
            bytes_read: load(&c.bytes_read),
            queued: load(&c.queued),
            duplicates: load(&c.duplicates),
            suppressed: load(&c.suppressed),
            not_selected: load(&c.not_selected),
            rejected: load(&c.rejected),
            parser_errors: load(&c.parser_errors),
            too_large: load(&c.too_large),
            malformed: load(&c.malformed),
            oversized: load(&c.oversized),
            blank: load(&c.blank),
            rotations: load(&c.rotations),
            rotation_gaps: load(&c.rotation_gaps),
            backpressure: load(&c.backpressure),
            read_errors: load(&c.read_errors),
            submit_failures: load(&c.submit_failures),
            cursor_conflicts: load(&c.cursor_conflicts),
            last_line_at: *self
                .last_line_at
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
            last_poll_at: *self
                .last_poll_at
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        }
    }
}

/// Counters shared with the status endpoint after the source moved into its run task.
#[derive(Clone)]
pub struct FileTailMetrics(Arc<Vec<Arc<InputState>>>);

impl FileTailMetrics {
    pub fn snapshot(&self) -> Vec<InputStatus> {
        self.0.iter().map(|input| input.snapshot()).collect()
    }
}

pub struct FileTailSource {
    configuration: FileTailSourceConfiguration,
    roots: Vec<String>,
    poll_interval: Duration,
    max_lines_per_batch: usize,
    max_bytes_per_batch: u64,
    sink: Arc<dyn FileTailSink>,
    cursors: Arc<dyn SourceCursorStore>,
    clock: Arc<dyn Clock>,
    inputs: Arc<Vec<Arc<InputState>>>,
    by_id: HashMap<String, usize>,
    stopping: Arc<AtomicBool>,
    retry_delay: Duration,
    maximum_backoff: Duration,
    rotation_grace_polls: i32,
    transient: Arc<dyn Fn(&StoreError) -> bool + Send + Sync>,
}

impl FileTailSource {
    pub fn new(
        configuration: FileTailSourceConfiguration,
        sink: Arc<dyn FileTailSink>,
        cursors: Arc<dyn SourceCursorStore>,
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        let inputs: Vec<Arc<InputState>> = configuration
            .inputs()
            .map(|options| {
                Arc::new(InputState {
                    options: options.clone(),
                    gate: Mutex::new(()),
                    counters: Counters::default(),
                    state: Mutex::new("starting".into()),
                    offset: AtomicI64::new(-1),
                    last_line_at: Mutex::new(None),
                    last_poll_at: Mutex::new(None),
                })
            })
            .collect();
        let by_id = inputs
            .iter()
            .enumerate()
            .map(|(index, input)| (input.options.id.clone(), index))
            .collect();
        Self {
            roots: configuration.roots(),
            poll_interval: Duration::from_millis(
                u64::try_from(configuration.poll_interval_milliseconds).unwrap_or(1_000),
            ),
            max_lines_per_batch: usize::try_from(configuration.max_lines_per_batch).unwrap_or(256),
            max_bytes_per_batch: u64::try_from(configuration.max_bytes_per_batch)
                .unwrap_or(1_048_576),
            sink,
            cursors,
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
            inputs: Arc::new(inputs),
            by_id,
            stopping: Arc::new(AtomicBool::new(false)),
            retry_delay: Duration::from_secs(1),
            maximum_backoff: Duration::from_secs(60),
            rotation_grace_polls: configuration.rotation_grace_polls,
            transient: Arc::new(|_| false),
            configuration,
        }
    }

    /// Recognises contention on the cursor store (the collector supplies SQLite busy and
    /// locked, C# `IsTransientStorageFailure`). Such a poll is retried after the retry delay
    /// as backpressure, not reported as a source failure; the cursor is unchanged.
    pub fn with_transient_storage(
        mut self,
        transient: impl Fn(&StoreError) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.transient = Arc::new(transient);
        self
    }

    /// Wait before retrying a line the queue could not take yet (default 1 s).
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    pub fn metrics(&self) -> FileTailMetrics {
        FileTailMetrics(Arc::clone(&self.inputs))
    }

    pub fn snapshot(&self) -> Vec<InputStatus> {
        self.metrics().snapshot()
    }

    /// Makes polls stop between lines (the run loop sets it on stop).
    pub fn request_stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// One read of one input: resume from the cursor, hand each line to the sink and
    /// commit the new position. Progress made before a sink failure is still committed.
    pub fn poll_once(&self, input_id: &str) -> Result<PollResult, FileTailError> {
        let input = Arc::clone(&self.inputs[self.by_id[input_id]]);
        let _gate = input
            .gate
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let result = match self.poll(&input) {
            Err(error) if error.code == BUSY => {
                input.set_state("backpressure");
                input.counters.backpressure.fetch_add(1, Ordering::Relaxed);
                return Ok(PollResult {
                    lines: 0,
                    backpressure: true,
                    more: false,
                });
            }
            result => result,
        };
        if let Err(error) = &result {
            input.set_state(error.code);
            if matches!(error.code, failures::READ_FAILED | failures::PATH_REFUSED) {
                input.counters.read_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    fn poll(&self, input: &InputState) -> Result<PollResult, FileTailError> {
        let options = &input.options;
        *input
            .last_poll_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(self.clock.utc_now());
        let source_id = options.source_id();
        let snapshot = self
            .cursors
            .read(&source_id)
            .map_err(|error| self.storage(&error))?;
        let cursor = match &snapshot {
            Some(snapshot) => {
                // Never reinterpret or silently reset a position this version did not write.
                let cursor = Cursor::deserialize(&snapshot.value)
                    .ok_or_else(|| FileTailError::new(failures::CURSOR_INVALID))?;
                input.offset.store(cursor.offset, Ordering::Relaxed);
                Some(cursor)
            }
            None => None,
        };

        let (state, path) = self.check(options)?;
        // path.1 gets exactly the same checks as the configured path (never a link).
        let (rotated_state, rotated) = self.check_rotated(&path)?;
        // A missing file is read as missing: the cursor is still persisted and the rotated
        // file may still hold unread lines.
        let read = reader::read(
            (state == PathState::Ready).then_some(Path::new(&path)),
            (rotated_state == PathState::Ready).then_some(Path::new(&rotated)),
            cursor.as_ref(),
            &ReaderOptions {
                max_line_bytes: usize::try_from(options.max_line_bytes).unwrap_or(16_384),
                max_lines_per_batch: self.max_lines_per_batch,
                max_bytes_per_batch: self.max_bytes_per_batch,
                start_at_end: options.start_at != "beginning",
                rotation_grace_polls: self.rotation_grace_polls,
                use_file_ids: true,
            },
            Some(&self.stopping),
        );
        let batch = match read {
            Ok(batch) => batch,
            Err(ReadError::Refused) => return Err(FileTailError::new(failures::PATH_REFUSED)),
            Err(ReadError::Io(_)) => return Err(FileTailError::new(failures::READ_FAILED)),
            Err(ReadError::Stopped) => {
                input.set_state("stopped");
                return Ok(PollResult {
                    lines: 0,
                    backpressure: false,
                    more: false,
                });
            }
        };

        // Re-check after reading: a link swapped in during the read discards the read.
        self.check(options)?;
        if batch.rotated_opened {
            self.check_rotated(&path)?;
        }
        if batch.gap {
            input.counters.rotation_gaps.fetch_add(1, Ordering::Relaxed);
        }

        let (next, handled, backpressure, failed, stopped) = self.submit(input, &batch);
        if batch.rotated && handled == batch.lines.len() {
            input.counters.rotations.fetch_add(1, Ordering::Relaxed);
        }
        let value = next.serialize();
        if snapshot.as_ref().map(|snapshot| snapshot.value.as_str()) != Some(value.as_str()) {
            let expected = snapshot.as_ref().map_or(0, |snapshot| snapshot.version);
            let advanced = self
                .cursors
                .try_advance(&source_id, expected, &value, self.clock.utc_now())
                .map_err(|error| self.storage(&error))?;
            if !advanced {
                input
                    .counters
                    .cursor_conflicts
                    .fetch_add(1, Ordering::Relaxed);
                return Err(FileTailError::new(failures::CURSOR_CONFLICT));
            }
        }
        input.offset.store(next.offset, Ordering::Relaxed);
        if failed {
            return Err(FileTailError::new(failures::SUBMIT_FAILED));
        }
        input.set_state(if stopped {
            "stopped"
        } else if backpressure {
            "backpressure"
        } else if state == PathState::Missing {
            "waiting"
        } else {
            "running"
        });
        Ok(PollResult {
            lines: handled,
            backpressure,
            more: !backpressure && !stopped && batch.more,
        })
    }

    /// Hands the batch's lines to the sink in order; returns the cursor to commit.
    fn submit(&self, input: &InputState, batch: &Batch) -> (Cursor, usize, bool, bool, bool) {
        let mut handled = 0;
        for line in &batch.lines {
            if self.stopping.load(Ordering::SeqCst) {
                return (batch.rewind_to(line), handled, false, false, true);
            }
            let mut outcome = None;
            if !line.oversized && !line.bytes.is_empty() {
                match record::build(&input.options, line, &self.clock.utc_now()) {
                    Ok(record) => match self.sink.submit(&input.options, &record) {
                        Ok(SubmitOutcome::Unavailable) => {
                            input.counters.backpressure.fetch_add(1, Ordering::Relaxed);
                            return (batch.rewind_to(line), handled, true, false, false);
                        }
                        Ok(result) => outcome = Some(result),
                        Err(SinkFailure) => {
                            input
                                .counters
                                .submit_failures
                                .fetch_add(1, Ordering::Relaxed);
                            return (batch.rewind_to(line), handled, false, true, false);
                        }
                    },
                    Err(_) => {
                        input.counters.malformed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            handled += 1;
            self.count(input, line, outcome);
        }
        (batch.cursor.clone(), handled, false, false, false)
    }

    fn count(&self, input: &InputState, line: &Line, outcome: Option<SubmitOutcome>) {
        let c = &input.counters;
        c.lines_read.fetch_add(1, Ordering::Relaxed);
        c.bytes_read
            .fetch_add(line.end_offset - line.start_offset, Ordering::Relaxed);
        *input
            .last_line_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(self.clock.utc_now());
        let counter = if line.oversized {
            &c.oversized
        } else if line.bytes.is_empty() {
            &c.blank
        } else {
            match outcome {
                Some(SubmitOutcome::Queued) => &c.queued,
                Some(SubmitOutcome::Duplicate) => &c.duplicates,
                Some(SubmitOutcome::Suppressed) => &c.suppressed,
                Some(SubmitOutcome::NotSelected) => &c.not_selected,
                Some(SubmitOutcome::Rejected) => &c.rejected,
                Some(SubmitOutcome::Invalid) => &c.parser_errors,
                Some(SubmitOutcome::TooLarge) => &c.too_large,
                Some(SubmitOutcome::Unavailable) | None => return,
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The configured path, refused when it is a link, outside the roots, or (through an
    /// allowed link) another input's file or rotated file.
    fn check(&self, options: &InputOptions) -> Result<(PathState, String), FileTailError> {
        let (state, path) = paths::resolve(&options.path, &self.roots, options.allow_symlink);
        // Another input's file directly, through linked directories or through an allowed link.
        if state == PathState::Refused
            || config::overlaps_another(&self.configuration, options, &path)
        {
            return Err(FileTailError::new(failures::PATH_REFUSED));
        }
        Ok((state, path))
    }

    /// `path.1`: missing is fine, refused fails the poll (never read past a swapped link).
    fn check_rotated(&self, path: &str) -> Result<(PathState, String), FileTailError> {
        match paths::resolve(&format!("{path}.1"), &self.roots, false) {
            (PathState::Refused, _) => Err(FileTailError::new(failures::PATH_REFUSED)),
            resolved => Ok(resolved),
        }
    }

    /// Busy or locked storage is backpressure (C# `IsTransientStorageFailure`); anything
    /// else fails the poll.
    fn storage(&self, error: &StoreError) -> FileTailError {
        if (self.transient)(error) {
            FileTailError::new(BUSY)
        } else {
            FileTailError::new(failures::SOURCE_FAILED)
        }
    }

    /// One reader loop per input until `stop` turns true. Failures back off (doubling from
    /// the poll interval to 60 s) and are reported in the status; nothing else is logged.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let source = Arc::new(self);
        let mut tasks = JoinSet::new();
        for input in source.inputs.iter() {
            tasks.spawn(run_input(
                Arc::clone(&source),
                input.options.id.clone(),
                stop.clone(),
            ));
        }
        let watcher = Arc::clone(&source);
        tasks.spawn(async move {
            let _ = stop.wait_for(|stopped| *stopped).await;
            watcher.request_stop();
        });
        while tasks.join_next().await.is_some() {}
        for input in source.inputs.iter() {
            input.set_state("stopped");
        }
    }
}

async fn run_input(source: Arc<FileTailSource>, id: String, mut stop: watch::Receiver<bool>) {
    let mut failures = 0u32;
    loop {
        if *stop.borrow() {
            break;
        }
        let (poller, poll_id) = (Arc::clone(&source), id.clone());
        let result = tokio::task::spawn_blocking(move || poller.poll_once(&poll_id)).await;
        let wait = match result {
            Ok(Ok(result)) => {
                failures = 0;
                if result.backpressure {
                    source.retry_delay
                } else if result.more {
                    Duration::ZERO
                } else {
                    source.poll_interval
                }
            }
            Ok(Err(_)) | Err(_) => {
                failures = (failures + 1).min(16);
                source
                    .poll_interval
                    .saturating_mul(1 << failures.min(10))
                    .min(source.maximum_backoff)
            }
        };
        if wait.is_zero() {
            continue;
        }
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stop.wait_for(|stopped| *stopped) => break,
        }
    }
}

/// Internal marker for busy storage; reported as backpressure, never as a failure code.
const BUSY: &str = "backpressure";
