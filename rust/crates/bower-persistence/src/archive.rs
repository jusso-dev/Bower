//! Long-term, self-verifying copy of every accepted event (C# `QueueArchive` and
//! `SqliteEventStore.Archive`).
//!
//! Segments are gzip JSON Lines of ledger entries with their payloads; each has a
//! manifest with the file digest and the ledger chain hash at both ends. The archive
//! continues the queue ledger chain, so it can be verified without the queue and checked
//! against a head witnessed by management.
//!
//! Bower never deletes or rewrites a committed segment (one with a manifest). Writers take
//! the exclusive [`WRITER_LOCK_FILE`] lock before reading the watermark, so writers in
//! either runtime and process exclude each other. While an archive is configured,
//! retention purges only events the archive verifiably holds for this queue
//! (see [`QueueArchive::verify_coverage`]).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use bower_contracts::time::{self, Clock, SystemClock, Timestamp};
use bower_contracts::{DurableEventStore, LedgerHead, StoreError, StoreResult};
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ledger;
use crate::pool::storage;
use crate::queue::SqliteEventStore;

/// Maximum events written to one segment.
pub const MAXIMUM_EVENTS_PER_SEGMENT: usize = 10_000;
/// `kind` of every archive manifest.
pub const MANIFEST_KIND: &str = "BowerArchiveSegment";
/// Lock file every archive writer (C# and Rust) holds exclusively for a whole run: an OS
/// file lock (`flock` on Unix, `LockFileEx` here and a share-mode lock in C# on Windows).
/// It is never deleted.
pub const WRITER_LOCK_FILE: &str = "archive.lock";

const API_VERSION: &str = "bower.security/v1";
const MANIFEST_SUFFIX: &str = ".manifest.json";
const SEGMENT_SUFFIX: &str = ".jsonl.gz";
const SEGMENT_PREFIX: &str = "segment-";
const MAXIMUM_MANIFEST_BYTES: u64 = 65_536;
/// C# `MaximumLineBytes`, compared against the decoded line length in UTF-16 units.
const MAXIMUM_LINE_CHARACTERS: usize = 4 * 1_048_576;
/// A UTF-8 byte sequence decodes to at least one UTF-16 unit per three bytes, so a raw
/// line longer than this is always over the character limit; reading stops there.
const MAXIMUM_LINE_RAW_BYTES: usize = 3 * MAXIMUM_LINE_CHARACTERS;
const MAXIMUM_LEDGER_READ: usize = 100_000;
const MAXIMUM_TEMPORARY_CLEANUP: usize = 1_000;

/// Stored event with its ledger entry (C# `LedgerEvent`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEvent {
    pub sequence: i64,
    pub event_id: String,
    /// Redacted envelope JSON exactly as queued.
    pub payload: String,
    /// Received time exactly as hashed into the ledger.
    pub received_at: String,
    pub chain_hash: String,
}

/// One archived ledger entry (C# `ArchivedEvent`); one JSON line per event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedEvent {
    pub sequence: i64,
    pub event_id: String,
    pub received_at: String,
    pub chain_hash: String,
    /// Redacted envelope JSON exactly as queued, kept as a string so its digest is
    /// reproducible.
    pub payload: String,
}

/// Segment manifest (C# `ArchiveManifest`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveManifest {
    pub api_version: String,
    pub kind: String,
    pub collector_id: String,
    pub segment_file: String,
    pub segment_sha256: String,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub event_count: i64,
    pub previous_chain_hash: String,
    pub last_chain_hash: String,
    #[serde(with = "time::serde_offset")]
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveRunResult {
    pub segments: i32,
    pub events: i64,
    pub head_sequence: i64,
    pub head_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveVerification {
    pub intact: bool,
    pub segments: i32,
    pub verified_events: i64,
    pub first_sequence: i64,
    pub head_sequence: i64,
    pub head_hash: Option<String>,
    pub anchor_verified: bool,
    pub break_segment: Option<String>,
    pub break_reason: Option<String>,
}

impl ArchiveVerification {
    fn broken(verified: i64, segments: usize, segment: Option<&str>, reason: &str) -> Self {
        Self {
            intact: false,
            segments: segment_count(segments),
            verified_events: verified,
            first_sequence: 0,
            head_sequence: 0,
            head_hash: None,
            anchor_verified: false,
            break_segment: segment.map(str::to_owned),
            break_reason: Some(reason.to_owned()),
        }
    }
}

/// Archive coverage retention may rely on (C# `ArchiveCoverage`): events
/// `first_sequence` to `through_sequence` when `verified`; otherwise a metadata-only
/// `reason` and nothing may be purged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveCoverage {
    pub verified: bool,
    pub first_sequence: i64,
    pub through_sequence: i64,
    pub reason: Option<String>,
}

impl ArchiveCoverage {
    pub fn refused(reason: &str, first_sequence: i64, through_sequence: i64) -> Self {
        Self {
            verified: false,
            first_sequence,
            through_sequence,
            reason: Some(reason.to_owned()),
        }
    }

    fn covered(first_sequence: i64, through_sequence: i64) -> Self {
        Self {
            verified: true,
            first_sequence,
            through_sequence,
            reason: None,
        }
    }
}

/// A verified segment as it was on disk: any change to its manifest, size or write time
/// invalidates the cached verification.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SegmentStamp {
    manifest: ArchiveManifest,
    length: i64,
    written: Option<SystemTime>,
}

struct VerifiedPrefix {
    stamps: Vec<SegmentStamp>,
    head_sequence: i64,
    head_hash: String,
}

fn segment_count(count: usize) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

/// Archive failures. Messages carry file names and sequences only, never payloads.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// C# `ArgumentException` (blank directory or collector id).
    #[error("{0}")]
    InvalidArgument(String),
    /// C# `InvalidDataException` / `JsonException`: the archive or queue cannot be trusted.
    #[error("{0}")]
    InvalidData(String),
    #[error("archive I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl SqliteEventStore {
    /// Stored events with their ledger entries, in ledger order, after `after_sequence`.
    /// Purged entries have no payload and are skipped, so a gap in the returned
    /// sequences means the events were purged before they were read.
    pub fn read_ledger_events(
        &self,
        after_sequence: i64,
        maximum_count: usize,
    ) -> StoreResult<Vec<LedgerEvent>> {
        if after_sequence < 0 {
            return Err(StoreError::Invalid(
                "afterSequence must be a non-negative value.".into(),
            ));
        }
        if !(1..=MAXIMUM_LEDGER_READ).contains(&maximum_count) {
            return Err(StoreError::Invalid(
                "maximumCount must be between 1 and 100000.".into(),
            ));
        }
        let maximum = i64::try_from(maximum_count).unwrap_or(i64::MAX);
        self.pool().with(|connection| {
            let mut command = connection
                .prepare(
                    "SELECT l.sequence, l.event_id, e.payload, l.received_at, l.chain_hash
FROM queue_ledger l
JOIN queue_events_v5 e ON e.enqueue_sequence = l.sequence AND e.event_id = l.event_id
WHERE l.sequence > ?1 AND l.purged_at IS NULL
ORDER BY l.sequence ASC
LIMIT ?2;",
                )
                .map_err(storage)?;
            let rows = command
                .query_map(params![after_sequence, maximum], |row| {
                    Ok(LedgerEvent {
                        sequence: row.get(0)?,
                        event_id: row.get(1)?,
                        payload: row.get(2)?,
                        received_at: row.get(3)?,
                        chain_hash: row.get(4)?,
                    })
                })
                .map_err(storage)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage)
        })
    }

    /// Chain hash recorded at `sequence`: a ledger entry, the end of a compacted
    /// retention segment or the anchor; the genesis hash for 0. `None` when the ledger no
    /// longer holds that boundary.
    pub fn ledger_hash_at(&self, sequence: i64) -> StoreResult<Option<String>> {
        if sequence < 0 {
            return Err(StoreError::Invalid(
                "sequence must be a non-negative value.".into(),
            ));
        }
        if sequence == 0 {
            return Ok(Some(ledger::genesis_hash()));
        }
        self.pool().with(|connection| {
            connection
                .query_row(
                    "SELECT chain_hash FROM queue_ledger WHERE sequence = ?1
UNION ALL SELECT chain_hash FROM queue_ledger_segments WHERE end_sequence = ?1
UNION ALL SELECT chain_hash FROM queue_ledger_anchor WHERE sequence = ?1
LIMIT 1;",
                    params![sequence],
                    // C# `ExecuteScalarAsync(...) as string`: a non-text value reads as null.
                    |row| row.get::<_, rusqlite::types::Value>(0),
                )
                .optional()
                .map_err(storage)
                .map(|value| match value {
                    Some(rusqlite::types::Value::Text(text)) => Some(text),
                    _ => None,
                })
        })
    }

    /// Highest chain hash boundary the ledger records at or below `sequence` (entry,
    /// compacted segment end or anchor); `None` when none. Every sequence above it and up
    /// to `sequence` has been purged.
    pub fn ledger_boundary_at_or_below(&self, sequence: i64) -> StoreResult<Option<LedgerHead>> {
        if sequence < 0 {
            return Err(StoreError::Invalid(
                "sequence must be a non-negative value.".into(),
            ));
        }
        self.pool().with(|connection| {
            connection
                .query_row(
                    "SELECT sequence, chain_hash FROM (
    SELECT * FROM (SELECT sequence, chain_hash FROM queue_ledger
        WHERE sequence <= ?1 ORDER BY sequence DESC LIMIT 1)
    UNION ALL SELECT * FROM (SELECT end_sequence, chain_hash FROM queue_ledger_segments
        WHERE end_sequence <= ?1 ORDER BY end_sequence DESC LIMIT 1)
    UNION ALL SELECT sequence, chain_hash FROM queue_ledger_anchor WHERE sequence <= ?1
) ORDER BY sequence DESC LIMIT 1;",
                    params![sequence],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, rusqlite::types::Value>(1)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage)
                .map(|value| match value {
                    Some((sequence, rusqlite::types::Value::Text(hash))) => {
                        Some(LedgerHead { sequence, hash })
                    }
                    _ => None,
                })
        })
    }
}

/// Long-term, self-verifying archive of every accepted event (C# `QueueArchive`).
pub struct QueueArchive {
    directory: PathBuf,
    collector_id: String,
    clock: Arc<dyn Clock>,
    verified_prefix: Mutex<Option<VerifiedPrefix>>,
    /// Test hook: runs once while the writer owns the archive, before a segment is published.
    #[cfg(test)]
    before_publish: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for QueueArchive {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueueArchive")
            .field("directory", &self.directory)
            .field("collector_id", &self.collector_id)
            .finish_non_exhaustive()
    }
}

fn is_blank(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

/// `Path.GetFullPath`: absolute, with `.` and `..` resolved lexically.
fn full_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

impl QueueArchive {
    pub const MAXIMUM_EVENTS_PER_SEGMENT: usize = MAXIMUM_EVENTS_PER_SEGMENT;
    pub const MANIFEST_KIND: &'static str = MANIFEST_KIND;
    pub const WRITER_LOCK_FILE: &'static str = WRITER_LOCK_FILE;

    pub fn new(
        directory: impl AsRef<Path>,
        collector_id: &str,
        clock: Option<Arc<dyn Clock>>,
    ) -> Result<Self, ArchiveError> {
        let directory = directory.as_ref();
        if is_blank(&directory.as_os_str().to_string_lossy()) {
            return Err(ArchiveError::InvalidArgument(
                "directory cannot be empty or whitespace.".into(),
            ));
        }
        if is_blank(collector_id) {
            return Err(ArchiveError::InvalidArgument(
                "collectorId cannot be empty or whitespace.".into(),
            ));
        }
        Ok(Self {
            directory: full_path(directory)?,
            collector_id: collector_id.to_owned(),
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
            verified_prefix: Mutex::new(None),
            #[cfg(test)]
            before_publish: Mutex::new(None),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Last ledger sequence the manifests claim; 0 when empty. Unverified: retention uses
    /// [`QueueArchive::verify_coverage`].
    pub fn archived_through_sequence(&self) -> Result<i64, ArchiveError> {
        Ok(self
            .read_manifests()?
            .last()
            .map_or(0, |manifest| manifest.last_sequence))
    }

    /// Copies every stored event not yet archived into new segments. Safe to rerun after
    /// a crash: a segment left without a manifest is rewritten from the queue. Fails with
    /// an `io::ErrorKind::WouldBlock` I/O error, writing nothing, when another writer owns
    /// the archive.
    pub fn archive(&self, store: &SqliteEventStore) -> Result<ArchiveRunResult, ArchiveError> {
        fs::create_dir_all(&self.directory)?;

        // Own the archive before reading the watermark, so no other writer can publish
        // between the read and this run's segments.
        let _ownership = self.acquire_writer_lock()?;
        let manifests = self.read_manifests()?;
        let (mut last_sequence, mut last_hash) = match manifests.last() {
            Some(manifest) => {
                // Extend only this queue's chain. Another queue's archive, a diverged
                // restore or an archive ahead of the queue is refused before anything is
                // written.
                // A boundary compacted away (the events after it were purged) is left to
                // the purged-before-archived check below, which writes nothing either.
                let queue_hash = store.ledger_hash_at(manifest.last_sequence)?;
                let compacted =
                    queue_hash.is_none() && store.ledger_head()?.sequence >= manifest.last_sequence;
                if !compacted && queue_hash.as_deref() != Some(manifest.last_chain_hash.as_str()) {
                    return Err(ArchiveError::InvalidData(format!(
                        "Archive lineage-mismatch: the queue ledger does not match the archive head at sequence {}.",
                        manifest.last_sequence
                    )));
                }
                (manifest.last_sequence, manifest.last_chain_hash.clone())
            }
            None => {
                // A new archive starts at the oldest event still stored; its first manifest
                // records the ledger hash before it, so the chain continues from the queue.
                let first = store.read_ledger_events(0, 1)?;
                let Some(first) = first.first() else {
                    return Ok(ArchiveRunResult {
                        segments: 0,
                        events: 0,
                        head_sequence: 0,
                        head_hash: None,
                    });
                };
                let previous = first.sequence - 1;
                let hash = store.ledger_hash_at(previous)?.ok_or_else(|| {
                    ArchiveError::InvalidData(format!(
                        "Ledger no longer records the hash at sequence {previous}; cannot start the archive."
                    ))
                })?;
                (previous, hash)
            }
        };

        self.remove_abandoned_temporary_files()?;
        let mut segments = 0i32;
        let mut events = 0i64;
        loop {
            let rows = store.read_ledger_events(last_sequence, MAXIMUM_EVENTS_PER_SEGMENT)?;
            if rows.is_empty() {
                break;
            }
            if rows[0].sequence != last_sequence + 1 {
                return Err(ArchiveError::InvalidData(format!(
                    "Events after sequence {last_sequence} were purged before they were archived."
                )));
            }

            let mut contiguous = 1;
            while contiguous < rows.len()
                && rows[contiguous].sequence == rows[contiguous - 1].sequence + 1
            {
                contiguous += 1;
            }

            let manifest = self.write_segment(&rows[..contiguous], &last_hash)?;
            last_sequence = manifest.last_sequence;
            last_hash = manifest.last_chain_hash;
            segments += 1;
            events += i64::try_from(contiguous).unwrap_or(i64::MAX);
            if contiguous < rows.len() {
                // The next row follows a gap: stop and report it on the next run.
                break;
            }
        }

        Ok(ArchiveRunResult {
            segments,
            events,
            head_sequence: last_sequence,
            head_hash: Some(last_hash),
        })
    }

    /// Recomputes every ledger link across all segments and checks each file digest.
    /// With `anchor`, also proves the archived chain passes through that head.
    ///
    /// Unreadable manifests report `manifest-invalid`; a segment whose digest matches but
    /// whose gzip stream or JSON lines cannot be read is an error (C# throws there too).
    pub fn verify(&self, anchor: Option<&LedgerHead>) -> Result<ArchiveVerification, ArchiveError> {
        let manifests = match self.read_manifests() {
            Ok(manifests) => manifests,
            Err(ArchiveError::InvalidData(_)) => {
                return Ok(ArchiveVerification::broken(0, 0, None, "manifest-invalid"));
            }
            Err(error) => return Err(error),
        };
        if manifests.is_empty() {
            return Ok(ArchiveVerification::broken(0, 0, None, "archive-empty"));
        }

        let (previous, expected) = (
            manifests[0].previous_chain_hash.clone(),
            manifests[0].first_sequence,
        );
        self.verify_from(&manifests, 0, previous, expected, anchor)
    }

    /// Verified, contiguous coverage of `store`'s retained events (C#
    /// `VerifyCoverageAsync`). Refused (with a metadata-only reason) unless every segment
    /// exists and matches its manifest digest and chain, the archive starts at or below the
    /// oldest stored event, and the archived chain equals the queue ledger chain (same
    /// lineage). Segments verified earlier are not re-read while their manifests, sizes and
    /// write times are unchanged. Store failures are errors.
    pub fn verify_coverage(
        &self,
        store: &SqliteEventStore,
    ) -> Result<ArchiveCoverage, ArchiveError> {
        let oldest = store.read_ledger_events(0, 1)?;
        let manifests = match self.read_manifests() {
            Ok(manifests) => manifests,
            Err(ArchiveError::InvalidData(_)) => {
                return Ok(ArchiveCoverage::refused("manifest-invalid", 0, 0));
            }
            Err(error) => return Err(error),
        };
        let (Some(first_manifest), Some(last_manifest)) = (manifests.first(), manifests.last())
        else {
            // Nothing stored means nothing to purge; otherwise nothing is covered yet.
            return Ok(if oldest.is_empty() {
                ArchiveCoverage::covered(0, 0)
            } else {
                ArchiveCoverage::refused("archive-empty", 0, 0)
            });
        };

        let first = first_manifest.first_sequence;
        if oldest.first().is_some_and(|oldest| oldest.sequence < first) {
            return Ok(ArchiveCoverage::refused(
                "archive-starts-above-retained",
                first,
                last_manifest.last_sequence,
            ));
        }

        match self.verify_lineage(store, &manifests) {
            Err(ArchiveError::InvalidData(_) | ArchiveError::Io(_)) => {
                Ok(ArchiveCoverage::refused("segment-unreadable", first, 0))
            }
            result => result,
        }
    }

    fn verify_lineage(
        &self,
        store: &SqliteEventStore,
        manifests: &[ArchiveManifest],
    ) -> Result<ArchiveCoverage, ArchiveError> {
        let first = manifests[0].first_sequence;
        let verification = self.verify_incrementally(manifests)?;
        if !verification.intact {
            return Ok(ArchiveCoverage::refused(
                verification
                    .break_reason
                    .as_deref()
                    .unwrap_or("archive-broken"),
                first,
                0,
            ));
        }

        // The ledger chain is the queue's lineage: equal hashes at the highest boundary
        // both record prove every archived event up to it came from this queue. Every
        // sequence between that boundary and the archive head is already purged.
        let through = verification.head_sequence;
        let Some(boundary) = store
            .ledger_boundary_at_or_below(through)?
            .filter(|boundary| boundary.sequence >= first - 1)
        else {
            return Ok(ArchiveCoverage::refused(
                "lineage-unverifiable",
                first,
                through,
            ));
        };
        let archived = self.archived_hash_at(manifests, boundary.sequence)?;
        Ok(if archived.as_deref() == Some(boundary.hash.as_str()) {
            ArchiveCoverage::covered(first, through)
        } else {
            ArchiveCoverage::refused("lineage-mismatch", first, through)
        })
    }

    /// Re-hashes, bypassing the verification cache, each segment holding one of
    /// `sequences` (the events about to be purged), and checks its manifest is the one
    /// [`QueueArchive::verify_coverage`] last verified (C# `VerifySegmentsForPurgeAsync`).
    /// `None` when all match; otherwise a metadata-only reason, and the cache is dropped
    /// so the next coverage check verifies everything again.
    pub fn verify_segments_for_purge(&self, sequences: &[i64]) -> Option<String> {
        let mut cache = self
            .verified_prefix
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let reason = match cache.as_ref() {
            Some(cached) => self.rehash(cached, sequences),
            None => Some("archive-unverified"),
        };
        if reason.is_some() {
            *cache = None;
        }
        reason.map(str::to_owned)
    }

    fn rehash(&self, cached: &VerifiedPrefix, sequences: &[i64]) -> Option<&'static str> {
        let mut needed = std::collections::BTreeSet::new();
        for &sequence in sequences {
            let index = cached
                .stamps
                .binary_search_by(|stamp| {
                    if sequence < stamp.manifest.first_sequence {
                        std::cmp::Ordering::Greater
                    } else if sequence > stamp.manifest.last_sequence {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
                .ok()?;
            needed.insert(index);
        }
        let current: std::collections::HashMap<i64, ArchiveManifest> = match self.read_manifests() {
            Ok(manifests) => manifests
                .into_iter()
                .map(|manifest| (manifest.first_sequence, manifest))
                .collect(),
            Err(ArchiveError::InvalidData(_)) => return Some("manifest-invalid"),
            Err(_) => return Some("segment-unreadable"),
        };
        for index in needed {
            let manifest = &cached.stamps[index].manifest;
            if current.get(&manifest.first_sequence) != Some(manifest) {
                return Some("archive-changed");
            }
            let segment_path = self.directory.join(&manifest.segment_file);
            if !segment_path.is_file() {
                return Some("segment-missing");
            }
            match digest(&segment_path) {
                Ok(value) if value == manifest.segment_sha256 => {}
                Ok(_) => return Some("segment-digest-mismatch"),
                Err(_) => return Some("segment-unreadable"),
            }
        }
        None
    }

    fn verify_incrementally(
        &self,
        manifests: &[ArchiveManifest],
    ) -> Result<ArchiveVerification, ArchiveError> {
        // Stamp before reading, so a change made during verification invalidates the cache.
        let stamps: Vec<SegmentStamp> = manifests
            .iter()
            .map(|manifest| {
                let (length, written) =
                    match fs::metadata(self.directory.join(&manifest.segment_file)) {
                        Ok(metadata) if metadata.is_file() => (
                            i64::try_from(metadata.len()).unwrap_or(i64::MAX),
                            metadata.modified().ok(),
                        ),
                        _ => (-1, None),
                    };
                SegmentStamp {
                    manifest: manifest.clone(),
                    length,
                    written,
                }
            })
            .collect();
        let mut cache = self
            .verified_prefix
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (start, previous, expected) = match cache.take() {
            Some(cached)
                if cached.stamps.len() <= stamps.len()
                    && cached.stamps[..] == stamps[..cached.stamps.len()] =>
            {
                (
                    cached.stamps.len(),
                    cached.head_hash,
                    cached.head_sequence + 1,
                )
            }
            _ => (
                0,
                manifests[0].previous_chain_hash.clone(),
                manifests[0].first_sequence,
            ),
        };
        let result = self.verify_from(manifests, start, previous, expected, None)?;
        if result.intact {
            *cache = Some(VerifiedPrefix {
                stamps,
                head_sequence: result.head_sequence,
                head_hash: result.head_hash.clone().unwrap_or_default(),
            });
        }
        Ok(result)
    }

    fn archived_hash_at(
        &self,
        manifests: &[ArchiveManifest],
        sequence: i64,
    ) -> Result<Option<String>, ArchiveError> {
        if sequence == manifests[0].first_sequence - 1 {
            return Ok(Some(manifests[0].previous_chain_hash.clone()));
        }
        let Some(manifest) = manifests.iter().find(|manifest| {
            manifest.first_sequence <= sequence && sequence <= manifest.last_sequence
        }) else {
            return Ok(None);
        };
        if sequence == manifest.last_sequence {
            return Ok(Some(manifest.last_chain_hash.clone()));
        }
        for item in SegmentReader::open(&self.directory.join(&manifest.segment_file))? {
            let item = item?;
            if item.sequence == sequence {
                return Ok(item.chain_hash);
            }
        }
        Ok(None)
    }

    fn verify_from(
        &self,
        manifests: &[ArchiveManifest],
        start: usize,
        mut previous: String,
        mut expected: i64,
        anchor: Option<&LedgerHead>,
    ) -> Result<ArchiveVerification, ArchiveError> {
        let count = manifests.len();
        let mut verified = 0i64;
        let mut anchor_verified = false;
        for manifest in &manifests[start..] {
            let segment = Some(manifest.segment_file.as_str());
            let broken = |verified: i64, reason: &str| {
                ArchiveVerification::broken(verified, count, segment, reason)
            };
            let segment_path = self.directory.join(&manifest.segment_file);
            if !segment_path.is_file() {
                return Ok(broken(verified, "segment-missing"));
            }
            if digest(&segment_path)? != manifest.segment_sha256 {
                return Ok(broken(verified, "segment-digest-mismatch"));
            }
            if previous != manifest.previous_chain_hash {
                return Ok(broken(verified, "segment-not-contiguous"));
            }

            let mut read = 0i64;
            for item in SegmentReader::open(&segment_path)? {
                let item = item?;
                read += 1;
                if item.sequence != expected {
                    return Ok(broken(verified, "sequence-gap"));
                }
                // C# `QueueLedger.PayloadHash(null)` throws; fail the same way.
                let payload = item.payload.as_deref().ok_or_else(missing_payload)?;
                let computed = ledger::chain_hash(
                    &previous,
                    item.sequence,
                    &item.event_id,
                    &ledger::payload_hash(payload),
                    &item.received_at,
                );
                if item.chain_hash.as_deref() != Some(computed.as_str()) {
                    return Ok(broken(verified, "chain-broken"));
                }
                if let Some(anchor) = anchor.filter(|anchor| anchor.sequence == item.sequence) {
                    if computed != anchor.hash {
                        return Ok(broken(verified, "anchor-mismatch"));
                    }
                    anchor_verified = true;
                }
                previous = computed;
                expected += 1;
                verified += 1;
            }

            if read != manifest.event_count
                || expected - 1 != manifest.last_sequence
                || previous != manifest.last_chain_hash
            {
                return Ok(broken(verified, "manifest-mismatch"));
            }
        }

        if anchor.is_some() && !anchor_verified {
            return Ok(ArchiveVerification::broken(
                verified,
                count,
                None,
                "anchor-missing",
            ));
        }

        Ok(ArchiveVerification {
            intact: true,
            segments: segment_count(count),
            verified_events: verified,
            first_sequence: manifests[0].first_sequence,
            head_sequence: expected - 1,
            head_hash: Some(previous),
            anchor_verified,
            break_segment: None,
            break_reason: None,
        })
    }

    /// Archived events in ledger order. Verify first.
    pub fn read_all(&self) -> Result<Vec<ArchivedEvent>, ArchiveError> {
        let mut events = Vec::new();
        for manifest in self.read_manifests()? {
            for item in SegmentReader::open(&self.directory.join(&manifest.segment_file))? {
                let item = item?;
                events.push(ArchivedEvent {
                    sequence: item.sequence,
                    event_id: item.event_id,
                    received_at: item.received_at,
                    chain_hash: item.chain_hash.unwrap_or_default(),
                    // C# yields a null payload here; a Rust String cannot, so fail closed.
                    payload: item.payload.ok_or_else(missing_payload)?,
                });
            }
        }
        Ok(events)
    }

    fn write_segment(
        &self,
        rows: &[LedgerEvent],
        previous_hash: &str,
    ) -> Result<ArchiveManifest, ArchiveError> {
        let (first, last) = match (rows.first(), rows.last()) {
            (Some(first), Some(last)) => (first, last),
            _ => {
                return Err(ArchiveError::InvalidData(
                    "Archive segment is empty.".into(),
                ));
            }
        };
        let name = format!("{SEGMENT_PREFIX}{:012}", first.sequence);
        let segment_file = format!("{name}{SEGMENT_SUFFIX}");
        let segment_path = self.directory.join(&segment_file);
        let manifest_path = self.directory.join(format!("{name}{MANIFEST_SUFFIX}"));
        let temporary = temporary_path(&segment_path);
        let manifest_temporary = temporary_path(&manifest_path);
        let _cleanup = TemporaryFiles([&temporary, &manifest_temporary]);

        {
            let file = create_private(&temporary)?;
            let mut gzip = GzEncoder::new(io::BufWriter::new(file), Compression::best());
            for row in rows {
                let line = bower_contracts::json::to_vec(&ArchivedEvent {
                    sequence: row.sequence,
                    event_id: row.event_id.clone(),
                    received_at: row.received_at.clone(),
                    chain_hash: row.chain_hash.clone(),
                    payload: row.payload.clone(),
                })
                .map_err(|_| {
                    ArchiveError::InvalidData("Archived event cannot be serialized.".into())
                })?;
                gzip.write_all(&line)?;
                gzip.write_all(b"\n")?;
            }
            let file = gzip
                .finish()?
                .into_inner()
                .map_err(io::IntoInnerError::into_error)?;
            file.sync_all()?;
        }

        #[cfg(test)]
        {
            let hook = self
                .before_publish
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }

        // Only the lock owner gets here, so a segment without a manifest is an uncommitted
        // orphan of a crashed run. A committed segment is never replaced: the move fails.
        if !manifest_path.exists() && segment_path.is_file() {
            fs::remove_file(&segment_path)?;
        }
        move_without_overwrite(&temporary, &segment_path)?;
        restrict_permissions(&segment_path)?;
        // Make the published names durable before retention can rely on them.
        sync_directory(&self.directory)?;

        let manifest = ArchiveManifest {
            api_version: API_VERSION.into(),
            kind: MANIFEST_KIND.into(),
            collector_id: self.collector_id.clone(),
            segment_file,
            segment_sha256: digest(&segment_path)?,
            first_sequence: first.sequence,
            last_sequence: last.sequence,
            event_count: i64::try_from(rows.len()).unwrap_or(i64::MAX),
            previous_chain_hash: previous_hash.to_owned(),
            last_chain_hash: last.chain_hash.clone(),
            created_at: time::to_utc(time::truncate_to_ticks(self.clock.utc_now())),
        };
        {
            let bytes = bower_contracts::json::to_vec(&manifest).map_err(|_| {
                ArchiveError::InvalidData("Archive manifest cannot be serialized.".into())
            })?;
            let mut file = create_private(&manifest_temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }

        // Never replace a completed manifest: a collision means two writers share the archive.
        move_without_overwrite(&manifest_temporary, &manifest_path)?;
        restrict_permissions(&manifest_path)?;
        sync_directory(&self.directory)?;
        Ok(manifest)
    }

    fn acquire_writer_lock(&self) -> Result<File, ArchiveError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.directory.join(WRITER_LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(fs::TryLockError::WouldBlock) => Err(ArchiveError::Io(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Another writer holds the archive writer lock.",
            ))),
            Err(fs::TryLockError::Error(error)) => Err(error.into()),
        }
    }

    /// Removes temporary files of crashed runs. Call only while owning the archive.
    fn remove_abandoned_temporary_files(&self) -> io::Result<()> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.directory)? {
            if removed == MAXIMUM_TEMPORARY_CLEANUP {
                break;
            }
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            // `Directory.EnumerateFiles(directory, "segment-*.tmp")`.
            if file_name.starts_with(SEGMENT_PREFIX)
                && file_name.ends_with(".tmp")
                && entry.file_type()?.is_file()
            {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(())
    }

    fn read_manifests(&self) -> Result<Vec<ArchiveManifest>, ArchiveError> {
        if !self.directory.is_dir() {
            return Ok(Vec::new());
        }

        let mut manifests = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            // `Directory.EnumerateFiles(directory, "segment-*.manifest.json")`.
            if file_name.len() < SEGMENT_PREFIX.len() + MANIFEST_SUFFIX.len()
                || !file_name.starts_with(SEGMENT_PREFIX)
                || !file_name.ends_with(MANIFEST_SUFFIX)
            {
                continue;
            }
            let path = entry.path();
            let metadata = fs::metadata(&path)?;
            if !metadata.is_file() {
                continue;
            }
            if metadata.len() > MAXIMUM_MANIFEST_BYTES {
                return Err(ArchiveError::InvalidData(format!(
                    "Archive manifest too large: {file_name}"
                )));
            }

            let mut bytes = Vec::new();
            File::open(&path)?
                .take(MAXIMUM_MANIFEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAXIMUM_MANIFEST_BYTES {
                return Err(ArchiveError::InvalidData(format!(
                    "Archive manifest too large: {file_name}"
                )));
            }
            // `File.ReadAllText(path, Encoding.UTF8)`: BOM skipped, invalid bytes replaced.
            let text = String::from_utf8_lossy(strip_bom(&bytes)).into_owned();
            let manifest = bower_contracts::json::from_str::<Option<ManifestDocument>>(&text)
                .map_err(|_| {
                    ArchiveError::InvalidData(format!("Archive manifest invalid: {file_name}"))
                })?
                .ok_or_else(|| {
                    ArchiveError::InvalidData(format!("Archive manifest empty: {file_name}"))
                })?
                .into_manifest();
            if manifest.kind != MANIFEST_KIND
                || manifest.segment_file.is_empty()
                || !is_file_name(&manifest.segment_file)
                || manifest.first_sequence < 1
                || manifest.last_sequence < manifest.first_sequence
                || manifest.event_count != manifest.last_sequence - manifest.first_sequence + 1
            {
                return Err(ArchiveError::InvalidData(format!(
                    "Archive manifest invalid: {file_name}"
                )));
            }
            manifests.push(manifest);
        }

        manifests.sort_by_key(|manifest| manifest.first_sequence);
        for pair in manifests.windows(2) {
            if Some(pair[1].first_sequence) != pair[0].last_sequence.checked_add(1) {
                return Err(ArchiveError::InvalidData(format!(
                    "Archive is missing sequences before {}.",
                    pair[1].first_sequence
                )));
            }
        }
        Ok(manifests)
    }
}

fn missing_payload() -> ArchiveError {
    ArchiveError::InvalidData("Archived line has no payload.".into())
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// `Path.GetFileName(value) == value`.
fn is_file_name(value: &str) -> bool {
    if cfg!(windows) {
        !value.contains(['/', '\\', ':'])
    } else {
        !value.contains('/')
    }
}

/// C# `DirectorySync.Flush`: fsync the directory so names moved into it survive a power
/// loss. File systems that cannot sync a directory (EINVAL, ENOTSUP) have nothing more to
/// make durable. No-op off Unix (Windows journals renames).
#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    match File::open(directory)?.sync_all() {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

/// A temporary name no other run uses: `<path>.<process>-<time>-<counter>.tmp`.
fn temporary_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut text = path.as_os_str().to_owned();
    text.push(format!(
        ".{:x}-{nanos:x}-{:x}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(text)
}

/// Removes a run's temporary files however publication ends.
struct TemporaryFiles<'a>([&'a Path; 2]);

impl Drop for TemporaryFiles<'_> {
    fn drop(&mut self) {
        for path in self.0 {
            // Absent once published; anything left is swept by the next owner.
            let _ = fs::remove_file(path);
        }
    }
}

/// `FileMode.Create` (create or truncate); owner-only from the start on Unix.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// `File.Move(source, destination, overwrite: false)`. Like .NET on Unix, a hard link
/// claims the destination atomically (failing if it exists) and the source is then
/// removed. Where links are unsupported this falls back to check-then-rename, which,
/// as in .NET, can race with a concurrent writer.
fn move_without_overwrite(source: &Path, destination: &Path) -> io::Result<()> {
    match fs::hard_link(source, destination) {
        Ok(()) => fs::remove_file(source),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(error),
        Err(_) => {
            if fs::symlink_metadata(destination).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "archive file already exists",
                ));
            }
            fs::rename(source, destination)
        }
    }
}

/// `sha256:<lower hex>` of the file bytes.
fn digest(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 81_920];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// System.Text.Json default reading of `ArchiveManifest`: case-sensitive camelCase,
/// unknown members ignored, missing or null members default.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestDocument {
    #[serde(default)]
    api_version: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    collector_id: Option<String>,
    #[serde(default)]
    segment_file: Option<String>,
    #[serde(default)]
    segment_sha256: Option<String>,
    #[serde(default)]
    first_sequence: i64,
    #[serde(default)]
    last_sequence: i64,
    #[serde(default)]
    event_count: i64,
    #[serde(default)]
    previous_chain_hash: Option<String>,
    #[serde(default)]
    last_chain_hash: Option<String>,
    #[serde(default, with = "time::serde_offset_option")]
    created_at: Option<Timestamp>,
}

impl ManifestDocument {
    fn into_manifest(self) -> ArchiveManifest {
        ArchiveManifest {
            api_version: self.api_version.unwrap_or_default(),
            // A null kind or segment file fails validation exactly as empty text does.
            kind: self.kind.unwrap_or_default(),
            collector_id: self.collector_id.unwrap_or_default(),
            segment_file: self.segment_file.unwrap_or_default(),
            // A null digest never equals a computed one; empty behaves the same.
            segment_sha256: self.segment_sha256.unwrap_or_default(),
            first_sequence: self.first_sequence,
            last_sequence: self.last_sequence,
            event_count: self.event_count,
            // C# `string.Join` writes a null hash into the chain as empty text.
            previous_chain_hash: self.previous_chain_hash.unwrap_or_default(),
            last_chain_hash: self.last_chain_hash.unwrap_or_default(),
            // `default(DateTimeOffset)`.
            created_at: self.created_at.unwrap_or_else(|| {
                time::parse("0001-01-01T00:00:00+00:00").expect("minimum DateTimeOffset parses")
            }),
        }
    }
}

/// One archived line as System.Text.Json reads it (missing or null members default).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LineDocument {
    #[serde(default)]
    sequence: i64,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    received_at: Option<String>,
    #[serde(default)]
    chain_hash: Option<String>,
    #[serde(default)]
    payload: Option<String>,
}

/// A line with C# null handling applied: null `eventId`/`receivedAt` join the chain as
/// empty text, a null `chainHash` never matches, a null `payload` cannot be hashed.
struct ArchivedLine {
    sequence: i64,
    event_id: String,
    received_at: String,
    chain_hash: Option<String>,
    payload: Option<String>,
}

/// Streams a segment like C# `ReadSegmentAsync`: gzip (multi-member), UTF-8 with an
/// optional BOM, `StreamReader.ReadLine` line breaks (`\n`, `\r`, `\r\n`).
struct SegmentReader {
    reader: BufReader<MultiGzDecoder<File>>,
    first: bool,
    done: bool,
}

impl SegmentReader {
    fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            reader: BufReader::new(MultiGzDecoder::new(File::open(path)?)),
            first: true,
            done: false,
        })
    }

    /// Next raw line without its terminator; `None` at end of stream.
    fn read_line(&mut self) -> Result<Option<Vec<u8>>, ArchiveError> {
        let mut line = Vec::new();
        let mut any = false;
        loop {
            let buffer = match self.reader.fill_buf() {
                Ok(buffer) => buffer,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(segment_read_error(error)),
            };
            if buffer.is_empty() {
                return Ok(any.then_some(line));
            }
            any = true;
            match buffer
                .iter()
                .position(|byte| *byte == b'\n' || *byte == b'\r')
            {
                Some(index) => {
                    let carriage = buffer[index] == b'\r';
                    line.extend_from_slice(&buffer[..index]);
                    self.reader.consume(index + 1);
                    if carriage {
                        let next = match self.reader.fill_buf() {
                            Ok(next) => next,
                            Err(error) => return Err(segment_read_error(error)),
                        };
                        if next.first() == Some(&b'\n') {
                            self.reader.consume(1);
                        }
                    }
                    check_raw_length(&line)?;
                    return Ok(Some(line));
                }
                None => {
                    let length = buffer.len();
                    line.extend_from_slice(buffer);
                    self.reader.consume(length);
                    check_raw_length(&line)?;
                }
            }
        }
    }

    fn next_line(&mut self) -> Result<Option<ArchivedLine>, ArchiveError> {
        let Some(mut raw) = self.read_line()? else {
            return Ok(None);
        };
        if std::mem::take(&mut self.first) && raw.starts_with(b"\xEF\xBB\xBF") {
            raw.drain(..3);
        }
        let text = String::from_utf8_lossy(&raw);
        if text.encode_utf16().count() > MAXIMUM_LINE_CHARACTERS {
            return Err(line_too_large());
        }
        let document = bower_contracts::json::from_str::<Option<LineDocument>>(&text)
            .map_err(|_| ArchiveError::InvalidData("Archived line is not valid JSON.".into()))?
            .ok_or_else(|| ArchiveError::InvalidData("Archived line is empty.".into()))?;
        Ok(Some(ArchivedLine {
            sequence: document.sequence,
            event_id: document.event_id.unwrap_or_default(),
            received_at: document.received_at.unwrap_or_default(),
            chain_hash: document.chain_hash,
            payload: document.payload,
        }))
    }
}

impl Iterator for SegmentReader {
    type Item = Result<ArchivedLine, ArchiveError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = self.next_line().transpose();
        if !matches!(result, Some(Ok(_))) {
            self.done = true;
        }
        result
    }
}

fn check_raw_length(line: &[u8]) -> Result<(), ArchiveError> {
    if line.len() > MAXIMUM_LINE_RAW_BYTES {
        Err(line_too_large())
    } else {
        Ok(())
    }
}

fn line_too_large() -> ArchiveError {
    ArchiveError::InvalidData("Archived line exceeds maximum size.".into())
}

/// .NET `GZipStream` reports corrupt data as `InvalidDataException`.
fn segment_read_error(error: io::Error) -> ArchiveError {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof
    ) {
        ArchiveError::InvalidData("Archive segment is not valid gzip data.".into())
    } else {
        ArchiveError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use bower_contracts::{QueueState, QueuedEvent};

    use super::*;

    fn enqueue(store: &SqliteEventStore, first: i32, last: i32) {
        for index in first..=last {
            store
                .enqueue(&QueuedEvent {
                    lease_token: None,
                    event_id: format!("event-{index}"),
                    fingerprint: format!("sha256:event-{index}"),
                    payload: format!("{{\"eventId\":\"event-{index}\"}}"),
                    received_at: time::now(),
                    state: QueueState::Queued,
                    delivery_attempts: 0,
                    suppression: None,
                })
                .unwrap();
        }
    }

    /// Issue #67 (C# `Archive_LosingConcurrentWriterLeavesCommittedSegmentByteIdentical`):
    /// a writer paused after capturing two rows still owns the archive, so a second writer
    /// that would capture five rows from the same watermark loses without touching it.
    #[test]
    fn losing_concurrent_writer_leaves_committed_segment_byte_identical() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            SqliteEventStore::new(directory.path().join("queue.db"), 10 << 20, None).unwrap();
        store.initialize().unwrap();
        let root = directory.path().join("archive");
        let scheduled = QueueArchive::new(&root, "collector-1", None).unwrap();
        let manual = QueueArchive::new(&root, "manual", None).unwrap();
        enqueue(&store, 1, 2);
        let (captured, on_captured) = mpsc::channel::<()>();
        let (release, on_release) = mpsc::channel::<()>();
        *scheduled.before_publish.lock().unwrap() = Some(Box::new(move || {
            captured.send(()).unwrap();
            on_release.recv().unwrap();
        }));

        std::thread::scope(|scope| {
            let first = scope.spawn(|| scheduled.archive(&store).unwrap());
            on_captured.recv().unwrap();
            enqueue(&store, 3, 5);
            let error = manual.archive(&store).unwrap_err();
            assert!(
                matches!(&error, ArchiveError::Io(io) if io.kind() == io::ErrorKind::WouldBlock),
                "{error:?}"
            );
            release.send(()).unwrap();
            let committed = first.join().unwrap();
            // The winner published rows 1-2, then (still owning the archive) rows 3-5.
            assert_eq!((committed.segments, committed.events), (2, 5));
        });
        let segment = root.join("segment-000000000001.jsonl.gz");
        let manifest = root.join("segment-000000000001.manifest.json");
        let (segment_bytes, manifest_bytes) =
            (fs::read(&segment).unwrap(), fs::read(&manifest).unwrap());
        enqueue(&store, 6, 6);

        let later = manual.archive(&store).unwrap();
        let report = manual.verify(Some(&store.ledger_head().unwrap())).unwrap();

        assert_eq!(later.events, 1);
        assert_eq!(fs::read(&segment).unwrap(), segment_bytes);
        assert_eq!(fs::read(&manifest).unwrap(), manifest_bytes);
        assert!(report.intact, "{report:?}");
        assert_eq!(report.verified_events, 6);
    }
}
