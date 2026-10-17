//! Azure Monitor Agent spool output (port of `Bower.Output.AmaSpool`).
//!
//! Writes UTF-8 JSON Lines through owner-only temporary files in the active
//! directory, flushes them to disk, then atomically renames them into the ready
//! directory where AMA picks them up. Records are never split across files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock};

use bower_contracts::{DeliveryFailure, DeliveryResult, OutputAdapter, QueuedEvent};
use regex::Regex;

pub const DEFAULT_MAXIMUM_FILE_BYTES: i64 = 10 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmaSpoolOptions {
    pub id: String,
    pub collector_id: String,
    pub stream_name: String,
    pub active_directory: PathBuf,
    pub ready_directory: PathBuf,
    pub maximum_file_bytes: i64,
}

impl AmaSpoolOptions {
    pub fn new(
        id: impl Into<String>,
        collector_id: impl Into<String>,
        stream_name: impl Into<String>,
        active_directory: impl Into<PathBuf>,
        ready_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            id: id.into(),
            collector_id: collector_id.into(),
            stream_name: stream_name.into(),
            active_directory: active_directory.into(),
            ready_directory: ready_directory.into(),
            maximum_file_bytes: DEFAULT_MAXIMUM_FILE_BYTES,
        }
    }

    fn validate(&self) -> Result<(), AmaSpoolError> {
        for (name, value) in [
            ("id", &self.id),
            ("collector_id", &self.collector_id),
            ("stream_name", &self.stream_name),
        ] {
            if value.trim().is_empty() {
                return Err(AmaSpoolError::Invalid(format!("{name} is required")));
            }
        }
        for (name, value) in [
            ("active_directory", &self.active_directory),
            ("ready_directory", &self.ready_directory),
        ] {
            if value.as_os_str().to_string_lossy().trim().is_empty() {
                return Err(AmaSpoolError::Invalid(format!("{name} is required")));
            }
        }
        if full_path(&self.active_directory)? == full_path(&self.ready_directory)? {
            return Err(AmaSpoolError::Invalid(
                "Active and ready directories must differ.".to_owned(),
            ));
        }
        if self.maximum_file_bytes < 1_024 {
            return Err(AmaSpoolError::Invalid(
                "maximum_file_bytes must be at least 1024".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AmaSpoolError {
    #[error("invalid AMA spool options: {0}")]
    Invalid(String),
    #[error("AMA spool I/O failure: {0}")]
    Io(#[from] io::Error),
}

/// `Path.GetFullPath`: absolute and lexically normalised, without touching disk.
fn full_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normalised = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other),
        }
    }
    Ok(normalised)
}

pub struct AmaSpoolOutput {
    inner: Arc<Spool>,
}

struct Spool {
    options: AmaSpoolOptions,
    sequence: AtomicI64,
}

impl AmaSpoolOutput {
    /// Validates options and creates both directories with owner-only permissions.
    pub fn new(options: AmaSpoolOptions) -> Result<Self, AmaSpoolError> {
        options.validate()?;
        fs::create_dir_all(&options.active_directory)?;
        fs::create_dir_all(&options.ready_directory)?;
        set_directory_permissions(&options.active_directory)?;
        set_directory_permissions(&options.ready_directory)?;
        Ok(Self {
            inner: Arc::new(Spool {
                options,
                sequence: AtomicI64::new(0),
            }),
        })
    }

    pub fn options(&self) -> &AmaSpoolOptions {
        &self.inner.options
    }

    /// Synchronous delivery. I/O errors propagate (C# exceptions); files already
    /// moved to the ready directory stay there, so a retry may duplicate them
    /// (at-least-once, as in C#).
    pub fn deliver_blocking(&self, events: &[QueuedEvent]) -> io::Result<DeliveryResult> {
        self.inner.deliver_blocking(events)
    }
}

impl Spool {
    fn deliver_blocking(&self, events: &[QueuedEvent]) -> io::Result<DeliveryResult> {
        if events.is_empty() {
            return Ok(DeliveryResult::default());
        }
        let maximum = self.options.maximum_file_bytes;
        let mut acknowledged: Vec<String> = Vec::new();
        let mut failures: Vec<DeliveryFailure> = Vec::new();
        let mut current: Vec<&QueuedEvent> = Vec::new();
        let mut current_bytes: i64 = 0;

        for item in events {
            let record_bytes = i64::try_from(item.payload.len())
                .unwrap_or(i64::MAX)
                .saturating_add(1);
            if record_bytes > maximum {
                failures.push(DeliveryFailure {
                    event_id: item.event_id.clone(),
                    code: "record-exceeds-ama-file-limit".to_owned(),
                    is_retryable: false,
                    retry_after: None,
                });
                continue;
            }
            if !current.is_empty() && current_bytes + record_bytes > maximum {
                self.write_file(&current)?;
                acknowledged.extend(current.iter().map(|value| value.event_id.clone()));
                current.clear();
                current_bytes = 0;
            }
            current.push(item);
            current_bytes += record_bytes;
        }
        if !current.is_empty() {
            self.write_file(&current)?;
            acknowledged.extend(current.iter().map(|value| value.event_id.clone()));
        }

        let destination_acknowledgement = (!acknowledged.is_empty()).then(|| {
            format!(
                "ama-spool:{}:{}",
                self.options.collector_id,
                self.sequence.load(Ordering::SeqCst)
            )
        });
        Ok(DeliveryResult {
            acknowledged_event_ids: acknowledged,
            failures,
            destination_acknowledgement,
        })
    }

    fn write_file(&self, events: &[&QueuedEvent]) -> io::Result<()> {
        let file_sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let stem = format!(
            "{}-{}-{:020}",
            sanitize(&self.options.collector_id),
            sanitize(&self.options.stream_name),
            file_sequence
        );
        let temporary_path = self.options.active_directory.join(format!("{stem}.tmp"));
        let ready_path = self.options.ready_directory.join(format!("{stem}.jsonl"));

        {
            let mut file = create_new_owner_only(&temporary_path)?;
            let mut buffer = Vec::new();
            for item in events {
                buffer.extend_from_slice(item.payload.as_bytes());
                buffer.push(b'\n');
            }
            file.write_all(&buffer)?;
            file.sync_all()?;
        }
        move_no_overwrite(&temporary_path, &ready_path)
    }
}

impl OutputAdapter for AmaSpoolOutput {
    fn id(&self) -> &str {
        &self.inner.options.id
    }

    /// Runs the file I/O on the blocking pool. An I/O error becomes a retryable
    /// `output-adapter-failure` for every event, exactly what the C# delivery worker
    /// records when `DeliverAsync` throws. Dropping the future lets an in-flight
    /// write finish; its events stay unacknowledged and are retried (at-least-once).
    async fn deliver(&self, events: &[QueuedEvent]) -> DeliveryResult {
        let inner = Arc::clone(&self.inner);
        let owned = events.to_vec();
        let outcome = tokio::task::spawn_blocking(move || inner.deliver_blocking(&owned)).await;
        match outcome {
            Ok(Ok(result)) => result,
            _ => DeliveryResult {
                acknowledged_event_ids: Vec::new(),
                failures: events
                    .iter()
                    .map(|item| DeliveryFailure {
                        event_id: item.event_id.clone(),
                        code: "output-adapter-failure".to_owned(),
                        is_retryable: true,
                        retry_after: None,
                    })
                    .collect(),
                destination_acknowledgement: None,
            },
        }
    }
}

/// `char.IsLetterOrDigit` or `-`/`_` kept; everything else becomes `_` (per UTF-16
/// code unit, so a non-BMP character becomes two underscores as in C#).
fn sanitize(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '-'
            || character == '_'
            || (character.len_utf16() == 1 && is_letter_or_digit(character))
        {
            safe.push(character);
        } else {
            for _ in 0..character.len_utf16() {
                safe.push('_');
            }
        }
    }
    safe
}

/// .NET `char.IsLetterOrDigit`: Unicode general category L* or Nd, per BMP code unit.
fn is_letter_or_digit(character: char) -> bool {
    static LETTER_OR_DIGIT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[\p{L}\p{Nd}]$").expect("static pattern compiles"));
    if character.is_ascii() {
        return character.is_ascii_alphanumeric();
    }
    let mut buffer = [0u8; 4];
    LETTER_OR_DIGIT.is_match(character.encode_utf8(&mut buffer))
}

fn create_new_owner_only(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// `File.Move(source, destination)` without overwrite: fails if the destination
/// exists. Uses a hard link + unlink on Unix so the check is atomic.
fn move_no_overwrite(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        match fs::hard_link(source, destination) {
            Ok(()) => fs::remove_file(source),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
            // Filesystems without hard links: check then rename.
            Err(_) => {
                if destination.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "destination exists",
                    ));
                }
                fs::rename(source, destination)
            }
        }
    }
    #[cfg(not(unix))]
    {
        if destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination exists",
            ));
        }
        fs::rename(source, destination)
    }
}

fn set_directory_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_like_dotnet() {
        assert_eq!(sanitize("collector-1"), "collector-1");
        assert_eq!(
            sanitize("Custom-Bower.Security/x"),
            "Custom-Bower_Security_x"
        );
        assert_eq!(sanitize("é😀"), "é__");
    }
}
