//! One generation of a tailed file, opened once (C# `FileTailHandle`): its identity,
//! length and write time come from the same handle its lines are read from, so bytes of
//! one generation can never move another generation's cursor.
//!
//! On Unix the open does not follow a final symbolic link and does not block
//! (`O_NOFOLLOW | O_NONBLOCK`), and the handle must be a regular file with the same device
//! and inode as the path. (C# does the same on Linux through libc; elsewhere it checks the
//! path is still not a link after opening.)

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

/// The identity covers the first complete line, at least 64 and at most 4096 bytes.
pub const MINIMUM_IDENTITY_BYTES: u64 = 64;
pub const MAXIMUM_IDENTITY_BYTES: usize = 4_096;

/// The opened file is not the validated regular file (a link or another file was swapped in).
#[derive(Debug)]
pub enum OpenError {
    Refused,
    Io(std::io::Error),
}

pub struct Handle {
    pub(crate) file: File,
    /// Length when opened; bytes appended later wait for the next read.
    pub length: i64,
    pub write_time: Option<SystemTime>,
    /// `None` while the first line is incomplete (and shorter than 4096 bytes).
    pub fingerprint: Option<String>,
    /// `device:inode` of the opened file (Unix), or `None`.
    pub file_id: Option<String>,
}

/// Bytes before a cursor's offset that its anchor covers, at most (C# `AnchorBytes`).
pub const ANCHOR_BYTES: i64 = 256;

impl Handle {
    /// The continuity anchor at `offset` (C# `AnchorAt`): SHA-256 of the last
    /// min(offset, `ANCHOR_BYTES`) bytes before it, read through this handle. `None` at offset
    /// 0, or when those bytes are no longer all there.
    pub fn anchor_at(&mut self, offset: i64) -> Option<String> {
        if offset <= 0 {
            return None;
        }
        let count = offset.min(ANCHOR_BYTES);
        let mut bytes = vec![0; usize::try_from(count).ok()?];
        self.file
            .seek(SeekFrom::Start(u64::try_from(offset - count).ok()?))
            .ok()?;
        self.file.read_exact(&mut bytes).ok()?;
        Some(hex::encode(Sha256::digest(&bytes)))
    }

    /// Write time as 100 ns ticks since the Unix epoch (C# `WriteTicks`).
    pub fn write_ticks(&self) -> i64 {
        self.write_time
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |since| {
                i64::try_from(since.as_nanos() / 100).unwrap_or(i64::MAX)
            })
    }
}

/// `device:inode` of the regular file at `path` without opening it (Unix), or `None`.
pub fn file_id_of(path: &Path) -> Option<String> {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|metadata| file_id(&metadata))
}

#[cfg(unix)]
fn file_id(metadata: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_id(_: &std::fs::Metadata) -> Option<String> {
    None
}

/// Tests only: a hook on the path being opened.
#[cfg(test)]
pub(crate) type Hook = std::cell::RefCell<Option<Box<dyn Fn(&Path)>>>;

#[cfg(test)]
thread_local! {
    /// Tests only: runs before a validated path is opened (to swap the path).
    pub(crate) static BEFORE_OPEN: Hook = std::cell::RefCell::new(None);
    /// Tests only: runs once a path is opened and identified (to replace the file).
    pub(crate) static AFTER_OPEN: Hook = std::cell::RefCell::new(None);
}

/// Opens a path already checked by `paths::resolve`, or `None` when it is missing, not a
/// regular file or shorter than 64 bytes (never opened, so FIFOs and devices never block).
pub fn open(path: Option<&Path>) -> Result<Option<Handle>, OpenError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let named = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(OpenError::Io(error)),
    };
    if named.file_type().is_symlink() {
        return Err(OpenError::Refused);
    }
    if !named.is_file() || named.len() < MINIMUM_IDENTITY_BYTES {
        return Ok(None);
    }
    #[cfg(test)]
    BEFORE_OPEN.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(path);
        }
    });
    let file = match open_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) if is_loop(&error) => return Err(OpenError::Refused),
        Err(error) => return Err(OpenError::Io(error)),
    };
    let opened = file.metadata().map_err(OpenError::Io)?;
    if !opened.is_file() || !same_file(&opened, path) {
        return Err(OpenError::Refused);
    }
    let length = i64::try_from(opened.len()).unwrap_or(i64::MAX);
    let mut handle = Handle {
        file,
        length,
        write_time: opened.modified().ok(),
        fingerprint: None,
        file_id: file_id(&opened),
    };
    handle.fingerprint = identity(&mut handle.file, length).map_err(OpenError::Io)?;
    #[cfg(test)]
    AFTER_OPEN.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(path);
        }
    });
    Ok(Some(handle))
}

/// The identity of the file at `path` (`None` when it has none yet).
pub fn fingerprint(path: &Path) -> std::io::Result<Option<String>> {
    match open(Some(path)) {
        Ok(handle) => Ok(handle.and_then(|handle| handle.fingerprint)),
        Err(OpenError::Refused) => Ok(None),
        Err(OpenError::Io(error)) => Err(error),
    }
}

/// SHA-256 over the first complete line, extended to 64 bytes and capped at 4096.
fn identity(file: &mut File, length: i64) -> std::io::Result<Option<String>> {
    let available = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(MAXIMUM_IDENTITY_BYTES);
    let mut prefix = vec![0u8; available];
    file.seek(SeekFrom::Start(0))?;
    let mut read = 0;
    while read < available {
        let got = file.read(&mut prefix[read..])?;
        if got == 0 {
            break;
        }
        read += got;
    }
    let minimum = MINIMUM_IDENTITY_BYTES as usize;
    if read < minimum {
        return Ok(None);
    }
    let identity = match prefix[..read].iter().position(|&byte| byte == b'\n') {
        Some(newline) => Some(minimum.max(newline + 1)),
        None if read == MAXIMUM_IDENTITY_BYTES => Some(MAXIMUM_IDENTITY_BYTES),
        None => None,
    };
    Ok(identity
        .filter(|identity| *identity <= read)
        .map(|identity| hex::encode(Sha256::digest(&prefix[..identity]))))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn is_loop(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_loop(_: &std::io::Error) -> bool {
    false
}

/// The handle is the file the path names now (same device and inode, path not a link).
#[cfg(unix)]
fn same_file(opened: &std::fs::Metadata, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|named| {
        !named.file_type().is_symlink()
            && named.dev() == opened.dev()
            && named.ino() == opened.ino()
    })
}

#[cfg(not(unix))]
fn same_file(_: &std::fs::Metadata, path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|named| !named.file_type().is_symlink())
}
