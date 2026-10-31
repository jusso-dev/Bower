//! Stable default collector id, mirroring C# `CollectorIdentityFile`. Without
//! `BOWER_COLLECTOR_ID` the first start writes the machine name to `collector-id` beside
//! the queue database and later starts read it back, so a recreated container or pod
//! keeps its id. Both runtimes read and write the same file.

use std::path::{Path, PathBuf};

use crate::HostError;

pub const FILE_NAME: &str = "collector-id";
pub const MAXIMUM_LENGTH: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Configured,
    Persisted,
    Created,
}

pub fn is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAXIMUM_LENGTH
        && value.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

pub fn resolve(
    configured: Option<String>,
    queue_path: &Path,
    machine_name: impl Fn() -> String,
) -> Result<(String, Source), HostError> {
    if let Some(id) = configured.filter(|value| !value.trim().is_empty()) {
        return Ok((id, Source::Configured));
    }
    let directory = queue_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let path = directory.join(FILE_NAME);
    if path.exists() {
        let length = std::fs::metadata(&path)
            .map_err(|error| HostError::io(&path, &error))?
            .len();
        let stored = if length > (MAXIMUM_LENGTH + 2) as u64 {
            String::new()
        } else {
            std::fs::read_to_string(&path)
                .map_err(|error| HostError::io(&path, &error))?
                .trim()
                .to_string()
        };
        // Fail closed: silently replacing a persisted id would fork destination identity.
        return if is_valid(&stored) {
            Ok((stored, Source::Persisted))
        } else {
            Err(HostError::new(
                "InvalidOperationException",
                format!(
                    "{} is not a valid collector id; fix it or set BOWER_COLLECTOR_ID.",
                    path.display()
                ),
            ))
        };
    }
    let id = machine_name().trim().to_string();
    if !is_valid(&id) {
        return Err(HostError::new(
            "InvalidOperationException",
            "The machine name is not a valid collector id; set BOWER_COLLECTOR_ID.",
        ));
    }
    std::fs::create_dir_all(&directory).map_err(|error| HostError::io(&directory, &error))?;
    let temporary = directory.join(format!(
        ".{FILE_NAME}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let written = std::fs::write(&temporary, format!("{id}\n"))
        .and_then(|()| std::fs::hard_link(&temporary, &path));
    let _ = std::fs::remove_file(&temporary);
    match written {
        Ok(()) => Ok((id, Source::Created)),
        // Another process created it first; its id wins.
        Err(_) if path.exists() => resolve(None, queue_path, machine_name),
        Err(error) => Err(HostError::io(&path, &error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors C# `CollectorIdentityFileTests`.
    #[test]
    fn first_start_persists_the_machine_name_and_later_starts_reuse_it() {
        let directory = tempfile::tempdir().unwrap();
        let queue = directory.path().join("state").join("queue.db");
        assert_eq!(
            resolve(None, &queue, || "pod-abc".into()).unwrap(),
            ("pod-abc".into(), Source::Created)
        );
        // A recreated container has a new hostname but keeps the persisted id.
        assert_eq!(
            resolve(Some("  ".into()), &queue, || "pod-xyz".into()).unwrap(),
            ("pod-abc".into(), Source::Persisted)
        );
        assert_eq!(
            resolve(Some("explicit".into()), &queue, || "pod-xyz".into()).unwrap(),
            ("explicit".into(), Source::Configured)
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("state").join(FILE_NAME)).unwrap(),
            "pod-abc\n"
        );
    }

    #[test]
    fn invalid_persisted_or_machine_ids_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let queue = directory.path().join("queue.db");
        assert!(resolve(None, &queue, || "has space".into()).is_err());
        assert!(!directory.path().join(FILE_NAME).exists());
        std::fs::write(directory.path().join(FILE_NAME), "bad\u{1}id\n").unwrap();
        assert!(resolve(None, &queue, || "ok".into()).is_err());
    }
}
