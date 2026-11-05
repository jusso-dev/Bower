//! Path guards (C# `FileTailPaths`). Configuration paths are checked lexically; at read
//! time every directory between the root and the file must exist and not be a symbolic
//! link, and the file must not be one unless `allowSymlink` is set (then the link is
//! followed exactly once and its target must pass the same checks). Roots are trusted
//! operator configuration and may themselves be links.
//!
//! Divergence (recorded in the tests): the Rust port also refuses a FIFO, socket or device
//! at the path. C# cannot tell them from an empty file, so it treats them as too short to
//! fingerprint and never opens them either.

use std::io::ErrorKind;
use std::path::Path;

use crate::config::MAXIMUM_PATH_LENGTH;

/// What a configured path resolves to at read time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathState {
    /// A regular file below an allowed root, without links (or with the one allowed link).
    Ready,
    /// The file, or a directory on its path, does not exist yet. Not an error: wait.
    Missing,
    /// A symbolic link, a directory, a special file or a path outside the roots. Never read.
    Refused,
}

const WILDCARDS: [char; 6] = ['*', '?', '[', ']', '{', '}'];

/// Absolute and already normalised: no `.`, `..`, repeated or trailing separators,
/// wildcards or control characters (C# `Path.GetFullPath(path) == path`).
pub fn is_canonical(path: &str) -> bool {
    let length = path.encode_utf16().count();
    if !(1..=MAXIMUM_PATH_LENGTH).contains(&length)
        || path
            .chars()
            .any(|character| WILDCARDS.contains(&character) || character.is_control())
        || !path.starts_with('/')
    {
        return false;
    }
    if path == "/" {
        return true;
    }
    !path.ends_with('/')
        && path[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

pub fn is_file_system_root(path: &str) -> bool {
    path == "/"
}

/// The allowed root the path lies strictly below, or `None`.
pub fn root_of<'a>(path: &str, roots: &'a [String]) -> Option<&'a String> {
    roots.iter().find(|root| {
        let prefix = format!("{}/", root.trim_end_matches('/'));
        path.starts_with(&prefix)
    })
}

/// The path to open, or why it cannot be read now.
pub fn resolve(path: &str, roots: &[String], allow_symlink: bool) -> (PathState, String) {
    let Some(root) = root_of(path, roots) else {
        return (PathState::Refused, path.to_owned());
    };
    let directories = check_directories(root, path);
    if directories != PathState::Ready {
        return (directories, path.to_owned());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if !allow_symlink {
                return (PathState::Refused, path.to_owned());
            }
            let Ok(target) = std::fs::read_link(path) else {
                return (PathState::Missing, path.to_owned());
            };
            let Some(resolved) = link_target(path, &target) else {
                return (PathState::Refused, path.to_owned());
            };
            let Some(target_root) = root_of(&resolved, roots) else {
                return (PathState::Refused, path.to_owned());
            };
            let target_directories = check_directories(target_root, &resolved);
            if target_directories != PathState::Ready {
                return (target_directories, path.to_owned());
            }
            (finish(&resolved), resolved)
        }
        _ => (finish(path), path.to_owned()),
    }
}

/// The path with every directory resolved through symbolic links (`realpath` of the
/// directory, then the file name), or the path as written when its directory does not exist
/// yet (C# `FileTailPaths.Canonical`).
pub fn canonical(path: &str) -> String {
    let directory = parent(path);
    let name = &path[path.rfind('/').map_or(0, |index| index + 1)..];
    match std::fs::canonicalize(directory)
        .ok()
        .and_then(|real| real.to_str().map(str::to_owned))
    {
        Some(real) if real == "/" => format!("/{name}"),
        Some(real) => format!("{real}/{name}"),
        None => path.to_owned(),
    }
}

/// The normalised absolute target of the link at `path` (C# `Path.GetFullPath(target, parent)`).
pub fn link_target(path: &str, target: &Path) -> Option<String> {
    let joined = match target.to_str()? {
        target if target.starts_with('/') => target.to_owned(),
        target => format!("{}/{target}", parent(path)),
    };
    Some(normalise(&joined))
}

fn finish(path: &str) -> PathState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
            PathState::Refused
        }
        Ok(metadata) if !metadata.is_file() => PathState::Refused,
        Ok(_) => PathState::Ready,
        Err(error) if error.kind() == ErrorKind::NotFound => PathState::Missing,
        Err(_) => PathState::Missing,
    }
}

/// Every directory strictly between the root and the file name.
fn check_directories(root: &str, path: &str) -> PathState {
    let root = root.trim_end_matches('/');
    let directory = parent(path);
    let Some(relative) = directory.strip_prefix(root) else {
        return PathState::Refused;
    };
    let mut current = root.to_owned();
    for segment in relative.split('/').filter(|segment| !segment.is_empty()) {
        current.push('/');
        current.push_str(segment);
        match std::fs::symlink_metadata(Path::new(&current)) {
            Ok(metadata) if metadata.file_type().is_symlink() => return PathState::Refused,
            Ok(metadata) if metadata.is_dir() => {}
            _ => return PathState::Missing,
        }
    }
    PathState::Ready
}

fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(index) => &path[..index],
        None => "",
    }
}

/// Lexical normalisation (C# `Path.GetFullPath`): resolves `.` and `..` without touching
/// the file system.
fn normalise(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    format!("/{}", segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_resolves_dots_lexically() {
        assert_eq!(normalise("/var/log/../log/./a.log"), "/var/log/a.log");
        assert_eq!(normalise("/../a"), "/a");
        assert_eq!(parent("/a"), "/");
        assert_eq!(parent("/var/log/a.log"), "/var/log");
    }
}
