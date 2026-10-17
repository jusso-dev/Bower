//! Bearer authentication for event producers (C# `IngestAuthentication`).
//!
//! One shared token (`BOWER_INGEST_TOKEN`, producer id `default`) and/or a tokens
//! file with one revocable credential per producer. The file holds SHA-256 hashes,
//! never tokens: `sidecar-01 sha256:<hex>`. Removing a line revokes that producer
//! within seconds, without a restart. Comparisons are constant-time over every
//! entry, and tokens are never logged.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bower_contracts::time::{Clock, SystemClock, Timestamp};
use sha2::{Digest, Sha256};

use crate::error::HostError;

const RELOAD_INTERVAL_SECONDS: i64 = 2;

type Credential = (String, [u8; 32]);

struct FileState {
    tokens: Vec<Credential>,
    next_reload: Option<Timestamp>,
    stamp: Option<SystemTime>,
}

pub struct IngestAuthentication {
    shared: Option<Credential>,
    tokens_file: Option<PathBuf>,
    clock: Arc<dyn Clock>,
    state: Mutex<FileState>,
}

impl IngestAuthentication {
    pub fn new(token: Option<&str>, tokens_file: Option<&Path>) -> Result<Self, HostError> {
        Self::with_clock(token, tokens_file, Arc::new(SystemClock))
    }

    pub fn with_clock(
        token: Option<&str>,
        tokens_file: Option<&Path>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, HostError> {
        let shared = token
            .filter(|value| !value.is_empty())
            .map(|value| ("default".to_string(), digest(value)));
        let tokens_file = tokens_file
            .filter(|path| !crate::settings::is_blank(&path.to_string_lossy()))
            .map(Path::to_path_buf);
        let mut state = FileState {
            tokens: Vec::new(),
            next_reload: None,
            stamp: None,
        };
        if let Some(path) = &tokens_file {
            // Fail fast on a missing or malformed file at start-up.
            state.tokens = parse(&read_lines(path)?)?;
            state.stamp = std::fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok();
        }
        Ok(Self {
            shared,
            tokens_file,
            clock,
            state: Mutex::new(state),
        })
    }

    pub fn required(&self) -> bool {
        self.shared.is_some() || self.tokens_file.is_some()
    }

    /// The authenticated producer id, or `None`. `anonymous` when auth is off.
    /// `authorization` is the raw `Authorization` header value.
    pub fn authenticate(&self, authorization: Option<&str>) -> Option<String> {
        if !self.required() {
            return Some("anonymous".into());
        }

        const PREFIX: &str = "Bearer ";
        let header = authorization?;
        if header.len() < PREFIX.len()
            || !header.is_char_boundary(PREFIX.len())
            || !header[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
        {
            return None;
        }

        let presented = digest(header[PREFIX.len()..].trim());
        let mut matched: Option<String> = None;
        let file_tokens = self.file_tokens();
        // Check every entry so timing does not reveal which producer matched.
        for (producer, expected) in self.shared.iter().chain(file_tokens.iter()) {
            if fixed_time_equals(&presented, expected) && matched.is_none() {
                matched = Some(producer.clone());
            }
        }
        matched
    }

    /// Formats a tokens-file line for a producer and a freshly generated token.
    pub fn tokens_file_line(producer: &str, token: &str) -> String {
        format!("{producer} sha256:{}", hex::encode(digest(token)))
    }

    fn file_tokens(&self) -> Vec<Credential> {
        let Some(path) = &self.tokens_file else {
            return Vec::new();
        };

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = self.clock.utc_now();
        if state.next_reload.is_some_and(|next| now < next) {
            return state.tokens.clone();
        }

        state.next_reload = Some(now + chrono::TimeDelta::seconds(RELOAD_INTERVAL_SECONDS));
        let reloaded = std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .map_err(|error| HostError::io(path, &error))
            .and_then(|stamp| {
                if Some(stamp) == state.stamp {
                    return Ok(None);
                }
                Ok(Some((parse(&read_lines(path)?)?, stamp)))
            });
        match reloaded {
            Ok(Some((tokens, stamp))) => {
                state.tokens = tokens;
                state.stamp = Some(stamp);
            }
            Ok(None) => {}
            Err(_) => {
                // A missing or unreadable file revokes every file-based credential.
                state.tokens = Vec::new();
                state.stamp = None;
            }
        }
        state.tokens.clone()
    }
}

/// `File.ReadAllLines`: BOM stripped, split on `\r\n`, `\n` or `\r`.
fn read_lines(path: &Path) -> Result<Vec<String>, HostError> {
    let bytes = std::fs::read(path).map_err(|error| HostError::io(path, &error))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .flat_map(|line| line.split('\r'))
        .map(str::to_string)
        .collect();
    if text.ends_with('\n') || text.ends_with('\r') {
        lines.pop();
    }
    Ok(lines)
}

/// Parses tokens-file lines (C# `IngestAuthentication.Parse`).
pub fn parse(lines: &[String]) -> Result<Vec<(String, [u8; 32])>, HostError> {
    let mut tokens = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(' ').filter(|part| !part.is_empty()).collect();
        let producer_length = parts.first().map_or(0, |part| part.encode_utf16().count());
        if parts.len() != 2
            || !(1..=64).contains(&producer_length)
            || !parts[1].starts_with("sha256:")
            || parts[1].encode_utf16().count() != 7 + 64
        {
            return Err(HostError::new(
                "FormatException",
                format!(
                    "Ingest tokens file line {} must be '<producer-id> sha256:<64 hex>'.",
                    index + 1
                ),
            ));
        }

        let mut hash = [0u8; 32];
        hex::decode_to_slice(&parts[1][7..], &mut hash).map_err(|_| {
            HostError::new(
                "FormatException",
                "The input is not a valid hex string as it contains a non-hex character.",
            )
        })?;
        tokens.push((parts[0].to_string(), hash));
    }
    Ok(tokens)
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// `CryptographicOperations.FixedTimeEquals` for equal-length digests.
fn fixed_time_equals(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let difference = left
        .iter()
        .zip(right)
        .fold(0u8, |accumulator, (a, b)| accumulator | (a ^ b));
    std::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects_lines() {
        let line = IngestAuthentication::tokens_file_line("portal", "x");
        assert!(line.starts_with(
            "portal sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
        ));
        let parsed = parse(&["# c".into(), "".into(), line]).unwrap();
        assert_eq!(parsed.len(), 1);
        let error = parse(&["sidecar-01 not-a-hash".into()]).unwrap_err();
        assert_eq!(error.kind, "FormatException");
        assert!(error.message.contains("line 1"));
        let bad_hex = format!("p sha256:{}", "z".repeat(64));
        assert!(parse(&[bad_hex]).is_err());
    }

    #[test]
    fn prefix_is_case_insensitive_and_trimmed() {
        let auth =
            IngestAuthentication::new(Some("0123456789abcdef0123456789abcdef"), None).unwrap();
        assert_eq!(
            auth.authenticate(Some("bearer  0123456789abcdef0123456789abcdef "))
                .as_deref(),
            Some("default")
        );
        assert_eq!(auth.authenticate(Some("Basic abc")), None);
        assert_eq!(auth.authenticate(Some("Bearé")), None);
        assert_eq!(auth.authenticate(None), None);
    }

    #[test]
    fn anonymous_when_not_required() {
        let auth = IngestAuthentication::new(None, None).unwrap();
        assert!(!auth.required());
        assert_eq!(auth.authenticate(None).as_deref(), Some("anonymous"));
    }
}
