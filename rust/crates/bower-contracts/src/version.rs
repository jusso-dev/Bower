//! The Bower release version of this build (docs/operations/release-versioning.md), as
//! C# `BowerVersion.Current`: `MAJOR.MINOR.PATCH` from the workspace version (kept equal
//! to the repository `VERSION` file), with `-dev.N` or `-rc.N` for a pre-release build.
//! CI sets `BOWER_VERSION` at compile time; a build without it is `<version>-dev.0`.
//! A malformed `BOWER_VERSION` fails the build.

/// `MAJOR.MINOR.PATCH` of the workspace.
pub const CORE: &str = env!("CARGO_PKG_VERSION");

/// The version the collector, its status, heartbeat and events, and the CLI report.
pub const CURRENT: &str = match option_env!("BOWER_VERSION") {
    Some(version) if !version.is_empty() => version,
    _ => concat!(env!("CARGO_PKG_VERSION"), "-dev.0"),
};

const _: () = assert!(
    is_valid(CURRENT, CORE),
    "BOWER_VERSION must be the workspace version, optionally with -dev.N or -rc.N (N at most 65535)"
);

/// True when `version` is `core`, `core-dev.N` or `core-rc.N` with N in 0..=65535 and no
/// leading zero, the scheme `tools/ci/version.py` and Directory.Build.props enforce.
pub const fn is_valid(version: &str, core: &str) -> bool {
    let version = version.as_bytes();
    let core = core.as_bytes();
    if version.len() < core.len() {
        return false;
    }
    let mut index = 0;
    while index < core.len() {
        if version[index] != core[index] {
            return false;
        }
        index += 1;
    }
    if index == version.len() {
        return true;
    }
    let rest = split_at(version, index);
    let number = if starts_with(rest, b"-dev.") {
        split_at(rest, 5)
    } else if starts_with(rest, b"-rc.") {
        split_at(rest, 4)
    } else {
        return false;
    };
    if number.is_empty() || number.len() > 5 || (number.len() > 1 && number[0] == b'0') {
        return false;
    }
    let mut value: u32 = 0;
    let mut digit = 0;
    while digit < number.len() {
        if !number[digit].is_ascii_digit() {
            return false;
        }
        value = value * 10 + (number[digit] - b'0') as u32;
        digit += 1;
    }
    value <= 65535
}

const fn split_at(bytes: &[u8], at: usize) -> &[u8] {
    bytes.split_at(at).1
}

const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    if bytes.len() < prefix.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_release_scheme() {
        for version in [
            "0.1.0",
            "0.1.0-dev.0",
            "0.1.0-dev.362",
            "0.1.0-rc.2",
            "0.1.0-dev.65535",
        ] {
            assert!(is_valid(version, "0.1.0"), "{version}");
        }
        for version in [
            "0.1.1",
            "0.1",
            "0.1.0-",
            "0.1.0-dev",
            "0.1.0-dev.",
            "0.1.0-dev.01",
            "0.1.0-dev.65536",
            "0.1.0-beta.1",
            "0.1.0+abc",
            "0.1.0-dev.1x",
            "0.1.00",
            "0.1.0-dev.123456",
        ] {
            assert!(!is_valid(version, "0.1.0"), "{version}");
        }
    }

    #[test]
    fn current_is_the_workspace_version_or_a_prerelease_of_it() {
        assert!(is_valid(CURRENT, CORE));
        assert!(CURRENT.starts_with(CORE));
        if let Some(expected) = option_env!("BOWER_EXPECTED_VERSION") {
            assert_eq!(CURRENT, expected);
        }
    }

    #[test]
    fn workspace_version_matches_the_repository_version_file() {
        // Shared asset read from the repository, like policies/ and packs/.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../VERSION");
        let file = std::fs::read_to_string(path).expect("repository VERSION file");
        assert_eq!(file.trim(), CORE);
    }
}
