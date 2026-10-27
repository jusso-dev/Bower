//! `PackArchive`: builds, signs, verifies and loads `.bowerpack` archives.
//!
//! Never loads an unsigned pack or one signed by an untrusted key; there is no
//! "skip verification" switch. Every archive file must be listed in the signed
//! manifest with its SHA-256; unlisted files, path traversal and oversized entries
//! fail verification. Content is parsed and validated (and samples run) at build
//! time, so a broken pack cannot be signed.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use bower_contracts::time::{Clock, SystemClock};
use bower_detection::DetectionRule;
use bower_integrity::{DetachedSignature, canonical_json, sha256_hex};
use bower_pipeline::{CustomLogParserConfiguration, validate_configuration};
use bower_policy::LoadedPolicy;
use bower_redaction::PrivacyPolicy;
use regex::Regex;
use serde_json::Value;

use crate::model::{PackFile, PackManifest, PackPolicyEntry, PackSource, roles};
use crate::tester;
use crate::zip;

pub const MANIFEST_ENTRY: &str = "manifest.json";
pub const SIGNATURE_ENTRY: &str = "manifest.sig";
const CONTENT_PREFIX: &str = "content/";
pub const MAXIMUM_ENTRIES: usize = 500;
pub const MAXIMUM_FILE_BYTES: u64 = 1_048_576;
pub const MAXIMUM_ARCHIVE_BYTES: u64 = 50 * 1_048_576;

static PACK_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$").expect("static regex"));
static SEMVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$").expect("static regex")
});
static SAFE_ENTRY_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(manifest\.json|manifest\.sig|content/[A-Za-z0-9_.\-/]+)$").expect("static regex")
});

/// Pack failures. `Verification` is C# `PackVerificationException`: the archive is
/// not trusted. The others mirror `InvalidDataException`, `FileNotFoundException`
/// and I/O errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackError {
    #[error("{0}")]
    Verification(String),
    #[error("{0}")]
    InvalidData(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Io(String),
}

fn verification(message: impl Into<String>) -> PackError {
    PackError::Verification(message.into())
}

fn invalid(message: impl Into<String>) -> PackError {
    PackError::InvalidData(message.into())
}

/// A verified pack: signature checked, every file hash matched, content parsed.
#[derive(Clone)]
pub struct LoadedPack {
    /// `None` only for the unsigned candidate the builder tests before signing.
    pub manifest: Option<PackManifest>,
    pub signed_by_key_id: String,
    pub policies: Vec<LoadedPolicy>,
    pub privacy_profile_yaml: Option<String>,
    pub detections: Vec<DetectionRule>,
    pub parsers: Vec<CustomLogParserConfiguration>,
    /// Pack path of each parser, parallel to `parsers` (manifest order).
    pub parser_paths: Vec<String>,
    pub sample_lines: Vec<String>,
    pub dcr_template_json: Option<String>,
}

impl fmt::Debug for LoadedPack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedPack")
            .field(
                "id",
                &self.manifest.as_ref().map(|manifest| manifest.id.as_str()),
            )
            .field(
                "version",
                &self
                    .manifest
                    .as_ref()
                    .map(|manifest| manifest.version.as_str()),
            )
            .field("signed_by_key_id", &self.signed_by_key_id)
            .field("policies", &self.policies.len())
            .field("detections", &self.detections.len())
            .field("parsers", &self.parsers.len())
            .field("samples", &self.sample_lines.len())
            .field("dcr", &self.dcr_template_json.is_some())
            .finish()
    }
}

/// Validates a source directory and writes a signed archive
/// (`<output>/<id>-<version>.bowerpack`). Returns its path.
pub fn build(
    source_directory: &Path,
    private_key_pem: &str,
    output_directory: &Path,
    clock: Option<&dyn Clock>,
) -> Result<PathBuf, PackError> {
    let clock = clock.unwrap_or(&SystemClock);
    let root = full_path(source_directory)?;
    let source = read_source(&root.join("pack.yaml"))?;
    validate_source(&source)?;

    let mut files: Vec<(String, String, Vec<u8>)> = Vec::new();
    let mut add = |relative: &str, role: &str| -> Result<(), PackError> {
        let full = safe_join(&root, relative)?;
        let metadata = std::fs::metadata(&full)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .ok_or_else(|| PackError::NotFound(format!("Pack file not found: {relative}")))?;
        if metadata.len() > MAXIMUM_FILE_BYTES {
            return Err(invalid(format!("Pack file exceeds 1 MiB: {relative}")));
        }
        let content = std::fs::read(&full)
            .map_err(|error| PackError::Io(format!("{relative}: {}", error.kind())))?;
        files.push((normalise_relative(relative), role.to_owned(), content));
        Ok(())
    };

    for path in &source.policies {
        add(path, roles::POLICY)?;
    }
    if let Some(path) = &source.privacy_profile {
        add(path, roles::PRIVACY_PROFILE)?;
    }
    for path in &source.parsers {
        add(path, roles::PARSER)?;
    }
    for path in &source.detections {
        add(path, roles::DETECTION)?;
    }
    for path in &source.samples {
        add(path, roles::SAMPLE)?;
    }
    if source.dcr {
        let template =
            bower_dcr::generator::generate_json(&bower_dcr::DcrTemplateOptions::default())
                .map_err(|error| invalid(error.to_string()))?;
        files.push((
            "dcr/bower-dcr.json".to_owned(),
            roles::DCR.to_owned(),
            template.into_bytes(),
        ));
    }

    // Parse everything and run the samples so a broken pack cannot be signed. Parsers
    // take manifest (ordinal path) order, as at load, so a sample's parser index means
    // the same parser at build and at test time.
    let mut parsed = parse_content(
        files
            .iter()
            .map(|(path, role, content)| (path.as_str(), role.as_str(), content.as_slice())),
    )?;
    let mut parsers: Vec<_> = std::mem::take(&mut parsed.parser_paths)
        .into_iter()
        .zip(std::mem::take(&mut parsed.parsers))
        .collect();
    parsers.sort_by(|left, right| canonical_json::compare_ordinal(&left.0, &right.0));
    (parsed.parser_paths, parsed.parsers) = parsers.into_iter().unzip();
    let candidate = parsed.into_pack(None, "unsigned".to_owned());
    let privacy = test_privacy_policy(candidate.privacy_profile_yaml.as_deref())?;
    let failures: Vec<_> = tester::run(&candidate, privacy, Some(clock))?
        .into_iter()
        .filter(|result| !result.passed)
        .collect();
    if !failures.is_empty() {
        let details: Vec<String> = failures
            .iter()
            .map(|item| format!("{}: {}", item.name, item.problems.join(" ")))
            .collect();
        return Err(invalid(format!(
            "Pack samples failed: {}",
            details.join("; ")
        )));
    }

    files.sort_by(|left, right| canonical_json::compare_ordinal(&left.0, &right.0));
    let pack_files: Vec<PackFile> = files
        .iter()
        .map(|(path, role, content)| PackFile {
            path: path.clone(),
            role: role.clone(),
            sha256: sha256_hex(content),
            bytes: i64::try_from(content.len()).expect("pack files are bounded"),
        })
        .collect();
    let metadata = &source.metadata;
    let manifest = PackManifest {
        api_version: "bower.security/v1".to_owned(),
        kind: PackManifest::CURRENT_KIND.to_owned(),
        id: metadata.id.clone(),
        version: metadata.version.clone(),
        name: metadata.name.clone(),
        description: metadata.description.clone(),
        owner: metadata.owner.clone(),
        created_at: clock.utc_now(),
        pack_hash: pack_hash(&pack_files),
        files: pack_files,
        policies: candidate
            .policies
            .iter()
            .map(|policy| PackPolicyEntry {
                id: policy.policy.metadata.id.clone(),
                version: policy.policy.metadata.version.clone(),
                hash: policy.hash.clone(),
                event_types: policy.policy.r#match.event_types.clone(),
            })
            .collect(),
    };

    let manifest_bytes = manifest.canonical_bytes();
    let signature = bower_integrity::sign(&manifest_bytes, private_key_pem)
        .map_err(|error| invalid(format!("Pack signing failed: {error}")))?;
    let signature_bytes = bower_contracts::json::to_vec(&signature)
        .map_err(|_| invalid("Pack signature could not be serialized."))?;

    let mut entries = vec![
        (MANIFEST_ENTRY.to_owned(), manifest_bytes),
        (SIGNATURE_ENTRY.to_owned(), signature_bytes),
    ];
    entries.extend(
        files
            .into_iter()
            .map(|(path, _, content)| (format!("{CONTENT_PREFIX}{path}"), content)),
    );
    let archive = zip::write(&entries);

    std::fs::create_dir_all(output_directory).map_err(|error| {
        PackError::Io(format!(
            "Cannot create the output directory: {}",
            error.kind()
        ))
    })?;
    let output = output_directory.join(format!("{}-{}.bowerpack", metadata.id, metadata.version));
    std::fs::write(&output, archive).map_err(|error| {
        PackError::Io(format!("Cannot write the pack archive: {}", error.kind()))
    })?;
    Ok(output)
}

/// Verifies signature and hashes, then parses the content. Fails on any problem.
pub fn load<S: AsRef<str>>(
    archive_path: &Path,
    trusted_public_key_pems: &[S],
) -> Result<LoadedPack, PackError> {
    require_trust(trusted_public_key_pems)?;
    let too_large = || verification("Pack archive is missing or exceeds 50 MiB.");
    let metadata = std::fs::metadata(archive_path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .ok_or_else(too_large)?;
    if metadata.len() > MAXIMUM_ARCHIVE_BYTES {
        return Err(too_large());
    }
    let archive = std::fs::read(archive_path).map_err(|_| too_large())?;
    load_bytes(&archive, trusted_public_key_pems)
}

/// [`load`] for an archive already in memory.
pub fn load_bytes<S: AsRef<str>>(
    archive: &[u8],
    trusted_public_key_pems: &[S],
) -> Result<LoadedPack, PackError> {
    require_trust(trusted_public_key_pems)?;
    if archive.len() as u64 > MAXIMUM_ARCHIVE_BYTES {
        return Err(verification("Pack archive is missing or exceeds 50 MiB."));
    }
    // `ZipFile.OpenRead` / `ZipArchiveEntry.Open` throw InvalidDataException.
    let unreadable = |error: zip::ZipError| invalid(error.to_string());
    let listing = zip::entries(archive).map_err(unreadable)?;
    if listing.len() > MAXIMUM_ENTRIES {
        return Err(verification("Pack archive has too many entries."));
    }

    let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(listing.len());
    for entry in &listing {
        if entry.name.ends_with('/') {
            continue;
        }
        if entry.length > MAXIMUM_FILE_BYTES
            || !SAFE_ENTRY_NAME.is_match(&entry.name)
            || entry
                .name
                .split('/')
                .any(|segment| segment == ".." || segment == ".")
        {
            return Err(verification(format!(
                "Pack entry '{}' is not allowed.",
                entry.name
            )));
        }
        // Stricter than C# (last duplicate wins there): an archive that names a file
        // twice is ambiguous to other zip tools, so it is refused.
        if entries.iter().any(|(name, _)| *name == entry.name) {
            return Err(verification(format!(
                "Pack entry '{}' is not allowed.",
                entry.name
            )));
        }
        let content = zip::read(archive, entry, MAXIMUM_FILE_BYTES).map_err(unreadable)?;
        entries.push((entry.name.clone(), content));
    }
    let entry = |name: &str| {
        entries
            .iter()
            .find(|(entry, _)| entry == name)
            .map(|(_, content)| content.as_slice())
    };

    let (Some(manifest_bytes), Some(signature_bytes)) =
        (entry(MANIFEST_ENTRY), entry(SIGNATURE_ENTRY))
    else {
        return Err(verification("Pack is missing its manifest or signature."));
    };
    let signature: DetachedSignature =
        match bower_contracts::json::from_slice::<Option<DetachedSignature>>(signature_bytes) {
            Ok(Some(signature)) => signature,
            _ => return Err(verification("Pack signature is unreadable.")),
        };
    let manifest: PackManifest =
        match bower_contracts::json::from_slice::<Option<PackManifest>>(manifest_bytes) {
            Ok(Some(manifest)) => manifest,
            _ => return Err(verification("Pack manifest is unreadable.")),
        };
    // Re-serializing must reproduce the stored bytes exactly: no unknown, duplicate
    // or reordered members can ride along under the signature.
    let canonical = manifest.canonical_bytes();
    if canonical != manifest_bytes
        || !bower_integrity::verify(
            &canonical,
            &signature,
            trusted_public_key_pems.iter().map(AsRef::as_ref),
        )
    {
        return Err(verification(
            "Pack signature is invalid or not from a trusted key.",
        ));
    }

    if pack_hash(&manifest.files) != manifest.pack_hash {
        return Err(verification("Pack hash does not match its file list."));
    }

    for (name, _) in &entries {
        if name == MANIFEST_ENTRY || name == SIGNATURE_ENTRY {
            continue;
        }
        if !manifest
            .files
            .iter()
            .any(|file| format!("{CONTENT_PREFIX}{}", file.path) == *name)
        {
            return Err(verification(format!(
                "Pack contains an unlisted file: {name}"
            )));
        }
    }

    let mut files = Vec::with_capacity(manifest.files.len());
    for file in &manifest.files {
        match entry(&format!("{CONTENT_PREFIX}{}", file.path)) {
            Some(content) if sha256_hex(content) == file.sha256 => {
                files.push((file.path.as_str(), file.role.as_str(), content))
            }
            _ => {
                return Err(verification(format!(
                    "Pack file '{}' is missing or modified.",
                    file.path
                )));
            }
        }
    }

    let parsed = parse_content(files)?;
    Ok(parsed.into_pack(Some(manifest), signature.key_id))
}

fn require_trust<S: AsRef<str>>(trusted: &[S]) -> Result<(), PackError> {
    if trusted.is_empty() {
        return Err(verification(
            "No trusted public keys configured; refusing to load an unverified pack.",
        ));
    }
    Ok(())
}

/// `sha256:` over `path\x1Frole\x1Fsha256` lines sorted by ordinal path.
pub fn pack_hash(files: &[PackFile]) -> String {
    let mut sorted: Vec<&PackFile> = files.iter().collect();
    sorted.sort_by(|left, right| canonical_json::compare_ordinal(&left.path, &right.path));
    let lines: Vec<String> = sorted
        .iter()
        .map(|file| format!("{}\u{1f}{}\u{1f}{}", file.path, file.role, file.sha256))
        .collect();
    format!("sha256:{}", sha256_hex(lines.join("\n").as_bytes()))
}

struct ParsedContent {
    policies: Vec<LoadedPolicy>,
    privacy_profile: Option<String>,
    detections: Vec<DetectionRule>,
    parsers: Vec<CustomLogParserConfiguration>,
    parser_paths: Vec<String>,
    samples: Vec<String>,
    dcr: Option<String>,
}

impl ParsedContent {
    fn into_pack(self, manifest: Option<PackManifest>, key_id: String) -> LoadedPack {
        LoadedPack {
            manifest,
            signed_by_key_id: key_id,
            policies: self.policies,
            privacy_profile_yaml: self.privacy_profile,
            detections: self.detections,
            parsers: self.parsers,
            parser_paths: self.parser_paths,
            sample_lines: self.samples,
            dcr_template_json: self.dcr,
        }
    }
}

fn parse_content<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str, &'a [u8])>,
) -> Result<ParsedContent, PackError> {
    let mut parsed = ParsedContent {
        policies: Vec::new(),
        privacy_profile: None,
        detections: Vec::new(),
        parsers: Vec::new(),
        parser_paths: Vec::new(),
        samples: Vec::new(),
        dcr: None,
    };
    for (path, role, content) in files {
        // `Encoding.UTF8.GetString`: invalid sequences become U+FFFD.
        let text = String::from_utf8_lossy(content).into_owned();
        match role {
            roles::POLICY => parsed.policies.push(
                bower_policy::load_yaml(&text, path).map_err(|error| invalid(error.to_string()))?,
            ),
            roles::PRIVACY_PROFILE => {
                // Structural validation only: keys are supplied by the host at load time.
                // A throwaway key lets profiles that use Hmac validate.
                bower_redaction::load_privacy_profile(&text, Some(&[0u8; 32]), Some("validation"))
                    .map_err(|error| invalid(error.to_string()))?;
                parsed.privacy_profile = Some(text);
            }
            roles::DETECTION => parsed.detections.push(
                bower_detection::load_yaml(&text, Some(path))
                    .map_err(|error| invalid(error.to_string()))?,
            ),
            roles::PARSER => {
                let configuration = CustomLogParserConfiguration::from_json(&text)
                    .map_err(|error| invalid(format!("Parser '{path}' is invalid: {error}")))?;
                let issues = validate_configuration(&configuration);
                if !issues.is_empty() {
                    return Err(invalid(format!(
                        "Parser '{path}' is invalid: {}",
                        issues.join(" ")
                    )));
                }
                parsed.parsers.push(configuration);
                parsed.parser_paths.push(path.to_owned());
            }
            roles::SAMPLE => parsed.samples.extend(
                text.split('\n')
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned),
            ),
            roles::DCR => {
                match serde_json::from_str::<Value>(&text) {
                    Ok(Value::Null) => return Err(invalid("DCR template is empty.")),
                    Ok(_) => {}
                    Err(_) => return Err(invalid("DCR template is not valid JSON.")),
                }
                parsed.dcr = Some(text);
            }
            other => return Err(invalid(format!("Unknown pack file role '{other}'."))),
        }
    }

    let mut ids = std::collections::HashSet::new();
    if parsed.parsers.len() > 64
        || parsed.detections.len() > 64
        || parsed
            .detections
            .iter()
            .any(|rule| !ids.insert(rule.id.to_lowercase()))
    {
        return Err(invalid(
            "Duplicate detection identity or runtime pack limit exceeded.",
        ));
    }
    if parsed.policies.is_empty() {
        return Err(invalid("A pack must contain at least one policy."));
    }
    Ok(parsed)
}

/// Privacy policy for sample tests: the pack's profile with a throwaway HMAC key,
/// or the default policy when the pack ships no profile.
pub fn test_privacy_policy(profile_yaml: Option<&str>) -> Result<PrivacyPolicy, PackError> {
    let Some(yaml) = profile_yaml else {
        return Ok(PrivacyPolicy::create_default());
    };
    let mut key = [0u8; 32];
    getrandom::fill(&mut key)
        .map_err(|_| PackError::Io("No secure random source is available.".to_owned()))?;
    bower_redaction::load_privacy_profile(yaml, Some(&key), Some("test"))
        .map(|profile| profile.policy)
        .map_err(|error| invalid(error.to_string()))
}

fn read_source(path: &Path) -> Result<PackSource, PackError> {
    if !path.is_file() {
        return Err(PackError::NotFound("pack.yaml not found.".to_owned()));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| PackError::Io(format!("pack.yaml: {}", error.kind())))?;
    match serde_yaml_ng::from_str::<Option<PackSource>>(&text) {
        Ok(Some(source)) => Ok(source),
        Ok(None) => Err(invalid("pack.yaml is empty.")),
        Err(error) => {
            let line = error.location().map_or(0, |location| location.line());
            Err(invalid(format!(
                "pack.yaml is invalid at line {line}: {error}"
            )))
        }
    }
}

fn validate_source(source: &PackSource) -> Result<(), PackError> {
    if source.api_version != "bower.security/v1" || source.kind != "Pack" {
        return Err(invalid(
            "pack.yaml must be apiVersion bower.security/v1, kind Pack.",
        ));
    }
    if !PACK_ID.is_match(&source.metadata.id) {
        return Err(invalid(
            "Pack id must be lowercase letters, digits and hyphens (3-64).",
        ));
    }
    if !SEMVER.is_match(&source.metadata.version) {
        return Err(invalid(
            "Pack version must be semantic (for example 1.2.0).",
        ));
    }
    Ok(())
}

/// `Path.GetFullPath`: absolute and lexically normalised (`.` and `..` resolved
/// without touching the file system or following links).
fn full_path(path: &Path) -> Result<PathBuf, PackError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| PackError::Io(format!("current directory: {}", error.kind())))?
            .join(path)
    };
    let mut normalised = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other.as_os_str()),
        }
    }
    Ok(normalised)
}

/// Joins `relative` to `root`; fails when the result escapes the pack directory.
fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, PackError> {
    let full = full_path(&root.join(relative))?;
    if full == root || !full.starts_with(root) {
        return Err(invalid(format!(
            "Pack path escapes the pack directory: {relative}"
        )));
    }
    Ok(full)
}

/// `relative.Replace('\\', '/').TrimStart('.', '/')`.
fn normalise_relative(relative: &str) -> String {
    relative
        .replace('\\', "/")
        .trim_start_matches(['.', '/'])
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_relative_paths_like_csharp() {
        assert_eq!(normalise_relative("./policies/a.yaml"), "policies/a.yaml");
        assert_eq!(normalise_relative("policies\\a.yaml"), "policies/a.yaml");
        assert_eq!(normalise_relative(".hidden/a"), "hidden/a");
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let root = Path::new("/packs/demo");
        assert!(safe_join(root, "policies/a.yaml").is_ok());
        assert!(safe_join(root, "policies/../a.yaml").is_ok());
        assert!(safe_join(root, "../other/a.yaml").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, ".").is_err());
        assert!(safe_join(Path::new("/packs/demo"), "../demo2/a").is_err());
    }
}
