//! `PolicyBundle`: everything that decides what the collector accepts and how it
//! redacts. Policies from the policy directory and signed packs, plus the privacy
//! profile. Its hash is reported to management, which compares it with the desired
//! policy.

use std::collections::HashSet;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::app::{BundleInfo, PackSummary, PolicySummary};
use crate::error::HostError;
use crate::host::LoadedBundle;
use crate::settings::{CollectorSettings, read_all_text};

fn policy_error(error: bower_policy::PolicyError) -> HostError {
    use bower_policy::PolicyError;
    let kind = match &error {
        PolicyError::InvalidData(_) => "InvalidDataException",
        PolicyError::FileNotFound(_) => "FileNotFoundException",
        PolicyError::DirectoryNotFound(_) => "DirectoryNotFoundException",
        PolicyError::BlankDirectory => "ArgumentException",
        PolicyError::Io(_) => "IOException",
    };
    HostError::new(kind, error.to_string())
}

fn pack_error(error: bower_packs::PackError) -> HostError {
    use bower_packs::PackError;
    let kind = match &error {
        PackError::Verification(_) => "PackVerificationException",
        PackError::InvalidData(_) => "InvalidDataException",
        PackError::NotFound(_) => "FileNotFoundException",
        PackError::Io(_) => "IOException",
    };
    HostError::new(kind, error.to_string())
}

/// A pack loaded by `bower_packs::load` is always signed, so its manifest is present.
fn manifest(pack: &bower_packs::LoadedPack) -> &bower_packs::PackManifest {
    pack.manifest
        .as_ref()
        .expect("signed packs always carry a manifest")
}

pub fn load(settings: &CollectorSettings) -> Result<LoadedBundle, HostError> {
    load_inner(settings, || match &settings.privacy_hmac_key_file {
        Some(path) => bower_redaction::read_key_file(path)
            .map(Some)
            .map_err(|error| HostError::new(error.dotnet_type(), error.to_string())),
        None => Ok(None),
    })
}

/// [`load`] with the privacy HMAC key supplied by the host instead of
/// `privacy_hmac_key_file` (which is ignored). Used by hosts that fetch the key
/// with their own identity, such as the AWS Lambda host. Load order and error
/// precedence are unchanged.
pub fn load_with_key(
    settings: &CollectorSettings,
    key: Option<&[u8]>,
) -> Result<LoadedBundle, HostError> {
    load_inner(settings, || Ok(key.map(<[u8]>::to_vec)))
}

fn load_inner(
    settings: &CollectorSettings,
    read_key: impl FnOnce() -> Result<Option<Vec<u8>>, HostError>,
) -> Result<LoadedBundle, HostError> {
    let mut policies = Vec::new();
    if settings.policy_directory.is_dir() {
        policies.extend(
            bower_policy::load_directory(&settings.policy_directory).map_err(policy_error)?,
        );
    } else if settings.packs.is_empty() {
        return Err(HostError::new(
            "DirectoryNotFoundException",
            format!(
                "Policy directory does not exist: {}",
                settings.policy_directory.display()
            ),
        ));
    }

    let trusted = settings
        .pack_trusted_key_files
        .iter()
        .map(|path| read_all_text(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut packs = Vec::new();
    for path in &settings.packs {
        packs.push(bower_packs::load(std::path::Path::new(path), &trusted).map_err(pack_error)?);
    }
    let mut pack_ids = HashSet::new();
    let mut detection_ids = HashSet::new();
    let mut parser_count = 0;
    let mut detection_count = 0;
    for pack in &packs {
        parser_count += pack.parsers.len();
        detection_count += pack.detections.len();
        if !pack_ids.insert(manifest(pack).id.clone())
            || pack
                .detections
                .iter()
                .any(|rule| !detection_ids.insert(rule.id.to_lowercase()))
            || parser_count > 64
            || detection_count > 64
        {
            return Err(HostError::new(
                "InvalidDataException",
                "Duplicate pack/detection identity or runtime pack limit exceeded.",
            ));
        }
    }
    for pack in &packs {
        policies.extend(pack.policies.iter().cloned());
    }

    let mut seen = HashSet::new();
    if let Some(duplicate) = policies
        .iter()
        .map(|policy| policy.policy.metadata.id.as_str())
        .find(|id| !seen.insert(*id))
    {
        return Err(HostError::new(
            "InvalidDataException",
            format!(
                "Policy id '{duplicate}' is defined more than once across the directory and packs."
            ),
        ));
    }

    bower_policy::validate_set(&policies).map_err(policy_error)?;

    let profile_yaml = match &settings.privacy_profile_path {
        Some(path) => Some(read_all_text(&path.to_string_lossy())?),
        None => None,
    };
    let pack_profiles: Vec<&String> = packs
        .iter()
        .filter_map(|pack| pack.privacy_profile_yaml.as_ref())
        .collect();
    if pack_profiles.len() + usize::from(profile_yaml.is_some()) > 1 {
        return Err(HostError::new(
            "InvalidDataException",
            "Only one privacy profile may be active (BOWER_PRIVACY_PROFILE or one pack).",
        ));
    }
    if settings.uses_managed_privacy_profile() && !pack_profiles.is_empty() {
        return Err(HostError::new(
            "InvalidDataException",
            "BOWER_PRIVACY_PROFILE_SOURCE=management cannot be combined with pack privacy profiles.",
        ));
    }
    let profile_yaml = profile_yaml.or_else(|| pack_profiles.first().map(|yaml| (*yaml).clone()));
    let key = read_key()?;
    // Management mode: the verified cached envelope, read once so the ingest gate and the
    // active profile always agree. No cache or a cached explicit clear resolves to the
    // built-in default.
    let managed_privacy = if settings.uses_managed_privacy_profile() {
        crate::managed_privacy::load_verified(settings, key.as_deref())?
    } else {
        None
    };
    let profile = match &profile_yaml {
        _ if settings.uses_managed_privacy_profile() => managed_privacy
            .as_ref()
            .and_then(|verified| verified.profile.clone()),
        Some(yaml) => Some(
            bower_redaction::load_privacy_profile(
                yaml,
                key.as_deref(),
                Some(&settings.privacy_hmac_key_id),
            )
            .map_err(|error| HostError::new(error.dotnet_type(), error.to_string()))?,
        ),
        None => None,
    };
    let privacy = profile
        .as_ref()
        .map_or_else(bower_redaction::PrivacyPolicy::create_default, |profile| {
            profile.policy.clone()
        });

    let mut ordered: Vec<_> = policies.iter().collect();
    ordered.sort_by(|left, right| left.policy.metadata.id.cmp(&right.policy.metadata.id));
    let mut lines: Vec<String> = ordered
        .iter()
        .map(|policy| {
            format!(
                "{}@{}:{}",
                policy.policy.metadata.id, policy.policy.metadata.version, policy.hash
            )
        })
        .collect();
    lines.extend(packs.iter().map(|pack| {
        let manifest = manifest(pack);
        format!(
            "pack:{}@{}:{}",
            manifest.id, manifest.version, manifest.pack_hash
        )
    }));
    lines.push(format!(
        "privacy:{}",
        profile
            .as_ref()
            .map_or("default", |profile| profile.hash.as_str())
    ));
    let hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(lines.join("\n").as_bytes()))
    );

    let info = BundleInfo {
        hash,
        policies: policies
            .iter()
            .map(|policy| PolicySummary {
                id: policy.policy.metadata.id.clone(),
                version: policy.policy.metadata.version.clone(),
            })
            .collect(),
        packs: packs
            .iter()
            .map(|pack| PackSummary {
                id: manifest(pack).id.clone(),
                version: manifest(pack).version.clone(),
                pack_hash: manifest(pack).pack_hash.clone(),
                parser_statuses: pack
                    .parsers
                    .iter()
                    .map(|parser| bower_packs::runtime::parser_status(parser).into())
                    .collect(),
                detection_status: if pack.detections.is_empty() {
                    "absent"
                } else {
                    "active-local"
                }
                .into(),
                dcr_status: if pack.dcr_template_json.is_some() {
                    "packaged-only"
                } else {
                    "absent"
                }
                .into(),
            })
            .collect(),
        privacy_profile: profile.as_ref().and_then(|profile| profile.id.clone()),
        privacy_profile_version: profile.as_ref().and_then(|profile| profile.version.clone()),
        privacy_profile_hash: profile.as_ref().map(|profile| profile.hash.clone()),
        privacy_profile_source: settings.privacy_profile_source.clone(),
    };
    Ok(LoadedBundle {
        info,
        managed_privacy,
        packs,
        redactor: Arc::new(
            bower_redaction::JsonEventRedactor::with_policy(privacy)
                .map_err(|error| HostError::new(error.dotnet_type(), error.to_string()))?,
        ),
        evaluator: Arc::new(bower_policy::DeterministicPolicyEvaluator::new(policies)),
    })
}
