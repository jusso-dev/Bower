//! `bower pack build|verify|inspect|test|diff` (C# `PackCommands`).

use std::path::Path;

use bower_packs::{LoadedPack, PackError, PackManifest, PackSampleResult, PolicyChange};

use crate::cli::{PackBuildArgs, PackDiffArgs, PackFileArgs, PackTestArgs};
use crate::commands::doctor::load_profile;
use crate::output::{Json, pad};
use crate::support::{CliError, CliResult, read_all, read_text, required};

pub fn pack_error(error: PackError) -> CliError {
    CliError::from_display(error)
}

/// `TrustedKeys`: reads every `--trusted-key` file; at least one is required.
fn trusted_keys(paths: &[String]) -> CliResult<Vec<String>> {
    let keys = read_all(paths)?;
    if keys.is_empty() {
        return Err(CliError::new(
            "Provide at least one --trusted-key PUBLIC.pem.",
        ));
    }
    Ok(keys)
}

/// The manifest of a verified pack (always present after `load`).
pub fn manifest(pack: &LoadedPack) -> CliResult<&PackManifest> {
    pack.manifest
        .as_ref()
        .ok_or_else(|| CliError::new("Pack manifest is unreadable."))
}

fn load(args: &PackFileArgs) -> CliResult<LoadedPack> {
    let file = args
        .file
        .as_deref()
        .ok_or_else(|| CliError::new("Provide a .bowerpack file."))?;
    let keys = trusted_keys(&args.trusted_keys)?;
    bower_packs::load(Path::new(file), &keys).map_err(pack_error)
}

/// `bower pack build DIR --key PRIVATE.pem [--out DIR]` (default `artifacts/packs`).
pub fn build(args: &PackBuildArgs) -> CliResult {
    let source = args
        .source
        .as_deref()
        .ok_or_else(|| CliError::new("Provide the pack source directory."))?;
    let key = read_text(required(args.key.as_deref(), "--key")?)?;
    let out = args.out.as_deref().unwrap_or("artifacts/packs");
    let output =
        bower_packs::build(Path::new(source), &key, Path::new(out), None).map_err(pack_error)?;
    println!("Built and signed {}", output.display());
    Ok(0)
}

/// `bower pack verify FILE --trusted-key PUBLIC.pem [--trusted-key ...]`.
pub fn verify(args: &PackFileArgs) -> CliResult {
    let pack = load(args)?;
    println!("{}", verify_line(manifest(&pack)?, &pack.signed_by_key_id));
    Ok(0)
}

pub fn verify_line(manifest: &PackManifest, key_id: &str) -> String {
    format!(
        "Verified {}@{} signed by key {key_id}; {} files, pack hash {}.",
        manifest.id,
        manifest.version,
        manifest.files.len(),
        manifest.pack_hash
    )
}

/// `bower pack inspect FILE --trusted-key PUBLIC.pem`: metadata as JSON.
pub fn inspect(args: &PackFileArgs) -> CliResult {
    let pack = load(args)?;
    println!("{}", inspect_json(&pack)?.to_indented());
    Ok(0)
}

fn count(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// The C# anonymous object: member names as written (`Id`, `PackHash`, ...), manifest
/// policy entries with their `[JsonPropertyName]` names.
pub fn inspect_json(pack: &LoadedPack) -> CliResult<Json> {
    let manifest = manifest(pack)?;
    let policies = manifest
        .policies
        .iter()
        .map(|policy| {
            Json::object([
                ("id", Json::str(policy.id.clone())),
                ("version", Json::str(policy.version.clone())),
                ("hash", Json::str(policy.hash.clone())),
                (
                    "eventTypes",
                    Json::Array(policy.event_types.iter().cloned().map(Json::Str).collect()),
                ),
            ])
        })
        .collect();
    let files = manifest
        .files
        .iter()
        .map(|file| {
            Json::object([
                ("Path", Json::str(file.path.clone())),
                ("Role", Json::str(file.role.clone())),
                ("Bytes", Json::Int(file.bytes)),
            ])
        })
        .collect();
    Ok(Json::object([
        ("Id", Json::str(manifest.id.clone())),
        ("Version", Json::str(manifest.version.clone())),
        ("Name", Json::str(manifest.name.clone())),
        ("Owner", Json::str(manifest.owner.clone())),
        ("signedBy", Json::str(pack.signed_by_key_id.clone())),
        ("PackHash", Json::str(manifest.pack_hash.clone())),
        ("policies", Json::Array(policies)),
        ("files", Json::Array(files)),
        ("detections", count(pack.detections.len())),
        ("parsers", count(pack.parsers.len())),
        ("samples", count(pack.sample_lines.len())),
        (
            "privacyProfile",
            Json::Bool(pack.privacy_profile_yaml.is_some()),
        ),
        ("dcrTemplate", Json::Bool(pack.dcr_template_json.is_some())),
    ]))
}

/// `bower pack test FILE --trusted-key PUBLIC.pem [--hmac-key-file FILE]`.
/// Exit 1 when any sample fails.
pub fn test(args: &PackTestArgs) -> CliResult {
    let pack = load(&args.pack)?;
    let privacy = match (&args.hmac_key_file, &pack.privacy_profile_yaml) {
        (Some(key_file), Some(yaml)) => {
            load_profile(yaml, Some(key_file)).map_err(CliError::from_display)?
        }
        _ => bower_packs::test_privacy_policy(pack.privacy_profile_yaml.as_deref())
            .map_err(pack_error)?,
    };
    let results = bower_packs::run_samples(&pack, privacy, None).map_err(pack_error)?;
    for line in test_lines(&results) {
        println!("{line}");
    }
    Ok(if results.iter().all(|result| result.passed) {
        0
    } else {
        1
    })
}

pub fn test_lines(results: &[PackSampleResult]) -> Vec<String> {
    let mut lines = Vec::new();
    for result in results {
        lines.push(format!(
            "{} {} (expected {}, got {})",
            pad(if result.passed { "PASS" } else { "FAIL" }, 5),
            result.name,
            result.expected_decision,
            result.actual_decision
        ));
        for problem in &result.problems {
            lines.push(format!("      {problem}"));
        }
    }
    lines
}

/// `bower pack diff OLD.bowerpack NEW.bowerpack --trusted-key PUBLIC.pem`: policy
/// population diff. Exit 1 when a changed policy kept its version.
pub fn diff(args: &PackDiffArgs) -> CliResult {
    let [old, new] = args.files.as_slice() else {
        return Err(CliError::new("Provide two .bowerpack files: old then new."));
    };
    let trusted = trusted_keys(&args.trusted_keys)?;
    let before = bower_packs::load(Path::new(old), &trusted).map_err(pack_error)?;
    let after = bower_packs::load(Path::new(new), &trusted).map_err(pack_error)?;
    let changes = bower_packs::compare(&before, &after).map_err(pack_error)?;
    for line in diff_lines(manifest(&before)?, manifest(&after)?, &changes) {
        println!("{line}");
    }
    Ok(
        if changes
            .iter()
            .any(|change| change.change == "version-not-bumped")
        {
            1
        } else {
            0
        },
    )
}

pub fn diff_lines(
    before: &PackManifest,
    after: &PackManifest,
    changes: &[PolicyChange],
) -> Vec<String> {
    let mut lines = vec![format!(
        "{} {} -> {}",
        before.id, before.version, after.version
    )];
    for change in changes {
        lines.push(format!(
            "  {} {} {}",
            pad(&change.policy_id, 28),
            pad(&change.change, 24),
            change.detail
        ));
    }
    if changes.is_empty() {
        lines.push("  No policy population changes.".to_owned());
    }
    lines
}
