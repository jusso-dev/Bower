//! `bower privacy validate` (C# `PrivacyCommands.Validate`).

use std::path::Path;

use bower_redaction::{PrivacyEngine, load_privacy_profile};

use crate::cli::PrivacyValidateArgs;
use crate::output::Json;
use crate::support::{CliError, CliResult, read_bytes, read_text};

/// Key id used with the random key when no `--hmac-key-file` is given.
const VALIDATION_KEY_ID: &str = "validation";

fn count(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Loads the profile exactly as the collector does (running every custom detector's
/// tests) and prints a metadata-only summary, plus the redacted sample with
/// `--sample FILE`. Without `--hmac-key-file` a random key is used. Exit 1 when the
/// profile is invalid, 2 when the sample cannot be redacted.
pub fn validate(args: &PrivacyValidateArgs) -> CliResult {
    let Some(path) = args
        .file
        .as_deref()
        .filter(|path| !path.trim().is_empty() && Path::new(path).is_file())
    else {
        return Err(CliError::new(
            "Provide an existing privacy profile file: bower privacy validate FILE.",
        ));
    };

    let (key, key_id) = match args.hmac_key_file.as_deref() {
        Some(key_file) => {
            // .NET-style I/O messages ("Could not find file '...'.").
            read_bytes(key_file)?;
            (
                bower_redaction::read_key_file(key_file).map_err(CliError::from_display)?,
                None,
            )
        }
        None => {
            let mut key = vec![0u8; 32];
            getrandom::fill(&mut key).map_err(CliError::from_display)?;
            (key, Some(VALIDATION_KEY_ID))
        }
    };
    let yaml = read_text(path)?;
    let sample = args.sample.as_deref().map(read_text).transpose()?;
    let profile =
        load_privacy_profile(&yaml, Some(&key), key_id).map_err(CliError::from_display)?;
    let policy = &profile.policy;
    let mut fields = vec![
        ("valid", Json::Bool(true)),
        ("profileId", Json::opt_str(profile.id.clone())),
        ("version", Json::opt_str(profile.version.clone())),
        ("hash", Json::str(profile.hash.clone())),
        (
            "customDetectors",
            Json::Array(
                policy
                    .custom_detectors
                    .iter()
                    .map(|detector| {
                        Json::object([
                            ("id", Json::str(detector.id())),
                            ("action", Json::str(detector.action().name())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("secretFieldNames", count(policy.secret_field_names.len())),
        ("testsPassed", count(profile.custom_detector_tests)),
    ];

    let mut code = 0;
    if let Some(sample) = sample {
        let result = PrivacyEngine::new(profile.policy.clone())
            .map_err(CliError::from_display)?
            .redact_json(&sample);
        if !result.succeeded {
            code = 2;
        }
        fields.push((
            "sample",
            Json::object([
                ("succeeded", Json::Bool(result.succeeded)),
                ("failureCode", Json::opt_str(result.failure_code)),
                ("redacted", Json::opt_str(result.redacted_json)),
            ]),
        ));
    }

    println!("{}", Json::object(fields).to_indented());
    Ok(code)
}
