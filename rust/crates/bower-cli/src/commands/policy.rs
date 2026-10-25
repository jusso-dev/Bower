//! `bower policy test` (C# `PolicyCommands.TestAsync`): sample events through the
//! collector's intake (redaction, schema validation, default-deny policy, privacy
//! alerts) offline, printing a metadata-only decision per event. Nothing is
//! queued, sent or written.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bower_collector::CollectorSettings;
use bower_collector::app::MAXIMUM_PAYLOAD_BYTES;
use bower_collector::host::LoadedBundle;
use bower_contracts::time::{Clock, SystemClock};
use bower_contracts::{DecisionAction, EventRedactor};
use bower_core::capture::CaptureStore;
use bower_core::{CollectorIdentity, ProcessingResult, SecurityEventProcessor};

use crate::cli::{PolicyDiffArgs, PolicyTestArgs};
use crate::output::Json;
use crate::support::{CliError, CliResult, read_text, required};

pub const MAXIMUM_EVENT_FILES: usize = 1_000;

const DECISIONS: [DecisionAction; 7] = [
    DecisionAction::Accept,
    DecisionAction::Reject,
    DecisionAction::Sample,
    DecisionAction::Aggregate,
    DecisionAction::RedactAndAccept,
    DecisionAction::Quarantine,
    DecisionAction::DeadLetter,
];

/// `DecisionAction.ToString().ToLowerInvariant()`.
fn decision_name(action: DecisionAction) -> String {
    action.pascal_name().to_lowercase()
}

/// `--expect`: a decision name, case-insensitive, `-` ignored (letters only).
fn parse_expect(value: &str) -> Option<String> {
    let name = value.replace('-', "");
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    DECISIONS
        .into_iter()
        .map(decision_name)
        .find(|decision| decision.eq_ignore_ascii_case(&name))
}

/// Loads the bundle exactly as the collector does (policy directory, signed packs,
/// privacy profile). Exit 1 when the bundle or an event file cannot be read, 3 when
/// `--expect DECISION` is given and any event's decision differs.
pub fn test(args: &PolicyTestArgs) -> CliResult {
    if args.files.is_empty() || args.files.len() > MAXIMUM_EVENT_FILES {
        return Err(CliError::new(format!(
            "Provide 1-{MAXIMUM_EVENT_FILES} event files: bower policy test EVENT.json [EVENT.json ...]."
        )));
    }
    let expect = match args.expect.as_deref() {
        Some(value) => Some(parse_expect(value).ok_or_else(|| {
            CliError::new(
                "--expect must be a decision: accept, redact-and-accept, reject, quarantine, sample, aggregate or dead-letter.",
            )
        })?),
        None => None,
    };

    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        std::env::temp_dir().join("bower-policy-test-unused.db"),
        args.policy_directory
            .as_deref()
            .map_or_else(|| PathBuf::from("policies").join("default"), PathBuf::from),
        "bower-cli",
    );
    settings.packs = args.packs.clone();
    settings.pack_trusted_key_files = args.trusted_keys.clone();
    settings.privacy_profile_path = args.privacy_profile.as_deref().map(PathBuf::from);
    settings.privacy_hmac_key_file = args.hmac_key_file.as_deref().map(PathBuf::from);
    if let Some(key_id) = &args.hmac_key_id {
        settings.privacy_hmac_key_id = key_id.clone();
    }
    let bundle =
        bower_collector::bundle::load(&settings).map_err(|error| CliError::new(error.message))?;

    let mut events = Vec::with_capacity(args.files.len());
    for file in &args.files {
        let path = Path::new(file);
        if !path.is_file() {
            return Err(CliError::new(format!("Event file not found: {file}")));
        }
        let length = std::fs::metadata(path)
            .map_err(CliError::from_display)?
            .len();
        if length > MAXIMUM_PAYLOAD_BYTES as u64 {
            return Err(CliError::new(format!(
                "Event file exceeds {MAXIMUM_PAYLOAD_BYTES} bytes: {file}"
            )));
        }
        events.push((file.clone(), read_text(file)?));
    }

    let (output, decisions) = evaluate(&bundle, &events, Arc::new(SystemClock));
    println!("{}", output.to_indented());
    let mismatch =
        expect.is_some_and(|expect| decisions.iter().any(|decision| *decision != expect));
    Ok(if mismatch { 3 } else { 0 })
}

/// Each event runs alone (its own capture store), as its own `/v1/events` request
/// would, so one sample never deduplicates against another.
fn process_each(
    bundle: &LoadedBundle,
    events: &[(String, String)],
    clock: Arc<dyn Clock>,
) -> Vec<ProcessingResult> {
    // Same redaction path as the collector and serverless hosts.
    let redactor: Arc<dyn EventRedactor> = Arc::new(bower_packs::runtime::PackDetectionRedactor {
        inner: Arc::clone(&bundle.redactor),
        evaluator: Arc::clone(&bundle.evaluator),
        rules: bundle
            .packs
            .iter()
            .flat_map(|pack| pack.detections.iter().cloned())
            .collect(),
    });
    let identity = CollectorIdentity::new("bower-cli", "0.1.0", "policy-test", "policy-test");
    events
        .iter()
        .map(|(_, json)| {
            let processor = SecurityEventProcessor::new(
                Arc::clone(&redactor),
                Arc::clone(&bundle.evaluator),
                Arc::new(CaptureStore::default()),
                Arc::clone(&clock),
            );
            processor.process(json, &identity).unwrap_or_else(|_| {
                ProcessingResult::failed(DecisionAction::Quarantine, "processing-failed")
            })
        })
        .collect()
}

/// Returns the `policy test` output document and the decision per event.
pub fn evaluate(
    bundle: &LoadedBundle,
    events: &[(String, String)],
    clock: Arc<dyn Clock>,
) -> (Json, Vec<String>) {
    let mut results = Vec::with_capacity(events.len());
    let mut decisions = Vec::with_capacity(events.len());
    for ((file, _), result) in events.iter().zip(process_each(bundle, events, clock)) {
        let decision = decision_name(result.action);
        decisions.push(decision.clone());
        results.push(Json::object([
            ("file", Json::str(file.clone())),
            ("eventId", Json::opt_str(result.event_id)),
            ("decision", Json::str(decision)),
            ("wouldQueue", Json::Bool(result.queued)),
            (
                "privacyAlert",
                Json::Bool(result.privacy_alert_event_id.is_some()),
            ),
            (
                "reasons",
                Json::Array(result.reasons.into_iter().map(Json::str).collect()),
            ),
            (
                "policy",
                result.policy_decision.map_or(Json::Null, |policy| {
                    Json::object([
                        ("policyId", Json::str(policy.policy_id)),
                        ("policyVersion", Json::str(policy.policy_version)),
                        ("policyHash", Json::str(policy.policy_hash)),
                        ("score", Json::Int(i64::from(policy.score))),
                    ])
                }),
            ),
        ]));
    }
    let output = Json::object([
        ("bundleHash", Json::str(bundle.info.hash.clone())),
        (
            "policyCount",
            Json::Int(i64::try_from(bundle.info.policies.len()).unwrap_or(i64::MAX)),
        ),
        ("results", Json::Array(results)),
    ]);
    (output, decisions)
}

/// Reads event files like C# `DiffAsync`/`TestAsync`: each must exist and be at
/// most [`MAXIMUM_PAYLOAD_BYTES`].
fn read_events(files: &[String]) -> CliResult<Vec<(String, String)>> {
    let mut events = Vec::with_capacity(files.len());
    for file in files {
        let path = Path::new(file);
        if !path.is_file() {
            return Err(CliError::new(format!("Event file not found: {file}")));
        }
        let length = std::fs::metadata(path)
            .map_err(CliError::from_display)?
            .len();
        if length > MAXIMUM_PAYLOAD_BYTES as u64 {
            return Err(CliError::new(format!(
                "Event file exceeds {MAXIMUM_PAYLOAD_BYTES} bytes: {file}"
            )));
        }
        events.push((file.clone(), read_text(file)?));
    }
    Ok(events)
}

/// `PolicyBundle.Load(new PolicyBundleSources { PolicyDirectory = directory })`.
pub fn load_directory_bundle(directory: &str) -> CliResult<LoadedBundle> {
    let settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        std::env::temp_dir().join("bower-policy-test-unused.db"),
        PathBuf::from(directory),
        "bower-cli",
    );
    bower_collector::bundle::load(&settings).map_err(|error| CliError::new(error.message))
}

/// `bower policy diff --baseline DIR --candidate DIR EVENT.json... [--fail-on-change]`
/// (C# `PolicyCommands.DiffAsync`): population diff. Runs every sample through both
/// policy directories and lists each event whose decision or deciding policy
/// changes. Exit 3 with `--fail-on-change` when any changes.
pub fn diff(args: &PolicyDiffArgs) -> CliResult {
    if args.files.is_empty() || args.files.len() > MAXIMUM_EVENT_FILES {
        return Err(CliError::new(format!(
            "Provide 1-{MAXIMUM_EVENT_FILES} event files: bower policy diff --baseline DIR --candidate DIR EVENT.json [EVENT.json ...]."
        )));
    }
    let events = read_events(&args.files)?;
    let baseline = load_directory_bundle(required(args.baseline.as_deref(), "--baseline")?)?;
    let candidate = load_directory_bundle(required(args.candidate.as_deref(), "--candidate")?)?;
    let (output, changed) = compute_diff(&baseline, &candidate, &events, Arc::new(SystemClock));
    println!("{}", output.to_indented());
    Ok(if changed > 0 && args.fail_on_change {
        3
    } else {
        0
    })
}

/// Population diff of `events` between two loaded bundles (C# `ComputeDiffAsync`):
/// the `PolicyDiffOutput` document and the number of changed events.
pub fn compute_diff(
    baseline: &LoadedBundle,
    candidate: &LoadedBundle,
    events: &[(String, String)],
    clock: Arc<dyn Clock>,
) -> (Json, usize) {
    let before = process_each(baseline, events, Arc::clone(&clock));
    let after = process_each(candidate, events, clock);
    let outcome = |result: &ProcessingResult| {
        (
            decision_name(result.action),
            result
                .policy_decision
                .as_ref()
                .map(|decision| decision.policy_id.clone()),
        )
    };
    let outcome_json = |(decision, policy_id): (String, Option<String>)| {
        Json::object([
            ("decision", Json::str(decision)),
            ("policyId", Json::opt_str(policy_id)),
        ])
    };
    let mut changes = Vec::new();
    for (((file, _), old), new) in events.iter().zip(&before).zip(&after) {
        let (previous, updated) = (outcome(old), outcome(new));
        if previous != updated {
            changes.push(Json::object([
                ("file", Json::str(file.clone())),
                (
                    "eventId",
                    Json::opt_str(new.event_id.clone().or_else(|| old.event_id.clone())),
                ),
                ("baseline", outcome_json(previous)),
                ("candidate", outcome_json(updated)),
            ]));
        }
    }
    let changed = changes.len();
    let count = |value: usize| Json::Int(i64::try_from(value).unwrap_or(i64::MAX));
    let output = Json::object([
        ("baselineBundleHash", Json::str(baseline.info.hash.clone())),
        (
            "candidateBundleHash",
            Json::str(candidate.info.hash.clone()),
        ),
        ("events", count(events.len())),
        ("changed", count(changed)),
        ("changes", Json::Array(changes)),
    ]);
    (output, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expect_accepts_decision_names_only() {
        assert_eq!(
            parse_expect("redact-and-accept").as_deref(),
            Some("redactandaccept")
        );
        assert_eq!(parse_expect("Reject").as_deref(), Some("reject"));
        assert_eq!(parse_expect("dead-letter").as_deref(), Some("deadletter"));
        assert!(parse_expect("1").is_none());
        assert!(parse_expect("").is_none());
        assert!(parse_expect("allow").is_none());
    }
}
