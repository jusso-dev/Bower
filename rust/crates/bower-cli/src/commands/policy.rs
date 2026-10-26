//! `bower policy test` (C# `PolicyCommands.TestAsync`): sample events through the
//! collector's intake (redaction, schema validation, default-deny policy, privacy
//! alerts) offline, printing a metadata-only decision per event. Nothing is
//! queued, sent or written.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bower_collector::CollectorSettings;
use bower_collector::app::MAXIMUM_PAYLOAD_BYTES;
use bower_collector::host::LoadedBundle;
use bower_contracts::time::{self, Clock, SystemClock, Timestamp};
use bower_contracts::{DecisionAction, EventRedactor, RedactionResult};
use bower_core::capture::CaptureStore;
use bower_core::{CollectorIdentity, ProcessingResult, ProcessingStage, SecurityEventProcessor};

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

    let bundle = load_bundle(&BundleSources {
        policy_directory: args
            .policy_directory
            .as_deref()
            .map_or_else(|| PathBuf::from("policies").join("default"), PathBuf::from),
        packs: args.packs.clone(),
        trusted_keys: args.trusted_keys.clone(),
        privacy_profile: args.privacy_profile.clone(),
        hmac_key_file: args.hmac_key_file.clone(),
        hmac_key_id: args.hmac_key_id.clone(),
    })?;

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

/// `PolicyBundleSources` as `policy test` and each side of the bundle comparison read it.
struct BundleSources {
    policy_directory: PathBuf,
    packs: Vec<String>,
    trusted_keys: Vec<String>,
    privacy_profile: Option<String>,
    hmac_key_file: Option<String>,
    hmac_key_id: Option<String>,
}

/// `PolicyBundle.Load`: the bundle exactly as the collector loads it.
fn load_bundle(sources: &BundleSources) -> CliResult<LoadedBundle> {
    let mut settings = CollectorSettings::new(
        "http://127.0.0.1:4319",
        std::env::temp_dir().join("bower-policy-test-unused.db"),
        sources.policy_directory.clone(),
        "bower-cli",
    );
    settings.packs = sources.packs.clone();
    settings.pack_trusted_key_files = sources.trusted_keys.clone();
    settings.privacy_profile_path = sources.privacy_profile.as_deref().map(PathBuf::from);
    settings.privacy_hmac_key_file = sources.hmac_key_file.as_deref().map(PathBuf::from);
    if let Some(key_id) = &sources.hmac_key_id {
        settings.privacy_hmac_key_id = key_id.clone();
    }
    bower_collector::bundle::load(&settings).map_err(|error| CliError::new(error.message))
}

/// Observes the redaction the processor runs (C# `RecordingRedactor`); never alters it.
struct RecordingRedactor {
    inner: Arc<dyn EventRedactor>,
    result: Mutex<Option<RedactionResult>>,
}

impl EventRedactor for RecordingRedactor {
    fn redact(&self, json: &str) -> RedactionResult {
        let result = self.inner.redact(json);
        if let Ok(mut recorded) = self.result.lock() {
            *recorded = Some(result.clone());
        }
        result
    }
}

/// Each event runs alone (its own capture store), as its own `/v1/events` request
/// would, so one sample never deduplicates against another. Returns each result with
/// the one redaction the processor ran (`None` when the redactor panicked).
fn process_each(
    bundle: &LoadedBundle,
    events: &[(String, String)],
    clock: Arc<dyn Clock>,
) -> Vec<(ProcessingResult, Option<RedactionResult>)> {
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
            let recording = Arc::new(RecordingRedactor {
                inner: Arc::clone(&redactor),
                result: Mutex::new(None),
            });
            let processor = SecurityEventProcessor::new(
                Arc::clone(&recording) as Arc<dyn EventRedactor>,
                Arc::clone(&bundle.evaluator),
                Arc::new(CaptureStore::default()),
                Arc::clone(&clock),
            );
            let result = processor.process(json, &identity).unwrap_or_else(|_| {
                ProcessingResult::failed(DecisionAction::Quarantine, "processing-failed")
            });
            let redaction = recording
                .result
                .lock()
                .ok()
                .and_then(|mut recorded| recorded.take());
            (result, redaction)
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
    for ((file, _), (result, _)) in events.iter().zip(process_each(bundle, events, clock)) {
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
/// changes. Exit 3 with `--fail-on-change` when any changes. Any [`BUNDLE_OPTIONS`]
/// option (or `--at`) selects the bundle comparison: each side is a full trusted
/// bundle and every sample runs at one fixed time. Both bundles load, and every
/// pack's signature is checked, before any sample is evaluated; a load failure is
/// exit 1 with nothing printed.
pub fn diff(args: &PolicyDiffArgs) -> CliResult {
    if args.files.is_empty() || args.files.len() > MAXIMUM_EVENT_FILES {
        return Err(CliError::new(format!(
            "Provide 1-{MAXIMUM_EVENT_FILES} event files: bower policy diff --baseline DIR --candidate DIR EVENT.json [EVENT.json ...]."
        )));
    }
    let events = read_events(&args.files)?;
    if args.bundle {
        let at = match parse_at(args)? {
            Some(at) => at,
            None => time::now(),
        };
        let baseline = load_bundle(&side_sources(
            "baseline",
            args.baseline.as_deref(),
            &args.baseline_packs,
            &args.baseline_trusted_keys,
            args.baseline_privacy_profile.as_deref(),
            args.baseline_hmac_key_file.as_deref(),
            args.baseline_hmac_key_id.as_deref(),
        )?)?;
        let candidate = load_bundle(&side_sources(
            "candidate",
            args.candidate.as_deref(),
            &args.candidate_packs,
            &args.candidate_trusted_keys,
            args.candidate_privacy_profile.as_deref(),
            args.candidate_hmac_key_file.as_deref(),
            args.candidate_hmac_key_id.as_deref(),
        )?)?;
        let (output, changed) = compute_bundle_diff(&baseline, &candidate, &events, at);
        println!("{}", output.to_indented());
        return Ok(if changed > 0 && args.fail_on_change {
            3
        } else {
            0
        });
    }
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
    let results = |bundle, clock| -> Vec<ProcessingResult> {
        process_each(bundle, events, clock)
            .into_iter()
            .map(|(result, _)| result)
            .collect()
    };
    let before = results(baseline, Arc::clone(&clock));
    let after = results(candidate, clock);
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

/// Per-side suffixes of the `policy test` bundle options (C# `PolicyCommands.BundleOptions`).
pub const BUNDLE_OPTIONS: [&str; 5] = [
    "pack",
    "trusted-key",
    "privacy-profile",
    "hmac-key-file",
    "hmac-key-id",
];

/// Stateful behaviour a single offline request per sample cannot show
/// (C# `PolicyCommands.NotExercisedOffline`).
const NOT_EXERCISED_OFFLINE: [&str; 7] = [
    "suppression-windows",
    "source-silence",
    "cross-event-deduplication",
    "queue-capacity-and-backpressure",
    "delivery-and-destination-validation",
    "pack-parsers",
    "management-privacy-assignment",
];

/// C# `ParseAt`: `--at` as UTC; `None` when absent. ISO 8601 only: other shapes
/// `DateTimeOffset.TryParse` accepts are refused here (fail closed).
fn parse_at(args: &PolicyDiffArgs) -> CliResult<Option<Timestamp>> {
    if !args.at_given {
        return Ok(None);
    }
    args.at
        .as_deref()
        .and_then(|text| time::parse(text.trim()))
        .map(|at| Some(time::to_utc(at)))
        .ok_or_else(|| CliError::new("--at must be an ISO 8601 timestamp."))
}

/// C# `BundleSources`: one side of the bundle comparison.
fn side_sources(
    side: &str,
    directory: Option<&str>,
    packs: &[String],
    trusted_keys: &[String],
    privacy_profile: Option<&str>,
    hmac_key_file: Option<&str>,
    hmac_key_id: Option<&str>,
) -> CliResult<BundleSources> {
    if directory.is_none() && packs.is_empty() {
        return Err(CliError::new(format!(
            "--{side} or --{side}-pack is required."
        )));
    }
    Ok(BundleSources {
        // No directory: the bundle is the packs alone (a missing directory is skipped
        // when packs are given).
        policy_directory: PathBuf::from(directory.unwrap_or_default()),
        packs: packs.to_vec(),
        trusted_keys: trusted_keys.to_vec(),
        privacy_profile: privacy_profile.map(str::to_owned),
        hmac_key_file: hmac_key_file.map(str::to_owned),
        hmac_key_id: hmac_key_id.map(str::to_owned),
    })
}

/// C# `PolicyBundleOutcome`: one fixture's intake outcome under one bundle.
struct BundleOutcome {
    decision: String,
    policy_id: Option<String>,
    accepted: bool,
    failure_stage: Option<&'static str>,
    failure_reasons: Vec<String>,
    privacy_actions: Vec<(String, String)>,
    privacy_alert: bool,
    detections: Vec<String>,
}

fn stage_name(stage: ProcessingStage) -> &'static str {
    match stage {
        ProcessingStage::Redaction => "redaction",
        ProcessingStage::Schema => "schema",
        ProcessingStage::Validation => "validation",
        ProcessingStage::Policy => "policy",
    }
}

/// Rule ids of the evidence the pack detection redactor attached (never matched values).
fn detection_rule_ids(redaction: Option<&RedactionResult>) -> Vec<String> {
    let Some(text) = redaction
        .filter(|redaction| redaction.succeeded)
        .and_then(|redaction| redaction.redacted_json.as_deref())
    else {
        return Vec::new();
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    document["attributes"]["bowerDetections"]
        .as_array()
        .map(|evidence| {
            evidence
                .iter()
                .map(|item| item["ruleId"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn bundle_outcome(
    (result, redaction): &(ProcessingResult, Option<RedactionResult>),
) -> BundleOutcome {
    let accepted = matches!(
        result.action,
        DecisionAction::Accept | DecisionAction::RedactAndAccept
    );
    let mut privacy_actions: Vec<(String, String)> = redaction
        .as_ref()
        .and_then(|redaction| redaction.privacy_actions.as_ref())
        .map(|actions| {
            actions
                .iter()
                .map(|(detector, action)| (detector.clone(), action.clone()))
                .collect()
        })
        .unwrap_or_default();
    privacy_actions.sort_by(|left, right| left.0.cmp(&right.0));
    BundleOutcome {
        decision: decision_name(result.action),
        policy_id: result
            .policy_decision
            .as_ref()
            .map(|decision| decision.policy_id.clone()),
        accepted,
        failure_stage: (!accepted).then(|| stage_name(result.stage)),
        failure_reasons: if accepted {
            Vec::new()
        } else {
            result.reasons.clone()
        },
        privacy_actions,
        privacy_alert: result.privacy_alert_event_id.is_some(),
        // Detection evidence only travels with an accepted event.
        detections: if accepted {
            detection_rule_ids(redaction.as_ref())
        } else {
            Vec::new()
        },
    }
}

fn changed_fields(old: &BundleOutcome, new: &BundleOutcome) -> Vec<&'static str> {
    [
        ("decision", old.decision == new.decision),
        ("policyId", old.policy_id == new.policy_id),
        ("accepted", old.accepted == new.accepted),
        ("failureStage", old.failure_stage == new.failure_stage),
        ("failureReasons", old.failure_reasons == new.failure_reasons),
        ("privacyActions", old.privacy_actions == new.privacy_actions),
        ("privacyAlert", old.privacy_alert == new.privacy_alert),
        ("detections", old.detections == new.detections),
    ]
    .into_iter()
    .filter(|(_, same)| !same)
    .map(|(name, _)| name)
    .collect()
}

fn outcome_json(outcome: &BundleOutcome) -> Json {
    let strings = |values: &[String]| Json::Array(values.iter().cloned().map(Json::str).collect());
    Json::object([
        ("decision", Json::str(outcome.decision.clone())),
        ("policyId", Json::opt_str(outcome.policy_id.clone())),
        ("accepted", Json::Bool(outcome.accepted)),
        ("failureStage", Json::opt_str(outcome.failure_stage)),
        ("failureReasons", strings(&outcome.failure_reasons)),
        (
            "privacyActions",
            Json::Array(
                outcome
                    .privacy_actions
                    .iter()
                    .map(|(detector, action)| {
                        Json::object([
                            ("detector", Json::str(detector.clone())),
                            ("action", Json::str(action.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("privacyAlert", Json::Bool(outcome.privacy_alert)),
        ("detections", strings(&outcome.detections)),
    ])
}

fn count(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// C# `Provenance`: hashes and identities of what was compared.
fn provenance(bundle: &LoadedBundle) -> Json {
    let info = &bundle.info;
    Json::object([
        ("bundleHash", Json::str(info.hash.clone())),
        ("policyCount", count(info.policies.len())),
        (
            "packs",
            Json::Array(
                info.packs
                    .iter()
                    .map(|pack| {
                        Json::object([
                            ("id", Json::str(pack.id.clone())),
                            ("version", Json::str(pack.version.clone())),
                            ("packHash", Json::str(pack.pack_hash.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "privacyProfile",
            info.privacy_profile.as_ref().map_or(Json::Null, |id| {
                Json::object([
                    ("id", Json::str(id.clone())),
                    (
                        "version",
                        Json::opt_str(info.privacy_profile_version.clone()),
                    ),
                    ("hash", Json::opt_str(info.privacy_profile_hash.clone())),
                ])
            }),
        ),
        (
            "detectionRules",
            count(bundle.packs.iter().map(|pack| pack.detections.len()).sum()),
        ),
    ])
}

/// Bundle comparison of `events` at one fixed time (C# `ComputeBundleDiffAsync`):
/// the `PolicyBundleDiffOutput` document and the number of changed events.
pub fn compute_bundle_diff(
    baseline: &LoadedBundle,
    candidate: &LoadedBundle,
    events: &[(String, String)],
    at: Timestamp,
) -> (Json, usize) {
    let clock: Arc<dyn Clock> = Arc::new(move || at);
    let before = process_each(baseline, events, Arc::clone(&clock));
    let after = process_each(candidate, events, clock);
    let mut changes = Vec::new();
    for (((file, _), old), new) in events.iter().zip(&before).zip(&after) {
        let (previous, updated) = (bundle_outcome(old), bundle_outcome(new));
        let fields = changed_fields(&previous, &updated);
        if !fields.is_empty() {
            changes.push(Json::object([
                ("file", Json::str(file.clone())),
                (
                    "eventId",
                    Json::opt_str(new.0.event_id.clone().or_else(|| old.0.event_id.clone())),
                ),
                ("baseline", outcome_json(&previous)),
                ("candidate", outcome_json(&updated)),
                (
                    "changedFields",
                    Json::Array(fields.into_iter().map(Json::str).collect()),
                ),
            ]));
        }
    }
    let changed = changes.len();
    let output = Json::object([
        ("baselineBundleHash", Json::str(baseline.info.hash.clone())),
        (
            "candidateBundleHash",
            Json::str(candidate.info.hash.clone()),
        ),
        ("events", count(events.len())),
        ("changed", count(changed)),
        ("changes", Json::Array(changes)),
        ("evaluatedAt", Json::Time(at)),
        ("baselineBundle", provenance(baseline)),
        ("candidateBundle", provenance(candidate)),
        (
            "notExercisedOffline",
            Json::Array(NOT_EXERCISED_OFFLINE.into_iter().map(Json::str).collect()),
        ),
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
