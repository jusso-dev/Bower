//! `bower archive create|verify|replay` and `bower sources check` (C#
//! `ArchiveCommands`, `SourceCommands`). Output is metadata only: counts, sequences,
//! hashes and states, never payloads.

use std::collections::BTreeMap;
use std::time::Duration;

use bower_contracts::time::{self, Timestamp};
use bower_contracts::{DurableEventStore, JsonElement, LedgerHead};
use bower_core::source_expectations;
use bower_persistence::{ArchiveVerification, QueueArchive};

use crate::cli::{ArchiveCreateArgs, ArchiveReplayArgs, ArchiveVerifyArgs, SourcesCheckArgs};
use crate::commands::queue::{open_existing, store_error};
use crate::commands::{block_on, timeout_message};
use crate::output::Json;
use crate::support::{CliError, CliResult, ensure_slash, required};

const REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

fn archive_error(error: bower_persistence::ArchiveError) -> CliError {
    CliError::from_display(error)
}

fn int(value: i64) -> Json {
    Json::Int(value)
}

/// `ArchiveVerifyOutput` (camelCase, C# record order).
fn verify_json(value: &ArchiveVerification) -> Json {
    Json::object([
        ("intact", Json::Bool(value.intact)),
        ("segments", int(i64::from(value.segments))),
        ("verifiedEvents", int(value.verified_events)),
        ("firstSequence", int(value.first_sequence)),
        ("headSequence", int(value.head_sequence)),
        ("headHash", Json::opt_str(value.head_hash.clone())),
        ("anchorVerified", Json::Bool(value.anchor_verified)),
        ("breakSegment", Json::opt_str(value.break_segment.clone())),
        ("breakReason", Json::opt_str(value.break_reason.clone())),
    ])
}

/// `bower archive create --archive DIR [--database FILE] [--collector-id ID]`.
pub fn create(args: &ArchiveCreateArgs) -> CliResult {
    let store = open_existing(&args.database)?;
    let directory = required(args.archive.as_deref(), "--archive")?;
    let collector_id = args
        .collector_id
        .clone()
        .unwrap_or_else(bower_collector::settings::machine_name);
    let archive = QueueArchive::new(directory, &collector_id, None).map_err(archive_error)?;
    let result = archive.archive(&store).map_err(archive_error)?;
    println!(
        "{}",
        Json::object([
            ("segments", int(i64::from(result.segments))),
            ("events", int(result.events)),
            ("headSequence", int(result.head_sequence)),
            ("headHash", Json::opt_str(result.head_hash)),
        ])
        .to_indented()
    );
    Ok(0)
}

/// `bower archive verify --archive DIR [--anchor SEQUENCE:HASH]`: exit 3 when broken.
pub fn verify(args: &ArchiveVerifyArgs) -> CliResult {
    let archive = QueueArchive::new(
        required(args.archive.as_deref(), "--archive")?,
        "verifier",
        None,
    )
    .map_err(archive_error)?;
    let anchor = parse_anchor(args.anchor.as_deref())?;
    let result = archive.verify(anchor.as_ref()).map_err(archive_error)?;
    println!("{}", verify_json(&result).to_indented());
    Ok(if result.intact { 0 } else { 3 })
}

/// C# `ArchiveCommands.ParseAnchor`: digits, a colon and 64 lower-case hex digits.
pub fn parse_anchor(value: Option<&str>) -> CliResult<Option<LedgerHead>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = value.split_once(':').and_then(|(sequence, hash)| {
        let digits = !sequence.is_empty() && sequence.bytes().all(|byte| byte.is_ascii_digit());
        let hex = hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let sequence = sequence.parse::<i64>().ok().filter(|_| digits)?;
        hex.then(|| LedgerHead {
            sequence,
            hash: hash.to_owned(),
        })
    });
    parsed
        .map(Some)
        .ok_or_else(|| CliError::new("--anchor must be SEQUENCE:HASH (64 lower-case hex digits)."))
}

/// `DateTimeOffset.Parse(value, InvariantCulture, AssumeUniversal | AdjustToUniversal)`
/// for ISO 8601 text. Other .NET-accepted shapes are refused (fail closed).
fn parse_time(value: Option<&str>) -> CliResult<Option<Timestamp>> {
    value
        .map(|text| {
            time::parse(text.trim()).map(time::to_utc).ok_or_else(|| {
                CliError(format!(
                    "The string '{text}' was not recognized as a valid DateTime. There is an unknown word starting at index '0'."
                ))
            })
        })
        .transpose()
}

fn is_stop(outcome: &str) -> bool {
    matches!(outcome, "unreachable" | "401" | "403" | "429") || outcome.starts_with('5')
}

/// `bower archive replay --archive DIR --collector-url URL [--from ISO] [--to ISO]
/// [--event-type TYPE]... [--dry-run]`: verifies the archive, then posts selected
/// events through a collector's full intake labelled `bowerReplay: archive`. Sends
/// `BOWER_INGEST_TOKEN` when set. Exit 3 when the archive fails verification, 2 when
/// the collector refused or was unreachable.
pub fn replay(args: &ArchiveReplayArgs) -> CliResult {
    let archive = QueueArchive::new(
        required(args.archive.as_deref(), "--archive")?,
        "replay",
        None,
    )
    .map_err(archive_error)?;
    let verification = archive.verify(None).map_err(archive_error)?;
    if !verification.intact {
        println!("{}", verify_json(&verification).to_indented());
        eprintln!("Archive failed verification; replay refused.");
        return Ok(3);
    }

    let from = parse_time(args.from.as_deref())?;
    let to = parse_time(args.to.as_deref())?;
    let dry_run = args.dry_run;
    let collector = required(args.collector_url.as_deref(), "--collector-url")?;
    let base = reqwest::Url::parse(&ensure_slash(collector)).map_err(|_| {
        CliError::new("Invalid URI: The format of the URI could not be determined.")
    })?;
    let endpoint = base.join("v1/events").map_err(CliError::from_display)?;
    let token = std::env::var("BOWER_INGEST_TOKEN")
        .ok()
        .filter(|value| !value.is_empty());
    let client = reqwest::Client::builder()
        .timeout(REPLAY_TIMEOUT)
        .build()
        .map_err(CliError::from_display)?;

    let events = archive.read_all().map_err(archive_error)?;
    let (selected, responses) = block_on(async {
        let mut responses: BTreeMap<String, i64> = BTreeMap::new();
        let mut selected = 0_i64;
        for item in events {
            let mut envelope = match JsonElement::parse(&item.payload) {
                Ok(JsonElement::Object(properties)) => properties,
                _ => {
                    return Err(CliError(format!(
                        "Archived event {} is not a JSON object.",
                        item.sequence
                    )));
                }
            };
            let text = |name: &str| {
                envelope
                    .iter()
                    .find(|(key, _)| key == name)
                    .and_then(|(_, value)| value.as_str())
                    .unwrap_or_default()
                    .to_owned()
            };
            let generated = time::parse(&text("timeGenerated")).ok_or_else(|| {
                CliError::new("String '' was not recognized as a valid DateTime.")
            })?;
            let event_type = text("eventType");
            if from.is_some_and(|from| generated < from)
                || to.is_some_and(|to| generated >= to)
                || (!args.event_types.is_empty() && !args.event_types.contains(&event_type))
            {
                continue;
            }
            selected += 1;
            if dry_run {
                continue;
            }

            // JsonObject: a duplicate top-level name cannot be materialised.
            let mut names = std::collections::HashSet::new();
            if !envelope.iter().all(|(key, _)| names.insert(key.clone())) {
                return Err(CliError(format!(
                    "Archived event {} has duplicate property names.",
                    item.sequence
                )));
            }
            let mut labels = match envelope.iter().position(|(key, _)| key == "labels") {
                Some(index) => match envelope.remove(index).1 {
                    JsonElement::Object(labels) => labels,
                    _ => Vec::new(),
                },
                None => Vec::new(),
            };
            match labels.iter_mut().find(|(key, _)| key == "bowerReplay") {
                Some(entry) => entry.1 = JsonElement::String("archive".into()),
                None => labels.push(("bowerReplay".into(), JsonElement::String("archive".into()))),
            }
            envelope.push(("labels".into(), JsonElement::Object(labels)));
            let body = bower_contracts::json::to_string(&JsonElement::Object(envelope))
                .map_err(CliError::from_display)?;

            let mut request = client
                .post(endpoint.clone())
                .header("content-type", "application/json; charset=utf-8")
                .body(body);
            if let Some(token) = &token {
                request = request.bearer_auth(token);
            }
            let outcome = match request.send().await {
                Ok(response) => response.status().as_u16().to_string(),
                Err(error) if error.is_timeout() => {
                    return Err(CliError(timeout_message(REPLAY_TIMEOUT)));
                }
                Err(_) => "unreachable".to_owned(),
            };
            *responses.entry(outcome.clone()).or_default() += 1;
            if is_stop(&outcome) {
                break;
            }
        }
        Ok((selected, responses))
    })?;

    let failed = responses.keys().any(|code| is_stop(code));
    println!(
        "{}",
        Json::object([
            ("selected", int(selected)),
            ("dryRun", Json::Bool(dry_run)),
            (
                "responses",
                Json::Object(
                    responses
                        .into_iter()
                        .map(|(code, count)| (code, int(count)))
                        .collect()
                ),
            ),
        ])
        .to_indented()
    );
    Ok(if failed { 2 } else { 0 })
}

/// `bower sources check --expectations FILE [--database FILE]`: offline silence check
/// from the activity the collector last persisted. Exit 3 when any expected source is
/// quiet. Offline there is no grace period: a source never seen is reported at once.
pub fn sources_check(args: &SourcesCheckArgs) -> CliResult {
    let expectations =
        source_expectations::load_file(required(args.expectations.as_deref(), "--expectations")?)
            .map_err(CliError::from_display)?;
    let store = open_existing(&args.database)?;
    let activity = store.get_source_activity().map_err(store_error)?;
    // DateTimeOffset.MinValue.
    let minimum = time::parse("0001-01-01T00:00:00+00:00").expect("minimum timestamp");
    let statuses =
        source_expectations::evaluate(&expectations, &activity, &[], minimum, time::now());
    let healthy = statuses.iter().all(|item| item.is_active());
    let sources = statuses
        .into_iter()
        .map(|item| {
            Json::object([
                ("application", Json::str(item.application)),
                ("environment", Json::str(item.environment)),
                ("state", Json::str(item.state)),
                (
                    "lastSeenAt",
                    item.last_seen_at.map_or(Json::Null, Json::Time),
                ),
                (
                    "silentSeconds",
                    if item.last_seen_at.is_some() {
                        int(item.silent_seconds)
                    } else {
                        Json::Null
                    },
                ),
                ("allowedSilenceSeconds", int(item.allowed_silence_seconds)),
            ])
        })
        .collect();
    println!(
        "{}",
        Json::object([
            ("healthy", Json::Bool(healthy)),
            ("sources", Json::Array(sources))
        ])
        .to_indented()
    );
    Ok(if healthy { 0 } else { 3 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_parse_like_csharp() {
        let hash = "a".repeat(64);
        let parsed = parse_anchor(Some(&format!("12:{hash}"))).unwrap().unwrap();
        assert_eq!((parsed.sequence, parsed.hash.as_str()), (12, hash.as_str()));
        assert!(parse_anchor(None).unwrap().is_none());
        for bad in [
            format!("+1:{hash}"),
            format!(" 1:{hash}"),
            format!("1:{}", "A".repeat(64)),
            format!("1:{}", "a".repeat(63)),
            format!(":{hash}"),
            "1".to_owned(),
            format!("99999999999999999999:{hash}"),
        ] {
            assert_eq!(
                parse_anchor(Some(&bad)).unwrap_err().to_string(),
                "--anchor must be SEQUENCE:HASH (64 lower-case hex digits).",
                "{bad}"
            );
        }
    }
}
