//! `bower doctor` (C# `DoctorCommand`): checks a deployment for problems Azure
//! would otherwise handle silently (truncation, dropped rows, schema drift,
//! out-of-region data) and for local misconfiguration. Exit 1 when any check fails.

use std::path::Path;
use std::time::Duration;

use bower_contracts::types::{event_categories, event_types};
use bower_contracts::{
    ActorContext, ApplicationContext, CURRENT_SCHEMA_VERSION, DurableEventStore, EventResult,
    EventSeverity, RequestContext, SecurityEventEnvelope, SourceContext,
};
use bower_dcr::drift::{compare_rule, compare_table_default, lint_schema};
use bower_dcr::{DcrFinding, FindingLevel, SentinelSchema};
use bower_redaction::{PrivacyEngine, PrivacyError, PrivacyPolicy};

use crate::cli::DoctorArgs;
use crate::commands::azure::ArmSession;
use crate::commands::content::{self, ContentError};
use crate::commands::queue::{open_store, store_error};
use crate::output::{Json, pad};
use crate::support::{CliError, CliResult, ensure_slash, read_all, read_text};

/// C# `DoctorCommand.CollectorTimeout`.
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(10);

const AUSTRALIAN_REGIONS: &[&str] = &[
    "australiaeast",
    "australiasoutheast",
    "australiacentral",
    "australiacentral2",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub status: &'static str,
    pub area: String,
    pub detail: String,
}

#[derive(Default)]
struct Checks(Vec<Check>);

impl Checks {
    fn add(&mut self, status: &'static str, area: &str, detail: impl Into<String>) {
        self.0.push(Check {
            status,
            area: area.to_owned(),
            detail: detail.into(),
        });
    }
    fn pass(&mut self, area: &str, detail: impl Into<String>) {
        self.add("PASS", area, detail);
    }
    fn warn(&mut self, area: &str, detail: impl Into<String>) {
        self.add("WARN", area, detail);
    }
    fn fail(&mut self, area: &str, detail: impl Into<String>) {
        self.add("FAIL", area, detail);
    }
}

pub fn run(args: &DoctorArgs) -> CliResult {
    let mut checks = Checks::default();

    // Policies.
    let policy_directory = args.policy_directory.clone().unwrap_or_else(|| {
        Path::new("policies")
            .join("default")
            .to_string_lossy()
            .into_owned()
    });
    let mut policy_ids: Vec<String> = Vec::new();
    if Path::new(&policy_directory).is_dir() {
        match content::load_policy_directory(&policy_directory) {
            Ok(policies) => {
                checks.pass(
                    "policies",
                    format!(
                        "{} policies load strictly from {policy_directory}.",
                        policies.len()
                    ),
                );
                policy_ids.extend(policies.into_iter().map(|policy| policy.id));
            }
            Err(ContentError::Reported(message)) => checks.fail("policies", message),
            Err(ContentError::Fatal(error)) => return Err(error),
        }
    } else {
        checks.warn(
            "policies",
            format!(
                "Policy directory {policy_directory} not found (fine if packs supply policies)."
            ),
        );
    }

    // Packs.
    let trusted = read_all(&args.trusted_keys)?;
    let mut pack_profile: Option<String> = None;
    for pack in &args.packs {
        // Every `PackError` is a C# PackVerificationException, InvalidDataException
        // or IOException, all of which doctor reports as a FAIL check.
        match bower_packs::load(Path::new(pack), &trusted) {
            Ok(loaded) => {
                let manifest = super::pack::manifest(&loaded)?;
                policy_ids.extend(
                    loaded
                        .policies
                        .iter()
                        .map(|policy| policy.policy.metadata.id.clone()),
                );
                if pack_profile.is_none() {
                    pack_profile.clone_from(&loaded.privacy_profile_yaml);
                }
                checks.pass(
                    "pack",
                    format!(
                        "{}@{} signature and hashes verified (key {}).",
                        manifest.id, manifest.version, loaded.signed_by_key_id
                    ),
                );
            }
            Err(error) => {
                let name = Path::new(pack)
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                checks.fail("pack", format!("{name}: {error}"));
            }
        }
    }

    let duplicates = duplicate_ids(&policy_ids);
    if !duplicates.is_empty() {
        checks.fail(
            "policies",
            format!(
                "Duplicate policy ids across directory and packs: {}.",
                duplicates.join(", ")
            ),
        );
    }

    // Privacy profile.
    let mut privacy = PrivacyPolicy::create_default();
    let profile_yaml = match &args.privacy_profile {
        Some(path) => Some(read_text(path)?),
        None => pack_profile,
    };
    match profile_yaml {
        Some(yaml) => match load_profile(&yaml, args.hmac_key_file.as_deref()) {
            Ok(policy) => {
                checks.pass(
                    "privacy",
                    format!(
                        "Privacy profile loads; {} field rule(s), max field length {}.",
                        policy.field_rules.len(),
                        policy.maximum_field_length
                    ),
                );
                privacy = policy;
            }
            Err(PrivacyError::Argument(message)) => return Err(CliError(message)),
            Err(error) => checks.fail("privacy", error.to_string()),
        },
        None => checks.pass(
            "privacy",
            "Default Australian privacy policy (TFN masked, secrets removed).",
        ),
    }

    // Schema and preflight against the Logs Ingestion API limits.
    let schema = SentinelSchema::default_schema();
    let lint = lint_schema(schema);
    if lint.is_empty() {
        checks.pass(
            "schema",
            format!(
                "{}: {} columns, names valid, TimeGenerated present.",
                schema.table_name,
                schema.table_columns.len()
            ),
        );
    }
    for finding in &lint {
        checks.fail("schema", finding.detail.clone());
    }
    let maximum_field_length = privacy.maximum_field_length;
    let engine = PrivacyEngine::new(privacy).map_err(CliError::from_display)?;
    let sample = engine.redact_json(&sample_envelope()?);
    if sample.succeeded
        && let Some(redacted) = &sample.redacted_json
        && let Ok(serde_json::Value::Object(record)) =
            serde_json::from_str::<serde_json::Value>(redacted)
    {
        let issues = bower_dcr::preflight::check(&record, schema);
        if issues.is_empty() {
            checks.pass(
                "preflight",
                "Representative event passes Logs Ingestion API size, type and field checks after redaction.",
            );
        }
        for issue in issues {
            checks.fail("preflight", format!("{}: {}", issue.field, issue.detail));
        }
    }
    if maximum_field_length.saturating_mul(2) > bower_dcr::MAXIMUM_FIELD_BYTES {
        checks.warn(
            "preflight",
            format!(
                "maximumFieldLength {maximum_field_length} could exceed Azure's 64 KB field limit for non-ASCII text."
            ),
        );
    }

    // Region placement (sovereignty).
    for endpoint in &args.ingestion_endpoints {
        let host = reqwest::Url::parse(endpoint)
            .ok()
            .and_then(|url| url.host_str().map(str::to_lowercase))
            .ok_or_else(|| {
                CliError::new("Invalid URI: The format of the URI could not be determined.")
            })?;
        match AUSTRALIAN_REGIONS
            .iter()
            .find(|region| host.contains(**region))
        {
            Some(region) => checks.pass("region", format!("Ingestion endpoint is in {region}.")),
            None => checks.warn(
                "region",
                format!("Ingestion endpoint {host} is not recognisably in an Australian region."),
            ),
        }
    }

    // Live collector.
    if let Some(collector_url) = &args.collector_url {
        check_collector(collector_url, COLLECTOR_TIMEOUT, &mut checks)?;
    }

    // Local queue ledger.
    if let Some(database) = &args.database {
        let store = open_store(database)?;
        let ledger = store.verify_ledger().map_err(store_error)?;
        if ledger.intact {
            checks.pass(
                "ledger",
                format!(
                    "Queue ledger intact ({} entries, head {}).",
                    ledger.entries, ledger.head_sequence
                ),
            );
        } else {
            checks.fail(
                "ledger",
                format!(
                    "Queue ledger has {} issue(s); run 'bower queue verify'.",
                    ledger.issues.len()
                ),
            );
        }
        let snapshot = store.snapshot().map_err(store_error)?;
        if snapshot.dead_lettered > 0 {
            checks.warn(
                "queue",
                format!(
                    "{} dead-lettered event(s); inspect with 'bower queue dead-letters'.",
                    snapshot.dead_lettered
                ),
            );
        }
    }

    // Live Azure resources (read-only).
    if args.dcr_resource_id.is_some() || args.workspace_resource_id.is_some() {
        let arm = ArmSession::new(args.credential.as_deref(), None)?;
        if let Some(rule_id) = &args.dcr_resource_id {
            match arm.get_rule(rule_id)? {
                None => checks.fail("dcr", "DCR not found or not readable with this credential."),
                Some(rule) => {
                    let findings =
                        compare_rule(&rule.to_string(), schema).map_err(CliError::from_display)?;
                    report("dcr", &findings, &mut checks);
                    check_region("dcr", rule.get("location"), &mut checks);
                }
            }
        }
        if let Some(workspace_id) = &args.workspace_resource_id {
            let workspace = arm.get_workspace(workspace_id)?;
            check_region(
                "workspace",
                workspace.as_ref().and_then(|value| value.get("location")),
                &mut checks,
            );
            match arm.get_table(workspace_id, &schema.table_name)? {
                None => checks.fail(
                    "table",
                    format!(
                        "{} not found; deploy with 'bower dcr generate'.",
                        schema.table_name
                    ),
                ),
                Some(table) => {
                    let findings = compare_table_default(&table.to_string(), schema)
                        .map_err(CliError::from_display)?;
                    report("table", &findings, &mut checks);
                }
            }
        }
    }

    let checks = checks.0;
    if args.json {
        println!("{}", checks_json(&checks).to_indented());
    } else {
        for line in text_lines(&checks) {
            println!("{line}");
        }
    }
    Ok(if checks.iter().any(|check| check.status == "FAIL") {
        1
    } else {
        0
    })
}

pub fn load_profile(yaml: &str, key_file: Option<&str>) -> Result<PrivacyPolicy, PrivacyError> {
    let key = match key_file {
        Some(path) => {
            // Surface .NET-style I/O messages ("Could not find file '...'.").
            crate::support::read_bytes(path).map_err(|error| PrivacyError::Io(error.0))?;
            Some(bower_redaction::read_key_file(path)?)
        }
        None => None,
    };
    Ok(bower_redaction::load_privacy_profile(yaml, key.as_deref(), None)?.policy)
}

/// Ids appearing more than once, in order of first appearance (`GroupBy`).
pub fn duplicate_ids(ids: &[String]) -> Vec<String> {
    let mut duplicates: Vec<String> = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        if !duplicates.contains(id) && ids[index + 1..].contains(id) && !ids[..index].contains(id) {
            duplicates.push(id.clone());
        }
    }
    duplicates
}

pub fn checks_json(checks: &[Check]) -> Json {
    Json::Array(
        checks
            .iter()
            .map(|check| {
                Json::object([
                    ("Status", Json::str(check.status)),
                    ("Area", Json::str(check.area.clone())),
                    ("Detail", Json::str(check.detail.clone())),
                ])
            })
            .collect(),
    )
}

pub fn text_lines(checks: &[Check]) -> Vec<String> {
    let mut lines: Vec<String> = checks
        .iter()
        .map(|check| {
            format!(
                "{} {} {}",
                pad(check.status, 5),
                pad(&check.area, 10),
                check.detail
            )
        })
        .collect();
    let failed = checks.iter().filter(|check| check.status == "FAIL").count();
    let warned = checks.iter().filter(|check| check.status == "WARN").count();
    lines.push(format!(
        "{} checks: {failed} failed, {warned} warnings.",
        checks.len()
    ));
    lines
}

fn report(area: &str, findings: &[DcrFinding], checks: &mut Checks) {
    if findings.is_empty() {
        checks.pass(area, "Matches Bower's schema.");
    }
    for finding in findings {
        let detail = format!("{}: {}", finding.code, finding.detail);
        match finding.level {
            FindingLevel::Error => checks.fail(area, detail),
            FindingLevel::Warning => checks.warn(area, detail),
            FindingLevel::Info => checks.pass(area, detail),
        }
    }
}

fn check_region(area: &str, location: Option<&serde_json::Value>, checks: &mut Checks) {
    let location = location.and_then(serde_json::Value::as_str);
    let normalised = location.unwrap_or_default().replace(' ', "").to_lowercase();
    if AUSTRALIAN_REGIONS.contains(&normalised.as_str()) {
        checks.pass(area, format!("Located in {normalised}."));
    } else {
        checks.warn(
            area,
            format!(
                "Located in '{}', outside Australia.",
                location.unwrap_or("unknown")
            ),
        );
    }
    if area == "workspace" && normalised != "australiaeast" && !normalised.is_empty() {
        checks.warn(
            area,
            "The Sentinel data lake is only available in Australia East.",
        );
    }
}

/// Checks a live collector's `/health` and `/v1/status`. Unreachable collectors and
/// HTTP timeouts are FAIL checks, never a crash.
fn check_collector(collector_url: &str, timeout: Duration, checks: &mut Checks) -> CliResult<()> {
    let base = reqwest::Url::parse(&ensure_slash(collector_url)).map_err(|_| {
        CliError::new("Invalid URI: The format of the URI could not be determined.")
    })?;
    let host = base.host_str().unwrap_or_default().to_owned();
    let token = std::env::var("BOWER_INGEST_TOKEN")
        .ok()
        .filter(|value| !value.is_empty());
    let outcome = super::block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(CliError::from_display)?;
        let health_url = base.join("health").map_err(CliError::from_display)?;
        let health = match client.get(health_url).send().await {
            Ok(response) => response,
            Err(error) => {
                return Ok(CollectorOutcome::Unreachable(super::http_error_with_host(
                    &error, timeout,
                )));
            }
        };
        if !health.status().is_success() {
            return Ok(CollectorOutcome::HealthStatus(health.status().as_u16()));
        }
        let status_url = base.join("v1/status").map_err(CliError::from_display)?;
        let mut request = client.get(status_url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return Ok(CollectorOutcome::ReachableThenUnreachable(
                    super::http_error_with_host(&error, timeout),
                ));
            }
        };
        if !response.status().is_success() {
            return Ok(CollectorOutcome::StatusHttp(response.status().as_u16()));
        }
        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => {
                return Ok(CollectorOutcome::ReachableThenUnreachable(
                    super::http_error_with_host(&error, timeout),
                ));
            }
        };
        Ok(CollectorOutcome::Status(body))
    })?;

    match outcome {
        CollectorOutcome::Unreachable(message) => {
            checks.fail("collector", format!("Unreachable: {message}"))
        }
        CollectorOutcome::HealthStatus(code) => {
            checks.fail("collector", format!("/health returned HTTP {code}."))
        }
        CollectorOutcome::ReachableThenUnreachable(message) => {
            checks.pass("collector", format!("{host} is reachable."));
            checks.fail("collector", format!("Unreachable: {message}"));
        }
        CollectorOutcome::StatusHttp(code) => {
            checks.pass("collector", format!("{host} is reachable."));
            checks.warn(
                "collector",
                format!("/v1/status returned HTTP {code} (set BOWER_INGEST_TOKEN for details)."),
            );
        }
        CollectorOutcome::Status(body) => {
            checks.pass("collector", format!("{host} is reachable."));
            let status: serde_json::Value =
                bower_contracts::json::from_str(&body).map_err(CliError::from_display)?;
            let dead = status
                .pointer("/queue/deadLettered")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            if dead > 0 {
                checks.warn(
                    "collector",
                    format!("{dead} dead-lettered event(s) on the collector."),
                );
            }
            let hash = status
                .pointer("/policy/hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            checks.pass("collector", format!("Running policy bundle {hash}."));
        }
    }
    Ok(())
}

enum CollectorOutcome {
    Unreachable(String),
    HealthStatus(u16),
    ReachableThenUnreachable(String),
    StatusHttp(u16),
    Status(String),
}

/// The representative event `doctor` redacts and preflights (2,000-character reason).
fn sample_envelope() -> CliResult<String> {
    let envelope = SecurityEventEnvelope {
        schema_version: CURRENT_SCHEMA_VERSION.to_owned(),
        event_id: "doctor-sample".to_owned(),
        event_original_id: None,
        time_generated: bower_contracts::time::now(),
        time_observed: None,
        event_category: event_categories::AUTHENTICATION.to_owned(),
        event_type: event_types::AUTHENTICATION_FAILURE.to_owned(),
        event_action: "authentication.attempt".to_owned(),
        event_result: EventResult::Failure,
        event_severity: EventSeverity::default(),
        event_outcome_reason: Some("x".repeat(2_000)),
        application: ApplicationContext {
            name: "doctor".to_owned(),
            version: None,
            environment: "test".to_owned(),
            instance: None,
            tenant_id: None,
        },
        actor: Some(ActorContext {
            username: Some("doctor".to_owned()),
            ..ActorContext::default()
        }),
        target: None,
        source: Some(SourceContext {
            ip_address: Some("192.0.2.1".to_owned()),
            ..SourceContext::default()
        }),
        request: Some(RequestContext {
            correlation_id: Some("doctor".to_owned()),
            ..RequestContext::default()
        }),
        change: None,
        security: None,
        collector: None,
        labels: None,
        attributes: None,
        privacy: None,
    };
    bower_contracts::json::to_string(&envelope).map_err(CliError::from_display)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_follow_first_appearance() {
        let ids: Vec<String> = ["b", "a", "b", "c", "a", "b"]
            .iter()
            .map(|id| (*id).to_owned())
            .collect();
        assert_eq!(duplicate_ids(&ids), vec!["b".to_owned(), "a".to_owned()]);
    }

    #[test]
    fn text_output_matches_csharp_layout() {
        let checks = vec![
            Check {
                status: "PASS",
                area: "policies".to_owned(),
                detail: "ok.".to_owned(),
            },
            Check {
                status: "WARN",
                area: "collector".to_owned(),
                detail: "warn.".to_owned(),
            },
        ];
        assert_eq!(
            text_lines(&checks),
            vec![
                "PASS  policies   ok.",
                "WARN  collector  warn.",
                "2 checks: 0 failed, 1 warnings."
            ]
        );
    }

    /// A collector that accepts the connection and never answers is a FAIL check
    /// with the .NET timeout message, not a crash.
    #[test]
    fn collector_timeout_is_a_failed_check() {
        let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else {
            eprintln!("skipping: cannot bind a loopback socket here");
            return;
        };
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let held = listener.accept();
            std::thread::sleep(Duration::from_millis(1_500));
            drop(held);
        });
        let mut checks = Checks::default();
        check_collector(
            &format!("http://{address}"),
            Duration::from_millis(500),
            &mut checks,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(
            checks.0,
            vec![Check {
                status: "FAIL",
                area: "collector".to_owned(),
                detail: "Unreachable: The request was canceled due to the configured HttpClient.Timeout of 0.5 seconds elapsing.".to_owned(),
            }]
        );
    }

    #[test]
    fn workspace_outside_australia_east_warns_about_data_lake() {
        let mut checks = Checks::default();
        check_region(
            "workspace",
            Some(&serde_json::json!("Australia Southeast")),
            &mut checks,
        );
        assert_eq!(checks.0.len(), 2);
        assert_eq!(checks.0[0].detail, "Located in australiasoutheast.");
        let mut checks = Checks::default();
        check_region("dcr", None, &mut checks);
        assert_eq!(
            checks.0[0].detail,
            "Located in 'unknown', outside Australia."
        );
    }
}
