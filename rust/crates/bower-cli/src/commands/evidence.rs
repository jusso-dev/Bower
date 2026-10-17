//! `bower evidence run|verify` (C# `EvidenceCommands`).

use std::sync::Arc;
use std::time::Duration;

use bower_evidence::bundle::format_double;
use bower_evidence::{
    ArmReader, EvidenceBundle, EvidenceError, EvidenceOptions, EvidenceRunner, HttpArmReader,
    HttpCanarySender, LogAnalyticsQuery, LogAnalyticsQueryClient, SignedEvidence,
    default_http_client, modes, verifier_credential,
};

use crate::cli::{EvidenceRunArgs, EvidenceVerifyArgs};
use crate::commands::azure::evidence_error;
use crate::output::pad;
use crate::support::{
    CliError, CliResult, ensure_slash, int_or, read_all, read_text, required, write_text,
};

fn run_error(error: EvidenceError) -> CliError {
    match error {
        // Transport failures carry no status prefix in the C# message.
        EvidenceError::Http(message) => CliError(message),
        other => evidence_error(other),
    }
}

/// `bower evidence run --collector-url URL [--workspace-id ID] [--workspace-resource-id RID]
/// [--table NAME] [--credential MODE] [--client-id ID] [--timeout-minutes N]
/// [--signing-key FILE] [--out FILE]`. Exit 0 only for a query-verified bundle, else 2.
pub fn run(args: &EvidenceRunArgs) -> CliResult {
    let http = default_http_client();
    let credential = if args.workspace_id.is_none() && args.workspace_resource_id.is_none() {
        None
    } else {
        Some(
            verifier_credential(args.credential.as_deref(), args.client_id.as_deref())
                .map_err(evidence_error)?,
        )
    };
    let query: Option<Arc<dyn LogAnalyticsQuery>> = match (&args.workspace_id, &credential) {
        (Some(_), Some(credential)) => Some(Arc::new(LogAnalyticsQueryClient::new(
            http.clone(),
            Arc::clone(credential),
        ))),
        _ => None,
    };
    let arm: Option<Arc<dyn ArmReader>> = credential.map(|credential| {
        Arc::new(HttpArmReader::new(http.clone(), credential)) as Arc<dyn ArmReader>
    });
    let runner = EvidenceRunner::new(Arc::new(HttpCanarySender::new(http)), query, arm);

    let collector = required(args.collector_url.as_deref(), "--collector-url")?;
    let collector_url = reqwest::Url::parse(&ensure_slash(collector)).map_err(|_| {
        CliError::new("Invalid URI: The format of the URI could not be determined.")
    })?;
    let mut options = EvidenceOptions::new(collector_url);
    options.ingest_token = std::env::var("BOWER_INGEST_TOKEN").ok();
    options.workspace_id.clone_from(&args.workspace_id);
    options
        .workspace_resource_id
        .clone_from(&args.workspace_resource_id);
    if let Some(table) = &args.table {
        table.clone_into(&mut options.table);
    }
    let minutes = int_or(args.timeout_minutes.as_deref(), 15)?;
    options.timeout = Duration::from_secs(u64::try_from(minutes).unwrap_or(0) * 60);

    let bundle = super::block_on(async { runner.run(&options).await.map_err(run_error) })?;

    let key = match &args.signing_key {
        Some(path) => Some(read_text(path)?),
        None => None,
    };
    let signed = EvidenceRunner::sign(&bundle, key.as_deref()).map_err(evidence_error)?;
    let output = args.out.clone().unwrap_or_else(|| {
        format!(
            "bower-evidence-{}.json",
            bundle.generated_at.format("%Y%m%dT%H%M%SZ")
        )
    });
    write_text(&output, &signed.to_json_indented())?;

    for line in summary_lines(&bundle, &signed, &output) {
        println!("{line}");
    }
    Ok(if bundle.mode == modes::VERIFIED { 0 } else { 2 })
}

/// The console summary `evidence run` prints after writing the bundle.
pub fn summary_lines(
    bundle: &EvidenceBundle,
    signed: &SignedEvidence,
    output: &str,
) -> Vec<String> {
    let canary = &bundle.canary;
    let arrival = &bundle.arrival;
    let mut lines = vec![
        format!("Mode:     {}", bundle.mode),
        format!(
            "Canary:   {} -> collector HTTP {} ({})",
            canary.event_id,
            canary.collector_status,
            canary
                .collector_decision
                .as_deref()
                .unwrap_or("no decision")
        ),
    ];
    lines.push(if arrival.found {
        format!(
            "Arrival:  found in {} after {} s ({} queries)",
            arrival.table,
            arrival
                .latency_seconds
                .map(format_double)
                .unwrap_or_default(),
            arrival.attempts
        )
    } else {
        format!(
            "Arrival:  not proven ({})",
            arrival.query_error.as_deref().unwrap_or(&bundle.mode)
        )
    });
    for control in &bundle.controls {
        lines.push(format!(
            "  {} {} {}",
            pad(&control.id, 16),
            pad(&control.status, 14),
            control.requirement
        ));
    }
    lines.push(format!(
        "Signed:   {}",
        signed
            .signature
            .as_ref()
            .map_or("no (pass --signing-key)", |signature| signature
                .key_id
                .as_str())
    ));
    lines.push(format!("Bundle:   {output}"));
    lines
}

/// `bower evidence verify FILE --trusted-key PUBLIC.pem`. Exit 1 unless the
/// signature verifies under a trusted key.
pub fn verify(args: &EvidenceVerifyArgs) -> CliResult {
    let file = args
        .file
        .as_deref()
        .ok_or_else(|| CliError::new("Provide an evidence bundle file."))?;
    let evidence = SignedEvidence::from_json(&read_text(file)?).map_err(evidence_error)?;
    let keys = read_all(&args.trusted_keys)?;
    let valid = EvidenceRunner::verify(&evidence, keys.iter().map(String::as_str));
    match (&evidence.signature, valid) {
        (Some(signature), true) => println!(
            "Signature valid (key {}). Mode: {}.",
            signature.key_id,
            evidence.mode()
        ),
        _ => println!("Signature INVALID or from an untrusted key."),
    }
    Ok(if valid { 0 } else { 1 })
}
