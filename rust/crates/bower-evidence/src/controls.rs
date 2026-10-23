//! Maps evidence results to Australian control requirements (`ControlMapping`).
//! Statuses are evidence statements for an assessor, not compliance determinations.
//! Identifiers follow the ISM release current when this was written; confirm them
//! against your ISM version.

use crate::bundle::{ArrivalRecord, ControlRecord, RetentionRecord, format_double, modes};

pub const ISM_MINIMUM_RETENTION_DAYS: i32 = 365;

fn control(
    framework: &str,
    id: &str,
    requirement: &str,
    status: &str,
    evidence: String,
) -> ControlRecord {
    ControlRecord {
        framework: framework.to_owned(),
        id: id.to_owned(),
        requirement: requirement.to_owned(),
        status: status.to_owned(),
        evidence,
    }
}

pub fn map(
    mode: &str,
    arrival: &ArrivalRecord,
    retention: Option<&RetentionRecord>,
) -> Vec<ControlRecord> {
    let verified = mode == modes::VERIFIED && arrival.found;
    let simulated = mode == modes::SIMULATED;
    let delivery = if verified {
        format!(
            "Canary {} row found by KQL after {} s.",
            arrival.table,
            arrival
                .latency_seconds
                .map_or_else(|| "?".to_owned(), format_double)
        )
    } else if simulated {
        "Simulated: no destination query was run.".to_owned()
    } else {
        format!(
            "Canary not found ({}).",
            arrival.query_error.as_deref().unwrap_or("unknown")
        )
    };
    let delivery_status = if verified {
        "evidenced"
    } else if simulated {
        "not-assessed"
    } else {
        "not-evidenced"
    };

    let (retention_status, retention_evidence) = match retention
        .and_then(|retention| retention.total_days.map(|total| (retention, total)))
    {
        Some((retention, total)) => (
            if total >= ISM_MINIMUM_RETENTION_DAYS {
                "not-assessed"
            } else {
                "not-evidenced"
            },
            format!(
                "Table total retention {total} days (plan {}). Configured total retention does not establish searchable retention or historical data availability.",
                retention.plan.as_deref().unwrap_or("unknown")
            ),
        ),
        None => (
            "not-assessed",
            "Retention not read (no workspace resource id or no ARM read access).".to_owned(),
        ),
    };

    vec![
        control(
            "ISM",
            "ISM-0580",
            "A security monitoring (event logging) policy is implemented; events are centrally logged.",
            delivery_status,
            delivery.clone(),
        ),
        control(
            "ISM",
            "ISM-1988",
            "Event logs are retained and searchable for at least 12 months.",
            retention_status,
            retention_evidence,
        ),
        control(
            "Essential Eight",
            "E8-ML2-LOGGING",
            "Event logs are centrally stored and protected from unauthorised modification and deletion.",
            "not-assessed",
            format!("{delivery} Protection against modification and deletion was not assessed."),
        ),
        control(
            "Privacy Act",
            "APP-11",
            "Technical measures protect personal information (redaction before data leaves the host).",
            "not-assessed",
            "Canary arrival and policy hashes do not establish redaction effectiveness. Independent privacy tests were not assessed.".to_owned(),
        ),
    ]
}
