//! `bower dcr generate|diff` (C# `DcrCommands`).

use bower_dcr::drift::{compare_rule, compare_table_default, lint_schema};
use bower_dcr::{DcrFinding, DcrTemplateOptions, FindingLevel, SentinelSchema};

use crate::cli::{DcrDiffArgs, DcrGenerateArgs};
use crate::commands::azure::ArmSession;
use crate::output::pad;
use crate::support::{CliError, CliResult, int_or, read_text, write_text};

/// `bower dcr generate [--out FILE] [--rule-name NAME] [--plan PLAN] [--retention-days N] [--total-retention-days N]`.
pub fn generate(args: &DcrGenerateArgs) -> CliResult {
    let options = DcrTemplateOptions {
        rule_name: args
            .rule_name
            .clone()
            .unwrap_or_else(|| "bower-dcr".to_owned()),
        plan: args.plan.clone().unwrap_or_else(|| "Analytics".to_owned()),
        retention_in_days: int_or(args.retention_days.as_deref(), 90)?,
        total_retention_in_days: int_or(args.total_retention_days.as_deref(), 365)?,
        schema: SentinelSchema::default_schema().clone(),
    };
    let json = bower_dcr::generator::generate_json(&options).map_err(CliError::from_display)?;
    match &args.out {
        Some(path) => {
            write_text(path, &json)?;
            println!(
                "Wrote {path}. Deploy with: az deployment group create -g <rg> -f {path} -p workspaceName=<workspace>"
            );
        }
        None => println!("{json}"),
    }
    Ok(0)
}

/// One finding line: `{LEVEL,-7} {Code,-26} {Detail}`.
pub fn finding_line(finding: &DcrFinding) -> String {
    format!(
        "{} {} {}",
        pad(&finding.level.as_str().to_uppercase(), 7),
        pad(&finding.code, 26),
        finding.detail
    )
}

/// `bower dcr diff (--rule FILE | --dcr-resource-id ID) [--table FILE | --workspace-resource-id ID] [--credential MODE]`.
/// Exit code 1 when any error-level drift is found.
pub fn diff(args: &DcrDiffArgs) -> CliResult {
    let schema = SentinelSchema::default_schema();
    let mut findings = lint_schema(schema);
    let arm = if args.arm_requested {
        Some(ArmSession::new(args.credential.as_deref(), None)?)
    } else {
        None
    };

    let rule_json = match (&args.rule, &args.dcr_resource_id, &arm) {
        (Some(file), _, _) => read_text(file)?,
        (None, Some(rule_id), Some(arm)) => arm
            .get_rule(rule_id)?
            .map(|value| value.to_string())
            .ok_or_else(|| {
            CliError::new("DCR not found or not readable with this credential.")
        })?,
        _ => {
            return Err(CliError::new(
                "Provide --rule FILE or --dcr-resource-id ID.",
            ));
        }
    };
    findings.extend(compare_rule(&rule_json, schema).map_err(CliError::from_display)?);

    let table_json = match (&args.table, &args.workspace_resource_id, &arm) {
        (Some(file), _, _) => Some(read_text(file)?),
        (None, Some(workspace), Some(arm)) => arm
            .get_table(workspace, &schema.table_name)?
            .map(|value| value.to_string()),
        _ => None,
    };
    if let Some(table_json) = table_json {
        findings
            .extend(compare_table_default(&table_json, schema).map_err(CliError::from_display)?);
    }

    for finding in &findings {
        println!("{}", finding_line(finding));
    }
    if findings.is_empty() {
        println!("OK      no drift          Deployed DCR matches Bower's schema.");
    }
    Ok(
        if findings
            .iter()
            .any(|finding| finding.level == FindingLevel::Error)
        {
            1
        } else {
            0
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_lines_pad_like_csharp() {
        let finding = DcrFinding {
            level: FindingLevel::Warning,
            code: "retention-short".to_owned(),
            detail: "Total retention is 30 days.".to_owned(),
        };
        assert_eq!(
            finding_line(&finding),
            "WARNING retention-short            Total retention is 30 days."
        );
    }
}
