//! Offline DCR assessment (`DcrDocumentParser`, `DcrOptimiser`). Never calls Azure.

use std::fmt::Write as _;

use bower_contracts::time::Timestamp;
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::DcrError;
use crate::json_text::{contains_ignore_case, format_two_decimals};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcrDataSource {
    pub name: String,
    pub kind: String,
    pub streams: Vec<String>,
    pub xpath_queries: Vec<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcrDocument {
    pub id: String,
    pub name: String,
    pub workspace_id: Option<String>,
    pub data_sources: Vec<DcrDataSource>,
    pub destinations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DcrRecommendation {
    pub code: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub estimated_monthly_gb_saved: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DcrAssessmentReport {
    pub dcr_id: String,
    pub dcr_name: String,
    pub coverage_score: i32,
    pub health_score: i32,
    pub estimated_monthly_ingestion_gb: Option<f64>,
    pub estimated_monthly_savings_gb: Option<f64>,
    pub recommendations: Vec<DcrRecommendation>,
    pub assessed_at: Timestamp,
}

// --- A minimal JsonElement: kind, raw text and ordered properties. ---

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Object,
    Array,
    String,
    Number,
    True,
    False,
    Null,
}

#[derive(Clone, Copy)]
struct Element<'a> {
    raw: &'a RawValue,
}

fn invalid(_: impl std::fmt::Display) -> DcrError {
    DcrError::InvalidData("DCR JSON is invalid.".to_owned())
}

impl<'a> Element<'a> {
    fn kind(self) -> Kind {
        match self.raw.get().as_bytes().first() {
            Some(b'{') => Kind::Object,
            Some(b'[') => Kind::Array,
            Some(b'"') => Kind::String,
            Some(b't') => Kind::True,
            Some(b'f') => Kind::False,
            Some(b'n') => Kind::Null,
            _ => Kind::Number,
        }
    }

    fn properties(self) -> Result<Vec<(String, Element<'a>)>, DcrError> {
        struct Properties;
        impl<'de> Visitor<'de> for Properties {
            type Value = Vec<(String, &'de RawValue)>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, &'de RawValue>()? {
                    entries.push((key, value));
                }
                Ok(entries)
            }
        }
        let mut deserializer = serde_json::Deserializer::from_str(self.raw.get());
        let entries = (&mut deserializer)
            .deserialize_map(Properties)
            .map_err(invalid)?;
        Ok(entries
            .into_iter()
            .map(|(key, raw)| (key, Element { raw }))
            .collect())
    }

    fn items(self) -> Result<Vec<Element<'a>>, DcrError> {
        struct Items;
        impl<'de> Visitor<'de> for Items {
            type Value = Vec<&'de RawValue>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON array")
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<&'de RawValue>()? {
                    items.push(item);
                }
                Ok(items)
            }
        }
        let mut deserializer = serde_json::Deserializer::from_str(self.raw.get());
        let items = (&mut deserializer)
            .deserialize_seq(Items)
            .map_err(invalid)?;
        Ok(items.into_iter().map(|raw| Element { raw }).collect())
    }

    /// `TryGetProperty`: the last property with that name wins. Throws (here: errors)
    /// when the element is not an object.
    fn property(self, name: &str) -> Result<Option<Element<'a>>, DcrError> {
        if self.kind() != Kind::Object {
            return Err(DcrError::InvalidData(format!(
                "DCR JSON element is not an object (looking up '{name}')."
            )));
        }
        Ok(self
            .properties()?
            .into_iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value))
    }

    /// `GetString()`: the unescaped string, `None` for null, error otherwise.
    fn get_string(self) -> Result<Option<String>, DcrError> {
        match self.kind() {
            Kind::String => serde_json::from_str::<String>(self.raw.get())
                .map(Some)
                .map_err(invalid),
            Kind::Null => Ok(None),
            _ => Err(DcrError::InvalidData(
                "DCR JSON value is not a string.".to_owned(),
            )),
        }
    }

    /// `JsonElement.ToString()`.
    fn to_text(self) -> Result<String, DcrError> {
        Ok(match self.kind() {
            Kind::String => self.get_string()?.unwrap_or_default(),
            Kind::Null => String::new(),
            Kind::True => "True".to_owned(),
            Kind::False => "False".to_owned(),
            Kind::Number | Kind::Array | Kind::Object => self.raw.get().to_owned(),
        })
    }
}

fn read_string(element: Element<'_>, name: &str) -> Result<Option<String>, DcrError> {
    match element.property(name)? {
        None => Ok(None),
        Some(property) if property.kind() == Kind::String => property.get_string(),
        Some(property) => property.to_text().map(Some),
    }
}

fn read_nested(element: Element<'_>, path: &[&str]) -> Result<Option<String>, DcrError> {
    let mut current = element;
    for segment in path {
        if current.kind() != Kind::Object {
            return Ok(None);
        }
        match current.property(segment)? {
            Some(next) => current = next,
            None => return Ok(None),
        }
    }
    if current.kind() == Kind::String {
        current.get_string()
    } else {
        current.to_text().map(Some)
    }
}

fn read_string_array(element: Element<'_>, name: &str) -> Result<Vec<String>, DcrError> {
    let Some(property) = element.property(name)? else {
        return Ok(Vec::new());
    };
    if property.kind() != Kind::Array {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for item in property.items()? {
        let value = match item.get_string()? {
            Some(value) => value,
            None => item.to_text()?,
        };
        if !value.trim().is_empty() {
            values.push(value);
        }
    }
    Ok(values)
}

fn parse_source(item: Element<'_>, fallback_kind: Option<&str>) -> Result<DcrDataSource, DcrError> {
    let name = match read_string(item, "name")? {
        Some(name) => name,
        None => read_string(item, "streams")?.unwrap_or_else(|| "source".to_owned()),
    };
    let kind = match read_string(item, "kind")? {
        Some(kind) => kind,
        None => read_string(item, "type")?
            .or_else(|| fallback_kind.map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned()),
    };
    let streams = read_string_array(item, "streams")?;
    let mut xpaths = read_string_array(item, "xPathQueries")?;
    if xpaths.is_empty() {
        xpaths = read_string_array(item, "xpathQueries")?;
    }
    let enabled = item
        .property("enabled")?
        .is_none_or(|enabled| enabled.kind() != Kind::False);
    Ok(DcrDataSource {
        name,
        kind,
        streams,
        xpath_queries: xpaths,
        enabled,
    })
}

/// `DcrDocumentParser.Parse`: reads a DCR export (flattened or ARM shaped).
pub fn parse_document(json: &str) -> Result<DcrDocument, DcrError> {
    if json.trim().is_empty() {
        return Err(DcrError::InvalidArgument(
            "The value cannot be an empty string or composed entirely of whitespace.".to_owned(),
        ));
    }
    let root_raw: &RawValue = serde_json::from_str(json).map_err(invalid)?;
    let root = Element { raw: root_raw };
    let id = match read_string(root, "id")? {
        Some(id) => id,
        None => read_string(root, "name")?.unwrap_or_else(|| "unknown".to_owned()),
    };
    let name = read_string(root, "name")?.unwrap_or_else(|| id.clone());
    let workspace = match read_string(root, "workspaceId")? {
        Some(workspace) => Some(workspace),
        None => read_nested(
            root,
            &["destinations", "logAnalytics", "workspaceResourceId"],
        )?,
    };

    let mut sources = Vec::new();
    if let Some(data_sources) = root.property("dataSources")? {
        match data_sources.kind() {
            Kind::Array => {
                for item in data_sources.items()? {
                    sources.push(parse_source(item, None)?);
                }
            }
            Kind::Object => {
                for (kind, value) in data_sources.properties()? {
                    if value.kind() == Kind::Array {
                        for item in value.items()? {
                            sources.push(parse_source(item, Some(&kind))?);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut destinations = Vec::new();
    if let Some(node) = root.property("destinations")? {
        match node.kind() {
            Kind::Array => {
                for item in node.items()? {
                    let value = match read_string(item, "name")? {
                        Some(value) => value,
                        None => item.to_text()?,
                    };
                    if !value.trim().is_empty() {
                        destinations.push(value);
                    }
                }
            }
            Kind::Object => destinations.extend(node.properties()?.into_iter().map(|(key, _)| key)),
            _ => {}
        }
    }

    Ok(DcrDocument {
        id,
        name,
        workspace_id: workspace,
        data_sources: sources,
        destinations,
    })
}

const RECOMMENDED_SECURITY_EVENT_IDS: &[&str] = &[
    "4624", "4625", "4648", "4672", "4688", "4720", "4728", "4732", "1102",
];
const RECOMMENDED_SYSMON_IDS: &[&str] = &["1", "3", "11"];

fn recommendation(
    code: &str,
    severity: &str,
    title: &str,
    detail: String,
    saved: Option<f64>,
) -> DcrRecommendation {
    DcrRecommendation {
        code: code.to_owned(),
        severity: severity.to_owned(),
        title: title.to_owned(),
        detail,
        estimated_monthly_gb_saved: saved,
    }
}

/// `DcrOptimiser.Assess`. Savings are estimated only when a volume signal
/// (`current_monthly_ingestion_gb`) is supplied.
pub fn assess(
    document: &DcrDocument,
    current_monthly_ingestion_gb: Option<f64>,
    now: Option<Timestamp>,
) -> DcrAssessmentReport {
    let assessed_at = now.unwrap_or_else(bower_contracts::time::now);
    let mut recommendations = Vec::new();
    let sources = &document.data_sources;

    // Duplicate names (case-insensitive), grouped in first-seen order.
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for source in sources {
        match groups
            .iter_mut()
            .find(|(key, _)| eq_ordinal_ignore_case(key, &source.name))
        {
            Some(group) => group.1 += 1,
            None => groups.push((&source.name, 1)),
        }
    }
    for (key, count) in groups.into_iter().filter(|(_, count)| *count > 1) {
        recommendations.push(recommendation(
            "duplicate-source",
            "medium",
            "Duplicate collection sources",
            format!("Data source name '{key}' appears {count} times."),
            current_monthly_ingestion_gb.map(|gb| gb * 0.05),
        ));
    }

    let has_windows_events = sources.iter().any(|item| {
        contains_ignore_case(&item.kind, "windows")
            || item
                .streams
                .iter()
                .any(|stream| contains_ignore_case(stream, "WindowsEvent"))
    });

    let has_wildcard_security = sources.iter().any(|item| {
        item.xpath_queries.iter().any(|query| {
            contains_ignore_case(query, "Security!*")
                || contains_ignore_case(query, "*[System[(EventID='*')]]")
        })
    });
    if has_wildcard_security {
        recommendations.push(recommendation(
            "broad-security-events",
            "high",
            "Replace Security Event * with targeted Event IDs",
            "Broad Security channel collection inflates ingestion. Prefer targeted Event IDs."
                .to_owned(),
            current_monthly_ingestion_gb.map(|gb| gb * 0.25),
        ));
    }

    let joined_xpath = sources
        .iter()
        .flat_map(|item| item.xpath_queries.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let missing_security_ids: Vec<&str> = RECOMMENDED_SECURITY_EVENT_IDS
        .iter()
        .copied()
        .filter(|id| !joined_xpath.contains(id))
        .collect();
    if has_windows_events && !missing_security_ids.is_empty() {
        recommendations.push(recommendation(
            "missing-security-event-ids",
            "medium",
            "Missing high-value Windows Event IDs",
            format!(
                "Consider collecting Event IDs: {}.",
                missing_security_ids.join(", ")
            ),
            None,
        ));
    }

    let has_sysmon = sources.iter().any(|item| {
        contains_ignore_case(&item.name, "sysmon")
            || item
                .xpath_queries
                .iter()
                .any(|query| contains_ignore_case(query, "Sysmon"))
            || item
                .streams
                .iter()
                .any(|stream| contains_ignore_case(stream, "Sysmon"))
    });
    if !has_sysmon {
        recommendations.push(recommendation(
            "missing-sysmon",
            "high",
            "Missing Sysmon configuration",
            "Collect Sysmon Event IDs 1, 3 and 11 for process, network and file visibility."
                .to_owned(),
            None,
        ));
    } else {
        let missing_sysmon = RECOMMENDED_SYSMON_IDS.iter().any(|id| {
            !contains_ignore_case(&joined_xpath, &format!("EventID={id}"))
                && !contains_ignore_case(&joined_xpath, &format!("EventID='{id}'"))
        });
        if missing_sysmon {
            recommendations.push(recommendation(
                "incomplete-sysmon",
                "medium",
                "Incomplete Sysmon Event IDs",
                format!(
                    "Ensure Sysmon Event IDs {} are collected.",
                    RECOMMENDED_SYSMON_IDS.join(", ")
                ),
                None,
            ));
        }
    }

    let has_defender = sources.iter().any(|item| {
        contains_ignore_case(&item.name, "defender")
            || item
                .streams
                .iter()
                .any(|stream| contains_ignore_case(stream, "Microsoft-Windows-Windows Defender"))
    });
    if !has_defender {
        recommendations.push(recommendation(
            "missing-defender",
            "medium",
            "Disabled or missing Defender telemetry",
            "Enable Defender / XDR connector or collect Defender operational channels.".to_owned(),
            None,
        ));
    }

    let has_iis = sources.iter().any(|item| {
        contains_ignore_case(&item.name, "iis")
            || item
                .streams
                .iter()
                .any(|stream| contains_ignore_case(stream, "IIS"))
    });
    if !has_iis {
        recommendations.push(recommendation(
            "missing-iis",
            "low",
            "Missing IIS logs",
            "If web workloads exist, collect IIS W3C logs with path filters.".to_owned(),
            None,
        ));
    }

    if sources.iter().any(|item| !item.enabled) {
        recommendations.push(recommendation(
            "disabled-sources",
            "medium",
            "Disabled data sources present",
            "Review disabled sources for accidental coverage gaps or stale configuration."
                .to_owned(),
            None,
        ));
    }

    if document.destinations.is_empty() {
        recommendations.push(recommendation(
            "missing-destination",
            "critical",
            "No destinations configured",
            "DCR has no Log Analytics / destination association.".to_owned(),
            None,
        ));
    }

    let count = |severity: &str| {
        recommendations
            .iter()
            .filter(|item| item.severity == severity)
            .count() as i32
    };
    let health_score = (100
        - count("critical") * 30
        - count("high") * 15
        - count("medium") * 8
        - count("low") * 3)
        .clamp(0, 100);

    let mut coverage_points = 0;
    if has_windows_events {
        coverage_points += 30;
    }
    if has_sysmon {
        coverage_points += 30;
    }
    if has_defender {
        coverage_points += 20;
    }
    if has_iis {
        coverage_points += 10;
    }
    if !document.destinations.is_empty() {
        coverage_points += 10;
    }
    let coverage_score = coverage_points.clamp(0, 100);

    let savings: f64 = recommendations
        .iter()
        .filter_map(|item| item.estimated_monthly_gb_saved)
        .sum();
    let savings = if savings == 0.0 { None } else { Some(savings) };

    DcrAssessmentReport {
        dcr_id: document.id.clone(),
        dcr_name: document.name.clone(),
        coverage_score,
        health_score,
        estimated_monthly_ingestion_gb: current_monthly_ingestion_gb,
        estimated_monthly_savings_gb: savings,
        recommendations,
        assessed_at,
    }
}

/// `StringComparer.OrdinalIgnoreCase` equality (simple upper-case folding).
fn eq_ordinal_ignore_case(left: &str, right: &str) -> bool {
    left.chars()
        .flat_map(char::to_uppercase)
        .eq(right.chars().flat_map(char::to_uppercase))
}

/// `DcrOptimiser.ExportMarkdown` (`\n` line endings).
pub fn export_markdown(report: &DcrAssessmentReport) -> String {
    let mut builder = String::new();
    let _ = writeln!(builder, "# DCR Assessment: {}", report.dcr_name);
    builder.push('\n');
    let _ = writeln!(builder, "- DCR id: `{}`", report.dcr_id);
    let _ = writeln!(builder, "- Coverage score: **{}**", report.coverage_score);
    let _ = writeln!(builder, "- Health score: **{}**", report.health_score);
    if let Some(ingestion) = report.estimated_monthly_ingestion_gb {
        let _ = writeln!(
            builder,
            "- Current monthly ingestion: **{} GB**",
            format_two_decimals(ingestion)
        );
    }
    if let Some(savings) = report.estimated_monthly_savings_gb {
        let _ = writeln!(
            builder,
            "- Estimated monthly savings: **{} GB**",
            format_two_decimals(savings)
        );
    }
    builder.push('\n');
    builder.push_str("## Recommendations\n");
    if report.recommendations.is_empty() {
        builder.push_str("- No issues detected.\n");
    } else {
        for item in &report.recommendations {
            let _ = writeln!(
                builder,
                "- **[{}] {}** ({}): {}",
                item.severity, item.title, item.code, item.detail
            );
        }
    }
    builder
}
