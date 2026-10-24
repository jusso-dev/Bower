//! The Sentinel table and stream schema (`SentinelSchema`).

use std::sync::LazyLock;

/// A column in the incoming stream (Bower envelope JSON, camelCase).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamColumn {
    pub name: String,
    pub column_type: String,
}

/// A column in the destination Log Analytics table and how the transform fills it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableColumn {
    pub name: String,
    pub column_type: String,
    pub expression: String,
}

impl StreamColumn {
    pub fn new(name: impl Into<String>, column_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            column_type: column_type.into(),
        }
    }
}

impl TableColumn {
    pub fn new(
        name: impl Into<String>,
        column_type: impl Into<String>,
        expression: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            column_type: column_type.into(),
            expression: expression.into(),
        }
    }
}

/// The single source of truth for how Bower envelopes land in Sentinel. The DCR
/// generator, drift check, ingestion preflight and Bicep template all follow it.
/// Evolve additively: never rename or retype an existing column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentinelSchema {
    pub stream_name: String,
    pub table_name: String,
    pub stream_columns: Vec<StreamColumn>,
    pub table_columns: Vec<TableColumn>,
    pub schema_version_filter: String,
}

static DEFAULT_SCHEMA: LazyLock<SentinelSchema> = LazyLock::new(|| {
    let stream = [
        ("schemaVersion", "string"),
        ("eventId", "string"),
        ("eventOriginalId", "string"),
        ("timeGenerated", "datetime"),
        ("eventCategory", "string"),
        ("eventType", "string"),
        ("eventAction", "string"),
        ("eventResult", "string"),
        ("eventSeverity", "string"),
        ("application", "dynamic"),
        ("actor", "dynamic"),
        ("source", "dynamic"),
        ("request", "dynamic"),
        ("security", "dynamic"),
        ("collector", "dynamic"),
        ("labels", "dynamic"),
        ("privacy", "dynamic"),
        ("timeObserved", "datetime"),
        ("eventOutcomeReason", "string"),
        ("target", "dynamic"),
        ("change", "dynamic"),
        ("attributes", "dynamic"),
    ];
    let table = [
        ("TimeGenerated", "datetime", "timeGenerated"),
        ("EventId", "string", "substring(tostring(eventId), 0, 128)"),
        (
            "EventOriginalId",
            "string",
            "substring(tostring(eventOriginalId), 0, 256)",
        ),
        (
            "EventCategory",
            "string",
            "substring(tostring(eventCategory), 0, 128)",
        ),
        (
            "EventType",
            "string",
            "substring(tostring(eventType), 0, 128)",
        ),
        (
            "EventAction",
            "string",
            "substring(tostring(eventAction), 0, 128)",
        ),
        (
            "EventResult",
            "string",
            "substring(tostring(eventResult), 0, 32)",
        ),
        (
            "EventSeverity",
            "string",
            "substring(tostring(eventSeverity), 0, 32)",
        ),
        (
            "ApplicationName",
            "string",
            "substring(tostring(application.name), 0, 128)",
        ),
        (
            "ApplicationEnvironment",
            "string",
            "substring(tostring(application.environment), 0, 64)",
        ),
        (
            "ActorUserId",
            "string",
            "substring(tostring(actor.userId), 0, 256)",
        ),
        (
            "ActorUsername",
            "string",
            "substring(tostring(actor.username), 0, 256)",
        ),
        (
            "SourceIpAddress",
            "string",
            "substring(tostring(source.ipAddress), 0, 64)",
        ),
        (
            "CorrelationId",
            "string",
            "substring(tostring(request.correlationId), 0, 256)",
        ),
        (
            "PolicyId",
            "string",
            "substring(tostring(security.policyId), 0, 128)",
        ),
        (
            "PolicyVersion",
            "string",
            "substring(tostring(security.policyVersion), 0, 32)",
        ),
        (
            "PolicyHash",
            "string",
            "substring(tostring(security.policyHash), 0, 128)",
        ),
        ("ValueScore", "int", "toint(security.valueScore)"),
        (
            "CollectorId",
            "string",
            "substring(tostring(collector.id), 0, 128)",
        ),
        ("PrivacyDetected", "dynamic", "privacy.detected"),
        ("Labels", "dynamic", "labels"),
        ("RawEnvelope", "dynamic", "pack_all()"),
        ("TimeObserved", "datetime", "timeObserved"),
        (
            "EventOutcomeReason",
            "string",
            "substring(tostring(eventOutcomeReason), 0, 1024)",
        ),
        ("Target", "dynamic", "target"),
        ("Change", "dynamic", "change"),
        ("Attributes", "dynamic", "attributes"),
    ];
    SentinelSchema {
        stream_name: "Custom-BowerSecurity".to_owned(),
        table_name: "BowerSecurity_CL".to_owned(),
        stream_columns: stream
            .iter()
            .map(|(name, kind)| StreamColumn::new(*name, *kind))
            .collect(),
        table_columns: table
            .iter()
            .map(|(name, kind, expression)| TableColumn::new(*name, *kind, *expression))
            .collect(),
        schema_version_filter: "1.0.0".to_owned(),
    }
});

impl SentinelSchema {
    /// `SentinelSchema.Default`: the Bower security table.
    pub fn default_schema() -> &'static SentinelSchema {
        &DEFAULT_SCHEMA
    }

    /// The KQL transformation that maps the stream onto the table.
    pub fn transform_kql(&self) -> String {
        let projections: Vec<String> = self
            .table_columns
            .iter()
            .map(|column| format!("    {} = {}", column.name, column.expression))
            .collect();
        format!(
            "source\n| where schemaVersion == \"{}\"\n| project\n{}",
            self.schema_version_filter,
            projections.join(",\n")
        )
    }

    pub fn output_stream(&self) -> String {
        format!("Custom-{}", self.table_name)
    }

    /// Log Analytics table schema type names (`dateTime`) differ from DCR stream types
    /// (`datetime`).
    pub fn table_type(column_type: &str) -> &str {
        if column_type == "datetime" {
            "dateTime"
        } else {
            column_type
        }
    }
}

impl Default for SentinelSchema {
    fn default() -> Self {
        DEFAULT_SCHEMA.clone()
    }
}
