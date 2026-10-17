//! ARM template for the Bower table and a Direct-kind DCR (`DcrTemplateGenerator`).

use serde_json::{Map, Value, json};

use crate::DcrError;
use crate::json_text::to_indented_string;
use crate::schema::SentinelSchema;

/// Pinned ARM api-version for `Microsoft.OperationalInsights/workspaces` and
/// `workspaces/tables` (C# `AzureApiVersions.LogAnalytics`).
pub const LOG_ANALYTICS_API_VERSION: &str = "2025-07-01";

/// Pinned ARM api-version for `Microsoft.Insights/dataCollectionRules` (latest GA;
/// C# `AzureApiVersions.DataCollectionRules`). ARM rejects an api-version the
/// provider does not publish, so each resource type uses its own.
pub const DATA_COLLECTION_RULES_API_VERSION: &str = "2024-03-11";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcrTemplateOptions {
    pub rule_name: String,
    pub plan: String,
    pub retention_in_days: i32,
    /// ISM requires event logs to be searchable for at least 12 months.
    pub total_retention_in_days: i32,
    pub schema: SentinelSchema,
}

impl Default for DcrTemplateOptions {
    fn default() -> Self {
        Self {
            rule_name: "bower-dcr".to_owned(),
            plan: "Analytics".to_owned(),
            retention_in_days: 90,
            total_retention_in_days: 365,
            schema: SentinelSchema::default(),
        }
    }
}

/// Generates the template as a JSON object with the C# property order.
pub fn generate(options: &DcrTemplateOptions) -> Result<Value, DcrError> {
    if options.total_retention_in_days < options.retention_in_days {
        return Err(DcrError::InvalidArgument(
            "Total retention cannot be shorter than interactive retention.".to_owned(),
        ));
    }

    let schema = &options.schema;
    let table_columns: Vec<Value> = schema
        .table_columns
        .iter()
        .map(|column| json!({ "name": column.name, "type": SentinelSchema::table_type(&column.column_type) }))
        .collect();
    let stream_columns: Vec<Value> = schema
        .stream_columns
        .iter()
        .map(|column| json!({ "name": column.name, "type": column.column_type }))
        .collect();
    let mut declarations = Map::new();
    declarations.insert(
        schema.stream_name.clone(),
        json!({ "columns": stream_columns }),
    );
    let rule = &options.rule_name;
    let table = &schema.table_name;

    Ok(json!({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceName": { "type": "string" },
            "location": { "type": "string", "defaultValue": "[resourceGroup().location]" }
        },
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/workspaces/tables",
                "apiVersion": LOG_ANALYTICS_API_VERSION,
                "name": format!("[format('{{0}}/{table}', parameters('workspaceName'))]"),
                "properties": {
                    "plan": options.plan,
                    "retentionInDays": options.retention_in_days,
                    "totalRetentionInDays": options.total_retention_in_days,
                    "schema": { "name": table, "columns": table_columns }
                }
            },
            {
                "type": "Microsoft.Insights/dataCollectionRules",
                "apiVersion": DATA_COLLECTION_RULES_API_VERSION,
                "name": rule,
                "location": "[parameters('location')]",
                // Direct kind exposes its own logs ingestion endpoint; no DCE needed
                // unless Private Link is used.
                "kind": "Direct",
                "dependsOn": [
                    format!("[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspaceName'), '{table}')]")
                ],
                "properties": {
                    "streamDeclarations": Value::Object(declarations),
                    "destinations": {
                        "logAnalytics": [
                            {
                                "name": "BowerWorkspace",
                                "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
                            }
                        ]
                    },
                    "dataFlows": [
                        {
                            "streams": [schema.stream_name],
                            "destinations": ["BowerWorkspace"],
                            "outputStream": schema.output_stream(),
                            "transformKql": schema.transform_kql()
                        }
                    ]
                }
            }
        ],
        "outputs": {
            "logsIngestionEndpoint": {
                "type": "string",
                "value": format!("[reference(resourceId('Microsoft.Insights/dataCollectionRules', '{rule}'), '{DATA_COLLECTION_RULES_API_VERSION}').endpoints.logsIngestion]")
            },
            "dataCollectionRuleImmutableId": {
                "type": "string",
                "value": format!("[reference(resourceId('Microsoft.Insights/dataCollectionRules', '{rule}'), '{DATA_COLLECTION_RULES_API_VERSION}').immutableId]")
            },
            "streamName": { "type": "string", "value": schema.stream_name }
        }
    }))
}

/// The template as `ToJsonString(new JsonSerializerOptions { WriteIndented = true })`
/// writes it: what `bower dcr generate` prints and packs embed as `dcr/bower-dcr.json`.
pub fn generate_json(options: &DcrTemplateOptions) -> Result<String, DcrError> {
    let template = generate(options)?;
    Ok(to_indented_string(&template).expect("JSON values always serialize"))
}
