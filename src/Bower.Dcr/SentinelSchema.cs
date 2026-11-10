using System.Text.Json.Nodes;

namespace Bower.Dcr;

/// <summary>A column in the incoming stream (Bower envelope JSON, camelCase).</summary>
public sealed record StreamColumn(string Name, string Type);

/// <summary>A column in the destination Log Analytics table and how the transform fills it.</summary>
public sealed record TableColumn(string Name, string Type, string Expression);

/// <summary>
/// The single source of truth for how Bower envelopes land in Sentinel. The DCR
/// generator, drift check, ingestion preflight and Bicep template all follow it.
/// Evolve additively: never rename or retype an existing column.
/// </summary>
public sealed record SentinelSchema(
    string StreamName,
    string TableName,
    IReadOnlyList<StreamColumn> StreamColumns,
    IReadOnlyList<TableColumn> TableColumns,
    string SchemaVersionFilter)
{
    /// <summary>Default Bower security table.</summary>
    public static SentinelSchema Default { get; } = new(
        "Custom-BowerSecurity",
        "BowerSecurity_CL",
        [
            new("schemaVersion", "string"),
            new("eventId", "string"),
            new("eventOriginalId", "string"),
            new("timeGenerated", "datetime"),
            new("eventCategory", "string"),
            new("eventType", "string"),
            new("eventAction", "string"),
            new("eventResult", "string"),
            new("eventSeverity", "string"),
            new("application", "dynamic"),
            new("actor", "dynamic"),
            new("source", "dynamic"),
            new("request", "dynamic"),
            new("security", "dynamic"),
            new("collector", "dynamic"),
            new("labels", "dynamic"),
            new("privacy", "dynamic"),
            new("timeObserved", "datetime"),
            new("eventOutcomeReason", "string"),
            new("target", "dynamic"),
            new("change", "dynamic"),
            new("attributes", "dynamic")
        ],
        [
            new("TimeGenerated", "datetime", "timeGenerated"),
            new("EventId", "string", "substring(tostring(eventId), 0, 128)"),
            new("EventOriginalId", "string", "substring(tostring(eventOriginalId), 0, 256)"),
            new("EventCategory", "string", "substring(tostring(eventCategory), 0, 128)"),
            new("EventType", "string", "substring(tostring(eventType), 0, 128)"),
            new("EventAction", "string", "substring(tostring(eventAction), 0, 128)"),
            new("EventResult", "string", "substring(tostring(eventResult), 0, 32)"),
            new("EventSeverity", "string", "substring(tostring(eventSeverity), 0, 32)"),
            new("ApplicationName", "string", "substring(tostring(application.name), 0, 128)"),
            new("ApplicationEnvironment", "string", "substring(tostring(application.environment), 0, 64)"),
            new("ActorUserId", "string", "substring(tostring(actor.userId), 0, 256)"),
            new("ActorUsername", "string", "substring(tostring(actor.username), 0, 256)"),
            new("SourceIpAddress", "string", "substring(tostring(source.ipAddress), 0, 64)"),
            new("CorrelationId", "string", "substring(tostring(request.correlationId), 0, 256)"),
            new("PolicyId", "string", "substring(tostring(security.policyId), 0, 128)"),
            new("PolicyVersion", "string", "substring(tostring(security.policyVersion), 0, 32)"),
            new("PolicyHash", "string", "substring(tostring(security.policyHash), 0, 128)"),
            new("ValueScore", "int", "toint(security.valueScore)"),
            new("CollectorId", "string", "substring(tostring(collector.id), 0, 128)"),
            new("PrivacyDetected", "dynamic", "privacy.detected"),
            new("Labels", "dynamic", "labels"),
            new("RawEnvelope", "dynamic", "pack_all()"),
            new("TimeObserved", "datetime", "timeObserved"),
            new("EventOutcomeReason", "string", "substring(tostring(eventOutcomeReason), 0, 1024)"),
            new("Target", "dynamic", "target"),
            new("Change", "dynamic", "change"),
            new("Attributes", "dynamic", "attributes"),
            // Additive (#228, #253): where the event entered Bower, set by Bower, never the producer.
            new("Origin", "dynamic", "collector.origin")
        ],
        "1.0.0");

    /// <summary>The KQL transformation that maps the stream onto the table.</summary>
    public string TransformKql()
    {
        IEnumerable<string> projections = TableColumns.Select(column => $"    {column.Name} = {column.Expression}");
        return $"source\n| where schemaVersion == \"{SchemaVersionFilter}\"\n| project\n{string.Join(",\n", projections)}";
    }

    public string OutputStream => $"Custom-{TableName}";

    /// <summary>
    /// The transform for Azure Monitor Agent's syslog collection (<c>deploy/bicep/ama-syslog-dcr.bicep</c>):
    /// keep only a message whose tag is <paramref name="processName"/> and whose text is, apart
    /// from surrounding white space, <paramref name="marker"/> followed by base64; decode it into
    /// the envelope <c>e</c>; then project the same columns as <see cref="TransformKql"/>, read
    /// from <c>e</c> instead of the stream. Not run against a live agent until the live run (#249).
    /// </summary>
    public string SyslogTransformKql(string marker, string processName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(marker);
        ArgumentException.ThrowIfNullOrWhiteSpace(processName);
        HashSet<string> stream = [.. StreamColumns.Select(column => column.Name)];
        HashSet<string> datetimes = [.. StreamColumns.Where(column => column.Type == "datetime").Select(column => column.Name)];
        IEnumerable<string> projections = TableColumns.Select(column =>
        {
            // Origin on this path is the machine the agent recorded, never the envelope's:
            // the agent sets Computer from the host, and a local sender cannot choose it.
            if (column.Name == "Origin")
            {
                return "    Origin = pack(\"kind\", \"ama-syslog\", \"host\", Computer)";
            }

            string expression = column.Expression == "pack_all()"
                ? "e"
                : System.Text.RegularExpressions.Regex.Replace(
                    column.Expression,
                    @"(?<![.\w])([A-Za-z_]\w*)(?![\w(])",
                    match => stream.Contains(match.Value) ? $"e.{match.Value}" : match.Value);
            // The stream types datetime columns; read from dynamic JSON they need converting.
            if (datetimes.Contains(column.Expression))
            {
                expression = $"todatetime({expression})";
            }

            return $"    {column.Name} = {expression}";
        });

        string quotedMarker = System.Text.RegularExpressions.Regex.Escape(marker);
        return string.Join('\n',
            "source",
            $"| where ProcessName == \"{processName}\"",
            $"| extend b64 = extract(@\"^\\s*{quotedMarker}([A-Za-z0-9+/]+={{0,2}})\\s*$\", 1, SyslogMessage)",
            "| where isnotempty(b64)",
            "| extend e = parse_json(base64_decodestring(b64))",
            $"| where tostring(e.schemaVersion) == \"{SchemaVersionFilter}\"",
            "| project",
            string.Join(",\n", projections));
    }

    /// <summary>Log Analytics table schema type names (dateTime) differ from DCR stream types (datetime).</summary>
    internal static string TableType(string type) => type == "datetime" ? "dateTime" : type;
}

public sealed record DcrTemplateOptions
{
    public string RuleName { get; init; } = "bower-dcr";

    public string Plan { get; init; } = "Analytics";

    public int RetentionInDays { get; init; } = 90;

    /// <summary>Total retention includes archive; it does not establish interactive searchability.</summary>
    public int TotalRetentionInDays { get; init; } = 365;

    public SentinelSchema Schema { get; init; } = SentinelSchema.Default;
}

/// <summary>Generates an ARM template for the Bower table and a Direct-kind DCR.</summary>
public static class DcrTemplateGenerator
{
    public static JsonObject Generate(DcrTemplateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.TotalRetentionInDays < options.RetentionInDays)
        {
            throw new ArgumentException("Total retention cannot be shorter than interactive retention.");
        }

        SentinelSchema schema = options.Schema;
        JsonArray tableColumns = new(schema.TableColumns
            .Select(column => (JsonNode)new JsonObject
            {
                ["name"] = column.Name,
                ["type"] = SentinelSchema.TableType(column.Type)
            })
            .ToArray());
        JsonArray streamColumns = new(schema.StreamColumns
            .Select(column => (JsonNode)new JsonObject { ["name"] = column.Name, ["type"] = column.Type })
            .ToArray());

        return new JsonObject
        {
            ["$schema"] = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            ["contentVersion"] = "1.0.0.0",
            ["parameters"] = new JsonObject
            {
                ["workspaceName"] = new JsonObject { ["type"] = "string" },
                ["location"] = new JsonObject
                {
                    ["type"] = "string",
                    ["defaultValue"] = "[resourceGroup().location]"
                }
            },
            ["resources"] = new JsonArray
            {
                (JsonNode)new JsonObject
                {
                    ["type"] = "Microsoft.OperationalInsights/workspaces/tables",
                    ["apiVersion"] = AzureApiVersions.LogAnalytics,
                    ["name"] = $"[format('{{0}}/{schema.TableName}', parameters('workspaceName'))]",
                    ["properties"] = new JsonObject
                    {
                        ["plan"] = options.Plan,
                        ["retentionInDays"] = options.RetentionInDays,
                        ["totalRetentionInDays"] = options.TotalRetentionInDays,
                        ["schema"] = new JsonObject
                        {
                            ["name"] = schema.TableName,
                            ["columns"] = tableColumns
                        }
                    }
                },
                (JsonNode)new JsonObject
                {
                    ["type"] = "Microsoft.Insights/dataCollectionRules",
                    ["apiVersion"] = AzureApiVersions.DataCollectionRules,
                    ["name"] = options.RuleName,
                    ["location"] = "[parameters('location')]",
                    // Direct kind exposes its own logs ingestion endpoint; no DCE needed
                    // unless Private Link is used.
                    ["kind"] = "Direct",
                    ["dependsOn"] = new JsonArray
                    {
                        (JsonNode)$"[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspaceName'), '{schema.TableName}')]"
                    },
                    ["properties"] = new JsonObject
                    {
                        ["streamDeclarations"] = new JsonObject
                        {
                            [schema.StreamName] = new JsonObject { ["columns"] = streamColumns }
                        },
                        ["destinations"] = new JsonObject
                        {
                            ["logAnalytics"] = new JsonArray
                            {
                                (JsonNode)new JsonObject
                                {
                                    ["name"] = "BowerWorkspace",
                                    ["workspaceResourceId"] =
                                        "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
                                }
                            }
                        },
                        ["dataFlows"] = new JsonArray
                        {
                            (JsonNode)new JsonObject
                            {
                                ["streams"] = new JsonArray { (JsonNode)schema.StreamName },
                                ["destinations"] = new JsonArray { (JsonNode)"BowerWorkspace" },
                                ["outputStream"] = schema.OutputStream,
                                ["transformKql"] = schema.TransformKql()
                            }
                        }
                    }
                }
            },
            ["outputs"] = new JsonObject
            {
                ["logsIngestionEndpoint"] = new JsonObject
                {
                    ["type"] = "string",
                    ["value"] = $"[reference(resourceId('Microsoft.Insights/dataCollectionRules', '{options.RuleName}'), '{AzureApiVersions.DataCollectionRules}').endpoints.logsIngestion]"
                },
                ["dataCollectionRuleImmutableId"] = new JsonObject
                {
                    ["type"] = "string",
                    ["value"] = $"[reference(resourceId('Microsoft.Insights/dataCollectionRules', '{options.RuleName}'), '{AzureApiVersions.DataCollectionRules}').immutableId]"
                },
                ["streamName"] = new JsonObject { ["type"] = "string", ["value"] = schema.StreamName }
            }
        };
    }
}
