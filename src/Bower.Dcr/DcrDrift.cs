using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Bower.Dcr;

public enum FindingLevel
{
    Info,
    Warning,
    Error
}

public sealed record DcrFinding(FindingLevel Level, string Code, string Detail);

/// <summary>
/// Compares deployed Azure resources (DCR and table JSON from ARM or `az ... show`)
/// with what Bower expects, and lints schemas and transformations for known traps.
/// </summary>
public static partial class DcrDrift
{
    /// <summary>Azure rejects transformations longer than this.</summary>
    public const int MaximumTransformLength = 15_360;

    private static readonly HashSet<string> ReservedColumns = new(
        ["TenantId", "Type", "SourceSystem", "MG", "ManagementGroupName", "Computer", "RawData",
         "_ResourceId", "_SubscriptionId", "_ItemId", "_IsBillable", "_BilledSize", "_TimeReceived"],
        StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<DcrFinding> CompareRule(string deployedRuleJson, SentinelSchema expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        List<DcrFinding> findings = [];
        JsonObject root = ParseObject(deployedRuleJson, "DCR");
        JsonObject properties = root["properties"] as JsonObject ?? root;

        string? kind = root["kind"]?.GetValue<string>();
        if (!string.Equals(kind, "Direct", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new(FindingLevel.Info, "rule-not-direct",
                $"DCR kind is '{kind ?? "(none)"}'. Bower expects 'Direct' so the rule exposes its own ingestion endpoint; a DCE is then needed only for Private Link."));
        }

        JsonObject? declarations = properties["streamDeclarations"] as JsonObject;
        JsonObject? stream = declarations?[expected.StreamName] as JsonObject;
        if (stream is null)
        {
            findings.Add(new(FindingLevel.Error, "stream-missing",
                $"Stream declaration '{expected.StreamName}' is not deployed."));
        }
        else
        {
            Dictionary<string, string> deployed = Columns(stream["columns"] as JsonArray);
            foreach (StreamColumn column in expected.StreamColumns)
            {
                if (!deployed.TryGetValue(column.Name, out string? type))
                {
                    findings.Add(new(FindingLevel.Error, "stream-column-missing",
                        $"Stream column '{column.Name}' is missing; the value is dropped at ingestion."));
                }
                else if (!TypesMatch(type, column.Type))
                {
                    findings.Add(new(FindingLevel.Error, "stream-column-type",
                        $"Stream column '{column.Name}' is '{type}', expected '{column.Type}'."));
                }
            }

            foreach (string extra in deployed.Keys.Except(expected.StreamColumns.Select(c => c.Name), StringComparer.Ordinal))
            {
                findings.Add(new(FindingLevel.Info, "stream-column-extra",
                    $"Stream column '{extra}' is deployed but Bower does not send it."));
            }
        }

        JsonObject? flow = (properties["dataFlows"] as JsonArray)?
            .OfType<JsonObject>()
            .FirstOrDefault(item => (item["streams"] as JsonArray)?
                .Any(name => string.Equals(name?.GetValue<string>(), expected.StreamName, StringComparison.Ordinal)) == true);
        if (flow is null)
        {
            findings.Add(new(FindingLevel.Error, "dataflow-missing",
                $"No data flow consumes '{expected.StreamName}'; ingested events are discarded."));
            return findings;
        }

        string? output = flow["outputStream"]?.GetValue<string>();
        if (!string.Equals(output, expected.OutputStream, StringComparison.Ordinal))
        {
            findings.Add(new(FindingLevel.Error, "output-stream",
                $"Data flow writes to '{output ?? "(none)"}', expected '{expected.OutputStream}'."));
        }

        string transform = flow["transformKql"]?.GetValue<string>() ?? "source";
        if (!string.Equals(Normalise(transform), Normalise(expected.TransformKql()), StringComparison.Ordinal))
        {
            findings.Add(new(FindingLevel.Warning, "transform-drift",
                "Deployed transformKql differs from the transformation Bower generates. Regenerate with `bower dcr generate` or review the change."));
        }

        findings.AddRange(LintTransform(transform));
        return findings;
    }

    public static IReadOnlyList<DcrFinding> CompareTable(string deployedTableJson, SentinelSchema expected, int minimumTotalRetentionDays = 365)
    {
        List<DcrFinding> findings = [];
        JsonObject root = ParseObject(deployedTableJson, "table");
        JsonObject properties = root["properties"] as JsonObject ?? root;
        JsonObject? schema = properties["schema"] as JsonObject;
        Dictionary<string, string> deployed = Columns(schema?["columns"] as JsonArray);
        foreach (TableColumn column in expected.TableColumns)
        {
            if (!deployed.TryGetValue(column.Name, out string? type))
            {
                findings.Add(new(FindingLevel.Error, "table-column-missing",
                    $"Table column '{column.Name}' is missing; the transformation cannot write it."));
            }
            else if (!TypesMatch(type, column.Type))
            {
                findings.Add(new(FindingLevel.Error, "table-column-type",
                    $"Table column '{column.Name}' is '{type}', expected '{column.Type}'."));
            }
        }

        int? total = ReadInt(properties, "totalRetentionInDays") ?? ReadInt(properties, "retentionInDays");
        if (total is null || total < minimumTotalRetentionDays)
        {
            findings.Add(new(FindingLevel.Warning, "retention-short",
                $"Total retention is {total?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"} days; ISM event logging guidance expects at least {minimumTotalRetentionDays}."));
        }

        return findings;
    }

    /// <summary>Validates table column names against Log Analytics naming rules.</summary>
    public static IReadOnlyList<DcrFinding> LintSchema(SentinelSchema schema)
    {
        List<DcrFinding> findings = [];
        if (!schema.TableName.EndsWith("_CL", StringComparison.Ordinal))
        {
            findings.Add(new(FindingLevel.Error, "table-name", "Custom tables must end in _CL."));
        }

        if (schema.TableColumns.FirstOrDefault(column => column.Name == "TimeGenerated") is not { Type: "datetime" })
        {
            findings.Add(new(FindingLevel.Error, "time-generated", "Tables need a TimeGenerated datetime column."));
        }

        foreach (TableColumn column in schema.TableColumns)
        {
            if (!ColumnName().IsMatch(column.Name) || ReservedColumns.Contains(column.Name))
            {
                findings.Add(new(FindingLevel.Error, "column-name",
                    $"Column '{column.Name}' is reserved or invalid (start with a letter; letters, digits, underscore; 45 characters max)."));
            }
        }

        return findings;
    }

    /// <summary>Flags transformation patterns that silently lose data.</summary>
    public static IReadOnlyList<DcrFinding> LintTransform(string transformKql)
    {
        List<DcrFinding> findings = [];
        if (transformKql.Length > MaximumTransformLength)
        {
            findings.Add(new(FindingLevel.Error, "transform-too-long",
                $"transformKql is {transformKql.Length} characters; Azure's limit is {MaximumTransformLength}."));
        }

        if (RegexParse().IsMatch(transformKql))
        {
            findings.Add(new(FindingLevel.Warning, "parse-regex-full-match",
                "`parse kind=regex` must match the whole value; a partial match leaves every extracted column empty without an error."));
        }

        foreach (Match match in ParseStatement().Matches(transformKql))
        {
            int columns = match.Value.Count(c => c == ':');
            if (columns > 10)
            {
                findings.Add(new(FindingLevel.Warning, "parse-too-many-columns",
                    "A `parse` statement extracts more than 10 columns; transformations support at most 10 per parse."));
            }
        }

        if (transformKql.Contains("| where", StringComparison.OrdinalIgnoreCase)
            && !transformKql.Contains("schemaVersion", StringComparison.Ordinal))
        {
            findings.Add(new(FindingLevel.Info, "filter-present",
                "The transformation filters rows. Filtered rows are dropped without an error; confirm the filter matches Bower's policy."));
        }

        return findings;
    }

    private static Dictionary<string, string> Columns(JsonArray? columns)
    {
        Dictionary<string, string> result = new(StringComparer.Ordinal);
        foreach (JsonObject column in columns?.OfType<JsonObject>() ?? [])
        {
            string? name = column["name"]?.GetValue<string>();
            string? type = column["type"]?.GetValue<string>();
            if (name is not null && type is not null)
            {
                result[name] = type;
            }
        }

        return result;
    }

    private static bool TypesMatch(string deployed, string expected) =>
        string.Equals(deployed, expected, StringComparison.OrdinalIgnoreCase);

    private static int? ReadInt(JsonObject properties, string name) =>
        properties[name] is JsonValue value && value.TryGetValue(out int result) ? result : null;

    private static string Normalise(string kql) => Whitespace().Replace(kql, " ").Trim();

    private static JsonObject ParseObject(string json, string what)
    {
        try
        {
            return JsonNode.Parse(json) as JsonObject
                ?? throw new InvalidDataException($"Deployed {what} JSON must be an object.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Deployed {what} JSON is invalid.", exception);
        }
    }

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex Whitespace();

    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_]{0,44}$", RegexOptions.CultureInvariant)]
    private static partial Regex ColumnName();

    [GeneratedRegex(@"parse\s+kind\s*=\s*regex", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RegexParse();

    [GeneratedRegex(@"\|\s*parse\b[^|]*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ParseStatement();
}
