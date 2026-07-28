using System.Globalization;
using System.Text.Json;

namespace Bower.Dcr;

public sealed record DcrDataSource(
    string Name,
    string Kind,
    IReadOnlyList<string> Streams,
    IReadOnlyList<string> XPathQueries,
    bool Enabled);

public sealed record DcrDocument(
    string Id,
    string Name,
    string? WorkspaceId,
    IReadOnlyList<DcrDataSource> DataSources,
    IReadOnlyList<string> Destinations);

public sealed record DcrRecommendation(
    string Code,
    string Severity,
    string Title,
    string Detail,
    double? EstimatedMonthlyGbSaved);

public sealed record DcrAssessmentReport(
    string DcrId,
    string DcrName,
    int CoverageScore,
    int HealthScore,
    double? EstimatedMonthlyIngestionGb,
    double? EstimatedMonthlySavingsGb,
    IReadOnlyList<DcrRecommendation> Recommendations,
    DateTimeOffset AssessedAt);

public static class DcrDocumentParser
{
    public static DcrDocument Parse(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        string id = ReadString(root, "id") ?? ReadString(root, "name") ?? "unknown";
        string name = ReadString(root, "name") ?? id;
        string? workspace = ReadString(root, "workspaceId")
            ?? ReadNested(root, "destinations", "logAnalytics", "workspaceResourceId");

        List<DcrDataSource> sources = [];
        if (root.TryGetProperty("dataSources", out JsonElement dataSources))
        {
            if (dataSources.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in dataSources.EnumerateArray())
                {
                    sources.Add(ParseSource(item));
                }
            }
            else if (dataSources.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty property in dataSources.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement item in property.Value.EnumerateArray())
                        {
                            sources.Add(ParseSource(item, property.Name));
                        }
                    }
                }
            }
        }

        List<string> destinations = [];
        if (root.TryGetProperty("destinations", out JsonElement destNode))
        {
            if (destNode.ValueKind == JsonValueKind.Array)
            {
                destinations.AddRange(
                    destNode.EnumerateArray()
                        .Select(item => ReadString(item, "name") ?? item.ToString())
                        .Where(item => !string.IsNullOrWhiteSpace(item))!);
            }
            else if (destNode.ValueKind == JsonValueKind.Object)
            {
                destinations.AddRange(destNode.EnumerateObject().Select(item => item.Name));
            }
        }

        return new DcrDocument(id, name, workspace, sources, destinations);
    }

    private static DcrDataSource ParseSource(JsonElement item, string? fallbackKind = null)
    {
        string name = ReadString(item, "name") ?? ReadString(item, "streams") ?? "source";
        string kind = ReadString(item, "kind")
            ?? ReadString(item, "type")
            ?? fallbackKind
            ?? "unknown";
        List<string> streams = ReadStringArray(item, "streams");
        List<string> xpaths = ReadStringArray(item, "xPathQueries");
        if (xpaths.Count == 0)
        {
            xpaths = ReadStringArray(item, "xpathQueries");
        }

        bool enabled = !item.TryGetProperty("enabled", out JsonElement enabledNode)
            || enabledNode.ValueKind != JsonValueKind.False;
        return new DcrDataSource(name, kind, streams, xpaths, enabled);
    }

    private static string? ReadString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property))
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
    }

    private static string? ReadNested(JsonElement element, params string[] path)
    {
        JsonElement current = element;
        foreach (string segment in path)
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(segment, out current))
            {
                return null;
            }
        }

        return current.ValueKind == JsonValueKind.String ? current.GetString() : current.ToString();
    }

    private static List<string> ReadStringArray(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) ||
            property.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return property.EnumerateArray()
            .Select(item => item.GetString() ?? item.ToString())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToList()!;
    }
}

public static class DcrOptimiser
{
    private static readonly string[] RecommendedSecurityEventIds =
    [
        "4624", "4625", "4648", "4672", "4688", "4720", "4728", "4732", "1102"
    ];

    private static readonly string[] RecommendedSysmonIds = ["1", "3", "11"];

    public static DcrAssessmentReport Assess(
        DcrDocument document,
        double? currentMonthlyIngestionGb = null,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(document);
        DateTimeOffset assessedAt = now ?? DateTimeOffset.UtcNow;
        List<DcrRecommendation> recommendations = [];

        // Duplicate names
        IEnumerable<IGrouping<string, DcrDataSource>> duplicates = document.DataSources
            .GroupBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1);
        foreach (IGrouping<string, DcrDataSource> group in duplicates)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "duplicate-source",
                    "medium",
                    "Duplicate collection sources",
                    $"Data source name '{group.Key}' appears {group.Count()} times.",
                    currentMonthlyIngestionGb is null ? null : currentMonthlyIngestionGb * 0.05));
        }

        bool hasWindowsEvents = document.DataSources.Any(item =>
            item.Kind.Contains("windows", StringComparison.OrdinalIgnoreCase)
            || item.Streams.Any(stream => stream.Contains("WindowsEvent", StringComparison.OrdinalIgnoreCase)));

        bool hasWildcardSecurity = document.DataSources.Any(item =>
            item.XPathQueries.Any(query =>
                query.Contains("Security!*", StringComparison.OrdinalIgnoreCase)
                || query.Contains("*[System[(EventID='*')]]", StringComparison.OrdinalIgnoreCase)));

        if (hasWildcardSecurity)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "broad-security-events",
                    "high",
                    "Replace Security Event * with targeted Event IDs",
                    "Broad Security channel collection inflates ingestion. Prefer targeted Event IDs.",
                    currentMonthlyIngestionGb is null ? null : currentMonthlyIngestionGb * 0.25));
        }

        string joinedXPath = string.Join(' ', document.DataSources.SelectMany(item => item.XPathQueries));
        string[] missingSecurityIds = RecommendedSecurityEventIds
            .Where(id => !joinedXPath.Contains(id, StringComparison.Ordinal))
            .ToArray();
        if (hasWindowsEvents && missingSecurityIds.Length > 0)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "missing-security-event-ids",
                    "medium",
                    "Missing high-value Windows Event IDs",
                    $"Consider collecting Event IDs: {string.Join(", ", missingSecurityIds)}.",
                    null));
        }

        bool hasSysmon = document.DataSources.Any(item =>
            item.Name.Contains("sysmon", StringComparison.OrdinalIgnoreCase)
            || item.XPathQueries.Any(query => query.Contains("Sysmon", StringComparison.OrdinalIgnoreCase))
            || item.Streams.Any(stream => stream.Contains("Sysmon", StringComparison.OrdinalIgnoreCase)));
        if (!hasSysmon)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "missing-sysmon",
                    "high",
                    "Missing Sysmon configuration",
                    "Collect Sysmon Event IDs 1, 3 and 11 for process, network and file visibility.",
                    null));
        }
        else
        {
            string[] missingSysmon = RecommendedSysmonIds
                .Where(id => !joinedXPath.Contains($"EventID={id}", StringComparison.OrdinalIgnoreCase)
                    && !joinedXPath.Contains($"EventID='{id}'", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (missingSysmon.Length > 0)
            {
                recommendations.Add(
                    new DcrRecommendation(
                        "incomplete-sysmon",
                        "medium",
                        "Incomplete Sysmon Event IDs",
                        $"Ensure Sysmon Event IDs {string.Join(", ", RecommendedSysmonIds)} are collected.",
                        null));
            }
        }

        bool hasDefender = document.DataSources.Any(item =>
            item.Name.Contains("defender", StringComparison.OrdinalIgnoreCase)
            || item.Streams.Any(stream => stream.Contains("Microsoft-Windows-Windows Defender", StringComparison.OrdinalIgnoreCase)));
        if (!hasDefender)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "missing-defender",
                    "medium",
                    "Disabled or missing Defender telemetry",
                    "Enable Defender / XDR connector or collect Defender operational channels.",
                    null));
        }

        bool hasIis = document.DataSources.Any(item =>
            item.Name.Contains("iis", StringComparison.OrdinalIgnoreCase)
            || item.Streams.Any(stream => stream.Contains("IIS", StringComparison.OrdinalIgnoreCase)));
        if (!hasIis)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "missing-iis",
                    "low",
                    "Missing IIS logs",
                    "If web workloads exist, collect IIS W3C logs with path filters.",
                    null));
        }

        if (document.DataSources.Any(item => !item.Enabled))
        {
            recommendations.Add(
                new DcrRecommendation(
                    "disabled-sources",
                    "medium",
                    "Disabled data sources present",
                    "Review disabled sources for accidental coverage gaps or stale configuration.",
                    null));
        }

        if (document.Destinations.Count == 0)
        {
            recommendations.Add(
                new DcrRecommendation(
                    "missing-destination",
                    "critical",
                    "No destinations configured",
                    "DCR has no Log Analytics / destination association.",
                    null));
        }

        int healthScore = 100;
        healthScore -= recommendations.Count(item => item.Severity == "critical") * 30;
        healthScore -= recommendations.Count(item => item.Severity == "high") * 15;
        healthScore -= recommendations.Count(item => item.Severity == "medium") * 8;
        healthScore -= recommendations.Count(item => item.Severity == "low") * 3;
        healthScore = Math.Clamp(healthScore, 0, 100);

        int coveragePoints = 0;
        if (hasWindowsEvents) coveragePoints += 30;
        if (hasSysmon) coveragePoints += 30;
        if (hasDefender) coveragePoints += 20;
        if (hasIis) coveragePoints += 10;
        if (document.Destinations.Count > 0) coveragePoints += 10;
        int coverageScore = Math.Clamp(coveragePoints, 0, 100);

        double? savings = recommendations
            .Where(item => item.EstimatedMonthlyGbSaved is not null)
            .Select(item => item.EstimatedMonthlyGbSaved!.Value)
            .DefaultIfEmpty()
            .Sum();
        if (savings == 0)
        {
            savings = null;
        }

        return new DcrAssessmentReport(
            document.Id,
            document.Name,
            coverageScore,
            healthScore,
            currentMonthlyIngestionGb,
            savings,
            recommendations,
            assessedAt);
    }

    public static string ExportMarkdown(DcrAssessmentReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        System.Text.StringBuilder builder = new();
        builder.AppendLine(CultureInfo.InvariantCulture, $"# DCR Assessment: {report.DcrName}");
        builder.AppendLine();
        builder.AppendLine(CultureInfo.InvariantCulture, $"- DCR id: `{report.DcrId}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Coverage score: **{report.CoverageScore}**");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Health score: **{report.HealthScore}**");
        if (report.EstimatedMonthlyIngestionGb is not null)
        {
            builder.AppendLine(
                CultureInfo.InvariantCulture,
                $"- Current monthly ingestion: **{report.EstimatedMonthlyIngestionGb:0.##} GB**");
        }

        if (report.EstimatedMonthlySavingsGb is not null)
        {
            builder.AppendLine(
                CultureInfo.InvariantCulture,
                $"- Estimated monthly savings: **{report.EstimatedMonthlySavingsGb:0.##} GB**");
        }

        builder.AppendLine();
        builder.AppendLine("## Recommendations");
        if (report.Recommendations.Count == 0)
        {
            builder.AppendLine("- No issues detected.");
        }
        else
        {
            foreach (DcrRecommendation recommendation in report.Recommendations)
            {
                builder.AppendLine(
                    CultureInfo.InvariantCulture,
                    $"- **[{recommendation.Severity}] {recommendation.Title}** ({recommendation.Code}): {recommendation.Detail}");
            }
        }

        return builder.ToString();
    }
}
