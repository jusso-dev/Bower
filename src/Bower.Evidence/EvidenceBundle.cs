using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Bower.Evidence;

public static class EvidenceModes
{
    /// <summary>The canary was found in Sentinel by query.</summary>
    public const string Verified = "verified";

    /// <summary>The canary was not found before the timeout, or a check failed.</summary>
    public const string Failed = "failed";

    /// <summary>No destination query was run. Never counts as delivery proof.</summary>
    public const string Simulated = "simulated";
}

public sealed record CanaryRecord(
    [property: JsonPropertyName("eventId")] string EventId,
    [property: JsonPropertyName("sentAt")] DateTimeOffset SentAt,
    [property: JsonPropertyName("collectorHost")] string CollectorHost,
    [property: JsonPropertyName("collectorStatus")] int CollectorStatus,
    [property: JsonPropertyName("collectorDecision")] string? CollectorDecision,
    [property: JsonPropertyName("policyId")] string? PolicyId);

public sealed record ArrivalRecord(
    [property: JsonPropertyName("found")] bool Found,
    [property: JsonPropertyName("workspaceId")] string? WorkspaceId,
    [property: JsonPropertyName("table")] string Table,
    [property: JsonPropertyName("query")] string? Query,
    [property: JsonPropertyName("attempts")] int Attempts,
    [property: JsonPropertyName("timeGenerated")] DateTimeOffset? TimeGenerated,
    [property: JsonPropertyName("ingestionTime")] DateTimeOffset? IngestionTime,
    [property: JsonPropertyName("latencySeconds")] double? LatencySeconds,
    [property: JsonPropertyName("rowPolicyHash")] string? RowPolicyHash,
    [property: JsonPropertyName("queryError")] string? QueryError);

public sealed record RetentionRecord(
    [property: JsonPropertyName("plan")] string? Plan,
    [property: JsonPropertyName("interactiveDays")] int? InteractiveDays,
    [property: JsonPropertyName("totalDays")] int? TotalDays,
    [property: JsonPropertyName("workspaceRegion")] string? WorkspaceRegion);

public sealed record ControlRecord(
    [property: JsonPropertyName("framework")] string Framework,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("requirement")] string Requirement,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("evidence")] string Evidence);

/// <summary>A signed, metadata-only record that Bower delivery was proven (or not).</summary>
public sealed record EvidenceBundle(
    [property: JsonPropertyName("schema")] string Schema,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("generatedAt")] DateTimeOffset GeneratedAt,
    [property: JsonPropertyName("tool")] string Tool,
    [property: JsonPropertyName("canary")] CanaryRecord Canary,
    [property: JsonPropertyName("arrival")] ArrivalRecord Arrival,
    [property: JsonPropertyName("retention")] RetentionRecord? Retention,
    [property: JsonPropertyName("ingestionErrorsLastHour")] long? IngestionErrorsLastHour,
    [property: JsonPropertyName("controls")] IReadOnlyList<ControlRecord> Controls,
    [property: JsonPropertyName("limitations")] IReadOnlyList<string> Limitations)
{
    public const string CurrentSchema = "bower.evidence/v1";
}

/// <summary>The bundle plus a detached signature over its canonical JSON.</summary>
public sealed record SignedEvidence(
    [property: JsonPropertyName("bundle")] JsonObject Bundle,
    [property: JsonPropertyName("signature")] Bower.Integrity.DetachedSignature? Signature);
