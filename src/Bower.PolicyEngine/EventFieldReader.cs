using System.Text.Json;
using Bower.Contracts;

namespace Bower.PolicyEngine;

internal static class EventFieldReader
{
    private const string LabelsPrefix = "labels.";
    private const string AttributesPrefix = "attributes.";

    public static bool HasValue(SecurityEventEnvelope value, string path)
    {
        // labels.<key> and attributes.<key> name one top-level entry; the key is the rest of
        // the path, matched ordinally (it may itself contain dots).
        if (path.StartsWith(LabelsPrefix, StringComparison.Ordinal))
        {
            return value.Labels is not null
                && value.Labels.TryGetValue(path[LabelsPrefix.Length..], out string? label)
                && Present(label);
        }

        if (path.StartsWith(AttributesPrefix, StringComparison.Ordinal))
        {
            return value.Attributes is not null
                && value.Attributes.TryGetValue(path[AttributesPrefix.Length..], out JsonElement attribute)
                && Present(attribute);
        }

        return path switch
        {
            "schemaVersion" => Present(value.SchemaVersion),
            "eventId" => Present(value.EventId),
            "eventOriginalId" => Present(value.EventOriginalId),
            "timeGenerated" => value.TimeGenerated != default,
            "eventCategory" => Present(value.EventCategory),
            "eventType" => Present(value.EventType),
            "eventAction" => Present(value.EventAction),
            "eventResult" => value.EventResult != EventResult.Unknown,
            "application.name" => Present(value.Application.Name),
            "application.environment" => Present(value.Application.Environment),
            "application.tenantId" => Present(value.Application.TenantId),
            "actor.userId" => Present(value.Actor?.UserId),
            "actor.username" => Present(value.Actor?.Username),
            "target.id" => Present(value.Target?.Id),
            "target.type" => Present(value.Target?.Type),
            "target.name" => Present(value.Target?.Name),
            "change.field" => Present(value.Change?.Field),
            "change.previousValue" => Present(value.Change?.PreviousValue),
            "change.newValue" => Present(value.Change?.NewValue),
            "source.ipAddress" => Present(value.Source?.IpAddress),
            "request.correlationId" => Present(value.Request?.CorrelationId),
            "request.traceId" => Present(value.Request?.TraceId),
            "eventOutcomeReason" => Present(value.EventOutcomeReason),
            _ => false
        };
    }

    /// <summary>
    /// String-valued paths a suppression key may use: identity and context fields plus
    /// <c>labels.&lt;key&gt;</c>. Times, results, ids and change values are excluded.
    /// </summary>
    private static readonly string[] SuppressionKeyPaths =
    [
        "eventCategory",
        "eventType",
        "eventAction",
        "eventOutcomeReason",
        "application.name",
        "application.environment",
        "application.tenantId",
        "actor.userId",
        "actor.username",
        "target.id",
        "target.type",
        "target.name",
        "change.field",
        "source.ipAddress",
        "request.correlationId",
        "request.traceId"
    ];

    public static bool IsSuppressionKey(string? path) =>
        path is not null
        && (SuppressionKeyPaths.Contains(path, StringComparer.Ordinal)
            || (path.StartsWith(LabelsPrefix, StringComparison.Ordinal) && path.Length > LabelsPrefix.Length));

    /// <summary>Value of a suppression key path; an absent value is the empty string.</summary>
    public static string GetSuppressionKeyValue(SecurityEventEnvelope value, string path)
    {
        if (path.StartsWith(LabelsPrefix, StringComparison.Ordinal))
        {
            return value.Labels is not null
                && value.Labels.TryGetValue(path[LabelsPrefix.Length..], out string? label)
                ? label ?? string.Empty
                : string.Empty;
        }

        return path switch
        {
            "eventCategory" => value.EventCategory,
            "eventType" => value.EventType,
            "eventAction" => value.EventAction,
            "eventOutcomeReason" => value.EventOutcomeReason,
            "application.name" => value.Application?.Name,
            "application.environment" => value.Application?.Environment,
            "application.tenantId" => value.Application?.TenantId,
            "actor.userId" => value.Actor?.UserId,
            "actor.username" => value.Actor?.Username,
            "target.id" => value.Target?.Id,
            "target.type" => value.Target?.Type,
            "target.name" => value.Target?.Name,
            "change.field" => value.Change?.Field,
            "source.ipAddress" => value.Source?.IpAddress,
            "request.correlationId" => value.Request?.CorrelationId,
            "request.traceId" => value.Request?.TraceId,
            _ => null
        } ?? string.Empty;
    }

    private static bool Present(string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }

    /// <summary>
    /// JSON null is absent and a string must be non-blank; numbers, booleans, objects and
    /// arrays are present.
    /// </summary>
    private static bool Present(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Undefined or JsonValueKind.Null => false,
        JsonValueKind.String => Present(value.GetString()),
        _ => true
    };
}
