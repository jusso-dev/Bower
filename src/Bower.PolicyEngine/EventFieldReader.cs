using Bower.Contracts;

namespace Bower.PolicyEngine;

internal static class EventFieldReader
{
    public static bool HasValue(SecurityEventEnvelope value, string path)
    {
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
            "source.ipAddress" => Present(value.Source?.IpAddress),
            "request.correlationId" => Present(value.Request?.CorrelationId),
            "request.traceId" => Present(value.Request?.TraceId),
            "eventOutcomeReason" => Present(value.EventOutcomeReason),
            _ => false
        };
    }

    private static bool Present(string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }
}
