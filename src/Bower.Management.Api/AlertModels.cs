namespace Bower.Management.Api;

/// <summary>One entry in the plain-language alert catalogue mapping internal codes to operator fixes.</summary>
public sealed record AlertCatalogueEntry(
    string ConditionId,
    string Severity,
    string Title,
    string PlainDescription,
    string SuggestedFix,
    string Page,
    IReadOnlyList<string> RelatedEventIds);

/// <summary>Request to mute one alert condition (fleet-wide or for one collector) with a required reason.</summary>
public sealed record AlertMuteRequest(
    string? ConditionId,
    string? CollectorId,
    int? DurationMinutes,
    string? Reason);

/// <summary>An active or historical audited alert mute.</summary>
public sealed record AlertMuteRecord(
    string Id,
    string ConditionId,
    string? CollectorId,
    string Reason,
    string MutedByObjectId,
    string MutedByName,
    DateTimeOffset MutedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? UnmutedAt,
    string? UnmutedByName);

/// <summary>Metadata-only status of configured notification channels (never URLs, paths or secrets).</summary>
public sealed record AlertChannelStatus(
    bool TeamsConfigured,
    bool EmailConfigured,
    bool ConsoleUrlConfigured,
    int DedupWindowMinutes);

/// <summary>Metadata-only outbound notification payload. Never contains raw event content or secrets.</summary>
public sealed record AlertNotificationMessage(
    string DedupKey,
    string ConditionId,
    string Severity,
    string Summary,
    string SuggestedFix,
    int AffectedCount,
    string? ConsoleAlertsUrl,
    DateTimeOffset DetectedAt);
