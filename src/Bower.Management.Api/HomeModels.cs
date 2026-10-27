namespace Bower.Management.Api;

/// <summary>
/// Redaction counters a collector reports on its heartbeat: queued events per detector type
/// since <see cref="ObservedSince"/> (its process start). Type ids and counts only.
/// </summary>
public sealed record RedactionReport(DateTimeOffset ObservedSince, IReadOnlyList<RedactionReportCount> Counts);

/// <summary>Queued events in which a detector type removed or masked at least one value.</summary>
public sealed record RedactionReportCount(string Type, long Events);

/// <summary>Traffic-light states. The console always pairs them with words and an icon.</summary>
public static class HomeStates
{
    public const string Green = "green";
    public const string Amber = "amber";
    public const string Red = "red";
}

/// <summary>Sentinel proof states. Only <c>verified</c> is destination query proof.</summary>
public static class HomeProofStates
{
    public const string Verified = "verified";
    public const string Simulated = "simulated";
    public const string InProgress = "in-progress";
    public const string NotProven = "not-proven";
}

/// <summary>What to do, in plain English, and the console page (a fixed route) where it is done.</summary>
public sealed record HomeFix(string Action, string Page);

/// <summary>One thing that needs attention. Fixed Bower text, never raw collector or Azure detail.</summary>
public sealed record HomeAttention(string Id, string State, string Message, HomeFix Fix, int Count);

/// <summary>
/// One collector group (environment): the worst condition decides the state and the reason.
/// <see cref="OtherIssues"/> counts further conditions the reason does not mention.
/// </summary>
public sealed record HomeGroup(
    string Name,
    string State,
    int Collectors,
    int Healthy,
    string Reason,
    HomeFix? Fix,
    int OtherIssues);

/// <summary>
/// Whether a setup test event was found in Sentinel by query. <see cref="At"/> is when the
/// proof (or the last attempt) finished. Collector acceptance is never shown as proof.
/// </summary>
public sealed record HomeSentinelProof(string State, string Message, DateTimeOffset? At, HomeFix? Fix);

/// <summary>
/// "Is my data flowing?" <see cref="Sending"/> collectors are checking in with working
/// delivery; <see cref="LastAcceptedAt"/> is the latest output acceptance any collector
/// reported, which is not Sentinel proof.
/// </summary>
public sealed record HomeFlow(
    string State,
    string Summary,
    int Sending,
    int Enrolled,
    DateTimeOffset? LastAcceptedAt,
    HomeSentinelProof Proof);

/// <summary>Queued events this week in which Bower removed one kind of sensitive detail.</summary>
public sealed record HomeRedaction(string Type, string Label, long Events);

/// <summary>
/// "What was protected this week?" Counts by detector type only, never values.
/// <see cref="CollectorsNotReporting"/> are working collectors whose version does not report
/// counts, so the totals can be low.
/// </summary>
public sealed record HomeProtection(
    DateTimeOffset Since,
    string Summary,
    IReadOnlyList<HomeRedaction> ByType,
    int CollectorsReporting,
    int CollectorsNotReporting);

/// <summary>The plain-English home view, computed server side from management state at query time.</summary>
public sealed record HomeRecord(
    DateTimeOffset GeneratedAt,
    string State,
    HomeFlow Flow,
    HomeProtection Protection,
    IReadOnlyList<HomeAttention> Attention,
    IReadOnlyList<HomeGroup> Groups,
    int GroupsTotal);
