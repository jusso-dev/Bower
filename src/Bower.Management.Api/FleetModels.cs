namespace Bower.Management.Api;

/// <summary>
/// Plain fleet states, one per collector. The console shows the label the API sends, so a
/// new state (for example a relay's own topology state) needs no console change.
/// </summary>
public static class FleetStates
{
    public const string Healthy = "healthy";
    public const string BehindRelay = "behind-relay";
    public const string WaitingForApproval = "waiting-for-approval";
    public const string NotHeardFrom = "not-heard-from";
    public const string CannotDeliver = "cannot-deliver";
    public const string NeedsCheck = "needs-check";
    public const string OldVersion = "old-version";
    public const string Paused = "paused";
    public const string Removed = "removed";

    /// <summary>
    /// Reserved for air-gapped sites (#111): a collector that reports by signed import bundle
    /// rather than heartbeat. Nothing produces it until imports exist.
    /// </summary>
    public const string OfflineSite = "offline-site";
}

/// <summary>Traffic lights for the fleet view: the home view's three plus <c>none</c> for removed collectors.</summary>
public static class FleetLights
{
    public const string None = "none";
}

/// <summary>How a collector's events leave its network, from its last heartbeat's output report.</summary>
public static class FleetPaths
{
    public const string Direct = "direct";
    public const string Relay = "relay";
}

/// <summary>
/// What to do, in plain English. <see cref="Page"/> is a fixed console route where it is
/// done, or null when the action happens on the machine itself.
/// </summary>
public sealed record FleetFix(string Action, string? Page);

/// <summary>
/// One collector in plain English. <see cref="State"/>, <see cref="Label"/>,
/// <see cref="Reason"/> and <see cref="Fix"/> are fixed Bower text chosen server side;
/// <see cref="OtherIssues"/> counts further conditions the reason does not mention.
/// <see cref="Path"/> is null until the collector reports an output.
/// </summary>
public sealed record FleetCollector(
    string Id,
    string MachineName,
    string Site,
    string Version,
    string State,
    string Label,
    string Light,
    string Reason,
    FleetFix? Fix,
    int OtherIssues,
    string Connectivity,
    string? Path,
    DateTimeOffset LastSeenAt);

/// <summary>How many collectors are in one plain state, in catalogue order (worst first).</summary>
public sealed record FleetStateCount(string State, string Label, string Light, int Collectors);

/// <summary>A site (the environment a collector reports) and how many collectors it has.</summary>
public sealed record FleetSiteCount(string Name, int Collectors);

/// <summary>
/// The plain-English fleet view, computed server side at query time from collector records,
/// heartbeat v2 connectivity and credential state. Collectors are sorted most urgent first.
/// <see cref="NewestVersion"/> is the newest stable Bower version a recently connected collector reports.
/// </summary>
public sealed record FleetRecord(
    DateTimeOffset GeneratedAt,
    IReadOnlyList<FleetCollector> Collectors,
    IReadOnlyList<FleetStateCount> States,
    IReadOnlyList<FleetSiteCount> Sites,
    string? NewestVersion);
