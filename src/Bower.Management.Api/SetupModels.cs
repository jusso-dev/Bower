namespace Bower.Management.Api;

/// <summary>Onboarding wizard step identifiers, in order.</summary>
public static class SetupStepIds
{
    public const string SignIn = "sign-in";
    public const string Entra = "entra";
    public const string Destination = "destination";
    public const string Collector = "collector";
    public const string Probe = "probe";
    public const string Canary = "canary";
    public const string Proof = "proof";
}

/// <summary>Plain-language step states the console renders with text and icon, never colour alone.</summary>
public static class SetupStepStates
{
    public const string Complete = "complete";
    public const string Attention = "attention";
    public const string Blocked = "blocked";
    public const string InProgress = "in-progress";
    public const string NotStarted = "not-started";
}

public static class SetupCheckStates
{
    public const string Pass = "pass";
    public const string Warn = "warn";
    public const string Fail = "fail";
    public const string Pending = "pending";
}

/// <summary>One validation result. Message and fix are fixed Bower text, never raw Azure or framework detail.</summary>
public sealed record SetupCheck(string Id, string State, string Message, string? Fix);

public sealed record SetupStep(
    string Id,
    string State,
    IReadOnlyList<SetupCheck> Checks,
    string? UpdatedBy,
    DateTimeOffset? UpdatedAt);

public sealed record SetupDestination(
    string WorkspaceId,
    string? WorkspaceResourceId,
    string? DcrResourceId,
    string Table,
    string UpdatedBy,
    DateTimeOffset UpdatedAt);

public sealed record SetupProbeChoice(string Profile, string UpdatedBy, DateTimeOffset UpdatedAt);

/// <summary>A probe profile the canary can run: generic intake or a repo-owned parser fixture.</summary>
public sealed record SetupProbeOption(
    string Profile,
    string Title,
    string Description,
    string? PackId,
    string? ExpectedEventType);

/// <summary>Server canary configuration as metadata only: never the token, key or file paths.</summary>
public sealed record SetupCanaryConfiguration(
    bool Configured,
    bool VerifierConfigured,
    bool SigningConfigured,
    string? CollectorHost,
    int TimeoutMinutes);

/// <summary>
/// One canary run. <see cref="CollectorAccepted"/> is collector acceptance only; delivery is
/// proven only when <see cref="Mode"/> is <c>verified</c>.
/// </summary>
public sealed record SetupCanaryRun(
    string Id,
    string Profile,
    string State,
    string? Mode,
    string? Outcome,
    string? Message,
    string? Fix,
    bool CollectorAccepted,
    string? EventId,
    string WorkspaceId,
    string Table,
    double? LatencySeconds,
    bool HasSignature,
    bool HasBundle,
    string RequestedBy,
    DateTimeOffset RequestedAt,
    DateTimeOffset? CompletedAt);

public static class SetupCanaryRunStates
{
    public const string Running = "running";
    public const string Completed = "completed";
    public const string Interrupted = "interrupted";
}

public sealed record SetupStatus(
    bool CanChange,
    IReadOnlyList<SetupStep> Steps,
    SetupDestination? Destination,
    SetupProbeChoice? Probe,
    IReadOnlyList<SetupProbeOption> ProbeOptions,
    SetupCanaryConfiguration Canary,
    SetupCanaryRun? LatestRun);

public sealed record SetupDestinationRequest(
    string? WorkspaceId,
    string? WorkspaceResourceId,
    string? DcrResourceId,
    string? Table);

public sealed record SetupProbeRequest(string? Profile);

public sealed record SetupCheckResult(IReadOnlyList<SetupCheck> Checks, DateTimeOffset CheckedAt);
