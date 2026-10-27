using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Core;
using Bower.Jobs;

namespace Bower.Collector;

// Collector HTTP bodies. These named records replace anonymous types so serialization is
// source generated (Native AOT). Property names and declaration order are the wire
// contract: with Web defaults they serialize to the same camelCase JSON as before.

internal sealed record ErrorResponse(string Error);

internal sealed record HealthResponse(string Status);

internal sealed record IngestResponse(
    string? EventId,
    string Decision,
    bool Queued,
    bool Duplicate,
    IReadOnlyList<string> Reasons,
    IngestPolicyResponse? Policy)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Remediation { get; init; }

    /// <summary>Present only when true: accepted, but counted instead of queued.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Suppressed { get; init; }
}

internal sealed record IngestPolicyResponse(string PolicyId, string PolicyVersion, string PolicyHash, int Score);

internal sealed record StatusResponse(
    string Status,
    StatusPolicyResponse Policy,
    LedgerResponse Ledger,
    StatusQueueResponse Queue,
    IReadOnlyList<BackgroundJobStatus> Jobs)
{
    public EventIdentityConflictSnapshot? EventIdentityConflicts { get; init; }

    /// <summary>Selection counters since start. Metadata only.</summary>
    public Bower.Core.PipelineMetricsSnapshot? Pipeline { get; init; }

    /// <summary>Intake attempts and queue-capacity refusals since start. Metadata only.</summary>
    public Bower.Core.IntakeMetricsSnapshot? Intake { get; init; }

    /// <summary>Expected sources; omitted when BOWER_SOURCE_EXPECTATIONS is not set.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<Bower.Core.SourceSilenceStatus>? Sources { get; init; }

    /// <summary>Adaptive request concurrency of the output; omitted when it has none.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Bower.Abstractions.OutputConcurrencySnapshot? Delivery { get; init; }

    /// <summary>Syslog listener counters; omitted when BOWER_SYSLOG_CONFIG is not set. Metadata only.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<Bower.Source.Syslog.SyslogListenerStatus>? Syslog { get; init; }
    /// <summary>Relay counters since start; omitted unless BOWER_RELAY_LISTEN_URL is set.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Relay.RelayStatusSnapshot? Relay { get; init; }

    /// <summary>Windows Event Log subscription counters; omitted when BOWER_WINDOWS_EVENTLOG_CONFIG is not set. Metadata only.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<Bower.Source.WindowsEventLog.WindowsEventSubscriptionStatus>? WindowsEventLog { get; init; }
}

internal sealed record StatusPolicyResponse(
    string Hash,
    IReadOnlyList<StatusPolicyItem> Policies,
    IReadOnlyList<StatusPackItem> Packs,
    string? PrivacyProfile,
    string? PrivacyProfileVersion,
    string PrivacyProfileHash,
    string PrivacyProfileSource,
    string? ManagedPrivacyProfileState,
    long? ManagedPrivacyProfileRevision);

internal sealed record StatusPolicyItem(string Id, string Version);

internal sealed record StatusPackItem(string Id, string Version, string PackHash,
    IReadOnlyList<string> ParserStatuses, string DetectionStatus, string DcrStatus);

internal sealed record LedgerResponse(long Sequence, string Hash);

internal sealed record StatusQueueResponse(
    long Queued,
    long Retrying,
    long Uploading,
    long Delivered,
    long DeadLettered,
    long TotalBytes,
    long UndeliveredBytes,
    DateTimeOffset? OldestUndelivered);

internal sealed record CollectorRegistration(
    string CollectorId,
    string MachineName,
    string Environment,
    string Version,
    string ConfigurationHash,
    string PolicyHash,
    IReadOnlyList<SourceReport> Sources,
    IReadOnlyList<OutputReport> Outputs);

internal sealed record CollectorHeartbeat(
    string Version,
    string ConfigurationHash,
    string PolicyHash,
    long QueueDepth,
    string DeliveryStatus,
    IReadOnlyList<SourceReport> Sources,
    IReadOnlyList<OutputReport> Outputs,
    IReadOnlyList<BackgroundJobStatus> Jobs,
    long DeadLettered,
    LedgerResponse Ledger,
    string PrivacyProfileHash)
{
    // Heartbeat v2: additive. A body without schemaVersion is v1.
    public int SchemaVersion { get; init; } = 2;

    public int HeartbeatIntervalSeconds { get; init; } = 60;

    public long? OldestUndeliveredAgeSeconds { get; init; }

    public DateTimeOffset? LastSuccessfulDeliveryAt { get; init; }

    public CanaryReport? LastCanary { get; init; }

    public IReadOnlyList<string> CommandCapabilities { get; init; } = [];

    public IReadOnlyList<CommandResultReport> CommandResults { get; init; } = [];

    /// <summary>Queued events per redacted detector type since process start. Counts only.</summary>
    public RedactionSnapshot? Redactions { get; init; }
}

/// <summary>
/// Heartbeat v2 response. A v1 management API answers with its collector record instead,
/// which has no schemaVersion: the collector then takes no commands and keeps its results.
/// </summary>
internal sealed record ManagementHeartbeatResponse(
    int? SchemaVersion,
    IReadOnlyList<JsonElement>? Commands,
    IReadOnlyList<string>? AcknowledgedResults);

internal sealed record SourceReport(string Id, string Type, string Status, long? LagSeconds, DateTimeOffset? LastEventAt);

internal sealed record OutputReport(
    string Id,
    string Type,
    string Status,
    DateTimeOffset? LastAcknowledgedAt,
    string? LastErrorCode);

/// <summary>Source-generated metadata for collector HTTP bodies (ASP.NET Core Web defaults).</summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(JsonElement))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(IngestResponse))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(CollectorRegistration))]
[JsonSerializable(typeof(CollectorHeartbeat))]
[JsonSerializable(typeof(ManagedPrivacyProfileDocument))]
[JsonSerializable(typeof(ManagementHeartbeatResponse))]
[JsonSerializable(typeof(ManagementCommandDocument))]
[JsonSerializable(typeof(CommandLedgerDocument))]
[JsonSerializable(typeof(ManagementCredentialState))]
[JsonSerializable(typeof(CollectorEnrolmentRequest))]
[JsonSerializable(typeof(CollectorCredentialRotationRequest))]
[JsonSerializable(typeof(IssuedCollectorCredential))]
internal sealed partial class CollectorJsonContext : JsonSerializerContext;
