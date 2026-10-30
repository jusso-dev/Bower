using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Jobs;
using Bower.Source.Syslog;
using Bower.Source.WindowsEventLog;

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
    IngestPolicyResponse? Policy);

internal sealed record IngestPolicyResponse(string PolicyId, string PolicyVersion, string PolicyHash, int Score);

internal sealed record StatusResponse(
    string Status,
    StatusPolicyResponse Policy,
    LedgerResponse Ledger,
    StatusQueueResponse Queue,
    IReadOnlyList<BackgroundJobStatus> Jobs,
    IReadOnlyList<SyslogListenerStatus>? Syslog = null,
    IReadOnlyList<WindowsEventSubscriptionStatus>? WindowsEventLog = null);

internal sealed record StatusPolicyResponse(
    string Hash,
    IReadOnlyList<StatusPolicyItem> Policies,
    IReadOnlyList<StatusPackItem> Packs,
    string? PrivacyProfile);

internal sealed record StatusPolicyItem(string Id, string Version);

internal sealed record StatusPackItem(string Id, string Version, string PackHash);

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
    LedgerResponse Ledger);

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
internal sealed partial class CollectorJsonContext : JsonSerializerContext;
