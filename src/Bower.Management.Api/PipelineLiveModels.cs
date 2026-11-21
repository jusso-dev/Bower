namespace Bower.Management.Api;

/// <summary>Selection counters reported by a collector on heartbeat v2+. Metadata only.</summary>
public sealed record PipelineReport(
    DateTimeOffset StartedAt,
    long EventsIn,
    long EventsQueued,
    long Duplicates,
    long Suppressed,
    long BytesIn,
    long BytesQueued,
    IReadOnlyList<PipelineRowReport>? Rows = null);

/// <summary>Per-stage / per-policy counter row from <see cref="PipelineReport"/>. Metadata only.</summary>
public sealed record PipelineRowReport(
    string Stage,
    string PolicyId,
    string Action,
    long Events,
    long Queued,
    long Duplicates,
    long Suppressed,
    long BytesIn,
    long BytesQueued);

/// <summary>One busy source reported by a collector (equivalent to <c>bower top</c>). Metadata only.</summary>
public sealed record SourceActivityReport(
    string Application,
    string Environment,
    DateTimeOffset LastSeenAt,
    long EventCount);

/// <summary>One stage in the 5-stage visual pipeline view (Collect → Redact → Select → Queue → Deliver).</summary>
public sealed record PipelineFlowStage(
    string Id,
    string Title,
    string Light,
    string Headline,
    string Detail);

/// <summary>Live visual pipeline summary for one collector, computed server-side from heartbeat metadata.</summary>
public sealed record CollectorPipelineFlow(
    string CollectorId,
    string MachineName,
    string Site,
    string Connectivity,
    DateTimeOffset LastSeenAt,
    string PolicyHash,
    string PrivacyProfileHash,
    long EventsIn,
    long EventsQueued,
    long EventsSuppressed,
    long EventsRejected,
    long Duplicates,
    long BytesIn,
    long BytesQueued,
    int? ReductionPercent,
    long QueueDepth,
    long DeadLettered,
    long? OldestUndeliveredAgeSeconds,
    string DeliveryStatus,
    DateTimeOffset? LastSuccessfulDeliveryAt,
    IReadOnlyList<PipelineFlowStage> Stages,
    IReadOnlyList<SourceReport> Sources,
    IReadOnlyList<OutputReport> Outputs,
    IReadOnlyList<SourceActivityReport> TopSources,
    IReadOnlyList<RedactionSummaryItem> Redactions,
    IReadOnlyList<PipelineRowReport> PolicyBreakdown);

/// <summary>Redaction total for one detector type on a collector. Metadata only.</summary>
public sealed record RedactionSummaryItem(string Type, string Label, long Events);

/// <summary>Request body for <c>POST /api/pipelines/collectors/{id}/tap</c>.</summary>
public sealed record PipelineTapRequest(string? Source = null, string? EventType = null, int? Limit = null);

/// <summary>One already-redacted tap frame returned to an operator.</summary>
public sealed record PipelineTapFrame(
    DateTimeOffset ObservedAt,
    string Stage,
    string Decision,
    string? EventType,
    string? Source,
    string? PolicyId,
    string? RedactedPayload);

/// <summary>
/// Response for <c>POST /api/pipelines/collectors/{id}/tap</c>. In outbound-only deployments
/// returns <c>mode: "cli"</c> with the exact <c>bower tap</c> command to run locally on the
/// collector host; when an allow-listed tap client is configured returns <c>mode: "live"</c>
/// with bounded, already-redacted frames.
/// </summary>
public sealed record PipelineTapResponse(
    string CollectorId,
    string Mode,
    string Command,
    string Note,
    IReadOnlyList<PipelineTapFrame> Frames,
    DateTimeOffset CapturedAt);

/// <summary>
/// Optional server-side client for fetching bounded, post-redaction tap frames from an
/// administrator-allowlisted collector endpoint. Default deployments keep collectors outbound-only
/// and do not configure a direct tap client.
/// </summary>
public interface ICollectorTapClient
{
    Task<IReadOnlyList<PipelineTapFrame>?> TrySampleAsync(
        string collectorId,
        PipelineTapRequest request,
        CancellationToken cancellationToken);
}
