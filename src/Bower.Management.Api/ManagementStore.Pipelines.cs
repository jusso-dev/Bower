using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

public sealed partial class ManagementStore
{
    public const int MaximumActivitySources = 25;
    public const int MaximumPipelineRows = 64;

    private static Task InitializePipelinesAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS collector_pipeline_snapshots (
                collector_id TEXT PRIMARY KEY REFERENCES collectors(id) ON DELETE CASCADE,
                captured_at TEXT NOT NULL,
                pipeline_json TEXT NULL,
                activity_json TEXT NULL
            );
            """,
            cancellationToken);

    private static async Task SavePipelineSnapshotAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        PipelineReport? pipeline,
        IReadOnlyList<SourceActivityReport>? activity,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (pipeline is null && activity is null)
        {
            return;
        }

        string? pipelineJson = pipeline is null
            ? null
            : JsonSerializer.Serialize(
                pipeline with { Rows = pipeline.Rows?.Take(MaximumPipelineRows).ToArray() },
                ManagementJsonContext.Default.PipelineReport);
        string? activityJson = activity is null
            ? null
            : JsonSerializer.Serialize(
                activity.Take(MaximumActivitySources).ToArray(),
                ManagementJsonContext.Default.SourceActivityReportArray);

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO collector_pipeline_snapshots (collector_id, captured_at, pipeline_json, activity_json)
            VALUES ($collector, $captured, $pipeline, $activity)
            ON CONFLICT(collector_id) DO UPDATE SET
                captured_at = excluded.captured_at,
                pipeline_json = COALESCE(excluded.pipeline_json, collector_pipeline_snapshots.pipeline_json),
                activity_json = COALESCE(excluded.activity_json, collector_pipeline_snapshots.activity_json);
            """,
            [
                ("$collector", collectorId),
                ("$captured", Format(now)),
                ("$pipeline", pipelineJson),
                ("$activity", activityJson)
            ],
            cancellationToken);
    }

    public async Task<List<CollectorPipelineFlow>> ListLivePipelinesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<CollectorRecord> collectors = await ListAsync(null, cancellationToken);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);

        Dictionary<string, (PipelineReport? Pipeline, SourceActivityReport[] Activity)> snapshots = new(StringComparer.Ordinal);
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText = "SELECT collector_id, pipeline_json, activity_json FROM collector_pipeline_snapshots;";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                string id = reader.GetString(0);
                PipelineReport? pipeline = reader.IsDBNull(1)
                    ? null
                    : JsonSerializer.Deserialize(reader.GetString(1), ManagementJsonContext.Default.PipelineReport);
                SourceActivityReport[] activity = reader.IsDBNull(2)
                    ? []
                    : JsonSerializer.Deserialize(reader.GetString(2), ManagementJsonContext.Default.SourceActivityReportArray) ?? [];
                snapshots[id] = (pipeline, activity);
            }
        }

        Dictionary<string, List<RedactionSummaryItem>> redactionsByCollector = new(StringComparer.Ordinal);
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT collector_id, type, events
                FROM collector_redaction_totals
                WHERE events > 0
                ORDER BY events DESC, type ASC;
                """;
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                string collectorId = reader.GetString(0);
                string type = reader.GetString(1);
                long events = reader.GetInt64(2);
                if (!redactionsByCollector.TryGetValue(collectorId, out List<RedactionSummaryItem>? list))
                {
                    list = [];
                    redactionsByCollector[collectorId] = list;
                }

                list.Add(new RedactionSummaryItem(type, RedactionLabels.Label(RedactionLabels.Group(type)), events));
            }
        }

        List<CollectorPipelineFlow> flows = [];
        foreach (CollectorRecord raw in collectors)
        {
            CollectorRecord record = CollectorConnectivity.With(raw, now);
            snapshots.TryGetValue(record.Id, out (PipelineReport? Pipeline, SourceActivityReport[] Activity) snap);
            redactionsByCollector.TryGetValue(record.Id, out List<RedactionSummaryItem>? redactions);
            flows.Add(BuildPipelineFlow(record, snap.Pipeline, snap.Activity ?? [], redactions ?? []));
        }

        return flows;
    }

    public async Task RecordPipelineTapAuditAsync(
        string collectorId,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await InsertAuditAsync(
            connection,
            transaction,
            "pipeline.tap-sampled",
            collectorId,
            actorObjectId,
            actorName,
            now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static CollectorPipelineFlow BuildPipelineFlow(
        CollectorRecord collector,
        PipelineReport? pipeline,
        SourceActivityReport[] activity,
        List<RedactionSummaryItem> redactions)
    {
        long eventsIn = pipeline?.EventsIn ?? 0;
        long eventsQueued = pipeline?.EventsQueued ?? 0;
        long suppressed = pipeline?.Suppressed ?? 0;
        long duplicates = pipeline?.Duplicates ?? 0;
        long bytesIn = pipeline?.BytesIn ?? 0;
        long bytesQueued = pipeline?.BytesQueued ?? 0;
        long rejected = Math.Max(0, eventsIn - eventsQueued - suppressed - duplicates);
        int? reductionPercent = eventsIn > 0
            ? (int)Math.Clamp(Math.Round((eventsIn - eventsQueued) * 100.0 / eventsIn), 0, 100)
            : null;
        long totalRedactions = redactions.Sum(item => item.Events);

        int degradedSources = collector.Sources.Count(source =>
            !string.Equals(source.Status, "healthy", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(source.Status, "pending", StringComparison.OrdinalIgnoreCase));
        string collectLight = degradedSources > 0
            ? "amber"
            : collector.Sources.Count > 0 ? "green" : "amber";
        string collectHeadline = collector.Sources.Count == 1
            ? "1 source configured"
            : $"{collector.Sources.Count} sources configured";
        string collectDetail = degradedSources > 0
            ? $"{degradedSources} source(s) quiet or degraded"
            : eventsIn > 0
                ? $"{eventsIn.ToString("N0", CultureInfo.InvariantCulture)} candidate event(s) seen since start"
                : "Listening for events";

        bool privacyDrifted = collector.PrivacyProfileInSync == false;
        string redactLight = privacyDrifted ? "amber" : "green";
        string redactHeadline = totalRedactions > 0
            ? $"{totalRedactions.ToString("N0", CultureInfo.InvariantCulture)} finding(s) protected"
            : "Active before queue";
        string redactDetail = privacyDrifted
            ? "Privacy profile differs from assigned version"
            : string.Equals(collector.ReportedPrivacyProfileHash, "default", StringComparison.OrdinalIgnoreCase)
                ? "Built-in Australian privacy rules active"
                : "Assigned privacy profile in sync";

        bool policyDrifted = collector.PolicyInSync == false;
        string selectLight = policyDrifted ? "amber" : "green";
        string selectHeadline = eventsIn > 0
            ? $"{eventsQueued.ToString("N0", CultureInfo.InvariantCulture)} kept of {eventsIn.ToString("N0", CultureInfo.InvariantCulture)}"
            : "Default-deny policy active";
        string selectDetail = reductionPercent is { } pct && eventsIn > 0
            ? $"{pct}% noise filtered ({suppressed} suppressed, {rejected} dropped/quarantined)"
            : policyDrifted
                ? "Policy bundle differs from desired hash"
                : "Policy bundle in sync";

        string queueLight = collector.DeadLettered > 0
            ? "red"
            : collector.QueueDepth > 1000 ? "amber" : "green";
        string queueHeadline = collector.QueueDepth == 0
            ? "Queue drained"
            : $"{collector.QueueDepth.ToString("N0", CultureInfo.InvariantCulture)} waiting";
        string queueDetail = collector.DeadLettered > 0
            ? $"{collector.DeadLettered.ToString("N0", CultureInfo.InvariantCulture)} dead-lettered event(s) need review"
            : collector.OldestUndeliveredAgeSeconds is { } age and > 0
                ? $"Oldest waiting event is {age}s old"
                : "SQLite WAL durable queue healthy";

        string deliveryLower = collector.DeliveryStatus.ToLowerInvariant();
        string deliverLight = deliveryLower is "healthy" or "waiting" or "idle"
            ? "green"
            : deliveryLower is "degraded" or "retrying" or "paused"
                ? "amber"
                : "red";
        string deliverHeadline = collector.Outputs.Count > 0
            ? string.Join(", ", collector.Outputs.Select(output => output.Type))
            : collector.DeliveryStatus;
        string deliverDetail = collector.LastSuccessfulDeliveryAt is { } lastAck
            ? $"Status: {collector.DeliveryStatus} · last ack {lastAck:u}"
            : $"Status: {collector.DeliveryStatus}";

        PipelineFlowStage[] stages =
        [
            new("collect", "Collect", collectLight, collectHeadline, collectDetail),
            new("redact", "Redact", redactLight, redactHeadline, redactDetail),
            new("select", "Select", selectLight, selectHeadline, selectDetail),
            new("queue", "Queue", queueLight, queueHeadline, queueDetail),
            new("deliver", "Deliver", deliverLight, deliverHeadline, deliverDetail)
        ];

        return new CollectorPipelineFlow(
            collector.Id,
            collector.MachineName,
            collector.Environment,
            collector.Connectivity ?? "unknown",
            collector.LastSeenAt,
            collector.PolicyHash,
            collector.ReportedPrivacyProfileHash ?? "default",
            eventsIn,
            eventsQueued,
            suppressed,
            rejected,
            duplicates,
            bytesIn,
            bytesQueued,
            reductionPercent,
            collector.QueueDepth,
            collector.DeadLettered,
            collector.OldestUndeliveredAgeSeconds,
            collector.DeliveryStatus,
            collector.LastSuccessfulDeliveryAt,
            stages,
            collector.Sources,
            collector.Outputs,
            activity,
            redactions,
            pipeline?.Rows ?? []);
    }
}
