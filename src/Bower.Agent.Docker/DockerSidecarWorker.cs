using Bower.Abstractions;
using Bower.Source.Docker;

namespace Bower.Agent.Docker;

public sealed record SidecarPassResult(
    int Containers,
    int Forwarded,
    int Rejected,
    int Dropped,
    int Malformed,
    int Oversized,
    bool Backpressure);

/// <summary>
/// Tails opted-in container logs and forwards candidate events to the collector.
/// At-least-once: the durable cursor advances only past lines the collector accepted
/// or definitively rejected, or lines the sidecar intentionally dropped.
/// </summary>
public sealed partial class DockerSidecarWorker(
    SidecarSettings settings,
    ISourceCursorStore cursors,
    CollectorClient collector,
    TimeProvider clock,
    ILogger<DockerSidecarWorker> logger) : BackgroundService
{
    private static readonly TimeSpan MaximumBackoff = TimeSpan.FromMinutes(2);
    private readonly DockerLogEventMapper mapper = new(new DockerMapperOptions
    {
        SidecarId = settings.SidecarId,
        DefaultEnvironment = settings.Environment
    });

    private readonly DockerLogReaderOptions readerOptions = new() { StartAtEnd = !settings.ReadExistingLogs };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan backoff = settings.PollInterval;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                SidecarPassResult result = await ProcessOnceAsync(stoppingToken);
                WriteHeartbeat();
                if (result.Forwarded + result.Rejected + result.Malformed + result.Oversized > 0)
                {
                    LogPass(logger, result.Containers, result.Forwarded, result.Rejected,
                        result.Dropped, result.Malformed, result.Oversized);
                }

                backoff = result.Backpressure
                    ? TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaximumBackoff.Ticks))
                    : settings.PollInterval;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                LogPassFailure(logger, exception.GetType().Name);
                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaximumBackoff.Ticks));
            }

            await Task.Delay(backoff, clock, stoppingToken);
        }
    }

    public async Task<SidecarPassResult> ProcessOnceAsync(CancellationToken cancellationToken)
    {
        DockerCatalogResult catalog = DockerContainerCatalog.Discover(new DockerCatalogOptions
        {
            Root = settings.DockerRoot,
            OptInLabel = settings.OptInLabel
        });

        int forwarded = 0, rejected = 0, dropped = 0, malformed = 0, oversized = 0;
        foreach (DockerContainer container in catalog.Containers)
        {
            string sourceId = $"docker:{container.Id}";
            SourceCursorSnapshot? snapshot = await cursors.ReadAsync(sourceId, cancellationToken);
            DockerLogCursor? cursor = DockerLogCursor.Deserialize(snapshot?.Value);
            DockerLogBatch batch = DockerJsonLogReader.Read(container, cursor, readerOptions);
            malformed += batch.Malformed;
            oversized += batch.Oversized;
            if (batch.RotationGap)
            {
                LogRotationGap(logger, container.Name);
            }

            DockerLogCursor next = batch.Cursor;
            SendOutcome? stoppedBy = null;
            foreach (DockerLogRecord record in batch.Records)
            {
                DockerMappedEvent mapped = mapper.Map(container, record, clock.GetUtcNow());
                if (mapped.Json is null)
                {
                    dropped++;
                    continue;
                }

                SendOutcome outcome = await collector.SendAsync(mapped.Json, cancellationToken);
                if (outcome is SendOutcome.Accepted)
                {
                    forwarded++;
                }
                else if (outcome is SendOutcome.Rejected)
                {
                    rejected++;
                }
                else
                {
                    // Stop before this record; it is retried on the next pass.
                    next = new DockerLogCursor(
                        DockerLogCursor.CurrentSchemaVersion,
                        record.FileFingerprint,
                        record.StartOffset);
                    stoppedBy = outcome;
                    break;
                }
            }

            if (cursor is null || next != cursor)
            {
                bool advanced = await cursors.TryAdvanceAsync(
                    sourceId,
                    snapshot?.Version ?? 0,
                    next.Serialize(),
                    clock.GetUtcNow(),
                    cancellationToken);
                if (!advanced)
                {
                    LogCursorConflict(logger, container.Name);
                }
            }

            if (stoppedBy is SendOutcome.Unauthorized)
            {
                LogUnauthorized(logger);
            }

            if (stoppedBy is not null)
            {
                return new SidecarPassResult(catalog.Containers.Count, forwarded, rejected, dropped, malformed, oversized, true);
            }
        }

        return new SidecarPassResult(catalog.Containers.Count, forwarded, rejected, dropped, malformed, oversized, false);
    }

    private void WriteHeartbeat()
    {
        string? directory = Path.GetDirectoryName(settings.HeartbeatPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(settings.HeartbeatPath, clock.GetUtcNow().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
    }

    [LoggerMessage(EventId = 3001, Level = LogLevel.Information,
        Message = "Sidecar pass: {Containers} container(s), {Forwarded} forwarded, {Rejected} rejected by policy, {Dropped} dropped, {Malformed} malformed, {Oversized} oversized.")]
    private static partial void LogPass(ILogger logger, int containers, int forwarded, int rejected, int dropped, int malformed, int oversized);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Warning,
        Message = "Sidecar pass failed with {FailureType}; backing off.")]
    private static partial void LogPassFailure(ILogger logger, string failureType);

    [LoggerMessage(EventId = 3003, Level = LogLevel.Warning,
        Message = "Container {Container} log rotated more than once between reads; some lines were not collected.")]
    private static partial void LogRotationGap(ILogger logger, string container);

    [LoggerMessage(EventId = 3004, Level = LogLevel.Warning,
        Message = "Cursor for {Container} changed concurrently; it will be re-read.")]
    private static partial void LogCursorConflict(ILogger logger, string container);

    [LoggerMessage(EventId = 3005, Level = LogLevel.Error,
        Message = "Collector refused the ingest token. Check BOWER_INGEST_TOKEN; forwarding is paused.")]
    private static partial void LogUnauthorized(ILogger logger);
}
