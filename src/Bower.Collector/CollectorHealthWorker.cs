using Bower.Abstractions;
using Bower.Collector.Jobs;
using Bower.Core;
using Bower.Persistence;
using Bower.Source.Syslog;
using Bower.Source.WindowsEventLog;

namespace Bower.Collector;

/// <summary>
/// Queues one <c>collector_health</c> record at start-up and then every
/// <c>BOWER_HEALTH_RECORD_INTERVAL_SECONDS</c>. A hosted loop beside the delivery worker
/// rather than a scheduled job: it writes queue state. It only reads queue and source
/// metadata and never leases, acknowledges or deletes events. A refused or failed record
/// is logged and superseded by the next one; collection and delivery never wait for it.
/// </summary>
public sealed partial class CollectorHealthWorker(
    SecurityEventProcessor processor,
    CollectorIdentity identity,
    IDurableEventStore queue,
    PipelineTelemetry telemetry,
    SourceHealth sourceHealth,
    DeliveryActivity deliveryActivity,
    CollectorSettings settings,
    TimeProvider clock,
    ILogger<CollectorHealthWorker> logger,
    SyslogSource? syslog = null,
    WindowsEventLogSource? windowsEventLog = null,
    ManagedPrivacyProfileState? managedPrivacy = null) : BackgroundService
{
    private CollectorHealthSample? previous;
    private long sequence;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan interval = settings.HealthRecordInterval
            ?? throw new InvalidOperationException("Collector health records are not enabled.");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RecordAsync(interval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                LogRecordFailed(logger, exception.GetType().Name);
            }

            try
            {
                await Task.Delay(interval, clock, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Samples and queues one record. Returns the processing outcome, or null when the queue
    /// refused it or managed privacy still gates intake.
    /// </summary>
    public async Task<ProcessingResult?> RecordAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        if (managedPrivacy is { AcceptsEvents: false })
        {
            // Same gate as every intake path: nothing is processed until the assigned privacy
            // profile is in force. The missing records are themselves the destination signal.
            LogRecordGated(logger, managedPrivacy.State);
            return null;
        }

        QueueSnapshot snapshot = await queue.GetSnapshotAsync(cancellationToken);
        DateTimeOffset now = clock.GetUtcNow();
        CollectorHealthSample sample = new(
            now,
            telemetry.StartedAt,
            ++sequence,
            interval,
            settings.OutputType,
            DeliveryHealth.Evaluate(settings.OutputType, snapshot, settings.MaximumQueueBytes, now),
            deliveryActivity.LastSuccessfulDeliveryAt,
            snapshot,
            settings.MaximumQueueBytes,
            telemetry.IntakeSnapshot(),
            telemetry.Snapshot(),
            sourceHealth.IsConfigured,
            sourceHealth.Evaluate(),
            syslog?.Snapshot(),
            windowsEventLog?.Snapshot(),
            QueueFileBytes(),
            // SqliteEventStore sets PRAGMA max_page_count to a quarter of its physical budget.
            (queue as SqliteEventStore)?.MaximumStorageBytes / 4);
        string record = CollectorHealthRecord.CreateJson(sample, identity.Id, settings.Environment, previous);
        try
        {
            ProcessingResult result = await processor.ProcessAsync(
                record,
                identity with { SourceAdapter = CollectorHealthRecord.SourceAdapter },
                cancellationToken);
            if (result.Queued || result.Duplicate)
            {
                // Counters are deltas since the last queued record, so a refused or rejected
                // record's interval is carried into the next one instead of being lost.
                previous = sample;
            }
            else
            {
                // Start-up checks that the policy accepts the record, so this is a later change
                // (for example a managed privacy profile) or a validation failure.
                LogRecordNotQueued(logger, PipelineTelemetry.ActionName(result.Action), string.Join(",", result.Reasons));
            }

            return result;
        }
        catch (QueueCapacityExceededException)
        {
            // Capacity refusals are counted in intake metrics; the next record reports them.
            LogRecordRefused(logger);
            return null;
        }
    }

    private long? QueueFileBytes()
    {
        try
        {
            FileInfo file = new(settings.QueuePath);
            return file.Exists ? file.Length : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [LoggerMessage(
        EventId = 1330,
        Level = LogLevel.Warning,
        Message = "Collector health record refused: the queue is at capacity.")]
    private static partial void LogRecordRefused(ILogger logger);

    [LoggerMessage(
        EventId = 1331,
        Level = LogLevel.Warning,
        Message = "Collector health record was not queued ({Action}: {Reasons}).")]
    private static partial void LogRecordNotQueued(ILogger logger, string action, string reasons);

    [LoggerMessage(
        EventId = 1333,
        Level = LogLevel.Information,
        Message = "Collector health record skipped: managed privacy profile state is {State}.")]
    private static partial void LogRecordGated(ILogger logger, string state);

    [LoggerMessage(
        EventId = 1332,
        Level = LogLevel.Warning,
        Message = "Collector health record failed with {ExceptionType}; the next interval retries.")]
    private static partial void LogRecordFailed(ILogger logger, string exceptionType);
}
