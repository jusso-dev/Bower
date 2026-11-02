using Bower.Abstractions;
using Bower.Collector.Jobs;
using Bower.Core;
using Bower.Jobs;
using Bower.Persistence;

namespace Bower.Collector;

/// <summary>
/// Storage pressure facts shared by the monitor, the retention job and status: acknowledged
/// rows purged early under pressure. In memory; resets on restart.
/// </summary>
public sealed class QueueStoragePressure
{
    private long purgedEvents;
    private long lastPurgeTicks;

    public long PurgedEvents => Interlocked.Read(ref purgedEvents);

    public DateTimeOffset? LastPurgeAt
    {
        get
        {
            long ticks = Interlocked.Read(ref lastPurgeTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public void RecordPurge(int count, DateTimeOffset at)
    {
        if (count <= 0)
        {
            return;
        }

        Interlocked.Exchange(ref lastPurgeTicks, at.UtcTicks);
        Interlocked.Add(ref purgedEvents, count);
    }
}

/// <summary>
/// Queue storage for <c>/v1/status</c> and the management heartbeat. Metadata only: sizes,
/// ratios, ages, states and counters; never paths, payloads or event ids.
/// </summary>
/// <param name="State"><c>normal</c>, <c>warning</c>, <c>critical</c> or <c>unknown</c> (free space unmeasurable).</param>
/// <param name="IntakePaused">True while the critical watermark refuses new events.</param>
public sealed record QueueStorageStatus(
    string State,
    bool IntakePaused,
    DateTimeOffset ObservedAt,
    long? FreeBytes,
    long? TotalBytes,
    double? FreePercent,
    long? WarningFreeBytes,
    long? CriticalFreeBytes,
    DateTimeOffset? StateChangedAt,
    long WarningTransitions,
    long CriticalTransitions,
    long QueueFileBytes,
    long QueueDatabaseBytes,
    long QueueWalBytes,
    long QueueFreePageBytes,
    long QueueMaximumBytes,
    long QueueUndeliveredBytes,
    double QueueUtilisationPercent,
    double QueuePageUtilisationPercent,
    long? OldestPendingAgeSeconds,
    long PressurePurgedEvents,
    DateTimeOffset? LastPressurePurgeAt,
    long StorageRefusals,
    long StorageRefusedBytes,
    DateTimeOffset? LastStorageRefusalAt,
    string? LastStorageRefusalReason)
{
    public static async Task<QueueStorageStatus?> CaptureAsync(
        IDurableEventStore queue,
        QueueSnapshot snapshot,
        QueueStoragePressure? pressure,
        PipelineTelemetry? telemetry,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (queue is not SqliteEventStore store || store.Storage is not { } guard)
        {
            return null;
        }

        StorageWatermarkSnapshot disk = guard.Evaluate();
        QueueStorageSnapshot files = await store.GetStorageSnapshotAsync(cancellationToken);
        long maximum = store.MaximumUndeliveredBytes;
        StorageRefusalSnapshot refusals = telemetry?.StorageRefusalSnapshot() ?? new StorageRefusalSnapshot(0, 0, null, null);
        return new QueueStorageStatus(
            StorageWatermarkSnapshot.Name(disk.State),
            disk.State == StorageState.Critical,
            disk.ObservedAt,
            disk.FreeBytes,
            disk.TotalBytes,
            disk.FreePercent,
            disk.WarningThresholdBytes,
            disk.CriticalThresholdBytes,
            disk.StateChangedAt,
            disk.WarningTransitions,
            disk.CriticalTransitions,
            files.FileBytes,
            files.DatabaseBytes,
            files.WalBytes,
            files.FreeBytes,
            maximum,
            snapshot.UndeliveredBytes,
            Math.Round(snapshot.UndeliveredBytes * 100.0 / maximum, 2),
            files.PageUtilisationPercent,
            snapshot.OldestUndelivered is { } oldest ? Math.Max(0, (long)(now - oldest).TotalSeconds) : null,
            pressure?.PurgedEvents ?? 0,
            pressure?.LastPurgeAt,
            refusals.Refusals,
            refusals.RefusedBytes,
            refusals.LastRefusalAt,
            refusals.LastRefusalReason);
    }
}

/// <summary>
/// Samples the queue volume's free-space watermarks and page use every
/// <see cref="Interval"/>, logs state changes and refused intake (rate limited, metadata
/// only), and asks the retention job to reclaim acknowledged rows under pressure. It never
/// writes queue state itself: the store enforces the watermark on every insert.
/// </summary>
public sealed partial class QueueStorageMonitor(
    IDurableEventStore queue,
    PipelineTelemetry telemetry,
    RecurringJobRegistry jobs,
    TimeProvider clock,
    ILogger<QueueStorageMonitor> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    /// <summary>Most one refusal summary (and one retention trigger) per this period.</summary>
    public static readonly TimeSpan RepeatInterval = TimeSpan.FromMinutes(1);

    /// <summary>Page use of the queue ceiling at which retention reclaims acknowledged rows early.</summary>
    public const double PagePressurePercent = 80;

    private StorageState loggedState = StorageState.Normal;
    private long loggedRefusals;
    private DateTimeOffset nextRefusalLog = DateTimeOffset.MinValue;
    private DateTimeOffset nextTrigger = DateTimeOffset.MinValue;
    private DateTimeOffset nextFailureLog = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        loggedRefusals = telemetry.IntakeSnapshot().CapacityRefusals;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SampleAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // A busy or full volume must never stop the monitor; report it rarely.
                DateTimeOffset now = clock.GetUtcNow();
                if (now >= nextFailureLog)
                {
                    nextFailureLog = now + RepeatInterval;
                    LogSampleFailure(logger, exception.GetType().Name);
                }
            }

            try
            {
                await Task.Delay(Interval, clock, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>One sample. Public for tests.</summary>
    public async Task SampleAsync(CancellationToken cancellationToken)
    {
        if (queue is not SqliteEventStore store || store.Storage is not { } guard)
        {
            return;
        }

        DateTimeOffset now = clock.GetUtcNow();
        StorageWatermarkSnapshot disk = guard.Evaluate(force: true);
        if (disk.State != loggedState)
        {
            LogTransition(disk);
            loggedState = disk.State;
        }

        IntakeMetricsSnapshot intake = telemetry.IntakeSnapshot();
        if (intake.CapacityRefusals > loggedRefusals && now >= nextRefusalLog)
        {
            StorageRefusalSnapshot storage = telemetry.StorageRefusalSnapshot();
            LogIntakeRefused(
                logger,
                intake.CapacityRefusals - loggedRefusals,
                storage.LastRefusalAt >= intake.LastRefusalAt
                    ? storage.LastRefusalReason!
                    : intake.LastRefusalReason ?? PipelineTelemetry.QueueCapacityReason,
                storage.Refusals);
            loggedRefusals = intake.CapacityRefusals;
            nextRefusalLog = now + RepeatInterval;
        }

        QueueStorageSnapshot files = await store.GetStorageSnapshotAsync(cancellationToken);
        bool pressure = disk.State is StorageState.Warning or StorageState.Critical
            || files.PageUtilisationPercent >= PagePressurePercent;
        if (pressure && now >= nextTrigger && jobs.Trigger(QueueRetentionJob.Id))
        {
            nextTrigger = now + RepeatInterval;
        }
    }

    private void LogTransition(StorageWatermarkSnapshot disk)
    {
        long free = disk.FreeBytes ?? 0;
        double percent = disk.FreePercent ?? 0;
        long warning = disk.WarningThresholdBytes ?? 0;
        long critical = disk.CriticalThresholdBytes ?? 0;
        switch (disk.State)
        {
            case StorageState.Critical:
                LogCritical(logger, free, percent, critical);
                break;
            case StorageState.Warning:
                LogWarning(logger, free, percent, warning, critical);
                break;
            case StorageState.Normal:
                LogRecovered(logger, free, percent, warning);
                break;
            default:
                LogUnknown(logger);
                break;
        }
    }

    [LoggerMessage(EventId = 1500, Level = LogLevel.Error,
        Message = "Queue volume below the critical free-space watermark: {FreeBytes} bytes ({FreePercent}%) free, critical below {CriticalBytes}. New events are refused; delivery and acknowledgement continue.")]
    private static partial void LogCritical(ILogger logger, long freeBytes, double freePercent, long criticalBytes);

    [LoggerMessage(EventId = 1501, Level = LogLevel.Warning,
        Message = "Queue volume below the warning free-space watermark: {FreeBytes} bytes ({FreePercent}%) free, warning below {WarningBytes}, critical below {CriticalBytes}. Intake continues.")]
    private static partial void LogWarning(ILogger logger, long freeBytes, double freePercent, long warningBytes, long criticalBytes);

    [LoggerMessage(EventId = 1502, Level = LogLevel.Information,
        Message = "Queue volume free space recovered: {FreeBytes} bytes ({FreePercent}%) free, warning below {WarningBytes}. Intake is accepted.")]
    private static partial void LogRecovered(ILogger logger, long freeBytes, double freePercent, long warningBytes);

    [LoggerMessage(EventId = 1503, Level = LogLevel.Warning,
        Message = "Queue volume free space cannot be measured; free-space watermarks are not enforced until it can. The queue byte cap still applies.")]
    private static partial void LogUnknown(ILogger logger);

    [LoggerMessage(EventId = 1504, Level = LogLevel.Warning,
        Message = "Queue refused {Count} event(s) since the last report (latest reason {Reason}; {StorageRefusals} storage refusals since start). Sources keep them and retry.")]
    private static partial void LogIntakeRefused(ILogger logger, long count, string reason, long storageRefusals);

    [LoggerMessage(EventId = 1505, Level = LogLevel.Warning,
        Message = "Queue storage sampling failed with {ExceptionType}; the watermark is still enforced on every insert.")]
    private static partial void LogSampleFailure(ILogger logger, string exceptionType);
}
