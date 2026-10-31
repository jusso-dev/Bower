using Bower.Abstractions;
using Bower.Persistence;

namespace Bower.Collector.Jobs;

/// <summary>
/// Removes acknowledged events once they are older than the duplicate-detection window.
/// Undelivered, retrying and dead-lettered events are never touched, nor are events a
/// configured archive does not verifiably hold for this queue: unverified coverage purges
/// nothing.
/// <para>
/// Under storage pressure (queue pages at <see cref="QueueStorageMonitor.PagePressurePercent"/>
/// of the ceiling, or the volume below its warning watermark) it also removes acknowledged
/// events older than <see cref="CollectorSettings.PressureRetentionFloor"/>, oldest first, so retained
/// acknowledgements cannot refuse new events. That shortens duplicate detection, never
/// delivery: only acknowledged rows are eligible.
/// </para>
/// </summary>
public sealed partial class QueueRetentionJob(
    IDurableEventStore queue,
    TimeProvider clock,
    CollectorSettings settings,
    ILogger<QueueRetentionJob> logger,
    QueueArchive? archive = null,
    QueueStoragePressure? pressure = null)
{
    public const string Id = "queue-retention";
    public const int RetryAttempts = 3;
    private const int BatchSize = 5_000;

    // Smaller batches under page pressure, so purging stops close to the target.
    private const int PressureBatchSize = 500;

    /// <summary>Page use the pressure purge brings the queue down to once it starts.</summary>
    public const double PressureTargetPercent = 70;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        int total = await PurgeAsync(now - settings.DeliveredRetention, BatchSize, _ => Task.FromResult(true), cancellationToken);
        if (total < 0)
        {
            return;
        }

        if (total > 0)
        {
            LogPurged(logger, total);
        }

        if (queue is SqliteEventStore store)
        {
            await ReclaimUnderPressureAsync(store, now, cancellationToken);
        }
    }

    private async Task ReclaimUnderPressureAsync(SqliteEventStore store, DateTimeOffset now, CancellationToken cancellationToken)
    {
        StorageState disk = store.Storage?.Evaluate(force: true).State ?? StorageState.Normal;
        bool diskPressure = disk is StorageState.Warning or StorageState.Critical;
        QueueStorageSnapshot files = await store.GetStorageSnapshotAsync(cancellationToken);
        if (!diskPressure && files.PageUtilisationPercent < QueueStorageMonitor.PagePressurePercent)
        {
            return;
        }

        // Low disk: reclaim every eligible row, so new events reuse freed pages instead of
        // growing the file. Page pressure alone: stop once use is back at the target.
        int purged = await PurgeAsync(
            now - settings.PressureRetentionFloor,
            diskPressure ? BatchSize : PressureBatchSize,
            async token => diskPressure
                || (await store.GetStorageSnapshotAsync(token)).PageUtilisationPercent > PressureTargetPercent,
            cancellationToken);
        if (purged > 0)
        {
            pressure?.RecordPurge(purged, clock.GetUtcNow());
            QueueStorageSnapshot after = await store.GetStorageSnapshotAsync(cancellationToken);
            LogPressurePurged(
                logger,
                purged,
                diskPressure ? "low-disk" : "queue-pages",
                files.PageUtilisationPercent,
                after.PageUtilisationPercent,
                (long)settings.PressureRetentionFloor.TotalSeconds);
        }
    }

    /// <summary>Purges acknowledged rows delivered before the cutoff while <paramref name="more"/> holds; -1 when archive coverage refused.</summary>
    private async Task<int> PurgeAsync(
        DateTimeOffset cutoff,
        int batchSize,
        Func<CancellationToken, Task<bool>> more,
        CancellationToken cancellationToken)
    {
        // With an archive, purge only what verified archive coverage of this queue holds.
        ArchiveCoverage? coverage = null;
        SqliteEventStore? ledger = queue as SqliteEventStore;
        if (archive is not null)
        {
            coverage = ledger is not null
                ? await archive.VerifyCoverageAsync(ledger, cancellationToken)
                : ArchiveCoverage.Refused("queue-unsupported");
            if (!coverage.Verified)
            {
                LogCoverageRefused(logger, coverage.Reason, coverage.FirstSequence, coverage.ThroughSequence);
                return -1;
            }
        }

        int total = 0;
        int purged;
        do
        {
            if (!await more(cancellationToken))
            {
                break;
            }

            if (coverage is not null)
            {
                // The cache trusts size and write time; re-hash the segments holding this
                // batch so silent corruption is caught before their last local copy goes.
                long through = coverage.ThroughSequence;
                IReadOnlyList<long> batch = await ledger!.ReadPurgeCandidateSequencesAsync(cutoff, batchSize, through, cancellationToken);
                if (batch.Count == 0)
                {
                    break;
                }

                if (await archive!.VerifySegmentsForPurgeAsync(batch, cancellationToken) is { } reason)
                {
                    LogCoverageRefused(logger, reason, coverage.FirstSequence, through);
                    break;
                }

                purged = await queue.PurgeDeliveredAsync(cutoff, batchSize, through, cancellationToken);
            }
            else
            {
                purged = await queue.PurgeDeliveredAsync(cutoff, batchSize, cancellationToken);
            }

            total += purged;
        }
        while (purged == batchSize && !cancellationToken.IsCancellationRequested);

        return total;
    }

    [LoggerMessage(
        EventId = 1201,
        Level = LogLevel.Information,
        Message = "Queue retention removed {Count} acknowledged event(s).")]
    private static partial void LogPurged(ILogger logger, int count);

    [LoggerMessage(
        EventId = 1506,
        Level = LogLevel.Warning,
        Message = "Queue retention removed {Count} acknowledged event(s) early under storage pressure ({Trigger}); queue pages {BeforePercent}% -> {AfterPercent}% of the ceiling. Duplicate detection now covers at least {FloorSeconds} seconds of acknowledged events.")]
    private static partial void LogPressurePurged(
        ILogger logger, int count, string trigger, double beforePercent, double afterPercent, long floorSeconds);

    [LoggerMessage(
        EventId = 1202,
        Level = LogLevel.Warning,
        Message = "Queue retention stopped before purging: archive coverage is not verified ({Reason}; first {FirstSequence}, through {ThroughSequence}).")]
    private static partial void LogCoverageRefused(ILogger logger, string? reason, long firstSequence, long throughSequence);
}
