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
        if (total > 0)
        {
            LogPurged(logger, total);
        }

        if (queue is SqliteEventStore store)
        {
            // Unverified archive coverage purges nothing, but pages already free still go back.
            if (total >= 0)
            {
                await ReclaimUnderPressureAsync(store, now, cancellationToken);
            }

            await ReleaseFreePagesAsync(store, cancellationToken);
        }
    }

    /// <summary>Pages returned to the file system per step (8 MiB at 4 KiB pages), so the WAL stays small.</summary>
    public const int ReleaseStepPages = 2_048;

    private const int MaximumReleaseSteps = 64;

    /// <summary>Longest one run spends releasing free pages; the rest waits for the next run.</summary>
    public static readonly TimeSpan MaximumReleaseDuration = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Shrinks the database by releasing free pages when the volume is short of space or the
    /// file grew past the intake limit (after settling a large backlog). Not while a backlog
    /// is still settling: undelivered rows dominate, or the pages in use are still past the
    /// intake limit. Those rows' acknowledgements reuse the free pages, and releasing them
    /// only makes the file grow again. Bounded in steps and time, one checkpoint at the end.
    /// </summary>
    private async Task ReleaseFreePagesAsync(SqliteEventStore store, CancellationToken cancellationToken)
    {
        QueueStorageSnapshot files = await store.GetStorageSnapshotAsync(cancellationToken);
        StorageState disk = store.Storage?.Evaluate().State ?? StorageState.Normal;
        bool needed = disk is StorageState.Warning or StorageState.Critical || files.PageCount > files.IntakeLimitPages;
        if (!needed || files.FreePages == 0 || await SettlingAsync(store, files, cancellationToken))
        {
            return;
        }

        long released = 0;
        long started = clock.GetTimestamp();
        for (int step = 0; step < MaximumReleaseSteps && !cancellationToken.IsCancellationRequested; step++)
        {
            long pages = await store.ReleaseFreePagesAsync(ReleaseStepPages, checkpoint: false, cancellationToken);
            released += pages;
            if (pages < ReleaseStepPages || clock.GetElapsedTime(started) >= MaximumReleaseDuration)
            {
                break;
            }
        }

        if (released > 0)
        {
            await store.TruncateWalAsync(cancellationToken);
            long databaseBytes = (await store.GetStorageSnapshotAsync(cancellationToken)).DatabaseBytes;
            LogPagesReleased(logger, released * files.PageSize, databaseBytes);
        }
    }

    /// <summary>
    /// True while a backlog is settling: pages in use past the intake limit (only
    /// settlement can put them there), or more undelivered rows than acknowledged ones.
    /// </summary>
    private static async Task<bool> SettlingAsync(SqliteEventStore store, QueueStorageSnapshot files, CancellationToken cancellationToken)
    {
        if (files.UsedPages > files.IntakeLimitPages)
        {
            return true;
        }

        QueueSnapshot rows = await store.GetSnapshotAsync(cancellationToken);
        return rows.Queued + rows.Retrying + rows.Uploading > rows.Delivered;
    }

    private async Task ReclaimUnderPressureAsync(SqliteEventStore store, DateTimeOffset now, CancellationToken cancellationToken)
    {
        StorageState disk = store.Storage?.Evaluate(force: true).State ?? StorageState.Normal;
        bool diskPressure = disk is StorageState.Warning or StorageState.Critical;
        QueueStorageSnapshot files = await store.GetStorageSnapshotAsync(cancellationToken);

        // A new event the page limit refused, however far below the trigger: a large event
        // can need more pages than the gap, and sources retry it until it fits. Not for
        // archived queues: a verified segment can still change before its row is deleted.
        long refusedPages = store.TakeRefusedIntakePages();
        if (archive is not null)
        {
            refusedPages = 0;
        }

        if (!diskPressure && refusedPages == 0 && files.PageUtilisationPercent < QueueStorageMonitor.PagePressurePercent)
        {
            return;
        }

        // Low disk: reclaim every eligible row, so new events reuse freed pages instead of
        // growing the file. Page pressure alone: stop once use, counting the refused event,
        // is back at the target. Once new events are refused, intake outranks duplicate
        // detection: the floor no longer protects acknowledged rows (after a large drain
        // they are all recent).
        bool intakeBlocked = refusedPages > 0 || files.PageUtilisationPercent >= DeliveryHealth.PageBackpressurePercent;
        double targetPages = files.IntakeLimitPages * PressureTargetPercent / 100;
        int purged = await PurgeAsync(
            intakeBlocked ? now.AddSeconds(1) : now - settings.PressureRetentionFloor,
            diskPressure ? BatchSize : PressureBatchSize,
            async token => diskPressure
                || (await store.GetStorageSnapshotAsync(token)).UsedPages + refusedPages > targetPages,
            cancellationToken);
        if (purged > 0)
        {
            pressure?.RecordPurge(purged, clock.GetUtcNow());
            QueueStorageSnapshot after = await store.GetStorageSnapshotAsync(cancellationToken);
            LogPressurePurged(
                logger,
                purged,
                diskPressure ? "low-disk" : intakeBlocked ? "intake-blocked" : "queue-pages",
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

                purged = await ledger!.PurgeVerifiedDeliveredAsync(cutoff, batch, cancellationToken);
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
        EventId = 1507,
        Level = LogLevel.Information,
        Message = "Queue retention returned {ReleasedBytes} bytes of free pages to the file system; database now {DatabaseBytes} bytes.")]
    private static partial void LogPagesReleased(ILogger logger, long releasedBytes, long databaseBytes);

    [LoggerMessage(
        EventId = 1506,
        Level = LogLevel.Warning,
        Message = "Queue retention removed {Count} acknowledged event(s) early under storage pressure ({Trigger}); queue pages {BeforePercent}% -> {AfterPercent}% of the ceiling. Acknowledged events younger than {FloorSeconds} seconds are kept unless intake was blocked.")]
    private static partial void LogPressurePurged(
        ILogger logger, int count, string trigger, double beforePercent, double afterPercent, long floorSeconds);

    [LoggerMessage(
        EventId = 1202,
        Level = LogLevel.Warning,
        Message = "Queue retention stopped before purging: archive coverage is not verified ({Reason}; first {FirstSequence}, through {ThroughSequence}).")]
    private static partial void LogCoverageRefused(ILogger logger, string? reason, long firstSequence, long throughSequence);
}
