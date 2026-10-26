using Bower.Abstractions;
using Bower.Persistence;

namespace Bower.Collector.Jobs;

/// <summary>
/// Removes acknowledged events once they are older than the duplicate-detection window.
/// Undelivered, retrying and dead-lettered events are never touched, nor are events a
/// configured archive does not verifiably hold for this queue: unverified coverage purges
/// nothing.
/// </summary>
public sealed partial class QueueRetentionJob(
    IDurableEventStore queue,
    TimeProvider clock,
    CollectorSettings settings,
    ILogger<QueueRetentionJob> logger,
    QueueArchive? archive = null)
{
    public const string Id = "queue-retention";
    public const int RetryAttempts = 3;
    private const int BatchSize = 5_000;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset cutoff = clock.GetUtcNow() - settings.DeliveredRetention;
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
                return;
            }
        }

        int total = 0;
        int purged;
        do
        {
            if (coverage is not null)
            {
                // The cache trusts size and write time; re-hash the segments holding this
                // batch so silent corruption is caught before their last local copy goes.
                long through = coverage.ThroughSequence;
                IReadOnlyList<long> batch = await ledger!.ReadPurgeCandidateSequencesAsync(cutoff, BatchSize, through, cancellationToken);
                if (batch.Count == 0)
                {
                    break;
                }

                if (await archive!.VerifySegmentsForPurgeAsync(batch, cancellationToken) is { } reason)
                {
                    LogCoverageRefused(logger, reason, coverage.FirstSequence, through);
                    break;
                }

                purged = await queue.PurgeDeliveredAsync(cutoff, BatchSize, through, cancellationToken);
            }
            else
            {
                purged = await queue.PurgeDeliveredAsync(cutoff, BatchSize, cancellationToken);
            }

            total += purged;
        }
        while (purged == BatchSize && !cancellationToken.IsCancellationRequested);

        LogPurged(logger, total);
    }

    [LoggerMessage(
        EventId = 1201,
        Level = LogLevel.Information,
        Message = "Queue retention removed {Count} acknowledged event(s).")]
    private static partial void LogPurged(ILogger logger, int count);

    [LoggerMessage(
        EventId = 1202,
        Level = LogLevel.Warning,
        Message = "Queue retention stopped before purging: archive coverage is not verified ({Reason}; first {FirstSequence}, through {ThroughSequence}).")]
    private static partial void LogCoverageRefused(ILogger logger, string? reason, long firstSequence, long throughSequence);
}
