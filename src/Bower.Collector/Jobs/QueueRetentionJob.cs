using Bower.Abstractions;
using Hangfire;

namespace Bower.Collector.Jobs;

/// <summary>
/// Removes acknowledged events once they are older than the duplicate-detection window.
/// Undelivered, retrying and dead-lettered events are never touched.
/// </summary>
public sealed partial class QueueRetentionJob(
    IDurableEventStore queue,
    TimeProvider clock,
    CollectorSettings settings,
    ILogger<QueueRetentionJob> logger)
{
    public const string Id = "queue-retention";
    private const int BatchSize = 5_000;

    [AutomaticRetry(Attempts = 3)]
    [DisableConcurrentExecution(timeoutInSeconds: 600)]
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset cutoff = clock.GetUtcNow() - settings.DeliveredRetention;
        int total = 0;
        int purged;
        do
        {
            purged = await queue.PurgeDeliveredAsync(cutoff, BatchSize, cancellationToken);
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
}
