using Bower.Abstractions;
using Bower.Persistence;

namespace Bower.Collector.Jobs;

/// <summary>
/// Copies newly stored events into the long-term archive. Reads the queue only; retention
/// consults <see cref="QueueArchive.VerifyCoverageAsync"/> so nothing is purged unarchived.
/// </summary>
public sealed partial class QueueArchiveJob(
    IDurableEventStore queue,
    QueueArchive archive,
    ILogger<QueueArchiveJob> logger)
{
    public const string Id = "queue-archive";

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (queue is not SqliteEventStore store)
        {
            return;
        }

        ArchiveRunResult result = await archive.ArchiveAsync(store, cancellationToken);
        if (result.Segments > 0)
        {
            LogArchived(logger, result.Events, result.Segments, result.HeadSequence);
        }
    }

    [LoggerMessage(
        EventId = 1311,
        Level = LogLevel.Information,
        Message = "Archived {Events} event(s) in {Segments} segment(s); archive head {HeadSequence}.")]
    private static partial void LogArchived(ILogger logger, long events, int segments, long headSequence);
}
