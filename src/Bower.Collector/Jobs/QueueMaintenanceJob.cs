using Bower.Abstractions;

namespace Bower.Collector.Jobs;

/// <summary>Checkpoints the WAL and refreshes SQLite query statistics.</summary>
public sealed class QueueMaintenanceJob(IDurableEventStore queue)
{
    public const string Id = "queue-maintenance";
    public const int RetryAttempts = 2;

    public Task RunAsync(CancellationToken cancellationToken) =>
        queue.MaintainAsync(cancellationToken);
}
