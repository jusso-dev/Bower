using Bower.Abstractions;
using Hangfire;

namespace Bower.Collector.Jobs;

/// <summary>Checkpoints the WAL and refreshes SQLite query statistics.</summary>
public sealed class QueueMaintenanceJob(IDurableEventStore queue)
{
    public const string Id = "queue-maintenance";

    [AutomaticRetry(Attempts = 2)]
    [DisableConcurrentExecution(timeoutInSeconds: 600)]
    public Task RunAsync(CancellationToken cancellationToken) =>
        queue.MaintainAsync(cancellationToken);
}
