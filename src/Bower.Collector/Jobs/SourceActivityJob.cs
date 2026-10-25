using Bower.Abstractions;
using Bower.Core;

namespace Bower.Collector.Jobs;

/// <summary>
/// Persists per-source last-seen times so silence detection survives restarts. Reporting
/// metadata only: never touches event, lease or delivery state.
/// </summary>
public sealed class SourceActivityJob(IDurableEventStore queue, PipelineTelemetry telemetry)
{
    public const string Id = "source-activity";

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<SourceActivity> changed = telemetry.TakeChangedSources();
        try
        {
            await queue.UpsertSourceActivityAsync(changed, cancellationToken);
        }
        catch
        {
            telemetry.MarkChanged(changed);
            throw;
        }
    }
}
