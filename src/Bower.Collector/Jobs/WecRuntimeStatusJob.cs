using Bower.Source.WindowsEventLog;

namespace Bower.Collector.Jobs;

/// <summary>
/// Polls <c>wecutil gr</c> on a schedule for configured WEC subscriptions so <c>/v1/status</c>
/// and management heartbeats carry per-client runtime counts without stalling HTTP requests.
/// </summary>
public sealed class WecRuntimeStatusJob(WecRuntimeStatusTracker tracker)
{
    public const string Id = "wec-runtime-status";

    public Task RunAsync(CancellationToken cancellationToken) =>
        tracker.RefreshAsync(cancellationToken);
}
