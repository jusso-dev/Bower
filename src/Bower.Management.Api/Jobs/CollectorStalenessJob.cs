using Hangfire;

namespace Bower.Management.Api.Jobs;

/// <summary>
/// Flags approved or active collectors that stopped reporting, so a silent collector shows
/// up in the console and the audit trail instead of only as an old timestamp.
/// </summary>
public sealed partial class CollectorStalenessJob(
    ManagementStore store,
    TimeProvider clock,
    ILogger<CollectorStalenessJob> logger)
{
    public const string Id = "collector-staleness";
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(15);

    [AutomaticRetry(Attempts = 2)]
    [DisableConcurrentExecution(timeoutInSeconds: 120)]
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        int marked = await store.MarkStaleAsync(now - StaleAfter, now, cancellationToken);
        if (marked > 0)
        {
            LogMarkedStale(logger, marked);
        }
    }

    [LoggerMessage(
        EventId = 2101,
        Level = LogLevel.Warning,
        Message = "{Count} collector(s) stopped reporting and were marked stale.")]
    private static partial void LogMarkedStale(ILogger logger, int count);
}
