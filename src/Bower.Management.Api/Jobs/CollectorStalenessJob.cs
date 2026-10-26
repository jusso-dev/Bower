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
    public const int RetryAttempts = 2;
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(15);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        int marked = await store.MarkStaleAsync(now - StaleAfter, now, cancellationToken);
        if (marked > 0)
        {
            LogMarkedStale(logger, marked);
        }

        // Collectors that stopped heartbeating, were suspended or downgraded to v1 never run
        // the v2 exchange that expires their commands, so expire and audit them here.
        int expired = await store.ExpireOverdueCommandsAsync(now, cancellationToken);
        if (expired > 0)
        {
            LogCommandsExpired(logger, expired);
        }
    }

    [LoggerMessage(
        EventId = 2102,
        Level = LogLevel.Information,
        Message = "{Count} collector command(s) expired without a result.")]
    private static partial void LogCommandsExpired(ILogger logger, int count);

    [LoggerMessage(
        EventId = 2101,
        Level = LogLevel.Warning,
        Message = "{Count} collector(s) stopped reporting and were marked stale.")]
    private static partial void LogMarkedStale(ILogger logger, int count);
}
