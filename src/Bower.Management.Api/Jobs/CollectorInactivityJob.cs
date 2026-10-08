using Hangfire;

namespace Bower.Management.Api.Jobs;

/// <summary>
/// Suspends collector identities that have not reported for the inactivity window
/// (Elastic Fleet revokes inactive agents' credentials the same way). Suspended
/// collectors are refused at heartbeat until an administrator reinstates them.
/// </summary>
public sealed partial class CollectorInactivityJob(
    ManagementStore store,
    TimeProvider clock,
    IConfiguration configuration,
    ILogger<CollectorInactivityJob> logger)
{
    public const string Id = "collector-inactivity";

    [AutomaticRetry(Attempts = 2)]
    [DisableConcurrentExecution(timeoutInSeconds: 300)]
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        int days = configuration.GetValue("BOWER_COLLECTOR_INACTIVE_DAYS", 30);
        if (days is < 1 or > 365)
        {
            days = 30;
        }

        DateTimeOffset now = clock.GetUtcNow();
        int suspended = await store.SuspendInactiveAsync(now.AddDays(-days), now, cancellationToken);
        if (suspended > 0)
        {
            LogSuspended(logger, suspended, days);
        }
    }

    [LoggerMessage(
        EventId = 2102,
        Level = LogLevel.Warning,
        Message = "{Count} collector(s) inactive for {Days} days were suspended.")]
    private static partial void LogSuspended(ILogger logger, int count, int days);
}
