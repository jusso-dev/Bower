namespace Bower.Collector.Jobs;

/// <summary>
/// Hourly removal of abandoned atomic-write temporaries in the collector's own state
/// directories (#138). Idempotent maintenance only: no queue or delivery state.
/// </summary>
public sealed class TemporaryFileSweepJob(CollectorSettings settings, TimeProvider clock, ILogger<TemporaryFileSweepJob> logger)
{
    public const string Id = "temporary-file-sweep";

    /// <summary>Directories whose <c>.NAME.GUID.tmp</c> files belong to the collector.</summary>
    public static IEnumerable<string> Directories(CollectorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        yield return Path.GetDirectoryName(Path.GetFullPath(settings.QueuePath)) ?? ".";
        yield return settings.ManagedPrivacyCacheDirectory;
        yield return settings.ManagementCredentialDirectory;
        yield return settings.ManagementCommandDirectory;
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int removed = CrashRecovery.SweepTemporaryFiles(Directories(settings), clock.GetUtcNow());
        if (removed > 0)
        {
            CrashRecoveryLog.TemporaryFilesRemoved(logger, removed);
        }

        return Task.CompletedTask;
    }
}
