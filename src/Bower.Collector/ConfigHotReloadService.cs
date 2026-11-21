using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

namespace Bower.Collector;

/// <summary>
/// Coordinates zero-downtime hot reload triggers for <see cref="PolicyBundleHolder"/>:
/// SIGHUP on Unix hosts and optional debounced file watching (<c>BOWER_POLICY_WATCH=true</c>).
/// Rapid bursts coalesce into a single serialized reload without closing the queue,
/// dropping active connections or interrupting delivery workers.
/// </summary>
public sealed partial class ConfigHotReloadService(
    PolicyBundleHolder holder,
    CollectorSettings settings,
    ILogger<ConfigHotReloadService> logger) : BackgroundService
{
    private readonly Channel<string> triggers = Channel.CreateBounded<string>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.DropOldest
    });
    private readonly List<FileSystemWatcher> watchers = [];
    private PosixSignalRegistration? sighup;
    private string? lastWatchedFingerprint;

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        sighup = RegisterSighup();
        if (settings.PolicyWatchEnabled)
        {
            lastWatchedFingerprint = CaptureWatchedFingerprint();
            StartWatchers(watchers);
        }

        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        Task? pollTask = settings.PolicyWatchEnabled ? PollWatchedMetadataAsync(linked.Token) : null;
        try
        {
            await foreach (string trigger in triggers.Reader.ReadAllAsync(stoppingToken))
            {
                if (string.Equals(trigger, "watch", StringComparison.Ordinal))
                {
                    // Debounce bursts from atomic saves / multi-file deployments.
                    await Task.Delay(settings.PolicyWatchDebounce, stoppingToken);
                    while (triggers.Reader.TryRead(out _))
                    {
                    }

                    lastWatchedFingerprint = CaptureWatchedFingerprint();
                }

                try
                {
                    await holder.ReloadAsync(trigger, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception)
                {
                    LogTriggerFailure(logger, trigger, exception.GetType().Name);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
        finally
        {
            await linked.CancelAsync();
            if (pollTask is not null)
            {
                try
                {
                    await pollTask;
                }
                catch (OperationCanceledException)
                {
                }
            }

            DisposeResources();
        }
    }

    public override void Dispose()
    {
        DisposeResources();
        base.Dispose();
    }

    private void DisposeResources()
    {
        sighup?.Dispose();
        sighup = null;
        foreach (FileSystemWatcher watcher in watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        watchers.Clear();
    }

    private async Task PollWatchedMetadataAsync(CancellationToken stoppingToken)
    {
        TimeSpan interval = settings.PolicyWatchDebounce > TimeSpan.FromMilliseconds(250)
            ? settings.PolicyWatchDebounce
            : TimeSpan.FromMilliseconds(250);
        using PeriodicTimer timer = new(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            string current = CaptureWatchedFingerprint();
            if (!string.Equals(current, lastWatchedFingerprint, StringComparison.Ordinal))
            {
                lastWatchedFingerprint = current;
                triggers.Writer.TryWrite("watch");
            }
        }
    }

    private string CaptureWatchedFingerprint()
    {
        StringBuilder sb = new();
        if (Directory.Exists(settings.PolicyDirectory))
        {
            try
            {
                foreach (string file in Directory.GetFiles(settings.PolicyDirectory).Order(StringComparer.Ordinal))
                {
                    AppendFileStat(sb, file);
                }
            }
            catch (IOException)
            {
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.PrivacyProfilePath))
        {
            AppendFileStat(sb, Path.GetFullPath(settings.PrivacyProfilePath));
        }

        foreach (string packPath in settings.Packs.Order(StringComparer.Ordinal))
        {
            AppendFileStat(sb, Path.GetFullPath(packPath));
        }

        return sb.ToString();
    }

    private static void AppendFileStat(StringBuilder sb, string path)
    {
        try
        {
            FileInfo info = new(path);
            if (!info.Exists)
            {
                sb.Append(path).Append("|missing\n");
                return;
            }

            sb.Append(path).Append('|').Append(info.Length).Append('|').Append(info.LastWriteTimeUtc.Ticks).Append('\n');
        }
        catch (IOException)
        {
            sb.Append(path).Append("|io-error\n");
        }
    }

    private PosixSignalRegistration? RegisterSighup()
    {
        if (OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            return PosixSignalRegistration.Create(PosixSignal.SIGHUP, context =>
            {
                context.Cancel = true;
                triggers.Writer.TryWrite("sighup");
            });
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }

    private void StartWatchers(List<FileSystemWatcher> targetWatchers)
    {
        HashSet<string> watchedKeys = new(StringComparer.Ordinal);
        if (Directory.Exists(settings.PolicyDirectory))
        {
            AddWatcher(targetWatchers, watchedKeys, Path.GetFullPath(settings.PolicyDirectory), "*");
        }

        if (!string.IsNullOrWhiteSpace(settings.PrivacyProfilePath))
        {
            string full = Path.GetFullPath(settings.PrivacyProfilePath);
            if (Path.GetDirectoryName(full) is { } dir && Directory.Exists(dir))
            {
                AddWatcher(targetWatchers, watchedKeys, dir, Path.GetFileName(full));
            }
        }

        foreach (string packPath in settings.Packs)
        {
            string full = Path.GetFullPath(packPath);
            if (Path.GetDirectoryName(full) is { } dir && Directory.Exists(dir))
            {
                AddWatcher(targetWatchers, watchedKeys, dir, Path.GetFileName(full));
            }
        }

        LogWatchStarted(logger, targetWatchers.Count, (int)settings.PolicyWatchDebounce.TotalMilliseconds);
    }

    private void AddWatcher(
        List<FileSystemWatcher> targetWatchers,
        HashSet<string> watchedKeys,
        string directory,
        string filter)
    {
        string key = $"{directory}\u001f{filter}";
        if (!watchedKeys.Add(key))
        {
            return;
        }

        FileSystemWatcher watcher = new(directory, filter)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.Size,
            IncludeSubdirectories = false
        };
        FileSystemEventHandler onChanged = (_, _) => triggers.Writer.TryWrite("watch");
        RenamedEventHandler onRenamed = (_, _) => triggers.Writer.TryWrite("watch");
        ErrorEventHandler onError = (_, _) => triggers.Writer.TryWrite("watch");
        watcher.Changed += onChanged;
        watcher.Created += onChanged;
        watcher.Deleted += onChanged;
        watcher.Renamed += onRenamed;
        watcher.Error += onError;
        watcher.EnableRaisingEvents = true;
        targetWatchers.Add(watcher);
    }

    [LoggerMessage(
        EventId = 1704,
        Level = LogLevel.Information,
        Message = "Policy file watch enabled on {WatcherCount} target(s) with {DebounceMilliseconds} ms debounce.")]
    private static partial void LogWatchStarted(ILogger logger, int watcherCount, int debounceMilliseconds);

    [LoggerMessage(
        EventId = 1705,
        Level = LogLevel.Warning,
        Message = "Hot reload trigger ({Trigger}) failed with {ExceptionType}; the previous policy bundle stays active.")]
    private static partial void LogTriggerFailure(ILogger logger, string trigger, string exceptionType);
}
