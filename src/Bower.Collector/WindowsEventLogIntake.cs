using Bower.Packs;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;

namespace Bower.Collector;

/// <summary>
/// Collector side of the Windows Event Log source (see <see cref="PackRecordIntake"/>).
/// <see cref="WindowsEventSubmitOutcome.Queued"/> means durably enqueued; only then can the
/// bookmark move past the event. With the SQLite queue, one read's events share one durable
/// commit (<see cref="QueueEnqueueBatch"/>); <c>Queued</c> then means durable once the
/// batch commits, and the source moves the bookmark only after that.
/// </summary>
internal sealed class CollectorWindowsEventSink(PackRecordIntake intake, SqliteEventStore? queue = null)
    : IWindowsEventSink, IWindowsEventBatchSink
{
    public async ValueTask<IWindowsEventBatch> BeginBatchAsync(CancellationToken cancellationToken) =>
        queue is null ? NoBatch.Instance : new Batch(await queue.BeginEnqueueBatchAsync(cancellationToken));

    private sealed class Batch(QueueEnqueueBatch batch) : IWindowsEventBatch
    {
        public void Join() => batch.Join();

        public Task CommitAsync(CancellationToken cancellationToken) => batch.CommitAsync(cancellationToken);

        public ValueTask DisposeAsync() => batch.DisposeAsync();
    }

    /// <summary>Another queue implementation: each event commits on its own.</summary>
    private sealed class NoBatch : IWindowsEventBatch
    {
        public static readonly NoBatch Instance = new();

        public void Join()
        {
        }

        public Task CommitAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    public async ValueTask<WindowsEventSubmitOutcome> SubmitAsync(
        WindowsEventSubscriptionOptions subscription,
        string record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        PackRecordOutcome outcome = await intake.SubmitAsync(
            subscription.Pack,
            subscription.Parser,
            $"windows-eventlog:{subscription.Id}:{subscription.Pack}:{subscription.Parser}",
            record,
            cancellationToken);
        return outcome switch
        {
            PackRecordOutcome.Queued => WindowsEventSubmitOutcome.Queued,
            PackRecordOutcome.Duplicate => WindowsEventSubmitOutcome.Duplicate,
            PackRecordOutcome.Suppressed => WindowsEventSubmitOutcome.Suppressed,
            PackRecordOutcome.NotSelected => WindowsEventSubmitOutcome.NotSelected,
            PackRecordOutcome.Invalid => WindowsEventSubmitOutcome.Invalid,
            PackRecordOutcome.TooLarge => WindowsEventSubmitOutcome.TooLarge,
            PackRecordOutcome.Unavailable => WindowsEventSubmitOutcome.Unavailable,
            _ => WindowsEventSubmitOutcome.Rejected
        };
    }
}

internal static class WindowsEventLogRoutes
{
    /// <summary>Every subscription must name an active parser of a loaded signed pack; checked at start-up.</summary>
    public static void Validate(WindowsEventLogSourceConfiguration configuration, PolicyBundle bundle)
    {
        foreach (WindowsEventSubscriptionOptions subscription in configuration.Subscriptions)
        {
            if (PackRecordIntake.Parser(bundle, subscription.Pack, subscription.Parser) is null)
            {
                throw new InvalidOperationException(
                    $"Windows Event Log subscription {subscription.Id}: pack {subscription.Pack} parser {subscription.Parser} is not an active parser of a loaded pack.");
            }
        }
    }

    /// <summary>
    /// The local event log service. Fails closed off Windows: the source never starts
    /// without the reader it was configured for.
    /// </summary>
    public static IWindowsEventChannelFactory PlatformChannels() =>
        OperatingSystem.IsWindows()
            ? new WindowsEventLogChannelFactory()
            : throw new PlatformNotSupportedException(
                "BOWER_WINDOWS_EVENTLOG_CONFIG needs Windows: the Windows Event Log source reads the local event log service.");
}

/// <summary>Bookmark table in the queue database, then the subscription loops; stopped first on shutdown.</summary>
internal sealed partial class WindowsEventLogIntakeService(
    WindowsEventLogSource source,
    WindowsEventLogBookmarks bookmarks,
    ILogger<WindowsEventLogIntakeService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await bookmarks.Store.InitializeAsync(cancellationToken);
        await source.StartAsync(cancellationToken);
        foreach (WindowsEventSubscriptionStatus subscription in source.Snapshot())
        {
            LogSubscribed(logger, subscription.Id, subscription.Channel);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken) =>
        await source.DisposeAsync().AsTask().WaitAsync(cancellationToken);

    [LoggerMessage(EventId = 1110, Level = LogLevel.Information, Message = "Windows Event Log subscription {Subscription} reading channel {Channel}.")]
    private static partial void LogSubscribed(ILogger logger, string subscription, string channel);
}

/// <summary>The source cursor table inside the queue database (<c>BOWER_QUEUE_PATH</c>).</summary>
internal sealed class WindowsEventLogBookmarks(string queuePath)
{
    public EfSourceCursorStore Store { get; } = new(queuePath);
}
