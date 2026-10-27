using System.Text;
using Bower.Abstractions;

namespace Bower.Source.WindowsEventLog;

/// <summary>What happened to one record handed to the collector.</summary>
public enum WindowsEventSubmitOutcome
{
    /// <summary>Durably enqueued. Only then can the bookmark move past the event.</summary>
    Queued,
    Duplicate,
    Suppressed,

    /// <summary>The pack parser's filter did not select the record.</summary>
    NotSelected,

    /// <summary>Policy rejected or quarantined the event.</summary>
    Rejected,

    /// <summary>The record does not satisfy the pack parser's field types.</summary>
    Invalid,
    TooLarge,

    /// <summary>Queue at capacity or ingest gated: stop reading and retry the same event.</summary>
    Unavailable
}

/// <summary>Collector side of the source: pack parser, redaction, policy and durable enqueue.</summary>
public interface IWindowsEventSink
{
    ValueTask<WindowsEventSubmitOutcome> SubmitAsync(
        WindowsEventSubscriptionOptions subscription,
        string record,
        CancellationToken cancellationToken);
}

/// <summary>One event as the Windows event log service returned it for a subscription query.</summary>
/// <param name="Message">Publisher message string, when requested and the publisher could render it.</param>
public sealed record WindowsRawEvent(long RecordId, string Xml, string? Message);

/// <summary>Record ids currently in a channel; both 0 when it is empty.</summary>
public sealed record WindowsChannelRange(long OldestRecordId, long NewestRecordId);

/// <summary>One channel. Implementations return only events matching the query.</summary>
public interface IWindowsEventChannel : IDisposable
{
    /// <summary>Channel metadata only; reads no events.</summary>
    WindowsChannelRange GetRange();

    IReadOnlyList<WindowsRawEvent> Read(WindowsEventQuery query, int maximum, bool includeMessage, CancellationToken cancellationToken);
}

public interface IWindowsEventChannelFactory
{
    IWindowsEventChannel Open(string channel);
}

/// <summary>Stable, metadata-only codes for channel and subscription failures.</summary>
public static class WindowsEventChannelFailures
{
    public const string ChannelNotFound = "winevt-channel-not-found";
    public const string AccessDenied = "winevt-access-denied";
    public const string QueryInvalid = "winevt-query-invalid";
    public const string ReadFailed = "winevt-read-failed";
    public const string BookmarkInvalid = "winevt-bookmark-invalid";
    public const string SubmitFailed = "winevt-submit-failed";

    /// <summary>Any other failure, for example the bookmark store.</summary>
    public const string SourceFailed = "winevt-source-failed";
}

public sealed class WindowsEventChannelException(string code, Exception? innerException = null)
    : Exception(code, innerException)
{
    public string Code { get; } = code;
}

/// <summary>Per-subscription counters since start. Metadata only: no event content, ever.</summary>
/// <param name="State"><c>starting</c>, <c>running</c>, <c>backpressure</c>, <c>stopped</c> or a failure code.</param>
/// <param name="BookmarkRecordId">Durable position: the last record id handled.</param>
public sealed record WindowsEventSubscriptionStatus(
    string Id,
    string Channel,
    string State,
    long? BookmarkRecordId,
    long EventsRead,
    long BytesRead,
    long Queued,
    long Duplicates,
    long Suppressed,
    long NotSelected,
    long Rejected,
    long ParserErrors,
    long Malformed,
    long Oversized,
    long Retries,
    long SubmitFailures,
    long ReadErrors,
    long Gaps,
    long Resets,
    long CursorConflicts,
    DateTimeOffset? LastEventAt,
    DateTimeOffset? LastPollAt);

/// <param name="Read">Events the channel returned for the query.</param>
/// <param name="Backpressure">The queue could not take an event; it is retried next time.</param>
/// <param name="More">A full batch was handled; read again without waiting.</param>
public sealed record WindowsEventPollResult(int Read, bool Backpressure, bool More);

/// <summary>
/// Pull-mode Windows Event Log subscriptions with durable bookmarks.
/// <para>
/// Each subscription queries its channel with a generated filter (event ID allow-list,
/// optional providers, records after the bookmark), so the event log service returns
/// only allow-listed events. Events are handled one at a time: the bookmark moves past an
/// event only once it is durably enqueued or definitively dropped, and is committed to the
/// queue database after each batch. A crash between enqueue and commit re-reads those
/// events; their deterministic event ids make the queue drop them as duplicates, so a
/// restart neither loses nor duplicates events. A full queue stops reading (the events
/// stay in the channel) instead of buffering or dropping.
/// </para>
/// </summary>
public sealed class WindowsEventLogSource : IAsyncDisposable
{
    private readonly IWindowsEventSink sink;
    private readonly ISourceCursorStore cursors;
    private readonly IWindowsEventChannelFactory channels;
    private readonly TimeProvider clock;
    private readonly Dictionary<string, Subscription> subscriptions;
    private readonly CancellationTokenSource stopping = new();
    private readonly List<Task> running = [];
    private int started;
    private int disposed;

    public WindowsEventLogSource(
        WindowsEventLogSourceConfiguration configuration,
        IWindowsEventSink sink,
        ISourceCursorStore cursors,
        IWindowsEventChannelFactory channels,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(cursors);
        ArgumentNullException.ThrowIfNull(channels);
        this.sink = sink;
        this.cursors = cursors;
        this.channels = channels;
        this.clock = clock ?? TimeProvider.System;
        subscriptions = configuration.Subscriptions.ToDictionary(
            options => options.Id,
            options => new Subscription(options),
            StringComparer.Ordinal);
    }

    /// <summary>Wait before retrying an event the queue could not take yet.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Longest wait between attempts after repeated channel or storage failures.</summary>
    public TimeSpan MaximumBackoff { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Starts one reader loop per subscription. Failures are retried with backoff and reported in <see cref="Snapshot"/>.</summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Interlocked.Exchange(ref started, 1) != 0)
        {
            throw new InvalidOperationException("Windows Event Log source is already started.");
        }

        CancellationToken token = stopping.Token;
        foreach (Subscription subscription in subscriptions.Values)
        {
            running.Add(Task.Run(() => RunAsync(subscription, token), CancellationToken.None));
        }

        return Task.CompletedTask;
    }

    public IReadOnlyList<WindowsEventSubscriptionStatus> Snapshot() =>
        [.. subscriptions.Values.Select(subscription => subscription.Snapshot())];

    /// <summary>
    /// One read of one subscription: resume from the bookmark, hand each event to the sink
    /// and commit the new position. Throws <see cref="WindowsEventChannelException"/> on a
    /// channel, bookmark or sink failure (progress made before it is still committed).
    /// </summary>
    public async Task<WindowsEventPollResult> PollOnceAsync(string subscriptionId, CancellationToken cancellationToken)
    {
        Subscription subscription = subscriptions[subscriptionId];
        await subscription.Gate.WaitAsync(cancellationToken);
        try
        {
            return await PollAsync(subscription, cancellationToken);
        }
        catch (WindowsEventChannelException exception)
        {
            subscription.State = exception.Code;
            if (exception.Code is not (WindowsEventChannelFailures.SubmitFailed or WindowsEventChannelFailures.BookmarkInvalid))
            {
                Interlocked.Increment(ref subscription.Counters.ReadErrors);
            }

            throw;
        }
        finally
        {
            subscription.Gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await stopping.CancelAsync();
        try
        {
            await Task.WhenAll(running);
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }

        foreach (Subscription subscription in subscriptions.Values)
        {
            subscription.Channel?.Dispose();
            subscription.Gate.Dispose();
            subscription.State = "stopped";
        }

        stopping.Dispose();
    }

    private async Task RunAsync(Subscription subscription, CancellationToken cancellationToken)
    {
        TimeSpan interval = TimeSpan.FromSeconds(subscription.Options.PollIntervalSeconds);
        int failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            TimeSpan wait;
            try
            {
                WindowsEventPollResult result = await PollOnceAsync(subscription.Options.Id, cancellationToken);
                failures = 0;
                wait = result.Backpressure ? RetryDelay : result.More ? TimeSpan.Zero : interval;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // Channel missing, access denied, storage or sink failure: keep the bookmark,
                // back off and retry. The state carries the code; nothing else is reported.
                if (exception is not WindowsEventChannelException)
                {
                    subscription.State = WindowsEventChannelFailures.SourceFailed;
                }

                failures = Math.Min(failures + 1, 16);
                wait = TimeSpan.FromTicks(Math.Min(interval.Ticks << Math.Min(failures, 10), MaximumBackoff.Ticks));
            }

            if (wait > TimeSpan.Zero)
            {
                try
                {
                    await Task.Delay(wait, clock, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private async Task<WindowsEventPollResult> PollAsync(Subscription subscription, CancellationToken cancellationToken)
    {
        WindowsEventSubscriptionOptions options = subscription.Options;
        Interlocked.Exchange(ref subscription.LastPollTicks, clock.GetUtcNow().UtcTicks);
        SourceCursorSnapshot? snapshot = await cursors.ReadAsync(options.SourceId, cancellationToken);
        WindowsEventBookmark? bookmark;
        try
        {
            bookmark = snapshot is null ? null : WindowsEventBookmark.Deserialize(snapshot.Value, options.Channel);
        }
        catch (InvalidDataException exception)
        {
            // Never reinterpret or silently reset someone else's position: fail closed.
            throw new WindowsEventChannelException(WindowsEventChannelFailures.BookmarkInvalid, exception);
        }

        subscription.Channel ??= channels.Open(options.Channel);
        WindowsChannelRange range = subscription.Channel.GetRange();
        long version = snapshot?.Version ?? 0;
        long position;
        if (bookmark is null)
        {
            // First start: begin at the newest event unless asked to read what is there.
            position = options.ReadExisting ? 0 : range.NewestRecordId;
            version = await CommitAsync(subscription, version, position) ?? version;
            if (!options.ReadExisting)
            {
                subscription.State = "running";
                return new WindowsEventPollResult(0, false, false);
            }
        }
        else
        {
            position = bookmark.RecordId;
            subscription.SetBookmark(position);
            if (range.NewestRecordId < position)
            {
                // Cleared or recreated: record ids started again, everything there now is new.
                Interlocked.Increment(ref subscription.Counters.Resets);
                position = 0;
            }
            else if (range.OldestRecordId > position + 1)
            {
                // Overwritten (log full) before they were scanned; some may have been
                // allow-listed. Those records no longer exist, so carry on from the oldest.
                Interlocked.Increment(ref subscription.Counters.Gaps);
                position = range.OldestRecordId - 1;
            }
        }

        long start = bookmark?.RecordId ?? position;
        IReadOnlyList<WindowsRawEvent> events = [];
        bool backpressure = false;
        try
        {
            events = subscription.Channel.Read(
                WindowsEventQuery.For(options, position),
                options.BatchSize,
                options.IncludeMessage,
                cancellationToken);
            foreach (WindowsRawEvent raw in events)
            {
                if (raw.RecordId <= position)
                {
                    continue; // Never move backwards.
                }

                if (!await HandleAsync(subscription, raw, cancellationToken))
                {
                    backpressure = true;
                    break;
                }

                position = raw.RecordId;
            }

            if (!backpressure && events.Count < options.BatchSize && range.NewestRecordId > position)
            {
                // Caught up: the query returned every matching event up to the newest record
                // the channel had before it ran, so nothing at or below it is left to read.
                // Keeping the bookmark near the head makes gap and reset detection exact.
                position = range.NewestRecordId;
            }
        }
        finally
        {
            if (position != start)
            {
                // Committed even when stopping or failing mid-batch (and after a reset or gap
                // even if the read failed), so handled events are not re-read.
                await CommitAsync(subscription, version, position);
            }
        }

        subscription.State = backpressure ? "backpressure" : "running";
        return new WindowsEventPollResult(events.Count, backpressure, !backpressure && events.Count >= options.BatchSize);
    }

    /// <returns>False when the queue could not take the event (it is retried later).</returns>
    private async Task<bool> HandleAsync(Subscription subscription, WindowsRawEvent raw, CancellationToken cancellationToken)
    {
        Counters counters = subscription.Counters;
        Interlocked.Increment(ref counters.EventsRead);
        Interlocked.Add(ref counters.BytesRead, Encoding.UTF8.GetByteCount(raw.Xml));
        Interlocked.Exchange(ref subscription.LastEventTicks, clock.GetUtcNow().UtcTicks);
        string record;
        try
        {
            WindowsEvent parsed = WindowsEventXml.Parse(raw.Xml);
            record = WindowsEventRecord.Build(parsed, subscription.Options.Id, subscription.Options.IncludeMessage ? raw.Message : null);
        }
        catch (WindowsEventFormatException exception)
        {
            // Deterministic: re-reading gives the same result, so the event is dropped and counted.
            Interlocked.Increment(ref exception.Code is WindowsEventFailures.XmlTooLarge or WindowsEventFailures.RecordTooLarge
                ? ref counters.Oversized
                : ref counters.Malformed);
            return true;
        }

        WindowsEventSubmitOutcome outcome;
        try
        {
            outcome = await sink.SubmitAsync(subscription.Options, record, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Interlocked.Increment(ref counters.SubmitFailures);
            throw new WindowsEventChannelException(WindowsEventChannelFailures.SubmitFailed, exception);
        }

        switch (outcome)
        {
            case WindowsEventSubmitOutcome.Unavailable:
                Interlocked.Increment(ref counters.Retries);
                return false;
            case WindowsEventSubmitOutcome.Queued:
                Interlocked.Increment(ref counters.Queued);
                break;
            case WindowsEventSubmitOutcome.Duplicate:
                Interlocked.Increment(ref counters.Duplicates);
                break;
            case WindowsEventSubmitOutcome.Suppressed:
                Interlocked.Increment(ref counters.Suppressed);
                break;
            case WindowsEventSubmitOutcome.NotSelected:
                Interlocked.Increment(ref counters.NotSelected);
                break;
            case WindowsEventSubmitOutcome.Invalid:
                Interlocked.Increment(ref counters.ParserErrors);
                break;
            case WindowsEventSubmitOutcome.TooLarge:
                Interlocked.Increment(ref counters.Oversized);
                break;
            default:
                Interlocked.Increment(ref counters.Rejected);
                break;
        }

        return true;
    }

    /// <returns>The new cursor version, or null when another writer moved the cursor first.</returns>
    private async Task<long?> CommitAsync(Subscription subscription, long version, long position)
    {
        WindowsEventSubscriptionOptions options = subscription.Options;
        // Not cancellable: progress already made must survive a stop.
        bool advanced = await cursors.TryAdvanceAsync(
            options.SourceId,
            version,
            WindowsEventBookmark.At(options.Channel, position).Serialize(),
            clock.GetUtcNow(),
            CancellationToken.None);
        if (!advanced)
        {
            // Another writer moved it; the next read resumes from theirs and duplicates dedupe.
            Interlocked.Increment(ref subscription.Counters.CursorConflicts);
            return null;
        }

        subscription.SetBookmark(position);
        return version + 1;
    }

    private sealed class Subscription(WindowsEventSubscriptionOptions options)
    {
        private long bookmarkRecordId = -1;
        private string state = "starting";

        public WindowsEventSubscriptionOptions Options { get; } = options;

        public SemaphoreSlim Gate { get; } = new(1, 1);

        public IWindowsEventChannel? Channel { get; set; }

        public Counters Counters { get; } = new();

        public long LastEventTicks;

        public long LastPollTicks;

        public string State
        {
            get => Volatile.Read(ref state);
            set => Volatile.Write(ref state, value);
        }

        public void SetBookmark(long recordId) => Interlocked.Exchange(ref bookmarkRecordId, recordId);

        public WindowsEventSubscriptionStatus Snapshot()
        {
            long bookmark = Interlocked.Read(ref bookmarkRecordId);
            long lastEvent = Interlocked.Read(ref LastEventTicks);
            long lastPoll = Interlocked.Read(ref LastPollTicks);
            return new WindowsEventSubscriptionStatus(
                Options.Id,
                Options.Channel,
                State,
                bookmark < 0 ? null : bookmark,
                Interlocked.Read(ref Counters.EventsRead),
                Interlocked.Read(ref Counters.BytesRead),
                Interlocked.Read(ref Counters.Queued),
                Interlocked.Read(ref Counters.Duplicates),
                Interlocked.Read(ref Counters.Suppressed),
                Interlocked.Read(ref Counters.NotSelected),
                Interlocked.Read(ref Counters.Rejected),
                Interlocked.Read(ref Counters.ParserErrors),
                Interlocked.Read(ref Counters.Malformed),
                Interlocked.Read(ref Counters.Oversized),
                Interlocked.Read(ref Counters.Retries),
                Interlocked.Read(ref Counters.SubmitFailures),
                Interlocked.Read(ref Counters.ReadErrors),
                Interlocked.Read(ref Counters.Gaps),
                Interlocked.Read(ref Counters.Resets),
                Interlocked.Read(ref Counters.CursorConflicts),
                lastEvent == 0 ? null : new DateTimeOffset(lastEvent, TimeSpan.Zero),
                lastPoll == 0 ? null : new DateTimeOffset(lastPoll, TimeSpan.Zero));
        }
    }

    private sealed class Counters
    {
        public long EventsRead;
        public long BytesRead;
        public long Queued;
        public long Duplicates;
        public long Suppressed;
        public long NotSelected;
        public long Rejected;
        public long ParserErrors;
        public long Malformed;
        public long Oversized;
        public long Retries;
        public long SubmitFailures;
        public long ReadErrors;
        public long Gaps;
        public long Resets;
        public long CursorConflicts;
    }
}
