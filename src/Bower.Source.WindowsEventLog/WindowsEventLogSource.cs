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

/// <summary>
/// Optional group commit: the events of one read become durable together, instead of one
/// durable commit per event (which bounds a WEC to the disk's flush latency). Nothing a batch
/// queued is durable before <see cref="IWindowsEventBatch.CommitAsync"/>, so the bookmark only
/// moves after it.
/// </summary>
public interface IWindowsEventBatchSink
{
    ValueTask<IWindowsEventBatch> BeginBatchAsync(CancellationToken cancellationToken);
}

/// <summary>One read's submissions; disposing without committing rolls them back.</summary>
public interface IWindowsEventBatch : IAsyncDisposable
{
    /// <summary>
    /// Routes the calling flow's submissions into this batch. Call it directly from the reading
    /// method (it sets async-local state that flows only to calls made after it).
    /// </summary>
    void Join();

    /// <returns>
    /// False when the queue refused the batch (full volume or page ceiling at commit, or an
    /// earlier refusal lost the transaction): nothing was written, and the read is retried as
    /// backpressure.
    /// </returns>
    Task<bool> CommitAsync(CancellationToken cancellationToken);
}

/// <summary>A batching sink that can commit its queue and cursor in one transaction.</summary>
public interface IWindowsEventAtomicBatch : IWindowsEventBatch
{
    bool CanAdvanceCursor(ISourceCursorStore cursors);
    void BeginRecord();
    void EndRecord(bool handled);
    Task<WindowsEventAtomicCommit> CommitWithCursorAsync(
        ISourceCursorStore cursors, string sourceId, long expectedVersion, string value,
        DateTimeOffset updatedAt, CancellationToken cancellationToken);
}

/// <summary>The result of committing a batch and its cursor together.</summary>
public enum WindowsEventAtomicCommit { Committed, Refused, Conflict }

/// <summary>One event as the Windows event log service returned it for a subscription query.</summary>
/// <param name="Message">Publisher message string, when requested and the publisher could render it.</param>
public sealed record WindowsRawEvent(long RecordId, string Xml, string? Message);

/// <summary>Record ids currently in a channel; both 0 when it is empty.</summary>
public sealed record WindowsChannelRange(long OldestRecordId, long NewestRecordId);

/// <summary>One channel. Implementations return only events matching the query.</summary>
public interface IWindowsEventChannel : IDisposable
{
    /// <summary>Channel boundary record IDs only; never renders event content.</summary>
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

    /// <summary>A detected reset or gap could not be reconciled with a competing cursor.</summary>
    public const string CursorUnreconciled = "winevt-cursor-unreconciled";

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
/// queue database after each batch. A sink that supports <see cref="IWindowsEventBatchSink"/>
/// makes one read's events durable in one commit (group commit); the bookmark then moves only
/// after that commit, and a failure before it rolls the whole read back to be read again. A crash between enqueue and commit re-reads those
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

    /// <summary>
    /// Recognises contention on the bookmark and queue store (the collector supplies SQLite
    /// busy/locked). Such a poll is retried after <see cref="RetryDelay"/> as backpressure,
    /// not reported as a source failure; the bookmark is unchanged, so nothing is skipped.
    /// </summary>
    public Func<Exception, bool> IsTransientStorageFailure { get; init; } = static _ => false;

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
            catch (Exception exception) when (IsTransientStorageFailure(exception))
            {
                // A different failure may have replaced the visible state since the
                // conflict. A busy read cannot reconcile it: restore the persistent
                // unhealthy state until the pending reposition is actually resolved.
                subscription.State = subscription.Reposition is { ConflictObserved: true }
                    ? WindowsEventChannelFailures.CursorUnreconciled : "backpressure";
                Interlocked.Increment(ref subscription.Counters.Retries);
                failures = 0;
                wait = RetryDelay;
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
            // A pending reposition must compare the raw CAS value before interpreting a
            // competing writer's value, even when that value is malformed.
            bookmark = snapshot is null || subscription.Reposition is not null
                ? null : WindowsEventBookmark.Deserialize(snapshot.Value, options.Channel);
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
        if (subscription.Reposition is { } pendingReposition)
        {
            // A reset/gap was observed but its baseline could not be saved. The channel
            // may since have grown past the old bookmark: never infer that reset vanished.
            bool unchanged = snapshot is not null && snapshot.Version == pendingReposition.Version
                && string.Equals(snapshot.Value, pendingReposition.Value, StringComparison.Ordinal);
            bool baselineCommitted = snapshot is not null && pendingReposition.Version < long.MaxValue
                && snapshot.Version == pendingReposition.Version + 1
                && string.Equals(snapshot.Value,
                    WindowsEventBookmark.At(options.Channel, pendingReposition.Position).Serialize(), StringComparison.Ordinal);
            if (pendingReposition.ConflictObserved || (!unchanged && !baselineCommitted))
            {
                // A competing writer moved the cursor. Its generation is unknown, so do
                // not overwrite it or resume from it while this reset is unresolved. A
                // later return to the old value does not prove the intervening cursor was
                // safe. This remains unhealthy after the conflict counter's first delta.
                if (!pendingReposition.ConflictObserved)
                {
                    Interlocked.Increment(ref subscription.Counters.CursorConflicts);
                    subscription.Reposition = pendingReposition with { ConflictObserved = true };
                }
                Interlocked.Increment(ref subscription.Counters.Retries);
                subscription.State = WindowsEventChannelFailures.CursorUnreconciled;
                return new WindowsEventPollResult(0, true, false);
            }

            if (baselineCommitted)
            {
                // The prior CAS may have committed even though its caller saw failure, or
                // another writer set exactly this baseline. Neither advances past a record.
                version = snapshot!.Version;
                bookmark = WindowsEventBookmark.At(options.Channel, pendingReposition.Position);
                subscription.SetBookmark(pendingReposition.Position);
                subscription.Reposition = null;
            }
            position = pendingReposition.Position;
            if (range.NewestRecordId < position)
            {
                // The channel reset again while the baseline write was unavailable.
                position = 0;
                Interlocked.Increment(ref subscription.Counters.Resets);
            }
            else if (range.OldestRecordId > position && range.OldestRecordId - position > 1)
            {
                // More records aged out while retrying the write. They are no longer
                // readable; expose the gap and resume just before the oldest retained ID.
                position = range.OldestRecordId - 1;
                Interlocked.Increment(ref subscription.Counters.Gaps);
            }
            if (position != pendingReposition.Position)
            {
                subscription.Reposition = new(snapshot!.Version, snapshot.Value, position);
            }
        }
        else if (bookmark is null)
        {
            // First start: begin at the newest event unless asked to read what is there.
            position = options.ReadExisting ? 0 : range.NewestRecordId;
            long? initialized = await CommitAsync(subscription, version, position);
            if (initialized is null)
            {
                Interlocked.Increment(ref subscription.Counters.Retries);
                subscription.State = "backpressure";
                return new WindowsEventPollResult(0, true, false);
            }
            version = initialized.Value;
            if (!options.ReadExisting)
            {
                subscription.State = "running";
                return new WindowsEventPollResult(0, false, false);
            }
        }
        else if (bookmark.SchemaVersion == 1)
        {
            // Version 1 used the origin EventRecordID, which is not the receiving
            // position for WEF. Replay retained events through durable deduplication;
            // never reinterpret a plausible old origin ID as a receiving position.
            position = 0;
            Interlocked.Increment(ref subscription.Counters.Resets);
            subscription.Reposition = new(version, snapshot!.Value, position);
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
                subscription.Reposition = new(version, snapshot!.Value, position);
            }
            else if (range.OldestRecordId > position && range.OldestRecordId - position > 1)
            {
                // Overwritten (log full) before they were scanned; some may have been
                // allow-listed. Those records no longer exist, so carry on from the oldest.
                Interlocked.Increment(ref subscription.Counters.Gaps);
                position = range.OldestRecordId - 1;
                subscription.Reposition = new(version, snapshot!.Value, position);
            }
        }

        if (subscription.Reposition is not null)
        {
            // Persist the generation baseline before reading any events. If storage is
            // unavailable, keep the in-memory latch and retry it before another query.
            long? advanced = await CommitAsync(subscription, version, position);
            if (advanced is null)
            {
                Interlocked.Increment(ref subscription.Counters.Retries);
                subscription.State = "backpressure";
                return new WindowsEventPollResult(0, true, false);
            }
            version = advanced.Value;
            subscription.Reposition = null;
            bookmark = WindowsEventBookmark.At(options.Channel, position);
        }

        long start = bookmark?.RecordId ?? position;
        // Durable position: every event up to it is in the queue or definitively dropped. With a
        // batch, events become durable only when the batch commits, so it lags the read position.
        long durable = position;
        IReadOnlyList<WindowsRawEvent> events = [];
        bool backpressure = false;
        IWindowsEventBatch? batch = null;
        IWindowsEventAtomicBatch? atomic = null;
        // Outcome counters of a batched read are applied only when it commits: a rolled-back
        // read is read again and must not be counted twice.
        List<Tally>? pending = null;
        try
        {
            events = subscription.Channel.Read(
                WindowsEventQuery.For(options, position),
                options.BatchSize,
                options.IncludeMessage,
                cancellationToken);
            if (sink is IWindowsEventBatchSink batching && events.Any(raw => raw.RecordId > position))
            {
                // Opened only when there is something to write: an idle poll takes no write lock.
                batch = await batching.BeginBatchAsync(cancellationToken);
                batch.Join();
                if (batch is IWindowsEventAtomicBatch candidate && candidate.CanAdvanceCursor(cursors))
                {
                    atomic = candidate;
                }
                pending = [];
            }

            foreach (WindowsRawEvent raw in events)
            {
                if (raw.RecordId <= position)
                {
                    continue; // Never move backwards.
                }

                atomic?.BeginRecord();
                bool handled = await HandleAsync(subscription, raw, pending, cancellationToken);
                atomic?.EndRecord(handled);
                if (!handled)
                {
                    backpressure = true;
                    break;
                }

                position = raw.RecordId;
                if (batch is null)
                {
                    durable = position;
                }
            }

            if (!backpressure && events.Count < options.BatchSize && range.NewestRecordId > position)
            {
                // This point was included in the channel query even if no events matched.
                position = range.NewestRecordId;
                if (batch is null)
                {
                    durable = position;
                }
            }

            if (batch is not null)
            {
                // Not cancellable, like the bookmark commit: once the read is handled, a stop
                // must not throw it away.
                WindowsEventAtomicCommit result = atomic is null
                    ? await batch.CommitAsync(CancellationToken.None) ? WindowsEventAtomicCommit.Committed : WindowsEventAtomicCommit.Refused
                    : await atomic.CommitWithCursorAsync(cursors, options.SourceId, version,
                        WindowsEventBookmark.At(options.Channel, position).Serialize(), clock.GetUtcNow(), CancellationToken.None);
                if (result == WindowsEventAtomicCommit.Committed)
                {
                    durable = position;
                    if (atomic is not null)
                    {
                        subscription.SetBookmark(position);
                    }
                    foreach (Tally tally in pending!)
                    {
                        Count(subscription.Counters, tally);
                    }
                }
                else
                {
                    if (result == WindowsEventAtomicCommit.Conflict)
                    {
                        Interlocked.Increment(ref subscription.Counters.CursorConflicts);
                    }
                    // The queue refused the whole batch (as it would refuse one event): keep the
                    // bookmark and read the same events again after the retry delay.
                    if (!backpressure)
                    {
                        Interlocked.Increment(ref subscription.Counters.Retries);
                    }
                    position = durable;
                    backpressure = true;
                }
            }

        }
        finally
        {
            if (batch is not null)
            {
                // Rolls back whatever the batch did not commit; those events are read again.
                await batch.DisposeAsync();
            }

            if (atomic is null && (durable != start || bookmark?.SchemaVersion == 1))
            {
                // Committed even when stopping or failing mid-read (and after a reset or gap
                // even if the read failed), so durable events are not re-read.
                await CommitAsync(subscription, version, durable);
            }
        }

        subscription.State = backpressure ? "backpressure" : "running";
        return new WindowsEventPollResult(events.Count, backpressure, !backpressure && events.Count >= options.BatchSize);
    }

    /// <returns>False when the queue could not take the event (it is retried later).</returns>
    /// <param name="pending">In a batched read, outcome counters to apply once it commits; null applies them now.</param>
    private async Task<bool> HandleAsync(
        Subscription subscription,
        WindowsRawEvent raw,
        List<Tally>? pending,
        CancellationToken cancellationToken)
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
            Record(exception.Code is WindowsEventFailures.XmlTooLarge or WindowsEventFailures.RecordTooLarge
                ? Tally.Oversized
                : Tally.Malformed);
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

        if (outcome == WindowsEventSubmitOutcome.Unavailable)
        {
            Interlocked.Increment(ref counters.Retries);
            return false;
        }

        Record(outcome switch
        {
            WindowsEventSubmitOutcome.Queued => Tally.Queued,
            WindowsEventSubmitOutcome.Duplicate => Tally.Duplicates,
            WindowsEventSubmitOutcome.Suppressed => Tally.Suppressed,
            WindowsEventSubmitOutcome.NotSelected => Tally.NotSelected,
            WindowsEventSubmitOutcome.Invalid => Tally.ParserErrors,
            WindowsEventSubmitOutcome.TooLarge => Tally.Oversized,
            _ => Tally.Rejected
        });
        return true;

        void Record(Tally tally)
        {
            if (pending is null)
            {
                Count(counters, tally);
            }
            else
            {
                pending.Add(tally);
            }
        }
    }

    /// <summary>Per-event outcome counters that a batched read applies only on commit.</summary>
    private enum Tally
    {
        Queued,
        Duplicates,
        Suppressed,
        NotSelected,
        Rejected,
        ParserErrors,
        Malformed,
        Oversized
    }

    private static void Count(Counters counters, Tally tally)
    {
        switch (tally)
        {
            case Tally.Queued: Interlocked.Increment(ref counters.Queued); break;
            case Tally.Duplicates: Interlocked.Increment(ref counters.Duplicates); break;
            case Tally.Suppressed: Interlocked.Increment(ref counters.Suppressed); break;
            case Tally.NotSelected: Interlocked.Increment(ref counters.NotSelected); break;
            case Tally.ParserErrors: Interlocked.Increment(ref counters.ParserErrors); break;
            case Tally.Malformed: Interlocked.Increment(ref counters.Malformed); break;
            case Tally.Oversized: Interlocked.Increment(ref counters.Oversized); break;
            default: Interlocked.Increment(ref counters.Rejected); break;
        }
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

    private sealed record PendingReposition(long Version, string Value, long Position, bool ConflictObserved = false);

    private sealed class Subscription(WindowsEventSubscriptionOptions options)
    {
        private long bookmarkRecordId = -1;
        private string state = "starting";

        public WindowsEventSubscriptionOptions Options { get; } = options;

        public PendingReposition? Reposition { get; set; }

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
