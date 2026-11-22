using Bower.Abstractions;

namespace Bower.Source.MicrosoftCloud;

/// <summary>What happened to one record handed to the collector.</summary>
public enum MicrosoftCloudSubmitOutcome
{
    /// <summary>Durably enqueued. Only then can the cursor move past the page.</summary>
    Queued,
    Duplicate,
    Suppressed,

    /// <summary>The pack parser's filter did not select the record: counted and dropped.</summary>
    NotSelected,

    /// <summary>Policy rejected or quarantined the event.</summary>
    Rejected,

    /// <summary>The record does not satisfy the pack parser's field types.</summary>
    Invalid,
    TooLarge,

    /// <summary>Queue at capacity or ingest gated: stop and read the same page again later.</summary>
    Unavailable
}

/// <summary>Collector side of the source: pack parser, redaction, policy and durable enqueue.</summary>
public interface IMicrosoftCloudSink
{
    ValueTask<MicrosoftCloudSubmitOutcome> SubmitAsync(
        MicrosoftCloudInputOptions input,
        string record,
        CancellationToken cancellationToken);
}

/// <summary>Per-input counters since start. Metadata only: no record content, URL or token, ever.</summary>
/// <param name="State"><c>starting</c>, <c>running</c>, <c>idle</c> (caught up), <c>backpressure</c>, <c>stopped</c> or a failure code.</param>
/// <param name="Committed">Window kinds: every record before this time is durably handled.</param>
/// <param name="CompletedDate">Snapshot kinds: the last UTC day whose snapshot finished.</param>
/// <param name="OutOfScope">API items the kind never turns into records (for example compliant devices): dropped in memory.</param>
/// <param name="Gaps">Windows that had to start later than the cursor because the API keeps no older data.</param>
/// <param name="PageRestarts">Stored page links the API refused (expired); the window was read again from its first page.</param>
public sealed record MicrosoftCloudInputStatus(
    string Id,
    string SourceKind,
    string State,
    DateTimeOffset? Committed,
    string? CompletedDate,
    long Pages,
    long Items,
    long Queued,
    long Duplicates,
    long Suppressed,
    long NotSelected,
    long Rejected,
    long ParserErrors,
    long TooLarge,
    long OutOfScope,
    long Backpressure,
    long Gaps,
    long PageRestarts,
    long Retries,
    long Throttled,
    long Failures,
    DateTimeOffset? LastPollAt,
    DateTimeOffset? LastRecordAt);

/// <param name="Records">Records handed to the sink.</param>
/// <param name="Backpressure">The queue could not take a record; the page is read again next time.</param>
/// <param name="More">A limit stopped the poll or a backlog remains; poll again without waiting.</param>
public sealed record MicrosoftCloudPollResult(int Records, bool Backpressure, bool More);

/// <summary>
/// Pull source for Microsoft cloud admin and audit APIs (Intune and, later, Power Platform
/// and Entra provisioning). Each input reads one API for one tenant, and every record goes
/// through its route's signed pack parser, then redaction, policy and the durable queue.
/// This is not a log shipper: there is no collect-everything form and no default route.
/// <para>
/// The cursor moves past a page only once every record in it is durably enqueued or
/// definitively dropped, and is committed after each page. A full queue stops the poll and
/// keeps the page; nothing is dropped for backpressure. A crash between enqueue and commit
/// re-reads that page; deterministic event ids make the queue drop the copies as duplicates.
/// Windows trail now by a settle delay and start an overlap before the committed bound, so
/// late-arriving records are read; the overlap's re-reads deduplicate the same way.
/// </para>
/// </summary>
public sealed class MicrosoftCloudSource : IAsyncDisposable
{
    private readonly MicrosoftCloudSourceConfiguration configuration;
    private readonly IMicrosoftCloudSink sink;
    private readonly ISourceCursorStore cursors;
    private readonly MicrosoftCloudHttp http;
    private readonly TimeProvider clock;
    private readonly Dictionary<string, Input> inputs;
    private readonly CancellationTokenSource stopping = new();
    private readonly List<Task> running = [];
    private int started;
    private int disposed;

    public MicrosoftCloudSource(
        MicrosoftCloudSourceConfiguration configuration,
        IMicrosoftCloudSink sink,
        ISourceCursorStore cursors,
        MicrosoftCloudHttp http,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(cursors);
        ArgumentNullException.ThrowIfNull(http);
        this.configuration = configuration;
        this.sink = sink;
        this.cursors = cursors;
        this.http = http;
        this.clock = clock ?? TimeProvider.System;
        inputs = configuration.Inputs.ToDictionary(
            input => input.Id,
            input => new Input(input, MicrosoftCloudReader.For(input.SourceKind)),
            StringComparer.Ordinal);
    }

    /// <summary>Wait after a backpressure stop before the page is read again.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Longest wait between failed polls (permission, throttling, outage).</summary>
    public TimeSpan MaximumBackoff { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>Busy queue database (for example during a retention batch): treated as backpressure.</summary>
    public Func<Exception, bool> IsTransientStorageFailure { get; init; } = static _ => false;

    /// <summary>Starts one poll loop per input. Failures are retried with backoff and reported in <see cref="Snapshot"/>.</summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Interlocked.Exchange(ref started, 1) != 0)
        {
            throw new InvalidOperationException("Microsoft cloud source is already started.");
        }

        CancellationToken token = stopping.Token;
        foreach (Input input in inputs.Values)
        {
            running.Add(Task.Run(() => RunAsync(input, token), CancellationToken.None));
        }

        return Task.CompletedTask;
    }

    public IReadOnlyList<MicrosoftCloudInputStatus> Snapshot() =>
        [.. inputs.Values.Select(input => input.Snapshot(http.Counters))];

    /// <summary>
    /// One poll of one input: resume the open window or snapshot, hand each record to the
    /// sink and commit after every completed page. Throws <see cref="MicrosoftCloudException"/>
    /// on an API, cursor or response failure; pages committed before it stay committed.
    /// </summary>
    public async Task<MicrosoftCloudPollResult> PollOnceAsync(string inputId, CancellationToken cancellationToken)
    {
        Input input = inputs[inputId];
        await input.Gate.WaitAsync(cancellationToken);
        try
        {
            return await PollAsync(input, cancellationToken);
        }
        catch (MicrosoftCloudException exception)
        {
            input.State = exception.Code;
            Interlocked.Increment(ref input.Counters.Failures);
            throw;
        }
        finally
        {
            input.Gate.Release();
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

        foreach (Input input in inputs.Values)
        {
            input.Gate.Dispose();
            input.State = "stopped";
        }

        stopping.Dispose();
    }

    private async Task RunAsync(Input input, CancellationToken cancellationToken)
    {
        TimeSpan interval = TimeSpan.FromSeconds(configuration.PollIntervalSeconds);
        int failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            TimeSpan wait;
            try
            {
                MicrosoftCloudPollResult result = await PollOnceAsync(input.Options.Id, cancellationToken);
                failures = 0;
                wait = result.Backpressure ? RetryDelay : result.More ? TimeSpan.Zero : interval;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (IsTransientStorageFailure(exception))
            {
                input.State = "backpressure";
                Interlocked.Increment(ref input.Counters.Backpressure);
                failures = 0;
                wait = RetryDelay;
            }
            catch (Exception exception)
            {
                // Keep the cursor, back off and retry. The state carries the code; nothing else
                // is reported, so a body, URL or token can never reach status or logs.
                if (exception is not MicrosoftCloudException)
                {
                    input.State = MicrosoftCloudFailures.SourceFailed;
                    Interlocked.Increment(ref input.Counters.Failures);
                }

                failures = Math.Min(failures + 1, 16);
                TimeSpan first = TimeSpan.FromSeconds(30);
                wait = TimeSpan.FromTicks(Math.Min(first.Ticks << Math.Min(failures - 1, 10), MaximumBackoff.Ticks));
            }

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

    private async Task<MicrosoftCloudPollResult> PollAsync(Input input, CancellationToken cancellationToken)
    {
        MicrosoftCloudInputOptions options = input.Options;
        DateTimeOffset now = clock.GetUtcNow();
        input.LastPollTicks = now.UtcTicks;
        SourceCursorSnapshot? snapshot = await cursors.ReadAsync(options.SourceId, cancellationToken);
        MicrosoftCloudCursor cursor;
        if (snapshot is null)
        {
            cursor = new MicrosoftCloudCursor(MicrosoftCloudCursor.CurrentSchemaVersion, options.SourceKind);
        }
        else
        {
            cursor = MicrosoftCloudCursor.Deserialize(snapshot.Value, options.SourceKind)
                ?? throw new MicrosoftCloudException(MicrosoftCloudFailures.CursorInvalid);
        }

        long version = snapshot?.Version ?? 0;
        input.Observe(cursor);
        MicrosoftCloudCursor opened = Open(input, cursor, now, out MicrosoftCloudSpan? span);
        if (span is null)
        {
            input.State = "idle";
            return new MicrosoftCloudPollResult(0, false, false);
        }

        if (opened != cursor)
        {
            // Store a new window before reading it, so a failure or backpressure resumes this
            // exact window (and a gap is counted once, when the window is first opened).
            cursor = opened;
            version = await CommitAsync(input, cursor, version, cancellationToken);
        }

        input.State = "running";
        int submitted = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MicrosoftCloudPage page;
            try
            {
                page = await input.Reader.ReadPageAsync(http, options, span, cursor.Page, cancellationToken);
            }
            catch (MicrosoftCloudException exception) when (
                exception.Code == MicrosoftCloudFailures.RequestRefused && cursor.Page is not null)
            {
                // A stored page link expired (skip tokens do). Restart the same window or
                // snapshot from its first page; records already queued deduplicate.
                Interlocked.Increment(ref input.Counters.PageRestarts);
                cursor = cursor with { Page = null };
                version = await CommitAsync(input, cursor, version, cancellationToken);
                continue;
            }

            Interlocked.Increment(ref input.Counters.Pages);
            Interlocked.Add(ref input.Counters.Items, page.Items);
            Interlocked.Add(ref input.Counters.OutOfScope, page.OutOfScope);
            foreach (string record in page.Records)
            {
                MicrosoftCloudSubmitOutcome outcome = await sink.SubmitAsync(options, record, cancellationToken);
                if (outcome == MicrosoftCloudSubmitOutcome.Unavailable)
                {
                    // Keep the page: what was queued from it deduplicates when it is read again.
                    input.State = "backpressure";
                    Interlocked.Increment(ref input.Counters.Backpressure);
                    return new MicrosoftCloudPollResult(submitted, true, false);
                }

                submitted++;
                input.Count(outcome, clock.GetUtcNow());
            }

            cursor = page.Next is null ? Close(cursor) : cursor with { Page = page.Next };
            version = await CommitAsync(input, cursor, version, cancellationToken);
            input.Observe(cursor);
            if (page.Next is null)
            {
                // A window ended. Poll again at once only while the backlog exceeds one interval,
                // so a caught-up input never spins on second-long windows.
                DateTimeOffset settled = clock.GetUtcNow() - TimeSpan.FromSeconds(options.SettleDelaySeconds);
                bool more = !input.Reader.IsSnapshot
                    && settled - span.End > TimeSpan.FromSeconds(configuration.PollIntervalSeconds);
                return new MicrosoftCloudPollResult(submitted, false, more);
            }

            if (submitted >= options.MaxRecordsPerPoll)
            {
                return new MicrosoftCloudPollResult(submitted, false, true);
            }
        }
    }

    /// <summary>The open window or snapshot, or a new one when one is due; null span when caught up.</summary>
    private static MicrosoftCloudCursor Open(Input input, MicrosoftCloudCursor cursor, DateTimeOffset now, out MicrosoftCloudSpan? span)
    {
        MicrosoftCloudInputOptions options = input.Options;
        MicrosoftCloudReader reader = input.Reader;
        if (reader.IsSnapshot)
        {
            if (cursor.SnapshotDate is { } open)
            {
                span = new MicrosoftCloudSpan(cursor.SnapshotAt!.Value, cursor.SnapshotAt.Value, open);
                return cursor;
            }

            string today = now.UtcDateTime.ToString("yyyy'-'MM'-'dd", System.Globalization.CultureInfo.InvariantCulture);
            if (string.Equals(cursor.CompletedDate, today, StringComparison.Ordinal))
            {
                span = null;
                return cursor;
            }

            span = new MicrosoftCloudSpan(now, now, today);
            return cursor with { SnapshotDate = today, SnapshotAt = now, Page = null };
        }

        if (cursor.WindowStart is { } start && cursor.WindowEnd is { } end)
        {
            span = new MicrosoftCloudSpan(start, end);
            return cursor;
        }

        DateTimeOffset floor = now - reader.MaximumLookback;
        DateTimeOffset lower = cursor.Committed is { } committed
            ? committed - TimeSpan.FromSeconds(options.OverlapSeconds)
            : now - TimeSpan.FromHours(options.StartLookbackHours);
        if (lower < floor)
        {
            if (cursor.Committed is not null)
            {
                // The API keeps no older data: what lay between the cursor and the floor is lost.
                Interlocked.Increment(ref input.Counters.Gaps);
            }

            lower = floor;
        }

        DateTimeOffset upper = now - TimeSpan.FromSeconds(options.SettleDelaySeconds);
        if (upper - lower > reader.MaximumWindow)
        {
            upper = lower + reader.MaximumWindow;
        }

        // Nothing new to read until the settled bound passes the committed one.
        if (upper <= lower || (cursor.Committed is { } done && upper <= done))
        {
            span = null;
            return cursor;
        }

        span = new MicrosoftCloudSpan(lower, upper);
        return cursor with { WindowStart = lower, WindowEnd = upper, Page = null };
    }

    private static MicrosoftCloudCursor Close(MicrosoftCloudCursor cursor) =>
        cursor.SnapshotDate is { } date
            ? cursor with { CompletedDate = date, SnapshotDate = null, SnapshotAt = null, Page = null }
            : cursor with
            {
                Committed = cursor.Committed is { } committed && committed > cursor.WindowEnd ? committed : cursor.WindowEnd,
                WindowStart = null,
                WindowEnd = null,
                Page = null
            };

    private async Task<long> CommitAsync(Input input, MicrosoftCloudCursor cursor, long version, CancellationToken cancellationToken)
    {
        bool advanced = await cursors.TryAdvanceAsync(
            input.Options.SourceId, version, cursor.Serialize(), clock.GetUtcNow(), cancellationToken);
        if (!advanced)
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.CursorConflict);
        }

        return version + 1;
    }

    private sealed class Input(MicrosoftCloudInputOptions options, MicrosoftCloudReader reader)
    {
        public MicrosoftCloudInputOptions Options { get; } = options;

        public MicrosoftCloudReader Reader { get; } = reader;

        public SemaphoreSlim Gate { get; } = new(1, 1);

        public Counters Counters { get; } = new();

        public volatile string State = "starting";

        public long LastPollTicks;

        public long LastRecordTicks;

        private long committedTicks;
        private volatile string? completedDate;

        public void Observe(MicrosoftCloudCursor cursor)
        {
            Interlocked.Exchange(ref committedTicks, cursor.Committed?.UtcTicks ?? 0);
            completedDate = cursor.CompletedDate;
        }

        public void Count(MicrosoftCloudSubmitOutcome outcome, DateTimeOffset at)
        {
            Interlocked.Exchange(ref LastRecordTicks, at.UtcTicks);
            switch (outcome)
            {
                case MicrosoftCloudSubmitOutcome.Queued: Interlocked.Increment(ref Counters.Queued); break;
                case MicrosoftCloudSubmitOutcome.Duplicate: Interlocked.Increment(ref Counters.Duplicates); break;
                case MicrosoftCloudSubmitOutcome.Suppressed: Interlocked.Increment(ref Counters.Suppressed); break;
                case MicrosoftCloudSubmitOutcome.NotSelected: Interlocked.Increment(ref Counters.NotSelected); break;
                case MicrosoftCloudSubmitOutcome.Invalid: Interlocked.Increment(ref Counters.ParserErrors); break;
                case MicrosoftCloudSubmitOutcome.TooLarge: Interlocked.Increment(ref Counters.TooLarge); break;
                default: Interlocked.Increment(ref Counters.Rejected); break;
            }
        }

        public MicrosoftCloudInputStatus Snapshot(MicrosoftCloudRetryCounters retries)
        {
            long committed = Interlocked.Read(ref committedTicks);
            long poll = Interlocked.Read(ref LastPollTicks);
            long record = Interlocked.Read(ref LastRecordTicks);
            return new MicrosoftCloudInputStatus(
                Options.Id,
                Options.SourceKind,
                State,
                committed == 0 ? null : new DateTimeOffset(committed, TimeSpan.Zero),
                completedDate,
                Interlocked.Read(ref Counters.Pages),
                Interlocked.Read(ref Counters.Items),
                Interlocked.Read(ref Counters.Queued),
                Interlocked.Read(ref Counters.Duplicates),
                Interlocked.Read(ref Counters.Suppressed),
                Interlocked.Read(ref Counters.NotSelected),
                Interlocked.Read(ref Counters.Rejected),
                Interlocked.Read(ref Counters.ParserErrors),
                Interlocked.Read(ref Counters.TooLarge),
                Interlocked.Read(ref Counters.OutOfScope),
                Interlocked.Read(ref Counters.Backpressure),
                Interlocked.Read(ref Counters.Gaps),
                Interlocked.Read(ref Counters.PageRestarts),
                Interlocked.Read(ref retries.Retries),
                Interlocked.Read(ref retries.Throttled),
                Interlocked.Read(ref Counters.Failures),
                poll == 0 ? null : new DateTimeOffset(poll, TimeSpan.Zero),
                record == 0 ? null : new DateTimeOffset(record, TimeSpan.Zero));
        }
    }

    private sealed class Counters
    {
        public long Pages;
        public long Items;
        public long Queued;
        public long Duplicates;
        public long Suppressed;
        public long NotSelected;
        public long Rejected;
        public long ParserErrors;
        public long TooLarge;
        public long OutOfScope;
        public long Backpressure;
        public long Gaps;
        public long PageRestarts;
        public long Failures;
    }
}
