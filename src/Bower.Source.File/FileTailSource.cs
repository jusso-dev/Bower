using Bower.Abstractions;

namespace Bower.Source.File;

/// <summary>What happened to one record handed to the collector.</summary>
public enum FileTailSubmitOutcome
{
    /// <summary>Durably enqueued. Only then can the cursor move past the line.</summary>
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

    /// <summary>Queue at capacity or ingest gated: stop reading and retry the same line.</summary>
    Unavailable
}

/// <summary>Collector side of the source: pack parser, redaction, policy and durable enqueue.</summary>
public interface IFileTailSink
{
    ValueTask<FileTailSubmitOutcome> SubmitAsync(
        FileTailInputOptions input,
        string record,
        CancellationToken cancellationToken);
}

/// <summary>Stable, metadata-only codes for input failures.</summary>
public static class FileTailFailures
{
    /// <summary>A symbolic link, a directory or a path outside the allowed roots.</summary>
    public const string PathRefused = "file-path-refused";
    public const string ReadFailed = "file-read-failed";
    public const string CursorInvalid = "file-cursor-invalid";

    /// <summary>Another writer moved the cursor; the poll is retried from its value.</summary>
    public const string CursorConflict = "file-cursor-conflict";
    public const string SubmitFailed = "file-submit-failed";
    public const string SourceFailed = "file-source-failed";
}

public sealed class FileTailException(string code, Exception? innerException = null) : Exception(code, innerException)
{
    public string Code { get; } = code;
}

/// <summary>Per-input counters since start. Metadata only: no line content, ever.</summary>
/// <param name="State"><c>starting</c>, <c>running</c>, <c>waiting</c> (file missing), <c>backpressure</c>, <c>stopped</c> or a failure code.</param>
/// <param name="Offset">Durable position in the current file.</param>
/// <param name="NotSelected">Lines the pack parser's filter did not select: dropped (default deny).</param>
/// <param name="Malformed">Lines that are not UTF-8, or not a JSON object for json-lines: dropped.</param>
/// <param name="Oversized">Lines longer than <c>maxLineBytes</c>: skipped without being buffered.</param>
/// <param name="RotationGaps">Missed rotations or in-place truncations: lines may have been lost.</param>
/// <param name="Backpressure">Polls stopped because the queue could not take a line; the line is retried.</param>
public sealed record FileTailInputStatus(
    string Id,
    string Path,
    string State,
    long? Offset,
    long LinesRead,
    long BytesRead,
    long Queued,
    long Duplicates,
    long Suppressed,
    long NotSelected,
    long Rejected,
    long ParserErrors,
    long TooLarge,
    long Malformed,
    long Oversized,
    long Blank,
    long Rotations,
    long RotationGaps,
    long Backpressure,
    long ReadErrors,
    long SubmitFailures,
    long CursorConflicts,
    DateTimeOffset? LastLineAt,
    DateTimeOffset? LastPollAt);

/// <param name="Lines">Lines read (including oversized and blank ones).</param>
/// <param name="Backpressure">The queue could not take a line; it is retried next time.</param>
/// <param name="More">A limit stopped the read; read again without waiting.</param>
public sealed record FileTailPollResult(int Lines, bool Backpressure, bool More);

/// <summary>
/// Security-selected local file tail: each configured file is read line by line, and every
/// line goes through its route's signed pack parser (match filter and transforms), then
/// redaction, policy and the durable queue. Lines the parser does not select are counted
/// and dropped. This is not a log shipper: there are no wildcards and no default route.
/// <para>
/// The cursor moves past a line only once it is durably enqueued or definitively dropped
/// (not selected, rejected, quarantined, malformed, oversized or too large) and is committed
/// to the queue database after each poll. A full queue stops reading and rewinds to the start
/// of the line it could not take; nothing is dropped for backpressure. A crash between
/// enqueue and commit re-reads those lines; their deterministic event ids make the queue
/// drop them as duplicates, so a restart neither loses nor duplicates events.
/// </para>
/// </summary>
public sealed class FileTailSource : IAsyncDisposable
{
    private readonly FileTailSourceConfiguration configuration;
    private readonly IFileTailSink sink;
    private readonly ISourceCursorStore cursors;
    private readonly TimeProvider clock;
    private readonly Dictionary<string, Input> inputs;
    private readonly CancellationTokenSource stopping = new();
    private readonly List<Task> running = [];
    private int started;
    private int disposed;

    public FileTailSource(
        FileTailSourceConfiguration configuration,
        IFileTailSink sink,
        ISourceCursorStore cursors,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(cursors);
        this.configuration = configuration;
        this.sink = sink;
        this.cursors = cursors;
        this.clock = clock ?? TimeProvider.System;
        inputs = configuration.Inputs.ToDictionary(options => options.Id, options => new Input(options), StringComparer.Ordinal);
    }

    /// <summary>Wait before retrying a line the queue could not take yet.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Longest wait between attempts after repeated read or storage failures.</summary>
    public TimeSpan MaximumBackoff { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Recognises contention on the cursor and queue store (the collector supplies SQLite
    /// busy/locked). Such a poll is retried after <see cref="RetryDelay"/> as backpressure.
    /// </summary>
    public Func<Exception, bool> IsTransientStorageFailure { get; init; } = static _ => false;

    /// <summary>Starts one reader loop per input. Failures are retried with backoff and reported in <see cref="Snapshot"/>.</summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Interlocked.Exchange(ref started, 1) != 0)
        {
            throw new InvalidOperationException("File tail source is already started.");
        }

        CancellationToken token = stopping.Token;
        foreach (Input input in inputs.Values)
        {
            running.Add(Task.Run(() => RunAsync(input, token), CancellationToken.None));
        }

        return Task.CompletedTask;
    }

    public IReadOnlyList<FileTailInputStatus> Snapshot() => [.. inputs.Values.Select(input => input.Snapshot())];

    /// <summary>
    /// One read of one input: resume from the cursor, hand each line to the sink and commit
    /// the new position. Throws <see cref="FileTailException"/> on a path, read, cursor or sink
    /// failure (progress made before a sink failure is still committed).
    /// </summary>
    public async Task<FileTailPollResult> PollOnceAsync(string inputId, CancellationToken cancellationToken)
    {
        Input input = inputs[inputId];
        await input.Gate.WaitAsync(cancellationToken);
        try
        {
            return await PollAsync(input, cancellationToken);
        }
        catch (FileTailException exception)
        {
            input.State = exception.Code;
            if (exception.Code is FileTailFailures.ReadFailed or FileTailFailures.PathRefused)
            {
                Interlocked.Increment(ref input.Counters.ReadErrors);
            }

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
        TimeSpan interval = TimeSpan.FromMilliseconds(configuration.PollIntervalMilliseconds);
        int failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            TimeSpan wait;
            try
            {
                FileTailPollResult result = await PollOnceAsync(input.Options.Id, cancellationToken);
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
                // Path refused, read, storage or sink failure: keep the cursor, back off and
                // retry. The state carries the code; nothing else is reported.
                if (exception is not FileTailException)
                {
                    input.State = FileTailFailures.SourceFailed;
                }

                failures = Math.Min(failures + 1, 16);
                wait = TimeSpan.FromTicks(Math.Min(interval.Ticks << Math.Min(failures, 10), MaximumBackoff.Ticks));
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

    private async Task<FileTailPollResult> PollAsync(Input input, CancellationToken cancellationToken)
    {
        FileTailInputOptions options = input.Options;
        Interlocked.Exchange(ref input.LastPollTicks, clock.GetUtcNow().UtcTicks);
        SourceCursorSnapshot? snapshot = await cursors.ReadAsync(options.SourceId, cancellationToken);
        FileTailCursor? cursor = null;
        if (snapshot is not null)
        {
            // Never reinterpret or silently reset a position this version did not write.
            cursor = FileTailCursor.Deserialize(snapshot.Value) ?? throw new FileTailException(FileTailFailures.CursorInvalid);
            Interlocked.Exchange(ref input.Offset, cursor.Offset);
        }

        (FileTailPathState state, string path) = FileTailPaths.Resolve(options.Path, configuration.AllowedRoots, options.AllowSymlink);
        if (state == FileTailPathState.Refused)
        {
            throw new FileTailException(FileTailFailures.PathRefused);
        }

        // A missing file is read as missing: the cursor is still persisted (a file created
        // later is read from its start) and the rotated file may still hold unread lines.
        FileTailBatch batch = Read(state == FileTailPathState.Ready ? path : null, Rotated(path), cursor, options);

        // Re-check after reading: a link swapped in during the read discards the read.
        if (FileTailPaths.Resolve(options.Path, configuration.AllowedRoots, options.AllowSymlink).State == FileTailPathState.Refused)
        {
            throw new FileTailException(FileTailFailures.PathRefused);
        }

        if (batch.Gap)
        {
            Interlocked.Increment(ref input.Counters.RotationGaps);
        }

        FileTailCursor next = batch.Cursor;
        bool backpressure = false;
        int handled = 0;
        Exception? failure = null;
        foreach (FileTailLine line in batch.Lines)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                next = Rewind(line);
                break;
            }

            FileTailSubmitOutcome? outcome = null;
            if (!line.Oversized && line.Bytes.Length > 0)
            {
                string? record = FileTailRecord.TryBuild(options, line, clock.GetUtcNow(), out _);
                if (record is not null)
                {
                    try
                    {
                        outcome = await sink.SubmitAsync(options, record, cancellationToken);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        next = Rewind(line);
                        break;
                    }
                    catch (Exception exception)
                    {
                        Interlocked.Increment(ref input.Counters.SubmitFailures);
                        failure = exception;
                        next = Rewind(line);
                        break;
                    }

                    if (outcome == FileTailSubmitOutcome.Unavailable)
                    {
                        Interlocked.Increment(ref input.Counters.Backpressure);
                        backpressure = true;
                        next = Rewind(line);
                        break;
                    }
                }
                else
                {
                    Interlocked.Increment(ref input.Counters.Malformed);
                }
            }

            handled++;
            Count(input, line, outcome);
        }

        if (batch.Rotated && handled == batch.Lines.Count)
        {
            Interlocked.Increment(ref input.Counters.Rotations);
        }

        string value = next.Serialize();
        if (!string.Equals(value, snapshot?.Value, StringComparison.Ordinal))
        {
            // Commit even when stopping, so lines already handled are not read again.
            bool advanced = await cursors.TryAdvanceAsync(
                options.SourceId, snapshot?.Version ?? 0, value, clock.GetUtcNow(), CancellationToken.None);
            if (!advanced)
            {
                Interlocked.Increment(ref input.Counters.CursorConflicts);
                throw new FileTailException(FileTailFailures.CursorConflict);
            }
        }

        Interlocked.Exchange(ref input.Offset, next.Offset);
        if (failure is not null)
        {
            throw new FileTailException(FileTailFailures.SubmitFailed, failure);
        }

        cancellationToken.ThrowIfCancellationRequested();
        input.State = backpressure ? "backpressure" : state == FileTailPathState.Missing ? "waiting" : "running";
        return new FileTailPollResult(handled, backpressure, !backpressure && batch.More);
    }

    private FileTailBatch Read(string? path, string? rotated, FileTailCursor? cursor, FileTailInputOptions options)
    {
        try
        {
            return FileTailReader.Read(path, rotated, cursor, new FileTailReaderOptions
            {
                MaxLineBytes = options.MaxLineBytes,
                MaxLinesPerBatch = configuration.MaxLinesPerBatch,
                MaxBytesPerBatch = configuration.MaxBytesPerBatch,
                StartAtEnd = !string.Equals(options.StartAt, "beginning", StringComparison.Ordinal)
            });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new FileTailException(FileTailFailures.ReadFailed, exception);
        }
    }

    /// <summary>The rotated file (<c>path.1</c>, never a link), or null when it cannot be read.</summary>
    private string? Rotated(string path) =>
        FileTailPaths.Resolve(path + ".1", configuration.AllowedRoots, allowSymlink: false) is (FileTailPathState.Ready, string rotated)
            ? rotated
            : null;

    private static FileTailCursor Rewind(FileTailLine line) =>
        new(FileTailCursor.CurrentSchemaVersion, line.Fingerprint, line.StartOffset);

    private void Count(Input input, FileTailLine line, FileTailSubmitOutcome? outcome)
    {
        FileTailCounters counters = input.Counters;
        Interlocked.Increment(ref counters.LinesRead);
        Interlocked.Add(ref counters.BytesRead, line.EndOffset - line.StartOffset);
        Interlocked.Exchange(ref input.LastLineTicks, clock.GetUtcNow().UtcTicks);
        if (line.Oversized)
        {
            Interlocked.Increment(ref counters.Oversized);
            return;
        }

        if (line.Bytes.Length == 0)
        {
            Interlocked.Increment(ref counters.Blank);
            return;
        }

        switch (outcome)
        {
            case FileTailSubmitOutcome.Queued:
                Interlocked.Increment(ref counters.Queued);
                break;
            case FileTailSubmitOutcome.Duplicate:
                Interlocked.Increment(ref counters.Duplicates);
                break;
            case FileTailSubmitOutcome.Suppressed:
                Interlocked.Increment(ref counters.Suppressed);
                break;
            case FileTailSubmitOutcome.NotSelected:
                Interlocked.Increment(ref counters.NotSelected);
                break;
            case FileTailSubmitOutcome.Rejected:
                Interlocked.Increment(ref counters.Rejected);
                break;
            case FileTailSubmitOutcome.Invalid:
                Interlocked.Increment(ref counters.ParserErrors);
                break;
            case FileTailSubmitOutcome.TooLarge:
                Interlocked.Increment(ref counters.TooLarge);
                break;
        }
    }

    private sealed class FileTailCounters
    {
        public long LinesRead;
        public long BytesRead;
        public long Queued;
        public long Duplicates;
        public long Suppressed;
        public long NotSelected;
        public long Rejected;
        public long ParserErrors;
        public long TooLarge;
        public long Malformed;
        public long Oversized;
        public long Blank;
        public long Rotations;
        public long RotationGaps;
        public long Backpressure;
        public long ReadErrors;
        public long SubmitFailures;
        public long CursorConflicts;
    }

    private sealed class Input(FileTailInputOptions options)
    {
        public FileTailInputOptions Options { get; } = options;
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public FileTailCounters Counters { get; } = new();
        public volatile string State = "starting";
        public long Offset = -1;
        public long LastLineTicks;
        public long LastPollTicks;

        public FileTailInputStatus Snapshot()
        {
            FileTailCounters counters = Counters;
            long offset = Interlocked.Read(ref Offset);
            long lastLine = Interlocked.Read(ref LastLineTicks);
            long lastPoll = Interlocked.Read(ref LastPollTicks);
            return new FileTailInputStatus(
                Options.Id,
                Options.Path,
                State,
                offset < 0 ? null : offset,
                Interlocked.Read(ref counters.LinesRead),
                Interlocked.Read(ref counters.BytesRead),
                Interlocked.Read(ref counters.Queued),
                Interlocked.Read(ref counters.Duplicates),
                Interlocked.Read(ref counters.Suppressed),
                Interlocked.Read(ref counters.NotSelected),
                Interlocked.Read(ref counters.Rejected),
                Interlocked.Read(ref counters.ParserErrors),
                Interlocked.Read(ref counters.TooLarge),
                Interlocked.Read(ref counters.Malformed),
                Interlocked.Read(ref counters.Oversized),
                Interlocked.Read(ref counters.Blank),
                Interlocked.Read(ref counters.Rotations),
                Interlocked.Read(ref counters.RotationGaps),
                Interlocked.Read(ref counters.Backpressure),
                Interlocked.Read(ref counters.ReadErrors),
                Interlocked.Read(ref counters.SubmitFailures),
                Interlocked.Read(ref counters.CursorConflicts),
                lastLine == 0 ? null : new DateTimeOffset(lastLine, TimeSpan.Zero),
                lastPoll == 0 ? null : new DateTimeOffset(lastPoll, TimeSpan.Zero));
        }
    }
}
