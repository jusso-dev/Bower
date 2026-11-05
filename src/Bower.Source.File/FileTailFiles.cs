namespace Bower.Source.File;

/// <summary>The length a read decides with, for each generation it opened.</summary>
public enum FileTailLength
{
    /// <summary>
    /// The length taken when the generation was opened, the same snapshot as its identity and
    /// write time (the file tail source): the grace window compares one consistent observation,
    /// the scan stops at the same length, a truncation seen at open stays seen even if the
    /// file regrows during the read, and the Rust port decides the same way.
    /// </summary>
    Opened,

    /// <summary>
    /// The handle's length measured again at each decision (the Docker source, whose reader
    /// always measured afresh): truncation, the start-at-end scan, a copy or drain check and
    /// the abandoned generation's growth.
    /// </summary>
    Measured
}

/// <summary>
/// How a reader treats rotation and its start position. Every policy names its decision
/// length; otherwise the file tail source uses the defaults, and the Docker source keeps its
/// historical behaviour through its own policy.
/// </summary>
public sealed record FileTailPolicy
{
    /// <summary>Which length the read's decisions use; every policy chooses.</summary>
    public required FileTailLength DecisionLength { get; init; }

    /// <summary>When a file is first seen, start after its last complete line.</summary>
    public bool StartAtEnd { get; init; } = true;

    /// <summary>Bytes the start-at-end scan looks back; beyond it the read starts at the end, discarding.</summary>
    public long StartScanBudget { get; init; } = long.MaxValue;

    /// <summary>Lines one read may return (bounds the settled tail of a rename).</summary>
    public int MaxLinesPerBatch { get; init; } = int.MaxValue;

    /// <summary>
    /// While the current file is missing or cannot be identified, do nothing at all, even when
    /// <c>path.1</c> still holds unread lines (the Docker source).
    /// </summary>
    public bool WaitWhileCurrentUnidentified { get; init; }

    /// <summary>A current file shorter than the cursor with the same identity drains a matching <c>path.1</c> first (copytruncate).</summary>
    public bool DrainCopyOfSameIdentity { get; init; } = true;

    /// <summary>
    /// Unchanged end-of-file polls of a renamed <c>path.1</c> before the cursor leaves it; null
    /// leaves as soon as it is drained to its end (the Docker source).
    /// </summary>
    public int? RotationGracePolls { get; init; } = FileTailSourceConfigurationLoader.DefaultRotationGracePolls;

    /// <summary>
    /// Counted polls a rename or copytruncate drain may take before the cursor moves on anyway
    /// (only polls that reach the end of <c>path.1</c> or pass its length when the drain began
    /// count; kept in the cursor); null never forces the switch (the Docker source, whose cursor keeps no
    /// rotation state).
    /// </summary>
    public int? RotationDrainMaxPolls { get; init; } = FileTailSourceConfigurationLoader.DefaultRotationDrainMaxPolls;

    /// <summary>Keep skipping an oversized line that continues in the new file (the Docker source).</summary>
    public bool CarryDiscardingAcrossRotation { get; init; }

    /// <summary>Record the generation a rename left, so its later growth is reported as a gap.</summary>
    public bool TrackAbandoned { get; init; } = true;
}

/// <summary>A line format on top of the shared tailer: scans one opened generation within its bounds.</summary>
public interface IFileTailDecoder<TBatch>
{
    /// <param name="eofEndsLine">The generation no longer grows: its unterminated last line is complete.</param>
    TBatch Scan(FileTailHandle file, FileTailCursor cursor, bool eofEndsLine, bool gap);

    TBatch Empty(FileTailCursor cursor, bool gap);

    FileTailCursor CursorOf(TBatch batch);

    /// <summary>A line or byte limit stopped the scan.</summary>
    bool StoppedByLimit(TBatch batch);

    int LineCount(TBatch batch);

    TBatch WithCursor(TBatch batch, FileTailCursor cursor);

    TBatch WithGap(TBatch batch);

    /// <summary>The drained <c>path.1</c> batch with the cursor moved to the current file.</summary>
    TBatch MovedToCurrent(TBatch batch, FileTailCursor moved);

    /// <summary>The batch followed by the tail's lines (same file); the cursor stays the batch's.</summary>
    TBatch Append(TBatch batch, TBatch tail);
}

/// <summary>
/// The shared tailer: file identity, provisional cursors, truncation, rename and
/// copytruncate draining with durable rotation state, the grace window, abandoned
/// generations and the start position, for any line format. Each generation is opened once
/// (<see cref="FileTailHandle"/>) and its identity and lines come from that handle;
/// <see cref="Plan"/> decides which generation to scan and from where, and the caller's
/// decoder scans it (plain text lines in <see cref="FileTailReader"/>, Docker json-file
/// entries in the Docker source). See <see cref="FileTailReader"/> for the rotation rules.
/// </summary>
public static class FileTailFiles
{
    /// <param name="current">The current file, or null when it is missing or too short.</param>
    /// <param name="fileId">The current file's <c>device:inode</c>, or null when unknown or not used.</param>
    /// <param name="rotated">Opens <c>path.1</c> on first use; null when it is missing.</param>
    public static TBatch Plan<TBatch>(
        FileTailHandle? current,
        string? fileId,
        Func<FileTailHandle?> rotated,
        FileTailCursor? cursor,
        FileTailPolicy policy,
        IFileTailDecoder<TBatch> decoder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rotated);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(decoder);
        string? fingerprint = current?.Fingerprint;
        if (cursor is null)
        {
            if (fingerprint is null)
            {
                return decoder.Empty(Provisional(), false);
            }

            FileTailCursor initial = Normal(fingerprint, 0, fileId);
            if (!policy.StartAtEnd)
            {
                return decoder.Scan(current!, initial, false, false);
            }

            (long offset, bool discarding) = StartPosition(current!, LengthOf(current!), policy.StartScanBudget, cancellationToken);
            return decoder.Empty(initial with { Offset = offset, Discarding = discarding }, false);
        }

        if (fingerprint is null && policy.WaitWhileCurrentUnidentified)
        {
            return decoder.Empty(cursor, false);
        }

        if (cursor.Drain is not null)
        {
            return Drain(cursor);
        }

        // Watched from a provisional cursor too: a drain left at the cap while the current file
        // was missing keeps its abandoned generation.
        (FileTailCursor watched, bool late) = WatchAbandoned(cursor);
        TBatch batch = watched.Fingerprint.Length > 0
            ? Detect(watched)
            : fingerprint is null
                // Provisional cursor: the file was missing or could not be identified.
                ? decoder.Empty(watched, false)
                : decoder.Scan(current!, Normal(fingerprint, 0, fileId) with
                {
                    Abandoned = watched.Abandoned,
                    AbandonedLength = watched.AbandonedLength
                }, false, false);
        return late ? decoder.WithGap(batch) : batch;

        long LengthOf(FileTailHandle file) => policy.DecisionLength == FileTailLength.Measured ? file.Stream.Length : file.Length;

        FileTailHandle? Previous(FileTailCursor at) => rotated() is { } file
            && string.Equals(file.Fingerprint, at.Fingerprint, StringComparison.Ordinal) ? file : null;

        // A generation the cursor left after a rename: writes to it now can never be read.
        (FileTailCursor Cursor, bool Late) WatchAbandoned(FileTailCursor at)
        {
            if (at.Abandoned is null)
            {
                return (at, false);
            }

            FileTailHandle? file = rotated();
            if (file is null || !string.Equals(file.Fingerprint, at.Abandoned, StringComparison.Ordinal))
            {
                // Rotated again or removed: nothing more can arrive.
                return (at with { Abandoned = null, AbandonedLength = null }, false);
            }

            long length = LengthOf(file);
            return length > at.AbandonedLength
                ? (at with { AbandonedLength = length }, true)
                : (at, false);
        }

        TBatch Detect(FileTailCursor at)
        {
            bool sameFile = fileId is not null && at.FileId is not null && string.Equals(fileId, at.FileId, StringComparison.Ordinal);
            bool otherFile = fileId is not null && at.FileId is not null && !sameFile;
            bool sameIdentity = string.Equals(at.Fingerprint, fingerprint, StringComparison.Ordinal);

            if (sameIdentity)
            {
                // The same first line at another device and inode: a rename when path.1 carries
                // it, else another generation with the same first line or the same content
                // restored or copied, which no bounded check tells apart safely. Read it from
                // its start and count the gap: a restore replays with the same event ids.
                if (otherFile)
                {
                    return Previous(at) is not null
                        ? Drain(StartDrain(at, FileTailCursor.RenameDrain))
                        : decoder.Scan(current!, Normal(fingerprint!, 0, fileId), false, true);
                }

                if (LengthOf(current!) >= at.Offset)
                {
                    return decoder.Scan(current!, at with { FileId = fileId ?? at.FileId }, false, false);
                }

                // Shorter than the cursor: copytruncate when path.1 is the copy, else truncated.
                if (policy.DrainCopyOfSameIdentity && Previous(at) is { } copy && LengthOf(copy) >= at.Offset)
                {
                    return Drain(StartDrain(at, FileTailCursor.CopyDrain));
                }

                return decoder.Scan(current!, Normal(fingerprint!, 0, fileId), false, true);
            }

            if (sameFile)
            {
                // The same file rewritten in place (its first line changed): copytruncate.
                if (Previous(at) is not null)
                {
                    return Drain(StartDrain(at, FileTailCursor.CopyDrain));
                }

                return fingerprint is null
                    ? decoder.Empty(Provisional(), true)
                    : decoder.Scan(current!, Normal(fingerprint, 0, fileId), false, true);
            }

            // Another file at the path: rename rotation when path.1 is ours.
            if (Previous(at) is not null)
            {
                return Drain(StartDrain(at, FileTailCursor.RenameDrain));
            }

            // Missing or not identified yet, and not rotated: wait. Otherwise rotated more than
            // once since the last read, or replaced: lines were lost.
            return fingerprint is null
                ? decoder.Empty(at, false)
                : decoder.Scan(current!, Normal(fingerprint, 0, fileId), false, true);
        }

        TBatch Drain(FileTailCursor at)
        {
            FileTailHandle? file = rotated();
            FileTailCursor next = fingerprint is null ? Provisional() : Normal(fingerprint, 0, fileId);
            if (file is null || !string.Equals(file.Fingerprint, at.Fingerprint, StringComparison.Ordinal))
            {
                // The generation being drained is gone (removed or rotated again): lines were lost.
                return fingerprint is null ? decoder.Empty(next, true) : decoder.Scan(current!, next, false, true);
            }

            if (at.Drain == FileTailCursor.CopyDrain)
            {
                // A static copy: drain it to its end, then move to the truncated original at once.
                TBatch copied = decoder.Scan(file, at, true, false);
                if (!decoder.StoppedByLimit(copied))
                {
                    return decoder.MovedToCurrent(copied, Carry(next, copied));
                }

                // A copy that keeps growing cannot hold the cursor either.
                (TBatch counted, bool copyCapped) = CountDrainPoll(copied, at, file);
                return copyCapped ? Leave(counted, next, at, file) : counted;
            }

            (TBatch batch, bool capped) = CountDrainPoll(decoder.Scan(file, at, false, false), at, file);
            if (capped)
            {
                return Leave(batch, next, at, file);
            }

            if (decoder.StoppedByLimit(batch))
            {
                return batch; // A backlog poll never counts towards the grace window.
            }

            if (policy.RotationGracePolls is not { } grace)
            {
                // No grace window: leave once drained to its end, measured after the scan, so
                // bytes appended meanwhile keep the cursor on it (never leaves early, whatever the
                // policy's decision length).
                return fingerprint is null || decoder.CursorOf(batch).Offset < file.Stream.Length
                    ? batch
                    : decoder.MovedToCurrent(batch, Abandon(Carry(next, batch), at, file));
            }

            // At the end of path.1 (only an unterminated last line may remain).
            long length = LengthOf(file);
            bool unchanged = at.ObservedLength == length && at.ObservedWriteTime == file.WriteTicks;
            FileTailCursor observed = decoder.CursorOf(batch) with
            {
                ObservedLength = length,
                ObservedWriteTime = file.WriteTicks,
                StablePolls = unchanged ? Math.Min((at.StablePolls ?? 0) + 1, FileTailSourceConfigurationLoader.MaximumRotationGracePolls) : 0
            };
            if (fingerprint is null || observed.StablePolls < grace || decoder.LineCount(batch) >= policy.MaxLinesPerBatch)
            {
                return decoder.WithCursor(batch, observed);
            }

            // Settled: its unterminated last line is complete, then leave it.
            TBatch tail = decoder.Scan(file, observed, true, false);
            return decoder.MovedToCurrent(decoder.Append(batch, tail), Abandon(Carry(next, tail), at, file));
        }

        // Only a poll that reaches the end of path.1, or gets past its length when the drain
        // began, counts towards the cap: a static backlog is read in full however long it is,
        // and a path.1 that keeps growing is still left after a bounded number of polls.
        (TBatch Batch, bool Capped) CountDrainPoll(TBatch scanned, FileTailCursor at, FileTailHandle file)
        {
            if (policy.RotationDrainMaxPolls is not { } cap)
            {
                return (scanned, false);
            }

            FileTailCursor reached = decoder.CursorOf(scanned);
            long backlog = at.DrainLength ?? LengthOf(file);
            bool counts = !decoder.StoppedByLimit(scanned) || reached.Offset >= backlog;
            int polls = counts
                ? Math.Min((at.DrainPolls ?? 0) + 1, FileTailSourceConfigurationLoader.MaximumRotationDrainMaxPolls)
                : at.DrainPolls ?? 0;
            return (decoder.WithCursor(scanned, reached with { DrainPolls = polls, DrainLength = backlog }), counts && polls >= cap);
        }

        // A path.1 that never settles cannot hold the cursor: move on anyway. What is left
        // unread in it now is a gap, and so are later writes to it while it can be observed.
        TBatch Leave(TBatch batch, FileTailCursor next, FileTailCursor at, FileTailHandle file)
        {
            TBatch forced = decoder.MovedToCurrent(batch, Abandon(Carry(next, batch), at, file));
            return decoder.CursorOf(batch).Offset < LengthOf(file) ? decoder.WithGap(forced) : forced;
        }

        FileTailCursor Carry(FileTailCursor next, TBatch scanned) =>
            policy.CarryDiscardingAcrossRotation ? next with { Discarding = decoder.CursorOf(scanned).Discarding } : next;

        FileTailCursor Abandon(FileTailCursor next, FileTailCursor at, FileTailHandle file) =>
            policy.TrackAbandoned ? next with { Abandoned = at.Fingerprint, AbandonedLength = LengthOf(file) } : next;
    }

    /// <summary>
    /// After the last complete line before <paramref name="length"/>, scanning back at most
    /// <paramref name="budget"/> bytes. Without a newline in that window the read starts at the
    /// end, skipping the rest of the line being written; a file with no newline at all starts at 0.
    /// </summary>
    public static (long Offset, bool Discarding) StartPosition(FileTailHandle file, long length, long budget, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        byte[] block = new byte[4_096];
        long end = length;
        long floor = Math.Max(0, length - budget);
        while (end > floor)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = (int)Math.Min(block.Length, end - floor);
            long start = end - count;
            // A concurrent truncation can shorten the read; bytes past EOF are never '\n'.
            int read = RandomAccess.Read(file.Stream.SafeFileHandle, block.AsSpan(0, count), start);
            int newline = block.AsSpan(0, read).LastIndexOf((byte)'\n');
            if (newline >= 0)
            {
                return (start + newline + 1, false);
            }

            end = start;
        }

        return floor > 0 ? (length, true) : (0, false);
    }

    private static FileTailCursor Provisional() => new(FileTailCursor.CurrentSchemaVersion, string.Empty, 0);

    private static FileTailCursor Normal(string fingerprint, long offset, string? fileId) =>
        new(FileTailCursor.CurrentSchemaVersion, fingerprint, offset, FileId: fileId);

    /// <summary>The cursor now refers to path.1; grace and abandoned state start afresh.</summary>
    private static FileTailCursor StartDrain(FileTailCursor at, string kind) =>
        at with
        {
            Drain = kind,
            ObservedLength = null,
            ObservedWriteTime = null,
            StablePolls = null,
            DrainPolls = null,
            DrainLength = null,
            Abandoned = null,
            AbandonedLength = null
        };
}
