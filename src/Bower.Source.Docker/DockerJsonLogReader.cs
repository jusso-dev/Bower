using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Bower.Source.File;

namespace Bower.Source.Docker;

/// <summary>
/// Position in a container's json-file log. The fingerprint identifies the file by its
/// first bytes (which never change once written), so rotation is detected even though
/// Docker reuses the same file name.
/// <para>
/// <paramref name="Discarding"/> (additive, omitted when false) means an oversized logical
/// line is being skipped: its chunks after <paramref name="Offset"/>, up to and including its
/// terminator, are consumed. It carries no line content.
/// </para>
/// <para>
/// <paramref name="Pending"/> (additive, omitted when empty) names the logical lines still
/// open at <paramref name="Offset"/>, at most one per stream, by their stream and Docker
/// <c>time</c> (shared by every chunk of one line): one being skipped (it then also sets
/// <paramref name="Discarding"/>), one being assembled (where its first chunk is and how long
/// it is so far, so the next read re-reads it, from <c>.1</c> when the log rotated in between),
/// or the rest of one whose head could not be read. Offsets, a length and the time only, never
/// line content. A cursor written before this field existed with <paramref name="Discarding"/>
/// set is read as described on <see cref="DockerJsonLogReader"/>.
/// </para>
/// </summary>
public sealed record DockerLogCursor(
    int SchemaVersion,
    string Fingerprint,
    long Offset,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Discarding = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<DockerPendingLine>? Pending = null)
{
    public const int CurrentSchemaVersion = 1;

    /// <summary>Longest Docker <c>time</c> value kept as a line's key (RFC 3339 with nanoseconds is 30).</summary>
    public const int MaximumTimeLength = 64;

    public string Serialize() => JsonSerializer.Serialize(this, DockerCursorJsonContext.Default.DockerLogCursor);

    public static DockerLogCursor? Deserialize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            DockerLogCursor? cursor = JsonSerializer.Deserialize(value, DockerCursorJsonContext.Default.DockerLogCursor);
            return cursor is { SchemaVersion: CurrentSchemaVersion, Offset: >= 0 } && PendingIsValid(cursor) ? cursor : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public bool Equals(DockerLogCursor? other) =>
        other is not null
        && SchemaVersion == other.SchemaVersion
        && string.Equals(Fingerprint, other.Fingerprint, StringComparison.Ordinal)
        && Offset == other.Offset
        && Discarding == other.Discarding
        && (Pending ?? []).SequenceEqual(other.Pending ?? []);

    public override int GetHashCode() => HashCode.Combine(SchemaVersion, Fingerprint, Offset, Discarding, Pending?.Count ?? 0);

    private static bool PendingIsValid(DockerLogCursor cursor)
    {
        if (cursor.Pending is not { } pending)
        {
            return true;
        }

        if (pending.Count is 0 or > 2 || (pending.Count == 2 && pending[0]?.Stream == pending[1]?.Stream))
        {
            return false;
        }

        bool discarding = false;
        foreach (DockerPendingLine? line in pending)
        {
            if (line is null
                || line.Stream is not ("stdout" or "stderr")
                || line.Time is { Length: > MaximumTimeLength })
            {
                return false;
            }

            bool valid = line switch
            {
                { Discarding: true } => line is { Fragment: false, File: null, Start: null, Length: null },
                { Start: null } => line is { Fragment: true, File: null, Length: null },
                _ => line is { Start: >= 0, File.Length: > 0 and <= 128, Length: >= 0 }
            };
            if (!valid)
            {
                return false;
            }

            discarding |= line.Discarding;
        }

        return discarding == cursor.Discarding;
    }
}

/// <summary>
/// A logical line open at a <see cref="DockerLogCursor"/>, keyed by its stream and Docker
/// <c>time</c>. Skipped (<paramref name="Discarding"/>), assembled from its first chunk at
/// <paramref name="Start"/> in the file <paramref name="File"/> (<paramref name="Length"/>
/// characters so far), or, with no start, the rest of a line whose head could not be read.
/// <paramref name="Fragment"/>: its head could not be read, so it is never a whole line.
/// </summary>
public sealed record DockerPendingLine(
    string Stream,
    string? Time,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Discarding = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? File = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Start = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Length = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Fragment = false);

/// <summary>Cursor JSON: camelCase, otherwise default options (source generated).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DockerLogCursor))]
internal sealed partial class DockerCursorJsonContext : JsonSerializerContext;

/// <summary>One logical log line (Docker splits lines over 16 KiB into chunks).</summary>
/// <param name="StartOffset">Its first chunk, in the file <paramref name="FileFingerprint"/> names.</param>
/// <param name="EndOffset">The end of its last chunk, in the file that holds that chunk.</param>
/// <param name="Fragment">
/// Additive: the rest of a line whose head could not be read (its file rotated away or
/// changed). Never a whole line, so it is never mapped as a security event.
/// </param>
/// <param name="Resume">
/// Where a read reproduces this record and every later one in its batch (the sidecar rewinds
/// there when the collector pushes back); null only for records built outside the reader.
/// </param>
public sealed record DockerLogRecord(
    string Text,
    string Stream,
    DateTimeOffset? Time,
    string FileFingerprint,
    long StartOffset,
    long EndOffset,
    bool Fragment = false,
    DockerLogCursor? Resume = null);

/// <param name="OpenAtRotation">
/// Lines still open at the end of a drained <c>.1</c> when the cursor moved to the new file
/// (additive, zero by default): each is re-read from <c>.1</c> and joined with its rest.
/// </param>
public sealed record DockerLogBatch(
    IReadOnlyList<DockerLogRecord> Records,
    DockerLogCursor Cursor,
    int Malformed,
    int Oversized,
    bool RotationGap,
    int OpenAtRotation = 0);

public sealed record DockerLogReaderOptions
{
    public int MaximumLineBytes { get; init; } = 65_536;

    public int MaximumRecordsPerBatch { get; init; } = 1_000;

    public int MaximumBytesPerBatch { get; init; } = 4 * 1_048_576;

    /// <summary>When a container is first seen, start at the end instead of replaying history.</summary>
    public bool StartAtEnd { get; init; } = true;
}

/// <summary>
/// Bounded, read-only tail of Docker json-file logs with rotation handling.
/// Only complete lines are consumed; a line still being written is left for the next read.
/// <para>
/// File identity, rotation (<c>.1</c> draining), truncation and the start position come
/// from the shared tailer (<see cref="FileTailFiles"/>) with Docker's own policy: the
/// 64-byte identity, no rotation grace window, no copy drain on a same-identity truncation,
/// waiting while the current file cannot be identified, an oversized-line discard carried
/// across rotation, and a drained <c>.1</c> taken as final (Docker never writes it again).
/// This class is the Docker line decoder on top of it: json-file entries, the 16 KiB
/// partial-chunk join, malformed entries and the oversized-line discard, within the record
/// and byte bounds.
/// </para>
/// <para>
/// Lines are told apart by stream and time, from how moby writes them
/// (moby/moby@402d0a16f131d93ee89f1b06cb5fc8c98e766dfc): <c>daemon/logger/copier.go</c> runs
/// one <c>copySrc</c> per stream (lines 46-53), so stdout and stderr entries interleave in one
/// file; every partial chunk of a line after the first carries the first one's
/// <c>partialTS</c>, and so does its <c>Last</c> chunk (lines 111-124 and 136-157), while a
/// line that is not a partial gets its own <c>time.Now()</c> (line 121); at stream end what is
/// left goes out as a partial with <c>Last: false</c> and nothing follows (lines 136-168).
/// <c>daemon/logger/jsonfilelog/jsonfilelog.go</c> <c>marshalMessage</c> (lines 127-131) ends
/// <c>log</c> with a newline only when there is no partial metadata or <c>Last</c> is set. So
/// an entry joins an open line only with the same stream and time; another stream's entries
/// never touch it; and a same-stream entry with another time means the open line ended at
/// stream end, so it is a whole line and is emitted as one.
/// </para>
/// <para>
/// A cursor from before <see cref="DockerLogCursor.Pending"/> with
/// <see cref="DockerLogCursor.Discarding"/> set has no key for the line being skipped. The
/// entry that ends at its offset is the chunk it skipped last, so its stream and time become
/// the key. When that entry cannot be read as such a chunk (the offset is at the start of the
/// file after a rotation, or the entry is malformed or terminated), the old rule holds for that
/// one line: every entry is skipped up to and including the first one that ends with a newline,
/// whatever its stream. Nothing skipped is ever mapped, and at worst the one entry the old
/// reader would have dropped is still dropped.
/// </para>
/// </summary>
public static class DockerJsonLogReader
{
    public static DockerLogBatch Read(
        DockerContainer container,
        DockerLogCursor? cursor,
        DockerLogReaderOptions options)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(options);

        using FileTailHandle? current = FileTailHandle.OpenWithPrefixIdentity(container.LogPath);
        FileTailHandle? rotated = null;
        try
        {
            FileTailHandle? Rotated() => rotated ??= FileTailHandle.OpenWithPrefixIdentity(container.LogPath + ".1");
            return FileTailFiles.Plan(
                current,
                fileId: null,
                Rotated,
                cursor is null ? null : Shared(cursor),
                options.StartAtEnd ? StartAtEndPolicy : ReplayPolicy,
                new Decoder(options, cursor, Rotated));
        }
        finally
        {
            rotated?.Dispose();
        }
    }

    /// <summary>
    /// Docker's historical rotation behaviour on the shared tailer: every length measured again
    /// where the reader used to measure it (truncation, the start-at-end scan, leaving a drained
    /// <c>.1</c>), wait while the current file cannot be identified, no copy drain, no grace
    /// window, no abandoned tracking, the oversized discard carried across rotation and an
    /// unbounded start-at-end scan. One deliberate change from the old reader: a renamed
    /// <c>.1</c> is final, so a line left open at its end no longer stalls the cursor at its
    /// start in <c>.1</c> until the new file is rotated away and lost. The cursor moves to the
    /// new file with the open line in <see cref="DockerLogCursor.Pending"/>, and the line is
    /// re-read from <c>.1</c> and joined with its rest there.
    /// </summary>
    private static readonly FileTailPolicy StartAtEndPolicy = new()
    {
        DecisionLength = FileTailLength.Measured,
        StartAtEnd = true,
        WaitWhileCurrentUnidentified = true,
        DrainCopyOfSameIdentity = false,
        RotationGracePolls = null,
        RotationDrainMaxPolls = null,
        CarryDiscardingAcrossRotation = true,
        RenamedFileIsFinal = true,
        TrackAbandoned = false
    };

    private static readonly FileTailPolicy ReplayPolicy = StartAtEndPolicy with { StartAtEnd = false };

    /// <summary>
    /// Docker json-file entries. A drain stopped by the record limit is not drained. Docker's
    /// cursor keeps no rotation state, so each read detects the rotation again, as it always did.
    /// The shared cursor has no <see cref="DockerLogCursor.Pending"/>: it is restored from the
    /// read's own cursor wherever the tailer hands that position back, carried across a
    /// rotation by <see cref="MovedToCurrent"/>, and dropped with any other position (a gap or a
    /// new file starts with no open line).
    /// </summary>
    internal sealed class Decoder(DockerLogReaderOptions options, DockerLogCursor? input, Func<FileTailHandle?> rotated) : IFileTailDecoder<DockerLogBatch>
    {
        // eofEndsLine only for a renamed .1 that Docker never writes again (RenamedFileIsFinal).
        // Docker's policy has no copy drain, grace window or file id, so anything else would
        // mean a policy change, not data.
        public DockerLogBatch Scan(FileTailHandle file, FileTailCursor cursor, bool eofEndsLine, bool gap) =>
            eofEndsLine && (cursor.Drain != FileTailCursor.RenameDrain || cursor.FileId is not null)
                ? throw new UnreachableException("The Docker policy ends a line at end of file only in a renamed .1.")
                : new LineScan(file, Restore(cursor), options, rotated).Read(gap, eofEndsLine);

        public DockerLogBatch Empty(FileTailCursor cursor, bool gap) => DockerJsonLogReader.Empty(Restore(cursor)) with { RotationGap = gap };

        public FileTailCursor CursorOf(DockerLogBatch batch) => Shared(batch.Cursor);

        public bool StoppedByLimit(DockerLogBatch batch) => batch.Records.Count >= options.MaximumRecordsPerBatch;

        public int LineCount(DockerLogBatch batch) => batch.Records.Count;

        public DockerLogBatch WithCursor(DockerLogBatch batch, FileTailCursor cursor) => batch with { Cursor = Restore(cursor) };

        public DockerLogBatch WithGap(DockerLogBatch batch) => batch with { RotationGap = true };

        // The lines open at the end of .1 go with the cursor into the new file.
        public DockerLogBatch MovedToCurrent(DockerLogBatch batch, FileTailCursor moved) => batch with
        {
            Cursor = Docker(moved) with { Pending = batch.Cursor.Pending },
            OpenAtRotation = batch.Cursor.Pending?.Count(line => line.Start is not null) ?? 0
        };

        public DockerLogBatch Append(DockerLogBatch batch, DockerLogBatch tail) =>
            throw new UnreachableException("The Docker policy has no grace window, so no settled tail is appended.");

        private DockerLogCursor Restore(FileTailCursor cursor)
        {
            DockerLogCursor docker = Docker(cursor);
            return input is { Pending: not null } && docker == input with { Pending = null }
                ? input
                : docker;
        }
    }

    // Mapped by name; Docker's JSON and schema version stay DockerLogCursor's own (see Docker()).
    private static FileTailCursor Shared(DockerLogCursor cursor) =>
        new(cursor.SchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>Docker's own schema version, independent of the file tail cursor's.</summary>
    internal static DockerLogCursor Docker(FileTailCursor cursor) =>
        new(DockerLogCursor.CurrentSchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>A logical line open during a scan: being assembled, skipped, or the rest of one whose head is lost.</summary>
    private sealed class OpenLine(string stream, string? time)
    {
        public string Stream { get; } = stream;

        public string? Time { get; } = time;

        public bool Discarding { get; set; }

        /// <summary>Its head could not be read: what is assembled is a fragment.</summary>
        public bool Fragment { get; set; }

        /// <summary>The file holding its first chunk.</summary>
        public string? File { get; set; }

        /// <summary>Its first chunk; -1 before one is read (the rest of a line whose head is lost).</summary>
        public long Start { get; set; } = -1;

        public long End { get; set; }

        /// <summary>Bytes from its first chunk to <see cref="Origin"/>, for a line opened before this read.</summary>
        public long Span { get; set; }

        /// <summary>Where this read began counting its bytes: the read's offset, or its first chunk.</summary>
        public long Origin { get; set; }

        public DateTimeOffset? ParsedTime { get; set; }

        public StringBuilder Text { get; } = new();

        public DockerLogCursor? Resume { get; set; }

        public bool Assembling => !Discarding && Start >= 0;

        public bool Matches(string? time) => string.Equals(Time, time, StringComparison.Ordinal);
    }

    /// <summary>One scan of one generation from a cursor, within the record and byte bounds.</summary>
    private sealed class LineScan(FileTailHandle file, DockerLogCursor cursor, DockerLogReaderOptions options, Func<FileTailHandle?> rotated)
    {
        private readonly List<DockerLogRecord> records = [];
        private readonly OpenLine?[] lines = new OpenLine?[2];
        private readonly int maximumEntry = options.MaximumLineBytes * 2 + 4_096;
        private int malformed;
        private int oversized;

        // A cursor from before the discard key whose key could not be recovered (see the class remarks).
        private bool blind;

        // Pinning: while nothing has been emitted, counted or closed since the last point with no
        // line being assembled, a read that ends with lines open commits that point, as the
        // reader always did, rather than recording where those lines started.
        private DockerLogCursor? safe;
        private bool quiet;

        public DockerLogBatch Read(bool rotationGap, bool final)
        {
            rotationGap |= RestorePending();

            FileStream stream = file.Stream;
            stream.Seek(cursor.Offset, SeekOrigin.Begin);
            long budgetEnd = Math.Min(stream.Length, cursor.Offset + options.MaximumBytesPerBatch);
            long position = cursor.Offset;
            while (records.Count < options.MaximumRecordsPerBatch && position < budgetEnd)
            {
                long entryStart = position;
                byte[]? entry = ReadEntry(stream, maximumEntry, out bool complete, out bool tooLong);
                if (!complete)
                {
                    if (final)
                    {
                        // A torn entry at the end of a file that is never written again.
                        malformed++;
                        position = stream.Position;
                    }

                    break; // Writer has not finished this line; read it next time.
                }

                position = stream.Position;
                if (tooLong || entry is null || !TryParseEntry(entry, out Entry parsed))
                {
                    malformed++;
                    continue;
                }

                Add(parsed, entryStart, position);
            }

            // A file that is never written again (a drained .1) ends here: every line still open
            // goes into the cursor, which moves to the new file, so it is re-read from .1 and
            // joined with its rest there. Otherwise one logical line that was open from the start
            // of this read and spans a whole byte budget without ending can never be read within
            // bounds: skip it rather than re-read the same prefix every poll. (A line that began
            // later in the read is judged by the next read, which starts with it.)
            bool ended = final && position >= stream.Length;
            if (!ended)
            {
                foreach (OpenLine? line in lines)
                {
                    if (line is { Assembling: true }
                        && line.Origin == cursor.Offset
                        && line.Span + position - cursor.Offset >= options.MaximumBytesPerBatch)
                    {
                        line.Discarding = true;
                        line.Text.Clear();
                        quiet = false;
                    }
                }
            }

            DockerLogCursor committed = !ended && quiet && safe is not null && lines.Any(line => line is { Assembling: true })
                ? safe
                : Snapshot(position);
            return new DockerLogBatch(records, committed, malformed, oversized, rotationGap);
        }

        private void Add(Entry entry, long entryStart, long position)
        {
            if (blind)
            {
                if (entry.Log.EndsWith('\n'))
                {
                    oversized++;
                    blind = false;
                }

                return;
            }

            int slot = Slot(entry.Stream);
            OpenLine? line = lines[slot];
            if (line is not null && !line.Matches(entry.Time))
            {
                // The same stream with another time: that line ended at stream end, unterminated.
                Close(slot);
                line = null;
            }

            if (line is null || line is { Discarding: false, Start: < 0 })
            {
                DockerLogCursor resume = Snapshot(entryStart);
                if (!lines.Any(open => open is { Assembling: true }))
                {
                    (safe, quiet) = (resume, true);
                }

                line ??= lines[slot] = new OpenLine(entry.Stream, entry.Time);
                line.File = cursor.Fingerprint;
                line.Start = entryStart;
                line.Origin = entryStart;
                line.ParsedTime = entry.ParsedTime;
                line.Resume = resume;
            }

            if (!line.Discarding)
            {
                if (line.Text.Length + entry.Log.Length > options.MaximumLineBytes)
                {
                    line.Discarding = true;
                    line.Text.Clear();
                    quiet = false;
                }
                else
                {
                    line.Text.Append(entry.Log);
                }
            }

            line.End = position;
            if (entry.Log.EndsWith('\n'))
            {
                Close(slot);
            }
        }

        private void Close(int slot)
        {
            OpenLine line = lines[slot]!;
            lines[slot] = null;
            quiet = false;
            if (line.Discarding)
            {
                oversized++;
            }
            else if (line.Start >= 0)
            {
                records.Add(new DockerLogRecord(
                    line.Text.ToString().TrimEnd('\n', '\r'),
                    line.Stream,
                    line.ParsedTime,
                    line.File!,
                    line.Start,
                    line.End,
                    line.Fragment,
                    line.Resume));
            }

            // The rest of a line whose head was lost, and nothing of it arrived: nothing to emit.
        }

        /// <summary>The cursor at <paramref name="offset"/> with the lines open now.</summary>
        private DockerLogCursor Snapshot(long offset)
        {
            List<DockerPendingLine>? pending = null;
            bool discarding = blind;
            foreach (OpenLine? line in lines)
            {
                if (line is null)
                {
                    continue;
                }

                pending ??= [];
                pending.Add(line switch
                {
                    { Discarding: true } => new DockerPendingLine(line.Stream, line.Time, Discarding: true),
                    { Start: < 0 } => new DockerPendingLine(line.Stream, line.Time, Fragment: true),
                    _ => new DockerPendingLine(line.Stream, line.Time, File: line.File, Start: line.Start, Length: line.Text.Length, Fragment: line.Fragment)
                });
                discarding |= line.Discarding;
            }

            return cursor with { Offset = offset, Discarding = discarding, Pending = pending };
        }

        /// <summary>Restores the cursor's open lines; true when a line's head was lost.</summary>
        private bool RestorePending()
        {
            if (cursor.Pending is not { } pending)
            {
                if (cursor.Discarding)
                {
                    if (LastChunkKey() is { } key)
                    {
                        lines[Slot(key.Stream)] = new OpenLine(key.Stream, key.Time) { Discarding = true };
                    }
                    else
                    {
                        blind = true;
                    }
                }

                return false;
            }

            bool lost = false;
            foreach (DockerPendingLine saved in pending)
            {
                OpenLine line = new(saved.Stream, saved.Time)
                {
                    Discarding = saved.Discarding,
                    Fragment = saved.Fragment,
                    Origin = cursor.Offset,
                    Resume = cursor
                };
                lines[Slot(saved.Stream)] = line;
                if (saved.Start is { } start && !RestoreHead(line, saved.File!, start, saved.Length!.Value))
                {
                    // Its file rotated away or no longer holds it: the rest is only a fragment.
                    lost = true;
                    line.Text.Clear();
                    (line.Fragment, line.File, line.Start, line.Span, line.ParsedTime) = (true, null, -1, 0, null);
                }
            }

            return lost;
        }

        /// <summary>
        /// Re-reads an open line's chunks from its first one to the cursor: in this file, or in
        /// <c>.1</c> then this file when the log rotated in between. At most two lines, each
        /// within the line limit, and the bytes re-read are bounded by the byte budget (a line
        /// spanning a whole budget is skipped before its start is ever stored).
        /// </summary>
        private bool RestoreHead(OpenLine line, string headFile, long start, int length)
        {
            if (string.Equals(headFile, cursor.Fingerprint, StringComparison.Ordinal))
            {
                line.Span = cursor.Offset - start;
                if (!Collect(file, start, cursor.Offset, line))
                {
                    return false;
                }
            }
            else
            {
                FileTailHandle? previous = rotated();
                if (previous is null
                    || ReferenceEquals(previous, file)
                    || !string.Equals(previous.Fingerprint, headFile, StringComparison.Ordinal))
                {
                    return false;
                }

                long previousLength = previous.Stream.Length;
                line.Span = previousLength - start + cursor.Offset;
                if (!Collect(previous, start, previousLength, line, tornEnd: true) || !Collect(file, 0, cursor.Offset, line))
                {
                    return false;
                }
            }

            (line.File, line.Start) = (headFile, start);
            return line.Text.Length == length;
        }

        /// <param name="tornEnd">The range ends at the end of a final <c>.1</c>, whose torn last entry was counted when it was drained.</param>
        private bool Collect(FileTailHandle source, long from, long to, OpenLine line, bool tornEnd = false)
        {
            FileStream stream = source.Stream;
            stream.Seek(from, SeekOrigin.Begin);
            long position = from;
            while (position < to)
            {
                byte[]? entry = ReadEntry(stream, maximumEntry, out bool complete, out bool tooLong);
                if (!complete)
                {
                    return tornEnd;
                }

                position = stream.Position;
                if (tooLong || entry is null || !TryParseEntry(entry, out Entry parsed)
                    || parsed.Stream != line.Stream || !line.Matches(parsed.Time))
                {
                    continue;
                }

                if (parsed.Log.EndsWith('\n') || line.Text.Length + parsed.Log.Length > options.MaximumLineBytes)
                {
                    return false; // Not the open line the cursor recorded.
                }

                line.ParsedTime ??= parsed.ParsedTime;
                line.Text.Append(parsed.Log);
                line.End = position;
            }

            return position == to;
        }

        /// <summary>The stream and time of the partial chunk that ends at the cursor, if it is one.</summary>
        private (string Stream, string? Time)? LastChunkKey()
        {
            long offset = cursor.Offset;
            if (offset <= 0)
            {
                return null;
            }

            // The entry and its newline, and the newline before it.
            int count = (int)Math.Min(offset, maximumEntry + 2L);
            byte[] window = new byte[count];
            FileStream stream = file.Stream;
            stream.Seek(offset - count, SeekOrigin.Begin);
            if (stream.ReadAtLeast(window, count, throwOnEndOfStream: false) != count || window[^1] != '\n')
            {
                return null;
            }

            int previous = window.AsSpan(0, count - 1).LastIndexOf((byte)'\n');
            if (previous < 0 && offset > count)
            {
                return null; // Longer than any entry the reader accepts.
            }

            return TryParseEntry(window[(previous + 1)..^1], out Entry parsed) && !parsed.Log.EndsWith('\n')
                ? (parsed.Stream, parsed.Time)
                : null;
        }
    }

    private static int Slot(string stream) => stream == "stderr" ? 1 : 0;

    /// <summary>Reads bytes up to and including '\n'. Incomplete means no newline before EOF.</summary>
    private static byte[]? ReadEntry(FileStream stream, int maximumBytes, out bool complete, out bool tooLong)
    {
        using MemoryStream buffer = new();
        tooLong = false;
        int value;
        while ((value = stream.ReadByte()) >= 0)
        {
            if (value == '\n')
            {
                complete = true;
                return tooLong ? null : buffer.ToArray();
            }

            if (!tooLong)
            {
                if (buffer.Length >= maximumBytes)
                {
                    tooLong = true;
                }
                else
                {
                    buffer.WriteByte((byte)value);
                }
            }
        }

        complete = false;
        return null;
    }

    /// <param name="Stream">stdout (also when absent, as Docker always names it) or stderr.</param>
    /// <param name="Time">The raw <c>time</c> value, compared exactly: it keys the line.</param>
    private readonly record struct Entry(string Log, string Stream, string? Time, DateTimeOffset? ParsedTime);

    /// <summary>
    /// A json-file entry. Docker writes only the stdout and stderr streams, so another stream,
    /// or a time longer than any Docker writes, is malformed: the reader tracks one open line
    /// per stream and keeps the time in the cursor.
    /// </summary>
    private static bool TryParseEntry(byte[] entry, out Entry parsed)
    {
        parsed = default;
        try
        {
            using JsonDocument document = JsonDocument.Parse(entry, new JsonDocumentOptions { MaxDepth = 4 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("log", out JsonElement logElement)
                || logElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            string stream = "stdout";
            if (root.TryGetProperty("stream", out JsonElement streamElement)
                && streamElement.ValueKind == JsonValueKind.String)
            {
                stream = streamElement.GetString() switch
                {
                    "stdout" => "stdout",
                    "stderr" => "stderr",
                    _ => string.Empty
                };
                if (stream.Length == 0)
                {
                    return false;
                }
            }

            string? time = null;
            DateTimeOffset? parsedTime = null;
            if (root.TryGetProperty("time", out JsonElement timeElement)
                && timeElement.ValueKind == JsonValueKind.String)
            {
                time = timeElement.GetString();
                if (time is { Length: > DockerLogCursor.MaximumTimeLength })
                {
                    return false;
                }

                if (DateTimeOffset.TryParse(
                    time,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset value))
                {
                    parsedTime = value;
                }
            }

            parsed = new Entry(logElement.GetString() ?? string.Empty, stream, time, parsedTime);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static DockerLogBatch Empty(DockerLogCursor cursor) => new([], cursor, 0, 0, false);
}
