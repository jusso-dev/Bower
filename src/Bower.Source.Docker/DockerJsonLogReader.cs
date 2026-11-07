using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
/// <paramref name="Pending"/> (additive, omitted when empty) names every logical line still
/// open at <paramref name="Offset"/>, at most one per stream, by its stream and Docker
/// <c>time</c> (shared by every chunk of one line): one being skipped (it then also sets
/// <paramref name="Discarding"/>), one being assembled (where each of its chunks is, how long it
/// is so far and a digest of it, so the next read re-reads exactly those chunks, from <c>.1</c>
/// when the log rotated in between), one whose head is the next entry of its key (nothing of it
/// read yet), or the rest of one whose head could not be read. Offsets, a length, a digest and
/// the time only, never line content. A cursor written before this field existed with
/// <paramref name="Discarding"/> set is read as described on <see cref="DockerJsonLogReader"/>.
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

    /// <summary>
    /// Most chunks of one open line the cursor names. Docker cuts a line every 16 KiB, so a line
    /// within the default 64 KiB-character limit has at most 13 (three-byte characters); a line
    /// with more is skipped as oversized.
    /// </summary>
    public const int MaximumChunks = 32;

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
        HashSet<(string File, long Offset)> chunks = [];
        foreach (DockerPendingLine? line in pending)
        {
            if (line is null
                || line.Stream is not ("stdout" or "stderr")
                || line.Time is { Length: > MaximumTimeLength }
                || !LineIsValid(line, cursor, chunks))
            {
                return false;
            }

            discarding |= line.Discarding;
        }

        return discarding == cursor.Discarding;
    }

    /// <summary>
    /// One of the four forms, with every chunk an entry of its own: in order, never shared with
    /// the other line, and those in the cursor's file before its offset.
    /// </summary>
    private static bool LineIsValid(DockerPendingLine line, DockerLogCursor cursor, HashSet<(string File, long Offset)> taken)
    {
        bool keyOnly = line is { File: null, Start: null, Length: null, Chunks: null, Rest: null, Digest: null };
        if (line.Discarding)
        {
            return keyOnly && !line.Fragment;
        }

        if (line.Start is not { } start)
        {
            return keyOnly && line.Fragment;
        }

        if (line.File is not { Length: > 0 and <= 128 } file || start < 0 || line.Length is not { } length || length < 0)
        {
            return false;
        }

        bool here = string.Equals(file, cursor.Fingerprint, StringComparison.Ordinal);
        if (line.Digest is null)
        {
            // Its head is the next entry of its key, at or after the offset.
            return here && start == cursor.Offset && length == 0 && !line.Fragment && line is { Chunks: null, Rest: null };
        }

        IReadOnlyList<long> chunks = line.Chunks ?? [];
        IReadOnlyList<long> rest = line.Rest ?? [];
        if (!IsDigest(line.Digest) || 1 + chunks.Count + rest.Count > MaximumChunks || (here && rest.Count > 0))
        {
            return false;
        }

        long previous = -1;
        long[] inFile = [start, .. chunks];
        foreach (long chunk in inFile)
        {
            if (chunk <= previous || (here && chunk >= cursor.Offset) || !taken.Add((file, chunk)))
            {
                return false;
            }

            previous = chunk;
        }

        previous = -1;
        foreach (long chunk in rest)
        {
            if (chunk <= previous || chunk >= cursor.Offset || !taken.Add((cursor.Fingerprint, chunk)))
            {
                return false;
            }

            previous = chunk;
        }

        return true;
    }

    private static bool IsDigest(string digest)
    {
        Span<byte> bytes = stackalloc byte[18];
        return digest.Length == 24 && Convert.TryFromBase64String(digest, bytes, out int written) && written == DockerPendingLine.DigestBytes;
    }
}

/// <summary>
/// A logical line open at a <see cref="DockerLogCursor"/>, keyed by its stream and Docker
/// <c>time</c>, in one of four forms. Skipped (<paramref name="Discarding"/>). The rest of a line
/// whose head could not be read (<paramref name="Fragment"/> and no start). Its head not read
/// yet: the next entry of its key at or after the cursor (<paramref name="File"/> and
/// <paramref name="Start"/> are the cursor's own, <paramref name="Length"/> 0, no digest).
/// Assembled: its first chunk at <paramref name="Start"/> and its later ones at
/// <paramref name="Chunks"/> in <paramref name="File"/>, then at <paramref name="Rest"/> in the
/// cursor's file when <paramref name="File"/> is the rotated one; <paramref name="Length"/>
/// characters so far, whose SHA-256 (UTF-16, first 16 bytes, base64) is
/// <paramref name="Digest"/>. <paramref name="Fragment"/>: part of it could not be read, so it is
/// never a whole line.
/// </summary>
public sealed record DockerPendingLine(
    string Stream,
    string? Time,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Discarding = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? File = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Start = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Length = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Fragment = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<long>? Chunks = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<long>? Rest = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Digest = null)
{
    internal const int DigestBytes = 16;

    public bool Equals(DockerPendingLine? other) =>
        other is not null
        && Stream == other.Stream
        && string.Equals(Time, other.Time, StringComparison.Ordinal)
        && Discarding == other.Discarding
        && string.Equals(File, other.File, StringComparison.Ordinal)
        && Start == other.Start
        && Length == other.Length
        && Fragment == other.Fragment
        && (Chunks ?? []).SequenceEqual(other.Chunks ?? [])
        && (Rest ?? []).SequenceEqual(other.Rest ?? [])
        && string.Equals(Digest, other.Digest, StringComparison.Ordinal);

    public override int GetHashCode() => HashCode.Combine(Stream, Time, Discarding, File, Start, Length, Fragment, Digest);

    /// <summary>The digest kept for an assembled line's text.</summary>
    internal static string DigestOf(string text) =>
        Convert.ToBase64String(SHA256.HashData(MemoryMarshal.AsBytes(text.AsSpan())).AsSpan(0, DigestBytes));
}

/// <summary>Cursor JSON: camelCase, otherwise default options (source generated).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DockerLogCursor))]
internal sealed partial class DockerCursorJsonContext : JsonSerializerContext;

/// <summary>One logical log line (Docker splits lines over 16 KiB into chunks).</summary>
/// <param name="StartOffset">Its first chunk, in the file <paramref name="FileFingerprint"/> names.</param>
/// <param name="EndOffset">The end of its last chunk, in the file that holds that chunk.</param>
/// <param name="Fragment">
/// Additive: part of a line, never a whole one (its head could not be read, it was open when
/// Bower first saw the log or lost track of it, or an entry between its chunks could not be
/// read). Never mapped as a security event.
/// </param>
/// <param name="Resume">
/// A cursor from which a read emits this record and every later one in its batch again (the
/// sidecar rewinds there when the collector pushes back). It can also emit again records of
/// the batch before this one that ended after it began (another stream's lines), with the same
/// event ids, so they deduplicate. Null only for records built outside the reader.
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
    int OpenAtRotation = 0)
{
    /// <summary>Bytes this read took from the log files: the scan, open lines read again and any look back.</summary>
    internal long BytesRead { get; init; }
}

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
/// Fragments. The cursor names every open line, so once Bower has seen a line open it never
/// emits that line's rest as a whole line: when its head cannot be read again (a gap: the log
/// was rotated twice, <c>.1</c> was removed, or, with <c>max-file: 1</c>, moby's
/// <c>loggerutils/logfile.go</c> unlinks the log and creates it again instead of renaming it),
/// or its saved chunks no longer match their length and digest, what is read of it is a
/// <see cref="DockerLogRecord.Fragment"/>. When Bower first sees a log, or after a gap, each
/// stream whose last entry before the read's start (within one byte budget, in the file and
/// then in <c>.1</c>) leaves its line open is a fragment too. The limit: a line whose head was
/// written after the cursor and lost in the same gap (with <c>max-file: 1</c> while Bower is
/// behind) was never seen, so it cannot be told from a whole line; the gap is counted.
/// </para>
/// <para>
/// A cursor from before <see cref="DockerLogCursor.Pending"/> with
/// <see cref="DockerLogCursor.Discarding"/> set has no key for the line being skipped. The old
/// reader skipped every entry up to and including the first one that ends with a newline,
/// whatever its stream, so the entries before its offset back to the last newline-terminated
/// one are what it skipped. When they are all one stream and time, that is the key. Otherwise
/// (another stream's chunk among them, or none at all: the offset is at the start of the file
/// after a rotation, the entry there is malformed or terminated, or the run reaches past the
/// look-back window) the old rule holds for that one line: every entry is skipped up to and
/// including the first one that ends with a newline, whatever its stream. Nothing skipped is
/// ever mapped. At worst what the old reader would have done is done: that first terminated
/// entry is dropped, and the rest of another stream's line that it had joined into the skipped
/// one is read as a line, as the old reader read it.
/// </para>
/// </summary>
public static class DockerJsonLogReader
{
    /// <summary>
    /// Longest json-file entry read: a 16 KiB chunk whose every byte is escaped to six
    /// (<c>\u0000</c>), plus the stream, time and attributes.
    /// </summary>
    internal const int MaximumEntryBytes = 16_384 * 6 + 4_096;

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
                new Decoder(options, cursor, current, Rotated));
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
    /// read's own cursor wherever the tailer hands that position back and carried across a
    /// rotation by <see cref="MovedToCurrent"/>. Any other position is a first sight or a gap, so
    /// no open line can be re-read there: each one the read's cursor names, and each one left
    /// open just before that position, goes on as a fragment.
    /// </summary>
    internal sealed class Decoder(
        DockerLogReaderOptions options,
        DockerLogCursor? input,
        FileTailHandle? current,
        Func<FileTailHandle?> rotated) : IFileTailDecoder<DockerLogBatch>
    {
        private long lookedBack;

        // eofEndsLine only for a renamed .1 that Docker never writes again (RenamedFileIsFinal).
        // Docker's policy has no copy drain, grace window or file id, so anything else would
        // mean a policy change, not data.
        public DockerLogBatch Scan(FileTailHandle file, FileTailCursor cursor, bool eofEndsLine, bool gap)
        {
            if (eofEndsLine && (cursor.Drain != FileTailCursor.RenameDrain || cursor.FileId is not null))
            {
                throw new UnreachableException("The Docker policy ends a line at end of file only in a renamed .1.");
            }

            DockerLogCursor restored = Restore(cursor, file);
            DockerLogBatch batch = new LineScan(file, restored, options, rotated).Read(gap, eofEndsLine);
            return batch with { BytesRead = batch.BytesRead + lookedBack };
        }

        public DockerLogBatch Empty(FileTailCursor cursor, bool gap)
        {
            DockerLogCursor restored = Restore(cursor, current);
            return DockerJsonLogReader.Empty(restored) with { RotationGap = gap, BytesRead = lookedBack };
        }

        public FileTailCursor CursorOf(DockerLogBatch batch) => Shared(batch.Cursor);

        public bool StoppedByLimit(DockerLogBatch batch) => batch.Records.Count >= options.MaximumRecordsPerBatch;

        public int LineCount(DockerLogBatch batch) => batch.Records.Count;

        public DockerLogBatch WithCursor(DockerLogBatch batch, FileTailCursor cursor) =>
            throw new UnreachableException("The Docker policy has no drain cap or grace window, so no drain state is written.");

        public DockerLogBatch WithGap(DockerLogBatch batch) => batch with { RotationGap = true };

        // The lines open at the end of .1 go with the cursor into the new file. One whose head
        // was still to come in .1 never came: only a fragment of it can follow.
        public DockerLogBatch MovedToCurrent(DockerLogBatch batch, FileTailCursor moved)
        {
            IReadOnlyList<DockerPendingLine>? pending = batch.Cursor.Pending?
                .Select(line => line is { Digest: null, Start: not null } ? new DockerPendingLine(line.Stream, line.Time, Fragment: true) : line)
                .ToList();
            return batch with
            {
                Cursor = Docker(moved) with { Pending = pending },
                OpenAtRotation = pending?.Count(line => line.Digest is not null) ?? 0
            };
        }

        public DockerLogBatch Append(DockerLogBatch batch, DockerLogBatch tail) =>
            throw new UnreachableException("The Docker policy has no grace window, so no settled tail is appended.");

        private DockerLogCursor Restore(FileTailCursor cursor, FileTailHandle? file)
        {
            DockerLogCursor docker = Docker(cursor);
            if (input is not null && docker == input with { Pending = null })
            {
                return input;
            }

            if (docker.Fingerprint.Length == 0 || file is null || !string.Equals(file.Fingerprint, docker.Fingerprint, StringComparison.Ordinal))
            {
                return docker;
            }

            // A first sight or a gap: every line known to be open goes on as the rest of one.
            DockerPendingLine?[] fragments = new DockerPendingLine?[2];
            foreach (DockerPendingLine known in input?.Pending ?? [])
            {
                fragments[Slot(known.Stream)] = new DockerPendingLine(known.Stream, known.Time, Fragment: true);
            }

            int window = options.MaximumBytesPerBatch;
            (DockerPendingLine? Open, bool Seen)[] here = OpenAtEnd(file, docker.Offset, window, ref lookedBack);
            (DockerPendingLine? Open, bool Seen)[] before = docker.Offset <= window
                && rotated() is { } previous
                && !ReferenceEquals(previous, file)
                && !string.Equals(previous.Fingerprint, file.Fingerprint, StringComparison.Ordinal)
                    ? OpenAtEnd(previous, previous.Stream.Length, window, ref lookedBack)
                    : new (DockerPendingLine?, bool)[2];
            for (int slot = 0; slot < 2; slot++)
            {
                fragments[slot] = here[slot].Seen ? here[slot].Open : before[slot].Open ?? fragments[slot];
            }

            List<DockerPendingLine> pending = [.. fragments.OfType<DockerPendingLine>()];
            return docker with { Pending = pending.Count > 0 ? pending : null };
        }
    }

    // Mapped by name; Docker's JSON and schema version stay DockerLogCursor's own (see Docker()).
    private static FileTailCursor Shared(DockerLogCursor cursor) =>
        new(cursor.SchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>Docker's own schema version, independent of the file tail cursor's.</summary>
    internal static DockerLogCursor Docker(FileTailCursor cursor) =>
        new(DockerLogCursor.CurrentSchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>
    /// For each stream, whether an entry of it was read in the <paramref name="window"/> bytes
    /// before <paramref name="end"/>, and, when the last one leaves its line open, that line's
    /// key as a fragment.
    /// </summary>
    private static (DockerPendingLine? Open, bool Seen)[] OpenAtEnd(FileTailHandle source, long end, int window, ref long read)
    {
        (DockerPendingLine? Open, bool Seen)[] last = new (DockerPendingLine?, bool)[2];
        int count = (int)Math.Min(end, window);
        if (count <= 0)
        {
            return last;
        }

        byte[] bytes = new byte[count];
        FileStream stream = source.Stream;
        stream.Seek(end - count, SeekOrigin.Begin);
        int filled = stream.ReadAtLeast(bytes, count, throwOnEndOfStream: false);
        read += filled;
        int position = 0;
        if (end > count)
        {
            // The window starts inside an entry.
            position = bytes.AsSpan(0, filled).IndexOf((byte)'\n') + 1;
            if (position == 0)
            {
                return last;
            }
        }

        int newline;
        while ((newline = bytes.AsSpan(position, filled - position).IndexOf((byte)'\n')) >= 0)
        {
            ReadOnlyMemory<byte> entry = bytes.AsMemory(position, newline);
            position += newline + 1;
            if (entry.Length <= MaximumEntryBytes && TryParseEntry(entry, out Entry parsed))
            {
                last[Slot(parsed.Stream)] = (parsed.Log.EndsWith('\n') ? null : new DockerPendingLine(parsed.Stream, parsed.Time, Fragment: true), true);
            }
        }

        return last;
    }

    /// <summary>A logical line open during a scan: being assembled, skipped, or known only by its key.</summary>
    private sealed class OpenLine(string stream, string? time)
    {
        private string? digest;

        public string Stream { get; } = stream;

        public string? Time { get; } = time;

        public bool Discarding { get; private set; }

        /// <summary>Part of it could not be read: what is assembled is a fragment.</summary>
        public bool Fragment { get; set; }

        /// <summary>The file holding its first chunk.</summary>
        public string? File { get; set; }

        /// <summary>Its first chunk; -1 before one is read (its head is next, or lost when a fragment).</summary>
        public long Start { get; private set; } = -1;

        /// <summary>Its later chunks in <see cref="File"/>.</summary>
        public List<long> Chunks { get; } = [];

        /// <summary>Its chunks in the scanned file, when <see cref="File"/> is the rotated one.</summary>
        public List<long> Rest { get; } = [];

        public long End { get; set; }

        /// <summary>Where this read met its head, if it did.</summary>
        public long Origin { get; set; } = -1;

        public DateTimeOffset? ParsedTime { get; set; }

        public StringBuilder Text { get; } = new();

        public DockerLogCursor? Resume { get; set; }

        public bool Assembling => !Discarding && Start >= 0;

        public int ChunkCount => Start < 0 ? 0 : 1 + Chunks.Count + Rest.Count;

        public bool Matches(string? time) => string.Equals(Time, time, StringComparison.Ordinal);

        public void Append(string log, long offset, bool inFile)
        {
            if (Start < 0)
            {
                Start = offset;
            }
            else
            {
                (inFile ? Chunks : Rest).Add(offset);
            }

            Text.Append(log);
            digest = null;
        }

        public void Skip()
        {
            Discarding = true;
            Clear();
        }

        /// <summary>Its head cannot be read: only the rest of it, a fragment, can follow.</summary>
        public void Lose()
        {
            Clear();
            (Fragment, File, Start, Origin, ParsedTime) = (true, null, -1, -1, null);
        }

        public string Digest() => digest ??= DockerPendingLine.DigestOf(Text.ToString());

        private void Clear()
        {
            Text.Clear();
            Chunks.Clear();
            Rest.Clear();
            digest = null;
        }
    }

    /// <summary>One scan of one generation from a cursor, within the record and byte bounds.</summary>
    private sealed class LineScan(FileTailHandle file, DockerLogCursor cursor, DockerLogReaderOptions options, Func<FileTailHandle?> rotated)
    {
        private readonly List<DockerLogRecord> records = [];
        private readonly OpenLine?[] lines = new OpenLine?[2];
        private int malformed;
        private int oversized;
        private long consumed;

        // A cursor from before the discard key whose key could not be recovered (see the class remarks).
        private bool blind;

        // Pinning: while nothing has been emitted, counted or closed since the last point with no
        // line being assembled, a read that ends with lines open commits that point, as the
        // reader always did, rather than recording where those lines' chunks are.
        private DockerLogCursor? safe;
        private bool quiet;

        public DockerLogBatch Read(bool rotationGap, bool final)
        {
            rotationGap |= RestorePending();

            // Reading the open lines again counts against the byte budget, but every read still
            // takes at least one entry, so it always moves on.
            FileStream stream = file.Stream;
            stream.Seek(cursor.Offset, SeekOrigin.Begin);
            long budgetEnd = Math.Min(stream.Length, cursor.Offset + Math.Max(1, options.MaximumBytesPerBatch - consumed));
            long position = cursor.Offset;
            while (records.Count < options.MaximumRecordsPerBatch && position < budgetEnd)
            {
                long entryStart = position;
                byte[]? entry = ReadEntry(stream, consumeLong: true, out bool complete, out bool tooLong);
                consumed += stream.Position - entryStart;
                if (!complete)
                {
                    if (final)
                    {
                        // A torn entry at the end of a file that is never written again.
                        malformed++;
                        Unreadable();
                        position = stream.Position;
                    }

                    break; // Writer has not finished this line; read it next time.
                }

                position = stream.Position;
                if (tooLong || entry is null || !TryParseEntry(entry, out Entry parsed))
                {
                    malformed++;
                    Unreadable();
                    continue;
                }

                Add(parsed, entryStart, position);
            }

            // A file that is never written again (a drained .1) ends here: every line still open
            // goes into the cursor, which moves to the new file, so it is re-read from .1 and
            // joined with its rest there. Otherwise, a read that would commit where it began (a
            // line that began there, open and alone) after a whole byte budget can never read
            // that line within bounds: skip it rather than read the same bytes every poll.
            bool ended = final && position >= stream.Length;
            bool pinned = !ended && quiet && safe is not null && lines.Any(line => line is { Assembling: true });
            if (pinned && safe!.Offset == cursor.Offset && position - cursor.Offset >= options.MaximumBytesPerBatch)
            {
                foreach (OpenLine? line in lines)
                {
                    if (line is { Assembling: true } && line.Origin == cursor.Offset)
                    {
                        line.Skip();
                    }
                }

                pinned = false;
            }

            DockerLogCursor committed = pinned ? Pin(safe!) : Snapshot(position);
            return new DockerLogBatch(records, committed, malformed, oversized, rotationGap) { BytesRead = consumed };
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
                line.Origin = entryStart;
                line.ParsedTime = entry.ParsedTime;
                line.Resume = resume;
            }

            if (!line.Discarding)
            {
                if (line.Text.Length + entry.Log.Length > options.MaximumLineBytes || line.ChunkCount >= DockerLogCursor.MaximumChunks)
                {
                    line.Skip();
                    quiet = false;
                }
                else
                {
                    line.Append(entry.Log, entryStart, string.Equals(line.File, cursor.Fingerprint, StringComparison.Ordinal));
                }
            }

            line.End = position;
            if (entry.Log.EndsWith('\n'))
            {
                Close(slot);
            }
        }

        // An entry that cannot be read may be a chunk of any line being assembled: none is whole now.
        private void Unreadable()
        {
            foreach (OpenLine? line in lines)
            {
                if (line is { Assembling: true })
                {
                    line.Fragment = true;
                }
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

            // Known by its key only, and nothing of it arrived: nothing to emit.
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
                    { Start: < 0, Fragment: true } => new DockerPendingLine(line.Stream, line.Time, Fragment: true),
                    { Start: < 0 } => Unread(line, offset),
                    _ => new DockerPendingLine(
                        line.Stream,
                        line.Time,
                        File: line.File,
                        Start: line.Start,
                        Length: line.Text.Length,
                        Fragment: line.Fragment,
                        Chunks: line.Chunks.Count > 0 ? [.. line.Chunks] : null,
                        Rest: line.Rest.Count > 0 ? [.. line.Rest] : null,
                        Digest: line.Digest())
                });
                discarding |= line.Discarding;
            }

            return cursor with { Offset = offset, Discarding = discarding, Pending = pending };
        }

        /// <summary>
        /// The pinned point, naming each line assembled since by its key, so a gap or a lost
        /// <c>.1</c> before the next read still knows that its rest is a fragment.
        /// </summary>
        private DockerLogCursor Pin(DockerLogCursor at)
        {
            DockerPendingLine?[] pending = new DockerPendingLine?[2];
            foreach (DockerPendingLine saved in at.Pending ?? [])
            {
                pending[Slot(saved.Stream)] = saved;
            }

            for (int slot = 0; slot < 2; slot++)
            {
                if (pending[slot] is null && lines[slot] is { Assembling: true } line)
                {
                    pending[slot] = Unread(line, at.Offset);
                }
            }

            return at with { Pending = [.. pending.OfType<DockerPendingLine>()] };
        }

        private DockerPendingLine Unread(OpenLine line, long offset) =>
            new(line.Stream, line.Time, File: cursor.Fingerprint, Start: offset, Length: 0);

        /// <summary>Restores the cursor's open lines; true when a line's head was lost.</summary>
        private bool RestorePending()
        {
            if (cursor.Pending is not { } pending)
            {
                if (cursor.Discarding)
                {
                    if (LastChunkKey() is { } key)
                    {
                        OpenLine line = new(key.Stream, key.Time);
                        line.Skip();
                        lines[Slot(key.Stream)] = line;
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
                OpenLine line = new(saved.Stream, saved.Time) { Fragment = saved.Fragment, Resume = cursor };
                lines[Slot(saved.Stream)] = line;
                if (saved.Discarding)
                {
                    line.Skip();
                }
                else if (saved.Digest is not null && !RestoreChunks(line, saved))
                {
                    // Its file rotated away or no longer holds it: the rest is only a fragment.
                    lost = true;
                    line.Lose();
                }

                // Otherwise known by its key only: the rest of a lost head, or a head still to come.
            }

            return lost;
        }

        /// <summary>
        /// Reads an open line's saved chunks again, in this file or in <c>.1</c> then this one
        /// when the log rotated in between: at most <see cref="DockerLogCursor.MaximumChunks"/>
        /// entries, so the cost is the line's own size, never the span to the cursor. They must
        /// give the saved length and digest.
        /// </summary>
        private bool RestoreChunks(OpenLine line, DockerPendingLine saved)
        {
            bool here = string.Equals(saved.File, cursor.Fingerprint, StringComparison.Ordinal);
            FileTailHandle? head = here
                ? file
                : rotated() is { } previous && !ReferenceEquals(previous, file) && string.Equals(previous.Fingerprint, saved.File, StringComparison.Ordinal)
                    ? previous
                    : null;
            if (head is null)
            {
                return false;
            }

            line.File = saved.File;
            long limit = here ? cursor.Offset : long.MaxValue;
            long[] inFile = [saved.Start!.Value, .. saved.Chunks ?? []];
            foreach (long offset in inFile)
            {
                if (!ReadChunk(head, offset, limit, line, inFile: true))
                {
                    return false;
                }
            }

            foreach (long offset in saved.Rest ?? [])
            {
                if (!ReadChunk(file, offset, cursor.Offset, line, inFile: false))
                {
                    return false;
                }
            }

            return line.Text.Length == saved.Length && string.Equals(line.Digest(), saved.Digest, StringComparison.Ordinal);
        }

        /// <summary>One saved chunk: a whole, unterminated entry of the line's key that ends by <paramref name="limit"/>.</summary>
        private bool ReadChunk(FileTailHandle source, long offset, long limit, OpenLine line, bool inFile)
        {
            FileStream stream = source.Stream;
            stream.Seek(offset, SeekOrigin.Begin);
            byte[]? entry = ReadEntry(stream, consumeLong: false, out bool complete, out bool tooLong);
            consumed += stream.Position - offset;
            if (!complete || tooLong || entry is null || stream.Position > limit
                || !TryParseEntry(entry, out Entry parsed)
                || parsed.Stream != line.Stream
                || !line.Matches(parsed.Time)
                || parsed.Log.EndsWith('\n')
                || line.Text.Length + parsed.Log.Length > options.MaximumLineBytes)
            {
                return false; // Not the open line the cursor recorded.
            }

            line.ParsedTime ??= parsed.ParsedTime;
            line.Append(parsed.Log, offset, inFile);
            line.End = stream.Position;
            return true;
        }

        /// <summary>
        /// The stream and time of the line an old discarding cursor was skipping: the entries
        /// before its offset, back to the last terminated one, when they are all one key.
        /// </summary>
        private (string Stream, string? Time)? LastChunkKey()
        {
            long offset = cursor.Offset;
            if (offset <= 0)
            {
                return null;
            }

            int count = (int)Math.Min(offset, 4L * MaximumEntryBytes);
            byte[] window = new byte[count];
            FileStream stream = file.Stream;
            stream.Seek(offset - count, SeekOrigin.Begin);
            int filled = stream.ReadAtLeast(window, count, throwOnEndOfStream: false);
            consumed += filled;
            if (filled != count || window[^1] != '\n')
            {
                return null;
            }

            (string Stream, string? Time)? key = null;
            int end = count - 1;
            while (true)
            {
                int previous = window.AsSpan(0, end).LastIndexOf((byte)'\n');
                if (previous < 0 && offset > count)
                {
                    return null; // The run reaches past the window: it cannot be told apart.
                }

                ReadOnlyMemory<byte> entry = window.AsMemory(previous + 1, end - previous - 1);
                Entry chunk = default;
                bool parsed = entry.Length <= MaximumEntryBytes && TryParseEntry(entry, out chunk);
                if (key is null && (!parsed || chunk.Log.EndsWith('\n')))
                {
                    return null; // The entry it skipped last is not a partial chunk.
                }

                if (parsed)
                {
                    if (chunk.Log.EndsWith('\n'))
                    {
                        return key; // The line before the one it skipped.
                    }

                    if (key is { } known && known != (chunk.Stream, chunk.Time))
                    {
                        return null; // Another line's chunk: the old reader joined them.
                    }

                    key = (chunk.Stream, chunk.Time);
                }

                if (previous < 0)
                {
                    return key; // The start of the file.
                }

                end = previous;
            }
        }
    }

    private static int Slot(string stream) => stream == "stderr" ? 1 : 0;

    /// <summary>
    /// Reads bytes up to and including '\n'. Incomplete means no newline before EOF. An entry
    /// over <see cref="MaximumEntryBytes"/> is too long: read to its newline when
    /// <paramref name="consumeLong"/>, so the scan can pass it, else left at once.
    /// </summary>
    private static byte[]? ReadEntry(FileStream stream, bool consumeLong, out bool complete, out bool tooLong)
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
                if (buffer.Length >= MaximumEntryBytes)
                {
                    tooLong = true;
                    if (!consumeLong)
                    {
                        complete = true;
                        return null;
                    }
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
    private static bool TryParseEntry(ReadOnlyMemory<byte> entry, out Entry parsed)
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
