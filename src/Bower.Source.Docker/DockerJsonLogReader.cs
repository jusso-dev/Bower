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
/// is so far and a digest of it, so the next read re-reads exactly those chunks, from the
/// rotated files when the log rotated in between), one whose head lies after the offset (read
/// once, checked by its length and digest when it is read again), the rest of one whose head
/// could not be read, or a stream not proven clean after a gap or a first sight. Offsets, a
/// length, a digest and the time only, never line content. A cursor written before this field
/// existed with <paramref name="Discarding"/> set is read as described on
/// <see cref="DockerJsonLogReader"/>. Only the formats released on main are read: a
/// <paramref name="Pending"/> from an unreleased build that this one does not write is refused
/// as damaged.
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
    /// One of the six forms, with every chunk an entry of its own: in order, never shared with
    /// the other line, those in the cursor's file before its offset, and a head after the offset
    /// alone.
    /// </summary>
    private static bool LineIsValid(DockerPendingLine line, DockerLogCursor cursor, HashSet<(string File, long Offset)> taken)
    {
        bool keyOnly = line is { File: null, Start: null, Length: null, Chunks: null, Rest: null, Digest: null, Through: null };
        if (line is { Unproven: true, Time: null })
        {
            return keyOnly && line.Fragment && !line.Discarding && !line.Lost;
        }

        // With a time, unproven marks an open line in any of the other forms (see DockerPendingLine).

        if (line.Lost && (!keyOnly || !line.Fragment || line.Discarding))
        {
            return false;
        }

        if (line.Discarding)
        {
            return keyOnly && !line.Fragment;
        }

        if (line.Start is not { } start)
        {
            return keyOnly && line.Fragment;
        }

        if (!IsFile(line.File) || start < 0 || line.Length is not { } length || length < 0 || line.Digest is null || !IsDigest(line.Digest))
        {
            return false;
        }

        string file = line.File!;
        bool here = string.Equals(file, cursor.Fingerprint, StringComparison.Ordinal);
        if (here && start >= cursor.Offset)
        {
            // Read once, committed before its head: the head and its length and digest only.
            return line is { Chunks: null, Rest: null, Through: null } && taken.Add((file, start));
        }

        IReadOnlyList<long> chunks = line.Chunks ?? [];
        IReadOnlyList<long> rest = line.Rest ?? [];
        IReadOnlyList<DockerChunkRun> through = line.Through ?? [];
        if (here && (rest.Count > 0 || through.Count > 0))
        {
            return false;
        }

        if (through.Any(run => run is null) || 1 + chunks.Count + rest.Count + through.Sum(run => run.Chunks?.Count ?? 0) > MaximumChunks)
        {
            return false;
        }

        if (!InOrder(file, [start, .. chunks], here ? cursor.Offset : long.MaxValue, taken))
        {
            return false;
        }

        HashSet<string> files = [file, cursor.Fingerprint];
        foreach (DockerChunkRun run in through)
        {
            if (!IsFile(run.File) || !files.Add(run.File) || run.Chunks is not { Count: > 0 } || !InOrder(run.File, run.Chunks, long.MaxValue, taken))
            {
                return false;
            }
        }

        return InOrder(cursor.Fingerprint, rest, cursor.Offset, taken);
    }

    private static bool IsFile(string? file) => file is { Length: > 0 and <= 128 };

    private static bool InOrder(string file, IReadOnlyList<long> chunks, long limit, HashSet<(string File, long Offset)> taken)
    {
        long previous = -1;
        foreach (long chunk in chunks)
        {
            if (chunk <= previous || chunk >= limit || !taken.Add((file, chunk)))
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
/// <c>time</c>, in one of six forms. Skipped (<paramref name="Discarding"/>). The rest of a line
/// whose head could not be read (<paramref name="Fragment"/> and no start). A stream not proven
/// clean (<paramref name="Unproven"/>, also <paramref name="Fragment"/>, no time): after a gap or
/// a first sight the look back found neither its last entry nor a point where no line of it was
/// open, or an entry that could not be read came while none was, so its next entry, whatever its
/// time, keys a line that is a fragment. <paramref name="Unproven"/> with a time, on any other
/// form: an entry that could not be read came while this line was open, so if another time ends
/// it (it never got its final chunk) the line that time starts is a fragment. Read once and
/// committed before its head (<paramref name="File"/> the cursor's own and
/// <paramref name="Start"/> at or after its offset): the next read meets it again and checks
/// that its first <paramref name="Length"/> characters give <paramref name="Digest"/>.
/// Assembled: its first chunk at <paramref name="Start"/> and its later ones at
/// <paramref name="Chunks"/> in <paramref name="File"/>, then those at <paramref name="Through"/>
/// in the files rotated after it, oldest first, then those at <paramref name="Rest"/> in the
/// cursor's file when <paramref name="File"/> is a rotated one; <paramref name="Length"/>
/// characters so far, whose SHA-256 (UTF-16, first 16 bytes, base64) is
/// <paramref name="Digest"/>. <paramref name="Fragment"/>: part of it could not be read, so it is
/// never a whole line. <paramref name="Lost"/>, on the rest of a line: Bower had read part of it,
/// so if none of the rest is read either it is counted as lost (<see cref="DockerLogBatch.Lost"/>).
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
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Digest = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<DockerChunkRun>? Through = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Unproven = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Lost = false)
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
        && string.Equals(Digest, other.Digest, StringComparison.Ordinal)
        && (Through ?? []).SequenceEqual(other.Through ?? [])
        && Unproven == other.Unproven
        && Lost == other.Lost;

    public override int GetHashCode() => HashCode.Combine(Stream, Time, Discarding, File, Start, Length, Fragment, HashCode.Combine(Digest, Unproven, Lost));

    /// <summary>A stream whose next line is a fragment, whatever its time.</summary>
    internal static DockerPendingLine UnprovenStream(string stream) => new(stream, null, Fragment: true, Unproven: true);

    /// <summary>This open line, its stream's next line a fragment when another time ends it.</summary>
    internal DockerPendingLine WithUnprovenNext(bool unproven) => !unproven
        ? this
        : Time is null ? UnprovenStream(Stream) : this with { Unproven = true }; // No time: only the keyless form can say so.

    /// <summary>The digest kept for an assembled line's text.</summary>
    internal static string DigestOf(string text) =>
        Convert.ToBase64String(SHA256.HashData(MemoryMarshal.AsBytes(text.AsSpan())).AsSpan(0, DigestBytes));
}

/// <summary>Chunks of an open line in one file rotated between its head's file and the cursor's.</summary>
public sealed record DockerChunkRun(string File, IReadOnlyList<long> Chunks)
{
    public bool Equals(DockerChunkRun? other) =>
        other is not null
        && string.Equals(File, other.File, StringComparison.Ordinal)
        && (Chunks ?? []).SequenceEqual(other.Chunks ?? []);

    public override int GetHashCode() => HashCode.Combine(File, Chunks?.Count ?? 0);
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
/// (additive, zero by default): each is re-read from the rotated files and joined with its rest.
/// </param>
/// <param name="Lost">
/// Open lines part of which Bower had read and can no longer read again (their head rotated
/// away, was removed or changed, or a gap passed them) and of which nothing more was read, so
/// no fragment of them was emitted (additive, zero by default). One whose rest is read is
/// emitted as a <see cref="DockerLogRecord.Fragment"/> instead, so each lost line is counted
/// once, one way or the other.
/// </param>
public sealed record DockerLogBatch(
    IReadOnlyList<DockerLogRecord> Records,
    DockerLogCursor Cursor,
    int Malformed,
    int Oversized,
    bool RotationGap,
    int OpenAtRotation = 0,
    int Lost = 0)
{
    /// <summary>
    /// Bytes this read took from the log files: any look back, the identities of rotated files
    /// it opened beyond <c>.1</c>, open lines read again and the scan. Within the byte budget plus
    /// one entry, as each read still takes one new entry.
    /// </summary>
    internal long BytesRead { get; init; }
}

public sealed record DockerLogReaderOptions
{
    public int MaximumLineBytes { get; init; } = 65_536;

    public int MaximumRecordsPerBatch { get; init; } = 1_000;

    public int MaximumBytesPerBatch { get; init; } = 4 * 1_048_576;

    /// <summary>When a container is first seen, start at the end instead of replaying history.</summary>
    public bool StartAtEnd { get; init; } = true;

    /// <summary>
    /// Tests only, never set in production: the look back after a gap or a first sight is not
    /// charged to <see cref="MaximumBytesPerBatch"/>, so <c>DockerReaderDifferentialTests</c> can
    /// compare each read with the pre-refactor reader, which never looked back.
    /// </summary>
    internal bool LookBackOutsideBudget { get; init; }
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
/// was rotated twice between reads with nothing keeping the head, a rotated file was removed,
/// or, with <c>max-file: 1</c>, moby's <c>loggerutils/logfile.go</c> unlinks the log and creates
/// it again instead of renaming it), or its saved chunks no longer match their length and
/// digest, what is read of it is a <see cref="DockerLogRecord.Fragment"/>. A line's chunks are
/// found by the identity of their file in the current file or any rotated one, <c>.1</c> to
/// <c>.N</c>, so a line that spans several rotations while Bower keeps up stays whole. An entry
/// that cannot be read (malformed, over-long or torn) may be any stream's, a chunk of an open
/// line or the head of a stream's next one, so the open lines are fragments and each stream's
/// next line is one too (for a line still open, the line another time starts after it).
/// </para>
/// <para>
/// Fail closed after a gap or a first sight. Where a read starts anywhere but its own last
/// position, a stream counts as clean only when the look back (one byte budget, charged to the
/// pass, from the read's start back through the file and then <c>.1</c>, <c>.2</c> and on)
/// reaches the stream's last entry (terminated: clean; open: the rest of that line is a
/// fragment), the read's own last position in a rotated file (the cursor named every line open
/// there), or, at a first sight only, the start of the oldest rotated file there is. Otherwise
/// (the window ran out, a rotated file between is missing, unreadable or not a predecessor, or
/// after a gap the file before the oldest one is gone) the stream is
/// <see cref="DockerPendingLine.Unproven"/>: its next entry, whatever its time, keys a line that
/// is a fragment, and the stream is clean once that line ends. That costs at most one line per
/// stream per gap or first sight. The limit, at a first sight only: a stream with no entry at
/// all in the files Docker kept is taken as clean, so if Docker had already deleted a file
/// holding the head of one of its lines, the rest of that line is read as whole.
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
        using Generations generations = new(container.LogPath);
        return FileTailFiles.Plan(
            current,
            fileId: null,
            generations.First,
            cursor is null ? null : Shared(cursor),
            options.StartAtEnd ? StartAtEndPolicy : ReplayPolicy,
            new Decoder(options, cursor, current, generations));
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
    /// re-read from the rotated files and joined with its rest there.
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
    /// A log's rotated files, <c>.1</c> to <c>.N</c> (at most <see cref="MaximumRotated"/>), each
    /// opened and identified on first use and kept for the read. The tailer uses <c>.1</c> only;
    /// the decoder finds a line's chunks and looks back in all of them.
    /// </summary>
    internal sealed class Generations(string logPath) : IDisposable
    {
        internal const int MaximumRotated = 32;

        private readonly List<FileTailHandle?> opened = [];

        /// <summary>Bytes read to identify the rotated files after <c>.1</c> (the tailer identifies <c>.1</c> for itself).</summary>
        public long IdentityBytes { get; private set; }

        public FileTailHandle? First() => Rotated(1);

        /// <summary><c>.age</c>, or null when it is missing or too short to identify.</summary>
        public FileTailHandle? Rotated(int age)
        {
            if (age is < 1 or > MaximumRotated)
            {
                return null;
            }

            while (opened.Count < age)
            {
                int next = opened.Count + 1;
                FileTailHandle? file = FileTailHandle.OpenWithPrefixIdentity(Path(next));
                if (file is not null && next > 1)
                {
                    IdentityBytes += FileTailHandle.PrefixIdentityBytes;
                }

                opened.Add(file);
            }

            return opened[age - 1];
        }

        /// <summary>Whether <c>.age</c> is there, identified or not.</summary>
        public bool Exists(int age) => System.IO.File.Exists(Path(age));

        /// <summary>At most what opening <c>.age</c> reads: nothing for <c>.1</c> or a file already opened.</summary>
        public long IdentityCost(int age) => age > 1 && age > opened.Count ? FileTailHandle.PrefixIdentityBytes : 0;

        /// <summary>0 for any file that is not a rotated one (the current file), else its age.</summary>
        public int AgeOf(FileTailHandle file) => opened.FindIndex(open => ReferenceEquals(open, file)) + 1;

        /// <summary>
        /// The youngest rotated file other than <paramref name="except"/> with this identity,
        /// identifying files only within <paramref name="allowance"/> bytes; when it would need
        /// more, <paramref name="outOfBudget"/> and null.
        /// </summary>
        public FileTailHandle? Find(string fingerprint, FileTailHandle except, long allowance, out bool outOfBudget)
        {
            outOfBudget = false;
            for (int age = 1; ; age++)
            {
                if (IdentityCost(age) > allowance)
                {
                    outOfBudget = true;
                    return null;
                }

                long identified = IdentityBytes;
                if (Rotated(age) is not { } file)
                {
                    return null;
                }

                allowance -= IdentityBytes - identified;
                if (!ReferenceEquals(file, except) && string.Equals(file.Fingerprint, fingerprint, StringComparison.Ordinal))
                {
                    return file;
                }
            }
        }

        public void Dispose()
        {
            foreach (FileTailHandle? file in opened)
            {
                file?.Dispose();
            }
        }

        private string Path(int age) => logPath + "." + age.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Docker json-file entries. A drain stopped by the record limit is not drained. Docker's
    /// cursor keeps no rotation state, so each read detects the rotation again, as it always did.
    /// The shared cursor has no <see cref="DockerLogCursor.Pending"/>: it is restored from the
    /// read's own cursor wherever the tailer hands that position back and carried across a
    /// rotation by <see cref="MovedToCurrent"/>. Any other position is a first sight or a gap, so
    /// no open line can be re-read there: each one the read's cursor names goes on as a fragment,
    /// and the look back decides for each stream (see the class remarks).
    /// </summary>
    internal sealed class Decoder(
        DockerLogReaderOptions options,
        DockerLogCursor? input,
        FileTailHandle? current,
        Generations generations) : IFileTailDecoder<DockerLogBatch>
    {
        // The look back and the identities it read, charged to the pass's byte budget.
        private long lookedBack;
        private int lost;

        // eofEndsLine only for a renamed .1 that Docker never writes again (RenamedFileIsFinal).
        // Docker's policy has no copy drain, grace window or file id, so anything else would
        // mean a policy change, not data.
        public DockerLogBatch Scan(FileTailHandle file, FileTailCursor cursor, bool eofEndsLine, bool gap)
        {
            if (eofEndsLine && (cursor.Drain != FileTailCursor.RenameDrain || cursor.FileId is not null))
            {
                throw new UnreachableException("The Docker policy ends a line at end of file only in a renamed .1.");
            }

            DockerLogCursor restored = Restore(cursor, file, gap);
            long charged = options.LookBackOutsideBudget ? 0 : lookedBack;
            DockerLogBatch batch = new LineScan(file, restored, options, generations, charged).Read(gap, eofEndsLine);
            return batch with { Lost = batch.Lost + lost, BytesRead = batch.BytesRead + lookedBack - charged };
        }

        public DockerLogBatch Empty(FileTailCursor cursor, bool gap)
        {
            DockerLogCursor restored = Restore(cursor, current, gap);
            return DockerJsonLogReader.Empty(restored) with { RotationGap = gap, BytesRead = lookedBack, Lost = lost };
        }

        public FileTailCursor CursorOf(DockerLogBatch batch) => Shared(batch.Cursor);

        public bool StoppedByLimit(DockerLogBatch batch) => batch.Records.Count >= options.MaximumRecordsPerBatch;

        public int LineCount(DockerLogBatch batch) => batch.Records.Count;

        public DockerLogBatch WithCursor(DockerLogBatch batch, FileTailCursor cursor) =>
            throw new UnreachableException("The Docker policy has no drain cap or grace window, so no drain state is written.");

        public DockerLogBatch WithGap(DockerLogBatch batch) => batch with { RotationGap = true };

        // The lines open at the end of .1 go with the cursor into the new file, their chunks in
        // .1 now a run between their head's file and the new one. A head after the cursor in .1
        // never came there: only a fragment of it can follow.
        public DockerLogBatch MovedToCurrent(DockerLogBatch batch, FileTailCursor moved)
        {
            DockerLogCursor from = batch.Cursor;
            IReadOnlyList<DockerPendingLine>? pending = from.Pending?
                .Select(line => line switch
                {
                    { Start: { } start } when start >= from.Offset && string.Equals(line.File, from.Fingerprint, StringComparison.Ordinal) =>
                        new DockerPendingLine(line.Stream, line.Time, Fragment: true, Lost: true).WithUnprovenNext(line.Unproven),
                    { Rest: { Count: > 0 } rest } => line with { Rest = null, Through = [.. line.Through ?? [], new DockerChunkRun(from.Fingerprint, rest)] },
                    _ => line
                })
                .ToList();
            return batch with
            {
                Cursor = Docker(moved) with { Pending = pending },
                OpenAtRotation = pending?.Count(line => line.Digest is not null) ?? 0
            };
        }

        public DockerLogBatch Append(DockerLogBatch batch, DockerLogBatch tail) =>
            throw new UnreachableException("The Docker policy has no grace window, so no settled tail is appended.");

        private DockerLogCursor Restore(FileTailCursor cursor, FileTailHandle? file, bool gap)
        {
            DockerLogCursor docker = Docker(cursor);
            if (input is not null && docker == input with { Pending = null })
            {
                return input;
            }

            if (docker.Fingerprint.Length == 0 || file is null || !string.Equals(file.Fingerprint, docker.Fingerprint, StringComparison.Ordinal))
            {
                // Nothing to look back in. After a gap no stream is proven clean.
                return gap ? docker with { Pending = [DockerPendingLine.UnprovenStream("stdout"), DockerPendingLine.UnprovenStream("stderr")] } : docker;
            }

            // A first sight, a gap or a replay: every line known to be open goes on as the rest of
            // one, lost when Bower had read part of it.
            DockerPendingLine?[] known = new DockerPendingLine?[2];
            foreach (DockerPendingLine line in input?.Pending ?? [])
            {
                known[Slot(line.Stream)] = line is { Unproven: true, Time: null }
                    ? line
                    : new DockerPendingLine(line.Stream, line.Time, Fragment: true, Lost: line.Lost || line.Digest is not null).WithUnprovenNext(line.Unproven);
            }

            if (input is { Discarding: true, Pending: null })
            {
                // An old cursor skipping a line of a stream it did not name.
                known = [DockerPendingLine.UnprovenStream("stdout"), DockerPendingLine.UnprovenStream("stderr")];
            }

            bool firstSight = input is null || (input.Fingerprint.Length == 0 && input.Pending is null);
            LookBack look = Walk(file, docker.Offset);
            List<DockerPendingLine> pending = [];
            for (int slot = 0; slot < 2; slot++)
            {
                // An open last entry of a line the cursor knew keeps that line's own key.
                DockerPendingLine? line = look.Found[slot]
                    ? look.Open[slot] is { } open && known[slot] is { } same && same is not { Unproven: true, Time: null } && string.Equals(same.Time, open.Time, StringComparison.Ordinal)
                        ? same
                        : look.Open[slot]
                    : look.AtInput
                        ? known[slot]
                        : look.AtOldest && firstSight && !gap
                            ? null
                            : DockerPendingLine.UnprovenStream(slot == 0 ? "stdout" : "stderr");
                if (line is not null)
                {
                    pending.Add(line);
                }

                // A lost line the look back ended (or could not follow) is counted now.
                lost += known[slot] is { Lost: true } && !ReferenceEquals(line, known[slot]) ? 1 : 0;
            }

            lookedBack += generations.IdentityBytes;
            return docker with { Pending = pending.Count > 0 ? pending : null };
        }

        /// <summary>
        /// Looks back from <paramref name="offset"/> in <paramref name="start"/>, then through each
        /// older rotated file, within one byte budget, until each stream's state there is known.
        /// </summary>
        private LookBack Walk(FileTailHandle start, long offset)
        {
            LookBack look = new();
            long budget = options.MaximumBytesPerBatch;
            int age = generations.AgeOf(start);
            HashSet<string> examined = [start.Fingerprint!];
            FileTailHandle source = start;
            long end = offset;
            while (true)
            {
                // The read's own last position, in an older file: its cursor named every line open there.
                bool own = !ReferenceEquals(source, start)
                    && input is { Fingerprint.Length: > 0 }
                    && string.Equals(source.Fingerprint, input.Fingerprint, StringComparison.Ordinal)
                    && input.Offset <= end;
                long from = own ? input!.Offset : 0;
                if (!LookBackIn(source, from, end, ref budget, look) || look.Found.All(found => found))
                {
                    return look;
                }

                if (own)
                {
                    look.AtInput = true;
                    return look;
                }

                // Identifying .2 and on is read from the same budget.
                if (generations.IdentityCost(age + 1) > budget)
                {
                    return look;
                }

                long identified = generations.IdentityBytes;
                FileTailHandle? older = generations.Rotated(++age);
                budget -= generations.IdentityBytes - identified;
                if (older is null)
                {
                    // The start of the oldest file, unless one is there that cannot be identified.
                    look.AtOldest = !generations.Exists(age);
                    return look;
                }

                if (!examined.Add(older.Fingerprint!))
                {
                    return look; // The same identity again: not a file before it.
                }

                (source, end) = (older, older.Stream.Length);
            }
        }

        /// <summary>
        /// Reads <c>[from, end)</c> of <paramref name="source"/>, or its last bytes within the
        /// budget, and records each stream not found yet whose last entry it holds. True when the
        /// whole span was read and every entry in it could be read.
        /// </summary>
        private bool LookBackIn(FileTailHandle source, long from, long end, ref long budget, LookBack look)
        {
            long span = end - from;
            int count = (int)Math.Min(span, Math.Max(0, budget));
            if (count <= 0)
            {
                return span <= 0;
            }

            byte[] bytes = new byte[count];
            FileStream stream = source.Stream;
            stream.Seek(end - count, SeekOrigin.Begin);
            int filled = stream.ReadAtLeast(bytes, count, throwOnEndOfStream: false);
            budget -= filled;
            lookedBack += filled;
            bool whole = filled == count && count == span;
            int position = 0;
            if (count < span)
            {
                // The window starts inside an entry.
                position = bytes.AsSpan(0, filled).IndexOf((byte)'\n') + 1;
                if (position == 0)
                {
                    return false;
                }
            }

            // An entry that cannot be read may belong to any stream: only what follows it counts.
            (DockerPendingLine? Open, bool Seen)[] last = new (DockerPendingLine?, bool)[2];
            int newline;
            while ((newline = bytes.AsSpan(position, filled - position).IndexOf((byte)'\n')) >= 0)
            {
                ReadOnlyMemory<byte> entry = bytes.AsMemory(position, newline);
                position += newline + 1;
                if (entry.Length <= MaximumEntryBytes && TryParseEntry(entry, out Entry parsed))
                {
                    last[Slot(parsed.Stream)] = (parsed.Log.EndsWith('\n') ? null : new DockerPendingLine(parsed.Stream, parsed.Time, Fragment: true), true);
                }
                else
                {
                    (last, whole) = (new (DockerPendingLine?, bool)[2], false);
                }
            }

            if (position < filled)
            {
                (last, whole) = (new (DockerPendingLine?, bool)[2], false); // A torn last entry.
            }

            for (int slot = 0; slot < 2; slot++)
            {
                if (!look.Found[slot] && last[slot].Seen)
                {
                    (look.Found[slot], look.Open[slot]) = (true, last[slot].Open);
                }
            }

            return whole;
        }
    }

    /// <summary>What a look back proved about each stream at the read's start.</summary>
    private sealed class LookBack
    {
        /// <summary>The stream's last entry was read; <see cref="Open"/> is its line when that entry leaves it open.</summary>
        public bool[] Found { get; } = new bool[2];

        public DockerPendingLine?[] Open { get; } = new DockerPendingLine?[2];

        /// <summary>It reached the read's own last position in an older file.</summary>
        public bool AtInput { get; set; }

        /// <summary>It reached the start of the oldest rotated file there is.</summary>
        public bool AtOldest { get; set; }
    }

    // Mapped by name; Docker's JSON and schema version stay DockerLogCursor's own (see Docker()).
    private static FileTailCursor Shared(DockerLogCursor cursor) =>
        new(cursor.SchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>Docker's own schema version, independent of the file tail cursor's.</summary>
    internal static DockerLogCursor Docker(FileTailCursor cursor) =>
        new(DockerLogCursor.CurrentSchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>A logical line open during a scan: being assembled, skipped, or known only by its key.</summary>
    private sealed class OpenLine(string stream, string? time)
    {
        private string? digest;

        // A head read once and committed before (see DockerPendingLine): where it is and what its
        // first characters give, checked when it is read again.
        private (long Start, int Length, string Digest)? expected;

        public string Stream { get; } = stream;

        public string? Time { get; private set; } = time;

        /// <summary>A stream not proven clean: its next entry keys the line, whatever its time.</summary>
        public bool Unproven { get; private set; }

        /// <summary>
        /// An entry that could not be read came while it was open: if another time ends it, that
        /// entry may have been the head of the line the time starts, which is then a fragment.
        /// </summary>
        public bool UnprovenNext { get; set; }

        public bool Discarding { get; private set; }

        /// <summary>Part of it could not be read: what is assembled is a fragment.</summary>
        public bool Fragment { get; set; }

        /// <summary>Bower had read part of it and cannot read that again: counted if nothing more of it is read.</summary>
        public bool Lost { get; set; }

        /// <summary>The file holding its first chunk.</summary>
        public string? File { get; set; }

        /// <summary>Its first chunk; -1 before one is read (its head is next, or lost when a fragment).</summary>
        public long Start { get; private set; } = -1;

        /// <summary>Its later chunks in <see cref="File"/>.</summary>
        public List<long> Chunks { get; } = [];

        /// <summary>Its chunks in the files rotated between <see cref="File"/> and the scanned one, oldest first.</summary>
        public List<(string File, List<long> Chunks)> Through { get; } = [];

        /// <summary>Its chunks in the scanned file, when <see cref="File"/> is a rotated one.</summary>
        public List<long> Rest { get; } = [];

        public long End { get; set; }

        /// <summary>Where this read met its head, if it did.</summary>
        public long Origin { get; set; } = -1;

        public DateTimeOffset? ParsedTime { get; set; }

        public StringBuilder Text { get; } = new();

        public DockerLogCursor? Resume { get; set; }

        public bool Assembling => !Discarding && Start >= 0;

        public int ChunkCount => Start < 0 ? 0 : 1 + Chunks.Count + Rest.Count + Through.Sum(run => run.Chunks.Count);

        /// <summary>Where its head read once and committed before should be met again.</summary>
        public long? ExpectedStart => expected?.Start;

        public (long Start, int Length, string Digest)? Expected => expected;

        public bool Matches(string? time) => string.Equals(Time, time, StringComparison.Ordinal);

        public void MarkUnproven() => (Unproven, Fragment) = (true, true);

        /// <summary>The first entry of an unproven stream keys its line.</summary>
        public void Adopt(string? time) => (Time, Unproven) = (time, false);

        public void Expect(long start, int length, string text) => expected = (start, length, text);

        /// <summary>
        /// Appends a chunk read at <paramref name="offset"/> in the file <paramref name="source"/>
        /// names; <paramref name="scanned"/> is the scanned file's. False when it is the head read
        /// once before and it no longer matches.
        /// </summary>
        public bool Append(string log, long offset, string source, string scanned)
        {
            bool head = Start < 0;
            if (head)
            {
                Start = offset;
            }
            else if (string.Equals(source, File, StringComparison.Ordinal))
            {
                Chunks.Add(offset);
            }
            else if (string.Equals(source, scanned, StringComparison.Ordinal))
            {
                Rest.Add(offset);
            }
            else if (Through.Count > 0 && string.Equals(Through[^1].File, source, StringComparison.Ordinal))
            {
                Through[^1].Chunks.Add(offset);
            }
            else
            {
                Through.Add((source, [offset]));
            }

            Text.Append(log);
            digest = null;
            if (expected is not { } at)
            {
                return true;
            }

            if (head && offset != at.Start)
            {
                return Mismatch();
            }

            if (Text.Length < at.Length)
            {
                return true;
            }

            bool same = Text.Length == at.Length && string.Equals(Digest(), at.Digest, StringComparison.Ordinal);
            expected = null;
            return same || Mismatch();
        }

        /// <summary>At its end: false when a head read once before was not all read again.</summary>
        public bool Verify() => expected is null || Mismatch();

        /// <summary>Its head read once before is not where it was: only a fragment of it can follow.</summary>
        public bool Mismatch()
        {
            (expected, Fragment, Lost) = (null, true, Lost || Start < 0);
            return false;
        }

        public void Skip()
        {
            Discarding = true;
            expected = null;
            Clear();
        }

        /// <summary>Its head cannot be read: only the rest of it, a fragment, can follow.</summary>
        public void Lose()
        {
            Clear();
            (Fragment, Lost, File, Start, Origin, ParsedTime, expected) = (true, true, null, -1, -1, null, null);
        }

        public string Digest() => digest ??= DockerPendingLine.DigestOf(Text.ToString());

        private void Clear()
        {
            Text.Clear();
            Chunks.Clear();
            Through.Clear();
            Rest.Clear();
            digest = null;
        }
    }

    /// <summary>One scan of one generation from a cursor, within the record and byte bounds.</summary>
    private sealed class LineScan(FileTailHandle file, DockerLogCursor cursor, DockerLogReaderOptions options, Generations generations, long spent)
    {
        private readonly List<DockerLogRecord> records = [];
        private readonly OpenLine?[] lines = new OpenLine?[2];
        private int malformed;
        private int oversized;
        private int lost;
        private long consumed = spent;

        // A head read once before no longer matches (counted as a gap, as a changed saved chunk is).
        private bool changed;

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

            // The look back and reading the open lines again count against the byte budget, but
            // every read still takes at least one entry, so it always moves on.
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
                    Passed(entryStart, -1);
                    continue;
                }

                Add(parsed, entryStart, position);
            }

            // A file that is never written again (a drained .1) ends here: every line still open
            // goes into the cursor, which moves to the new file, so it is re-read from the rotated
            // files and joined with its rest there. Otherwise, a read that would commit where it
            // began after a whole byte budget would read the same bytes every poll. A line that
            // began there, open alone, can never be read within bounds: skip it. With another
            // stream's line open too, record both lines' chunks instead: the next read takes them
            // again within its budget, and skips one that does not fit (RestorePending).
            bool ended = final && position >= stream.Length;
            bool pinned = !ended && quiet && safe is not null && lines.Any(line => line is { Assembling: true })
                && lines.All(line => line is not { Assembling: true } || string.Equals(line.File, cursor.Fingerprint, StringComparison.Ordinal));
            if (pinned && safe!.Offset == cursor.Offset && position - cursor.Offset >= options.MaximumBytesPerBatch)
            {
                if (lines.Count(line => line is { Assembling: true }) == 1)
                {
                    foreach (OpenLine? line in lines)
                    {
                        if (line is { Assembling: true } && line.Origin == cursor.Offset)
                        {
                            line.Skip();
                        }
                    }
                }

                pinned = false;
            }

            DockerLogCursor committed = pinned ? Pin(safe!) : Snapshot(position);
            return new DockerLogBatch(records, committed, malformed, oversized, rotationGap || changed, Lost: lost) { BytesRead = consumed };
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
            Passed(entryStart, slot);
            OpenLine? line = lines[slot];
            if (line is { Unproven: true })
            {
                line.Adopt(entry.Time);
            }

            if (line is not null && !line.Matches(entry.Time))
            {
                // The same stream with another time: that line ended at stream end, unterminated.
                // After an entry that could not be read while it was open, this one may be the
                // rest of a line whose head was that entry.
                bool unproven = line.UnprovenNext;
                Close(slot);
                line = unproven ? lines[slot] = new OpenLine(entry.Stream, entry.Time) { Fragment = true } : null;
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
                    changed |= !line.Append(entry.Log, entryStart, cursor.Fingerprint, cursor.Fingerprint);
                }
            }

            line.End = position;
            if (entry.Log.EndsWith('\n'))
            {
                Close(slot);
            }
        }

        /// <summary>
        /// A head read once before that this entry passes without being it (any line's when
        /// <paramref name="slot"/> is -1, another line's at its very offset) is not where it was:
        /// the line is lost.
        /// </summary>
        private void Passed(long entryStart, int slot)
        {
            for (int index = 0; index < 2; index++)
            {
                if (lines[index] is { Start: < 0, ExpectedStart: { } at } line && (entryStart > at || (entryStart == at && index != slot)))
                {
                    line.Mismatch();
                    changed = true;
                }
            }
        }

        /// <summary>
        /// An entry that cannot be read may belong to either stream: a chunk of a line being
        /// assembled (none is whole now), or the head of a stream's next line. So a stream with
        /// no line open is not proven clean, and an open line's stream is not either once
        /// another time ends that line.
        /// </summary>
        private void Unreadable()
        {
            for (int slot = 0; slot < 2; slot++)
            {
                if (lines[slot] is not { } line)
                {
                    lines[slot] = new OpenLine(slot == 0 ? "stdout" : "stderr", null);
                    lines[slot]!.MarkUnproven();
                }
                else if (!line.Unproven)
                {
                    line.Fragment |= line.Assembling;
                    line.UnprovenNext = true;
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
                changed |= !line.Verify();
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

            else if (line.Lost)
            {
                lost++; // Bower read part of it, and nothing of its rest arrived.
            }

            // Otherwise known by its key only, and nothing of it arrived: nothing to emit.
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
                DockerPendingLine saved = (line switch
                {
                    { Discarding: true } => new DockerPendingLine(line.Stream, line.Time, Discarding: true),
                    { Unproven: true } => DockerPendingLine.UnprovenStream(line.Stream),
                    { Start: < 0, Expected: { } at } when offset <= at.Start => new DockerPendingLine(
                        line.Stream, line.Time, File: cursor.Fingerprint, Start: at.Start, Length: at.Length, Fragment: line.Fragment, Digest: at.Digest),
                    { Start: < 0, Expected: null } => new DockerPendingLine(line.Stream, line.Time, Fragment: true, Lost: line.Lost),
                    { Start: < 0 } => new DockerPendingLine(line.Stream, line.Time, Fragment: true, Lost: true),
                    _ => new DockerPendingLine(
                        line.Stream,
                        line.Time,
                        File: line.File,
                        Start: line.Start,
                        Length: line.Text.Length,
                        Fragment: line.Fragment,
                        Chunks: line.Chunks.Count > 0 ? [.. line.Chunks] : null,
                        Rest: line.Rest.Count > 0 ? [.. line.Rest] : null,
                        Digest: line.Digest(),
                        Through: line.Through.Count > 0 ? [.. line.Through.Select(run => new DockerChunkRun(run.File, [.. run.Chunks]))] : null)
                }).WithUnprovenNext(line.UnprovenNext);
                pending.Add(saved);
                discarding |= saved.Discarding;
            }

            return cursor with { Offset = offset, Discarding = discarding, Pending = pending };
        }

        /// <summary>
        /// The pinned point, naming each line assembled since by its head, length and digest, so
        /// the next read checks that head when it meets it again, and a gap or a lost <c>.1</c>
        /// before then still knows that its rest is a fragment.
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
                    pending[slot] = new DockerPendingLine(
                        line.Stream, line.Time, File: line.File, Start: line.Start, Length: line.Text.Length, Fragment: line.Fragment, Digest: line.Digest());
                }
            }

            return at with { Pending = [.. pending.OfType<DockerPendingLine>()] };
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

            bool gap = false;
            foreach (DockerPendingLine saved in pending)
            {
                OpenLine line = new(saved.Stream, saved.Time)
                {
                    Fragment = saved.Fragment,
                    Lost = saved.Lost,
                    UnprovenNext = saved is { Unproven: true, Time: not null },
                    Resume = cursor
                };
                lines[Slot(saved.Stream)] = line;
                if (saved.Discarding)
                {
                    line.Skip();
                }
                else if (saved is { Unproven: true, Time: null })
                {
                    line.MarkUnproven();
                }
                else if (saved is { Start: { } start, Length: { } length, Digest: { } digest }
                    && start >= cursor.Offset
                    && string.Equals(saved.File, cursor.Fingerprint, StringComparison.Ordinal))
                {
                    line.Expect(start, length, digest);
                }
                else if (saved.Digest is not null)
                {
                    switch (RestoreChunks(line, saved))
                    {
                        case Reread.Changed:
                            // Its files rotated away or no longer hold it: the rest is only a fragment.
                            gap = true;
                            line.Lose();
                            break;
                        case Reread.OverBudget:
                            // Not within what is left of the byte budget, so never joined within
                            // one: skipped as oversized, its key kept, so its rest is never a line.
                            line.Skip();
                            break;
                    }
                }

                // Otherwise known by its key only: the rest of a lost head.
            }

            return gap;
        }

        private enum Reread
        {
            Matched,
            Changed,
            OverBudget
        }

        /// <summary>
        /// Reads an open line's saved chunks again, each from the file its identity names (this
        /// one or any rotated one): at most <see cref="DockerLogCursor.MaximumChunks"/> entries, so
        /// the cost is the line's own size, never the span to the cursor, and never more than is
        /// left of the byte budget (with the identities of rotated files after <c>.1</c>). They
        /// must give the saved length and digest.
        /// </summary>
        private Reread RestoreChunks(OpenLine line, DockerPendingLine saved)
        {
            line.File = saved.File;
            List<(string File, IReadOnlyList<long> Chunks)> runs = [(saved.File!, [saved.Start!.Value, .. saved.Chunks ?? []])];
            runs.AddRange((saved.Through ?? []).Select(run => (run.File, run.Chunks)));
            runs.Add((cursor.Fingerprint, saved.Rest ?? []));
            foreach ((string fingerprint, IReadOnlyList<long> chunks) in runs)
            {
                if (chunks.Count == 0)
                {
                    continue;
                }

                FileTailHandle? source = file;
                bool outOfBudget = false;
                if (!string.Equals(fingerprint, cursor.Fingerprint, StringComparison.Ordinal))
                {
                    long identified = generations.IdentityBytes;
                    source = generations.Find(fingerprint, file, options.MaximumBytesPerBatch - consumed, out outOfBudget);
                    consumed += generations.IdentityBytes - identified;
                }

                if (source is null)
                {
                    return outOfBudget ? Reread.OverBudget : Reread.Changed;
                }

                long limit = ReferenceEquals(source, file) ? cursor.Offset : long.MaxValue;
                foreach (long offset in chunks)
                {
                    Reread chunk = ReadChunk(source, offset, limit, line, fingerprint);
                    if (chunk != Reread.Matched)
                    {
                        return chunk;
                    }
                }
            }

            return line.Text.Length == saved.Length && string.Equals(line.Digest(), saved.Digest, StringComparison.Ordinal) ? Reread.Matched : Reread.Changed;
        }

        /// <summary>
        /// One saved chunk: a whole, unterminated entry of the line's key that ends by
        /// <paramref name="limit"/>, read only within what is left of the byte budget.
        /// </summary>
        private Reread ReadChunk(FileTailHandle source, long offset, long limit, OpenLine line, string fingerprint)
        {
            FileStream stream = source.Stream;
            stream.Seek(offset, SeekOrigin.Begin);
            long left = options.MaximumBytesPerBatch - consumed;
            if (left <= 0)
            {
                return Reread.OverBudget;
            }

            byte[]? entry = ReadEntry(stream, consumeLong: false, out bool complete, out bool tooLong, left);
            consumed += stream.Position - offset;
            if (!complete && stream.Position - offset == left)
            {
                return Reread.OverBudget;
            }

            if (!complete || tooLong || entry is null || stream.Position > limit
                || !TryParseEntry(entry, out Entry parsed)
                || parsed.Stream != line.Stream
                || !line.Matches(parsed.Time)
                || parsed.Log.EndsWith('\n')
                || line.Text.Length + parsed.Log.Length > options.MaximumLineBytes)
            {
                return Reread.Changed; // Not the open line the cursor recorded.
            }

            line.ParsedTime ??= parsed.ParsedTime;
            line.Append(parsed.Log, offset, fingerprint, cursor.Fingerprint);
            line.End = stream.Position;
            return Reread.Matched;
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
    /// Reads bytes up to and including '\n', at most <paramref name="within"/>. Incomplete means
    /// no newline before EOF or within them. An entry over <see cref="MaximumEntryBytes"/> is too
    /// long: read to its newline when <paramref name="consumeLong"/>, so the scan can pass it,
    /// else left at once.
    /// </summary>
    private static byte[]? ReadEntry(FileStream stream, bool consumeLong, out bool complete, out bool tooLong, long within = long.MaxValue)
    {
        using MemoryStream buffer = new();
        tooLong = false;
        int value;
        for (long read = 0; read < within && (value = stream.ReadByte()) >= 0; read++)
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
