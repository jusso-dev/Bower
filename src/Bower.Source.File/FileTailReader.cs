using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.File;

/// <summary>
/// Position in one tailed file. The fingerprint identifies the file by its first 64 bytes
/// (which never change once written), so rename rotation and copytruncate are detected even
/// though the file name stays the same. An empty fingerprint is provisional: the file did
/// not exist or was too short to identify, and is read from <paramref name="Offset"/> 0 once
/// it can be.
/// <para>
/// <paramref name="Discarding"/> (omitted when false) means <paramref name="Offset"/> lies
/// inside an oversized line: bytes up to and including its newline are skipped. The cursor
/// carries no line content.
/// </para>
/// </summary>
public sealed record FileTailCursor(
    int SchemaVersion,
    string Fingerprint,
    long Offset,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Discarding = false)
{
    public const int CurrentSchemaVersion = 1;

    public string Serialize() => JsonSerializer.Serialize(this, FileTailCursorJsonContext.Default.FileTailCursor);

    /// <summary>The cursor, or null when the stored value is not a cursor this version wrote.</summary>
    public static FileTailCursor? Deserialize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            FileTailCursor? cursor = JsonSerializer.Deserialize(value, FileTailCursorJsonContext.Default.FileTailCursor);
            return cursor is { SchemaVersion: CurrentSchemaVersion, Offset: >= 0, Fingerprint: not null }
                && (cursor.Fingerprint.Length == 0 || IsFingerprint(cursor.Fingerprint))
                ? cursor
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool IsFingerprint(string value) =>
        value.Length == 64 && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');
}

/// <summary>Cursor JSON: camelCase, otherwise default options (source generated).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(FileTailCursor))]
internal sealed partial class FileTailCursorJsonContext : JsonSerializerContext;

/// <summary>
/// One complete line, in file order. <see cref="Bytes"/> excludes the newline and one
/// trailing carriage return. An oversized line carries no bytes and <see cref="Oversized"/>;
/// <see cref="ContinuesDiscard"/> means it started inside a line already being skipped, so a
/// rewind to its start must keep skipping.
/// </summary>
public sealed record FileTailLine(
    byte[] Bytes,
    string Fingerprint,
    long StartOffset,
    long EndOffset,
    bool Oversized = false,
    bool ContinuesDiscard = false);

/// <param name="Cursor">Position after every line in <paramref name="Lines"/>.</param>
/// <param name="Rotated">A rotated file (<c>path.1</c>) was drained and the cursor moved to the current file.</param>
/// <param name="Gap">
/// Lines may have been lost: rotated more than once between reads, truncated in place, or
/// written to <c>path.1</c> after the cursor moved to the current file.
/// </param>
/// <param name="More">A limit stopped the read, or the cursor moved files: read again without waiting.</param>
/// <param name="RotatedPath">The rotated file this read opened, so the caller can re-check it; null when none.</param>
public sealed record FileTailBatch(
    IReadOnlyList<FileTailLine> Lines,
    FileTailCursor Cursor,
    bool Rotated,
    bool Gap,
    bool More,
    string? RotatedPath = null);

public sealed record FileTailReaderOptions
{
    public int MaxLineBytes { get; init; } = FileTailSourceConfigurationLoader.DefaultMaxLineBytes;

    public int MaxLinesPerBatch { get; init; } = 256;

    public int MaxBytesPerBatch { get; init; } = 1_048_576;

    /// <summary>When a file is first seen, start after its last complete line instead of replaying it.</summary>
    public bool StartAtEnd { get; init; } = true;

    /// <summary>Polls <c>path.1</c> must stay unchanged (size and write time) before the cursor leaves it.</summary>
    public int RotationGracePolls { get; init; } = FileTailSourceConfigurationLoader.DefaultRotationGracePolls;
}

/// <summary>
/// What a reader remembers between polls of one input, in memory only (a restart starts
/// the grace window again and forgets the abandoned generation).
/// </summary>
public sealed class FileTailRotationState
{
    internal (long Length, DateTime WriteTime)? Observed { get; set; }

    internal int StablePolls { get; set; }

    /// <summary>The generation the cursor left, and its length then: later growth is a gap.</summary>
    internal (string Fingerprint, long Length)? Abandoned { get; set; }
}

/// <summary>
/// Bounded, read-only tail of one plain-text file with rename and copytruncate rotation.
/// Generalised from the Docker json-file reader: only complete lines are consumed, an
/// oversized line is skipped without being buffered, and each read is bounded by a line count
/// and a byte budget. Each file is opened once per read (<see cref="FileTailHandle"/>): its
/// identity and its lines come from the same handle.
/// <para>
/// A writer keeps writing to <c>path.1</c> until it reopens its file (rsyslog until HUP), so
/// the cursor leaves <c>path.1</c> only once the current file can be identified and
/// <c>path.1</c> stayed unchanged for <see cref="FileTailReaderOptions.RotationGracePolls"/>
/// polls; only then is its unterminated last line complete. Lines written to it afterwards
/// cannot be read and are reported as a gap.
/// </para>
/// </summary>
public static class FileTailReader
{
    /// <param name="path">The current file (already checked by <see cref="FileTailPaths"/>), or null when it is missing.</param>
    /// <param name="rotatedPath">The rotated file to drain (<c>path.1</c>, already checked), or null when it is missing.</param>
    /// <param name="state">Grace and abandoned-generation state for this input; null for a single read.</param>
    /// <exception cref="FileTailRefusedException">An opened handle is not the validated regular file.</exception>
    public static FileTailBatch Read(
        string? path,
        string? rotatedPath,
        FileTailCursor? cursor,
        FileTailReaderOptions options,
        FileTailRotationState? state = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        state ??= new FileTailRotationState();
        using FileTailHandle? current = FileTailHandle.Open(path);
        FileTailHandle? rotated = null;
        try
        {
            FileTailBatch batch = Plan();
            return batch with { Gap = batch.Gap || LateRotatedLines(), RotatedPath = rotated is null ? null : rotatedPath };
        }
        finally
        {
            rotated?.Dispose();
        }

        FileTailHandle? Rotated() => rotated ??= FileTailHandle.Open(rotatedPath);

        bool LateRotatedLines()
        {
            if (state.Abandoned is not { } abandoned)
            {
                return false;
            }

            FileTailHandle? file = Rotated();
            if (file is null || !string.Equals(file.Fingerprint, abandoned.Fingerprint, StringComparison.Ordinal))
            {
                state.Abandoned = null; // Rotated again or removed: nothing more can arrive.
                return false;
            }

            if (file.Length <= abandoned.Length)
            {
                return false;
            }

            state.Abandoned = abandoned with { Length = file.Length };
            return true;
        }

        FileTailBatch Plan()
        {
            string? fingerprint = current?.Fingerprint;
            if (cursor is null)
            {
                state.Observed = null;
                if (fingerprint is null)
                {
                    return Empty(new FileTailCursor(FileTailCursor.CurrentSchemaVersion, string.Empty, 0));
                }

                if (!options.StartAtEnd)
                {
                    return ReadFile(current!, new FileTailCursor(FileTailCursor.CurrentSchemaVersion, fingerprint, 0), options, eofEndsLine: false, gap: false);
                }

                (long offset, bool discarding) = StartPosition(current!, options.MaxBytesPerBatch, cancellationToken);
                return Empty(new FileTailCursor(FileTailCursor.CurrentSchemaVersion, fingerprint, offset, discarding));
            }

            if (cursor.Fingerprint.Length == 0)
            {
                // Provisional cursor: the file was missing or too short to identify.
                state.Observed = null;
                return fingerprint is null
                    ? Empty(cursor)
                    : ReadFile(current!, cursor with { Fingerprint = fingerprint, Offset = 0, Discarding = false }, options, eofEndsLine: false, gap: false);
            }

            if (string.Equals(cursor.Fingerprint, fingerprint, StringComparison.Ordinal))
            {
                if (current!.Length >= cursor.Offset)
                {
                    state.Observed = null;
                    return ReadFile(current, cursor, options, eofEndsLine: false, gap: false);
                }

                // Shorter than the cursor with the same identity: copytruncate whose new first
                // line repeats the old one. Drain the copy in path.1 first when it is ours.
                if (Rotated() is { } copy
                    && string.Equals(copy.Fingerprint, cursor.Fingerprint, StringComparison.Ordinal)
                    && copy.Length >= cursor.Offset)
                {
                    return Drain(copy, fingerprint);
                }

                // Truncated in place without a matching copy: restart and flag the gap.
                state.Observed = null;
                return ReadFile(current, cursor with { Offset = 0, Discarding = false }, options, eofEndsLine: false, gap: true);
            }

            // The current file is another file. Drain the rotated file first if it is ours
            // (rename rotation, or the copy copytruncate made).
            if (Rotated() is { } previous && string.Equals(previous.Fingerprint, cursor.Fingerprint, StringComparison.Ordinal))
            {
                return Drain(previous, fingerprint);
            }

            state.Observed = null;
            // Missing or too short to identify, and not rotated: wait until it can be.
            // Otherwise rotated more than once since the last read, or replaced: lines were lost.
            return fingerprint is null
                ? Empty(cursor)
                : ReadFile(current!, new FileTailCursor(FileTailCursor.CurrentSchemaVersion, fingerprint, 0), options, eofEndsLine: false, gap: true);
        }

        FileTailBatch Drain(FileTailHandle file, string? currentFingerprint)
        {
            (long, DateTime) observed = (file.Length, file.WriteTime);
            if (state.Observed == observed)
            {
                state.StablePolls = Math.Min(state.StablePolls + 1, FileTailSourceConfigurationLoader.MaximumRotationGracePolls);
            }
            else
            {
                state.Observed = observed;
                state.StablePolls = 0;
            }

            // Leave path.1 only once the current file is identified and path.1 has settled;
            // until then a writer may still add to it, and its last line may still grow.
            bool leave = currentFingerprint is not null && state.StablePolls >= options.RotationGracePolls;
            FileTailBatch batch = ReadFile(file, cursor!, options, eofEndsLine: leave, gap: false);
            if (!leave || batch.More || batch.Cursor.Offset < file.Length)
            {
                return batch;
            }

            state.Observed = null;
            state.Abandoned = (cursor!.Fingerprint, file.Length);
            return batch with
            {
                Cursor = new FileTailCursor(FileTailCursor.CurrentSchemaVersion, currentFingerprint!, 0),
                Rotated = true,
                More = true
            };
        }
    }

    /// <summary>The identity of the file at <paramref name="path"/> (null when it has none yet).</summary>
    public static string? Fingerprint(string path) => FileTailHandle.FingerprintOf(path);

    private static FileTailBatch ReadFile(
        FileTailHandle file,
        FileTailCursor cursor,
        FileTailReaderOptions options,
        bool eofEndsLine,
        bool gap)
    {
        List<FileTailLine> lines = [];
        long committed = cursor.Offset;
        bool discarding = cursor.Discarding;
        bool more = false;

        FileStream stream = file.Stream;
        // The length when opened bounds this read; bytes appended meanwhile wait for the next.
        long length = file.Length;
        if (cursor.Offset > length)
        {
            return Empty(cursor);
        }

        stream.Seek(cursor.Offset, SeekOrigin.Begin);
        long budgetEnd = Math.Min(length, cursor.Offset + options.MaxBytesPerBatch);
        byte[] buffer = new byte[options.MaxLineBytes];
        byte[] chunk = new byte[65_536];
        int chunkLength = 0;
        int chunkIndex = 0;
        long position = cursor.Offset;

        while (position < budgetEnd)
        {
            if (lines.Count >= options.MaxLinesPerBatch)
            {
                more = true;
                break;
            }

            long lineStart = position;
            bool continuesDiscard = discarding;
            // A line may run up to its own limit past the byte budget, never past the snapshot.
            long limit = Math.Min(length, Math.Max(budgetEnd, lineStart + options.MaxLineBytes + 1));
            int count = 0;
            bool oversized = discarding;
            bool terminated = false;
            while (position < limit)
            {
                if (chunkIndex == chunkLength)
                {
                    chunkLength = stream.Read(chunk, 0, (int)Math.Min(chunk.Length, limit - position));
                    chunkIndex = 0;
                    if (chunkLength == 0)
                    {
                        break; // Shortened underneath us: treat as the end of the snapshot.
                    }
                }

                byte value = chunk[chunkIndex++];
                position++;
                if (value == (byte)'\n')
                {
                    terminated = true;
                    break;
                }

                if (!oversized)
                {
                    if (count == buffer.Length)
                    {
                        oversized = true;
                    }
                    else
                    {
                        buffer[count++] = value;
                    }
                }
            }

            bool atEnd = position >= length;
            if (terminated || (eofEndsLine && atEnd && (oversized || count > 0)))
            {
                lines.Add(oversized
                    ? new FileTailLine([], cursor.Fingerprint, lineStart, position, Oversized: true, ContinuesDiscard: continuesDiscard)
                    : new FileTailLine(TrimCarriageReturn(buffer, count), cursor.Fingerprint, lineStart, position));
                committed = position;
                discarding = false;
                continue;
            }

            if (oversized)
            {
                // Consume what was scanned so a huge line never pins the cursor across reads.
                committed = position;
                discarding = true;
                more = !atEnd;
            }

            // Otherwise the line is still being written: leave it for the next read.
            break;
        }

        if (!more && committed < length && position >= budgetEnd && budgetEnd < length)
        {
            more = true;
        }

        return new FileTailBatch(lines, cursor with { Offset = committed, Discarding = discarding }, false, gap, more);
    }

    private static byte[] TrimCarriageReturn(byte[] buffer, int count) =>
        buffer.AsSpan(0, count > 0 && buffer[count - 1] == (byte)'\r' ? count - 1 : count).ToArray();

    /// <summary>
    /// After the last complete line, scanning back at most <paramref name="budget"/> bytes.
    /// Without a newline in that window the read starts at the end, skipping the rest of the
    /// line being written; a file with no newline at all starts at 0.
    /// </summary>
    private static (long Offset, bool Discarding) StartPosition(FileTailHandle file, long budget, CancellationToken cancellationToken)
    {
        byte[] block = new byte[4_096];
        long end = file.Length;
        long floor = Math.Max(0, file.Length - budget);
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

        return floor > 0 ? (file.Length, true) : (0, false);
    }

    private static FileTailBatch Empty(FileTailCursor cursor) => new([], cursor, false, false, false);
}
