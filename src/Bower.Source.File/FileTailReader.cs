using System.Security.Cryptography;
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
/// trailing carriage return. An oversized line carries no bytes and <see cref="Oversized"/>.
/// </summary>
public sealed record FileTailLine(
    byte[] Bytes,
    string Fingerprint,
    long StartOffset,
    long EndOffset,
    bool Oversized = false);

/// <param name="Cursor">Position after every line in <paramref name="Lines"/>.</param>
/// <param name="Rotated">A rotated file (<c>path.1</c>) was drained and the cursor moved to the current file.</param>
/// <param name="Gap">Lines may have been lost: rotated more than once between reads, or truncated in place.</param>
/// <param name="More">A limit stopped the read, or the cursor moved files: read again without waiting.</param>
public sealed record FileTailBatch(
    IReadOnlyList<FileTailLine> Lines,
    FileTailCursor Cursor,
    bool Rotated,
    bool Gap,
    bool More);

public sealed record FileTailReaderOptions
{
    public int MaxLineBytes { get; init; } = FileTailSourceConfigurationLoader.DefaultMaxLineBytes;

    public int MaxLinesPerBatch { get; init; } = 256;

    public int MaxBytesPerBatch { get; init; } = 1_048_576;

    /// <summary>When a file is first seen, start after its last complete line instead of replaying it.</summary>
    public bool StartAtEnd { get; init; } = true;
}

/// <summary>
/// Bounded, read-only tail of one plain-text file with rename and copytruncate rotation.
/// Generalised from the Docker json-file reader: only complete lines are consumed (a line
/// still being written is left for the next read, except at the end of a rotated file, which
/// no longer grows), an oversized line is skipped without being buffered, and each read is
/// bounded by a line count and a byte budget.
/// </summary>
public static class FileTailReader
{
    public const int FingerprintBytes = 64;

    /// <param name="path">The current file (already checked by <see cref="FileTailPaths"/>), or null when it is missing.</param>
    /// <param name="rotatedPath">The rotated file to drain (<c>path.1</c>), or null when it cannot be read.</param>
    public static FileTailBatch Read(string? path, string? rotatedPath, FileTailCursor? cursor, FileTailReaderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        string? currentFingerprint = path is null ? null : Fingerprint(path);

        if (cursor is null)
        {
            if (currentFingerprint is null)
            {
                return Empty(new FileTailCursor(FileTailCursor.CurrentSchemaVersion, string.Empty, 0));
            }

            FileTailCursor initial = new(FileTailCursor.CurrentSchemaVersion, currentFingerprint,
                options.StartAtEnd ? LastCompleteLineEnd(path!) : 0);
            return options.StartAtEnd ? Empty(initial) : ReadFile(path!, initial, options, eofEndsLine: false, gap: false);
        }

        if (cursor.Fingerprint.Length == 0)
        {
            // Provisional cursor: the file was missing or too short to identify.
            return currentFingerprint is null
                ? Empty(cursor)
                : ReadFile(path!, cursor with { Fingerprint = currentFingerprint, Offset = 0, Discarding = false },
                    options, eofEndsLine: false, gap: false);
        }

        if (string.Equals(cursor.Fingerprint, currentFingerprint, StringComparison.Ordinal))
        {
            if (new FileInfo(path!).Length < cursor.Offset)
            {
                // Truncated in place without a matching copy: restart and flag the gap.
                return ReadFile(path!, cursor with { Offset = 0, Discarding = false }, options, eofEndsLine: false, gap: true);
            }

            return ReadFile(path!, cursor, options, eofEndsLine: false, gap: false);
        }

        // The current file is another file. Drain the rotated file first if it is ours
        // (rename rotation, or the copy copytruncate made).
        if (rotatedPath is not null
            && string.Equals(Fingerprint(rotatedPath), cursor.Fingerprint, StringComparison.Ordinal))
        {
            FileTailBatch rotated = ReadFile(rotatedPath, cursor, options, eofEndsLine: true, gap: false);
            bool drained = rotated.Cursor.Offset >= new FileInfo(rotatedPath).Length && !rotated.More;
            return drained
                ? rotated with
                {
                    Cursor = new FileTailCursor(FileTailCursor.CurrentSchemaVersion, currentFingerprint ?? string.Empty, 0),
                    Rotated = true,
                    More = true
                }
                : rotated;
        }

        if (currentFingerprint is null)
        {
            // Missing or too short to identify, and not rotated to path.1: wait until it can be.
            return Empty(cursor);
        }

        // Rotated more than once since the last read, or replaced: lines were lost.
        return ReadFile(path!, new FileTailCursor(FileTailCursor.CurrentSchemaVersion, currentFingerprint, 0),
            options, eofEndsLine: false, gap: true);
    }

    /// <summary>
    /// SHA-256 of the first 64 bytes, or null when the file is missing or shorter. A shorter
    /// file is never opened, which also keeps FIFOs and devices (reported as empty) unopened.
    /// </summary>
    public static string? Fingerprint(string path)
    {
        try
        {
            FileInfo info = new(path);
            if (!info.Exists || info.Length < FingerprintBytes)
            {
                return null;
            }

            using FileStream stream = Open(path);
            byte[] prefix = new byte[FingerprintBytes];
            stream.ReadExactly(prefix);
            return Convert.ToHexStringLower(SHA256.HashData(prefix));
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException or EndOfStreamException)
        {
            return null;
        }
    }

    private static FileTailBatch ReadFile(
        string path,
        FileTailCursor cursor,
        FileTailReaderOptions options,
        bool eofEndsLine,
        bool gap)
    {
        List<FileTailLine> lines = [];
        long committed = cursor.Offset;
        bool discarding = cursor.Discarding;
        bool more = false;

        using FileStream stream = Open(path);
        // A snapshot of the length bounds this read; bytes appended meanwhile wait for the next.
        long length = stream.Length;
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
                    ? new FileTailLine([], cursor.Fingerprint, lineStart, position, Oversized: true)
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

    private static long LastCompleteLineEnd(string path)
    {
        using FileStream stream = Open(path);
        byte[] block = new byte[4_096];
        long end = stream.Length;
        while (end > 0)
        {
            int count = (int)Math.Min(block.Length, end);
            long start = end - count;
            stream.Seek(start, SeekOrigin.Begin);
            // A concurrent truncation can shorten the read; bytes past EOF are never '\n'.
            int read = stream.ReadAtLeast(block.AsSpan(0, count), count, throwOnEndOfStream: false);
            int newline = block.AsSpan(0, read).LastIndexOf((byte)'\n');
            if (newline >= 0)
            {
                return start + newline + 1;
            }

            end = start;
        }

        return 0;
    }

    private static FileStream Open(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4_096);

    private static FileTailBatch Empty(FileTailCursor cursor) => new([], cursor, false, false, false);
}
