using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.File;

/// <summary>
/// Position in one tailed file, and the rotation state that must survive a restart. The
/// fingerprint identifies the file by its first complete line (64–4096 bytes, which never
/// change once written), so rename rotation and copytruncate are detected even though the
/// file name stays the same. An empty fingerprint is provisional: the file did not exist or
/// could not be identified yet, and is read from <paramref name="Offset"/> 0 once it can be.
/// <para>
/// <paramref name="Discarding"/> means <paramref name="Offset"/> lies inside an oversized
/// line: bytes up to and including its newline are skipped. <paramref name="FileId"/> is the
/// file's <c>device:inode</c> where the platform reports it (Linux; every Unix in Rust).
/// <paramref name="Drain"/> (<c>rename</c> or <c>copytruncate</c>) means the cursor refers to
/// <c>path.1</c>, which is drained before the current file is read again; for a rename,
/// <paramref name="ObservedLength"/>, <paramref name="ObservedWriteTime"/> (100 ns ticks since
/// the Unix epoch) and <paramref name="StablePolls"/> track the grace window.
/// <paramref name="DrainLength"/> is <c>path.1</c>'s length when the drain began and
/// <paramref name="DrainPolls"/> the polls counted towards the drain cap: only polls that reach
/// the end of <c>path.1</c> or get past that length count, so a backlog is always read in full.
/// <paramref name="Abandoned"/> and <paramref name="AbandonedLength"/> are the generation the
/// cursor left: later growth of that <c>path.1</c> is a gap while it can still be observed.
/// Optional fields are omitted when unset. The cursor carries no line content.
/// </para>
/// </summary>
public sealed record FileTailCursor(
    int SchemaVersion,
    string Fingerprint,
    long Offset,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Discarding = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? FileId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Drain = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? ObservedLength = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? ObservedWriteTime = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? StablePolls = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? DrainPolls = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? DrainLength = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Abandoned = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? AbandonedLength = null)
{
    /// <summary>
    /// 2 since the rotation fields. A stored cursor of any other version (the pre-release
    /// version 1 lacked them) is never interpreted: <see cref="IsOtherSchema"/> lets the source
    /// replay the current file from its start instead (at least once, with a counted gap).
    /// </summary>
    public const int CurrentSchemaVersion = 2;
    public const string RenameDrain = "rename";
    public const string CopyDrain = "copytruncate";

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
            return cursor is { SchemaVersion: CurrentSchemaVersion, Offset: >= 0, Fingerprint: not null } && IsValid(cursor)
                ? cursor
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// A JSON object with an integer <c>schemaVersion</c> other than <see cref="CurrentSchemaVersion"/>:
    /// a cursor from another (older or newer) build, whose meaning this version must not guess.
    /// </summary>
    public static bool IsOtherSchema(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(value);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("schemaVersion", out JsonElement version)
                && version.ValueKind == JsonValueKind.Number
                && version.TryGetInt32(out int number)
                && number != CurrentSchemaVersion;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsValid(FileTailCursor cursor) =>
        (cursor.Fingerprint.Length == 0 || IsFingerprint(cursor.Fingerprint))
        && (cursor.FileId is null || IsFileId(cursor.FileId))
        && (cursor.Drain is null || (cursor.Fingerprint.Length > 0 && cursor.Drain is RenameDrain or CopyDrain))
        && (cursor.ObservedLength is null) == (cursor.ObservedWriteTime is null)
        && (cursor.ObservedLength is null) == (cursor.StablePolls is null)
        && cursor.ObservedLength is null or >= 0
        && cursor.StablePolls is null or >= 0
        && (cursor.ObservedLength is null || cursor.Drain == RenameDrain)
        && (cursor.DrainPolls is null || (cursor.Drain is not null && cursor.DrainPolls >= 0))
        && (cursor.DrainLength is null || (cursor.Drain is not null && cursor.DrainLength >= 0))
        && (cursor.Abandoned is null) == (cursor.AbandonedLength is null)
        && (cursor.Abandoned is null || IsFingerprint(cursor.Abandoned))
        && cursor.AbandonedLength is null or >= 0;

    private static bool IsFingerprint(string value) =>
        value.Length == 64 && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');

    private static bool IsFileId(string value)
    {
        int colon = value.IndexOf(':', StringComparison.Ordinal);
        return colon > 0 && colon < value.Length - 1 && value.Length <= 41
            && value.AsSpan(0, colon).ContainsAnyExceptInRange('0', '9') is false
            && value.AsSpan(colon + 1).ContainsAnyExceptInRange('0', '9') is false;
    }
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
/// <param name="Rotated">The cursor moved from a drained <c>path.1</c> to the current file.</param>
/// <param name="Gap">
/// Lines may have been lost: rotated more than once between reads, truncated in place, the
/// generation being drained disappeared, or lines were written to <c>path.1</c> after the
/// cursor left it.
/// </param>
/// <param name="More">A limit stopped the read, or the cursor moved files: read again without waiting.</param>
/// <param name="RotatedPath">The rotated file this read opened, so the caller can re-check it; null when none.</param>
/// <param name="Origin">
/// The cursor the lines were read under: a rewind to a line's start is this cursor at that
/// offset, so it never carries a switch (or an abandoned generation) the batch did not commit.
/// </param>
public sealed record FileTailBatch(
    IReadOnlyList<FileTailLine> Lines,
    FileTailCursor Cursor,
    bool Rotated,
    bool Gap,
    bool More,
    string? RotatedPath = null,
    FileTailCursor? Origin = null)
{
    /// <summary>Back to a line's start; inside an oversized line, keep skipping it.</summary>
    public FileTailCursor RewindTo(FileTailLine line)
    {
        ArgumentNullException.ThrowIfNull(line);
        return (Origin ?? Cursor) with { Offset = line.StartOffset, Discarding = line.ContinuesDiscard };
    }
}

public sealed record FileTailReaderOptions
{
    public int MaxLineBytes { get; init; } = FileTailSourceConfigurationLoader.DefaultMaxLineBytes;

    public int MaxLinesPerBatch { get; init; } = 256;

    public int MaxBytesPerBatch { get; init; } = 1_048_576;

    /// <summary>When a file is first seen, start after its last complete line instead of replaying it.</summary>
    public bool StartAtEnd { get; init; } = true;

    /// <summary>
    /// Unchanged end-of-file polls of a renamed <c>path.1</c> (size and write time) before the
    /// cursor moves to the new file. Copytruncate never waits.
    /// </summary>
    public int RotationGracePolls { get; init; } = FileTailSourceConfigurationLoader.DefaultRotationGracePolls;

    /// <summary>
    /// Polls a drain may take before the cursor moves to the new file anyway, so a
    /// <c>path.1</c> that keeps changing cannot starve the current file. Only polls that reach
    /// the end of <c>path.1</c> or get past its length when the drain began count, so a static
    /// backlog of any size is read in full. Unread lines left in it are counted as a gap, and
    /// later writes to it are too while it can still be observed.
    /// </summary>
    public int RotationDrainMaxPolls { get; init; } = FileTailSourceConfigurationLoader.DefaultRotationDrainMaxPolls;

    /// <summary>
    /// Use device and inode numbers where the platform reports them (Linux) to tell rename
    /// from copytruncate and to spot a replaced file. Off, identities alone decide (as on
    /// other platforms); the shared vectors run this way so both runtimes agree everywhere.
    /// </summary>
    public bool UseFileIds { get; init; } = true;
}

/// <summary>
/// Bounded, read-only tail of one plain-text file with rename and copytruncate rotation.
/// Only complete lines are consumed, an oversized line is skipped without being buffered,
/// and each read is bounded by a line count and a byte budget. Each file is opened once per
/// read (<see cref="FileTailHandle"/>): its identity and its lines come from the same handle.
/// <para>
/// Rotation state lives in the cursor, so it survives a restart. Once a rotation is detected
/// the cursor refers to <c>path.1</c> (<see cref="FileTailCursor.Drain"/>) and the current
/// file is not read until <c>path.1</c> is drained:
/// </para>
/// <list type="bullet">
/// <item>Copytruncate (the current file is the original, truncated; <c>path.1</c> is a static
/// copy): the copy is drained to its end and the cursor moves to the current file at once.</item>
/// <item>Rename (the writer keeps writing to <c>path.1</c> until it reopens its file, rsyslog
/// until HUP): the cursor leaves only once the current file is identified and <c>path.1</c>
/// stayed unchanged over <see cref="FileTailReaderOptions.RotationGracePolls"/> end-of-file
/// polls; only then is its unterminated last line complete. Later growth of that
/// <c>path.1</c> is reported as a gap (<see cref="FileTailCursor.Abandoned"/>) while it can
/// still be observed; once it is rotated away, nothing more is seen (best effort).</item>
/// </list>
/// <para>
/// Device and inode numbers tell the two apart where available (Linux): copytruncate keeps the
/// original file, rename moves it. Without them, a current file shorter than the cursor with
/// the same identity is copytruncate and a changed identity is a rename.
/// </para>
/// </summary>
public static class FileTailReader
{
    /// <param name="path">The current file (already checked by <see cref="FileTailPaths"/>), or null when it is missing.</param>
    /// <param name="rotatedPath">The rotated file to drain (<c>path.1</c>, already checked), or null when it is missing.</param>
    /// <exception cref="FileTailRefusedException">An opened handle is not the validated regular file.</exception>
    public static FileTailBatch Read(
        string? path,
        string? rotatedPath,
        FileTailCursor? cursor,
        FileTailReaderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        using FileTailHandle? current = FileTailHandle.Open(path);
        FileTailHandle? rotated = null;
        bool rotatedOpened = false;
        try
        {
            FileTailBatch batch = FileTailFiles.Plan(
                current,
                options.UseFileIds ? current?.FileId ?? FileTailHandle.FileIdOf(path) : null,
                Rotated,
                cursor,
                new FileTailPolicy
                {
                    StartAtEnd = options.StartAtEnd,
                    StartScanBudget = options.MaxBytesPerBatch,
                    MaxLinesPerBatch = options.MaxLinesPerBatch,
                    RotationGracePolls = options.RotationGracePolls,
                    RotationDrainMaxPolls = options.RotationDrainMaxPolls
                },
                new TextDecoder(options),
                cancellationToken);
            return batch with { RotatedPath = rotated is null ? null : rotatedPath };
        }
        finally
        {
            rotated?.Dispose();
        }

        FileTailHandle? Rotated()
        {
            if (!rotatedOpened)
            {
                rotatedOpened = true;
                rotated = FileTailHandle.Open(rotatedPath);
            }

            return rotated;
        }
    }

    /// <summary>Plain text lines; a settled rotated file's unterminated last line is complete.</summary>
    private sealed class TextDecoder(FileTailReaderOptions options) : IFileTailDecoder<FileTailBatch>
    {
        public FileTailBatch Scan(FileTailHandle file, FileTailCursor cursor, bool eofEndsLine, bool gap) =>
            ReadFile(file, cursor, options, eofEndsLine, gap) with { Origin = cursor };

        public FileTailBatch Empty(FileTailCursor cursor, bool gap) => FileTailReader.Empty(cursor) with { Gap = gap };

        public FileTailCursor CursorOf(FileTailBatch batch) => batch.Cursor;

        public bool StoppedByLimit(FileTailBatch batch) => batch.More;

        public int LineCount(FileTailBatch batch) => batch.Lines.Count;

        public FileTailBatch WithCursor(FileTailBatch batch, FileTailCursor cursor) => batch with { Cursor = cursor };

        public FileTailBatch WithGap(FileTailBatch batch) => batch with { Gap = true };

        public FileTailBatch MovedToCurrent(FileTailBatch batch, FileTailCursor moved) =>
            batch with { Cursor = moved, Rotated = true, More = true };

        public FileTailBatch Append(FileTailBatch batch, FileTailBatch tail) =>
            batch with { Lines = [.. batch.Lines, .. tail.Lines] };
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

    private static FileTailBatch Empty(FileTailCursor cursor) => new([], cursor, false, false, false);
}
