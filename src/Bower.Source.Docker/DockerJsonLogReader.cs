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
/// <paramref name="Discarding"/> (additive, omitted when false) means <paramref name="Offset"/>
/// is the next physical chunk of an oversized logical line: chunks up to and including its
/// terminator are skipped. It carries no line content.
/// </para>
/// </summary>
public sealed record DockerLogCursor(
    int SchemaVersion,
    string Fingerprint,
    long Offset,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Discarding = false)
{
    public const int CurrentSchemaVersion = 1;

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
            return cursor is { SchemaVersion: CurrentSchemaVersion, Offset: >= 0 } ? cursor : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>Cursor JSON: camelCase, otherwise default options (source generated).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DockerLogCursor))]
internal sealed partial class DockerCursorJsonContext : JsonSerializerContext;

/// <summary>One logical log line (Docker splits lines over 16 KiB into chunks).</summary>
public sealed record DockerLogRecord(
    string Text,
    string Stream,
    DateTimeOffset? Time,
    string FileFingerprint,
    long StartOffset,
    long EndOffset);

public sealed record DockerLogBatch(
    IReadOnlyList<DockerLogRecord> Records,
    DockerLogCursor Cursor,
    int Malformed,
    int Oversized,
    bool RotationGap);

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
/// waiting while the current file cannot be identified, and an oversized-line discard
/// carried across rotation. This class is the Docker line decoder on top of it: json-file
/// entries, the 16 KiB partial-chunk join, malformed entries and the oversized-line discard,
/// within the record and byte bounds.
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
            return FileTailFiles.Plan(
                current,
                fileId: null,
                () => rotated ??= FileTailHandle.OpenWithPrefixIdentity(container.LogPath + ".1"),
                cursor is null ? null : Shared(cursor),
                options.StartAtEnd ? StartAtEndPolicy : ReplayPolicy,
                new Decoder(options));
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
    /// unbounded start-at-end scan.
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
        TrackAbandoned = false
    };

    private static readonly FileTailPolicy ReplayPolicy = StartAtEndPolicy with { StartAtEnd = false };

    /// <summary>
    /// Docker json-file entries. A drain stopped by the record limit is not drained. Docker's
    /// cursor keeps no rotation state, so each read detects the rotation again, as it always did.
    /// </summary>
    private sealed class Decoder(DockerLogReaderOptions options) : IFileTailDecoder<DockerLogBatch>
    {
        // Only a copy drain or a settled grace window ends a line at end of file; Docker's
        // policy has neither, so reaching this would mean a policy change, not data.
        public DockerLogBatch Scan(FileTailHandle file, FileTailCursor cursor, bool eofEndsLine, bool gap) =>
            eofEndsLine
                ? throw new UnreachableException("The Docker policy never ends a line at end of file.")
                : ReadFile(file, Docker(cursor), options, gap);

        public DockerLogBatch Empty(FileTailCursor cursor, bool gap) => DockerJsonLogReader.Empty(Docker(cursor)) with { RotationGap = gap };

        public FileTailCursor CursorOf(DockerLogBatch batch) => Shared(batch.Cursor);

        public bool StoppedByLimit(DockerLogBatch batch) => batch.Records.Count >= options.MaximumRecordsPerBatch;

        public int LineCount(DockerLogBatch batch) => batch.Records.Count;

        public DockerLogBatch WithCursor(DockerLogBatch batch, FileTailCursor cursor) => batch with { Cursor = Docker(cursor) };

        public DockerLogBatch WithGap(DockerLogBatch batch) => batch with { RotationGap = true };

        public DockerLogBatch MovedToCurrent(DockerLogBatch batch, FileTailCursor moved) => batch with { Cursor = Docker(moved) };

        public DockerLogBatch Append(DockerLogBatch batch, DockerLogBatch tail) =>
            throw new UnreachableException("The Docker policy has no grace window, so no settled tail is appended.");
    }

    // Mapped by name; Docker's JSON and schema version stay DockerLogCursor's own (see Docker()).
    private static FileTailCursor Shared(DockerLogCursor cursor) =>
        new(cursor.SchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    /// <summary>Docker's own schema version, independent of the file tail cursor's.</summary>
    internal static DockerLogCursor Docker(FileTailCursor cursor) =>
        new(DockerLogCursor.CurrentSchemaVersion, cursor.Fingerprint, cursor.Offset, cursor.Discarding);

    private static DockerLogBatch ReadFile(
        FileTailHandle file,
        DockerLogCursor cursor,
        DockerLogReaderOptions options,
        bool rotationGap)
    {
        List<DockerLogRecord> records = [];
        int malformed = 0;
        int oversized = 0;
        long committed = cursor.Offset;
        bool committedDiscarding = cursor.Discarding;

        FileStream stream = file.Stream;
        stream.Seek(cursor.Offset, SeekOrigin.Begin);
        long budgetEnd = Math.Min(stream.Length, cursor.Offset + options.MaximumBytesPerBatch);

        // Logical line being assembled from Docker's 16 KiB partial chunks. An oversized line
        // is never buffered: its chunks are consumed and committed as they are read, so a line
        // larger than the byte budget cannot pin the cursor across polls or restarts.
        StringBuilder pending = new();
        long pendingStart = cursor.Discarding ? cursor.Offset : -1;
        bool pendingOversized = cursor.Discarding;
        string pendingStream = "stdout";
        DateTimeOffset? pendingTime = null;

        long position = cursor.Offset;
        while (records.Count < options.MaximumRecordsPerBatch && position < budgetEnd)
        {
            long entryStart = position;
            byte[]? entry = ReadEntry(stream, options.MaximumLineBytes * 2 + 4_096, out bool complete, out bool tooLong);
            if (!complete)
            {
                break; // Writer has not finished this line; read it next time.
            }

            position = stream.Position;
            if (tooLong || entry is null)
            {
                malformed++;
                if (pendingStart < 0 || pendingOversized)
                {
                    committed = position;
                }

                continue;
            }

            if (!TryParseEntry(entry, out string? log, out string? streamName, out DateTimeOffset? time))
            {
                malformed++;
                if (pendingStart < 0 || pendingOversized)
                {
                    committed = position;
                }

                continue;
            }

            if (pendingStart < 0)
            {
                pendingStart = entryStart;
                pendingStream = streamName ?? "stdout";
                pendingTime = time;
            }

            if (!pendingOversized)
            {
                if (pending.Length + log!.Length > options.MaximumLineBytes)
                {
                    pendingOversized = true;
                    pending.Clear();
                }
                else
                {
                    pending.Append(log);
                }
            }

            if (!log!.EndsWith('\n'))
            {
                if (pendingOversized)
                {
                    committed = position;
                    committedDiscarding = true;
                }

                continue; // Partial chunk: the rest of the line follows.
            }

            if (pendingOversized)
            {
                oversized++;
            }
            else
            {
                records.Add(new DockerLogRecord(
                    pending.ToString().TrimEnd('\n', '\r'),
                    pendingStream,
                    pendingTime,
                    cursor.Fingerprint,
                    pendingStart,
                    position));
            }

            committed = position;
            committedDiscarding = false;
            pending.Clear();
            pendingStart = -1;
            pendingOversized = false;
        }

        // One logical line filled the whole byte budget without ending: it can never be read
        // within bounds, so discard it rather than re-reading the same prefix every poll.
        if (pendingStart == cursor.Offset
            && !pendingOversized
            && position - cursor.Offset >= options.MaximumBytesPerBatch)
        {
            committed = position;
            committedDiscarding = true;
        }

        return new DockerLogBatch(
            records,
            cursor with { Offset = committed, Discarding = committedDiscarding },
            malformed,
            oversized,
            rotationGap);
    }

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

    private static bool TryParseEntry(
        byte[] entry,
        out string? log,
        out string? stream,
        out DateTimeOffset? time)
    {
        log = null;
        stream = null;
        time = null;
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

            log = logElement.GetString() ?? string.Empty;
            if (root.TryGetProperty("stream", out JsonElement streamElement)
                && streamElement.ValueKind == JsonValueKind.String)
            {
                stream = streamElement.GetString();
            }

            if (root.TryGetProperty("time", out JsonElement timeElement)
                && timeElement.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(
                    timeElement.GetString(),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset parsed))
            {
                time = parsed;
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static DockerLogBatch Empty(DockerLogCursor cursor) => new([], cursor, 0, 0, false);
}
