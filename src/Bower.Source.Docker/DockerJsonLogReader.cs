using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bower.Source.Docker;

/// <summary>
/// Position in a container's json-file log. The fingerprint identifies the file by its
/// first bytes (which never change once written), so rotation is detected even though
/// Docker reuses the same file name.
/// </summary>
public sealed record DockerLogCursor(int SchemaVersion, string Fingerprint, long Offset)
{
    public const int CurrentSchemaVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public string Serialize() => JsonSerializer.Serialize(this, JsonOptions);

    public static DockerLogCursor? Deserialize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            DockerLogCursor? cursor = JsonSerializer.Deserialize<DockerLogCursor>(value, JsonOptions);
            return cursor is { SchemaVersion: CurrentSchemaVersion, Offset: >= 0 } ? cursor : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

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
/// </summary>
public static class DockerJsonLogReader
{
    internal const int FingerprintBytes = 64;

    public static DockerLogBatch Read(
        DockerContainer container,
        DockerLogCursor? cursor,
        DockerLogReaderOptions options)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(options);

        string currentPath = container.LogPath;
        string rotatedPath = currentPath + ".1";
        string? currentFingerprint = Fingerprint(currentPath);

        if (cursor is null)
        {
            if (currentFingerprint is null)
            {
                return Empty(new DockerLogCursor(DockerLogCursor.CurrentSchemaVersion, string.Empty, 0));
            }

            long start = options.StartAtEnd ? LastCompleteLineEnd(currentPath) : 0;
            DockerLogCursor initial = new(DockerLogCursor.CurrentSchemaVersion, currentFingerprint, start);
            return options.StartAtEnd ? Empty(initial) : ReadFile(currentPath, initial, options, false);
        }

        if (currentFingerprint is null)
        {
            return Empty(cursor);
        }

        // Provisional cursor recorded before the file had enough bytes to fingerprint.
        if (cursor.Fingerprint.Length == 0)
        {
            return ReadFile(currentPath, cursor with { Fingerprint = currentFingerprint, Offset = 0 }, options, false);
        }

        if (string.Equals(cursor.Fingerprint, currentFingerprint, StringComparison.Ordinal))
        {
            long length = new FileInfo(currentPath).Length;
            if (length < cursor.Offset)
            {
                // Truncated in place: restart and flag the gap.
                return ReadFile(currentPath, cursor with { Offset = 0 }, options, true);
            }

            return ReadFile(currentPath, cursor, options, false);
        }

        // The current file is new. Drain the rotated file first if it is the one we were reading.
        if (string.Equals(Fingerprint(rotatedPath), cursor.Fingerprint, StringComparison.Ordinal))
        {
            DockerLogBatch rotated = ReadFile(rotatedPath, cursor, options, false);
            bool drained = rotated.Cursor.Offset >= new FileInfo(rotatedPath).Length;
            if (drained && rotated.Records.Count < options.MaximumRecordsPerBatch)
            {
                return rotated with
                {
                    Cursor = new DockerLogCursor(DockerLogCursor.CurrentSchemaVersion, currentFingerprint, 0)
                };
            }

            return rotated;
        }

        // Rotated more than once since the last read (or file recreated): lines were lost.
        return ReadFile(
            currentPath,
            new DockerLogCursor(DockerLogCursor.CurrentSchemaVersion, currentFingerprint, 0),
            options,
            true);
    }

    internal static string? Fingerprint(string path)
    {
        try
        {
            using FileStream stream = Open(path);
            if (stream.Length < FingerprintBytes)
            {
                return null;
            }

            byte[] prefix = new byte[FingerprintBytes];
            stream.ReadExactly(prefix);
            return Convert.ToHexStringLower(SHA256.HashData(prefix));
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static DockerLogBatch ReadFile(
        string path,
        DockerLogCursor cursor,
        DockerLogReaderOptions options,
        bool rotationGap)
    {
        List<DockerLogRecord> records = [];
        int malformed = 0;
        int oversized = 0;
        long committed = cursor.Offset;

        using FileStream stream = Open(path);
        stream.Seek(cursor.Offset, SeekOrigin.Begin);
        long budgetEnd = Math.Min(stream.Length, cursor.Offset + options.MaximumBytesPerBatch);

        // Logical line being assembled from Docker's 16 KiB partial chunks.
        StringBuilder pending = new();
        long pendingStart = -1;
        bool pendingOversized = false;
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
                committed = pendingStart < 0 ? position : committed;
                continue;
            }

            if (!TryParseEntry(entry, out string? log, out string? streamName, out DateTimeOffset? time))
            {
                malformed++;
                if (pendingStart < 0)
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
            pending.Clear();
            pendingStart = -1;
            pendingOversized = false;
        }

        return new DockerLogBatch(
            records,
            cursor with { Offset = committed },
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

    private static long LastCompleteLineEnd(string path)
    {
        using FileStream stream = Open(path);
        long position = stream.Length;
        while (position > 0)
        {
            stream.Seek(position - 1, SeekOrigin.Begin);
            if (stream.ReadByte() == '\n')
            {
                return position;
            }

            position--;
        }

        return 0;
    }

    private static FileStream Open(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65_536);

    private static DockerLogBatch Empty(DockerLogCursor cursor) => new([], cursor, 0, 0, false);
}
