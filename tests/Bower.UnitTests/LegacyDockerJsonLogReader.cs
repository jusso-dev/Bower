using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Source.Docker;

namespace Bower.UnitTests;

#pragma warning disable CA1508, CA1502, CA1505 // Frozen copy: kept byte-for-byte in logic.

/// <summary>
/// TEST ONLY: the Docker json-file reader exactly as it was before it moved onto the shared
/// tailer (origin/feat/file-tail-source at 05fa1e6, unchanged since the Docker source was
/// written). <see cref="DockerReaderDifferentialTests"/> runs it against the current reader.
/// Do not change its logic. The only addition is two test hooks at the points that match
/// <see cref="Bower.Source.File.FileTailHandle"/>'s, so a race can hit both readers in the
/// same window; unset, they do nothing.
/// </summary>
internal static class LegacyDockerJsonLogReader
{
    internal const int FingerprintBytes = 64;

    /// <summary>Tests only: after the 64-byte length check of the identity read (as <c>FileTailHandle.BeforePrefixRead</c>).</summary>
    [ThreadStatic]
    internal static Action<string>? BeforePrefixRead;

    /// <summary>Tests only: once the identity is read (as <c>FileTailHandle.AfterOpen</c>).</summary>
    [ThreadStatic]
    internal static Action<string>? AfterOpen;

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
            return ReadFile(
                currentPath,
                cursor with { Fingerprint = currentFingerprint, Offset = 0, Discarding = false },
                options,
                false);
        }

        if (string.Equals(cursor.Fingerprint, currentFingerprint, StringComparison.Ordinal))
        {
            long length = new FileInfo(currentPath).Length;
            if (length < cursor.Offset)
            {
                // Truncated in place: restart and flag the gap.
                return ReadFile(currentPath, cursor with { Offset = 0, Discarding = false }, options, true);
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
                // A line split across the rotation keeps being discarded in the new file.
                return rotated with
                {
                    Cursor = new DockerLogCursor(
                        DockerLogCursor.CurrentSchemaVersion,
                        currentFingerprint,
                        0,
                        rotated.Cursor.Discarding)
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

            BeforePrefixRead?.Invoke(path);
            byte[] prefix = new byte[FingerprintBytes];
            stream.ReadExactly(prefix);
            AfterOpen?.Invoke(path);
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
        bool committedDiscarding = cursor.Discarding;

        using FileStream stream = Open(path);
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

    private static long LastCompleteLineEnd(string path)
    {
        // Scan backwards in blocks: seeking back one byte at a time discarded the 64 KiB
        // read buffer on every step, so a long unterminated tail cost one buffer refill per byte.
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
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65_536);

    private static DockerLogBatch Empty(DockerLogCursor cursor) => new([], cursor, 0, 0, false);
}
