using System.Text;
using System.Text.Json;
using Bower.Source.Docker;
using Bower.Source.File;

namespace Bower.UnitTests;

/// <summary>
/// The Docker reader on the shared tailer must behave exactly as before. Seeded random
/// sequences of file operations (appends, Docker partial chunks, oversized and unfinished
/// lines, malformed entries, rename and copytruncate rotation, truncation, deletion) run
/// both the frozen pre-refactor reader (<see cref="LegacyDockerJsonLogReader"/>) and the
/// current one over the same files; records, offsets, fingerprints, counters, gap flags and
/// serialised cursors must be identical after every read.
/// <para>
/// One deliberate difference: the current reader treats a renamed <c>.1</c> as final, so a
/// line left open at its end within the limits (split across the rotation, or ended by a
/// stream without a newline), or a torn entry, no longer holds the cursor on <c>.1</c> while
/// the new file goes unread and is later lost. The random histories therefore end such a line
/// before they rotate, as the readers see it from their cursor, but leave an oversized one
/// open so the discard carried across rotation is still compared;
/// <see cref="LineSplitAcrossRotation_IsClosedWhereThePreRefactorReaderLostTheNextFile"/> pins
/// the difference.
/// </para>
/// </summary>
public sealed class DockerReaderDifferentialTests
{
    private const int Seeds = 300;
    private const int Steps = 60;

    [Fact]
    public void CurrentReader_MatchesThePreRefactorReaderOnRandomFileHistories()
    {
        int reads = 0, records = 0, gaps = 0, discarding = 0, carried = 0, rotations = 0, failures = 0, restarts = 0;
        for (int seed = 0; seed < Seeds; seed++)
        {
            Random random = new(seed);
            using TemporaryDirectory root = new();
            DockerContainer container = DockerFixture.Catalogued(root);
            string path = container.LogPath;
            string rotated = path + ".1";
            DockerLogReaderOptions options = new()
            {
                MaximumLineBytes = random.Next(16, 200),
                MaximumRecordsPerBatch = random.Next(1, 7),
                MaximumBytesPerBatch = random.Next(300, 3_000),
                StartAtEnd = random.Next(2) == 0
            };
            DockerLogCursor? legacyCursor = null, currentCursor = null;
            string? pendingTail = null;
            for (int step = 0; step < Steps; step++)
            {
                switch (random.Next(17))
                {
                    case 0 or 1:
                        Append(path, Entries(random, random.Next(1, 5)));
                        break;
                    case 2:
                        // One logical line in partial chunks, sometimes not finished yet, sometimes
                        // with a complete stderr line copied in between its chunks.
                        Append(path, Chunks(random, random.Next(2, 6), terminate: random.Next(3) != 0));
                        break;
                    case 3:
                        Append(path, Entry(new string('o', random.Next(150, 500)) + "\n"));
                        break;
                    case 4 when pendingTail is null:
                        string entry = Entry("half " + random.Next() + "\n");
                        int cut = random.Next(1, entry.Length - 1);
                        Append(path, entry[..cut]);
                        pendingTail = entry[cut..];
                        break;
                    case 4:
                        Append(path, pendingTail!);
                        pendingTail = null;
                        break;
                    case 5:
                        Append(path, random.Next(2) == 0 ? "not json at all\n" : """{"log":5,"stream":"stdout"}""" + "\n");
                        break;
                    case 6 when System.IO.File.Exists(path):
                        EndOpenLine(path, currentCursor, options.MaximumLineBytes);
                        System.IO.File.Move(path, rotated, overwrite: true);
                        pendingTail = null;
                        if (random.Next(2) == 0)
                        {
                            Append(path, Entries(random, random.Next(1, 4)));
                        }

                        rotations++;
                        break;
                    case 7 when System.IO.File.Exists(path):
                        EndOpenLine(path, currentCursor, options.MaximumLineBytes);
                        System.IO.File.Copy(path, rotated, overwrite: true);
                        Truncate(path);
                        pendingTail = null;
                        rotations++;
                        break;
                    case 8 when System.IO.File.Exists(path):
                        Truncate(path);
                        pendingTail = null;
                        break;
                    case 9 when random.Next(4) == 0:
                        System.IO.File.Delete(rotated);
                        break;
                    case 10 when random.Next(6) == 0:
                        System.IO.File.Delete(path);
                        pendingTail = null;
                        break;
                    case 11 when random.Next(3) == 0:
                        // A new container (or a lost cursor): both start again from no cursor,
                        // so the start-at-end scan runs over whatever the file holds now.
                        legacyCursor = null;
                        currentCursor = null;
                        restarts++;
                        break;
                    case 12 when pendingTail is null:
                        // An unfinished entry longer than any batch byte budget.
                        string longEntry = Entry("long " + random.Next() + new string('z', random.Next(3_000, 6_000)) + "\n");
                        int split = longEntry.Length - random.Next(2, 40);
                        Append(path, longEntry[..split]);
                        pendingTail = longEntry[split..];
                        break;
                    default:
                        (DockerLogBatch? legacy, string? legacyError) = Run(() => LegacyDockerJsonLogReader.Read(container, legacyCursor, options));
                        (DockerLogBatch? current, string? currentError) = Run(() => DockerJsonLogReader.Read(container, currentCursor, options));
                        string where = $"seed {seed}, step {step}";
                        Assert.True(legacyError == currentError, $"{where}: errors {legacyError} vs {currentError}");
                        reads++;
                        if (legacy is null)
                        {
                            failures++;
                            break;
                        }

                        Assert.True(legacy.Records.SequenceEqual(current!.Records), $"{where}: records differ");
                        Assert.True(legacy.Cursor == current.Cursor, $"{where}: cursor {legacy.Cursor} vs {current.Cursor}");
                        Assert.Equal(legacy.Cursor.Serialize(), current.Cursor.Serialize());
                        Assert.True((legacy.Malformed, legacy.Oversized, legacy.RotationGap, legacy.ClosedAtRotation) == (current.Malformed, current.Oversized, current.RotationGap, current.ClosedAtRotation),
                            $"{where}: counters differ");
                        legacyCursor = legacy.Cursor;
                        currentCursor = current.Cursor;
                        records += current.Records.Count;
                        gaps += current.RotationGap ? 1 : 0;
                        discarding += current.Cursor.Discarding ? 1 : 0;
                        // Only a discard carried across rotation sits at the start of a file.
                        carried += current.Cursor is { Discarding: true, Offset: 0 } ? 1 : 0;
                        break;
                }
            }
        }

        // The histories must actually exercise the interesting paths.
        Assert.True(reads > Seeds * 10 && records > 1_000 && gaps > 20 && discarding > 20 && carried > 5 && rotations > 200 && restarts > 100,
            $"reads {reads}, records {records}, gaps {gaps}, discarding {discarding}, carried {carried}, rotations {rotations}, restarts {restarts}, failures {failures}");
    }

    [Fact]
    public void LineSplitAcrossRotation_IsClosedWhereThePreRefactorReaderLostTheNextFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        string rotated = container.LogPath + ".1";
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerLogCursor? legacyCursor = null, currentCursor = null;
        List<string> legacyLines = [], currentLines = [];
        int currentOversized = 0, currentClosed = 0;
        bool legacyGap = false, currentGap = false;
        DockerFixture.Append(container, "file A line one\n", "first chunk of a split line ");
        Read();
        System.IO.File.Move(container.LogPath, rotated);
        DockerFixture.Append(container, "rest of the split line\n", "file B line one\n", "file B line two\n");

        // The old reader stays on .1 at the start of the split line, reading nothing.
        for (int poll = 0; poll < 5; poll++)
        {
            Read();
        }

        // The second rotation: B becomes .1 (A is gone) and C is the new file.
        System.IO.File.Move(container.LogPath, rotated, overwrite: true);
        DockerFixture.Append(container, "file C line one\n");
        Read();
        Read();

        Assert.Equal(["file A line one", "file C line one"], legacyLines);
        Assert.True(legacyGap);
        // The head is emitted as it stood in .1, the rest as its own fragment record.
        Assert.Equal(
            ["file A line one", "first chunk of a split line ", "rest of the split line", "file B line one", "file B line two", "file C line one"],
            currentLines);
        Assert.Equal((0, 1), (currentOversized, currentClosed));
        Assert.False(currentGap);

        void Read()
        {
            DockerLogBatch legacy = LegacyDockerJsonLogReader.Read(container, legacyCursor, options);
            DockerLogBatch current = DockerJsonLogReader.Read(container, currentCursor, options);
            (legacyCursor, currentCursor) = (legacy.Cursor, current.Cursor);
            legacyLines.AddRange(legacy.Records.Select(record => record.Text));
            currentLines.AddRange(current.Records.Select(record => record.Text));
            currentOversized += current.Oversized;
            currentClosed += current.ClosedAtRotation;
            legacyGap |= legacy.RotationGap;
            currentGap |= current.RotationGap;
        }
    }

    [Fact]
    public void FileThatShrinksBeforeItsIdentityIsRead_StillThrowsSoTheSidecarLogsAndBacksOff()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "a line long enough to give the file an identity\n");
        FileTailHandle.BeforePrefixRead = opened =>
        {
            if (opened == container.LogPath)
            {
                using FileStream shrink = new(opened, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                shrink.SetLength(10);
            }
        };
        try
        {
            // As before the shared tailer: the read fails instead of returning an empty batch.
            Assert.Throws<EndOfStreamException>(() => DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()));
        }
        finally
        {
            FileTailHandle.BeforePrefixRead = null;
        }
    }

    private static (DockerLogBatch? Batch, string? Error) Run(Func<DockerLogBatch> read)
    {
        try
        {
            return (read(), null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return (null, exception.GetType().Name);
        }
    }

    private static string Entry(string log, string stream = "stdout") =>
        JsonSerializer.Serialize(new { log, stream, time = "2026-10-07T10:00:00.123456789Z" }) + "\n";

    private static string Entries(Random random, int count)
    {
        StringBuilder text = new();
        for (int index = 0; index < count; index++)
        {
            text.Append(Entry("line " + random.Next() + new string('x', random.Next(0, 120)) + "\n"));
        }

        return text.ToString();
    }

    private static string Chunks(Random random, int count, bool terminate)
    {
        StringBuilder text = new();
        for (int index = 0; index < count; index++)
        {
            bool last = index == count - 1;
            text.Append(Entry(new string((char)('a' + index), random.Next(5, 80)) + (last && terminate ? "\n" : string.Empty)));
            if (!last && random.Next(4) == 0)
            {
                // Docker copies stdout and stderr into the same file concurrently.
                text.Append(Entry("interleaved " + random.Next() + "\n", "stderr"));
            }
        }

        return text.ToString();
    }

    private static void Append(string path, string text) => System.IO.File.AppendAllText(path, text);

    /// <summary>
    /// Before a rotation, ends a torn entry and a logical line left open within the line limit,
    /// where the readers deliberately differ (see the class remarks). The line is followed as the
    /// readers see it, from their cursor when it is on this file. An oversized open line is left
    /// open: both readers carry its discard into the new file.
    /// </summary>
    private static void EndOpenLine(string path, DockerLogCursor? cursor, int maximumLineBytes)
    {
        byte[] bytes = System.IO.File.ReadAllBytes(path);
        if (bytes.Length > 0 && bytes[^1] != '\n')
        {
            Append(path, "\n");
            bytes = [.. bytes, (byte)'\n'];
        }

        string? fingerprint;
        using (FileTailHandle? file = FileTailHandle.OpenWithPrefixIdentity(path))
        {
            fingerprint = file?.Fingerprint;
        }

        bool onThisFile = cursor is not null && cursor.Fingerprint == fingerprint && cursor.Offset <= bytes.Length;
        int position = onThisFile ? (int)cursor!.Offset : 0;
        bool open = onThisFile && cursor!.Discarding;
        bool oversized = open;
        int length = 0;
        while (position < bytes.Length)
        {
            int newline = Array.IndexOf(bytes, (byte)'\n', position);
            ReadOnlySpan<byte> entry = bytes.AsSpan(position, newline - position);
            position = newline + 1;
            if (entry.Length > maximumLineBytes * 2 + 4_096 || !TryLog(entry, out string log))
            {
                continue; // Malformed: does not end or extend a line.
            }

            open = true;
            if (!oversized)
            {
                oversized = length + log.Length > maximumLineBytes;
                length += log.Length;
            }

            if (log.EndsWith('\n'))
            {
                (open, oversized, length) = (false, false, 0);
            }
        }

        if (open && !oversized)
        {
            Append(path, Entry("closed\n"));
        }

        static bool TryLog(ReadOnlySpan<byte> entry, out string log)
        {
            log = string.Empty;
            try
            {
                using JsonDocument document = JsonDocument.Parse(entry.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
                if (document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("log", out JsonElement value)
                    && value.ValueKind == JsonValueKind.String)
                {
                    log = value.GetString()!;
                    return true;
                }
            }
            catch (JsonException)
            {
            }

            return false;
        }
    }

    private static void Truncate(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.SetLength(0);
    }
}
