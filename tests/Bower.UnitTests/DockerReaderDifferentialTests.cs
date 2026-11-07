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
/// line left unfinished at its end (split across the rotation, or a torn entry) no longer
/// holds the cursor on <c>.1</c> while the new file goes unread and is later lost. The random
/// histories therefore end any open line before they rotate (Docker rotates between writes,
/// and only a line over 16 KiB is ever split), and
/// <see cref="LineSplitAcrossRotation_IsSkippedWhereThePreRefactorReaderLostTheNextFile"/>
/// pins the difference.
/// </para>
/// </summary>
public sealed class DockerReaderDifferentialTests
{
    private const int Seeds = 300;
    private const int Steps = 60;

    [Fact]
    public void CurrentReader_MatchesThePreRefactorReaderOnRandomFileHistories()
    {
        int reads = 0, records = 0, gaps = 0, discarding = 0, rotations = 0, failures = 0, restarts = 0;
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
                        // One logical line in partial chunks, sometimes not finished yet.
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
                        EndOpenLine(path);
                        System.IO.File.Move(path, rotated, overwrite: true);
                        pendingTail = null;
                        if (random.Next(2) == 0)
                        {
                            Append(path, Entries(random, random.Next(1, 4)));
                        }

                        rotations++;
                        break;
                    case 7 when System.IO.File.Exists(path):
                        EndOpenLine(path);
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
                        Assert.True((legacy.Malformed, legacy.Oversized, legacy.RotationGap) == (current.Malformed, current.Oversized, current.RotationGap),
                            $"{where}: counters differ");
                        legacyCursor = legacy.Cursor;
                        currentCursor = current.Cursor;
                        records += current.Records.Count;
                        gaps += current.RotationGap ? 1 : 0;
                        discarding += current.Cursor.Discarding ? 1 : 0;
                        break;
                }
            }
        }

        // The histories must actually exercise the interesting paths.
        Assert.True(reads > Seeds * 10 && records > 1_000 && gaps > 20 && discarding > 20 && rotations > 200 && restarts > 100,
            $"reads {reads}, records {records}, gaps {gaps}, discarding {discarding}, rotations {rotations}, restarts {restarts}, failures {failures}");
    }

    [Fact]
    public void LineSplitAcrossRotation_IsSkippedWhereThePreRefactorReaderLostTheNextFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        string rotated = container.LogPath + ".1";
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerLogCursor? legacyCursor = null, currentCursor = null;
        List<string> legacyLines = [], currentLines = [];
        int currentOversized = 0;
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
        Assert.Equal(["file A line one", "file B line one", "file B line two", "file C line one"], currentLines);
        Assert.Equal(1, currentOversized);
        Assert.False(currentGap);

        void Read()
        {
            DockerLogBatch legacy = LegacyDockerJsonLogReader.Read(container, legacyCursor, options);
            DockerLogBatch current = DockerJsonLogReader.Read(container, currentCursor, options);
            (legacyCursor, currentCursor) = (legacy.Cursor, current.Cursor);
            legacyLines.AddRange(legacy.Records.Select(record => record.Text));
            currentLines.AddRange(current.Records.Select(record => record.Text));
            currentOversized += current.Oversized;
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

    private static string Entry(string log) =>
        JsonSerializer.Serialize(new { log, stream = "stdout", time = "2026-10-07T10:00:00.123456789Z" }) + "\n";

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
        }

        return text.ToString();
    }

    private static void Append(string path, string text) => System.IO.File.AppendAllText(path, text);

    /// <summary>
    /// Ends a torn entry and an unfinished chunked line before a rotation, where the readers
    /// deliberately differ (see the class remarks).
    /// </summary>
    private static void EndOpenLine(string path)
    {
        string text = System.IO.File.ReadAllText(path);
        if (text.Length > 0 && text[^1] != '\n')
        {
            Append(path, "\n");
            text += "\n";
        }

        foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Reverse())
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(line);
                if (document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("log", out JsonElement log)
                    && log.ValueKind == JsonValueKind.String)
                {
                    if (!log.GetString()!.EndsWith('\n'))
                    {
                        Append(path, Entry("closed\n"));
                    }

                    return;
                }
            }
            catch (JsonException)
            {
                // Malformed entries do not end a line; look further back.
            }
        }
    }

    private static void Truncate(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.SetLength(0);
    }
}
