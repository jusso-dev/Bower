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
/// </summary>
public sealed class DockerReaderDifferentialTests
{
    private const int Seeds = 300;
    private const int Steps = 60;

    [Fact]
    public void CurrentReader_MatchesThePreRefactorReaderOnRandomFileHistories()
    {
        int reads = 0, records = 0, gaps = 0, discarding = 0, rotations = 0, failures = 0;
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
                switch (random.Next(14))
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
                        System.IO.File.Move(path, rotated, overwrite: true);
                        pendingTail = null;
                        if (random.Next(2) == 0)
                        {
                            Append(path, Entries(random, random.Next(1, 4)));
                        }

                        rotations++;
                        break;
                    case 7 when System.IO.File.Exists(path):
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
        Assert.True(reads > Seeds * 10 && records > 1_000 && gaps > 20 && discarding > 20 && rotations > 200,
            $"reads {reads}, records {records}, gaps {gaps}, discarding {discarding}, rotations {rotations}, failures {failures}");
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

    private static void Truncate(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.SetLength(0);
    }
}
