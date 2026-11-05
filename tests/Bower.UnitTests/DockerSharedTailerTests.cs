using System.Text.Json;
using Bower.Source.Docker;
using Bower.Source.File;

namespace Bower.UnitTests;

/// <summary>
/// Docker behaviour on the shared tailer that the random differential cannot reach on its
/// own: a rotated file that grows during a read, a start-at-end scan past the batch budget,
/// and Docker's own cursor schema. Each behavioural case runs on the frozen pre-refactor
/// reader (<see cref="LegacyDockerJsonLogReader"/>) and the current one.
/// </summary>
public sealed class DockerSharedTailerTests
{
    private static string Entry(string log) =>
        JsonSerializer.Serialize(new { log, stream = "stdout", time = "2026-10-07T10:00:00.123456789Z" }) + "\n";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RotatedFileThatGrowsAfterItsLengthIsTaken_IsNotLeftEarlyAndItsLateRecordIsRead(bool legacy)
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        string rotated = container.LogPath + ".1";
        System.IO.File.WriteAllText(container.LogPath,
            Entry("first record with enough bytes for the identity\n") + Entry("unread record before rotation\n"));
        DockerLogBatch Read(DockerLogCursor? cursor, DockerLogReaderOptions options) => legacy
            ? LegacyDockerJsonLogReader.Read(container, cursor, options)
            : DockerJsonLogReader.Read(container, cursor, options);
        DockerLogCursor first = Read(null, new DockerLogReaderOptions { StartAtEnd = false, MaximumRecordsPerBatch = 1 }).Cursor;
        long rotatedEnd = new FileInfo(container.LogPath).Length;
        System.IO.File.Move(container.LogPath, rotated);
        System.IO.File.WriteAllText(container.LogPath, Entry("current generation record that has a different identity\n"));
        string late = Entry("late record appended during the same poll\n");
        // The byte budget ends exactly at the rotated file's length when it was opened.
        DockerLogReaderOptions budget = new() { StartAtEnd = false, MaximumRecordsPerBatch = 100, MaximumBytesPerBatch = (int)(rotatedEnd - first.Offset) };

        DockerLogBatch batch;
        if (legacy)
        {
            // The frozen reader reopens path.1 for the scan and measures it again afterwards.
            System.IO.File.AppendAllText(rotated, late);
            batch = Read(first, budget);
        }
        else
        {
            // Grow path.1 after its length was taken at open, before the drain decision.
            FileTailHandle.BeforePrefixRead = path =>
            {
                if (path == rotated)
                {
                    System.IO.File.AppendAllText(path, late);
                }
            };
            try
            {
                batch = Read(first, budget);
            }
            finally
            {
                FileTailHandle.BeforePrefixRead = null;
            }
        }

        // Still on path.1, at its length when opened: not drained, so nothing is skipped.
        Assert.Equal("unread record before rotation", Assert.Single(batch.Records).Text);
        Assert.Equal((first.Fingerprint, rotatedEnd, false), (batch.Cursor.Fingerprint, batch.Cursor.Offset, batch.RotationGap));
        DockerLogBatch next = Read(batch.Cursor, new DockerLogReaderOptions { StartAtEnd = false });
        Assert.Equal("late record appended during the same poll", Assert.Single(next.Records).Text);
        DockerLogBatch moved = Read(next.Cursor, new DockerLogReaderOptions { StartAtEnd = false });
        Assert.Equal("current generation record that has a different identity", Assert.Single(moved.Records).Text);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StartAtEnd_ScansBackPastAnUnfinishedTailLongerThanTheBatchBudget(bool legacy)
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "history before the sidecar started\n");
        long history = new FileInfo(container.LogPath).Length;
        string unfinished = Entry("a long line still being written " + new string('x', 2_000) + "\n");
        // Everything but the final newline: one unfinished entry, longer than the byte budget.
        System.IO.File.AppendAllText(container.LogPath, unfinished[..^1]);
        DockerLogReaderOptions options = new() { MaximumBytesPerBatch = 300, MaximumLineBytes = 4_096 };
        DockerLogBatch Read(DockerLogCursor? cursor) => legacy
            ? LegacyDockerJsonLogReader.Read(container, cursor, options)
            : DockerJsonLogReader.Read(container, cursor, options);

        DockerLogBatch first = Read(null);

        Assert.Empty(first.Records);
        Assert.Equal((history, false), (first.Cursor.Offset, first.Cursor.Discarding));
        System.IO.File.AppendAllText(container.LogPath, "\n");
        DockerLogCursor cursor = first.Cursor;
        List<DockerLogRecord> records = [];
        for (int poll = 0; poll < 20 && records.Count == 0; poll++)
        {
            DockerLogBatch batch = Read(cursor);
            records.AddRange(batch.Records);
            cursor = batch.Cursor;
        }

        Assert.StartsWith("a long line still being written", Assert.Single(records).Text, StringComparison.Ordinal);
    }

    [Fact]
    public void NewDockerCursors_UseDockersOwnSchemaVersion()
    {
        // A file tail cursor schema bump must never leak into persisted Docker cursors.
        FileTailCursor shared = new(DockerLogCursor.CurrentSchemaVersion + 98, new string('a', 64), 5, Discarding: true);

        DockerLogCursor docker = DockerJsonLogReader.Docker(shared);

        Assert.Equal(new DockerLogCursor(DockerLogCursor.CurrentSchemaVersion, new string('a', 64), 5, true), docker);
        Assert.NotNull(DockerLogCursor.Deserialize(docker.Serialize()));
    }
}
