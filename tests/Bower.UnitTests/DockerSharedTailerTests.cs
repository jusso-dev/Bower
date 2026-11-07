using System.Text.Json;
using Bower.Source.Docker;
using Bower.Source.File;

namespace Bower.UnitTests;

/// <summary>
/// Docker behaviour on the shared tailer that the random differential cannot reach on its
/// own: a file that changes between its open and a decision, a start-at-end scan past the
/// batch budget, and Docker's own cursor schema. Each behavioural case runs on the frozen
/// pre-refactor reader (<see cref="LegacyDockerJsonLogReader"/>) and the current one; the races
/// fire through matching hooks in both, so both see the same window.
/// </summary>
public sealed class DockerSharedTailerTests
{
    private static readonly DockerLogReaderOptions Replay = new() { StartAtEnd = false };

    private static string Entry(string log) =>
        JsonSerializer.Serialize(new { log, stream = "stdout", time = "2026-10-07T10:00:00.123456789Z" }) + "\n";

    private static readonly string First = Entry("first record with enough bytes for the identity\n");

    [Fact]
    public void RotatedFileThatGrowsAfterItsLengthIsTaken_IsNotLeftEarlyAndItsLateRecordIsRead()
    {
        IReadOnlyList<DockerLogBatch> batches = SameAsLegacy((container, reader) =>
        {
            string rotated = container.LogPath + ".1";
            System.IO.File.WriteAllText(container.LogPath, First + Entry("unread record before rotation\n"));
            DockerLogCursor first = reader.Read(null, Replay with { MaximumRecordsPerBatch = 1 }).Cursor;
            long rotatedEnd = new FileInfo(container.LogPath).Length;
            System.IO.File.Move(container.LogPath, rotated);
            System.IO.File.WriteAllText(container.LogPath, Entry("current generation record that has a different identity\n"));
            // The byte budget ends exactly at the rotated file's length when it was opened.
            DockerLogReaderOptions budget = Replay with { MaximumRecordsPerBatch = 100, MaximumBytesPerBatch = (int)(rotatedEnd - first.Offset) };

            // Grow path.1 after its length check, before the drain decision.
            DockerLogBatch batch = reader.Read(first, budget, beforePrefixRead: path =>
            {
                if (path == rotated)
                {
                    System.IO.File.AppendAllText(path, Entry("late record appended during the same poll\n"));
                }
            });

            // Still on path.1, at its length when opened: not drained, so nothing is skipped.
            Assert.Equal((first.Fingerprint, rotatedEnd, false), (batch.Cursor.Fingerprint, batch.Cursor.Offset, batch.RotationGap));
            DockerLogBatch next = reader.Read(batch.Cursor, Replay);
            return [batch, next, reader.Read(next.Cursor, Replay)];
        });

        Assert.Equal(
            ["unread record before rotation", "late record appended during the same poll", "current generation record that has a different identity"],
            batches.Select(batch => Assert.Single(batch.Records).Text));
    }

    [Fact]
    public void TruncationWhileTheFileIsOpened_IsSeenSoRecordsWrittenAfterItAreNotSkipped()
    {
        IReadOnlyList<DockerLogBatch> batches = SameAsLegacy((container, reader) =>
        {
            System.IO.File.WriteAllText(container.LogPath, First + Entry("second\n") + Entry("third\n") + Entry("fourth\n"));
            DockerLogBatch all = reader.Read(null, Replay);
            // Truncated in place to the first record (same identity) after the open took its length.
            DockerLogBatch truncated = reader.Read(all.Cursor, Replay, beforePrefixRead: path => Truncate(path, First.Length));
            // Then it regrows past the old cursor before the next poll.
            System.IO.File.AppendAllText(container.LogPath, string.Concat(Enumerable.Range(1, 5).Select(index => Entry($"replacement {index}\n"))));
            Assert.True(new FileInfo(container.LogPath).Length > all.Cursor.Offset);
            return [all, truncated, reader.Read(truncated.Cursor, Replay)];
        });

        Assert.Equal(4, batches[0].Records.Count);
        Assert.True(batches[1].RotationGap);
        Assert.Equal("first record with enough bytes for the identity", Assert.Single(batches[1].Records).Text);
        Assert.Equal(Enumerable.Range(1, 5).Select(index => $"replacement {index}"), batches[2].Records.Select(record => record.Text));
    }

    [Fact]
    public void TruncatedFileThatRegrowsPastTheCursorWhileItIsOpened_ContinuesFromTheCursorAsBefore()
    {
        IReadOnlyList<DockerLogBatch> batches = SameAsLegacy((container, reader) =>
        {
            System.IO.File.WriteAllText(container.LogPath, First + Entry("second record\n"));
            DockerLogBatch both = reader.Read(null, Replay);
            Truncate(container.LogPath, First.Length);
            // Back to the cursor's length and beyond after the open took the truncated length.
            DockerLogBatch read = reader.Read(both.Cursor, Replay, beforePrefixRead: path =>
                System.IO.File.AppendAllText(path, Entry("other record!\n") + Entry("newest record\n")));
            return [both, read];
        });

        // As the reader always did: at least as long as the cursor is not truncated.
        Assert.False(batches[1].RotationGap);
        Assert.Equal("newest record", Assert.Single(batches[1].Records).Text);
    }

    [Fact]
    public void StartAtEnd_StartsAfterARecordAppendedWhileTheIdentityIsRead()
    {
        IReadOnlyList<DockerLogBatch> batches = SameAsLegacy((container, reader) =>
        {
            System.IO.File.WriteAllText(container.LogPath, First + Entry("history\n"));
            DockerLogBatch start = reader.Read(null, new DockerLogReaderOptions(), beforePrefixRead: path =>
                System.IO.File.AppendAllText(path, Entry("written while the identity is read\n")));
            // After the record appended during the open, not before it.
            Assert.Equal(new FileInfo(container.LogPath).Length, start.Cursor.Offset);
            System.IO.File.AppendAllText(container.LogPath, Entry("written after the start\n"));
            return [start, reader.Read(start.Cursor, new DockerLogReaderOptions())];
        });

        Assert.Equal("written after the start", Assert.Single(batches[1].Records).Text);
    }

    [Fact]
    public void FileRewrittenAfterItsIdentityIsRead_IsReadAsItIsThen()
    {
        IReadOnlyList<DockerLogBatch> batches = SameAsLegacy((container, reader) =>
        {
            System.IO.File.WriteAllText(container.LogPath, First + Entry("second record\n"));
            DockerLogBatch one = reader.Read(null, Replay with { MaximumRecordsPerBatch = 1 });
            // Rewritten in place past the cursor, same length, once the identity was read.
            DockerLogBatch read = reader.Read(one.Cursor, Replay, afterOpen: path =>
            {
                Truncate(path, First.Length);
                System.IO.File.AppendAllText(path, Entry("other record!\n"));
            });
            return [one, read];
        });

        Assert.Equal("other record!", Assert.Single(batches[1].Records).Text);
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
    public void ShortReadsFromTheFilesystem_GiveTheSameIdentityAndStartPosition()
    {
        // FUSE or a network filesystem returning 7 bytes per read, before the end of the file.
        FileTailHandle.ShortReads = 7;
        try
        {
            IReadOnlyList<DockerLogBatch> batches = SameAsLegacy((container, reader) =>
            {
                string unfinished = Entry("unfinished " + new string('x', 5_000) + "\n");
                // The start-at-end scan crosses more than one 4 KiB block of the unfinished entry.
                System.IO.File.WriteAllText(container.LogPath, First + Entry("history\n") + unfinished[..^1]);
                DockerLogBatch start = reader.Read(null, new DockerLogReaderOptions());
                System.IO.File.AppendAllText(container.LogPath, "\n" + Entry("after the start\n"));
                return [start, reader.Read(start.Cursor, new DockerLogReaderOptions())];
            });

            Assert.Equal(
                ["unfinished " + new string('x', 5_000), "after the start"],
                batches[1].Records.Select(record => record.Text));
        }
        finally
        {
            FileTailHandle.ShortReads = null;
        }
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

    private static void Truncate(string path, long length)
    {
        using FileStream file = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        file.SetLength(length);
    }

    /// <summary>
    /// Runs the scenario on the frozen reader and on the current one, each in its own
    /// directory: every batch (records, cursor, its JSON and counters) must be identical.
    /// </summary>
    private static IReadOnlyList<DockerLogBatch> SameAsLegacy(Func<DockerContainer, Reader, IReadOnlyList<DockerLogBatch>> scenario)
    {
        IReadOnlyList<DockerLogBatch> Run(bool legacy)
        {
            using TemporaryDirectory root = new();
            DockerContainer container = DockerFixture.Catalogued(root);
            return scenario(container, new Reader(legacy, container));
        }

        IReadOnlyList<DockerLogBatch> expected = Run(legacy: true);
        IReadOnlyList<DockerLogBatch> actual = Run(legacy: false);
        Assert.Equal(expected.Count, actual.Count);
        for (int index = 0; index < expected.Count; index++)
        {
            // Compared without what the old reader did not have (see DockerReaderDifferentialTests).
            Assert.Equal(expected[index].Records, actual[index].Records.Select(DockerReaderDifferentialTests.Unresumed));
            Assert.Equal(expected[index].Cursor, DockerReaderDifferentialTests.Legacy(actual[index].Cursor));
            Assert.Equal(expected[index].Cursor.Serialize(), DockerReaderDifferentialTests.Legacy(actual[index].Cursor).Serialize());
            Assert.Equal(
                (expected[index].Malformed, expected[index].Oversized, expected[index].RotationGap),
                (actual[index].Malformed, actual[index].Oversized, actual[index].RotationGap));
        }

        return actual;
    }

    /// <summary>One reader, the frozen one or the current one, with its identity-read hooks set for a single read.</summary>
    private sealed class Reader(bool legacy, DockerContainer container)
    {
        public DockerLogBatch Read(
            DockerLogCursor? cursor,
            DockerLogReaderOptions options,
            Action<string>? beforePrefixRead = null,
            Action<string>? afterOpen = null)
        {
            try
            {
                if (legacy)
                {
                    LegacyDockerJsonLogReader.BeforePrefixRead = beforePrefixRead;
                    LegacyDockerJsonLogReader.AfterOpen = afterOpen;
                    return LegacyDockerJsonLogReader.Read(container, cursor, options);
                }

                FileTailHandle.BeforePrefixRead = beforePrefixRead;
                FileTailHandle.AfterOpen = afterOpen;
                return DockerJsonLogReader.Read(container, cursor, options);
            }
            finally
            {
                LegacyDockerJsonLogReader.BeforePrefixRead = null;
                LegacyDockerJsonLogReader.AfterOpen = null;
                FileTailHandle.BeforePrefixRead = null;
                FileTailHandle.AfterOpen = null;
            }
        }
    }
}
