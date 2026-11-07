using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Source.Docker;

namespace Bower.UnitTests;

public sealed class DockerSourceTests
{
    [Fact]
    public void Catalog_ReturnsOnlyOptedInJsonFileContainers()
    {
        using TemporaryDirectory root = new();
        DockerFixture.Container(root, "a", "web", collect: true);
        DockerFixture.Container(root, "b", "db", collect: false);
        DockerFixture.Container(root, "c", "journald-app", collect: true, driver: "journald");
        Directory.CreateDirectory(Path.Combine(root.Path, "not-a-container"));
        string broken = DockerFixture.Container(root, "d", "broken", collect: true);
        File.WriteAllText(Path.Combine(broken, "config.v2.json"), "{not json");

        DockerCatalogResult result = DockerContainerCatalog.Discover(new DockerCatalogOptions { Root = root.Path });

        DockerContainer container = Assert.Single(result.Containers);
        Assert.Equal("web", container.Name);
        Assert.Equal("example/web:1", container.Image);
        Assert.Equal(1, result.Skipped);
    }

    [Fact]
    public void Catalog_FailsClearlyWhenRootIsNotMounted()
    {
        DirectoryNotFoundException error = Assert.Throws<DirectoryNotFoundException>(() =>
            DockerContainerCatalog.Discover(new DockerCatalogOptions { Root = "/definitely/not/mounted" }));

        Assert.Contains("read-only", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Reader_StartsAtEndByDefaultAndReadsOnlyNewCompleteLines()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "history before the sidecar started\n");

        DockerLogBatch first = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions());
        DockerFixture.Append(container, "new line\n");
        DockerFixture.AppendRaw(container, """{"log":"half written""");
        DockerLogBatch second = DockerJsonLogReader.Read(container, first.Cursor, new DockerLogReaderOptions());

        Assert.Empty(first.Records);
        DockerLogRecord record = Assert.Single(second.Records);
        Assert.Equal("new line", record.Text);
        Assert.Equal(record.EndOffset, second.Cursor.Offset);
    }

    [Fact]
    public void Reader_StartsAtEndBeforeLongUnterminatedTail()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "history\n");
        long lastLineEnd = new FileInfo(container.LogPath).Length;
        // Longer than the backwards scan block, so the newline sits in an earlier block.
        DockerFixture.AppendRaw(container, "{\"log\":\"" + new string('x', 10_000));

        DockerLogBatch first = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions());

        Assert.Empty(first.Records);
        Assert.Equal(lastLineEnd, first.Cursor.Offset);
    }

    [Fact]
    public void Reader_StartsAtZeroWhenNoLineIsComplete()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.AppendRaw(container, "{\"log\":\"" + new string('x', 9_000));

        DockerLogBatch first = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions());

        Assert.Equal(0, first.Cursor.Offset);
    }

    [Fact]
    public void Reader_ReplaysHistoryWhenConfigured()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "one\n", "two\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(
            container, null, new DockerLogReaderOptions { StartAtEnd = false });

        Assert.Equal(["one", "two"], batch.Records.Select(item => item.Text));
    }

    [Fact]
    public void Reader_JoinsDockerPartialChunksIntoOneLine()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.Append(container, "first half ", "second half\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, new DockerLogReaderOptions());

        Assert.Equal("first half second half", Assert.Single(batch.Records).Text);
    }

    [Fact]
    public void Reader_LeavesUnfinishedChunkedLineForNextRead()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.Append(container, "done\n", "chunk without end ");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, new DockerLogReaderOptions());
        DockerFixture.Append(container, "and its end\n");
        DockerLogBatch next = DockerJsonLogReader.Read(container, batch.Cursor, new DockerLogReaderOptions());

        Assert.Equal("done", Assert.Single(batch.Records).Text);
        Assert.Equal("chunk without end and its end", Assert.Single(next.Records).Text);
    }

    [Fact]
    public void Reader_SkipsMalformedAndOversizedLinesButAdvances()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.AppendRaw(container, "{broken json\n");
        DockerFixture.AppendRaw(container, "[1,2,3]\n");
        DockerFixture.Append(container, new string('x', 5_000) + "\n");
        DockerFixture.Append(container, "kept\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(
            container, start, new DockerLogReaderOptions { MaximumLineBytes = 1_024 });

        Assert.Equal("kept", Assert.Single(batch.Records).Text);
        Assert.Equal(2, batch.Malformed);
        Assert.Equal(1, batch.Oversized);
        Assert.Equal(new FileInfo(container.LogPath).Length, batch.Cursor.Offset);
    }

    [Fact]
    public void Reader_DiscardsOversizedLineAcrossByteBudgetsThenEmitsNextRecordOnce()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor cursor = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 12, chunkLength: 1_000);
        DockerFixture.Append(container, "Failed password for root from 203.0.113.5 port 22 ssh2\n");
        DockerLogReaderOptions options = new() { MaximumLineBytes = 1_024, MaximumBytesPerBatch = 3_000 };
        long maximumEntryBytes = options.MaximumLineBytes * 2 + 4_096 + 1;

        List<DockerLogRecord> records = [];
        int oversized = 0, polls = 0;
        while (polls++ < 50)
        {
            DockerLogBatch batch = DockerJsonLogReader.Read(container, cursor, options);
            Assert.DoesNotContain("xxxx", batch.Cursor.Serialize(), StringComparison.Ordinal);
            Assert.True(batch.Cursor.Offset - cursor.Offset <= options.MaximumBytesPerBatch + maximumEntryBytes);
            records.AddRange(batch.Records);
            oversized += batch.Oversized;
            if (batch.Cursor == cursor)
            {
                break;
            }

            Assert.True(batch.Cursor.Offset > cursor.Offset);
            cursor = batch.Cursor;
        }

        Assert.True(polls > 3);
        Assert.Equal("Failed password for root from 203.0.113.5 port 22 ssh2", Assert.Single(records).Text);
        Assert.Equal(1, oversized);
        Assert.False(cursor.Discarding);
        Assert.Equal(new FileInfo(container.LogPath).Length, cursor.Offset);
    }

    [Fact]
    public void Reader_KeepsForwardProgressWhenRestartedMidDiscard()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 12, chunkLength: 1_000);
        DockerFixture.Append(container, "kept\n");
        DockerLogReaderOptions options = new() { MaximumLineBytes = 1_024, MaximumBytesPerBatch = 3_000 };

        DockerLogBatch first = DockerJsonLogReader.Read(container, start, options);
        string persisted = first.Cursor.Serialize();
        DockerLogCursor restored = DockerLogCursor.Deserialize(persisted)!;

        Assert.Empty(first.Records);
        Assert.Equal(0, first.Oversized);
        Assert.True(restored.Discarding);
        Assert.True(restored.Offset > start.Offset);
        Assert.DoesNotContain("xxxx", persisted, StringComparison.Ordinal);

        List<DockerLogRecord> records = [];
        int oversized = 0;
        DockerLogCursor cursor = restored;
        for (int poll = 0; poll < 50 && records.Count == 0; poll++)
        {
            // Every poll is a fresh process reading the persisted cursor.
            DockerLogBatch batch = DockerJsonLogReader.Read(container, DockerLogCursor.Deserialize(cursor.Serialize()), options);
            Assert.True(batch.Cursor.Offset > cursor.Offset);
            records.AddRange(batch.Records);
            oversized += batch.Oversized;
            cursor = batch.Cursor;
        }

        Assert.Equal("kept", Assert.Single(records).Text);
        Assert.Equal(1, oversized);
        Assert.Empty(DockerJsonLogReader.Read(container, cursor, options).Records);
    }

    [Fact]
    public void Reader_SkipsLineWhoseChunksExceedTheByteBudget()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor cursor = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        // Under the line limit, but its chunks span more than one byte budget.
        DockerFixture.AppendOversizedLine(container, chunks: 6, chunkLength: 1_000);
        DockerFixture.Append(container, "kept\n");
        DockerLogReaderOptions options = new() { MaximumBytesPerBatch = 2_000 };

        List<DockerLogRecord> records = [];
        int oversized = 0;
        for (int poll = 0; poll < 50 && records.Count == 0; poll++)
        {
            DockerLogBatch batch = DockerJsonLogReader.Read(container, cursor, options);
            Assert.True(batch.Cursor.Offset > cursor.Offset);
            records.AddRange(batch.Records);
            oversized += batch.Oversized;
            cursor = batch.Cursor;
        }

        Assert.Equal("kept", Assert.Single(records).Text);
        Assert.Equal(1, oversized);
    }

    [Fact]
    public void Reader_WaitsForUnfinishedEntryWhileDiscarding()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 3, chunkLength: 1_000, terminate: false);
        long unfinishedStart = new FileInfo(container.LogPath).Length;
        DockerFixture.AppendRaw(container, "{\"log\":\"tail of the oversized line");
        DockerLogReaderOptions options = new() { MaximumLineBytes = 1_024 };

        DockerLogBatch waiting = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch again = DockerJsonLogReader.Read(container, waiting.Cursor, options);
        DockerFixture.AppendRaw(container, "\\n\",\"stream\":\"stdout\"}\n");
        DockerFixture.Append(container, "kept\n");
        DockerLogBatch finished = DockerJsonLogReader.Read(container, again.Cursor, options);

        Assert.Empty(waiting.Records);
        Assert.Equal(0, waiting.Oversized);
        Assert.True(waiting.Cursor.Discarding);
        Assert.Equal(unfinishedStart, waiting.Cursor.Offset);
        Assert.Equal(waiting.Cursor, again.Cursor);
        Assert.Equal("kept", Assert.Single(finished.Records).Text);
        Assert.Equal(1, finished.Oversized);
        Assert.False(finished.Cursor.Discarding);
    }

    [Fact]
    public void Reader_CountsMalformedEntriesWhileDiscarding()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "seed\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 3, chunkLength: 1_000, terminate: false);
        DockerFixture.AppendRaw(container, "{broken json\n");
        DockerFixture.Append(container, "end\n", "kept\n");
        DockerLogReaderOptions options = new() { MaximumLineBytes = 1_024, MaximumBytesPerBatch = 2_000 };

        int malformed = 0, oversized = 0;
        List<DockerLogRecord> records = [];
        DockerLogCursor cursor = start;
        for (int poll = 0; poll < 50 && records.Count == 0; poll++)
        {
            DockerLogBatch batch = DockerJsonLogReader.Read(container, cursor, options);
            Assert.True(batch.Cursor.Offset > cursor.Offset);
            malformed += batch.Malformed;
            oversized += batch.Oversized;
            records.AddRange(batch.Records);
            cursor = batch.Cursor;
        }

        Assert.Equal("kept", Assert.Single(records).Text);
        Assert.Equal(1, malformed);
        Assert.Equal(1, oversized);
    }

    [Fact]
    public void Reader_CarriesDiscardAcrossRotation()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "before rotation\n");
        DockerLogCursor start = DockerJsonLogReader.Read(
            container, null, new DockerLogReaderOptions { StartAtEnd = false }).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 3, chunkLength: 1_000, terminate: false);
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "rest of the oversized line written after rotation\n", "kept\n");
        DockerLogReaderOptions options = new() { MaximumLineBytes = 1_024 };

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.Empty(rotated.Records);
        Assert.False(rotated.RotationGap);
        Assert.True(rotated.Cursor.Discarding);
        Assert.Equal(0, rotated.Cursor.Offset);
        Assert.Equal("kept", Assert.Single(current.Records).Text);
        Assert.Equal(1, current.Oversized);
        Assert.False(current.RotationGap);
    }

    [Fact]
    public void Reader_ClosesLineSplitAcrossRotationAndReadsTheWholeNewFile()
    {
        // Docker rotated between two chunks of one line: .1 ends with an unfinished line it
        // never completes. The old reader waited on it until the new file was rotated away.
        // Now the head is emitted as it stood in .1 and the rest is read from the new file as a
        // separate fragment record: no gap, nothing after it lost.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "file A line one\n", "first chunk of a split line ");
        DockerLogBatch first = DockerJsonLogReader.Read(container, null, options);
        string fileA = first.Cursor.Fingerprint;
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "rest of the split line\n", "file B line one\n", "file B line two\n");

        List<DockerLogBatch> polls = Poll(container, first.Cursor, options, 5);
        File.Move(container.LogPath, container.LogPath + ".1", overwrite: true);
        DockerFixture.Append(container, "file C line one\n");
        List<DockerLogBatch> after = Poll(container, polls[^1].Cursor, options, 2);
        List<DockerLogRecord> records = [.. polls.Concat(after).SelectMany(batch => batch.Records)];

        Assert.Equal("file A line one", Assert.Single(first.Records).Text);
        Assert.Equal(
            ["first chunk of a split line ", "rest of the split line", "file B line one", "file B line two", "file C line one"],
            records.Select(record => record.Text));
        Assert.Equal((fileA, first.Cursor.Offset), (records[0].FileFingerprint, records[0].StartOffset));
        Assert.NotEqual(fileA, records[1].FileFingerprint);
        Assert.Equal(0, records[1].StartOffset);
        Assert.Equal(1, polls.Sum(batch => batch.ClosedAtRotation));
        Assert.Equal(0, after.Sum(batch => batch.ClosedAtRotation));
        Assert.DoesNotContain(polls.Concat(after), batch => batch.RotationGap || batch.Malformed > 0 || batch.Oversized > 0);
    }

    [Fact]
    public void Reader_ClosesLineSplitAtTheVeryEndOfRotatedFile()
    {
        // The cursor is already at the last entry of .1, a partial chunk, and the new file
        // starts with nothing but the line's terminating chunk, read as an empty fragment.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "a line long enough to fingerprint the file\n", "partial chunk at the very end ");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "\n", "first whole line in the new file\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.Equal("partial chunk at the very end ", Assert.Single(rotated.Records).Text);
        Assert.Equal((0L, false, false, 1), (rotated.Cursor.Offset, rotated.Cursor.Discarding, rotated.RotationGap, rotated.ClosedAtRotation));
        Assert.NotEqual(start.Fingerprint, rotated.Cursor.Fingerprint);
        Assert.Equal(["", "first whole line in the new file"], current.Records.Select(record => record.Text));
        Assert.Equal((0, 0, false), (current.Oversized, current.ClosedAtRotation, current.RotationGap));
    }

    [Fact]
    public void Reader_ClosesLineSplitAcrossRotationInSeveralChunks()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before rotation\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.Append(container, "kept before the split\n", "chunk one ", "chunk two ", "chunk three ");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "chunk four ", "chunk five ", "last chunk\n", "kept after the split\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.Equal(["kept before the split", "chunk one chunk two chunk three "], rotated.Records.Select(record => record.Text));
        Assert.False(rotated.Cursor.Discarding);
        Assert.Equal(["chunk four chunk five last chunk", "kept after the split"], current.Records.Select(record => record.Text));
        Assert.Equal((0, 0), (rotated.Oversized, current.Oversized));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void Reader_DeliversInterleavedStderrLineAfterStdoutLineSplitByRotation()
    {
        // Docker copies stdout and stderr into the same file concurrently: a complete stderr
        // line can sit between the two halves of a stdout line split by rotation.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.Append(container, "stdout first half ");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.AppendFrom(container, "stderr", "a complete stderr line\n");
        DockerFixture.Append(container, "stdout second half\n", "after\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.Equal(("stdout first half ", "stdout"), Only(rotated));
        Assert.Equal(
            [("a complete stderr line", "stderr"), ("stdout second half", "stdout"), ("after", "stdout")],
            current.Records.Select(record => (record.Text, record.Stream)));
        Assert.Equal((0, 0, 0), (rotated.Oversized + current.Oversized, rotated.Malformed + current.Malformed, current.ClosedAtRotation));
        Assert.Equal(1, rotated.ClosedAtRotation);
        Assert.False(rotated.RotationGap || current.RotationGap);

        static (string, string) Only(DockerLogBatch batch)
        {
            DockerLogRecord record = Assert.Single(batch.Records);
            return (record.Text, record.Stream);
        }
    }

    [Fact]
    public void Reader_DeliversFreshFirstLineAfterAStreamEndedWithoutNewline()
    {
        // Docker's copier writes what is left at stream end (container stop) as an entry with
        // no newline, and no continuation follows. After a restart and a rotation, the new
        // file's first entry is a fresh line and must be delivered.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before the container stopped, long enough\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.Append(container, "goodbye without a newline");
        DockerLogBatch stopped = DockerJsonLogReader.Read(container, start, options);
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "fresh first line after the restart\n", "second line\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, stopped.Cursor, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        // Before the rotation the reader cannot know the line is over, so it waits.
        Assert.Empty(stopped.Records);
        Assert.Equal(start, stopped.Cursor);
        Assert.Equal("goodbye without a newline", Assert.Single(rotated.Records).Text);
        Assert.Equal(["fresh first line after the restart", "second line"], current.Records.Select(record => record.Text));
        Assert.Equal((0, 0), (rotated.Oversized + current.Oversized, rotated.Malformed + current.Malformed));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void Reader_ClosesSplitLineAcrossRestartsBetweenPolls()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n", "chunk one ");
        DockerLogBatch waiting = DockerJsonLogReader.Read(container, null, options);
        // A restart: the cursor comes back from the store, still on the unfinished line.
        DockerLogCursor restored = Restart(waiting.Cursor);
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "chunk two of the split line, written after the rotation ");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, restored, options);
        // Another restart between leaving .1 and reading the new file.
        DockerLogCursor moved = Restart(rotated.Cursor);
        DockerFixture.Append(container, "last chunk\n", "kept after the restart\n");
        DockerLogBatch resumed = DockerJsonLogReader.Read(container, moved, options);

        Assert.Equal("before rotation, long enough to fingerprint", Assert.Single(waiting.Records).Text);
        Assert.Equal("chunk one ", Assert.Single(rotated.Records).Text);
        Assert.Equal((0L, false), (moved.Offset, moved.Discarding));
        Assert.Equal(
            ["chunk two of the split line, written after the rotation last chunk", "kept after the restart"],
            resumed.Records.Select(record => record.Text));
        Assert.Equal((0, 0, 0), (rotated.Oversized, resumed.Oversized, resumed.ClosedAtRotation));
        Assert.False(rotated.RotationGap || resumed.RotationGap);

        static DockerLogCursor Restart(DockerLogCursor cursor)
        {
            DockerLogCursor restored = DockerLogCursor.Deserialize(cursor.Serialize())!;
            Assert.Equal(cursor, restored);
            return restored;
        }
    }

    [Fact]
    public void Reader_ClosesSplitLineOnceWhenTheRecordLimitIsReachedAtTheEndOfRotatedFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false, MaximumRecordsPerBatch = 1 };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.Append(container, "open line ");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "new file line\n");

        List<DockerLogBatch> polls = Poll(container, start, options, 4);

        Assert.Equal(["open line ", "new file line"], polls.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal(1, polls.Sum(batch => batch.ClosedAtRotation));
        Assert.DoesNotContain(polls, batch => batch.RotationGap);
    }

    [Fact]
    public void Reader_WaitsOnSplitLineUntilTheNewFileCanBeIdentified()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n", "chunk one ");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;

        // Not rotated: the line is still being written, so the reader waits on it.
        DockerLogBatch unrotated = DockerJsonLogReader.Read(container, start, options);
        File.Move(container.LogPath, container.LogPath + ".1");
        // Rotated, but no new file yet, then one too short to identify.
        DockerLogBatch missing = DockerJsonLogReader.Read(container, start, options);
        DockerFixture.AppendRaw(container, "{\"log\":\"x\\n\"}\n");
        DockerLogBatch tooShort = DockerJsonLogReader.Read(container, start, options);
        DockerFixture.Append(container, "the new file, now long enough to identify\n");
        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        foreach (DockerLogBatch waiting in new[] { unrotated, missing, tooShort })
        {
            Assert.Empty(waiting.Records);
            Assert.Equal(start, waiting.Cursor);
            Assert.False(waiting.RotationGap);
        }

        Assert.Equal("chunk one ", Assert.Single(rotated.Records).Text);
        Assert.False(rotated.Cursor.Discarding);
        // The new file is read from its start: its first entry ends the split line, as a fragment.
        Assert.Equal(["x", "the new file, now long enough to identify"], current.Records.Select(record => record.Text));
        Assert.Equal((0, false), (current.Oversized, current.RotationGap));
    }

    [Fact]
    public void Reader_CountsTornEntryAtTheEndOfRotatedFileAndReadsTheNewFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendRaw(container, "{\"log\":\"torn en");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "first line of the new file\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.Empty(rotated.Records);
        Assert.Equal((1, 0, false, 0L), (rotated.Malformed, rotated.ClosedAtRotation, rotated.Cursor.Discarding, rotated.Cursor.Offset));
        Assert.Equal("first line of the new file", Assert.Single(current.Records).Text);
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void Reader_ClosesOpenLineBeforeATornEntryAtTheEndOfRotatedFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.Append(container, "open chunk ");
        DockerFixture.AppendRaw(container, "{\"log\":\"torn en");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "first line of the new file\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.Equal("open chunk ", Assert.Single(rotated.Records).Text);
        Assert.Equal((1, 1, false), (rotated.Malformed, rotated.ClosedAtRotation, rotated.Cursor.Discarding));
        Assert.Equal("first line of the new file", Assert.Single(current.Records).Text);
    }

    [Fact]
    public void Reader_KeepsCarryingTheDiscardOfALineAlreadyOversizedAtTheEndOfRotatedFile()
    {
        // The line went over the limit in an earlier poll, before the rotation: it is never
        // emitted, its discard is carried into the new file, and it is counted once there.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false, MaximumLineBytes = 1_024 };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 3, chunkLength: 1_000, terminate: false);
        DockerLogBatch discarding = DockerJsonLogReader.Read(container, start, options);
        DockerFixture.AppendOversizedLine(container, chunks: 1, chunkLength: 10, terminate: false);
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "rest of the oversized line\n", "kept\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, discarding.Cursor, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.True(discarding.Cursor.Discarding);
        Assert.Empty(rotated.Records);
        Assert.Equal((0L, true, 0), (rotated.Cursor.Offset, rotated.Cursor.Discarding, rotated.ClosedAtRotation));
        Assert.Equal("kept", Assert.Single(current.Records).Text);
        Assert.Equal((0, 1), (rotated.Oversized, current.Oversized));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void Reader_KeepsCarryingTheDiscardOfALineThatFillsTheByteBudgetAtTheEndOfRotatedFile()
    {
        // Within the line limit, but its chunks fill a whole pass's byte budget: discarded as
        // before, not closed at the rotation.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = new() { StartAtEnd = false, MaximumBytesPerBatch = 200 };
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 5, chunkLength: 60, terminate: false);
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "rest of the long line\n", "kept\n");

        List<DockerLogBatch> polls = Poll(container, start, options, 5);

        Assert.Equal(["kept"], polls.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal((1, 0), (polls.Sum(batch => batch.Oversized), polls.Sum(batch => batch.ClosedAtRotation)));
        Assert.DoesNotContain(polls, batch => batch.RotationGap);
    }

    private static List<DockerLogBatch> Poll(DockerContainer container, DockerLogCursor cursor, DockerLogReaderOptions options, int count)
    {
        List<DockerLogBatch> batches = [];
        for (int poll = 0; poll < count; poll++)
        {
            batches.Add(DockerJsonLogReader.Read(container, batches.Count == 0 ? cursor : batches[^1].Cursor, options));
        }

        return batches;
    }

    [Fact]
    public void Reader_ClearsDiscardAfterTruncation()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "a line long enough to fingerprint the file\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 3, chunkLength: 1_000, terminate: false);
        DockerLogBatch discarding = DockerJsonLogReader.Read(
            container, start, new DockerLogReaderOptions { MaximumLineBytes = 1_024 });
        byte[] firstEntry = File.ReadAllLines(container.LogPath)[0].Select(c => (byte)c).Append((byte)'\n').ToArray();
        File.WriteAllBytes(container.LogPath, firstEntry);

        DockerLogBatch batch = DockerJsonLogReader.Read(
            container, discarding.Cursor, new DockerLogReaderOptions { MaximumLineBytes = 1_024 });

        Assert.True(discarding.Cursor.Discarding);
        Assert.True(batch.RotationGap);
        Assert.False(batch.Cursor.Discarding);
        Assert.Equal("a line long enough to fingerprint the file", Assert.Single(batch.Records).Text);
    }

    [Fact]
    public void Reader_RespectsRecordLimitAndResumes()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Enumerable.Range(0, 5).Select(index => $"line {index}\n").ToArray());
        DockerLogReaderOptions options = new() { StartAtEnd = false, MaximumRecordsPerBatch = 2 };

        DockerLogBatch first = DockerJsonLogReader.Read(container, null, options);
        DockerLogBatch second = DockerJsonLogReader.Read(container, first.Cursor, options);

        Assert.Equal(["line 0", "line 1"], first.Records.Select(item => item.Text));
        Assert.Equal(["line 2", "line 3"], second.Records.Select(item => item.Text));
    }

    [Fact]
    public void Reader_DrainsRotatedFileBeforeSwitchingToNewFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "before rotation\n");
        DockerLogCursor start = DockerJsonLogReader.Read(
            container, null, new DockerLogReaderOptions { StartAtEnd = false }).Cursor;
        DockerFixture.Append(container, "written just before rotation\n");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "first line after rotation\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, new DockerLogReaderOptions());
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, new DockerLogReaderOptions());

        Assert.Equal("written just before rotation", Assert.Single(rotated.Records).Text);
        Assert.False(rotated.RotationGap);
        Assert.Equal(0, rotated.Cursor.Offset);
        Assert.Equal("first line after rotation", Assert.Single(current.Records).Text);
    }

    [Fact]
    public void Reader_FlagsGapWhenRotatedFileIsAlreadyGone()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "old\n");
        DockerLogCursor start = DockerJsonLogReader.Read(
            container, null, new DockerLogReaderOptions { StartAtEnd = false }).Cursor;
        File.Delete(container.LogPath);
        DockerFixture.Append(container, "brand new file\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, new DockerLogReaderOptions());

        Assert.True(batch.RotationGap);
        Assert.Equal("brand new file", Assert.Single(batch.Records).Text);
    }

    [Fact]
    public void Reader_RestartsAfterTruncation()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "a line long enough to fingerprint the file\n", "second\n");
        DockerLogCursor end = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor;
        byte[] firstEntry = File.ReadAllLines(container.LogPath)[0].Select(c => (byte)c).Append((byte)'\n').ToArray();
        File.WriteAllBytes(container.LogPath, firstEntry);

        DockerLogBatch batch = DockerJsonLogReader.Read(container, end, new DockerLogReaderOptions());

        Assert.True(batch.RotationGap);
        Assert.Equal("a line long enough to fingerprint the file", Assert.Single(batch.Records).Text);
    }

    [Fact]
    public void Cursor_RoundTripsAndRejectsGarbage()
    {
        DockerLogCursor cursor = new(DockerLogCursor.CurrentSchemaVersion, "abc", 42);

        Assert.Equal(cursor, DockerLogCursor.Deserialize(cursor.Serialize()));
        Assert.Null(DockerLogCursor.Deserialize("{not json"));
        Assert.Null(DockerLogCursor.Deserialize("""{"schemaVersion":9,"fingerprint":"a","offset":1}"""));
        Assert.Null(DockerLogCursor.Deserialize("""{"schemaVersion":1,"fingerprint":"a","offset":-1}"""));
    }

    [Fact]
    public void Cursor_DiscardFlagIsAdditive()
    {
        const string legacy = """{"schemaVersion":1,"fingerprint":"abc","offset":42}""";
        DockerLogCursor discarding = new(DockerLogCursor.CurrentSchemaVersion, "abc", 42, Discarding: true);

        Assert.Equal(new DockerLogCursor(1, "abc", 42), DockerLogCursor.Deserialize(legacy));
        Assert.Equal(legacy, new DockerLogCursor(1, "abc", 42).Serialize());
        Assert.Equal(discarding, DockerLogCursor.Deserialize(discarding.Serialize()));
        Assert.Contains("\"discarding\":true", discarding.Serialize(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Failed password for root from 203.0.113.5 port 22 ssh2", "authentication_failure", "root", "203.0.113.5")]
    [InlineData("Failed password for invalid user admin from 198.51.100.9 port 4242 ssh2", "authentication_failure", "admin", "198.51.100.9")]
    [InlineData("Invalid user oracle from 192.0.2.44 port 50022", "authentication_failure", "oracle", "192.0.2.44")]
    [InlineData("error: maximum authentication attempts exceeded for root from 203.0.113.5 port 22 ssh2 [preauth]", "account_lockout", "root", "203.0.113.5")]
    [InlineData("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=deploy", "authentication_failure", "deploy", "203.0.113.7")]
    [InlineData("2026/10/07 10:00:00 [error] 29#29: *1 user \"alice\": password mismatch, client: 192.0.2.10, server: _", "authentication_failure", "alice", "192.0.2.10")]
    public void Mapper_RecognisesAuthenticationSignals(string line, string eventType, string user, string ip)
    {
        DockerContainer container = DockerFixture.InMemory();
        DockerLogRecord record = new(line, "stderr", TestEvents.Now, "fingerprint", 100, 200);

        DockerMappedEvent mapped = Mapper().Map(container, record, TestEvents.Now);

        Assert.Equal(DockerMappingKind.RecognisedSignal, mapped.Kind);
        SecurityEventEnvelope envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(mapped.Json!, BowerJson.Options)!;
        Assert.Equal(eventType, envelope.EventType);
        Assert.Equal(user, envelope.Actor?.Username);
        Assert.Equal(ip, envelope.Source?.IpAddress);
        Assert.Equal("web", envelope.Application.Name);
        Assert.DoesNotContain(line, mapped.Json!, StringComparison.Ordinal);
    }

    [Fact]
    public void Mapper_UsesStableIdsForTheSameBytes()
    {
        DockerContainer container = DockerFixture.InMemory();
        DockerLogRecord record = new("Invalid user x from 192.0.2.1", "stdout", null, "fp", 10, 50);

        string first = Mapper().Map(container, record, TestEvents.Now).Json!;
        string replay = Mapper().Map(container, record, TestEvents.Now.AddHours(1)).Json!;

        Assert.Equal(EventId(first), EventId(replay));
        Assert.NotEqual(EventId(first), EventId(Mapper().Map(container, record with { StartOffset = 11 }, TestEvents.Now).Json!));
    }

    [Fact]
    public void Mapper_PassesThroughBowerEnvelopesWithContainerLabels()
    {
        DockerContainer container = DockerFixture.InMemory();
        string line = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(TestEvents.Now), BowerJson.Options);

        DockerMappedEvent mapped = Mapper().Map(container, new DockerLogRecord(line, "stdout", null, "fp", 0, 1), TestEvents.Now);

        Assert.Equal(DockerMappingKind.SemanticEvent, mapped.Kind);
        SecurityEventEnvelope envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(mapped.Json!, BowerJson.Options)!;
        Assert.Equal("event-1", envelope.EventId);
        Assert.Equal("web", envelope.Labels!["docker.containerName"]);
    }

    [Theory]
    [InlineData("GET /index.html 200")]
    [InlineData("{\"level\":\"info\",\"msg\":\"started\"}")]
    [InlineData("{not json at all")]
    [InlineData("   ")]
    public void Mapper_DropsUnrecognisedLines(string line)
    {
        DockerMappedEvent mapped = Mapper().Map(
            DockerFixture.InMemory(),
            new DockerLogRecord(line, "stdout", null, "fp", 0, 1),
            TestEvents.Now);

        Assert.Equal(DockerMappingKind.Unrecognised, mapped.Kind);
        Assert.Null(mapped.Json);
    }

    [Fact]
    public void Mapper_IgnoresInvalidAddressesAndUsesLabels()
    {
        DockerContainer container = DockerFixture.InMemory() with
        {
            Labels = new Dictionary<string, string>
            {
                ["bower.collect"] = "true",
                ["bower.application"] = "customer-portal",
                ["bower.environment"] = "staging"
            }
        };

        string json = Mapper().Map(
            container,
            new DockerLogRecord("Invalid user bob from ::ffff::bad:::1 port 1", "stdout", null, "fp", 0, 1),
            TestEvents.Now).Json!;
        SecurityEventEnvelope envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(json, BowerJson.Options)!;

        Assert.Null(envelope.Source);
        Assert.Equal("customer-portal", envelope.Application.Name);
        Assert.Equal("staging", envelope.Application.Environment);
    }

    private static DockerLogEventMapper Mapper() => new(new DockerMapperOptions { SidecarId = "sidecar-test" });

    private static string EventId(string json) =>
        JsonDocument.Parse(json).RootElement.GetProperty("eventId").GetString()!;
}

internal static class DockerFixture
{
    public static string Container(
        TemporaryDirectory root,
        string seed,
        string name,
        bool collect,
        string driver = "json-file")
    {
        string id = IdFor(seed);
        string directory = Path.Combine(root.Path, id);
        Directory.CreateDirectory(directory);
        File.WriteAllText(
            Path.Combine(directory, "config.v2.json"),
            JsonSerializer.Serialize(new
            {
                ID = id,
                Name = "/" + name,
                Config = new
                {
                    Image = "example/" + name + ":1",
                    Labels = collect
                        ? new Dictionary<string, string> { ["bower.collect"] = "true" }
                        : new Dictionary<string, string> { ["other"] = "x" }
                }
            }));
        File.WriteAllText(
            Path.Combine(directory, "hostconfig.json"),
            JsonSerializer.Serialize(new { LogConfig = new { Type = driver } }));
        return directory;
    }

    public static DockerContainer Catalogued(TemporaryDirectory root)
    {
        Container(root, "a", "web", collect: true);
        return Assert.Single(DockerContainerCatalog.Discover(new DockerCatalogOptions { Root = root.Path }).Containers);
    }

    public static DockerContainer InMemory() =>
        new(IdFor("a"), "web", "example/web:1", "/tmp/none",
            new Dictionary<string, string> { ["bower.collect"] = "true" });

    public static void Append(DockerContainer container, params string[] logs) => AppendFrom(container, "stdout", logs);

    public static void AppendFrom(DockerContainer container, string stream, params string[] logs)
    {
        StringBuilder text = new();
        foreach (string log in logs)
        {
            text.Append(JsonSerializer.Serialize(new { log, stream, time = "2026-10-07T10:00:00.123456789Z" }));
            text.Append('\n');
        }

        File.AppendAllText(container.LogPath, text.ToString());
    }

    /// <summary>One logical line as Docker writes it: partial chunks, then a terminating chunk.</summary>
    public static void AppendOversizedLine(DockerContainer container, int chunks, int chunkLength, bool terminate = true)
    {
        string[] logs = Enumerable.Repeat(new string('x', chunkLength), chunks).ToArray();
        Append(container, terminate ? [.. logs, "end\n"] : logs);
    }

    public static void AppendRaw(DockerContainer container, string raw) =>
        File.AppendAllText(container.LogPath, raw);

    private static string IdFor(string seed) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(seed)));
}
