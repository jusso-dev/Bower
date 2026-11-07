using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Source.Docker;
using Bower.Source.File;

namespace Bower.UnitTests;

/// <summary>
/// The Docker decoder keys a logical line on its stream and Docker time (moby's copier gives
/// every chunk of one line the same time, and each stream its own), and a line split by a
/// rotation is re-read from <c>.1</c> and joined with its rest. Each regression here failed on
/// the reader that joined and discarded entries without regard to their line: another
/// stream's entries were merged into an open line or swallowed by its discard, a line left
/// open at the end of <c>.1</c> was emitted as a whole line, and its rest was mapped on its own.
/// </summary>
public sealed class DockerLineIdentityTests
{
    private const string Before = "before rotation, long enough to fingerprint\n";

    private static readonly DockerLogReaderOptions Replay = new() { StartAtEnd = false };

    private static readonly string T0 = DockerFixture.Time(0);
    private static readonly string T1 = DockerFixture.Time(1);
    private static readonly string T2 = DockerFixture.Time(2);
    private static readonly string T3 = DockerFixture.Time(3);
    private static readonly string T4 = DockerFixture.Time(4);

    // ---- A line split across a rotation ----

    [Fact]
    public void LineSplitAcrossRotation_IsJoinedAndTheWholeNewFileIsRead()
    {
        // Docker rotated between two chunks of one line: .1 ends with a line it never
        // completes. The old reader waited on it until the new file was rotated away; the
        // round-2 reader emitted the head and the rest as two lines. Now the cursor moves to the
        // new file with the line open, re-reads its head from .1 and joins it with its rest.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "file A line one\n", "first chunk of a split line ");
        DockerLogBatch first = DockerJsonLogReader.Read(container, null, Replay);
        string fileA = first.Cursor.Fingerprint;
        Rotate(container);
        DockerFixture.Append(container, "rest of the split line\n", "file B line one\n", "file B line two\n");

        List<DockerLogBatch> polls = Poll(container, first.Cursor, Replay, 5);
        Rotate(container);
        DockerFixture.Append(container, "file C line one\n");
        List<DockerLogBatch> after = Poll(container, polls[^1].Cursor, Replay, 2);
        List<DockerLogRecord> records = [.. polls.Concat(after).SelectMany(batch => batch.Records)];

        Assert.Equal("file A line one", Assert.Single(first.Records).Text);
        Assert.Equal(
            ["first chunk of a split line rest of the split line", "file B line one", "file B line two", "file C line one"],
            records.Select(record => record.Text));
        Assert.Equal((fileA, first.Cursor.Offset), (records[0].FileFingerprint, records[0].StartOffset));
        Assert.NotEqual(fileA, records[1].FileFingerprint);
        Assert.Equal(1, polls.Sum(batch => batch.OpenAtRotation));
        Assert.Equal(0, after.Sum(batch => batch.OpenAtRotation));
        Assert.DoesNotContain(records, record => record.Fragment);
        Assert.DoesNotContain(polls.Concat(after), batch => batch.RotationGap || batch.Malformed > 0 || batch.Oversized > 0);
    }

    [Fact]
    public void LineSplitAtTheVeryEndOfRotatedFile_IsJoinedWithItsTerminatorInTheNewFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "a line long enough to fingerprint the file\n", "partial chunk at the very end ");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        Rotate(container);
        DockerFixture.Append(container, "\n", "first whole line in the new file\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        Assert.Equal((0L, false, false, 1), (rotated.Cursor.Offset, rotated.Cursor.Discarding, rotated.RotationGap, rotated.OpenAtRotation));
        Assert.NotEqual(start.Fingerprint, rotated.Cursor.Fingerprint);
        DockerPendingLine open = Assert.Single(rotated.Cursor.Pending!);
        Assert.Equal(("stdout", T0, start.Fingerprint, (long?)start.Offset, false), (open.Stream, open.Time, open.File, open.Start, open.Fragment));
        Assert.Equal(["partial chunk at the very end ", "first whole line in the new file"], current.Records.Select(record => record.Text));
        Assert.Equal((start.Fingerprint, start.Offset), (current.Records[0].FileFingerprint, current.Records[0].StartOffset));
        Assert.Equal((0, 0, false), (current.Oversized, current.OpenAtRotation, current.RotationGap));
        Assert.Null(current.Cursor.Pending);
    }

    [Fact]
    public void LineSplitAcrossRotationInSeveralChunks_IsJoined()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.Append(container, "kept before the split\n", "chunk one ", "chunk two ", "chunk three ");
        Rotate(container);
        DockerFixture.Append(container, "chunk four ", "chunk five ", "last chunk\n", "kept after the split\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Equal(["kept before the split"], rotated.Records.Select(record => record.Text));
        Assert.Equal(
            ["chunk one chunk two chunk three chunk four chunk five last chunk", "kept after the split"],
            current.Records.Select(record => record.Text));
        Assert.Equal((0, 0), (rotated.Oversized, current.Oversized));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void StderrEnvelopeBetweenTheHalvesOfAStdoutLineSplitByRotation_IsDeliveredIntact()
    {
        // A stdout continuation, a complete stderr Bower envelope, then the stdout last chunk,
        // after the rotation: the envelope was concatenated into the stdout line and lost.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "stdout first half ");
        Rotate(container);
        DockerFixture.AppendAt(container, "stdout", T1, "stdout middle ");
        DockerFixture.AppendAt(container, "stderr", T2, Envelope() + "\n");
        DockerFixture.AppendAt(container, "stdout", T1, "stdout second half\n");
        DockerFixture.AppendAt(container, "stdout", T3, "after\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        Assert.Equal(1, rotated.OpenAtRotation);
        Assert.Equal(
            [(Envelope(), "stderr"), ("stdout first half stdout middle stdout second half", "stdout"), ("after", "stdout")],
            current.Records.Select(record => (record.Text, record.Stream)));
        Assert.Equal(DockerMappingKind.SemanticEvent, Map(container, current.Records[0]).Kind);
        Assert.Equal((0, 0), (rotated.Oversized + current.Oversized, rotated.Malformed + current.Malformed));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void LineEndedByItsStreamBeforeRotation_IsWholeAndTheFreshLineAfterItIsDelivered()
    {
        // Docker's copier writes what is left at stream end (container stop) as a partial entry
        // with no newline, and nothing follows it. After a restart and a rotation, the new
        // file's first entry has its own time: it is a fresh line, and the old one was whole.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "before the container stopped, long enough\n");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "goodbye without a newline");
        DockerLogBatch stopped = DockerJsonLogReader.Read(container, start, Replay);
        Rotate(container);
        DockerFixture.AppendAt(container, "stdout", T2, "fresh first line after the restart\n", "second line\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, stopped.Cursor, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        // Until another entry of its stream arrives the reader cannot know the line is over. It
        // stays at the line's start, naming the line by its key.
        Assert.Empty(stopped.Records);
        Assert.Equal(start with { Pending = [new DockerPendingLine("stdout", T1, File: start.Fingerprint, Start: start.Offset, Length: 0)] }, stopped.Cursor);
        Assert.Empty(rotated.Records);
        Assert.Equal(
            ["goodbye without a newline", "fresh first line after the restart", "second line"],
            current.Records.Select(record => record.Text));
        Assert.DoesNotContain(current.Records, record => record.Fragment);
        Assert.Equal((0, 0), (rotated.Oversized + current.Oversized, rotated.Malformed + current.Malformed));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void LineSplitAcrossRotation_IsJoinedAcrossRestartsMidContinuation()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before, "chunk one ");
        DockerLogBatch waiting = DockerJsonLogReader.Read(container, null, Replay);
        DockerLogCursor restored = Restart(waiting.Cursor);
        Rotate(container);
        DockerFixture.AppendAt(container, "stderr", T2, "a stderr line that identifies the new file\n");
        DockerLogBatch rotated = DockerJsonLogReader.Read(container, restored, Replay);
        // A restart after leaving .1, then a chunk in the new file and another restart: the
        // head is re-read from .1 and the chunk from the new file, past the stderr line.
        DockerLogCursor moved = Restart(rotated.Cursor);
        DockerFixture.Append(container, "chunk two, written after the rotation ");
        DockerLogBatch middle = DockerJsonLogReader.Read(container, moved, Replay);
        DockerLogCursor again = Restart(middle.Cursor);
        DockerFixture.Append(container, "last chunk\n", "kept after the restart\n");
        DockerLogBatch resumed = DockerJsonLogReader.Read(container, again, Replay);

        Assert.Equal("before rotation, long enough to fingerprint", Assert.Single(waiting.Records).Text);
        Assert.Empty(rotated.Records);
        Assert.Equal("a stderr line that identifies the new file", Assert.Single(middle.Records).Text);
        Assert.Equal(("chunk one chunk two, written after the rotation ".Length, rotated.Cursor.Fingerprint),
            (Assert.Single(again.Pending!).Length!.Value, again.Fingerprint));
        Assert.Equal(
            ["chunk one chunk two, written after the rotation last chunk", "kept after the restart"],
            resumed.Records.Select(record => record.Text));
        Assert.Equal((waiting.Cursor.Fingerprint, waiting.Cursor.Offset), (resumed.Records[0].FileFingerprint, resumed.Records[0].StartOffset));
        Assert.Equal((0, 0), (rotated.Oversized + middle.Oversized + resumed.Oversized, resumed.OpenAtRotation));
        Assert.False(rotated.RotationGap || middle.RotationGap || resumed.RotationGap);
    }

    [Fact]
    public void OpenLineAtTheEndOfRotatedFile_IsCountedOnceWhenTheRecordLimitStopsADrain()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumRecordsPerBatch = 1 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.Append(container, "kept before the open line\n", "open line ");
        Rotate(container);
        DockerFixture.Append(container, "new file line\n");

        List<DockerLogBatch> polls = Poll(container, start, options, 4);

        Assert.Equal(["kept before the open line", "open line new file line"], polls.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal(1, polls.Sum(batch => batch.OpenAtRotation));
        Assert.DoesNotContain(polls, batch => batch.RotationGap);
    }

    [Fact]
    public void OpenLine_WaitsUntilTheNewFileCanBeIdentified()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before, "chunk one ");
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;

        // Not rotated: the line is still being written, so the reader waits on it.
        DockerLogBatch unrotated = DockerJsonLogReader.Read(container, start, Replay);
        Rotate(container);
        // Rotated, but no new file yet, then one too short to identify.
        DockerLogBatch missing = DockerJsonLogReader.Read(container, start, Replay);
        DockerFixture.AppendRaw(container, "{\"log\":\"x\\n\"}\n");
        DockerLogBatch tooShort = DockerJsonLogReader.Read(container, start, Replay);
        DockerFixture.Append(container, "the new file, now long enough to identify\n");
        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        foreach (DockerLogBatch waiting in new[] { unrotated, missing, tooShort })
        {
            Assert.Empty(waiting.Records);
            Assert.Equal(start, waiting.Cursor);
            Assert.False(waiting.RotationGap);
        }

        Assert.Empty(rotated.Records);
        // The raw entry has no time, so it is another line: the open one ended at stream end.
        Assert.Equal(["chunk one ", "x", "the new file, now long enough to identify"], current.Records.Select(record => record.Text));
        Assert.Equal((0, false), (current.Oversized, current.RotationGap));
    }

    [Fact]
    public void TornEntryAtTheEndOfRotatedFile_IsCountedAndTheNewFileIsRead()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendRaw(container, "{\"log\":\"torn en");
        Rotate(container);
        DockerFixture.Append(container, "first line of the new file\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        Assert.Equal((1, 0, false, 0L), (rotated.Malformed, rotated.OpenAtRotation, rotated.Cursor.Discarding, rotated.Cursor.Offset));
        Assert.Equal("first line of the new file", Assert.Single(current.Records).Text);
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void OpenLineBeforeATornEntryAtTheEndOfRotatedFile_IsJoinedAsAFragment()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.Append(container, "open chunk ");
        DockerFixture.AppendRaw(container, "{\"log\":\"torn en");
        Rotate(container);
        DockerFixture.Append(container, "rest of the open line\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        Assert.Equal((1, 1, false), (rotated.Malformed, rotated.OpenAtRotation, rotated.Cursor.Discarding));
        // The torn entry may have been one of its chunks, so the line is not known whole.
        Assert.Equal(("open chunk rest of the open line", true), (Assert.Single(current.Records).Text, current.Records[0].Fragment));
        Assert.Equal(0, current.Malformed);
    }

    [Fact]
    public void LineAlreadyOversizedAtTheEndOfRotatedFile_KeepsItsKeyedDiscardIntoTheNewFile()
    {
        // The line went over the limit before the rotation: it is never emitted, its discard
        // key is carried into the new file, and it is counted once there.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumLineBytes = 1_024 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 3, chunkLength: 1_000, terminate: false);
        DockerLogBatch discarding = DockerJsonLogReader.Read(container, start, options);
        DockerFixture.AppendOversizedLine(container, chunks: 1, chunkLength: 10, terminate: false);
        Rotate(container);
        DockerFixture.Append(container, "rest of the oversized line\n", "kept\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, discarding.Cursor, options);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, options);

        Assert.True(discarding.Cursor.Discarding);
        Assert.Equal(new DockerPendingLine("stdout", T0, Discarding: true), Assert.Single(discarding.Cursor.Pending!));
        Assert.Empty(rotated.Records);
        Assert.Equal((0L, true, 0), (rotated.Cursor.Offset, rotated.Cursor.Discarding, rotated.OpenAtRotation));
        Assert.Equal("kept", Assert.Single(current.Records).Text);
        Assert.Equal((0, 1), (rotated.Oversized, current.Oversized));
        Assert.False(rotated.RotationGap || current.RotationGap);
    }

    [Fact]
    public void LineThatFillsTheByteBudgetBeforeTheEndOfRotatedFile_IsDiscardedAsBefore()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumBytesPerBatch = 200 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 5, chunkLength: 60, terminate: false);
        Rotate(container);
        DockerFixture.Append(container, "rest of the long line\n", "kept\n");

        List<DockerLogBatch> polls = Poll(container, start, options, 5);

        Assert.Equal(["kept"], polls.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal((1, 0), (polls.Sum(batch => batch.Oversized), polls.Sum(batch => batch.OpenAtRotation)));
        Assert.DoesNotContain(polls, batch => batch.RotationGap);
    }

    [Fact]
    public void LineThatFillsTheByteBudgetInThePollThatReachesTheEndOfRotatedFile_IsKeptAndJoined()
    {
        // The budget fills exactly at the end of .1, with the line still within the line limit
        // and intact. It was discarded; now it goes open into the new file and is joined there.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 2, chunkLength: 60, terminate: false);
        DockerLogReaderOptions options = Replay with { MaximumBytesPerBatch = (int)(new FileInfo(container.LogPath).Length - start.Offset) };
        Rotate(container);
        DockerFixture.Append(container, "the end of the long line\n", "kept\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, options);
        // Reading the head again takes the whole budget: each read still takes one entry.
        List<DockerLogBatch> current = Poll(container, rotated.Cursor, options, 2);

        Assert.Empty(rotated.Records);
        Assert.Equal((false, 1), (rotated.Cursor.Discarding, rotated.OpenAtRotation));
        Assert.Equal([new string('x', 120) + "the end of the long line", "kept"], current.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal((0, 0), (rotated.Oversized, current.Sum(batch => batch.Oversized)));
    }

    // ---- Reproductions from council round 2 ----

    [Fact]
    public void FiveChunkStdoutLineOpenAtRotation_DoesNotSwallowTheNextStderrEvent()
    {
        // Five newline-free 16 KiB stdout chunks (over the 64 KiB limit), then a rotation, then a
        // complete stderr Bower event: the carried discard consumed it, whatever its stream.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendOversizedLine(container, chunks: 5, chunkLength: 16_384, terminate: false);
        Rotate(container);
        DockerFixture.AppendFrom(container, "stderr", Envelope() + "\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        Assert.True(rotated.Cursor.Discarding);
        DockerLogRecord record = Assert.Single(current.Records);
        Assert.Equal((Envelope(), "stderr", false), (record.Text, record.Stream, record.Fragment));
        Assert.Equal(DockerMappingKind.SemanticEvent, Map(container, record).Kind);
        // The stdout line is still being skipped: its last chunk has not arrived.
        Assert.Equal(new DockerPendingLine("stdout", T0, Discarding: true), Assert.Single(current.Cursor.Pending!));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FreshStdoutEventAfterAnOverLimitLineEndedByItsStream_IsDelivered(bool rotate)
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumLineBytes = 1_024 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, new string('x', 1_000), new string('x', 1_000), new string('x', 1_000));
        List<DockerLogBatch> polls = Poll(container, start, options, 1);
        if (rotate)
        {
            Rotate(container);
        }

        DockerFixture.AppendAt(container, "stdout", T2, "Invalid user mallory from 192.0.2.66 port 22\n");
        polls.AddRange(Poll(container, polls[^1].Cursor, options, 3));

        Assert.Equal(["Invalid user mallory from 192.0.2.66 port 22"], polls.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal(1, polls.Sum(batch => batch.Oversized));
        Assert.Null(polls[^1].Cursor.Pending);
    }

    [Fact]
    public void TwoStreamsOpenAtTheEndOfRotatedFile_AreTwoSeparateLines()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "stdout head ");
        DockerFixture.AppendAt(container, "stderr", T2, "stderr head ");
        Rotate(container);
        DockerFixture.AppendAt(container, "stderr", T2, "stderr tail\n");
        DockerFixture.AppendAt(container, "stdout", T1, "stdout tail\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        Assert.Equal((2, 2), (rotated.OpenAtRotation, rotated.Cursor.Pending!.Count));
        Assert.Equal(
            [("stderr head stderr tail", "stderr", false), ("stdout head stdout tail", "stdout", false)],
            current.Records.Select(record => (record.Text, record.Stream, record.Fragment)));
        Assert.False(current.RotationGap);
    }

    [Fact]
    public void TwoStreamsOpenAtTheEndOfRotatedFileThatIsThenLost_AreTwoSeparateFragments()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "stdout head ");
        DockerFixture.AppendAt(container, "stderr", T2, "stderr head ");
        Rotate(container);
        DockerFixture.AppendAt(container, "stderr", T2, "stderr tail\n");
        DockerFixture.AppendAt(container, "stdout", T1, "stdout tail\n");
        DockerFixture.AppendAt(container, "stdout", T3, "a whole line\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        // Compressed away (or rotated again) before the next pass: both heads are gone.
        File.Delete(container.LogPath + ".1");
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Equal(
            [("stderr tail", "stderr", true), ("stdout tail", "stdout", true), ("a whole line", "stdout", false)],
            current.Records.Select(record => (record.Text, record.Stream, record.Fragment)));
        Assert.True(current.RotationGap);
        Assert.Equal(DockerMappingKind.Unrecognised, Map(container, current.Records[2]).Kind);
        Assert.All(current.Records.Take(2), record => Assert.Equal(DockerMappingKind.Fragment, Map(container, record).Kind));
    }

    [Fact]
    public void HeadEndingInAPartialAddress_IsNeverMappedAsASignal()
    {
        // The real address is 10.0.0.12; the head in .1 ends at "10.0.0.1". Mapped on its own,
        // the unanchored pattern turned it into a signal with the wrong address.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.Append(container, "sshd[1]: Failed password for root from 10.0.0.1");
        Rotate(container);
        DockerFixture.Append(container, "2 port 22 ssh2\n");

        List<DockerMappedEvent> mapped = [.. Poll(container, start, Replay, 3)
            .SelectMany(batch => batch.Records)
            .Select(record => Map(container, record))];

        DockerMappedEvent signal = Assert.Single(mapped);
        Assert.Equal(DockerMappingKind.RecognisedSignal, signal.Kind);
        Assert.Equal("10.0.0.12", Envelope(signal).Source?.IpAddress);
    }

    [Fact]
    public void HeadEndingInAPartialAddressWhoseRestIsLost_IsNeverMapped()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.Append(container, "sshd[1]: Failed password for root from 10.0.0.1");
        Rotate(container);
        DockerFixture.Append(container, "2 port 22 ssh2\n");

        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);
        File.Delete(container.LogPath + ".1");
        DockerLogBatch current = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        Assert.Empty(rotated.Records);
        DockerLogRecord tail = Assert.Single(current.Records);
        Assert.True(tail.Fragment);
        Assert.Equal(new DockerMappedEvent(DockerMappingKind.Fragment, null, null), Map(container, tail));
    }

    [Fact]
    public void RestThatIsACompleteEnvelope_IsNeverMappedAsASemanticEvent()
    {
        // An application that logs untrusted text: a head in .1, and a rest that is a whole
        // Bower envelope. Joined, it is not an envelope; with its head lost, it is a fragment.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.Append(container, "comment from a user: ");
        Rotate(container);
        DockerFixture.Append(container, Envelope() + "\n");
        DockerLogBatch rotated = DockerJsonLogReader.Read(container, start, Replay);

        DockerLogBatch joined = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);
        File.Delete(container.LogPath + ".1");
        DockerLogBatch lost = DockerJsonLogReader.Read(container, rotated.Cursor, Replay);

        DockerLogRecord whole = Assert.Single(joined.Records);
        Assert.Equal(("comment from a user: " + Envelope(), false), (whole.Text, whole.Fragment));
        Assert.Equal(DockerMappingKind.Unrecognised, Map(container, whole).Kind);
        DockerLogRecord fragment = Assert.Single(lost.Records);
        Assert.Equal((Envelope(), true), (fragment.Text, fragment.Fragment));
        Assert.Equal(DockerMappingKind.Fragment, Map(container, fragment).Kind);
        Assert.True(lost.RotationGap);
    }

    // ---- Within one file ----

    [Fact]
    public void StderrBetweenStdoutChunks_IsNotMerged()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "stdout part one ");
        DockerFixture.AppendAt(container, "stderr", T2, Envelope() + "\n");
        DockerFixture.AppendAt(container, "stdout", T1, "stdout part two\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, Replay);

        Assert.Equal(
            [(Envelope(), "stderr"), ("stdout part one stdout part two", "stdout")],
            batch.Records.Select(record => (record.Text, record.Stream)));
        Assert.Equal(start.Offset, batch.Records[1].StartOffset);
        Assert.True(batch.Records[0].StartOffset > batch.Records[1].StartOffset);
        Assert.Equal(DockerMappingKind.SemanticEvent, Map(container, batch.Records[0]).Kind);
        Assert.Equal((new FileInfo(container.LogPath).Length, (IReadOnlyList<DockerPendingLine>?)null), (batch.Cursor.Offset, batch.Cursor.Pending));
    }

    [Fact]
    public void OverLimitDiscard_SkipsOnlyItsOwnChunksBetweenInterleavedStderr()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumLineBytes = 1_024 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, new string('x', 1_000));
        DockerFixture.AppendAt(container, "stderr", T2, "Invalid user a from 192.0.2.1 port 1\n");
        DockerFixture.AppendAt(container, "stdout", T1, new string('x', 1_000));
        DockerFixture.AppendAt(container, "stderr", T3, "Invalid user b from 192.0.2.2 port 1\n");
        DockerFixture.AppendAt(container, "stdout", T1, "end of the long line\n");
        DockerFixture.AppendAt(container, "stdout", T4, "after\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, options);

        Assert.Equal(
            ["Invalid user a from 192.0.2.1 port 1", "Invalid user b from 192.0.2.2 port 1", "after"],
            batch.Records.Select(record => record.Text));
        Assert.Equal((1, 0), (batch.Oversized, batch.Malformed));
        Assert.Null(batch.Cursor.Pending);
    }

    [Fact]
    public void FreshLineAfterALineEndedByItsStream_IsDeliveredWithinOneFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "goodbye without a newline");
        DockerFixture.AppendAt(container, "stdout", T2, "Invalid user a from 192.0.2.1 port 1\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, Replay);

        Assert.Equal(["goodbye without a newline", "Invalid user a from 192.0.2.1 port 1"], batch.Records.Select(record => record.Text));
        Assert.DoesNotContain(batch.Records, record => record.Fragment);
    }

    [Fact]
    public void OpenLineWithMoreOtherStreamLinesThanABatchHolds_NeitherStallsNorRepeats()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumRecordsPerBatch = 2 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "open ");
        DockerFixture.AppendAt(container, "stderr", T2, "e1\n", "e2\n", "e3\n", "e4\n", "e5\n");
        DockerFixture.AppendAt(container, "stdout", T1, "close\n");

        List<DockerLogBatch> polls = Poll(container, start, options, 6);

        Assert.Equal(["e1", "e2", "e3", "e4", "e5", "open close"], polls.SelectMany(batch => batch.Records).Select(record => record.Text));
        Assert.Equal(new FileInfo(container.LogPath).Length, polls[^1].Cursor.Offset);
    }

    [Fact]
    public void RestartMidDiscard_SkipsOnlyTheDiscardedLine()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumLineBytes = 1_024 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, new string('x', 1_000), new string('x', 1_000));
        DockerFixture.AppendAt(container, "stderr", T2, "Invalid user a from 192.0.2.1 port 1\n");
        DockerLogBatch first = DockerJsonLogReader.Read(container, start, options);
        DockerLogCursor restored = Restart(first.Cursor);
        DockerFixture.AppendAt(container, "stderr", T3, "Invalid user b from 192.0.2.2 port 1\n");
        DockerFixture.AppendAt(container, "stdout", T1, "end of the long line\n");
        DockerFixture.AppendAt(container, "stdout", T4, "after\n");
        DockerLogBatch second = DockerJsonLogReader.Read(container, restored, options);

        Assert.Equal(["Invalid user a from 192.0.2.1 port 1"], first.Records.Select(record => record.Text));
        Assert.Equal(new DockerPendingLine("stdout", T1, Discarding: true), Assert.Single(restored.Pending!));
        Assert.Equal(["Invalid user b from 192.0.2.2 port 1", "after"], second.Records.Select(record => record.Text));
        Assert.Equal((0, 1), (first.Oversized, second.Oversized));
    }

    [Fact]
    public void RestartMidContinuationWithinOneFile_JoinsTheLineAtItsOwnStart()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "head ");
        DockerFixture.AppendAt(container, "stderr", T2, "Invalid user a from 192.0.2.1 port 1\n");
        DockerLogBatch first = DockerJsonLogReader.Read(container, start, Replay);
        DockerLogCursor restored = Restart(first.Cursor);
        DockerFixture.AppendAt(container, "stdout", T1, "tail\n");
        DockerLogBatch second = DockerJsonLogReader.Read(container, restored, Replay);

        Assert.Equal(["Invalid user a from 192.0.2.1 port 1"], first.Records.Select(record => record.Text));
        // Past the stderr line, with the stdout line's start recorded so it is re-read.
        Assert.Equal(new DockerPendingLine("stdout", T1, File: start.Fingerprint, Start: start.Offset, Length: 5, Digest: DockerPendingLine.DigestOf("head ")), Assert.Single(restored.Pending!));
        DockerLogRecord joined = Assert.Single(second.Records);
        Assert.Equal(("head tail", start.Fingerprint, start.Offset), (joined.Text, joined.FileFingerprint, joined.StartOffset));
    }

    [Fact]
    public void ResumeCursors_ReproduceEachRecordAndEveryLaterOne()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "sshd[1]: Failed password for root from 10.0.0.");
        DockerFixture.AppendAt(container, "stderr", T2, "Invalid user a from 192.0.2.1 port 1\n");
        DockerFixture.AppendAt(container, "stdout", T1, "12 port 22 ssh2\n");
        DockerFixture.AppendAt(container, "stderr", T3, "Invalid user b from 192.0.2.2 port 1\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, Replay);

        Assert.Equal(
            ["Invalid user a from 192.0.2.1 port 1", "sshd[1]: Failed password for root from 10.0.0.12 port 22 ssh2", "Invalid user b from 192.0.2.2 port 1"],
            batch.Records.Select(record => record.Text));
        for (int index = 0; index < batch.Records.Count; index++)
        {
            DockerLogBatch replay = DockerJsonLogReader.Read(container, Restart(batch.Records[index].Resume!), Replay);
            // Everything from this record on, after some already sent at most: never anything else.
            List<string> expected = [.. batch.Records.Skip(index).Select(Identity)];
            List<string> replayed = [.. replay.Records.Select(Identity)];
            Assert.Equal(expected, replayed.Skip(replayed.Count - expected.Count));
            Assert.All(replayed, identity => Assert.Contains(identity, batch.Records.Select(Identity)));
        }

        static string Identity(DockerLogRecord record) => $"{record.Text}|{record.FileFingerprint}|{record.StartOffset}|{record.EndOffset}";
    }

    [Fact]
    public void EntryOfAnotherStreamOrWithAnOverlongTime_IsMalformed()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdin", T1, "not a Docker stream\n");
        DockerFixture.AppendAt(container, "stdout", new string('9', DockerLogCursor.MaximumTimeLength + 1), "no Docker time is this long\n");
        DockerFixture.Append(container, "kept\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, Replay);

        Assert.Equal("kept", Assert.Single(batch.Records).Text);
        Assert.Equal(2, batch.Malformed);
    }

    [Fact]
    public void Decoder_EndsALineAtEndOfFileOnlyInARenamedRotatedFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before, "open ");
        using FileTailHandle file = FileTailHandle.OpenWithPrefixIdentity(container.LogPath)!;
        DockerJsonLogReader.Decoder decoder = new(Replay, null, file, () => null);
        FileTailCursor at = new(FileTailCursor.CurrentSchemaVersion, file.Fingerprint!, 0);

        Assert.Throws<UnreachableException>(() => decoder.Scan(file, at, eofEndsLine: true, gap: false));
        Assert.Throws<UnreachableException>(() => decoder.Scan(file, at with { Drain = FileTailCursor.CopyDrain }, eofEndsLine: true, gap: false));
        Assert.Throws<UnreachableException>(() => decoder.Scan(file, at with { Drain = FileTailCursor.RenameDrain, FileId = "1:2" }, eofEndsLine: true, gap: false));
        DockerLogBatch renamed = decoder.Scan(file, at with { Drain = FileTailCursor.RenameDrain }, eofEndsLine: true, gap: false);
        Assert.Equal(Before.TrimEnd('\n'), Assert.Single(renamed.Records).Text);
        Assert.Equal(new FileInfo(container.LogPath).Length, renamed.Cursor.Offset);
        Assert.Throws<UnreachableException>(() => decoder.Append(renamed, renamed));
        Assert.Throws<UnreachableException>(() => decoder.WithCursor(renamed, at));
    }

    // ---- Reproductions from council round 3 ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LogUnlinkedAndCreatedAgainWithALineOpen_MaxFileOne_TheRestIsAFragment(bool otherStreamAfterTheHead)
    {
        // With max-file: 1, moby unlinks the log and creates it again instead of renaming it to
        // .1: every rotation is a gap. The key was dropped there (or never stored, when the read
        // pinned the line's start), so a rest that is a whole envelope was mapped as one.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "comment from a user: ");
        if (otherStreamAfterTheHead)
        {
            DockerFixture.AppendAt(container, "stderr", T2, "a stderr line after the head\n");
        }

        DockerLogBatch open = DockerJsonLogReader.Read(container, start, Replay);
        File.Delete(container.LogPath);
        DockerFixture.AppendAt(container, "stdout", T1, Envelope() + "\n");
        DockerFixture.AppendAt(container, "stdout", T3, "a fresh line after the rotation\n");

        DockerLogBatch recreated = DockerJsonLogReader.Read(container, Restart(open.Cursor), Replay);

        Assert.Equal(("stdout", T1), (open.Cursor.Pending![0].Stream, open.Cursor.Pending[0].Time));
        Assert.True(recreated.RotationGap);
        Assert.Equal(
            [(Envelope(), true), ("a fresh line after the rotation", false)],
            recreated.Records.Select(record => (record.Text, record.Fragment)));
        Assert.Equal(DockerMappingKind.Fragment, Map(container, recreated.Records[0]).Kind);
    }

    [Fact]
    public void LineWhoseHeadRotatesAwayBeforeItsRestArrives_TheRestIsAFragment()
    {
        // Sol's repro: the head in A, a rotation, a read that commits with A's head pending, then
        // enough rotations to remove A and B before the terminator, a valid envelope, arrives.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "comment from a user: ");
        Rotate(container);
        DockerFixture.AppendAt(container, "stderr", T2, "file B, long enough to give it an identity\n");
        List<DockerLogBatch> polls = Poll(container, start, Replay, 2);
        Rotate(container);
        DockerFixture.AppendAt(container, "stderr", T3, "file C, long enough to give it an identity\n");
        Rotate(container);
        DockerFixture.AppendAt(container, "stdout", T1, Envelope() + "\n");
        DockerFixture.AppendAt(container, "stdout", T4, "a fresh line in file D\n");

        DockerLogBatch lost = DockerJsonLogReader.Read(container, Restart(polls[^1].Cursor), Replay);

        Assert.NotNull(Assert.Single(polls[^1].Cursor.Pending!).Digest);
        Assert.True(lost.RotationGap);
        Assert.Equal(
            [(Envelope(), true), ("a fresh line in file D", false)],
            lost.Records.Select(record => (record.Text, record.Fragment)));
        Assert.Equal(DockerMappingKind.Fragment, Map(container, lost.Records[0]).Kind);
    }

    [Fact]
    public void FirstSightAtTheEndWhileALineIsOpen_TheRestIsAFragment()
    {
        // Start-at-end lands after the last newline, inside a line: its rest is not a line.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerFixture.AppendAt(container, "stdout", T1, "comment from a user: ");
        DockerFixture.AppendAt(container, "stderr", T2, "a stderr line between\n");

        DockerLogBatch first = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions());
        DockerFixture.AppendAt(container, "stdout", T1, Envelope() + "\n");
        DockerFixture.AppendAt(container, "stdout", T3, "a fresh line\n");
        DockerLogBatch next = DockerJsonLogReader.Read(container, Restart(first.Cursor), new DockerLogReaderOptions());

        Assert.Empty(first.Records);
        Assert.Equal(new DockerPendingLine("stdout", T1, Fragment: true), Assert.Single(first.Cursor.Pending!));
        Assert.Equal([(Envelope(), true), ("a fresh line", false)], next.Records.Select(record => (record.Text, record.Fragment)));
        Assert.Equal(DockerMappingKind.Fragment, Map(container, next.Records[0]).Kind);
    }

    [Fact]
    public void FirstSightReplayingAFileThatStartsWithTheRestOfALineInDotOne_TheRestIsAFragment()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerFixture.AppendAt(container, "stdout", T1, "comment from a user: ");
        Rotate(container);
        DockerFixture.AppendAt(container, "stdout", T1, Envelope() + "\n");
        DockerFixture.AppendAt(container, "stdout", T3, "a fresh line\n");

        DockerLogBatch replay = DockerJsonLogReader.Read(container, null, Replay);

        Assert.Equal([(Envelope(), true), ("a fresh line", false)], replay.Records.Select(record => (record.Text, record.Fragment)));
        Assert.Equal(DockerMappingKind.Fragment, Map(container, replay.Records[0]).Kind);
    }

    [Fact]
    public void OpenLineReadAgain_CostsItsOwnSizeNotTheSpanAndCountsAgainstTheBudget()
    {
        // A stdout head left open while stderr trickles in: every poll read the whole span from
        // the head to the cursor again (quadratic). Now it reads the head's chunk only.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor cursor = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        long before = new FileInfo(container.LogPath).Length;
        DockerFixture.AppendAt(container, "stdout", T1, new string('h', 1_000));
        long head = new FileInfo(container.LogPath).Length - before;
        long total = 0;
        for (int poll = 0; poll < 300; poll++)
        {
            long length = new FileInfo(container.LogPath).Length;
            DockerFixture.AppendAt(container, "stderr", $"2026-10-07T10:01:00.{poll:D9}Z", $"stderr line {poll}\n");
            long appended = new FileInfo(container.LogPath).Length - length;
            DockerLogBatch batch = DockerJsonLogReader.Read(container, cursor, Replay);
            Assert.True(batch.BytesRead <= head + appended, $"poll {poll}: {batch.BytesRead} bytes for a {head}-byte head and {appended} new bytes");
            total += batch.BytesRead;
            cursor = Restart(batch.Cursor);
        }

        // Within a small budget, the head read again leaves room for one entry only.
        DockerFixture.AppendAt(container, "stderr", T3, "one\n", "two\n", "three\n");
        DockerLogBatch tight = DockerJsonLogReader.Read(container, cursor, Replay with { MaximumBytesPerBatch = (int)head + 1 });
        DockerFixture.AppendAt(container, "stdout", T1, "end\n");
        List<DockerLogBatch> rest = Poll(container, tight.Cursor, Replay, 4);

        Assert.True(total < 300 * (head + 200), $"{total} bytes over 300 polls");
        Assert.Equal(["one"], tight.Records.Select(record => record.Text));
        Assert.True(tight.BytesRead <= head + 100, $"{tight.BytesRead} bytes within a {head + 1}-byte budget");
        Assert.Equal(["two", "three", new string('h', 1_000) + "end"], rest.SelectMany(batch => batch.Records).Select(record => record.Text));
    }

    [Fact]
    public void SameLengthEditToASavedHeadInDotOne_IsAFragment()
    {
        // The length matched, so an edited head was joined as if it were the one read.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "sshd[1]: Failed password for root from 10.0.0.1");
        Rotate(container);
        DockerFixture.AppendAt(container, "stderr", T2, "file B, long enough to give it an identity\n");
        DockerLogBatch moved = DockerJsonLogReader.Read(container, start, Replay);
        byte[] rotated = File.ReadAllBytes(container.LogPath + ".1");
        int at = Encoding.UTF8.GetString(rotated).IndexOf("10.0.0.1", StringComparison.Ordinal);
        rotated[at + 7] = (byte)'9';
        File.WriteAllBytes(container.LogPath + ".1", rotated);
        DockerFixture.AppendAt(container, "stdout", T1, "2 port 22 ssh2\n");

        DockerLogBatch current = DockerJsonLogReader.Read(container, moved.Cursor, Replay);

        Assert.Equal(1, moved.OpenAtRotation);
        DockerLogRecord tail = Assert.Single(current.Records, record => record.Stream == "stdout");
        Assert.Equal(("2 port 22 ssh2", true), (tail.Text, tail.Fragment));
        Assert.True(current.RotationGap);
        Assert.Equal(DockerMappingKind.Fragment, Map(container, tail).Kind);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("long")]
    public void EntryThatCannotBeReadBetweenTheChunksOfALine_MakesTheLineAFragment(string unreadable)
    {
        // It may be one of the line's chunks: the rest was joined around it into a whole record.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, Replay).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, "sshd[1]: Failed password for root from 10.0.0.1");
        DockerFixture.AppendRaw(container, unreadable == "long"
            ? "{\"log\":\"" + new string('z', DockerJsonLogReader.MaximumEntryBytes) + "\",\"stream\":\"stdout\",\"time\":\"" + T1 + "\"}\n"
            : unreadable + "\n");
        DockerFixture.AppendAt(container, "stdout", T1, "2 port 22 ssh2\n");
        DockerFixture.AppendAt(container, "stdout", T2, "Invalid user a from 192.0.2.1 port 1\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, Replay);

        Assert.Equal(1, batch.Malformed);
        Assert.Equal(
            [("sshd[1]: Failed password for root from 10.0.0.12 port 22 ssh2", true), ("Invalid user a from 192.0.2.1 port 1", false)],
            batch.Records.Select(record => (record.Text, record.Fragment)));
        Assert.Equal(DockerMappingKind.Fragment, Map(container, batch.Records[0]).Kind);
        Assert.Equal(DockerMappingKind.RecognisedSignal, Map(container, batch.Records[1]).Kind);
    }

    [Fact]
    public void DockerChunkEscapedToSixBytesACharacter_IsAnEntryWhateverTheLineLimit()
    {
        // The entry limit followed the line limit, so with a small one a whole Docker chunk of
        // control characters was malformed, not an oversized line.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogReaderOptions options = Replay with { MaximumLineBytes = 1_024 };
        DockerFixture.Append(container, Before);
        DockerLogCursor start = DockerJsonLogReader.Read(container, null, options).Cursor;
        DockerFixture.AppendAt(container, "stdout", T1, new string('\u0001', 16_384), "end\n");
        DockerFixture.AppendAt(container, "stdout", T2, "kept\n");

        DockerLogBatch batch = DockerJsonLogReader.Read(container, start, options);

        Assert.True(new FileInfo(container.LogPath).Length - start.Offset > 16_384 * 6);
        Assert.Equal((0, 1), (batch.Malformed, batch.Oversized));
        Assert.Equal("kept", Assert.Single(batch.Records).Text);
    }

    internal static string Envelope() => JsonSerializer.Serialize(TestEvents.AuthenticationFailure(TestEvents.Now), BowerJson.Options);

    private static SecurityEventEnvelope Envelope(DockerMappedEvent mapped) =>
        JsonSerializer.Deserialize<SecurityEventEnvelope>(mapped.Json!, BowerJson.Options)!;

    private static DockerMappedEvent Map(DockerContainer container, DockerLogRecord record) =>
        new DockerLogEventMapper(new DockerMapperOptions { SidecarId = "sidecar-test" }).Map(container, record, TestEvents.Now);

    private static void Rotate(DockerContainer container) => File.Move(container.LogPath, container.LogPath + ".1", overwrite: true);

    private static DockerLogCursor Restart(DockerLogCursor cursor)
    {
        DockerLogCursor restored = DockerLogCursor.Deserialize(cursor.Serialize())!;
        Assert.Equal(cursor, restored);
        return restored;
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
}
