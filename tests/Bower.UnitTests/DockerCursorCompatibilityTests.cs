using Bower.Persistence;
using Bower.Source.Docker;

namespace Bower.UnitTests;

/// <summary>
/// Cursors persisted by the Docker reader before it moved onto the shared tailer
/// (<c>Bower.Source.File.FileTailFiles</c>). The literals are exactly what that code wrote
/// to <c>source_cursors</c> for these files; the current reader must resume from them and
/// write the same values back, so an upgraded sidecar neither replays nor skips lines.
/// </summary>
public sealed class DockerCursorCompatibilityTests
{
    private const string First = "first line from the old sidecar\n";
    private const string Second = "second line after the restart\n";

    // SHA-256 of the first 64 bytes of the log written by Append(First, Second).
    private const string Fingerprint = "f67ca8f19d9e999a38c0028f52d1777224229b7374e19d291863c9759ad19895";

    /// <summary>After the first entry (102 bytes).</summary>
    private const string PersistedAfterFirst = """{"schemaVersion":1,"fingerprint":"f67ca8f19d9e999a38c0028f52d1777224229b7374e19d291863c9759ad19895","offset":102}""";

    /// <summary>After both entries (202 bytes).</summary>
    private const string PersistedAtEnd = """{"schemaVersion":1,"fingerprint":"f67ca8f19d9e999a38c0028f52d1777224229b7374e19d291863c9759ad19895","offset":202}""";

    [Fact]
    public async Task CursorPersistedByTheOldReader_ResumesWithoutReplayOrSkipAndIsWrittenBackUnchanged()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, First, Second);
        EfSourceCursorStore store = new(Path.Combine(root.Path, "cursors.db"));
        await store.InitializeAsync(cancellation);
        string sourceId = $"docker:{container.Id}";
        Assert.True(await store.TryAdvanceAsync(sourceId, 0, PersistedAfterFirst, DateTimeOffset.UnixEpoch, cancellation));

        DockerLogCursor? stored = DockerLogCursor.Deserialize((await store.ReadAsync(sourceId, cancellation))!.Value);
        DockerLogBatch batch = DockerJsonLogReader.Read(container, stored, new DockerLogReaderOptions());

        Assert.Equal(new DockerLogCursor(1, Fingerprint, 102), stored);
        DockerLogRecord record = Assert.Single(batch.Records);
        Assert.Equal(Second.TrimEnd('\n'), record.Text);
        Assert.Equal((Fingerprint, 102L, 202L), (record.FileFingerprint, record.StartOffset, record.EndOffset));
        Assert.Equal(PersistedAtEnd, batch.Cursor.Serialize());
        Assert.False(batch.RotationGap);

        // A fresh read from the start persists the same value the old reader did.
        DockerLogBatch replay = DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions { StartAtEnd = false });
        Assert.Equal(PersistedAtEnd, replay.Cursor.Serialize());
        Assert.Equal(PersistedAtEnd, DockerJsonLogReader.Read(container, null, new DockerLogReaderOptions()).Cursor.Serialize());
    }

    [Fact]
    public void DiscardingCursorPersistedByTheOldReader_SkipsTheRestOfTheLineThenReadsTheNextOnce()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, First);
        DockerFixture.Append(container, new string('x', 40), new string('y', 40) + "\n", "after the long line\n");
        // Written while skipping a line over a 32-byte limit, after its first partial chunk (102 + 109).
        string persisted = """{"schemaVersion":1,"fingerprint":"FP","offset":211,"discarding":true}"""
            .Replace("FP", DockerFingerprint(container), StringComparison.Ordinal);
        DockerLogReaderOptions options = new() { MaximumLineBytes = 32 };

        DockerLogBatch batch = DockerJsonLogReader.Read(container, DockerLogCursor.Deserialize(persisted), options);

        Assert.Equal(1, batch.Oversized);
        Assert.Equal("after the long line", Assert.Single(batch.Records).Text);
        Assert.Equal(
            """{"schemaVersion":1,"fingerprint":"FP","offset":412}""".Replace("FP", DockerFingerprint(container), StringComparison.Ordinal),
            batch.Cursor.Serialize());
    }

    [Fact]
    public void DiscardingCursorPersistedByTheOldReader_TakesItsKeyFromTheChunkItSkippedLast()
    {
        // The old cursor names no line: the chunk ending at its offset is the one it skipped
        // last, so its stream and time key the discard, and a stderr line in between is kept.
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, First, new string('x', 40));
        long offset = new FileInfo(container.LogPath).Length;
        DockerFixture.AppendAt(container, "stderr", DockerFixture.Time(5), "a stderr line\n");
        DockerFixture.Append(container, new string('y', 40) + "\n", "after the long line\n");
        string persisted = $$"""{"schemaVersion":1,"fingerprint":"{{DockerFingerprint(container)}}","offset":{{offset}},"discarding":true}""";

        DockerLogBatch batch = DockerJsonLogReader.Read(container, DockerLogCursor.Deserialize(persisted), new DockerLogReaderOptions { MaximumLineBytes = 32 });

        Assert.Equal(["a stderr line", "after the long line"], batch.Records.Select(record => record.Text));
        Assert.Equal(1, batch.Oversized);
        Assert.Equal(new DockerLogCursor(1, DockerFingerprint(container), new FileInfo(container.LogPath).Length), batch.Cursor);
    }

    [Fact]
    public void DiscardingCursorPersistedByTheOldReaderAtTheStartOfAFile_KeepsTheOldRuleForThatLine()
    {
        // Carried across a rotation, the old cursor sits at offset 0 with no chunk before it,
        // so no key can be recovered: as the old reader did, entries are skipped up to and
        // including the first that ends with a newline, whatever its stream (the documented
        // limit: a stderr line first in the file is skipped, as it was before the upgrade).
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "rest of the long line from before the rotation\n", "kept\n");
        string persisted = $$"""{"schemaVersion":1,"fingerprint":"{{DockerFingerprint(container)}}","offset":0,"discarding":true}""";

        DockerLogBatch batch = DockerJsonLogReader.Read(container, DockerLogCursor.Deserialize(persisted), new DockerLogReaderOptions());

        Assert.Equal("kept", Assert.Single(batch.Records).Text);
        Assert.Equal(1, batch.Oversized);
        Assert.Equal(new DockerLogCursor(1, DockerFingerprint(container), new FileInfo(container.LogPath).Length), batch.Cursor);
    }

    [Fact]
    public void DiscardingCursorPersistedByTheOldReaderWhileTheChunkIsBeingWritten_KeepsItsDiscardUntilItEnds()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, First, new string('x', 40));
        long offset = new FileInfo(container.LogPath).Length;
        string persisted = $$"""{"schemaVersion":1,"fingerprint":"{{DockerFingerprint(container)}}","offset":{{offset}},"discarding":true}""";
        DockerLogReaderOptions options = new() { MaximumLineBytes = 32 };

        DockerLogBatch waiting = DockerJsonLogReader.Read(container, DockerLogCursor.Deserialize(persisted), options);
        DockerFixture.Append(container, new string('y', 40) + "\n", "after the long line\n");
        DockerLogBatch finished = DockerJsonLogReader.Read(container, waiting.Cursor, options);

        // Nothing more yet: the recovered key is written back, additively, next to the flag.
        Assert.Empty(waiting.Records);
        Assert.Equal(
            $$"""{"schemaVersion":1,"fingerprint":"{{DockerFingerprint(container)}}","offset":{{offset}},"discarding":true,"pending":[{"stream":"stdout","time":"{{DockerFixture.Time(0)}}","discarding":true}]}""",
            waiting.Cursor.Serialize());
        Assert.Equal("after the long line", Assert.Single(finished.Records).Text);
        Assert.Equal(1, finished.Oversized);
    }

    [Fact]
    public void PendingLines_AreAdditiveAndValidated()
    {
        const string written = """{"schemaVersion":1,"fingerprint":"abc","offset":42,"discarding":true,"pending":[{"stream":"stdout","time":"2026-10-07T10:00:00.123456789Z","discarding":true},{"stream":"stderr","time":"2026-10-07T10:00:01.123456789Z","file":"def","start":7,"length":5}]}""";
        DockerLogCursor cursor = new(1, "abc", 42, Discarding: true, Pending:
        [
            new DockerPendingLine("stdout", "2026-10-07T10:00:00.123456789Z", Discarding: true),
            new DockerPendingLine("stderr", "2026-10-07T10:00:01.123456789Z", File: "def", Start: 7, Length: 5)
        ]);

        Assert.Equal(cursor, DockerLogCursor.Deserialize(written));
        Assert.Equal(written, cursor.Serialize());
        Assert.Equal(cursor.GetHashCode(), DockerLogCursor.Deserialize(written)!.GetHashCode());
        Assert.Equal(
            """{"schemaVersion":1,"fingerprint":"abc","offset":42,"pending":[{"stream":"stdout","time":null,"fragment":true}]}""",
            (cursor with { Discarding = false, Pending = [new DockerPendingLine("stdout", null, Fragment: true)] }).Serialize());

        // A damaged cursor is refused as a whole, as any other damaged Docker cursor.
        foreach (string pending in new[]
        {
            """[]""",
            """[{"stream":"stdin","time":"t","discarding":true}]""",
            """[{"stream":"stdout","time":"t","discarding":true},{"stream":"stdout","time":"u","fragment":true}]""",
            """[{"stream":"stdout","time":"t"}]""",
            """[{"stream":"stdout","time":"t","start":1,"length":1}]""",
            """[{"stream":"stdout","time":"t","file":"f","start":-1,"length":1}]""",
            """[{"stream":"stdout","time":"t","discarding":true,"start":1}]""",
            $$"""[{"stream":"stdout","time":"{{new string('9', DockerLogCursor.MaximumTimeLength + 1)}}","discarding":true}]""",
            """[null]"""
        })
        {
            Assert.Null(DockerLogCursor.Deserialize($$"""{"schemaVersion":1,"fingerprint":"abc","offset":42,"discarding":true,"pending":{{pending}}}"""));
        }

        // The flag and the keys must agree.
        Assert.Null(DockerLogCursor.Deserialize("""{"schemaVersion":1,"fingerprint":"abc","offset":42,"pending":[{"stream":"stdout","time":"t","discarding":true}]}"""));
        Assert.Null(DockerLogCursor.Deserialize("""{"schemaVersion":1,"fingerprint":"abc","offset":42,"discarding":true,"pending":[{"stream":"stdout","time":"t","fragment":true}]}"""));
    }

    [Fact]
    public void ProvisionalCursorPersistedByTheOldReader_ReadsTheFileFromItsStart()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, First, Second);

        DockerLogBatch batch = DockerJsonLogReader.Read(
            container, DockerLogCursor.Deserialize("""{"schemaVersion":1,"fingerprint":"","offset":0}"""), new DockerLogReaderOptions());

        Assert.Equal([First.TrimEnd('\n'), Second.TrimEnd('\n')], batch.Records.Select(record => record.Text));
        Assert.Equal(PersistedAtEnd, batch.Cursor.Serialize());
    }

    [Fact]
    public void CursorOfARotatedFilePersistedByTheOldReader_DrainsPathDotOneThenMovesOn()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, First, Second);
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "new file line one that is long enough\n", "new file line two\n");

        DockerLogBatch drained = DockerJsonLogReader.Read(container, DockerLogCursor.Deserialize(PersistedAfterFirst), new DockerLogReaderOptions());
        DockerLogBatch next = DockerJsonLogReader.Read(container, drained.Cursor, new DockerLogReaderOptions());

        Assert.Equal(Second.TrimEnd('\n'), Assert.Single(drained.Records).Text);
        Assert.Equal((DockerFingerprint(container), 0L, false), (drained.Cursor.Fingerprint, drained.Cursor.Offset, drained.RotationGap));
        Assert.Equal(2, next.Records.Count);
    }

    private static string DockerFingerprint(DockerContainer container)
    {
        byte[] prefix = new byte[64];
        using FileStream stream = new(container.LogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        stream.ReadExactly(prefix);
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(prefix));
    }
}
