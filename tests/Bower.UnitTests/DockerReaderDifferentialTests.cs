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
/// Deliberate differences, kept out of the random histories and pinned by targeted tests:
/// </para>
/// <list type="bullet">
/// <item>The current reader treats a renamed <c>.1</c> as final, so a line left open at its end
/// within the limits, or a torn entry, no longer holds the cursor on <c>.1</c> while the new file
/// goes unread and is later lost: the line is re-read from <c>.1</c> and joined with its rest.
/// The histories end such a line before they rotate, as the readers see it from their cursor,
/// but leave an oversized one open so the discard carried across rotation is still compared;
/// <see cref="LineSplitAcrossRotation_IsJoinedWhereThePreRefactorReaderLostTheNextFile"/> pins
/// it.</item>
/// <item>The current reader keys a line on its stream and Docker time, so another stream's
/// entries between its chunks are neither merged into it nor skipped by its discard, and an
/// entry of the same stream with another time ends it. The old reader joined whatever came
/// next. The histories are therefore single-stream, with one time, where both must agree;
/// interleaving is covered by <c>DockerSourceTests</c>. The histories run twice: once with one
/// time for every entry, and once with each line's own time shared by its chunks (as Docker
/// writes them, a line left open going on with its time), so keys that differ are compared too.</item>
/// <item>The current reader marks as a <see cref="DockerLogRecord.Fragment"/> the rest of a line it
/// saw open but cannot read whole (open when the log is first seen or at a gap, or with an entry
/// it cannot read between its chunks); the old reader emitted the same text as a line. Records are
/// compared without the flag; the flag is pinned by <c>DockerLineIdentityTests</c>. Its entry limit
/// is a whole Docker chunk however it is escaped, where the old one followed the line limit, so the
/// histories' over-long entries are longer than both.</item>
/// <item>The current cursor also names the lines open at it (<see cref="DockerLogCursor.Pending"/>),
/// and each record carries the cursor it is re-read from (<see cref="DockerLogRecord.Resume"/>).
/// Both are compared apart: cursors without <c>Pending</c>, and each resume cursor with the
/// position the old sidecar rewound to, its record's start (naming at most the record's own line,
/// its head still to come).</item>
/// </list>
/// </summary>
public sealed class DockerReaderDifferentialTests
{
    private const int Seeds = 300;
    private const int Steps = 60;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CurrentReader_MatchesThePreRefactorReaderOnRandomFileHistories(bool linesHaveTheirOwnTime)
    {
        int reads = 0, records = 0, fragments = 0, gaps = 0, discarding = 0, carried = 0, rotations = 0, failures = 0, restarts = 0;
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
            bool tailEndsLine = false;
            Times times = new(linesHaveTheirOwnTime);
            for (int step = 0; step < Steps; step++)
            {
                int operation = random.Next(17);
                if (linesHaveTheirOwnTime && pendingTail is not null && operation is 0 or 1 or 2 or 3 or 5)
                {
                    // An entry appended to a torn one would be lost in it, and the line it ends or
                    // goes on with with it: end the torn entry first, so the times stay as written.
                    Append(path, "\n");
                    pendingTail = null;
                }

                switch (operation)
                {
                    case 0 or 1:
                        Append(path, Entries(random, random.Next(1, 5), times));
                        break;
                    case 2:
                        // One logical line in partial chunks, sometimes not finished yet.
                        Append(path, Chunks(random, random.Next(2, 6), terminate: random.Next(3) != 0, times));
                        break;
                    case 3:
                        Append(path, Entry(new string('o', random.Next(150, 500)) + "\n", times.Line(ends: true)));
                        break;
                    case 4 when pendingTail is null:
                        string entry = Entry("half " + random.Next() + "\n", times.Next);
                        int cut = random.Next(1, entry.Length - 1);
                        Append(path, entry[..cut]);
                        (pendingTail, tailEndsLine) = (entry[cut..], true);
                        break;
                    case 4:
                        Append(path, pendingTail!);
                        pendingTail = null;
                        times.Open = tailEndsLine ? null : times.Open;
                        break;
                    case 5:
                        Append(path, random.Next(2) == 0 ? "not json at all\n" : """{"log":5,"stream":"stdout"}""" + "\n");
                        break;
                    case 6 when System.IO.File.Exists(path):
                        times.Open = EndOpenLine(path, currentCursor, options.MaximumLineBytes);
                        System.IO.File.Move(path, rotated, overwrite: true);
                        pendingTail = null;
                        if (random.Next(2) == 0)
                        {
                            Append(path, Entries(random, random.Next(1, 4), times));
                        }

                        rotations++;
                        break;
                    case 7 when System.IO.File.Exists(path):
                        times.Open = EndOpenLine(path, currentCursor, options.MaximumLineBytes);
                        System.IO.File.Copy(path, rotated, overwrite: true);
                        Truncate(path);
                        pendingTail = null;
                        rotations++;
                        break;
                    case 8 when System.IO.File.Exists(path):
                        Truncate(path);
                        pendingTail = null;
                        times.Open = null;
                        break;
                    case 9 when random.Next(4) == 0:
                        System.IO.File.Delete(rotated);
                        break;
                    case 10 when random.Next(6) == 0:
                        System.IO.File.Delete(path);
                        pendingTail = null;
                        times.Open = null;
                        break;
                    case 11 when random.Next(3) == 0:
                        // A new container (or a lost cursor): both start again from no cursor,
                        // so the start-at-end scan runs over whatever the file holds now.
                        legacyCursor = null;
                        currentCursor = null;
                        restarts++;
                        break;
                    case 12 when pendingTail is null:
                        // An unfinished entry longer than any batch byte budget and either reader's entry limit.
                        string longEntry = Entry("long " + random.Next() + new string('z', random.Next(MaximumEntry, MaximumEntry + 3_000)) + "\n", times.Next);
                        int split = longEntry.Length - random.Next(2, 40);
                        Append(path, longEntry[..split]);
                        (pendingTail, tailEndsLine) = (longEntry[split..], false); // Malformed: it ends no line.
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

                        Assert.True(legacy.Records.SequenceEqual(current!.Records.Select(Comparable)), $"{where}: records differ");
                        Assert.All(current.Records, AssertResumesWhereTheOldSidecarRewound);
                        Assert.True(legacy.Cursor == Legacy(current.Cursor), $"{where}: cursor {legacy.Cursor} vs {current.Cursor}");
                        Assert.Equal(legacy.Cursor.Serialize(), Legacy(current.Cursor).Serialize());
                        Assert.True((legacy.Malformed, legacy.Oversized, legacy.RotationGap, legacy.OpenAtRotation) == (current.Malformed, current.Oversized, current.RotationGap, current.OpenAtRotation),
                            $"{where}: counters differ");
                        legacyCursor = legacy.Cursor;
                        currentCursor = current.Cursor;
                        records += current.Records.Count;
                        fragments += current.Records.Count(record => record.Fragment);
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
            $"reads {reads}, records {records}, fragments {fragments}, gaps {gaps}, discarding {discarding}, carried {carried}, rotations {rotations}, restarts {restarts}, failures {failures}");
    }

    [Theory]
    [InlineData(65_536, 1_000, 4 * 1_048_576)]
    [InlineData(64, 2, 400)]
    [InlineData(200, 1, 250)]
    public void OrdinarySingleStreamLogs_KeepTheirRecordsOffsetsCursorsAndEventIds(int lineBytes, int records, int bytes)
    {
        // Ordinary logs (one stream, Docker's own time on every chunk) read exactly as before:
        // the same records at the same offsets, the same cursors and the same event ids.
        DockerLogReaderOptions options = new() { StartAtEnd = false, MaximumLineBytes = lineBytes, MaximumRecordsPerBatch = records, MaximumBytesPerBatch = bytes };
        DockerLogEventMapper mapper = new(new DockerMapperOptions { SidecarId = "sidecar-test" });
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerLogCursor? legacyCursor = null, currentCursor = null;
        List<string> legacyIds = [], currentIds = [];
        string[] history =
        [
            Entry("Server listening on 0.0.0.0 port 22.\n"),
            Entry("Failed password for root from 203.0.113.5 port 22 ssh2\n"),
            Entry("Invalid user oracle from "), Entry("192.0.2.44 "), Entry("port 50022\n"),
            Entry(new string('o', 300) + "\n"),
            "not json at all\n",
            Entry("Accepted publickey for deploy from 192.0.2.4 port 50000 ssh2\n"),
            Entry(new string('a', 40)), Entry(new string('b', 40)), Entry(new string('c', 40)), Entry("Invalid user b from 192.0.2.2 port 1\n"),
            Entry("still being written "),
            Entry("Invalid user c from 192.0.2.3 port 1\n")
        ];
        foreach (string entries in history)
        {
            Append(container.LogPath, entries);
            for (int poll = 0; poll < 3; poll++)
            {
                DockerLogBatch legacy = LegacyDockerJsonLogReader.Read(container, legacyCursor, options);
                DockerLogBatch current = DockerJsonLogReader.Read(container, currentCursor, options);
                Assert.Equal(legacy.Records, current.Records.Select(Unresumed));
                Assert.All(current.Records, AssertResumesWhereTheOldSidecarRewound);
                Assert.Equal(legacy.Cursor, Legacy(current.Cursor));
                Assert.Equal(legacy.Cursor.Serialize(), Legacy(current.Cursor).Serialize());
                Assert.Equal((legacy.Malformed, legacy.Oversized, legacy.RotationGap), (current.Malformed, current.Oversized, current.RotationGap));
                legacyIds.AddRange(legacy.Records.Select(record => mapper.Map(container, record, DateTimeOffset.UnixEpoch).Json ?? "-"));
                currentIds.AddRange(current.Records.Select(record => mapper.Map(container, record, DateTimeOffset.UnixEpoch).Json ?? "-"));
                (legacyCursor, currentCursor) = (legacy.Cursor, current.Cursor);
            }
        }

        Assert.Equal(legacyIds, currentIds);
        Assert.True(currentIds.Count(json => json != "-") >= 2, string.Join(", ", currentIds));
    }

    [Fact]
    public void LineSplitAcrossRotation_IsJoinedWhereThePreRefactorReaderLostTheNextFile()
    {
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        string rotated = container.LogPath + ".1";
        DockerLogReaderOptions options = new() { StartAtEnd = false };
        DockerLogCursor? legacyCursor = null, currentCursor = null;
        List<string> legacyLines = [], currentLines = [];
        int currentOversized = 0, currentOpen = 0;
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
        // The head is read again from .1 and joined with its rest in the new file.
        Assert.Equal(
            ["file A line one", "first chunk of a split line rest of the split line", "file B line one", "file B line two", "file C line one"],
            currentLines);
        Assert.Equal((0, 1), (currentOversized, currentOpen));
        Assert.False(currentGap);

        void Read()
        {
            DockerLogBatch legacy = LegacyDockerJsonLogReader.Read(container, legacyCursor, options);
            DockerLogBatch current = DockerJsonLogReader.Read(container, currentCursor, options);
            (legacyCursor, currentCursor) = (legacy.Cursor, current.Cursor);
            legacyLines.AddRange(legacy.Records.Select(record => record.Text));
            currentLines.AddRange(current.Records.Select(record => record.Text));
            currentOversized += current.Oversized;
            currentOpen += current.OpenAtRotation;
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

    /// <summary>Without <see cref="DockerLogRecord.Resume"/>, which the old reader did not have.</summary>
    internal static DockerLogRecord Unresumed(DockerLogRecord record) => record with { Resume = null };

    /// <summary>Also without <see cref="DockerLogRecord.Fragment"/>, which the old reader never set (see the class remarks).</summary>
    private static DockerLogRecord Comparable(DockerLogRecord record) => record with { Resume = null, Fragment = false };

    /// <summary>The old sidecar's rewind position, naming at most the record's own line, its head still to come.</summary>
    private static void AssertResumesWhereTheOldSidecarRewound(DockerLogRecord record)
    {
        Assert.Equal(LegacyRewind(record), Legacy(record.Resume!));
        Assert.All(record.Resume!.Pending ?? [], line => Assert.Equal(
            (record.Stream, (string?)null),
            (line.Stream, line.Digest)));
    }

    /// <summary>Without <see cref="DockerLogCursor.Pending"/>, which the old reader did not write.</summary>
    internal static DockerLogCursor Legacy(DockerLogCursor cursor) => cursor with { Pending = null };

    /// <summary>Where the old sidecar rewound to on backpressure: the record's start, with nothing open.</summary>
    internal static DockerLogCursor LegacyRewind(DockerLogRecord record) =>
        new(DockerLogCursor.CurrentSchemaVersion, record.FileFingerprint, record.StartOffset);

    private const string SharedTime = "2026-10-07T10:00:00.123456789Z";

    /// <summary>Above the current reader's entry limit, and so the old reader's for every line limit used here.</summary>
    private const int MaximumEntry = 16_384 * 6 + 4_096 + 1;

    private static string Entry(string log, string time = SharedTime) =>
        JsonSerializer.Serialize(new { log, stream = "stdout", time }) + "\n";

    private static string Entries(Random random, int count, Times times)
    {
        StringBuilder text = new();
        for (int index = 0; index < count; index++)
        {
            text.Append(Entry("line " + random.Next() + new string('x', random.Next(0, 120)) + "\n", times.Line(ends: true)));
        }

        return text.ToString();
    }

    private static string Chunks(Random random, int count, bool terminate, Times times)
    {
        StringBuilder text = new();
        for (int index = 0; index < count; index++)
        {
            bool last = index == count - 1;
            text.Append(Entry(new string((char)('a' + index), random.Next(5, 80)) + (last && terminate ? "\n" : string.Empty), times.Line(ends: last && terminate)));
        }

        return text.ToString();
    }

    /// <summary>
    /// Docker's time for each entry written: one for all, or each line's own, which a line left
    /// open keeps until it ends (also across a rotation).
    /// </summary>
    private sealed class Times(bool own)
    {
        private int next;

        /// <summary>The time of the line still open, if any.</summary>
        public string? Open { get; set; }

        /// <summary>The next entry's time, leaving the open line as it is.</summary>
        public string Next => Open ?? (own ? $"2026-10-07T10:00:00.{next++:D9}Z" : SharedTime);

        public string Line(bool ends)
        {
            string time = Open ?? (own ? $"2026-10-07T10:00:00.{next++:D9}Z" : SharedTime);
            Open = ends ? null : time;
            return time;
        }
    }

    private static void Append(string path, string text) => System.IO.File.AppendAllText(path, text);

    /// <summary>
    /// Before a rotation, ends a torn entry and a logical line left open within the line limit,
    /// where the readers deliberately differ (see the class remarks). The line is followed as the
    /// readers see it, from their cursor when it is on this file, with its time. An oversized open
    /// line is left open: both readers carry its discard into the new file. Returns its time.
    /// </summary>
    private static string? EndOpenLine(string path, DockerLogCursor? cursor, int maximumLineBytes)
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
        string time = (open ? cursor!.Pending?.FirstOrDefault(line => line.Discarding)?.Time : null) ?? SharedTime;
        while (position < bytes.Length)
        {
            int newline = Array.IndexOf(bytes, (byte)'\n', position);
            ReadOnlySpan<byte> entry = bytes.AsSpan(position, newline - position);
            position = newline + 1;
            if (entry.Length > maximumLineBytes * 2 + 4_096 || !TryLog(entry, out string log, out string entryTime))
            {
                continue; // Malformed: does not end or extend a line.
            }

            (open, time) = (true, entryTime);
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
            Append(path, Entry("closed\n", time));
        }

        return open && oversized ? time : null;

        static bool TryLog(ReadOnlySpan<byte> entry, out string log, out string time)
        {
            log = string.Empty;
            time = SharedTime;
            try
            {
                using JsonDocument document = JsonDocument.Parse(entry.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
                if (document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("log", out JsonElement value)
                    && value.ValueKind == JsonValueKind.String)
                {
                    log = value.GetString()!;
                    if (document.RootElement.TryGetProperty("time", out JsonElement entryTime) && entryTime.ValueKind == JsonValueKind.String)
                    {
                        time = entryTime.GetString()!;
                    }

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
