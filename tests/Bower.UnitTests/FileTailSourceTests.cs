using System.Collections.Concurrent;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Persistence;
using Bower.Source.File;

namespace Bower.UnitTests;

/// <summary>
/// The file tail source without the collector: shared vectors (record shape, event ids,
/// rotation and truncation sequences, malformed and oversized lines, configuration errors),
/// path guards, durable cursors, backpressure, bounds and cancellation against a fake sink.
/// The vectors are shared with the Rust port (<c>rust/crates/bower-source-file</c>). Inputs
/// are hand-written; set <c>BOWER_FILE_TAIL_VECTOR_OUTPUT</c> to a file path to regenerate the
/// expectations after an intended change, then review the diff.
/// </summary>
public sealed class FileTailSourceTests
{
    private static string FixturePath => Path.Combine(AppContext.BaseDirectory, "file-tail-vectors", "file-tail-vectors.json");

    [Fact]
    public void SharedVectors_MatchTheCSharpSpecification()
    {
        string text = File.ReadAllText(FixturePath);
        JsonObject fixture = JsonNode.Parse(text)!.AsObject();
        string inputId = fixture["input"]!["id"]!.GetValue<string>();
        string inputPath = fixture["input"]!["path"]!.GetValue<string>();
        string fingerprint = fixture["fingerprint"]!.GetValue<string>();
        DateTimeOffset readAt = DateTimeOffset.Parse(fixture["readAt"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);

        foreach (JsonObject vector in fixture["records"]!.AsArray().Select(node => node!.AsObject()))
        {
            byte[] line = vector["line"] is { } plain
                ? Encoding.UTF8.GetBytes(plain.GetValue<string>())
                : Convert.FromBase64String(vector["lineBase64"]!.GetValue<string>());
            FileTailInputOptions input = new(inputId, inputPath, new FileTailRoute("pack", 0), vector["format"]!.GetValue<string>());
            long offset = vector["offset"]!.GetValue<long>();
            string? record = FileTailRecord.TryBuild(input, new FileTailLine(line, fingerprint, offset, offset + line.Length + 1), readAt, out string? failure);
            vector["expect"] = record is null ? new JsonObject { ["failure"] = failure } : new JsonObject { ["record"] = record };
        }

        foreach (JsonObject sequence in fixture["sequences"]!.AsArray().Select(node => node!.AsObject()))
        {
            RunSequence(sequence);
        }

        foreach (JsonObject vector in fixture["config"]!.AsArray().Select(node => node!.AsObject()))
        {
            string json = vector["text"]?.GetValue<string>() ?? vector["config"]!.ToJsonString();
            string? error = null;
            try
            {
                _ = FileTailSourceConfigurationLoader.Parse(json);
            }
            catch (InvalidDataException exception)
            {
                error = exception.Message;
            }

            // Serializer messages differ between runtimes: only Bower's prefix is shared.
            const string Prefix = "File tail source configuration is invalid:";
            vector["expect"] = error is null
                ? new JsonObject { ["valid"] = true }
                : error.StartsWith(Prefix, StringComparison.Ordinal)
                    ? new JsonObject { ["errorPrefix"] = Prefix }
                    : new JsonObject { ["error"] = error };
        }

        string generated = fixture.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }) + "\n";
        if (Environment.GetEnvironmentVariable("BOWER_FILE_TAIL_VECTOR_OUTPUT") is { Length: > 0 } outputPath)
        {
            File.WriteAllText(outputPath, generated);
        }

        Assert.Equal(text.ReplaceLineEndings("\n"), generated);
    }

    /// <summary>Replays file operations and reads; every read's result is the expectation.</summary>
    private static void RunSequence(JsonObject sequence)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "app.log");
        string rotated = path + ".1";
        JsonObject options = sequence["options"]!.AsObject();
        FileTailReaderOptions reader = new()
        {
            StartAtEnd = options["startAtEnd"]!.GetValue<bool>(),
            MaxLineBytes = options["maxLineBytes"]?.GetValue<int>() ?? 256,
            MaxLinesPerBatch = options["maxLinesPerBatch"]?.GetValue<int>() ?? 256,
            MaxBytesPerBatch = options["maxBytesPerBatch"]?.GetValue<int>() ?? 1_048_576
        };
        FileTailCursor? cursor = null;
        foreach (JsonObject step in sequence["steps"]!.AsArray().Select(node => node!.AsObject()))
        {
            if (step["write"] is { } write)
            {
                // In place (same file), as a writer truncating and rewriting would.
                using FileStream stream = new(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                stream.SetLength(0);
                stream.Write(Encoding.UTF8.GetBytes(write.GetValue<string>()));
            }
            else if (step["append"] is { } append)
            {
                File.AppendAllText(path, append.GetValue<string>());
            }
            else if (step.ContainsKey("rename"))
            {
                File.Move(path, rotated, overwrite: true);
            }
            else if (step.ContainsKey("copytruncate"))
            {
                File.Copy(path, rotated, overwrite: true);
                using FileStream stream = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                stream.SetLength(0);
            }
            else
            {
                FileTailBatch batch = FileTailReader.Read(
                    File.Exists(path) ? path : null, File.Exists(rotated) ? rotated : null, cursor, reader);
                cursor = batch.Cursor;
                step["read"] = Describe(batch);
            }
        }
    }

    private static JsonObject Describe(FileTailBatch batch)
    {
        JsonArray lines = [];
        foreach (FileTailLine line in batch.Lines)
        {
            lines.Add(line.Oversized
                ? new JsonObject { ["oversized"] = true, ["start"] = line.StartOffset, ["end"] = line.EndOffset }
                : new JsonObject { ["text"] = Encoding.UTF8.GetString(line.Bytes), ["start"] = line.StartOffset, ["end"] = line.EndOffset });
        }

        return new JsonObject
        {
            ["lines"] = lines,
            ["provisional"] = batch.Cursor.Fingerprint.Length == 0,
            ["offset"] = batch.Cursor.Offset,
            ["discarding"] = batch.Cursor.Discarding,
            ["rotated"] = batch.Rotated,
            ["gap"] = batch.Gap,
            ["more"] = batch.More
        };
    }

    [Fact]
    public void EventId_IsStableAndBindsInputFileOffsetAndBytes()
    {
        byte[] line = "Failed password"u8.ToArray();
        string id = FileTailRecord.EventId("auth", new string('a', 64), 10, line);
        Assert.Equal(id, FileTailRecord.EventId("auth", new string('a', 64), 10, line));
        Assert.True(GeneratedEventIds.IsWellFormed(id));
        Assert.NotEqual(id, FileTailRecord.EventId("auth-2", new string('a', 64), 10, line));
        Assert.NotEqual(id, FileTailRecord.EventId("auth", new string('b', 64), 10, line));
        Assert.NotEqual(id, FileTailRecord.EventId("auth", new string('a', 64), 11, line));
        Assert.NotEqual(id, FileTailRecord.EventId("auth", new string('a', 64), 10, "Failed passwore"u8));
        string record = FileTailRecord.TryBuild(
            new FileTailInputOptions("auth", "/var/log/auth.log", new FileTailRoute("p", 0)),
            new FileTailLine(line, new string('a', 64), 10, 26), DateTimeOffset.UnixEpoch, out _)!;
        Assert.Equal(id, GeneratedEventIds.FromSourceRecord(record));
    }

    [Fact]
    public void Cursor_RoundTripsAndRefusesValuesThisVersionDidNotWrite()
    {
        FileTailCursor cursor = new(FileTailCursor.CurrentSchemaVersion, new string('a', 64), 42, Discarding: true);
        Assert.Equal(cursor, FileTailCursor.Deserialize(cursor.Serialize()));
        Assert.Equal("""{"schemaVersion":1,"fingerprint":"","offset":0}""",
            new FileTailCursor(FileTailCursor.CurrentSchemaVersion, string.Empty, 0).Serialize());
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"","offset":0}"""));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":1,"fingerprint":"zz","offset":0}"""));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":1,"fingerprint":"","offset":-1}"""));
        Assert.Null(FileTailCursor.Deserialize("not json"));
    }

    [Fact]
    public async Task SelectedLines_AreSubmittedInOrderAndDefaultDenyCountsTheRest()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("history"), cancellation);
        FakeSink sink = new(record => record.Contains("select-me", StringComparison.Ordinal)
            ? FileTailSubmitOutcome.Queued : FileTailSubmitOutcome.NotSelected);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path), sink, cursors);

        Assert.Equal(0, (await source.PollOnceAsync("auth", cancellation)).Lines); // startAt end
        await File.AppendAllTextAsync(path, Line("select-me secret-marker") + Line("other secret-marker") + "\n" + "partial", cancellation);
        FileTailPollResult result = await source.PollOnceAsync("auth", cancellation);

        Assert.Equal(3, result.Lines);
        Assert.Equal(2, sink.Records.Count);
        FileTailInputStatus status = Assert.Single(source.Snapshot());
        Assert.Equal((1, 1, 1, "running"), (status.Queued, status.NotSelected, status.Blank, status.State));
        Assert.DoesNotContain("secret-marker", JsonSerializer.Serialize(source.Snapshot()), StringComparison.Ordinal);
        using JsonDocument first = JsonDocument.Parse(sink.Records.First());
        Assert.StartsWith("select-me", first.RootElement.GetProperty("message").GetString(), StringComparison.Ordinal);
        Assert.Equal(path, first.RootElement.GetProperty("path").GetString());
        Assert.Equal(Line("history").Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            first.RootElement.GetProperty("offset").GetString());
    }

    [Fact]
    public async Task FullQueue_StopsReadingRewindsToTheLineAndLosesNothing()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("one") + Line("two") + Line("three"), cancellation);
        bool full = false;
        FakeSink sink = new(record => full && record.Contains("two", StringComparison.Ordinal)
            ? FileTailSubmitOutcome.Unavailable : FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);

        full = true;
        FileTailPollResult blocked = await source.PollOnceAsync("auth", cancellation);
        Assert.True(blocked.Backpressure);
        Assert.Equal(1, blocked.Lines);
        Assert.Equal("backpressure", source.Snapshot()[0].State);
        FileTailCursor stored = FileTailCursor.Deserialize(cursors.Value("file:auth"))!;
        Assert.Equal(Line("one").Length, stored.Offset);

        // Still full: the same line is offered again, never skipped.
        Assert.True((await source.PollOnceAsync("auth", cancellation)).Backpressure);
        full = false;
        Assert.False((await source.PollOnceAsync("auth", cancellation)).Backpressure);

        string[] messages = [.. sink.Records.Select(Message).Distinct()];
        Assert.Equal(["one", "two", "three"], messages.Select(message => message.Split(' ')[0]));
        FileTailInputStatus status = source.Snapshot()[0];
        Assert.Equal((3, 2, "running"), (status.Queued, status.Backpressure, status.State));
    }

    [Fact]
    public async Task DurableCursor_ResumesAfterRestartAndACrashBeforeCommitReplaysTheSameIds()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        string queue = Path.Combine(directory.Path, "queue.db");
        await File.WriteAllTextAsync(path, Line("one") + Line("two"), cancellation);
        FileTailSourceConfiguration configuration = Configuration(directory.Path, path, startAt: "beginning");

        // First run: the queue takes both lines, then the process dies before the cursor commit.
        FakeSink first = new(_ => FileTailSubmitOutcome.Queued);
        EfSourceCursorStore store = new(queue);
        await store.InitializeAsync(cancellation);
        await using (FileTailSource crashed = new(configuration, first, new FailingCommitCursors(store)))
        {
            await Assert.ThrowsAsync<IOException>(() => crashed.PollOnceAsync("auth", cancellation));
        }

        Assert.Null(await store.ReadAsync("file:auth", cancellation));

        // Restart: the same lines are read again with the same ids (the queue drops them as duplicates).
        FakeSink second = new(record => first.Records.Select(Id).Contains(Id(record), StringComparer.Ordinal)
            ? FileTailSubmitOutcome.Duplicate : FileTailSubmitOutcome.Queued);
        await using (FileTailSource restarted = new(configuration, second, new EfSourceCursorStore(queue)))
        {
            await restarted.PollOnceAsync("auth", cancellation);
            Assert.Equal(first.Records.Select(Id), second.Records.Select(Id));
            Assert.Equal(2, restarted.Snapshot()[0].Duplicates);
        }

        // Another restart resumes after the committed cursor: only new lines are read.
        await File.AppendAllTextAsync(path, Line("three"), cancellation);
        FakeSink third = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource resumed = new(configuration, third, new EfSourceCursorStore(queue));
        await resumed.PollOnceAsync("auth", cancellation);
        Assert.Equal("three", Message(Assert.Single(third.Records)).Split(' ')[0]);
    }

    [Fact]
    public async Task MalformedOversizedAndRejectedLines_AreCountedDroppedAndConsumed()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "app.jsonl");
        byte[] content = [.. Encoding.UTF8.GetBytes("""{"event":"login","pad":"0123456789012345678901234567890123456789012345"}""" + "\n"),
            .. Encoding.UTF8.GetBytes("not json\n"),
            .. "{\"a\":\""u8, 0xFF, .. "\"}\n"u8,
            .. Encoding.UTF8.GetBytes("{\"big\":\"" + new string('x', 400) + "\"}\n"),
            .. Encoding.UTF8.GetBytes("""{"event":"other"}""" + "\n")];
        await File.WriteAllBytesAsync(path, content, cancellation);
        FakeSink sink = new(record => record.Contains("login", StringComparison.Ordinal)
            ? FileTailSubmitOutcome.Rejected : FileTailSubmitOutcome.Invalid);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(
            Configuration(directory.Path, path, startAt: "beginning", format: FileTailFormats.JsonLines, maxLineBytes: 256), sink, cursors);

        await source.PollOnceAsync("auth", cancellation);

        Assert.Equal(2, sink.Records.Count);
        FileTailInputStatus status = source.Snapshot()[0];
        Assert.Equal((2, 1, 1, 1), (status.Malformed, status.Oversized, status.Rejected, status.ParserErrors));
        Assert.Equal(content.Length, FileTailCursor.Deserialize(cursors.Value("file:auth"))!.Offset);
        using JsonDocument record = JsonDocument.Parse(sink.Records.First());
        Assert.Equal("login", record.RootElement.GetProperty("json").GetProperty("event").GetString());
    }

    [Fact]
    public async Task BoundedPolls_ReadAtMostTheLineLimitAndAskForMore()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, string.Concat(Enumerable.Range(0, 5).Select(index => Line($"line-{index}"))), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(
            Configuration(directory.Path, path, startAt: "beginning") with { MaxLinesPerBatch = 2 }, sink, new MemoryCursors());

        Assert.Equal((2, true), Shape(await source.PollOnceAsync("auth", cancellation)));
        Assert.Equal((2, true), Shape(await source.PollOnceAsync("auth", cancellation)));
        Assert.Equal((1, false), Shape(await source.PollOnceAsync("auth", cancellation)));
        Assert.Equal(5, sink.Records.Count);

        static (int, bool) Shape(FileTailPollResult result) => (result.Lines, result.More);
    }

    [Fact]
    public async Task Rotation_IsCountedAndAMissedRotationIsAGap()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, new MemoryCursors());
        await source.PollOnceAsync("auth", cancellation);

        await File.AppendAllTextAsync(path, Line("first-2"), cancellation);
        File.Move(path, path + ".1");
        await File.WriteAllTextAsync(path, Line("second-1"), cancellation);
        Assert.True((await source.PollOnceAsync("auth", cancellation)).More);
        await source.PollOnceAsync("auth", cancellation);

        File.Move(path, path + ".1", overwrite: true);
        await File.WriteAllTextAsync(path, Line("third-1"), cancellation);
        File.Move(path, path + ".1", overwrite: true);
        await File.WriteAllTextAsync(path, Line("fourth-1"), cancellation);
        await source.PollOnceAsync("auth", cancellation);

        Assert.Equal(["first-1", "first-2", "second-1", "fourth-1"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        FileTailInputStatus status = source.Snapshot()[0];
        Assert.Equal((1, 1), (status.Rotations, status.RotationGaps));
    }

    [Fact]
    public async Task MissingFile_WaitsAndIsReadFromItsStartOnceCreated()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "later", "auth.log");
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(Configuration(directory.Path, path), sink, new MemoryCursors());

        await source.PollOnceAsync("auth", cancellation);
        Assert.Equal("waiting", source.Snapshot()[0].State);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, Line("created"), cancellation);
        await source.PollOnceAsync("auth", cancellation);

        Assert.Single(sink.Records);
        Assert.Equal("running", source.Snapshot()[0].State);
    }

    [Fact]
    public void PathGuards_RefuseLinksDirectoriesAndPathsOutsideTheRoots()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        using TemporaryDirectory directory = new();
        using TemporaryDirectory outside = new();
        string root = Path.Combine(directory.Path, "logs");
        Directory.CreateDirectory(Path.Combine(root, "app"));
        string secret = Path.Combine(outside.Path, "shadow");
        File.WriteAllText(secret, Line("secret"));
        string inside = Path.Combine(root, "app", "real.log");
        File.WriteAllText(inside, Line("real"));
        File.CreateSymbolicLink(Path.Combine(root, "escape.log"), secret);
        File.CreateSymbolicLink(Path.Combine(root, "inside.log"), inside);
        File.CreateSymbolicLink(Path.Combine(root, "chain.log"), Path.Combine(root, "inside.log"));
        Directory.CreateSymbolicLink(Path.Combine(root, "linked"), outside.Path);
        Directory.CreateSymbolicLink(Path.Combine(root, "linked-inside"), Path.Combine(root, "app"));
        string[] roots = [root];

        Assert.Equal(FileTailPathState.Ready, FileTailPaths.Resolve(inside, roots, false).State);
        Assert.Equal(FileTailPathState.Missing, FileTailPaths.Resolve(Path.Combine(root, "app", "none.log"), roots, false).State);
        Assert.Equal(FileTailPathState.Missing, FileTailPaths.Resolve(Path.Combine(root, "none", "a.log"), roots, false).State);
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(secret, roots, true).State);
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(Path.Combine(root, "app"), roots, false).State);
        // The file itself is a link: refused unless allowed, and an allowed link must stay inside a root.
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(Path.Combine(root, "inside.log"), roots, false).State);
        Assert.Equal((FileTailPathState.Ready, inside), FileTailPaths.Resolve(Path.Combine(root, "inside.log"), roots, true));
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(Path.Combine(root, "escape.log"), roots, true).State);
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(Path.Combine(root, "chain.log"), roots, true).State);
        // A linked directory between the root and the file is refused, even one pointing inside.
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(Path.Combine(root, "linked", "shadow"), roots, true).State);
        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(Path.Combine(root, "linked-inside", "real.log"), roots, true).State);
    }

    [Fact]
    public async Task RefusedPath_IsNeverReadAndReportsTheFailureCode()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using TemporaryDirectory outside = new();
        string secret = Path.Combine(outside.Path, "shadow");
        await File.WriteAllTextAsync(secret, Line("root:secret-marker"), cancellation);
        string path = Path.Combine(directory.Path, "auth.log");
        File.CreateSymbolicLink(path, secret);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);

        FileTailException refused = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("auth", cancellation));

        Assert.Equal(FileTailFailures.PathRefused, refused.Code);
        Assert.Empty(sink.Records);
        Assert.Null(cursors.Value("file:auth"));
        FileTailInputStatus status = source.Snapshot()[0];
        Assert.Equal((FileTailFailures.PathRefused, 1), (status.State, status.ReadErrors));
    }

    [Fact]
    public async Task Cancellation_StopsWithinASubmissionAndCommitsOnlyHandledLines()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("one") + Line("block") + Line("three"), cancellation);
        BlockingSink sink = new("block");
        MemoryCursors cursors = new();
        FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning") with { PollIntervalMilliseconds = 100 }, sink, cursors);
        await source.StartAsync(cancellation);
        await sink.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellation);

        await source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), cancellation);

        Assert.Equal("stopped", source.Snapshot()[0].State);
        Assert.Equal(Line("one").Length, FileTailCursor.Deserialize(cursors.Value("file:auth"))!.Offset);
    }

    [Fact]
    public async Task RunLoop_TailsNewLinesUntilStopped()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("history"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(
            Configuration(directory.Path, path) with { PollIntervalMilliseconds = 100 }, sink, new MemoryCursors());
        await source.StartAsync(cancellation);
        await WaitFor(() => source.Snapshot()[0].Offset is not null, cancellation);
        await File.AppendAllTextAsync(path, Line("live"), cancellation);
        await WaitFor(() => !sink.Records.IsEmpty, cancellation);
        Assert.Equal("live", Message(Assert.Single(sink.Records)).Split(' ')[0]);
    }

    [Fact]
    public void Configuration_LoadsDefaultsAndRejectsOversizedFiles()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "file.json");
        File.WriteAllText(path, """
            {"apiVersion":"bower.security/v1","kind":"FileTailSource","allowedRoots":["/var/log"],
             "inputs":[{"id":"auth","path":"/var/log/auth.log","route":{"pack":"linux-authlog-ssh","parser":0}}]}
            """);
        FileTailSourceConfiguration configuration = FileTailSourceConfigurationLoader.LoadFile(path);
        FileTailInputOptions input = Assert.Single(configuration.Inputs);
        Assert.Equal((FileTailFormats.Text, "end", 16_384, false), (input.Format, input.StartAt, input.MaxLineBytes, input.AllowSymlink));
        Assert.Equal((1_000, 256, 1_048_576), (configuration.PollIntervalMilliseconds, configuration.MaxLinesPerBatch, configuration.MaxBytesPerBatch));
        Assert.Equal("file:auth", input.SourceId);

        File.WriteAllText(path, new string(' ', 262_145));
        Assert.Throws<InvalidDataException>(() => FileTailSourceConfigurationLoader.LoadFile(path));
        Assert.Throws<FileNotFoundException>(() => FileTailSourceConfigurationLoader.LoadFile(Path.Combine(directory.Path, "none.json")));
    }

    internal static string Line(string text) => text + " " + new string('x', Math.Max(0, 69 - text.Length)) + "\n";

    private static string Message(string record)
    {
        using JsonDocument document = JsonDocument.Parse(record);
        return document.RootElement.GetProperty("message").GetString()!;
    }

    private static string Id(string record)
    {
        using JsonDocument document = JsonDocument.Parse(record);
        return document.RootElement.GetProperty("id").GetString()!;
    }

    private static FileTailSourceConfiguration Configuration(
        string root, string path, string startAt = "end", string format = FileTailFormats.Text, int maxLineBytes = 16_384) =>
        new("bower.security/v1", "FileTailSource", [root],
            [new FileTailInputOptions("auth", path, new FileTailRoute("pack", 0), format, startAt, maxLineBytes)]);

    private static async Task WaitFor(Func<bool> condition, CancellationToken cancellation)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        while (!condition())
        {
            await Task.Delay(20, timeout.Token);
        }
    }

    private sealed class FakeSink(Func<string, FileTailSubmitOutcome> decide) : IFileTailSink
    {
        public ConcurrentQueue<string> Records { get; } = new();

        public ValueTask<FileTailSubmitOutcome> SubmitAsync(FileTailInputOptions input, string record, CancellationToken cancellationToken)
        {
            Records.Enqueue(record);
            return ValueTask.FromResult(decide(record));
        }
    }

    private sealed class BlockingSink(string marker) : IFileTailSink
    {
        public TaskCompletionSource Blocked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<FileTailSubmitOutcome> SubmitAsync(FileTailInputOptions input, string record, CancellationToken cancellationToken)
        {
            if (record.Contains(marker, StringComparison.Ordinal))
            {
                Blocked.TrySetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return FileTailSubmitOutcome.Queued;
        }
    }

    internal sealed class MemoryCursors : ISourceCursorStore
    {
        private readonly ConcurrentDictionary<string, SourceCursorSnapshot> values = new(StringComparer.Ordinal);

        public string? Value(string sourceId) => values.TryGetValue(sourceId, out SourceCursorSnapshot? snapshot) ? snapshot.Value : null;

        public Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default) =>
            Task.FromResult(values.TryGetValue(sourceId, out SourceCursorSnapshot? snapshot) ? snapshot : null);

        public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value, DateTimeOffset updatedAt, CancellationToken cancellationToken = default)
        {
            lock (values)
            {
                long current = values.TryGetValue(sourceId, out SourceCursorSnapshot? snapshot) ? snapshot.Version : 0;
                if (current != expectedVersion)
                {
                    return Task.FromResult(false);
                }

                values[sourceId] = new SourceCursorSnapshot(value, expectedVersion + 1);
                return Task.FromResult(true);
            }
        }
    }

    /// <summary>Simulates a crash after enqueue and before the cursor commit.</summary>
    private sealed class FailingCommitCursors(ISourceCursorStore inner) : ISourceCursorStore
    {
        public Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(sourceId, cancellationToken);

        public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value, DateTimeOffset updatedAt, CancellationToken cancellationToken = default) =>
            throw new IOException("injected crash before commit");
    }
}
