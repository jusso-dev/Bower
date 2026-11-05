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
            MaxBytesPerBatch = options["maxBytesPerBatch"]?.GetValue<int>() ?? 1_048_576,
            RotationGracePolls = options["rotationGracePolls"]?.GetValue<int>() ?? 1,
            RotationDrainMaxPolls = options["rotationDrainMaxPolls"]?.GetValue<int>() ?? FileTailSourceConfigurationLoader.DefaultRotationDrainMaxPolls,
            // Identities alone decide unless the sequence models device and inode numbers
            // ("fileIds"): the Rust port uses its real ones, C# models the same rules here, so
            // both runtimes agree on every platform.
            UseFileIds = options["fileIds"]?.GetValue<bool>() ?? false
        };
        // device:inode of each path: kept by in-place writes, appends and copytruncate, moved
        // to path.1 by a rename, new whenever a file is created or restored.
        Dictionary<string, string> ids = new(StringComparer.Ordinal);
        int nextId = 0;
        void Created(string at)
        {
            if (!File.Exists(at))
            {
                ids[at] = $"1:{++nextId}";
            }
        }

        FileTailHandle.FileIds = at => File.Exists(at) && ids.TryGetValue(at, out string? id) ? id : null;
        try
        {
            RunSteps(sequence, path, rotated, reader, ids, Created, () => $"1:{++nextId}");
        }
        finally
        {
            FileTailHandle.FileIds = null;
        }
    }

    private static void RunSteps(
        JsonObject sequence, string path, string rotated, FileTailReaderOptions reader,
        Dictionary<string, string> ids, Action<string> created, Func<string> newId)
    {
        FileTailCursor? cursor = null;
        foreach (JsonObject step in sequence["steps"]!.AsArray().Select(node => node!.AsObject()))
        {
            if (step["write"] is { } write)
            {
                created(path);
                // In place (same file), as a writer truncating and rewriting would.
                using FileStream stream = new(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                stream.SetLength(0);
                stream.Write(Encoding.UTF8.GetBytes(write.GetValue<string>()));
            }
            else if (step["append"] is { } append)
            {
                created(path);
                File.AppendAllText(path, append.GetValue<string>());
            }
            else if (step["appendRotated"] is { } late)
            {
                // A writer that has not reopened its file yet keeps writing to path.1.
                File.AppendAllText(rotated, late.GetValue<string>());
            }
            else if (step.ContainsKey("deleteRotated"))
            {
                File.Delete(rotated);
                ids.Remove(rotated);
            }
            else if (step.ContainsKey("rename"))
            {
                File.Move(path, rotated, overwrite: true);
                ids[rotated] = ids.GetValueOrDefault(path, newId());
                ids.Remove(path);
            }
            else if (step.ContainsKey("restore"))
            {
                // The same content at a new inode, as a restore from backup or a copy leaves it.
                File.WriteAllBytes(path + ".restore", File.ReadAllBytes(path));
                File.Move(path + ".restore", path, overwrite: true);
                ids[path] = newId();
            }
            else if (step.ContainsKey("copytruncate"))
            {
                ids[rotated] = newId();
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
            ["drain"] = batch.Cursor.Drain,
            ["abandoned"] = batch.Cursor.Abandoned is not null,
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
        Assert.Equal("""{"schemaVersion":2,"fingerprint":"","offset":0}""",
            new FileTailCursor(FileTailCursor.CurrentSchemaVersion, string.Empty, 0).Serialize());
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":3,"fingerprint":"","offset":0}"""));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"zz","offset":0}"""));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"","offset":-1}"""));
        Assert.Null(FileTailCursor.Deserialize("not json"));
        // Every field, in the order both runtimes write it (Rust: cursor_json_matches_csharp).
        string full = $$"""{"schemaVersion":2,"fingerprint":"{{new string('a', 64)}}","offset":42,"discarding":true,"fileId":"1:2","drain":"rename","observedLength":10,"observedWriteTime":11,"stablePolls":1,"drainPolls":3,"drainLength":12,"abandoned":"{{new string('b', 64)}}","abandonedLength":13}""";
        Assert.Equal(full, FileTailCursor.Deserialize(full)!.Serialize());
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"","offset":0,"drainLength":5}"""));
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
        // Drain path.1, wait one unchanged poll (grace), then move to the new file.
        Assert.False((await source.PollOnceAsync("auth", cancellation)).More);
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

    [Fact]
    public void RotatedFileSwappedForAnOutsideLinkBeforeTheOpen_IsRefusedAndNeverRead()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        using TemporaryDirectory directory = new();
        using TemporaryDirectory outside = new();
        string path = Path.Combine(directory.Path, "auth.log");
        string rotated = path + ".1";
        string secret = Path.Combine(outside.Path, "shadow");
        File.WriteAllText(secret, Line("root:secret-marker"));
        File.WriteAllText(path, Line("first-1"));
        FileTailReaderOptions options = new() { StartAtEnd = false, RotationGracePolls = 1 };
        FileTailCursor cursor = FileTailReader.Read(path, null, null, options, cancellationToken: TestContext.Current.CancellationToken).Cursor;
        File.AppendAllText(path, Line("first-2"));
        File.Move(path, rotated);
        File.WriteAllText(path, Line("second-1"));
        // path.1 passed validation; it is replaced by a link to a file outside the root
        // after the check and before the open.
        Assert.Equal(FileTailPathState.Ready, FileTailPaths.Resolve(rotated, [directory.Path], false).State);
        FileTailHandle.BeforeOpen = opening =>
        {
            if (opening == rotated)
            {
                File.Delete(rotated);
                File.CreateSymbolicLink(rotated, secret);
            }
        };
        try
        {
            Assert.Throws<FileTailRefusedException>(() => FileTailReader.Read(path, rotated, cursor, options, cancellationToken: TestContext.Current.CancellationToken));
        }
        finally
        {
            FileTailHandle.BeforeOpen = null;
        }

        Assert.Equal(FileTailPathState.Refused, FileTailPaths.Resolve(rotated, [directory.Path], false).State);
    }

    [Fact]
    public async Task RotatedFileThatBecomesALink_FailsThePollWithoutReadingIt()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using TemporaryDirectory outside = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);
        await source.PollOnceAsync("auth", cancellation);
        string secret = Path.Combine(outside.Path, "shadow");
        await File.WriteAllTextAsync(secret, Line("root:secret-marker"), cancellation);
        File.Move(path, Path.Combine(outside.Path, "moved"));
        File.CreateSymbolicLink(path + ".1", secret);
        await File.WriteAllTextAsync(path, Line("second-1"), cancellation);

        FileTailException refused = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("auth", cancellation));

        Assert.Equal(FileTailFailures.PathRefused, refused.Code);
        Assert.DoesNotContain(sink.Records, record => record.Contains("secret-marker", StringComparison.Ordinal));
        Assert.Equal(Line("first-1").Length, FileTailCursor.Deserialize(cursors.Value("file:auth"))!.Offset);
    }

    [Fact]
    public void FileReplacedWhileBeingRead_OnlyItsOwnGenerationMovesTheCursor()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "app.log");
        File.WriteAllText(path, Line("old-1"));
        FileTailReaderOptions options = new() { StartAtEnd = false, RotationGracePolls = 1 };
        FileTailCursor cursor = FileTailReader.Read(path, null, null, options, cancellationToken: TestContext.Current.CancellationToken).Cursor;
        string oldIdentity = cursor.Fingerprint;
        File.AppendAllText(path, Line("old-2"));
        // Another generation replaces the path right after it was opened and identified.
        string replacement = Path.Combine(directory.Path, "replacement");
        File.WriteAllText(replacement, Line("new-1") + Line("new-2") + Line("new-3"));
        FileTailHandle.AfterOpen = opened =>
        {
            if (opened == path)
            {
                File.Move(replacement, path, overwrite: true);
            }
        };
        FileTailBatch batch;
        try
        {
            batch = FileTailReader.Read(path, null, cursor, options, cancellationToken: TestContext.Current.CancellationToken);
        }
        finally
        {
            FileTailHandle.AfterOpen = null;
        }

        FileTailLine line = Assert.Single(batch.Lines);
        Assert.StartsWith("old-2", Encoding.UTF8.GetString(line.Bytes), StringComparison.Ordinal);
        Assert.Equal((oldIdentity, (long)Line("old-1").Length * 2), (batch.Cursor.Fingerprint, batch.Cursor.Offset));

        // The next read sees the new generation: a missed rotation, read from its start.
        FileTailBatch next = FileTailReader.Read(path, null, batch.Cursor, options, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(next.Gap);
        Assert.Equal(3, next.Lines.Count);
        Assert.NotEqual(oldIdentity, next.Cursor.Fingerprint);
    }

    [Fact]
    public async Task StopInsideAnOversizedLine_RewindsAndKeepsDiscarding()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("before") + new string('o', 300), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors memory = new();
        FileTailSourceConfiguration configuration = Configuration(directory.Path, path, startAt: "beginning", maxLineBytes: 256);
        await using (FileTailSource first = new(configuration, sink, memory))
        {
            await first.PollOnceAsync("auth", cancellation);
        }

        FileTailCursor discarding = FileTailCursor.Deserialize(memory.Value("file:auth"))!;
        Assert.True(discarding.Discarding);
        await File.AppendAllTextAsync(path, "ooo\n" + Line("after"), cancellation);
        using CancellationTokenSource stop = new();
        await using FileTailSource stopping = new(configuration, sink, new CancelOnRead(memory, stop));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stopping.PollOnceAsync("auth", stop.Token));

        FileTailCursor stored = FileTailCursor.Deserialize(memory.Value("file:auth"))!;
        Assert.Equal((discarding.Offset, true), (stored.Offset, stored.Discarding));
        Assert.Single(sink.Records);
    }

    [Fact]
    public async Task FullQueueWhileDrainingTheRotatedFile_RewindsIntoItAndLosesNothing()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        bool full = false;
        FakeSink sink = new(record => full && record.Contains("first-3", StringComparison.Ordinal)
            ? FileTailSubmitOutcome.Unavailable : FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);
        await source.PollOnceAsync("auth", cancellation);
        string generation = FileTailCursor.Deserialize(cursors.Value("file:auth"))!.Fingerprint;
        await File.AppendAllTextAsync(path, Line("first-2") + Line("first-3") + Line("first-4"), cancellation);
        File.Move(path, path + ".1");
        await File.WriteAllTextAsync(path, Line("second-1"), cancellation);

        full = true;
        Assert.True((await source.PollOnceAsync("auth", cancellation)).Backpressure);
        FileTailCursor rewound = FileTailCursor.Deserialize(cursors.Value("file:auth"))!;
        Assert.Equal((generation, Line("first-1").Length * 2L), (rewound.Fingerprint, rewound.Offset));
        full = false;
        for (int poll = 0; poll < 4; poll++)
        {
            await source.PollOnceAsync("auth", cancellation);
        }

        Assert.Equal(["first-1", "first-2", "first-3", "first-4", "second-1"],
            sink.Records.Select(record => Message(record).Split(' ')[0]).Distinct());
        Assert.Equal((5, 0), (source.Snapshot()[0].Queued, source.Snapshot()[0].RotationGaps));
    }

    [Fact]
    public async Task SinkFailure_CommitsHandledLinesAndRetriesTheFailedOne()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("one") + Line("fail"), cancellation);
        bool failing = true;
        FakeSink sink = new(record => failing && record.Contains("fail", StringComparison.Ordinal)
            ? throw new IOException("injected sink failure") : FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);

        FileTailException failed = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("auth", cancellation));

        Assert.Equal(FileTailFailures.SubmitFailed, failed.Code);
        Assert.Equal(Line("one").Length, FileTailCursor.Deserialize(cursors.Value("file:auth"))!.Offset);
        Assert.Equal(1, source.Snapshot()[0].SubmitFailures);
        failing = false;
        await source.PollOnceAsync("auth", cancellation);
        Assert.Equal(["one", "fail", "fail"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        Assert.Equal(2, source.Snapshot()[0].Queued);
    }

    [Fact]
    public void StartAtEnd_ScanIsBoundedAndCancellable()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "app.log");
        File.WriteAllText(path, Line("first") + new string('z', 200_000));
        FileTailReaderOptions options = new() { StartAtEnd = true, MaxBytesPerBatch = 65_536 };

        FileTailBatch batch = FileTailReader.Read(path, null, null, options, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal((new FileInfo(path).Length, true), (batch.Cursor.Offset, batch.Cursor.Discarding));
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => FileTailReader.Read(path, null, null, options, cancelled.Token));
    }

    [Fact]
    public void AllowedLinkToAnotherInputsFile_IsRefusedAtLoad()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        using TemporaryDirectory directory = new();
        string auth = Path.Combine(directory.Path, "auth.log");
        string linked = Path.Combine(directory.Path, "alias.log");
        File.WriteAllText(auth, Line("one"));
        File.CreateSymbolicLink(linked, auth + ".1");
        string configuration = Path.Combine(directory.Path, "file.json");
        File.WriteAllText(configuration, new JsonObject
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "FileTailSource",
            ["allowedRoots"] = new JsonArray(directory.Path),
            ["inputs"] = new JsonArray(
                new JsonObject { ["id"] = "auth", ["path"] = auth, ["route"] = new JsonObject { ["pack"] = "p", ["parser"] = 0 } },
                new JsonObject { ["id"] = "alias", ["path"] = linked, ["allowSymlink"] = true, ["route"] = new JsonObject { ["pack"] = "p", ["parser"] = 0 } })
        }.ToJsonString());

        InvalidDataException refused = Assert.Throws<InvalidDataException>(() => FileTailSourceConfigurationLoader.LoadFile(configuration));
        Assert.Equal("File tail input alias: allowSymlink target is another input's file or rotated file.", refused.Message);
    }

    [Fact]
    public async Task RestartMidDrain_ContinuesThePersistedDrainWithoutLossOrDuplicates()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        FileTailSourceConfiguration configuration = Configuration(directory.Path, path, startAt: "beginning") with { RotationGracePolls = 2 };
        await using (FileTailSource first = new(configuration, sink, cursors))
        {
            await first.PollOnceAsync("auth", cancellation);
            await File.AppendAllTextAsync(path, Line("first-2"), cancellation);
            File.Move(path, path + ".1");
            await File.WriteAllTextAsync(path, Line("second-1"), cancellation);
            await first.PollOnceAsync("auth", cancellation); // Drains first-2; the grace window starts.
            await first.PollOnceAsync("auth", cancellation); // One unchanged end-of-file poll.
        }

        FileTailCursor persisted = FileTailCursor.Deserialize(cursors.Value("file:auth"))!;
        Assert.Equal((FileTailCursor.RenameDrain, 1), (persisted.Drain, persisted.StablePolls));

        // A restart resumes the drain and its grace window from the cursor.
        await File.AppendAllTextAsync(path + ".1", Line("first-3 late but before the switch"), cancellation);
        await using FileTailSource restarted = new(configuration, sink, cursors);
        for (int poll = 0; poll < 5; poll++)
        {
            await restarted.PollOnceAsync("auth", cancellation);
        }

        Assert.Equal(["first-1", "first-2", "first-3", "second-1"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        Assert.Equal((1, 0), (restarted.Snapshot()[0].Rotations, restarted.Snapshot()[0].RotationGaps));
    }

    [Fact]
    public async Task RestartAfterTheSwitch_StillCountsLateWritesToTheAbandonedGeneration()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        FileTailSourceConfiguration configuration = Configuration(directory.Path, path, startAt: "beginning");
        await using (FileTailSource first = new(configuration, sink, cursors))
        {
            await first.PollOnceAsync("auth", cancellation);
            File.Move(path, path + ".1");
            await File.WriteAllTextAsync(path, Line("second-1"), cancellation);
            for (int poll = 0; poll < 3; poll++)
            {
                await first.PollOnceAsync("auth", cancellation);
            }

            Assert.Equal(1, first.Snapshot()[0].Rotations);
        }

        Assert.NotNull(FileTailCursor.Deserialize(cursors.Value("file:auth"))!.Abandoned);
        await File.AppendAllTextAsync(path + ".1", Line("written after the switch"), cancellation);
        await using FileTailSource restarted = new(configuration, sink, cursors);
        await restarted.PollOnceAsync("auth", cancellation);

        Assert.Equal(1, restarted.Snapshot()[0].RotationGaps);
        Assert.DoesNotContain(sink.Records, record => record.Contains("written after", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BackpressureOnTheSwitchingBatch_RewindsIntoTheDrainWithoutAFalseGap()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        bool full = false;
        FakeSink sink = new(record => full && record.Contains("tail", StringComparison.Ordinal)
            ? FileTailSubmitOutcome.Unavailable : FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);
        await source.PollOnceAsync("auth", cancellation);
        await File.AppendAllTextAsync(path, "tail without a newline, completed only by the switch", cancellation);
        File.Move(path, path + ".1");
        await File.WriteAllTextAsync(path, Line("second-1"), cancellation);
        await source.PollOnceAsync("auth", cancellation); // End of path.1; the window starts.

        full = true;
        Assert.True((await source.PollOnceAsync("auth", cancellation)).Backpressure); // The switching batch is refused.
        FileTailCursor rewound = FileTailCursor.Deserialize(cursors.Value("file:auth"))!;
        Assert.Equal((FileTailCursor.RenameDrain, (string?)null), (rewound.Drain, rewound.Abandoned));

        // The writer adds to path.1 before the switch commits: still part of the drain, not a gap.
        await File.AppendAllTextAsync(path + ".1", "\n" + Line("first-3"), cancellation);
        full = false;
        for (int poll = 0; poll < 4; poll++)
        {
            await source.PollOnceAsync("auth", cancellation);
        }

        Assert.Equal(["first-1", "tail", "first-3", "second-1"], sink.Records.Select(record => Message(record).Split(' ')[0]).Distinct());
        Assert.Equal(0, source.Snapshot()[0].RotationGaps);
    }

    [Fact]
    public void CopytruncateDetectedByInode_DrainsWithoutGraceAndRenameByInodeKeepsIt()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Device and inode numbers are read on Linux only.");
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "app.log");
        string rotated = path + ".1";
        FileTailReaderOptions options = new() { StartAtEnd = false, RotationGracePolls = 3 };
        File.WriteAllText(path, Line("first-1"));
        FileTailCursor cursor = FileTailReader.Read(path, null, null, options, TestContext.Current.CancellationToken).Cursor;
        Assert.NotNull(cursor.FileId);
        File.AppendAllText(path, Line("first-2"));
        // copytruncate with a new first line: the original stays at the path.
        File.Copy(path, rotated);
        using (FileStream truncate = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            truncate.SetLength(0);
        }

        File.AppendAllText(path, Line("second-1"));
        FileTailBatch copied = FileTailReader.Read(path, rotated, cursor, options, TestContext.Current.CancellationToken);
        Assert.True(copied.Rotated); // No grace window for a copy.
        Assert.StartsWith("first-2", Encoding.UTF8.GetString(Assert.Single(copied.Lines).Bytes), StringComparison.Ordinal);

        // A rename with the same first line: another file at the path, so the old one is drained.
        FileTailCursor at = FileTailReader.Read(path, null, copied.Cursor, options, TestContext.Current.CancellationToken).Cursor;
        File.Delete(rotated);
        File.Move(path, rotated);
        File.WriteAllText(path, Line("second-1") + Line("third-1"));
        FileTailBatch renamed = FileTailReader.Read(path, rotated, at, options, TestContext.Current.CancellationToken);
        Assert.Equal(FileTailCursor.RenameDrain, renamed.Cursor.Drain);
    }

    [Fact]
    public void TwoAllowedLinksToTheSameFile_AreRefusedAtLoad()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        using TemporaryDirectory directory = new();
        string real = Path.Combine(directory.Path, "real.log");
        File.WriteAllText(real, Line("one"));
        string first = Path.Combine(directory.Path, "first.log");
        string second = Path.Combine(directory.Path, "second.log");
        File.CreateSymbolicLink(first, real);
        File.CreateSymbolicLink(second, real);
        JsonObject Input(string id, string path) => new()
        {
            ["id"] = id,
            ["path"] = path,
            ["allowSymlink"] = true,
            ["route"] = new JsonObject { ["pack"] = "p", ["parser"] = 0 }
        };
        string configuration = Path.Combine(directory.Path, "file.json");
        File.WriteAllText(configuration, new JsonObject
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "FileTailSource",
            ["allowedRoots"] = new JsonArray(directory.Path),
            ["inputs"] = new JsonArray(Input("first", first), Input("second", second))
        }.ToJsonString());

        InvalidDataException refused = Assert.Throws<InvalidDataException>(() => FileTailSourceConfigurationLoader.LoadFile(configuration));
        Assert.Equal("File tail input first: allowSymlink target is another input's file or rotated file.", refused.Message);
    }

    [Fact]
    public async Task TwoAllowedLinksThatMeetAfterLoad_AreRefusedAtReadTime()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string real = Path.Combine(directory.Path, "real.log");
        string other = Path.Combine(directory.Path, "other.log");
        await File.WriteAllTextAsync(real, Line("one"), cancellation);
        await File.WriteAllTextAsync(other, Line("two"), cancellation);
        string first = Path.Combine(directory.Path, "first.log");
        string second = Path.Combine(directory.Path, "second.log");
        File.CreateSymbolicLink(first, real);
        File.CreateSymbolicLink(second, other);
        FileTailSourceConfiguration configuration = new("bower.security/v1", "FileTailSource", [directory.Path],
        [
            new FileTailInputOptions("first", first, new FileTailRoute("p", 0), StartAt: "beginning", AllowSymlink: true),
            new FileTailInputOptions("second", second, new FileTailRoute("p", 0), StartAt: "beginning", AllowSymlink: true)
        ]);
        FileTailSourceConfigurationLoader.ValidateLinks(configuration);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(configuration, sink, new MemoryCursors());
        File.Delete(second);
        File.CreateSymbolicLink(second, real);

        FileTailException refused = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("second", cancellation));
        Assert.Equal(FileTailFailures.PathRefused, refused.Code);
        // The input whose link did not move keeps reading.
        await source.PollOnceAsync("first", cancellation);
        Assert.Equal(["one"], sink.Records.Select(record => Message(record).Split(' ')[0]));
    }

    [Fact]
    public void LinuxOpenFlags_UseEachArchitecturesNoFollowValue()
    {
        Assert.Equal(0x20000 | 0x80000 | 0x800, LinuxTailFile.OpenFlags(System.Runtime.InteropServices.Architecture.X64));
        Assert.Equal(0x8000 | 0x80000 | 0x800, LinuxTailFile.OpenFlags(System.Runtime.InteropServices.Architecture.Arm64));
        // Unknown flag values: open without them and rely on the post-open checks.
        Assert.Null(LinuxTailFile.OpenFlags(System.Runtime.InteropServices.Architecture.X86));
        Assert.Null(LinuxTailFile.OpenFlags(System.Runtime.InteropServices.Architecture.Arm));
        Assert.Null(LinuxTailFile.OpenFlags(System.Runtime.InteropServices.Architecture.RiscV64));
    }

    [Fact]
    public void Cursor_RotationFieldsRoundTripAndInconsistentStateIsRefused()
    {
        FileTailCursor draining = new(FileTailCursor.CurrentSchemaVersion, new string('a', 64), 10, FileId: "2049:131",
            Drain: FileTailCursor.RenameDrain, ObservedLength: 10, ObservedWriteTime: 17_000_000_000_000_000, StablePolls: 1);
        Assert.Equal(draining, FileTailCursor.Deserialize(draining.Serialize()));
        Assert.Equal(
            """{"schemaVersion":2,"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","offset":10,"fileId":"2049:131","drain":"rename","observedLength":10,"observedWriteTime":17000000000000000,"stablePolls":1}""",
            draining.Serialize());
        FileTailCursor abandoned = new(FileTailCursor.CurrentSchemaVersion, new string('b', 64), 0, Abandoned: new string('a', 64), AbandonedLength: 99);
        Assert.Equal(abandoned, FileTailCursor.Deserialize(abandoned.Serialize()));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"","offset":0,"drain":"rename"}"""));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"%A","offset":0,"drain":"move"}""".Replace("%A", new string('a', 64), StringComparison.Ordinal)));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"","offset":0,"abandoned":"zz","abandonedLength":1}"""));
        Assert.Null(FileTailCursor.Deserialize("""{"schemaVersion":2,"fingerprint":"","offset":0,"fileId":"x:1"}"""));
    }

    [Fact]
    public void TheSameFileThroughALinkedDirectory_IsRefusedAtLoad()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        using TemporaryDirectory directory = new();
        // The shape of /var/run -> /run on standard Linux.
        string run = Path.Combine(directory.Path, "run");
        string varRun = Path.Combine(directory.Path, "varrun");
        Directory.CreateDirectory(Path.Combine(run, "security"));
        Directory.CreateSymbolicLink(varRun, run);
        File.WriteAllText(Path.Combine(run, "security", "auth.log"), Line("one"));
        string LoadWith(string otherPath)
        {
            string configuration = Path.Combine(directory.Path, "file.json");
            File.WriteAllText(configuration, new JsonObject
            {
                ["apiVersion"] = "bower.security/v1",
                ["kind"] = "FileTailSource",
                ["allowedRoots"] = new JsonArray(run, varRun),
                ["inputs"] = new JsonArray(
                    new JsonObject { ["id"] = "run", ["path"] = Path.Combine(run, "security", "auth.log"), ["route"] = new JsonObject { ["pack"] = "p", ["parser"] = 0 } },
                    new JsonObject { ["id"] = "var-run", ["path"] = otherPath, ["route"] = new JsonObject { ["pack"] = "p", ["parser"] = 0 } })
            }.ToJsonString());
            return Assert.Throws<InvalidDataException>(() => FileTailSourceConfigurationLoader.LoadFile(configuration)).Message;
        }

        Assert.Equal("File tail input var-run: path is already read by another input.",
            LoadWith(Path.Combine(varRun, "security", "auth.log")));
        Assert.Equal("File tail input var-run: path overlaps another input's rotated file (path.1).",
            LoadWith(Path.Combine(varRun, "security", "AUTH.log.1")));
        // A directory that does not exist yet falls back to the text rules.
        Assert.Equal(Path.Combine(directory.Path, "later", "a.log"), FileTailPaths.Canonical(Path.Combine(directory.Path, "later", "a.log")));
    }

    [Fact]
    public async Task TheSameFileThroughADirectoryLinkedAfterLoad_IsRefusedAtReadTime()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string run = Path.Combine(directory.Path, "run");
        string varRun = Path.Combine(directory.Path, "varrun");
        Directory.CreateDirectory(Path.Combine(run, "security"));
        Directory.CreateDirectory(Path.Combine(varRun, "security"));
        await File.WriteAllTextAsync(Path.Combine(run, "security", "auth.log"), Line("one"), cancellation);
        await File.WriteAllTextAsync(Path.Combine(varRun, "security", "auth.log"), Line("two"), cancellation);
        FileTailSourceConfiguration configuration = new("bower.security/v1", "FileTailSource", [run, varRun],
        [
            new FileTailInputOptions("run", Path.Combine(run, "security", "auth.log"), new FileTailRoute("p", 0), StartAt: "beginning"),
            new FileTailInputOptions("var-run", Path.Combine(varRun, "security", "auth.log"), new FileTailRoute("p", 0), StartAt: "beginning")
        ]);
        FileTailSourceConfigurationLoader.ValidateLinks(configuration);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        List<(string Input, string Reason)> refusals = [];
        await using FileTailSource source = new(configuration, sink, new MemoryCursors())
        {
            InputRefused = (input, reason) => refusals.Add((input, reason))
        };
        await source.PollOnceAsync("var-run", cancellation);

        Directory.Delete(varRun, recursive: true);
        Directory.CreateSymbolicLink(varRun, run);

        // Only the input whose resolution changed is refused; the other keeps reading.
        FileTailException refused = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("var-run", cancellation));
        Assert.Equal((FileTailFailures.PathRefused, FileTailRefusals.Overlap), (refused.Code, refused.Reason));
        await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("var-run", cancellation));
        await source.PollOnceAsync("run", cancellation);
        Assert.Equal(["two", "one"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        // Logged once per transition, with the id and reason code only.
        Assert.Equal([("var-run", FileTailRefusals.Overlap)], refusals);
    }

    [Fact]
    public async Task ALinkMovedOntoAnotherInputsFile_RefusesOnlyTheMovedInput()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string auth = Path.Combine(directory.Path, "auth.log");
        string other = Path.Combine(directory.Path, "other.log");
        string alias = Path.Combine(directory.Path, "alias.log");
        await File.WriteAllTextAsync(auth, Line("one"), cancellation);
        await File.WriteAllTextAsync(other, Line("two"), cancellation);
        File.CreateSymbolicLink(alias, other);
        FileTailSourceConfiguration configuration = new("bower.security/v1", "FileTailSource", [directory.Path],
        [
            new FileTailInputOptions("auth", auth, new FileTailRoute("p", 0), StartAt: "beginning"),
            new FileTailInputOptions("alias", alias, new FileTailRoute("p", 0), StartAt: "beginning", AllowSymlink: true)
        ]);
        FileTailSourceConfigurationLoader.ValidateLinks(configuration);
        List<(string Input, string Reason)> refusals = [];
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(configuration, sink, new MemoryCursors())
        {
            InputRefused = (input, reason) => refusals.Add((input, reason))
        };
        File.Delete(alias);
        File.CreateSymbolicLink(alias, auth);

        // auth's path never changed: it keeps collecting. alias moved onto it: refused.
        await source.PollOnceAsync("auth", cancellation);
        FileTailException refused = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("alias", cancellation));
        Assert.Equal(FileTailRefusals.Overlap, refused.Reason);
        Assert.Equal(["one"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        Assert.Equal([("alias", FileTailRefusals.Overlap)], refusals);
    }

    [Fact]
    public async Task APathOneThatKeepsChanging_IsLeftAtTheDrainCapAndLateWritesAreGaps()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        FileTailSourceConfiguration configuration = Configuration(directory.Path, path, startAt: "beginning")
            with
        { RotationGracePolls = 2, RotationDrainMaxPolls = 5 };
        await using (FileTailSource first = new(configuration, sink, cursors))
        {
            await first.PollOnceAsync("auth", cancellation);
        }

        File.Move(path, path + ".1");
        await File.WriteAllTextAsync(path, Line("second-1"), cancellation);
        long gaps = 0;
        // Sol's case: one line appended to path.1 before every poll, the cursor reloaded each time.
        for (int poll = 0; poll < 20; poll++)
        {
            await File.AppendAllTextAsync(path + ".1", Line($"late-{poll}"), cancellation);
            await using FileTailSource reloaded = new(configuration, sink, cursors);
            await reloaded.PollOnceAsync("auth", cancellation);
            gaps += reloaded.Snapshot()[0].RotationGaps;
        }

        string[] words = [.. sink.Records.Select(record => Message(record).Split(' ')[0])];
        // The cursor leaves path.1 at the cap (five drain polls), reads the current file, and
        // every later write to path.1 is counted as a gap instead of starving it.
        Assert.Equal(["first-1", "late-0", "late-1", "late-2", "late-3", "late-4", "second-1"], words);
        Assert.Equal(15, gaps); // late-5 to late-19.
    }

    [Theory]
    [InlineData("first-line identity (05fa1e6)", true)]
    [InlineData("64-byte identity (0649987)", false)]
    public async Task LegacyCursors_ReplayTheCurrentFileFromItsStartWithAGap(string format, bool firstLine)
    {
        _ = format;
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        string old = Line("old-1 with a first line long enough") + Line("old-2") + Line("old-3") + Line("old-4");
        // Mid-copytruncate: path.1 holds the copy, the original was truncated and rewritten.
        await File.WriteAllTextAsync(path + ".1", old, cancellation);
        await File.WriteAllTextAsync(path, Line("new-1") + Line("new-2") + Line("new-3"), cancellation);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(old);
        int identity = firstLine ? old.IndexOf('\n', StringComparison.Ordinal) + 1 : 64;
        string fingerprint = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes.AsSpan(0, identity)));
        // Exactly the JSON those builds stored: schema 1, no rotation fields.
        string legacy = $$"""{"schemaVersion":1,"fingerprint":"{{fingerprint}}","offset":246}""";
        MemoryCursors cursors = new();
        Assert.True(await cursors.TryAdvanceAsync("file:auth", 0, legacy, DateTimeOffset.UnixEpoch, cancellation));
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "end"), sink, cursors);

        await source.PollOnceAsync("auth", cancellation);

        // Never skipped: the current file is read from its start, and the gap is counted.
        Assert.Equal(["new-1", "new-2", "new-3"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        Assert.Equal(1, source.Snapshot()[0].RotationGaps);
        FileTailCursor written = FileTailCursor.Deserialize(cursors.Value("file:auth"))!;
        Assert.Equal((FileTailCursor.CurrentSchemaVersion, (long)Line("new-1").Length * 3), (written.SchemaVersion, written.Offset));
    }

    [Fact]
    public async Task UnknownCursorSchemas_ReplayButDamagedCurrentCursorsStillFailClosed()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("one"), cancellation);
        MemoryCursors future = new();
        await future.TryAdvanceAsync("file:auth", 0, """{"schemaVersion":99,"anything":"else"}""", DateTimeOffset.UnixEpoch, cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using (FileTailSource source = new(Configuration(directory.Path, path), sink, future))
        {
            await source.PollOnceAsync("auth", cancellation);
            Assert.Equal(1, source.Snapshot()[0].RotationGaps);
        }

        Assert.Single(sink.Records);
        MemoryCursors damaged = new();
        await damaged.TryAdvanceAsync("file:auth", 0, """{"schemaVersion":2,"fingerprint":"zz","offset":0}""", DateTimeOffset.UnixEpoch, cancellation);
        await using FileTailSource refused = new(Configuration(directory.Path, path), sink, damaged);
        FileTailException failure = await Assert.ThrowsAsync<FileTailException>(() => refused.PollOnceAsync("auth", cancellation));
        Assert.Equal(FileTailFailures.CursorInvalid, failure.Code);
    }

    [Fact]
    public async Task ADrainLeftAtTheCapWhileTheCurrentFileIsMissing_StillCountsALateWriteToPathOne()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        FileTailSourceConfiguration configuration = Configuration(directory.Path, path, startAt: "beginning")
            with
        { RotationGracePolls = 2, RotationDrainMaxPolls = 4 };
        await using FileTailSource source = new(configuration, sink, new MemoryCursors());
        await source.PollOnceAsync("auth", cancellation);
        // Renamed, and no new file yet: the drain reaches the cap with the current file missing.
        File.Move(path, path + ".1");
        for (int poll = 0; poll < 4; poll++)
        {
            await source.PollOnceAsync("auth", cancellation);
        }

        await File.AppendAllTextAsync(path + ".1", Line("late-1"), cancellation);
        await File.WriteAllTextAsync(path, Line("second-1"), cancellation);
        await source.PollOnceAsync("auth", cancellation);
        await source.PollOnceAsync("auth", cancellation);

        Assert.Equal(["first-1", "second-1"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        Assert.Equal(1, source.Snapshot()[0].RotationGaps); // late-1, written after the cursor left.
    }

    [Fact]
    public async Task LegacyCursorGap_IsCountedOnceThoughThePathIsRefusedFirst()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        string elsewhere = Path.Combine(directory.Path, "elsewhere.log");
        await File.WriteAllTextAsync(elsewhere, Line("one"), cancellation);
        File.CreateSymbolicLink(path, elsewhere);
        MemoryCursors cursors = new();
        Assert.True(await cursors.TryAdvanceAsync(
            "file:auth", 0, """{"schemaVersion":1,"fingerprint":"","offset":0}""", DateTimeOffset.UnixEpoch, cancellation));
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(Configuration(directory.Path, path), sink, cursors);

        for (int retry = 0; retry < 3; retry++)
        {
            FileTailException refused = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("auth", cancellation));
            Assert.Equal(FileTailFailures.PathRefused, refused.Code);
        }

        File.Delete(path);
        await File.WriteAllTextAsync(path, Line("one"), cancellation);
        await source.PollOnceAsync("auth", cancellation);
        await source.PollOnceAsync("auth", cancellation);

        // One replay stored, one gap: the refused polls stored nothing and counted nothing.
        Assert.Single(sink.Records);
        Assert.Equal(1, source.Snapshot()[0].RotationGaps);
    }

    [Fact]
    public async Task ARestoredFileWithTheSameContentAtANewInode_ContinuesWithoutAGapOrReplay()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "C# reads device and inode numbers on Linux only.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        await File.WriteAllTextAsync(path, Line("first-1") + Line("two"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        MemoryCursors cursors = new();
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, cursors);
        await source.PollOnceAsync("auth", cancellation);
        string? before = FileTailHandle.FileIdOf(path);

        // Restored from a backup: the same content, a new inode, and no path.1.
        await File.WriteAllTextAsync(path + ".restore", await File.ReadAllTextAsync(path, cancellation), cancellation);
        File.Move(path + ".restore", path, overwrite: true);
        await source.PollOnceAsync("auth", cancellation);
        await File.AppendAllTextAsync(path, Line("three"), cancellation);
        await source.PollOnceAsync("auth", cancellation);

        Assert.NotEqual(before, FileTailHandle.FileIdOf(path));
        Assert.Equal(["first-1", "two", "three"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        Assert.Equal(0, source.Snapshot()[0].RotationGaps);
        // The stored id is only a hint, and now names the restored file.
        Assert.Equal(FileTailHandle.FileIdOf(path), FileTailCursor.Deserialize(cursors.Value("file:auth"))!.FileId);
    }

    [Fact]
    public void RecordLimit_IsThePackRecordLimit() =>
        Assert.Equal(Bower.Packs.PackRuntime.MaximumRecordBytes, FileTailRecord.MaximumRecordBytes);

    [Fact]
    public async Task ALineWithinMaxLineBytesButOverThePackLimitOnceEscaped_IsCountedAsOversized()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "auth.log");
        // 6000 bytes (below maxLineBytes 16384), 36000 once each control character is \u0001.
        await File.WriteAllTextAsync(path, new string('\u0001', 6_000) + "\n" + Line("next"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        await using FileTailSource source = new(Configuration(directory.Path, path, startAt: "beginning"), sink, new MemoryCursors());

        await source.PollOnceAsync("auth", cancellation);

        // Never submitted (no parser-side TooLarge): counted as oversized, and the cursor moves on.
        Assert.Equal(["next"], sink.Records.Select(record => Message(record).Split(' ')[0]));
        FileTailInputStatus status = source.Snapshot()[0];
        Assert.Equal((1L, 0L, 0L, 2L), (status.Oversized, status.Malformed, status.TooLarge, status.LinesRead));
    }

    [Fact]
    public async Task ADirectoryTheServiceCannotSearch_IsInaccessibleNotWaiting()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Unix directory permissions.");
            return;
        }

        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string locked = Path.Combine(directory.Path, "locked");
        Directory.CreateDirectory(locked);
        string path = Path.Combine(locked, "auth.log");
        await File.WriteAllTextAsync(path, Line("one"), cancellation);
        FakeSink sink = new(_ => FileTailSubmitOutcome.Queued);
        List<(string Input, string Reason)> refusals = [];
        await using FileTailSource source = new(Configuration(directory.Path, path), sink, new MemoryCursors())
        {
            InputRefused = (input, reason) => refusals.Add((input, reason))
        };
        File.SetUnixFileMode(locked, UnixFileMode.None);
        try
        {
            // A privileged account (root in a container) searches it anyway: nothing to test.
            Assert.SkipWhen(CanList(locked), "The test account bypasses directory permissions.");
            for (int poll = 0; poll < 2; poll++)
            {
                FileTailException failure = await Assert.ThrowsAsync<FileTailException>(() => source.PollOnceAsync("auth", cancellation));
                Assert.Equal(FileTailFailures.PathInaccessible, failure.Code);
            }
        }
        finally
        {
            File.SetUnixFileMode(locked, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        // A failure state, counted and logged once (id and reason only), never "waiting".
        FileTailInputStatus status = source.Snapshot()[0];
        Assert.Equal((FileTailFailures.PathInaccessible, 2L), (status.State, status.ReadErrors));
        Assert.Equal([("auth", FileTailRefusals.Inaccessible)], refusals);
        Assert.Empty(sink.Records);
        // A directory that does not exist still waits.
        Assert.Equal(
            FileTailPathState.Missing,
            FileTailPaths.Resolve(Path.Combine(directory.Path, "absent", "auth.log"), [directory.Path], allowSymlink: false).State);

        static bool CanList(string directory)
        {
            try
            {
                _ = Directory.GetFileSystemEntries(directory);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    [Fact]
    public void Canonical_ResolvesDotDotPhysicallyThroughALinkedDirectory()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Symbolic links need privileges on Windows.");
        using TemporaryDirectory directory = new();
        string root = directory.Path;
        Directory.CreateDirectory(Path.Combine(root, "deep", "inner"));
        Directory.CreateDirectory(Path.Combine(root, "deep", "z"));
        Directory.CreateDirectory(Path.Combine(root, "z"));
        Directory.CreateSymbolicLink(Path.Combine(root, "y"), Path.Combine(root, "deep", "inner"));
        // x -> y/../z: through the linked y, '..' is deep, so x is deep/z (not root/z).
        Directory.CreateSymbolicLink(Path.Combine(root, "x"), "y/../z");

        Assert.Equal(
            FileTailPaths.Canonical(Path.Combine(root, "deep", "z", "f.log")),
            FileTailPaths.Canonical(Path.Combine(root, "x", "f.log")));
        Assert.NotEqual(
            FileTailPaths.Canonical(Path.Combine(root, "z", "f.log")),
            FileTailPaths.Canonical(Path.Combine(root, "x", "f.log")));
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
            [new FileTailInputOptions("auth", path, new FileTailRoute("pack", 0), format, startAt, maxLineBytes)],
            RotationGracePolls: 1);

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

    /// <summary>Requests a stop as soon as the poll has read its cursor.</summary>
    private sealed class CancelOnRead(ISourceCursorStore inner, CancellationTokenSource stop) : ISourceCursorStore
    {
        public async Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default)
        {
            SourceCursorSnapshot? snapshot = await inner.ReadAsync(sourceId, CancellationToken.None);
            await stop.CancelAsync();
            return snapshot;
        }

        public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value, DateTimeOffset updatedAt, CancellationToken cancellationToken = default) =>
            inner.TryAdvanceAsync(sourceId, expectedVersion, value, updatedAt, cancellationToken);
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
