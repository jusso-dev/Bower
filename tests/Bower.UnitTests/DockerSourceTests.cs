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

    public static void Append(DockerContainer container, params string[] logs)
    {
        StringBuilder text = new();
        foreach (string log in logs)
        {
            text.Append(JsonSerializer.Serialize(new { log, stream = "stdout", time = "2026-10-07T10:00:00.123456789Z" }));
            text.Append('\n');
        }

        File.AppendAllText(container.LogPath, text.ToString());
    }

    public static void AppendRaw(DockerContainer container, string raw) =>
        File.AppendAllText(container.LogPath, raw);

    private static string IdFor(string seed) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(seed)));
}
