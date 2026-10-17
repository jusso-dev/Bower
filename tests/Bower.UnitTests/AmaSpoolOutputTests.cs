using Bower.Abstractions;
using Bower.Output.AmaSpool;

namespace Bower.UnitTests;

public sealed class AmaSpoolOutputTests
{
    [Fact]
    public async Task Deliver_WritesCompleteUtf8JsonLinesToReadyDirectory()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string active = Path.Combine(directory.Path, "active");
        string ready = Path.Combine(directory.Path, "ready");
        AmaSpoolOutput output = new(new AmaSpoolOptions
        {
            Id = "ama",
            CollectorId = "collector-1",
            StreamName = "Custom-BowerSecurity",
            ActiveDirectory = active,
            ReadyDirectory = ready,
            MaximumFileBytes = 4_096
        });
        QueuedEvent[] events =
        [
            new("event-1", "sha256:one", """{"eventId":"event-1"}""", DateTimeOffset.UtcNow),
            new("event-2", "sha256:two", """{"eventId":"event-2"}""", DateTimeOffset.UtcNow)
        ];

        DeliveryResult result = await output.DeliverAsync(events, cancellationToken);

        Assert.Equal(2, result.AcknowledgedEventIds.Count);
        Assert.Empty(result.Failures);
        Assert.Empty(Directory.EnumerateFiles(active));
        string readyFile = Assert.Single(Directory.EnumerateFiles(ready, "*.jsonl"));
        string[] lines = await File.ReadAllLinesAsync(readyFile, cancellationToken);
        Assert.Equal(2, lines.Length);
        Assert.Equal("""{"eventId":"event-1"}""", lines[0]);
        Assert.Equal("""{"eventId":"event-2"}""", lines[1]);
    }

    [Fact]
    public async Task Restart_ContinuesNumberingAfterUnconsumedReadyFiles()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        AmaSpoolOptions options = Options(directory);

        DeliveryResult first = await new AmaSpoolOutput(options).DeliverAsync([Event("event-1")], cancellationToken);
        // A new process: before the fix numbering restarted at 1 and File.Move failed on
        // every retry while AMA had not consumed the first file.
        DeliveryResult second = await new AmaSpoolOutput(options).DeliverAsync([Event("event-2")], cancellationToken);

        Assert.Equal("ama-spool:collector-1:1", first.DestinationAcknowledgement);
        Assert.Equal("ama-spool:collector-1:2", second.DestinationAcknowledgement);
        Assert.Equal(["event-2"], second.AcknowledgedEventIds);
        Assert.Equal(
            [ReadyName(1), ReadyName(2)],
            Directory.EnumerateFiles(options.ReadyDirectory).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        Assert.Equal("""{"eventId":"event-1"}""" + "\n", await File.ReadAllTextAsync(Path.Combine(options.ReadyDirectory, ReadyName(1)), cancellationToken));
    }

    [Fact]
    public async Task Restart_RemovesStaleTemporaryFilesAndNeverReusesTheirNames()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        AmaSpoolOptions options = Options(directory);
        Directory.CreateDirectory(options.ActiveDirectory);
        string stale = Path.Combine(options.ActiveDirectory, $"{Prefix}00000000000000000005.tmp");
        string foreign = Path.Combine(options.ActiveDirectory, "other-Custom-BowerSecurity-00000000000000000009.tmp");
        await File.WriteAllTextAsync(stale, "{\"eventId\":\"partial", cancellationToken);
        await File.WriteAllTextAsync(foreign, "{}", cancellationToken);

        AmaSpoolOutput output = new(options);
        DeliveryResult result = await output.DeliverAsync([Event("event-1")], cancellationToken);

        Assert.False(File.Exists(stale));
        Assert.True(File.Exists(foreign));
        Assert.Equal("ama-spool:collector-1:6", result.DestinationAcknowledgement);
        Assert.Equal(ReadyName(6), Path.GetFileName(Assert.Single(Directory.EnumerateFiles(options.ReadyDirectory))));
    }

    [Fact]
    public async Task Deliver_FailedMoveLeavesNoTemporaryFileAndRetryUsesNewName()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        AmaSpoolOptions options = Options(directory);
        AmaSpoolOutput output = new(options);
        // Another writer takes the next name after start-up.
        await File.WriteAllTextAsync(Path.Combine(options.ReadyDirectory, ReadyName(1)), "{}\n", cancellationToken);

        await Assert.ThrowsAnyAsync<IOException>(() => output.DeliverAsync([Event("event-1")], cancellationToken));
        Assert.Empty(Directory.EnumerateFiles(options.ActiveDirectory));

        DeliveryResult retry = await output.DeliverAsync([Event("event-1")], cancellationToken);

        Assert.Equal(["event-1"], retry.AcknowledgedEventIds);
        Assert.True(File.Exists(Path.Combine(options.ReadyDirectory, ReadyName(2))));
        Assert.Equal("{}\n", await File.ReadAllTextAsync(Path.Combine(options.ReadyDirectory, ReadyName(1)), cancellationToken));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/./")]
    public void Options_TreatTrailingSeparatorAsSameDirectory(string suffix)
    {
        using TemporaryDirectory directory = new();
        string ready = Path.Combine(directory.Path, "ready");

        Assert.Throws<ArgumentException>(() => new AmaSpoolOutput(Options(directory) with
        {
            ActiveDirectory = ready + suffix.Replace('/', Path.DirectorySeparatorChar),
            ReadyDirectory = ready
        }));
    }

    private const string Prefix = "collector-1-Custom-BowerSecurity-";

    private static string ReadyName(long sequence) => $"{Prefix}{sequence:D20}.jsonl";

    private static AmaSpoolOptions Options(TemporaryDirectory directory) => new()
    {
        Id = "ama",
        CollectorId = "collector-1",
        StreamName = "Custom-BowerSecurity",
        ActiveDirectory = Path.Combine(directory.Path, "active"),
        ReadyDirectory = Path.Combine(directory.Path, "ready"),
        MaximumFileBytes = 4_096
    };

    private static QueuedEvent Event(string eventId) =>
        new(eventId, $"sha256:{eventId}", $$"""{"eventId":"{{eventId}}"}""", DateTimeOffset.UtcNow);
}
