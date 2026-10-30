using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Output.AmaSpool;
using Bower.Persistence;
using Microsoft.Extensions.Logging.Abstractions;

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

    [Fact]
    public async Task Deadline_AfterCommittedFile_RetriesOnlyUnfinishedEventsAcrossRestart()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManualTimeProvider clock = new(TestEvents.Now);
        string database = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(database, 10 * 1024 * 1024, clock);
        await store.InitializeAsync(token);
        foreach (string id in new[] { "first", "second", "third" })
        {
            await store.EnqueueAsync(new QueuedEvent(id, $"sha256:{id}",
                $$"""{"eventId":"{{id}}","padding":"{{new string('x', 700)}}"}""", clock.GetUtcNow()), token);
        }

        AmaSpoolOptions options = Options(directory) with { MaximumFileBytes = 1024 };
        AmaSpoolOutput output = new(options);
        DeadlineBetweenFiles controlled = new(output, () =>
        {
            Assert.Single(Directory.EnumerateFiles(options.ReadyDirectory));
            clock.Advance(TimeSpan.FromSeconds(60));
        });
        QueueDeliveryOptions delivery = new()
        {
            LeaseDuration = TimeSpan.FromSeconds(90),
            DeliveryTimeout = TimeSpan.FromSeconds(60),
            MaximumDeliveryAttempts = 1
        };
        using QueueDeliveryWorker worker = new(store, controlled, clock, delivery, NullLogger<QueueDeliveryWorker>.Instance);
        Assert.Equal(3, await worker.DeliverOnceAsync(token));
        QueueSnapshot partial = await store.GetSnapshotAsync(token);
        Assert.Equal((1L, 2L, 0L, 0L),
            (partial.Delivered, partial.Retrying, partial.Uploading, partial.DeadLettered));
        Assert.Empty(Directory.EnumerateFiles(options.ActiveDirectory));

        SqliteEventStore reopened = new(database, 10 * 1024 * 1024, clock);
        await reopened.InitializeAsync(token);
        clock.Advance(TimeSpan.FromSeconds(30));
        using QueueDeliveryWorker restarted = new(reopened, new AmaSpoolOutput(options), clock, delivery,
            NullLogger<QueueDeliveryWorker>.Instance);
        Assert.Equal(2, await restarted.DeliverOnceAsync(token));
        Assert.Equal(3, (await reopened.GetSnapshotAsync(token)).Delivered);
        string[] lines = Directory.EnumerateFiles(options.ReadyDirectory).SelectMany(File.ReadAllLines).ToArray();
        Assert.Equal(["first", "second", "third"], lines.Select(line =>
        {
            using JsonDocument document = JsonDocument.Parse(line);
            return document.RootElement.GetProperty("eventId").GetString();
        }).Order(StringComparer.Ordinal));
        Assert.True((await reopened.VerifyLedgerAsync(token)).Intact);
    }

    private sealed class DeadlineBetweenFiles(AmaSpoolOutput inner, Action cancel) : IOutputAdapter
    {
        public string Id => inner.Id;
        public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default) =>
            inner.DeliverAsync(new InterruptedEnumeration(events, cancel), cancellationToken);
    }

    private sealed class InterruptedEnumeration(IReadOnlyList<QueuedEvent> events, Action cancel) : IReadOnlyList<QueuedEvent>
    {
        private bool interrupted;
        public int Count => events.Count;
        public QueuedEvent this[int index] => events[index];
        public IEnumerator<QueuedEvent> GetEnumerator()
        {
            for (int index = 0; index < events.Count; index++)
            {
                // Three bounded records form separate files. Reading record three occurs
                // after file one committed and before file two is written.
                if (index == 2 && !interrupted)
                {
                    interrupted = true;
                    cancel();
                }
                yield return events[index];
            }
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
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
