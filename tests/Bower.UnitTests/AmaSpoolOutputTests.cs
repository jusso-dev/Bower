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
}
