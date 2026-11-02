using System.Net;
using System.Text;
using Bower.Abstractions;
using Bower.Cli.Commands;
using Bower.Persistence;

namespace Bower.UnitTests;

/// <summary>
/// <c>bower archive replay</c> origin labels and per-event mismatch handling. The Rust port
/// pins the same cases (rust/crates/bower-cli/tests/archive_and_sources.rs).
/// </summary>
public sealed class ArchiveReplayCliTests
{
    [Fact]
    public async Task ArchiveReplay_LabelsTheStampedCollectorAndSkipsMismatchesPerEvent()
    {
        using TemporaryDirectory directory = new();
        string archive = await ArchiveWithCollectorsAsync(directory);
        ReplayCollector collector = new();
        StringWriter output = new();
        StringWriter error = new();

        int code = await ArchiveCommands.ReplayAsync(
            ["--archive", archive, "--collector-url", "http://127.0.0.1:4329"], collector, output, error);

        // A refused event is skipped, the replay goes on, and the exit code reports it.
        Assert.Equal(2, code);
        Assert.Equal(
            "{\n  \"selected\": 3,\n  \"dryRun\": false,\n  \"responses\": {\n    \"202\": 2,\n    \"collector-mismatch\": 1\n  }\n}",
            output.ToString().ReplaceLineEndings("\n").Trim());
        Assert.Contains("1 event(s) skipped", error.ToString(), StringComparison.Ordinal);
        // The forged label is replaced by the stamped id, or removed without one.
        Assert.Contains("\"bowerReplayCollectorId\":\"edge-a\"", collector.Bodies[0], StringComparison.Ordinal);
        Assert.DoesNotContain("attacker", collector.Bodies[0], StringComparison.Ordinal);
        Assert.Contains("\"bowerReplayCollectorId\":\"edge-b\"", collector.Bodies[1], StringComparison.Ordinal);
        Assert.DoesNotContain("bowerReplayCollectorId", collector.Bodies[2], StringComparison.Ordinal);
        Assert.All(collector.Bodies, body => Assert.Contains("\"bowerReplay\":\"archive\"", body, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ArchiveReplay_CollectorIdSelectsOneCollectorsSlice()
    {
        using TemporaryDirectory directory = new();
        string archive = await ArchiveWithCollectorsAsync(directory);
        StringWriter dry = new();
        Assert.Equal(0, await ArchiveCommands.ReplayAsync(
            ["--archive", archive, "--collector-url", "http://127.0.0.1:9", "--collector-id", "edge-b", "--dry-run"],
            new ReplayCollector(), dry, new StringWriter()));
        Assert.Contains("\"selected\": 1", dry.ToString(), StringComparison.Ordinal);

        ReplayCollector collector = new();
        StringWriter output = new();
        int code = await ArchiveCommands.ReplayAsync(
            ["--archive", archive, "--collector-url", "http://127.0.0.1:4329", "--collector-id", "edge-a"],
            collector, output, new StringWriter());
        Assert.Equal(0, code);
        Assert.Equal(
            "{\n  \"selected\": 1,\n  \"dryRun\": false,\n  \"responses\": {\n    \"202\": 1\n  }\n}",
            output.ToString().ReplaceLineEndings("\n").Trim());
        Assert.Contains("\"eventId\":\"c0\"", Assert.Single(collector.Bodies), StringComparison.Ordinal);
    }

    private static async Task<string> ArchiveWithCollectorsAsync(TemporaryDirectory directory)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = await QueueArchiveTests.CreateStoreAsync(directory, clock, cancellationToken);
        // c0: stamped edge-a with a forged origin label; c1: stamped edge-b; c2: no collector
        // block but a forged label.
        (string Collector, string Labels)[] events =
        [
            (",\"collector\":{\"id\":\"edge-a\"}", "{\"bowerReplayCollectorId\":\"attacker\"}"),
            (",\"collector\":{\"id\":\"edge-b\"}", "{\"team\":\"b\"}"),
            ("", "{\"bowerReplayCollectorId\":\"forged\"}")
        ];
        for (int index = 0; index < events.Length; index++)
        {
            clock.Advance(TimeSpan.FromSeconds(1));
            string payload = "{\"schemaVersion\":\"1.0.0\",\"eventId\":\"c" + index + "\",\"timeGenerated\":\"2026-05-01T10:2"
                + index + ":00+00:00\",\"eventType\":\"authentication_failure\",\"labels\":" + events[index].Labels
                + events[index].Collector + "}";
            await store.EnqueueAsync(new QueuedEvent($"c{index}", $"fp-c{index}", payload, clock.GetUtcNow()), cancellationToken);
        }

        string path = Path.Combine(directory.Path, "archive");
        await new QueueArchive(path, "edge-a", clock).ArchiveAsync(store, cancellationToken);
        return path;
    }

    /// <summary>202 when the origin label names edge-a or is absent, else the collector's mismatch answer.</summary>
    private sealed class ReplayCollector : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Bodies.Add(body);
            bool refused = body.Contains("bowerReplayCollectorId", StringComparison.Ordinal)
                && !body.Contains("\"bowerReplayCollectorId\":\"edge-a\"", StringComparison.Ordinal);
            return refused
                ? new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("{\"reasons\":[\"archive-replay-collector-mismatch\"]}", Encoding.UTF8, "application/json")
                }
                : new HttpResponseMessage(HttpStatusCode.Accepted) { Content = new StringContent("{}") };
        }
    }
}
