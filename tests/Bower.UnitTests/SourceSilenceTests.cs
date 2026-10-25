using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;

namespace Bower.UnitTests;

public sealed class SourceSilenceTests
{
    private const string Expectations =
        """
        {
          "apiVersion": "bower.security/v1",
          "kind": "SourceExpectations",
          "sources": [
            { "application": "FinanceApi", "environment": "production", "maximumSilenceMinutes": 15 },
            { "application": "Portal", "environment": "production", "maximumSilenceMinutes": 60 },
            { "application": "Payroll", "environment": "production", "maximumSilenceMinutes": 30 }
          ]
        }
        """;

    [Fact]
    public void Evaluate_ReportsActiveSilentAndNeverSeenSources()
    {
        SourceExpectations expectations = SourceExpectationsLoader.Parse(Expectations);
        DateTimeOffset started = TestEvents.Now;
        DateTimeOffset now = started.AddMinutes(45);
        SourceActivity[] activity =
        [
            new("FinanceApi", "production", now.AddMinutes(-20), 10),
            new("Portal", "production", now.AddMinutes(-20), 4)
        ];

        IReadOnlyList<SourceSilenceStatus> statuses =
            SourceSilenceEvaluator.Evaluate(expectations, activity, started, now);
        IReadOnlyList<SourceSilenceStatus> early =
            SourceSilenceEvaluator.Evaluate(expectations, [], started, started.AddMinutes(10));

        Assert.Equal(["silent", "active", "never-seen"], statuses.Select(item => item.State));
        Assert.Equal(1200, statuses[0].SilentSeconds);
        Assert.Equal(900, statuses[0].AllowedSilenceSeconds);
        Assert.All(early, item => Assert.True(item.IsActive));
    }

    [Theory]
    [InlineData("\"kind\": \"SourceExpectations\"", "\"kind\": \"TelemetryPolicy\"")]
    [InlineData("\"maximumSilenceMinutes\": 15", "\"maximumSilenceMinutes\": 0")]
    [InlineData("\"maximumSilenceMinutes\": 15", "\"maximumSilenceMinutes\": 20000")]
    [InlineData("\"application\": \"Portal\"", "\"application\": \"FinanceApi\"")]
    [InlineData("\"application\": \"Portal\"", "\"application\": \" \"")]
    [InlineData("\"kind\": \"SourceExpectations\",", "\"kind\": \"SourceExpectations\", \"script\": \"x\",")]
    [InlineData("\"maximumSilenceMinutes\": 15", "\"maximumSilenceMinutes\": \"15\"")]
    public void Parse_RejectsInvalidExpectations(string original, string replacement)
    {
        string json = Expectations.Replace(original, replacement, StringComparison.Ordinal);
        Assert.NotEqual(Expectations, json);

        Assert.Throws<InvalidDataException>(() => SourceExpectationsLoader.Parse(json));
    }

    [Fact]
    public async Task Activity_IsTrackedFromAcceptedEventsAndSurvivesRestart()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock,
            telemetry);
        string accepted = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options);
        string rejected = JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(clock.UtcNow, "event-2", "source-2") with { EventType = "unknown_type" },
            BowerJson.Options);

        await processor.ProcessAsync(accepted, new CollectorIdentity("c", "1", "test", "h"), cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(3));
        await processor.ProcessAsync(accepted, new CollectorIdentity("c", "1", "test", "h"), cancellationToken);
        await processor.ProcessAsync(rejected, new CollectorIdentity("c", "1", "test", "h"), cancellationToken);
        await processor.ProcessAsync("[]", new CollectorIdentity("c", "1", "test", "h"), cancellationToken);
        IReadOnlyList<SourceActivity> changed = telemetry.TakeChangedSources();
        await store.UpsertSourceActivityAsync(changed, cancellationToken);
        await store.UpsertSourceActivityAsync(
            [new SourceActivity("TestApplication", "test", TestEvents.Now, 1)],
            cancellationToken);

        PipelineTelemetry restarted = new(clock);
        restarted.Load(await store.GetSourceActivityAsync(cancellationToken));
        PipelineMetricsSnapshot metrics = telemetry.Snapshot();

        SourceActivity activity = Assert.Single(restarted.Sources());
        Assert.Equal(("TestApplication", "test", 2L), (activity.Application, activity.Environment, activity.EventCount));
        Assert.Equal(TestEvents.Now.AddMinutes(3), activity.LastSeenAt);
        Assert.Empty(telemetry.TakeChangedSources());
        Assert.Equal((4L, 1L, 1L), (metrics.EventsIn, metrics.EventsQueued, metrics.Duplicates));
        Assert.Contains(metrics.Rows, row => row is { Stage: "policy", PolicyId: "BWR-POL-DEFAULT-DENY", Action: "reject" });
        Assert.Contains(metrics.Rows, row => row is { Stage: "redaction", PolicyId: "-", Action: "quarantine" });
        Assert.True(metrics.BytesQueued > 0);
    }
}
