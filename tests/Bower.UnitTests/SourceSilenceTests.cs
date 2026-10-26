using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

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
            SourceSilenceEvaluator.Evaluate(expectations, activity, [], started, now);
        IReadOnlyList<SourceSilenceStatus> early =
            SourceSilenceEvaluator.Evaluate(expectations, [], [], started, started.AddMinutes(10));

        Assert.Equal(["silent", "active", "never-seen"], statuses.Select(item => item.State));
        Assert.Equal(1200, statuses[0].SilentSeconds);
        Assert.Equal(900, statuses[0].AllowedSilenceSeconds);
        // Never observed and inside the allowance: pending, not active, not overdue.
        Assert.All(early, item => Assert.Equal(("pending", false, false), (item.State, item.IsActive, item.IsOverdue)));
    }

    [Fact]
    public async Task MonitoringStart_SurvivesRestartsAndOnlyNewSourcesGetFreshGrace()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SourceExpectations one = OneMinute(("TestApplication", "test"));
        SourceExpectations two = OneMinute(("TestApplication", "test"), ("Payroll", "production"));

        (SourceHealth health, _, _) = await StartAsync(path, one, clock, cancellationToken);
        Assert.Equal([("pending", 0L)], States(health));
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal([("never-seen", 120L)], States(health));

        // Repeated restarts keep the first monitoring start.
        for (int restart = 0; restart < 3; restart++)
        {
            (health, _, _) = await StartAsync(path, one, clock, cancellationToken);
            Assert.Equal([("never-seen", 120L + (restart * 10))], States(health));
            clock.Advance(TimeSpan.FromSeconds(10));
        }

        // A newly expected source gets its own grace; the existing deadline stands.
        (health, PipelineTelemetry telemetry, SecurityEventProcessor processor) =
            await StartAsync(path, two, clock, cancellationToken);
        Assert.Equal([("never-seen", 150L), ("pending", 0L)], States(health));

        // A valid event updates last-seen and restores activity, also after a restart.
        string accepted = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options);
        await processor.ProcessAsync(accepted, new CollectorIdentity("c", "1", "test", "h"), cancellationToken);
        Assert.Equal([("active", 0L), ("pending", 0L)], States(health));
        Assert.Equal(clock.UtcNow, health.Evaluate()[0].LastSeenAt);
        SqliteEventStore store = new(path, 10 * 1024 * 1024, clock);
        await store.UpsertSourceActivityAsync(telemetry.TakeChangedSources(), cancellationToken);
        clock.Advance(TimeSpan.FromSeconds(30));
        (health, _, _) = await StartAsync(path, two, clock, cancellationToken);
        Assert.Equal([("active", 30L), ("pending", 30L)], States(health));

        // Removing a source forgets its start; expecting it again starts afresh.
        await StartAsync(path, one, clock, cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(5));
        (health, _, _) = await StartAsync(path, two, clock, cancellationToken);
        Assert.Equal([("silent", 330L), ("pending", 0L)], States(health));
        Assert.Equal(
            [("TestApplication", "test", TestEvents.Now), ("Payroll", "production", clock.UtcNow)],
            (await store.StartSourceMonitoringAsync(
                [new SourceMonitoring("TestApplication", "test", clock.UtcNow), new SourceMonitoring("Payroll", "production", clock.UtcNow)],
                cancellationToken))
                .Select(item => (item.Application, item.Environment, item.MonitoringSince)));
    }

    [Fact]
    public async Task MonitoringStore_KeepsStartsAcrossRestartsForgetsRemovedSourcesAndPinsDdl()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SourceMonitoring Source(string application, int minutes) =>
            new(application, "prod", TestEvents.Now.AddMinutes(minutes));
        async Task<IReadOnlyList<SourceMonitoring>> OpenAndStartAsync(params SourceMonitoring[] expected)
        {
            SqliteEventStore store = new(path, 10 * 1024 * 1024, clock);
            await store.InitializeAsync(cancellationToken);
            return await store.StartSourceMonitoringAsync(expected, cancellationToken);
        }

        IReadOnlyList<SourceMonitoring> first = await OpenAndStartAsync(Source("App", 0), Source("Payroll", 0));
        // Restarts propose later starts; stored starts win and an unlisted source is forgotten.
        IReadOnlyList<SourceMonitoring> restarted = await OpenAndStartAsync(Source("App", 5));
        IReadOnlyList<SourceMonitoring> readded = await OpenAndStartAsync(Source("App", 9), Source("Payroll", 9));
        // A start stored while the clock ran ahead is replaced by an earlier one, never a later one.
        IReadOnlyList<SourceMonitoring> earlier = await OpenAndStartAsync(Source("App", -3), Source("Payroll", 9));
        IReadOnlyList<SourceMonitoring> none = await OpenAndStartAsync();

        Assert.Equal([Source("App", 0), Source("Payroll", 0)], first);
        Assert.Equal([Source("App", 0)], restarted);
        Assert.Equal([Source("App", 0), Source("Payroll", 9)], readded);
        Assert.Equal([Source("App", -3), Source("Payroll", 9)], earlier);
        Assert.Empty(none);
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT (SELECT COUNT(*) FROM source_monitoring) || '|' || (SELECT sql FROM sqlite_master WHERE name = 'source_monitoring');";
        // The Rust store test pins the same text, so either runtime opens the other's table.
        Assert.Equal(
            """
            0|CREATE TABLE source_monitoring (
                application TEXT NOT NULL,
                environment TEXT NOT NULL,
                monitoring_since TEXT NOT NULL,
                PRIMARY KEY (application, environment)
            )
            """,
            (string?)await command.ExecuteScalarAsync(cancellationToken));
    }

    [Fact]
    public async Task MonitoringStart_RecordedWhileTheClockRanAheadIsCorrectedAtTheNextStart()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        // First start before time synchronisation: the host clock is an hour ahead.
        FakeClock clock = new(TestEvents.Now.AddHours(1));
        string path = Path.Combine(directory.Path, "queue.db");
        SourceExpectations one = OneMinute(("TestApplication", "test"));

        await StartAsync(path, one, clock, cancellationToken);
        clock.Advance(TimeSpan.FromHours(-1));
        (SourceHealth health, _, _) = await StartAsync(path, one, clock, cancellationToken);
        Assert.Equal([("pending", 0L)], States(health));
        clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal([("never-seen", 120L)], States(health));
        (health, _, _) = await StartAsync(path, one, clock, cancellationToken);
        Assert.Equal([("never-seen", 120L)], States(health));
    }

    [Fact]
    public async Task Initialize_LogsForgottenMonitoringStartsAsMetadata()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SourceExpectations one = OneMinute(("TestApplication", "test"));
        await StartAsync(path, OneMinute(("TestApplication", "test"), ("Payroll", "production")), clock, cancellationToken);
        SqliteEventStore store = new(path, 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        ListLogger logger = new();

        IReadOnlyList<SourceMonitoring> removed =
            await new SourceHealth(one, new PipelineTelemetry(clock), clock, logger).InitializeAsync(store, cancellationToken);
        IReadOnlyList<SourceMonitoring> unchanged =
            await new SourceHealth(one, new PipelineTelemetry(clock), clock, logger).InitializeAsync(store, cancellationToken);
        // Starting without expectations forgets every start.
        IReadOnlyList<SourceMonitoring> unconfigured =
            await new SourceHealth(null, new PipelineTelemetry(clock), clock, logger).InitializeAsync(store, cancellationToken);

        Assert.Equal([("Payroll", "production")], removed.Select(item => (item.Application, item.Environment)));
        Assert.Empty(unchanged);
        Assert.Equal([("TestApplication", "test")], unconfigured.Select(item => (item.Application, item.Environment)));
        Assert.Equal(
            [
                (LogLevel.Warning, 1321, "Forgot the monitoring start of 1 source(s) no longer expected: Payroll/production. Expecting one again starts a fresh allowance."),
                (LogLevel.Warning, 1321, "Forgot the monitoring start of 1 source(s) no longer expected: TestApplication/test. Expecting one again starts a fresh allowance.")
            ],
            logger.Entries);
    }

    private sealed class ListLogger : ILogger<SourceHealth>
    {
        public List<(LogLevel Level, int EventId, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, eventId.Id, formatter(state, exception)));
    }

    private static SourceExpectations OneMinute(params (string Application, string Environment)[] sources) =>
        new("bower.security/v1", "SourceExpectations", [.. sources.Select(item => new SourceExpectation(item.Application, item.Environment, 1))]);

    private static (string State, long SilentSeconds)[] States(SourceHealth health) =>
        [.. health.Evaluate().Select(item => (item.State, item.SilentSeconds))];

    /// <summary>A collector start over an existing queue file: fresh process state, durable store.</summary>
    private static async Task<(SourceHealth, PipelineTelemetry, SecurityEventProcessor)> StartAsync(
        string path,
        SourceExpectations expectations,
        FakeClock clock,
        CancellationToken cancellationToken)
    {
        SqliteEventStore store = new(path, 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        telemetry.Load(await store.GetSourceActivityAsync(cancellationToken));
        SourceHealth health = new(expectations, telemetry, clock);
        await health.InitializeAsync(store, cancellationToken);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock,
            telemetry);
        return (health, telemetry, processor);
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
