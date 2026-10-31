using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Source.Syslog;
using Bower.Source.WindowsEventLog;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class CollectorHealthRecordTests
{
    private static readonly CollectorIdentity Identity = new("collector-health-test", "0.1.0", "test", "sha256:configuration");

    private static string HealthPolicyFile =>
        Path.Combine(AppContext.BaseDirectory, "examples", "policies", "collector-health", "collector-health.yaml");

    [Fact]
    public void Create_ReportsQueueDeliverySourcesAndTransportAsMetadataOnly()
    {
        CollectorHealthSample sample = Sample(TestEvents.Now, sequence: 3) with
        {
            DeliveryStatus = "stalled",
            Queue = new QueueSnapshot(40, 2, 1, 900, 0, 9_437_184, TestEvents.Now.AddMinutes(-20), 4_194_304),
            Sources =
            [
                new SourceSilenceStatus("nftables-firewall", "production", "silent", TestEvents.Now.AddMinutes(-30), 1_800, 900),
                new SourceSilenceStatus("windows-security", "production", "active", TestEvents.Now, 0, 900)
            ],
            Syslog = [Listener(tlsHandshakeFailures: 2)],
            WindowsEventLog = [Subscription("winevt-read-failed")],
            QueueFileBytes = 12_582_912,
            QueueFileLimitBytes = 14_680_064
        };

        SecurityEventEnvelope record = CollectorHealthRecord.Create(sample, Identity.Id, "production");

        Assert.Equal(SecurityEventTypes.CollectorHealth, record.EventType);
        Assert.Equal(SecurityEventCategories.CollectorHealth, record.EventCategory);
        Assert.Equal(CollectorHealthRecord.EventAction, record.EventAction);
        Assert.Equal(EventResult.Failure, record.EventResult);
        Assert.StartsWith("collector-health-", record.EventId, StringComparison.Ordinal);
        Assert.Equal(TestEvents.Now, record.TimeGenerated);
        Assert.Equal("Collector health: stalled, source-overdue, syslog-errors, windows-event-log-errors", record.EventOutcomeReason);
        IReadOnlyDictionary<string, JsonElement> attributes = record.Attributes!;
        Assert.Equal("degraded", attributes["status"].GetString());
        Assert.Equal(1_200, attributes["queue"].GetProperty("oldestUndeliveredAgeSeconds").GetInt64());
        Assert.Equal(43, attributes["queue"].GetProperty("undelivered").GetInt64());
        Assert.Equal(4.0, attributes["storage"].GetProperty("undeliveredMiB").GetDouble());
        Assert.Equal(9.0, attributes["storage"].GetProperty("storedMiB").GetDouble());
        Assert.Equal(10.0, attributes["storage"].GetProperty("queueCapacityMiB").GetDouble());
        Assert.Equal(40.0, attributes["storage"].GetProperty("capacityUsedPercent").GetDouble());
        Assert.Equal(12.0, attributes["storage"].GetProperty("queueFileMiB").GetDouble());
        Assert.Equal(14.0, attributes["storage"].GetProperty("queueFileLimitMiB").GetDouble());
        Assert.Equal(85.7, attributes["storage"].GetProperty("queueFileUsedPercent").GetDouble());
        Assert.Equal("2026-07-26T01:14:19.0000000+00:00", attributes["countersSince"].GetString());
        JsonElement overdue = Assert.Single(attributes["sources"].GetProperty("overdue").EnumerateArray());
        Assert.Equal("nftables-firewall", overdue.GetProperty("application").GetString());
        Assert.Equal(1_800, overdue.GetProperty("silentSeconds").GetInt64());
        Assert.Equal(2, attributes["syslog"][0].GetProperty("tlsHandshakeFailures").GetInt64());
        Assert.Equal("winevt-read-failed", attributes["windowsEventLog"][0].GetProperty("state").GetString());
        // The listener endpoint is configuration, not health; it stays behind the status token.
        Assert.DoesNotContain("127.0.0.1", JsonSerializer.Serialize(record, BowerJson.Envelope), StringComparison.Ordinal);
        Assert.True(attributes.Count <= 64);
    }

    [Fact]
    public void Create_IdentifiesEachRecordOfAProcessUniquely()
    {
        CollectorHealthSample first = Sample(TestEvents.Now, sequence: 1);
        string id = CollectorHealthRecord.Create(first, Identity.Id, "production").EventId;

        Assert.Equal(id, CollectorHealthRecord.Create(first, Identity.Id, "production").EventId);
        Assert.NotEqual(id, CollectorHealthRecord.Create(first with { Sequence = 2 }, Identity.Id, "production").EventId);
        // A restart starts a new series: same sequence, different process start.
        Assert.NotEqual(
            id,
            CollectorHealthRecord.Create(first with { CollectorStartedAt = TestEvents.Now.AddSeconds(1) }, Identity.Id, "production").EventId);
        Assert.NotEqual(id, CollectorHealthRecord.Create(first, "another-collector", "production").EventId);
    }

    [Fact]
    public void Problems_ReportNewCountersSinceTheLastRecordOfTheSameProcess()
    {
        CollectorHealthSample previous = Sample(TestEvents.Now, sequence: 1) with
        {
            Intake = Intake(capacityRefusals: 2),
            Syslog = [Listener(tlsHandshakeFailures: 2)]
        };
        CollectorHealthSample unchanged = previous with { At = TestEvents.Now.AddMinutes(5), Sequence = 2 };
        CollectorHealthSample worse = unchanged with
        {
            Intake = Intake(capacityRefusals: 3),
            Syslog = [Listener(tlsHandshakeFailures: 2, dropped: 1)]
        };

        Assert.Empty(CollectorHealthRecord.Problems(unchanged, previous));
        Assert.Equal(
            [CollectorHealthRecord.CapacityRefusals, CollectorHealthRecord.SyslogErrors],
            CollectorHealthRecord.Problems(worse, previous));
        // Counters are the change since the previous record.
        IReadOnlyDictionary<string, JsonElement> attributes =
            CollectorHealthRecord.Create(worse, Identity.Id, "production", previous).Attributes!;
        Assert.Equal(1, attributes["intake"].GetProperty("capacityRefusals").GetInt64());
        Assert.Equal(1, attributes["syslog"][0].GetProperty("dropped").GetInt64());
        Assert.Equal(0, attributes["syslog"][0].GetProperty("tlsHandshakeFailures").GetInt64());
        Assert.Equal(0, attributes["syslog"][0].GetProperty("framesReceived").GetInt64());
        Assert.Equal(1, attributes["syslog"][0].GetProperty("activeConnections").GetInt64());
        Assert.Equal("2026-07-26T02:14:19.0000000+00:00", attributes["countersSince"].GetString());
        // After a restart counters start again, so a previous sample of another process is no baseline.
        CollectorHealthSample restarted = worse with { CollectorStartedAt = TestEvents.Now.AddMinutes(4) };
        Assert.Equal(
            [CollectorHealthRecord.CapacityRefusals, CollectorHealthRecord.SyslogErrors],
            CollectorHealthRecord.Problems(restarted, previous));
        Assert.Equal(
            [CollectorHealthRecord.DeadLetters, CollectorHealthRecord.Backpressure],
            CollectorHealthRecord.Problems(
                unchanged with { DeliveryStatus = "backpressure", Queue = new QueueSnapshot(1, 0, 0, 0, 2, 10, TestEvents.Now, 10) },
                previous));
    }

    [Fact]
    public void Create_BoundsListedSources()
    {
        SourceSilenceStatus[] sources = [.. Enumerable.Range(0, 40).Select(index =>
            new SourceSilenceStatus($"app-{index:00}", "production", "never-seen", null, 1_000 + index, 900))];
        SecurityEventEnvelope record = CollectorHealthRecord.Create(
            Sample(TestEvents.Now, sequence: 1) with { Sources = sources, SourcesConfigured = true },
            Identity.Id,
            "production");

        JsonElement listed = record.Attributes!["sources"].GetProperty("overdue");
        Assert.Equal(CollectorHealthRecord.MaximumListed, listed.GetArrayLength());
        Assert.Equal("app-39", listed[0].GetProperty("application").GetString());
        Assert.Equal(40, record.Attributes["sources"].GetProperty("neverSeen").GetInt64());
    }

    [Fact]
    public async Task Process_DefaultPrivacyAndTheExamplePolicyQueueTheRecordUnchanged()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([PolicyLoader.LoadFile(HealthPolicyFile)]),
            store,
            clock);
        // Default detectors scan JSON numbers: eight or more digits can match a card, TFN, ABN
        // or Medicare checksum and be masked. Values shaped like those are clamped to seven
        // digits, so the alert queries can always compare them numerically.
        CollectorHealthSample sample = Sample(TestEvents.Now, sequence: 1) with
        {
            Queue = new QueueSnapshot(4_111_111_111_111_111, 0, 0, 123_456_782, 0, 61_412_345_678, TestEvents.Now.AddDays(-400), 412_345_678),
            Intake = Intake(capacityRefusals: 4_012_888_888_881_881),
            Syslog = [Listener(tlsHandshakeFailures: 876_543_210)]
        };
        string candidate = CollectorHealthRecord.CreateJson(sample, Identity.Id, "production");

        ProcessingResult result = await processor.ProcessAsync(
            candidate, Identity with { SourceAdapter = CollectorHealthRecord.SourceAdapter }, cancellationToken);

        Assert.True(result.Queued, string.Join(",", result.Reasons));
        Assert.Equal("BWR-POL-COLLECTOR-HEALTH", result.PolicyDecision!.PolicyId);
        QueuedEvent queued = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken));
        SecurityEventEnvelope stored = JsonSerializer.Deserialize(queued.Payload, BowerJson.Envelope)!;
        SecurityEventEnvelope original = JsonSerializer.Deserialize(candidate, BowerJson.Envelope)!;
        Assert.Equal(
            original.Attributes!.Select(item => $"{item.Key}={item.Value.GetRawText()}"),
            stored.Attributes!.Select(item => $"{item.Key}={item.Value.GetRawText()}"));
        Assert.Equal(Identity.Id, stored.Collector!.Id);
        Assert.Equal(CollectorHealthRecord.SourceAdapter, stored.Collector.SourceAdapter);
        Assert.Equal(CollectorHealthRecord.MaximumReportedValue, stored.Attributes!["queue"].GetProperty("queued").GetInt64());
        Assert.Equal(
            CollectorHealthRecord.MaximumReportedValue,
            stored.Attributes["queue"].GetProperty("oldestUndeliveredAgeSeconds").GetInt64());
    }

    [Fact]
    public void Redaction_LeavesEveryRecordIdentityAndCounterIntact()
    {
        // Ids are written with letters only: a run of hex digits can match a numeric detector
        // (the native pilot saw a generated event id masked). Probe many ids and counters.
        JsonEventRedactor redactor = new();
        for (int sequence = 1; sequence <= 2_000; sequence++)
        {
            CollectorHealthSample sample = Sample(TestEvents.Now, sequence) with
            {
                Intake = Intake(capacityRefusals: (sequence * 7_919L) % CollectorHealthRecord.MaximumReportedValue),
                Syslog = [Listener(tlsHandshakeFailures: (sequence * 104_729L) % CollectorHealthRecord.MaximumReportedValue)]
            };
            string candidate = CollectorHealthRecord.CreateJson(sample, Identity.Id, "production");

            RedactionResult result = redactor.Redact(candidate);

            Assert.True(result.Succeeded);
            SecurityEventEnvelope original = JsonSerializer.Deserialize(candidate, BowerJson.Envelope)!;
            SecurityEventEnvelope redacted = JsonSerializer.Deserialize(result.RedactedJson!, BowerJson.Envelope)!;
            Assert.Equal(original.EventId, redacted.EventId);
            Assert.Equal(
                original.Attributes!.Select(item => $"{item.Key}={item.Value.GetRawText()}"),
                redacted.Attributes!.Select(item => $"{item.Key}={item.Value.GetRawText()}"));
        }
    }

    [Fact]
    public async Task Worker_ContinuesWhenTheQueueRefusesARecordAndReportsTheRefusalNext()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        await store.EnqueueAsync(
            new QueuedEvent("filler", "sha256:filler", new string('x', 1_048_000), clock.UtcNow),
            cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([PolicyLoader.LoadFile(HealthPolicyFile)]),
            store,
            clock,
            telemetry);
        CollectorSettings settings = Settings(directory.Path) with
        {
            MaximumQueueBytes = 1_048_576,
            HealthRecordInterval = TimeSpan.FromMinutes(1)
        };
        CollectorHealthWorker worker = new(
            processor, Identity, store, telemetry, new SourceHealth(null, telemetry, clock), new DeliveryActivity(),
            settings, clock, NullLogger<CollectorHealthWorker>.Instance);

        Assert.Null(await worker.RecordAsync(TimeSpan.FromMinutes(1), cancellationToken));
        Assert.Equal(1, telemetry.IntakeSnapshot().CapacityRefusals);

        // Room again (the filler was delivered): the next record carries the refusal.
        QueuedEvent filler = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), cancellationToken));
        await store.MarkDeliveredAsync(filler.EventId, "test", filler.LeaseToken, cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(1));
        ProcessingResult? queued = await worker.RecordAsync(TimeSpan.FromMinutes(1), cancellationToken);

        Assert.True(queued?.Queued);
        QueuedEvent record = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken));
        SecurityEventEnvelope envelope = JsonSerializer.Deserialize(record.Payload, BowerJson.Envelope)!;
        Assert.Equal(1, envelope.Attributes!["intake"].GetProperty("capacityRefusals").GetInt64());
        Assert.Equal(2, envelope.Attributes["sequence"].GetInt64());
        Assert.Contains(
            CollectorHealthRecord.CapacityRefusals,
            envelope.Attributes["problems"].EnumerateArray().Select(item => item.GetString()));
    }

    [Fact]
    public async Task Worker_QueuesNothingWhileManagedPrivacyGatesIntake()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([PolicyLoader.LoadFile(HealthPolicyFile)]),
            store,
            clock,
            telemetry);
        CollectorHealthWorker worker = new(
            processor, Identity, store, telemetry, new SourceHealth(null, telemetry, clock), new DeliveryActivity(),
            Settings(directory.Path) with { HealthRecordInterval = TimeSpan.FromMinutes(1) }, clock,
            NullLogger<CollectorHealthWorker>.Instance,
            managedPrivacy: new ManagedPrivacyProfileState(null, allowDefault: false));

        Assert.Null(await worker.RecordAsync(TimeSpan.FromMinutes(1), cancellationToken));
        Assert.Equal(0, (await store.GetSnapshotAsync(cancellationToken)).Queued);
        Assert.Equal(0, telemetry.IntakeSnapshot().AttemptedRequests);
    }

    [Fact]
    public async Task Host_QueuesAndDeliversARecordAtStartUp()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string policies = PolicyDirectoryWithHealth(directory.Path);
        CapturingOutput output = new();
        await using WebApplication app = CollectorApplication.Build(
            Settings(directory.Path) with
            {
                PolicyDirectory = policies,
                Environment = "production",
                HealthRecordInterval = TimeSpan.FromMinutes(1)
            },
            builder => builder.WebHost.UseTestServer(),
            output);
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);

        QueuedEvent? delivered = null;
        for (int attempt = 0; attempt < 200 && delivered is null; attempt++)
        {
            delivered = output.Delivered.FirstOrDefault(item => item.EventId.StartsWith("collector-health-", StringComparison.Ordinal));
            if (delivered is null)
            {
                await Task.Delay(50, cancellationToken);
            }
        }

        Assert.NotNull(delivered);
        SecurityEventEnvelope envelope = JsonSerializer.Deserialize(delivered.Payload, BowerJson.Envelope)!;
        Assert.Equal(SecurityEventTypes.CollectorHealth, envelope.EventType);
        Assert.Equal("collector-test", envelope.Collector!.Id);
        Assert.Equal("production", envelope.Application!.Environment);
        Assert.Equal(60, envelope.Attributes!["intervalSeconds"].GetInt64());
        Assert.Equal("none", envelope.Attributes["delivery"].GetProperty("output").GetString());
        Assert.Equal("BWR-POL-COLLECTOR-HEALTH", envelope.Security!.PolicyId);
        // The queue database's page limit is a quarter of the store's physical budget.
        JsonElement storage = envelope.Attributes["storage"];
        Assert.Equal(Math.Round((10L * 1024 * 1024 * 1024 * 4 + 16_777_216) / 4 / 1_048_576.0, 1), storage.GetProperty("queueFileLimitMiB").GetDouble());
        Assert.True(storage.GetProperty("queueFileMiB").GetDouble() > 0);
        await app.StopAsync(cancellationToken);
    }

    [Fact]
    public void Build_FailsClosedWhenNoPolicyAcceptsHealthRecords()
    {
        using TemporaryDirectory directory = new();
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorApplication.Build(
            Settings(directory.Path) with { HealthRecordInterval = TimeSpan.FromMinutes(5) },
            builder => builder.WebHost.UseTestServer()));

        Assert.Contains("no loaded policy accepts collector_health", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("0", null)]
    [InlineData("60", 60)]
    [InlineData("3600", 3600)]
    public void Settings_ReadTheHealthRecordInterval(string? value, int? seconds)
    {
        CollectorSettings settings = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_COLLECTOR_ID" => "collector-health-settings",
            "BOWER_HEALTH_RECORD_INTERVAL_SECONDS" => value,
            _ => null
        });

        Assert.Equal(seconds is null ? null : TimeSpan.FromSeconds(seconds.Value), settings.HealthRecordInterval);
    }

    [Theory]
    [InlineData("59")]
    [InlineData("3601")]
    [InlineData("-60")]
    public void Settings_RefuseAnIntervalOutsideTheRange(string value)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_COLLECTOR_ID" => "collector-health-settings",
            "BOWER_HEALTH_RECORD_INTERVAL_SECONDS" => value,
            _ => null
        }).Validate());

        Assert.Contains("BOWER_HEALTH_RECORD_INTERVAL_SECONDS", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_ChangeTheConfigurationHashOnlyWhenEnabled()
    {
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory.Path);

        Assert.Equal(settings.ConfigurationHash(), (settings with { HealthRecordInterval = null }).ConfigurationHash());
        Assert.NotEqual(
            settings.ConfigurationHash(),
            (settings with { HealthRecordInterval = TimeSpan.FromMinutes(5) }).ConfigurationHash());
    }

    private static string PolicyDirectoryWithHealth(string root)
    {
        string policies = Path.Combine(root, "policies");
        Directory.CreateDirectory(policies);
        foreach (string file in Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "policies", "default"), "*.yaml"))
        {
            File.Copy(file, Path.Combine(policies, Path.GetFileName(file)));
        }

        File.Copy(HealthPolicyFile, Path.Combine(policies, "collector-health.yaml"));
        return policies;
    }

    private static CollectorSettings Settings(string directory) =>
        new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "collector-test",
            SingleTrustDomain = true
        };

    private static CollectorHealthSample Sample(DateTimeOffset at, long sequence) =>
        new(
            at,
            at.AddHours(-1),
            sequence,
            TimeSpan.FromMinutes(5),
            "azure-logs-ingestion",
            "idle",
            at.AddSeconds(-10),
            new QueueSnapshot(0, 0, 0, 100, 0, 1_000, null),
            10_485_760,
            Intake(capacityRefusals: 0),
            new PipelineMetricsSnapshot(at.AddHours(-1), 100, 100, 0, 0, 10_000, 12_000, []),
            false,
            [],
            null,
            null);

    private static IntakeMetricsSnapshot Intake(long capacityRefusals) =>
        new(TestEvents.Now.AddHours(-1), 100, 10_000, capacityRefusals, capacityRefusals * 10, 0, 0,
            capacityRefusals == 0 ? null : TestEvents.Now.AddMinutes(-1),
            capacityRefusals == 0 ? null : PipelineTelemetry.QueueCapacityReason);

    private static SyslogListenerStatus Listener(long tlsHandshakeFailures = 0, long dropped = 0) =>
        new("firewall-tls", "tls", "127.0.0.1:6514", 1, 3, 0, 0, tlsHandshakeFailures, 500, 50_000, 500, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, dropped, 0, 0, 0, TestEvents.Now.AddSeconds(-5));

    private static WindowsEventSubscriptionStatus Subscription(string state) =>
        new("forwarded-security", "ForwardedEvents", state, 1_000, 1_000, 1_000_000, 900, 0, 0, 100, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, TestEvents.Now.AddMinutes(-1), TestEvents.Now);
}
