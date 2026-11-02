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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
            WindowsEventLog = [Subscription("winevt-read-failed", malformed: 2, oversized: 1)],
            // 3,072 in-use pages of 3,584, plus 512 free pages the file keeps after retention.
            QueuePages = new QueuePageUsage(4_096, 3_584, 512, 3_584)
        };

        SecurityEventEnvelope record = CollectorHealthRecord.Create(sample, Identity.Id, "production");

        Assert.Equal(SecurityEventTypes.CollectorHealth, record.EventType);
        Assert.Equal(SecurityEventCategories.CollectorHealth, record.EventCategory);
        Assert.Equal(CollectorHealthRecord.EventAction, record.EventAction);
        Assert.Equal(EventResult.Failure, record.EventResult);
        Assert.StartsWith("collector-health-", record.EventId, StringComparison.Ordinal);
        Assert.Equal(TestEvents.Now, record.TimeGenerated);
        Assert.Equal(
            "Collector health: stalled, retrying, source-overdue, syslog-errors, windows-event-log-errors",
            record.EventOutcomeReason);
        Assert.Equal(EventSeverity.High, record.EventSeverity);
        IReadOnlyDictionary<string, JsonElement> attributes = record.Attributes!;
        Assert.Equal("critical", attributes["status"].GetString());
        Assert.Equal(1_200, attributes["queue"].GetProperty("oldestUndeliveredAgeSeconds").GetInt64());
        Assert.Equal(43, attributes["queue"].GetProperty("undelivered").GetInt64());
        Assert.Equal(4.0, attributes["storage"].GetProperty("undeliveredMiB").GetDouble());
        Assert.Equal(9.0, attributes["storage"].GetProperty("storedMiB").GetDouble());
        Assert.Equal(10.0, attributes["storage"].GetProperty("queueCapacityMiB").GetDouble());
        Assert.Equal(40.0, attributes["storage"].GetProperty("capacityUsedPercent").GetDouble());
        // In-use pages, not the file length: the 2 MiB free list does not count.
        Assert.Equal(12.0, attributes["storage"].GetProperty("queuePagesUsedMiB").GetDouble());
        Assert.Equal(2.0, attributes["storage"].GetProperty("queueFreeListMiB").GetDouble());
        Assert.Equal(14.0, attributes["storage"].GetProperty("queuePageLimitMiB").GetDouble());
        Assert.Equal(85.7, attributes["storage"].GetProperty("queuePagesUsedPercent").GetDouble());
        Assert.Equal(2, attributes["windowsEventLog"][0].GetProperty("malformed").GetInt64());
        Assert.Equal(1, attributes["windowsEventLog"][0].GetProperty("oversized").GetInt64());
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
    }

    [Fact]
    public void Problems_ReportEveryDeliveryConditionAlongsideDeadLetters()
    {
        // Dead letters make DeliveryHealth.Evaluate say only "degraded"; the record must still
        // report backpressure, a stall and retries, and rank its status by the worst of them.
        CollectorHealthSample sample = Sample(TestEvents.Now, sequence: 1) with
        {
            DeliveryStatus = "degraded",
            Queue = new QueueSnapshot(100, 5, 1, 0, 2, 10_000_000, TestEvents.Now.AddMinutes(-30), 9_500_000)
        };

        Assert.Equal(
            [CollectorHealthRecord.DeadLetters, CollectorHealthRecord.Backpressure, CollectorHealthRecord.Stalled, CollectorHealthRecord.Retrying],
            CollectorHealthRecord.Problems(sample, null));
        SecurityEventEnvelope record = CollectorHealthRecord.Create(sample, Identity.Id, "production");
        Assert.Equal(EventSeverity.High, record.EventSeverity);
        Assert.Equal("critical", record.Attributes!["status"].GetString());
        Assert.Equal("degraded", record.Attributes["delivery"].GetProperty("status").GetString());

        CollectorHealthSample deadLettersOnly = sample with { Queue = new QueueSnapshot(0, 0, 0, 0, 2, 10, null, 0) };
        Assert.Equal([CollectorHealthRecord.DeadLetters], CollectorHealthRecord.Problems(deadLettersOnly, null));
        Assert.Equal(EventSeverity.Medium, CollectorHealthRecord.Create(deadLettersOnly, Identity.Id, "production").EventSeverity);
        Assert.Equal("degraded", CollectorHealthRecord.StatusOf([CollectorHealthRecord.DeadLetters]));

        CollectorHealthSample retryingOnly = sample with { Queue = new QueueSnapshot(0, 1, 0, 0, 0, 10, TestEvents.Now, 10) };
        Assert.Equal([CollectorHealthRecord.Retrying], CollectorHealthRecord.Problems(retryingOnly, null));
        Assert.Equal(EventSeverity.Low, CollectorHealthRecord.Create(retryingOnly, Identity.Id, "production").EventSeverity);
        Assert.Equal("warning", CollectorHealthRecord.StatusOf([CollectorHealthRecord.Retrying]));
        Assert.Equal("healthy", CollectorHealthRecord.StatusOf([]));

        // Delivery conditions do not apply without an output.
        Assert.Empty(CollectorHealthRecord.Problems(retryingOnly with { OutputType = "none" }, null));
    }

    [Fact]
    public void Problems_ReportACredentialFailureUntilADeliverySucceeds()
    {
        CollectorHealthSample previous = Sample(TestEvents.Now, sequence: 1);
        CollectorHealthSample failing = previous with
        {
            At = TestEvents.Now.AddMinutes(5),
            Sequence = 2,
            LastSuccessfulDeliveryAt = TestEvents.Now.AddMinutes(-1),
            LastDeliveryFailure = new DeliveryFailureActivity("destination-azure-credential-failed", TestEvents.Now.AddMinutes(4))
        };

        Assert.Equal([CollectorHealthRecord.DestinationCredential], CollectorHealthRecord.Problems(failing, previous));
        // A mixed batch can report success and a credential failure at the same clock tick.
        Assert.Equal([CollectorHealthRecord.DestinationCredential], CollectorHealthRecord.Problems(
            failing with { LastSuccessfulDeliveryAt = TestEvents.Now.AddMinutes(4) }, previous));
        SecurityEventEnvelope record = CollectorHealthRecord.Create(failing, Identity.Id, "production", previous);
        Assert.Equal(EventSeverity.High, record.EventSeverity);
        Assert.Equal("destination-azure-credential-failed", record.Attributes!["delivery"].GetProperty("lastFailureCode").GetString());
        // A missing role (HTTP 403) is an identity problem too.
        Assert.Equal(
            [CollectorHealthRecord.DestinationCredential],
            CollectorHealthRecord.Problems(
                failing with { LastDeliveryFailure = new DeliveryFailureActivity("destination-azure-http-403", TestEvents.Now.AddMinutes(4)) },
                previous));
        // An unreachable destination is not; nor a failure a later delivery superseded, nor one
        // reported by an earlier record.
        Assert.Empty(CollectorHealthRecord.Problems(
            failing with { LastDeliveryFailure = new DeliveryFailureActivity("destination-azure-unavailable", TestEvents.Now.AddMinutes(4)) },
            previous));
        Assert.Empty(CollectorHealthRecord.Problems(failing with { LastSuccessfulDeliveryAt = TestEvents.Now.AddMinutes(4.5) }, previous));
        Assert.Empty(CollectorHealthRecord.Problems(
            failing with { LastDeliveryFailure = new DeliveryFailureActivity("destination-azure-credential-failed", TestEvents.Now.AddMinutes(-2)) },
            previous));
    }

    [Fact]
    public void Create_ReportsSyslogTlsReloadAndCertificateLifetimes()
    {
        CollectorHealthSample previous = Sample(TestEvents.Now, sequence: 1) with { Syslog = [Listener()] };
        SyslogListenerStatus listener = Listener() with
        {
            TlsReloads = 2,
            TlsReloadFailures = 1,
            TlsRevoked = 1,
            RelpAcknowledged = 40,
            RelpServerCloses = 2,
            RelpBusyCloses = 1,
            ServerCertificateNotAfter = TestEvents.Now.AddDays(10),
            ClientCertificateAuthorityNotAfter = TestEvents.Now.AddDays(300),
            ClientRevocationListNextUpdate = TestEvents.Now.AddDays(1)
        };
        CollectorHealthSample current = previous with { At = TestEvents.Now.AddMinutes(5), Sequence = 2, Syslog = [listener] };

        SecurityEventEnvelope record = CollectorHealthRecord.Create(current, Identity.Id, "production", previous);

        JsonElement item = record.Attributes!["syslog"][0];
        Assert.Equal(2, item.GetProperty("tlsReloads").GetInt64());
        Assert.Equal(1, item.GetProperty("tlsReloadFailures").GetInt64());
        Assert.Equal(1, item.GetProperty("tlsRevoked").GetInt64());
        Assert.Equal(TestEvents.Now.AddDays(10), item.GetProperty("serverCertificateNotAfter").GetDateTimeOffset());
        Assert.Equal(TestEvents.Now.AddDays(1), item.GetProperty("clientRevocationListNextUpdate").GetDateTimeOffset());
        Assert.True(item.GetProperty("tls").GetBoolean());
        Assert.Equal((40, 2, 1), (item.GetProperty("relpAcknowledged").GetInt64(), item.GetProperty("relpServerCloses").GetInt64(),
            item.GetProperty("relpBusyCloses").GetInt64()));
        Assert.False(CollectorHealthRecord.Create(previous, Identity.Id, "production", null).Attributes!["syslog"][0].GetProperty("tls").GetBoolean());
        Assert.Equal([CollectorHealthRecord.SyslogErrors], CollectorHealthRecord.Problems(current, previous));
        // A successful reload alone is not an error.
        Assert.Empty(CollectorHealthRecord.Problems(
            previous with { At = TestEvents.Now.AddMinutes(5), Sequence = 2, Syslog = [Listener() with { TlsReloads = 1 }] },
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
    public void Create_ReportsIncompleteTransportCoverageWhenListsAreTruncated()
    {
        SyslogListenerStatus[] listeners = [.. Enumerable.Range(0, 26).Select(i =>
            Listener(tlsHandshakeFailures: i == 25 ? 1 : 0) with
            {
                Id = $"listener-{i}",
                ServerCertificateNotAfter = i == 25 ? TestEvents.Now.AddDays(1) : null
            })];
        WindowsEventSubscriptionStatus[] subscriptions = [.. Enumerable.Range(0, 26).Select(i =>
            Subscription(i == 25 ? "winevt-read-failed" : "running") with { Id = $"subscription-{i}" })];
        CollectorHealthSample sample = Sample(TestEvents.Now, 1) with { Syslog = listeners, WindowsEventLog = subscriptions };
        SecurityEventEnvelope record = CollectorHealthRecord.Create(sample, Identity.Id, "production");
        Assert.Equal(25, record.Attributes!["syslog"].GetArrayLength());
        Assert.Equal(25, record.Attributes["windowsEventLog"].GetArrayLength());
        Assert.Contains(CollectorHealthRecord.SyslogErrors, CollectorHealthRecord.Problems(sample, null));
        Assert.Contains(CollectorHealthRecord.WindowsEventLogErrors, CollectorHealthRecord.Problems(sample, null));
        JsonElement coverage = record.Attributes["monitoringCoverage"];
        Assert.False(coverage.GetProperty("syslogComplete").GetBoolean());
        Assert.False(coverage.GetProperty("windowsEventLogComplete").GetBoolean());
        Assert.DoesNotContain("127.0.0.1", JsonSerializer.Serialize(record, BowerJson.Envelope), StringComparison.Ordinal);
        foreach (CollectorHealthSample complete in new[]
        {
            sample with { Syslog = listeners[..25], WindowsEventLog = subscriptions[..25] },
            sample with { Syslog = null, WindowsEventLog = null }
        })
        {
            coverage = CollectorHealthRecord.Create(complete, Identity.Id, "production").Attributes!["monitoringCoverage"];
            Assert.True(coverage.GetProperty("syslogComplete").GetBoolean());
            Assert.True(coverage.GetProperty("windowsEventLogComplete").GetBoolean());
        }
    }

    [Fact]
    public async Task Process_QuarantinesExternallySubmittedHealthRegardlessOfCategoryOrAdapter()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(new JsonEventRedactor(), new RejectUnexpectedPolicyEvaluation(), store, clock);
        SecurityEventEnvelope health = CollectorHealthRecord.Create(Sample(TestEvents.Now, 1), Identity.Id, "production");
        foreach (string category in new[] { SecurityEventCategories.CollectorHealth, "authentication" })
        {
            string payload = JsonSerializer.Serialize(health with { EventCategory = category }, BowerJson.Envelope);
            ProcessingResult result = await processor.ProcessAsync(payload,
                Identity with { SourceAdapter = CollectorHealthRecord.SourceAdapter }, cancellationToken);
            Assert.Equal(DecisionAction.Quarantine, result.Action);
            Assert.Equal(ProcessingStage.Validation, result.Stage);
            Assert.Equal(["reserved-event-type"], result.Reasons);
            Assert.False(result.Queued);
        }
        Assert.Equal(0, (await store.GetSnapshotAsync(cancellationToken)).Queued);
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

        ProcessingResult result = await processor.ProcessCollectorHealthAsync(
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
        // Health records may use a small reserve past the cap; fill that too.
        await store.EnqueueAsync(
            new QueuedEvent("reserve-filler", "sha256:reserve-filler", new string('x', 66_000), clock.UtcNow) { UsesStorageReserve = true },
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

        // Room again (the fillers were delivered): the next record carries the refusal.
        foreach (QueuedEvent filler in await store.LeaseAsync(2, TimeSpan.FromMinutes(1), cancellationToken))
        {
            await store.MarkDeliveredAsync(filler.EventId, "test", filler.LeaseToken, cancellationToken);
        }

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

    /// <summary>
    /// Large events can fill the logical byte cap while most pages are free. The record still
    /// goes in from its small reserve and reports the saturation (council round 1).
    /// </summary>
    [Fact]
    public async Task Worker_RecordIsQueuedAndReportsBackpressureWhenLargeEventsFillTheByteCap()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(cancellationToken);
        int index = 0;
        foreach (int size in new[] { 100_000, 1_000, 10 })
        {
            while (true)
            {
                try
                {
                    await store.EnqueueAsync(new QueuedEvent($"large-{index}", $"sha256:large-{index}", new string('x', size), clock.UtcNow), cancellationToken);
                    index++;
                }
                catch (QueueCapacityExceededException exception)
                {
                    Assert.Equal(QueueCapacityReasons.Queue, exception.Reason);
                    break;
                }
            }
        }

        QueuePageUsage pages = await store.GetPageUsageAsync(cancellationToken);
        Assert.True(pages.UsedPercent < 60, $"pages {pages.UsedPercent}%");
        Assert.True((await store.GetSnapshotAsync(cancellationToken)).UndeliveredBytes > 1_048_576 - 20);
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
            OutputType = "azure-logs-ingestion",
            HealthRecordInterval = TimeSpan.FromMinutes(1)
        };
        CollectorHealthWorker worker = new(
            processor, Identity, store, telemetry, new SourceHealth(null, telemetry, clock), new DeliveryActivity(),
            settings, clock, NullLogger<CollectorHealthWorker>.Instance);

        ProcessingResult? result = await worker.RecordAsync(TimeSpan.FromMinutes(1), cancellationToken);

        Assert.True(result?.Queued);
        QueuedEvent record = (await store.LeaseAsync(10_000, TimeSpan.FromMinutes(1), cancellationToken))
            .Single(item => item.EventId.StartsWith("collector-health-", StringComparison.Ordinal));
        SecurityEventEnvelope envelope = JsonSerializer.Deserialize(record.Payload, BowerJson.Envelope)!;
        Assert.Contains(
            CollectorHealthRecord.Backpressure,
            envelope.Attributes!["problems"].EnumerateArray().Select(item => item.GetString()));
        Assert.True(envelope.Attributes["storage"].GetProperty("capacityUsedPercent").GetDouble() >= 99);
        // The reserve is bounded: ordinary events stay refused, and records stop at the reserve.
        Assert.True((await store.GetSnapshotAsync(cancellationToken)).UndeliveredBytes <= 1_048_576 + store.HealthRecordReserveBytes);
        await Assert.ThrowsAsync<QueueCapacityExceededException>(() => store.EnqueueAsync(
            new QueuedEvent("ordinary", "sha256:ordinary", "x", clock.UtcNow), cancellationToken));
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
    public async Task Host_RejectsProducerHealthRecord()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = CollectorApplication.Build(
            Settings(directory.Path) with { PolicyDirectory = PolicyDirectoryWithHealth(directory.Path) },
            builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        using HttpClient client = app.GetTestClient();
        string payload = CollectorHealthRecord.CreateJson(Sample(TestEvents.Now, 1), Identity.Id, "production");
        using HttpResponseMessage response = await client.PostAsync("/v1/events",
            new StringContent(payload, System.Text.Encoding.UTF8, "application/json"), cancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("reserved-event-type", await response.Content.ReadAsStringAsync(cancellationToken), StringComparison.Ordinal);
        await app.StopAsync(cancellationToken);
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
        // The limit at which new events are refused, and the settlement ceiling SQLite enforces.
        JsonElement storage = envelope.Attributes["storage"];
        long basePages = (10L * 1024 * 1024 * 1024 * 4 + 16_777_216) / 4 / 4_096;
        Assert.Equal(Math.Round(SqliteEventStore.IntakePageLimit(basePages, 4_096) * 4_096 / 1_048_576.0, 1), storage.GetProperty("queuePageLimitMiB").GetDouble());
        Assert.Equal(Math.Round(basePages * 7 / 4 * 4_096 / 1_048_576.0, 1), storage.GetProperty("queueCeilingMiB").GetDouble());
        // The test host's real volume: any measured state, with free space in MiB.
        Assert.Matches("^(normal|warning|critical|unknown)$", storage.GetProperty("volumeState").GetString()!);
        Assert.True(storage.GetProperty("intakePaused").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.True(storage.GetProperty("volumeFreeMiB").GetDouble() > 0);
        Assert.True(storage.GetProperty("queuePagesUsedMiB").GetDouble() > 0);
        Assert.True(storage.GetProperty("queuePagesUsedPercent").GetDouble() < 1);
        await app.StopAsync(cancellationToken);
    }

    [Fact]
    public void Build_FailsClosedWhenThePolicyRefusesDegradedHealthRecords()
    {
        using TemporaryDirectory directory = new();
        string policies = PolicyDirectoryWithHealth(directory.Path);
        // Accepts healthy and medium records only: high-severity records (a stall,
        // backpressure) would be refused every interval, exactly when they matter.
        string health = Path.Combine(policies, "collector-health.yaml");
        File.WriteAllText(health, File.ReadAllText(health).Replace(
            "  eventActions:\n    - collector.health\n",
            "  eventActions:\n    - collector.health\n  eventSeverities:\n    - informational\n    - low\n    - medium\n",
            StringComparison.Ordinal));
        Assert.Contains("eventSeverities", File.ReadAllText(health), StringComparison.Ordinal);

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorApplication.Build(
            Settings(directory.Path) with { PolicyDirectory = policies, HealthRecordInterval = TimeSpan.FromMinutes(5) },
            builder => builder.WebHost.UseTestServer()));

        Assert.Contains("severity High", error.Message, StringComparison.Ordinal);
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
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reload_RefusesRebuiltHealthSettingsWithoutChangingTheRunningCollector(bool refusesDegraded)
    {
        using TemporaryDirectory directory = new();
        CollectorSettings running = Settings(directory.Path);
        await using WebApplication app = CollectorApplication.Build(running, builder => builder.WebHost.UseTestServer());
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        try
        {
            string candidatePolicies = PolicyDirectoryWithHealth(directory.Path);
            string health = Path.Combine(candidatePolicies, "collector-health.yaml");
            if (refusesDegraded)
            {
                File.WriteAllText(health, File.ReadAllText(health).Replace(
                    "  eventActions:\n    - collector.health\n",
                    "  eventActions:\n    - collector.health\n  eventSeverities:\n    - informational\n    - low\n    - medium\n",
                    StringComparison.Ordinal));
                Assert.Contains("eventSeverities", File.ReadAllText(health), StringComparison.Ordinal);
            }
            Dictionary<string, string> restart = new(StringComparer.Ordinal)
            {
                ["BOWER_QUEUE_PATH"] = running.QueuePath,
                ["BOWER_COLLECTOR_ID"] = running.CollectorId,
                ["BOWER_SINGLE_TRUST_DOMAIN"] = "true",
                ["BOWER_POLICY_DIRECTORY"] = refusesDegraded ? candidatePolicies : running.PolicyDirectory,
                ["BOWER_HEALTH_RECORD_INTERVAL_SECONDS"] = "300"
            };

            Assert.Null(ManagementCommandWorker.ReloadRefusal(running));
            Assert.Equal(nameof(InvalidOperationException), ManagementCommandWorker.ReloadRefusal(
                running, () => name => restart.GetValueOrDefault(name)));
            Assert.Null(running.HealthRecordInterval);
            Assert.False(app.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.IsCancellationRequested);
            using HttpClient client = app.GetTestClient();
            using HttpResponseMessage response = await client.GetAsync("/health", cancellation);
            response.EnsureSuccessStatusCode();

            // A corrected candidate passes the same pre-check without changing current settings.
            File.Copy(HealthPolicyFile, health, overwrite: true);
            restart["BOWER_POLICY_DIRECTORY"] = candidatePolicies;
            Assert.Null(ManagementCommandWorker.ReloadRefusal(running, () => name => restart.GetValueOrDefault(name)));
            Assert.Null(running.HealthRecordInterval);
        }
        finally { await app.StopAsync(cancellation); }
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("0", null)]
    [InlineData("00", null)]
    [InlineData("+0", null)]
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

    [Fact]
    public void Create_ReportsQueueVolumeWatermarksAsMebibytesAndStorageProblems()
    {
        CollectorHealthSample first = Sample(TestEvents.Now, sequence: 1) with
        {
            OutputType = "azure-logs-ingestion",
            QueuePages = new QueuePageUsage(4_096, 2_000, 0, 2_000, 3_500),
            Storage = Volume("warning", intakePaused: false, freeBytes: 900L * 1_048_576, refusals: 2, purged: 10)
        };
        CollectorHealthSample second = Sample(TestEvents.Now.AddMinutes(5), sequence: 2) with
        {
            CollectorStartedAt = first.CollectorStartedAt,
            OutputType = "azure-logs-ingestion",
            QueuePages = first.QueuePages,
            Storage = Volume("critical", intakePaused: true, freeBytes: 100L * 1_048_576, refusals: 7, purged: 40)
        };

        Assert.Contains(CollectorHealthRecord.StorageLow, CollectorHealthRecord.Problems(first, null));
        IReadOnlyList<string> problems = CollectorHealthRecord.Problems(second, first);
        Assert.Contains(CollectorHealthRecord.StorageCritical, problems);
        // Pages at the intake limit and a paused volume are backpressure, as for a full queue.
        Assert.Contains(CollectorHealthRecord.Backpressure, problems);
        SecurityEventEnvelope record = CollectorHealthRecord.Create(second, Identity.Id, "production", first);
        Assert.Equal(EventSeverity.High, record.EventSeverity);
        JsonElement storage = record.Attributes!["storage"];
        Assert.Equal("critical", storage.GetProperty("volumeState").GetString());
        Assert.True(storage.GetProperty("intakePaused").GetBoolean());
        Assert.Equal(100.0, storage.GetProperty("volumeFreeMiB").GetDouble());
        Assert.Equal(4.9, storage.GetProperty("volumeFreePercent").GetDouble());
        Assert.Equal(1_024.0, storage.GetProperty("volumeWarningFreeMiB").GetDouble());
        Assert.Equal(256.0, storage.GetProperty("volumeCriticalFreeMiB").GetDouble());
        Assert.Equal(13.7, storage.GetProperty("queueCeilingMiB").GetDouble());
        // Counters are deltas since the previous record, like every other counter.
        Assert.Equal(5, storage.GetProperty("storageRefusals").GetInt64());
        Assert.Equal(30, storage.GetProperty("pressurePurgedEvents").GetInt64());
        Assert.All(storage.EnumerateObject().Where(item => item.Value.ValueKind == JsonValueKind.Number),
            item => Assert.InRange(item.Value.GetDouble(), 0, CollectorHealthRecord.MaximumReportedValue));
    }

    [Fact]
    public void NextBaseline_KeepsTheLastReportedStorageWhenARecordHadNone()
    {
        CollectorHealthSample first = Sample(TestEvents.Now, sequence: 1) with
        {
            Storage = Volume("critical", intakePaused: true, freeBytes: 100L * 1_048_576, refusals: 5, purged: 10)
        };
        // The volume could not be read for the second record, which was still queued.
        CollectorHealthSample second = Sample(TestEvents.Now.AddMinutes(5), sequence: 2) with
        {
            CollectorStartedAt = first.CollectorStartedAt,
            Storage = null
        };
        CollectorHealthSample third = Sample(TestEvents.Now.AddMinutes(10), sequence: 3) with
        {
            CollectorStartedAt = first.CollectorStartedAt,
            Storage = Volume("critical", intakePaused: true, freeBytes: 100L * 1_048_576, refusals: 7, purged: 12)
        };

        CollectorHealthSample baseline = CollectorHealthRecord.NextBaseline(second, CollectorHealthRecord.NextBaseline(first, null));
        JsonElement storage = CollectorHealthRecord.Create(third, Identity.Id, "production", baseline).Attributes!["storage"];

        // Deltas since the last reported storage, not since process start (7 and 12).
        Assert.Equal(2, storage.GetProperty("storageRefusals").GetInt64());
        Assert.Equal(2, storage.GetProperty("pressurePurgedEvents").GetInt64());
        Assert.Equal(second.At, baseline.At);
        Assert.Same(third, CollectorHealthRecord.NextBaseline(third, baseline));
    }

    private static QueueStorageStatus Volume(string state, bool intakePaused, long freeBytes, long refusals, long purged) =>
        new(state, intakePaused, TestEvents.Now, freeBytes, 2_048L * 1_048_576, Math.Round(freeBytes * 100.0 / (2_048L * 1_048_576), 2),
            1_024L * 1_048_576, 256L * 1_048_576, TestEvents.Now, 1, intakePaused ? 1 : 0,
            8L * 1_048_576, 7L * 1_048_576, 1_048_576, 64L * 1_048_576, 1_000, 0.1, 30, purged, null,
            refusals, refusals * 1_000, null, intakePaused ? "storage-critical" : null);

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

    private sealed class RejectUnexpectedPolicyEvaluation : ITelemetryPolicyEvaluator
    {
        public PolicyDecision Evaluate(SecurityEventEnvelope candidate) =>
            throw new InvalidOperationException("Reserved events must not reach policy evaluation.");
    }

    private static SyslogListenerStatus Listener(long tlsHandshakeFailures = 0, long dropped = 0) =>
        new("firewall-tls", "tls", "127.0.0.1:6514", 1, 3, 0, 0, tlsHandshakeFailures, 500, 50_000, 500, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, dropped, 0, 0, 0, TestEvents.Now.AddSeconds(-5));

    private static WindowsEventSubscriptionStatus Subscription(string state, long malformed = 0, long oversized = 0) =>
        new("forwarded-security", "ForwardedEvents", state, 1_000, 1_000, 1_000_000, 900, 0, 0, 100, 0, 0, malformed, oversized,
            0, 0, 1, 0, 0, 0, TestEvents.Now.AddMinutes(-1), TestEvents.Now);
}
