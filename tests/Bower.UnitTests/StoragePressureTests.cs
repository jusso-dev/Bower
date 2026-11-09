using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

/// <summary>
/// Free-space watermarks, retained-acknowledgement pressure and disk-full crash/recovery.
/// Refused events are never committed; acknowledgement and retention keep running; nothing
/// unacknowledged is ever deleted.
/// </summary>
public sealed class StoragePressureTests
{
    private const long MiB = 1024 * 1024;
    private const long GiB = 1024 * MiB;
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public void Watermarks_UseTheLargerOfBytesAndPercentAndLeaveStatesWithHysteresis()
    {
        FakeDiskSpaceProbe probe = new(2 * GiB, 10 * GiB);
        FakeClock clock = new(TestEvents.Now);
        StorageGuard guard = new("/data/queue.db", new StorageWatermarkOptions(), probe, clock);

        StorageWatermarkSnapshot normal = guard.Evaluate(force: true);
        Assert.Equal(StorageState.Normal, normal.State);
        // 10% of 10 GiB beats 1 GiB only when larger; 5% (512 MiB) beats 256 MiB.
        Assert.Equal(1 * GiB, normal.WarningThresholdBytes);
        Assert.Equal(10 * GiB / 20, normal.CriticalThresholdBytes);
        Assert.Equal(20.0, normal.FreePercent);

        long margin = StorageGuard.HysteresisBytes(10 * GiB);
        long critical = 10 * GiB / 20;
        (long Free, StorageState Expected)[] steps =
        [
            (900 * MiB, StorageState.Warning),
            (critical - 1, StorageState.Critical),
            (critical + margin - 1, StorageState.Critical),
            (critical + margin, StorageState.Warning),
            (GiB + margin - 1, StorageState.Warning),
            (GiB + margin, StorageState.Normal),
            (GiB - 1, StorageState.Warning)
        ];
        foreach ((long free, StorageState expected) in steps)
        {
            probe.FreeBytes = free;
            Assert.Equal(expected, guard.Evaluate(force: true).State);
        }

        StorageWatermarkSnapshot last = guard.Evaluate(force: true);
        Assert.Equal(3, last.WarningTransitions);
        Assert.Equal(1, last.CriticalTransitions);
        Assert.Equal(clock.UtcNow, last.StateChangedAt);
    }

    [Fact]
    public void Watermarks_SmallVolumesUseTheByteFloorAndSamplingIsBounded()
    {
        FakeDiskSpaceProbe probe = new(800 * MiB, GiB);
        FakeClock clock = new(TestEvents.Now);
        StorageGuard guard = new("/data/queue.db", new StorageWatermarkOptions(), probe, clock);
        StorageWatermarkSnapshot first = guard.Evaluate();
        Assert.Equal((GiB, 256 * MiB), (first.WarningThresholdBytes!.Value, first.CriticalThresholdBytes!.Value));
        Assert.Equal(StorageState.Warning, first.State);

        // Intake calls this per insert: one measurement per sample interval.
        for (int index = 0; index < 100; index++)
        {
            guard.ThrowIfCritical();
        }

        Assert.Equal(1, probe.Calls);
        probe.FreeBytes = 100 * MiB;
        guard.ThrowIfCritical();
        clock.Advance(guard.SampleInterval);
        QueueCapacityExceededException refused = Assert.Throws<QueueCapacityExceededException>(guard.ThrowIfCritical);
        Assert.Equal(QueueCapacityReasons.StorageCritical, refused.Reason);
        Assert.True(refused.IsStorage);
        Assert.Equal(2, probe.Calls);
    }

    [Fact]
    public void Watermarks_UnmeasurableVolumeIsUnknownAndDoesNotRefuse()
    {
        FakeDiskSpaceProbe probe = new(0, GiB) { Fails = true };
        StorageGuard guard = new("/data/queue.db", new StorageWatermarkOptions(), probe, new FakeClock(TestEvents.Now));
        guard.ThrowIfCritical();
        StorageWatermarkSnapshot snapshot = guard.Evaluate(force: true);
        Assert.Equal(StorageState.Unknown, snapshot.State);
        Assert.Null(snapshot.FreeBytes);
        Assert.Null(snapshot.FreePercent);
        Assert.Equal("unknown", StorageWatermarkSnapshot.Name(snapshot.State));
    }

    [Fact]
    public void SystemProbe_MeasuresTheQueueVolume()
    {
        using TemporaryDirectory directory = new();
        DiskSpace? space = SystemDiskSpaceProbe.Instance.Measure(directory.Path);
        Assert.NotNull(space);
        Assert.InRange(space.Value.FreeBytes, 1, space.Value.TotalBytes);
    }

    [Theory]
    [InlineData(MiB, 0, 16 * MiB, 0)]
    [InlineData(64 * MiB, 0, 128 * MiB, 0)]
    [InlineData(GiB, 4, 256 * MiB, 5)]
    [InlineData(GiB, 10, 256 * MiB, 51)]
    [InlineData(GiB, -1, 256 * MiB, 0)]
    public void Watermarks_RejectUnsafeConfiguration(long warningBytes, int warningPercent, long criticalBytes, int criticalPercent)
    {
        StorageWatermarkOptions options = new()
        {
            WarningFreeBytes = warningBytes,
            WarningFreePercent = warningPercent,
            CriticalFreeBytes = criticalBytes,
            CriticalFreePercent = criticalPercent
        };
        Assert.Throws<InvalidOperationException>(() => options.Validate());
    }

    [Fact]
    public void Settings_ReadWatermarksAndKeepDefaultConfigurationHashes()
    {
        Dictionary<string, string> environment = new()
        {
            ["BOWER_QUEUE_PATH"] = "/var/lib/bower/queue.db",
            ["BOWER_POLICY_DIRECTORY"] = "/etc/bower/policies"
        };
        CollectorSettings defaults = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        Assert.Equal(new StorageWatermarkOptions(), defaults.StorageWatermarks);
        Assert.Equal(TimeSpan.FromHours(1), defaults.PressureRetentionFloor);
        Assert.Equal(defaults.ConfigurationHash(), (defaults with { StorageWatermarks = new() }).ConfigurationHash());

        environment["BOWER_STORAGE_WARNING_FREE_BYTES"] = "536870912";
        environment["BOWER_STORAGE_WARNING_FREE_PERCENT"] = "25";
        environment["BOWER_STORAGE_CRITICAL_FREE_BYTES"] = "268435456";
        environment["BOWER_STORAGE_CRITICAL_FREE_PERCENT"] = "12";
        CollectorSettings custom = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        custom.Validate();
        Assert.Equal(
            new StorageWatermarkOptions
            {
                WarningFreeBytes = 512 * MiB,
                WarningFreePercent = 25,
                CriticalFreeBytes = 256 * MiB,
                CriticalFreePercent = 12
            },
            custom.StorageWatermarks);
        Assert.NotEqual(defaults.ConfigurationHash(), custom.ConfigurationHash());

        environment["BOWER_QUEUE_PRESSURE_RETENTION_MINUTES"] = "5";
        CollectorSettings floor = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        Assert.Equal(TimeSpan.FromMinutes(5), floor.PressureRetentionFloor);
        Assert.NotEqual(custom.ConfigurationHash(), floor.ConfigurationHash());
        environment["BOWER_QUEUE_PRESSURE_RETENTION_MINUTES"] = "100000";
        Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name)).Validate());
        environment.Remove("BOWER_QUEUE_PRESSURE_RETENTION_MINUTES");

        environment["BOWER_STORAGE_CRITICAL_FREE_BYTES"] = "1048576";
        Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name)).Validate());
    }

    [Fact]
    public async Task CriticalWatermark_RefusesOnlyNewEventsWhileAcknowledgementAndRetentionDrainTheQueue()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        Assert.True((await store.EnqueueAsync(Event("a"), Cancellation)).Enqueued);
        Assert.True((await store.EnqueueAsync(Event("b"), Cancellation)).Enqueued);
        Assert.True((await store.EnqueueAsync(Event("c"), Cancellation)).Enqueued);
        LedgerHead before = await store.GetLedgerHeadAsync(Cancellation);

        probe.FreeBytes = 100 * MiB;
        clock.Advance(TimeSpan.FromSeconds(1));
        QueueCapacityExceededException refused = await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => store.EnqueueAsync(Event("d"), Cancellation));
        Assert.Equal(QueueCapacityReasons.StorageCritical, refused.Reason);
        // Nothing was committed, and an exact replay is still a duplicate, not a refusal.
        Assert.Equal(before, await store.GetLedgerHeadAsync(Cancellation));
        Assert.True((await store.EnqueueAsync(Event("a"), Cancellation)).Duplicate);

        // Delivery, acknowledgement, retry, dead-letter and retention all still commit.
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation);
        Assert.Equal(3, leased.Count);
        Assert.Empty(await store.MarkDeliveredBatchAsync(
            ["a"], "ack", leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation));
        await store.MarkRetryingAsync("b", "destination-test", clock.UtcNow, LeaseTestClaims.Token(leased, "b"), Cancellation);
        await store.MarkDeadLetteredAsync("c", "bad", LeaseTestClaims.Token(leased, "c"), Cancellation);
        Assert.Equal(1, await store.PurgeDeliveredAsync(clock.UtcNow.AddSeconds(1), 10, Cancellation));
        await store.MaintainAsync(Cancellation);
        QueueSnapshot drained = await store.GetSnapshotAsync(Cancellation);
        Assert.Equal((0, 1, 1), (drained.Delivered, drained.Retrying, drained.DeadLettered));

        // Space returns: intake resumes by itself on the next sample.
        probe.FreeBytes = 10 * GiB;
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True((await store.EnqueueAsync(Event("d"), Cancellation)).Enqueued);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task StorageRefusals_AreCountedAsCapacityRefusalsWithTheirReason()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * MiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock,
            telemetry);
        string candidate = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options);
        long bytes = Encoding.UTF8.GetByteCount(candidate);

        await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => processor.ProcessAsync(candidate, new CollectorIdentity("c", "1", "test", "sha256:x"), Cancellation));
        IntakeMetricsSnapshot intake = telemetry.IntakeSnapshot();
        StorageRefusalSnapshot storage = telemetry.StorageRefusalSnapshot();
        // Intake keeps its stable shape and reason codes; storage detail is separate.
        Assert.Equal((1, bytes), (intake.CapacityRefusals, intake.CapacityRefusedBytes));
        Assert.Equal(PipelineTelemetry.QueueCapacityReason, intake.LastRefusalReason);
        Assert.Equal((1, bytes), (storage.Refusals, storage.RefusedBytes));
        Assert.Equal(PipelineTelemetry.StorageCriticalReason, storage.LastRefusalReason);
        Assert.Equal(clock.UtcNow, storage.LastRefusalAt);

        clock.Advance(TimeSpan.FromSeconds(1));
        telemetry.RecordCapacityRefusal(5, PipelineTelemetry.StorageFullReason);
        Assert.Equal(PipelineTelemetry.StorageFullReason, telemetry.StorageRefusalSnapshot().LastRefusalReason);
        clock.Advance(TimeSpan.FromSeconds(1));
        telemetry.RecordCapacityRefusal(5);
        Assert.Equal((3, 2), (telemetry.IntakeSnapshot().CapacityRefusals, telemetry.StorageRefusalSnapshot().Refusals));
        Assert.Equal(clock.UtcNow.AddSeconds(-1), telemetry.StorageRefusalSnapshot().LastRefusalAt);
        Assert.Equal(0, telemetry.Snapshot().EventsIn);
    }

    [Fact]
    public async Task RetainedAcknowledgements_CannotRefuseIntakeOncePressureRetentionReclaimsThem()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("never-acknowledged"), Cancellation);
        QueuedEvent held = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromHours(10), Cancellation));
        await store.MarkDeadLetteredAsync(held.EventId, "bad", held.LeaseToken, Cancellation);
        await store.EnqueueAsync(Event("still-queued"), Cancellation);

        // Acknowledged rows inside the seven-day duplicate window fill the page ceiling
        // even though almost nothing is undelivered: the defect this guards against.
        int acknowledged = 0;
        QueueCapacityExceededException? full = null;
        while (full is null)
        {
            try
            {
                await store.EnqueueAsync(Event($"ack-{acknowledged}", 2_000), Cancellation);
            }
            catch (QueueCapacityExceededException exception)
            {
                full = exception;
                break;
            }

            QueuedEvent lease = (await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation))
                .Single(item => item.EventId.StartsWith("ack-", StringComparison.Ordinal));
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
            acknowledged++;
        }

        Assert.Equal(QueueCapacityReasons.Queue, full.Reason);
        Assert.True(acknowledged > 100);
        QueueSnapshot saturated = await store.GetSnapshotAsync(Cancellation);
        Assert.True(saturated.UndeliveredBytes < 1_000, "Undelivered bytes stay tiny while intake is refused.");
        Assert.True((await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent > QueueStorageMonitor.PagePressurePercent);

        // An hour later the acknowledgements are past the pressure floor but well inside
        // the configured seven-day retention.
        clock.Advance(TimeSpan.FromHours(2));
        QueueStoragePressure pressure = new();
        RecordingLogger<QueueRetentionJob> logger = new();
        QueueRetentionJob job = new(store, clock, Settings(), logger, null, pressure);
        await job.RunAsync(Cancellation);

        QueueStorageSnapshot reclaimed = await store.GetStorageSnapshotAsync(Cancellation);
        Assert.True(reclaimed.PageUtilisationPercent <= QueueRetentionJob.PressureTargetPercent + 5);
        Assert.True(pressure.PurgedEvents > 0);
        Assert.Equal(clock.UtcNow, pressure.LastPurgeAt);
        Assert.Contains(logger.Messages, message => message.Contains("early under storage pressure", StringComparison.Ordinal));
        QueueSnapshot after = await store.GetSnapshotAsync(Cancellation);
        Assert.Equal(1, after.DeadLettered);
        Assert.Equal(1, after.Queued + after.Uploading);
        Assert.True(after.Delivered > 0, "Purging stops at the target instead of emptying retention.");
        Assert.True((await store.EnqueueAsync(Event("accepted-again", 2_000), Cancellation)).Enqueued);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>
    /// Regression for a drain deadlock seen on AWS: intake filled every page, and leasing and
    /// acknowledging enlarge rows, so settlement failed with SQLITE_FULL forever. Intake now
    /// stops at the intake limit (pages in use) and settlement may grow the file further.
    /// </summary>
    [Fact]
    public async Task FullIntakeLimit_BacklogStillLeasesAcknowledgesAndDrains()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 8 * MiB, clock);
        await store.InitializeAsync(Cancellation);
        int accepted = 0;
        QueueCapacityExceededException? refused = null;
        while (refused is null)
        {
            try
            {
                await store.EnqueueAsync(Event($"backlog-{accepted}", 1_200), Cancellation);
                accepted++;
            }
            catch (QueueCapacityExceededException exception)
            {
                refused = exception;
            }
        }

        // The page limit, not the logical byte cap, refused the next event.
        QueueSnapshot backlog = await store.GetSnapshotAsync(Cancellation);
        Assert.Equal(QueueCapacityReasons.Queue, refused.Reason);
        Assert.True(backlog.UndeliveredBytes < 8 * MiB);
        QueueStorageSnapshot full = await store.GetStorageSnapshotAsync(Cancellation);
        Assert.True(full.PageUtilisationPercent >= 99);
        Assert.True(full.IntakeLimitPages < full.CeilingPages);

        int settled = 0;
        while (true)
        {
            IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(500, TimeSpan.FromMinutes(5), Cancellation);
            if (leased.Count == 0)
            {
                break;
            }

            // Half fail first (retry codes enlarge rows too) and are settled on a later pass.
            QueuedEvent[] retried = [.. leased.Where(item => item.DeliveryAttempts == 1).Take(leased.Count / 2)];
            Assert.Empty(await store.MarkFailedBatchAsync(
                [.. retried.Select(item => new FailureSettlement(item.EventId, "temporary-test", clock.UtcNow, item.LeaseToken))],
                Cancellation));
            QueuedEvent[] acknowledged = [.. leased.Except(retried)];
            Assert.Empty(await store.MarkDeliveredBatchAsync(
                [.. acknowledged.Select(item => item.EventId)], "azure-logs-ingestion:00000000-0000-0000-0000-000000000000",
                acknowledged.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation));
            settled += acknowledged.Length;
        }

        Assert.Equal(accepted, settled);
        QueueSnapshot drained = await store.GetSnapshotAsync(Cancellation);
        Assert.Equal((0, accepted), (drained.Queued + drained.Uploading + drained.Retrying, drained.Delivered));
        QueueStorageSnapshot grown = await store.GetStorageSnapshotAsync(Cancellation);
        Assert.True(grown.PageCount <= grown.CeilingPages);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);

        // Acknowledged rows go, freed pages are reused and intake resumes; a restart opens
        // the grown file.
        Assert.Equal(accepted, await store.PurgeDeliveredAsync(clock.UtcNow.AddSeconds(1), 100_000, Cancellation));
        SqliteConnection.ClearAllPools();
        SqliteEventStore restarted = new(path, 8 * MiB, clock);
        await restarted.InitializeAsync(Cancellation);
        Assert.True((await restarted.EnqueueAsync(Event("after-drain", 1_200), Cancellation)).Enqueued);
    }

    /// <summary>
    /// When an enqueue is actually refused, reclaim enough recent acknowledgements to
    /// admit it, retaining the others for duplicate detection.
    /// </summary>
    [Fact]
    public async Task RefusedPagePressureReclaim_AdmitsTheRefusedEventAndKeepsOtherAcknowledgements()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        string refusedId = "";
        for (int index = 0; ; index++)
        {
            try
            {
                await store.EnqueueAsync(Event($"small-{index}", 64), Cancellation);
            }
            catch (QueueCapacityExceededException)
            {
                refusedId = $"small-{index}";
                break;
            }

            if (index % 100 == 99)
            {
                IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(100, TimeSpan.FromMinutes(1), Cancellation);
                await store.MarkDeliveredBatchAsync([.. leased.Select(item => item.EventId)], "ack",
                    leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
            }
        }

        Assert.True((await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent >= DeliveryHealth.PageBackpressurePercent);
        Assert.True(store.RefusedIntakePages > 0);
        long retained = (await store.GetSnapshotAsync(Cancellation)).Delivered;
        QueueStoragePressure pressure = new();
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
            .RunAsync(Cancellation);
        Assert.True(pressure.PurgedEvents > 0);
        Assert.True((await store.GetSnapshotAsync(Cancellation)).Delivered > retained / 2);
        Assert.True((await store.EnqueueAsync(Event(refusedId, 64), Cancellation)).Enqueued);
    }

    [Fact]
    public async Task HealthBackpressureWithoutARefusal_KeepsThePressureRetentionFloor()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 4 * MiB, clock,
            new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        int index = 0;
        double utilisation;
        do
        {
            for (int added = 0; added < 10; added++)
            {
                await store.EnqueueAsync(Event($"health-threshold-{index++}", 64), Cancellation);
            }
            IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation);
            await store.MarkDeliveredBatchAsync([.. leased.Select(item => item.EventId)], "ack",
                leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
            utilisation = (await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent;
        }
        while (utilisation < DeliveryHealth.PageBackpressurePercent);

        Assert.True((await store.EnqueueAsync(Event("still-admitted", 64), Cancellation)).Enqueued);
        Assert.Equal(0, store.RefusedIntakePages);
        long retained = (await store.GetSnapshotAsync(Cancellation)).Delivered;
        QueueStoragePressure pressure = new();
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
            .RunAsync(Cancellation);
        Assert.Equal(0, pressure.PurgedEvents);
        Assert.Equal(retained, (await store.GetSnapshotAsync(Cancellation)).Delivered);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task CriticalDiskRefusal_CanReclaimRecentAcknowledgements()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        SqliteEventStore store = new(path, 10 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("recent-ack"), Cancellation);
        QueuedEvent leased = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        await store.MarkDeliveredAsync(leased.EventId, "ack", leased.LeaseToken, Cancellation);
        probe.FreeBytes = 100 * MiB;
        clock.Advance(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<QueueCapacityExceededException>(() => store.EnqueueAsync(Event("refused"), Cancellation));
        QueueStoragePressure pressure = new();
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
            .RunAsync(Cancellation);
        Assert.Equal(1, pressure.PurgedEvents);
        Assert.Equal(0, (await store.GetSnapshotAsync(Cancellation)).Delivered);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task PagePressureReclaim_AllowsAWriterBetweenBatchesWhileIntakeIsOpen()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 4 * MiB, clock,
            new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        int index = 0;
        double utilisation;
        do
        {
            for (int added = 0; added < 50; added++)
            {
                await store.EnqueueAsync(Event($"page-pressure-{index++}", 64), Cancellation);
            }

            IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(50, TimeSpan.FromMinutes(1), Cancellation);
            await store.MarkDeliveredBatchAsync([.. leased.Select(item => item.EventId)], "ack",
                leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
            utilisation = (await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent;
        }
        while (utilisation < 90);

        Assert.InRange(utilisation, QueueStorageMonitor.PagePressurePercent, DeliveryHealth.PageBackpressurePercent - 0.001);
        clock.Advance(TimeSpan.FromHours(2));
        QueueStoragePressure pressure = new();
        List<TimeSpan> pauses = [];
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
        {
            Pause = async (pause, cancellation) =>
            {
                pauses.Add(pause);
                if (pauses.Count == 1)
                {
                    EnqueueResult written = await store.EnqueueAsync(Event("writer-during-page-pressure"), cancellation)
                        .WaitAsync(TimeSpan.FromSeconds(3), cancellation);
                    Assert.True(written.Enqueued);
                }
            }
        }.RunAsync(Cancellation);

        Assert.True(pressure.PurgedEvents >= 500);
        Assert.NotEmpty(pauses);
        Assert.All(pauses, pause => Assert.Equal(QueueRetentionJob.BatchPause, pause));
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Queued);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task LowDiskReclaim_AllowsAWriterBetweenBatches()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        SqliteEventStore store = new(path, 64 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        for (int index = 0; index < 2_100; index++)
        {
            await store.EnqueueAsync(Event($"low-disk-{index}", 64), Cancellation);
        }

        while (await store.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation) is { Count: > 0 } leased)
        {
            await store.MarkDeliveredBatchAsync([.. leased.Select(item => item.EventId)], "ack",
                leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
        }

        clock.Advance(TimeSpan.FromHours(2));
        probe.FreeBytes = 1536 * MiB; // warning, but not critical: new intake is still allowed
        QueueStoragePressure pressure = new();
        List<TimeSpan> pauses = [];
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
        {
            Pause = async (pause, cancellation) =>
            {
                pauses.Add(pause);
                if (pauses.Count == 1)
                {
                    // An actual SQLite writer must complete while the purge is between
                    // transactions; fail rather than silently wait for the busy timeout.
                    EnqueueResult written = await store.EnqueueAsync(Event("writer-during-low-disk"), cancellation)
                        .WaitAsync(TimeSpan.FromSeconds(3), cancellation);
                    Assert.True(written.Enqueued);
                }
            }
        }.RunAsync(Cancellation);

        Assert.Equal(2_100, pressure.PurgedEvents);
        Assert.Equal([QueueRetentionJob.BatchPause, QueueRetentionJob.BatchPause], pauses);
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Queued);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task LargeEventPressureReclaim_YieldsBetweenBatches()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 4 * MiB, clock,
            new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("settle-during-large-event-reclaim"), Cancellation);
        QueuedEvent waiting = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        int index = 0;
        double utilisation;
        do
        {
            for (int added = 0; added < 50; added++)
            {
                await store.EnqueueAsync(Event($"large-pressure-{index++}", 2_000), Cancellation);
            }

            IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(50, TimeSpan.FromMinutes(1), Cancellation);
            await store.MarkDeliveredBatchAsync([.. leased.Select(item => item.EventId)], "ack",
                leased.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
            utilisation = (await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent;
        }
        while (utilisation < 75);

        Assert.True(utilisation < QueueStorageMonitor.PagePressurePercent);
        await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => store.EnqueueAsync(Event("large-pressure-candidate", 2_000_000), Cancellation));
        Assert.True(store.RefusedIntakePages > 0);
        List<TimeSpan> pauses = [];
        bool settled = false;
        QueueStoragePressure pressure = new();
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
        {
            Pause = async (pause, cancellation) =>
            {
                pauses.Add(pause);
                if (!settled)
                {
                    await store.MarkDeliveredAsync(waiting.EventId, "ack", waiting.LeaseToken, cancellation)
                        .WaitAsync(TimeSpan.FromSeconds(3), cancellation);
                    settled = true;
                }
            }
        }.RunAsync(Cancellation);

        Assert.True(pressure.PurgedEvents >= 50);
        Assert.NotEmpty(pauses);
        Assert.All(pauses, pause => Assert.Equal(QueueRetentionJob.BatchPause, pause));
        Assert.True(settled);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>
    /// Seen on AWS: after a backlog drained, every page held a fresh acknowledgement, so the
    /// floor kept them and intake stayed refused. Once intake is blocked the floor yields.
    /// </summary>
    [Fact]
    public async Task BlockedIntake_ReclaimsRecentAcknowledgementsDespiteTheFloor()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        for (int index = 0; ; index++)
        {
            try
            {
                await store.EnqueueAsync(Event($"ack-{index}", 2_000), Cancellation);
            }
            catch (QueueCapacityExceededException)
            {
                break;
            }

            QueuedEvent lease = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation));
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        }

        Assert.True((await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent >= DeliveryHealth.PageBackpressurePercent);
        QueueStoragePressure pressure = new();
        RecordingLogger<QueueRetentionJob> logger = new();
        await new QueueRetentionJob(store, clock, Settings(), logger, null, pressure).RunAsync(Cancellation);
        Assert.True(pressure.PurgedEvents > 0);
        Assert.Contains(logger.Messages, message => message.Contains("large-event", StringComparison.Ordinal));
        Assert.True((await store.GetSnapshotAsync(Cancellation)).Delivered > 0);
        Assert.True((await store.EnqueueAsync(Event("accepted-again", 2_000), Cancellation)).Enqueued);
    }

    /// <summary>
    /// A WAL a reader kept pinned refuses writes, acknowledgements included; once the reader
    /// is gone the next write resets the WAL itself instead of waiting for daily maintenance.
    /// </summary>
    [Fact]
    public async Task PinnedWal_SelfHealsOnTheNextWriteOnceTheReaderCloses()
    {
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(path, MiB, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("retained"), Cancellation);
        await using (SqliteConnection reader = new($"Data Source={path};Pooling=False"))
        {
            await reader.OpenAsync(Cancellation);
            using SqliteTransaction snapshot = reader.BeginTransaction(deferred: true);
            using SqliteCommand read = reader.CreateCommand();
            read.Transaction = snapshot;
            read.CommandText = "SELECT COUNT(*) FROM queue_events_v5;";
            await read.ExecuteScalarAsync(Cancellation);
            bool blocked = false;
            for (int index = 0; index < 2_000 && !blocked; index++)
            {
                try
                {
                    IReadOnlyList<QueuedEvent> leases = await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation);
                    if (leases.Count != 0)
                    {
                        await store.MarkRetryingAsync("retained", "temporary", clock.UtcNow, leases[0].LeaseToken, Cancellation);
                    }
                }
                catch (QueueCapacityExceededException)
                {
                    blocked = true;
                }
            }

            Assert.True(blocked);
        }

        // No MaintainAsync: once the rate limit allows, the write path truncates the WAL itself.
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True((await store.EnqueueAsync(Event("after-reader"), Cancellation)).Enqueued);
        Assert.True(new FileInfo(path + "-wal").Length < store.StorageReserveBytes);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>
    /// Workstream 6's reproduction (docs/evidence/ws6-20261031-074751, PR #164): 4 MiB cap,
    /// 1,300 acknowledged rows, then enqueue until refused. Before the fix the next lease
    /// failed with SQLITE_FULL and delivery never resumed. Now leasing and acknowledgement
    /// succeed, a crash in the middle of settlement recovers every event, and retention
    /// reopens intake without raising the cap.
    /// </summary>
    [Fact]
    public async Task Workstream6PageCeiling_DeliveryResumesSurvivesACrashAndIntakeReopens()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 4 * MiB, clock);
        await store.InitializeAsync(Cancellation);
        string payload = "{\"v\":\"" + new string('x', 1100) + "\"}";
        QueuedEvent Candidate(int index) => new($"e{index}", $"sha256:{index}", payload, clock.UtcNow);
        int index = 0;
        for (; index < 1300; index++)
        {
            await store.EnqueueAsync(Candidate(index), Cancellation);
        }

        await DrainAsync(store);
        int accepted = 0;
        for (; ; index++)
        {
            try
            {
                await store.EnqueueAsync(Candidate(index), Cancellation);
                accepted++;
            }
            catch (QueueCapacityExceededException exception)
            {
                Assert.Equal(QueueCapacityReasons.Queue, exception.Reason);
                break;
            }
        }

        Assert.True(accepted > 1_000);
        LedgerHead head = await store.GetLedgerHeadAsync(Cancellation);

        // Settle half, then crash with the rest leased.
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(10_000, TimeSpan.FromMinutes(1), Cancellation);
        Assert.Equal(accepted, leased.Count);
        QueuedEvent[] firstHalf = [.. leased.Take(accepted / 2)];
        Assert.Empty(await store.MarkDeliveredBatchAsync(
            [.. firstHalf.Select(item => item.EventId)], "ack", firstHalf.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation));
        SqliteConnection.ClearAllPools();

        SqliteEventStore restarted = new(path, 4 * MiB, clock);
        await restarted.InitializeAsync(Cancellation);
        Assert.Equal(head, await restarted.GetLedgerHeadAsync(Cancellation));
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(accepted - firstHalf.Length, await DrainAsync(restarted));
        QueueSnapshot drained = await restarted.GetSnapshotAsync(Cancellation);
        Assert.Equal((0L, 1300L + accepted), (drained.Queued + drained.Uploading + drained.Retrying, drained.Delivered));
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);

        // Intake is blocked by acknowledged rows only; retention reclaims them without a
        // cap change or restart, and freed pages are reused.
        await Assert.ThrowsAsync<QueueCapacityExceededException>(() => restarted.EnqueueAsync(Candidate(index), Cancellation));
        QueueStoragePressure pressure = new();
        await new QueueRetentionJob(restarted, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure).RunAsync(Cancellation);
        Assert.True(pressure.PurgedEvents > 0);
        long fileBefore = new FileInfo(path).Length;
        Assert.True((await restarted.EnqueueAsync(Candidate(index), Cancellation)).Enqueued);
        Assert.True(new FileInfo(path).Length <= fileBefore);

        async Task<int> DrainAsync(SqliteEventStore target)
        {
            int settled = 0;
            while (await target.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation) is { Count: > 0 } batch)
            {
                Assert.Empty(await target.MarkDeliveredBatchAsync(
                    [.. batch.Select(item => item.EventId)], "ack", batch.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation));
                settled += batch.Count;
            }

            return settled;
        }
    }

    [Fact]
    public async Task Retention_ReturnsFreedPagesToTheFileSystemUnderPressure()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 64 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        Assert.Equal(2, await ScalarAsync(path, "PRAGMA auto_vacuum;"));
        for (int index = 0; index < 3_000; index++)
        {
            await store.EnqueueAsync(Event($"r-{index}", 2_000), Cancellation);
        }

        while (await store.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation) is { Count: > 0 } batch)
        {
            await store.MarkDeliveredBatchAsync(
                [.. batch.Select(item => item.EventId)], "ack", batch.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
        }

        await store.MaintainAsync(Cancellation);
        long grown = new FileInfo(path).Length;
        clock.Advance(TimeSpan.FromHours(2));

        // Low disk: acknowledged rows past the floor go and their pages leave the file.
        probe.FreeBytes = 1536 * MiB;
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, new QueueStoragePressure())
            .RunAsync(Cancellation);
        long shrunk = new FileInfo(path).Length;
        Assert.True(shrunk < grown / 4, $"database {grown} -> {shrunk} bytes");
        // Only the small reserve kept for settlement remains free (no backlog).
        Assert.InRange((await store.GetStorageSnapshotAsync(Cancellation)).FreePages, 0, QueueRetentionJob.SettlementReservePages(0, 4_096));
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
        Assert.True((await store.EnqueueAsync(Event("after-release"), Cancellation)).Enqueued);
    }

    [Fact]
    public async Task ReleaseFreePages_ReportsReleasedPagesAndPreservesUnacknowledgedEventsAfterReopen()
    {
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 64 * MiB);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("unacknowledged"), Cancellation);

        // Create free pages without purging queue events.
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(Cancellation);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE vacuum_test (payload BLOB); INSERT INTO vacuum_test VALUES (zeroblob(1048576)); DROP TABLE vacuum_test;";
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        long before = (await store.GetStorageSnapshotAsync(Cancellation)).FreePages;
        Assert.True(before > 0);
        long released = await store.ReleaseFreePagesAsync(10, Cancellation);
        long after = (await store.GetStorageSnapshotAsync(Cancellation)).FreePages;
        Assert.InRange(released, 1, 10);
        Assert.Equal(before - after, released);

        SqliteConnection.ClearAllPools();
        SqliteEventStore reopened = new(path, 64 * MiB);
        await reopened.InitializeAsync(Cancellation);
        Assert.Equal(1, (await reopened.GetSnapshotAsync(Cancellation)).Queued);
        Assert.Single(await reopened.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
    }

    [Fact]
    public async Task ReleaseFreePages_IsANoOpForDatabasesCreatedWithoutIncrementalVacuum()
    {
        using SqliteTemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(Cancellation);
            await using SqliteCommand create = connection.CreateCommand();
            create.CommandText = "CREATE TABLE existing_before_bower(id INTEGER);";
            await create.ExecuteNonQueryAsync(Cancellation);
        }

        SqliteEventStore store = new(path, 10 * MiB);
        await store.InitializeAsync(Cancellation);
        Assert.Equal(0, await ScalarAsync(path, "PRAGMA auto_vacuum;"));
        await store.EnqueueAsync(Event("kept", 50_000), Cancellation);
        Assert.Equal(0, await store.ReleaseFreePagesAsync(1_000, Cancellation));
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Queued);
    }

    private static async Task<long> ScalarAsync(string path, string sql)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(Cancellation);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(Cancellation), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The collector's own health record uses the settlement reserve and is not refused by
    /// the critical watermark, so storage alerts see a full or critical queue (workstream 6's
    /// D4 drill: the queue-storage alert stayed silent because records were refused).
    /// </summary>
    [Fact]
    public async Task HealthRecord_IsQueuedWhenNewEventsAreRefusedByTheVolumeOrThePageLimit()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(MiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        QueueCapacityExceededException critical = await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => store.EnqueueAsync(Event("ordinary"), Cancellation));
        Assert.Equal(QueueCapacityReasons.StorageCritical, critical.Reason);
        Assert.True((await store.EnqueueAsync(Event("health-1") with { UsesStorageReserve = true }, Cancellation)).Enqueued);

        probe.FreeBytes = 10 * GiB;
        clock.Advance(TimeSpan.FromSeconds(1));
        int index = 0;
        while (true)
        {
            try
            {
                await store.EnqueueAsync(Event($"fill-{index++}", 2_000), Cancellation);
            }
            catch (QueueCapacityExceededException exception)
            {
                Assert.Equal(QueueCapacityReasons.Queue, exception.Reason);
                break;
            }
        }

        Assert.True((await store.EnqueueAsync(Event("health-2") with { UsesStorageReserve = true }, Cancellation)).Enqueued);
        // The record still leaves room to lease and acknowledge the whole backlog.
        while (await store.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation) is { Count: > 0 } batch)
        {
            Assert.Empty(await store.MarkDeliveredBatchAsync(
                [.. batch.Select(item => item.EventId)], "ack", batch.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation));
        }

        Assert.Equal(index + 1, (await store.GetSnapshotAsync(Cancellation)).Delivered);
    }

    [Fact]
    public async Task PressureRetention_KeepsAcknowledgementsInsideTheFloor()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        await DeliverAsync(store, "old");
        clock.Advance(TimeSpan.FromMinutes(90));
        await DeliverAsync(store, "recent");
        clock.Advance(TimeSpan.FromMinutes(10));

        // Low disk (warning) triggers the purge of every eligible acknowledgement, never the recent one.
        probe.FreeBytes = 1536 * MiB;
        QueueStoragePressure pressure = new();
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, pressure)
            .RunAsync(Cancellation);
        Assert.Equal(1, pressure.PurgedEvents);
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Delivered);
        Assert.True((await store.EnqueueAsync(Event("recent"), Cancellation)).Duplicate);
        Assert.True((await store.EnqueueAsync(Event("old"), Cancellation)).Enqueued);

        // No pressure: nothing inside the configured retention is touched.
        probe.FreeBytes = 10 * GiB;
        clock.Advance(TimeSpan.FromHours(3));
        QueueStoragePressure idle = new();
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, idle)
            .RunAsync(Cancellation);
        Assert.Equal(0, idle.PurgedEvents);
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Delivered);

        async Task DeliverAsync(SqliteEventStore target, string id)
        {
            await target.EnqueueAsync(Event(id), Cancellation);
            QueuedEvent lease = Assert.Single(await target.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
            await target.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        }
    }

    [Fact]
    public async Task Monitor_LogsTransitionsAndRefusalsBoundedAndTriggersRetention()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        PipelineTelemetry telemetry = new(clock);
        Bower.Jobs.RecurringJobRegistry jobs = new(clock);
        jobs.AddOrUpdate<QueueRetentionJob>(QueueRetentionJob.Id, (job, token) => job.RunAsync(token), Bower.Jobs.Cron.Hourly());
        RecordingLogger<QueueStorageMonitor> logger = new();
        QueueStorageMonitor monitor = new(store, telemetry, jobs, clock, logger);

        await monitor.SampleAsync(Cancellation);
        Assert.Empty(logger.Messages);

        probe.FreeBytes = 100 * MiB;
        for (int index = 0; index < 50; index++)
        {
            telemetry.RecordCapacityRefusal(10, PipelineTelemetry.StorageCriticalReason);
            await monitor.SampleAsync(Cancellation);
            clock.Advance(TimeSpan.FromSeconds(1));
        }

        // One transition and one refusal summary, not one line per refused event.
        Assert.Equal(2, logger.Messages.Count);
        Assert.Contains("critical free-space watermark", logger.Messages[0], StringComparison.Ordinal);
        Assert.Contains("Queue refused 1 event(s)", logger.Messages[1], StringComparison.Ordinal);

        clock.Advance(QueueStorageMonitor.RepeatInterval);
        await monitor.SampleAsync(Cancellation);
        Assert.Contains("Queue refused 49 event(s)", logger.Messages[2], StringComparison.Ordinal);

        probe.FreeBytes = 10 * GiB;
        await monitor.SampleAsync(Cancellation);
        Assert.Contains("recovered", logger.Messages[^1], StringComparison.Ordinal);
        foreach (string message in logger.Messages)
        {
            Assert.DoesNotContain(directory.Path, message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void DeliveryHealth_ReportsBackpressureWhileTheVolumeIsCritical()
    {
        QueueSnapshot idle = new(0, 0, 0, 0, 0, 0, null, 0);
        Assert.Equal("waiting", DeliveryHealth.Evaluate("azure-logs-ingestion", idle, 10 * MiB, TestEvents.Now));
        Assert.Equal("backpressure", DeliveryHealth.Evaluate("azure-logs-ingestion", idle, 10 * MiB, TestEvents.Now, intakePaused: true));
        Assert.Equal("disabled", DeliveryHealth.Evaluate("none", idle, 10 * MiB, TestEvents.Now, intakePaused: true));
    }

    /// <summary>
    /// A refusal at the intake page limit commits nothing, and a restarted store recovers
    /// every committed event. A real ENOSPC (SQLITE_FULL from a full volume, reported as
    /// <c>storage-full</c>) is exercised on full xfs and NTFS volumes in the AWS
    /// storage-pressure lab (docs/production-readiness/03-storage-pressure.md).
    /// </summary>
    [Fact]
    public async Task PageLimitRefusal_CommitsNothingAndRecoversAfterRestart()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("committed"), Cancellation);
        IReadOnlyList<QueuedEvent> held = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation);
        // Acknowledged rows occupy most pages while undelivered bytes stay tiny.
        for (int index = 0; (await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent < 90; index++)
        {
            await store.EnqueueAsync(Event($"ack-{index}", 4_000), Cancellation);
            QueuedEvent lease = (await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation))
                .Single(item => item.EventId.StartsWith("ack-", StringComparison.Ordinal));
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        }

        LedgerHead before = await store.GetLedgerHeadAsync(Cancellation);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(Cancellation);
        QueueCapacityExceededException refused = await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => store.EnqueueAsync(Event("too-large", 600_000), Cancellation));
        Assert.Equal(QueueCapacityReasons.Queue, refused.Reason);
        Assert.Equal(before, await store.GetLedgerHeadAsync(Cancellation));

        // Crash: drop every handle and open the files again.
        SqliteConnection.ClearAllPools();
        SqliteEventStore restarted = new(path, MiB, clock, new StorageGuard(path, new(), probe, clock));
        await restarted.InitializeAsync(Cancellation);
        Assert.Equal(before, await restarted.GetLedgerHeadAsync(Cancellation));
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
        Assert.Equal(snapshot, await restarted.GetSnapshotAsync(Cancellation));
        Assert.Empty(await restarted.MarkDeliveredBatchAsync(
            ["committed"], "ack", held.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation));
        Assert.Equal(snapshot.Delivered + 1, await restarted.PurgeDeliveredAsync(clock.UtcNow.AddSeconds(1), 100_000, Cancellation));
        Assert.True((await restarted.EnqueueAsync(Event("too-large", 600_000), Cancellation)).Enqueued);
        Assert.True((await restarted.EnqueueAsync(Event("committed"), Cancellation)).Enqueued);
        await using SqliteConnection check = new($"Data Source={path};Pooling=False");
        await check.OpenAsync(Cancellation);
        await using SqliteCommand integrity = check.CreateCommand();
        integrity.CommandText = "PRAGMA integrity_check;";
        Assert.Equal("ok", await integrity.ExecuteScalarAsync(Cancellation));
    }

    [Fact]
    public async Task RestartWhileCritical_StartsAndDrainsButRefusesNewEventsUntilSpaceReturns()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("before-restart"), Cancellation);
        SqliteConnection.ClearAllPools();

        FakeDiskSpaceProbe probe = new(MiB, 20 * GiB);
        SqliteEventStore restarted = new(path, 10 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await restarted.InitializeAsync(Cancellation);
        QueueCapacityExceededException refused = await Assert.ThrowsAsync<QueueCapacityExceededException>(
            () => restarted.EnqueueAsync(Event("during-critical"), Cancellation));
        Assert.Equal(QueueCapacityReasons.StorageCritical, refused.Reason);
        QueuedEvent lease = Assert.Single(await restarted.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation));
        await restarted.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        Assert.Equal(1, (await restarted.GetSnapshotAsync(Cancellation)).Delivered);

        probe.FreeBytes = 10 * GiB;
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True((await restarted.EnqueueAsync(Event("during-critical"), Cancellation)).Enqueued);
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>
    /// A large event needs more pages than the gap below the intake limit, so it is refused
    /// below the pressure trigger. The refusal itself triggers retention, which reclaims
    /// acknowledged rows until it fits; otherwise the source would retry it forever.
    /// </summary>
    [Fact]
    public async Task LargeEventRefusedBelowThePressureTrigger_ReclaimsAcknowledgementsAndIsAccepted()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("pending"), Cancellation);
        for (int index = 0; (await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent < 75; index++)
        {
            await store.EnqueueAsync(Event($"ack-{index}", 4_000), Cancellation);
            QueuedEvent lease = (await store.LeaseAsync(100, TimeSpan.FromMinutes(1), Cancellation))
                .Single(item => item.EventId == $"ack-{index}");
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        }

        Assert.True((await store.GetStorageSnapshotAsync(Cancellation)).PageUtilisationPercent < QueueStorageMonitor.PagePressurePercent);
        QueuedEvent candidate = Event("large", 1_000_000);
        await Assert.ThrowsAsync<QueueCapacityExceededException>(() => store.EnqueueAsync(candidate, Cancellation));
        Assert.True(store.RefusedIntakePages > 0);

        // The monitor triggers retention for the refusal alone.
        Bower.Jobs.RecurringJobRegistry jobs = new(clock);
        jobs.AddOrUpdate<QueueRetentionJob>(QueueRetentionJob.Id, (job, token) => job.RunAsync(token), Bower.Jobs.Cron.Hourly());
        Assert.Empty(jobs.ClaimDue(clock.UtcNow));
        await new QueueStorageMonitor(store, new PipelineTelemetry(clock), jobs, clock, new RecordingLogger<QueueStorageMonitor>())
            .SampleAsync(Cancellation);
        Assert.Equal(QueueRetentionJob.Id, Assert.Single(jobs.ClaimDue(clock.UtcNow)).Id);

        long acknowledged = (await store.GetSnapshotAsync(Cancellation)).Delivered;
        QueueStoragePressure pressure = new();
        RecordingLogger<QueueRetentionJob> logger = new();
        await new QueueRetentionJob(store, clock, Settings(), logger, null, pressure).RunAsync(Cancellation);
        Assert.True(pressure.PurgedEvents > 0);
        Assert.Contains(logger.Messages, message => message.Contains("large-event", StringComparison.Ordinal));
        Assert.Equal(0, store.RefusedIntakePages);
        Assert.True((await store.EnqueueAsync(candidate, Cancellation)).Enqueued);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(Cancellation);
        Assert.Equal(2, snapshot.Queued + snapshot.Uploading);
        // Only about the pages the event needed: most recent acknowledgements keep detecting duplicates.
        Assert.True(snapshot.Delivered > acknowledged / 2, $"{snapshot.Delivered} of {acknowledged} kept");
        Assert.True((await store.EnqueueAsync(Event($"ack-{acknowledged - 1}", 4_000), Cancellation)).Duplicate);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>
    /// Under disk pressure free pages go back to the file system even while a backlog waits
    /// for the destination; only a reserve for those rows to settle stays (council round 1:
    /// a stuck backlog of 5 kept every free page and the volume stayed critical).
    /// </summary>
    [Fact]
    public async Task Retention_ReleasesFreePagesOnALowDiskDespiteASmallStuckBacklog()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        FakeDiskSpaceProbe probe = new(10 * GiB, 20 * GiB);
        SqliteEventStore store = new(path, 64 * MiB, clock, new StorageGuard(path, new(), probe, clock));
        await store.InitializeAsync(Cancellation);
        for (int index = 0; index < 3_000; index++)
        {
            await store.EnqueueAsync(Event($"delivered-{index}", 2_000), Cancellation);
        }

        while (await store.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation) is { Count: > 0 } batch)
        {
            await store.MarkDeliveredBatchAsync(
                [.. batch.Select(item => item.EventId)], "ack", batch.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
        }

        // The destination is now down: five events wait, never acknowledged.
        for (int index = 0; index < 5; index++)
        {
            await store.EnqueueAsync(Event($"stuck-{index}", 2_000), Cancellation);
        }

        await store.MaintainAsync(Cancellation);
        long grown = new FileInfo(path).Length;
        clock.Advance(TimeSpan.FromHours(2));
        probe.FreeBytes = 100 * MiB;
        await new QueueRetentionJob(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, new QueueStoragePressure())
            .RunAsync(Cancellation);

        QueueStorageSnapshot after = await store.GetStorageSnapshotAsync(Cancellation);
        long shrunk = new FileInfo(path).Length;
        Assert.True(shrunk < grown / 4, $"database {grown} -> {shrunk} bytes");
        long reserve = QueueRetentionJob.SettlementReservePages((await store.GetSnapshotAsync(Cancellation)).UndeliveredBytes, after.PageSize);
        Assert.InRange(after.FreePages, 1, reserve);
        Assert.Equal(5, (await store.GetSnapshotAsync(Cancellation)).Queued);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>
    /// A large backlog keeps a free-page reserve sized for its rows to settle, so its
    /// acknowledgements reuse pages instead of regrowing the file; the rest is released.
    /// Once drained, the reserve goes too.
    /// </summary>
    [Fact]
    public async Task Retention_KeepsAReserveSizedForTheBacklogAndReleasesTheRest()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 64 * MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(1536 * MiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        for (int index = 0; index < 500; index++)
        {
            await store.EnqueueAsync(Event($"backlog-{index}", 2_000), Cancellation);
        }

        await CreateFreePagesAsync(path, 8 * MiB);
        QueueStorageSnapshot before = await store.GetStorageSnapshotAsync(Cancellation);
        long reserve = QueueRetentionJob.SettlementReservePages((await store.GetSnapshotAsync(Cancellation)).UndeliveredBytes, before.PageSize);
        Assert.True(before.FreePages > reserve);
        QueueRetentionJob retention = new(store, clock, Settings(), new RecordingLogger<QueueRetentionJob>(), null, new QueueStoragePressure());
        await retention.RunAsync(Cancellation);
        Assert.Equal(reserve, (await store.GetStorageSnapshotAsync(Cancellation)).FreePages);

        while (await store.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation) is { Count: > 0 } batch)
        {
            await store.MarkDeliveredBatchAsync(
                [.. batch.Select(item => item.EventId)], "ack", batch.ToDictionary(item => item.EventId, item => item.LeaseToken!), Cancellation);
        }

        clock.Advance(TimeSpan.FromHours(2));
        await retention.RunAsync(Cancellation);
        Assert.InRange((await store.GetStorageSnapshotAsync(Cancellation)).FreePages, 0, QueueRetentionJob.SettlementReservePages(0, before.PageSize));
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    /// <summary>Unverified archive coverage purges nothing, but pages already free still go back.</summary>
    [Fact]
    public async Task Retention_ReleasesFreePagesWhenArchiveCoverageIsRefused()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 64 * MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(1536 * MiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("delivered"), Cancellation);
        QueuedEvent lease = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        await CreateFreePagesAsync(path, 4 * MiB);
        string archivePath = Path.Combine(directory.Path, "archive");
        Directory.CreateDirectory(archivePath);
        clock.Advance(TimeSpan.FromDays(10));
        RecordingLogger<QueueRetentionJob> logger = new();

        await new QueueRetentionJob(store, clock, Settings(), logger, new QueueArchive(archivePath, "collector-1", clock), new QueueStoragePressure())
            .RunAsync(Cancellation);

        Assert.Contains(logger.Messages, message => message.Contains("archive coverage is not verified", StringComparison.Ordinal));
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Delivered);
        // Only the small reserve kept for settlement remains free (no backlog).
        Assert.InRange((await store.GetStorageSnapshotAsync(Cancellation)).FreePages, 0, QueueRetentionJob.SettlementReservePages(0, 4_096));
    }

    /// <summary>Status, heartbeats and health records omit storage instead of failing when the queue cannot be read.</summary>
    [Fact]
    public async Task StorageCapture_IsOmittedWhenTheQueueCannotBeRead()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string queueDirectory = Path.Combine(directory.Path, "state");
        Directory.CreateDirectory(queueDirectory);
        string path = Path.Combine(queueDirectory, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock, new StorageGuard(path, new(), new FakeDiskSpaceProbe(10 * GiB, 20 * GiB), clock));
        await store.InitializeAsync(Cancellation);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(Cancellation);
        QueuePageUsage? pages = await QueueStorageStatus.TryReadPagesAsync(store, Cancellation);
        Assert.NotNull(pages);
        Assert.NotNull(await QueueStorageStatus.TryCaptureAsync(store, snapshot, null, null, clock.UtcNow, pages, Cancellation));

        SqliteConnection.ClearAllPools();
        Directory.Delete(queueDirectory, recursive: true);

        Assert.Null(await QueueStorageStatus.TryReadPagesAsync(store, Cancellation));
        Assert.Null(await QueueStorageStatus.TryCaptureAsync(store, snapshot, null, null, clock.UtcNow, null, Cancellation));
    }

    /// <summary>
    /// Builds before the settlement ceiling cap the file at M + 4 MiB and refuse to open a
    /// larger one. The documented rollback recovery: drain, purge acknowledged rows and
    /// <c>VACUUM</c> with the collector stopped, until the file is below that ceiling.
    /// </summary>
    [Fact]
    public async Task Rollback_GrownQueueOpensInAnOlderBuildAfterDrainPurgeAndVacuum()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, MiB, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("undelivered", 2_000), Cancellation);
        for (int index = 0; index < 200; index++)
        {
            await store.EnqueueAsync(Event($"acknowledged-{index}", 4_000), Cancellation);
        }

        IReadOnlyList<QueuedEvent> leases = await store.LeaseAsync(500, TimeSpan.FromMinutes(1), Cancellation);
        foreach (QueuedEvent lease in leases.Where(item => item.EventId != "undelivered"))
        {
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        }

        // Settlement growth past the old ceiling (M + 4 MiB = 5 MiB here), below the new one.
        await CreateFreePagesAsync(path, 6 * MiB);
        SqliteConnection.ClearAllPools();
        Assert.False(await OlderBuildOpensAsync(path, MiB));

        // Drain, purge acknowledged rows, then VACUUM with the collector stopped.
        QueuedEvent pending = leases.Single(item => item.EventId == "undelivered");
        await store.MarkDeliveredAsync(pending.EventId, "ack", pending.LeaseToken, Cancellation);
        await store.PurgeDeliveredAsync(clock.UtcNow.AddSeconds(1), 10_000, Cancellation);
        await store.EnqueueAsync(Event("kept"), Cancellation);
        SqliteConnection.ClearAllPools();
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(Cancellation);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);";
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        Assert.True(await OlderBuildOpensAsync(path, MiB));
        SqliteEventStore reopened = new(path, MiB, clock);
        await reopened.InitializeAsync(Cancellation);
        Assert.Equal(1, (await reopened.GetSnapshotAsync(Cancellation)).Queued);
        Assert.True((await reopened.VerifyLedgerAsync(Cancellation)).Intact);
    }

    // The open check of builds before the settlement ceiling: max_page_count = (M + 4 MiB) / page size.
    private static async Task<bool> OlderBuildOpensAsync(string path, long maximumBytes)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(Cancellation);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA page_size;";
        long pageSize = Convert.ToInt64(await command.ExecuteScalarAsync(Cancellation), System.Globalization.CultureInfo.InvariantCulture);
        long requested = (maximumBytes * 4 + 16 * MiB) / 4 / pageSize;
        command.CommandText = $"PRAGMA max_page_count = {requested};";
        return Convert.ToInt64(await command.ExecuteScalarAsync(Cancellation), System.Globalization.CultureInfo.InvariantCulture) <= requested;
    }

    private static async Task CreateFreePagesAsync(string path, long bytes)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(Cancellation);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"CREATE TABLE free_pages (payload BLOB); INSERT INTO free_pages VALUES (zeroblob({bytes})); DROP TABLE free_pages;";
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    [Fact]
    public async Task VerifiedPurgeCannotDeleteAShiftedBatchAfterConcurrentPurge()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * MiB, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("first"), Cancellation);
        await store.EnqueueAsync(Event("second"), Cancellation);
        foreach (QueuedEvent lease in await store.LeaseAsync(2, TimeSpan.FromMinutes(1), Cancellation))
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        DateTimeOffset cutoff = clock.UtcNow.AddSeconds(1);
        long selected = Assert.Single(await store.ReadPurgeCandidateSequencesAsync(cutoff, 1, long.MaxValue, Cancellation));
        Assert.Equal(1, await store.PurgeDeliveredAsync(cutoff, 1, long.MaxValue, Cancellation));
        long next = Assert.Single(await store.ReadPurgeCandidateSequencesAsync(cutoff, 1, long.MaxValue, Cancellation));
        Assert.NotEqual(selected, next);
        Assert.Equal(0, await store.PurgeVerifiedDeliveredAsync(cutoff, [selected], Cancellation));
        Assert.Equal(next, Assert.Single(await store.ReadPurgeCandidateSequencesAsync(cutoff, 1, long.MaxValue, Cancellation)));
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task VerifiedPurgeRechecksAcknowledgementAndRetentionCutoff()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * MiB, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("old"), Cancellation);
        QueuedEvent old = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        await store.MarkDeliveredAsync(old.EventId, "ack", old.LeaseToken, Cancellation);
        clock.Advance(TimeSpan.FromHours(2));
        DateTimeOffset cutoff = clock.UtcNow.AddHours(-1);
        await store.EnqueueAsync(Event("recent"), Cancellation);
        QueuedEvent recent = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        await store.MarkDeliveredAsync(recent.EventId, "ack", recent.LeaseToken, Cancellation);
        await store.EnqueueAsync(Event("pending"), Cancellation);
        Assert.Equal(1, await store.PurgeVerifiedDeliveredAsync(cutoff, [1, 2, 3], Cancellation));
        QueueSnapshot remaining = await store.GetSnapshotAsync(Cancellation);
        Assert.Equal(1, remaining.Delivered);
        Assert.Equal(1, remaining.Queued);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task CancelledVerifiedPurgeKeepsAcknowledgementAcrossRestart()
    {
        using SqliteTemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * MiB, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event("delivered"), Cancellation);
        QueuedEvent lease = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.PurgeVerifiedDeliveredAsync(clock.UtcNow.AddSeconds(1), [1], cancelled.Token));
        SqliteConnection.ClearAllPools();
        SqliteEventStore restarted = new(path, 10 * MiB, clock);
        await restarted.InitializeAsync(Cancellation);
        Assert.Equal(1, (await restarted.GetSnapshotAsync(Cancellation)).Delivered);
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
    }

    private static CollectorSettings Settings() => new()
    {
        ListenUrl = "http://127.0.0.1:4319",
        QueuePath = "queue.db",
        PolicyDirectory = "policies",
        CollectorId = "collector-1"
    };

    private static QueuedEvent Event(string id, int payloadBytes = 16) =>
        new(id, $"sha256:{id}", $$"""{"eventId":"{{id}}","pad":"{{new string('p', payloadBytes)}}"}""", TestEvents.Now);

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                Messages.Add(formatter(state, exception));
            }
        }
    }
}
