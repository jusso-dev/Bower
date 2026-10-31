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
        // Intake keeps its Rust-shared shape and reason codes; storage detail is separate.
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
