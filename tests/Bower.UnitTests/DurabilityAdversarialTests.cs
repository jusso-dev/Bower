using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class DurabilityAdversarialTests
{
    /// <summary>SQLite WAL format: every frame is this header followed by one page.</summary>
    private const int WalFrameHeaderBytes = 24;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public void Identity_DistinguishesSameTimestampAttemptsAndSourceNamespaces()
    {
        SecurityEventEnvelope first = TestEvents.AuthenticationFailure(TestEvents.Now) with { EventOriginalId = null };
        Assert.NotEqual(EventFingerprint.Create(first), EventFingerprint.Create(first with { EventId = "other" }));
        var original = first with { EventOriginalId = "source-row-1" };
        Assert.Equal(EventFingerprint.Create(original), EventFingerprint.Create(original with { EventId = "reconstructed" }));
        Assert.NotEqual(EventFingerprint.Create(original), EventFingerprint.Create(original with
        {
            Application = original.Application with { Instance = "other-source" }
        }));
        Assert.NotEqual(EventFingerprint.Create(original with { Application = original.Application with { Name = "a\u001fb", Environment = "c" } }),
            EventFingerprint.Create(original with { Application = original.Application with { Name = "a", Environment = "b\u001fc" } }));
    }

    [Fact]
    public async Task Replay_IgnoresReceiptDecorationButRejectsChangedSourceContentAfterRestart()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 1_048_576);
        await store.InitializeAsync(Cancellation);
        var envelope = TestEvents.AuthenticationFailure(TestEvents.Now);
        string payload = JsonSerializer.Serialize(envelope, BowerJson.Envelope);
        QueuedEvent item = new(envelope.EventId, EventFingerprint.Create(envelope), payload, TestEvents.Now);
        await store.EnqueueAsync(item, Cancellation);
        SqliteEventStore restarted = new(path, 1_048_576);
        await restarted.InitializeAsync(Cancellation);
        Assert.True((await restarted.EnqueueAsync(item with
        {
            Payload = JsonSerializer.Serialize(envelope with { TimeObserved = TestEvents.Now.AddMinutes(1) }, BowerJson.Envelope)
        }, Cancellation)).Duplicate);
        await Assert.ThrowsAsync<EventIdentityConflictException>(() => restarted.EnqueueAsync(item with
        {
            Payload = JsonSerializer.Serialize(envelope with { EventOutcomeReason = "different-fact" }, BowerJson.Envelope)
        }, Cancellation));
        await Assert.ThrowsAsync<EventIdentityConflictException>(() => restarted.EnqueueAsync(item with
        {
            Payload = payload[..^1] + ",\"futureField\":true}"
        }, Cancellation));
        await Assert.ThrowsAsync<EventIdentityConflictException>(() => restarted.EnqueueAsync(item with
        {
            Fingerprint = "sha256:v2:different-source"
        }, Cancellation));
        Assert.Equal(payload, Assert.Single(await restarted.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation)).Payload);
    }

    [Fact]
    public async Task Replay_IgnoresLocalDetectionChangesButPreservesSourceAttributes()
    {
        using TemporaryDirectory directory = new();
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576);
        await store.InitializeAsync(Cancellation);
        const string plain = """{"schemaVersion":"1.0.0","eventType":"test","attributes":{"sourceFact":1}}""";
        QueuedEvent first = new("detection", "fp", plain, TestEvents.Now);
        await store.EnqueueAsync(first, Cancellation);
        foreach (string version in new[] { "1", "2" })
        {
            string enriched = plain.Replace("\"sourceFact\":1", "\"sourceFact\":1,\"bowerDetections\":[{\"ruleVersion\":\"" + version + "\"}]", StringComparison.Ordinal);
            Assert.True((await store.EnqueueAsync(first with { Payload = enriched }, Cancellation)).Duplicate);
        }
        await Assert.ThrowsAsync<EventIdentityConflictException>(() => store.EnqueueAsync(first with
        {
            Payload = plain.Replace("sourceFact\":1", "sourceFact\":2", StringComparison.Ordinal)
        }, Cancellation));
        const string empty = """{"schemaVersion":"1.0.0","eventType":"test"}""";
        QueuedEvent onlyEvidence = new("only-evidence", "fp-two", empty, TestEvents.Now);
        await store.EnqueueAsync(onlyEvidence, Cancellation);
        string withEvidence = empty[..^1] + """, "attributes":{"bowerDetections":[]}}""";
        Assert.True((await store.EnqueueAsync(onlyEvidence with { Payload = withEvidence }, Cancellation)).Duplicate);
        Assert.Equal(plain, (await store.LeaseAsync(2, TimeSpan.FromMinutes(1), Cancellation)).Single(row => row.EventId == first.EventId).Payload);
    }

    [Fact]
    public async Task StaleClaims_CannotSettleNewLeaseOrNewIncarnation()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(Cancellation);
        QueuedEvent item = new("one", "fp", "{}", clock.UtcNow);
        await store.EnqueueAsync(item, Cancellation);
        QueuedEvent old = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromSeconds(1), Cancellation));
        clock.Advance(TimeSpan.FromSeconds(2));
        QueuedEvent current = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        Assert.NotEqual(old.LeaseToken, current.LeaseToken);
        await Assert.ThrowsAsync<InvalidQueueTransitionException>(() => store.MarkDeliveredAsync("one", "stale", old.LeaseToken, Cancellation));
        await Assert.ThrowsAsync<InvalidQueueTransitionException>(() => store.MarkRetryingAsync("one", "stale", clock.UtcNow, old.LeaseToken, Cancellation));
        await Assert.ThrowsAsync<InvalidQueueTransitionException>(() => store.MarkDeadLetteredAsync("one", "stale", old.LeaseToken, Cancellation));
        Assert.Equal(["one"], await store.MarkDeliveredBatchAsync(["one"], "stale", LeaseTestClaims.Map([old]), Cancellation));
        Assert.Equal(["one"], await store.MarkFailedBatchAsync([new("one", "stale", null, old.LeaseToken)], Cancellation));
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Uploading);
        await store.MarkDeliveredAsync("one", "ack", current.LeaseToken, Cancellation);
        await store.PurgeDeliveredAsync(clock.UtcNow.AddSeconds(1), 1, Cancellation);
        await store.EnqueueAsync(item, Cancellation);
        QueuedEvent incarnation = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        Assert.NotEqual(old.LeaseToken, incarnation.LeaseToken);
        await Assert.ThrowsAsync<InvalidQueueTransitionException>(() => store.MarkDeadLetteredAsync("one", "stale", old.LeaseToken, Cancellation));
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task UnresolvedEvent_DoesNotPinHistoryOrConfuseReplayAcrossRestart()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(path, 1_048_576, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(new("unresolved", "unresolved", "{}", clock.UtcNow), Cancellation);
        QueuedEvent unresolved = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
        await store.MarkDeadLetteredAsync(unresolved.EventId, "test", unresolved.LeaseToken, Cancellation);
        string payload = new('x', 8_192);
        for (int index = 0; index < 300; index++)
        {
            await store.EnqueueAsync(new("replayed", "replayed", payload, clock.UtcNow), Cancellation);
            QueuedEvent lease = Assert.Single(await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation));
            await store.MarkDeliveredAsync(lease.EventId, "ack", lease.LeaseToken, Cancellation);
            await store.PurgeDeliveredAsync(clock.UtcNow.AddSeconds(1), 10, Cancellation);
        }
        await store.EnqueueAsync(new("replayed", "replayed", payload, clock.UtcNow), Cancellation);
        SqliteEventStore restarted = new(path, 1_048_576, clock);
        await restarted.InitializeAsync(Cancellation);
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
        Assert.Equal(1, (await restarted.GetSnapshotAsync(Cancellation)).DeadLettered);
        Assert.Equal(1, await ScalarAsync(path, "SELECT COUNT(*) FROM queue_ledger_segments;"));
        Assert.Equal(2, await ScalarAsync(path, "SELECT COUNT(*) FROM queue_ledger;"));
        Assert.True(StorageBytes(path) < store.MaximumStorageBytes);
        await ExecuteAsync(path, "INSERT INTO queue_events_v5(event_id,fingerprint,payload,payload_bytes,received_at,state,enqueue_sequence) SELECT 'injected','injected','{}',2,received_at,0,(SELECT MIN(start_sequence) FROM queue_ledger_segments) FROM queue_events_v5 WHERE event_id='replayed';");
        Assert.False((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
        await ExecuteAsync(path, "DELETE FROM queue_events_v5 WHERE event_id='injected';");
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
        await ExecuteAsync(path, "UPDATE queue_ledger_segments SET checkpoint_hash = 'corrupt';");
        Assert.False((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
        await Assert.ThrowsAsync<InvalidOperationException>(() => restarted.PurgeDeliveredAsync(clock.UtcNow.AddDays(1), 10, Cancellation));
    }

    [Fact]
    public async Task PinnedWalReader_TriggersBoundedBackpressureAndResumesWithoutLoss()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 1_048_576);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(new("retained", "retained", "{}", TestEvents.Now), Cancellation);
        await using SqliteConnection readerConnection = new($"Data Source={path};Pooling=False");
        await readerConnection.OpenAsync(Cancellation);
        using SqliteTransaction snapshot = readerConnection.BeginTransaction(deferred: true);
        using SqliteCommand read = readerConnection.CreateCommand();
        read.Transaction = snapshot;
        read.CommandText = "SELECT COUNT(*) FROM queue_events_v5;";
        await read.ExecuteScalarAsync(Cancellation);
        bool blocked = false;
        for (int index = 0; index < 2_000; index++)
        {
            try
            {
                // Repeated state changes grow WAL even with constant live payload volume.
                var leases = await store.LeaseAsync(1, TimeSpan.FromMinutes(1), Cancellation);
                if (leases.Count != 0)
                {
                    await store.MarkRetryingAsync("retained", "temporary", TestEvents.Now, leases[0].LeaseToken, Cancellation);
                }
            }
            catch (QueueCapacityExceededException)
            {
                blocked = true;
                break;
            }
        }
        Assert.True(blocked);
        Assert.True(StorageBytes(path) <= store.MaximumStorageBytes);
        snapshot.Dispose();
        await store.MaintainAsync(Cancellation);
        Assert.True(StorageBytes(path) <= store.MaximumStorageBytes);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
        Assert.Equal(1, (await store.GetSnapshotAsync(Cancellation)).Retrying + (await store.GetSnapshotAsync(Cancellation)).Uploading);
        Assert.True((await store.EnqueueAsync(new("recovered", "recovered", "{}", TestEvents.Now), Cancellation)).Enqueued);
    }

    [Fact]
    public async Task PinnedWalReader_BackpressuresSuppressionCountersWithinPhysicalBound()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(path, 1_048_576, clock);
        await store.InitializeAsync(Cancellation);
        SuppressionRequest rule = new(
            "BWR-POL-X", "1.0.0", "sha256:p", "abc", ["source.ipAddress"], ["192.0.2.1"], 60, 1,
            "authentication", "authentication_failure", "App", "prod", null);
        QueuedEvent Suppressible(string id) =>
            new(id, $"sha256:{id}", $$"""{"eventId":"{{id}}"}""", clock.UtcNow, Suppression: rule);
        Assert.True((await store.EnqueueAsync(Suppressible("admitted"), Cancellation)).Enqueued);
        await using SqliteConnection readerConnection = new($"Data Source={path};Pooling=False");
        await readerConnection.OpenAsync(Cancellation);
        using SqliteTransaction snapshot = readerConnection.BeginTransaction(deferred: true);
        using SqliteCommand read = readerConnection.CreateCommand();
        read.Transaction = snapshot;
        read.CommandText = "SELECT COUNT(*) FROM queue_events_v5;";
        await read.ExecuteScalarAsync(Cancellation);

        // Allowance is spent: every unique event only updates the window counters, and
        // each commit grows the WAL the pinned reader keeps from being reset.
        long counted = 0;
        bool blocked = false;
        for (int index = 0; index < 6_000; index++)
        {
            try
            {
                Assert.True((await store.EnqueueAsync(Suppressible($"unique-{index}"), Cancellation)).Suppressed);
                counted++;
            }
            catch (QueueCapacityExceededException)
            {
                blocked = true;
                break;
            }
        }

        Assert.True(blocked);
        Assert.True(counted > 0);
        // Refusal starts at the ceiling minus the reserve; the last admitted commit can
        // add one WAL frame for the counter page it changed.
        long pageSize = await ScalarAsync(path, "PRAGMA page_size;");
        long admissionBound = store.MaximumStorageBytes - store.StorageReserveBytes + WalFrameHeaderBytes + pageSize;
        Assert.True(StorageBytes(path) <= admissionBound);
        long storage = StorageBytes(path);
        for (int index = 0; index < 3; index++)
        {
            await Assert.ThrowsAsync<QueueCapacityExceededException>(
                () => store.EnqueueAsync(Suppressible($"refused-{index}"), Cancellation));
        }

        // Refusals leave the counters and the files untouched; exact replay still wins.
        Assert.Equal(storage, StorageBytes(path));
        Assert.Equal(counted, await ScalarAsync(path, "SELECT suppressed FROM suppression_windows;"));
        Assert.True((await store.EnqueueAsync(Suppressible("admitted"), Cancellation)).Duplicate);

        snapshot.Dispose();
        await store.MaintainAsync(Cancellation);
        Assert.True(StorageBytes(path) <= store.MaximumStorageBytes);
        SqliteEventStore restarted = new(path, 1_048_576, clock);
        await restarted.InitializeAsync(Cancellation);
        Assert.True((await restarted.EnqueueAsync(Suppressible("recovered"), Cancellation)).Suppressed);
        clock.Advance(TimeSpan.FromMinutes(2));
        SuppressionWindow? closed = null;
        Assert.Equal(1, await restarted.CloseExpiredSuppressionWindowsAsync(clock.UtcNow, window =>
        {
            closed = window;
            return new QueuedEvent("summary", "sha256:summary", """{"eventId":"summary"}""", clock.UtcNow);
        }, Cancellation));
        Assert.Equal((1L, counted + 1), (closed!.Admitted, closed.Suppressed));
        Assert.Equal(2, (await restarted.GetSnapshotAsync(Cancellation)).Queued);
        Assert.True((await restarted.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task PopulatedLegacyMigration_RollsBackOnInterruptionAndRefusesOldWriters()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        File.Copy(Path.Combine(RepositoryDirectory(), "rust/crates/bower-persistence/tests/fixtures/csharp-queue.db"), path);
        long before = await ScalarAsync(path, "SELECT COUNT(*) FROM queue_events;");
        await ExecuteAsync(path, "CREATE TRIGGER interrupt_v5 BEFORE INSERT ON schema_history WHEN NEW.version = 5 BEGIN SELECT RAISE(ROLLBACK, 'interrupted'); END;");
        SqliteEventStore store = new(path, 10_485_760);
        await Assert.ThrowsAsync<SqliteException>(() => store.InitializeAsync(Cancellation));
        Assert.Equal(before, await ScalarAsync(path, "SELECT COUNT(*) FROM queue_events;"));
        Assert.Equal(0, await ScalarAsync(path, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'queue_events_v5';"));
        await ExecuteAsync(path, "DROP TRIGGER interrupt_v5;");
        await store.InitializeAsync(Cancellation);
        Assert.Equal(before, await ScalarAsync(path, "SELECT COUNT(*) FROM queue_events_v5;"));
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
        await Assert.ThrowsAsync<SqliteException>(() => ExecuteAsync(path, "UPDATE queue_events SET state = 4 WHERE state = 1;"));
        await Assert.ThrowsAsync<SqliteException>(() => ExecuteAsync(path, "INSERT INTO queue_events(event_id,fingerprint,payload,payload_bytes,received_at,state) VALUES ('old','old','{}',2,'now',0);"));
        await new SqliteEventStore(path, 10_485_760).InitializeAsync(Cancellation);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task Processor_QuarantinesConflictAndKeepsDistinctSameTimeAttempts()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1_048_576, clock);
        await store.InitializeAsync(Cancellation);
        SecurityEventProcessor processor = new(new Bower.Redaction.JsonEventRedactor(),
            new Bower.PolicyEngine.DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        var candidate = TestEvents.AuthenticationFailure(clock.UtcNow, originalId: null);
        CollectorIdentity identity = new("collector", "v1", "test", "configuration");
        async Task<ProcessingResult> Process(SecurityEventEnvelope value) => await processor.ProcessAsync(
            JsonSerializer.Serialize(value, BowerJson.Envelope), identity, Cancellation);
        Assert.True((await Process(candidate)).Queued);
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True((await Process(candidate)).Duplicate);
        var conflict = await Process(candidate with { EventOutcomeReason = "different-fact" });
        Assert.Equal(DecisionAction.Quarantine, conflict.Action);
        Assert.False(conflict.Duplicate);
        Assert.Equal(["event-identity-conflict"], conflict.Reasons);
        Assert.True((await Process(candidate with { EventId = "different-attempt" })).Queued);
        Assert.Equal(2, (await store.GetSnapshotAsync(Cancellation)).Queued);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyEnvelopeMigration_RekeysIdentityOrRollsBackCollision(bool collision)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        File.Copy(Path.Combine(RepositoryDirectory(), "rust/crates/bower-persistence/tests/fixtures/csharp-queue.db"), path);
        await ExecuteAsync(path, "DROP TABLE queue_ledger; DROP TABLE queue_ledger_anchor; DELETE FROM schema_history WHERE version >= 3;");
        var envelope = TestEvents.AuthenticationFailure(TestEvents.Now, "e3", "stable-source-id");
        string payload = JsonSerializer.Serialize(envelope, BowerJson.Envelope);
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(Cancellation);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE queue_events SET payload=$payload,payload_bytes=$bytes WHERE event_id='e3' OR ($collision=1 AND event_id='e4');";
            command.Parameters.AddWithValue("$payload", payload);
            command.Parameters.AddWithValue("$bytes", System.Text.Encoding.UTF8.GetByteCount(payload));
            command.Parameters.AddWithValue("$collision", collision);
            await command.ExecuteNonQueryAsync(Cancellation);
        }
        SqliteEventStore store = new(path, 10_485_760);
        if (collision)
        {
            await Assert.ThrowsAsync<SqliteException>(() => store.InitializeAsync(Cancellation));
            Assert.Equal(0, await ScalarAsync(path, "SELECT COUNT(*) FROM sqlite_master WHERE name='queue_events_v5';"));
            Assert.Equal(4, await ScalarAsync(path, "SELECT COUNT(*) FROM queue_events;"));
        }
        else
        {
            await store.InitializeAsync(Cancellation);
            Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
            var replay = envelope with { EventId = "reconstructed" };
            Assert.True((await store.EnqueueAsync(new(replay.EventId, EventFingerprint.Create(replay),
                JsonSerializer.Serialize(replay, BowerJson.Envelope), TestEvents.Now), Cancellation)).Duplicate);
        }
    }

    [Fact]
    public async Task RustV5Database_OpensAndSettlesInCSharp()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        File.Copy(Path.Combine(RepositoryDirectory(), "rust/crates/bower-persistence/tests/fixtures/rust-queue-v5.db"), path);
        SqliteEventStore store = new(path, 10_485_760);
        await store.InitializeAsync(Cancellation);
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
        var leases = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), Cancellation);
        Assert.NotEmpty(leases);
        foreach (var lease in leases)
        {
            await store.MarkDeliveredAsync(lease.EventId, "csharp", lease.LeaseToken, Cancellation);
        }
        Assert.True((await store.VerifyLedgerAsync(Cancellation)).Intact);
    }

    [Fact]
    public async Task CorruptLegacyLedger_RefusesMigrationWithoutRewritingEvidence()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        File.Copy(Path.Combine(RepositoryDirectory(), "rust/crates/bower-persistence/tests/fixtures/csharp-queue.db"), path);
        await ExecuteAsync(path, "UPDATE queue_ledger SET chain_hash='corrupt' WHERE sequence=3;");
        SqliteEventStore store = new(path, 10_485_760);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.InitializeAsync(Cancellation));
        Assert.Equal(0, await ScalarAsync(path, "SELECT COUNT(*) FROM sqlite_master WHERE name='queue_events_v5';"));
        Assert.Equal(4, await ScalarAsync(path, "SELECT COUNT(*) FROM queue_events;"));
    }

    private static string RepositoryDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "rust")))
        {
            directory = directory.Parent;
        }
        return directory!.FullName;
    }

    private static long StorageBytes(string path) => new[] { path, path + "-wal" }
        .Where(File.Exists).Sum(file => new FileInfo(file).Length);

    private static async Task ExecuteAsync(string path, string sql)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(Cancellation);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    private static async Task<long> ScalarAsync(string path, string sql)
    {
        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(Cancellation);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(Cancellation), System.Globalization.CultureInfo.InvariantCulture);
    }
}
