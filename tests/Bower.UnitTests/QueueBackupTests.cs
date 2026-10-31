using System.Security.Cryptography;
using Bower.Abstractions;
using Bower.Persistence;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class QueueBackupTests
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Backup_OfLiveQueue_RestoresEveryStateCursorAndDeduplicationOnANewHost()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string live = Path.Combine(directory.Path, "live", "queue.db");
        SqliteEventStore store = new(live, 1_048_576, clock);
        await store.InitializeAsync(Cancellation);
        for (int index = 1; index <= 5; index++)
        {
            await store.EnqueueAsync(Event(index, clock), Cancellation);
        }
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(3, TimeSpan.FromSeconds(90), Cancellation);
        await store.MarkDeliveredAsync(leased[0].EventId, "ack-1", leased[0].LeaseToken, Cancellation);
        EfSourceCursorStore cursors = new(live);
        await cursors.InitializeAsync(Cancellation);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:wec", 0, "{\"schemaVersion\":2,\"channel\":\"ForwardedEvents\",\"recordId\":42}", clock.UtcNow, Cancellation));

        string backup = Path.Combine(directory.Path, "backups", "queue.bowerbackup");
        QueueBackupManifest manifest = await QueueBackup.CreateAsync(live, backup, "collector-a", clock, cancellationToken: Cancellation);
        // Accepted after the backup: not part of it.
        await store.EnqueueAsync(Event(6, clock), Cancellation);

        Assert.Equal(new QueueBackupCounts(2, 2, 0, 1, 0), manifest.Counts);
        Assert.Equal(1, manifest.SourceCursors);
        Assert.Equal(5, manifest.LedgerSequence);
        Assert.True(manifest.LedgerIntact);
        Assert.True(manifest.IntegrityOk);
        Assert.False(manifest.Damaged);
        Assert.Equal("collector-a", manifest.CollectorId);
        Assert.False(File.Exists(backup + "-wal"));
        Assert.Equal(manifest.DatabaseSha256, Sha256(backup));
        Assert.Equal(manifest, await QueueBackup.ReadManifestAsync(backup + QueueBackup.ManifestSuffix, Cancellation));
        if (!OperatingSystem.IsWindows())
        {
            UnixFileMode owner = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            Assert.Equal(owner, File.GetUnixFileMode(backup));
            Assert.Equal(owner, File.GetUnixFileMode(backup + QueueBackup.ManifestSuffix));
            // The backup directory did not exist, so it was created owner-only.
            Assert.Equal(owner | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.GetDirectoryName(backup)!));
        }

        string fresh = Path.Combine(directory.Path, "fresh-host", "queue.db");
        FakeClock later = new(TestEvents.Now.AddHours(3));
        QueueRestoreResult restored = await QueueBackup.RestoreAsync(backup, fresh, later, cancellationToken: Cancellation);
        // The backup's own manifest is reported unchanged; the restored file has its own hash
        // after the WAL header change, taken at restore time.
        Assert.Equal(manifest, restored.Backup);
        Assert.Equal(later.UtcNow, restored.RestoredAt);
        Assert.Equal(Sha256(fresh), restored.RestoredDatabaseSha256);
        Assert.Equal(new FileInfo(fresh).Length, restored.RestoredDatabaseBytes);
        Assert.NotEqual(manifest.DatabaseSha256, restored.RestoredDatabaseSha256);
        Assert.False(restored.RestoredDamagedBackup);

        SqliteEventStore recovered = new(fresh, 1_048_576, clock);
        await recovered.InitializeAsync(Cancellation);
        Assert.True((await recovered.VerifyLedgerAsync(Cancellation)).Intact);
        Assert.Equal("{\"schemaVersion\":2,\"channel\":\"ForwardedEvents\",\"recordId\":42}",
            (await new EfSourceCursorStore(fresh).ReadAsync("windows-eventlog:wec", Cancellation))!.Value);
        // A replayed delivered event is still a duplicate; nothing accepted is lost.
        Assert.True((await recovered.EnqueueAsync(Event(1, clock), Cancellation)).Duplicate);
        clock.Advance(TimeSpan.FromSeconds(91));
        IReadOnlyList<QueuedEvent> redelivered = await recovered.LeaseAsync(10, TimeSpan.FromSeconds(90), Cancellation);
        Assert.Equal(["event-2", "event-3", "event-4", "event-5"], redelivered.Select(item => item.EventId).Order());
        Assert.True((await recovered.EnqueueAsync(Event(6, clock), Cancellation)).Enqueued);
    }

    [Fact]
    public void PrivateFiles_AreOwnerOnlyFromCreation()
    {
        using TemporaryDirectory directory = new();
        string file = Path.Combine(directory.Path, "copy.tmp");
        string folder = Path.Combine(directory.Path, "private");

        QueueBackup.CreatePrivateFile(file, privateAcl: true);
        QueueBackup.CreatePrivateDirectory(folder);

        Assert.Equal(0, new FileInfo(file).Length);
        if (!OperatingSystem.IsWindows())
        {
            // Mode is fixed at creation (before any queue page is written), whatever the umask.
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(folder));
        }
        Assert.Throws<IOException>(() => QueueBackup.CreatePrivateFile(file, privateAcl: true));
    }

    [Fact]
    public async Task Backup_InterruptedByCancellation_LeavesNoCopyBehind()
    {
        using TemporaryDirectory directory = new();
        string live = await CreateQueueAsync(directory);
        string output = Path.Combine(directory.Path, "out", "queue.bowerbackup");
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            QueueBackup.CreateAsync(live, output, null, cancellationToken: cancelled.Token));

        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(output)!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("-wal")]
    [InlineData("-shm")]
    public async Task Backup_RefusesToWriteOverTheLiveQueueOrItsWal(string suffix)
    {
        using TemporaryDirectory directory = new();
        string live = await CreateQueueAsync(directory);
        string sha = Sha256(live);

        IOException failure = await Assert.ThrowsAsync<IOException>(() =>
            QueueBackup.CreateAsync(live, live + suffix, null, cancellationToken: Cancellation));

        Assert.Contains("must not be the live queue database", failure.Message, StringComparison.Ordinal);
        SqliteConnection.ClearAllPools();
        Assert.Equal(sha, Sha256(live));
    }

    [Fact]
    public async Task Restore_NeverOverwritesAQueueOrAdoptsAStaleWal()
    {
        using TemporaryDirectory directory = new();
        string backup = await CreateBackupAsync(directory);
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            string target = Path.Combine(directory.Path, "target" + suffix.Replace("-", "", StringComparison.Ordinal), "queue.db");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await File.WriteAllTextAsync(target + suffix, "existing", Cancellation);

            await Assert.ThrowsAsync<IOException>(() => QueueBackup.RestoreAsync(backup, target, cancellationToken: Cancellation));

            Assert.Equal("existing", await File.ReadAllTextAsync(target + suffix, Cancellation));
            Assert.Single(Directory.GetFiles(Path.GetDirectoryName(target)!));
        }
    }

    [Fact]
    public async Task Restore_RejectsABackupThatDoesNotMatchItsManifest()
    {
        using TemporaryDirectory directory = new();
        string backup = await CreateBackupAsync(directory);
        await using (FileStream stream = new(backup, FileMode.Open, FileAccess.Write))
        {
            stream.Seek(-1, SeekOrigin.End);
            stream.WriteByte(0x5a);
        }
        string target = Path.Combine(directory.Path, "target", "queue.db");

        await Assert.ThrowsAsync<InvalidDataException>(() => QueueBackup.RestoreAsync(backup, target, cancellationToken: Cancellation));

        Assert.False(Directory.Exists(Path.GetDirectoryName(target)));
    }

    [Fact]
    public async Task Backup_RefusesToOverwriteAnExistingBackup()
    {
        using TemporaryDirectory directory = new();
        string backup = await CreateBackupAsync(directory);
        string sha = Sha256(backup);

        await Assert.ThrowsAsync<IOException>(() => QueueBackup.CreateAsync(
            Path.Combine(directory.Path, "live", "queue.db"), backup, null, cancellationToken: Cancellation));

        Assert.Equal(sha, Sha256(backup));
    }

    [Fact]
    public async Task DamagedQueue_IsStillBackedUpButRestoresOnlyWithExplicitConsent()
    {
        using TemporaryDirectory directory = new();
        string live = await CreateQueueAsync(directory, events: 3);
        // Tamper with a ledger entry: the database is readable, the evidence chain is not intact.
        await ExecuteAsync(live, "UPDATE queue_ledger SET chain_hash = 'tampered' WHERE sequence = 2;");
        SqliteConnection.ClearAllPools();
        string backup = Path.Combine(directory.Path, "damaged.bowerbackup");

        QueueBackupManifest manifest = await QueueBackup.CreateAsync(live, backup, null, cancellationToken: Cancellation);

        Assert.True(manifest.Damaged);
        Assert.False(manifest.LedgerIntact);
        Assert.True(manifest.IntegrityOk);
        Assert.Equal(manifest.DatabaseSha256, Sha256(backup));
        Assert.True((await QueueBackup.ReadManifestAsync(backup + QueueBackup.ManifestSuffix, Cancellation)).Damaged);

        string target = Path.Combine(directory.Path, "target", "queue.db");
        InvalidDataException refused = await Assert.ThrowsAsync<InvalidDataException>(() =>
            QueueBackup.RestoreAsync(backup, target, cancellationToken: Cancellation));
        Assert.Contains("--allow-damaged", refused.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(target));

        QueueRestoreResult restored = await QueueBackup.RestoreAsync(backup, target, allowDamaged: true, cancellationToken: Cancellation);
        Assert.True(restored.RestoredDamagedBackup);
        Assert.Equal(3, await ScalarAsync(target, "SELECT COUNT(*) FROM queue_events_v5;"));
    }

    [Fact]
    public async Task CorruptPages_AreStillCopiedAndMarkedDamaged()
    {
        using TemporaryDirectory directory = new();
        string live = await CreateQueueAsync(directory, events: 200, payloadBytes: 3000);
        await ExecuteAsync(live, "PRAGMA wal_checkpoint(TRUNCATE);");
        SqliteConnection.ClearAllPools();
        long pageSize = await ScalarAsync(live, "PRAGMA page_size;");
        long pages = await ScalarAsync(live, "PRAGMA page_count;");
        SqliteConnection.ClearAllPools();
        await using (FileStream stream = new(live, FileMode.Open, FileAccess.Write))
        {
            // Overwrite interior pages (never page 1, which holds the header and schema).
            for (long page = pages / 2; page < pages / 2 + 4; page++)
            {
                stream.Seek(page * pageSize, SeekOrigin.Begin);
                stream.Write(new byte[pageSize]);
            }
        }
        string backup = Path.Combine(directory.Path, "corrupt.bowerbackup");

        QueueBackupManifest manifest = await QueueBackup.CreateAsync(live, backup, null, cancellationToken: Cancellation);

        Assert.True(manifest.Damaged);
        Assert.False(manifest.IntegrityOk);
        Assert.StartsWith("failed", manifest.IntegrityCheck, StringComparison.Ordinal);
        Assert.True(File.Exists(backup));
        Assert.True(File.Exists(backup + QueueBackup.ManifestSuffix));
    }

    [Fact]
    public async Task Backup_WaitsOutABusyQueueWithinItsBound()
    {
        using TemporaryDirectory directory = new();
        string live = await CreateQueueAsync(directory);
        string output = Path.Combine(directory.Path, "busy.bowerbackup");
        SqliteConnection holder = await HoldExclusiveLockAsync(live);
        Task<QueueBackupManifest> backup = Task.Run(() => QueueBackup.CreateAsync(
            live, output, null, busyTimeout: TimeSpan.FromSeconds(20), cancellationToken: Cancellation), Cancellation);
        await Task.Delay(TimeSpan.FromMilliseconds(1500), Cancellation);
        Assert.False(backup.IsCompleted);

        await holder.DisposeAsync();
        QueueBackupManifest manifest = await backup;

        Assert.True(manifest.LedgerIntact);
        Assert.Equal(1, manifest.Counts!.Total);
    }

    [Fact]
    public async Task Backup_GivesUpOnAPersistentLockWithoutLeavingFiles()
    {
        using TemporaryDirectory directory = new();
        string live = await CreateQueueAsync(directory);
        string output = Path.Combine(directory.Path, "out", "busy.bowerbackup");
        await using SqliteConnection holder = await HoldExclusiveLockAsync(live);

        await Assert.ThrowsAsync<TimeoutException>(() => QueueBackup.CreateAsync(
            live, output, null, busyTimeout: TimeSpan.FromSeconds(1), cancellationToken: Cancellation));

        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(output)!));
    }

    [Fact]
    public async Task Backup_IsConsistentWhileAWriterAndCheckpointsRun()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string live = Path.Combine(directory.Path, "live", "queue.db");
        SqliteEventStore store = new(live, 64L * 1024 * 1024, clock);
        await store.InitializeAsync(Cancellation);
        using CancellationTokenSource stop = new();
        int written = 0;
        Task writer = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                await store.EnqueueAsync(Event(Interlocked.Increment(ref written), clock), CancellationToken.None);
                if (written % 25 == 0)
                {
                    await store.MaintainAsync(CancellationToken.None); // wal_checkpoint(TRUNCATE)
                }
            }
        }, Cancellation);

        List<QueueBackupManifest> manifests = [];
        for (int round = 0; round < 5; round++)
        {
            await Task.Delay(50, Cancellation);
            manifests.Add(await QueueBackup.CreateAsync(
                live, Path.Combine(directory.Path, $"round-{round}.bowerbackup"), null, cancellationToken: Cancellation));
        }
        await stop.CancelAsync();
        await writer;

        foreach (QueueBackupManifest manifest in manifests)
        {
            Assert.False(manifest.Damaged);
            // A point-in-time copy: every accepted row has its ledger entry and nothing more.
            Assert.Equal(manifest.LedgerSequence, manifest.Counts!.Total);
        }
        Assert.True(manifests[^1].Counts!.Total >= manifests[0].Counts!.Total);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NewerSchema_FailsClosedWithoutChangingTheDatabase(bool futureRenamedQueueTable)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 1_048_576);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event(1, new FakeClock(TestEvents.Now)), Cancellation);
        // Simulate a future release: a higher schema version, optionally after it has moved
        // the writable table. An old build must not recreate or migrate legacy tables in it.
        await ExecuteAsync(path, (futureRenamedQueueTable
            ? "DROP VIEW queue_events; ALTER TABLE queue_events_v5 RENAME TO queue_events_v6; "
            : "") + "INSERT INTO schema_history(version, applied_at, hash) VALUES (6, '2027-01-01T00:00:00Z', 'future'); PRAGMA wal_checkpoint(TRUNCATE);");
        SqliteConnection.ClearAllPools();
        string before = Sha256(path);
        long objects = await ScalarAsync(path, "SELECT COUNT(*) FROM sqlite_master;");
        SqliteConnection.ClearAllPools();

        UnsupportedQueueSchemaException failure = await Assert.ThrowsAsync<UnsupportedQueueSchemaException>(
            () => new SqliteEventStore(path, 1_048_576).InitializeAsync(Cancellation));
        await Assert.ThrowsAsync<UnsupportedQueueSchemaException>(() => new EfSourceCursorStore(path).InitializeAsync(Cancellation));
        await Assert.ThrowsAsync<UnsupportedQueueSchemaException>(() => QueueBackup.CreateAsync(
            path, Path.Combine(directory.Path, "backup.db"), null, cancellationToken: Cancellation));

        Assert.Equal(6, failure.Found);
        Assert.Equal(SqliteEventStore.SchemaVersion, failure.Supported);
        Assert.Contains("newer than this Bower build supports", failure.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(directory.Path, "backup.db")));
        Assert.All(Directory.GetFiles(directory.Path), file => Assert.StartsWith("queue.db", Path.GetFileName(file), StringComparison.Ordinal));
        Assert.Equal(objects, await ScalarAsync(path, "SELECT COUNT(*) FROM sqlite_master;"));
        SqliteConnection.ClearAllPools();
        Assert.Equal(before, Sha256(path));
    }

    [Fact]
    public async Task Restore_RefusesAManifestFromANewerSchema()
    {
        using TemporaryDirectory directory = new();
        string backup = await CreateBackupAsync(directory);
        string manifestPath = backup + QueueBackup.ManifestSuffix;
        string manifest = await File.ReadAllTextAsync(manifestPath, Cancellation);
        await File.WriteAllTextAsync(manifestPath, manifest.Replace("\"schemaVersion\": 5", "\"schemaVersion\": 6", StringComparison.Ordinal), Cancellation);
        string target = Path.Combine(directory.Path, "target", "queue.db");

        await Assert.ThrowsAsync<UnsupportedQueueSchemaException>(() => QueueBackup.RestoreAsync(backup, target, cancellationToken: Cancellation));

        Assert.False(File.Exists(target));
    }

    /// <summary>
    /// Holds an EXCLUSIVE write lock. WAL readers are never blocked by writers, so the queue is
    /// switched to a rollback journal first: then every other reader gets SQLITE_BUSY until
    /// this connection ends its transaction, the same error path a busy WAL queue takes.
    /// </summary>
    private static async Task<SqliteConnection> HoldExclusiveLockAsync(string path)
    {
        SqliteConnection.ClearAllPools();
        await ExecuteAsync(path, "PRAGMA journal_mode = DELETE;");
        SqliteConnection holder = new($"Data Source={path};Pooling=False");
        await holder.OpenAsync(Cancellation);
        await using SqliteCommand command = holder.CreateCommand();
        command.CommandText = "BEGIN EXCLUSIVE;";
        await command.ExecuteNonQueryAsync(Cancellation);
        return holder;
    }

    private static async Task<string> CreateQueueAsync(TemporaryDirectory directory, int events = 1, int payloadBytes = 0)
    {
        FakeClock clock = new(TestEvents.Now);
        string live = Path.Combine(directory.Path, "live", "queue.db");
        SqliteEventStore store = new(live, 16L * 1024 * 1024, clock);
        await store.InitializeAsync(Cancellation);
        for (int index = 1; index <= events; index++)
        {
            string padding = new('x', payloadBytes);
            await store.EnqueueAsync(new QueuedEvent($"event-{index}", $"sha256:{index}",
                $$"""{"eventId":"event-{{index}}","pad":"{{padding}}"}""", clock.UtcNow), Cancellation);
        }
        return live;
    }

    private static async Task<string> CreateBackupAsync(TemporaryDirectory directory)
    {
        string live = await CreateQueueAsync(directory);
        string backup = Path.Combine(directory.Path, "queue.bowerbackup");
        await QueueBackup.CreateAsync(live, backup, null, new FakeClock(TestEvents.Now), cancellationToken: Cancellation);
        return backup;
    }

    private static QueuedEvent Event(int index, FakeClock clock) =>
        new($"event-{index}", $"sha256:{index}", $$"""{"eventId":"event-{{index}}"}""", clock.UtcNow);

    private static string Sha256(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

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
        await using SqliteConnection connection = new($"Data Source={path};Mode=ReadOnly;Pooling=False");
        await connection.OpenAsync(Cancellation);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(Cancellation), System.Globalization.CultureInfo.InvariantCulture);
    }
}
