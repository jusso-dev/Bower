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
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
        QueueBackupManifest manifest = await QueueBackup.CreateAsync(live, backup, "collector-a", clock, Cancellation);
        // Accepted after the backup: not part of it.
        await store.EnqueueAsync(Event(6, clock), Cancellation);

        Assert.Equal(new QueueBackupCounts(2, 2, 0, 1, 0), manifest.Counts);
        Assert.Equal(1, manifest.SourceCursors);
        Assert.Equal(5, manifest.LedgerSequence);
        Assert.True(manifest.LedgerIntact);
        Assert.Equal("collector-a", manifest.CollectorId);
        Assert.False(File.Exists(backup + "-wal"));
        Assert.Equal(manifest.DatabaseSha256, Sha256(backup));
        Assert.Equal(manifest, await QueueBackup.ReadManifestAsync(backup + QueueBackup.ManifestSuffix, Cancellation));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(backup));
        }

        string fresh = Path.Combine(directory.Path, "fresh-host", "queue.db");
        QueueBackupManifest restored = await QueueBackup.RestoreAsync(backup, fresh, clock, Cancellation);
        Assert.Equal(manifest.Counts, restored.Counts);
        Assert.Equal(manifest.LedgerHash, restored.LedgerHash);

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

    private static async Task<string> CreateBackupAsync(TemporaryDirectory directory)
    {
        FakeClock clock = new(TestEvents.Now);
        string live = Path.Combine(directory.Path, "live", "queue.db");
        SqliteEventStore store = new(live, 1_048_576, clock);
        await store.InitializeAsync(Cancellation);
        await store.EnqueueAsync(Event(1, clock), Cancellation);
        string backup = Path.Combine(directory.Path, "queue.bowerbackup");
        await QueueBackup.CreateAsync(live, backup, null, clock, Cancellation);
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
