using System.Globalization;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Persistence;
using Bower.Tools.QueueMigrationCheck;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class QueueMigrationPreflightTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public async Task Command_PopulatedV4_ReportsPairsWithoutChangingDatabaseWalOrSchema(bool collision, int exitCode)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using SqliteConnection writer = await CreateV4Async(path, collision);
        byte[] database = await File.ReadAllBytesAsync(path, Token);
        byte[] wal = await File.ReadAllBytesAsync(path + "-wal", Token);
        string schema = await SchemaAsync(writer);
        using StringWriter output = new(CultureInfo.InvariantCulture);

        Assert.Equal(exitCode, await MigrationCheckCommand.RunAsync(["--database", path], output, Token));
        using JsonDocument report = JsonDocument.Parse(output.ToString());
        Assert.True(report.RootElement.GetProperty("complete").GetBoolean());
        Assert.Equal(2, report.RootElement.GetProperty("scannedRows").GetInt32());
        JsonElement pairs = report.RootElement.GetProperty("collisions");
        Assert.Equal(collision ? 1 : 0, pairs.GetArrayLength());
        if (collision)
        {
            Assert.Equal("event-b", pairs[0].GetProperty("eventId").GetString());
            Assert.Equal("event-a", pairs[0].GetProperty("conflictingEventId").GetString());
        }
        Assert.DoesNotContain("payload", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("test-user", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("source-1", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(database, await File.ReadAllBytesAsync(path, Token));
        Assert.Equal(wal, await File.ReadAllBytesAsync(path + "-wal", Token));
        Assert.Equal(schema, await SchemaAsync(writer));

        // Preflight does not change the upgrade's fail-closed behavior.
        SqliteEventStore store = new(path, 8 * 1_048_576);
        if (collision)
        {
            await Assert.ThrowsAsync<SqliteException>(() => store.InitializeAsync(Token));
            Assert.Equal(schema, await SchemaAsync(writer));
            Assert.Equal(2L, await ScalarAsync(writer, "SELECT COUNT(*) FROM queue_events;"));
        }
        else
        {
            await store.InitializeAsync(Token);
            Assert.Equal(5L, await ScalarAsync(writer, "SELECT MAX(version) FROM schema_history;"));
            Assert.True((await store.VerifyLedgerAsync(Token)).Intact);
        }
    }

    [Theory]
    [InlineData("INSERT INTO schema_history VALUES(6, 'now', 'future');")]
    [InlineData("UPDATE schema_history SET hash='unknown' WHERE version=4;")]
    [InlineData("DELETE FROM schema_history WHERE version=4;")]
    [InlineData("DROP TABLE schema_history;")]
    [InlineData("ALTER TABLE queue_events RENAME TO unexpected;")]
    public async Task UnknownSchema_IsRefusedWithoutWrites(string mutation)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using SqliteConnection writer = await CreateV4Async(path, false);
        await ExecuteAsync(writer, mutation);
        byte[] database = await File.ReadAllBytesAsync(path, Token);
        byte[] wal = await File.ReadAllBytesAsync(path + "-wal", Token);
        string schema = await SchemaAsync(writer);
        MigrationCheckReport report = await MigrationPreflight.CheckAsync(path, Token);
        Assert.False(report.Complete);
        Assert.Equal("unsupported-schema", report.Status);
        Assert.Equal(database, await File.ReadAllBytesAsync(path, Token));
        Assert.Equal(wal, await File.ReadAllBytesAsync(path + "-wal", Token));
        Assert.Equal(schema, await SchemaAsync(writer));
    }

    [Fact]
    public async Task MissingDatabase_IsNotCreated_AndCommandRequiresExactArguments()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "missing.db");
        using StringWriter output = new(CultureInfo.InvariantCulture);
        Assert.Equal(1, await MigrationCheckCommand.RunAsync(["--database", path], output, Token));
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(directory.Path));
        Assert.Equal(1, await MigrationCheckCommand.RunAsync(["--database", path, "--repair"], output, Token));
    }

    [Fact]
    public async Task OpaqueFingerprint_CollidingWithNewIdentity_IsReported()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using SqliteConnection writer = await CreateV4Async(path, false);
        await using SqliteCommand command = writer.CreateCommand();
        command.CommandText = "UPDATE queue_events SET payload='opaque-private-value', fingerprint=$key WHERE event_id='event-b';";
        command.Parameters.AddWithValue("$key", EventIdentity.Create(TestEvents.AuthenticationFailure(TestEvents.Now, "event-a")));
        await command.ExecuteNonQueryAsync(Token);
        MigrationCheckReport report = await MigrationPreflight.CheckAsync(path, Token);
        Assert.True(report.Complete);
        Assert.Equal(1, report.OpaqueRows);
        Assert.Equal(new IdentityCollision("event-a", "event-b"), Assert.Single(report.Collisions));
    }

    [Theory]
    [InlineData("UPDATE queue_events SET payload=CAST(zeroblob(1048577) AS TEXT);")]
    [InlineData("UPDATE queue_events SET event_id=printf('%0130d', 1) WHERE event_id='event-a';")]
    public async Task OversizedInput_IsIncompleteWithoutPayloadDisclosure(string mutation)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using SqliteConnection writer = await CreateV4Async(path, false);
        await ExecuteAsync(writer, "PRAGMA ignore_check_constraints=ON;" + mutation);
        MigrationCheckReport report = await MigrationPreflight.CheckAsync(path, Token);
        Assert.False(report.Complete);
        Assert.Equal("invalid-or-oversized-row", report.Status);
    }

    [Fact]
    public async Task MalformedPayload_IsOpaque_AndCancellationPropagates()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using SqliteConnection writer = await CreateV4Async(path, false);
        await ExecuteAsync(writer, "UPDATE queue_events SET payload='{private-malformed-data';");
        MigrationCheckReport report = await MigrationPreflight.CheckAsync(path, Token);
        Assert.True(report.Complete);
        Assert.Equal(2, report.OpaqueRows);
        Assert.Empty(report.Collisions);
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MigrationPreflight.CheckAsync(path, cancelled.Token));
    }

    [Theory]
    [InlineData(100_001, 2, false, "row-limit")]
    [InlineData(65, 1_048_576, false, "payload-budget")]
    [InlineData(102, 0, true, "collision-limit")]
    public async Task ScanLimits_NeverReportClean(int count, int bytes, bool envelopes, string status)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        await using SqliteConnection writer = await CreateV4Async(path, false);
        // Synthetic bounded-input fixture; no ledger claim is made for these rows.
        await using SqliteCommand command = writer.CreateCommand();
        command.CommandText = """
            DELETE FROM queue_events;
            WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<$count)
            INSERT INTO queue_events(event_id, fingerprint, payload, payload_bytes, received_at, state)
            SELECT printf('event-%06d', n), printf('legacy-%06d', n), $payload, length($payload), 'now', 0 FROM ids;
            """;
        command.Parameters.AddWithValue("$count", count);
        command.Parameters.AddWithValue("$payload", envelopes
            ? JsonSerializer.Serialize(TestEvents.AuthenticationFailure(TestEvents.Now), BowerJson.Envelope)
            : new string('x', bytes));
        await command.ExecuteNonQueryAsync(Token);
        MigrationCheckReport report = await MigrationPreflight.CheckAsync(path, Token);
        Assert.False(report.Complete);
        Assert.Equal(status, report.Status);
        Assert.True(report.Collisions.Count <= MigrationPreflight.MaximumCollisions);
    }

    private static async Task<SqliteConnection> CreateV4Async(string path, bool collision)
    {
        SqliteEventStore store = new(path, 8 * 1_048_576);
        await store.InitializeAsync(Token);
        foreach (string id in new[] { "event-a", "event-b" })
        {
            SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(TestEvents.Now, id,
                collision || id == "event-a" ? "source-1" : "source-2");
            await store.EnqueueAsync(new QueuedEvent(id, "legacy-" + id,
                JsonSerializer.Serialize(envelope, BowerJson.Envelope), TestEvents.Now), Token);
        }
        SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        await connection.OpenAsync(Token);
        await ExecuteAsync(connection, """
            PRAGMA wal_autocheckpoint=0;
            DROP VIEW queue_events;
            DROP INDEX ix_queue_events_incarnation;
            ALTER TABLE queue_events_v5 DROP COLUMN enqueue_sequence;
            ALTER TABLE queue_events_v5 DROP COLUMN lease_generation;
            ALTER TABLE queue_events_v5 RENAME TO queue_events;
            DELETE FROM schema_history WHERE version=5;
            """);
        return connection;
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(Token);
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(Token);
    }

    private static async Task<string> SchemaAsync(SqliteConnection connection) =>
        (string)(await ScalarAsync(connection, "SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_master ORDER BY name);"))!;
}
