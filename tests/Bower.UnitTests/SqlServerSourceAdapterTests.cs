using Bower.Abstractions;
using Bower.Persistence;
using Bower.Source.SqlServer;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class SqlServerSourceAdapterTests
{
    [Fact]
    public void Options_AcceptReadOnlyBoundedEfMapping()
    {
        SqlServerSourceOptions options = ValidOptions();

        options.Validate();

        Assert.Equal(SqlServerCursorKind.Incrementing, options.CursorKind);
        Assert.Equal(1_000, options.BatchSize);
    }

    [Fact]
    public void Options_RejectConnectionWithoutReadOnlyIntent()
    {
        SqlServerSourceOptions options = ValidOptions() with
        {
            ConnectionString =
                "Server=sql.example.test;Database=Audit;Integrated Security=true;Encrypt=true"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(options.Validate);

        Assert.Contains("ApplicationIntent=ReadOnly", exception.Message);
        Assert.DoesNotContain("sql.example.test", exception.Message);
    }

    [Fact]
    public void Options_RejectUnsafeMappedIdentifier()
    {
        SqlServerSourceOptions options = ValidOptions() with
        {
            Table = "AuditLog; DROP TABLE AuditLog"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(options.Validate);

        Assert.Contains("SQL identifiers", exception.Message);
    }

    [Fact]
    public void Options_RejectUnboundedBatch()
    {
        SqlServerSourceOptions options = ValidOptions() with { BatchSize = 10_001 };

        Assert.Throws<ArgumentOutOfRangeException>(options.Validate);
    }

    [Fact]
    public void Options_RejectTimestampOverlapForIncrementingCursor()
    {
        SqlServerSourceOptions options = ValidOptions() with
        {
            TimestampOverlap = TimeSpan.FromMinutes(1)
        };

        Assert.Throws<ArgumentException>(options.Validate);
    }

    [Fact]
    public void Options_RejectBatchMemoryAboveBound()
    {
        SqlServerSourceOptions options = ValidOptions() with
        {
            BatchSize = 1_000,
            MaximumRecordBytes = 1_048_576
        };

        Assert.Throws<ArgumentException>(options.Validate);
    }

    [Fact]
    public async Task CursorStore_SurvivesRestartAndRejectsStaleCheckpoint()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "source-cursors.db");
        EfSourceCursorStore first = new(path);
        await first.InitializeAsync(cancellationToken);

        bool created = await first.TryAdvanceAsync(
            "finance-audit",
            expectedVersion: 0,
            """{"sequence":100}""",
            TestEvents.Now,
            cancellationToken);

        EfSourceCursorStore restarted = new(path);
        await restarted.InitializeAsync(cancellationToken);
        var snapshot = await restarted.ReadAsync("finance-audit", cancellationToken);
        bool advanced = await restarted.TryAdvanceAsync(
            "finance-audit",
            expectedVersion: snapshot!.Version,
            """{"sequence":200}""",
            TestEvents.Now.AddMinutes(1),
            cancellationToken);
        bool stale = await first.TryAdvanceAsync(
            "finance-audit",
            expectedVersion: snapshot.Version,
            """{"sequence":150}""",
            TestEvents.Now.AddMinutes(2),
            cancellationToken);
        var current = await first.ReadAsync("finance-audit", cancellationToken);

        Assert.True(created);
        Assert.True(advanced);
        Assert.False(stale);
        Assert.NotNull(current);
        Assert.Equal(2, current.Version);
        Assert.Equal("""{"sequence":200}""", current.Value);
    }

    [Fact]
    public async Task CursorStore_KeepsTheEfCoreSchemaAndTimestampFormat()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "source-cursors.db");
        EfSourceCursorStore store = new(path);
        await store.InitializeAsync(cancellationToken);
        Assert.True(await store.TryAdvanceAsync(
            "finance-audit",
            expectedVersion: 0,
            """{"sequence":1}""",
            new DateTimeOffset(2026, 5, 1, 12, 30, 15, 250, TimeSpan.FromHours(10)),
            cancellationToken));

        await using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT sql FROM sqlite_master WHERE name = 'source_cursors'),
                   (SELECT "UpdatedAt" FROM "source_cursors"),
                   (SELECT journal_mode FROM pragma_journal_mode);
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        Assert.True(await reader.ReadAsync(cancellationToken));

        // The DDL EF Core 10 EnsureCreated produced for SourceCursorEntity, as SQLite stores it.
        Assert.Equal(
            "CREATE TABLE \"source_cursors\" (\n"
            + "    \"SourceId\" TEXT NOT NULL CONSTRAINT \"PK_source_cursors\" PRIMARY KEY,\n"
            + "    \"Value\" TEXT NOT NULL,\n"
            + "    \"Version\" INTEGER NOT NULL,\n"
            + "    \"UpdatedAt\" TEXT NOT NULL\n"
            + ")",
            reader.GetString(0).ReplaceLineEndings("\n"));
        // EF Core's SQLite DateTimeOffset text, normalised to UTC.
        Assert.Equal("2026-05-01 02:30:15.25+00:00", reader.GetString(1));
        Assert.Equal("wal", reader.GetString(2));
    }

    [Fact]
    public async Task CursorStore_ReadsAndAdvancesAnEfCoreCreatedDatabase()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "source-cursors.db");
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA journal_mode = 'wal';
                CREATE TABLE "source_cursors" (
                    "SourceId" TEXT NOT NULL CONSTRAINT "PK_source_cursors" PRIMARY KEY,
                    "Value" TEXT NOT NULL,
                    "Version" INTEGER NOT NULL,
                    "UpdatedAt" TEXT NOT NULL
                );
                INSERT INTO "source_cursors" VALUES ('finance-audit', '{"sequence":7}', 3, '2026-05-01 02:30:15+00:00');
                """;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        EfSourceCursorStore store = new(path);
        await store.InitializeAsync(cancellationToken);
        SourceCursorSnapshot? snapshot = await store.ReadAsync("finance-audit", cancellationToken);

        Assert.Equal(new SourceCursorSnapshot("""{"sequence":7}""", 3), snapshot);
        Assert.False(await store.TryAdvanceAsync("finance-audit", 0, "x", TestEvents.Now, cancellationToken));
        Assert.True(await store.TryAdvanceAsync("finance-audit", 3, "y", TestEvents.Now, cancellationToken));
        Assert.Equal(4, (await store.ReadAsync("finance-audit", cancellationToken))!.Version);
    }

    [Fact]
    public async Task CursorStore_RestrictsDatabasePermissionsOnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "source-cursors.db");
        EfSourceCursorStore store = new(path);

        await store.InitializeAsync(cancellationToken);

        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(path));
    }

    [Fact]
    public void BuildBatch_HoldsBackRowsInsideCommitSettleWindow()
    {
        FakeClock clock = new(TestEvents.Now);
        SqlServerSourceOptions options = ValidOptions();
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore(), clock);
        SqlServerAuditRow[] rows =
        [
            Row(10, TestEvents.Now.AddMinutes(-1)),
            Row(11, TestEvents.Now.AddSeconds(-2)),
            Row(12, TestEvents.Now.AddMinutes(-2))
        ];

        SqlServerPollBatch batch = adapter.BuildBatch(rows, SqlServerSourceCursor.Initial(options), 0);

        SqlServerSourceRecord record = Assert.Single(batch.Records);
        Assert.Equal(10, record.Sequence);
        Assert.Contains("\"sequence\":10", batch.Checkpoint!.Value, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildBatch_OmitsValuesFromOversizedRecordAndAdvances()
    {
        FakeClock clock = new(TestEvents.Now);
        SqlServerSourceOptions options = ValidOptions() with { MaximumRecordBytes = 1_024 };
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore(), clock);
        SqlServerAuditRow large = Row(20, TestEvents.Now.AddMinutes(-5));
        large.NewValue = new string('x', 10_000);

        SqlServerPollBatch batch = adapter.BuildBatch([large], SqlServerSourceCursor.Initial(options), 0);

        SqlServerSourceRecord record = Assert.Single(batch.Records);
        Assert.True(record.ValuesOmitted);
        Assert.Null(record.NewValue);
        Assert.NotNull(batch.Checkpoint);
    }

    [Fact]
    public void BuildBatch_FailsOversizedRecordWhenConfigured()
    {
        FakeClock clock = new(TestEvents.Now);
        SqlServerSourceOptions options = ValidOptions() with
        {
            MaximumRecordBytes = 1_024,
            OversizedRecords = SqlServerOversizedRecordHandling.Fail
        };
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore(), clock);
        SqlServerAuditRow large = Row(20, TestEvents.Now.AddMinutes(-5));
        large.NewValue = new string('x', 10_000);

        Assert.Throws<SqlServerSourceRecordTooLargeException>(
            () => adapter.BuildBatch([large], SqlServerSourceCursor.Initial(options), 0));
    }

    [Fact]
    public void Options_RejectNegativeSettleDelay()
    {
        SqlServerSourceOptions options = ValidOptions() with { CommitSettleDelay = TimeSpan.FromSeconds(-1) };

        Assert.Throws<ArgumentOutOfRangeException>(options.Validate);
    }

    private static SqlServerAuditRow Row(long sequence, DateTimeOffset eventTime) =>
        new()
        {
            Sequence = sequence,
            EventTime = eventTime,
            Username = "auditor",
            Action = "update",
            TargetType = "invoice",
            TargetId = $"invoice-{sequence}"
        };

    private sealed class NoCursorStore : Bower.Abstractions.ISourceCursorStore
    {
        public Task<Bower.Abstractions.SourceCursorSnapshot?> ReadAsync(
            string sourceId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<Bower.Abstractions.SourceCursorSnapshot?>(null);

        public Task<bool> TryAdvanceAsync(
            string sourceId,
            long expectedVersion,
            string value,
            DateTimeOffset updatedAt,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private static SqlServerSourceOptions ValidOptions()
    {
        return new SqlServerSourceOptions
        {
            SourceId = "finance-audit",
            ConnectionString =
                "Server=sql.example.test;Database=Audit;Integrated Security=true;Encrypt=true;Application Intent=ReadOnly",
            Schema = "dbo",
            Table = "AuditLog"
        };
    }
}
