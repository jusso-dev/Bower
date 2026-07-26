using Bower.Persistence;
using Bower.Source.SqlServer;

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
