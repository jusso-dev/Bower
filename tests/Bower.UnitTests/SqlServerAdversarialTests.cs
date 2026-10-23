using Bower.Persistence;
using Bower.Source.SqlServer;
using Microsoft.EntityFrameworkCore;

namespace Bower.UnitTests;

public sealed partial class SqlServerSourceAdapterTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(60)]
    public async Task TimestampKeyset_TraversesTiesAndRestartsWithoutSkipping(int overlapSeconds)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        EfSourceCursorStore cursors = new(Path.Combine(directory.Path, "cursor.db"));
        await cursors.InitializeAsync(cancellation);
        SqlServerSourceOptions options = ValidOptions() with
        {
            CursorKind = SqlServerCursorKind.Timestamp,
            BatchSize = 3,
            TimestampOverlap = TimeSpan.FromSeconds(overlapSeconds)
        };
        DateTimeOffset timestamp = TestEvents.Now.AddMinutes(-10);
        List<SqlServerAuditRow> rows = Enumerable.Range(1, 20).Select(id => Row(id, timestamp)).ToList();
        HashSet<long> seen = [];
        for (int page = 0; page < 30; page++)
        {
            // New adapter every page; only the committed checkpoint survives.
            SqlServerSourceAdapter adapter = new(options, cursors, new FakeClock(TestEvents.Now));
            var snapshot = await cursors.ReadAsync(options.SourceId, cancellation);
            var cursor = snapshot is null ? SqlServerSourceCursor.Initial(options) : adapter.DeserializeCursor(snapshot.Value);
            var selected = adapter.BuildQuery(rows.AsQueryable(), cursor).Take(options.BatchSize).ToArray();
            var batch = adapter.BuildBatch(selected, cursor, snapshot?.Version ?? 0);
            seen.UnionWith(batch.Records.Select(record => record.Sequence));
            if (batch.Checkpoint is not null)
            {
                await adapter.CommitAsync(batch.Checkpoint, cancellation);
            }
            if (page == 15 && overlapSeconds > 0)
            {
                // Visible after an earlier sweep has already passed its timestamp.
                rows.Add(Row(100, timestamp.AddSeconds(-30)));
            }
        }
        Assert.Subset(seen, Enumerable.Range(1, 20).Select(id => (long)id).ToHashSet());
        Assert.Equal(overlapSeconds > 0, seen.Contains(100));
    }

    [Fact]
    public void BoundedProjection_IsServerSideAndIncludesTrailingSpaceBytes()
    {
        SqlServerSourceOptions options = ValidOptions();
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore());
        using SqlServerAuditDbContext context = new(options);
        string sql = adapter.BoundProjection(adapter.BuildQuery(context.AuditRows,
            SqlServerSourceCursor.Initial(options)).Take(options.BatchSize)).ToQueryString();
        Assert.Contains("DATALENGTH", sql, StringComparison.Ordinal);
        Assert.Contains("CASE", sql, StringComparison.Ordinal);
        Assert.Contains("TOP(", sql, StringComparison.Ordinal);
        Assert.Contains("AS [OversizedIdentity]", sql, StringComparison.Ordinal);
        Assert.Contains("AS [OversizedValues]", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void BoundedProjectionMarkers_RejectOversizedIdentityWithoutCheckpoint()
    {
        SqlServerSourceOptions options = ValidOptions();
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore());
        var row = Row(1, TestEvents.Now.AddMinutes(-1));
        row.OversizedIdentity = true;
        Assert.Throws<SqlServerSourceRecordTooLargeException>(() => adapter.BuildBatch([row], SqlServerSourceCursor.Initial(options), 0));
        row.OversizedIdentity = false;
        row.OversizedValues = true;
        row.ValuesOmitted = true;
        Assert.True(Assert.Single(adapter.BuildBatch([row], SqlServerSourceCursor.Initial(options), 0).Records).ValuesOmitted);
        SqlServerSourceAdapter fail = new(options with { OversizedRecords = SqlServerOversizedRecordHandling.Fail }, new NoCursorStore());
        Assert.Throws<SqlServerSourceRecordTooLargeException>(() => fail.BuildBatch([row], SqlServerSourceCursor.Initial(options), 0));
    }

    [Fact]
    public void CursorV1_UpgradesAndUnknownVersionIsRefused()
    {
        SqlServerSourceOptions options = ValidOptions();
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore());
        var upgraded = adapter.DeserializeCursor("""{"schemaVersion":1,"kind":0,"sequence":7,"eventTime":"2026-01-01T00:00:00Z"}""");
        Assert.Equal(2, upgraded.SchemaVersion);
        Assert.Equal(7, upgraded.Sequence);
        Assert.Throws<InvalidSourceCursorException>(() => adapter.DeserializeCursor("""{"schemaVersion":3,"kind":0,"sequence":7,"eventTime":"2026-01-01T00:00:00Z"}"""));
    }
}
