using Bower.Persistence;
using Bower.Source.SqlServer;
using Microsoft.EntityFrameworkCore;

namespace Bower.UnitTests;

public sealed partial class SqlServerSourceAdapterTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TimestampReplay_RecoversPinnedOverlapWhileForwardPagesStayFull(bool continuousBacklog)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "cursor.db");
        DateTimeOffset origin = TestEvents.Now.AddHours(-1);
        SqlServerSourceOptions options = ValidOptions() with
        {
            CursorKind = SqlServerCursorKind.Timestamp,
            InitialTimestamp = origin.AddSeconds(100),
            InitialSequence = 100,
            BatchSize = 2,
            TimestampOverlap = TimeSpan.FromSeconds(60)
        };
        List<SqlServerAuditRow> rows = Enumerable.Range(201, continuousBacklog ? 100 : 4)
            .Select(id => Row(id, origin.AddSeconds(id))).ToList();
        HashSet<long> seen = [];
        for (int page = 0; page < 16; page++)
        {
            // Reopen both the adapter and its durable cursor store on every page.
            var (adapter, batch) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
            Assert.InRange(batch.Records.Count, 0, options.BatchSize);
            seen.UnionWith(batch.Records.Select(record => record.Sequence));
            if (batch.Checkpoint is not null)
            {
                await adapter.CommitAsync(batch.Checkpoint, cancellation);
            }
            if (page == 0)
            {
                // Commit becomes visible after the first full page has moved 100 to 202.
                // All these rows belonged to the pending [40, 100] overlap at that point.
                rows.Add(Row(900, origin.AddSeconds(40)));
                rows.AddRange(Enumerable.Range(901, 6).Select(id => Row(id, origin.AddSeconds(90))));
                rows.Add(Row(99, origin.AddSeconds(100)));
            }
        }

        Assert.Subset(seen, Enumerable.Range(900, 7).Select(id => (long)id).Append(99).ToHashSet());
        if (continuousBacklog)
        {
            // A multi-page replay must not stop the forward stream either.
            Assert.True(seen.Count(id => id is >= 201 and < 900) >= 16);
        }
    }

    [Fact]
    public async Task TimestampReplay_NextSweepCoversForwardProgressDuringPreviousSweep()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "cursor.db");
        DateTimeOffset origin = TestEvents.Now.AddHours(-1);
        SqlServerSourceOptions options = ValidOptions() with
        {
            CursorKind = SqlServerCursorKind.Timestamp,
            InitialTimestamp = origin.AddSeconds(100),
            InitialSequence = 100,
            BatchSize = 2,
            TimestampOverlap = TimeSpan.FromSeconds(60)
        };
        List<SqlServerAuditRow> rows = Enumerable.Range(1, 100)
            .Select(id => Row(id, origin.AddSeconds(id * 200))).ToList();
        rows.AddRange(Enumerable.Range(901, 6).Select(id => Row(id, origin.AddSeconds(90))));
        HashSet<long> seen = [];
        for (int page = 0; page < 30; page++)
        {
            var (adapter, batch) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
            seen.UnionWith(batch.Records.Select(record => record.Sequence));
            if (batch.Checkpoint is not null)
            {
                await adapter.CommitAsync(batch.Checkpoint, cancellation);
            }
            if (page == 2)
            {
                // The active sweep ends at 400, but forward polling already reached 800.
                // This row needs the next sweep, even if forward polling advances again.
                rows.Add(Row(999, origin.AddSeconds(750)));
            }
        }

        Assert.Contains(999, seen);
        Assert.True(seen.Count(id => id < 900) >= 30);
    }

    [Fact]
    public async Task TimestampReplay_UncommittedPageRepeatsAndStaleCommitCannotSkipTies()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "cursor.db");
        DateTimeOffset origin = TestEvents.Now.AddHours(-1);
        SqlServerSourceOptions options = ValidOptions() with
        {
            CursorKind = SqlServerCursorKind.Timestamp,
            InitialTimestamp = origin.AddSeconds(100),
            BatchSize = 2,
            TimestampOverlap = TimeSpan.FromSeconds(60)
        };
        List<SqlServerAuditRow> rows = Enumerable.Range(1, 6)
            .Select(id => Row(id, origin.AddSeconds(90))).ToList();
        rows.AddRange(Enumerable.Range(201, 6).Select(id => Row(id, origin.AddSeconds(200))));
        var (first, forward) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
        await first.CommitAsync(forward.Checkpoint!, cancellation);

        // Simulate termination after accepting a page but before committing its checkpoint.
        var (crashed, uncommitted) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
        var (restarted, repeated) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
        Assert.Equal(new long[] { 1, 2 }, repeated.Records.Select(record => record.Sequence));
        Assert.Equal(uncommitted.Records, repeated.Records);
        Assert.Equal(uncommitted.Checkpoint, repeated.Checkpoint);
        await restarted.CommitAsync(repeated.Checkpoint!, cancellation);
        await Assert.ThrowsAsync<SourceCursorConflictException>(
            () => crashed.CommitAsync(uncommitted.Checkpoint!, cancellation));

        var (next, nextForward) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
        Assert.Equal(new long[] { 203, 204 }, nextForward.Records.Select(record => record.Sequence));
        await next.CommitAsync(nextForward.Checkpoint!, cancellation);
        SqlServerSourceCursor cursor = next.DeserializeCursor(nextForward.Checkpoint!.Value);
        Assert.Equal(202, cursor.ReplayUpperSequence);
        Assert.Equal(204, cursor.Sequence);
        Assert.DoesNotContain(next.BuildQuery(rows.AsQueryable(), cursor), row => row.Sequence is 203 or 204);

        var (_, nextReplay) = await ReadReplayTestPageAsync(path, options, rows, cancellation);
        Assert.Equal(new long[] { 3, 4 }, nextReplay.Records.Select(record => record.Sequence));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void TimestampCursor_LegacyForwardStateStartsReplayFromPreAdvanceWatermark(int version)
    {
        SqlServerSourceOptions options = ValidOptions() with
        {
            CursorKind = SqlServerCursorKind.Timestamp,
            BatchSize = 1,
            TimestampOverlap = TimeSpan.FromSeconds(60)
        };
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore());
        var cursor = adapter.DeserializeCursor($$"""{"schemaVersion":{{version}},"kind":1,"sequence":100,"eventTime":"2026-01-01T00:01:40Z"}""");
        DateTimeOffset watermark = cursor.EventTime;
        var batch = adapter.BuildBatch([Row(200, watermark.AddSeconds(100))], cursor, 7);
        var migrated = adapter.DeserializeCursor(batch.Checkpoint!.Value);

        Assert.Equal(3, migrated.SchemaVersion);
        Assert.Equal(watermark.AddSeconds(-60), migrated.ReplayTime);
        Assert.Equal(watermark.AddSeconds(100), migrated.ReplayUpperTime);
        Assert.True(migrated.ReplayNext);
        Assert.Equal(7, batch.Checkpoint.ExpectedVersion);
    }

    [Fact]
    public void TimestampCursor_V2ResumesPartialReplayWithoutChangingBounds()
    {
        SqlServerSourceOptions options = ValidOptions() with { CursorKind = SqlServerCursorKind.Timestamp };
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore());
        var cursor = adapter.DeserializeCursor("""{"schemaVersion":2,"kind":1,"sequence":100,"eventTime":"2026-01-01T00:01:40Z","replayTime":"2026-01-01T00:01:30Z","replaySequence":3}""");
        SqlServerAuditRow[] rows =
        [
            Row(3, cursor.ReplayTime!.Value),
            Row(4, cursor.ReplayTime.Value),
            Row(99, cursor.EventTime),
            Row(100, cursor.EventTime),
            Row(101, cursor.EventTime)
        ];

        Assert.Equal(3, cursor.SchemaVersion);
        Assert.True(cursor.ReplayNext);
        Assert.Equal(cursor.EventTime, cursor.ReplayUpperTime);
        Assert.Equal(new long[] { 4, 99, 100 }, adapter.BuildQuery(rows.AsQueryable(), cursor).Select(row => row.Sequence));
    }

    [Theory]
    [InlineData("\"replayNext\":true")]
    [InlineData("\"replayTime\":\"2026-01-01T00:00:00Z\"")]
    [InlineData("\"replayUpperTime\":\"2026-01-02T00:00:00Z\"")]
    [InlineData("\"replayUpperTime\":\"2026-01-01T00:01:40Z\",\"replayUpperSequence\":101")]
    [InlineData("\"replayTime\":\"2026-01-01T00:01:30Z\",\"replayUpperTime\":\"2026-01-01T00:01:00Z\"")]
    [InlineData("\"replayTime\":\"2026-01-01T00:01:30Z\",\"replaySequence\":5,\"replayUpperTime\":\"2026-01-01T00:01:30Z\",\"replayUpperSequence\":4")]
    public void TimestampCursor_RejectsMalformedV3ReplayBounds(string replayMembers)
    {
        SqlServerSourceAdapter adapter = new(ValidOptions() with { CursorKind = SqlServerCursorKind.Timestamp }, new NoCursorStore());
        Assert.Throws<InvalidSourceCursorException>(() => adapter.DeserializeCursor(
            $$"""{"schemaVersion":3,"kind":1,"sequence":100,"eventTime":"2026-01-01T00:01:40Z",{{replayMembers}}}"""));
    }

    [Fact]
    public void TimestampReplay_GeneratedSqlUsesFixedUpperKeysetAndBoundedProjection()
    {
        SqlServerSourceOptions options = ValidOptions() with { CursorKind = SqlServerCursorKind.Timestamp };
        SqlServerSourceAdapter adapter = new(options, new NoCursorStore());
        var cursor = adapter.DeserializeCursor("""{"schemaVersion":3,"kind":1,"sequence":200,"eventTime":"2026-01-01T00:03:20Z","replayTime":"2026-01-01T00:01:30Z","replaySequence":3,"replayUpperTime":"2026-01-01T00:01:40Z","replayUpperSequence":100,"replayNext":true}""");
        using SqlServerAuditDbContext context = new(options);
        string sql = adapter.BoundProjection(adapter.BuildQuery(context.AuditRows, cursor).Take(options.BatchSize)).ToQueryString();

        Assert.Contains("ReplayUpperTime", sql, StringComparison.Ordinal);
        Assert.Contains("ReplayUpperSequence", sql, StringComparison.Ordinal);
        Assert.Contains("[AuditId] <=", sql, StringComparison.Ordinal);
        Assert.Contains("[AuditId] >", sql, StringComparison.Ordinal);
        Assert.Contains("ORDER BY", sql, StringComparison.Ordinal);
        Assert.Contains("TOP(", sql, StringComparison.Ordinal);
        Assert.Contains("DATALENGTH", sql, StringComparison.Ordinal);
    }

    private static async Task<(SqlServerSourceAdapter Adapter, SqlServerPollBatch Batch)> ReadReplayTestPageAsync(
        string path,
        SqlServerSourceOptions options,
        List<SqlServerAuditRow> rows,
        CancellationToken cancellation)
    {
        EfSourceCursorStore store = new(path);
        await store.InitializeAsync(cancellation);
        SqlServerSourceAdapter adapter = new(options, store, new FakeClock(TestEvents.Now));
        var snapshot = await store.ReadAsync(options.SourceId, cancellation);
        var cursor = snapshot is null ? SqlServerSourceCursor.Initial(options) : adapter.DeserializeCursor(snapshot.Value);
        var selected = adapter.BuildQuery(rows.AsQueryable(), cursor).Take(options.BatchSize).ToArray();
        return (adapter, adapter.BuildBatch(selected, cursor, snapshot?.Version ?? 0));
    }
}
