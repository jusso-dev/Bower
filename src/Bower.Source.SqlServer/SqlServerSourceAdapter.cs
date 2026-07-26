using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Bower.Source.SqlServer;

public sealed record SqlServerSourceRecord(
    long Sequence,
    DateTimeOffset EventTime,
    string OriginalId,
    string? Username,
    string? Action,
    string? TargetType,
    string? TargetId,
    string? PreviousValue,
    string? NewValue,
    string? SourceIpAddress,
    string Fingerprint);

public sealed record SqlServerCursorCheckpoint(
    string SourceId,
    long ExpectedVersion,
    string Value);

public sealed record SqlServerPollBatch(
    IReadOnlyList<SqlServerSourceRecord> Records,
    SqlServerCursorCheckpoint? Checkpoint);

public sealed class SqlServerSourceAdapter
{
    private static readonly JsonSerializerOptions CursorJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly SqlServerSourceOptions options;
    private readonly ISourceCursorStore cursorStore;
    private readonly IClock clock;

    public SqlServerSourceAdapter(
        SqlServerSourceOptions options,
        ISourceCursorStore cursorStore,
        IClock? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(cursorStore);
        options.Validate();
        this.options = options;
        this.cursorStore = cursorStore;
        this.clock = clock ?? new SystemClock();
    }

    public async Task<SqlServerPollBatch> PollAsync(
        CancellationToken cancellationToken = default)
    {
        SourceCursorSnapshot? snapshot = await cursorStore.ReadAsync(
            options.SourceId,
            cancellationToken);
        SqlServerSourceCursor cursor = snapshot is null
            ? SqlServerSourceCursor.Initial(options)
            : DeserializeCursor(snapshot.Value);

        await using SqlServerAuditDbContext context = new(options);
        IQueryable<SqlServerAuditRow> query = BuildQuery(context.AuditRows, cursor);
        List<SqlServerAuditRow> rows = await query
            .Take(options.BatchSize)
            .ToListAsync(cancellationToken);

        if (rows.Count == 0)
        {
            return new SqlServerPollBatch([], null);
        }

        List<SqlServerSourceRecord> records = new(rows.Count);
        SqlServerSourceCursor next = cursor;
        foreach (SqlServerAuditRow row in rows)
        {
            SqlServerSourceCursor candidate = new(
                1,
                options.CursorKind,
                row.Sequence,
                row.EventTime.ToUniversalTime());
            next = Max(next, candidate);

            SqlServerSourceRecord record = Map(row);
            int size = JsonSerializer.SerializeToUtf8Bytes(record).Length;
            if (size > options.MaximumRecordBytes)
            {
                throw new SqlServerSourceRecordTooLargeException(
                    options.SourceId,
                    row.Sequence,
                    size,
                    options.MaximumRecordBytes);
            }

            records.Add(record);
        }

        if (rows.Count == options.BatchSize &&
            options.TimestampOverlap > TimeSpan.Zero &&
            Compare(next, cursor) <= 0)
        {
            throw new SqlServerOverlapWindowSaturatedException(options.SourceId);
        }

        SqlServerCursorCheckpoint? checkpoint = Compare(next, cursor) > 0
            ? new SqlServerCursorCheckpoint(
                options.SourceId,
                snapshot?.Version ?? 0,
                JsonSerializer.Serialize(next, CursorJsonOptions))
            : null;

        return new SqlServerPollBatch(records, checkpoint);
    }

    public async Task CommitAsync(
        SqlServerCursorCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (!string.Equals(checkpoint.SourceId, options.SourceId, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Checkpoint belongs to a different source.",
                nameof(checkpoint));
        }

        bool advanced = await cursorStore.TryAdvanceAsync(
            checkpoint.SourceId,
            checkpoint.ExpectedVersion,
            checkpoint.Value,
            clock.UtcNow,
            cancellationToken);
        if (!advanced)
        {
            throw new SourceCursorConflictException(options.SourceId);
        }
    }

    private IQueryable<SqlServerAuditRow> BuildQuery(
        IQueryable<SqlServerAuditRow> rows,
        SqlServerSourceCursor cursor)
    {
        return options.CursorKind switch
        {
            SqlServerCursorKind.Incrementing => rows
                .Where(row => row.Sequence > cursor.Sequence)
                .OrderBy(row => row.Sequence),
            SqlServerCursorKind.Timestamp => rows
                .Where(row => row.EventTime >= cursor.EventTime - options.TimestampOverlap)
                .OrderBy(row => row.EventTime)
                .ThenBy(row => row.Sequence),
            SqlServerCursorKind.Composite => rows
                .Where(
                    row =>
                        row.EventTime > cursor.EventTime ||
                        (row.EventTime == cursor.EventTime && row.Sequence > cursor.Sequence))
                .OrderBy(row => row.EventTime)
                .ThenBy(row => row.Sequence),
            _ => throw new InvalidOperationException("Unsupported SQL cursor kind.")
        };
    }

    private SqlServerSourceRecord Map(SqlServerAuditRow row)
    {
        string originalId = row.Sequence.ToString(CultureInfo.InvariantCulture);
        string fingerprintMaterial = string.Join(
            '\u001f',
            options.SourceId,
            row.Sequence.ToString(CultureInfo.InvariantCulture),
            row.EventTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        string fingerprint = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintMaterial)))
            .ToLowerInvariant();

        return new SqlServerSourceRecord(
            row.Sequence,
            row.EventTime.ToUniversalTime(),
            originalId,
            row.Username,
            row.Action,
            row.TargetType,
            row.TargetId,
            row.PreviousValue,
            row.NewValue,
            row.SourceIpAddress,
            fingerprint);
    }

    private SqlServerSourceCursor DeserializeCursor(string value)
    {
        try
        {
            SqlServerSourceCursor cursor =
                JsonSerializer.Deserialize<SqlServerSourceCursor>(value, CursorJsonOptions)
                ?? throw new JsonException("Cursor is empty.");
            if (cursor.SchemaVersion != 1 || cursor.Kind != options.CursorKind)
            {
                throw new JsonException("Cursor version or kind does not match source.");
            }

            return cursor;
        }
        catch (JsonException exception)
        {
            throw new InvalidSourceCursorException(options.SourceId, exception);
        }
    }

    private static SqlServerSourceCursor Max(
        SqlServerSourceCursor left,
        SqlServerSourceCursor right)
    {
        return Compare(left, right) >= 0 ? left : right;
    }

    private static int Compare(SqlServerSourceCursor left, SqlServerSourceCursor right)
    {
        if (left.Kind == SqlServerCursorKind.Incrementing)
        {
            return left.Sequence.CompareTo(right.Sequence);
        }

        int timestamp = left.EventTime.CompareTo(right.EventTime);
        return timestamp != 0 ? timestamp : left.Sequence.CompareTo(right.Sequence);
    }
}

internal sealed record SqlServerSourceCursor(
    int SchemaVersion,
    SqlServerCursorKind Kind,
    long Sequence,
    DateTimeOffset EventTime)
{
    public static SqlServerSourceCursor Initial(SqlServerSourceOptions options)
    {
        return new SqlServerSourceCursor(
            1,
            options.CursorKind,
            options.InitialSequence,
            options.InitialTimestamp.ToUniversalTime());
    }
}

public sealed class SourceCursorConflictException(string sourceId)
    : InvalidOperationException(
        $"Source cursor for '{sourceId}' changed before checkpoint commit.");

public sealed class InvalidSourceCursorException(string sourceId, Exception innerException)
    : InvalidOperationException(
        $"Stored cursor for source '{sourceId}' is invalid.",
        innerException);

public sealed class SqlServerOverlapWindowSaturatedException(string sourceId)
    : InvalidOperationException(
        $"Timestamp overlap for source '{sourceId}' filled the complete batch without advancing. Reduce overlap or increase batch size.");

public sealed class SqlServerSourceRecordTooLargeException(
    string sourceId,
    long sequence,
    int actualBytes,
    int maximumBytes)
    : InvalidOperationException(
        $"SQL source '{sourceId}' record at sequence {sequence} is {actualBytes} bytes; maximum is {maximumBytes} bytes.");
