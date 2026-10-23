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
    string Fingerprint,
    bool ValuesOmitted = false);

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
    private readonly TimeProvider clock;

    public SqlServerSourceAdapter(
        SqlServerSourceOptions options,
        ISourceCursorStore cursorStore,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(cursorStore);
        options.Validate();
        this.options = options;
        this.cursorStore = cursorStore;
        this.clock = clock ?? TimeProvider.System;
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
        List<SqlServerAuditRow> rows = await BoundProjection(query.Take(options.BatchSize))
            .ToListAsync(cancellationToken);

        return BuildBatch(rows, cursor, snapshot?.Version ?? 0);
    }

    internal SqlServerPollBatch BuildBatch(
        IReadOnlyList<SqlServerAuditRow> rows,
        SqlServerSourceCursor cursor,
        long expectedVersion)
    {
        DateTimeOffset settledBefore = clock.GetUtcNow() - options.CommitSettleDelay;
        bool holdBackRecent = options.CommitSettleDelay > TimeSpan.Zero
            && options.CursorKind != SqlServerCursorKind.Timestamp;
        List<SqlServerSourceRecord> records = new(rows.Count);
        SqlServerSourceCursor next = cursor;
        foreach (SqlServerAuditRow row in rows)
        {
            if (holdBackRecent && row.EventTime.ToUniversalTime() > settledBefore)
            {
                // Rows are ordered by the cursor; stop here and pick this row up next poll.
                break;
            }

            SqlServerSourceCursor candidate = new(
                2,
                options.CursorKind,
                row.Sequence,
                row.EventTime.ToUniversalTime());
            records.Add(MapBounded(row));
            next = cursor.ReplayTime is null
                ? Max(next, candidate)
                : next with { ReplayTime = row.EventTime.ToUniversalTime(), ReplaySequence = row.Sequence };
        }

        // Forward progress and overlap replay use independent keyset positions. A replay
        // sweep has a fixed upper bound, so tied timestamps never pin the first page.
        if (options.CursorKind == SqlServerCursorKind.Timestamp && rows.Count < options.BatchSize)
        {
            next = cursor.ReplayTime is not null
                ? next with { ReplayTime = null, ReplaySequence = long.MinValue }
                : options.TimestampOverlap > TimeSpan.Zero
                    ? next with { ReplayTime = next.EventTime - options.TimestampOverlap, ReplaySequence = long.MinValue }
                    : next;
        }

        SqlServerCursorCheckpoint? checkpoint = next != cursor
            ? new SqlServerCursorCheckpoint(options.SourceId, expectedVersion,
                JsonSerializer.Serialize(next with { SchemaVersion = 2 }, CursorJsonOptions))
            : null;

        return new SqlServerPollBatch(records, checkpoint);
    }

    private SqlServerSourceRecord MapBounded(SqlServerAuditRow row)
    {
        if (row.OversizedIdentity || (row.OversizedValues && options.OversizedRecords == SqlServerOversizedRecordHandling.Fail))
        {
            throw new SqlServerSourceRecordTooLargeException(options.SourceId, row.Sequence,
                -1, options.MaximumRecordBytes);
        }

        SqlServerSourceRecord record = Map(row) with { ValuesOmitted = row.ValuesOmitted };
        int size = JsonSerializer.SerializeToUtf8Bytes(record).Length;
        if (size <= options.MaximumRecordBytes)
        {
            return record;
        }

        if (options.OversizedRecords == SqlServerOversizedRecordHandling.OmitValues)
        {
            // Keep the audit fact (who, what, when) and drop the unbounded value columns so
            // one large row cannot block the source permanently.
            SqlServerSourceRecord trimmed = record with
            {
                PreviousValue = null,
                NewValue = null,
                ValuesOmitted = true
            };
            if (JsonSerializer.SerializeToUtf8Bytes(trimmed).Length <= options.MaximumRecordBytes)
            {
                return trimmed;
            }
        }

        throw new SqlServerSourceRecordTooLargeException(
            options.SourceId,
            row.Sequence,
            size,
            options.MaximumRecordBytes);
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
            clock.GetUtcNow(),
            cancellationToken);
        if (!advanced)
        {
            throw new SourceCursorConflictException(options.SourceId);
        }
    }

    internal IQueryable<SqlServerAuditRow> BuildQuery(
        IQueryable<SqlServerAuditRow> rows,
        SqlServerSourceCursor cursor)
    {
        return options.CursorKind switch
        {
            SqlServerCursorKind.Incrementing => rows
                .Where(row => row.Sequence > cursor.Sequence)
                .OrderBy(row => row.Sequence),
            SqlServerCursorKind.Timestamp when cursor.ReplayTime is DateTimeOffset replayTime => rows
                .Where(row => (row.EventTime > replayTime ||
                    (row.EventTime == replayTime && row.Sequence > cursor.ReplaySequence)) &&
                    (row.EventTime < cursor.EventTime ||
                    (row.EventTime == cursor.EventTime && row.Sequence <= cursor.Sequence)))
                .OrderBy(row => row.EventTime).ThenBy(row => row.Sequence),
            SqlServerCursorKind.Timestamp => rows
                .Where(row => row.EventTime > cursor.EventTime ||
                    (row.EventTime == cursor.EventTime && row.Sequence > cursor.Sequence))
                .OrderBy(row => row.EventTime).ThenBy(row => row.Sequence),
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

    internal IQueryable<SqlServerAuditRow> BoundProjection(IQueryable<SqlServerAuditRow> rows)
    {
        int limit = options.MaximumRecordBytes;
        return rows.Select(row => new
        {
            Row = row,
            IdentityBytes = (long)(EF.Functions.DataLength(row.Username) ?? 0)
                + (EF.Functions.DataLength(row.Action) ?? 0)
                + (EF.Functions.DataLength(row.TargetType) ?? 0)
                + (EF.Functions.DataLength(row.TargetId) ?? 0)
                + (EF.Functions.DataLength(row.SourceIpAddress) ?? 0),
            ValueBytes = (long)(EF.Functions.DataLength(row.PreviousValue) ?? 0)
                + (EF.Functions.DataLength(row.NewValue) ?? 0)
        }).Select(value => new SqlServerAuditRow
        {
            Sequence = value.Row.Sequence,
            EventTime = value.Row.EventTime,
            Username = value.IdentityBytes <= limit ? value.Row.Username : null,
            Action = value.IdentityBytes <= limit ? value.Row.Action : null,
            TargetType = value.IdentityBytes <= limit ? value.Row.TargetType : null,
            TargetId = value.IdentityBytes <= limit ? value.Row.TargetId : null,
            SourceIpAddress = value.IdentityBytes <= limit ? value.Row.SourceIpAddress : null,
            PreviousValue = value.ValueBytes <= limit ? value.Row.PreviousValue : null,
            NewValue = value.ValueBytes <= limit ? value.Row.NewValue : null,
            OversizedIdentity = value.IdentityBytes > limit,
            OversizedValues = value.ValueBytes > limit,
            ValuesOmitted = value.ValueBytes > limit
        });
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

    internal SqlServerSourceCursor DeserializeCursor(string value)
    {
        try
        {
            SqlServerSourceCursor cursor =
                JsonSerializer.Deserialize<SqlServerSourceCursor>(value, CursorJsonOptions)
                ?? throw new JsonException("Cursor is empty.");
            if (cursor.SchemaVersion is not (1 or 2) || cursor.Kind != options.CursorKind
                || (cursor.ReplayTime is not null && (cursor.Kind != SqlServerCursorKind.Timestamp || cursor.ReplayTime > cursor.EventTime)))
            {
                throw new JsonException("Cursor version or kind does not match source.");
            }

            return cursor with { SchemaVersion = 2 };
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
    DateTimeOffset EventTime,
    DateTimeOffset? ReplayTime = null,
    long ReplaySequence = long.MinValue)
{
    public static SqlServerSourceCursor Initial(SqlServerSourceOptions options)
    {
        return new SqlServerSourceCursor(
            2,
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
    : InvalidOperationException(actualBytes < 0
        ? $"SQL source '{sourceId}' record at sequence {sequence} exceeds the bounded source projection ({maximumBytes} bytes per column group)."
        : $"SQL source '{sourceId}' record at sequence {sequence} is {actualBytes} bytes; maximum is {maximumBytes} bytes.");
