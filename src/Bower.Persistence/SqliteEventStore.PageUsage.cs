using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// Read-only page accounting of the queue database. New events are refused once in-use
/// pages reach <see cref="PageLimit"/> (85% of <c>BOWER_QUEUE_MAX_BYTES</c> + 4 MiB); the
/// rest, up to <see cref="CeilingPages"/> (SQLite <c>max_page_count</c>), is kept for
/// leasing, acknowledgement and retries, which enlarge rows. In-use pages, not the file
/// length, show how close the queue is to refusing events: pages freed by delivery and
/// retention stay in the free list and are reused first (or, for queues created with
/// incremental vacuum, returned to the file system under pressure).
/// </summary>
public sealed record QueuePageUsage(long PageSize, long PageCount, long FreeListPages, long PageLimit, long CeilingPages = 0)
{
    /// <summary>In-use bytes at which new events are refused.</summary>
    public long PageLimitBytes => PageLimit * PageSize;

    /// <summary>Largest size the database file may reach (settlement only).</summary>
    public long CeilingBytes => (CeilingPages > 0 ? CeilingPages : PageLimit) * PageSize;

    /// <summary>Pages holding rows, indexes and the ledger.</summary>
    public long UsedBytes => Math.Max(0, PageCount - FreeListPages) * PageSize;

    /// <summary>Free pages inside the file, available for reuse.</summary>
    public long FreeListBytes => FreeListPages * PageSize;

    /// <summary>In-use pages as a share of <see cref="PageLimit"/>, 0-100, one decimal: at 100 new events are refused.</summary>
    public double UsedPercent => PageLimit <= 0
        ? 0
        : Math.Min(100.0, Math.Round(100.0 * Math.Max(0, PageCount - FreeListPages) / PageLimit, 1));
}

/// <summary>A queue that can report <see cref="QueuePageUsage"/>.</summary>
public interface IQueuePageUsageSource
{
    Task<QueuePageUsage> GetPageUsageAsync(CancellationToken cancellationToken = default);
}

public sealed partial class SqliteEventStore : IQueuePageUsageSource
{
    /// <summary>
    /// Reads page size, page count, free-list pages and the effective ceiling from SQLite on
    /// its own connection; the intake limit is the one every insert checks. Never writes and
    /// never takes the write lock.
    /// </summary>
    public async Task<QueuePageUsage> GetPageUsageAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        async Task<long> PragmaAsync(string name)
        {
            command.CommandText = $"PRAGMA {name};";
            return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }

        long pageSize = await PragmaAsync("page_size");
        long pageCount = await PragmaAsync("page_count");
        long freeList = await PragmaAsync("freelist_count");
        long ceiling = await PragmaAsync("max_page_count");
        return new QueuePageUsage(pageSize, pageCount, freeList, IntakePageLimit(MaximumStorageBytes / 4 / pageSize, pageSize), ceiling);
    }
}
