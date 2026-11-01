using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// Read-only page accounting of the queue database. The database cannot grow past
/// <see cref="PageLimit"/> pages (SQLite <c>max_page_count</c>), so in-use pages, not the
/// file length, show how close the queue is to "database or disk is full". The file never
/// shrinks (no vacuum): pages freed by delivery and retention stay in the free list and are
/// reused first.
/// </summary>
public sealed record QueuePageUsage(long PageSize, long PageCount, long FreeListPages, long PageLimit)
{
    /// <summary>Largest size the database file may reach.</summary>
    public long PageLimitBytes => PageLimit * PageSize;

    /// <summary>Pages holding rows, indexes and the ledger.</summary>
    public long UsedBytes => Math.Max(0, PageCount - FreeListPages) * PageSize;

    /// <summary>Free pages inside the file, available for reuse.</summary>
    public long FreeListBytes => FreeListPages * PageSize;

    /// <summary>In-use pages as a share of the page limit, 0-100, one decimal.</summary>
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
    /// Reads page size, page count, free-list pages and the effective page limit from SQLite
    /// on its own connection. Never writes and never takes the write lock; the limit is the
    /// one the store applies to every connection, so it is read rather than recomputed.
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
        long limit = await PragmaAsync("max_page_count");
        return new QueuePageUsage(pageSize, pageCount, freeList, limit);
    }
}
