using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// Group commit for one source read (<see cref="SqliteEventStore.BeginEnqueueBatchAsync"/>).
/// A durable enqueue costs a commit and a checkpoint, each flushed to disk; reading a
/// forwarded-events channel one event per commit is bound by that latency (about 45 events a
/// second on a gp3 WEC), so a burst became a backlog. In a batch, each enqueue is a savepoint
/// in one write transaction and the whole read becomes durable at one commit.
/// <para>
/// Nothing in the batch is durable before <see cref="CommitAsync"/> returns: callers move
/// their cursor only after it. A refused or conflicting event rolls back to its savepoint and
/// leaves the others; any other failure breaks the batch, and dispose rolls everything back.
/// </para>
/// </summary>
public sealed class QueueEnqueueBatch : IAsyncDisposable
{
    private static readonly AsyncLocal<QueueEnqueueBatch?> Ambient = new();
    private readonly SqliteEventStore store;
    private readonly SqliteConnection connection;
    private readonly SqliteTransaction transaction;
    private bool open = true;
    private bool broken;

    internal QueueEnqueueBatch(SqliteEventStore store, SqliteConnection connection, SqliteTransaction transaction)
    {
        this.store = store;
        this.connection = connection;
        this.transaction = transaction;
    }

    /// <summary>Events enqueued (not duplicates or refusals) and not yet committed.</summary>
    public int Pending { get; private set; }

    /// <summary>
    /// Routes the calling flow's enqueues on this store into the batch. Call it directly from the
    /// reading method, not from an awaited helper: it sets async-local state, which flows to the
    /// calls that method makes afterwards and nowhere else (other sources, delivery and HTTP
    /// intake keep their own transactions and wait for the write lock).
    /// </summary>
    public void Join() => Ambient.Value = this;

    internal static QueueEnqueueBatch? Current(SqliteEventStore store) =>
        Ambient.Value is { open: true } batch && ReferenceEquals(batch.store, store) ? batch : null;

    internal async Task<EnqueueResult> EnqueueAsync(QueuedEvent candidate, CancellationToken cancellationToken)
    {
        if (broken)
        {
            throw new InvalidOperationException("The enqueue batch failed; dispose it and read again.");
        }

        const string savepoint = "bower_enqueue";
        transaction.Save(savepoint);
        try
        {
            EnqueueResult result = await store.EnqueueInTransactionAsync(connection, transaction, candidate, cancellationToken);
            transaction.Release(savepoint);
            if (result.Enqueued)
            {
                Pending++;
            }

            return result;
        }
        catch (Exception exception) when (exception is QueueCapacityExceededException or EventIdentityConflictException or ArgumentException)
        {
            // Nothing of this event was written; the batch carries on without it.
            Undo(savepoint);
            throw;
        }
        catch (SqliteException exception) when (store.AsCapacityRefusal(exception) is { } refusal)
        {
            Undo(savepoint);
            throw refusal;
        }
        catch
        {
            broken = true;
            throw;
        }
    }

    /// <summary>Makes every event enqueued in the batch durable at once. The batch is closed afterwards.</summary>
    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(!open, this);
        if (broken)
        {
            throw new InvalidOperationException("The enqueue batch failed; dispose it and read again.");
        }

        open = false;
        try
        {
            await transaction.CommitAsync(cancellationToken);
        }
        catch (SqliteException exception) when (store.AsCapacityRefusal(exception) is { } refusal)
        {
            throw refusal;
        }
    }

    /// <summary>Rolls back anything not committed and releases the connection.</summary>
    public async ValueTask DisposeAsync()
    {
        open = false;
        if (Ambient.Value == this)
        {
            Ambient.Value = null;
        }

        await transaction.DisposeAsync();
        await connection.DisposeAsync();
    }

    private void Undo(string savepoint)
    {
        try
        {
            transaction.Rollback(savepoint);
            transaction.Release(savepoint);
        }
        catch (SqliteException)
        {
            // SQLite already rolled the whole transaction back (for example after an I/O
            // error): nothing in the batch can commit.
            broken = true;
        }
    }
}
