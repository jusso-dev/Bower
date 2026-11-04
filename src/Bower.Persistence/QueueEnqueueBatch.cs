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
/// Nothing in the batch is durable before <see cref="CommitAsync"/> returns true: callers move
/// their cursor only after it. A refused or conflicting event rolls back to its savepoint and
/// leaves the others; any other failure breaks the batch, and dispose rolls everything back.
/// Signals that report an event as handled (selection counters, tap frames) are registered
/// with <see cref="WhenDurable"/> and run only after the commit, so a rolled-back read that is
/// read again is counted once.
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
    private List<Action>? durable;
    private List<Action<QueueCapacityExceededException>>? refused;
    private QueueCapacityExceededException? brokenRefusal;
    private int recordPending;
    private int recordDurable;
    private int recordRefused;
    private bool recordOpen;
    private bool recordMutated;

    internal QueueEnqueueBatch(SqliteEventStore store, SqliteConnection connection, SqliteTransaction transaction)
    {
        this.store = store;
        this.connection = connection;
        this.transaction = transaction;
    }

    /// <summary>Events enqueued (not duplicates or refusals) and not yet committed.</summary>
    public int Pending { get; private set; }

    /// <summary>Whether the cursor store is in this batch's queue database.</summary>
    public bool CanAdvanceCursor(ISourceCursorStore cursors) =>
        cursors is EfSourceCursorStore sqlite && store.SharesDatabase(sqlite);

    /// <summary>Starts a savepoint around one complete source record, including generated events.</summary>
    public void BeginRecord()
    {
        ObjectDisposedException.ThrowIf(!open, this);
        if (recordOpen || broken)
        {
            throw new InvalidOperationException("The batch cannot start another source record.");
        }

        transaction.Save("bower_source_record");
        recordPending = Pending;
        recordDurable = durable?.Count ?? 0;
        recordRefused = refused?.Count ?? 0;
        recordMutated = false;
        recordOpen = true;
    }

    /// <summary>Releases a handled record, or rolls back all effects and deferred signals of a refused one.</summary>
    public void EndRecord(bool handled)
    {
        if (!recordOpen)
        {
            throw new InvalidOperationException("No source record is open.");
        }

        recordOpen = false;
        if (handled)
        {
            transaction.Release("bower_source_record");
            return;
        }

        Undo("bower_source_record");
        Pending = recordPending;
        if (durable is not null)
        {
            durable.RemoveRange(recordDurable, durable.Count - recordDurable);
        }
        if (refused is not null)
        {
            refused.RemoveRange(recordRefused, refused.Count - recordRefused);
        }
    }

    /// <summary>Atomically commits the batch with a compare-and-swap cursor advance.</summary>
    public async Task<QueueBatchCursorResult> CommitWithCursorAsync(
        ISourceCursorStore cursors, string sourceId, long expectedVersion, string value,
        DateTimeOffset updatedAt, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(!open, this);
        if (!CanAdvanceCursor(cursors))
        {
            throw new InvalidOperationException("The cursor and queue must share the same SQLite database.");
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        ArgumentOutOfRangeException.ThrowIfNegative(expectedVersion);
        if (sourceId.Length > 128 || expectedVersion == long.MaxValue || recordOpen)
        {
            throw new ArgumentException("Invalid cursor or open source record.");
        }
        if (broken)
        {
            await CommitAsync(cancellationToken);
            return QueueBatchCursorResult.Refused;
        }

        try
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.Parameters.AddWithValue("$sourceId", sourceId);
            command.Parameters.AddWithValue("$value", value);
            command.Parameters.AddWithValue("$updatedAt", updatedAt.ToUniversalTime());
            command.Parameters.AddWithValue("$expected", expectedVersion);
            command.Parameters.AddWithValue("$next", expectedVersion + 1);
            command.CommandText = expectedVersion == 0
                ? """
                  INSERT INTO "source_cursors" ("SourceId", "Value", "Version", "UpdatedAt")
                  VALUES ($sourceId, $value, 1, $updatedAt) ON CONFLICT ("SourceId") DO NOTHING;
                  """
                : """
                  UPDATE "source_cursors" SET "Value" = $value, "Version" = $next, "UpdatedAt" = $updatedAt
                  WHERE "SourceId" = $sourceId AND "Version" = $expected;
                  """;
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                open = false;
                durable = null;
                refused = null;
                return QueueBatchCursorResult.Conflict;
            }
        }
        catch (SqliteException exception) when (store.AsCapacityRefusal(exception) is { } refusal)
        {
            open = false;
            durable = null;
            ReportRefusal(refusal);
            return QueueBatchCursorResult.Refused;
        }

        return await CommitAsync(cancellationToken) ? QueueBatchCursorResult.Committed : QueueBatchCursorResult.Refused;
    }

    /// <summary>
    /// Routes the calling flow's enqueues on this store into the batch. Call it directly from the
    /// reading method, not from an awaited helper: it sets async-local state, which flows to the
    /// calls that method makes afterwards and nowhere else (other sources, delivery and HTTP
    /// intake keep their own transactions and wait for the write lock).
    /// </summary>
    public void Join() => Ambient.Value = this;

    internal static QueueEnqueueBatch? Current(SqliteEventStore store) =>
        Ambient.Value is { open: true } batch && ReferenceEquals(batch.store, store) ? batch : null;

    /// <summary>Provisional inserts in the current batch, or null outside one.</summary>
    public static int? PendingCount(IDurableEventStore store) =>
        store is SqliteEventStore sqlite ? Current(sqlite)?.Pending : null;

    /// <summary>Whether the current flow is handling a batched source record.</summary>
    public static bool IsSourceRecord(IDurableEventStore store) =>
        store is SqliteEventStore sqlite && Current(sqlite) is { recordOpen: true };

    /// <summary>Whether this source record has a provisional queue or suppression write.</summary>
    public static bool SourceRecordMutated(IDurableEventStore store) =>
        store is SqliteEventStore sqlite && Current(sqlite) is { recordOpen: true, recordMutated: true };

    /// <summary>
    /// Runs <paramref name="action"/> once the calling flow's open batch on <paramref name="store"/>
    /// commits, and never if it rolls back; outside a batch it runs immediately. Use it for
    /// signals that claim an event was handled, not for refusals (which happened either way).
    /// </summary>
    public static void WhenDurable(IDurableEventStore store, Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (store is SqliteEventStore sqlite && Current(sqlite) is { } batch)
        {
            (batch.durable ??= []).Add(action);
            return;
        }

        action();
    }

    /// <summary>
    /// Registers a capacity signal for a successfully processed event in an open batch.
    /// It runs only if the batch subsequently fails for capacity, with the refusal reason.
    /// No action is needed outside a batch, where enqueue refusal is reported directly.
    /// </summary>
    public static void WhenRefused(IDurableEventStore store, Action<QueueCapacityExceededException> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (store is SqliteEventStore sqlite && Current(sqlite) is { } batch)
        {
            (batch.refused ??= []).Add(action);
        }
    }

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
            if (recordOpen && (result.Enqueued || result.Suppressed))
            {
                recordMutated = true;
            }
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
            if (broken && exception is QueueCapacityExceededException refusal)
            {
                brokenRefusal = refusal;
            }
            throw;
        }
        catch (SqliteException exception) when (store.AsCapacityRefusal(exception) is { } refusal)
        {
            Undo(savepoint);
            if (broken)
            {
                brokenRefusal = refusal;
            }
            throw refusal;
        }
        catch
        {
            broken = true;
            throw;
        }
    }

    /// <summary>
    /// Makes every event enqueued in the batch durable at once, then runs the
    /// <see cref="WhenDurable"/> actions. Returns false, with nothing written, when the queue
    /// refused the batch: the volume or page ceiling was reached at commit, or an earlier
    /// refusal lost the transaction (SQLite rolled it back). Callers treat that as
    /// backpressure, like a refused event. The batch is closed afterwards either way.
    /// </summary>
    public async Task<bool> CommitAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(!open, this);
        open = false;
        if (broken)
        {
            durable = null;
            ReportRefusal(brokenRefusal);
            return false;
        }

        try
        {
            if (store.BatchCommitFaultForTesting?.Invoke() is { } fault)
            {
                throw fault;
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch (SqliteException exception) when (store.AsCapacityRefusal(exception) is { } refusal)
        {
            durable = null;
            ReportRefusal(refusal);
            return false;
        }

        List<Action>? actions = durable;
        durable = null;
        refused = null;
        foreach (Action action in actions ?? [])
        {
            RunSignal(action);
        }

        return true;
    }

    /// <summary>Rolls back anything not committed and releases the connection.</summary>
    public async ValueTask DisposeAsync()
    {
        // The async-local set by Join lives in the reader's flow and cannot be cleared from
        // here; closing the batch is what stops Current from returning it.
        open = false;
        durable = null;
        refused = null;
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
        catch (Exception exception) when (exception is SqliteException or InvalidOperationException)
        {
            // SQLite already rolled the whole transaction back (for example after an I/O
            // error): nothing in the batch can commit.
            broken = true;
        }
    }

    private void ReportRefusal(QueueCapacityExceededException? reason)
    {
        List<Action<QueueCapacityExceededException>>? actions = refused;
        refused = null;
        if (reason is not null)
        {
            foreach (Action<QueueCapacityExceededException> action in actions ?? [])
            {
                RunSignal(() => action(reason));
            }
        }
    }

    // These signals are observational. Once SQLite commits, a faulty observer must not make
    // the caller believe the transaction failed or prevent later observers from running.
    private static void RunSignal(Action action)
    {
        try
        {
            action();
        }
        catch (Exception)
        {
            // No payload or exception text: observers may handle sensitive event content.
            try
            {
                System.Diagnostics.Trace.TraceWarning("A queue batch signal failed.");
            }
            catch (Exception)
            {
                // A trace listener must not change the commit result either.
            }
        }
    }
}

/// <summary>Outcome of an atomic queue and source-cursor commit.</summary>
public enum QueueBatchCursorResult
{
    Committed,
    Refused,
    Conflict
}
