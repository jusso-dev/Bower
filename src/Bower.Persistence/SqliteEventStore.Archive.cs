using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

public sealed partial class SqliteEventStore
{
    /// <summary>
    /// Stored events with their ledger entries, in ledger order, after
    /// <paramref name="afterSequence"/>. Purged entries have no payload and are skipped, so a
    /// gap in the returned sequences means the events were purged before they were read.
    /// </summary>
    public async Task<IReadOnlyList<LedgerEvent>> ReadLedgerEventsAsync(
        long afterSequence,
        int maximumCount,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(afterSequence);
        if (maximumCount is < 1 or > 100_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT l.sequence, l.event_id, e.payload, l.received_at, l.chain_hash
            FROM queue_ledger l
            JOIN queue_events_v5 e ON e.enqueue_sequence = l.sequence AND e.event_id = l.event_id
            WHERE l.sequence > $after AND l.purged_at IS NULL
            ORDER BY l.sequence ASC
            LIMIT $maximum;
            """;
        command.Parameters.AddWithValue("$after", afterSequence);
        command.Parameters.AddWithValue("$maximum", maximumCount);

        List<LedgerEvent> rows = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new LedgerEvent(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4)));
        }

        return rows;
    }

    /// <summary>
    /// Chain hash recorded at <paramref name="sequence"/>: a ledger entry, the end of a
    /// compacted retention segment or the anchor; the genesis hash for 0. Null when the
    /// ledger no longer holds that boundary.
    /// </summary>
    public async Task<string?> GetLedgerHashAtAsync(long sequence, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sequence);
        if (sequence == 0)
        {
            return QueueLedger.GenesisHash();
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT chain_hash FROM queue_ledger WHERE sequence = $sequence
            UNION ALL SELECT chain_hash FROM queue_ledger_segments WHERE end_sequence = $sequence
            UNION ALL SELECT chain_hash FROM queue_ledger_anchor WHERE sequence = $sequence
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$sequence", sequence);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }

    /// <summary>
    /// Highest chain hash boundary the ledger records at or below
    /// <paramref name="sequence"/> (entry, compacted segment end or anchor); null when none.
    /// Every sequence above it and up to <paramref name="sequence"/> has been purged.
    /// </summary>
    public async Task<LedgerHead?> GetLedgerBoundaryAtOrBelowAsync(long sequence, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sequence);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT sequence, chain_hash FROM (
                SELECT * FROM (SELECT sequence, chain_hash FROM queue_ledger
                    WHERE sequence <= $sequence ORDER BY sequence DESC LIMIT 1)
                UNION ALL SELECT * FROM (SELECT end_sequence, chain_hash FROM queue_ledger_segments
                    WHERE end_sequence <= $sequence ORDER BY end_sequence DESC LIMIT 1)
                UNION ALL SELECT sequence, chain_hash FROM queue_ledger_anchor WHERE sequence <= $sequence
            ) ORDER BY sequence DESC LIMIT 1;
            """;
        command.Parameters.AddWithValue("$sequence", sequence);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) && !reader.IsDBNull(1)
            ? new LedgerHead(reader.GetInt64(0), reader.GetString(1))
            : null;
    }
}

/// <param name="ReceivedAt">Received time exactly as hashed into the ledger.</param>
public sealed record LedgerEvent(
    long Sequence,
    string EventId,
    string Payload,
    string ReceivedAt,
    string ChainHash);
