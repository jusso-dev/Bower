using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// Append-only hash chain over every event the queue accepts. Each entry commits to the
/// previous entry, the event id, a SHA-256 of the stored payload and the receive time,
/// so edited payloads, deleted rows and re-ordering are detectable. Retention marks
/// entries as purged instead of deleting them; compaction folds a fully purged prefix
/// into a signed-off anchor.
/// </summary>
internal static class QueueLedger
{
    internal const string Genesis = "bower-queue-ledger-v1";

    internal const string Schema =
        """
        CREATE TABLE IF NOT EXISTS queue_ledger (
            sequence INTEGER PRIMARY KEY NOT NULL,
            event_id TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            received_at TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            purged_at TEXT NULL
        );

        CREATE INDEX IF NOT EXISTS ix_queue_ledger_event ON queue_ledger(event_id);

        CREATE TABLE IF NOT EXISTS queue_ledger_anchor (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sequence INTEGER NOT NULL,
            chain_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
        VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v3-ledger');
        """;

    internal static string PayloadHash(string payload) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));

    internal static string Chain(string previous, long sequence, string eventId, string payloadHash, string receivedAt) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '\u001f',
            previous,
            sequence.ToString(CultureInfo.InvariantCulture),
            eventId,
            payloadHash,
            receivedAt))));

    internal static string GenesisHash() =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Genesis)));

    internal static async Task<(long Sequence, string Hash)> HeadAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT sequence, chain_hash FROM queue_ledger ORDER BY sequence DESC LIMIT 1;
            """;
        await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                return (reader.GetInt64(0), reader.GetString(1));
            }
        }

        return await AnchorAsync(connection, transaction, cancellationToken);
    }

    internal static async Task<(long Sequence, string Hash)> AnchorAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT sequence, chain_hash FROM queue_ledger_anchor WHERE id = 1;";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? (reader.GetInt64(0), reader.GetString(1))
            : (0, GenesisHash());
    }

    internal static async Task AppendAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string eventId,
        string payload,
        string receivedAt,
        CancellationToken cancellationToken)
    {
        (long sequence, string previous) = await HeadAsync(connection, transaction, cancellationToken);
        long next = sequence + 1;
        string payloadHash = PayloadHash(payload);
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO queue_ledger (sequence, event_id, payload_sha256, received_at, chain_hash)
            VALUES ($sequence, $event_id, $payload_sha256, $received_at, $chain_hash);
            """;
        command.Parameters.AddWithValue("$sequence", next);
        command.Parameters.AddWithValue("$event_id", eventId);
        command.Parameters.AddWithValue("$payload_sha256", payloadHash);
        command.Parameters.AddWithValue("$received_at", receivedAt);
        command.Parameters.AddWithValue("$chain_hash", Chain(previous, next, eventId, payloadHash, receivedAt));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Adds ledger entries for events stored before the ledger existed.</summary>
    internal static async Task BackfillAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using SqliteTransaction transaction =
            connection.BeginTransaction(System.Data.IsolationLevel.Serializable, deferred: false);
        List<(string EventId, string Payload, string ReceivedAt)> missing = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT e.event_id, e.payload, e.received_at
                FROM queue_events e
                WHERE NOT EXISTS (SELECT 1 FROM queue_ledger l WHERE l.event_id = e.event_id)
                ORDER BY e.received_at ASC, e.event_id ASC;
                """;
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                missing.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
            }
        }

        foreach ((string eventId, string payload, string receivedAt) in missing)
        {
            await AppendAsync(connection, transaction, eventId, payload, receivedAt, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    internal static async Task MarkPurgedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyCollection<string> eventIds,
        string purgedAt,
        CancellationToken cancellationToken)
    {
        foreach (string eventId in eventIds)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                "UPDATE queue_ledger SET purged_at = $purged_at WHERE event_id = $event_id AND purged_at IS NULL;";
            command.Parameters.AddWithValue("$purged_at", purgedAt);
            command.Parameters.AddWithValue("$event_id", eventId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <summary>Folds the longest fully purged prefix into the anchor and deletes it.</summary>
    internal static async Task<int> CompactAsync(
        SqliteConnection connection,
        string now,
        CancellationToken cancellationToken)
    {
        await using SqliteTransaction transaction =
            connection.BeginTransaction(System.Data.IsolationLevel.Serializable, deferred: false);
        await using SqliteCommand find = connection.CreateCommand();
        find.Transaction = transaction;
        find.CommandText =
            """
            SELECT sequence, chain_hash FROM queue_ledger
            WHERE sequence < COALESCE((SELECT MIN(sequence) FROM queue_ledger WHERE purged_at IS NULL), 9223372036854775807)
            ORDER BY sequence DESC LIMIT 1;
            """;
        long sequence;
        string hash;
        await using (SqliteDataReader reader = await find.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken))
            {
                return 0;
            }

            sequence = reader.GetInt64(0);
            hash = reader.GetString(1);
        }

        await using SqliteCommand anchor = connection.CreateCommand();
        anchor.Transaction = transaction;
        anchor.CommandText =
            """
            INSERT INTO queue_ledger_anchor (id, sequence, chain_hash, created_at)
            VALUES (1, $sequence, $hash, $now)
            ON CONFLICT(id) DO UPDATE SET sequence = excluded.sequence, chain_hash = excluded.chain_hash, created_at = excluded.created_at;
            """;
        anchor.Parameters.AddWithValue("$sequence", sequence);
        anchor.Parameters.AddWithValue("$hash", hash);
        anchor.Parameters.AddWithValue("$now", now);
        await anchor.ExecuteNonQueryAsync(cancellationToken);

        await using SqliteCommand delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM queue_ledger WHERE sequence <= $sequence;";
        delete.Parameters.AddWithValue("$sequence", sequence);
        int removed = await delete.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return removed;
    }

    internal static async Task<Bower.Abstractions.LedgerVerification> VerifyAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        List<Bower.Abstractions.LedgerIssue> issues = [];
        (long anchorSequence, string previous) = await AnchorAsync(connection, null, cancellationToken);
        long expected = anchorSequence + 1;
        long entries = 0;
        long head = anchorSequence;
        string headHash = previous;

        Dictionary<string, string> payloads = new(StringComparer.Ordinal);
        await using (SqliteCommand events = connection.CreateCommand())
        {
            events.CommandText = "SELECT event_id, payload FROM queue_events;";
            await using SqliteDataReader reader = await events.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                payloads[reader.GetString(0)] = reader.GetString(1);
            }
        }

        HashSet<string> ledgered = new(StringComparer.Ordinal);
        await using (SqliteCommand ledger = connection.CreateCommand())
        {
            ledger.CommandText =
                "SELECT sequence, event_id, payload_sha256, received_at, chain_hash, purged_at FROM queue_ledger ORDER BY sequence;";
            await using SqliteDataReader reader = await ledger.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                long sequence = reader.GetInt64(0);
                string eventId = reader.GetString(1);
                string payloadHash = reader.GetString(2);
                string receivedAt = reader.GetString(3);
                string chainHash = reader.GetString(4);
                bool purged = !reader.IsDBNull(5);
                entries++;
                ledgered.Add(eventId);

                if (sequence != expected)
                {
                    issues.Add(new(sequence, eventId, "sequence-gap", $"Expected sequence {expected}, found {sequence}."));
                }

                string recomputed = Chain(previous, sequence, eventId, payloadHash, receivedAt);
                if (!string.Equals(recomputed, chainHash, StringComparison.Ordinal))
                {
                    issues.Add(new(sequence, eventId, "chain-broken", "Ledger entry does not chain from its predecessor."));
                }

                if (!purged)
                {
                    if (!payloads.TryGetValue(eventId, out string? payload))
                    {
                        issues.Add(new(sequence, eventId, "event-missing", "Event was removed without a purge record."));
                    }
                    else if (!string.Equals(PayloadHash(payload), payloadHash, StringComparison.Ordinal))
                    {
                        issues.Add(new(sequence, eventId, "payload-modified", "Stored payload no longer matches the ledger."));
                    }
                }
                else if (payloads.ContainsKey(eventId))
                {
                    issues.Add(new(sequence, eventId, "purge-mismatch", "Ledger marks the event purged but it is still stored."));
                }

                previous = chainHash;
                head = sequence;
                headHash = chainHash;
                expected = sequence + 1;
            }
        }

        foreach (string eventId in payloads.Keys.Where(id => !ledgered.Contains(id)))
        {
            issues.Add(new(0, eventId, "unledgered-event", "Event is stored without a ledger entry."));
        }

        return new Bower.Abstractions.LedgerVerification(issues.Count == 0, entries, head, headHash, issues);
    }
}
