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


        CREATE TABLE IF NOT EXISTS queue_ledger_segments (
            start_sequence INTEGER PRIMARY KEY NOT NULL,
            end_sequence INTEGER NOT NULL,
            previous_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            checkpoint_hash TEXT NOT NULL,
            CHECK(end_sequence >= start_sequence)
        );

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
            SELECT sequence, chain_hash FROM (
                SELECT sequence, chain_hash FROM queue_ledger
                UNION ALL SELECT end_sequence, chain_hash FROM queue_ledger_segments
            ) ORDER BY sequence DESC LIMIT 1;
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
        CancellationToken cancellationToken,
        bool assignIncarnation = true)
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
        if (assignIncarnation)
        {
            command.CommandText = "UPDATE queue_events_v5 SET enqueue_sequence = $sequence WHERE event_id = $event_id;";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <summary>Adds ledger entries for events stored before the ledger existed.</summary>
    internal static async Task BackfillAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
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
            await AppendAsync(connection, transaction, eventId, payload, receivedAt, cancellationToken, assignIncarnation: false);
        }

    }

    internal static async Task MarkPurgedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyCollection<string> eventIds,
        string purgedAt,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "UPDATE queue_ledger SET purged_at = $purged_at WHERE event_id = $event_id AND purged_at IS NULL;";
        command.Parameters.AddWithValue("$purged_at", purgedAt);
        SqliteParameter purgedEventId = command.Parameters.Add("$event_id", SqliteType.Text);
        foreach (string eventId in eventIds)
        {
            purgedEventId.Value = eventId;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    internal static string CheckpointHash(long start, long end, string previous, string hash) =>
        PayloadHash(string.Join('\u001f', "bower-ledger-segment-v1",
            start.ToString(CultureInfo.InvariantCulture), end.ToString(CultureInfo.InvariantCulture), previous, hash));

    /// <summary>Coalesces purged runs, including runs behind unresolved events.</summary>
    internal static async Task<int> CompactAsync(SqliteConnection connection, SqliteTransaction transaction, string now, CancellationToken cancellationToken)
    {
        _ = now;
        List<(long Start, long End, string Previous, string Hash)> runs = [];
        (long anchor, string previous) = await AnchorAsync(connection, transaction, cancellationToken);
        long expected = anchor + 1;
        long start = 0;
        long end = 0;
        string before = previous;
        string hash = previous;
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT sequence, sequence, chain_hash, purged_at IS NOT NULL,
                    event_id, payload_sha256, received_at, NULL, NULL FROM queue_ledger
                UNION ALL SELECT start_sequence, end_sequence, chain_hash, 1,
                    '', '', '', previous_hash, checkpoint_hash FROM queue_ledger_segments
                ORDER BY 1;
                """;
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                long rowStart = reader.GetInt64(0);
                long rowEnd = reader.GetInt64(1);
                string rowHash = reader.GetString(2);
                bool purged = reader.GetBoolean(3);
                bool segment = !reader.IsDBNull(7);
                bool valid = segment
                    ? reader.GetString(7) == previous && reader.GetString(8) == CheckpointHash(rowStart, rowEnd, previous, rowHash)
                    : rowHash == Chain(previous, rowStart, reader.GetString(4), reader.GetString(5), reader.GetString(6));
                if (rowStart != expected || !valid)
                {
                    throw new InvalidOperationException("Cannot compact a corrupt queue ledger.");
                }
                expected = rowEnd + 1;
                if (start != 0 && (!purged || rowStart != end + 1))
                {
                    runs.Add((start, end, before, hash));
                    start = 0;
                }
                if (purged)
                {
                    if (start == 0)
                    {
                        start = rowStart;
                        before = previous;
                    }
                    end = rowEnd;
                    hash = rowHash;
                }
                previous = rowHash;
            }
        }
        if (start != 0)
        {
            runs.Add((start, end, before, hash));
        }
        int removed = 0;
        foreach (var run in runs)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                DELETE FROM queue_ledger_segments WHERE start_sequence BETWEEN $start AND $end;
                INSERT INTO queue_ledger_segments VALUES ($start, $end, $previous, $hash, $checkpoint);
                """;
            command.Parameters.AddWithValue("$start", run.Start);
            command.Parameters.AddWithValue("$end", run.End);
            command.Parameters.AddWithValue("$previous", run.Previous);
            command.Parameters.AddWithValue("$hash", run.Hash);
            command.Parameters.AddWithValue("$checkpoint", CheckpointHash(run.Start, run.End, run.Previous, run.Hash));
            await command.ExecuteNonQueryAsync(cancellationToken);
            command.CommandText = "DELETE FROM queue_ledger WHERE sequence BETWEEN $start AND $end AND purged_at IS NOT NULL;";
            removed += await command.ExecuteNonQueryAsync(cancellationToken);
        }
        return removed;
    }

    internal static async Task<Bower.Abstractions.LedgerVerification> VerifyAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken) => await VerifyAsync(connection, null, cancellationToken);

    internal static async Task<Bower.Abstractions.LedgerVerification> VerifyAsync(
        SqliteConnection connection,
        SqliteTransaction? existingTransaction,
        CancellationToken cancellationToken)
    {
        List<Bower.Abstractions.LedgerIssue> issues = [];
        // One deferred (read) transaction: in WAL mode every read below sees the same
        // snapshot, so an enqueue committing mid-verification cannot produce a false
        // unledgered-event or event-missing issue.
        await using SqliteTransaction? owned = existingTransaction is null ? connection.BeginTransaction(deferred: true) : null;
        SqliteTransaction transaction = existingTransaction ?? owned!;
        (long anchorSequence, string previous) = await AnchorAsync(connection, transaction, cancellationToken);
        long expected = anchorSequence + 1;
        long entries = 0;
        long head = anchorSequence;
        string headHash = previous;

        // Hash while streaming so memory holds one digest per event, not every payload.
        Dictionary<long, (string EventId, string Hash)> payloads = [];
        await using (SqliteCommand events = connection.CreateCommand())
        {
            events.Transaction = transaction;
            events.CommandText = "SELECT enqueue_sequence, event_id, payload FROM queue_events_v5;";
            await using SqliteDataReader reader = await events.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                payloads[reader.GetInt64(0)] = (reader.GetString(1), PayloadHash(reader.GetString(2)));
            }
        }

        HashSet<long> ledgered = [];
        await using (SqliteCommand ledger = connection.CreateCommand())
        {
            ledger.Transaction = transaction;
            ledger.CommandText =
                """
                SELECT sequence, event_id, payload_sha256, received_at, chain_hash, purged_at,
                    sequence, NULL, NULL FROM queue_ledger
                UNION ALL SELECT start_sequence, '', '', '', chain_hash, 'segment',
                    end_sequence, previous_hash, checkpoint_hash FROM queue_ledger_segments
                ORDER BY 1;
                """;
            await using SqliteDataReader reader = await ledger.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                long sequence = reader.GetInt64(0);
                string eventId = reader.GetString(1);
                string payloadHash = reader.GetString(2);
                string receivedAt = reader.GetString(3);
                string chainHash = reader.GetString(4);
                bool purged = !reader.IsDBNull(5);
                if (!reader.IsDBNull(7))
                {
                    long end = reader.GetInt64(6);
                    string before = reader.GetString(7);
                    if (sequence != expected || before != previous ||
                        reader.GetString(8) != CheckpointHash(sequence, end, before, chainHash))
                    {
                        issues.Add(new(sequence, string.Empty, "checkpoint-broken", "Retention checkpoint does not match its boundary."));
                    }
                    previous = chainHash;
                    head = end;
                    headHash = chainHash;
                    expected = end + 1;
                    continue;
                }

                ledgered.Add(sequence);
                entries++;
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
                    if (!payloads.TryGetValue(sequence, out var storedPayload))
                    {
                        issues.Add(new(sequence, eventId, "event-missing", "Event was removed without a purge record."));
                    }
                    else if ((!string.Equals(storedPayload.Hash, payloadHash, StringComparison.Ordinal) || storedPayload.EventId != eventId))
                    {
                        issues.Add(new(sequence, eventId, "payload-modified", "Stored payload no longer matches the ledger."));
                    }
                }
                else if (payloads.ContainsKey(sequence))
                {
                    issues.Add(new(sequence, eventId, "purge-mismatch", "Ledger marks the event purged but it is still stored."));
                }

                previous = chainHash;
                head = sequence;
                headHash = chainHash;
                expected = sequence + 1;
            }
        }

        foreach (long incarnation in payloads.Keys.Where(id => !ledgered.Contains(id)))
        {
            issues.Add(new(incarnation, payloads[incarnation].EventId, "unledgered-event", "Event is stored without a ledger entry."));
        }

        return new Bower.Abstractions.LedgerVerification(issues.Count == 0, entries, head, headHash, issues);
    }
}
