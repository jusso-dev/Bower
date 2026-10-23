using System.Globalization;
using System.Text.Json;
using Bower.Contracts;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

internal static class QueueMigration
{
    internal static async Task UpgradeAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        // Recheck under the write lock: another runtime may have migrated first.
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='queue_events_v5';";
        if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != 0)
        {
            return;
        }
        command.CommandText = """
            ALTER TABLE queue_events RENAME TO queue_events_v5;
            ALTER TABLE queue_events_v5 ADD COLUMN enqueue_sequence INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE queue_events_v5 ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0;
            UPDATE queue_events_v5 SET enqueue_sequence = (
                SELECT MAX(sequence) FROM queue_ledger l
                WHERE l.event_id = queue_events_v5.event_id AND l.purged_at IS NULL);
            CREATE UNIQUE INDEX ix_queue_events_incarnation ON queue_events_v5(enqueue_sequence);
            CREATE VIEW queue_events AS SELECT event_id, fingerprint, payload, payload_bytes,
                received_at, state, delivery_attempts, lease_until, next_attempt_at,
                last_failure_code, acknowledgement, delivered_at FROM queue_events_v5;
            CREATE TABLE IF NOT EXISTS queue_ledger_segments (
                start_sequence INTEGER PRIMARY KEY NOT NULL,
                end_sequence INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                checkpoint_hash TEXT NOT NULL,
                CHECK(end_sequence >= start_sequence)
            );
            INSERT INTO schema_history(version, applied_at, hash)
            VALUES (5, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v5-fencing-segments');
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        // Re-key stored envelopes without rewriting payload/ledger bytes. Any identity
        // collision aborts the entire migration; never discard an accepted event.
        string? last = null;
        while (true)
        {
            command.CommandText = "SELECT event_id, payload FROM queue_events_v5 WHERE $last IS NULL OR event_id > $last ORDER BY event_id LIMIT 1;";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$last", (object?)last ?? DBNull.Value);
            string payload;
            await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                if (!await reader.ReadAsync(cancellationToken))
                {
                    break;
                }
                last = reader.GetString(0);
                payload = reader.GetString(1);
            }
            SecurityEventEnvelope? envelope;
            try
            {
                envelope = JsonSerializer.Deserialize(payload, BowerJson.Envelope);
            }
            catch (JsonException)
            {
                continue; // Opaque legacy queue clients retain their explicit fingerprints.
            }
            if (envelope is null)
            {
                continue;
            }
            command.CommandText = "UPDATE queue_events_v5 SET fingerprint = $fingerprint WHERE event_id = $event_id;";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$fingerprint", EventIdentity.Create(envelope));
            command.Parameters.AddWithValue("$event_id", last);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        if (!(await QueueLedger.VerifyAsync(connection, transaction, cancellationToken)).Intact)
        {
            throw new InvalidOperationException("Cannot migrate a corrupt queue ledger.");
        }
    }
}
