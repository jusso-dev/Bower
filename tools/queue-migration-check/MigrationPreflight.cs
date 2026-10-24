using System.Text.Json;
using Bower.Contracts;
using Bower.Persistence;
using Microsoft.Data.Sqlite;

namespace Bower.Tools.QueueMigrationCheck;

public sealed record IdentityCollision(string EventId, string ConflictingEventId);
public sealed record MigrationCheckReport(bool Complete, string Status, int ScannedRows, int OpaqueRows,
    IReadOnlyList<IdentityCollision> Collisions);

/// <summary>Read-only, bounded identity preflight for a stopped v4 queue or its consistent backup.</summary>
public static class MigrationPreflight
{
    public const int MaximumRows = 100_000;
    public const int MaximumPayloadBytes = 1_048_576;
    public const long MaximumTotalPayloadBytes = 64L * 1_048_576;
    public const int MaximumCollisions = 100;

    public static async Task<MigrationCheckReport> CheckAsync(string path, CancellationToken cancellationToken = default)
    {
        List<IdentityCollision> collisions = [];
        List<(string Id, string Before, string After)> rows = [];
        int opaque = 0;
        MigrationCheckReport Result(bool complete, string status) => new(complete, status, rows.Count, opaque, collisions);
        try
        {
            // Never construct SqliteEventStore: its constructor/initialization can write.
            await using SqliteConnection connection = new(new SqliteConnectionStringBuilder
            {
                DataSource = Path.GetFullPath(path),
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
                DefaultTimeout = 5
            }.ToString());
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;";
            await command.ExecuteNonQueryAsync(cancellationToken);
            // Deferred read transaction: one snapshot, no writer lock or migration.
            await using SqliteTransaction transaction = connection.BeginTransaction(deferred: true);
            command.Transaction = transaction;
            command.CommandText = """
                SELECT COUNT(*) FROM sqlite_master
                WHERE (type='table' AND name IN ('queue_events', 'schema_history', 'queue_ledger', 'queue_ledger_anchor'))
                   OR name='queue_events_v5';
                """;
            if ((long)(await command.ExecuteScalarAsync(cancellationToken))! != 4)
            {
                return Result(false, "unsupported-schema");
            }
            command.CommandText = """
                SELECT COUNT(*)=4 AND SUM(CASE
                    WHEN version=1 AND hash='bower-queue-v1' THEN 1
                    WHEN version=2 AND hash='bower-queue-v2-retention' THEN 1
                    WHEN version=3 AND hash='bower-queue-v3-ledger' THEN 1
                    WHEN version=4 AND hash='bower-queue-v4-capacity-index' THEN 1
                    ELSE 0 END)=4 FROM schema_history;
                """;
            if ((long)(await command.ExecuteScalarAsync(cancellationToken))! != 1)
            {
                return Result(false, "unsupported-schema");
            }
            // Bound materialization even when stored byte counts are corrupt. Never
            // trust payload_bytes, or expose parser/SQLite exception messages.
            command.CommandText = """
                SELECT CASE WHEN length(CAST(event_id AS BLOB)) BETWEEN 1 AND 128 THEN event_id END,
                       CASE WHEN length(CAST(fingerprint AS BLOB)) BETWEEN 1 AND 256 THEN fingerprint END,
                       length(CAST(payload AS BLOB)),
                       CASE WHEN length(CAST(payload AS BLOB)) <= $bytes THEN payload END
                FROM queue_events ORDER BY event_id LIMIT $rows;
                """;
            command.Parameters.AddWithValue("$bytes", MaximumPayloadBytes);
            command.Parameters.AddWithValue("$rows", MaximumRows + 1);
            long totalBytes = 0;
            await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (rows.Count == MaximumRows)
                    {
                        return Result(false, "row-limit");
                    }
                    if (reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2) || reader.IsDBNull(3))
                    {
                        return Result(false, "invalid-or-oversized-row");
                    }
                    totalBytes += reader.GetInt64(2);
                    if (totalBytes > MaximumTotalPayloadBytes)
                    {
                        return Result(false, "payload-budget");
                    }
                    string id = reader.GetString(0);
                    string before = reader.GetString(1);
                    string after = before;
                    SecurityEventEnvelope? envelope = null;
                    try
                    {
                        envelope = JsonSerializer.Deserialize(reader.GetString(3), BowerJson.Envelope);
                    }
                    catch (JsonException)
                    {
                        // Match migration: opaque legacy rows keep their fingerprint.
                    }
                    if (envelope is null)
                    {
                        opaque++;
                    }
                    else
                    {
                        after = EventIdentity.Create(envelope);
                    }
                    rows.Add((id, before, after));
                }
            }

            // Simulate the migration's ordered UNIQUE updates in memory. This also
            // catches an envelope colliding with a retained opaque fingerprint.
            Dictionary<string, string> owners = new(StringComparer.Ordinal);
            foreach (var row in rows)
            {
                if (!owners.TryAdd(row.Before, row.Id))
                {
                    return Result(false, "invalid-fingerprints");
                }
            }
            foreach (var row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (owners.TryGetValue(row.After, out string? owner) && owner != row.Id)
                {
                    collisions.Add(new(row.Id, owner));
                    if (collisions.Count == MaximumCollisions)
                    {
                        return Result(false, "collision-limit");
                    }
                    continue; // Failed UPDATE leaves its old key intact.
                }
                owners.Remove(row.Before);
                owners[row.After] = row.Id;
            }
            return Result(true, collisions.Count == 0 ? "no-identity-collisions" : "identity-collisions");
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return Result(false, "unreadable-or-invalid-database");
        }
    }
}
