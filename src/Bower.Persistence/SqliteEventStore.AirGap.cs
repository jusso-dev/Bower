using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>Last air-gapped export bundle recorded in the collector's queue database.</summary>
public sealed record ExportBundleCursor(
    long BundleSequence,
    string BundleId,
    long FromLedgerSequence,
    long ToLedgerSequence,
    string BundleHash,
    DateTimeOffset ExportedAt);

public sealed partial class SqliteEventStore
{
    private const string ExportBundleSchema =
        """
        CREATE TABLE IF NOT EXISTS queue_export_bundles (
            bundle_sequence INTEGER PRIMARY KEY NOT NULL,
            bundle_id TEXT NOT NULL UNIQUE,
            from_ledger_sequence INTEGER NOT NULL,
            to_ledger_sequence INTEGER NOT NULL,
            bundle_hash TEXT NOT NULL,
            exported_at TEXT NOT NULL
        );
        """;

    public async Task<ExportBundleCursor?> GetLastExportBundleAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        if (!await ExportBundleTableExistsAsync(connection, cancellationToken))
        {
            return null;
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT bundle_sequence, bundle_id, from_ledger_sequence, to_ledger_sequence, bundle_hash, exported_at
            FROM queue_export_bundles
            ORDER BY bundle_sequence DESC
            LIMIT 1;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ExportBundleCursor(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetInt64(2),
            reader.GetInt64(3),
            reader.GetString(4),
            DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));
    }

    public async Task RecordExportBundleAsync(
        ExportBundleCursor cursor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(cursor);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = await BeginWriteAsync(connection, true, cancellationToken);
        await using (SqliteCommand ddl = connection.CreateCommand())
        {
            ddl.Transaction = transaction;
            ddl.CommandText = ExportBundleSchema;
            await ddl.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (SqliteCommand insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO queue_export_bundles (
                    bundle_sequence, bundle_id, from_ledger_sequence, to_ledger_sequence, bundle_hash, exported_at)
                VALUES ($seq, $id, $from_seq, $to_seq, $hash, $at);
                """;
            insert.Parameters.AddWithValue("$seq", cursor.BundleSequence);
            insert.Parameters.AddWithValue("$id", cursor.BundleId);
            insert.Parameters.AddWithValue("$from_seq", cursor.FromLedgerSequence);
            insert.Parameters.AddWithValue("$to_seq", cursor.ToLedgerSequence);
            insert.Parameters.AddWithValue("$hash", cursor.BundleHash);
            insert.Parameters.AddWithValue("$at", cursor.ExportedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task<bool> ExportBundleTableExistsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'queue_export_bundles';";
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) > 0;
    }
}
