using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>Metadata written beside a queue backup. Counts and hashes only, never payloads.</summary>
public sealed record QueueBackupManifest(
    string ApiVersion,
    string Kind,
    DateTimeOffset CreatedAt,
    long SchemaVersion,
    string DatabaseFile,
    long DatabaseBytes,
    string DatabaseSha256,
    QueueBackupCounts Counts,
    long SourceCursors,
    long LedgerSequence,
    string LedgerHash,
    bool LedgerIntact,
    string IntegrityCheck,
    string? CollectorId);

public sealed record QueueBackupCounts(long Queued, long Uploading, long Retrying, long Delivered, long DeadLettered)
{
    public long Total => Queued + Uploading + Retrying + Delivered + DeadLettered;
}

/// <summary>
/// Consistent copy of a live queue database (events, ledger, source cursors and suppression
/// state) with the SQLite online backup API, and its verified restore onto a new path.
/// The backup is a single self-contained file (no WAL) plus <c>FILE.manifest.json</c>.
/// Neither operation initializes, migrates or repairs the source; both fail closed on a
/// schema this build does not support. Secrets live outside the queue database and are
/// never part of a backup.
/// </summary>
public static class QueueBackup
{
    public const string ApiVersion = "bower.security/v1";
    public const string Kind = "BowerQueueBackup";
    public const string ManifestSuffix = ".manifest.json";

    public static async Task<QueueBackupManifest> CreateAsync(
        string databasePath,
        string outputPath,
        string? collectorId,
        TimeProvider? clock = null,
        CancellationToken cancellationToken = default)
    {
        string source = Path.GetFullPath(databasePath);
        string output = Path.GetFullPath(outputPath);
        if (!File.Exists(source))
        {
            throw new FileNotFoundException($"Queue database not found: {source}");
        }
        RefuseExisting(output);
        RefuseExisting(output + ManifestSuffix);
        if (string.Equals(source, output, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("The backup must not replace the live queue database.");
        }

        string temporary = Temporary(output);
        try
        {
            await using (SqliteConnection live = Open(source, SqliteOpenMode.ReadWrite))
            {
                await RequireSupportedSchemaAsync(live, cancellationToken);
                await using SqliteConnection copy = Open(temporary, SqliteOpenMode.ReadWriteCreate);
                // One step under a read transaction: a point-in-time snapshot that includes
                // every committed WAL frame. WAL writers keep going while it runs.
                live.BackupDatabase(copy);
            }
            await SetJournalModeAsync(temporary, "DELETE", cancellationToken);
            QueueBackupManifest manifest = await DescribeAsync(temporary, output, collectorId, clock, cancellationToken);
            Restrict(temporary);
            File.Move(temporary, output);
            DirectorySync.Flush(Path.GetDirectoryName(output)!);
            await WriteManifestAsync(output + ManifestSuffix, manifest, cancellationToken);
            return manifest;
        }
        finally
        {
            DeleteTemporary(temporary);
        }
    }

    public static async Task<QueueBackupManifest> RestoreAsync(
        string backupPath,
        string databasePath,
        TimeProvider? clock = null,
        CancellationToken cancellationToken = default)
    {
        string backup = Path.GetFullPath(backupPath);
        string target = Path.GetFullPath(databasePath);
        QueueBackupManifest expected = await ReadManifestAsync(backup + ManifestSuffix, cancellationToken);
        if (!File.Exists(backup) || Sha256(backup) != expected.DatabaseSha256)
        {
            throw new InvalidDataException("Queue backup is missing or does not match its manifest.");
        }
        // Never overwrite a queue, and never place a restored database beside a stale WAL:
        // SQLite would apply another database's frames to it.
        foreach (string path in new[] { target, target + "-wal", target + "-shm", target + "-journal" })
        {
            RefuseExisting(path);
        }
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);

        string temporary = Temporary(target);
        try
        {
            await using (SqliteConnection snapshot = Open(backup, SqliteOpenMode.ReadOnly))
            {
                await RequireSupportedSchemaAsync(snapshot, cancellationToken);
                await using SqliteConnection restored = Open(temporary, SqliteOpenMode.ReadWriteCreate);
                snapshot.BackupDatabase(restored);
            }
            QueueBackupManifest actual = await DescribeAsync(temporary, target, expected.CollectorId, clock, cancellationToken);
            if (actual.Counts != expected.Counts || actual.LedgerSequence != expected.LedgerSequence
                || actual.LedgerHash != expected.LedgerHash || actual.SourceCursors != expected.SourceCursors)
            {
                throw new InvalidDataException("Restored queue does not match the backup manifest.");
            }
            // The collector opens an existing v5 queue without changing its journal mode.
            await SetJournalModeAsync(temporary, "WAL", cancellationToken);
            Restrict(temporary);
            File.Move(temporary, target);
            DirectorySync.Flush(Path.GetDirectoryName(target)!);
            return actual;
        }
        finally
        {
            DeleteTemporary(temporary);
        }
    }

    public static async Task<QueueBackupManifest> ReadManifestAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path) || new FileInfo(path).Length > 65_536)
        {
            throw new InvalidDataException("Queue backup manifest is missing or too large.");
        }
        QueueBackupManifest? manifest;
        try
        {
            await using FileStream stream = File.OpenRead(path);
            manifest = await JsonSerializer.DeserializeAsync(stream, QueueBackupJsonContext.Default.QueueBackupManifest, cancellationToken);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Queue backup manifest is invalid.", exception);
        }
        if (manifest is null || manifest.ApiVersion != ApiVersion || manifest.Kind != Kind || manifest.Counts is null
            || string.IsNullOrEmpty(manifest.DatabaseSha256) || string.IsNullOrEmpty(manifest.LedgerHash))
        {
            throw new InvalidDataException("Queue backup manifest is invalid.");
        }
        if (manifest.SchemaVersion > SqliteEventStore.SchemaVersion)
        {
            throw new UnsupportedQueueSchemaException(manifest.SchemaVersion, SqliteEventStore.SchemaVersion);
        }
        return manifest;
    }

    private static async Task<QueueBackupManifest> DescribeAsync(
        string path,
        string reportedPath,
        string? collectorId,
        TimeProvider? clock,
        CancellationToken cancellationToken)
    {
        long[] states = new long[5];
        long cursors;
        string integrity;
        LedgerVerification ledger;
        (long Sequence, string Hash) head;
        await using (SqliteConnection connection = Open(path, SqliteOpenMode.ReadOnly))
        {
            await RequireSupportedSchemaAsync(connection, cancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "PRAGMA integrity_check;";
            integrity = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) ?? "";
            if (integrity != "ok")
            {
                throw new InvalidDataException("Queue backup failed the SQLite integrity check.");
            }
            command.CommandText = "SELECT state, COUNT(*) FROM queue_events_v5 GROUP BY state;";
            await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    long state = reader.GetInt64(0);
                    if (state is < 0 or > 4)
                    {
                        throw new InvalidDataException("Queue backup contains an unknown event state.");
                    }
                    states[state] = reader.GetInt64(1);
                }
            }
            command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='source_cursors';";
            cursors = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) == 0 ? 0 : -1;
            if (cursors < 0)
            {
                command.CommandText = "SELECT COUNT(*) FROM source_cursors;";
                cursors = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
            }
            ledger = await QueueLedger.VerifyAsync(connection, cancellationToken);
            head = await QueueLedger.HeadAsync(connection, null, cancellationToken);
        }
        if (!ledger.Intact)
        {
            throw new InvalidDataException("Queue backup ledger verification failed.");
        }
        return new QueueBackupManifest(
            ApiVersion,
            Kind,
            (clock ?? TimeProvider.System).GetUtcNow(),
            SqliteEventStore.SchemaVersion,
            Path.GetFileName(reportedPath),
            new FileInfo(path).Length,
            Sha256(path),
            new QueueBackupCounts(
                states[(int)QueueState.Queued],
                states[(int)QueueState.Uploading],
                states[(int)QueueState.Retrying],
                states[(int)QueueState.Delivered],
                states[(int)QueueState.DeadLettered]),
            cursors,
            head.Sequence,
            head.Hash,
            ledger.Intact,
            integrity,
            collectorId);
    }

    /// <summary>Exactly the version this build writes; never an older or newer schema.</summary>
    private static async Task RequireSupportedSchemaAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        await SqliteEventStore.RefuseNewerSchemaAsync(command, cancellationToken);
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('schema_history', 'queue_events_v5');";
        if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != 2)
        {
            throw new InvalidDataException("Not a Bower queue at the supported schema version; start a supported collector on it first.");
        }
        command.CommandText = "SELECT MAX(version) FROM schema_history;";
        if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != SqliteEventStore.SchemaVersion)
        {
            throw new InvalidDataException("Not a Bower queue at the supported schema version; start a supported collector on it first.");
        }
    }

    private static SqliteConnection Open(string path, SqliteOpenMode mode)
    {
        // No pooling: every handle is closed before the file is hashed, renamed or deleted.
        SqliteConnection connection = new(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 30
        }.ToString());
        connection.Open();
        return connection;
    }

    /// <summary>Sets the persistent journal mode and leaves a single, fully checkpointed file.</summary>
    private static async Task SetJournalModeAsync(string path, string mode, CancellationToken cancellationToken)
    {
        await using (SqliteConnection connection = Open(path, SqliteOpenMode.ReadWrite))
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText = $"PRAGMA journal_mode = {mode};";
            await command.ExecuteNonQueryAsync(cancellationToken);
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        if (File.Exists(path + "-wal") && new FileInfo(path + "-wal").Length > 0)
        {
            throw new IOException("Queue copy still has uncheckpointed WAL frames.");
        }
        File.Delete(path + "-wal");
        File.Delete(path + "-shm");
    }

    /// <summary>Removes an unfinished copy; after a successful rename only the name is gone.</summary>
    private static void DeleteTemporary(string temporary)
    {
        if (File.Exists(temporary))
        {
            File.Delete(temporary);
            File.Delete(temporary + "-wal");
            File.Delete(temporary + "-shm");
            File.Delete(temporary + "-journal");
        }
    }

    private static async Task WriteManifestAsync(string path, QueueBackupManifest manifest, CancellationToken cancellationToken)
    {
        string temporary = Temporary(path);
        try
        {
            await using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write))
            {
                await JsonSerializer.SerializeAsync(stream, manifest, QueueBackupJsonContext.Default.QueueBackupManifest, cancellationToken);
                stream.Flush(true);
            }
            Restrict(temporary);
            File.Move(temporary, path);
            DirectorySync.Flush(Path.GetDirectoryName(path)!);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private static void RefuseExisting(string path)
    {
        if (File.Exists(path) || Directory.Exists(path))
        {
            throw new IOException($"Refusing to overwrite existing file: {path}");
        }
    }

    private static string Temporary(string path) =>
        Path.Combine(Path.GetDirectoryName(path)!, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");

    private static string Sha256(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void Restrict(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(QueueBackupManifest))]
internal sealed partial class QueueBackupJsonContext : JsonSerializerContext;
