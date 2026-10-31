using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// Metadata written beside a queue backup. Counts and hashes only, never payloads. Counts and
/// ledger fields are null when a damaged queue could not be read far enough to compute them.
/// </summary>
public sealed record QueueBackupManifest(
    string ApiVersion,
    string Kind,
    DateTimeOffset CreatedAt,
    long SchemaVersion,
    string DatabaseFile,
    long DatabaseBytes,
    string DatabaseSha256,
    QueueBackupCounts? Counts,
    long? SourceCursors,
    long? LedgerSequence,
    string? LedgerHash,
    bool LedgerIntact,
    bool IntegrityOk,
    string IntegrityCheck,
    string? CollectorId)
{
    /// <summary>The source failed its SQLite integrity or ledger check when it was copied.</summary>
    public bool Damaged => !IntegrityOk || !LedgerIntact;
}

public sealed record QueueBackupCounts(long Queued, long Uploading, long Retrying, long Delivered, long DeadLettered)
{
    public long Total => Queued + Uploading + Retrying + Delivered + DeadLettered;
}

/// <summary>
/// Outcome of a restore: the backup's own manifest unchanged, plus the restored file's
/// size and SHA-256 after its final header change (WAL mode), at restore time.
/// </summary>
public sealed record QueueRestoreResult(
    QueueBackupManifest Backup,
    string RestoredDatabaseFile,
    long RestoredDatabaseBytes,
    string RestoredDatabaseSha256,
    DateTimeOffset RestoredAt,
    bool RestoredDamagedBackup);

/// <summary>
/// Consistent copy of a live queue database (events, ledger, source cursors and suppression
/// state) with the SQLite online backup API, and its verified restore onto a new path.
/// The backup is a single self-contained file (no WAL) plus <c>FILE.manifest.json</c>.
/// Neither operation initializes, migrates or repairs the source; both fail closed on a
/// schema this build does not support. Copies are owner-only from the moment they are
/// created. A damaged source is still copied (recorded in the manifest) because that is when
/// a copy matters most; restoring it needs explicit consent. Secrets live outside the queue
/// database and are never part of a backup.
/// </summary>
public static class QueueBackup
{
    public const string ApiVersion = "bower.security/v1";
    public const string Kind = "BowerQueueBackup";
    public const string ManifestSuffix = ".manifest.json";

    /// <summary>Default bound on waiting for a busy queue (SQLITE_BUSY/LOCKED).</summary>
    public static readonly TimeSpan DefaultBusyTimeout = TimeSpan.FromSeconds(30);

    private const int SqliteBusy = 5;
    private const int SqliteLocked = 6;

    public static async Task<QueueBackupManifest> CreateAsync(
        string databasePath,
        string outputPath,
        string? collectorId,
        TimeProvider? clock = null,
        TimeSpan? busyTimeout = null,
        CancellationToken cancellationToken = default)
    {
        string source = Path.GetFullPath(databasePath);
        string output = Path.GetFullPath(outputPath);
        if (new[] { source, source + "-wal", source + "-shm", source + "-journal" }
            .Any(path => string.Equals(path, output, StringComparison.OrdinalIgnoreCase)))
        {
            throw new IOException("The backup output must not be the live queue database or its WAL, SHM or journal file.");
        }
        if (!File.Exists(source))
        {
            throw new FileNotFoundException($"Queue database not found: {source}");
        }
        RefuseExisting(output);
        RefuseExisting(output + ManifestSuffix);
        CreatePrivateDirectory(Path.GetDirectoryName(output)!);
        TimeSpan timeout = busyTimeout ?? DefaultBusyTimeout;

        string temporary = Temporary(output);
        try
        {
            // Owner-only before any page is copied: an interrupted backup never leaves a
            // readable copy of the queue behind.
            CreatePrivateFile(temporary, privateAcl: true);
            await using (SqliteConnection live = Open(source, SqliteOpenMode.ReadWrite, timeout))
            await using (SqliteConnection copy = Open(temporary, SqliteOpenMode.ReadWrite, timeout))
            {
                // A point-in-time snapshot under one read transaction, including every
                // committed WAL frame. WAL writers keep going while it runs.
                await CopyAsync(live, copy, timeout, cancellationToken);
            }
            await SetJournalModeAsync(temporary, "DELETE", timeout, cancellationToken);
            Description description = await DescribeAsync(temporary, timeout, cancellationToken);
            QueueBackupManifest manifest = new(
                ApiVersion,
                Kind,
                (clock ?? TimeProvider.System).GetUtcNow(),
                SqliteEventStore.SchemaVersion,
                Path.GetFileName(output),
                new FileInfo(temporary).Length,
                Sha256(temporary),
                description.Counts,
                description.SourceCursors,
                description.LedgerSequence,
                description.LedgerHash,
                description.LedgerIntact,
                description.IntegrityOk,
                description.IntegrityCheck,
                collectorId);
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

    public static async Task<QueueRestoreResult> RestoreAsync(
        string backupPath,
        string databasePath,
        TimeProvider? clock = null,
        bool allowDamaged = false,
        TimeSpan? busyTimeout = null,
        CancellationToken cancellationToken = default)
    {
        string backup = Path.GetFullPath(backupPath);
        string target = Path.GetFullPath(databasePath);
        TimeSpan timeout = busyTimeout ?? DefaultBusyTimeout;
        QueueBackupManifest expected = await ReadManifestAsync(backup + ManifestSuffix, cancellationToken);
        if (expected.Damaged && !allowDamaged)
        {
            throw new InvalidDataException(
                "Queue backup was taken from a damaged queue (integrity or ledger check failed). " +
                "Restore it only for recovery with --allow-damaged.");
        }
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
            // Owner-only on Unix from creation; on Windows the copy inherits the queue
            // folder's ACL so the service account can open it.
            CreatePrivateFile(temporary, privateAcl: false);
            await using (SqliteConnection snapshot = Open(backup, SqliteOpenMode.ReadOnly, timeout))
            await using (SqliteConnection restored = Open(temporary, SqliteOpenMode.ReadWrite, timeout))
            {
                await CopyAsync(snapshot, restored, timeout, cancellationToken);
            }
            if (!expected.Damaged)
            {
                Description actual = await DescribeAsync(temporary, timeout, cancellationToken);
                if (actual.Damaged || actual.Counts != expected.Counts || actual.LedgerSequence != expected.LedgerSequence
                    || actual.LedgerHash != expected.LedgerHash || actual.SourceCursors != expected.SourceCursors)
                {
                    throw new InvalidDataException("Restored queue does not match the backup manifest.");
                }
            }
            // The collector opens an existing v5 queue without changing its journal mode.
            await SetJournalModeAsync(temporary, "WAL", timeout, cancellationToken);
            long bytes = new FileInfo(temporary).Length;
            string sha256 = Sha256(temporary);
            File.Move(temporary, target);
            DirectorySync.Flush(Path.GetDirectoryName(target)!);
            return new QueueRestoreResult(
                expected, Path.GetFileName(target), bytes, sha256, (clock ?? TimeProvider.System).GetUtcNow(), expected.Damaged);
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
        if (manifest is null || manifest.ApiVersion != ApiVersion || manifest.Kind != Kind
            || string.IsNullOrEmpty(manifest.DatabaseSha256)
            || (!manifest.Damaged && (manifest.Counts is null || string.IsNullOrEmpty(manifest.LedgerHash))))
        {
            throw new InvalidDataException("Queue backup manifest is invalid.");
        }
        if (manifest.SchemaVersion > SqliteEventStore.SchemaVersion)
        {
            throw new UnsupportedQueueSchemaException(manifest.SchemaVersion, SqliteEventStore.SchemaVersion);
        }
        return manifest;
    }

    public static string ToJson(QueueBackupManifest manifest) =>
        JsonSerializer.Serialize(manifest, QueueBackupJsonContext.Default.QueueBackupManifest);

    public static string ToJson(QueueRestoreResult result) =>
        JsonSerializer.Serialize(result, QueueBackupJsonContext.Default.QueueRestoreResult);

    private sealed record Description(
        QueueBackupCounts? Counts,
        long? SourceCursors,
        long? LedgerSequence,
        string? LedgerHash,
        bool LedgerIntact,
        bool IntegrityOk,
        string IntegrityCheck)
    {
        public bool Damaged => !IntegrityOk || !LedgerIntact;
    }

    /// <summary>
    /// Integrity, per-state counts, cursors and ledger of a copy. A newer or unknown schema
    /// fails closed; storage damage is recorded rather than thrown.
    /// </summary>
    private static async Task<Description> DescribeAsync(string path, TimeSpan timeout, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = Open(path, SqliteOpenMode.ReadOnly, timeout);
        await RequireSupportedSchemaAsync(connection, cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        int problems = 0;
        bool integrityOk;
        try
        {
            command.CommandText = "PRAGMA integrity_check(10);";
            List<string> rows = [];
            await using (SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    rows.Add(reader.GetString(0));
                }
            }
            integrityOk = rows is ["ok"];
            problems = integrityOk ? 0 : rows.Count;
        }
        catch (SqliteException)
        {
            integrityOk = false;
            problems = 1;
        }
        // Counts only, never the reported row content (a manifest carries no payload data).
        string integrity = integrityOk ? "ok" : $"failed ({problems} problem(s) reported)";
        try
        {
            long[] states = new long[5];
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
            long cursors = 0;
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != 0)
            {
                command.CommandText = "SELECT COUNT(*) FROM source_cursors;";
                cursors = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
            }
            LedgerVerification ledger = await QueueLedger.VerifyAsync(connection, cancellationToken);
            (long sequence, string hash) = await QueueLedger.HeadAsync(connection, null, cancellationToken);
            return new Description(
                new QueueBackupCounts(
                    states[(int)QueueState.Queued],
                    states[(int)QueueState.Uploading],
                    states[(int)QueueState.Retrying],
                    states[(int)QueueState.Delivered],
                    states[(int)QueueState.DeadLettered]),
                cursors, sequence, hash, ledger.Intact, integrityOk, integrity);
        }
        catch (Exception exception) when (exception is SqliteException or InvalidDataException or FormatException)
        {
            return new Description(null, null, null, null, false, integrityOk, integrity);
        }
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

    /// <summary>
    /// One <c>backup_step(-1)</c>, retried with bounded backoff while the source is busy or
    /// locked (for example a writer holding an exclusive lock or a TRUNCATE checkpoint).
    /// </summary>
    private static async Task CopyAsync(SqliteConnection source, SqliteConnection destination, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Stopwatch elapsed = Stopwatch.StartNew();
        TimeSpan delay = TimeSpan.FromMilliseconds(25);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                source.BackupDatabase(destination);
                return;
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode is SqliteBusy or SqliteLocked)
            {
                if (elapsed.Elapsed + delay > timeout)
                {
                    throw new TimeoutException(
                        $"Queue database stayed busy for {timeout.TotalSeconds:0} s; no backup was written. Retry when the queue is less busy.",
                        exception);
                }
                await Task.Delay(delay, cancellationToken);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 1000));
            }
        }
    }

    private static SqliteConnection Open(string path, SqliteOpenMode mode, TimeSpan timeout)
    {
        // No pooling: every handle is closed before the file is hashed, renamed or deleted.
        SqliteConnection connection = new(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = Math.Max(1, (int)Math.Ceiling(timeout.TotalSeconds))
        }.ToString());
        connection.Open();
        using SqliteCommand pragma = connection.CreateCommand();
        // Short SQLite-level waits: CopyAsync retries asynchronously up to the full bound
        // instead of blocking a thread inside backup_step for the whole timeout.
        pragma.CommandText = $"PRAGMA busy_timeout = {(long)Math.Min(timeout.TotalMilliseconds, 250)};";
        pragma.ExecuteNonQuery();
        return connection;
    }

    /// <summary>Sets the persistent journal mode and leaves a single, fully checkpointed file.</summary>
    private static async Task SetJournalModeAsync(string path, string mode, TimeSpan timeout, CancellationToken cancellationToken)
    {
        await using (SqliteConnection connection = Open(path, SqliteOpenMode.ReadWrite, timeout))
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
            CreatePrivateFile(temporary, privateAcl: true);
            await using (FileStream stream = new(temporary, FileMode.Truncate, FileAccess.Write))
            {
                await JsonSerializer.SerializeAsync(stream, manifest, QueueBackupJsonContext.Default.QueueBackupManifest, cancellationToken);
                stream.Flush(true);
            }
            File.Move(temporary, path);
            DirectorySync.Flush(Path.GetDirectoryName(path)!);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    /// <summary>
    /// Creates an empty file readable only by its owner: mode 0600 on Unix (set at creation,
    /// so the umask cannot widen it) and, with <paramref name="privateAcl"/>, a protected ACL
    /// for SYSTEM, Administrators and the current user on Windows.
    /// </summary>
    internal static void CreatePrivateFile(string path, bool privateAcl)
    {
        if (OperatingSystem.IsWindows())
        {
            if (privateAcl)
            {
                FileSecurity security = new();
                ApplyPrivateRules(security);
                using FileStream stream = new FileInfo(path).Create(
                    FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
            }
            else
            {
                using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            }
            return;
        }
        using FileStream unix = new(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
    }

    /// <summary>Creates a missing backup directory as owner-only (0700 / protected ACL); never changes an existing one.</summary>
    internal static void CreatePrivateDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            return;
        }
        if (OperatingSystem.IsWindows())
        {
            DirectorySecurity security = new();
            ApplyPrivateRules(security);
            new DirectoryInfo(path).Create(security);
            return;
        }
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyPrivateRules(FileSystemSecurity security)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        InheritanceFlags inherit = security is DirectorySecurity
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        SecurityIdentifier[] owners =
        [
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
            WindowsIdentity.GetCurrent().User!
        ];
        foreach (SecurityIdentifier sid in owners.Distinct())
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
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
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(QueueBackupManifest))]
[JsonSerializable(typeof(QueueRestoreResult))]
internal sealed partial class QueueBackupJsonContext : JsonSerializerContext;
