using System.Data;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// SQLite source cursor store with optimistic versioning. The type name is kept for
/// compatibility; it no longer uses Entity Framework Core (removed for Native AOT). The
/// schema is byte-for-byte the one EF Core created, so existing cursor databases keep
/// working unchanged.
/// </summary>
public sealed class EfSourceCursorStore : ISourceCursorStore
{
    // Identical to the DDL EF Core's EnsureCreated emitted for SourceCursorEntity.
    private const string CreateTableSql = """
        CREATE TABLE IF NOT EXISTS "source_cursors" (
            "SourceId" TEXT NOT NULL CONSTRAINT "PK_source_cursors" PRIMARY KEY,
            "Value" TEXT NOT NULL,
            "Version" INTEGER NOT NULL,
            "UpdatedAt" TEXT NOT NULL
        );
        """;

    private readonly string connectionString;
    private readonly string databasePath;

    public EfSourceCursorStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        this.databasePath = Path.GetFullPath(databasePath);
        string? directory = Path.GetDirectoryName(this.databasePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 5
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        bool created = !File.Exists(databasePath);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        // The cursor table shares the queue database: never add it to a newer queue schema.
        await SqliteEventStore.RefuseNewerSchemaAsync(command, cancellationToken);
        // As EF Core's EnsureCreated did: a new database file starts in WAL mode.
        command.CommandText = created ? "PRAGMA journal_mode = 'wal';" + CreateTableSql : CreateTableSql;
        await command.ExecuteNonQueryAsync(cancellationToken);
        ApplyRestrictivePermissions();
    }

    public async Task<SourceCursorSnapshot?> ReadAsync(
        string sourceId,
        CancellationToken cancellationToken = default)
    {
        ValidateSourceId(sourceId);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT "Value", "Version" FROM "source_cursors" WHERE "SourceId" = $sourceId LIMIT 2;
            """;
        command.Parameters.AddWithValue("$sourceId", sourceId);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        SourceCursorSnapshot snapshot = new(reader.GetString(0), reader.GetInt64(1));
        if (await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("Sequence contains more than one element.");
        }

        return snapshot;
    }

    public async Task<bool> TryAdvanceAsync(
        string sourceId,
        long expectedVersion,
        string value,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default)
    {
        ValidateSourceId(sourceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        ArgumentOutOfRangeException.ThrowIfNegative(expectedVersion);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        // Serializable maps to BEGIN IMMEDIATE: the read and the write hold one write lock.
        await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken);

        long? current;
        await using (SqliteCommand read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = """
                SELECT "Version" FROM "source_cursors" WHERE "SourceId" = $sourceId;
                """;
            read.Parameters.AddWithValue("$sourceId", sourceId);
            current = await read.ExecuteScalarAsync(cancellationToken) is long version ? version : null;
        }

        await using SqliteCommand write = connection.CreateCommand();
        write.Transaction = transaction;
        write.Parameters.AddWithValue("$sourceId", sourceId);
        write.Parameters.AddWithValue("$value", value);
        write.Parameters.AddWithValue("$updatedAt", updatedAt.ToUniversalTime());
        if (current is null)
        {
            if (expectedVersion != 0)
            {
                return false;
            }

            write.CommandText = """
                INSERT INTO "source_cursors" ("SourceId", "Value", "Version", "UpdatedAt")
                VALUES ($sourceId, $value, 1, $updatedAt);
                """;
        }
        else
        {
            if (current.Value != expectedVersion)
            {
                return false;
            }

            // The version predicate is the optimistic concurrency token.
            write.CommandText = """
                UPDATE "source_cursors" SET "Value" = $value, "Version" = $version, "UpdatedAt" = $updatedAt
                WHERE "SourceId" = $sourceId AND "Version" = $expectedVersion;
                """;
            write.Parameters.AddWithValue("$version", expectedVersion + 1);
            write.Parameters.AddWithValue("$expectedVersion", expectedVersion);
        }

        int affected;
        try
        {
            affected = await write.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (SqliteException)
        {
            // As EF Core's SaveChanges did (DbUpdateException): any failed write, such as a
            // concurrent writer creating the cursor first, is a lost race, not an error.
            return false;
        }

        if (affected != 1)
        {
            // The version predicate matched nothing: a concurrent update won.
            return false;
        }

        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        SqliteConnection connection = new(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private void ApplyRestrictivePermissions()
    {
        if (OperatingSystem.IsWindows() || !File.Exists(databasePath))
        {
            return;
        }

        File.SetUnixFileMode(databasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void ValidateSourceId(string sourceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceId);
        if (sourceId.Length > 128)
        {
            throw new ArgumentException(
                "Source identifier cannot exceed 128 characters.",
                nameof(sourceId));
        }
    }
}
