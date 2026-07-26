using System.Globalization;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

public sealed class SqliteEventStore : IDurableEventStore
{
    private const string TimestampFormat = "O";
    private readonly string databasePath;
    private readonly string connectionString;
    private readonly long maximumBytes;
    private readonly IClock clock;

    public SqliteEventStore(string databasePath, long maximumBytes, IClock? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (maximumBytes < 1_048_576)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumBytes),
                "Queue maximum must be at least 1 MiB.");
        }

        string fullPath = Path.GetFullPath(databasePath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        SqliteConnectionStringBuilder builder = new()
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        };
        connectionString = builder.ToString();
        this.databasePath = fullPath;
        this.maximumBytes = maximumBytes;
        this.clock = clock ?? new SystemClock();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS queue_events (
                event_id TEXT PRIMARY KEY NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL,
                received_at TEXT NOT NULL,
                state INTEGER NOT NULL,
                delivery_attempts INTEGER NOT NULL DEFAULT 0,
                lease_until TEXT NULL,
                next_attempt_at TEXT NULL,
                last_failure_code TEXT NULL,
                acknowledgement TEXT NULL,
                delivered_at TEXT NULL,
                CHECK (length(event_id) BETWEEN 1 AND 128),
                CHECK (payload_bytes > 0)
            );

            CREATE INDEX IF NOT EXISTS ix_queue_events_delivery
                ON queue_events(state, next_attempt_at, received_at);

            CREATE TABLE IF NOT EXISTS schema_history (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at TEXT NOT NULL,
                hash TEXT NOT NULL
            );

            INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
            VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v1');
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        ApplyRestrictivePermissions();
    }

    public async Task<EnqueueResult> EnqueueAsync(
        QueuedEvent candidate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        int payloadBytes = System.Text.Encoding.UTF8.GetByteCount(candidate.Payload);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        long currentBytes = await GetTotalBytesAsync(connection, transaction, cancellationToken);
        if (currentBytes + payloadBytes > maximumBytes)
        {
            throw new QueueCapacityExceededException(maximumBytes, currentBytes, payloadBytes);
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT OR IGNORE INTO queue_events (
                event_id, fingerprint, payload, payload_bytes, received_at, state,
                delivery_attempts)
            VALUES (
                $event_id, $fingerprint, $payload, $payload_bytes, $received_at,
                $state, $delivery_attempts);
            """;
        command.Parameters.AddWithValue("$event_id", candidate.EventId);
        command.Parameters.AddWithValue("$fingerprint", candidate.Fingerprint);
        command.Parameters.AddWithValue("$payload", candidate.Payload);
        command.Parameters.AddWithValue("$payload_bytes", payloadBytes);
        command.Parameters.AddWithValue(
            "$received_at",
            candidate.ReceivedAt.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$state", (int)QueueState.Queued);
        command.Parameters.AddWithValue("$delivery_attempts", candidate.DeliveryAttempts);

        int affected = await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new EnqueueResult(affected == 1, affected == 0, candidate.EventId);
    }

    public async Task<IReadOnlyList<QueuedEvent>> LeaseAsync(
        int maximumCount,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken = default)
    {
        if (maximumCount is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        }

        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(leaseDuration, TimeSpan.Zero);

        DateTimeOffset now = clock.UtcNow;
        string nowValue = now.ToString(TimestampFormat, CultureInfo.InvariantCulture);
        string leaseValue = now.Add(leaseDuration).ToString(TimestampFormat, CultureInfo.InvariantCulture);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using SqliteCommand select = connection.CreateCommand();
        select.Transaction = transaction;
        select.CommandText =
            """
            SELECT event_id, fingerprint, payload, received_at, state, delivery_attempts
            FROM queue_events
            WHERE (
                    state = $queued
                    OR (state = $retrying AND (next_attempt_at IS NULL OR next_attempt_at <= $now))
                    OR (state = $uploading AND lease_until <= $now)
                  )
            ORDER BY received_at ASC
            LIMIT $maximum_count;
            """;
        select.Parameters.AddWithValue("$queued", (int)QueueState.Queued);
        select.Parameters.AddWithValue("$retrying", (int)QueueState.Retrying);
        select.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        select.Parameters.AddWithValue("$now", nowValue);
        select.Parameters.AddWithValue("$maximum_count", maximumCount);

        List<QueuedEvent> selected = [];
        await using (SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                selected.Add(new QueuedEvent(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    DateTimeOffset.Parse(
                        reader.GetString(3),
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind),
                    (QueueState)reader.GetInt32(4),
                    reader.GetInt32(5)));
            }
        }

        foreach (QueuedEvent item in selected)
        {
            await using SqliteCommand update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText =
                """
                UPDATE queue_events
                SET state = $uploading,
                    lease_until = $lease_until,
                    delivery_attempts = delivery_attempts + 1
                WHERE event_id = $event_id;
                """;
            update.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
            update.Parameters.AddWithValue("$lease_until", leaseValue);
            update.Parameters.AddWithValue("$event_id", item.EventId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return selected
            .Select(item => item with
            {
                State = QueueState.Uploading,
                DeliveryAttempts = item.DeliveryAttempts + 1
            })
            .ToArray();
    }

    public async Task MarkDeliveredAsync(
        string eventId,
        string acknowledgement,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        ArgumentException.ThrowIfNullOrWhiteSpace(acknowledgement);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE queue_events
            SET state = $delivered,
                acknowledgement = $acknowledgement,
                delivered_at = $delivered_at,
                lease_until = NULL,
                next_attempt_at = NULL,
                last_failure_code = NULL
            WHERE event_id = $event_id AND state = $uploading;
            """;
        command.Parameters.AddWithValue("$delivered", (int)QueueState.Delivered);
        command.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        command.Parameters.AddWithValue("$acknowledgement", acknowledgement);
        command.Parameters.AddWithValue(
            "$delivered_at",
            clock.UtcNow.ToString(TimestampFormat, CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$event_id", eventId);

        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidQueueTransitionException(eventId, "uploading", "delivered");
        }
    }

    public async Task MarkRetryingAsync(
        string eventId,
        string failureCode,
        DateTimeOffset retryAfter,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        ArgumentException.ThrowIfNullOrWhiteSpace(failureCode);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE queue_events
            SET state = $retrying,
                next_attempt_at = $next_attempt_at,
                last_failure_code = $failure_code,
                lease_until = NULL
            WHERE event_id = $event_id AND state = $uploading;
            """;
        command.Parameters.AddWithValue("$retrying", (int)QueueState.Retrying);
        command.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        command.Parameters.AddWithValue(
            "$next_attempt_at",
            retryAfter.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$failure_code", failureCode);
        command.Parameters.AddWithValue("$event_id", eventId);

        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidQueueTransitionException(eventId, "uploading", "retrying");
        }
    }

    public async Task MarkDeadLetteredAsync(
        string eventId,
        string failureCode,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        ArgumentException.ThrowIfNullOrWhiteSpace(failureCode);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE queue_events
            SET state = $dead_lettered,
                last_failure_code = $failure_code,
                lease_until = NULL,
                next_attempt_at = NULL
            WHERE event_id = $event_id AND state = $uploading;
            """;
        command.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
        command.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        command.Parameters.AddWithValue("$failure_code", failureCode);
        command.Parameters.AddWithValue("$event_id", eventId);

        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidQueueTransitionException(eventId, "uploading", "dead-lettered");
        }
    }

    public async Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                SUM(CASE WHEN state = 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 3 THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 4 THEN 1 ELSE 0 END),
                COALESCE(SUM(payload_bytes), 0),
                MIN(CASE WHEN state IN (0, 1, 2) THEN received_at END)
            FROM queue_events;
            """;

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        DateTimeOffset? oldest = reader.IsDBNull(6)
            ? null
            : DateTimeOffset.Parse(
                reader.GetString(6),
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);

        return new QueueSnapshot(
            GetInt64OrZero(reader, 0),
            GetInt64OrZero(reader, 1),
            GetInt64OrZero(reader, 2),
            GetInt64OrZero(reader, 3),
            GetInt64OrZero(reader, 4),
            GetInt64OrZero(reader, 5),
            oldest);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static async Task<long> GetTotalBytesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COALESCE(SUM(payload_bytes), 0) FROM queue_events;";
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt64(result, CultureInfo.InvariantCulture);
    }

    private static long GetInt64OrZero(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);
    }

    private void ApplyRestrictivePermissions()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        foreach (string path in new[] { databasePath, $"{databasePath}-wal", $"{databasePath}-shm" })
        {
            if (File.Exists(path))
            {
                File.SetUnixFileMode(path, mode);
            }
        }
    }
}

public sealed class QueueCapacityExceededException(
    long maximumBytes,
    long currentBytes,
    long attemptedBytes)
    : Exception(
        $"Queue capacity exceeded. Maximum={maximumBytes}, Current={currentBytes}, Attempted={attemptedBytes}.")
{
}

public sealed class InvalidQueueTransitionException(
    string eventId,
    string expectedState,
    string requestedState)
    : Exception(
        $"Event '{eventId}' is not in required state '{expectedState}' for transition to '{requestedState}'.")
{
}
