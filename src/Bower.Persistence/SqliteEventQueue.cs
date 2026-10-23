using System.Data;
using System.Globalization;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

public sealed class SqliteEventStore : IDurableEventStore
{
    private const string TimestampFormat = "O";
    private const int MaximumEventIdLength = 128;
    private readonly string databasePath;
    private readonly string connectionString;
    private readonly long maximumBytes;
    private readonly TimeProvider clock;

    public SqliteEventStore(string databasePath, long maximumBytes, TimeProvider? clock = null)
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
            // Private cache: shared-cache mode is discouraged with WAL and serialises readers.
            Cache = SqliteCacheMode.Private,
            Pooling = true
        };
        connectionString = builder.ToString();
        this.databasePath = fullPath;
        this.maximumBytes = maximumBytes;
        this.clock = clock ?? TimeProvider.System;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA journal_mode = WAL;

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

            CREATE INDEX IF NOT EXISTS ix_queue_events_delivered_at
                ON queue_events(state, delivered_at);

            -- Covering index for the per-enqueue capacity SUM and the snapshot query.
            -- payload_bytes and received_at sit after the payload column, so without it
            -- both queries read every stored payload (including overflow pages).
            CREATE INDEX IF NOT EXISTS ix_queue_events_state_bytes
                ON queue_events(state, payload_bytes, received_at);

            CREATE TABLE IF NOT EXISTS schema_history (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at TEXT NOT NULL,
                hash TEXT NOT NULL
            );

            INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
            VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v1');

            INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
            VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v2-retention');
            """ + QueueLedger.Schema +
            """

            INSERT OR IGNORE INTO schema_history(version, applied_at, hash)
            VALUES (4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'bower-queue-v4-capacity-index');
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await QueueLedger.BackfillAsync(connection, cancellationToken);
        ApplyRestrictivePermissions();
    }

    public async Task<EnqueueResult> EnqueueAsync(
        QueuedEvent candidate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        // Reject what the table's NOT NULL and CHECK constraints would refuse, so invalid
        // input is an error and never mistaken for a duplicate.
        ValidateCandidate(candidate);
        int payloadBytes = System.Text.Encoding.UTF8.GetByteCount(candidate.Payload);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        // BEGIN IMMEDIATE takes the write lock before the duplicate and capacity checks so
        // concurrent enqueues cannot both pass them and insert or overshoot the limit.
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);

        // Idempotency wins over backpressure: a re-sent event is a duplicate even when the
        // queue is full.
        if (await ExistsAsync(connection, transaction, candidate, cancellationToken))
        {
            return new EnqueueResult(false, true, candidate.EventId);
        }

        long currentBytes = await GetUndeliveredBytesAsync(connection, transaction, cancellationToken);
        if (currentBytes + payloadBytes > maximumBytes)
        {
            throw new QueueCapacityExceededException(maximumBytes, currentBytes, payloadBytes);
        }

        // Plain INSERT: duplicates were ruled out under the write lock, so any constraint
        // failure is an error instead of being silently ignored.
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO queue_events (
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

        await command.ExecuteNonQueryAsync(cancellationToken);
        await QueueLedger.AppendAsync(
            connection,
            transaction,
            candidate.EventId,
            candidate.Payload,
            (string)command.Parameters["$received_at"].Value!,
            cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return new EnqueueResult(true, false, candidate.EventId);
    }

    /// <summary>
    /// Mirrors the table constraints: event id 1 to 128 characters (SQLite <c>length()</c>
    /// counts Unicode characters and stops at NUL), non-empty fingerprint and payload.
    /// Blank ids and fingerprints are also rejected: a blank id could never be settled.
    /// </summary>
    private static void ValidateCandidate(QueuedEvent candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate.EventId))
        {
            throw new ArgumentException("Event identifier cannot be empty or whitespace.", nameof(candidate));
        }

        if (candidate.EventId.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("Event identifier cannot contain NUL characters.", nameof(candidate));
        }

        if (candidate.EventId.Length > MaximumEventIdLength
            && candidate.EventId.EnumerateRunes().Count() > MaximumEventIdLength)
        {
            throw new ArgumentException("Event identifier cannot exceed 128 characters.", nameof(candidate));
        }

        if (string.IsNullOrWhiteSpace(candidate.Fingerprint))
        {
            throw new ArgumentException("Event fingerprint cannot be empty or whitespace.", nameof(candidate));
        }

        if (string.IsNullOrEmpty(candidate.Payload))
        {
            throw new ArgumentException("Event payload cannot be empty.", nameof(candidate));
        }
    }

    private static async Task<bool> ExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        QueuedEvent candidate,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        // Two EXISTS probes so each uses its own unique index.
        command.CommandText =
            """
            SELECT EXISTS (SELECT 1 FROM queue_events WHERE event_id = $event_id)
                OR EXISTS (SELECT 1 FROM queue_events WHERE fingerprint = $fingerprint);
            """;
        command.Parameters.AddWithValue("$event_id", candidate.EventId);
        command.Parameters.AddWithValue("$fingerprint", candidate.Fingerprint);
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt64(result, CultureInfo.InvariantCulture) != 0;
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

        DateTimeOffset now = clock.GetUtcNow();
        string nowValue = now.ToString(TimestampFormat, CultureInfo.InvariantCulture);
        string leaseValue = now.Add(leaseDuration).ToString(TimestampFormat, CultureInfo.InvariantCulture);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);

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
              AND NOT EXISTS (
                  SELECT 1 FROM queue_events AS outage
                  WHERE outage.state = $retrying
                    AND outage.last_failure_code GLOB 'destination-*'
                    AND outage.next_attempt_at > $now)
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

        // One prepared statement for the whole batch instead of one per leased row.
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
        SqliteParameter leasedEventId = update.Parameters.Add("$event_id", SqliteType.Text);
        foreach (QueuedEvent item in selected)
        {
            leasedEventId.Value = item.EventId;
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
            clock.GetUtcNow().ToString(TimestampFormat, CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$event_id", eventId);

        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidQueueTransitionException(eventId, "uploading", "delivered");
        }
    }

    public async Task<IReadOnlyList<string>> MarkDeliveredBatchAsync(
        IReadOnlyList<string> eventIds,
        string acknowledgement,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(eventIds);
        ArgumentException.ThrowIfNullOrWhiteSpace(acknowledgement);
        foreach (string eventId in eventIds)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        }

        if (eventIds.Count == 0)
        {
            return [];
        }

        // One transaction (one WAL commit and sync) for the whole batch instead of one per
        // event. Same guarded transition as MarkDeliveredAsync: only uploading rows change.
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
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
            clock.GetUtcNow().ToString(TimestampFormat, CultureInfo.InvariantCulture));
        SqliteParameter deliveredEventId = command.Parameters.Add("$event_id", SqliteType.Text);

        List<string> notLeased = [];
        foreach (string eventId in eventIds)
        {
            deliveredEventId.Value = eventId;
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                notLeased.Add(eventId);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return notLeased;
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

    public async Task<IReadOnlyList<string>> MarkFailedBatchAsync(
        IReadOnlyList<FailureSettlement> failures,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(failures);
        foreach (FailureSettlement failure in failures)
        {
            ArgumentNullException.ThrowIfNull(failure);
            ArgumentException.ThrowIfNullOrWhiteSpace(failure.EventId);
            ArgumentException.ThrowIfNullOrWhiteSpace(failure.FailureCode);
        }

        if (failures.Count == 0)
        {
            return [];
        }

        // One transaction for every failure in the batch, with the same guarded transitions
        // as MarkRetryingAsync and MarkDeadLetteredAsync. Any error rolls the whole batch
        // back, so the events stay leased and are redelivered after the lease expires.
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);
        await using SqliteCommand retry = connection.CreateCommand();
        retry.Transaction = transaction;
        retry.CommandText =
            """
            UPDATE queue_events
            SET state = $retrying,
                next_attempt_at = $next_attempt_at,
                delivery_attempts = MAX(0, delivery_attempts - CASE WHEN $failure_code GLOB 'destination-*' THEN 1 ELSE 0 END),
                last_failure_code = $failure_code,
                lease_until = NULL
            WHERE event_id = $event_id AND state = $uploading;
            """;
        retry.Parameters.AddWithValue("$retrying", (int)QueueState.Retrying);
        retry.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        SqliteParameter retryAt = retry.Parameters.Add("$next_attempt_at", SqliteType.Text);
        SqliteParameter retryCode = retry.Parameters.Add("$failure_code", SqliteType.Text);
        SqliteParameter retryEventId = retry.Parameters.Add("$event_id", SqliteType.Text);

        await using SqliteCommand deadLetter = connection.CreateCommand();
        deadLetter.Transaction = transaction;
        deadLetter.CommandText =
            """
            UPDATE queue_events
            SET state = $dead_lettered,
                last_failure_code = $failure_code,
                lease_until = NULL,
                next_attempt_at = NULL
            WHERE event_id = $event_id AND state = $uploading;
            """;
        deadLetter.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
        deadLetter.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        SqliteParameter deadCode = deadLetter.Parameters.Add("$failure_code", SqliteType.Text);
        SqliteParameter deadEventId = deadLetter.Parameters.Add("$event_id", SqliteType.Text);

        List<string> notLeased = [];
        foreach (FailureSettlement failure in failures)
        {
            SqliteCommand command;
            if (failure.RetryAfter is DateTimeOffset retryAfter)
            {
                retryAt.Value = retryAfter.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);
                retryCode.Value = failure.FailureCode;
                retryEventId.Value = failure.EventId;
                command = retry;
            }
            else
            {
                deadCode.Value = failure.FailureCode;
                deadEventId.Value = failure.EventId;
                command = deadLetter;
            }

            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                notLeased.Add(failure.EventId);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return notLeased;
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
                MIN(CASE WHEN state IN (0, 1, 2) THEN received_at END),
                COALESCE(SUM(CASE WHEN state <> 3 THEN payload_bytes ELSE 0 END), 0)
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
            oldest,
            GetInt64OrZero(reader, 7));
    }

    public async Task<int> PurgeDeliveredAsync(
        DateTimeOffset deliveredBefore,
        int maximumCount,
        CancellationToken cancellationToken = default)
    {
        if (maximumCount is < 1 or > 100_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);
        List<string> eventIds = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            // Only acknowledged rows are eligible. Undelivered, retrying and dead-lettered
            // events are never deleted here.
            select.CommandText =
                """
                SELECT event_id
                FROM queue_events
                WHERE state = $delivered
                  AND acknowledgement IS NOT NULL
                  AND delivered_at IS NOT NULL
                  AND delivered_at < $delivered_before
                ORDER BY delivered_at ASC
                LIMIT $maximum_count;
                """;
            select.Parameters.AddWithValue("$delivered", (int)QueueState.Delivered);
            select.Parameters.AddWithValue(
                "$delivered_before",
                deliveredBefore.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
            select.Parameters.AddWithValue("$maximum_count", maximumCount);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                eventIds.Add(reader.GetString(0));
            }
        }

        await using (SqliteCommand delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM queue_events WHERE event_id = $event_id AND state = $delivered;";
            SqliteParameter deletedEventId = delete.Parameters.Add("$event_id", SqliteType.Text);
            delete.Parameters.AddWithValue("$delivered", (int)QueueState.Delivered);
            foreach (string eventId in eventIds)
            {
                deletedEventId.Value = eventId;
                await delete.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        // Record the purge in the ledger in the same transaction so verification can tell
        // retention from tampering.
        await QueueLedger.MarkPurgedAsync(
            connection,
            transaction,
            eventIds,
            clock.GetUtcNow().ToString(TimestampFormat, CultureInfo.InvariantCulture),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        await QueueLedger.CompactAsync(
            connection,
            clock.GetUtcNow().ToString(TimestampFormat, CultureInfo.InvariantCulture),
            cancellationToken);
        return eventIds.Count;
    }

    public async Task<IReadOnlyList<DeadLetterRecord>> ListDeadLetteredAsync(
        int maximumCount,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumCount, 1);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT event_id, last_failure_code, delivery_attempts, received_at
            FROM queue_events
            WHERE state = $dead_lettered
            ORDER BY received_at ASC
            LIMIT $maximum_count;
            """;
        command.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
        command.Parameters.AddWithValue("$maximum_count", maximumCount);
        List<DeadLetterRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new DeadLetterRecord(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.GetInt32(2),
                DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)));
        }

        return records;
    }

    public async Task<int> ReplayDeadLetteredAsync(
        string? failureCodePrefix,
        IReadOnlyCollection<string>? eventIds,
        int maximumCount,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumCount, 1);
        if (string.IsNullOrWhiteSpace(failureCodePrefix) && (eventIds is null || eventIds.Count == 0))
        {
            return 0;
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);
        List<string> selected = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT event_id, last_failure_code FROM queue_events
                WHERE state = $dead_lettered
                ORDER BY received_at ASC;
                """;
            select.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            HashSet<string>? ids = eventIds is null ? null : new HashSet<string>(eventIds, StringComparer.Ordinal);
            while (await reader.ReadAsync(cancellationToken) && selected.Count < maximumCount)
            {
                string eventId = reader.GetString(0);
                string code = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
                bool idMatch = ids is null || ids.Count == 0 || ids.Contains(eventId);
                bool codeMatch = string.IsNullOrWhiteSpace(failureCodePrefix)
                    || code.StartsWith(failureCodePrefix, StringComparison.Ordinal);
                if (idMatch && codeMatch)
                {
                    selected.Add(eventId);
                }
            }
        }

        await using (SqliteCommand update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText =
                """
                UPDATE queue_events
                SET state = $queued, delivery_attempts = 0, next_attempt_at = NULL, lease_until = NULL
                WHERE event_id = $event_id AND state = $dead_lettered;
                """;
            update.Parameters.AddWithValue("$queued", (int)QueueState.Queued);
            update.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
            SqliteParameter replayedEventId = update.Parameters.Add("$event_id", SqliteType.Text);
            foreach (string eventId in selected)
            {
                replayedEventId.Value = eventId;
                await update.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return selected.Count;
    }

    public async Task<LedgerHead> GetLedgerHeadAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        (long sequence, string hash) = await QueueLedger.HeadAsync(connection, null, cancellationToken);
        return new LedgerHead(sequence, hash);
    }

    public async Task<LedgerVerification> VerifyLedgerAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        return await QueueLedger.VerifyAsync(connection, cancellationToken);
    }

    public async Task MaintainAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA wal_checkpoint(TRUNCATE);
            PRAGMA optimize;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        SqliteConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);
        // Connection-scoped settings must be applied on every pooled connection.
        await using SqliteCommand pragmas = connection.CreateCommand();
        pragmas.CommandText =
            """
            PRAGMA busy_timeout = 5000;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            """;
        await pragmas.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }

    private static async Task<long> GetUndeliveredBytesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        // Delivered rows are retained for idempotency only and are purged by retention,
        // so they do not count against the backpressure limit.
        command.CommandText =
            """
            SELECT COALESCE(SUM(payload_bytes), 0)
            FROM queue_events
            WHERE state IN ($queued, $uploading, $retrying, $dead_lettered);
            """;
        command.Parameters.AddWithValue("$queued", (int)QueueState.Queued);
        command.Parameters.AddWithValue("$uploading", (int)QueueState.Uploading);
        command.Parameters.AddWithValue("$retrying", (int)QueueState.Retrying);
        command.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
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
