using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

public sealed class ManagementStore(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = Path.GetFullPath(databasePath),
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Shared,
        Pooling = true
    }.ToString();

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await ExecuteAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken);
        await ExecuteAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken);
        await ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS collectors (
                id TEXT PRIMARY KEY,
                machine_name TEXT NOT NULL,
                environment TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                principal_object_id TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                configuration_hash TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                queue_depth INTEGER NOT NULL DEFAULT 0,
                delivery_status TEXT NOT NULL DEFAULT 'unknown'
            );
            CREATE TABLE IF NOT EXISTS collector_sources (
                collector_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                lag_seconds INTEGER NULL,
                last_event_at TEXT NULL,
                PRIMARY KEY (collector_id, source_id),
                FOREIGN KEY (collector_id) REFERENCES collectors(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS collector_outputs (
                collector_id TEXT NOT NULL,
                output_id TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                last_acknowledged_at TEXT NULL,
                last_error_code TEXT NULL,
                PRIMARY KEY (collector_id, output_id),
                FOREIGN KEY (collector_id) REFERENCES collectors(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                actor_object_id TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (collector_id) REFERENCES collectors(id)
            );
            CREATE TABLE IF NOT EXISTS management_audit (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                actor_object_id TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            """,
            cancellationToken);
    }

    public async Task<CollectorRecord> RegisterAsync(
        CollectorRegistration registration,
        string principalObjectId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ValidateRegistration(registration);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        string? boundPrincipal = await ScalarAsync(
            connection,
            transaction,
            "SELECT principal_object_id FROM collectors WHERE id = $id;",
            ("$id", registration.CollectorId),
            cancellationToken);
        if (boundPrincipal is not null &&
            !string.Equals(boundPrincipal, principalObjectId, StringComparison.Ordinal))
        {
            throw new CollectorIdentityConflictException(registration.CollectorId);
        }

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO collectors (
                id, machine_name, environment, version, status, principal_object_id,
                first_seen_at, last_seen_at, configuration_hash, policy_hash)
            VALUES (
                $id, $machine, $environment, $version, 'Pending', $principal,
                $now, $now, $configuration, $policy)
            ON CONFLICT(id) DO UPDATE SET
                machine_name = excluded.machine_name,
                environment = excluded.environment,
                version = excluded.version,
                last_seen_at = excluded.last_seen_at,
                configuration_hash = excluded.configuration_hash,
                policy_hash = excluded.policy_hash;
            """,
            [
                ("$id", registration.CollectorId),
                ("$machine", registration.MachineName),
                ("$environment", registration.Environment),
                ("$version", registration.Version),
                ("$principal", principalObjectId),
                ("$now", Format(now)),
                ("$configuration", registration.ConfigurationHash),
                ("$policy", registration.PolicyHash)
            ],
            cancellationToken);
        await ReplaceReportsAsync(
            connection,
            transaction,
            registration.CollectorId,
            registration.Sources,
            registration.Outputs,
            cancellationToken);
        await InsertAuditAsync(
            connection,
            transaction,
            "collector.registered",
            registration.CollectorId,
            principalObjectId,
            registration.CollectorId,
            now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (await GetAsync(registration.CollectorId, cancellationToken))!;
    }

    public async Task<CollectorRecord?> HeartbeatAsync(
        string collectorId,
        CollectorHeartbeat heartbeat,
        string principalObjectId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? status = await ScalarAsync(
            connection,
            transaction,
            """
            SELECT status FROM collectors
            WHERE id = $id AND principal_object_id = $principal;
            """,
            ("$id", collectorId),
            ("$principal", principalObjectId),
            cancellationToken);
        if (status is null)
        {
            return null;
        }

        if (status is "Pending" or "Suspended" or "Revoked")
        {
            throw new CollectorStateException(collectorId, status);
        }

        await CommandAsync(
            connection,
            transaction,
            """
            UPDATE collectors SET
                version = $version,
                status = 'Active',
                last_seen_at = $now,
                configuration_hash = $configuration,
                policy_hash = $policy,
                queue_depth = $queue,
                delivery_status = $delivery
            WHERE id = $id;
            """,
            [
                ("$version", heartbeat.Version),
                ("$now", Format(now)),
                ("$configuration", heartbeat.ConfigurationHash),
                ("$policy", heartbeat.PolicyHash),
                ("$queue", heartbeat.QueueDepth),
                ("$delivery", heartbeat.DeliveryStatus),
                ("$id", collectorId)
            ],
            cancellationToken);
        await ReplaceReportsAsync(
            connection,
            transaction,
            collectorId,
            heartbeat.Sources,
            heartbeat.Outputs,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(collectorId, cancellationToken);
    }

    public async Task<ApprovalRecord?> DecideAsync(
        string collectorId,
        CollectorStatus targetStatus,
        string action,
        string reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 500)
        {
            throw new ArgumentException("A reason of 1–500 characters is required.", nameof(reason));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? currentStatus = await ScalarAsync(
            connection,
            transaction,
            "SELECT status FROM collectors WHERE id = $id;",
            ("$id", collectorId),
            cancellationToken);
        if (currentStatus is null)
        {
            return null;
        }

        CollectorStatus current = Enum.Parse<CollectorStatus>(currentStatus);
        if (!TransitionAllowed(current, targetStatus, action))
        {
            throw new CollectorStateException(collectorId, currentStatus);
        }

        int changed = await CommandAsync(
            connection,
            transaction,
            "UPDATE collectors SET status = $status WHERE id = $id;",
            [("$status", targetStatus.ToString()), ("$id", collectorId)],
            cancellationToken);
        if (changed == 0)
        {
            return null;
        }

        ApprovalRecord record = new(
            Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            collectorId,
            action,
            reason.Trim(),
            actorObjectId,
            actorName,
            now);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO approvals (
                id, collector_id, action, reason, actor_object_id, actor_name, occurred_at)
            VALUES ($id, $collector, $action, $reason, $actor, $name, $occurred);
            """,
            [
                ("$id", record.Id),
                ("$collector", record.CollectorId),
                ("$action", record.Action),
                ("$reason", record.Reason),
                ("$actor", record.ActorObjectId),
                ("$name", record.ActorName),
                ("$occurred", Format(record.OccurredAt))
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection,
            transaction,
            $"collector.{action}",
            collectorId,
            actorObjectId,
            actorName,
            now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return record;
    }

    private static bool TransitionAllowed(
        CollectorStatus current,
        CollectorStatus target,
        string action) =>
        action switch
        {
            "approved" or "rejected" => current == CollectorStatus.Pending,
            "suspended" => current is CollectorStatus.Approved or CollectorStatus.Active,
            "revoked" => current != CollectorStatus.Revoked,
            _ => false
        } &&
        target switch
        {
            CollectorStatus.Approved => action == "approved",
            CollectorStatus.Suspended => action == "suspended",
            CollectorStatus.Revoked => action is "rejected" or "revoked",
            _ => false
        };

    public async Task<IReadOnlyList<CollectorRecord>> ListAsync(
        CollectorStatus? status,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = status is null
            ? "SELECT * FROM collectors ORDER BY last_seen_at DESC;"
            : "SELECT * FROM collectors WHERE status = $status ORDER BY last_seen_at DESC;";
        if (status is not null)
        {
            command.Parameters.AddWithValue("$status", status.Value.ToString());
        }

        List<CollectorRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(await ReadCollectorAsync(reader, connection, cancellationToken));
        }

        return records;
    }

    public async Task<CollectorRecord?> GetAsync(
        string id,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM collectors WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? await ReadCollectorAsync(reader, connection, cancellationToken)
            : null;
    }

    public async Task<IReadOnlyList<ApprovalRecord>> ListApprovalsAsync(
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT * FROM approvals ORDER BY occurred_at DESC LIMIT 250;";
        List<ApprovalRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new ApprovalRecord(
                reader.GetString(reader.GetOrdinal("id")),
                reader.GetString(reader.GetOrdinal("collector_id")),
                reader.GetString(reader.GetOrdinal("action")),
                reader.GetString(reader.GetOrdinal("reason")),
                reader.GetString(reader.GetOrdinal("actor_object_id")),
                reader.GetString(reader.GetOrdinal("actor_name")),
                Parse(reader.GetString(reader.GetOrdinal("occurred_at")))));
        }

        return records;
    }

    public async Task<IReadOnlyList<AuditRecord>> ListAuditAsync(
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT * FROM management_audit ORDER BY occurred_at DESC LIMIT 500;";
        List<AuditRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new AuditRecord(
                reader.GetString(reader.GetOrdinal("id")),
                reader.GetString(reader.GetOrdinal("action")),
                reader.GetString(reader.GetOrdinal("target_type")),
                reader.GetString(reader.GetOrdinal("target_id")),
                reader.GetString(reader.GetOrdinal("actor_object_id")),
                reader.GetString(reader.GetOrdinal("actor_name")),
                Parse(reader.GetString(reader.GetOrdinal("occurred_at")))));
        }

        return records;
    }

    public async Task<OverviewRecord> OverviewAsync(
        DateTimeOffset staleBefore,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<CollectorRecord> collectors = await ListAsync(null, cancellationToken);
        CollectorRecord[] exceptions = collectors
            .Where(item =>
                item.Status is CollectorStatus.Pending
                    or CollectorStatus.Suspended
                    or CollectorStatus.Revoked ||
                item.LastSeenAt < staleBefore ||
                !string.Equals(item.DeliveryStatus, "healthy", StringComparison.OrdinalIgnoreCase))
            .Take(12)
            .ToArray();
        return new OverviewRecord(
            collectors.Count,
            collectors.Count(item => item.Status == CollectorStatus.Pending),
            collectors.Count(item =>
                item.Status is CollectorStatus.Suspended or CollectorStatus.Revoked ||
                !string.Equals(item.DeliveryStatus, "healthy", StringComparison.OrdinalIgnoreCase)),
            collectors.Count(item => item.LastSeenAt < staleBefore),
            collectors.Sum(item => item.QueueDepth),
            collectors.SelectMany(item => item.Sources)
                .Count(item => string.Equals(item.Status, "healthy", StringComparison.OrdinalIgnoreCase)),
            collectors.SelectMany(item => item.Sources)
                .Count(item => !string.Equals(item.Status, "healthy", StringComparison.OrdinalIgnoreCase)),
            exceptions);
    }

    private async Task<CollectorRecord> ReadCollectorAsync(
        SqliteDataReader reader,
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        string id = reader.GetString(reader.GetOrdinal("id"));
        string machine = reader.GetString(reader.GetOrdinal("machine_name"));
        string environment = reader.GetString(reader.GetOrdinal("environment"));
        string version = reader.GetString(reader.GetOrdinal("version"));
        CollectorStatus status = Enum.Parse<CollectorStatus>(
            reader.GetString(reader.GetOrdinal("status")));
        string principal = reader.GetString(reader.GetOrdinal("principal_object_id"));
        DateTimeOffset firstSeen = Parse(reader.GetString(reader.GetOrdinal("first_seen_at")));
        DateTimeOffset lastSeen = Parse(reader.GetString(reader.GetOrdinal("last_seen_at")));
        string configuration = reader.GetString(reader.GetOrdinal("configuration_hash"));
        string policy = reader.GetString(reader.GetOrdinal("policy_hash"));
        long queue = reader.GetInt64(reader.GetOrdinal("queue_depth"));
        string delivery = reader.GetString(reader.GetOrdinal("delivery_status"));
        await using SqliteConnection detailConnection = await OpenAsync(cancellationToken);
        IReadOnlyList<SourceReport> sources =
            await ReadSourcesAsync(detailConnection, id, cancellationToken);
        IReadOnlyList<OutputReport> outputs =
            await ReadOutputsAsync(detailConnection, id, cancellationToken);
        return new(
            id, machine, environment, version, status, principal, firstSeen, lastSeen,
            configuration, policy, queue, delivery, sources, outputs);
    }

    private static async Task<IReadOnlyList<SourceReport>> ReadSourcesAsync(
        SqliteConnection connection,
        string collectorId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT * FROM collector_sources WHERE collector_id = $id ORDER BY source_id;";
        command.Parameters.AddWithValue("$id", collectorId);
        List<SourceReport> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new SourceReport(
                reader.GetString(reader.GetOrdinal("source_id")),
                reader.GetString(reader.GetOrdinal("type")),
                reader.GetString(reader.GetOrdinal("status")),
                reader.IsDBNull(reader.GetOrdinal("lag_seconds"))
                    ? null
                    : reader.GetInt64(reader.GetOrdinal("lag_seconds")),
                reader.IsDBNull(reader.GetOrdinal("last_event_at"))
                    ? null
                    : Parse(reader.GetString(reader.GetOrdinal("last_event_at")))));
        }

        return records;
    }

    private static async Task<IReadOnlyList<OutputReport>> ReadOutputsAsync(
        SqliteConnection connection,
        string collectorId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT * FROM collector_outputs WHERE collector_id = $id ORDER BY output_id;";
        command.Parameters.AddWithValue("$id", collectorId);
        List<OutputReport> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new OutputReport(
                reader.GetString(reader.GetOrdinal("output_id")),
                reader.GetString(reader.GetOrdinal("type")),
                reader.GetString(reader.GetOrdinal("status")),
                reader.IsDBNull(reader.GetOrdinal("last_acknowledged_at"))
                    ? null
                    : Parse(reader.GetString(reader.GetOrdinal("last_acknowledged_at"))),
                reader.IsDBNull(reader.GetOrdinal("last_error_code"))
                    ? null
                    : reader.GetString(reader.GetOrdinal("last_error_code"))));
        }

        return records;
    }

    private static async Task ReplaceReportsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        IReadOnlyList<SourceReport> sources,
        IReadOnlyList<OutputReport> outputs,
        CancellationToken cancellationToken)
    {
        await CommandAsync(
            connection,
            transaction,
            "DELETE FROM collector_sources WHERE collector_id = $id;",
            [("$id", collectorId)],
            cancellationToken);
        foreach (SourceReport source in sources)
        {
            await CommandAsync(
                connection,
                transaction,
                """
                INSERT INTO collector_sources (
                    collector_id, source_id, type, status, lag_seconds, last_event_at)
                VALUES ($collector, $id, $type, $status, $lag, $last);
                """,
                [
                    ("$collector", collectorId),
                    ("$id", source.Id),
                    ("$type", source.Type),
                    ("$status", source.Status),
                    ("$lag", source.LagSeconds),
                    ("$last", source.LastEventAt is null ? null : Format(source.LastEventAt.Value))
                ],
                cancellationToken);
        }

        await CommandAsync(
            connection,
            transaction,
            "DELETE FROM collector_outputs WHERE collector_id = $id;",
            [("$id", collectorId)],
            cancellationToken);
        foreach (OutputReport output in outputs)
        {
            await CommandAsync(
                connection,
                transaction,
                """
                INSERT INTO collector_outputs (
                    collector_id, output_id, type, status, last_acknowledged_at, last_error_code)
                VALUES ($collector, $id, $type, $status, $last, $error);
                """,
                [
                    ("$collector", collectorId),
                    ("$id", output.Id),
                    ("$type", output.Type),
                    ("$status", output.Status),
                    ("$last", output.LastAcknowledgedAt is null
                        ? null
                        : Format(output.LastAcknowledgedAt.Value)),
                    ("$error", output.LastErrorCode)
                ],
                cancellationToken);
        }
    }

    private static void ValidateRegistration(CollectorRegistration registration)
    {
        if (string.IsNullOrWhiteSpace(registration.CollectorId) ||
            registration.CollectorId.Length > 128 ||
            string.IsNullOrWhiteSpace(registration.MachineName) ||
            registration.MachineName.Length > 256 ||
            registration.ConfigurationHash.Length > 256 ||
            registration.PolicyHash.Length > 256 ||
            registration.Sources.Count > 250 ||
            registration.Outputs.Count > 50)
        {
            throw new ArgumentException("Collector registration is invalid.", nameof(registration));
        }
    }

    private static async Task InsertAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string action,
        string targetId,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO management_audit (
                id, action, target_type, target_id, actor_object_id, actor_name, occurred_at)
            VALUES ($id, $action, 'collector', $target, $actor, $name, $occurred);
            """,
            [
                ("$id", Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture)),
                ("$action", action),
                ("$target", targetId),
                ("$actor", actorObjectId),
                ("$name", actorName),
                ("$occurred", Format(now))
            ],
            cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await ExecuteAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken);
        return connection;
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<int> CommandAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        IReadOnlyList<(string Name, object? Value)> parameters,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static Task<int> CommandAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken) =>
        CommandAsync(connection, transaction, sql, [], cancellationToken);

    private static async Task<string?> ScalarAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        (string Name, object? Value) parameter,
        CancellationToken cancellationToken) =>
        await ScalarAsync(connection, transaction, sql, [parameter], cancellationToken);

    private static async Task<string?> ScalarAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        (string Name, object? Value) first,
        (string Name, object? Value) second,
        CancellationToken cancellationToken) =>
        await ScalarAsync(connection, transaction, sql, [first, second], cancellationToken);

    private static async Task<string?> ScalarAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        IReadOnlyList<(string Name, object? Value)> parameters,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        object? scalarResult = await command.ExecuteScalarAsync(cancellationToken);
        return scalarResult is null or DBNull
            ? null
            : Convert.ToString(scalarResult, CultureInfo.InvariantCulture);
    }

    private static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}

public sealed class CollectorIdentityConflictException(string collectorId)
    : InvalidOperationException($"Collector '{collectorId}' is bound to another identity.");

public sealed class CollectorStateException(string collectorId, string state)
    : InvalidOperationException($"Collector '{collectorId}' cannot heartbeat while {state}.");
