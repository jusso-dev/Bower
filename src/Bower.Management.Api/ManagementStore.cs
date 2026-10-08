using System.Globalization;
using Bower.Jobs;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

public sealed class ManagementStore(string databasePath)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = Path.GetFullPath(databasePath),
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Private,
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
            CREATE TABLE IF NOT EXISTS collector_jobs (
                collector_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                schedule TEXT NOT NULL,
                last_run_at TEXT NULL,
                last_state TEXT NULL,
                next_run_at TEXT NULL,
                PRIMARY KEY (collector_id, job_id),
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
        // Additive migrations for databases created by earlier versions.
        await AddColumnIfMissingAsync(connection, "collectors", "desired_policy_hash", "TEXT NULL", cancellationToken);
        await AddColumnIfMissingAsync(connection, "collectors", "ledger_sequence", "INTEGER NULL", cancellationToken);
        await AddColumnIfMissingAsync(connection, "collectors", "ledger_hash", "TEXT NULL", cancellationToken);
        await AddColumnIfMissingAsync(connection, "collectors", "dead_lettered", "INTEGER NOT NULL DEFAULT 0", cancellationToken);
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
        ValidateHeartbeat(heartbeat);
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

        string deliveryStatus = heartbeat.DeliveryStatus;
        if (heartbeat.Ledger is { } ledger
            && await LedgerRegressedAsync(connection, transaction, collectorId, ledger, cancellationToken))
        {
            // The collector's queue history went backwards or was rewritten since the last
            // witnessed head: flag it and keep the witnessed head, not the new one.
            deliveryStatus = "ledger-regression";
            await InsertAuditAsync(
                connection, transaction, "collector.ledger-regression", collectorId,
                principalObjectId, collectorId, now, cancellationToken);
        }
        else if (heartbeat.Ledger is { } accepted)
        {
            await CommandAsync(
                connection,
                transaction,
                "UPDATE collectors SET ledger_sequence = $sequence, ledger_hash = $hash WHERE id = $id;",
                [("$sequence", accepted.Sequence), ("$hash", accepted.Hash), ("$id", collectorId)],
                cancellationToken);
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
                delivery_status = $delivery,
                dead_lettered = $dead_lettered
            WHERE id = $id;
            """,
            [
                ("$version", heartbeat.Version),
                ("$now", Format(now)),
                ("$configuration", heartbeat.ConfigurationHash),
                ("$policy", heartbeat.PolicyHash),
                ("$queue", heartbeat.QueueDepth),
                ("$delivery", deliveryStatus),
                ("$dead_lettered", heartbeat.DeadLettered ?? 0),
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
        if (heartbeat.Jobs is not null)
        {
            await ReplaceJobsAsync(connection, transaction, collectorId, heartbeat.Jobs, cancellationToken);
        }

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
            "suspended" or "suspended-inactive" => current is CollectorStatus.Approved or CollectorStatus.Active,
            "reinstated" => current == CollectorStatus.Suspended,
            "revoked" => current != CollectorStatus.Revoked,
            _ => false
        } &&
        target switch
        {
            CollectorStatus.Approved => action is "approved" or "reinstated",
            CollectorStatus.Suspended => action is "suspended" or "suspended-inactive",
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
                item.PolicyInSync == false ||
                item.DeadLettered > 0 ||
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
            exceptions,
            collectors.Count(item => item.PolicyInSync == false),
            collectors.Sum(item => item.DeadLettered));
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
        string? desiredPolicy = ReadOptionalString(reader, "desired_policy_hash");
        long? ledgerSequence = reader.IsDBNull(reader.GetOrdinal("ledger_sequence"))
            ? null
            : reader.GetInt64(reader.GetOrdinal("ledger_sequence"));
        long deadLettered = reader.GetInt64(reader.GetOrdinal("dead_lettered"));
        await using SqliteConnection detailConnection = await OpenAsync(cancellationToken);
        IReadOnlyList<SourceReport> sources =
            await ReadSourcesAsync(detailConnection, id, cancellationToken);
        IReadOnlyList<OutputReport> outputs =
            await ReadOutputsAsync(detailConnection, id, cancellationToken);
        IReadOnlyList<BackgroundJobStatus> jobs =
            await ReadJobsAsync(detailConnection, id, cancellationToken);
        return new(
            id, machine, environment, version, status, principal, firstSeen, lastSeen,
            configuration, policy, queue, delivery, sources, outputs, jobs,
            desiredPolicy, ledgerSequence, deadLettered);
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

    private static async Task<IReadOnlyList<BackgroundJobStatus>> ReadJobsAsync(
        SqliteConnection connection,
        string collectorId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT * FROM collector_jobs WHERE collector_id = $id ORDER BY job_id;";
        command.Parameters.AddWithValue("$id", collectorId);
        List<BackgroundJobStatus> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new BackgroundJobStatus(
                reader.GetString(reader.GetOrdinal("job_id")),
                reader.GetString(reader.GetOrdinal("schedule")),
                ParseOptional(reader, "last_run_at"),
                reader.IsDBNull(reader.GetOrdinal("last_state"))
                    ? null
                    : reader.GetString(reader.GetOrdinal("last_state")),
                ParseOptional(reader, "next_run_at")));
        }

        return records;
    }

    private static DateTimeOffset? ParseOptional(SqliteDataReader reader, string column)
    {
        int ordinal = reader.GetOrdinal(column);
        return reader.IsDBNull(ordinal) ? null : Parse(reader.GetString(ordinal));
    }

    private static async Task ReplaceJobsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        IReadOnlyList<BackgroundJobStatus> jobs,
        CancellationToken cancellationToken)
    {
        await CommandAsync(
            connection,
            transaction,
            "DELETE FROM collector_jobs WHERE collector_id = $id;",
            [("$id", collectorId)],
            cancellationToken);
        foreach (BackgroundJobStatus job in jobs)
        {
            await CommandAsync(
                connection,
                transaction,
                """
                INSERT INTO collector_jobs (
                    collector_id, job_id, schedule, last_run_at, last_state, next_run_at)
                VALUES ($collector, $id, $schedule, $last, $state, $next);
                """,
                [
                    ("$collector", collectorId),
                    ("$id", job.Id),
                    ("$schedule", job.Schedule),
                    ("$last", job.LastRunAt is null ? null : Format(job.LastRunAt.Value)),
                    ("$state", job.LastState),
                    ("$next", job.NextRunAt is null ? null : Format(job.NextRunAt.Value))
                ],
                cancellationToken);
        }
    }

    private static void ValidateHeartbeat(CollectorHeartbeat heartbeat)
    {
        if (heartbeat.Sources.Count > 250
            || heartbeat.Outputs.Count > 50
            || heartbeat.Jobs is { Count: > 50 }
            || heartbeat.Ledger is { } ledger && (ledger.Sequence < 0 || ledger.Hash.Length is 0 or > 128)
            || heartbeat.DeadLettered is < 0
            || (heartbeat.Jobs?.Any(job =>
                string.IsNullOrWhiteSpace(job.Id)
                || job.Id.Length > 128
                || job.Schedule.Length > 128
                || job.LastState?.Length > 64) ?? false))
        {
            throw new ArgumentException("Collector heartbeat is invalid.", nameof(heartbeat));
        }
    }

    /// <summary>
    /// Marks active collectors that have not reported since <paramref name="staleBefore"/>
    /// as stale and audits each transition once. A later heartbeat restores its status.
    /// </summary>
    public async Task<int> MarkStaleAsync(
        DateTimeOffset staleBefore,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        List<string> stale = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT id FROM collectors
                WHERE status IN ('Active', 'Approved')
                  AND last_seen_at < $stale_before
                  AND delivery_status <> 'stale'
                ORDER BY id;
                """;
            select.Parameters.AddWithValue("$stale_before", Format(staleBefore));
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                stale.Add(reader.GetString(0));
            }
        }

        foreach (string collectorId in stale)
        {
            await CommandAsync(
                connection,
                transaction,
                "UPDATE collectors SET delivery_status = 'stale' WHERE id = $id;",
                [("$id", collectorId)],
                cancellationToken);
            await InsertAuditAsync(
                connection,
                transaction,
                "collector.stale",
                collectorId,
                SystemActorId,
                SystemActorName,
                now,
                cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return stale.Count;
    }

    /// <summary>
    /// Sets the policy bundle hash a collector is expected to run. Heartbeats then show the
    /// collector as in sync or drifted. Null clears the expectation.
    /// </summary>
    public async Task<CollectorRecord?> SetDesiredPolicyAsync(
        string collectorId,
        string? policyHash,
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

        if (policyHash is not null && (policyHash.Length > 256 || !policyHash.StartsWith("sha256:", StringComparison.Ordinal)))
        {
            throw new ArgumentException("Policy hash must be a sha256: value.", nameof(policyHash));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        int changed = await CommandAsync(
            connection,
            transaction,
            "UPDATE collectors SET desired_policy_hash = $hash WHERE id = $id;",
            [("$hash", policyHash), ("$id", collectorId)],
            cancellationToken);
        if (changed == 0)
        {
            return null;
        }

        await InsertAuditAsync(
            connection, transaction, "collector.desired-policy-set", collectorId,
            actorObjectId, actorName, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(collectorId, cancellationToken);
    }

    /// <summary>
    /// Suspends approved or active collectors that have not reported for the inactivity
    /// window, so a forgotten machine identity cannot resume sending unnoticed. An
    /// administrator reinstates it explicitly.
    /// </summary>
    public async Task<int> SuspendInactiveAsync(
        DateTimeOffset inactiveBefore,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        List<string> inactive = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT id FROM collectors
                WHERE status IN ('Active', 'Approved') AND last_seen_at < $before
                ORDER BY id;
                """;
            select.Parameters.AddWithValue("$before", Format(inactiveBefore));
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                inactive.Add(reader.GetString(0));
            }
        }

        foreach (string collectorId in inactive)
        {
            await CommandAsync(
                connection,
                transaction,
                "UPDATE collectors SET status = 'Suspended' WHERE id = $id;",
                [("$id", collectorId)],
                cancellationToken);
            await InsertAuditAsync(
                connection, transaction, "collector.suspended-inactive", collectorId,
                SystemActorId, SystemActorName, now, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return inactive.Count;
    }

    private static async Task<bool> LedgerRegressedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        LedgerReport ledger,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT ledger_sequence, ledger_hash FROM collectors WHERE id = $id;";
        command.Parameters.AddWithValue("$id", collectorId);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken) || reader.IsDBNull(0))
        {
            return false;
        }

        long witnessed = reader.GetInt64(0);
        string witnessedHash = reader.GetString(1);
        return ledger.Sequence < witnessed
            || (ledger.Sequence == witnessed && !string.Equals(ledger.Hash, witnessedHash, StringComparison.Ordinal));
    }

    private static string? ReadOptionalString(SqliteDataReader reader, string column)
    {
        int ordinal = reader.GetOrdinal(column);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static async Task AddColumnIfMissingAsync(
        SqliteConnection connection,
        string table,
        string column,
        string definition,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand info = connection.CreateCommand();
        info.CommandText = $"SELECT 1 FROM pragma_table_info('{table}') WHERE name = $column;";
        info.Parameters.AddWithValue("$column", column);
        if (await info.ExecuteScalarAsync(cancellationToken) is not null)
        {
            return;
        }

        await ExecuteAsync(connection, $"ALTER TABLE {table} ADD COLUMN {column} {definition};", cancellationToken);
    }

    /// <summary>Records an operator action that is not a collector state change.</summary>
    public async Task RecordAuditAsync(
        string action,
        string targetType,
        string targetId,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await InsertAuditAsync(
            connection,
            transaction,
            action,
            targetId,
            actorObjectId,
            actorName,
            now,
            cancellationToken,
            targetType);
        await transaction.CommitAsync(cancellationToken);
    }

    public const string SystemActorId = "bower.background-jobs";
    public const string SystemActorName = "Bower background jobs";

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
        CancellationToken cancellationToken,
        string targetType = "collector")
    {
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO management_audit (
                id, action, target_type, target_id, actor_object_id, actor_name, occurred_at)
            VALUES ($id, $action, $target_type, $target, $actor, $name, $occurred);
            """,
            [
                ("$id", Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture)),
                ("$action", action),
                ("$target_type", targetType),
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
        await ExecuteAsync(
            connection,
            "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
            cancellationToken);
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
