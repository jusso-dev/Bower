using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>
/// Heartbeat v2 state and collector commands. A command is signed once when issued and the
/// same signed fields are delivered on every heartbeat until the collector reports a result
/// or it expires. Every state change writes an audit row in the same transaction.
/// </summary>
public sealed partial class ManagementStore
{
    public const int MaximumOutstandingCommands = 16;
    public const int MaximumCommandsPerHeartbeat = 8;
    public const int MaximumCommandResults = 32;
    public const int DefaultCommandLifetimeMinutes = 15;
    public const int MaximumCommandLifetimeMinutes = 60;

    /// <summary>
    /// Two missed intervals (<c>stale</c>) must come before the 15-minute <c>offline</c>
    /// threshold, so a reported interval may not exceed 5 minutes.
    /// </summary>
    public const int MaximumHeartbeatIntervalSeconds = 300;

    private static readonly string[] ResultStatuses =
        [CollectorCommandStatus.Succeeded, CollectorCommandStatus.Failed, CollectorCommandStatus.Rejected];

    private static async Task InitializeHeartbeatV2Async(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS collector_commands (
                id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL REFERENCES collectors(id),
                command TEXT NOT NULL,
                nonce TEXT NOT NULL UNIQUE,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                actor_object_id TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signature_key_id TEXT NOT NULL,
                signature_value TEXT NOT NULL,
                status TEXT NOT NULL,
                delivered_at TEXT NULL,
                completed_at TEXT NULL,
                result_code TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_collector_commands_collector
                ON collector_commands(collector_id, status, issued_at);
            """,
            cancellationToken);
        (string Column, string Definition)[] columns =
        [
            ("heartbeat_schema_version", "INTEGER NOT NULL DEFAULT 1"),
            ("heartbeat_interval_seconds", "INTEGER NULL"),
            ("oldest_undelivered_age_seconds", "INTEGER NULL"),
            ("last_successful_delivery_at", "TEXT NULL"),
            ("last_canary_command_id", "TEXT NULL"),
            ("last_canary_event_id", "TEXT NULL"),
            ("last_canary_at", "TEXT NULL"),
            ("last_canary_outcome", "TEXT NULL"),
            ("command_capabilities", "TEXT NULL"),
            ("delivery_failing_since", "TEXT NULL")
        ];
        foreach ((string column, string definition) in columns)
        {
            await AddColumnIfMissingAsync(connection, "collectors", column, definition, cancellationToken);
        }
    }

    /// <summary>
    /// Issues one signed command to an active collector that advertised it on its last
    /// heartbeat. Throws <see cref="CollectorStateException"/> (not active),
    /// <see cref="CollectorCommandCapabilityException"/>, <see cref="CollectorCommandLimitException"/>
    /// or <see cref="ArgumentException"/> (invalid request). Null for an unknown collector.
    /// </summary>
    public async Task<CollectorCommandRecord?> IssueCommandAsync(
        string collectorId,
        string command,
        string reason,
        int lifetimeMinutes,
        ManagementCommandSigner signer,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (!CollectorCommandTypes.All.Contains(command, StringComparer.Ordinal))
        {
            throw new ArgumentException("Unknown command.", nameof(command));
        }

        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 500)
        {
            throw new ArgumentException("A reason of 1–500 characters is required.", nameof(reason));
        }

        if (lifetimeMinutes is < 1 or > MaximumCommandLifetimeMinutes)
        {
            throw new ArgumentException("Command lifetime must be 1–60 minutes.", nameof(lifetimeMinutes));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? status;
        string? capabilities;
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT status, command_capabilities FROM collectors WHERE id = $id;";
            select.Parameters.AddWithValue("$id", collectorId);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            status = reader.GetString(0);
            capabilities = reader.IsDBNull(1) ? null : reader.GetString(1);
        }

        if (status != nameof(CollectorStatus.Active))
        {
            throw new CollectorStateException(collectorId, status);
        }

        if (!SplitCapabilities(capabilities).Contains(command, StringComparer.Ordinal))
        {
            throw new CollectorCommandCapabilityException(collectorId);
        }

        string? outstanding = await ScalarAsync(
            connection,
            transaction,
            """
            SELECT COUNT(*) FROM collector_commands
            WHERE collector_id = $id AND status IN ('pending', 'delivered') AND expires_at > $now;
            """,
            ("$id", collectorId),
            ("$now", Format(now)),
            cancellationToken);
        if (long.Parse(outstanding ?? "0", CultureInfo.InvariantCulture) >= MaximumOutstandingCommands)
        {
            throw new CollectorCommandLimitException(collectorId);
        }

        // UTC ticks are exactly the seven signed fractional digits, so stored times re-sign identically.
        DateTimeOffset issuedAt = Truncate(now);
        DateTimeOffset expiresAt = issuedAt.AddMinutes(lifetimeMinutes);
        string commandId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        string nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        SignedCollectorCommand signed = signer.Sign(commandId, collectorId, command, nonce, issuedAt, expiresAt);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO collector_commands (
                id, collector_id, command, nonce, issued_at, expires_at, reason, actor_object_id,
                actor_name, signature_algorithm, signature_key_id, signature_value, status)
            VALUES (
                $id, $collector, $command, $nonce, $issued, $expires, $reason, $actor,
                $name, $algorithm, $key, $value, 'pending');
            """,
            [
                ("$id", commandId),
                ("$collector", collectorId),
                ("$command", command),
                ("$nonce", nonce),
                ("$issued", Format(issuedAt)),
                ("$expires", Format(expiresAt)),
                ("$reason", reason.Trim()),
                ("$actor", actorObjectId),
                ("$name", actorName),
                ("$algorithm", signed.Signature.Algorithm),
                ("$key", signed.Signature.KeyId),
                ("$value", signed.Signature.Value)
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, $"collector.command-issued:{command}", CommandTarget(collectorId, commandId),
            actorObjectId, actorName, now, cancellationToken, "collector-command");
        await transaction.CommitAsync(cancellationToken);
        return new CollectorCommandRecord(
            commandId, collectorId, command, CollectorCommandStatus.Pending, reason.Trim(), actorObjectId,
            actorName, issuedAt, expiresAt, null, null, null);
    }

    /// <summary>
    /// Expires and audits every overdue pending or delivered command, whatever the
    /// collector's state (offline, suspended, revoked or heartbeating v1, none of which run
    /// the v2 exchange). Run by the <c>collector-staleness</c> job; idempotent.
    /// </summary>
    public async Task<int> ExpireOverdueCommandsAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        List<(string Id, string CollectorId)> expired = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT id, collector_id FROM collector_commands
                WHERE status IN ('pending', 'delivered') AND expires_at <= $now
                ORDER BY issued_at, id;
                """;
            select.Parameters.AddWithValue("$now", Format(now));
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                expired.Add((reader.GetString(0), reader.GetString(1)));
            }
        }

        foreach ((string commandId, string collectorId) in expired)
        {
            await ExpireAsync(connection, transaction, collectorId, commandId, now, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return expired.Count;
    }

    /// <summary>
    /// The 50 most recent commands for a collector, newest first. No signatures. An overdue
    /// pending or delivered command reads as <c>expired</c> before the job records it.
    /// </summary>
    public async Task<IReadOnlyList<CollectorCommandRecord>> ListCommandsAsync(
        string collectorId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT * FROM collector_commands WHERE collector_id = $id ORDER BY issued_at DESC, id LIMIT 50;";
        command.Parameters.AddWithValue("$id", collectorId);
        List<CollectorCommandRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            string status = reader.GetString(reader.GetOrdinal("status"));
            DateTimeOffset expiresAt = Parse(reader.GetString(reader.GetOrdinal("expires_at")));
            records.Add(new CollectorCommandRecord(
                reader.GetString(reader.GetOrdinal("id")),
                reader.GetString(reader.GetOrdinal("collector_id")),
                reader.GetString(reader.GetOrdinal("command")),
                status is CollectorCommandStatus.Pending or CollectorCommandStatus.Delivered && expiresAt <= now
                    ? CollectorCommandStatus.Expired
                    : status,
                reader.GetString(reader.GetOrdinal("reason")),
                reader.GetString(reader.GetOrdinal("actor_object_id")),
                reader.GetString(reader.GetOrdinal("actor_name")),
                Parse(reader.GetString(reader.GetOrdinal("issued_at"))),
                expiresAt,
                ParseOptional(reader, "delivered_at"),
                ParseOptional(reader, "completed_at"),
                ReadOptionalString(reader, "result_code")));
        }

        return records;
    }

    /// <summary>
    /// Inside the heartbeat transaction: record reported results (audited, acknowledged),
    /// expire overdue commands (audited), then select up to <see cref="MaximumCommandsPerHeartbeat"/>
    /// deliverable commands the collector advertised, first delivery audited.
    /// </summary>
    private static async Task<(IReadOnlyList<SignedCollectorCommand> Commands, IReadOnlyList<string> Acknowledged)>
        ExchangeCommandsAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string collectorId,
            CollectorHeartbeat heartbeat,
            string principalObjectId,
            DateTimeOffset now,
            CancellationToken cancellationToken)
    {
        List<string> acknowledged = [];
        bool unknownAudited = false;
        foreach (CommandResultReport result in heartbeat.CommandResults ?? [])
        {
            string? stored = result.CommandId is null
                ? null
                : await ScalarAsync(
                    connection,
                    transaction,
                    "SELECT status FROM collector_commands WHERE id = $id AND collector_id = $collector;",
                    ("$id", result.CommandId),
                    ("$collector", collectorId),
                    cancellationToken);
            if (stored is null)
            {
                // A forged, replayed or foreign command the collector refused: audit once per
                // heartbeat and acknowledge so it stops resending.
                if (!unknownAudited)
                {
                    await InsertAuditAsync(
                        connection, transaction, "collector.command-result-unknown", collectorId,
                        principalObjectId, collectorId, now, cancellationToken);
                    unknownAudited = true;
                }
            }
            else if (stored is CollectorCommandStatus.Pending or CollectorCommandStatus.Delivered
                or CollectorCommandStatus.Expired)
            {
                await CommandAsync(
                    connection,
                    transaction,
                    """
                    UPDATE collector_commands
                    SET status = $status, result_code = $code, completed_at = $completed
                    WHERE id = $id;
                    """,
                    [
                        ("$status", result.Status),
                        ("$code", result.Code),
                        ("$completed", Format(result.CompletedAt)),
                        ("$id", result.CommandId)
                    ],
                    cancellationToken);
                await InsertAuditAsync(
                    connection, transaction, $"collector.command-{result.Status}",
                    CommandTarget(collectorId, result.CommandId!), principalObjectId, collectorId, now,
                    cancellationToken, "collector-command");
            }

            if (result.CommandId is not null)
            {
                acknowledged.Add(result.CommandId);
            }
        }

        List<string> expired = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT id FROM collector_commands
                WHERE collector_id = $id AND status IN ('pending', 'delivered') AND expires_at <= $now
                ORDER BY issued_at, id;
                """;
            select.Parameters.AddWithValue("$id", collectorId);
            select.Parameters.AddWithValue("$now", Format(now));
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                expired.Add(reader.GetString(0));
            }
        }

        foreach (string commandId in expired)
        {
            await ExpireAsync(connection, transaction, collectorId, commandId, now, cancellationToken);
        }

        HashSet<string> capabilities = new(heartbeat.CommandCapabilities ?? [], StringComparer.Ordinal);
        List<(SignedCollectorCommand Command, bool FirstDelivery)> deliverable = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT * FROM collector_commands
                WHERE collector_id = $id AND status IN ('pending', 'delivered') AND expires_at > $now
                ORDER BY issued_at, id;
                """;
            select.Parameters.AddWithValue("$id", collectorId);
            select.Parameters.AddWithValue("$now", Format(now));
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken) && deliverable.Count < MaximumCommandsPerHeartbeat)
            {
                string command = reader.GetString(reader.GetOrdinal("command"));
                if (!capabilities.Contains(command))
                {
                    continue;
                }

                deliverable.Add((
                    new SignedCollectorCommand(
                        ManagementCommandSigner.Kind,
                        reader.GetString(reader.GetOrdinal("id")),
                        collectorId,
                        command,
                        reader.GetString(reader.GetOrdinal("nonce")),
                        ManagementCommandSigner.FormatTimestamp(Parse(reader.GetString(reader.GetOrdinal("issued_at")))),
                        ManagementCommandSigner.FormatTimestamp(Parse(reader.GetString(reader.GetOrdinal("expires_at")))),
                        new Bower.Integrity.DetachedSignature(
                            reader.GetString(reader.GetOrdinal("signature_algorithm")),
                            reader.GetString(reader.GetOrdinal("signature_key_id")),
                            reader.GetString(reader.GetOrdinal("signature_value")))),
                    reader.IsDBNull(reader.GetOrdinal("delivered_at"))));
            }
        }

        foreach ((SignedCollectorCommand command, bool first) in deliverable.Where(item => item.FirstDelivery))
        {
            await CommandAsync(
                connection,
                transaction,
                "UPDATE collector_commands SET status = 'delivered', delivered_at = $now WHERE id = $id;",
                [("$now", Format(now)), ("$id", command.CommandId)],
                cancellationToken);
            await InsertAuditAsync(
                connection, transaction, "collector.command-delivered", CommandTarget(collectorId, command.CommandId),
                principalObjectId, collectorId, now, cancellationToken, "collector-command");
        }

        return ([.. deliverable.Select(item => item.Command)], acknowledged);
    }

    private static async Task ExpireAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        string commandId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await CommandAsync(
            connection,
            transaction,
            "UPDATE collector_commands SET status = 'expired' WHERE id = $id;",
            [("$id", commandId)],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "collector.command-expired", CommandTarget(collectorId, commandId),
            SystemActorId, SystemActorName, now, cancellationToken, "collector-command");
    }

    /// <summary>The v2 heartbeat columns, written on every heartbeat (v1 clears the v2-only ones).</summary>
    private static Task<int> UpdateHeartbeatV2Async(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        CollectorHeartbeat heartbeat,
        string deliveryStatus,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        CanaryReport? canary = heartbeat.IsV2 ? heartbeat.LastCanary : null;
        IEnumerable<string> capabilities = heartbeat.IsV2
            ? (heartbeat.CommandCapabilities ?? []).Where(item => CollectorCommandTypes.All.Contains(item, StringComparer.Ordinal))
            : [];
        return CommandAsync(
            connection,
            transaction,
            """
            UPDATE collectors SET
                heartbeat_schema_version = $schema,
                heartbeat_interval_seconds = $interval,
                oldest_undelivered_age_seconds = $oldest,
                last_successful_delivery_at = COALESCE($last_delivery, last_successful_delivery_at),
                last_canary_command_id = COALESCE($canary_command, last_canary_command_id),
                last_canary_event_id = CASE WHEN $canary_command IS NULL THEN last_canary_event_id ELSE $canary_event END,
                last_canary_at = COALESCE($canary_at, last_canary_at),
                last_canary_outcome = COALESCE($canary_outcome, last_canary_outcome),
                command_capabilities = $capabilities,
                delivery_failing_since = CASE WHEN $operational = 1 THEN NULL
                    ELSE COALESCE(delivery_failing_since, $now) END
            WHERE id = $id;
            """,
            [
                ("$schema", heartbeat.IsV2 ? 2 : 1),
                ("$interval", heartbeat.IsV2 ? heartbeat.HeartbeatIntervalSeconds : null),
                ("$oldest", heartbeat.IsV2 ? heartbeat.OldestUndeliveredAgeSeconds : null),
                ("$last_delivery", heartbeat.IsV2 && heartbeat.LastSuccessfulDeliveryAt is { } delivered ? Format(delivered) : null),
                ("$canary_command", canary?.CommandId),
                ("$canary_event", canary?.EventId),
                ("$canary_at", canary is null ? null : Format(canary.RanAt)),
                ("$canary_outcome", canary?.Outcome),
                ("$capabilities", string.Join(',', capabilities) is { Length: > 0 } list ? list : null),
                ("$operational", DeliveryOperational(deliveryStatus) ? 1 : 0),
                ("$now", Format(now)),
                ("$id", collectorId)
            ],
            cancellationToken);
    }

    private static bool ValidHeartbeatV2(CollectorHeartbeat heartbeat) =>
        heartbeat.SchemaVersion is null or >= 1
        && heartbeat.HeartbeatIntervalSeconds is null or (>= 15 and <= MaximumHeartbeatIntervalSeconds)
        && heartbeat.OldestUndeliveredAgeSeconds is null or (>= 0 and <= MaximumReportedCount)
        && heartbeat.CommandCapabilities is null or { Count: <= 16 }
        && (heartbeat.CommandCapabilities?.All(item => ValidText(item, 64)) ?? true)
        && heartbeat.CommandResults is null or { Count: <= MaximumCommandResults }
        && (heartbeat.CommandResults?.All(result => result is not null
            && (result.CommandId is null || IsCommandIdentifier(result.CommandId))
            && ResultStatuses.Contains(result.Status, StringComparer.Ordinal)
            && ValidText(result.Code, 64)) ?? true)
        && heartbeat.LastCanary is null or
        {
            CommandId: not null,
            Outcome: { Length: > 0 and <= 32 },
            EventId: null or { Length: > 0 and <= 128 }
        } && (heartbeat.LastCanary is null || IsCommandIdentifier(heartbeat.LastCanary.CommandId));

    private static bool IsCommandIdentifier(string value) =>
        value.Length == 32 && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');

    private static string[] SplitCapabilities(string? value) =>
        value is null ? [] : value.Split(',', StringSplitOptions.RemoveEmptyEntries);

    private static string CommandTarget(string collectorId, string commandId) => $"{collectorId}/{commandId}";

    private static DateTimeOffset Truncate(DateTimeOffset value) =>
        new(value.UtcTicks, TimeSpan.Zero);

    private static CanaryReport? ReadCanary(SqliteDataReader reader)
    {
        string? commandId = ReadOptionalString(reader, "last_canary_command_id");
        string? at = ReadOptionalString(reader, "last_canary_at");
        string? outcome = ReadOptionalString(reader, "last_canary_outcome");
        return commandId is null || at is null || outcome is null
            ? null
            : new CanaryReport(commandId, ReadOptionalString(reader, "last_canary_event_id"), Parse(at), outcome);
    }
}
