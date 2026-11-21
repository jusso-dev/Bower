using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>
/// Audited alert mutes and outbound notification deduplication state.
/// Every mute and unmute writes an audit row in the same SQLite transaction.
/// </summary>
public sealed partial class ManagementStore
{
    public const int MinimumMuteMinutes = 15;
    public const int MaximumMuteMinutes = 43_200; // 30 days
    public const int DefaultMuteMinutes = 240; // 4 hours
    private const string AlertMuteTargetType = "alert-mute";

    private static Task InitializeAlertsAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS alert_mutes (
                id TEXT PRIMARY KEY,
                condition_id TEXT NOT NULL,
                collector_id TEXT NULL,
                reason TEXT NOT NULL,
                muted_by_object_id TEXT NOT NULL,
                muted_by_name TEXT NOT NULL,
                muted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                unmuted_at TEXT NULL,
                unmuted_by_object_id TEXT NULL,
                unmuted_by_name TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_alert_mutes_active
                ON alert_mutes(condition_id, expires_at);

            CREATE TABLE IF NOT EXISTS alert_notification_state (
                dedup_key TEXT PRIMARY KEY,
                condition_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                last_sent_at TEXT NOT NULL,
                resolved_at TEXT NULL,
                send_count INTEGER NOT NULL DEFAULT 1
            );
            """,
            cancellationToken);

    internal async Task<AlertMuteRecord> MuteAlertAsync(
        string conditionId,
        string? collectorId,
        int durationMinutes,
        string? reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!AlertCatalogue.IsKnownCondition(conditionId))
        {
            throw new ArgumentException("Unknown alert condition.", nameof(conditionId));
        }

        if (durationMinutes is < MinimumMuteMinutes or > MaximumMuteMinutes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(durationMinutes),
                $"Mute duration must be between {MinimumMuteMinutes} and {MaximumMuteMinutes} minutes.");
        }

        string trimmedReason = RequireText(reason, nameof(reason));
        string? trimmedCollector = string.IsNullOrWhiteSpace(collectorId) ? null : collectorId.Trim();
        if (trimmedCollector is { Length: > 128 })
        {
            throw new ArgumentException("Collector id is too long.", nameof(collectorId));
        }

        string id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        DateTimeOffset expiresAt = now.AddMinutes(durationMinutes);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO alert_mutes (
                id, condition_id, collector_id, reason,
                muted_by_object_id, muted_by_name, muted_at, expires_at)
            VALUES ($id, $condition, $collector, $reason, $actor, $actor_name, $now, $expires);
            """,
            [
                ("$id", id),
                ("$condition", conditionId),
                ("$collector", trimmedCollector),
                ("$reason", trimmedReason),
                ("$actor", actorObjectId),
                ("$actor_name", actorName),
                ("$now", Format(now)),
                ("$expires", Format(expiresAt))
            ],
            cancellationToken);

        await InsertAuditAsync(
            connection,
            transaction,
            "alert.muted",
            trimmedCollector is null ? conditionId : $"{conditionId}:{trimmedCollector}",
            actorObjectId,
            actorName,
            now,
            cancellationToken,
            AlertMuteTargetType);

        await transaction.CommitAsync(cancellationToken);
        return new AlertMuteRecord(
            id, conditionId, trimmedCollector, trimmedReason, actorObjectId, actorName, now, expiresAt, null, null);
    }

    internal async Task<AlertMuteRecord?> UnmuteAlertAsync(
        string id,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);

        AlertMuteRecord? existing = await ReadAlertMuteAsync(connection, transaction, id, cancellationToken);
        if (existing is null)
        {
            return null;
        }

        if (existing.UnmutedAt is null)
        {
            await CommandAsync(
                connection,
                transaction,
                """
                UPDATE alert_mutes
                SET unmuted_at = $now,
                    unmuted_by_object_id = $actor,
                    unmuted_by_name = $actor_name
                WHERE id = $id;
                """,
                [
                    ("$now", Format(now)),
                    ("$actor", actorObjectId),
                    ("$actor_name", actorName),
                    ("$id", id)
                ],
                cancellationToken);

            await InsertAuditAsync(
                connection,
                transaction,
                "alert.unmuted",
                existing.CollectorId is null ? existing.ConditionId : $"{existing.ConditionId}:{existing.CollectorId}",
                actorObjectId,
                actorName,
                now,
                cancellationToken,
                AlertMuteTargetType);
        }

        await transaction.CommitAsync(cancellationToken);
        return existing with { UnmutedAt = existing.UnmutedAt ?? now, UnmutedByName = existing.UnmutedByName ?? actorName };
    }

    internal async Task<List<AlertMuteRecord>> ListActiveMutesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT * FROM alert_mutes
            WHERE unmuted_at IS NULL AND expires_at > $now
            ORDER BY muted_at DESC;
            """;
        command.Parameters.AddWithValue("$now", Format(now));
        List<AlertMuteRecord> mutes = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            mutes.Add(MapAlertMute(reader));
        }

        return mutes;
    }

    internal async Task<bool> ShouldSendAlertNotificationAsync(
        string dedupKey,
        TimeSpan dedupWindow,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT last_sent_at, resolved_at FROM alert_notification_state
            WHERE dedup_key = $key;
            """;
        command.Parameters.AddWithValue("$key", dedupKey);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return true;
        }

        // If the condition previously cleared and returned, notify again immediately.
        if (!reader.IsDBNull(1))
        {
            return true;
        }

        DateTimeOffset lastSent = Parse(reader.GetString(0));
        return now - lastSent >= dedupWindow;
    }

    internal async Task RecordAlertNotificationSentAsync(
        string dedupKey,
        string conditionId,
        string severity,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO alert_notification_state (dedup_key, condition_id, severity, last_sent_at, resolved_at, send_count)
            VALUES ($key, $condition, $severity, $now, NULL, 1)
            ON CONFLICT(dedup_key) DO UPDATE SET
                severity = excluded.severity,
                last_sent_at = excluded.last_sent_at,
                resolved_at = NULL,
                send_count = alert_notification_state.send_count + 1;
            """,
            [
                ("$key", dedupKey),
                ("$condition", conditionId),
                ("$severity", severity),
                ("$now", Format(now))
            ],
            cancellationToken);

        await InsertAuditAsync(
            connection,
            transaction,
            "alert.notification-sent",
            dedupKey,
            "system",
            "Bower Alert Notifier",
            now,
            cancellationToken,
            "alert-notification");

        await transaction.CommitAsync(cancellationToken);
    }

    internal async Task ResolveClearedAlertNotificationsAsync(
        IReadOnlySet<string> activeDedupKeys,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);
        List<string> openKeys = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT dedup_key FROM alert_notification_state WHERE resolved_at IS NULL;";
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                string key = reader.GetString(0);
                if (!activeDedupKeys.Contains(key))
                {
                    openKeys.Add(key);
                }
            }
        }

        foreach (string key in openKeys)
        {
            await CommandAsync(
                connection,
                transaction,
                "UPDATE alert_notification_state SET resolved_at = $now WHERE dedup_key = $key;",
                [("$now", Format(now)), ("$key", key)],
                cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task<AlertMuteRecord?> ReadAlertMuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string id,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM alert_mutes WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? MapAlertMute(reader) : null;
    }

    private static AlertMuteRecord MapAlertMute(SqliteDataReader reader)
    {
        int colOrd = reader.GetOrdinal("collector_id");
        int unmutedAtOrd = reader.GetOrdinal("unmuted_at");
        int unmutedByOrd = reader.GetOrdinal("unmuted_by_name");
        return new AlertMuteRecord(
            reader.GetString(reader.GetOrdinal("id")),
            reader.GetString(reader.GetOrdinal("condition_id")),
            reader.IsDBNull(colOrd) ? null : reader.GetString(colOrd),
            reader.GetString(reader.GetOrdinal("reason")),
            reader.GetString(reader.GetOrdinal("muted_by_object_id")),
            reader.GetString(reader.GetOrdinal("muted_by_name")),
            Parse(reader.GetString(reader.GetOrdinal("muted_at"))),
            Parse(reader.GetString(reader.GetOrdinal("expires_at"))),
            reader.IsDBNull(unmutedAtOrd) ? null : Parse(reader.GetString(unmutedAtOrd)),
            reader.IsDBNull(unmutedByOrd) ? null : reader.GetString(unmutedByOrd));
    }
}
