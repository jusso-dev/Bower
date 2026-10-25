using System.Globalization;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

public sealed partial class SqliteEventStore
{
    /// <summary>
    /// Auxiliary tables. Additive and created on every start without a schema version, so
    /// a queue stays at version 5 and either runtime can open the other's file.
    /// </summary>
    internal const string AuxiliarySchema =
        """

        CREATE TABLE IF NOT EXISTS suppression_windows (
            policy_id TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            window_end INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            allow_per_window INTEGER NOT NULL,
            admitted INTEGER NOT NULL,
            suppressed INTEGER NOT NULL,
            first_suppressed_at TEXT NULL,
            last_suppressed_at TEXT NULL,
            policy_version TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            event_category TEXT NOT NULL,
            event_type TEXT NOT NULL,
            application TEXT NOT NULL,
            environment TEXT NOT NULL,
            tenant_id TEXT NULL,
            key_fields TEXT NOT NULL,
            key_values TEXT NOT NULL,
            PRIMARY KEY (policy_id, key_hash, window_start)
        );

        CREATE INDEX IF NOT EXISTS ix_suppression_windows_end ON suppression_windows(window_end);

        CREATE TABLE IF NOT EXISTS source_activity (
            application TEXT NOT NULL,
            environment TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            PRIMARY KEY (application, environment)
        );
        """;

    private const int MaximumWindowsPerClose = 1_000;

    /// <summary>
    /// Fixed windows aligned to the Unix epoch, so every collector and runtime computes the
    /// same boundaries and a restart continues an open window from its durable counts.
    /// Returns false when the allowance is spent and the event was only counted.
    /// </summary>
    private static async Task<bool> AdmitAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SuppressionRequest rule,
        DateTimeOffset receivedAt,
        CancellationToken cancellationToken)
    {
        long now = receivedAt.ToUnixTimeSeconds();
        long windowStart = now - (((now % rule.WindowSeconds) + rule.WindowSeconds) % rule.WindowSeconds);

        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO suppression_windows (
                policy_id, key_hash, window_start, window_end, window_seconds, allow_per_window,
                admitted, suppressed, policy_version, policy_hash, event_category, event_type,
                application, environment, tenant_id, key_fields, key_values)
            VALUES (
                $policy, $key, $start, $end, $seconds, $allow, 0, 0, $version, $hash, $category,
                $type, $application, $environment, $tenant, $fields, $values)
            ON CONFLICT (policy_id, key_hash, window_start) DO NOTHING;
            """;
        command.Parameters.AddWithValue("$policy", rule.PolicyId);
        command.Parameters.AddWithValue("$key", rule.KeyHash);
        command.Parameters.AddWithValue("$start", windowStart);
        command.Parameters.AddWithValue("$end", windowStart + rule.WindowSeconds);
        command.Parameters.AddWithValue("$seconds", rule.WindowSeconds);
        command.Parameters.AddWithValue("$allow", rule.AllowPerWindow);
        command.Parameters.AddWithValue("$version", rule.PolicyVersion);
        command.Parameters.AddWithValue("$hash", rule.PolicyHash);
        command.Parameters.AddWithValue("$category", rule.EventCategory);
        command.Parameters.AddWithValue("$type", rule.EventType);
        command.Parameters.AddWithValue("$application", rule.Application);
        command.Parameters.AddWithValue("$environment", rule.Environment);
        command.Parameters.AddWithValue("$tenant", (object?)rule.TenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$fields", WriteStrings(rule.KeyFields));
        command.Parameters.AddWithValue("$values", WriteStrings(rule.KeyValues));
        await command.ExecuteNonQueryAsync(cancellationToken);

        command.Parameters.Clear();
        command.CommandText =
            """
            SELECT admitted < allow_per_window FROM suppression_windows
            WHERE policy_id = $policy AND key_hash = $key AND window_start = $start;
            """;
        command.Parameters.AddWithValue("$policy", rule.PolicyId);
        command.Parameters.AddWithValue("$key", rule.KeyHash);
        command.Parameters.AddWithValue("$start", windowStart);
        bool admit = Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture) == 1;

        command.CommandText = admit
            ? """
              UPDATE suppression_windows SET admitted = admitted + 1
              WHERE policy_id = $policy AND key_hash = $key AND window_start = $start;
              """
            : """
              UPDATE suppression_windows SET
                  suppressed = suppressed + 1,
                  first_suppressed_at = COALESCE(first_suppressed_at, $now),
                  last_suppressed_at = $now
              WHERE policy_id = $policy AND key_hash = $key AND window_start = $start;
              """;
        command.Parameters.AddWithValue(
            "$now",
            receivedAt.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
        return admit;
    }

    public async Task<int> CloseExpiredSuppressionWindowsAsync(
        DateTimeOffset now,
        Func<SuppressionWindow, QueuedEvent> createSummary,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(createSummary);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = await BeginWriteAsync(connection, false, cancellationToken);

        List<SuppressionWindow> expired = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT policy_id, key_hash, window_start, window_end, window_seconds,
                    allow_per_window, admitted, suppressed, first_suppressed_at,
                    last_suppressed_at, policy_version, policy_hash, event_category,
                    event_type, application, environment, tenant_id, key_fields, key_values
                FROM suppression_windows
                WHERE window_end <= $now
                ORDER BY window_end, policy_id, key_hash
                LIMIT $limit;
                """;
            select.Parameters.AddWithValue("$now", now.ToUnixTimeSeconds());
            select.Parameters.AddWithValue("$limit", MaximumWindowsPerClose);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                SuppressionRequest rule = new(
                    reader.GetString(0),
                    reader.GetString(10),
                    reader.GetString(11),
                    reader.GetString(1),
                    ReadStrings(reader.GetString(17)),
                    ReadStrings(reader.GetString(18)),
                    reader.GetInt32(4),
                    reader.GetInt32(5),
                    reader.GetString(12),
                    reader.GetString(13),
                    reader.GetString(14),
                    reader.GetString(15),
                    reader.IsDBNull(16) ? null : reader.GetString(16));
                expired.Add(new SuppressionWindow(
                    rule,
                    DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(2)),
                    DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(3)),
                    reader.GetInt64(6),
                    reader.GetInt64(7),
                    reader.IsDBNull(8) ? null : ParseTimestamp(reader.GetString(8)),
                    reader.IsDBNull(9) ? null : ParseTimestamp(reader.GetString(9))));
            }
        }

        int summaries = 0;
        foreach (SuppressionWindow window in expired)
        {
            if (window.Suppressed > 0)
            {
                QueuedEvent summary = createSummary(window);
                ValidateCandidate(summary);
                if (!await ExistsAsync(connection, transaction, summary, cancellationToken))
                {
                    await InsertAsync(connection, transaction, summary, cancellationToken);
                    summaries++;
                }
            }

            await using SqliteCommand delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText =
                """
                DELETE FROM suppression_windows
                WHERE policy_id = $policy AND key_hash = $key AND window_start = $start;
                """;
            delete.Parameters.AddWithValue("$policy", window.Rule.PolicyId);
            delete.Parameters.AddWithValue("$key", window.Rule.KeyHash);
            delete.Parameters.AddWithValue("$start", window.WindowStart.ToUnixTimeSeconds());
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return summaries;
    }

    public async Task<IReadOnlyList<SourceActivity>> GetSourceActivityAsync(
        CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT application, environment, last_seen_at, event_count
            FROM source_activity
            ORDER BY application, environment;
            """;
        List<SourceActivity> activity = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            activity.Add(new SourceActivity(
                reader.GetString(0),
                reader.GetString(1),
                ParseTimestamp(reader.GetString(2)),
                reader.GetInt64(3)));
        }

        return activity;
    }

    public async Task UpsertSourceActivityAsync(
        IReadOnlyCollection<SourceActivity> activity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activity);
        if (activity.Count == 0)
        {
            return;
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = await BeginWriteAsync(connection, true, cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO source_activity (application, environment, last_seen_at, event_count)
            VALUES ($application, $environment, $last_seen, $count)
            ON CONFLICT (application, environment) DO UPDATE SET
                last_seen_at = MAX(last_seen_at, excluded.last_seen_at),
                event_count = MAX(event_count, excluded.event_count);
            """;
        SqliteParameter application = command.Parameters.Add("$application", SqliteType.Text);
        SqliteParameter environment = command.Parameters.Add("$environment", SqliteType.Text);
        SqliteParameter lastSeen = command.Parameters.Add("$last_seen", SqliteType.Text);
        SqliteParameter count = command.Parameters.Add("$count", SqliteType.Integer);
        foreach (SourceActivity item in activity)
        {
            application.Value = item.Application;
            environment.Value = item.Environment;
            lastSeen.Value = item.LastSeenAt.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);
            count.Value = item.EventCount;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static string WriteStrings(IReadOnlyList<string> values)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartArray();
            foreach (string value in values)
            {
                writer.WriteStringValue(value);
            }

            writer.WriteEndArray();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string[] ReadStrings(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        return document.RootElement.EnumerateArray()
            .Select(item => item.GetString() ?? throw new InvalidDataException("Suppression key value is not a string."))
            .ToArray();
    }
}
