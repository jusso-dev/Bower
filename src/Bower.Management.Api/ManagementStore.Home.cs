using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>
/// Redaction counts for the home view. A collector reports running totals per detector type
/// since its process start; management turns each report into the increase since the last
/// one (a new start counts from zero) and adds it to a per-day bucket. Types and counts only.
/// </summary>
public sealed partial class ManagementStore
{
    /// <summary>Most detector types one heartbeat may report (the collector's own bound).</summary>
    public const int MaximumRedactionTypes = 64;

    /// <summary>Days of redaction buckets kept per collector.</summary>
    public const int RedactionRetentionDays = 35;

    private static Task InitializeHomeAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS collector_redaction_totals (
                collector_id TEXT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
                type TEXT NOT NULL,
                observed_since TEXT NOT NULL,
                events INTEGER NOT NULL,
                PRIMARY KEY (collector_id, type)
            );
            CREATE TABLE IF NOT EXISTS collector_redaction_days (
                collector_id TEXT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
                day TEXT NOT NULL,
                type TEXT NOT NULL,
                events INTEGER NOT NULL,
                PRIMARY KEY (collector_id, day, type)
            );
            CREATE INDEX IF NOT EXISTS ix_collector_redaction_days_day ON collector_redaction_days(day);
            """,
            cancellationToken);

    private static async Task RecordRedactionsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        RedactionReport report,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string since = Format(report.ObservedSince);
        string day = Day(now);
        await CommandAsync(
            connection,
            transaction,
            "UPDATE collectors SET redactions_observed_since = $since WHERE id = $id;",
            [("$since", since), ("$id", collectorId)],
            cancellationToken);
        foreach (RedactionReportCount count in report.Counts)
        {
            (string? previousSince, long previous) = await ReadRedactionTotalAsync(
                connection, transaction, collectorId, count.Type, cancellationToken);
            // Same process and not lower: the increase. A new process (or a lower total) restarted
            // its count from zero, so everything it reports is new.
            long increase = previousSince == since && count.Events >= previous
                ? count.Events - previous
                : count.Events;
            if (increase == 0 && previousSince == since)
            {
                continue;
            }

            await CommandAsync(
                connection,
                transaction,
                """
                INSERT INTO collector_redaction_totals (collector_id, type, observed_since, events)
                VALUES ($collector, $type, $since, $events)
                ON CONFLICT(collector_id, type) DO UPDATE SET
                    observed_since = excluded.observed_since,
                    events = excluded.events;
                """,
                [("$collector", collectorId), ("$type", count.Type), ("$since", since), ("$events", count.Events)],
                cancellationToken);
            if (increase > 0)
            {
                await CommandAsync(
                    connection,
                    transaction,
                    """
                    INSERT INTO collector_redaction_days (collector_id, day, type, events)
                    VALUES ($collector, $day, $type, $events)
                    ON CONFLICT(collector_id, day, type) DO UPDATE SET
                        events = MIN(collector_redaction_days.events + excluded.events, $maximum);
                    """,
                    [
                        ("$collector", collectorId), ("$day", day), ("$type", count.Type),
                        ("$events", increase), ("$maximum", MaximumReportedCount)
                    ],
                    cancellationToken);
            }
        }

        await CommandAsync(
            connection,
            transaction,
            "DELETE FROM collector_redaction_days WHERE collector_id = $collector AND day < $cutoff;",
            [("$collector", collectorId), ("$cutoff", Day(now.AddDays(-RedactionRetentionDays)))],
            cancellationToken);
    }

    private static async Task<(string? ObservedSince, long Events)> ReadRedactionTotalAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        string type,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT observed_since, events FROM collector_redaction_totals WHERE collector_id = $collector AND type = $type;";
        command.Parameters.AddWithValue("$collector", collectorId);
        command.Parameters.AddWithValue("$type", type);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? (reader.GetString(0), reader.GetInt64(1))
            : (null, 0);
    }

    /// <summary>The plain-English home view at <paramref name="now"/>.</summary>
    public async Task<HomeRecord> HomeAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        IReadOnlyList<CollectorRecord> collectors = await ListAsync(null, cancellationToken);
        SetupCanaryRun? latest = await LatestSetupCanaryRunAsync(cancellationToken);
        SetupCanaryRun? verified = await LatestVerifiedSetupCanaryRunAsync(cancellationToken);
        DateTimeOffset since = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero).AddDays(-(HomeStatus.WeekDays - 1));

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        List<RedactionReportCount> counts = [];
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT type, SUM(events) FROM collector_redaction_days
                WHERE day >= $since GROUP BY type ORDER BY type;
                """;
            command.Parameters.AddWithValue("$since", Day(since));
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                counts.Add(new RedactionReportCount(reader.GetString(0), reader.GetInt64(1)));
            }
        }

        HashSet<string> reporting = new(StringComparer.Ordinal);
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id FROM collectors WHERE redactions_observed_since IS NOT NULL;";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                reporting.Add(reader.GetString(0));
            }
        }

        return HomeStatus.Evaluate(collectors, latest, verified, counts, reporting, since, now);
    }

    private static bool ValidRedactions(RedactionReport? report) =>
        report is null
        || report.Counts is { Count: <= MaximumRedactionTypes } counts
        && counts.All(count => count is not null
            && IsRedactionType(count.Type)
            && count.Events is >= 0 and <= MaximumReportedCount)
        && counts.Select(count => count.Type).Distinct(StringComparer.Ordinal).Count() == counts.Count;

    /// <summary>A detector type id: lowercase letters, digits, dots and hyphens, at most 128 characters.</summary>
    private static bool IsRedactionType(string? value) =>
        value is { Length: > 0 and <= 128 }
        && char.IsAsciiLetterLower(value[0])
        && value.All(character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character)
            || character is '.' or '-');

    private static string Day(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}
