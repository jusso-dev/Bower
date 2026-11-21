using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>Dead-letter count and oldest timestamp for pre-expiry warnings and heartbeats.</summary>
public sealed record DeadLetterHealth(long Count, DateTimeOffset? OldestReceivedAt);

/// <summary>
/// Metadata-only evidence record written to the queue ledger before opt-in dead-letter
/// retention purges expired dead letters (#138). Never carries event payloads.
/// </summary>
public sealed record DeadLetterPurgeEvidence(
    long LedgerSequence,
    string ChainHash,
    DateTimeOffset PurgedAt,
    int PurgedCount,
    IReadOnlyDictionary<string, int> ReasonCounts,
    DateTimeOffset? OldestReceivedAt,
    DateTimeOffset? NewestReceivedAt,
    string EvidenceSha256);

public sealed partial class SqliteEventStore
{
    internal const string DeadLetterPurgeSchema =
        """
        CREATE TABLE IF NOT EXISTS queue_dead_letter_purges (
            ledger_sequence INTEGER PRIMARY KEY NOT NULL,
            chain_hash TEXT NOT NULL,
            purged_at TEXT NOT NULL,
            purged_count INTEGER NOT NULL,
            reason_counts_json TEXT NOT NULL,
            oldest_received_at TEXT NULL,
            newest_received_at TEXT NULL,
            evidence_sha256 TEXT NOT NULL
        );
        """;

    public async Task<DeadLetterHealth> GetDeadLetterHealthAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT COUNT(*), MIN(received_at)
            FROM queue_events_v5
            WHERE state = $dead_lettered;
            """;
        command.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new DeadLetterHealth(0, null);
        }

        long count = reader.GetInt64(0);
        DateTimeOffset? oldest = reader.IsDBNull(1)
            ? null
            : DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        return new DeadLetterHealth(count, oldest);
    }

    /// <summary>
    /// Opt-in dead-letter retention purge: selects up to <paramref name="maximumCount"/>
    /// dead-lettered rows older than <paramref name="olderThan"/>, appends a hash-chained
    /// metadata-only evidence entry to <c>queue_ledger</c> and <c>queue_dead_letter_purges</c>,
    /// marks the purged events' ledger entries as purged, and deletes those rows inside one
    /// transaction. Returns null when no dead-lettered rows qualify.
    /// </summary>
    public async Task<DeadLetterPurgeEvidence?> PurgeExpiredDeadLettersAsync(
        DateTimeOffset olderThan,
        int maximumCount,
        DateTimeOffset? at = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumCount, 1);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = await BeginWriteAsync(connection, checkCapacity: false, cancellationToken);

        List<(string EventId, string Reason, string ReceivedAt)> victims = [];
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText =
                """
                SELECT event_id, COALESCE(last_failure_code, 'unknown'), received_at
                FROM queue_events_v5
                WHERE state = $dead_lettered
                  AND received_at < $older_than
                ORDER BY received_at ASC, event_id ASC
                LIMIT $maximum_count;
                """;
            select.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
            select.Parameters.AddWithValue(
                "$older_than",
                olderThan.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
            select.Parameters.AddWithValue("$maximum_count", maximumCount);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                victims.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
            }
        }

        if (victims.Count == 0)
        {
            return null;
        }

        DateTimeOffset now = (at ?? clock.GetUtcNow()).ToUniversalTime();
        string purgedAtText = now.ToString(TimestampFormat, CultureInfo.InvariantCulture);

        SortedDictionary<string, int> reasons = new(StringComparer.Ordinal);
        foreach ((_, string reason, _) in victims)
        {
            string key = string.IsNullOrWhiteSpace(reason) ? "unknown" : reason;
            reasons[key] = reasons.TryGetValue(key, out int existing) ? existing + 1 : 1;
        }

        string oldestText = victims[0].ReceivedAt;
        string newestText = victims[^1].ReceivedAt;
        DateTimeOffset oldest = DateTimeOffset.Parse(oldestText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        DateTimeOffset newest = DateTimeOffset.Parse(newestText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

        string reasonsJson = JsonSerializer.Serialize(reasons, DeadLetterEvidenceJsonContext.Default.SortedDictionaryStringInt32);
        string evidencePayload = JsonSerializer.Serialize(
            new DeadLetterPurgeLedgerPayload("dead_letter_purge", purgedAtText, victims.Count, oldestText, newestText, reasons),
            DeadLetterEvidenceJsonContext.Default.DeadLetterPurgeLedgerPayload);
        string evidenceSha256 = QueueLedger.PayloadHash(evidencePayload);

        // Append a hash-chained evidence record to queue_ledger (marked purged at creation since
        // it has no row in queue_events_v5, keeping VerifyLedgerAsync intact) before deleting rows.
        (long previousSequence, string previousHash) = await QueueLedger.HeadAsync(connection, transaction, cancellationToken);
        long evidenceSequence = previousSequence + 1;
        string evidenceEventId = $"dead-letter-purge:{evidenceSequence.ToString(CultureInfo.InvariantCulture)}";
        string chainHash = QueueLedger.Chain(previousHash, evidenceSequence, evidenceEventId, evidenceSha256, purgedAtText);

        await using (SqliteCommand appendEvidence = connection.CreateCommand())
        {
            appendEvidence.Transaction = transaction;
            appendEvidence.CommandText =
                """
                INSERT INTO queue_ledger (sequence, event_id, payload_sha256, received_at, chain_hash, purged_at)
                VALUES ($sequence, $event_id, $payload_sha256, $received_at, $chain_hash, $purged_at);
                """;
            appendEvidence.Parameters.AddWithValue("$sequence", evidenceSequence);
            appendEvidence.Parameters.AddWithValue("$event_id", evidenceEventId);
            appendEvidence.Parameters.AddWithValue("$payload_sha256", evidenceSha256);
            appendEvidence.Parameters.AddWithValue("$received_at", purgedAtText);
            appendEvidence.Parameters.AddWithValue("$chain_hash", chainHash);
            appendEvidence.Parameters.AddWithValue("$purged_at", purgedAtText);
            await appendEvidence.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (SqliteCommand recordEvidence = connection.CreateCommand())
        {
            recordEvidence.Transaction = transaction;
            recordEvidence.CommandText =
                """
                INSERT INTO queue_dead_letter_purges (
                    ledger_sequence, chain_hash, purged_at, purged_count,
                    reason_counts_json, oldest_received_at, newest_received_at, evidence_sha256)
                VALUES (
                    $ledger_sequence, $chain_hash, $purged_at, $purged_count,
                    $reason_counts_json, $oldest_received_at, $newest_received_at, $evidence_sha256);
                """;
            recordEvidence.Parameters.AddWithValue("$ledger_sequence", evidenceSequence);
            recordEvidence.Parameters.AddWithValue("$chain_hash", chainHash);
            recordEvidence.Parameters.AddWithValue("$purged_at", purgedAtText);
            recordEvidence.Parameters.AddWithValue("$purged_count", victims.Count);
            recordEvidence.Parameters.AddWithValue("$reason_counts_json", reasonsJson);
            recordEvidence.Parameters.AddWithValue("$oldest_received_at", oldestText);
            recordEvidence.Parameters.AddWithValue("$newest_received_at", newestText);
            recordEvidence.Parameters.AddWithValue("$evidence_sha256", evidenceSha256);
            await recordEvidence.ExecuteNonQueryAsync(cancellationToken);
        }

        string[] eventIds = [.. victims.Select(item => item.EventId)];
        await using (SqliteCommand delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM queue_events_v5 WHERE event_id = $event_id AND state = $dead_lettered;";
            SqliteParameter idParam = delete.Parameters.Add("$event_id", SqliteType.Text);
            delete.Parameters.AddWithValue("$dead_lettered", (int)QueueState.DeadLettered);
            foreach (string eventId in eventIds)
            {
                idParam.Value = eventId;
                await delete.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        long through = await QueueLedger.MarkPurgedAsync(connection, transaction, eventIds, purgedAtText, cancellationToken);
        await QueueLedger.CompactAsync(connection, transaction, purgedAtText, Math.Max(through, evidenceSequence), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new DeadLetterPurgeEvidence(
            evidenceSequence,
            chainHash,
            now,
            victims.Count,
            reasons,
            oldest,
            newest,
            evidenceSha256);
    }

    public async Task<IReadOnlyList<DeadLetterPurgeEvidence>> ListDeadLetterPurgesAsync(
        int maximumCount = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumCount, 1);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT ledger_sequence, chain_hash, purged_at, purged_count,
                   reason_counts_json, oldest_received_at, newest_received_at, evidence_sha256
            FROM queue_dead_letter_purges
            ORDER BY ledger_sequence DESC
            LIMIT $maximum_count;
            """;
        command.Parameters.AddWithValue("$maximum_count", maximumCount);
        List<DeadLetterPurgeEvidence> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            SortedDictionary<string, int> reasons = JsonSerializer.Deserialize(
                reader.GetString(4),
                DeadLetterEvidenceJsonContext.Default.SortedDictionaryStringInt32) ?? [];
            records.Add(new DeadLetterPurgeEvidence(
                reader.GetInt64(0),
                reader.GetString(1),
                DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                reader.GetInt32(3),
                reasons,
                reader.IsDBNull(5) ? null : DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                reader.IsDBNull(6) ? null : DateTimeOffset.Parse(reader.GetString(6), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                reader.GetString(7)));
        }

        return records;
    }

    internal sealed record DeadLetterPurgeLedgerPayload(
        string Kind,
        string PurgedAt,
        int Count,
        string OldestReceivedAt,
        string NewestReceivedAt,
        SortedDictionary<string, int> Reasons);
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SortedDictionary<string, int>))]
[JsonSerializable(typeof(SqliteEventStore.DeadLetterPurgeLedgerPayload))]
internal sealed partial class DeadLetterEvidenceJsonContext : JsonSerializerContext;
