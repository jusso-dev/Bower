using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>A stored source setup request: validated values and the generated plan, never secrets.</summary>
internal sealed record SourceSetupRow(
    string Id,
    string Type,
    string CollectorId,
    string Status,
    IReadOnlyDictionary<string, string> Values,
    SourceSetupPlan Plan,
    string ContentHash,
    string Reason,
    string RequestedByObjectId,
    string RequestedByName,
    DateTimeOffset RequestedAt,
    string? ReviewerName,
    DateTimeOffset? ReviewedAt,
    string? ReviewReason);

/// <summary>A source setup request that cannot move as asked (four-eyes, state or limit). HTTP 409.</summary>
public sealed class SourceSetupConflictException(string message) : InvalidOperationException(message);

/// <summary>
/// Guided source setup requests: submitted by an operator, decided by a different approver.
/// The plan is generated and hashed before it is stored, so a decision covers exactly the
/// stored bytes. Every change writes its audit row in the same transaction.
/// </summary>
public sealed partial class ManagementStore
{
    public const int MaximumPendingSourceSetupsPerCollector = 16;
    private const string SourceSetupTargetType = "source-setup-request";

    private static Task InitializeSourceSetupAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS source_setup_requests (
                id TEXT PRIMARY KEY,
                source_type TEXT NOT NULL,
                collector_id TEXT NOT NULL REFERENCES collectors(id),
                status TEXT NOT NULL,
                values_json TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_by_object_id TEXT NOT NULL,
                requested_by_name TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                reviewer_object_id TEXT NULL,
                reviewer_name TEXT NULL,
                reviewed_at TEXT NULL,
                review_reason TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS source_setup_requests_collector
                ON source_setup_requests(collector_id, status);
            """,
            cancellationToken);

    /// <summary>Stores a pending request. Null when the collector does not exist.</summary>
    /// <exception cref="ArgumentException">The reason is missing or too long.</exception>
    /// <exception cref="CollectorStateException">The collector is not approved or active.</exception>
    /// <exception cref="SourceSetupConflictException">The collector has too many pending requests.</exception>
    internal async Task<SourceSetupRow?> SubmitSourceSetupAsync(
        string sourceType,
        string collectorId,
        IReadOnlyDictionary<string, string> values,
        SourceSetupPlan plan,
        string? reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string trimmed = RequireText(reason, nameof(reason));
        string id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? status = await ScalarAsync(
            connection, transaction, "SELECT status FROM collectors WHERE id = $id;", ("$id", collectorId), cancellationToken);
        if (status is null)
        {
            return null;
        }

        if (status is not (nameof(CollectorStatus.Approved) or nameof(CollectorStatus.Active)))
        {
            throw new CollectorStateException(collectorId, status);
        }

        string? pending = await ScalarAsync(
            connection,
            transaction,
            "SELECT COUNT(*) FROM source_setup_requests WHERE collector_id = $id AND status = 'pending-review';",
            ("$id", collectorId),
            cancellationToken);
        if (int.Parse(pending ?? "0", System.Globalization.CultureInfo.InvariantCulture) >= MaximumPendingSourceSetupsPerCollector)
        {
            throw new SourceSetupConflictException(
                $"This collector already has {MaximumPendingSourceSetupsPerCollector} source setup requests waiting for approval.");
        }

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO source_setup_requests (
                id, source_type, collector_id, status, values_json, plan_json, content_hash, reason,
                requested_by_object_id, requested_by_name, requested_at)
            VALUES (
                $id, $type, $collector, 'pending-review', $values, $plan, $hash, $reason,
                $actor, $actor_name, $now);
            """,
            [
                ("$id", id),
                ("$type", sourceType),
                ("$collector", collectorId),
                ("$values", JsonSerializer.Serialize(
                    new Dictionary<string, string>(values, StringComparer.Ordinal),
                    ManagementJsonContext.Default.DictionaryStringString)),
                ("$plan", JsonSerializer.Serialize(plan, ManagementJsonContext.Default.SourceSetupPlan)),
                ("$hash", plan.ContentHash),
                ("$reason", trimmed),
                ("$actor", actorObjectId),
                ("$actor_name", actorName),
                ("$now", Format(now))
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "source-setup.requested", id, actorObjectId, actorName, now,
            cancellationToken, SourceSetupTargetType);
        await transaction.CommitAsync(cancellationToken);
        return await GetSourceSetupAsync(id, cancellationToken);
    }

    /// <summary>Approves or rejects a pending request. The requester can never decide it. Null when it does not exist.</summary>
    /// <exception cref="ArgumentException">The reason is missing or too long.</exception>
    /// <exception cref="SourceSetupConflictException">Four-eyes or state conflict.</exception>
    internal async Task<SourceSetupRow?> ReviewSourceSetupAsync(
        string id,
        bool approve,
        string? reason,
        string reviewerObjectId,
        string reviewerName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string trimmed = RequireText(reason, nameof(reason));
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? status = null;
        string? requester = null;
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT status, requested_by_object_id FROM source_setup_requests WHERE id = $id;";
            select.Parameters.AddWithValue("$id", id);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                status = reader.GetString(0);
                requester = reader.GetString(1);
            }
        }

        if (status is null)
        {
            return null;
        }

        if (string.Equals(requester, reviewerObjectId, StringComparison.Ordinal))
        {
            // Refusals are audited too: a self-approval attempt is worth seeing.
            await InsertAuditAsync(
                connection, transaction, "source-setup.self-review-refused", id, reviewerObjectId, reviewerName, now,
                cancellationToken, SourceSetupTargetType);
            await transaction.CommitAsync(cancellationToken);
            throw new SourceSetupConflictException("The person who requested a source setup cannot approve or reject it.");
        }

        if (status != SourceSetupRequestStatus.PendingReview)
        {
            throw new SourceSetupConflictException("Only source setup requests waiting for approval can be decided.");
        }

        await CommandAsync(
            connection,
            transaction,
            """
            UPDATE source_setup_requests SET
                status = $status,
                reviewer_object_id = $reviewer,
                reviewer_name = $reviewer_name,
                reviewed_at = $now,
                review_reason = $reason
            WHERE id = $id AND status = 'pending-review';
            """,
            [
                ("$status", approve ? SourceSetupRequestStatus.Approved : SourceSetupRequestStatus.Rejected),
                ("$reviewer", reviewerObjectId),
                ("$reviewer_name", reviewerName),
                ("$now", Format(now)),
                ("$reason", trimmed),
                ("$id", id)
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, approve ? "source-setup.approved" : "source-setup.rejected", id,
            reviewerObjectId, reviewerName, now, cancellationToken, SourceSetupTargetType);
        await transaction.CommitAsync(cancellationToken);
        return await GetSourceSetupAsync(id, cancellationToken);
    }

    /// <summary>The latest 200 requests, newest first.</summary>
    internal async Task<IReadOnlyList<SourceSetupRow>> ListSourceSetupsAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"SELECT {SourceSetupColumns} FROM source_setup_requests ORDER BY requested_at DESC, rowid DESC LIMIT 200;";
        List<SourceSetupRow> rows = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(ReadSourceSetup(reader));
        }

        return rows;
    }

    internal async Task<SourceSetupRow?> GetSourceSetupAsync(string id, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT {SourceSetupColumns} FROM source_setup_requests WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSourceSetup(reader) : null;
    }

    private const string SourceSetupColumns =
        "id, source_type, collector_id, status, values_json, plan_json, content_hash, reason, "
        + "requested_by_object_id, requested_by_name, requested_at, reviewer_name, reviewed_at, review_reason";

    private static SourceSetupRow ReadSourceSetup(SqliteDataReader reader) =>
        new(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            JsonSerializer.Deserialize(reader.GetString(4), ManagementJsonContext.Default.DictionaryStringString)
                ?? throw new InvalidDataException("Stored source setup values are invalid."),
            JsonSerializer.Deserialize(reader.GetString(5), ManagementJsonContext.Default.SourceSetupPlan)
                ?? throw new InvalidDataException("Stored source setup plan is invalid."),
            reader.GetString(6),
            reader.GetString(7),
            reader.GetString(8),
            reader.GetString(9),
            Parse(reader.GetString(10)),
            ReadOptionalString(reader, "reviewer_name"),
            ParseOptional(reader, "reviewed_at"),
            ReadOptionalString(reader, "review_reason"));
}
