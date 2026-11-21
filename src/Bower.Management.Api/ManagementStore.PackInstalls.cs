using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>A pack installation request that cannot move as asked (four-eyes, state, or missing pack). HTTP 409.</summary>
public sealed class PackInstallConflictException(string message) : InvalidOperationException(message);

/// <summary>
/// Four-eyes pack installation requests: an operator submits a verified pack install for a
/// collector group (environment) or single collector, and a different approver decides it.
/// Approval applies <c>desired_policy_hash</c> to every eligible collector and writes approval
/// and audit rows in the same transaction.
/// </summary>
public sealed partial class ManagementStore
{
    public const int MaximumPendingPackInstalls = 32;
    private const string PackInstallTargetType = "pack-install-request";

    private static Task InitializePackInstallsAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS pack_install_requests (
                id TEXT PRIMARY KEY,
                pack_id TEXT NOT NULL,
                pack_version TEXT NOT NULL,
                pack_name TEXT NOT NULL,
                pack_hash TEXT NOT NULL,
                signed_by_key_id TEXT NOT NULL,
                target_environment TEXT NULL,
                target_collector_id TEXT NULL,
                status TEXT NOT NULL,
                diff_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_by_object_id TEXT NOT NULL,
                requested_by_name TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                reviewer_object_id TEXT NULL,
                reviewer_name TEXT NULL,
                reviewed_at TEXT NULL,
                review_reason TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS pack_install_requests_status
                ON pack_install_requests(status, requested_at);
            """,
            cancellationToken);

    internal async Task<PackInstallRequestRecord> SubmitPackInstallAsync(
        string packId,
        string packVersion,
        string packName,
        string packHash,
        string signedByKeyId,
        string? targetEnvironment,
        string? targetCollectorId,
        PackPopulationDiff diff,
        string? reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string trimmed = RequireText(reason, nameof(reason));
        string id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);

        string? pendingCount = await ScalarAsync(
            connection,
            transaction,
            "SELECT COUNT(*) FROM pack_install_requests WHERE status = $status;",
            ("$status", PackInstallRequestStatus.PendingReview),
            cancellationToken);
        if (int.Parse(pendingCount ?? "0", CultureInfo.InvariantCulture) >= MaximumPendingPackInstalls)
        {
            throw new PackInstallConflictException(
                $"There are already {MaximumPendingPackInstalls} pack installation requests waiting for approval.");
        }

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO pack_install_requests (
                id, pack_id, pack_version, pack_name, pack_hash, signed_by_key_id,
                target_environment, target_collector_id, status, diff_json, reason,
                requested_by_object_id, requested_by_name, requested_at)
            VALUES (
                $id, $pack_id, $pack_version, $pack_name, $pack_hash, $key_id,
                $env, $collector, $status, $diff, $reason,
                $actor, $actor_name, $now);
            """,
            [
                ("$id", id),
                ("$pack_id", packId),
                ("$pack_version", packVersion),
                ("$pack_name", packName),
                ("$pack_hash", packHash),
                ("$key_id", signedByKeyId),
                ("$env", targetEnvironment),
                ("$collector", targetCollectorId),
                ("$status", PackInstallRequestStatus.PendingReview),
                ("$diff", JsonSerializer.Serialize(diff, ManagementJsonContext.Default.PackPopulationDiff)),
                ("$reason", trimmed),
                ("$actor", actorObjectId),
                ("$actor_name", actorName),
                ("$now", Format(now))
            ],
            cancellationToken);

        await InsertAuditAsync(
            connection,
            transaction,
            "pack.install-requested",
            id,
            actorObjectId,
            actorName,
            now,
            cancellationToken,
            PackInstallTargetType);

        await transaction.CommitAsync(cancellationToken);
        return (await GetPackInstallAsync(id, cancellationToken))!;
    }

    internal async Task<PackInstallRequestRecord?> ReviewPackInstallAsync(
        string id,
        bool approve,
        Func<PackInstallRequestRecord, string?>? verifyBeforeApprove,
        string? reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string trimmed = RequireText(reason, nameof(reason));
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);

        PackInstallRequestRecord? existing = await ReadPackInstallAsync(connection, transaction, id, cancellationToken);
        if (existing is null)
        {
            return null;
        }

        if (!string.Equals(existing.Status, PackInstallRequestStatus.PendingReview, StringComparison.Ordinal))
        {
            throw new PackInstallConflictException("This pack installation request has already been decided.");
        }

        if (string.Equals(existing.RequestedByObjectId, actorObjectId, StringComparison.Ordinal))
        {
            throw new PackInstallConflictException(
                "You requested this pack installation, so a different approver must decide it.");
        }

        if (approve && verifyBeforeApprove?.Invoke(existing) is { } refusal)
        {
            throw new PackInstallConflictException(refusal);
        }

        string nextStatus = approve ? PackInstallRequestStatus.Approved : PackInstallRequestStatus.Rejected;
        await CommandAsync(
            connection,
            transaction,
            """
            UPDATE pack_install_requests
            SET status = $status,
                reviewer_object_id = $reviewer,
                reviewer_name = $reviewer_name,
                reviewed_at = $reviewed_at,
                review_reason = $review_reason
            WHERE id = $id;
            """,
            [
                ("$status", nextStatus),
                ("$reviewer", actorObjectId),
                ("$reviewer_name", actorName),
                ("$reviewed_at", Format(now)),
                ("$review_reason", trimmed),
                ("$id", id)
            ],
            cancellationToken);

        if (approve)
        {
            List<string> targetCollectorIds = await ResolveEligiblePackTargetsAsync(
                connection, transaction, existing.TargetEnvironment, existing.TargetCollectorId, cancellationToken);
            if (targetCollectorIds.Count == 0)
            {
                throw new PackInstallConflictException(
                    "No approved or active collectors match the requested target.");
            }

            foreach (string collectorId in targetCollectorIds)
            {
                await CommandAsync(
                    connection,
                    transaction,
                    "UPDATE collectors SET desired_policy_hash = $hash WHERE id = $id;",
                    [("$hash", existing.PackHash), ("$id", collectorId)],
                    cancellationToken);

                await CommandAsync(
                    connection,
                    transaction,
                    """
                    INSERT INTO approvals (
                        id, collector_id, action, reason, actor_object_id, actor_name, occurred_at)
                    VALUES ($id, $collector, 'pack-installed', $reason, $actor, $name, $occurred);
                    """,
                    [
                        ("$id", Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture)),
                        ("$collector", collectorId),
                        ("$reason", $"Installed {existing.PackId} v{existing.PackVersion}: {trimmed}"),
                        ("$actor", actorObjectId),
                        ("$name", actorName),
                        ("$occurred", Format(now))
                    ],
                    cancellationToken);

                await InsertAuditAsync(
                    connection,
                    transaction,
                    "collector.desired-policy-updated",
                    collectorId,
                    actorObjectId,
                    actorName,
                    now,
                    cancellationToken,
                    initiatedByObjectId: existing.RequestedByObjectId,
                    initiatedByName: existing.RequestedByName);
            }
        }

        await InsertAuditAsync(
            connection,
            transaction,
            approve ? "pack.install-approved" : "pack.install-rejected",
            id,
            actorObjectId,
            actorName,
            now,
            cancellationToken,
            PackInstallTargetType,
            initiatedByObjectId: existing.RequestedByObjectId,
            initiatedByName: existing.RequestedByName);

        await transaction.CommitAsync(cancellationToken);
        return await GetPackInstallAsync(id, cancellationToken);
    }

    internal async Task<List<PackInstallRequestRecord>> ListPackInstallsAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM pack_install_requests ORDER BY requested_at DESC LIMIT 200;";
        List<PackInstallRequestRecord> items = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            items.Add(MapPackInstall(reader));
        }

        return items;
    }

    internal async Task<PackInstallRequestRecord?> GetPackInstallAsync(string id, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        return await ReadPackInstallAsync(connection, null, id, cancellationToken);
    }

    private static async Task<PackInstallRequestRecord?> ReadPackInstallAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string id,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM pack_install_requests WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? MapPackInstall(reader) : null;
    }

    private static async Task<List<string>> ResolveEligiblePackTargetsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string? targetEnvironment,
        string? targetCollectorId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        if (!string.IsNullOrWhiteSpace(targetCollectorId))
        {
            command.CommandText = """
                SELECT id FROM collectors
                WHERE id = $id AND status IN ('Approved', 'Active')
                ORDER BY id;
                """;
            command.Parameters.AddWithValue("$id", targetCollectorId);
        }
        else
        {
            command.CommandText = """
                SELECT id FROM collectors
                WHERE environment = $env AND status IN ('Approved', 'Active')
                ORDER BY id;
                """;
            command.Parameters.AddWithValue("$env", targetEnvironment ?? string.Empty);
        }

        List<string> ids = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetString(0));
        }

        return ids;
    }

    private static PackInstallRequestRecord MapPackInstall(SqliteDataReader reader)
    {
        string diffJson = reader.GetString(reader.GetOrdinal("diff_json"));
        PackPopulationDiff diff = JsonSerializer.Deserialize(diffJson, ManagementJsonContext.Default.PackPopulationDiff)!;
        int envOrd = reader.GetOrdinal("target_environment");
        int colOrd = reader.GetOrdinal("target_collector_id");
        int reviewerOrd = reader.GetOrdinal("reviewer_name");
        int reviewedAtOrd = reader.GetOrdinal("reviewed_at");
        int reviewReasonOrd = reader.GetOrdinal("review_reason");

        return new PackInstallRequestRecord(
            reader.GetString(reader.GetOrdinal("id")),
            reader.GetString(reader.GetOrdinal("pack_id")),
            reader.GetString(reader.GetOrdinal("pack_version")),
            reader.GetString(reader.GetOrdinal("pack_name")),
            reader.GetString(reader.GetOrdinal("pack_hash")),
            reader.GetString(reader.GetOrdinal("signed_by_key_id")),
            reader.IsDBNull(envOrd) ? null : reader.GetString(envOrd),
            reader.IsDBNull(colOrd) ? null : reader.GetString(colOrd),
            reader.GetString(reader.GetOrdinal("status")),
            diff,
            reader.GetString(reader.GetOrdinal("reason")),
            reader.GetString(reader.GetOrdinal("requested_by_object_id")),
            reader.GetString(reader.GetOrdinal("requested_by_name")),
            Parse(reader.GetString(reader.GetOrdinal("requested_at"))),
            reader.IsDBNull(reviewerOrd) ? null : reader.GetString(reviewerOrd),
            reader.IsDBNull(reviewedAtOrd) ? null : Parse(reader.GetString(reviewedAtOrd)),
            reader.IsDBNull(reviewReasonOrd) ? null : reader.GetString(reviewReasonOrd));
    }
}
