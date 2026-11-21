using Bower.Evidence;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>Thrown when an offline site import bundle breaks sequence or hash-chain continuity.</summary>
public sealed class OfflineBundleChainException(string message) : InvalidOperationException(message);

public sealed partial class ManagementStore
{
    private static async Task InitializeOfflineSitesAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await AddColumnIfMissingAsync(connection, "collectors", "is_offline_site", "INTEGER NOT NULL DEFAULT 0", cancellationToken);
        await AddColumnIfMissingAsync(connection, "collectors", "last_bundle_sequence", "INTEGER NULL", cancellationToken);
        await AddColumnIfMissingAsync(connection, "collectors", "last_bundle_hash", "TEXT NULL", cancellationToken);
    }

    public async Task<IReadOnlySet<string>> OfflineSiteCollectorsAsync(CancellationToken cancellationToken)
    {
        HashSet<string> ids = new(StringComparer.Ordinal);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM collectors WHERE is_offline_site = 1;";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetString(0));
        }

        return ids;
    }

    /// <summary>
    /// Records a verified metadata-only offline site status report from an air-gapped export
    /// bundle. Enforces monotonic bundle sequence and hash-chain continuity (rejecting replay
    /// or skipped bundles), checks ledger witness regression, marks the collector as an offline
    /// site, and writes an audit row. Never receives or stores event payloads.
    /// </summary>
    public async Task<CollectorRecord> ImportOfflineSiteReportAsync(
        OfflineSiteReportDocument report,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (string.IsNullOrWhiteSpace(report.CollectorId) || report.BundleSequence < 1)
        {
            throw new ArgumentException("Offline report must include a collector id and positive bundle sequence.");
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        long? lastSequence = null;
        string? lastHash = null;
        await using (SqliteCommand check = connection.CreateCommand())
        {
            check.Transaction = transaction;
            check.CommandText = "SELECT last_bundle_sequence, last_bundle_hash FROM collectors WHERE id = $id;";
            check.Parameters.AddWithValue("$id", report.CollectorId);
            await using SqliteDataReader reader = await check.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                if (!reader.IsDBNull(0)) lastSequence = reader.GetInt64(0);
                if (!reader.IsDBNull(1)) lastHash = reader.GetString(1);
            }
        }

        if (lastSequence is { } existingSeq)
        {
            if (report.BundleSequence <= existingSeq)
            {
                throw new OfflineBundleChainException(
                    $"Bundle sequence {report.BundleSequence} is not newer than already-imported sequence {existingSeq}.");
            }

            if (report.BundleSequence != existingSeq + 1)
            {
                throw new OfflineBundleChainException(
                    $"Bundle sequence gap: expected {existingSeq + 1}, received {report.BundleSequence}.");
            }

            if (lastHash is not null && !string.Equals(report.PreviousBundleHash, lastHash, StringComparison.Ordinal))
            {
                throw new OfflineBundleChainException(
                    "Bundle previousBundleHash does not match the last imported bundle hash.");
            }
        }

        LedgerReport ledger = new(report.LedgerSequence, report.LedgerHeadHash);
        string deliveryStatus = "healthy";
        if (await LedgerRegressedAsync(connection, transaction, report.CollectorId, ledger, cancellationToken))
        {
            deliveryStatus = "ledger-regression";
            await InsertAuditAsync(
                connection, transaction, "collector.ledger-regression", report.CollectorId,
                actorObjectId, actorName, now, cancellationToken);
        }

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO collectors (
                id, machine_name, environment, version, status, principal_object_id,
                first_seen_at, last_seen_at, configuration_hash, policy_hash,
                queue_depth, delivery_status, dead_lettered, reported_privacy_profile_hash,
                ledger_sequence, ledger_hash, is_offline_site, last_bundle_sequence, last_bundle_hash)
            VALUES (
                $id, $machine, $environment, $version, 'Active', $principal,
                $now, $now, 'air-gapped', $policy,
                $queue, $delivery, $dlq, $privacy,
                $ledger_seq, $ledger_hash, 1, $bundle_seq, $bundle_hash)
            ON CONFLICT(id) DO UPDATE SET
                machine_name = excluded.machine_name,
                environment = excluded.environment,
                version = excluded.version,
                status = 'Active',
                last_seen_at = excluded.last_seen_at,
                policy_hash = excluded.policy_hash,
                queue_depth = excluded.queue_depth,
                delivery_status = excluded.delivery_status,
                dead_lettered = excluded.dead_lettered,
                reported_privacy_profile_hash = excluded.reported_privacy_profile_hash,
                ledger_sequence = CASE WHEN excluded.delivery_status = 'ledger-regression' THEN collectors.ledger_sequence ELSE excluded.ledger_sequence END,
                ledger_hash = CASE WHEN excluded.delivery_status = 'ledger-regression' THEN collectors.ledger_hash ELSE excluded.ledger_hash END,
                is_offline_site = 1,
                last_bundle_sequence = excluded.last_bundle_sequence,
                last_bundle_hash = excluded.last_bundle_hash;
            """,
            [
                ("$id", report.CollectorId),
                ("$machine", report.MachineName),
                ("$environment", report.Environment),
                ("$version", report.Version),
                ("$principal", $"offline:{report.CollectorId}"),
                ("$now", Format(now)),
                ("$policy", report.PolicyHash),
                ("$queue", report.QueueDepth),
                ("$delivery", deliveryStatus),
                ("$dlq", report.DeadLettered),
                ("$privacy", report.PrivacyProfileHash),
                ("$ledger_seq", report.LedgerSequence),
                ("$ledger_hash", report.LedgerHeadHash),
                ("$bundle_seq", report.BundleSequence),
                ("$bundle_hash", report.BundleHash)
            ],
            cancellationToken);

        await InsertAuditAsync(
            connection,
            transaction,
            "fleet.offline-bundle-imported",
            report.CollectorId,
            actorObjectId,
            actorName,
            now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (await GetAsync(report.CollectorId, cancellationToken))!;
    }
}
