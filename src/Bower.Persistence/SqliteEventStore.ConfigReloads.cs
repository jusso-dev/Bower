using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;

namespace Bower.Persistence;

/// <summary>
/// Tamper-evident record of an in-process configuration hot reload, hash-chained to the
/// previous reload record and bound to the queue event ledger head at the reload boundary.
/// Metadata only: never stores raw policy YAML, secrets or file paths.
/// </summary>
public sealed record ConfigReloadLedgerEntry(
    long Sequence,
    DateTimeOffset ReloadedAt,
    string Trigger,
    string PreviousPolicyHash,
    string NewPolicyHash,
    string PreviousPrivacyHash,
    string NewPrivacyHash,
    long QueueLedgerSequence,
    string QueueLedgerHash,
    string ChainHash);

public sealed partial class SqliteEventStore
{
    private const string ConfigReloadGenesis = "bower-config-reload-ledger-v1";

    private const string ConfigReloadSchema =
        """
        CREATE TABLE IF NOT EXISTS queue_config_reloads (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            reloaded_at TEXT NOT NULL,
            trigger TEXT NOT NULL,
            previous_policy_hash TEXT NOT NULL,
            new_policy_hash TEXT NOT NULL,
            previous_privacy_hash TEXT NOT NULL,
            new_privacy_hash TEXT NOT NULL,
            queue_ledger_sequence INTEGER NOT NULL,
            queue_ledger_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL
        );
        """;

    public async Task<ConfigReloadLedgerEntry> RecordConfigReloadAsync(
        string trigger,
        string previousPolicyHash,
        string newPolicyHash,
        string previousPrivacyHash,
        string newPrivacyHash,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trigger);
        ArgumentException.ThrowIfNullOrWhiteSpace(previousPolicyHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(newPolicyHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(previousPrivacyHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(newPrivacyHash);

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction = await BeginWriteAsync(connection, true, cancellationToken);

        await EnsureConfigReloadTableAsync(connection, transaction, cancellationToken);

        (long ledgerSeq, string ledgerHash) = await QueueLedger.HeadAsync(connection, transaction, cancellationToken);

        string previousChainHash = ConfigReloadGenesisHash();
        long nextSequence = 1;
        await using (SqliteCommand prevCmd = connection.CreateCommand())
        {
            prevCmd.Transaction = transaction;
            prevCmd.CommandText = "SELECT sequence, chain_hash FROM queue_config_reloads ORDER BY sequence DESC LIMIT 1;";
            await using SqliteDataReader reader = await prevCmd.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                nextSequence = reader.GetInt64(0) + 1;
                previousChainHash = reader.GetString(1);
            }
        }

        DateTimeOffset now = clock.GetUtcNow();
        string reloadedAt = now.ToString("O", CultureInfo.InvariantCulture);
        string chainHash = ComputeConfigReloadChainHash(
            previousChainHash,
            nextSequence,
            reloadedAt,
            trigger,
            previousPolicyHash,
            newPolicyHash,
            previousPrivacyHash,
            newPrivacyHash,
            ledgerSeq,
            ledgerHash);

        await using (SqliteCommand insertCmd = connection.CreateCommand())
        {
            insertCmd.Transaction = transaction;
            insertCmd.CommandText =
                """
                INSERT INTO queue_config_reloads (
                    sequence, reloaded_at, trigger,
                    previous_policy_hash, new_policy_hash,
                    previous_privacy_hash, new_privacy_hash,
                    queue_ledger_sequence, queue_ledger_hash, chain_hash)
                VALUES (
                    $sequence, $reloaded_at, $trigger,
                    $previous_policy_hash, $new_policy_hash,
                    $previous_privacy_hash, $new_privacy_hash,
                    $queue_ledger_sequence, $queue_ledger_hash, $chain_hash);
                """;
            insertCmd.Parameters.AddWithValue("$sequence", nextSequence);
            insertCmd.Parameters.AddWithValue("$reloaded_at", reloadedAt);
            insertCmd.Parameters.AddWithValue("$trigger", trigger);
            insertCmd.Parameters.AddWithValue("$previous_policy_hash", previousPolicyHash);
            insertCmd.Parameters.AddWithValue("$new_policy_hash", newPolicyHash);
            insertCmd.Parameters.AddWithValue("$previous_privacy_hash", previousPrivacyHash);
            insertCmd.Parameters.AddWithValue("$new_privacy_hash", newPrivacyHash);
            insertCmd.Parameters.AddWithValue("$queue_ledger_sequence", ledgerSeq);
            insertCmd.Parameters.AddWithValue("$queue_ledger_hash", ledgerHash);
            insertCmd.Parameters.AddWithValue("$chain_hash", chainHash);
            await insertCmd.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return new ConfigReloadLedgerEntry(
            nextSequence,
            now,
            trigger,
            previousPolicyHash,
            newPolicyHash,
            previousPrivacyHash,
            newPrivacyHash,
            ledgerSeq,
            ledgerHash,
            chainHash);
    }

    public async Task<IReadOnlyList<ConfigReloadLedgerEntry>> ListConfigReloadsAsync(
        int limit = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        if (!await TableExistsAsync(connection, "queue_config_reloads", cancellationToken))
        {
            return [];
        }

        List<ConfigReloadLedgerEntry> entries = [];
        await using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT sequence, reloaded_at, trigger,
                   previous_policy_hash, new_policy_hash,
                   previous_privacy_hash, new_privacy_hash,
                   queue_ledger_sequence, queue_ledger_hash, chain_hash
            FROM queue_config_reloads
            ORDER BY sequence DESC
            LIMIT $limit;
            """;
        cmd.Parameters.AddWithValue("$limit", limit);
        await using SqliteDataReader reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new ConfigReloadLedgerEntry(
                reader.GetInt64(0),
                DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetInt64(7),
                reader.GetString(8),
                reader.GetString(9)));
        }

        return entries;
    }

    public async Task<bool> VerifyConfigReloadLedgerAsync(CancellationToken cancellationToken = default)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        if (!await TableExistsAsync(connection, "queue_config_reloads", cancellationToken))
        {
            return true;
        }

        string previousHash = ConfigReloadGenesisHash();
        long expectedSequence = 1;
        await using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT sequence, reloaded_at, trigger,
                   previous_policy_hash, new_policy_hash,
                   previous_privacy_hash, new_privacy_hash,
                   queue_ledger_sequence, queue_ledger_hash, chain_hash
            FROM queue_config_reloads
            ORDER BY sequence ASC;
            """;
        await using SqliteDataReader reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            long sequence = reader.GetInt64(0);
            if (sequence != expectedSequence)
            {
                return false;
            }

            string expectedHash = ComputeConfigReloadChainHash(
                previousHash,
                sequence,
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetInt64(7),
                reader.GetString(8));

            string actualHash = reader.GetString(9);
            if (!string.Equals(expectedHash, actualHash, StringComparison.Ordinal))
            {
                return false;
            }

            previousHash = actualHash;
            expectedSequence++;
        }

        return true;
    }

    private static async Task EnsureConfigReloadTableAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand cmd = connection.CreateCommand();
        cmd.Transaction = transaction;
        cmd.CommandText = ConfigReloadSchema;
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<bool> TableExistsAsync(
        SqliteConnection connection,
        string tableName,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name;";
        cmd.Parameters.AddWithValue("$name", tableName);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) > 0;
    }

    private static string ConfigReloadGenesisHash() =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ConfigReloadGenesis)));

    private static string ComputeConfigReloadChainHash(
        string previousHash,
        long sequence,
        string reloadedAt,
        string trigger,
        string previousPolicyHash,
        string newPolicyHash,
        string previousPrivacyHash,
        string newPrivacyHash,
        long queueLedgerSequence,
        string queueLedgerHash) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '\u001f',
            previousHash,
            sequence.ToString(CultureInfo.InvariantCulture),
            reloadedAt,
            trigger,
            previousPolicyHash,
            newPolicyHash,
            previousPrivacyHash,
            newPrivacyHash,
            queueLedgerSequence.ToString(CultureInfo.InvariantCulture),
            queueLedgerHash))));
}
