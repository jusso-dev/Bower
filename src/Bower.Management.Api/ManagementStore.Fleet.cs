using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>The plain-English fleet view. Reads existing state only; it stores nothing.</summary>
public sealed partial class ManagementStore
{
    /// <summary>The fleet view at <paramref name="now"/>.</summary>
    public async Task<FleetRecord> FleetAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        IReadOnlyList<CollectorRecord> collectors = await ListAsync(null, cancellationToken);
        return FleetStatus.Evaluate(collectors, await SignedOutCollectorsAsync(now, cancellationToken), now);
    }

    /// <summary>
    /// Token-enrolled collectors without a usable credential: every credential they were
    /// issued is revoked, retired or expired, so their next request will be refused. Entra
    /// collectors have no credential rows and never appear here.
    /// </summary>
    private async Task<IReadOnlySet<string>> SignedOutCollectorsAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        Dictionary<string, bool> usable = new(StringComparer.Ordinal);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT collector_id, status, expires_at FROM collector_credentials;";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            string collectorId = reader.GetString(0);
            bool active = reader.GetString(1) == CollectorCredentialStatus.Active && Parse(reader.GetString(2)) > now;
            usable[collectorId] = active || usable.GetValueOrDefault(collectorId);
        }

        return usable.Where(item => !item.Value).Select(item => item.Key).ToHashSet(StringComparer.Ordinal);
    }
}
