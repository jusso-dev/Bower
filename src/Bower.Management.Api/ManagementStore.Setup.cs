using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>
/// Onboarding wizard state: the chosen destination and probe profile (one row) and canary run
/// history (metadata and the signed, metadata-only bundle). Every change writes its audit row
/// in the same transaction.
/// </summary>
public sealed partial class ManagementStore
{
    public const string SetupActorId = "bower.setup";
    public const string SetupActorName = "Bower setup";

    private static Task InitializeSetupAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS setup_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                workspace_id TEXT NULL,
                workspace_resource_id TEXT NULL,
                dcr_resource_id TEXT NULL,
                table_name TEXT NULL,
                destination_by TEXT NULL,
                destination_at TEXT NULL,
                probe_profile TEXT NULL,
                probe_by TEXT NULL,
                probe_at TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS setup_canary_runs (
                id TEXT PRIMARY KEY,
                profile TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                state TEXT NOT NULL,
                mode TEXT NULL,
                outcome TEXT NULL,
                collector_accepted INTEGER NOT NULL DEFAULT 0,
                event_id TEXT NULL,
                latency_seconds REAL NULL,
                signed INTEGER NOT NULL DEFAULT 0,
                bundle TEXT NULL,
                requested_by_object_id TEXT NOT NULL,
                requested_by_name TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                completed_at TEXT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS setup_canary_runs_one_running
                ON setup_canary_runs(state) WHERE state = 'running';
            """,
            cancellationToken);

    public async Task<(SetupDestination? Destination, SetupProbeChoice? Probe)> GetSetupStateAsync(
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM setup_state WHERE id = 1;";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return (null, null);
        }

        SetupDestination? destination = ReadOptionalString(reader, "workspace_id") is { } workspaceId
            ? new SetupDestination(
                workspaceId,
                ReadOptionalString(reader, "workspace_resource_id"),
                ReadOptionalString(reader, "dcr_resource_id"),
                reader.GetString(reader.GetOrdinal("table_name")),
                reader.GetString(reader.GetOrdinal("destination_by")),
                Parse(reader.GetString(reader.GetOrdinal("destination_at"))))
            : null;
        SetupProbeChoice? probe = ReadOptionalString(reader, "probe_profile") is { } profile
            ? new SetupProbeChoice(
                profile,
                reader.GetString(reader.GetOrdinal("probe_by")),
                Parse(reader.GetString(reader.GetOrdinal("probe_at"))))
            : null;
        return (destination, probe);
    }

    /// <summary>Saves validated destination identifiers. Callers validate formats first.</summary>
    public async Task SetSetupDestinationAsync(
        string workspaceId,
        string? workspaceResourceId,
        string? dcrResourceId,
        string table,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO setup_state (id, workspace_id, workspace_resource_id, dcr_resource_id, table_name, destination_by, destination_at)
            VALUES (1, $workspace, $workspace_resource, $dcr, $table, $by, $at)
            ON CONFLICT(id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                workspace_resource_id = excluded.workspace_resource_id,
                dcr_resource_id = excluded.dcr_resource_id,
                table_name = excluded.table_name,
                destination_by = excluded.destination_by,
                destination_at = excluded.destination_at;
            """,
            [
                ("$workspace", workspaceId),
                ("$workspace_resource", workspaceResourceId),
                ("$dcr", dcrResourceId),
                ("$table", table),
                ("$by", actorName),
                ("$at", Format(now))
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "setup.destination-set", "destination",
            actorObjectId, actorName, now, cancellationToken, "setup");
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task SetSetupProbeProfileAsync(
        string profile,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO setup_state (id, probe_profile, probe_by, probe_at) VALUES (1, $profile, $by, $at)
            ON CONFLICT(id) DO UPDATE SET
                probe_profile = excluded.probe_profile,
                probe_by = excluded.probe_by,
                probe_at = excluded.probe_at;
            """,
            [("$profile", profile), ("$by", actorName), ("$at", Format(now))],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "setup.probe-profile-set", "probe-profile",
            actorObjectId, actorName, now, cancellationToken, "setup");
        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>Records a new running canary. At most one runs at a time (unique partial index).</summary>
    public async Task<SetupCanaryRun> StartSetupCanaryRunAsync(
        string profile,
        string workspaceId,
        string table,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await CommandAsync(
                connection,
                transaction,
                """
                INSERT INTO setup_canary_runs (
                    id, profile, workspace_id, table_name, state, requested_by_object_id, requested_by_name, requested_at)
                VALUES ($id, $profile, $workspace, $table, 'running', $actor, $name, $at);
                """,
                [
                    ("$id", id),
                    ("$profile", profile),
                    ("$workspace", workspaceId),
                    ("$table", table),
                    ("$actor", actorObjectId),
                    ("$name", actorName),
                    ("$at", Format(now))
                ],
                cancellationToken);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            throw new SetupCanaryBusyException();
        }

        await InsertAuditAsync(
            connection, transaction, "setup.canary-requested", id,
            actorObjectId, actorName, now, cancellationToken, "setup-canary");
        await transaction.CommitAsync(cancellationToken);
        return new SetupCanaryRun(
            id, profile, SetupCanaryRunStates.Running, null, null, null, null, false, null,
            workspaceId, table, null, false, false, actorName, now, null);
    }

    /// <summary>Stores a finished run once; a run that is no longer running is left unchanged.</summary>
    public async Task CompleteSetupCanaryRunAsync(
        string id,
        SetupCanaryResult result,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        bool interrupted = result.Outcome == SetupOutcomes.Interrupted;
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        int changed = await CommandAsync(
            connection,
            transaction,
            """
            UPDATE setup_canary_runs SET
                state = $state, mode = $mode, outcome = $outcome, collector_accepted = $accepted,
                event_id = $event, latency_seconds = $latency, signed = $signed, bundle = $bundle,
                completed_at = $at
            WHERE id = $id AND state = 'running';
            """,
            [
                ("$id", id),
                ("$state", interrupted ? SetupCanaryRunStates.Interrupted : SetupCanaryRunStates.Completed),
                ("$mode", interrupted ? null : result.Mode),
                ("$outcome", result.Outcome),
                ("$accepted", result.CollectorAccepted ? 1 : 0),
                ("$event", result.EventId),
                ("$latency", result.LatencySeconds),
                ("$signed", result.HasSignature ? 1 : 0),
                ("$bundle", result.BundleJson),
                ("$at", Format(now))
            ],
            cancellationToken);
        if (changed == 1)
        {
            string action = interrupted ? "setup.canary-interrupted" : result.Mode switch
            {
                Bower.Evidence.EvidenceModes.Verified => "setup.canary-verified",
                Bower.Evidence.EvidenceModes.Simulated => "setup.canary-simulated",
                _ => "setup.canary-failed"
            };
            await InsertAuditAsync(
                connection, transaction, action, id, actorObjectId, actorName, now, cancellationToken, "setup-canary");
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>Marks runs a previous process left running as interrupted. Call at start-up.</summary>
    public async Task<int> InterruptSetupCanaryRunsAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        List<string> running = [];
        await using (SqliteConnection connection = await OpenAsync(cancellationToken))
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id FROM setup_canary_runs WHERE state = 'running';";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                running.Add(reader.GetString(0));
            }
        }

        SetupCanaryResult interrupted = new(null, SetupOutcomes.Interrupted, false, null, null, false, null);
        foreach (string id in running)
        {
            await CompleteSetupCanaryRunAsync(id, interrupted, SetupActorId, SetupActorName, now, cancellationToken);
        }

        return running.Count;
    }

    public async Task<SetupCanaryRun?> LatestSetupCanaryRunAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT id, profile, workspace_id, table_name, state, mode, outcome, collector_accepted, event_id,
                   latency_seconds, signed, bundle IS NOT NULL AS has_bundle, requested_by_name, requested_at, completed_at
            FROM setup_canary_runs ORDER BY requested_at DESC, rowid DESC LIMIT 1;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        string? outcome = ReadOptionalString(reader, "outcome");
        (string Message, string Fix)? text = outcome is null ? null : SetupOutcomes.Describe(outcome);
        int latency = reader.GetOrdinal("latency_seconds");
        return new SetupCanaryRun(
            reader.GetString(reader.GetOrdinal("id")),
            reader.GetString(reader.GetOrdinal("profile")),
            reader.GetString(reader.GetOrdinal("state")),
            ReadOptionalString(reader, "mode"),
            outcome,
            text?.Message,
            text?.Fix,
            reader.GetInt64(reader.GetOrdinal("collector_accepted")) == 1,
            ReadOptionalString(reader, "event_id"),
            reader.GetString(reader.GetOrdinal("workspace_id")),
            reader.GetString(reader.GetOrdinal("table_name")),
            reader.IsDBNull(latency) ? null : reader.GetDouble(latency),
            reader.GetInt64(reader.GetOrdinal("signed")) == 1,
            reader.GetInt64(reader.GetOrdinal("has_bundle")) == 1,
            reader.GetString(reader.GetOrdinal("requested_by_name")),
            Parse(reader.GetString(reader.GetOrdinal("requested_at"))),
            ParseOptional(reader, "completed_at"));
    }

    /// <summary>The signed bundle JSON of a finished run, or null.</summary>
    public async Task<string?> GetSetupCanaryBundleAsync(string id, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT bundle FROM setup_canary_runs WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }
}

public sealed class SetupCanaryBusyException()
    : InvalidOperationException("A setup canary is already running.");
