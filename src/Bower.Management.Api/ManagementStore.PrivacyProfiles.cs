using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>Outcome of a collector's deployment lookup, bound to its principal.</summary>
public enum PrivacyProfileDeploymentState
{
    /// <summary>No collector with this id is bound to the calling principal.</summary>
    NotFound,

    /// <summary>The collector exists but is not Active.</summary>
    NotActive,

    /// <summary>No privacy profile version is assigned.</summary>
    Unassigned,

    Assigned
}

public sealed record PrivacyProfileDeployment(
    PrivacyProfileDeploymentState State,
    string? VersionId = null,
    string? ProfileId = null,
    string? Version = null,
    string? ContentHash = null,
    string? Content = null);

/// <summary>A privacy profile state rule was violated (HTTP 409).</summary>
public sealed class PrivacyProfileConflictException(string message) : InvalidOperationException(message);

/// <summary>Privacy profile versions, reviews and collector assignments.</summary>
public sealed partial class ManagementStore
{
    public const int MaximumReasonLength = 500;

    private const string VersionColumns =
        """
        v.id, v.profile_id, v.version, v.description, v.content_hash, v.change_summary, v.status,
        v.author_name, v.created_at, v.reviewer_name, v.reviewed_at, v.review_reason,
        (SELECT COUNT(*) FROM collectors c
         WHERE c.desired_privacy_profile_version_id = v.id AND c.status <> 'Revoked') AS assigned_collectors
        """;

    /// <summary>Latest version string of <paramref name="profileId"/> (any status), or null.</summary>
    public async Task<string?> LatestPrivacyProfileVersionAsync(string profileId, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        return Latest(await ReadVersionsOfAsync(connection, null, profileId, cancellationToken));
    }

    /// <summary>Stores a validated candidate as a new PendingReview version and audits it.</summary>
    /// <exception cref="ArgumentException">The change summary is missing or too long.</exception>
    /// <exception cref="PrivacyProfileValidationException">The version is not greater than the latest.</exception>
    public async Task<PrivacyProfileVersionDetail> SubmitPrivacyProfileVersionAsync(
        PrivacyProfileCandidate candidate,
        string? changeSummary,
        string authorObjectId,
        string authorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        string summary = RequireText(changeSummary, nameof(changeSummary));
        string id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        // Checked inside the write transaction so concurrent submissions stay monotonic.
        string? latest = Latest(await ReadVersionsOfAsync(connection, transaction, candidate.ProfileId, cancellationToken));
        if (PrivacyProfileInspector.RequireGreater(candidate.Version, latest) is { } versionError)
        {
            throw new PrivacyProfileValidationException(versionError);
        }

        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO privacy_profile_versions (
                id, profile_id, version, description, content, content_hash, change_summary,
                status, author_object_id, author_name, created_at)
            VALUES (
                $id, $profile, $version, $description, $content, $hash, $summary,
                'PendingReview', $author, $author_name, $now);
            """,
            [
                ("$id", id),
                ("$profile", candidate.ProfileId),
                ("$version", candidate.Version),
                ("$description", candidate.Description),
                ("$content", candidate.Content),
                ("$hash", candidate.ContentHash),
                ("$summary", summary),
                ("$author", authorObjectId),
                ("$author_name", authorName),
                ("$now", Format(now))
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "privacy-profile.submitted", id, authorObjectId, authorName, now,
            cancellationToken, VersionTargetType);
        await transaction.CommitAsync(cancellationToken);
        return (await GetPrivacyProfileVersionAsync(id, cancellationToken))!;
    }

    public async Task<IReadOnlyList<PrivacyProfileVersionSummary>> ListPrivacyProfileVersionsAsync(
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"SELECT {VersionColumns} FROM privacy_profile_versions v ORDER BY v.created_at DESC, v.rowid DESC LIMIT 500;";
        List<PrivacyProfileVersionSummary> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(ReadSummary(reader));
        }

        return records;
    }

    public async Task<PrivacyProfileVersionDetail?> GetPrivacyProfileVersionAsync(
        string id,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        PrivacyProfileVersionSummary summary;
        string content;
        string authorObjectId;
        await using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText =
                $"SELECT {VersionColumns}, v.content, v.author_object_id FROM privacy_profile_versions v WHERE v.id = $id;";
            command.Parameters.AddWithValue("$id", id);
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            summary = ReadSummary(reader);
            content = reader.GetString(reader.GetOrdinal("content"));
            authorObjectId = reader.GetString(reader.GetOrdinal("author_object_id"));
        }

        bool parsed = ProfileSemanticVersion.TryParse(summary.Version, out ProfileSemanticVersion current);
        string? previousApproved = (await ReadVersionsOfAsync(connection, null, summary.ProfileId, cancellationToken))
            .Where(item => parsed
                && item.Status == nameof(PrivacyProfileVersionStatus.Approved)
                && item.Parsed < current)
            .OrderByDescending(item => item.Parsed)
            .Select(item => item.Id)
            .FirstOrDefault();
        return new PrivacyProfileVersionDetail(
            summary.Id, summary.ProfileId, summary.Version, summary.Description, summary.ContentHash,
            summary.ChangeSummary, summary.Status, summary.AuthorName, summary.CreatedAt, summary.ReviewerName,
            summary.ReviewedAt, summary.ReviewReason, summary.AssignedCollectors, content, authorObjectId,
            previousApproved);
    }

    /// <summary>
    /// Approves or rejects a PendingReview version. The author can never review their own
    /// version (two-person rule). Returns null when the version does not exist.
    /// </summary>
    public async Task<PrivacyProfileVersionDetail?> ReviewPrivacyProfileVersionAsync(
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
        string? author = null;
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT status, author_object_id FROM privacy_profile_versions WHERE id = $id;";
            select.Parameters.AddWithValue("$id", id);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                status = reader.GetString(0);
                author = reader.GetString(1);
            }
        }

        if (status is null)
        {
            return null;
        }

        if (string.Equals(author, reviewerObjectId, StringComparison.Ordinal))
        {
            throw new PrivacyProfileConflictException("The author of a privacy profile version cannot review it.");
        }

        if (status != nameof(PrivacyProfileVersionStatus.PendingReview))
        {
            throw new PrivacyProfileConflictException(
                "Only privacy profile versions pending review can be approved or rejected.");
        }

        PrivacyProfileVersionStatus target = approve
            ? PrivacyProfileVersionStatus.Approved
            : PrivacyProfileVersionStatus.Rejected;
        await CommandAsync(
            connection,
            transaction,
            """
            UPDATE privacy_profile_versions SET
                status = $status,
                reviewer_object_id = $reviewer,
                reviewer_name = $reviewer_name,
                reviewed_at = $now,
                review_reason = $reason
            WHERE id = $id AND status = 'PendingReview';
            """,
            [
                ("$status", target.ToString()),
                ("$reviewer", reviewerObjectId),
                ("$reviewer_name", reviewerName),
                ("$now", Format(now)),
                ("$reason", trimmed),
                ("$id", id)
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, approve ? "privacy-profile.approved" : "privacy-profile.rejected", id,
            reviewerObjectId, reviewerName, now, cancellationToken, VersionTargetType);
        await transaction.CommitAsync(cancellationToken);
        return await GetPrivacyProfileVersionAsync(id, cancellationToken);
    }

    /// <summary>
    /// Assigns an Approved version to a collector, or clears the assignment when
    /// <paramref name="versionId"/> is null. Returns null when the collector does not exist.
    /// </summary>
    public async Task<CollectorRecord?> AssignPrivacyProfileAsync(
        string collectorId,
        string? versionId,
        string? reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string trimmed = RequireText(reason, nameof(reason));
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? collectorStatus = await ScalarAsync(
            connection, transaction, "SELECT status FROM collectors WHERE id = $id;", ("$id", collectorId),
            cancellationToken);
        if (collectorStatus is null)
        {
            return null;
        }

        if (versionId is not null)
        {
            if (collectorStatus == nameof(CollectorStatus.Revoked))
            {
                throw new PrivacyProfileConflictException("Revoked collectors cannot be assigned a privacy profile.");
            }

            string? versionStatus = await ScalarAsync(
                connection, transaction, "SELECT status FROM privacy_profile_versions WHERE id = $id;",
                ("$id", versionId), cancellationToken);
            if (versionStatus is null)
            {
                throw new PrivacyProfileValidationException("Privacy profile version was not found.");
            }

            if (versionStatus != nameof(PrivacyProfileVersionStatus.Approved))
            {
                throw new PrivacyProfileConflictException("Only approved privacy profile versions can be assigned.");
            }
        }

        await CommandAsync(
            connection,
            transaction,
            "UPDATE collectors SET desired_privacy_profile_version_id = $version WHERE id = $id;",
            [("$version", versionId), ("$id", collectorId)],
            cancellationToken);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO privacy_profile_assignments (
                collector_id, version_id, action, reason, actor_object_id, actor_name, occurred_at)
            VALUES ($collector, $version, $action, $reason, $actor, $name, $now);
            """,
            [
                ("$collector", collectorId),
                ("$version", versionId),
                ("$action", versionId is null ? "cleared" : "assigned"),
                ("$reason", trimmed),
                ("$actor", actorObjectId),
                ("$name", actorName),
                ("$now", Format(now))
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection,
            transaction,
            versionId is null ? "collector.privacy-profile-cleared" : "collector.privacy-profile-assigned",
            collectorId,
            actorObjectId,
            actorName,
            now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(collectorId, cancellationToken);
    }

    public async Task<IReadOnlyList<PrivacyProfileAssignment>> ListPrivacyProfileAssignmentsAsync(
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT a.id, a.collector_id, a.version_id, v.profile_id, v.version, a.action, a.reason,
                   a.actor_name, a.occurred_at
            FROM privacy_profile_assignments a
            LEFT JOIN privacy_profile_versions v ON v.id = a.version_id
            ORDER BY a.id DESC
            LIMIT 250;
            """;
        List<PrivacyProfileAssignment> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new PrivacyProfileAssignment(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                Parse(reader.GetString(8))));
        }

        return records;
    }

    /// <summary>
    /// The assigned version for a collector, bound to its principal exactly like heartbeats:
    /// a collector id registered by another principal is indistinguishable from an unknown one.
    /// </summary>
    public async Task<PrivacyProfileDeployment> GetPrivacyProfileDeploymentAsync(
        string collectorId,
        string principalObjectId,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT c.status, v.id, v.profile_id, v.version, v.content_hash, v.content
            FROM collectors c
            LEFT JOIN privacy_profile_versions v ON v.id = c.desired_privacy_profile_version_id
            WHERE c.id = $id AND c.principal_object_id = $principal;
            """;
        command.Parameters.AddWithValue("$id", collectorId);
        command.Parameters.AddWithValue("$principal", principalObjectId);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new PrivacyProfileDeployment(PrivacyProfileDeploymentState.NotFound);
        }

        if (reader.GetString(0) != nameof(CollectorStatus.Active))
        {
            return new PrivacyProfileDeployment(PrivacyProfileDeploymentState.NotActive);
        }

        return reader.IsDBNull(1)
            ? new PrivacyProfileDeployment(PrivacyProfileDeploymentState.Unassigned)
            : new PrivacyProfileDeployment(
                PrivacyProfileDeploymentState.Assigned,
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5));
    }

    /// <summary>True for <c>default</c> or <c>sha256:</c> followed by 64 lowercase hex characters.</summary>
    public static bool IsPrivacyProfileHash(string value) =>
        value == "default"
        || (value.Length == 71
            && value.StartsWith("sha256:", StringComparison.Ordinal)
            && IsLowerHex(value.AsSpan(7)));

    /// <summary>True when every character is 0-9 or a-f.</summary>
    public static bool IsLowerHex(ReadOnlySpan<char> value) => !value.ContainsAnyExcept(LowerHex);

    private static readonly System.Buffers.SearchValues<char> LowerHex =
        System.Buffers.SearchValues.Create("0123456789abcdef");

    private const string VersionTargetType = "privacy-profile-version";

    private static async Task<DesiredPrivacyProfile?> ReadDesiredPrivacyProfileAsync(
        SqliteConnection connection,
        string versionId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "SELECT profile_id, version, content_hash FROM privacy_profile_versions WHERE id = $id;";
        command.Parameters.AddWithValue("$id", versionId);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new DesiredPrivacyProfile(versionId, reader.GetString(0), reader.GetString(1), reader.GetString(2))
            : null;
    }

    private static PrivacyProfileVersionSummary ReadSummary(SqliteDataReader reader) =>
        new(
            reader.GetString(reader.GetOrdinal("id")),
            reader.GetString(reader.GetOrdinal("profile_id")),
            reader.GetString(reader.GetOrdinal("version")),
            ReadOptionalString(reader, "description"),
            reader.GetString(reader.GetOrdinal("content_hash")),
            reader.GetString(reader.GetOrdinal("change_summary")),
            Enum.Parse<PrivacyProfileVersionStatus>(reader.GetString(reader.GetOrdinal("status"))),
            ReadOptionalString(reader, "author_name"),
            Parse(reader.GetString(reader.GetOrdinal("created_at"))),
            ReadOptionalString(reader, "reviewer_name"),
            ParseOptional(reader, "reviewed_at"),
            ReadOptionalString(reader, "review_reason"),
            reader.GetInt32(reader.GetOrdinal("assigned_collectors")));

    private static async Task<IReadOnlyList<(string Id, string Status, ProfileSemanticVersion Parsed)>> ReadVersionsOfAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string profileId,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT id, status, version FROM privacy_profile_versions WHERE profile_id = $profile;";
        command.Parameters.AddWithValue("$profile", profileId);
        List<(string, string, ProfileSemanticVersion)> versions = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // Every stored version passed MAJOR.MINOR.PATCH validation on submission.
            if (ProfileSemanticVersion.TryParse(reader.GetString(2), out ProfileSemanticVersion parsed))
            {
                versions.Add((reader.GetString(0), reader.GetString(1), parsed));
            }
        }

        return versions;
    }

    private static string? Latest(IReadOnlyList<(string Id, string Status, ProfileSemanticVersion Parsed)> versions) =>
        versions.Count == 0 ? null : versions.Max(item => item.Parsed).ToString();

    private static string RequireText(string? value, string name) =>
        string.IsNullOrWhiteSpace(value) || value.Trim().Length > MaximumReasonLength
            ? throw new ArgumentException("A value of 1–500 characters is required.", name)
            : value.Trim();
}
