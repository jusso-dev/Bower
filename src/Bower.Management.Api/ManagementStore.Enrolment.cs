using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Bower.Management.Api;

/// <summary>
/// One-time enrolment tokens and key-bound collector credentials (#109). Tokens are stored
/// as SHA-256 hashes and consumed in the enrolment transaction. Credentials hold only the
/// collector's public key. Every state change writes an audit row in the same transaction.
/// </summary>
public sealed partial class ManagementStore
{
    public const int MaximumListedEnrolmentRecords = 250;

    private const string AnonymousActorId = "anonymous";
    private const string AnonymousActorName = "Unauthenticated enrolment request";

    /// <summary>Enrolment inventory bounds, as for registration. The public key is checked separately.</summary>
    public static bool ValidEnrolment(CollectorEnrolmentRequest? request) =>
        request is not null
        && request.Token is { Length: > 0 and <= 256 }
        && ValidText(request.CollectorId, 128)
        && ValidText(request.MachineName, 256)
        && ValidText(request.Environment, 128)
        && ValidText(request.Version, 128)
        && ValidText(request.ConfigurationHash, 256)
        && ValidText(request.PolicyHash, 256);

    private static async Task InitializeEnrolmentAsync(SqliteConnection connection, CancellationToken cancellationToken) =>
        await ExecuteAsync(
            connection,
            """
            CREATE TABLE IF NOT EXISTS enrolment_tokens (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                environment TEXT NOT NULL,
                collector_id TEXT NULL,
                reason TEXT NOT NULL,
                created_by_object_id TEXT NOT NULL,
                created_by_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT NULL,
                used_by_collector_id TEXT NULL,
                used_credential_id TEXT NULL,
                revoked_at TEXT NULL,
                revoked_reason TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS collector_credentials (
                id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL REFERENCES collectors(id),
                public_key TEXT NOT NULL,
                status TEXT NOT NULL,
                origin TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_used_at TEXT NULL,
                ended_at TEXT NULL,
                ended_reason TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_collector_credentials_collector
                ON collector_credentials(collector_id, status);
            """,
            cancellationToken);

    /// <summary>Creates a token, stores its hash and returns the token once.</summary>
    public async Task<IssuedEnrolmentToken> CreateEnrolmentTokenAsync(
        EnrolmentTokenRequest request,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        int hours = request.ExpiresInHours ?? CollectorEnrolment.DefaultTokenLifetimeHours;
        string? collectorId = string.IsNullOrWhiteSpace(request.CollectorId) ? null : request.CollectorId.Trim();
        if (!ValidText(request.Environment, 128) || !ValidText(request.Reason, 500)
            || collectorId is { Length: > 128 }
            || hours is < 1 or > CollectorEnrolment.MaximumTokenLifetimeHours)
        {
            throw new ArgumentException("Enrolment token request is invalid.", nameof(request));
        }

        string token = CollectorEnrolment.NewToken(out string id);
        EnrolmentTokenRecord record = new(
            id,
            request.Environment.Trim(),
            collectorId,
            EnrolmentTokenStatus.Active,
            request.Reason.Trim(),
            actorObjectId,
            actorName,
            now,
            now.AddHours(hours),
            null,
            null,
            null);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO enrolment_tokens (
                id, token_hash, environment, collector_id, reason, created_by_object_id,
                created_by_name, created_at, expires_at)
            VALUES ($id, $hash, $environment, $collector, $reason, $actor, $name, $created, $expires);
            """,
            [
                ("$id", record.Id),
                ("$hash", CollectorEnrolment.HashToken(token)),
                ("$environment", record.Environment),
                ("$collector", record.CollectorId),
                ("$reason", record.Reason),
                ("$actor", actorObjectId),
                ("$name", actorName),
                ("$created", Format(now)),
                ("$expires", Format(record.ExpiresAt))
            ],
            cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "enrolment-token.created", id, actorObjectId, actorName, now,
            cancellationToken, "enrolment-token");
        await transaction.CommitAsync(cancellationToken);
        return new IssuedEnrolmentToken(token, record);
    }

    public async Task<IReadOnlyList<EnrolmentTokenRecord>> ListEnrolmentTokensAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT * FROM enrolment_tokens ORDER BY created_at DESC, id
            LIMIT {MaximumListedEnrolmentRecords};
            """;
        List<EnrolmentTokenRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(ReadEnrolmentToken(reader, now));
        }

        return records;
    }

    /// <summary>Revokes an unused token. Null when unknown; <see cref="CollectorStateException"/> when already used or revoked.</summary>
    public async Task<EnrolmentTokenRecord?> RevokeEnrolmentTokenAsync(
        string id,
        string reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!ValidText(reason, 500))
        {
            throw new ArgumentException("A reason of 1–500 characters is required.", nameof(reason));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        if (await ScalarAsync(connection, transaction, "SELECT id FROM enrolment_tokens WHERE id = $id;",
                ("$id", id), cancellationToken) is null)
        {
            return null;
        }

        int changed = await CommandAsync(
            connection,
            transaction,
            """
            UPDATE enrolment_tokens SET revoked_at = $now, revoked_reason = $reason
            WHERE id = $id AND used_at IS NULL AND revoked_at IS NULL;
            """,
            [("$now", Format(now)), ("$reason", reason.Trim()), ("$id", id)],
            cancellationToken);
        if (changed == 0)
        {
            throw new CollectorStateException(id, "used or revoked");
        }

        await InsertAuditAsync(
            connection, transaction, "enrolment-token.revoked", id, actorObjectId, actorName, now,
            cancellationToken, "enrolment-token");
        await transaction.CommitAsync(cancellationToken);
        return await GetEnrolmentTokenAsync(id, now, cancellationToken);
    }

    /// <summary>
    /// Exchanges a token for a credential bound to <paramref name="publicKeyPem"/> and puts
    /// the collector in Pending. A refused token is audited and never consumed. Retrying a
    /// used token with the same collector and key returns the credential it issued, so a lost
    /// response does not strand the collector.
    /// </summary>
    public async Task<EnrolmentResult> EnrolAsync(
        CollectorEnrolmentRequest request,
        string publicKeyPem,
        string credentialId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        async Task<EnrolmentResult> RefuseAsync(string code, string target)
        {
            await InsertAuditAsync(
                connection, transaction, $"enrolment-token.refused:{code}", target, AnonymousActorId,
                AnonymousActorName, now, cancellationToken, "enrolment-token");
            await transaction.CommitAsync(cancellationToken);
            return new EnrolmentResult(null, code);
        }

        if (!CollectorEnrolment.TryParseToken(request.Token, out string tokenId))
        {
            return await RefuseAsync(EnrolmentRefusals.Malformed, "unknown");
        }

        TokenRow? token = await ReadTokenRowAsync(connection, transaction, tokenId, cancellationToken);
        if (token is null)
        {
            return await RefuseAsync(EnrolmentRefusals.Unknown, tokenId);
        }

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(CollectorEnrolment.HashToken(request.Token)),
                Encoding.ASCII.GetBytes(token.Hash)))
        {
            return await RefuseAsync(EnrolmentRefusals.Invalid, tokenId);
        }

        if (token.RevokedAt is not null)
        {
            return await RefuseAsync(EnrolmentRefusals.Revoked, tokenId);
        }

        string principal = CollectorEnrolment.PrincipalFor(request.CollectorId);
        if (token.UsedAt is not null)
        {
            // Idempotent retry of the exchange that consumed this token.
            if (string.Equals(token.UsedByCollectorId, request.CollectorId, StringComparison.Ordinal)
                && string.Equals(token.UsedCredentialId, credentialId, StringComparison.Ordinal)
                && await ReadIssuedCredentialAsync(connection, transaction, request.CollectorId, credentialId,
                    now, cancellationToken) is { } issued)
            {
                await transaction.CommitAsync(cancellationToken);
                return new EnrolmentResult(issued, null);
            }

            return await RefuseAsync(EnrolmentRefusals.Used, tokenId);
        }

        if (token.ExpiresAt <= now)
        {
            return await RefuseAsync(EnrolmentRefusals.Expired, tokenId);
        }

        if (!string.Equals(token.Environment, request.Environment, StringComparison.Ordinal))
        {
            return await RefuseAsync(EnrolmentRefusals.WrongEnvironment, tokenId);
        }

        if (token.CollectorId is not null
            && !string.Equals(token.CollectorId, request.CollectorId, StringComparison.Ordinal))
        {
            return await RefuseAsync(EnrolmentRefusals.WrongCollector, tokenId);
        }

        string? boundPrincipal = null;
        string? lifecycle = null;
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT principal_object_id, status FROM collectors WHERE id = $id;";
            select.Parameters.AddWithValue("$id", request.CollectorId);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                boundPrincipal = reader.GetString(0);
                lifecycle = reader.GetString(1);
            }
        }

        if (boundPrincipal is not null && !string.Equals(boundPrincipal, principal, StringComparison.Ordinal))
        {
            // An Entra-identity collector cannot be taken over with a token.
            return await RefuseAsync(EnrolmentRefusals.IdentityConflict, tokenId);
        }

        if (lifecycle is "Suspended" or "Revoked")
        {
            // Suspension and revocation are administrator decisions; a token cannot undo them.
            return await RefuseAsync(EnrolmentRefusals.CollectorNotEnrollable, tokenId);
        }

        if (await ScalarAsync(connection, transaction, "SELECT id FROM collector_credentials WHERE id = $id;",
                ("$id", credentialId), cancellationToken) is not null)
        {
            return await RefuseAsync(EnrolmentRefusals.KeyReused, tokenId);
        }

        int consumed = await CommandAsync(
            connection,
            transaction,
            """
            UPDATE enrolment_tokens SET
                used_at = $now, used_by_collector_id = $collector, used_credential_id = $credential
            WHERE id = $id AND used_at IS NULL AND revoked_at IS NULL;
            """,
            [("$now", Format(now)), ("$collector", request.CollectorId), ("$credential", credentialId), ("$id", tokenId)],
            cancellationToken);
        if (consumed != 1)
        {
            return await RefuseAsync(EnrolmentRefusals.Used, tokenId);
        }

        // New or re-enrolled, the collector waits in Pending for an approver: the token only
        // proves an administrator expected it, never that it is approved.
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO collectors (
                id, machine_name, environment, version, status, principal_object_id,
                first_seen_at, last_seen_at, configuration_hash, policy_hash)
            VALUES (
                $id, $machine, $environment, $version, 'Pending', $principal,
                $now, $now, $configuration, $policy)
            ON CONFLICT(id) DO UPDATE SET
                machine_name = excluded.machine_name,
                environment = excluded.environment,
                version = excluded.version,
                status = 'Pending',
                last_seen_at = excluded.last_seen_at,
                configuration_hash = excluded.configuration_hash,
                policy_hash = excluded.policy_hash;
            """,
            [
                ("$id", request.CollectorId),
                ("$machine", request.MachineName),
                ("$environment", request.Environment),
                ("$version", request.Version),
                ("$principal", principal),
                ("$now", Format(now)),
                ("$configuration", request.ConfigurationHash),
                ("$policy", request.PolicyHash)
            ],
            cancellationToken);
        await CommandAsync(
            connection,
            transaction,
            """
            UPDATE collector_credentials SET status = 'revoked', ended_at = $now, ended_reason = 're-enrolled'
            WHERE collector_id = $collector AND status = 'active';
            """,
            [("$now", Format(now)), ("$collector", request.CollectorId)],
            cancellationToken);
        await InsertCredentialAsync(
            connection, transaction, request.CollectorId, credentialId, publicKeyPem, "enrolment", now, cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "enrolment-token.used", tokenId, principal, request.CollectorId, now,
            cancellationToken, "enrolment-token");
        await InsertAuditAsync(
            connection, transaction, boundPrincipal is null ? "collector.enrolled" : "collector.re-enrolled",
            request.CollectorId, principal, request.CollectorId, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new EnrolmentResult(
            new IssuedCollectorCredential(
                request.CollectorId, credentialId, CollectorStatus.Pending, now, now + CollectorEnrolment.CredentialLifetime),
            null);
    }

    /// <summary>
    /// Checks an assertion against its credential and records the use. Returns null when it
    /// authenticates, else a <see cref="CredentialRefusals"/> code. The first use of a
    /// rotated credential retires the credential it replaced: rotation without downtime.
    /// </summary>
    public async Task<string?> AuthenticateCredentialAsync(
        CollectorAssertion assertion,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string collectorId, publicKey, status;
        DateTimeOffset expiresAt;
        bool firstUse;
        await using (SqliteCommand select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT collector_id, public_key, status, expires_at, last_used_at
                FROM collector_credentials WHERE id = $id;
                """;
            select.Parameters.AddWithValue("$id", assertion.CredentialId);
            await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return CredentialRefusals.UnknownCredential;
            }

            collectorId = reader.GetString(0);
            publicKey = reader.GetString(1);
            status = reader.GetString(2);
            expiresAt = Parse(reader.GetString(3));
            firstUse = reader.IsDBNull(4);
        }

        if (!string.Equals(collectorId, assertion.CollectorId, StringComparison.Ordinal))
        {
            return CredentialRefusals.WrongCollector;
        }

        if (!assertion.VerifiedBy(publicKey))
        {
            return CredentialRefusals.InvalidSignature;
        }

        if (status == CollectorCredentialStatus.Revoked)
        {
            return CredentialRefusals.CredentialRevoked;
        }

        if (status == CollectorCredentialStatus.Retired)
        {
            return CredentialRefusals.CredentialRetired;
        }

        if (expiresAt <= now)
        {
            return CredentialRefusals.CredentialExpired;
        }

        await CommandAsync(
            connection,
            transaction,
            "UPDATE collector_credentials SET last_used_at = $now WHERE id = $id;",
            [("$now", Format(now)), ("$id", assertion.CredentialId)],
            cancellationToken);
        if (firstUse)
        {
            List<string> retired = [];
            await using (SqliteCommand others = connection.CreateCommand())
            {
                others.Transaction = transaction;
                others.CommandText = """
                    SELECT id FROM collector_credentials
                    WHERE collector_id = $collector AND status = 'active' AND id <> $id;
                    """;
                others.Parameters.AddWithValue("$collector", collectorId);
                others.Parameters.AddWithValue("$id", assertion.CredentialId);
                await using SqliteDataReader reader = await others.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    retired.Add(reader.GetString(0));
                }
            }

            foreach (string id in retired)
            {
                await CommandAsync(
                    connection,
                    transaction,
                    """
                    UPDATE collector_credentials SET status = 'retired', ended_at = $now, ended_reason = 'rotated'
                    WHERE id = $id;
                    """,
                    [("$now", Format(now)), ("$id", id)],
                    cancellationToken);
                await InsertAuditAsync(
                    connection, transaction, "collector.credential-retired", collectorId,
                    CollectorEnrolment.PrincipalFor(collectorId), collectorId, now, cancellationToken);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return null;
    }

    /// <summary>
    /// Issues a successor credential under the caller's current one. The current credential
    /// stays valid until the successor is first used. An unused earlier successor is retired;
    /// resending the same key returns the same successor.
    /// </summary>
    public async Task<IssuedCollectorCredential> RotateCredentialAsync(
        string collectorId,
        string currentCredentialId,
        string publicKeyPem,
        string credentialId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        string? status = await ScalarAsync(connection, transaction, "SELECT status FROM collectors WHERE id = $id;",
            ("$id", collectorId), cancellationToken);
        if (status is null or "Suspended" or "Revoked")
        {
            throw new CollectorStateException(collectorId, status ?? "unknown");
        }

        if (await ScalarAsync(
                connection, transaction,
                "SELECT status FROM collector_credentials WHERE id = $id AND collector_id = $collector;",
                ("$id", currentCredentialId), ("$collector", collectorId), cancellationToken)
            != CollectorCredentialStatus.Active)
        {
            throw new CollectorStateException(collectorId, "credential not active");
        }

        if (await ScalarAsync(connection, transaction, "SELECT collector_id FROM collector_credentials WHERE id = $id;",
                ("$id", credentialId), cancellationToken) is not null)
        {
            if (await ReadIssuedCredentialAsync(connection, transaction, collectorId, credentialId, now,
                    cancellationToken, unusedOnly: true) is { } same)
            {
                await transaction.CommitAsync(cancellationToken);
                return same;
            }

            throw new ArgumentException("Credential keys cannot be reused.", nameof(publicKeyPem));
        }

        await CommandAsync(
            connection,
            transaction,
            """
            UPDATE collector_credentials SET status = 'retired', ended_at = $now, ended_reason = 'superseded'
            WHERE collector_id = $collector AND status = 'active' AND id <> $current AND last_used_at IS NULL;
            """,
            [("$now", Format(now)), ("$collector", collectorId), ("$current", currentCredentialId)],
            cancellationToken);
        await InsertCredentialAsync(
            connection, transaction, collectorId, credentialId, publicKeyPem, "rotation", now, cancellationToken);
        await InsertAuditAsync(
            connection, transaction, "collector.credential-rotated", collectorId,
            CollectorEnrolment.PrincipalFor(collectorId), collectorId, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new IssuedCollectorCredential(
            collectorId, credentialId, Enum.Parse<CollectorStatus>(status), now, now + CollectorEnrolment.CredentialLifetime);
    }

    public async Task<IReadOnlyList<CollectorCredentialRecord>> ListCredentialsAsync(
        string? collectorId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT * FROM collector_credentials
            WHERE $collector IS NULL OR collector_id = $collector
            ORDER BY issued_at DESC, id
            LIMIT {MaximumListedEnrolmentRecords};
            """;
        command.Parameters.AddWithValue("$collector", (object?)collectorId ?? DBNull.Value);
        List<CollectorCredentialRecord> records = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(ReadCredential(reader, now));
        }

        return records;
    }

    /// <summary>
    /// Revokes an active credential: the collector's next request (its next heartbeat) is
    /// refused. Null when unknown; <see cref="CollectorStateException"/> when not active.
    /// </summary>
    public async Task<CollectorCredentialRecord?> RevokeCredentialAsync(
        string collectorId,
        string credentialId,
        string reason,
        string actorObjectId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!ValidText(reason, 500))
        {
            throw new ArgumentException("A reason of 1–500 characters is required.", nameof(reason));
        }

        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        if (await ScalarAsync(
                connection, transaction,
                "SELECT id FROM collector_credentials WHERE id = $id AND collector_id = $collector;",
                ("$id", credentialId), ("$collector", collectorId), cancellationToken) is null)
        {
            return null;
        }

        int changed = await CommandAsync(
            connection,
            transaction,
            """
            UPDATE collector_credentials SET status = 'revoked', ended_at = $now, ended_reason = $reason
            WHERE id = $id AND status = 'active';
            """,
            [("$now", Format(now)), ("$reason", reason.Trim()), ("$id", credentialId)],
            cancellationToken);
        if (changed == 0)
        {
            throw new CollectorStateException(collectorId, "credential not active");
        }

        await InsertAuditAsync(
            connection, transaction, "collector.credential-revoked", collectorId, actorObjectId, actorName, now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (await ListCredentialsAsync(collectorId, now, cancellationToken))
            .Single(record => record.Id == credentialId);
    }

    private async Task<EnrolmentTokenRecord?> GetEnrolmentTokenAsync(
        string id,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM enrolment_tokens WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadEnrolmentToken(reader, now) : null;
    }

    private static async Task InsertCredentialAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        string credentialId,
        string publicKeyPem,
        string origin,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        await CommandAsync(
            connection,
            transaction,
            """
            INSERT INTO collector_credentials (
                id, collector_id, public_key, status, origin, issued_at, expires_at)
            VALUES ($id, $collector, $key, 'active', $origin, $issued, $expires);
            """,
            [
                ("$id", credentialId),
                ("$collector", collectorId),
                ("$key", publicKeyPem),
                ("$origin", origin),
                ("$issued", Format(now)),
                ("$expires", Format(now + CollectorEnrolment.CredentialLifetime))
            ],
            cancellationToken);

    /// <summary>The credential as issued, when it is still active (and, if asked, never used).</summary>
    private static async Task<IssuedCollectorCredential?> ReadIssuedCredentialAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectorId,
        string credentialId,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        bool unusedOnly = false)
    {
        await using SqliteCommand select = connection.CreateCommand();
        select.Transaction = transaction;
        select.CommandText = """
            SELECT c.issued_at, c.expires_at, c.last_used_at, k.status
            FROM collector_credentials c JOIN collectors k ON k.id = c.collector_id
            WHERE c.id = $id AND c.collector_id = $collector AND c.status = 'active';
            """;
        select.Parameters.AddWithValue("$id", credentialId);
        select.Parameters.AddWithValue("$collector", collectorId);
        await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        DateTimeOffset expiresAt = Parse(reader.GetString(1));
        if (expiresAt <= now || (unusedOnly && !reader.IsDBNull(2)))
        {
            return null;
        }

        return new IssuedCollectorCredential(
            collectorId, credentialId, Enum.Parse<CollectorStatus>(reader.GetString(3)),
            Parse(reader.GetString(0)), expiresAt);
    }

    private static async Task<TokenRow?> ReadTokenRowAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string id,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand select = connection.CreateCommand();
        select.Transaction = transaction;
        select.CommandText = "SELECT * FROM enrolment_tokens WHERE id = $id;";
        select.Parameters.AddWithValue("$id", id);
        await using SqliteDataReader reader = await select.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new TokenRow(
            reader.GetString(reader.GetOrdinal("token_hash")),
            reader.GetString(reader.GetOrdinal("environment")),
            ReadOptionalString(reader, "collector_id"),
            Parse(reader.GetString(reader.GetOrdinal("expires_at"))),
            ParseOptional(reader, "used_at"),
            ReadOptionalString(reader, "used_by_collector_id"),
            ReadOptionalString(reader, "used_credential_id"),
            ParseOptional(reader, "revoked_at"));
    }

    private static EnrolmentTokenRecord ReadEnrolmentToken(SqliteDataReader reader, DateTimeOffset now)
    {
        DateTimeOffset expiresAt = Parse(reader.GetString(reader.GetOrdinal("expires_at")));
        DateTimeOffset? usedAt = ParseOptional(reader, "used_at");
        DateTimeOffset? revokedAt = ParseOptional(reader, "revoked_at");
        string status = revokedAt is not null ? EnrolmentTokenStatus.Revoked
            : usedAt is not null ? EnrolmentTokenStatus.Used
            : expiresAt <= now ? EnrolmentTokenStatus.Expired
            : EnrolmentTokenStatus.Active;
        return new EnrolmentTokenRecord(
            reader.GetString(reader.GetOrdinal("id")),
            reader.GetString(reader.GetOrdinal("environment")),
            ReadOptionalString(reader, "collector_id"),
            status,
            reader.GetString(reader.GetOrdinal("reason")),
            reader.GetString(reader.GetOrdinal("created_by_object_id")),
            reader.GetString(reader.GetOrdinal("created_by_name")),
            Parse(reader.GetString(reader.GetOrdinal("created_at"))),
            expiresAt,
            usedAt,
            ReadOptionalString(reader, "used_by_collector_id"),
            revokedAt);
    }

    private static CollectorCredentialRecord ReadCredential(SqliteDataReader reader, DateTimeOffset now)
    {
        DateTimeOffset expiresAt = Parse(reader.GetString(reader.GetOrdinal("expires_at")));
        string status = reader.GetString(reader.GetOrdinal("status"));
        return new CollectorCredentialRecord(
            reader.GetString(reader.GetOrdinal("id")),
            reader.GetString(reader.GetOrdinal("collector_id")),
            status == CollectorCredentialStatus.Active && expiresAt <= now ? CollectorCredentialStatus.Expired : status,
            reader.GetString(reader.GetOrdinal("origin")),
            Parse(reader.GetString(reader.GetOrdinal("issued_at"))),
            expiresAt,
            ParseOptional(reader, "last_used_at"),
            ParseOptional(reader, "ended_at"));
    }

    private sealed record TokenRow(
        string Hash,
        string Environment,
        string? CollectorId,
        DateTimeOffset ExpiresAt,
        DateTimeOffset? UsedAt,
        string? UsedByCollectorId,
        string? UsedCredentialId,
        DateTimeOffset? RevokedAt);
}
