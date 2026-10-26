using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Bower.Management.Api.Jobs;

namespace Bower.Management.Api;

/// <summary>
/// The closed set of collector commands. Each maps to one fixed collector action; nothing
/// else can be issued. <c>reload</c> (a supervised restart) and <c>rotate-credential</c>
/// need an administrator; the others are operational.
/// </summary>
public static class CollectorCommandTypes
{
    public const string FetchBundle = "fetch-bundle";
    public const string RunCanary = "run-canary";
    public const string Reload = "reload";
    public const string RotateCredential = "rotate-credential";

    public static readonly IReadOnlyList<string> All = [FetchBundle, RunCanary, Reload, RotateCredential];

    public static bool RequiresAdministrator(string command) => command is Reload or RotateCredential;
}

/// <summary>Command lifecycle states stored and returned by the API.</summary>
public static class CollectorCommandStatus
{
    public const string Pending = "pending";
    public const string Delivered = "delivered";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string Rejected = "rejected";
    public const string Expired = "expired";
}

/// <summary>
/// Signs collector commands with the configured P-256 key. The canonical bytes must match the
/// collectors' <c>ManagementCommandVerifier.SignedBytes</c> (C# and Rust) byte for byte. The
/// signed <c>kind</c> keeps a command signature from verifying as any other Bower document.
/// </summary>
public sealed class ManagementCommandSigner
{
    public const string KeyFileSetting = "BOWER_MANAGEMENT_COMMAND_SIGNING_KEY_FILE";
    public const string Kind = "bower.collector-command/v1";

    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    private readonly string? privateKeyPem;

    private ManagementCommandSigner(string? privateKeyPem) => this.privateKeyPem = privateKeyPem;

    public bool Configured => privateKeyPem is not null;

    /// <summary>
    /// Unset path: commands cannot be issued (503) and all else works. A set path that is not a
    /// readable P-256 private key fails start-up. Never logs the key.
    /// </summary>
    public static ManagementCommandSigner FromFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return new ManagementCommandSigner(null);
        }

        try
        {
            string pem = File.ReadAllText(path);
            _ = Bower.Integrity.DetachedSigner.Sign([], pem);
            return new ManagementCommandSigner(pem);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or CryptographicException)
        {
            throw new InvalidOperationException(
                $"{KeyFileSetting} must name a readable ECDSA P-256 private key PEM file.");
        }
    }

    public SignedCollectorCommand Sign(
        string commandId,
        string collectorId,
        string command,
        string nonce,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        if (privateKeyPem is null)
        {
            throw new InvalidOperationException("Collector command signing is not configured.");
        }

        string issued = FormatTimestamp(issuedAt);
        string expires = FormatTimestamp(expiresAt);
        return new SignedCollectorCommand(
            Kind,
            commandId,
            collectorId,
            command,
            nonce,
            issued,
            expires,
            Bower.Integrity.DetachedSigner.Sign(
                SignedBytes(commandId, collectorId, command, nonce, issued, expires), privateKeyPem));
    }

    /// <summary>Canonical JSON of kind, commandId, collectorId, command, nonce, issuedAt and expiresAt.</summary>
    public static byte[] SignedBytes(
        string commandId,
        string collectorId,
        string command,
        string nonce,
        string issuedAt,
        string expiresAt) =>
        Bower.Integrity.CanonicalJson.Bytes(new JsonObject
        {
            ["kind"] = Kind,
            ["commandId"] = commandId,
            ["collectorId"] = collectorId,
            ["command"] = command,
            ["nonce"] = nonce,
            ["issuedAt"] = issuedAt,
            ["expiresAt"] = expiresAt
        });

    /// <summary>UTC with seven fractional digits and a <c>Z</c> suffix: the only accepted form.</summary>
    public static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);
}

/// <summary>
/// Query-time connectivity, apart from the 30-day suspension. <c>stale</c> appears after two
/// missed heartbeat intervals (the collector reports its interval; 60 s for v1),
/// <c>offline</c> after the 15-minute staleness threshold, and <c>unhealthy</c> when delivery
/// has been failing for 15 minutes. Pending, suspended and revoked collectors report their status.
/// </summary>
public static class CollectorConnectivity
{
    public const string Online = "online";
    public const string Stale = "stale";
    public const string Offline = "offline";
    public const string Unhealthy = "unhealthy";
    public const int DefaultIntervalSeconds = 60;
    public const int StaleAfterIntervals = 2;

    public static readonly TimeSpan UnhealthyAfter = TimeSpan.FromMinutes(15);

    public static string Evaluate(CollectorRecord record, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Status is CollectorStatus.Pending or CollectorStatus.Suspended or CollectorStatus.Revoked)
        {
            return record.Status.ToString().ToLowerInvariant();
        }

        TimeSpan silent = now - record.LastSeenAt;
        int interval = record.HeartbeatIntervalSeconds ?? DefaultIntervalSeconds;
        if (silent > CollectorStalenessJob.StaleAfter)
        {
            return Offline;
        }

        if (silent > TimeSpan.FromSeconds(interval * StaleAfterIntervals))
        {
            return Stale;
        }

        return record.DeliveryFailingSince is { } failing && now - failing >= UnhealthyAfter
            ? Unhealthy
            : Online;
    }

    public static CollectorRecord With(CollectorRecord record, DateTimeOffset now) =>
        record with { Connectivity = Evaluate(record, now) };
}

public sealed class CollectorCommandCapabilityException(string collectorId)
    : InvalidOperationException($"Collector '{collectorId}' does not support this command.");

public sealed class CollectorCommandLimitException(string collectorId)
    : InvalidOperationException($"Collector '{collectorId}' has too many outstanding commands.");
