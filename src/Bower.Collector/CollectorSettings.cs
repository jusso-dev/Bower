using System.Globalization;
using System.Net;

namespace Bower.Collector;

/// <summary>
/// Collector configuration read once from environment variables and validated before the
/// host starts. Invalid or unsafe combinations fail fast instead of degrading silently.
/// </summary>
public sealed record CollectorSettings
{
    public const int MinimumIngestTokenLength = 32;

    public required string ListenUrl { get; init; }

    public required string QueuePath { get; init; }

    public required string PolicyDirectory { get; init; }

    public required string CollectorId { get; init; }

    public string Version { get; init; } = "0.1.0";

    public string Environment { get; init; } = "unknown";

    public long MaximumQueueBytes { get; init; } = 10L * 1024 * 1024 * 1024;

    /// <summary>How long acknowledged events stay in the queue for duplicate detection.</summary>
    public TimeSpan DeliveredRetention { get; init; } = TimeSpan.FromDays(7);

    public string? IngestToken { get; init; }

    /// <summary>One revocable credential per producer: lines of "&lt;producer&gt; sha256:&lt;hex&gt;".</summary>
    public string? IngestTokensFile { get; init; }

    /// <summary>Signed .bowerpack archives to load policies and privacy profile from.</summary>
    public IReadOnlyList<string> Packs { get; init; } = [];

    /// <summary>PEM public keys trusted to sign packs.</summary>
    public IReadOnlyList<string> PackTrustedKeyFiles { get; init; } = [];

    public string? PrivacyProfilePath { get; init; }

    public string? PrivacyHmacKeyFile { get; init; }

    public string PrivacyHmacKeyId { get; init; } = "k1";

    public bool AllowUnauthenticatedIngest { get; init; }

    public int IngestRequestsPerSecond { get; init; } = 500;

    public int MaximumDeliveryAttempts { get; init; } = 20;

    public string OutputType { get; init; } = "none";

    public string AmaSpoolPath { get; init; } = Path.Combine(AppContext.BaseDirectory, "spool");

    public string StreamName { get; init; } = "Custom-BowerSecurity";

    public Uri? DceEndpoint { get; init; }

    public string? DcrImmutableId { get; init; }

    public AzureCredentialMode AzureCredential { get; init; } = AzureCredentialMode.ManagedIdentity;

    public string? AzureClientId { get; init; }

    public Uri? ManagementEndpoint { get; init; }

    public string? ManagementScope { get; init; }

    public bool IsLoopbackListener => IsLoopback(new Uri(ListenUrl).Host);

    public static CollectorSettings FromEnvironment(Func<string, string?>? read = null)
    {
        read ??= System.Environment.GetEnvironmentVariable;
        string? tokenFile = read("BOWER_INGEST_TOKEN_FILE");
        string? token = read("BOWER_INGEST_TOKEN");
        if (!string.IsNullOrWhiteSpace(tokenFile))
        {
            token = File.ReadAllText(tokenFile).Trim();
        }

        string? managementEndpoint = read("BOWER_MANAGEMENT_ENDPOINT");
        string? dceEndpoint = read("BOWER_DCE_ENDPOINT");
        CollectorSettings settings = new()
        {
            ListenUrl = read("BOWER_LISTEN_URL") ?? "http://127.0.0.1:4319",
            QueuePath = read("BOWER_QUEUE_PATH")
                ?? Path.Combine(AppContext.BaseDirectory, "data", "bower.db"),
            PolicyDirectory = read("BOWER_POLICY_DIRECTORY")
                ?? Path.Combine(Directory.GetCurrentDirectory(), "policies", "default"),
            CollectorId = read("BOWER_COLLECTOR_ID") ?? System.Environment.MachineName,
            Environment = read("BOWER_ENVIRONMENT") ?? "unknown",
            MaximumQueueBytes = ReadInt64(read, "BOWER_QUEUE_MAX_BYTES", 10L * 1024 * 1024 * 1024),
            DeliveredRetention = TimeSpan.FromHours(
                ReadInt64(read, "BOWER_QUEUE_RETENTION_HOURS", 7 * 24)),
            IngestToken = string.IsNullOrWhiteSpace(token) ? null : token,
            IngestTokensFile = Blank(read("BOWER_INGEST_TOKENS_FILE")),
            Packs = SplitList(read("BOWER_PACKS")),
            PackTrustedKeyFiles = SplitList(read("BOWER_PACK_TRUSTED_KEYS")),
            PrivacyProfilePath = Blank(read("BOWER_PRIVACY_PROFILE")),
            PrivacyHmacKeyFile = Blank(read("BOWER_PRIVACY_HMAC_KEY_FILE")),
            PrivacyHmacKeyId = Blank(read("BOWER_PRIVACY_HMAC_KEY_ID")) ?? "k1",
            AllowUnauthenticatedIngest = string.Equals(
                read("BOWER_ALLOW_UNAUTHENTICATED_INGEST"),
                "true",
                StringComparison.OrdinalIgnoreCase),
            IngestRequestsPerSecond = (int)ReadInt64(read, "BOWER_INGEST_RATE_PER_SECOND", 500),
            MaximumDeliveryAttempts = (int)ReadInt64(read, "BOWER_MAX_DELIVERY_ATTEMPTS", 20),
            OutputType = (read("BOWER_OUTPUT") ?? "none").ToLowerInvariant(),
            AmaSpoolPath = read("BOWER_AMA_SPOOL_PATH")
                ?? Path.Combine(AppContext.BaseDirectory, "spool"),
            StreamName = read("BOWER_STREAM_NAME") ?? "Custom-BowerSecurity",
            DceEndpoint = string.IsNullOrWhiteSpace(dceEndpoint)
                ? null
                : new Uri(dceEndpoint, UriKind.Absolute),
            DcrImmutableId = read("BOWER_DCR_ID"),
            AzureCredential = ParseCredentialMode(read("BOWER_AZURE_CREDENTIAL")),
            AzureClientId = read("BOWER_AZURE_CLIENT_ID"),
            ManagementEndpoint = string.IsNullOrWhiteSpace(managementEndpoint)
                ? null
                : new Uri(managementEndpoint, UriKind.Absolute),
            ManagementScope = read("BOWER_MANAGEMENT_SCOPE")
        };
        settings.Validate();
        return settings;
    }

    public void Validate()
    {
        if (!Uri.TryCreate(ListenUrl, UriKind.Absolute, out Uri? listen)
            || listen.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException("BOWER_LISTEN_URL must be an absolute HTTP(S) URL.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(CollectorId);
        if (IngestToken is not null && IngestToken.Length < MinimumIngestTokenLength)
        {
            throw new InvalidOperationException(
                $"BOWER_INGEST_TOKEN must contain at least {MinimumIngestTokenLength} characters.");
        }

        // Fail closed: a collector reachable from other hosts must authenticate producers.
        if (IngestToken is null && IngestTokensFile is null && !AllowUnauthenticatedIngest && !IsLoopbackListener)
        {
            throw new InvalidOperationException(
                "BOWER_LISTEN_URL is not loopback, so BOWER_INGEST_TOKEN, BOWER_INGEST_TOKEN_FILE " +
                "or BOWER_INGEST_TOKENS_FILE is required. Set BOWER_ALLOW_UNAUTHENTICATED_INGEST=true " +
                "only on an isolated network you control.");
        }

        if (Packs.Count > 0 && PackTrustedKeyFiles.Count == 0)
        {
            throw new InvalidOperationException(
                "BOWER_PACKS requires BOWER_PACK_TRUSTED_KEYS; packs are never loaded unverified.");
        }

        if (MaximumQueueBytes < 1_048_576)
        {
            throw new InvalidOperationException("BOWER_QUEUE_MAX_BYTES must be at least 1 MiB.");
        }

        if (DeliveredRetention < TimeSpan.FromHours(1) || DeliveredRetention > TimeSpan.FromDays(90))
        {
            throw new InvalidOperationException(
                "BOWER_QUEUE_RETENTION_HOURS must be between 1 and 2160.");
        }

        if (IngestRequestsPerSecond is < 1 or > 100_000)
        {
            throw new InvalidOperationException(
                "BOWER_INGEST_RATE_PER_SECOND must be between 1 and 100000.");
        }

        if (MaximumDeliveryAttempts is < 1 or > 1_000)
        {
            throw new InvalidOperationException(
                "BOWER_MAX_DELIVERY_ATTEMPTS must be between 1 and 1000.");
        }

        if (OutputType is not ("none" or "ama-spool" or "azure-logs-ingestion"))
        {
            throw new InvalidOperationException($"Unsupported BOWER_OUTPUT value: {OutputType}");
        }

        if (OutputType == "azure-logs-ingestion"
            && (DceEndpoint is null || string.IsNullOrWhiteSpace(DcrImmutableId)))
        {
            throw new InvalidOperationException(
                "BOWER_DCE_ENDPOINT and BOWER_DCR_ID are required for azure-logs-ingestion.");
        }

        if (ManagementEndpoint is not null)
        {
            if (string.IsNullOrWhiteSpace(ManagementScope))
            {
                throw new InvalidOperationException(
                    "BOWER_MANAGEMENT_SCOPE is required when BOWER_MANAGEMENT_ENDPOINT is set.");
            }

            // The heartbeat carries an Entra bearer token; never send it in cleartext.
            if (ManagementEndpoint.Scheme != Uri.UriSchemeHttps && !IsLoopback(ManagementEndpoint.Host))
            {
                throw new InvalidOperationException(
                    "BOWER_MANAGEMENT_ENDPOINT must use HTTPS unless it targets loopback.");
            }
        }
    }

    /// <summary>
    /// Hash of non-secret settings reported to management, so configuration drift is
    /// visible. Tokens, keys and file contents are excluded.
    /// </summary>
    public string ConfigurationHash()
    {
        string material = string.Join(
            '\u001f',
            ListenUrl,
            OutputType,
            StreamName,
            DceEndpoint?.ToString() ?? string.Empty,
            DcrImmutableId ?? string.Empty,
            AzureCredential.ToString(),
            MaximumQueueBytes.ToString(CultureInfo.InvariantCulture),
            DeliveredRetention.TotalHours.ToString(CultureInfo.InvariantCulture),
            IngestRequestsPerSecond.ToString(CultureInfo.InvariantCulture),
            MaximumDeliveryAttempts.ToString(CultureInfo.InvariantCulture),
            (IngestToken is not null || IngestTokensFile is not null).ToString(),
            PrivacyHmacKeyId);
        return "sha256:" + Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(material)));
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string[] SplitList(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static bool IsLoopback(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? address)
            && IPAddress.IsLoopback(address);
    }

    private static long ReadInt64(Func<string, string?> read, string name, long fallback)
    {
        string? value = read(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed)
            ? parsed
            : throw new InvalidOperationException($"{name} must be an integer.");
    }

    private static AzureCredentialMode ParseCredentialMode(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            null or "" or "managed-identity" => AzureCredentialMode.ManagedIdentity,
            "workload-identity" => AzureCredentialMode.WorkloadIdentity,
            "environment" => AzureCredentialMode.Environment,
            "azure-cli" => AzureCredentialMode.AzureCli,
            _ => throw new InvalidOperationException(
                "BOWER_AZURE_CREDENTIAL must be managed-identity, workload-identity, environment or azure-cli.")
        };
}

/// <summary>
/// Explicit Azure credential source. Production uses one least-privilege source instead of
/// probing every credential type the way <c>DefaultAzureCredential</c> does.
/// </summary>
public enum AzureCredentialMode
{
    ManagedIdentity,
    WorkloadIdentity,
    Environment,
    AzureCli
}
