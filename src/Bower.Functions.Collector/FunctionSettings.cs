using System.Globalization;
using Bower.Packs;

namespace Bower.Functions.Collector;

/// <summary>
/// Function collector configuration, read once from app settings and validated before the
/// worker starts. Missing or unsafe authentication settings fail start-up (fail closed).
/// Setting names match the HTTP collector wherever the meaning is the same.
/// </summary>
public sealed record FunctionSettings
{
    public const string DevelopmentEnvironment = "Development";
    public const int MinimumDeliveryTimeoutSeconds = 5;
    public const int MaximumDeliveryTimeoutSeconds = 120;

    /// <summary>
    /// Managed privacy profiles need a persistent signed cache and a sync job, which a
    /// serverless host does not have, so anything but <c>local</c> fails start-up. The value
    /// is never echoed.
    /// </summary>
    public const string UnsupportedPrivacyProfileSourceMessage =
        "The Azure Functions collector supports only BOWER_PRIVACY_PROFILE_SOURCE=local. Export an approved " +
        "privacy profile version and set BOWER_PRIVACY_PROFILE instead.";

    /// <summary>Entra tenant (directory) ID that issues producer tokens.</summary>
    public string? EntraTenantId { get; init; }

    /// <summary>Exact token audience: the ingest app registration's client ID (v2 tokens).</summary>
    public string? EntraAudience { get; init; }

    /// <summary>Claim that names the producer in producer scopes: <c>oid</c> (default) or <c>azp</c>.</summary>
    public string ProducerClaim { get; init; } = "oid";

    /// <summary>Accept every caller as producer "development". Only honoured in Development.</summary>
    public bool DevelopmentAuthentication { get; init; }

    /// <summary><c>AZURE_FUNCTIONS_ENVIRONMENT</c>; the platform default is Production.</summary>
    public string Environment { get; init; } = "Production";

    public required PolicyBundleSources PolicySources { get; init; }

    public string? ProducerScopesFile { get; init; }

    /// <summary>Inline producer scopes (same JSON array as the file) for hosts without a mounted file.</summary>
    public string? ProducerScopesJson { get; init; }

    public Uri? LogsIngestionEndpoint { get; init; }

    public string? DcrImmutableId { get; init; }

    public string StreamName { get; init; } = "Custom-BowerSecurity";

    public FunctionCredentialMode AzureCredential { get; init; } = FunctionCredentialMode.ManagedIdentity;

    /// <summary>User-assigned managed identity client ID. Empty selects the system-assigned identity.</summary>
    public string? AzureClientId { get; init; }

    public string CollectorId { get; init; } = "azure-function";

    public string Version { get; init; } = "0.1.0";

    /// <summary>Upper bound for one Logs Ingestion delivery before the caller is told to retry.</summary>
    public TimeSpan DeliveryTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public bool IsDevelopment =>
        string.Equals(Environment, DevelopmentEnvironment, StringComparison.OrdinalIgnoreCase);

    public static FunctionSettings FromEnvironment(Func<string, string?>? read = null)
    {
        read ??= System.Environment.GetEnvironmentVariable;
        string? endpoint = Blank(read("BOWER_DCE_ENDPOINT"));
        string? site = Blank(read("WEBSITE_SITE_NAME"));
        FunctionSettings settings = new()
        {
            EntraTenantId = Blank(read("BOWER_ENTRA_TENANT_ID")),
            EntraAudience = Blank(read("BOWER_ENTRA_AUDIENCE")),
            ProducerClaim = (Blank(read("BOWER_PRODUCER_CLAIM")) ?? "oid").ToLowerInvariant(),
            DevelopmentAuthentication = IsTrue(read("BOWER_DEVELOPMENT_AUTH")),
            Environment = Blank(read("AZURE_FUNCTIONS_ENVIRONMENT")) ?? "Production",
            PolicySources = new PolicyBundleSources
            {
                PolicyDirectory = Resolve(Blank(read("BOWER_POLICY_DIRECTORY")) ?? Path.Combine("policies", "default")),
                Packs = SplitList(read("BOWER_PACKS")).Select(Resolve).ToArray(),
                PackTrustedKeyFiles = SplitList(read("BOWER_PACK_TRUSTED_KEYS")).Select(Resolve).ToArray(),
                PrivacyProfilePath = ResolveOptional(read("BOWER_PRIVACY_PROFILE")),
                PrivacyHmacKeyFile = ResolveOptional(read("BOWER_PRIVACY_HMAC_KEY_FILE")),
                PrivacyHmacKeyId = Blank(read("BOWER_PRIVACY_HMAC_KEY_ID")) ?? "k1",
                PrivacyProfileSource = Blank(read("BOWER_PRIVACY_PROFILE_SOURCE"))?.Trim().ToLowerInvariant() ?? "local"
            },
            ProducerScopesFile = ResolveOptional(read("BOWER_PRODUCER_SCOPES_FILE")),
            ProducerScopesJson = Blank(read("BOWER_PRODUCER_SCOPES_JSON")),
            LogsIngestionEndpoint = endpoint is null ? null : ParseUri(endpoint),
            DcrImmutableId = Blank(read("BOWER_DCR_ID")),
            StreamName = Blank(read("BOWER_STREAM_NAME")) ?? "Custom-BowerSecurity",
            AzureCredential = ParseCredentialMode(read("BOWER_AZURE_CREDENTIAL")),
            AzureClientId = Blank(read("BOWER_AZURE_CLIENT_ID")),
            CollectorId = Blank(read("BOWER_COLLECTOR_ID")) ?? (site is null ? "azure-function" : $"azure-function:{site}"),
            DeliveryTimeout = TimeSpan.FromSeconds(ReadInt(read, "BOWER_DELIVERY_TIMEOUT_SECONDS", 30))
        };
        settings.Validate();
        return settings;
    }

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(PolicySources);
        if (PolicySources.PrivacyProfileSource != "local" || PolicySources.ManagedPrivacyProfile is not null)
        {
            throw new InvalidOperationException(UnsupportedPrivacyProfileSourceMessage);
        }

        if (DevelopmentAuthentication)
        {
            // Never deployable: the platform default environment is Production and the Bicep
            // template pins Production, so a stray setting stops the worker instead.
            if (!IsDevelopment)
            {
                throw new InvalidOperationException(
                    "BOWER_DEVELOPMENT_AUTH is only allowed when AZURE_FUNCTIONS_ENVIRONMENT is Development.");
            }
        }
        else
        {
            if (!Guid.TryParse(EntraTenantId, out Guid tenant) || tenant == Guid.Empty)
            {
                throw new InvalidOperationException("BOWER_ENTRA_TENANT_ID must be the Entra tenant ID (a GUID).");
            }

            if (string.IsNullOrWhiteSpace(EntraAudience) || EntraAudience.Length > 256
                || EntraAudience.Any(char.IsWhiteSpace) || EntraAudience.Contains('*', StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "BOWER_ENTRA_AUDIENCE must be the exact ingest application (client) ID.");
            }
        }

        if (ProducerClaim is not ("oid" or "azp"))
        {
            throw new InvalidOperationException("BOWER_PRODUCER_CLAIM must be oid or azp.");
        }

        if (ProducerScopesFile is not null && ProducerScopesJson is not null)
        {
            throw new InvalidOperationException(
                "Set BOWER_PRODUCER_SCOPES_FILE or BOWER_PRODUCER_SCOPES_JSON, not both.");
        }

        if (PolicySources.Packs.Count > 0 && PolicySources.PackTrustedKeyFiles.Count == 0)
        {
            throw new InvalidOperationException(
                "BOWER_PACKS requires BOWER_PACK_TRUSTED_KEYS; packs are never loaded unverified.");
        }

        if (LogsIngestionEndpoint is null || LogsIngestionEndpoint.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(LogsIngestionEndpoint.UserInfo))
        {
            throw new InvalidOperationException("BOWER_DCE_ENDPOINT must be the HTTPS Logs Ingestion endpoint.");
        }

        if (string.IsNullOrWhiteSpace(DcrImmutableId) || !DcrImmutableId.StartsWith("dcr-", StringComparison.Ordinal)
            || DcrImmutableId.Length > 128)
        {
            throw new InvalidOperationException("BOWER_DCR_ID must be the DCR immutable ID (dcr-...).");
        }

        if (!StreamName.StartsWith("Custom-", StringComparison.Ordinal) || StreamName.Length > 128)
        {
            throw new InvalidOperationException("BOWER_STREAM_NAME must name a Custom- stream.");
        }

        if (AzureCredential == FunctionCredentialMode.AzureCli && !IsDevelopment)
        {
            throw new InvalidOperationException(
                "BOWER_AZURE_CREDENTIAL=azure-cli is only allowed in Development; use managed identity.");
        }

        if (AzureClientId is not null && (!Guid.TryParse(AzureClientId, out Guid clientId) || clientId == Guid.Empty))
        {
            throw new InvalidOperationException("BOWER_AZURE_CLIENT_ID must be a user-assigned identity client ID.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(CollectorId);
        if (DeliveryTimeout < TimeSpan.FromSeconds(MinimumDeliveryTimeoutSeconds)
            || DeliveryTimeout > TimeSpan.FromSeconds(MaximumDeliveryTimeoutSeconds))
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"BOWER_DELIVERY_TIMEOUT_SECONDS must be between {MinimumDeliveryTimeoutSeconds} and {MaximumDeliveryTimeoutSeconds}."));
        }
    }

    /// <summary>
    /// Hash of non-secret settings, stamped on delivered events as the collector configuration
    /// hash. Never includes tokens, keys or file contents.
    /// </summary>
    public string ConfigurationHash()
    {
        string material = string.Join(
            '\u001f',
            "azure-function",
            EntraTenantId ?? string.Empty,
            EntraAudience ?? string.Empty,
            ProducerClaim,
            DevelopmentAuthentication.ToString(),
            StreamName,
            LogsIngestionEndpoint?.ToString() ?? string.Empty,
            DcrImmutableId ?? string.Empty,
            AzureCredential.ToString(),
            AzureClientId is null ? "system-assigned" : "user-assigned",
            ProducerScopesFile ?? (ProducerScopesJson is null ? string.Empty : "inline"),
            PolicySources.PrivacyHmacKeyId,
            DeliveryTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        return "sha256:" + Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(material)));
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool IsTrue(string? value) => string.Equals(value?.Trim(), "true", StringComparison.OrdinalIgnoreCase);

    // Packaged files (policies, privacy profile, scopes) live next to the worker; relative
    // paths resolve there rather than against the host's working directory.
    private static string Resolve(string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);

    private static string? ResolveOptional(string? path) => Blank(path) is { } value ? Resolve(value) : null;

    private static string[] SplitList(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static Uri ParseUri(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
            ? uri
            : throw new InvalidOperationException("BOWER_DCE_ENDPOINT must be an absolute HTTPS URL.");

    private static int ReadInt(Func<string, string?> read, string name, int fallback)
    {
        string? value = read(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : throw new InvalidOperationException($"{name} must be an integer.");
    }

    private static FunctionCredentialMode ParseCredentialMode(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            null or "" or "managed-identity" => FunctionCredentialMode.ManagedIdentity,
            "azure-cli" => FunctionCredentialMode.AzureCli,
            _ => throw new InvalidOperationException(
                "BOWER_AZURE_CREDENTIAL must be managed-identity (azure-cli only in Development).")
        };
}

/// <summary>
/// Explicit credential source for Logs Ingestion. Managed identity is the only deployable
/// mode; Azure CLI exists for local development and is refused outside Development.
/// </summary>
public enum FunctionCredentialMode
{
    ManagedIdentity,
    AzureCli
}
