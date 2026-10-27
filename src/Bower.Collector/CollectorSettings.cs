using System.Globalization;
using System.Net;
using Bower.Packs;
using Bower.Redaction.Privacy;

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

    public string? ProducerScopesFile { get; init; }

    /// <summary>Explicit legacy mode: every producer belongs to one trusted domain.</summary>
    public bool SingleTrustDomain { get; init; }

    /// <summary>Signed .bowerpack archives to load policies and privacy profile from.</summary>
    public IReadOnlyList<string> Packs { get; init; } = [];

    /// <summary>PEM public keys trusted to sign packs.</summary>
    public IReadOnlyList<string> PackTrustedKeyFiles { get; init; } = [];

    public string? PrivacyProfilePath { get; init; }

    /// <summary>
    /// <c>local</c> (default): BOWER_PRIVACY_PROFILE, one pack profile or the built-in default.
    /// <c>management</c>: the signed version assigned in the management API (cached locally).
    /// </summary>
    public string PrivacyProfileSource { get; init; } = PrivacyProfileSources.Local;

    /// <summary>PEM public keys trusted to sign managed privacy profiles.</summary>
    public IReadOnlyList<string> ManagedPrivacyTrustedKeyFiles { get; init; } = [];

    /// <summary>Cache directory for the managed privacy profile; null means next to the queue database.</summary>
    public string? ManagedPrivacyDirectory { get; init; }

    /// <summary>
    /// BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT=true: accept events under the built-in default
    /// privacy profile before the first managed sync resolves. Off by default: a management
    /// mode collector without a verified cache refuses ingest (503) until then.
    /// </summary>
    public bool ManagedPrivacyAllowDefault { get; init; }

    public bool UsesManagedPrivacyProfile =>
        string.Equals(PrivacyProfileSource, PrivacyProfileSources.Management, StringComparison.Ordinal);

    /// <summary>Resolved managed privacy profile cache directory.</summary>
    public string ManagedPrivacyCacheDirectory =>
        ManagedPrivacyDirectory
        ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(QueuePath)) ?? ".", "managed-privacy");

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

    /// <summary>JSON file of applications that must keep sending events (BOWER_SOURCE_EXPECTATIONS).</summary>
    public string? SourceExpectationsPath { get; init; }

    /// <summary>Directory for the verifiable long-term archive (BOWER_ARCHIVE_PATH).</summary>
    public string? ArchivePath { get; init; }

    /// <summary>JSON file of syslog listeners and pack routes (BOWER_SYSLOG_CONFIG).</summary>
    public string? SyslogConfigPath { get; init; }

    /// <summary>JSON file of Windows Event Log subscriptions and pack parsers (BOWER_WINDOWS_EVENTLOG_CONFIG). Windows only.</summary>
    public string? WindowsEventLogConfigPath { get; init; }

    public string? ManagementScope { get; init; }

    /// <summary>
    /// Explicit HTTP(S) proxy for the management channel (BOWER_MANAGEMENT_PROXY). Unset: the
    /// runtime's standard HTTPS_PROXY, HTTP_PROXY and NO_PROXY variables apply.
    /// </summary>
    public Uri? ManagementProxy { get; init; }

    /// <summary>Proxy user name (BOWER_MANAGEMENT_PROXY_USERNAME); the password comes from a file.</summary>
    public string? ManagementProxyUsername { get; init; }

    /// <summary>File holding the proxy password (BOWER_MANAGEMENT_PROXY_PASSWORD_FILE). Never logged.</summary>
    public string? ManagementProxyPasswordFile { get; init; }

    /// <summary>
    /// PEM bundle of extra roots trusted for the management channel (BOWER_MANAGEMENT_CA_BUNDLE),
    /// for example a TLS-inspection proxy CA. Merged with the system roots; verification stays on.
    /// </summary>
    public string? ManagementCaBundle { get; init; }

    /// <summary>PEM public keys trusted to sign management commands (BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS).</summary>
    public IReadOnlyList<string> ManagementCommandTrustedKeyFiles { get; init; } = [];

    /// <summary>
    /// How the collector authenticates to management (BOWER_MANAGEMENT_AUTH): <c>entra</c>
    /// (default, a machine token for BOWER_MANAGEMENT_SCOPE) or <c>enrolment</c> (a one-time
    /// token exchanged for a key-bound credential, for hosts without an Azure identity).
    /// </summary>
    public string ManagementAuthentication { get; init; } = ManagementAuthenticationModes.Entra;

    /// <summary>
    /// File holding a one-time enrolment token (BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE). Read
    /// only to enrol; the token is never stored, logged or reported. A new token in the file
    /// re-enrols the collector, which returns it to Pending.
    /// </summary>
    public string? ManagementEnrolmentTokenFile { get; init; }

    /// <summary>
    /// Relay this collector delivers to (BOWER_RELAY_URL, BOWER_OUTPUT=relay): an https URL
    /// with no path, credentials or query. The connection uses mutual TLS.
    /// </summary>
    public Uri? RelayUrl { get; init; }

    /// <summary>PEM client certificate presented to the relay (BOWER_RELAY_CLIENT_CERTIFICATE_FILE).</summary>
    public string? RelayClientCertificateFile { get; init; }

    /// <summary>PEM private key of the client certificate (BOWER_RELAY_CLIENT_KEY_FILE). Never logged.</summary>
    public string? RelayClientKeyFile { get; init; }

    /// <summary>PEM roots trusted for the relay's server certificate (BOWER_RELAY_CA_BUNDLE), merged with the system roots.</summary>
    public string? RelayCaBundle { get; init; }

    /// <summary>
    /// BOWER_MANAGEMENT_VIA_RELAY=true: management traffic goes through the relay's management
    /// tunnel. TLS to management stays end to end, so the relay sees only ciphertext.
    /// </summary>
    public bool ManagementViaRelay { get; init; }

    /// <summary>
    /// Relay role (BOWER_RELAY_LISTEN_URL): an https listener for downstream collectors,
    /// separate from BOWER_LISTEN_URL and always mutual TLS.
    /// </summary>
    public Uri? RelayListenUrl { get; init; }

    /// <summary>PEM server certificate of the relay listener (BOWER_RELAY_CERTIFICATE_FILE).</summary>
    public string? RelayCertificateFile { get; init; }

    /// <summary>PEM private key of the relay listener certificate (BOWER_RELAY_KEY_FILE). Never logged.</summary>
    public string? RelayKeyFile { get; init; }

    /// <summary>JSON file of downstream collector ids and pinned client certificates (BOWER_RELAY_DOWNSTREAMS_FILE).</summary>
    public string? RelayDownstreamsFile { get; init; }

    /// <summary>
    /// BOWER_RELAY_MANAGEMENT_TUNNEL=true: downstream collectors may open a byte tunnel to this
    /// relay's own BOWER_MANAGEMENT_ENDPOINT, and nowhere else.
    /// </summary>
    public bool RelayManagementTunnel { get; init; }

    public bool IsRelay => RelayListenUrl is not null;

    /// <summary>
    /// Deletes the enrolment token file once management has consumed or refused the token
    /// (BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE). The native installers set it so a
    /// pre-seeded token never stays on disk. Not part of the configuration hash.
    /// </summary>
    public bool ManagementEnrolmentTokenRemoveAfterUse { get; init; }

    public bool UsesEnrolment =>
        string.Equals(ManagementAuthentication, ManagementAuthenticationModes.Enrolment, StringComparison.Ordinal);

    /// <summary>Key-bound credential directory: <c>management-credential</c> next to the queue database.</summary>
    public string ManagementCredentialDirectory =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(QueuePath)) ?? ".", "management-credential");

    /// <summary>Durable command ledger directory: <c>management-commands</c> next to the queue database.</summary>
    public string ManagementCommandDirectory =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(QueuePath)) ?? ".", "management-commands");

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
            ProducerScopesFile = Blank(read("BOWER_PRODUCER_SCOPES_FILE")),
            SingleTrustDomain = string.Equals(read("BOWER_SINGLE_TRUST_DOMAIN"), "true", StringComparison.OrdinalIgnoreCase),
            Packs = SplitList(read("BOWER_PACKS")),
            PackTrustedKeyFiles = SplitList(read("BOWER_PACK_TRUSTED_KEYS")),
            PrivacyProfilePath = Blank(read("BOWER_PRIVACY_PROFILE")),
            PrivacyProfileSource = Blank(read("BOWER_PRIVACY_PROFILE_SOURCE"))?.Trim().ToLowerInvariant()
                ?? PrivacyProfileSources.Local,
            ManagedPrivacyTrustedKeyFiles = SplitList(read("BOWER_MANAGED_PRIVACY_TRUSTED_KEYS")),
            ManagedPrivacyDirectory = Blank(read("BOWER_MANAGED_PRIVACY_DIRECTORY")),
            ManagedPrivacyAllowDefault = string.Equals(
                read("BOWER_MANAGED_PRIVACY_ALLOW_DEFAULT"),
                "true",
                StringComparison.OrdinalIgnoreCase),
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
            ManagementScope = read("BOWER_MANAGEMENT_SCOPE"),
            ManagementProxy = ReadProxy(Blank(read("BOWER_MANAGEMENT_PROXY"))),
            ManagementProxyUsername = Blank(read("BOWER_MANAGEMENT_PROXY_USERNAME")),
            ManagementProxyPasswordFile = Blank(read("BOWER_MANAGEMENT_PROXY_PASSWORD_FILE")),
            ManagementCaBundle = Blank(read("BOWER_MANAGEMENT_CA_BUNDLE")),
            ManagementCommandTrustedKeyFiles = SplitList(read("BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS")),
            ManagementAuthentication = Blank(read("BOWER_MANAGEMENT_AUTH"))?.Trim().ToLowerInvariant()
                ?? ManagementAuthenticationModes.Entra,
            ManagementEnrolmentTokenFile = Blank(read("BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE")),
            RelayUrl = ReadUrl(Blank(read("BOWER_RELAY_URL")), "BOWER_RELAY_URL"),
            RelayClientCertificateFile = Blank(read("BOWER_RELAY_CLIENT_CERTIFICATE_FILE")),
            RelayClientKeyFile = Blank(read("BOWER_RELAY_CLIENT_KEY_FILE")),
            RelayCaBundle = Blank(read("BOWER_RELAY_CA_BUNDLE")),
            ManagementViaRelay = ReadBoolean(read, "BOWER_MANAGEMENT_VIA_RELAY"),
            RelayListenUrl = ReadUrl(Blank(read("BOWER_RELAY_LISTEN_URL")), "BOWER_RELAY_LISTEN_URL"),
            RelayCertificateFile = Blank(read("BOWER_RELAY_CERTIFICATE_FILE")),
            RelayKeyFile = Blank(read("BOWER_RELAY_KEY_FILE")),
            RelayDownstreamsFile = Blank(read("BOWER_RELAY_DOWNSTREAMS_FILE")),
            RelayManagementTunnel = ReadBoolean(read, "BOWER_RELAY_MANAGEMENT_TUNNEL"),
            ManagementEnrolmentTokenRemoveAfterUse = string.Equals(
                read("BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE"),
                "true",
                StringComparison.OrdinalIgnoreCase),
            SourceExpectationsPath = Blank(read("BOWER_SOURCE_EXPECTATIONS")),
            ArchivePath = Blank(read("BOWER_ARCHIVE_PATH")),
            SyslogConfigPath = Blank(read("BOWER_SYSLOG_CONFIG")),
            WindowsEventLogConfigPath = Blank(read("BOWER_WINDOWS_EVENTLOG_CONFIG"))
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

        if (SingleTrustDomain && ProducerScopesFile is not null)
        {
            throw new InvalidOperationException("Producer scopes and single trust domain mode are mutually exclusive.");
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

        if (OutputType is not ("none" or "ama-spool" or "azure-logs-ingestion" or "relay"))
        {
            throw new InvalidOperationException($"Unsupported BOWER_OUTPUT value: {OutputType}");
        }

        if (OutputType == "azure-logs-ingestion"
            && (DceEndpoint is null || string.IsNullOrWhiteSpace(DcrImmutableId)))
        {
            throw new InvalidOperationException(
                "BOWER_DCE_ENDPOINT and BOWER_DCR_ID are required for azure-logs-ingestion.");
        }

        if (ManagementAuthentication is not (ManagementAuthenticationModes.Entra or ManagementAuthenticationModes.Enrolment))
        {
            throw new InvalidOperationException("BOWER_MANAGEMENT_AUTH must be entra or enrolment.");
        }

        if (UsesEnrolment && ManagementEndpoint is null)
        {
            throw new InvalidOperationException("BOWER_MANAGEMENT_AUTH=enrolment requires BOWER_MANAGEMENT_ENDPOINT.");
        }

        if (ManagementEnrolmentTokenFile is not null && !UsesEnrolment)
        {
            throw new InvalidOperationException(
                "BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE requires BOWER_MANAGEMENT_AUTH=enrolment.");
        }

        if (ManagementEnrolmentTokenRemoveAfterUse && ManagementEnrolmentTokenFile is null)
        {
            throw new InvalidOperationException(
                "BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE requires BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE.");
        }

        if (ManagementEndpoint is not null)
        {
            if (!UsesEnrolment && string.IsNullOrWhiteSpace(ManagementScope))
            {
                throw new InvalidOperationException(
                    "BOWER_MANAGEMENT_SCOPE is required when BOWER_MANAGEMENT_ENDPOINT is set.");
            }

            // The heartbeat carries a bearer token or assertion; never send it in cleartext.
            if (ManagementEndpoint.Scheme != Uri.UriSchemeHttps && !IsLoopback(ManagementEndpoint.Host))
            {
                throw new InvalidOperationException(
                    "BOWER_MANAGEMENT_ENDPOINT must use HTTPS unless it targets loopback.");
            }
        }

        ValidateManagementConnection();
        ValidatePrivacyProfileSource();
        ValidateRelay();
    }

    /// <summary>
    /// Downstream (BOWER_OUTPUT=relay) and relay (BOWER_RELAY_LISTEN_URL) settings. One hop
    /// only: a relay never delivers to another relay.
    /// </summary>
    private void ValidateRelay()
    {
        bool relayOutput = string.Equals(OutputType, "relay", StringComparison.Ordinal);
        bool clientSettings = RelayUrl is not null || RelayClientCertificateFile is not null
            || RelayClientKeyFile is not null || RelayCaBundle is not null;
        if (clientSettings && !relayOutput)
        {
            throw new InvalidOperationException(
                "BOWER_RELAY_URL, BOWER_RELAY_CLIENT_CERTIFICATE_FILE, BOWER_RELAY_CLIENT_KEY_FILE and " +
                "BOWER_RELAY_CA_BUNDLE require BOWER_OUTPUT=relay.");
        }

        if (relayOutput)
        {
            if (RelayUrl is null || !IsValidHttpsOrigin(RelayUrl))
            {
                throw new InvalidOperationException(
                    "BOWER_OUTPUT=relay requires BOWER_RELAY_URL: an absolute https:// URL with a host and no " +
                    "credentials, path or query.");
            }

            if (RelayClientCertificateFile is null || RelayClientKeyFile is null)
            {
                throw new InvalidOperationException(
                    "BOWER_OUTPUT=relay requires BOWER_RELAY_CLIENT_CERTIFICATE_FILE and BOWER_RELAY_CLIENT_KEY_FILE: " +
                    "the relay accepts only pinned client certificates.");
            }
        }

        if (ManagementViaRelay)
        {
            if (!relayOutput || ManagementEndpoint is null)
            {
                throw new InvalidOperationException(
                    "BOWER_MANAGEMENT_VIA_RELAY requires BOWER_OUTPUT=relay and BOWER_MANAGEMENT_ENDPOINT.");
            }

            // An Entra token needs a route to Entra ID, which a collector behind a relay lacks.
            if (!UsesEnrolment)
            {
                throw new InvalidOperationException("BOWER_MANAGEMENT_VIA_RELAY requires BOWER_MANAGEMENT_AUTH=enrolment.");
            }

            if (ManagementProxy is not null)
            {
                throw new InvalidOperationException("BOWER_MANAGEMENT_VIA_RELAY cannot be combined with BOWER_MANAGEMENT_PROXY.");
            }
        }

        bool serverSettings = RelayCertificateFile is not null || RelayKeyFile is not null
            || RelayDownstreamsFile is not null || RelayManagementTunnel;
        if (serverSettings && RelayListenUrl is null)
        {
            throw new InvalidOperationException(
                "BOWER_RELAY_CERTIFICATE_FILE, BOWER_RELAY_KEY_FILE, BOWER_RELAY_DOWNSTREAMS_FILE and " +
                "BOWER_RELAY_MANAGEMENT_TUNNEL require BOWER_RELAY_LISTEN_URL.");
        }

        if (RelayListenUrl is null)
        {
            return;
        }

        if (!IsValidHttpsOrigin(RelayListenUrl) || RelayListenUrl.IsDefaultPort)
        {
            throw new InvalidOperationException(
                "BOWER_RELAY_LISTEN_URL must be an absolute https:// URL with an explicit port and no " +
                "credentials, path or query.");
        }

        if (RelayCertificateFile is null || RelayKeyFile is null || RelayDownstreamsFile is null)
        {
            throw new InvalidOperationException(
                "BOWER_RELAY_LISTEN_URL requires BOWER_RELAY_CERTIFICATE_FILE, BOWER_RELAY_KEY_FILE and " +
                "BOWER_RELAY_DOWNSTREAMS_FILE.");
        }

        if (relayOutput)
        {
            throw new InvalidOperationException(
                "A relay cannot use BOWER_OUTPUT=relay: relays deliver to the destination, one hop only.");
        }

        if (RelayManagementTunnel && ManagementEndpoint is null)
        {
            throw new InvalidOperationException("BOWER_RELAY_MANAGEMENT_TUNNEL requires BOWER_MANAGEMENT_ENDPOINT.");
        }

        // The tunnel opens a direct TCP connection to the management host.
        if (RelayManagementTunnel && ManagementProxy is not null)
        {
            throw new InvalidOperationException(
                "BOWER_RELAY_MANAGEMENT_TUNNEL connects directly and cannot be combined with BOWER_MANAGEMENT_PROXY.");
        }
    }

    internal static bool IsValidHttpsOrigin(Uri url) =>
        url.IsAbsoluteUri
        && url.Scheme == Uri.UriSchemeHttps
        && !string.IsNullOrEmpty(url.Host)
        && string.IsNullOrEmpty(url.UserInfo)
        && url.AbsolutePath == "/"
        && string.IsNullOrEmpty(url.Query)
        && string.IsNullOrEmpty(url.Fragment);

    /// <summary>Proxy, CA bundle and command keys apply to the management channel only.</summary>
    private void ValidateManagementConnection()
    {
        bool connectionSettings = ManagementProxy is not null || ManagementProxyUsername is not null
            || ManagementProxyPasswordFile is not null || ManagementCaBundle is not null
            || ManagementCommandTrustedKeyFiles.Count > 0;
        if (connectionSettings && ManagementEndpoint is null)
        {
            throw new InvalidOperationException(
                "BOWER_MANAGEMENT_PROXY, BOWER_MANAGEMENT_CA_BUNDLE and BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS " +
                "require BOWER_MANAGEMENT_ENDPOINT.");
        }

        // Messages never echo the proxy URL: it may have been written with credentials.
        if (ManagementProxy is not null && !IsValidProxy(ManagementProxy))
        {
            throw new InvalidOperationException(
                "BOWER_MANAGEMENT_PROXY must be an absolute http:// or https:// URL with a host and no " +
                "credentials, path or query. Put credentials in BOWER_MANAGEMENT_PROXY_USERNAME and " +
                "BOWER_MANAGEMENT_PROXY_PASSWORD_FILE.");
        }

        if ((ManagementProxyUsername is null) != (ManagementProxyPasswordFile is null))
        {
            throw new InvalidOperationException(
                "BOWER_MANAGEMENT_PROXY_USERNAME and BOWER_MANAGEMENT_PROXY_PASSWORD_FILE must be set together.");
        }

        if (ManagementProxyUsername is not null && ManagementProxy is null)
        {
            throw new InvalidOperationException("BOWER_MANAGEMENT_PROXY_USERNAME requires BOWER_MANAGEMENT_PROXY.");
        }
    }

    internal static bool IsValidProxy(Uri proxy) =>
        proxy.IsAbsoluteUri
        && proxy.Scheme is "http" or "https"
        && !string.IsNullOrEmpty(proxy.Host)
        && string.IsNullOrEmpty(proxy.UserInfo)
        && proxy.AbsolutePath == "/"
        && string.IsNullOrEmpty(proxy.Query)
        && string.IsNullOrEmpty(proxy.Fragment);

    private void ValidatePrivacyProfileSource()
    {
        if (PrivacyProfileSource is not (PrivacyProfileSources.Local or PrivacyProfileSources.Management))
        {
            throw new InvalidOperationException("BOWER_PRIVACY_PROFILE_SOURCE must be local or management.");
        }

        if (!UsesManagedPrivacyProfile)
        {
            return;
        }

        if (ManagementEndpoint is null)
        {
            throw new InvalidOperationException(
                "BOWER_PRIVACY_PROFILE_SOURCE=management requires BOWER_MANAGEMENT_ENDPOINT and BOWER_MANAGEMENT_SCOPE.");
        }

        if (ManagedPrivacyTrustedKeyFiles.Count == 0)
        {
            throw new InvalidOperationException(
                "BOWER_PRIVACY_PROFILE_SOURCE=management requires BOWER_MANAGED_PRIVACY_TRUSTED_KEYS; " +
                "managed privacy profiles are never loaded unverified.");
        }

        if (PrivacyProfilePath is not null)
        {
            throw new InvalidOperationException(
                "BOWER_PRIVACY_PROFILE cannot be combined with BOWER_PRIVACY_PROFILE_SOURCE=management.");
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
            PrivacyHmacKeyId,
            SingleTrustDomain.ToString(),
            ProducerScopesFile ?? string.Empty);
        // Appended only when set so existing configuration hashes are unchanged.
        if (SourceExpectationsPath is not null)
        {
            material += '\u001f' + "source-expectations:" + SourceExpectationsPath;
        }

        if (ArchivePath is not null)
        {
            material += '\u001f' + "archive:" + ArchivePath;
        }

        if (SyslogConfigPath is not null)
        {
            material += '\u001f' + "syslog:" + SyslogConfigPath;
        }

        if (WindowsEventLogConfigPath is not null)
        {
            material += '\u001f' + "windows-eventlog:" + WindowsEventLogConfigPath;
        }

        if (UsesManagedPrivacyProfile)
        {
            // Appended only in management mode so existing local configuration hashes are unchanged.
            material += '\u001f' + "privacy-source:" + PrivacyProfileSource
                + '\u001f' + "privacy-allow-default:" + ManagedPrivacyAllowDefault.ToString();
        }

        // Appended only when set so existing configuration hashes are unchanged. The proxy
        // contributes scheme, host and port only; credentials never enter the hash.
        if (ManagementProxy is not null)
        {
            material += '\u001f' + "management-proxy:" + ManagementProxy.Scheme + "://" + ManagementProxy.Host
                + ":" + ManagementProxy.Port.ToString(CultureInfo.InvariantCulture)
                + '\u001f' + "management-proxy-auth:" + (ManagementProxyUsername is not null).ToString();
        }

        if (ManagementCaBundle is not null)
        {
            material += '\u001f' + "management-ca:" + ManagementCaBundle;
        }

        if (ManagementCommandTrustedKeyFiles.Count > 0)
        {
            material += '\u001f' + "management-commands:True";
        }

        if (UsesEnrolment)
        {
            material += '\u001f' + "management-auth:enrolment";
        }

        // Relay settings, appended only when set. Hosts, ports and paths only, never file contents.
        if (RelayUrl is not null)
        {
            material += '\u001f' + "relay-url:" + RelayUrl.Host + ":" + RelayUrl.Port.ToString(CultureInfo.InvariantCulture)
                + '\u001f' + "relay-ca:" + (RelayCaBundle ?? string.Empty);
        }

        if (ManagementViaRelay)
        {
            material += '\u001f' + "management-via-relay:True";
        }

        if (RelayListenUrl is not null)
        {
            material += '\u001f' + "relay-listen:" + RelayListenUrl.Host + ":" + RelayListenUrl.Port.ToString(CultureInfo.InvariantCulture)
                + '\u001f' + "relay-downstreams:" + RelayDownstreamsFile
                + '\u001f' + "relay-tunnel:" + RelayManagementTunnel.ToString();
        }

        return "sha256:" + Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(material)));
    }

    /// <summary>Policy, pack and privacy profile sources for <see cref="PolicyBundle.Load"/>.</summary>
    /// <param name="observeManaged">
    /// Management mode: receives the verified cached document (or null when there is none),
    /// read once with the bundle so the ingest gate and the active profile always agree.
    /// </param>
    public PolicyBundleSources PolicySources(Action<VerifiedManagedPrivacyProfile?>? observeManaged = null) => new()
    {
        PolicyDirectory = PolicyDirectory,
        Packs = Packs,
        PackTrustedKeyFiles = PackTrustedKeyFiles,
        PrivacyProfilePath = PrivacyProfilePath,
        PrivacyHmacKeyFile = PrivacyHmacKeyFile,
        PrivacyHmacKeyId = PrivacyHmacKeyId,
        PrivacyProfileSource = PrivacyProfileSource,
        // A cached explicit clear resolves to the built-in default (null profile).
        ManagedPrivacyProfile = UsesManagedPrivacyProfile ? key => LoadManagedProfile(key, observeManaged) : null
    };

    private LoadedPrivacyProfile? LoadManagedProfile(byte[]? key, Action<VerifiedManagedPrivacyProfile?>? observe)
    {
        VerifiedManagedPrivacyProfile? cached = ManagedPrivacyProfileCache.LoadVerified(this, key);
        observe?.Invoke(cached);
        return cached?.Profile;
    }

    private static Uri? ReadProxy(string? value)
    {
        if (value is null)
        {
            return null;
        }

        // The value is never echoed: a proxy URL may carry credentials.
        return Uri.TryCreate(value.Trim(), UriKind.Absolute, out Uri? proxy)
            ? proxy
            : throw new InvalidOperationException("BOWER_MANAGEMENT_PROXY must be an absolute http:// or https:// URL.");
    }

    private static Uri? ReadUrl(string? value, string name)
    {
        if (value is null)
        {
            return null;
        }

        return Uri.TryCreate(value.Trim(), UriKind.Absolute, out Uri? url)
            ? url
            : throw new InvalidOperationException($"{name} must be an absolute https:// URL.");
    }

    private static bool ReadBoolean(Func<string, string?> read, string name) =>
        Blank(read(name))?.Trim().ToLowerInvariant() switch
        {
            null or "false" => false,
            "true" => true,
            _ => throw new InvalidOperationException($"{name} must be true or false.")
        };

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

/// <summary>Values of BOWER_PRIVACY_PROFILE_SOURCE.</summary>
/// <summary>BOWER_MANAGEMENT_AUTH values.</summary>
public static class ManagementAuthenticationModes
{
    public const string Entra = "entra";
    public const string Enrolment = "enrolment";
}

public static class PrivacyProfileSources
{
    public const string Local = "local";
    public const string Management = "management";
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
