using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Identity;
using Bower.Evidence;

namespace Bower.Management.Api;

/// <summary>
/// Server-side canary settings (<c>Bower:Setup:Canary:*</c>). The ingest token and signing key
/// stay in files on the management host; they are read per run and never returned or logged.
/// </summary>
public sealed record SetupCanaryOptions
{
    public const string Section = "Bower:Setup:Canary";
    public const int MaximumTokenBytes = 4096;
    public const int MaximumTimeoutMinutes = 60;

    public Uri? CollectorUrl { get; init; }

    public string? IngestTokenFile { get; init; }

    /// <summary>Read-only verifier identity mode. Null runs every canary in simulated mode.</summary>
    public string? Credential { get; init; }

    public string? ClientId { get; init; }

    public string? SigningKeyFile { get; init; }

    public int TimeoutMinutes { get; init; } = 15;

    public bool Configured => CollectorUrl is not null && !string.IsNullOrWhiteSpace(IngestTokenFile);

    public bool VerifierConfigured => !string.IsNullOrWhiteSpace(Credential);

    /// <summary>Reads and validates the section; invalid values fail start-up rather than a run.</summary>
    public static SetupCanaryOptions FromConfiguration(IConfiguration configuration)
    {
        IConfigurationSection section = configuration.GetSection(Section);
        Uri? collector = null;
        if (section["CollectorUrl"] is { Length: > 0 } url)
        {
            if (!Uri.TryCreate(url.EndsWith('/') ? url : url + "/", UriKind.Absolute, out collector)
                || collector.Scheme is not ("http" or "https"))
            {
                throw new InvalidOperationException($"{Section}:CollectorUrl must be an absolute http or https URL.");
            }
        }

        string? credential = Trimmed(section["Credential"]);
        if (credential is not null && credential is not ("managed-identity" or "workload-identity" or "environment" or "azure-cli"))
        {
            throw new InvalidOperationException(
                $"{Section}:Credential must be managed-identity, workload-identity, environment or azure-cli.");
        }

        int timeout = 15;
        if (section["TimeoutMinutes"] is { Length: > 0 } minutes
            && (!int.TryParse(minutes, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out timeout)
                || timeout is < 1 or > MaximumTimeoutMinutes))
        {
            throw new InvalidOperationException($"{Section}:TimeoutMinutes must be between 1 and {MaximumTimeoutMinutes}.");
        }

        return new SetupCanaryOptions
        {
            CollectorUrl = collector,
            IngestTokenFile = Trimmed(section["IngestTokenFile"]),
            Credential = credential,
            ClientId = Trimmed(section["ClientId"]),
            SigningKeyFile = Trimmed(section["SigningKeyFile"]),
            TimeoutMinutes = timeout
        };
    }

    private static string? Trimmed(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>Collector and read-only Azure clients for one canary run or rule check.</summary>
public sealed record SetupEvidenceClients(
    ICanarySender Sender,
    IParserProbeSender ParserSender,
    ILogAnalyticsQuery? Query,
    IArmReader? Arm);

public interface ISetupEvidenceClientFactory
{
    SetupEvidenceClients Create(SetupCanaryOptions options);
}

/// <summary>The same HTTP clients and verifier credential <c>bower evidence run</c> uses.</summary>
internal sealed class SetupEvidenceClientFactory : ISetupEvidenceClientFactory, IDisposable
{
    // Each collector, query and ARM request times out after 30 seconds, as in the CLI.
    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public SetupEvidenceClients Create(SetupCanaryOptions options)
    {
        HttpCanarySender sender = new(http);
        Azure.Core.TokenCredential? credential = options.VerifierConfigured
            ? VerifierCredential.Create(options.Credential, options.ClientId)
            : null;
        return new SetupEvidenceClients(
            sender,
            sender,
            credential is null ? null : new LogAnalyticsQueryClient(http, credential),
            credential is null ? null : new ArmReader(http, credential));
    }

    public void Dispose() => http.Dispose();
}

/// <summary>Fixed, plain-English text for each outcome. Raw Azure and framework detail stays server side.</summary>
public static class SetupOutcomes
{
    public const string CollectorUnreachable = "collector-unreachable";
    public const string VerifierCredentialUnavailable = "verifier-credential-unavailable";
    public const string CanaryTokenUnreadable = "canary-token-unreadable";
    public const string SigningKeyUnreadable = "signing-key-unreadable";
    public const string Interrupted = "interrupted";
    public const string CanaryError = "canary-error";
    public const string AcceptedNotChecked = "accepted-not-checked";

    private static readonly Dictionary<string, (string Message, string Fix)> Descriptions = new(StringComparer.Ordinal)
    {
        [ProbeOutcomes.Verified] = (
            "Verified: Bower queried Microsoft Sentinel and found the exact test event.",
            "Nothing to fix. Download the evidence bundle to keep a signed record."),
        [ProbeOutcomes.AcceptedNotVerified] = (
            "Simulated: the collector accepted the test event, but Bower did not query Sentinel, so this is not proof of delivery.",
            "Configure a read-only verifier identity (Bower:Setup:Canary:Credential) with Log Analytics Reader on the workspace, then run the test again."),
        [ProbeOutcomes.CollectorPermissionDenied] = (
            "The collector refused the test event's token or producer scope.",
            "Give the canary token its own producer ID and a scope for application BowerEvidence (or the probe pack), then run the test again."),
        [ProbeOutcomes.CollectorRejected] = (
            "The collector refused the test event (for example it is full, rate limited or rejected the event identity).",
            "Check the collector's health and queue on the Collectors page, then run the test again."),
        [ProbeOutcomes.CollectorStatusUnreadable] = (
            "Bower could not read the collector's status, so it does not know which pack and policy would be tested.",
            "Check that the canary token can read /v1/status on the collector, then run the test again."),
        [ProbeOutcomes.ParserInactive] = (
            "The chosen pack is not loaded on the collector, or its parser is not active.",
            "Install the signed pack on the collector, or choose the generic test in step 5."),
        [ProbeOutcomes.ParserNotSelected] = (
            "The pack parser no longer selects Bower's test record.",
            "Check the pack version installed on the collector, or choose the generic test in step 5."),
        [ProbeOutcomes.ParserRecordRejected] = (
            "The pack parser refused Bower's test record.",
            "Check the pack version installed on the collector, or choose the generic test in step 5."),
        [ProbeOutcomes.ParserWrongEvent] = (
            "The pack parser produced a different event than expected.",
            "Reinstall the signed pack on the collector, then run the test again."),
        [ProbeOutcomes.PolicyNotSelected] = (
            "The collector's policy or privacy rules did not accept the test event, so it was not sent on.",
            "Check that the collector runs Bower's default policies (including BWR-POL-EVIDENCE-CANARY), then run the test again."),
        [ProbeOutcomes.ProbeNotQueued] = (
            "The collector accepted the test event but did not queue it (duplicate or suppressed), so it can never arrive.",
            "Run the test again. If it repeats, check suppression settings for the probe pack."),
        [ProbeOutcomes.DestinationPermissionDenied] = (
            "The verifier identity is not allowed to query the workspace.",
            "Give the verifier identity Log Analytics Reader on the workspace, then run the test again."),
        [ProbeOutcomes.DestinationRowMissing] = (
            "The collector accepted the test event, but it was not found in Sentinel before the time limit.",
            "Check the collector's delivery status, the DCR and table (step 3), and the workspace ID, then run the test again."),
        [ProbeOutcomes.DestinationWrongEvent] = (
            "Sentinel returned a row, but it is not the exact test event.",
            "Check the table and data collection rule transformation in step 3, then run the test again."),
        [ProbeOutcomes.ConfigurationMismatch] = (
            "The test event arrived, but under a different policy than the collector reported.",
            "Point the canary at a single collector instance rather than a load balancer, then run the test again."),
        [ProbeOutcomes.DestinationTimeout] = (
            "Sentinel did not answer Bower's queries in time.",
            "Check network access from the management host to api.loganalytics.azure.com, then run the test again."),
        [ProbeOutcomes.DestinationQueryFailed] = (
            "Bower's queries to Sentinel failed.",
            "Check the workspace ID in step 3 and network access to api.loganalytics.azure.com, then run the test again."),
        [AcceptedNotChecked] = (
            "Accepted by the collector; Sentinel could not be checked (verifier sign-in failed).",
            "Check Bower:Setup:Canary:Credential (and ClientId for a user-assigned identity) on the management host, then run the test again."),
        [CollectorUnreachable] = (
            "Bower could not reach the collector.",
            "Check Bower:Setup:Canary:CollectorUrl and that the collector is running and reachable from the management host."),
        [VerifierCredentialUnavailable] = (
            "Bower could not sign in to Azure with its read-only verifier identity.",
            "Check Bower:Setup:Canary:Credential (and ClientId for a user-assigned identity) on the management host."),
        [CanaryTokenUnreadable] = (
            "Bower could not read the canary ingest token file.",
            "Check Bower:Setup:Canary:IngestTokenFile points to a readable file of at most 4 KiB."),
        [SigningKeyUnreadable] = (
            "Bower could not read the evidence signing key, so no test event was sent.",
            "Check Bower:Setup:Canary:SigningKeyFile points to a readable ECDSA P-256 private key, or remove the setting."),
        [Interrupted] = (
            "The management service restarted before the test finished.",
            "Run the test again.")
    };

    public static (string Message, string Fix) Describe(string? outcome) =>
        outcome is not null && Descriptions.TryGetValue(outcome, out (string Message, string Fix) text)
            ? text
            : ("The test did not complete.", "Run the test again. If it repeats, check the management service log.");

    /// <summary>
    /// The outcome of a generic canary bundle, in the parser probe's vocabulary. Only a
    /// returned destination row is <c>verified</c>.
    /// </summary>
    public static string Classify(EvidenceBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        if (bundle.Probe is { } probe)
        {
            return probe.Outcome;
        }

        int status = bundle.Canary.CollectorStatus;
        if (status is 401 or 403)
        {
            return ProbeOutcomes.CollectorPermissionDenied;
        }

        if (status is not (200 or 202))
        {
            return ProbeOutcomes.CollectorRejected;
        }

        if (bundle.Mode == EvidenceModes.Simulated)
        {
            return ProbeOutcomes.AcceptedNotVerified;
        }

        if (bundle.Mode == EvidenceModes.Verified && bundle.Arrival.Found)
        {
            return ProbeOutcomes.Verified;
        }

        string? error = bundle.Arrival.QueryError;
        return error is null or "not-found-before-timeout" ? ProbeOutcomes.DestinationRowMissing
            : ProbeOutcomes.IsPermissionError(error) ? ProbeOutcomes.DestinationPermissionDenied
            : ProbeOutcomes.IsTimeoutError(error) ? ProbeOutcomes.DestinationTimeout
            : ProbeOutcomes.DestinationQueryFailed;
    }

    /// <summary>Whether the collector took the event for delivery. Acceptance is never delivery proof.</summary>
    public static bool Accepted(EvidenceBundle bundle, string outcome) =>
        bundle.Canary.CollectorStatus is 200 or 202
        && outcome is not (ProbeOutcomes.ParserWrongEvent or ProbeOutcomes.ProbeNotQueued or ProbeOutcomes.PolicyNotSelected);
}

/// <summary>
/// Runs onboarding canaries in the background through the unchanged <see cref="EvidenceRunner"/>,
/// one at a time, and records metadata-only results. Started only by an administrator request.
/// </summary>
internal sealed partial class SetupCanaryService(
    ManagementStore store,
    ISetupEvidenceClientFactory factory,
    SetupCanaryOptions options,
    TimeProvider clock,
    IHostApplicationLifetime lifetime,
    ILogger<SetupCanaryService> logger)
{
    public void Launch(SetupCanaryRun run, SetupDestination destination) =>
        _ = Task.Run(() => ExecuteAsync(run, destination));

    private async Task ExecuteAsync(SetupCanaryRun run, SetupDestination destination)
    {
        CancellationToken stopping = lifetime.ApplicationStopping;
        SetupCanaryResult result;
        try
        {
            result = await RunAsync(run, destination, stopping);
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
            result = new SetupCanaryResult(null, SetupOutcomes.Interrupted, false, null, null, false, null);
        }
        catch (Exception exception)
        {
            // Type only: messages can carry host names, paths or Azure response text.
            LogRunFailed(logger, run.Id, exception.GetType().Name);
            result = new SetupCanaryResult(EvidenceModes.Failed, OutcomeFor(exception), false, null, null, false, null);
        }

        try
        {
            await store.CompleteSetupCanaryRunAsync(run.Id, result, clock.GetUtcNow(), CancellationToken.None);
        }
        catch (Exception exception)
        {
            LogRunFailed(logger, run.Id, exception.GetType().Name);
        }
    }

    private async Task<SetupCanaryResult> RunAsync(SetupCanaryRun run, SetupDestination destination, CancellationToken cancellationToken)
    {
        string token;
        try
        {
            token = await ReadBoundedAsync(options.IngestTokenFile!, SetupCanaryOptions.MaximumTokenBytes, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new SetupCanaryResult(EvidenceModes.Failed, SetupOutcomes.CanaryTokenUnreadable, false, null, null, false, null);
        }

        string? signingKey = null;
        if (options.SigningKeyFile is not null)
        {
            try
            {
                signingKey = await ReadBoundedAsync(options.SigningKeyFile, 64 * 1024, cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                return new SetupCanaryResult(EvidenceModes.Failed, SetupOutcomes.SigningKeyUnreadable, false, null, null, false, null);
            }
        }

        SetupEvidenceClients clients = factory.Create(options);
        GuardedClients guarded = new(clients, cancellationToken);
        EvidenceRunner runner = new(guarded, clients.Query is null ? null : guarded, clients.Arm is null ? null : guarded, clock, guarded);
        EvidenceBundle bundle;
        try
        {
            bundle = await runner.RunAsync(
                new EvidenceOptions
                {
                    CollectorUrl = options.CollectorUrl!,
                    IngestToken = token,
                    WorkspaceId = destination.WorkspaceId,
                    WorkspaceResourceId = destination.WorkspaceResourceId,
                    Table = destination.Table,
                    Timeout = TimeSpan.FromMinutes(options.TimeoutMinutes),
                    ProbeProfile = run.Profile
                },
                cancellationToken);
        }
        catch (SetupCanaryFailure failure)
        {
            // A verifier failure after acceptance: the event exists but Sentinel was never queried.
            string failed = failure.Outcome == SetupOutcomes.VerifierCredentialUnavailable && guarded.Accepted
                ? SetupOutcomes.AcceptedNotChecked
                : failure.Outcome;
            return new SetupCanaryResult(
                EvidenceModes.Failed, failed, guarded.Accepted, guarded.Accepted ? guarded.EventId : null, null, false, null);
        }
        SignedEvidence signed;
        try
        {
            signed = EvidenceRunner.Sign(bundle, signingKey);
        }
        catch (Exception exception) when (exception is ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            return new SetupCanaryResult(EvidenceModes.Failed, SetupOutcomes.SigningKeyUnreadable, false, null, null, false, null);
        }

        string outcome = SetupOutcomes.Classify(bundle);
        return new SetupCanaryResult(
            bundle.Mode,
            outcome,
            SetupOutcomes.Accepted(bundle, outcome),
            bundle.Canary.EventId,
            bundle.Arrival.LatencySeconds,
            signed.Signature is not null,
            JsonSerializer.Serialize(signed, SetupEvidenceJsonContext.Default.SignedEvidence));
    }

    private static string OutcomeFor(Exception exception) =>
        exception switch
        {
            SetupCanaryFailure failure => failure.Outcome,
            AuthenticationFailedException => SetupOutcomes.VerifierCredentialUnavailable,
            _ => SetupOutcomes.CanaryError
        };

    private static async Task<string> ReadBoundedAsync(string path, int maximumBytes, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maximumBytes)
        {
            throw new InvalidDataException("File is larger than allowed.");
        }

        byte[] buffer = new byte[maximumBytes + 1];
        int read = 0;
        int count;
        while ((count = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken)) > 0)
        {
            read += count;
            if (read > maximumBytes)
            {
                throw new InvalidDataException("File is larger than allowed.");
            }
        }

        string text = Encoding.UTF8.GetString(buffer, 0, read).Trim();
        return text.Length == 0 ? throw new InvalidDataException("File is empty.") : text;
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Setup canary run {RunId} failed with {ExceptionType}.")]
    private static partial void LogRunFailed(ILogger logger, string runId, string exceptionType);

    /// <summary>
    /// Tags transport failures by phase so the console can say which side failed. Query transport
    /// errors become the evidence query codes the parser probe already uses.
    /// </summary>
    private sealed class GuardedClients(SetupEvidenceClients inner, CancellationToken stopping)
        : ICanarySender, IParserProbeSender, ILogAnalyticsQuery, IArmReader
    {
        /// <summary>Whether the last event post (canary or parser record) was accepted with 200 or 202.</summary>
        public bool Accepted { get; private set; }

        /// <summary>The event id Bower sent, kept so a later verifier failure still names the event.</summary>
        public string? EventId { get; private set; }

        public async Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken)
        {
            EventId = SentId(json, "eventId");
            (int status, JsonObject? body) = await CollectorAsync(() => inner.Sender.SendAsync(collector, token, json, cancellationToken));
            Accepted = status is 200 or 202;
            return (status, body);
        }

        public Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken) =>
            CollectorAsync(() => inner.ParserSender.GetStatusAsync(collector, token, cancellationToken));

        public async Task<(int Status, JsonObject? Body)> SendRecordAsync(
            Uri collector, string? token, string packId, int parserIndex, string json, CancellationToken cancellationToken)
        {
            EventId = SentId(json, "id");
            (int status, JsonObject? body) = await CollectorAsync(
                () => inner.ParserSender.SendRecordAsync(collector, token, packId, parserIndex, json, cancellationToken));
            // Accepted as the same event and queued: duplicate, suppressed or unqueued records never arrive.
            Accepted = EventId is not null && ProbeOutcomes.Classify(status, body, EventId) is null;
            return (status, body);
        }

        private static string? SentId(string json, string property) =>
            JsonNode.Parse(json)?[property] is JsonValue value && value.TryGetValue(out string? text) ? text : null;

        public async Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            try
            {
                return await inner.Query!.QueryAsync(workspaceId, kql, timespan, cancellationToken);
            }
            catch (AuthenticationFailedException)
            {
                throw new SetupCanaryFailure(SetupOutcomes.VerifierCredentialUnavailable);
            }
            catch (Exception exception) when (exception is TaskCanceledException or TimeoutException && !stopping.IsCancellationRequested)
            {
                return new QueryRows([], ProbeOutcomes.QueryTimeoutCode);
            }
            catch (HttpRequestException)
            {
                return new QueryRows([], ProbeOutcomes.QueryTransportCode);
            }
        }

        public async Task<JsonObject?> GetAsync(string resourceId, string apiVersion, CancellationToken cancellationToken)
        {
            try
            {
                return await inner.Arm!.GetAsync(resourceId, apiVersion, cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !stopping.IsCancellationRequested)
            {
                // Retention and region are supporting detail; their absence never changes the outcome.
                return null;
            }
        }

        private async Task<(int Status, JsonObject? Body)> CollectorAsync(Func<Task<(int Status, JsonObject? Body)>> call)
        {
            try
            {
                return await call();
            }
            catch (Exception exception) when (
                exception is HttpRequestException or TimeoutException
                || (exception is TaskCanceledException && !stopping.IsCancellationRequested))
            {
                throw new SetupCanaryFailure(SetupOutcomes.CollectorUnreachable);
            }
        }
    }
}

/// <summary>A run failure with a fixed outcome code and no exception detail.</summary>
internal sealed class SetupCanaryFailure(string outcome) : Exception(outcome)
{
    public string Outcome { get; } = outcome;
}

/// <summary>What a finished run stores: metadata and the signed, metadata-only bundle.</summary>
public sealed record SetupCanaryResult(
    string? Mode,
    string Outcome,
    bool CollectorAccepted,
    string? EventId,
    double? LatencySeconds,
    bool HasSignature,
    string? BundleJson);
