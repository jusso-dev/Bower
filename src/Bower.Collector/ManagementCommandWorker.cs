using System.Text.Json;
using System.Threading.Channels;
using Bower.Collector.Jobs;
using Bower.Contracts;
using Bower.Core;
using Bower.Jobs;
using Bower.Persistence;

namespace Bower.Collector;

/// <summary>Hands admitted commands from the heartbeat job to the hosted command worker.</summary>
public sealed class ManagementCommandInbox
{
    public const int Capacity = 16;

    private readonly Channel<VerifiedManagementCommand> channel =
        Channel.CreateBounded<VerifiedManagementCommand>(new BoundedChannelOptions(Capacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait
        });

    public bool TryEnqueue(VerifiedManagementCommand command) => channel.Writer.TryWrite(command);

    public IAsyncEnumerable<VerifiedManagementCommand> ReadAllAsync(CancellationToken cancellationToken) =>
        channel.Reader.ReadAllAsync(cancellationToken);
}

/// <summary>
/// Reads the commands in a heartbeat v2 response. Every command is verified (signature,
/// collector binding, closed set, validity window), checked against what this collector
/// supports, admitted to the durable ledger and only then queued for the hosted worker. The
/// heartbeat job never executes a command itself. Logs are counts only.
/// </summary>
public sealed partial class ManagementCommandProcessor(
    CollectorSettings settings,
    ManagementCommandLedger ledger,
    ManagementCommandInbox queue,
    TimeProvider clock,
    ILogger<ManagementCommandProcessor> logger)
{
    public const int MaximumResponseBytes = 64 * 1024;
    public const int MaximumCommandsPerResponse = 8;

    // Parsed once at start-up: a missing or invalid key disables commands entirely.
    private readonly List<string> trustedKeys = LoadTrustedKeys(settings, logger);

    /// <summary>Advertised on the heartbeat; empty when commands cannot be run safely.</summary>
    public IReadOnlyList<string> Capabilities =>
        ledger.Available && trustedKeys.Count > 0 ? ManagementCommandTypes.Supported(settings) : [];

    public ManagementCommandLedger Ledger => ledger;

    public async Task HandleResponseAsync(
        HttpContent content,
        IReadOnlyList<CommandResultReport> reported,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(reported);
        ManagementHeartbeatResponse? response;
        try
        {
            byte[]? body = await ReadBoundedAsync(content, cancellationToken);
            if (body is null)
            {
                LogResponseTooLarge(logger);
                return;
            }

            response = body.Length == 0
                ? null
                : JsonSerializer.Deserialize(body, CollectorJsonContext.Default.ManagementHeartbeatResponse);
        }
        catch (JsonException)
        {
            LogResponseInvalid(logger);
            return;
        }

        // A v1 management API answers with its collector record: no commands, no acknowledgements.
        if (response is not { SchemaVersion: 2 })
        {
            return;
        }

        ledger.Acknowledge(response.AcknowledgedResults ?? [], reported);
        IReadOnlyList<JsonElement> commands = response.Commands ?? [];
        if (commands.Count == 0)
        {
            return;
        }

        List<string> trusted = trustedKeys;
        IReadOnlyList<string> supported = ManagementCommandTypes.Supported(settings);
        DateTimeOffset now = clock.GetUtcNow();
        int accepted = 0;
        int refused = 0;
        foreach (JsonElement element in commands.Take(MaximumCommandsPerResponse))
        {
            ManagementCommandVerification verification = ManagementCommandVerifier.Verify(
                element, settings.CollectorId, trusted, now);
            if (trusted.Count == 0)
            {
                ledger.Reject(verification.CommandId, ManagementCommandResults.CommandsNotConfigured);
                refused++;
                continue;
            }

            if (verification.Command is not { } command)
            {
                ledger.Reject(verification.CommandId, verification.RejectionCode!);
                refused++;
                continue;
            }

            if (!supported.Contains(command.Command, StringComparer.Ordinal))
            {
                ledger.Reject(command.CommandId, ManagementCommandResults.UnsupportedCommand);
                refused++;
                continue;
            }

            switch (ledger.Admit(command))
            {
                case CommandAdmission.Accepted when queue.TryEnqueue(command):
                    accepted++;
                    break;
                case CommandAdmission.Accepted:
                    ledger.Complete(command.CommandId, ManagementCommandResults.Failed, ManagementCommandResults.ExecutorBusy);
                    refused++;
                    break;
                case CommandAdmission.Rejected:
                    refused++;
                    break;
            }
        }

        LogCommandsReceived(logger, commands.Count, accepted, refused);
    }

    /// <summary>
    /// Every configured key must be a readable ECDSA P-256 public key PEM; otherwise no key is
    /// trusted (fail closed) and a metadata-only error names the setting, never the content.
    /// </summary>
    private static List<string> LoadTrustedKeys(CollectorSettings settings, ILogger logger)
    {
        List<string> keys = [];
        foreach (string path in settings.ManagementCommandTrustedKeyFiles)
        {
            try
            {
                string pem = File.ReadAllText(path);
                using System.Security.Cryptography.ECDsa key = System.Security.Cryptography.ECDsa.Create();
                key.ImportFromPem(pem);
                if (key.KeySize != 256)
                {
                    throw new System.Security.Cryptography.CryptographicException("Not a P-256 key.");
                }

                keys.Add(pem);
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or System.Security.Cryptography.CryptographicException)
            {
                LogTrustedKeysInvalid(logger, settings.ManagementCommandTrustedKeyFiles.Count, exception.GetType().Name);
                return [];
            }
        }

        return keys;
    }

    [LoggerMessage(
        EventId = 1306,
        Level = LogLevel.Error,
        Message = "BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS ({Count} file(s)) must all be readable ECDSA P-256 public key PEM files ({ExceptionType}); management commands are disabled.")]
    private static partial void LogTrustedKeysInvalid(ILogger logger, int count, string exceptionType);

    /// <summary>Null when the body exceeds <see cref="MaximumResponseBytes"/>.</summary>
    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumResponseBytes)
        {
            return null;
        }

        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream buffer = new();
        byte[] chunk = new byte[8 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > MaximumResponseBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    [LoggerMessage(
        EventId = 1301,
        Level = LogLevel.Information,
        Message = "Management sent {Count} command(s): {Accepted} accepted, {Refused} refused.")]
    private static partial void LogCommandsReceived(ILogger logger, int count, int accepted, int refused);

    [LoggerMessage(
        EventId = 1302,
        Level = LogLevel.Warning,
        Message = "Management heartbeat response exceeded the size limit; its commands were ignored.")]
    private static partial void LogResponseTooLarge(ILogger logger);

    [LoggerMessage(
        EventId = 1303,
        Level = LogLevel.Warning,
        Message = "Management heartbeat response is not valid JSON; its commands were ignored.")]
    private static partial void LogResponseInvalid(ILogger logger);
}

/// <summary>
/// Executes admitted management commands. A hosted loop, not a scheduled job: a canary is
/// queued through the normal pipeline (redaction and policy first), which is queue state.
/// Each command maps to one fixed action and runs at most once; its result is reported on
/// the next heartbeat.
/// </summary>
public sealed partial class ManagementCommandWorker(
    ManagementCommandInbox queue,
    ManagementCommandLedger ledger,
    RecurringJobRegistry jobs,
    SecurityEventProcessor processor,
    CollectorIdentity identity,
    CollectorSettings settings,
    TimeProvider clock,
    IHostApplicationLifetime lifetime,
    ILogger<ManagementCommandWorker> logger,
    ManagementEnrolment? enrolment = null) : BackgroundService
{
    public const string CanarySourceAdapter = "management-canary";
    public const string ExecutionFailed = "execution-failed";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (VerifiedManagementCommand command in queue.ReadAllAsync(stoppingToken))
            {
                await ExecuteOneAsync(command, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down; an admitted command left unfinished reports `interrupted`.
        }
    }

    public async Task ExecuteOneAsync(VerifiedManagementCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        try
        {
            (string status, string code) = command.Command switch
            {
                ManagementCommandTypes.FetchBundle => jobs.Trigger(ManagedPrivacyProfileJob.Id)
                    ? (ManagementCommandResults.Succeeded, ManagementCommandResults.FetchTriggered)
                    : (ManagementCommandResults.Failed, ManagementCommandResults.FetchUnavailable),
                ManagementCommandTypes.RunCanary => await RunCanaryAsync(command, cancellationToken),
                ManagementCommandTypes.Reload => Reload(command),
                ManagementCommandTypes.RotateCredential when enrolment is not null =>
                    await enrolment.RotateAsync(cancellationToken),
                _ => (ManagementCommandResults.Failed, ManagementCommandResults.UnsupportedCommand)
            };
            if (command.Command != ManagementCommandTypes.Reload || status != ManagementCommandResults.Succeeded)
            {
                ledger.Complete(command.CommandId, status, code);
            }

            LogExecuted(logger, command.Command, status, code);
        }
        catch (Exception exception) when (exception is not OperationCanceledException
            || !cancellationToken.IsCancellationRequested)
        {
            LogExecutionFailed(logger, command.Command, exception.GetType().Name);
            try
            {
                ledger.Complete(command.CommandId, ManagementCommandResults.Failed, ExecutionFailed);
            }
            catch (Exception ledgerFailure) when (ledgerFailure is IOException or UnauthorizedAccessException)
            {
                // Still `started` on disk: a restart reports it as interrupted.
                LogExecutionFailed(logger, command.Command, ledgerFailure.GetType().Name);
            }
        }
    }

    private (string Status, string Code) Reload(VerifiedManagementCommand command)
    {
        if (!ledger.TryBeginReload())
        {
            return (ManagementCommandResults.Failed, ManagementCommandResults.ReloadRateLimited);
        }

        // Recorded before stopping, so the result survives the restart and is reported then.
        ledger.Complete(command.CommandId, ManagementCommandResults.Succeeded, ManagementCommandResults.RestartRequested);
        ManagedPrivacyProfileJob.RequestSupervisorRestart(lifetime);
        return (ManagementCommandResults.Succeeded, ManagementCommandResults.RestartRequested);
    }

    private async Task<(string Status, string Code)> RunCanaryAsync(
        VerifiedManagementCommand command,
        CancellationToken cancellationToken)
    {
        DateTimeOffset ranAt = clock.GetUtcNow();
        string eventId = $"bower-canary-{Guid.CreateVersion7():N}";
        string outcome;
        try
        {
            ProcessingResult result = await processor.ProcessAsync(
                CanaryJson(eventId, ranAt, settings.Environment, command.CommandId),
                identity with { SourceAdapter = CanarySourceAdapter },
                cancellationToken);
            outcome = result switch
            {
                { Duplicate: true } => "duplicate",
                { Queued: true } => "queued",
                { Action: DecisionAction.Reject } => "rejected",
                _ => "quarantined"
            };
        }
        catch (QueueCapacityExceededException)
        {
            outcome = "failed";
        }

        ledger.RecordCanary(new CanaryReport(command.CommandId, eventId, ranAt, outcome));
        return outcome is "queued" or "duplicate"
            ? (ManagementCommandResults.Succeeded, ManagementCommandResults.CanaryQueued)
            : (ManagementCommandResults.Failed, $"canary-{outcome}");
    }

    /// <summary>
    /// A synthetic collector-health canary. It carries no user data and goes through the same
    /// redaction and policy as any event; the default canary policy accepts it.
    /// </summary>
    public static string CanaryJson(string eventId, DateTimeOffset at, string environment, string commandId)
    {
        SecurityEventEnvelope canary = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            EventOriginalId = eventId,
            TimeGenerated = at,
            EventCategory = SecurityEventCategories.CollectorHealth,
            EventType = SecurityEventTypes.CollectorCanary,
            EventAction = "management.canary",
            EventResult = EventResult.Success,
            EventSeverity = EventSeverity.Informational,
            EventOutcomeReason = "Synthetic management canary",
            Application = new ApplicationContext { Name = "bower-collector", Environment = environment },
            Actor = new ActorContext { Username = "bower.management", Type = ActorType.System },
            Request = new RequestContext { CorrelationId = eventId },
            Labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["evidenceType"] = "canary",
                ["commandId"] = commandId
            }
        };
        return JsonSerializer.Serialize(canary, BowerJson.Envelope);
    }

    [LoggerMessage(
        EventId = 1304,
        Level = LogLevel.Information,
        Message = "Management command {Command} finished: {Status} ({Code}).")]
    private static partial void LogExecuted(ILogger logger, string command, string status, string code);

    [LoggerMessage(
        EventId = 1305,
        Level = LogLevel.Warning,
        Message = "Management command {Command} failed with {ExceptionType}.")]
    private static partial void LogExecutionFailed(ILogger logger, string command, string exceptionType);
}
