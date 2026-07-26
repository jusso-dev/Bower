using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Azure.Core;
using Bower.Abstractions;

namespace Bower.Collector;

public sealed record ManagementReporterOptions(
    Uri Endpoint,
    string Scope,
    string CollectorId,
    string Version,
    string Environment,
    string ConfigurationHash,
    string PolicyHash,
    string OutputType,
    TimeSpan Interval);

public sealed partial class ManagementReporter(
    ManagementReporterOptions options,
    TokenCredential credential,
    IDurableEventStore eventStore,
    ILogger<ManagementReporter> logger)
    : BackgroundService
{
    private readonly HttpClient _client = new()
    {
        BaseAddress = options.Endpoint,
        Timeout = TimeSpan.FromSeconds(15)
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(options.Interval);
        do
        {
            try
            {
                await ReportAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                LogHeartbeatFailure(logger, exception.GetType().Name);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task ReportAsync(CancellationToken cancellationToken)
    {
        AccessToken accessToken = await credential.GetTokenAsync(
            new TokenRequestContext([options.Scope]),
            cancellationToken);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken.Token);

        QueueSnapshot snapshot = await eventStore.GetSnapshotAsync(cancellationToken);
        object[] sources =
        [
            new
            {
                id = "local-http",
                type = "local-http",
                status = "healthy",
                lagSeconds = (long?)null,
                lastEventAt = (DateTimeOffset?)null
            }
        ];
        object[] outputs =
        [
            new
            {
                id = options.OutputType,
                type = options.OutputType,
                status = snapshot.DeadLettered > 0 ? "degraded" : "healthy",
                lastAcknowledgedAt = (DateTimeOffset?)null,
                lastErrorCode = (string?)null
            }
        ];

        using HttpResponseMessage registration = await _client.PostAsJsonAsync(
            "api/collectors/register",
            new
            {
                collectorId = options.CollectorId,
                machineName = Environment.MachineName,
                environment = options.Environment,
                version = options.Version,
                configurationHash = options.ConfigurationHash,
                policyHash = options.PolicyHash,
                sources,
                outputs
            },
            cancellationToken);
        if (!registration.IsSuccessStatusCode)
        {
            LogRegistrationFailure(logger, (int)registration.StatusCode);
            return;
        }

        using HttpResponseMessage heartbeat = await _client.PostAsJsonAsync(
            $"api/collectors/{Uri.EscapeDataString(options.CollectorId)}/heartbeat",
            new
            {
                version = options.Version,
                configurationHash = options.ConfigurationHash,
                policyHash = options.PolicyHash,
                queueDepth = snapshot.Queued + snapshot.Retrying + snapshot.Uploading,
                deliveryStatus = snapshot.DeadLettered > 0 ? "degraded" : "healthy",
                sources,
                outputs
            },
            cancellationToken);
        if (heartbeat.StatusCode == HttpStatusCode.Conflict)
        {
            LogCollectorNotActive(logger);
            return;
        }

        heartbeat.EnsureSuccessStatusCode();
    }

    public override void Dispose()
    {
        _client.Dispose();
        base.Dispose();
    }

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Warning,
        Message =
            "Management heartbeat failed with {ExceptionType}; collection and delivery continue.")]
    private static partial void LogHeartbeatFailure(ILogger logger, string exceptionType);

    [LoggerMessage(
        EventId = 1102,
        Level = LogLevel.Warning,
        Message = "Management registration returned HTTP {StatusCode}.")]
    private static partial void LogRegistrationFailure(ILogger logger, int statusCode);

    [LoggerMessage(
        EventId = 1103,
        Level = LogLevel.Information,
        Message = "Collector is awaiting approval or is not permitted to heartbeat.")]
    private static partial void LogCollectorNotActive(ILogger logger);
}
