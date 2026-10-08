using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Azure.Core;
using Bower.Abstractions;
using Bower.Jobs;
using Hangfire;

namespace Bower.Collector.Jobs;

/// <summary>
/// Registers the collector and reports queue, output and background-job health to the
/// management API. Metadata only: never events, payloads or credentials.
/// </summary>
public sealed partial class ManagementHeartbeatJob(
    IHttpClientFactory httpClientFactory,
    TokenCredential credential,
    IDurableEventStore eventStore,
    BackgroundJobCatalog jobs,
    CollectorSettings settings,
    PolicyBundle bundle,
    ILogger<ManagementHeartbeatJob> logger)
{
    public const string Id = "management-heartbeat";
    public const string HttpClientName = "bower-management";

    // A missed heartbeat is superseded by the next scheduled run; never retry-stack.
    [AutomaticRetry(Attempts = 0, LogEvents = false)]
    [DisableConcurrentExecution(timeoutInSeconds: 60)]
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await ReportAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Collection and delivery continue when management is unreachable.
            LogHeartbeatFailure(logger, exception.GetType().Name);
        }
    }

    private async Task ReportAsync(CancellationToken cancellationToken)
    {
        AccessToken accessToken = await credential.GetTokenAsync(
            new TokenRequestContext([settings.ManagementScope!]),
            cancellationToken);
        HttpClient client = httpClientFactory.CreateClient(HttpClientName);

        QueueSnapshot snapshot = await eventStore.GetSnapshotAsync(cancellationToken);
        string deliveryStatus = snapshot.DeadLettered > 0 ? "degraded" : "healthy";
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
                id = settings.OutputType,
                type = settings.OutputType,
                status = deliveryStatus,
                lastAcknowledgedAt = (DateTimeOffset?)null,
                lastErrorCode = (string?)null
            }
        ];
        IReadOnlyList<BackgroundJobStatus> jobReports = jobs.List();
        // The management store keeps the last ledger head per collector as an external
        // witness: a later head with a lower sequence or a different hash is tampering.
        LedgerHead ledger = await eventStore.GetLedgerHeadAsync(cancellationToken);

        using HttpRequestMessage registration = CreateRequest(
            "api/collectors/register",
            accessToken.Token,
            new
            {
                collectorId = settings.CollectorId,
                machineName = System.Environment.MachineName,
                environment = settings.Environment,
                version = settings.Version,
                configurationHash = settings.ConfigurationHash(),
                policyHash = bundle.Hash,
                sources,
                outputs
            });
        using HttpResponseMessage registered = await client.SendAsync(registration, cancellationToken);
        if (!registered.IsSuccessStatusCode)
        {
            LogRegistrationFailure(logger, (int)registered.StatusCode);
            return;
        }

        using HttpRequestMessage heartbeat = CreateRequest(
            $"api/collectors/{Uri.EscapeDataString(settings.CollectorId)}/heartbeat",
            accessToken.Token,
            new
            {
                version = settings.Version,
                configurationHash = settings.ConfigurationHash(),
                policyHash = bundle.Hash,
                queueDepth = snapshot.Queued + snapshot.Retrying + snapshot.Uploading,
                deliveryStatus,
                sources,
                outputs,
                jobs = jobReports,
                deadLettered = snapshot.DeadLettered,
                ledger = new { sequence = ledger.Sequence, hash = ledger.Hash }
            });
        using HttpResponseMessage response = await client.SendAsync(heartbeat, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            LogCollectorNotActive(logger);
            return;
        }

        response.EnsureSuccessStatusCode();
    }

    // The bearer token is attached per request, never to shared default headers.
    private static HttpRequestMessage CreateRequest(string path, string token, object body) =>
        new(HttpMethod.Post, path)
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) },
            Content = JsonContent.Create(body)
        };

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Warning,
        Message = "Management heartbeat failed with {ExceptionType}; collection and delivery continue.")]
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
