using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Azure.Core;
using Bower.Abstractions;
using Bower.Jobs;

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
        SourceReport[] sources = [new SourceReport("local-http", "local-http", "healthy", null, null)];
        OutputReport[] outputs =
        [
            new OutputReport(settings.OutputType, settings.OutputType, deliveryStatus, null, null)
        ];
        IReadOnlyList<BackgroundJobStatus> jobReports = jobs.List();
        // The management store keeps the last ledger head per collector as an external
        // witness: a later head with a lower sequence or a different hash is tampering.
        LedgerHead ledger = await eventStore.GetLedgerHeadAsync(cancellationToken);

        using HttpRequestMessage registration = CreateRequest(
            "api/collectors/register",
            accessToken.Token,
            JsonContent.Create(
                new CollectorRegistration(
                    settings.CollectorId,
                    System.Environment.MachineName,
                    settings.Environment,
                    settings.Version,
                    settings.ConfigurationHash(),
                    bundle.Hash,
                    sources,
                    outputs),
                CollectorJsonContext.Default.CollectorRegistration));
        using HttpResponseMessage registered = await client.SendAsync(registration, cancellationToken);
        if (!registered.IsSuccessStatusCode)
        {
            LogRegistrationFailure(logger, (int)registered.StatusCode);
            return;
        }

        using HttpRequestMessage heartbeat = CreateRequest(
            $"api/collectors/{Uri.EscapeDataString(settings.CollectorId)}/heartbeat",
            accessToken.Token,
            JsonContent.Create(
                new CollectorHeartbeat(
                    settings.Version,
                    settings.ConfigurationHash(),
                    bundle.Hash,
                    snapshot.Queued + snapshot.Retrying + snapshot.Uploading,
                    deliveryStatus,
                    sources,
                    outputs,
                    jobReports,
                    snapshot.DeadLettered,
                    new LedgerResponse(ledger.Sequence, ledger.Hash)),
                CollectorJsonContext.Default.CollectorHeartbeat));
        using HttpResponseMessage response = await client.SendAsync(heartbeat, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            LogCollectorNotActive(logger);
            return;
        }

        response.EnsureSuccessStatusCode();
    }

    // The bearer token is attached per request, never to shared default headers.
    private static HttpRequestMessage CreateRequest(string path, string token, JsonContent body) =>
        new(HttpMethod.Post, path)
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) },
            Content = body
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
