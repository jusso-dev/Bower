using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Azure.Core;
using Bower.Abstractions;
using Bower.Jobs;
using Bower.Packs;

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
    ILogger<ManagementHeartbeatJob> logger,
    SourceHealth? sourceHealth = null,
    ManagementCommandProcessor? commands = null,
    DeliveryActivity? deliveryActivity = null,
    TimeSpan? exchangeTimeout = null)
{
    public const string Id = "management-heartbeat";
    public const string HttpClientName = "bower-management";

    /// <summary>The job runs every minute; management derives staleness from this interval.</summary>
    public const int IntervalSeconds = 60;

    /// <summary>
    /// Budget for one heartbeat exchange: request, response headers and the bounded body.
    /// <c>HttpClient.Timeout</c> stops at the headers, so the body read needs its own bound.
    /// </summary>
    public static readonly TimeSpan DefaultExchangeTimeout = TimeSpan.FromSeconds(15);

    internal TimeSpan ExchangeTimeout => exchangeTimeout ?? DefaultExchangeTimeout;

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
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string deliveryStatus = DeliveryHealth.Evaluate(settings.OutputType, snapshot,
            settings.MaximumQueueBytes, now);
        // Finished command results stay pending until management acknowledges them.
        IReadOnlyList<CommandResultReport> results = commands?.Ledger.PendingResults() ?? [];
        // Expected applications report as sources so silent ones show in the console.
        SourceReport[] sources =
        [
            new SourceReport("local-http", "local-http", "healthy", null, null),
            .. (sourceHealth?.Evaluate() ?? []).Select(item => new SourceReport(
                $"{item.Application}/{item.Environment}",
                "application",
                item.IsActive ? "healthy" : item.State,
                item.SilentSeconds,
                item.LastSeenAt))
        ];
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
                    new LedgerResponse(ledger.Sequence, ledger.Hash),
                    bundle.PrivacyProfileHash ?? "default")
                {
                    HeartbeatIntervalSeconds = IntervalSeconds,
                    OldestUndeliveredAgeSeconds = snapshot.OldestUndelivered is { } oldest
                        ? Math.Max(0, (long)(now - oldest).TotalSeconds)
                        : null,
                    LastSuccessfulDeliveryAt = deliveryActivity?.LastSuccessfulDeliveryAt,
                    LastCanary = commands?.Ledger.LastCanary,
                    CommandCapabilities = commands?.Capabilities ?? [],
                    CommandResults = results
                },
                CollectorJsonContext.Default.CollectorHeartbeat));
        // One budget for the whole exchange, body included: a stalled body cannot hold the
        // job (and so every later heartbeat) forever.
        using CancellationTokenSource exchange = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        exchange.CancelAfter(ExchangeTimeout);
        try
        {
            using HttpResponseMessage response = await client.SendAsync(
                heartbeat, HttpCompletionOption.ResponseHeadersRead, exchange.Token);
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                LogCollectorNotActive(logger);
                return;
            }

            response.EnsureSuccessStatusCode();
            if (commands is not null)
            {
                // Commands are verified and handed to the hosted worker; never executed here.
                await commands.HandleResponseAsync(response.Content, results, exchange.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The management heartbeat exchange exceeded its time budget.");
        }
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
