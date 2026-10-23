using System.Text.Json;
using System.Threading.RateLimiting;
using Azure.Core;
using Bower.Abstractions;
using Bower.Collector.Jobs;
using Bower.Contracts;
using Bower.Core;
using Bower.Jobs;
using Bower.Output.AmaSpool;
using Bower.Output.AzureLogsIngestion;
using Bower.Persistence;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction;
using Microsoft.AspNetCore.RateLimiting;

namespace Bower.Collector;

/// <summary>Composes the collector host. Kept separate from Program for integration tests.</summary>
public static partial class CollectorApplication
{
    public static WebApplication Build(
        CollectorSettings settings,
        Action<WebApplicationBuilder>? configure = null,
        IOutputAdapter? output = null,
        TokenCredential? credential = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();

        // Slim builder: no reflection-based startup, as Native AOT requires. HTTPS endpoint
        // configuration is opted back in because BOWER_LISTEN_URL may be https.
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls(settings.ListenUrl);
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Limits.MaxRequestBodySize = JsonEventRedactor.MaximumPayloadBytes;
            options.AddServerHeader = false;
        });
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ ";
            options.UseUtcTimestamp = true;
        });
        // Per-request framework logs add volume without security value.
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Services.Configure<HostOptions>(options =>
            // An unhandled worker fault is a delivery outage; stop so the supervisor restarts
            // the process instead of running a collector that silently stopped delivering.
            options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.StopHost);

        // Source-generated JSON for request and response bodies (Web defaults, as before).
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.TypeInfoResolverChain.Insert(0, CollectorJsonContext.Default));

        builder.Services.AddSingleton(settings);
        builder.Services.AddSingleton(TimeProvider.System);
        PolicyBundle bundle = PolicyBundle.Load(settings);
        builder.Services.AddSingleton(bundle);
        builder.Services.AddSingleton<IEventRedactor>(new PackDetectionRedactor(
            new JsonEventRedactor(bundle.Privacy), new DeterministicPolicyEvaluator(bundle.Policies),
            bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray()));
        builder.Services.AddSingleton<IDurableEventStore>(services =>
            new SqliteEventStore(
                settings.QueuePath,
                settings.MaximumQueueBytes,
                services.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<ITelemetryPolicyEvaluator>(new DeterministicPolicyEvaluator(bundle.Policies));
        builder.Services.AddSingleton<SecurityEventProcessor>();
        builder.Services.AddSingleton(
            new CollectorIdentity(settings.CollectorId, settings.Version, "local-http", settings.ConfigurationHash()));
        builder.Services.AddSingleton(new ProducerAuthorization(settings.ProducerScopesFile, settings.SingleTrustDomain));
        builder.Services.AddSingleton(new IngestAuthentication(settings.IngestToken, settings.IngestTokensFile));
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddTokenBucketLimiter("ingest", limiter =>
            {
                limiter.TokenLimit = settings.IngestRequestsPerSecond * 2;
                limiter.TokensPerPeriod = settings.IngestRequestsPerSecond;
                limiter.ReplenishmentPeriod = TimeSpan.FromSeconds(1);
                limiter.QueueLimit = 0;
                limiter.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            });
        });

        output ??= CreateOutput(settings, credential);
        if (output is not null)
        {
            builder.Services.AddSingleton(output);
            builder.Services.AddSingleton(new QueueDeliveryOptions
            {
                MaximumDeliveryAttempts = settings.MaximumDeliveryAttempts
            });
            builder.Services.AddHostedService<QueueDeliveryWorker>();
        }

        builder.Services.AddBowerBackgroundJobs($"bower-collector:{settings.CollectorId}");
        builder.Services.AddTransient<QueueRetentionJob>();
        builder.Services.AddTransient<QueueMaintenanceJob>();
        if (settings.ManagementEndpoint is not null)
        {
            builder.Services.AddSingleton(credential ?? AzureCredentialFactory.Create(settings));
            builder.Services.AddHttpClient(ManagementHeartbeatJob.HttpClientName, client =>
            {
                client.BaseAddress = settings.ManagementEndpoint;
                client.Timeout = TimeSpan.FromSeconds(15);
            });
            builder.Services.AddTransient<ManagementHeartbeatJob>();
        }

        configure?.Invoke(builder);

        WebApplication app = builder.Build();
        app.UseRateLimiter();
        MapEndpoints(app);
        return app;
    }

    /// <summary>Initialises storage and registers recurring jobs. Call before RunAsync.</summary>
    public static async Task InitializeAsync(WebApplication app, CancellationToken cancellationToken)
    {
        CollectorSettings settings = app.Services.GetRequiredService<CollectorSettings>();
        if (settings.IngestToken is null && !settings.IsLoopbackListener)
        {
            LogUnauthenticatedIngest(app.Logger);
        }

        await app.Services.GetRequiredService<IDurableEventStore>().InitializeAsync(cancellationToken);

        RecurringJobRegistry jobs = app.Services.GetRequiredService<RecurringJobRegistry>();
        jobs.AddOrUpdate<QueueRetentionJob>(
            QueueRetentionJob.Id,
            (job, token) => job.RunAsync(token),
            Cron.Hourly(),
            QueueRetentionJob.RetryAttempts);
        jobs.AddOrUpdate<QueueMaintenanceJob>(
            QueueMaintenanceJob.Id,
            (job, token) => job.RunAsync(token),
            Cron.Daily(3),
            QueueMaintenanceJob.RetryAttempts);
        if (settings.ManagementEndpoint is not null)
        {
            // A missed heartbeat is superseded by the next scheduled run; never retry-stack.
            jobs.AddOrUpdate<ManagementHeartbeatJob>(
                ManagementHeartbeatJob.Id,
                (job, token) => job.RunAsync(token),
                Cron.Minutely());
        }
    }

    private static void MapEndpoints(WebApplication app)
    {
        MapPackEndpoints(app);
        app.MapPost(
                "/v1/events",
                async (
                    JsonElement candidate,
                    HttpContext context,
                    SecurityEventProcessor processor,
                    ProducerAuthorization authorization,
                    CollectorIdentity identity,
                    CancellationToken cancellationToken) =>
                {
                    // Record which producer credential sent the event (never the token).
                    string producer = context.Items[IngestAuthenticationFilter.ProducerItem] as string ?? "anonymous";
                    if (!authorization.IsAuthorized(producer, candidate))
                    {
                        return Results.Json(
                            new ErrorResponse("Producer is not authorized for this event identity."),
                            CollectorJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status403Forbidden);
                    }

                    ProcessingResult result;
                    try
                    {
                        result = await processor.ProcessAsync(
                            candidate.GetRawText(),
                            identity with { SourceAdapter = $"local-http:{producer}" },
                            cancellationToken);
                    }
                    catch (QueueCapacityExceededException)
                    {
                        // Backpressure: producers should buffer and retry.
                        return Results.Json(
                            new ErrorResponse("Collector queue is at capacity; retry later."),
                            CollectorJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status503ServiceUnavailable);
                    }

                    IngestResponse response = new(
                        result.EventId,
                        result.Action.ToString().ToLowerInvariant(),
                        result.Queued,
                        result.Duplicate,
                        result.Reasons,
                        result.PolicyDecision is null
                            ? null
                            : new IngestPolicyResponse(
                                result.PolicyDecision.PolicyId,
                                result.PolicyDecision.PolicyVersion,
                                result.PolicyDecision.PolicyHash,
                                result.PolicyDecision.Score));

                    int statusCode = result.Action switch
                    {
                        DecisionAction.Accept or DecisionAction.RedactAndAccept => result.Duplicate ? 200 : 202,
                        DecisionAction.Reject => 422,
                        _ => 400
                    };
                    return Results.Json(response, CollectorJsonContext.Default.IngestResponse, statusCode: statusCode);
                })
            .AddEndpointFilter<IngestAuthenticationFilter>()
            .RequireRateLimiting("ingest");

        // Liveness for probes: status only, no queue metadata without a token.
        app.MapGet(
            "/health",
            async (IDurableEventStore eventQueue, CancellationToken cancellationToken) =>
            {
                QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
                return Results.Json(new HealthResponse(Status(snapshot)), CollectorJsonContext.Default.HealthResponse);
            });

        app.MapGet(
                "/v1/status",
                async (
                    IDurableEventStore eventQueue,
                    BackgroundJobCatalog jobs,
                    PolicyBundle bundle,
                    CancellationToken cancellationToken) =>
                {
                    QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
                    LedgerHead ledger = await eventQueue.GetLedgerHeadAsync(cancellationToken);
                    StatusResponse status = new(
                        Status(snapshot),
                        new StatusPolicyResponse(
                            bundle.Hash,
                            [.. bundle.Policies.Select(item => new StatusPolicyItem(
                                item.Policy.Metadata.Id,
                                item.Policy.Metadata.Version))],
                            [.. bundle.LoadedPacks.Select(pack => new StatusPackItem(
                                pack.Manifest.Id, pack.Manifest.Version, pack.Manifest.PackHash,
                                [.. pack.Parsers.Select(parser => parser.Runtime is null ? "inactive-preview-only" : "active-local-json")],
                                pack.Detections.Count == 0 ? "absent" : "active-local",
                                pack.DcrTemplateJson is null ? "absent" : "packaged-only"))],
                            bundle.PrivacyProfile),
                        new LedgerResponse(ledger.Sequence, ledger.Hash),
                        new StatusQueueResponse(
                            snapshot.Queued,
                            snapshot.Retrying,
                            snapshot.Uploading,
                            snapshot.Delivered,
                            snapshot.DeadLettered,
                            snapshot.TotalBytes,
                            snapshot.UndeliveredBytes,
                            snapshot.OldestUndelivered),
                        jobs.List());
                    return Results.Json(status, CollectorJsonContext.Default.StatusResponse);
                })
            .AddEndpointFilter<IngestAuthenticationFilter>();
    }

    private static string Status(QueueSnapshot snapshot) =>
        snapshot.DeadLettered > 0 ? "degraded" : "healthy";

    private static IOutputAdapter? CreateOutput(CollectorSettings settings, TokenCredential? credential)
    {
        return settings.OutputType switch
        {
            "none" => null,
            "ama-spool" => new AmaSpoolOutput(new AmaSpoolOptions
            {
                Id = "ama-spool",
                CollectorId = settings.CollectorId,
                StreamName = settings.StreamName,
                ActiveDirectory = Path.Combine(settings.AmaSpoolPath, "active"),
                ReadyDirectory = Path.Combine(settings.AmaSpoolPath, "ready")
            }),
            "azure-logs-ingestion" => new AzureLogsIngestionOutput(
                new AzureLogsIngestionOptions
                {
                    Id = "azure-logs-ingestion",
                    Endpoint = settings.DceEndpoint!,
                    DcrImmutableId = settings.DcrImmutableId!,
                    StreamName = settings.StreamName
                },
                credential ?? AzureCredentialFactory.Create(settings)),
            _ => throw new InvalidOperationException($"Unsupported BOWER_OUTPUT value: {settings.OutputType}")
        };
    }

    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Warning,
        Message = "Collector ingest authentication is disabled on a non-loopback listener. " +
            "Use BOWER_ALLOW_UNAUTHENTICATED_INGEST only on an isolated network.")]
    private static partial void LogUnauthenticatedIngest(ILogger logger);
}
