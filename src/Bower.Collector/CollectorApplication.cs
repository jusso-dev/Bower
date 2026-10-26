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
using Bower.Packs;
using Bower.Persistence;
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
        VerifiedManagedPrivacyProfile? cachedManagedProfile = null;
        PolicyBundle bundle = PolicyBundle.Load(settings.PolicySources(cached => cachedManagedProfile = cached));
        builder.Services.AddSingleton(bundle);
        // Management mode fails closed until the first sync resolves (see ManagedPrivacyProfileState).
        builder.Services.AddSingleton(settings.UsesManagedPrivacyProfile
            ? new ManagedPrivacyProfileState(cachedManagedProfile, settings.ManagedPrivacyAllowDefault)
            : ManagedPrivacyProfileState.Local);
        builder.Services.AddSingleton<IEventRedactor>(new PackDetectionRedactor(
            new JsonEventRedactor(bundle.Privacy), new DeterministicPolicyEvaluator(bundle.Policies),
            bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray()));
        builder.Services.AddSingleton<IDurableEventStore>(services =>
            new SqliteEventStore(
                settings.QueuePath,
                settings.MaximumQueueBytes,
                services.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<ITelemetryPolicyEvaluator>(new DeterministicPolicyEvaluator(bundle.Policies));
        builder.Services.AddSingleton<PipelineTelemetry>();
        builder.Services.AddSingleton<SecurityEventProcessor>();
        // Loaded at build so a malformed expectations file stops start-up.
        SourceExpectations? expectations = settings.SourceExpectationsPath is null
            ? null
            : SourceExpectationsLoader.LoadFile(settings.SourceExpectationsPath);
        builder.Services.AddSingleton(services => new SourceHealth(
            expectations,
            services.GetRequiredService<PipelineTelemetry>(),
            services.GetRequiredService<TimeProvider>(),
            services.GetRequiredService<ILogger<SourceHealth>>()));
        builder.Services.AddHostedService<SuppressionWindowWorker>();
        builder.Services.AddSingleton<EventIdentityConflicts>();
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

        builder.Services.AddSingleton<DeliveryActivity>();
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
        builder.Services.AddTransient<SourceActivityJob>();
        if (settings.ArchivePath is not null)
        {
            builder.Services.AddSingleton(services => new QueueArchive(
                settings.ArchivePath,
                settings.CollectorId,
                services.GetRequiredService<TimeProvider>()));
            builder.Services.AddTransient<QueueArchiveJob>();
        }
        if (settings.ManagementEndpoint is not null)
        {
            builder.Services.AddSingleton(credential ?? AzureCredentialFactory.Create(settings));
            // Proxy and CA bundle are read here, so a bad proxy password file or CA bundle stops start-up.
            SocketsHttpHandler managementHandler = ManagementHttp.CreateHandler(settings);
            builder.Services.AddHttpClient(ManagementHeartbeatJob.HttpClientName, client =>
            {
                client.BaseAddress = settings.ManagementEndpoint;
                client.Timeout = TimeSpan.FromSeconds(15);
            })
                .ConfigurePrimaryHttpMessageHandler(() => managementHandler)
                .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
            builder.Services.AddSingleton(services => new ManagementCommandLedger(
                settings.ManagementCommandDirectory, services.GetRequiredService<TimeProvider>()));
            builder.Services.AddSingleton<ManagementCommandInbox>();
            builder.Services.AddSingleton<ManagementCommandProcessor>();
            builder.Services.AddHostedService<ManagementCommandWorker>();
            builder.Services.AddTransient<ManagementHeartbeatJob>();
            if (settings.UsesManagedPrivacyProfile)
            {
                builder.Services.AddTransient<ManagedPrivacyProfileJob>();
            }
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

        IDurableEventStore queue = app.Services.GetRequiredService<IDurableEventStore>();
        await queue.InitializeAsync(cancellationToken);
        app.Services.GetRequiredService<PipelineTelemetry>().Load(
            await queue.GetSourceActivityAsync(cancellationToken));
        await app.Services.GetRequiredService<SourceHealth>().InitializeAsync(queue, cancellationToken);

        RecurringJobRegistry jobs = app.Services.GetRequiredService<RecurringJobRegistry>();
        // Superseded by the next run on failure; the in-memory set keeps unsaved changes.
        jobs.AddOrUpdate<SourceActivityJob>(
            SourceActivityJob.Id,
            (job, token) => job.RunAsync(token),
            Cron.Minutely());
        if (settings.ArchivePath is not null)
        {
            jobs.AddOrUpdate<QueueArchiveJob>(
                QueueArchiveJob.Id,
                (job, token) => job.RunAsync(token),
                Cron.Minutely());
        }

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
            // Parses the trusted command keys now, so an invalid key is reported at start-up.
            _ = app.Services.GetRequiredService<ManagementCommandProcessor>();
            // A missed heartbeat is superseded by the next scheduled run; never retry-stack.
            jobs.AddOrUpdate<ManagementHeartbeatJob>(
                ManagementHeartbeatJob.Id,
                (job, token) => job.RunAsync(token),
                Cron.Minutely());
            if (settings.UsesManagedPrivacyProfile)
            {
                // Idempotent: an unchanged assignment is a no-op; a failed run is retried
                // by the next scheduled occurrence with the current profile still active.
                jobs.AddOrUpdate<ManagedPrivacyProfileJob>(
                    ManagedPrivacyProfileJob.Id,
                    (job, token) => job.RunAsync(token),
                    Cron.Minutely());
                // Resolve immediately at start-up instead of waiting for the next minute:
                // register first (heartbeat), then fetch the assignment.
                jobs.Trigger(ManagementHeartbeatJob.Id);
                jobs.Trigger(ManagedPrivacyProfileJob.Id);
            }
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
                    EventIdentityConflicts conflicts,
                    IngestAuthentication authentication,
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
                                result.PolicyDecision.Score))
                    { Suppressed = result.Suppressed };

                    int statusCode = result.Action switch
                    {
                        DecisionAction.Accept or DecisionAction.RedactAndAccept => result.Duplicate ? 200 : 202,
                        DecisionAction.Reject => 422,
                        _ => 400
                    };
                    if (result.Reasons.Contains(EventIdentityConflicts.Reason, StringComparer.Ordinal))
                    {
                        conflicts.Record(producer, authentication.Required);
                        statusCode = StatusCodes.Status409Conflict;
                        response = response with { Remediation = EventIdentityConflicts.Remediation };
                    }
                    return Results.Json(response, CollectorJsonContext.Default.IngestResponse, statusCode: statusCode);
                })
            .AddEndpointFilter<IngestAuthenticationFilter>()
            .AddEndpointFilter<ManagedPrivacyProfileGateFilter>()
            .RequireRateLimiting("ingest");

        // Liveness for probes: status only, no queue metadata without a token.
        app.MapGet(
            "/health",
            async (IDurableEventStore eventQueue, SourceHealth sources, CancellationToken cancellationToken) =>
            {
                QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
                return Results.Json(new HealthResponse(Status(snapshot, sources.Evaluate())), CollectorJsonContext.Default.HealthResponse);
            });

        app.MapGet(
                "/v1/status",
                async (
                    IDurableEventStore eventQueue,
                    BackgroundJobCatalog jobs,
                    EventIdentityConflicts conflicts,
                    PolicyBundle bundle,
                    ManagedPrivacyProfileState managedPrivacy,
                    CollectorSettings settings,
                    PipelineTelemetry telemetry,
                    SourceHealth sourceHealth,
                    HttpContext context,
                    CancellationToken cancellationToken) =>
                {
                    QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
                    LedgerHead ledger = await eventQueue.GetLedgerHeadAsync(cancellationToken);
                    IReadOnlyList<SourceSilenceStatus> sources = sourceHealth.Evaluate();
                    StatusResponse status = new(
                        Status(snapshot, sources),
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
                            bundle.PrivacyProfile,
                            bundle.PrivacyProfileVersion,
                            bundle.PrivacyProfileHash ?? "default",
                            bundle.PrivacyProfileSource,
                            settings.UsesManagedPrivacyProfile ? managedPrivacy.State : null,
                            settings.UsesManagedPrivacyProfile ? managedPrivacy.Revision : null),
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
                        jobs.List())
                    {
                        EventIdentityConflicts = conflicts.Snapshot(),
                        Pipeline = telemetry.Snapshot(),
                        Intake = telemetry.IntakeSnapshot(),
                        Sources = sourceHealth.IsConfigured ? sources : null,
                        Delivery = (context.RequestServices.GetService<IOutputAdapter>() as IOutputConcurrencyStatus)
                            ?.GetConcurrencySnapshot()
                    };
                    return Results.Json(status, CollectorJsonContext.Default.StatusResponse);
                })
            .AddEndpointFilter<IngestAuthenticationFilter>();
    }

    private static string Status(QueueSnapshot snapshot, IReadOnlyList<SourceSilenceStatus> sources) =>
        snapshot.DeadLettered > 0 || sources.Any(source => source.IsOverdue) ? "degraded" : "healthy";

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
