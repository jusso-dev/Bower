using System.Globalization;
using System.Text.Json;
using System.Threading.RateLimiting;
using Azure.Core;
using Bower.Abstractions;
using Bower.Collector.Jobs;
using Bower.Collector.Relay;
using Bower.Contracts;
using Bower.Core;
using Bower.Forwarding;
using Bower.Jobs;
using Bower.Output.AmaSpool;
using Bower.Output.AmaSyslog;
using Bower.Output.AzureLogsIngestion;
using Bower.Output.Http;
using Bower.Output.S3;
using Bower.Packs;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Source.File;
using Bower.Source.Syslog;
using Bower.Source.WindowsEventLog;
using Microsoft.AspNetCore.RateLimiting;

namespace Bower.Collector;

/// <summary>Composes the collector host. Kept separate from Program for integration tests.</summary>
public static partial class CollectorApplication
{
    // A privacy refusal can remain deterministic until operator or producer remediation.
    private const string RedactionRetryAfterSeconds = "60";
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
        // Under the Windows service control manager (the MSI install) report start and stop
        // to it and write warnings and errors to the Application event log (source
        // Bower.Collector, registered by the MSI). A no-op everywhere else.
        builder.Services.AddWindowsService(options => options.ServiceName = "Bower");
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
        // Every other file a start reads, checked exactly as the signed reload pre-check does,
        // so a bad file stops start-up.
        CollectorStartupSources sources = CollectorStartupSources.Load(settings, bundle);
        // Management mode fails closed until the first sync resolves (see ManagedPrivacyProfileState).
        builder.Services.AddSingleton(settings.UsesManagedPrivacyProfile
            ? new ManagedPrivacyProfileState(cachedManagedProfile, settings.ManagedPrivacyAllowDefault)
            : ManagedPrivacyProfileState.Local);
        builder.Services.AddSingleton<IEventRedactor>(new PackDetectionRedactor(
            new JsonEventRedactor(bundle.Privacy), new DeterministicPolicyEvaluator(bundle.Policies),
            bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray()));
        // Free-space watermarks for the queue volume. Tests may supply an IDiskSpaceProbe.
        builder.Services.AddSingleton(services => new StorageGuard(
            settings.QueuePath,
            settings.StorageWatermarks,
            services.GetService<IDiskSpaceProbe>(),
            services.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<QueueStoragePressure>();
        builder.Services.AddSingleton<IDurableEventStore>(services =>
            new SqliteEventStore(
                settings.QueuePath,
                settings.MaximumQueueBytes,
                services.GetRequiredService<TimeProvider>(),
                services.GetRequiredService<StorageGuard>()));
        builder.Services.AddSingleton<ITelemetryPolicyEvaluator>(new DeterministicPolicyEvaluator(bundle.Policies));
        builder.Services.AddSingleton<PipelineTelemetry>();
        // Live post-redaction tap (bower tap). In memory only; never persisted.
        builder.Services.AddSingleton(services =>
            new EventTap(settings.TapOptions(), services.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<SecurityEventProcessor>();
        builder.Services.AddSingleton(services => new SourceHealth(
            sources.Expectations,
            services.GetRequiredService<PipelineTelemetry>(),
            services.GetRequiredService<TimeProvider>(),
            services.GetRequiredService<ILogger<SourceHealth>>()));
        builder.Services.AddHostedService<SuppressionWindowWorker>();
        if (settings.HealthRecordInterval is not null)
        {
            // Checked at build so a bundle that would refuse every health record stops start-up.
            RequireHealthRecordPolicy(settings, bundle);
            builder.Services.AddHostedService(services => new CollectorHealthWorker(
                services.GetRequiredService<SecurityEventProcessor>(),
                services.GetRequiredService<CollectorIdentity>(),
                services.GetRequiredService<IDurableEventStore>(),
                services.GetRequiredService<PipelineTelemetry>(),
                services.GetRequiredService<SourceHealth>(),
                services.GetRequiredService<DeliveryActivity>(),
                settings,
                services.GetRequiredService<TimeProvider>(),
                services.GetRequiredService<ILogger<CollectorHealthWorker>>(),
                services.GetService<SyslogSource>(),
                services.GetService<WindowsEventLogSource>(),
                services.GetRequiredService<ManagedPrivacyProfileState>(),
                services.GetRequiredService<QueueStoragePressure>(),
                services.GetService<IOutputAdapter>()));
        }
        builder.Services.AddHostedService<QueueStorageMonitor>();
        if (sources.Syslog is { } syslog)
        {
            builder.Services.AddSingleton(services => new SyslogSource(
                syslog,
                new CollectorSyslogSink(
                    bundle,
                    services.GetRequiredService<SecurityEventProcessor>(),
                    services.GetRequiredService<CollectorIdentity>(),
                    services.GetRequiredService<ManagedPrivacyProfileState>(),
                    services.GetRequiredService<PipelineTelemetry>(),
                    services.GetRequiredService<TimeProvider>(),
                    services.GetRequiredService<EventTap>()),
                services.GetRequiredService<TimeProvider>()));
            builder.Services.AddHostedService<SyslogIntakeService>();
        }
        if (sources.WindowsEventLog is { } windowsEventLog)
        {
            // Bookmarks live with the queue, so a restart resumes where the queue left off.
            builder.Services.AddSingleton(new WindowsEventLogBookmarks(settings.QueuePath));
            builder.Services.AddSingleton(services => new WindowsEventLogSource(
                windowsEventLog,
                new CollectorWindowsEventSink(new PackRecordIntake(
                    bundle,
                    services.GetRequiredService<SecurityEventProcessor>(),
                    services.GetRequiredService<CollectorIdentity>(),
                    services.GetRequiredService<ManagedPrivacyProfileState>(),
                    services.GetRequiredService<PipelineTelemetry>(),
                    services.GetRequiredService<TimeProvider>(),
                    services.GetRequiredService<EventTap>()),
                    services.GetRequiredService<IDurableEventStore>() as SqliteEventStore),
                services.GetRequiredService<WindowsEventLogBookmarks>().Store,
                // Tests supply an in-memory channel; otherwise the Windows reader (Windows only).
                services.GetService<IWindowsEventChannelFactory>() ?? WindowsEventLogRoutes.PlatformChannels(),
                services.GetRequiredService<TimeProvider>())
            {
                // A busy queue database (for example during a retention batch) is backpressure.
                IsTransientStorageFailure = QueueStorageErrors.IsBusy
            });
            builder.Services.AddHostedService<WindowsEventLogIntakeService>();
        }
        if (sources.FileTail is { } fileTail)
        {
            // Cursors live with the queue, so a restart resumes where the queue left off.
            builder.Services.AddSingleton(new FileTailCursors(settings.QueuePath));
            builder.Services.AddSingleton(services => new FileTailSource(
                fileTail,
                new CollectorFileTailSink(new PackRecordIntake(
                    bundle,
                    services.GetRequiredService<SecurityEventProcessor>(),
                    services.GetRequiredService<CollectorIdentity>(),
                    services.GetRequiredService<ManagedPrivacyProfileState>(),
                    services.GetRequiredService<PipelineTelemetry>(),
                    services.GetRequiredService<TimeProvider>(),
                    services.GetRequiredService<EventTap>())),
                services.GetRequiredService<FileTailCursors>().Store,
                services.GetRequiredService<TimeProvider>())
            {
                // A busy queue database (for example during a retention batch) is backpressure.
                IsTransientStorageFailure = QueueStorageErrors.IsBusy,
                // Metadata only: the input id and a reason code, never a path.
                InputRefused = FileTailIntakeService.Refused(services.GetRequiredService<ILogger<FileTailIntakeService>>())
            });
            builder.Services.AddHostedService<FileTailIntakeService>();
        }
        builder.Services.AddSingleton<EventIdentityConflicts>();
        builder.Services.AddSingleton(
            new CollectorIdentity(settings.CollectorId, settings.Version, "local-http", settings.ConfigurationHash()));
        builder.Services.AddSingleton(sources.Producers);
        builder.Services.AddSingleton(sources.Ingest);
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
        // Downstream of a relay: the client certificate and CA bundle are read here, so a bad
        // file stops start-up.
        RelayHttp? relayHttp = string.Equals(settings.OutputType, "relay", StringComparison.Ordinal)
            ? new RelayHttp(settings)
            : null;
        if (relayHttp is not null)
        {
            builder.Services.AddSingleton(relayHttp);
        }

        bool ownsOutput = output is null;
        output ??= CreateOutput(settings, credential, relayHttp);
        if (output is not null)
        {
            if (ownsOutput)
            {
                // A factory registration: the container disposes what it built (the syslog
                // socket, the S3 and HTTP clients) when the host stops. An instance passed in by
                // a caller stays the caller's to dispose.
                IOutputAdapter created = output;
                builder.Services.AddSingleton(_ => created);
            }
            else
            {
                builder.Services.AddSingleton(output);
            }

            builder.Services.AddSingleton(settings.DeliveryOptions());
            builder.Services.AddHostedService<QueueDeliveryWorker>();
        }

        if (settings.IsRelay)
        {
            // Relay role. The pins and the server certificate are read here, so a bad file
            // stops start-up; the listener starts with the host, after queue initialisation.
            RelayDownstreams downstreams = sources.RelayDownstreams!;
            builder.Services.AddSingleton(downstreams);
            builder.Services.AddSingleton(new RelayTelemetry(downstreams.CollectorIds));
            builder.Services.AddSingleton<RelayIntake>();
            builder.Services.AddSingleton<RelayListener>();
            builder.Services.AddHostedService(services => services.GetRequiredService<RelayListener>());
        }

        builder.Services.AddBowerBackgroundJobs($"bower-collector:{settings.CollectorId}");
        builder.Services.AddTransient<QueueRetentionJob>();
        builder.Services.AddTransient<QueueMaintenanceJob>();
        builder.Services.AddTransient<TemporaryFileSweepJob>();
        builder.Services.AddSingleton<CrashRecoveryState>();
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
            if (settings.UsesEnrolment)
            {
                // No Azure identity: a key-bound credential from a one-time enrolment token.
                builder.Services.AddSingleton<ManagementEnrolment>();
                builder.Services.AddSingleton<TokenCredential>(services => credential
                    ?? new EnrolledManagementCredential(
                        services.GetRequiredService<ManagementEnrolment>(),
                        services.GetRequiredService<TimeProvider>()));
            }
            else
            {
                builder.Services.AddSingleton(credential ?? AzureCredentialFactory.Create(settings));
            }

            // Proxy and CA bundle are read here, so a bad proxy password file or CA bundle stops start-up.
            SocketsHttpHandler managementHandler = ManagementHttp.CreateHandler(settings);
            if (settings.ManagementViaRelay)
            {
                // Every management request (enrolment, heartbeat, profile) through the relay's
                // tunnel; TLS to management stays end to end.
                relayHttp!.UseTunnel(managementHandler);
            }

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

        if (app.Services.GetService<IOutputAdapter>() is AmaSyslogOutput syslog)
        {
            // Do not stop start-up: the daemon may come up later and the queue is durable. Say
            // once, by path and error class, what delivery will report as unavailable.
            if (syslog.Probe() is { } problem)
            {
                LogSyslogSocketUnavailable(app.Logger, settings.AmaSyslogSocket, problem);
            }

            string facility = AmaSyslogOutputOptions.FacilityName(settings.AmaSyslogFacility!.Value);
            LogSyslogOutput(app.Logger, settings.AmaSyslogSocket, facility, settings.AmaSyslogMaximumBytes);
        }

        IDurableEventStore queue = app.Services.GetRequiredService<IDurableEventStore>();
        await queue.InitializeAsync(cancellationToken);
        await RecoverFromUncleanShutdownAsync(app, settings, queue, cancellationToken);
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
        jobs.AddOrUpdate<TemporaryFileSweepJob>(
            TemporaryFileSweepJob.Id,
            (job, token) => job.RunAsync(token),
            Cron.Hourly());
        if (settings.ManagementEndpoint is not null)
        {
            // Parses the trusted command keys now, so an invalid key is reported at start-up.
            _ = app.Services.GetRequiredService<ManagementCommandProcessor>();
            // A missed heartbeat is superseded by the next scheduled run; never retry-stack.
            jobs.AddOrUpdate<ManagementHeartbeatJob>(
                ManagementHeartbeatJob.Id,
                (job, token) => job.RunAsync(token),
                Cron.Minutely());
            if (settings.UsesEnrolment)
            {
                // Enrol (or report) straight away rather than at the next minute.
                jobs.Trigger(ManagementHeartbeatJob.Id);
            }

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

    /// <summary>
    /// Run marker, ledger check after an unclean shutdown and the first temporary-file sweep
    /// (#138). The marker is removed when the host stops cleanly.
    /// </summary>
    private static async Task RecoverFromUncleanShutdownAsync(
        WebApplication app, CollectorSettings settings, IDurableEventStore queue, CancellationToken cancellationToken)
    {
        TimeProvider clock = app.Services.GetRequiredService<TimeProvider>();
        string marker = CrashRecovery.MarkerPath(settings.QueuePath);
        DateTimeOffset? previous = CrashRecovery.BeginRun(marker, clock.GetUtcNow());
        app.Lifetime.ApplicationStopped.Register(() => CrashRecovery.EndRun(marker));
        int removed = CrashRecovery.SweepTemporaryFiles(TemporaryFileSweepJob.Directories(settings), clock.GetUtcNow());
        if (removed > 0)
        {
            CrashRecoveryLog.TemporaryFilesRemoved(app.Logger, removed);
        }

        CrashRecoveryStatus status = await CrashRecovery.RecoverAsync(queue, previous, removed, clock.GetUtcNow(), cancellationToken);
        app.Services.GetRequiredService<CrashRecoveryState>().Last = status;
        if (status.UncleanShutdown)
        {
            CrashRecoveryLog.Unclean(app.Logger,
                status.PreviousStartedAt?.ToString("O", CultureInfo.InvariantCulture) ?? "unknown",
                status.LedgerIntact == true, status.LedgerIssues);
            if (status.LedgerIntact == false)
            {
                CrashRecoveryLog.LedgerBroken(app.Logger, status.LedgerIssues);
            }
        }
    }

    private static void MapEndpoints(WebApplication app)
    {
        MapPackEndpoints(app);
        MapTapEndpoints(app);
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
                        // Origin only from a producer the operator trusts to report it (the cloud
                        // forwarder); never from the event, so an application cannot choose it.
                        EventOrigin? origin = OriginHeader.Read(
                            context.Request.Headers[OriginHeader.Name].ToString(), producer,
                            context.RequestServices.GetRequiredService<CollectorSettings>().OriginProducers);
                        result = await processor.ProcessAsync(
                            candidate.GetRawText(),
                            identity with { SourceAdapter = $"local-http:{producer}", Origin = origin },
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

                    int statusCode = result.RedactionRetryRequired ? StatusCodes.Status503ServiceUnavailable : result.Action switch
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
                    if (statusCode == StatusCodes.Status503ServiceUnavailable && result.RedactionRetryRequired)
                    {
                        context.Response.Headers.RetryAfter = RedactionRetryAfterSeconds;
                    }
                    return Results.Json(response, CollectorJsonContext.Default.IngestResponse, statusCode: statusCode);
                })
            .AddEndpointFilter<IngestAuthenticationFilter>()
            .AddEndpointFilter<ManagedPrivacyProfileGateFilter>()
            .RequireRateLimiting("ingest");

        // Process liveness: answers while the host serves requests and touches no storage, so a
        // busy or locked queue database never restarts a working collector. Metadata-free.
        app.MapGet(
            "/health/live",
            () => Results.Json(new HealthResponse("alive"), CollectorJsonContext.Default.HealthResponse));

        // Readiness and status for probes: status only, no queue metadata without a token.
        app.MapGet(
            "/health",
            async (IDurableEventStore eventQueue, SourceHealth sources, StorageGuard storage, CancellationToken cancellationToken) =>
            {
                QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
                return Results.Json(
                    new HealthResponse(Status(snapshot, sources.Evaluate(), storage.Evaluate().State)),
                    CollectorJsonContext.Default.HealthResponse);
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
                    StorageGuard storage,
                    QueueStoragePressure pressure,
                    TimeProvider clock,
                    HttpContext context,
                    CancellationToken cancellationToken) =>
                {
                    QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
                    LedgerHead ledger = await eventQueue.GetLedgerHeadAsync(cancellationToken);
                    IReadOnlyList<SourceSilenceStatus> sources = sourceHealth.Evaluate();
                    DeliveryActivity activity = context.RequestServices.GetRequiredService<DeliveryActivity>();
                    DeliveryFailureActivity? lastFailure = activity.LastFailure;
                    // Read once: queuePages and the storage block report the same page use.
                    QueuePageUsage? pages = await QueueStorageStatus.TryReadPagesAsync(eventQueue, cancellationToken);
                    StatusResponse status = new(
                        Status(snapshot, sources, storage.Evaluate().State),
                        settings.Version,
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
                            ?.GetConcurrencySnapshot(),
                        Syslog = context.RequestServices.GetService<SyslogSource>()?.Snapshot(),
                        Relay = context.RequestServices.GetService<RelayTelemetry>()?.Snapshot(),
                        Activity = telemetry.BusiestSources(),
                        Tap = context.RequestServices.GetRequiredService<EventTap>().Snapshot(),
                        WindowsEventLog = context.RequestServices.GetService<WindowsEventLogSource>()?.Snapshot(),
                        FileTail = context.RequestServices.GetService<FileTailSource>()?.Snapshot(),
                        QueuePages = pages is null ? null : StatusQueuePagesResponse.From(pages),
                        Output = context.RequestServices.GetService<IOutputAdapter>()?.Id,
                        DeliveryActivity = new StatusDeliveryActivityResponse(
                            activity.LastSuccessfulDeliveryAt, lastFailure?.Code, lastFailure?.At),
                        Storage = await QueueStorageStatus.TryCaptureAsync(
                            eventQueue, snapshot, pressure, telemetry, clock.GetUtcNow(), pages, cancellationToken),
                        Recovery = context.RequestServices.GetRequiredService<CrashRecoveryState>().Last
                    };
                    return Results.Json(status, CollectorJsonContext.Default.StatusResponse);
                })
            .AddEndpointFilter<IngestAuthenticationFilter>();
    }

    /// <summary>
    /// Health records go through policy like any event. Fail closed at start-up when the
    /// loaded bundle would refuse one, instead of refusing a record every interval: a healthy
    /// record and degraded ones of every severity (result failure; low, medium, high), since a
    /// bundle that refused only those would hide exactly the records the alerts need.
    /// </summary>
    internal static void RequireHealthRecordPolicy(CollectorSettings settings, PolicyBundle bundle)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        long capacity = settings.MaximumQueueBytes;
        CollectorHealthSample healthy = new(
            now, now, 1, settings.HealthRecordInterval ?? TimeSpan.FromMinutes(5), settings.OutputType, "waiting", null,
            new QueueSnapshot(0, 0, 0, 0, 0, 0, null), capacity,
            new IntakeMetricsSnapshot(now, 0, 0, 0, 0, 0, 0, null, null),
            new PipelineMetricsSnapshot(now, 0, 0, 0, 0, 0, 0, []),
            false, [], null, null);
        CollectorHealthSample[] probes =
        [
            healthy,
            // Low: retries only.
            healthy with { OutputType = "azure-logs-ingestion", Queue = new QueueSnapshot(0, 1, 0, 0, 0, 1, now, 1) },
            // Medium: dead letters.
            healthy with { OutputType = "azure-logs-ingestion", Queue = new QueueSnapshot(0, 0, 0, 0, 1, 1, null) },
            // High: backpressure and a stall.
            healthy with
            {
                OutputType = "azure-logs-ingestion",
                Queue = new QueueSnapshot(1, 0, 0, 0, 0, capacity, now.AddHours(-1), capacity)
            }
        ];
        DeterministicPolicyEvaluator evaluator = new(bundle.Policies);
        foreach (CollectorHealthSample probe in probes)
        {
            SecurityEventEnvelope record = CollectorHealthRecord.Create(probe, settings.CollectorId, settings.Environment);
            PolicyDecision decision = evaluator.Evaluate(record);
            if (decision.Action is not (DecisionAction.Accept or DecisionAction.RedactAndAccept))
            {
                throw new InvalidOperationException(
                    "BOWER_HEALTH_RECORD_INTERVAL_SECONDS is set but no loaded policy accepts collector_health " +
                    $"records with result {record.EventResult} and severity {record.EventSeverity} " +
                    $"(decision {PipelineTelemetry.ActionName(decision.Action)}). Add " +
                    "examples/policies/collector-health/collector-health.yaml to the policy directory or set the interval to 0.");
            }
        }
    }

    private static string Status(QueueSnapshot snapshot, IReadOnlyList<SourceSilenceStatus> sources, StorageState storage) =>
        snapshot.DeadLettered > 0 || sources.Any(source => source.IsOverdue) || storage == StorageState.Critical
            ? "degraded"
            : "healthy";

    private static IOutputAdapter? CreateOutput(CollectorSettings settings, TokenCredential? credential, RelayHttp? relay)
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
            "relay" => new RelayOutput(
                new HttpClient(relay!.CreateBatchHandler())
                {
                    BaseAddress = relay.RelayUrl,
                    // The relay commits every event (fsync) before it answers.
                    Timeout = TimeSpan.FromSeconds(60)
                },
                settings.CollectorId),
            "s3" => new S3Output(settings.S3Output! with { CollectorId = settings.CollectorId }),
            "ama-syslog" => new AmaSyslogOutput(new AmaSyslogOutputOptions
            {
                Id = "ama-syslog",
                SocketPath = settings.AmaSyslogSocket,
                Facility = settings.AmaSyslogFacility!.Value,
                MaximumMessageBytes = settings.AmaSyslogMaximumBytes,
                BusyWait = settings.AmaSyslogBusyWait
            }),
            // The token and CA bundle are read here, so a bad file stops start-up.
            HttpOutput.OutputId => new HttpOutput(
                settings.HttpOutput!.Options(settings.CollectorId), settings.HttpOutput.ReadToken()),
            _ => throw new InvalidOperationException($"Unsupported BOWER_OUTPUT value: {settings.OutputType}")
        };
    }

    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Warning,
        Message = "Collector ingest authentication is disabled on a non-loopback listener. " +
            "Use BOWER_ALLOW_UNAUTHENTICATED_INGEST only on an isolated network.")]
    private static partial void LogUnauthenticatedIngest(ILogger logger);

    [LoggerMessage(
        EventId = 1010,
        Level = LogLevel.Warning,
        Message = "AMA syslog output socket {SocketPath} does not accept connections ({SocketError}). Events stay queued and are retried; check that the syslog daemon is running and the path is right.")]
    private static partial void LogSyslogSocketUnavailable(ILogger logger, string socketPath, string socketError);

    [LoggerMessage(
        EventId = 1011,
        Level = LogLevel.Information,
        Message = "AMA syslog output writes to {SocketPath} on facility {Facility}, at most {MaximumBytes} bytes per message. The collection rule's facility must match.")]
    private static partial void LogSyslogOutput(ILogger logger, string socketPath, string facility, int maximumBytes);
}
