using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Bower.Jobs;
using Bower.Management.Api.Jobs;
using Bower.Pipeline;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Bower.Management.Api;

/// <summary>Composes the management API host. Kept separate from Program for integration tests.</summary>
public static class ManagementApplication
{
    /// <summary>Default scheme: forwards to the collector credential or the interactive scheme.</summary>
    public const string SelectorScheme = "Bower";

    public static WebApplication Build(
        string[] args,
        Action<WebApplicationBuilder>? configure = null,
        string? environmentName = null)
    {
        // Slim builder: no reflection-based startup, as Native AOT requires. HTTPS endpoint
        // configuration is opted back in because TLS may terminate at Kestrel.
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = args,
            EnvironmentName = environmentName
        });
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            // Source-generated metadata only (Native AOT): no reflection fallback.
            options.SerializerOptions.TypeInfoResolverChain.Clear();
            options.SerializerOptions.TypeInfoResolverChain.Add(ManagementJsonContext.Default);
            // Enum names as written, integers rejected (one converter per wire enum).
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter<CollectorStatus>(null, false));
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter<PipelineNodeKind>(null, false));
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter<CustomLogFormat>(null, false));
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter<CustomLogValueType>(null, false));
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter<PrivacyProfileVersionStatus>(null, false));
        });
        builder.WebHost.UseUrls(
            Environment.GetEnvironmentVariable("BOWER_MANAGEMENT_LISTEN_URL")
            ?? "http://127.0.0.1:4320");
        builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

        bool developmentAuthentication = string.Equals(
            builder.Configuration["BOWER_AUTH_MODE"],
            "development",
            StringComparison.OrdinalIgnoreCase);
        if (developmentAuthentication && !builder.Environment.IsDevelopment())
        {
            throw new InvalidOperationException(
                "BOWER_AUTH_MODE=development is allowed only in the Development environment.");
        }

        // A policy scheme picks the handler per request: enrolled-collector assertions go to
        // the credential handler, everything else to Entra (or development) authentication.
        string interactiveScheme = developmentAuthentication
            ? DevelopmentAuthenticationHandler.AuthenticationScheme
            : JwtBearerDefaults.AuthenticationScheme;
        AuthenticationBuilder authentication = builder.Services
            .AddAuthentication(SelectorScheme)
            .AddPolicyScheme(SelectorScheme, SelectorScheme, options =>
                options.ForwardDefaultSelector = context => CollectorEnrolment.HasAssertion(context.Request)
                    ? CollectorCredentialAuthenticationHandler.SchemeName
                    : interactiveScheme)
            .AddScheme<AuthenticationSchemeOptions, CollectorCredentialAuthenticationHandler>(
                CollectorCredentialAuthenticationHandler.SchemeName,
                _ => { });
        if (developmentAuthentication)
        {
            authentication.AddScheme<AuthenticationSchemeOptions, DevelopmentAuthenticationHandler>(
                DevelopmentAuthenticationHandler.AuthenticationScheme,
                _ => { });
        }
        else
        {
            string tenantId = RequiredConfiguration(builder.Configuration, "Bower:Entra:TenantId");
            string audience = RequiredConfiguration(builder.Configuration, "Bower:Entra:Audience");
            authentication.AddJwtBearer(options =>
            {
                options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
                options.Audience = audience;
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "roles",
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true
                };
            });
        }

        builder.Services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            options.AddPolicy("View", policy => policy.RequireRole(BowerRoles.Interactive));
            options.AddPolicy(
                "Operate",
                policy => policy.RequireRole(
                    BowerRoles.Operator,
                    BowerRoles.Approver,
                    BowerRoles.Administrator));
            options.AddPolicy(
                "Approve",
                policy => policy.RequireRole(BowerRoles.Approver, BowerRoles.Administrator));
            options.AddPolicy("Administer", policy => policy.RequireRole(BowerRoles.Administrator));
            options.AddPolicy("Collector", policy => policy.RequireRole(BowerRoles.Collector));
            // Only a key-bound credential can rotate itself; Entra collectors have none.
            options.AddPolicy(
                "EnrolledCollector",
                policy => policy.RequireRole(BowerRoles.Collector).RequireClaim(CollectorEnrolment.CredentialIdClaim));
        });

        string databasePath = builder.Configuration["BOWER_MANAGEMENT_DB_PATH"]
            ?? Path.Combine(AppContext.BaseDirectory, "data", "management.db");
        builder.Services.AddSingleton(new ManagementStore(databasePath));
        builder.Services.AddSingleton(TimeProvider.System);
        // Optional: without a key the deployment endpoint answers 503 and all else works.
        builder.Services.AddSingleton(ManagedPrivacyProfileSigner.FromFile(
            builder.Configuration[ManagedPrivacyProfileSigner.KeyFileSetting]));
        // Optional: without a key commands cannot be issued (503) and all else works.
        builder.Services.AddSingleton(ManagementCommandSigner.FromFile(
            builder.Configuration[ManagementCommandSigner.KeyFileSetting]));

        string[] allowedOrigins = builder.Configuration
            .GetSection("Bower:AllowedOrigins")
            .Get<string[]>()
            ?? ["http://localhost:5173"];
        builder.Services.AddCors(options =>
            options.AddDefaultPolicy(policy =>
                policy.WithOrigins(allowedOrigins)
                    .WithHeaders("Authorization", "Content-Type")
                    .WithMethods("GET", "POST")));

        int requestsPerMinute = builder.Configuration.GetValue("BOWER_MANAGEMENT_RATE_PER_MINUTE", 600);
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            // Partition by authenticated principal, falling back to the client address.
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.User.FindFirstValue("oid")
                        ?? context.Connection.RemoteIpAddress?.ToString()
                        ?? "anonymous",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = requestsPerMinute,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
            // Enrolment is anonymous (the token is the credential), so it gets a far tighter
            // per-address budget: every refused token writes an audit row.
            options.AddPolicy(EnrolmentEndpoints.RateLimitPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = builder.Configuration.GetValue("BOWER_MANAGEMENT_ENROLMENT_RATE_PER_MINUTE", 10),
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
        });
        builder.Services.AddHsts(options =>
        {
            options.MaxAge = TimeSpan.FromDays(365);
            options.IncludeSubDomains = true;
        });

        // Onboarding canary: opt-in server configuration; invalid values fail start-up.
        builder.Services.AddSingleton(SetupCanaryOptions.FromConfiguration(builder.Configuration));
        builder.Services.AddSingleton(new SetupEnvironment(
            developmentAuthentication,
            builder.Configuration["Bower:Entra:TenantId"],
            builder.Configuration["Bower:Entra:Audience"]));
        builder.Services.AddSingleton<ISetupEvidenceClientFactory, SetupEvidenceClientFactory>();
        builder.Services.AddSingleton<SetupCanaryService>();

        builder.Services.AddBowerBackgroundJobs("bower-management", workerCount: 1);
        builder.Services.AddTransient<CollectorStalenessJob>();
        builder.Services.AddTransient<CollectorInactivityJob>();

        configure?.Invoke(builder);

        WebApplication app = builder.Build();
        if (!app.Environment.IsDevelopment())
        {
            // Emitted only on HTTPS requests; TLS terminates at Kestrel or the proxy.
            app.UseHsts();
        }

        app.Use(
            async (context, next) =>
            {
                context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
                context.Response.Headers.Append("Referrer-Policy", "no-referrer");
                context.Response.Headers.Append("X-Frame-Options", "DENY");
                context.Response.Headers.Append(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=()");
                context.Response.Headers.Append(
                    "Content-Security-Policy",
                    "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; " +
                    "form-action 'self'; img-src 'self' data:; font-src 'self'; " +
                    "style-src 'self'; script-src 'self'; " +
                    "connect-src 'self' https://login.microsoftonline.com; " +
                    "frame-src https://login.microsoftonline.com;");
                await next(context);
            });
        // Runtime console settings (public SPA values, never secrets) so one published image
        // serves any tenant. Falls back to the bundled static config.js when unset.
        string? consoleConfig = ConsoleConfigScript(builder.Configuration, developmentAuthentication);
        if (consoleConfig is not null)
        {
            app.Use(async (context, next) =>
            {
                if (HttpMethods.IsGet(context.Request.Method)
                    && context.Request.Path.Equals("/config.js", StringComparison.Ordinal))
                {
                    context.Response.ContentType = "application/javascript; charset=utf-8";
                    context.Response.Headers.CacheControl = "no-store";
                    await context.Response.WriteAsync(consoleConfig);
                    return;
                }

                await next(context);
            });
        }

        // Public console assets are served before authentication: the fallback policy would
        // otherwise require a token for the JavaScript that performs the sign-in.
        string indexPath = Path.Combine(app.Environment.WebRootPath ?? string.Empty, "index.html");
        if (File.Exists(indexPath))
        {
            app.UseDefaultFiles();
            app.UseStaticFiles();
        }

        app.UseCors();
        app.UseAuthentication();
        app.UseRateLimiter();
        app.UseAuthorization();

        MapApi(app.MapGroup("/api"), developmentAuthentication);

        app.MapGet("/health", () => Results.Ok(new HealthResponse("healthy")))
            .AllowAnonymous()
            .DisableRateLimiting();

        if (File.Exists(indexPath))
        {
            app.MapFallbackToFile("index.html").AllowAnonymous();
        }

        return app;
    }

    /// <summary>Initialises storage and registers recurring jobs. Call before RunAsync.</summary>
    public static async Task InitializeAsync(WebApplication app, CancellationToken cancellationToken)
    {
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await store.InitializeAsync(cancellationToken);
        // A canary left running by a previous process can never complete.
        await store.InterruptSetupCanaryRunsAsync(
            app.Services.GetRequiredService<TimeProvider>().GetUtcNow(), cancellationToken);
        RecurringJobRegistry jobs = app.Services.GetRequiredService<RecurringJobRegistry>();
        jobs.AddOrUpdate<CollectorStalenessJob>(
            CollectorStalenessJob.Id,
            (job, token) => job.RunAsync(token),
            "*/5 * * * *",
            CollectorStalenessJob.RetryAttempts);
        jobs.AddOrUpdate<CollectorInactivityJob>(
            CollectorInactivityJob.Id,
            (job, token) => job.RunAsync(token),
            Cron.Daily(2),
            CollectorInactivityJob.RetryAttempts);
    }

    private static void MapApi(RouteGroupBuilder api, bool developmentAuthentication)
    {
        api.MapGet(
                "/access/me",
                (ClaimsPrincipal user) => new CurrentAccess(
                    ObjectId(user),
                    DisplayName(user),
                    user.FindAll("roles").Select(item => item.Value).Order().ToArray(),
                    developmentAuthentication))
            .RequireAuthorization("View");

        api.MapGet(
                "/overview",
                async (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                {
                    DateTimeOffset now = clock.GetUtcNow();
                    OverviewRecord overview = await store.OverviewAsync(
                        now - CollectorStalenessJob.StaleAfter,
                        cancellationToken);
                    return overview with
                    {
                        Exceptions = [.. overview.Exceptions.Select(record => CollectorConnectivity.With(record, now))]
                    };
                })
            .RequireAuthorization("View");

        // Plain-English home view: traffic lights, fixes and redaction counts, computed here.
        api.MapGet(
                "/home",
                async (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    await store.HomeAsync(clock.GetUtcNow(), cancellationToken))
            .RequireAuthorization("View");

        // Plain-English fleet view: one state, reason and fix per collector, computed here.
        api.MapGet(
                "/fleet",
                async (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    await store.FleetAsync(clock.GetUtcNow(), cancellationToken))
            .RequireAuthorization("View");

        api.MapGet(
                "/fleet/{id}",
                async (string id, ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    (await store.FleetAsync(clock.GetUtcNow(), cancellationToken)).Collectors
                        .FirstOrDefault(item => string.Equals(item.Id, id, StringComparison.Ordinal)) is { } collector
                        ? Results.Ok(collector)
                        : Results.NotFound())
            .RequireAuthorization("View");

        api.MapGet(
                "/collectors",
                async (
                    string? status,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    CollectorStatus? parsed = null;
                    if (!string.IsNullOrWhiteSpace(status))
                    {
                        if (!Enum.TryParse(status, true, out CollectorStatus value)
                            || !Enum.IsDefined(value))
                        {
                            return Results.BadRequest(new ErrorResponse("Unknown collector status."));
                        }

                        parsed = value;
                    }

                    DateTimeOffset now = clock.GetUtcNow();
                    return Results.Ok((await store.ListAsync(parsed, cancellationToken))
                        .Select(record => CollectorConnectivity.With(record, now))
                        .ToList());
                })
            .RequireAuthorization("View");

        api.MapGet(
                "/collectors/{id}",
                async (string id, ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    await store.GetAsync(id, cancellationToken) is { } record
                        ? Results.Ok(CollectorConnectivity.With(record, clock.GetUtcNow()))
                        : Results.NotFound())
            .RequireAuthorization("View");

        api.MapGet(
                "/collectors/{id}/commands",
                async (string id, ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    await store.GetAsync(id, cancellationToken) is null
                        ? Results.NotFound()
                        : Results.Ok(await store.ListCommandsAsync(id, clock.GetUtcNow(), cancellationToken)))
            .RequireAuthorization("View");

        api.MapPost(
                "/collectors/{id}/commands",
                IssueCommandAsync)
            .RequireAuthorization("Operate");

        api.MapPost(
                "/collectors/register",
                async (
                    CollectorRegistration registration,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!CollectorEnrolment.MayActFor(user, registration.CollectorId))
                    {
                        return Results.Forbid();
                    }

                    try
                    {
                        CollectorRecord record = await store.RegisterAsync(
                            registration,
                            ObjectId(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        return Results.Accepted($"/api/collectors/{record.Id}", record);
                    }
                    catch (CollectorIdentityConflictException)
                    {
                        return Results.Conflict(
                            new ErrorResponse("Collector id is bound to a different principal."));
                    }
                    catch (CollectorStateException)
                    {
                        return Results.Forbid();
                    }
                    catch (ArgumentException)
                    {
                        return Results.ValidationProblem(
                            new Dictionary<string, string[]>
                            {
                                ["registration"] = ["Collector registration is invalid."]
                            });
                    }
                })
            .RequireAuthorization("Collector");

        api.MapPost(
                "/collectors/{id}/heartbeat",
                async (
                    string id,
                    CollectorHeartbeat heartbeat,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!CollectorEnrolment.MayActFor(user, id))
                    {
                        return Results.Forbid();
                    }

                    try
                    {
                        HeartbeatExchange? exchange = await store.ExchangeHeartbeatAsync(
                            id,
                            heartbeat,
                            ObjectId(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        if (exchange is null)
                        {
                            return Results.NotFound();
                        }

                        // v1 collectors keep receiving the collector record they always did.
                        return heartbeat.IsV2
                            ? Results.Ok(new HeartbeatResponse(
                                2,
                                exchange.Record.Id,
                                exchange.Record.Status,
                                exchange.Commands,
                                exchange.AcknowledgedResults))
                            : Results.Ok(exchange.Record);
                    }
                    catch (CollectorStateException)
                    {
                        return Results.Conflict(
                            new ErrorResponse("Collector is not approved to send heartbeats."));
                    }
                    catch (ArgumentException)
                    {
                        return Results.ValidationProblem(
                            new Dictionary<string, string[]>
                            {
                                ["heartbeat"] = ["Collector heartbeat is invalid."]
                            });
                    }
                })
            .RequireAuthorization("Collector");

        api.MapGet(
                "/pipelines/templates",
                () => Results.Ok(
                    new[]
                    {
                        PipelineValidator.CreateTemplate("sentinel-app"),
                        PipelineValidator.CreateTemplate("aws-security")
                    }))
            .RequireAuthorization("View");

        api.MapPost(
                "/pipelines/validate",
                (TelemetryPipeline pipeline) =>
                {
                    PipelineValidationResult validation = PipelineValidator.Validate(pipeline);
                    PipelinePerformanceEstimate? estimate = PipelineValidator.TryEstimate(pipeline);
                    return Results.Ok(
                        new PipelineValidationResponse(
                            validation.IsValid,
                            validation.Issues,
                            validation.TopologicalOrder,
                            estimate));
                })
            .RequireAuthorization("Operate");

        api.MapPost(
                "/custom-logs/generate",
                async (CustomLogInput input, CancellationToken cancellationToken) =>
                {
                    try
                    {
                        string sample = await CustomLogSampleReader.ReadAsync(
                            input,
                            Environment.GetEnvironmentVariable("BOWER_CUSTOM_LOG_ROOTS"),
                            cancellationToken);
                        return Results.Ok(CustomLogParser.Generate(sample));
                    }
                    catch (Exception exception) when (IsCustomLogInputError(exception))
                    {
                        return Results.BadRequest(new ErrorResponse(CustomLogError(exception)));
                    }
                })
            .WithMetadata(new RequestSizeLimitAttribute(600 * 1024))
            .RequireAuthorization("Operate");

        api.MapPost(
                "/custom-logs/preview",
                async (CustomLogPreviewRequest request, CancellationToken cancellationToken) =>
                {
                    try
                    {
                        string sample = await CustomLogSampleReader.ReadAsync(
                            request.Input,
                            Environment.GetEnvironmentVariable("BOWER_CUSTOM_LOG_ROOTS"),
                            cancellationToken);
                        return Results.Ok(CustomLogParser.Preview(request.Configuration, sample));
                    }
                    catch (Exception exception) when (IsCustomLogInputError(exception))
                    {
                        return Results.BadRequest(new ErrorResponse(CustomLogError(exception)));
                    }
                })
            .WithMetadata(new RequestSizeLimitAttribute(600 * 1024))
            .RequireAuthorization("Operate");

        api.MapGet(
                "/approvals",
                (ManagementStore store, CancellationToken cancellationToken) =>
                    store.ListApprovalsAsync(cancellationToken))
            .RequireAuthorization("View");

        api.MapPost(
                "/approvals/{collectorId}/approve",
                (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    DecideAsync(
                        collectorId, CollectorStatus.Approved, "approved", request, user, store,
                        clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapPost(
                "/approvals/{collectorId}/reject",
                (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    DecideAsync(
                        collectorId, CollectorStatus.Revoked, "rejected", request, user, store,
                        clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapPost(
                "/collectors/{collectorId}/suspend",
                (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    DecideAsync(
                        collectorId, CollectorStatus.Suspended, "suspended", request, user, store,
                        clock, cancellationToken))
            .RequireAuthorization("Administer");

        api.MapPost(
                "/collectors/{collectorId}/revoke",
                (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    DecideAsync(
                        collectorId, CollectorStatus.Revoked, "revoked", request, user, store,
                        clock, cancellationToken))
            .RequireAuthorization("Administer");

        api.MapPost(
                "/collectors/{collectorId}/reinstate",
                (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    DecideAsync(
                        collectorId, CollectorStatus.Approved, "reinstated", request, user, store,
                        clock, cancellationToken))
            .RequireAuthorization("Administer");

        api.MapPost(
                "/collectors/{collectorId}/desired-policy",
                async (
                    string collectorId,
                    DesiredPolicyRequest request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    try
                    {
                        CollectorRecord? record = await store.SetDesiredPolicyAsync(
                            collectorId,
                            string.IsNullOrWhiteSpace(request.PolicyHash) ? null : request.PolicyHash.Trim(),
                            request.Reason,
                            ObjectId(user),
                            DisplayName(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        return record is null ? Results.NotFound() : Results.Ok(record);
                    }
                    catch (ArgumentException)
                    {
                        return Results.ValidationProblem(
                            new Dictionary<string, string[]>
                            {
                                ["desiredPolicy"] = ["A sha256: policy hash (or empty to clear) and a 1–500 character reason are required."]
                            });
                    }
                })
            .RequireAuthorization("Administer");

        PrivacyProfileEndpoints.Map(api);
        SetupEndpoints.Map(api);
        EnrolmentEndpoints.Map(api);

        api.MapGet(
                "/audit",
                (ManagementStore store, CancellationToken cancellationToken) =>
                    store.ListAuditAsync(cancellationToken))
            .RequireAuthorization("View");

        api.MapGet("/jobs", (BackgroundJobCatalog jobs) => Results.Ok(jobs.List()))
            .RequireAuthorization("View");

        api.MapPost(
                "/jobs/{id}/trigger",
                async (
                    string id,
                    ClaimsPrincipal user,
                    RecurringJobRegistry jobs,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!jobs.Trigger(id))
                    {
                        return Results.NotFound();
                    }

                    await store.RecordAuditAsync(
                        "job.triggered",
                        "job",
                        id,
                        ObjectId(user),
                        DisplayName(user),
                        clock.GetUtcNow(),
                        cancellationToken);
                    return Results.Accepted();
                })
            .RequireAuthorization("Administer");
    }

    /// <summary>
    /// Builds window.__BOWER_CONFIG__ from Bower:Console:* settings, or null when none are
    /// set. System.Text.Json escapes HTML-sensitive characters, so values cannot break out.
    /// </summary>
    internal static string? ConsoleConfigScript(IConfiguration configuration, bool developmentAuthentication)
    {
        IConfigurationSection console = configuration.GetSection("Bower:Console");
        string? clientId = console["ClientId"];
        if (string.IsNullOrWhiteSpace(clientId) && !developmentAuthentication)
        {
            return null;
        }

        Dictionary<string, string> values = new(StringComparer.Ordinal)
        {
            ["authMode"] = developmentAuthentication ? "development" : "entra",
            ["apiBaseUrl"] = string.Empty,
            ["entraTenantId"] = configuration["Bower:Entra:TenantId"] ?? string.Empty,
            ["entraClientId"] = clientId ?? string.Empty,
            ["entraApiScope"] = console["ApiScope"] ?? string.Empty,
            ["entraRedirectUri"] = console["RedirectUri"] ?? string.Empty
        };
        return $"window.__BOWER_CONFIG__ = {System.Text.Json.JsonSerializer.Serialize(values, ManagementJsonContext.Default.DictionaryStringString)};\n";
    }

    private static bool IsCustomLogInputError(Exception exception) =>
        exception is ArgumentException
            or InvalidDataException
            or InvalidOperationException
            or UnauthorizedAccessException
            or FileNotFoundException;

    /// <summary>
    /// Only Bower-authored validation messages reach the client. Framework exceptions can
    /// carry server paths or internal detail, so they map to fixed messages.
    /// </summary>
    private static string CustomLogError(Exception exception) =>
        exception switch
        {
            InvalidDataException => exception.Message,
            CustomLogInputException => exception.Message,
            UnauthorizedAccessException =>
                "Server path is outside configured custom-log roots or uses a symbolic link.",
            FileNotFoundException => "Custom-log sample file was not found.",
            _ => "Custom-log request is invalid."
        };

    /// <summary>
    /// Issues a command from the closed set. Unknown commands are refused and audited.
    /// <c>reload</c> and <c>rotate-credential</c> need an administrator.
    /// </summary>
    private static async Task<IResult> IssueCommandAsync(
        string id,
        CollectorCommandRequest request,
        ClaimsPrincipal user,
        ManagementStore store,
        ManagementCommandSigner signer,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        string command = request.Command?.Trim() ?? string.Empty;
        if (!CollectorCommandTypes.All.Contains(command, StringComparer.Ordinal))
        {
            if (await store.GetAsync(id, cancellationToken) is not null)
            {
                await store.RecordAuditAsync(
                    "collector.command-refused", "collector", id, ObjectId(user), DisplayName(user),
                    clock.GetUtcNow(), cancellationToken);
            }

            return Results.BadRequest(new ErrorResponse(
                "Unknown command. Allowed: fetch-bundle, run-canary, reload, rotate-credential."));
        }

        if (CollectorCommandTypes.RequiresAdministrator(command) && !user.IsInRole(BowerRoles.Administrator))
        {
            if (await store.GetAsync(id, cancellationToken) is not null)
            {
                await store.RecordAuditAsync(
                    $"collector.command-forbidden:{command}", "collector", id, ObjectId(user), DisplayName(user),
                    clock.GetUtcNow(), cancellationToken);
            }

            return Results.Forbid();
        }

        if (!signer.Configured)
        {
            return Results.Json(
                new ErrorResponse("Collector command signing is not configured."),
                ManagementJsonContext.Default.ErrorResponse,
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        try
        {
            CollectorCommandRecord? record = await store.IssueCommandAsync(
                id,
                command,
                request.Reason,
                request.ExpiresInMinutes ?? ManagementStore.DefaultCommandLifetimeMinutes,
                signer,
                ObjectId(user),
                DisplayName(user),
                clock.GetUtcNow(),
                cancellationToken);
            return record is null
                ? Results.NotFound()
                : Results.Accepted($"/api/collectors/{record.CollectorId}/commands", record);
        }
        catch (ArgumentException)
        {
            return Results.ValidationProblem(
                new Dictionary<string, string[]>
                {
                    ["command"] = ["A 1–500 character reason and a lifetime of 1–60 minutes are required."]
                });
        }
        catch (CollectorStateException)
        {
            return Results.Conflict(new ErrorResponse("Collector is not active."));
        }
        catch (CollectorCommandCapabilityException)
        {
            return Results.Conflict(new ErrorResponse(
                "Collector did not advertise this command on its last heartbeat."));
        }
        catch (CollectorCommandLimitException)
        {
            return Results.Conflict(new ErrorResponse("Collector has too many outstanding commands."));
        }
    }

    private static async Task<IResult> DecideAsync(
        string collectorId,
        CollectorStatus status,
        string action,
        ApprovalRequest request,
        ClaimsPrincipal user,
        ManagementStore store,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        try
        {
            ApprovalRecord? record = await store.DecideAsync(
                collectorId,
                status,
                action,
                request.Reason,
                ObjectId(user),
                DisplayName(user),
                clock.GetUtcNow(),
                cancellationToken);
            return record is null ? Results.NotFound() : Results.Ok(record);
        }
        catch (ArgumentException)
        {
            return Results.ValidationProblem(
                new Dictionary<string, string[]>
                {
                    ["reason"] = ["A reason of 1–500 characters is required."]
                });
        }
        catch (CollectorStateException)
        {
            return Results.Conflict(
                new ErrorResponse("Collector is not in a state that allows this decision."));
        }
    }

    internal static string ObjectId(ClaimsPrincipal user) =>
        user.FindFirstValue("oid")
        ?? user.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? throw new InvalidOperationException("Authenticated principal has no object identifier.");

    internal static string DisplayName(ClaimsPrincipal user) =>
        user.FindFirstValue("name") ?? "Unknown principal";

    private static string RequiredConfiguration(ConfigurationManager configuration, string key) =>
        configuration[key]
        ?? throw new InvalidOperationException($"Required configuration is missing: {key}");
}
