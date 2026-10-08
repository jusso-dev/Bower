using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Bower.Jobs;
using Bower.Management.Api.Jobs;
using Bower.Pipeline;
using Hangfire;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Bower.Management.Api;

/// <summary>Composes the management API host. Kept separate from Program for integration tests.</summary>
public static class ManagementApplication
{
    public static WebApplication Build(
        string[] args,
        Action<WebApplicationBuilder>? configure = null,
        string? environmentName = null)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            EnvironmentName = environmentName
        });
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.Converters.Add(
                new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false)));
        builder.WebHost.UseUrls(
            Environment.GetEnvironmentVariable("BOWER_MANAGEMENT_LISTEN_URL")
            ?? "http://127.0.0.1:4320");
        builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);
        builder.Logging.AddFilter("Hangfire", LogLevel.Warning);

        bool developmentAuthentication = string.Equals(
            builder.Configuration["BOWER_AUTH_MODE"],
            "development",
            StringComparison.OrdinalIgnoreCase);
        if (developmentAuthentication && !builder.Environment.IsDevelopment())
        {
            throw new InvalidOperationException(
                "BOWER_AUTH_MODE=development is allowed only in the Development environment.");
        }

        if (developmentAuthentication)
        {
            builder.Services
                .AddAuthentication(DevelopmentAuthenticationHandler.AuthenticationScheme)
                .AddScheme<AuthenticationSchemeOptions, DevelopmentAuthenticationHandler>(
                    DevelopmentAuthenticationHandler.AuthenticationScheme,
                    _ => { });
        }
        else
        {
            string tenantId = RequiredConfiguration(builder.Configuration, "Bower:Entra:TenantId");
            string audience = RequiredConfiguration(builder.Configuration, "Bower:Entra:Audience");
            builder.Services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
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
        });

        string databasePath = builder.Configuration["BOWER_MANAGEMENT_DB_PATH"]
            ?? Path.Combine(AppContext.BaseDirectory, "data", "management.db");
        builder.Services.AddSingleton(new ManagementStore(databasePath));
        builder.Services.AddSingleton(TimeProvider.System);

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
        });
        builder.Services.AddHsts(options =>
        {
            options.MaxAge = TimeSpan.FromDays(365);
            options.IncludeSubDomains = true;
        });

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

        app.MapGet("/health", () => Results.Ok(new { status = "healthy" }))
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
        await app.Services.GetRequiredService<ManagementStore>().InitializeAsync(cancellationToken);
        app.Services.GetRequiredService<IRecurringJobManager>().AddOrUpdate<CollectorStalenessJob>(
            CollectorStalenessJob.Id,
            job => job.RunAsync(CancellationToken.None),
            "*/5 * * * *",
            new RecurringJobOptions { TimeZone = TimeZoneInfo.Utc });
        app.Services.GetRequiredService<IRecurringJobManager>().AddOrUpdate<CollectorInactivityJob>(
            CollectorInactivityJob.Id,
            job => job.RunAsync(CancellationToken.None),
            Cron.Daily(2),
            new RecurringJobOptions { TimeZone = TimeZoneInfo.Utc });
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
                (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    store.OverviewAsync(
                        clock.GetUtcNow() - CollectorStalenessJob.StaleAfter,
                        cancellationToken))
            .RequireAuthorization("View");

        api.MapGet(
                "/collectors",
                async (
                    string? status,
                    ManagementStore store,
                    CancellationToken cancellationToken) =>
                {
                    CollectorStatus? parsed = null;
                    if (!string.IsNullOrWhiteSpace(status))
                    {
                        if (!Enum.TryParse(status, true, out CollectorStatus value)
                            || !Enum.IsDefined(value))
                        {
                            return Results.BadRequest(new { error = "Unknown collector status." });
                        }

                        parsed = value;
                    }

                    return Results.Ok(await store.ListAsync(parsed, cancellationToken));
                })
            .RequireAuthorization("View");

        api.MapGet(
                "/collectors/{id}",
                async (string id, ManagementStore store, CancellationToken cancellationToken) =>
                    await store.GetAsync(id, cancellationToken) is { } record
                        ? Results.Ok(record)
                        : Results.NotFound())
            .RequireAuthorization("View");

        api.MapPost(
                "/collectors/register",
                async (
                    CollectorRegistration registration,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
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
                            new { error = "Collector id is bound to a different principal." });
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
                    try
                    {
                        CollectorRecord? record = await store.HeartbeatAsync(
                            id,
                            heartbeat,
                            ObjectId(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        return record is null ? Results.NotFound() : Results.Ok(record);
                    }
                    catch (CollectorStateException)
                    {
                        return Results.Conflict(
                            new { error = "Collector is not approved to send heartbeats." });
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
                    PipelinePerformanceEstimate estimate = PipelineValidator.Estimate(pipeline);
                    return Results.Ok(
                        new
                        {
                            validation.IsValid,
                            validation.Issues,
                            validation.TopologicalOrder,
                            estimate
                        });
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
                        return Results.BadRequest(new { error = CustomLogError(exception) });
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
                        return Results.BadRequest(new { error = CustomLogError(exception) });
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
                    BackgroundJobCatalog jobs,
                    IRecurringJobManager manager,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!jobs.Exists(id))
                    {
                        return Results.NotFound();
                    }

                    manager.Trigger(id);
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
        return $"window.__BOWER_CONFIG__ = {System.Text.Json.JsonSerializer.Serialize(values)};\n";
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
                new { error = "Collector is not in a state that allows this decision." });
        }
    }

    private static string ObjectId(ClaimsPrincipal user) =>
        user.FindFirstValue("oid")
        ?? user.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? throw new InvalidOperationException("Authenticated principal has no object identifier.");

    private static string DisplayName(ClaimsPrincipal user) =>
        user.FindFirstValue("name") ?? "Unknown principal";

    private static string RequiredConfiguration(ConfigurationManager configuration, string key) =>
        configuration[key]
        ?? throw new InvalidOperationException($"Required configuration is missing: {key}");
}
