using System.Security.Claims;
using System.Text.Json.Serialization;
using Bower.Management.Api;
using Bower.Pipeline;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(
        new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false)));
builder.WebHost.UseUrls(
    Environment.GetEnvironmentVariable("BOWER_MANAGEMENT_LISTEN_URL")
    ?? "http://127.0.0.1:4320");

bool developmentAuthentication = string.Equals(
    Environment.GetEnvironmentVariable("BOWER_AUTH_MODE"),
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
    options.AddPolicy(
        "View",
        policy => policy.RequireRole(BowerRoles.Interactive));
    options.AddPolicy(
        "Operate",
        policy => policy.RequireRole(
            BowerRoles.Operator,
            BowerRoles.Approver,
            BowerRoles.Administrator));
    options.AddPolicy(
        "Approve",
        policy => policy.RequireRole(BowerRoles.Approver, BowerRoles.Administrator));
    options.AddPolicy(
        "Administer",
        policy => policy.RequireRole(BowerRoles.Administrator));
    options.AddPolicy(
        "Collector",
        policy => policy.RequireRole(BowerRoles.Collector));
});

string databasePath = Environment.GetEnvironmentVariable("BOWER_MANAGEMENT_DB_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "data", "management.db");
builder.Services.AddSingleton(new ManagementStore(databasePath));

string[] allowedOrigins = builder.Configuration
    .GetSection("Bower:AllowedOrigins")
    .Get<string[]>()
    ?? ["http://localhost:5173"];
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod()));

WebApplication app = builder.Build();
await app.Services.GetRequiredService<ManagementStore>()
    .InitializeAsync(app.Lifetime.ApplicationStopping);
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
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

string indexPath = Path.Combine(app.Environment.WebRootPath ?? string.Empty, "index.html");
if (File.Exists(indexPath))
{
    app.UseDefaultFiles();
    app.UseStaticFiles();
}

RouteGroupBuilder api = app.MapGroup("/api");

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
        (ManagementStore store, CancellationToken cancellationToken) =>
            store.OverviewAsync(DateTimeOffset.UtcNow.AddMinutes(-15), cancellationToken))
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
                if (!Enum.TryParse(status, true, out CollectorStatus value))
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
            CancellationToken cancellationToken) =>
        {
            try
            {
                CollectorRecord record = await store.RegisterAsync(
                    registration,
                    ObjectId(user),
                    DateTimeOffset.UtcNow,
                    cancellationToken);
                return Results.Accepted($"/api/collectors/{record.Id}", record);
            }
            catch (CollectorIdentityConflictException exception)
            {
                return Results.Conflict(new { error = exception.Message });
            }
            catch (ArgumentException exception)
            {
                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["registration"] = [exception.Message]
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
            CancellationToken cancellationToken) =>
        {
            try
            {
                CollectorRecord? record = await store.HeartbeatAsync(
                    id,
                    heartbeat,
                    ObjectId(user),
                    DateTimeOffset.UtcNow,
                    cancellationToken);
                return record is null ? Results.NotFound() : Results.Ok(record);
            }
            catch (CollectorStateException exception)
            {
                return Results.Conflict(new { error = exception.Message });
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

api.MapGet(
        "/approvals",
        (ManagementStore store, CancellationToken cancellationToken) =>
            store.ListApprovalsAsync(cancellationToken))
    .RequireAuthorization("View");

api.MapPost(
        "/approvals/{collectorId}/approve",
        (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
            ManagementStore store, CancellationToken cancellationToken) =>
            DecideAsync(
                collectorId, CollectorStatus.Approved, "approved", request, user, store,
                cancellationToken))
    .RequireAuthorization("Approve");

api.MapPost(
        "/approvals/{collectorId}/reject",
        (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
            ManagementStore store, CancellationToken cancellationToken) =>
            DecideAsync(
                collectorId, CollectorStatus.Revoked, "rejected", request, user, store,
                cancellationToken))
    .RequireAuthorization("Approve");

api.MapPost(
        "/collectors/{collectorId}/suspend",
        (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
            ManagementStore store, CancellationToken cancellationToken) =>
            DecideAsync(
                collectorId, CollectorStatus.Suspended, "suspended", request, user, store,
                cancellationToken))
    .RequireAuthorization("Administer");

api.MapPost(
        "/collectors/{collectorId}/revoke",
        (string collectorId, ApprovalRequest request, ClaimsPrincipal user,
            ManagementStore store, CancellationToken cancellationToken) =>
            DecideAsync(
                collectorId, CollectorStatus.Revoked, "revoked", request, user, store,
                cancellationToken))
    .RequireAuthorization("Administer");

api.MapGet(
        "/audit",
        (ManagementStore store, CancellationToken cancellationToken) =>
            store.ListAuditAsync(cancellationToken))
    .RequireAuthorization("View");

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }))
    .AllowAnonymous();

if (File.Exists(indexPath))
{
    app.MapFallbackToFile("index.html").AllowAnonymous();
}

await app.RunAsync();

static async Task<IResult> DecideAsync(
    string collectorId,
    CollectorStatus status,
    string action,
    ApprovalRequest request,
    ClaimsPrincipal user,
    ManagementStore store,
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
            DateTimeOffset.UtcNow,
            cancellationToken);
        return record is null ? Results.NotFound() : Results.Ok(record);
    }
    catch (ArgumentException exception)
    {
        return Results.ValidationProblem(
            new Dictionary<string, string[]> { ["reason"] = [exception.Message] });
    }
    catch (CollectorStateException exception)
    {
        return Results.Conflict(new { error = exception.Message });
    }
}

static string ObjectId(ClaimsPrincipal user) =>
    user.FindFirstValue("oid")
    ?? user.FindFirstValue(ClaimTypes.NameIdentifier)
    ?? throw new InvalidOperationException("Authenticated principal has no object identifier.");

static string DisplayName(ClaimsPrincipal user) =>
    user.FindFirstValue("name") ?? "Unknown principal";

static string RequiredConfiguration(IConfiguration configuration, string key) =>
    configuration[key]
    ?? throw new InvalidOperationException($"Required configuration is missing: {key}");

public partial class Program
{
}
