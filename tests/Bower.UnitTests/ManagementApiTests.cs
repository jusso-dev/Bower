using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Bower.Jobs;
using Bower.Management.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class ManagementApiTests
{
    [Theory]
    [InlineData("/api/overview", "")]
    [InlineData("/api/collectors", "Bower.Collector")]
    [InlineData("/api/jobs", "Bower.Collector")]
    public async Task ReadEndpoints_RequireInteractiveRole(string path, string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellationToken);
        HttpClient client = Client(app, roles);

        using HttpResponseMessage response = await client.GetAsync(path, cancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"{path} returned {response.StatusCode}");
    }

    [Fact]
    public async Task Jobs_ListsRecurringManagementJobsForViewers()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellationToken);

        BackgroundJobStatus[]? jobs = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<BackgroundJobStatus[]>("/api/jobs", cancellationToken);

        BackgroundJobStatus job = Assert.Single(jobs!);
        Assert.Equal("collector-staleness", job.Id);
        Assert.Equal("*/5 * * * *", job.Schedule);
    }

    [Fact]
    public async Task TriggerJob_RequiresAdministratorAndIsAudited()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellationToken);

        using HttpResponseMessage asOperator = await Client(app, BowerRoles.Operator)
            .PostAsync("/api/jobs/collector-staleness/trigger", null, cancellationToken);
        using HttpResponseMessage unknown = await Client(app, BowerRoles.Administrator)
            .PostAsync("/api/jobs/not-a-job/trigger", null, cancellationToken);
        using HttpResponseMessage asAdministrator = await Client(app, BowerRoles.Administrator)
            .PostAsync("/api/jobs/collector-staleness/trigger", null, cancellationToken);
        AuditRecord[]? audit = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<AuditRecord[]>("/api/audit", cancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, asOperator.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, asAdministrator.StatusCode);
        Assert.Contains(audit!, item => item.Action == "job.triggered" && item.TargetId == "collector-staleness");
    }

    [Fact]
    public async Task Heartbeat_StoresCollectorJobReports()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellationToken);
        HttpClient collector = Client(app, BowerRoles.Collector);
        HttpClient administrator = Client(app, BowerRoles.Administrator);

        using HttpResponseMessage registered = await collector.PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration("edge-01", "edge-01", "test", "0.1.0", "c", "p", [], []),
            cancellationToken);
        using HttpResponseMessage approved = await administrator.PostAsJsonAsync(
            "/api/approvals/edge-01/approve",
            new ApprovalRequest("Expected test collector"),
            cancellationToken);
        using HttpResponseMessage heartbeat = await collector.PostAsJsonAsync(
            "/api/collectors/edge-01/heartbeat",
            new CollectorHeartbeat(
                "0.1.0", "c", "p", 3, "healthy", [], [],
                [new BackgroundJobStatus("queue-retention", "0 * * * *", TestEvents.Now, "Succeeded", null)]),
            cancellationToken);
        CollectorRecord? record = await administrator.GetFromJsonAsync<CollectorRecord>(
            "/api/collectors/edge-01",
            ApiJson,
            cancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal(HttpStatusCode.OK, heartbeat.StatusCode);
        BackgroundJobStatus job = Assert.Single(record!.Jobs!);
        Assert.Equal("queue-retention", job.Id);
        Assert.Equal("Succeeded", job.LastState);
    }

    [Fact]
    public async Task Register_ReturnsFixedErrorWithoutInternalDetail()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await Client(app, BowerRoles.Collector).PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration("", "", "test", "0.1.0", "c", "p", [], []),
            cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("Collector registration is invalid.", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Parameter", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsoleConfig_IsServedAnonymouslyFromSettings()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(
            directory,
            cancellationToken,
            "--Bower:Console:ClientId=11111111-1111-1111-1111-111111111111",
            "--Bower:Console:ApiScope=api://bower/Bower.Access",
            "--Bower:Console:RedirectUri=https://bower.example.test/</script>");

        using HttpResponseMessage response = await app.GetTestClient()
            .GetAsync("/config.js", cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("window.__BOWER_CONFIG__ = {", body, StringComparison.Ordinal);
        Assert.Contains("\"entraClientId\":\"11111111-1111-1111-1111-111111111111\"", body, StringComparison.Ordinal);
        Assert.Contains("\"entraTenantId\":\"00000000-0000-0000-0000-000000000000\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("</script>", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsoleAssets_LoadWithoutSignInWhileApiStaysProtected()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string webRoot = Path.Combine(directory.Path, "wwwroot");
        Directory.CreateDirectory(Path.Combine(webRoot, "assets"));
        File.WriteAllText(Path.Combine(webRoot, "index.html"), "<!doctype html><div id=\"root\"></div>");
        File.WriteAllText(Path.Combine(webRoot, "assets", "app.js"), "console.log('bower');");
        await using WebApplication app = await StartAsync(directory, cancellationToken, $"--webroot={webRoot}");
        HttpClient anonymous = app.GetTestClient();

        using HttpResponseMessage asset = await anonymous.GetAsync("/assets/app.js", cancellationToken);
        using HttpResponseMessage index = await anonymous.GetAsync("/", cancellationToken);
        using HttpResponseMessage deepLink = await anonymous.GetAsync("/jobs", cancellationToken);
        using HttpResponseMessage api = await anonymous.GetAsync("/api/overview", cancellationToken);

        Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
        Assert.Equal(HttpStatusCode.OK, index.StatusCode);
        Assert.Equal(HttpStatusCode.OK, deepLink.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
    }

    [Fact]
    public async Task ConsoleConfig_IsNotGeneratedWhenUnset()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await app.GetTestClient()
            .GetAsync("/config.js", cancellationToken);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task StalenessJob_MarksSilentCollectorsOnceAndAudits()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManagementStore store = new(Path.Combine(directory.Path, "management.db"));
        await store.InitializeAsync(cancellationToken);
        await store.RegisterAsync(
            new CollectorRegistration("quiet-01", "quiet-01", "test", "0.1.0", "c", "p", [], []),
            "collector-principal",
            TestEvents.Now,
            cancellationToken);
        await store.DecideAsync(
            "quiet-01", CollectorStatus.Approved, "approved", "ok", "admin", "Admin",
            TestEvents.Now, cancellationToken);

        int first = await store.MarkStaleAsync(
            TestEvents.Now.AddMinutes(30), TestEvents.Now.AddMinutes(45), cancellationToken);
        int second = await store.MarkStaleAsync(
            TestEvents.Now.AddMinutes(30), TestEvents.Now.AddMinutes(50), cancellationToken);
        CollectorRecord? record = await store.GetAsync("quiet-01", cancellationToken);
        IReadOnlyList<AuditRecord> audit = await store.ListAuditAsync(cancellationToken);

        Assert.Equal(1, first);
        Assert.Equal(0, second);
        Assert.Equal("stale", record!.DeliveryStatus);
        Assert.Single(audit, item => item.Action == "collector.stale");
    }

    private static readonly System.Text.Json.JsonSerializerOptions ApiJson =
        new(System.Text.Json.JsonSerializerDefaults.Web)
        {
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
        };

    private static async Task<WebApplication> StartAsync(
        TemporaryDirectory directory,
        CancellationToken cancellationToken,
        params string[] extraArgs)
    {
        WebApplication app = ManagementApplication.Build(
            [
                "--Bower:Entra:TenantId=00000000-0000-0000-0000-000000000000",
                "--Bower:Entra:Audience=api://bower-test",
                $"--BOWER_MANAGEMENT_DB_PATH={Path.Combine(directory.Path, "management.db")}",
                .. extraArgs
            ],
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services
                    .AddAuthentication(HeaderAuthenticationHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                        HeaderAuthenticationHandler.SchemeName,
                        _ => { });
            },
            environmentName: "Production");
        await ManagementApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    private static HttpClient Client(WebApplication app, string roles)
    {
        HttpClient client = app.GetTestClient();
        if (!string.IsNullOrEmpty(roles))
        {
            client.DefaultRequestHeaders.Add(HeaderAuthenticationHandler.RolesHeader, roles);
        }

        return client;
    }

    /// <summary>Test-only scheme: authenticates when the roles header is present.</summary>
    private sealed class HeaderAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "BowerTest";
        public const string RolesHeader = "X-Test-Roles";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(RolesHeader, out Microsoft.Extensions.Primitives.StringValues roles))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            List<Claim> claims =
            [
                new("oid", $"principal-{roles}"),
                new("name", "Test principal")
            ];
            claims.AddRange(roles.ToString()
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(role => new Claim("roles", role)));
            ClaimsIdentity identity = new(claims, SchemeName, "name", "roles");
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }
}
