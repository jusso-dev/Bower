using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Bower.Management.Api;
using Bower.Management.Api.Jobs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Bower.UnitTests;

public sealed class AlertNotificationTests
{
    [Fact]
    public async Task Notifications_Deduplicate_RespectAuditedMutes_AndRecoverWhenCleared()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory temp = new();
        MutableClock clock = new(new DateTimeOffset(2026, 11, 22, 0, 0, 0, TimeSpan.Zero));
        RecordingChannel channel = new();

        await using WebApplication app = await StartManagementAsync(temp.Path, clock, channel, ct);
        using HttpClient client = app.GetTestClient();

        // 1. Alert catalogue covers every health condition and channel status never leaks secrets.
        using HttpRequestMessage catReq = Request(HttpMethod.Get, "/api/alerts/catalogue", "v1", "Viewer", BowerRoles.Viewer);
        HttpResponseMessage catResp = await client.SendAsync(catReq, ct);
        Assert.Equal(HttpStatusCode.OK, catResp.StatusCode);
        IReadOnlyList<AlertCatalogueEntry> catalogue =
            (await catResp.Content.ReadFromJsonAsync(ManagementJsonContext.Default.IReadOnlyListAlertCatalogueEntry, ct))!;
        Assert.Contains(catalogue, e => e.ConditionId == "offline");
        Assert.Contains(catalogue, e => e.ConditionId == "queue-full");
        Assert.Contains(catalogue, e => e.ConditionId == "job-failed");

        // Register & approve an offline collector (last seen > 15m ago once clock advances).
        using (HttpRequestMessage reg = Request(HttpMethod.Post, "/api/collectors/register", "sp-1", "col-1", BowerRoles.Collector))
        {
            reg.Content = JsonContent.Create(
                new CollectorRegistration("col-1", "host-1", "prod", "1.0.1", "cfg", "pol", [], []),
                ManagementJsonContext.Default.CollectorRegistration);
            Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(reg, ct)).StatusCode);
        }

        using (HttpRequestMessage appr = Request(HttpMethod.Post, "/api/approvals/col-1/approve", "adm-1", "Admin", BowerRoles.Administrator))
        {
            appr.Content = JsonContent.Create(new ApprovalRequest("Approved"), ManagementJsonContext.Default.ApprovalRequest);
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(appr, ct)).StatusCode);
        }

        // Advance 20 minutes -> collector is offline (red alert) + not-proven (amber).
        clock.Advance(TimeSpan.FromMinutes(20));

        AlertNotificationJob job = app.Services.GetRequiredService<AlertNotificationJob>();

        // First run sends notifications for active alerts.
        int firstSent = await job.RunAsync(ct);
        Assert.True(firstSent >= 1);
        Assert.Contains(channel.Sent, m => m.ConditionId == "offline" && m.ConsoleAlertsUrl == "https://console.example/alerts");

        // Second run 5 minutes later -> deduplicated (0 sent).
        clock.Advance(TimeSpan.FromMinutes(5));
        int secondSent = await job.RunAsync(ct);
        Assert.Equal(0, secondSent);

        // Viewer cannot mute (403).
        using (HttpRequestMessage viewerMute = Request(HttpMethod.Post, "/api/alerts/mute", "v1", "Viewer", BowerRoles.Viewer))
        {
            viewerMute.Content = JsonContent.Create(
                new AlertMuteRequest("offline", null, 240, "Viewer attempt"),
                ManagementJsonContext.Default.AlertMuteRequest);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(viewerMute, ct)).StatusCode);
        }

        // Operator mutes "offline" -> audited + reflected in /api/home + suppresses notification after dedup window.
        using HttpRequestMessage muteReq = Request(HttpMethod.Post, "/api/alerts/mute", "op-1", "Alex Operator", BowerRoles.Operator);
        muteReq.Content = JsonContent.Create(
            new AlertMuteRequest("offline", null, 240, "Planned patching window"),
            ManagementJsonContext.Default.AlertMuteRequest);
        HttpResponseMessage muteResp = await client.SendAsync(muteReq, ct);
        Assert.Equal(HttpStatusCode.Created, muteResp.StatusCode);
        AlertMuteRecord mute = (await muteResp.Content.ReadFromJsonAsync(ManagementJsonContext.Default.AlertMuteRecord, ct))!;

        using (HttpRequestMessage homeReq = Request(HttpMethod.Get, "/api/home", "v1", "Viewer", BowerRoles.Viewer))
        {
            HomeRecord home = (await (await client.SendAsync(homeReq, ct))
                .Content.ReadFromJsonAsync(ManagementJsonContext.Default.HomeRecord, ct))!;
            HomeAttention offlineAttention = Assert.Single(home.Attention, a => a.Id == "offline");
            Assert.True(offlineAttention.Muted);
            Assert.Equal(mute.Id, offlineAttention.MuteId);
            Assert.Equal("Planned patching window", offlineAttention.MuteReason);
        }

        // Advance past dedup window (70m) while still within 240m mute -> "offline" MUST NOT re-send!
        int offlineCountBefore = channel.Sent.Count(m => m.ConditionId == "offline");
        clock.Advance(TimeSpan.FromMinutes(70));
        await job.RunAsync(ct);
        Assert.Equal(offlineCountBefore, channel.Sent.Count(m => m.ConditionId == "offline"));

        // Unmute -> audited, and next run sends "offline" again since dedup window elapsed.
        using (HttpRequestMessage unmuteReq = Request(HttpMethod.Post, $"/api/alerts/mutes/{mute.Id}/unmute", "op-1", "Alex Operator", BowerRoles.Operator))
        {
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(unmuteReq, ct)).StatusCode);
        }

        await job.RunAsync(ct);
        Assert.Equal(offlineCountBefore + 1, channel.Sent.Count(m => m.ConditionId == "offline"));

        // Verify audit trail contains alert.muted, alert.unmuted, and alert.notification-sent.
        using HttpRequestMessage auditReq = Request(HttpMethod.Get, "/api/audit", "v1", "Viewer", BowerRoles.Viewer);
        List<AuditRecord> audits = (await (await client.SendAsync(auditReq, ct))
            .Content.ReadFromJsonAsync(ManagementJsonContext.Default.ListAuditRecord, ct))!;
        Assert.Contains(audits, a => a.Action == "alert.muted" && a.TargetId == "offline");
        Assert.Contains(audits, a => a.Action == "alert.unmuted" && a.TargetId == "offline");
        Assert.Contains(audits, a => a.Action == "alert.notification-sent" && a.TargetId == "offline:red");
    }

    private sealed class RecordingChannel : IAlertNotificationChannel
    {
        public List<AlertNotificationMessage> Sent { get; } = [];
        public string Name => "recording";
        public bool IsConfigured => true;

        public Task SendAsync(AlertNotificationMessage message, CancellationToken cancellationToken)
        {
            Sent.Add(message);
            return Task.CompletedTask;
        }
    }

    private sealed class MutableClock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _now = initial;
        public void Advance(TimeSpan delta) => _now += delta;
        public override DateTimeOffset GetUtcNow() => _now;
    }

    private static async Task<WebApplication> StartManagementAsync(
        string root,
        TimeProvider clock,
        IAlertNotificationChannel testChannel,
        CancellationToken cancellationToken)
    {
        WebApplication app = ManagementApplication.Build(
            [
                "--Bower:Entra:TenantId=tenant-test",
                "--Bower:Entra:Audience=api://bower-test",
                $"--BOWER_MANAGEMENT_DB_PATH={Path.Combine(root, "management.db")}",
                "--BOWER_ALERT_CONSOLE_URL=https://console.example",
                "--BOWER_ALERT_DEDUP_MINUTES=60"
            ],
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddSingleton(clock);
                builder.Services.AddSingleton(testChannel);
                builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "AlertTest";
                    options.DefaultChallengeScheme = "AlertTest";
                    options.DefaultScheme = "AlertTest";
                }).AddScheme<AuthenticationSchemeOptions, AlertTestAuthHandler>("AlertTest", _ => { });
            });
        await ManagementApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    private sealed class AlertTestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string? oid = Request.Headers["X-Test-Oid"].FirstOrDefault();
            if (string.IsNullOrEmpty(oid))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            List<Claim> claims =
            [
                new("oid", oid),
                new("name", Request.Headers["X-Test-Name"].FirstOrDefault() ?? oid)
            ];
            foreach (string? role in Request.Headers["X-Test-Role"])
            {
                if (!string.IsNullOrWhiteSpace(role))
                {
                    claims.Add(new("roles", role));
                }
            }

            ClaimsPrincipal principal = new(new ClaimsIdentity(claims, Scheme.Name, "name", "roles"));
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
        }
    }

    private static HttpRequestMessage Request(
        HttpMethod method,
        string path,
        string objectId,
        string name,
        params string[] roles)
    {
        HttpRequestMessage message = new(method, path);
        message.Headers.Add("X-Test-Oid", objectId);
        message.Headers.Add("X-Test-Name", name);
        foreach (string role in roles)
        {
            message.Headers.Add("X-Test-Role", role);
        }

        return message;
    }
}
