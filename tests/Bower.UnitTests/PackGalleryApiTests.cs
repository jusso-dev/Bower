using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Bower.Integrity;
using Bower.Management.Api;
using Bower.Packs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Bower.UnitTests;

public sealed class PackGalleryApiTests
{
    [Fact]
    public async Task Gallery_ListsVerifiedPack_RefusesUntrustedPack_AndEnforcesFourEyesGroupInstall()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory temp = new();
        string galleryDir = Path.Combine(temp.Path, "gallery");
        Directory.CreateDirectory(galleryDir);

        (string trustedPrivatePem, string trustedPublicPem, _) = DetachedSigner.GenerateKeyPair();
        (string roguePrivatePem, _, _) = DetachedSigner.GenerateKeyPair();

        string trustedKeyFile = Path.Combine(temp.Path, "trusted.pub.pem");
        File.WriteAllText(trustedKeyFile, trustedPublicPem);

        string sourcePackDir = FindPackDirectory("linux-ssh-gateway");
        string trustedArchive = PackArchive.Build(sourcePackDir, trustedPrivatePem, galleryDir);
        string rogueTemp = Path.Combine(temp.Path, "rogue-out");
        string rogueArchive = PackArchive.Build(sourcePackDir, roguePrivatePem, rogueTemp);
        File.Copy(rogueArchive, Path.Combine(galleryDir, "rogue-ssh-1.0.0.bowerpack"));

        // Also create a tampered copy of the trusted archive.
        string tamperedArchive = Path.Combine(galleryDir, "tampered-ssh-1.0.0.bowerpack");
        File.Copy(trustedArchive, tamperedArchive);
        using (ZipArchive zip = ZipFile.Open(tamperedArchive, ZipArchiveMode.Update))
        {
            ZipArchiveEntry extra = zip.CreateEntry("content/injected.txt");
            using StreamWriter writer = new(extra.Open(), Encoding.UTF8);
            writer.Write("tampered");
        }

        await using WebApplication app = await StartManagementAsync(temp.Path, galleryDir, trustedKeyFile, ct);
        using HttpClient client = app.GetTestClient();

        // Register and approve two collectors in "production" and one in "staging".
        foreach ((string id, string env) in new[] { ("col-prod-1", "production"), ("col-prod-2", "production"), ("col-stage-1", "staging") })
        {
            using HttpRequestMessage reg = Request(HttpMethod.Post, "/api/collectors/register", $"sp-{id}", id, BowerRoles.Collector);
            reg.Content = JsonContent.Create(
                new CollectorRegistration(id, id, env, "1.0.1", "cfg-1", "old-policy-hash", [], []),
                ManagementJsonContext.Default.CollectorRegistration);
            HttpResponseMessage regResp = await client.SendAsync(reg, ct);
            Assert.Equal(HttpStatusCode.Accepted, regResp.StatusCode);

            using HttpRequestMessage appr = Request(HttpMethod.Post, $"/api/approvals/{id}/approve", "admin-1", "Admin", BowerRoles.Administrator);
            appr.Content = JsonContent.Create(new ApprovalRequest("Approved for test"), ManagementJsonContext.Default.ApprovalRequest);
            HttpResponseMessage apprResp = await client.SendAsync(appr, ct);
            Assert.Equal(HttpStatusCode.OK, apprResp.StatusCode);
        }

        // 1. Viewer can browse gallery; trusted pack verified, rogue and tampered refused with clear reasons.
        using HttpRequestMessage listReq = Request(HttpMethod.Get, "/api/packs", "viewer-1", "Viewer", BowerRoles.Viewer);
        HttpResponseMessage listResp = await client.SendAsync(listReq, ct);
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        PackGalleryResponse gallery = (await listResp.Content.ReadFromJsonAsync(ManagementJsonContext.Default.PackGalleryResponse, ct))!;
        Assert.True(gallery.Configured);
        Assert.Equal(1, gallery.TrustedKeyCount);
        Assert.Equal(3, gallery.Packs.Count);

        PackGalleryItem verified = Assert.Single(gallery.Packs, p => p.Trusted);
        Assert.Equal("linux-ssh-gateway", verified.Id);
        Assert.NotEmpty(verified.EventTypes);
        Assert.NotEmpty(verified.Redactions);
        Assert.NotEmpty(verified.SampleResults);
        Assert.All(verified.SampleResults, sample => Assert.True(sample.Passed));

        PackGalleryItem[] refused = gallery.Packs.Where(p => !p.Trusted).ToArray();
        Assert.Equal(2, refused.Length);
        Assert.All(refused, item => Assert.False(string.IsNullOrWhiteSpace(item.RefusalReason)));

        // Ensure no full host directory paths leak in gallery response.
        string rawBody = await listResp.Content.ReadAsStringAsync(ct);
        Assert.DoesNotContain(temp.Path, rawBody, StringComparison.Ordinal);

        // 2. Untrusted pack cannot be submitted for install.
        using HttpRequestMessage badInstall = Request(HttpMethod.Post, "/api/packs/install-requests", "op-1", "Operator", BowerRoles.Operator);
        badInstall.Content = JsonContent.Create(
            new PackInstallSubmission("rogue-ssh", "1.0.0", "production", null, "Try untrusted"),
            ManagementJsonContext.Default.PackInstallSubmission);
        HttpResponseMessage badResp = await client.SendAsync(badInstall, ct);
        Assert.Equal(HttpStatusCode.BadRequest, badResp.StatusCode);

        // 3. Viewer cannot submit pack install (403).
        using HttpRequestMessage viewerInstall = Request(HttpMethod.Post, "/api/packs/install-requests", "viewer-1", "Viewer", BowerRoles.Viewer);
        viewerInstall.Content = JsonContent.Create(
            new PackInstallSubmission(verified.Id, verified.Version, "production", null, "Viewer attempt"),
            ManagementJsonContext.Default.PackInstallSubmission);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(viewerInstall, ct)).StatusCode);

        // 4. Operator submits group install for "production" -> 201 with population diff covering both prod collectors.
        using HttpRequestMessage submitReq = Request(HttpMethod.Post, "/api/packs/install-requests", "op-1", "Alice Operator", BowerRoles.Operator);
        submitReq.Content = JsonContent.Create(
            new PackInstallSubmission(verified.Id, verified.Version, "production", null, "Enable SSH pack in prod"),
            ManagementJsonContext.Default.PackInstallSubmission);
        HttpResponseMessage submitResp = await client.SendAsync(submitReq, ct);
        Assert.Equal(HttpStatusCode.Created, submitResp.StatusCode);
        PackInstallRequestRecord created = (await submitResp.Content.ReadFromJsonAsync(ManagementJsonContext.Default.PackInstallRequestRecord, ct))!;
        Assert.Equal(PackInstallRequestStatus.PendingReview, created.Status);
        Assert.Equal(2, created.Diff.AffectedCollectors.Count);
        Assert.Equal(verified.PackHash, created.PackHash);

        // 5. Four-eyes: requester (even if Approver) cannot approve their own request -> 409.
        using HttpRequestMessage selfApprove = Request(
            HttpMethod.Post,
            $"/api/packs/install-requests/{created.Id}/approve",
            "op-1",
            "Alice Operator",
            BowerRoles.Approver);
        selfApprove.Content = JsonContent.Create(new ApprovalRequest("Self approve"), ManagementJsonContext.Default.ApprovalRequest);
        Assert.Equal(HttpStatusCode.Conflict, (await client.SendAsync(selfApprove, ct)).StatusCode);

        // 6. Different Approver approves -> 200, updates desiredPolicyHash on both prod collectors only (not staging).
        using HttpRequestMessage approveReq = Request(
            HttpMethod.Post,
            $"/api/packs/install-requests/{created.Id}/approve",
            "approver-2",
            "Bob Approver",
            BowerRoles.Approver);
        approveReq.Content = JsonContent.Create(new ApprovalRequest("Reviewed diff and signature"), ManagementJsonContext.Default.ApprovalRequest);
        HttpResponseMessage approveResp = await client.SendAsync(approveReq, ct);
        Assert.Equal(HttpStatusCode.OK, approveResp.StatusCode);
        PackInstallRequestRecord approved = (await approveResp.Content.ReadFromJsonAsync(ManagementJsonContext.Default.PackInstallRequestRecord, ct))!;
        Assert.Equal(PackInstallRequestStatus.Approved, approved.Status);
        Assert.Equal("Bob Approver", approved.ReviewerName);

        // Verify desiredPolicyHash applied to both production collectors and NOT staging.
        using HttpRequestMessage colReq = Request(HttpMethod.Get, "/api/collectors", "viewer-1", "Viewer", BowerRoles.Viewer);
        using System.Text.Json.JsonDocument colDoc = System.Text.Json.JsonDocument.Parse(
            await (await client.SendAsync(colReq, ct)).Content.ReadAsStringAsync(ct));
        Dictionary<string, string?> desiredByCollector = colDoc.RootElement.EnumerateArray()
            .ToDictionary(
                item => item.GetProperty("id").GetString()!,
                item => item.TryGetProperty("desiredPolicyHash", out System.Text.Json.JsonElement h)
                    && h.ValueKind == System.Text.Json.JsonValueKind.String
                    ? h.GetString()
                    : null,
                StringComparer.Ordinal);
        Assert.Equal(verified.PackHash, desiredByCollector["col-prod-1"]);
        Assert.Equal(verified.PackHash, desiredByCollector["col-prod-2"]);
        Assert.Null(desiredByCollector["col-stage-1"]);

        // Verify audit trail captured both request and approval.
        using HttpRequestMessage auditReq = Request(HttpMethod.Get, "/api/audit", "viewer-1", "Viewer", BowerRoles.Viewer);
        List<AuditRecord> audits = (await (await client.SendAsync(auditReq, ct))
            .Content.ReadFromJsonAsync(ManagementJsonContext.Default.ListAuditRecord, ct))!;
        Assert.Contains(audits, a => a.Action == "pack.install-requested" && a.TargetId == created.Id);
        Assert.Contains(audits, a => a.Action == "pack.install-approved" && a.TargetId == created.Id && a.InitiatedByObjectId == "op-1");
    }

    private static string FindPackDirectory(string packName)
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(current.FullName, "packs", packName);
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException($"Could not locate packs/{packName}.");
    }

    private static async Task<WebApplication> StartManagementAsync(
        string root,
        string galleryDir,
        string trustedKeyFile,
        CancellationToken cancellationToken)
    {
        WebApplication app = ManagementApplication.Build(
            [
                "--Bower:Entra:TenantId=tenant-test",
                "--Bower:Entra:Audience=api://bower-test",
                $"--BOWER_MANAGEMENT_DB_PATH={Path.Combine(root, "management.db")}",
                $"--BOWER_PACK_GALLERY_DIR={galleryDir}",
                $"--BOWER_PACK_TRUSTED_KEYS={trustedKeyFile}"
            ],
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "PackTest";
                    options.DefaultChallengeScheme = "PackTest";
                    options.DefaultScheme = "PackTest";
                }).AddScheme<AuthenticationSchemeOptions, PackTestAuthHandler>("PackTest", _ => { });
            });
        await ManagementApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    private sealed class PackTestAuthHandler(
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
