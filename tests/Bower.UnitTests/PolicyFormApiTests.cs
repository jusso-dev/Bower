using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Bower.Management.Api;
using Bower.PolicyEngine;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Bower.UnitTests;

public sealed class PolicyFormApiTests
{
    private const string BaselineYaml = """
        apiVersion: bower.security/v1
        kind: TelemetryPolicy
        metadata:
          id: BWR-POL-AUTH-FAILURE
          name: Authentication failures
          version: 1.0.0
          owner: Security Operations
        match:
          eventCategories:
            - authentication
          eventTypes:
            - authentication_failure
        requirements:
          requiredFields:
            - timeGenerated
            - eventType
            - eventResult
            - application.name
          atLeastOne:
            - actor.username
          recommendedFields:
            - source.ipAddress
        decision:
          action: accept
          minimumValueScore: 70
          neverSample: true
        """;

    [Fact]
    public async Task PolicyForm_PreservesSemanticHash_SupportsAggregateSuppression_RedactsPreview_AndEnforcesRbac()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory temp = new();
        await using WebApplication app = await StartManagementAsync(temp.Path, ct);
        using HttpClient client = app.GetTestClient();

        // 1. Viewer can list templates but cannot edit forms (403).
        using (HttpRequestMessage tplReq = Request(HttpMethod.Get, "/api/policies/templates", "v1", "Viewer", BowerRoles.Viewer))
        {
            HttpResponseMessage tplResp = await client.SendAsync(tplReq, ct);
            Assert.Equal(HttpStatusCode.OK, tplResp.StatusCode);
            PolicyTemplateItem[] templates = (await tplResp.Content.ReadFromJsonAsync(
                ManagementJsonContext.Default.PolicyTemplateItemArray, ct))!;
            Assert.True(templates.Length >= 2);
        }

        using (HttpRequestMessage viewerPost = Request(HttpMethod.Post, "/api/policies/form", "v1", "Viewer", BowerRoles.Viewer))
        {
            viewerPost.Content = JsonContent.Create(new PolicyFormRequest(BaselineYaml, null), ManagementJsonContext.Default.PolicyFormRequest);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(viewerPost, ct)).StatusCode);
        }

        // 2. Round-trip unmodified form preserves identical loaded policy hash (semantic equivalence).
        LoadedPolicy baseline = PolicyLoader.LoadYaml(BaselineYaml, "baseline.yaml");
        using HttpRequestMessage loadReq = Request(HttpMethod.Post, "/api/policies/form", "op-1", "Operator", BowerRoles.Operator);
        loadReq.Content = JsonContent.Create(new PolicyFormRequest(BaselineYaml, null), ManagementJsonContext.Default.PolicyFormRequest);
        HttpResponseMessage loadResp = await client.SendAsync(loadReq, ct);
        Assert.Equal(HttpStatusCode.OK, loadResp.StatusCode);
        PolicyFormResult loaded = (await loadResp.Content.ReadFromJsonAsync(ManagementJsonContext.Default.PolicyFormResult, ct))!;
        Assert.True(loaded.Valid);
        Assert.Equal(baseline.Hash, loaded.PolicyHash);

        using HttpRequestMessage roundTripReq = Request(HttpMethod.Post, "/api/policies/form", "op-1", "Operator", BowerRoles.Operator);
        roundTripReq.Content = JsonContent.Create(new PolicyFormRequest(BaselineYaml, loaded.Form), ManagementJsonContext.Default.PolicyFormRequest);
        PolicyFormResult roundTripped = (await (await client.SendAsync(roundTripReq, ct))
            .Content.ReadFromJsonAsync(ManagementJsonContext.Default.PolicyFormResult, ct))!;
        Assert.True(roundTripped.Valid);
        Assert.Equal(baseline.Hash, roundTripped.PolicyHash);
        Assert.True(roundTripped.Diff!.SemanticallyIdentical);

        // 3. Change action to aggregate with suppression window and bump version -> valid YAML, diff + redacted preview.
        PolicyForm edited = loaded.Form with
        {
            Version = "1.1.0",
            Action = "aggregate",
            NeverSample = false,
            Suppression = new PolicySuppressionForm(true, ["application.name", "eventType", "source.ipAddress"], 60, 0)
        };
        using HttpRequestMessage editReq = Request(HttpMethod.Post, "/api/policies/form", "op-1", "Operator", BowerRoles.Operator);
        editReq.Content = JsonContent.Create(new PolicyFormRequest(BaselineYaml, edited), ManagementJsonContext.Default.PolicyFormRequest);
        PolicyFormResult editedResult = (await (await client.SendAsync(editReq, ct))
            .Content.ReadFromJsonAsync(ManagementJsonContext.Default.PolicyFormResult, ct))!;
        Assert.True(editedResult.Valid);
        Assert.False(editedResult.Diff!.SemanticallyIdentical);
        Assert.Contains(editedResult.Diff.Changes, c => c.Change == "action-changed");
        Assert.Contains(editedResult.Diff.Changes, c => c.Change == "suppression-changed");
        Assert.Equal("accept", editedResult.Preview!.BeforeDecision);
        Assert.Equal("aggregate", editedResult.Preview.AfterDecision);
        Assert.NotNull(editedResult.Preview.RedactedEventJson);
        // Built-in privacy protection MUST remove the synthetic password and mask the synthetic TFN.
        Assert.DoesNotContain("synthetic-secret-value", editedResult.Preview.RedactedEventJson, StringComparison.Ordinal);
        Assert.DoesNotContain("123456782", editedResult.Preview.RedactedEventJson, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> StartManagementAsync(string root, CancellationToken cancellationToken)
    {
        WebApplication app = ManagementApplication.Build(
            [
                "--Bower:Entra:TenantId=tenant-test",
                "--Bower:Entra:Audience=api://bower-test",
                $"--BOWER_MANAGEMENT_DB_PATH={Path.Combine(root, "management.db")}"
            ],
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "PolicyFormTest";
                    options.DefaultChallengeScheme = "PolicyFormTest";
                    options.DefaultScheme = "PolicyFormTest";
                }).AddScheme<AuthenticationSchemeOptions, PolicyFormAuthHandler>("PolicyFormTest", _ => { });
            });
        await ManagementApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    private sealed class PolicyFormAuthHandler(
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
