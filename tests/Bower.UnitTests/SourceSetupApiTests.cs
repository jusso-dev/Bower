using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Agent.Cloud;
using Bower.Core;
using Bower.Integrity;
using Bower.Management.Api;
using Bower.Source.Syslog;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Guided source setup: RBAC, validation, generated config, redacted preview, four-eyes, audit and the server-side check.</summary>
[Collection(SerialHostTests.Name)]
public sealed class SourceSetupApiTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 9, 30, 0, TimeSpan.Zero);

    private static Dictionary<string, string> SyslogValues() => new()
    {
        ["protocol"] = "tls",
        ["address"] = "0.0.0.0",
        ["port"] = "6514",
        ["allowedSenders"] = "10.20.0.0/24\n10.30.0.5",
        ["certificateFile"] = "/etc/bower/syslog/server.pem",
        ["privateKeyFile"] = "/etc/bower/syslog/server-key.pem",
        ["appName"] = "sshd",
        ["collectorHost"] = "collector.example.org"
    };

    [Theory]
    [InlineData("")]
    [InlineData(BowerRoles.Collector)]
    public async Task Types_RequireInteractiveRole(string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles).GetAsync("/api/sources/types", cancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Types_DescribeEverySupportedSourceForOneGenericForm()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        SourceTypeDefinition[] types = (await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<SourceTypeDefinition[]>("/api/sources/types", ManagementApiTests.ApiJson, cancellationToken))!;

        Assert.Equal(["syslog", "windows-eventlog", "docker", "aws", "gcp", "ama", "http-sdk"], types.Select(type => type.Id));
        string[] kinds =
        [
            SourceFieldKinds.Text, SourceFieldKinds.Number, SourceFieldKinds.Choice, SourceFieldKinds.Boolean,
            SourceFieldKinds.AddressList, SourceFieldKinds.NameList, SourceFieldKinds.FilePath,
            SourceFieldKinds.SecretReference, SourceFieldKinds.Url
        ];
        Assert.All(types, type =>
        {
            Assert.NotEmpty(type.Needs);
            Assert.False(string.IsNullOrWhiteSpace(type.CheckDescription));
            Assert.All(type.Fields, field =>
            {
                Assert.Contains(field.Kind, kinds);
                Assert.False(string.IsNullOrWhiteSpace(field.Help));
                Assert.True(field.Kind != SourceFieldKinds.Choice || field.Options is { Count: > 0 });
            });
        });
    }

    [Theory]
    [InlineData(BowerRoles.Viewer)]
    public async Task PlanAndSubmit_RequireOperator(string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);
        HttpClient client = ManagementApiTests.Client(app, roles);

        using HttpResponseMessage plan = await client.PostAsJsonAsync(
            "/api/sources/plan", new SourceSetupDraft("syslog", "edge-01", SyslogValues()), cancellationToken);
        using HttpResponseMessage submit = await client.PostAsJsonAsync(
            "/api/sources/requests", new SourceSetupSubmission("syslog", "edge-01", SyslogValues(), "Firewall logs"), cancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, plan.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, submit.StatusCode);
    }

    [Fact]
    public async Task Plan_GeneratesConfigurationTheSyslogSourceAndCollectorLoad()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);

        SourceSetupPlanResult result = await PlanAsync(app, "syslog", "edge-01", SyslogValues(), cancellationToken);

        Assert.True(result.Valid);
        SourceSetupPlan plan = result.Plan!;
        SyslogSourceConfiguration syslog = SyslogSourceConfigurationLoader.Parse(File(plan, "syslog.json"));
        SyslogListenerOptions listener = Assert.Single(syslog.Listeners);
        Assert.Equal("edge-tls", listener.Id);
        Assert.Equal(6514, listener.Port);
        Assert.Equal(2, listener.AllowedSenders.Count);
        Assert.Equal("linux-ssh-gateway", Assert.Single(listener.Routes).Pack);
        string expectations = Path.Combine(directory.Path, "expectations.json");
        await System.IO.File.WriteAllTextAsync(expectations, File(plan, "source-expectations.json"), cancellationToken);
        SourceExpectations loaded = SourceExpectationsLoader.LoadFile(expectations);
        Assert.Equal(("ssh-gateway", "production", 60), (loaded.Sources[0].Application, loaded.Sources[0].Environment, loaded.Sources[0].MaximumSilenceMinutes));
        Assert.Contains(plan.Variables, variable => variable is { Name: "BOWER_SYSLOG_CONFIG", Component: "collector" });
        Assert.Equal(new SourceSetupVerification("source", "ssh-gateway/production", plan.Verification.Description), plan.Verification);
        SourceSetupSnippet rsyslog = Assert.Single(plan.Snippets);
        Assert.Contains("if $programname == 'sshd' then {", rsyslog.Content, StringComparison.Ordinal);
        Assert.Contains("StreamDriverPermittedPeers=\"collector.example.org\"", rsyslog.Content, StringComparison.Ordinal);
        Assert.StartsWith("sha256:", plan.ContentHash, StringComparison.Ordinal);
        // Same values, same bytes, same hash.
        Assert.Equal(plan.ContentHash, (await PlanAsync(app, "syslog", "edge-01", SyslogValues(), cancellationToken)).Plan!.ContentHash);
    }

    [Fact]
    public async Task Plan_PreviewIsRedactedSyntheticSampleOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);

        SourceSetupPlanResult result = await PlanAsync(app, "syslog", "edge-01", SyslogValues(), cancellationToken);

        SourceSetupPreview preview = result.Preview!;
        Assert.True(preview.Valid);
        Assert.NotEmpty(preview.Findings);
        Assert.DoesNotContain("alex.citizen@example.com", preview.Redacted, StringComparison.Ordinal);
        Assert.Contains("built-in", preview.Rules, StringComparison.Ordinal);
    }

    private static List<(string Type, Dictionary<string, string> Values)> EveryType(string tokenFile) =>
    [
        ("syslog", SyslogValues()),
        ("docker", new() { ["service"] = "ssh-gateway", ["collectorUrl"] = "https://collector.example.org:4319", ["ingestTokenFile"] = tokenFile }),
        (
            "aws",
            new()
            {
                ["queueUrl"] = "https://sqs.ap-southeast-2.amazonaws.com/123456789012/bower-security",
                ["s3Buckets"] = "acme-logs, acme-trail",
                ["collectorUrl"] = "https://collector.example.org:4319",
                ["ingestTokenFile"] = tokenFile
            }),
        (
            "gcp",
            new()
            {
                ["subscription"] = "projects/acme-security/subscriptions/bower-security",
                ["collectorUrl"] = "https://collector.example.org:4319",
                ["ingestTokenFile"] = tokenFile
            }),
        ("ama", new()),
        ("windows-eventlog", new()),
        (
            "http-sdk",
            new()
            {
                ["application"] = "customer-portal",
                ["instance"] = "portal-01",
                ["endpoint"] = "https://collector.example.org:4319",
                ["ingestToken"] = "https://acme-vault.vault.azure.net/secrets/bower-ingest-token"
            })
    ];

    [Fact]
    public async Task Plan_EveryTypeProducesConfigurationItsComponentAccepts()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string tokenFile = Path.Combine(directory.Path, "ingest.token");
        await System.IO.File.WriteAllTextAsync(tokenFile, "test-token", cancellationToken);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);

        foreach ((string type, Dictionary<string, string> values) in EveryType(tokenFile))
        {
            SourceSetupPlanResult result = await PlanAsync(app, type, "edge-01", values, cancellationToken);
            Assert.True(result.Valid, $"{type}: {string.Join(" ", result.Checks.Select(check => check.Message))}");
            SourceSetupPlan plan = result.Plan!;
            Assert.True(result.Preview!.Valid, type);
            Assert.NotEmpty(plan.Snippets);
            Dictionary<string, string> forwarder = plan.Variables
                .Where(variable => variable.Component == "cloud-forwarder")
                .ToDictionary(variable => variable.Name, variable => variable.Value);
            switch (type)
            {
                case "windows-eventlog":
                    var windows = Bower.Source.WindowsEventLog.WindowsEventLogSourceConfigurationLoader.Parse(File(plan, "windows-event-log.json"));
                    Assert.Equal([4625], windows.Subscriptions.Single().EventIds);
                    Assert.Equal("Security", windows.Subscriptions.Single().Channel);
                    Assert.Equal("windows-security/production", plan.Verification.ReportId);
                    Assert.All(plan.Files, file => Assert.StartsWith(@"C:\ProgramData\Bower\", file.InstallPath, StringComparison.Ordinal));
                    break;
                case "aws":
                    CloudAgentSettings aws = CloudAgentSettings.FromEnvironment(name => forwarder.GetValueOrDefault(name));
                    Assert.Equal("ap-southeast-2", aws.Aws!.Region);
                    Assert.Equal(["acme-logs", "acme-trail"], aws.Aws.AllowedBuckets.Order());
                    Assert.Equal("aws-security/production", plan.Verification.ReportId);
                    break;
                case "gcp":
                    CloudAgentSettings gcp = CloudAgentSettings.FromEnvironment(name => forwarder.GetValueOrDefault(name));
                    Assert.Equal("projects/acme-security/subscriptions/bower-security", gcp.Gcp!.Subscription);
                    Assert.Equal("gcp-security/production", plan.Verification.ReportId);
                    break;
                case "ama":
                    Assert.Equal(new SourceSetupVerification("output", "ama-spool", plan.Verification.Description), plan.Verification);
                    Assert.Contains(plan.Variables, variable => variable is { Name: "BOWER_OUTPUT", Value: "ama-spool" });
                    break;
                case "http-sdk":
                    string scopes = Path.Combine(directory.Path, "scopes.json");
                    await System.IO.File.WriteAllTextAsync(scopes, File(plan, "producer-scopes.json"), cancellationToken);
                    _ = new ProducerAuthorization(scopes);
                    Assert.Contains("builder.Configuration[\"Bower:IngestToken\"]", plan.Snippets[0].Content, StringComparison.Ordinal);
                    break;
                case "docker":
                    Assert.Contains($"\"{tokenFile}:/run/secrets/bower-ingest-token:ro\"", File(plan, "compose.bower-sidecar.yaml"), StringComparison.Ordinal);
                    Assert.Contains("bower.collect: \"true\"", plan.Snippets[0].Content, StringComparison.Ordinal);
                    break;
            }
        }
    }

    [Theory]
    [InlineData("privateKeyFile", "-----BEGIN PRIVATE KEY-----MIIEv", "where the secret is stored")]
    [InlineData("privateKeyFile", "../server-key.pem", "where the secret is stored")]
    [InlineData("appName", "sshd' or $msg contains 'x", "not allowed")]
    [InlineData("appName", "sshd\naction(type=\"omfile\")", "single line")]
    [InlineData("allowedSenders", "10.20.0.1/24", "host bits zero")]
    [InlineData("port", "70000", "whole number")]
    [InlineData("protocol", "ftp", "not one of the choices")]
    [InlineData("unexpected", "surprise-42", "does not use")]
    public async Task Plan_RejectsUnsafeValuesWithAFix(string field, string value, string expected)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        Dictionary<string, string> values = SyslogValues();
        values[field] = value;

        SourceSetupPlanResult result = await PlanAsync(app, "syslog", "edge-01", values, cancellationToken);

        Assert.False(result.Valid);
        Assert.Null(result.Plan);
        Assert.Null(result.Preview);
        SetupCheck failure = Assert.Single(result.Checks, check => check.State == SetupCheckStates.Fail);
        Assert.Contains(expected, failure.Message + failure.Fix, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(failure.Fix));
        // A rejected value is never echoed back.
        Assert.DoesNotContain(value, JsonSerializer.Serialize(result, ManagementApiTests.ApiJson), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Plan_RefusesPlainNetworkSyslogAndUnapprovedCollectors()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await store.RegisterAsync(Registration("edge-02"), "principal-edge-02", Now, cancellationToken);
        Dictionary<string, string> plain = SyslogValues();
        plain["protocol"] = "udp";

        SourceSetupPlanResult udp = await PlanAsync(app, "syslog", "edge-01", plain, cancellationToken);
        SourceSetupPlanResult pending = await PlanAsync(app, "syslog", "edge-02", SyslogValues(), cancellationToken);
        SourceSetupPlanResult missing = await PlanAsync(app, "syslog", "nope", SyslogValues(), cancellationToken);
        plain["address"] = "127.0.0.1";
        SourceSetupPlanResult loopback = await PlanAsync(app, "syslog", "edge-01", plain, cancellationToken);

        Assert.Contains(udp.Checks, check => check is { Id: "protocol", State: SetupCheckStates.Fail });
        Assert.Contains(pending.Checks, check => check is { Id: "collector", State: SetupCheckStates.Fail });
        Assert.Contains(missing.Checks, check => check is { Id: "collector", State: SetupCheckStates.Fail });
        Assert.True(loopback.Valid);
        Assert.Null(SyslogSourceConfigurationLoader.Parse(File(loopback.Plan!, "syslog.json")).Listeners[0].Tls);
    }

    [Fact]
    public async Task Plan_EscapesWindowsPathsInGeneratedCSharpAndYaml()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        const string tokenPath = @"C:\ProgramData\Bower\ingest.token";
        SourceSetupPlanResult sdk = await PlanAsync(app, "http-sdk", "edge-01", new()
        {
            ["application"] = "portal",
            ["instance"] = "portal-01",
            ["ingestToken"] = tokenPath
        }, cancellationToken);
        SourceSetupPlanResult docker = await PlanAsync(app, "docker", "edge-01", new()
        {
            ["service"] = "portal",
            ["ingestTokenFile"] = tokenPath
        }, cancellationToken);
        Assert.True(sdk.Valid);
        Assert.True(docker.Valid);
        Assert.Contains("""File.ReadAllText("C:\\ProgramData\\Bower\\ingest.token")""", sdk.Plan!.Snippets.Single().Content, StringComparison.Ordinal);
        Assert.Contains("""C:\\ProgramData\\Bower\\ingest.token:/run/secrets""", File(docker.Plan!, "compose.bower-sidecar.yaml"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Requests_NeedADifferentApproverAndAreAudited()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        HttpClient requester = ManagementApiTests.Client(app, $"{BowerRoles.Operator},{BowerRoles.Approver}", "alex");
        HttpClient approver = ManagementApiTests.Client(app, BowerRoles.Approver, "sam");

        using HttpResponseMessage noReason = await requester.PostAsJsonAsync(
            "/api/sources/requests", new SourceSetupSubmission("syslog", "edge-01", SyslogValues(), " "), cancellationToken);
        SourceSetupRequestDetail created = await SubmitAsync(requester, "syslog", SyslogValues(), cancellationToken);
        using HttpResponseMessage self = await requester.PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Looks right"), cancellationToken);
        using HttpResponseMessage operatorOnly = await ManagementApiTests.Client(app, BowerRoles.Operator, "kim").PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Looks right"), cancellationToken);
        using HttpResponseMessage approved = await approver.PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Matches change BWR-200"), cancellationToken);
        using HttpResponseMessage again = await approver.PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/reject", new ApprovalRequest("Changed my mind"), cancellationToken);
        SourceSetupRequestDetail detail = (await approved.Content.ReadFromJsonAsync<SourceSetupRequestDetail>(ManagementApiTests.ApiJson, cancellationToken))!;
        AuditRecord[] audit = (await approver.GetFromJsonAsync<AuditRecord[]>("/api/audit", ManagementApiTests.ApiJson, cancellationToken))!;
        List<SourceSetupRequestSummary> list = (await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<List<SourceSetupRequestSummary>>("/api/sources/requests", ManagementApiTests.ApiJson, cancellationToken))!;

        Assert.Equal(HttpStatusCode.BadRequest, noReason.StatusCode);
        Assert.Equal(SourceSetupRequestStatus.PendingReview, created.Status);
        Assert.Equal("Waiting for approval", created.Check.Label);
        Assert.Equal(HttpStatusCode.Conflict, self.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, operatorOnly.StatusCode);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Equal(SourceSetupRequestStatus.Approved, detail.Status);
        Assert.Equal(created.ContentHash, detail.ContentHash);
        Assert.Equal("alex", detail.RequestedByObjectId);
        string[] actions = [.. audit.Where(item => item.TargetId == created.Id).Select(item => item.Action)];
        Assert.Contains("source-setup.requested", actions);
        Assert.Contains("source-setup.self-review-refused", actions);
        Assert.Contains("source-setup.approved", actions);
        Assert.All(audit.Where(item => item.TargetId == created.Id), item => Assert.Equal("source-setup-request", item.TargetType));
        Assert.Equal(created.Id, Assert.Single(list).Id);
    }

    [Fact]
    public async Task ConcurrentReviews_RecordExactlyOneDecisionAndAuditRow()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        SourceSetupRequestDetail created = await SubmitAsync(ManagementApiTests.Client(app, BowerRoles.Operator, "requester"), "syslog", SyslogValues(), cancellationToken);
        using HttpClient first = ManagementApiTests.Client(app, BowerRoles.Approver, "first");
        using HttpClient second = ManagementApiTests.Client(app, BowerRoles.Approver, "second");
        HttpResponseMessage[] responses = await Task.WhenAll(
            first.PostAsJsonAsync($"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Approve"), cancellationToken),
            second.PostAsJsonAsync($"/api/sources/requests/{created.Id}/reject", new ApprovalRequest("Reject"), cancellationToken));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Conflict);
            AuditRecord[] audit = (await first.GetFromJsonAsync<AuditRecord[]>("/api/audit", ManagementApiTests.ApiJson, cancellationToken))!;
            Assert.Single(audit, entry => entry.TargetId == created.Id
                && entry.Action is "source-setup.approved" or "source-setup.rejected");
        }
        finally
        {
            foreach (HttpResponseMessage response in responses) response.Dispose();
        }
    }

    [Fact]
    public async Task Check_ComesFromTheCollectorHeartbeatOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        HttpClient requester = ManagementApiTests.Client(app, BowerRoles.Operator, "alex");
        HttpClient approver = ManagementApiTests.Client(app, BowerRoles.Approver, "sam");
        SourceSetupRequestDetail created = await SubmitAsync(requester, "syslog", SyslogValues(), cancellationToken);
        SourceSetupRequestDetail rejectedRequest = await SubmitAsync(requester, "syslog", SyslogValues(), cancellationToken);
        await approver.PostAsJsonAsync($"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Approved"), cancellationToken);
        await approver.PostAsJsonAsync($"/api/sources/requests/{rejectedRequest.Id}/reject", new ApprovalRequest("Wrong pack"), cancellationToken);

        SourceSetupStatusCheck notExpected = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        await store.ExchangeHeartbeatAsync("edge-01", Heartbeat(new SourceReport("ssh-gateway/production", "application", "pending", null, null)), "principal-edge-01", Now, cancellationToken);
        SourceSetupStatusCheck waiting = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        await store.ExchangeHeartbeatAsync("edge-01", Heartbeat(new SourceReport("ssh-gateway/production", "application", "silent", 1200, Now.AddMinutes(-20))), "principal-edge-01", Now, cancellationToken);
        SourceSetupStatusCheck silent = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        await store.ExchangeHeartbeatAsync("edge-01", Heartbeat(new SourceReport("ssh-gateway/production", "application", "healthy", 0, Now.AddSeconds(-5))), "principal-edge-01", Now, cancellationToken);
        SourceSetupStatusCheck oldEvent = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        await store.ExchangeHeartbeatAsync("edge-01", Heartbeat(new SourceReport("ssh-gateway/production", "application", "healthy", 0, null)), "principal-edge-01", Now, cancellationToken);
        SourceSetupStatusCheck noEvent = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        clock.Advance(TimeSpan.FromSeconds(5));
        await store.ExchangeHeartbeatAsync("edge-01", Heartbeat(new SourceReport("ssh-gateway/production", "application", "healthy", 0, Now.AddSeconds(5))), "principal-edge-01", Now.AddSeconds(5), cancellationToken);
        SourceSetupStatusCheck receiving = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        clock.Advance(TimeSpan.FromMinutes(20));
        SourceSetupStatusCheck offline = (await DetailAsync(app, created.Id, cancellationToken)).Check;
        SourceSetupStatusCheck rejected = (await DetailAsync(app, rejectedRequest.Id, cancellationToken)).Check;

        Assert.Equal(("in-progress", "Waiting for the collector"), (notExpected.State, notExpected.Label));
        Assert.Equal(("in-progress", "Waiting for the first event"), (waiting.State, waiting.Label));
        Assert.Equal(("attention", "No events"), (silent.State, silent.Label));
        Assert.Equal(("complete", "Receiving events"), (receiving.State, receiving.Label));
        Assert.Equal(("in-progress", "Waiting for a new event"), (oldEvent.State, oldEvent.Label));
        Assert.Equal(("in-progress", "Waiting for a new event"), (noEvent.State, noEvent.Label));
        Assert.Equal(Now.AddSeconds(5), receiving.LastEventAt);
        Assert.Equal(("attention", "Collector not reporting"), (offline.State, offline.Label));
        Assert.Equal(("attention", "Rejected"), (rejected.State, rejected.Label));
        Assert.All(
            new[] { notExpected, waiting, silent, offline, rejected }.SelectMany(check => check.Checks),
            check => Assert.False(string.IsNullOrWhiteSpace(check.Fix)));
    }

    [Fact]
    public async Task Signed_OnlyForApprovedRequestsAndVerifiesWithThePublicKey()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string keyFile = Path.Combine(directory.Path, "source-signing.pem");
        await System.IO.File.WriteAllTextAsync(keyFile, privatePem, cancellationToken);
        await using WebApplication app = await ManagementApiTests.StartAsync(
            directory, new FakeClock(Now), cancellationToken, $"--{SourceSetupSigner.KeyFileSetting}={keyFile}");
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        HttpClient requester = ManagementApiTests.Client(app, BowerRoles.Operator, "alex");
        SourceSetupRequestDetail created = await SubmitAsync(requester, "syslog", SyslogValues(), cancellationToken);

        using HttpResponseMessage pending = await requester.GetAsync($"/api/sources/requests/{created.Id}/signed", cancellationToken);
        await ManagementApiTests.Client(app, BowerRoles.Approver, "sam").PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Approved"), cancellationToken);
        using HttpResponseMessage viewer = await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetAsync($"/api/sources/requests/{created.Id}/signed", cancellationToken);
        SignedSourceSetup signed = (await requester.GetFromJsonAsync<SignedSourceSetup>(
            $"/api/sources/requests/{created.Id}/signed", ManagementApiTests.ApiJson, cancellationToken))!;
        AuditRecord[] audit = (await requester.GetFromJsonAsync<AuditRecord[]>("/api/audit", ManagementApiTests.ApiJson, cancellationToken))!;

        Assert.Equal(HttpStatusCode.Conflict, pending.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, viewer.StatusCode);
        Assert.Equal(SourceSetupSigner.Kind, signed.Kind);
        Assert.Equal(created.ContentHash, signed.ContentHash);
        byte[] bytes = SourceSetupSigner.SignedBytes(
            signed.RequestId, signed.CollectorId, signed.SourceType, signed.ContentHash, signed.Files, signed.Variables, signed.Snippets, signed.Verification, signed.ApprovedAt);
        Assert.True(DetachedSigner.Verify(bytes, signed.Signature, [publicPem]));
        Assert.False(DetachedSigner.Verify(
            SourceSetupSigner.SignedBytes(signed.RequestId, "edge-02", signed.SourceType, signed.ContentHash, signed.Files, signed.Variables, signed.Snippets, signed.Verification, signed.ApprovedAt),
            signed.Signature,
            [publicPem]));
        Assert.NotEmpty(signed.Snippets);
        Assert.False(DetachedSigner.Verify(
            SourceSetupSigner.SignedBytes(signed.RequestId, signed.CollectorId, signed.SourceType, signed.ContentHash,
                signed.Files, signed.Variables, [signed.Snippets[0] with { Content = "changed sender configuration" }], signed.Verification, signed.ApprovedAt),
            signed.Signature, [publicPem]));
        Assert.Contains(audit, item => item is { Action: "source-setup.signed-config-issued" } && item.TargetId == created.Id);
    }

    [Fact]
    public async Task Signed_AnswersServiceUnavailableWithoutAKey()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        SourceSetupRequestDetail created = await SubmitAsync(
            ManagementApiTests.Client(app, BowerRoles.Operator, "alex"), "ama", [], cancellationToken);
        await ManagementApiTests.Client(app, BowerRoles.Approver, "sam").PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Approved"), cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, BowerRoles.Operator, "alex")
            .GetAsync($"/api/sources/requests/{created.Id}/signed", cancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Submit_LimitsPendingRequestsPerCollector()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        HttpClient requester = ManagementApiTests.Client(app, BowerRoles.Operator, "alex");
        for (int index = 0; index < ManagementStore.MaximumPendingSourceSetupsPerCollector; index++)
        {
            await SubmitAsync(requester, "ama", [], cancellationToken);
        }

        using HttpResponseMessage response = await requester.PostAsJsonAsync(
            "/api/sources/requests", new SourceSetupSubmission("ama", "edge-01", [], "One more"), cancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Theory]
    [InlineData("http://[2001:db8::1]:4319", false)]
    [InlineData("http://192.0.2.10:4319", false)]
    [InlineData("http://collector.example.org:4319", false)]
    [InlineData("http://[::1]:4319", true)]
    [InlineData("http://127.0.0.1:4319", true)]
    [InlineData("http://bower-collector:4319", true)]
    [InlineData("https://[2001:db8::1]:4319", true)]
    public async Task Plan_RequiresTlsForRemoteCollectorAddresses(string address, bool valid)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        SourceSetupPlanResult result = await PlanAsync(app, "docker", "edge-01", new()
        {
            ["service"] = "ssh-gateway",
            ["collectorUrl"] = address,
            ["ingestTokenFile"] = "/run/secrets/bower-ingest-token"
        }, cancellationToken);

        Assert.Equal(valid, result.Valid);
        if (!valid)
        {
            Assert.Null(result.Plan);
            Assert.Contains(result.Checks, check => check.Id == "collectorUrl" && check.State == SetupCheckStates.Fail);
        }
    }

    [Theory]
    [InlineData(null, "development-user")]
    [InlineData("reviewer", "development-reviewer")]
    [InlineData("someone-else", "development-user")]
    public async Task DevelopmentAuthentication_PersonHeaderOnlySelectsTheFixedReviewer(string? person, string expected)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = ManagementApplication.Build(
            ["--BOWER_AUTH_MODE=development", $"--BOWER_MANAGEMENT_DB_PATH={Path.Combine(directory.Path, "management.db")}"],
            builder => builder.WebHost.UseTestServer(),
            environmentName: "Development");
        await ManagementApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        HttpClient client = app.GetTestClient();
        if (person is not null)
        {
            client.DefaultRequestHeaders.Add(DevelopmentAuthenticationHandler.PersonHeader, person);
        }

        CurrentAccess access = (await client.GetFromJsonAsync<CurrentAccess>("/api/access/me", ManagementApiTests.ApiJson, cancellationToken))!;

        Assert.Equal(expected, access.ObjectId);
    }

    private static async Task<SourceSetupPlanResult> PlanAsync(
        WebApplication app, string type, string collectorId, Dictionary<string, string> values, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await ManagementApiTests.Client(app, BowerRoles.Operator).PostAsJsonAsync(
            "/api/sources/plan", new SourceSetupDraft(type, collectorId, values), cancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<SourceSetupPlanResult>(ManagementApiTests.ApiJson, cancellationToken))!;
    }

    private static async Task<SourceSetupRequestDetail> SubmitAsync(
        HttpClient client, string type, Dictionary<string, string> values, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "/api/sources/requests", new SourceSetupSubmission(type, "edge-01", values, "Add the edge firewall"), cancellationToken);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<SourceSetupRequestDetail>(ManagementApiTests.ApiJson, cancellationToken))!;
    }

    private static async Task<SourceSetupRequestDetail> DetailAsync(WebApplication app, string id, CancellationToken cancellationToken) =>
        (await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<SourceSetupRequestDetail>($"/api/sources/requests/{id}", ManagementApiTests.ApiJson, cancellationToken))!;

    private static string File(SourceSetupPlan plan, string name) => plan.Files.Single(file => file.Name == name).Content;

    private static async Task ActiveCollectorAsync(WebApplication app, string id, CancellationToken cancellationToken)
    {
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await store.RegisterAsync(Registration(id), $"principal-{id}", Now, cancellationToken);
        await store.DecideAsync(id, CollectorStatus.Approved, "approved", "Expected collector", "admin", "Admin", Now, cancellationToken);
        await store.ExchangeHeartbeatAsync(id, Heartbeat(), $"principal-{id}", Now, cancellationToken);
    }

    private static CollectorRegistration Registration(string id) =>
        new(id, id, "production", "0.1.0", "c", "p", [new SourceReport("local-http", "local-http", "healthy", null, null)], []);

    private static CollectorHeartbeat Heartbeat(params SourceReport[] extra) =>
        new("0.1.0", "c", "p", 0, "healthy", [new SourceReport("local-http", "local-http", "healthy", null, null), .. extra], []);
}
