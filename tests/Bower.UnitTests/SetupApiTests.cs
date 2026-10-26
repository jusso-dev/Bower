using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Dcr;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Onboarding wizard API: RBAC, validation, audit and canary proof semantics.</summary>
[Collection(SerialHostTests.Name)]
public sealed partial class SetupApiTests
{
    private const string WorkspaceId = "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b";
    private const string Subscription = "00000000-1111-2222-3333-444444444444";
    private const string WorkspaceResourceId =
        $"/subscriptions/{Subscription}/resourceGroups/rg-bower/providers/Microsoft.OperationalInsights/workspaces/law-bower";
    private const string DcrResourceId =
        $"/subscriptions/{Subscription}/resourceGroups/rg-bower/providers/Microsoft.Insights/dataCollectionRules/bower-dcr";

    [Theory]
    [InlineData("")]
    [InlineData("Bower.Collector")]
    public async Task Status_RequiresInteractiveRole(string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles)
            .GetAsync("/api/setup", cancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Status_ViewersSeeOrderedProgressReadOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        SetupStatus status = await StatusAsync(ManagementApiTests.Client(app, BowerRoles.Viewer), cancellationToken);
        SetupStatus admin = await StatusAsync(ManagementApiTests.Client(app, BowerRoles.Administrator), cancellationToken);

        Assert.False(status.CanChange);
        Assert.True(admin.CanChange);
        Assert.Equal(
            ["sign-in", "entra", "destination", "collector", "probe", "canary", "proof"],
            status.Steps.Select(step => step.Id));
        Assert.Equal(SetupStepStates.Complete, Step(status, SetupStepIds.SignIn).State);
        Assert.Equal(SetupStepStates.NotStarted, Step(status, SetupStepIds.Destination).State);
        Assert.Equal(SetupStepStates.NotStarted, Step(status, SetupStepIds.Collector).State);
        Assert.Equal(SetupStepStates.Blocked, Step(status, SetupStepIds.Canary).State);
        Assert.Equal(SetupStepStates.NotStarted, Step(status, SetupStepIds.Proof).State);
        Assert.False(status.Canary.Configured);
        Assert.Contains(status.ProbeOptions, option => option.Profile == ProbeProfiles.Generic);
        Assert.Contains(status.ProbeOptions, option => option.Profile == "parser:linux-ssh-gateway:0");
        // Every check that does not pass carries a suggested fix.
        Assert.All(
            status.Steps.SelectMany(step => step.Checks).Where(check => check.State != SetupCheckStates.Pass),
            check => Assert.False(string.IsNullOrWhiteSpace(check.Fix)));
    }

    [Theory]
    [InlineData("POST", "/api/setup/destination", BowerRoles.Operator)]
    [InlineData("POST", "/api/setup/destination", BowerRoles.Approver)]
    [InlineData("POST", "/api/setup/destination/check", BowerRoles.Operator)]
    [InlineData("POST", "/api/setup/probe-profile", BowerRoles.Viewer)]
    [InlineData("POST", "/api/setup/canary", BowerRoles.Approver)]
    [InlineData("POST", "/api/setup/canary", BowerRoles.Operator)]
    public async Task StateChanges_RequireAdministrator(string method, string path, string roles)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpRequestMessage request = new(new HttpMethod(method), path)
        {
            Content = JsonContent.Create(new SetupDestinationRequest(WorkspaceId, null, null, null))
        };
        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles).SendAsync(request, cancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("not-a-guid", null, null, null, "workspace ID")]
    [InlineData(WorkspaceId, $"/subscriptions/{Subscription}/resourceGroups/../providers/Microsoft.OperationalInsights/workspaces/law", null, null, "workspace resource ID")]
    [InlineData(WorkspaceId, null, $"/subscriptions/{Subscription}/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionRules/bad?x=1", null, "rule resource ID")]
    [InlineData(WorkspaceId, null, null, "Bower Security", "table")]
    public async Task Destination_RejectsInvalidIdentifiersWithFriendlyMessage(
        string workspaceId, string? workspaceResourceId, string? dcrResourceId, string? table, string expected)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            "/api/setup/destination",
            new SetupDestinationRequest(workspaceId, workspaceResourceId, dcrResourceId, table),
            cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(expected, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DestinationAndProbe_AreSavedServerSideAndAudited()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        using HttpResponseMessage saved = await admin.PostAsJsonAsync(
            "/api/setup/destination",
            new SetupDestinationRequest($" {WorkspaceId} ", WorkspaceResourceId, DcrResourceId, null),
            cancellationToken);
        using HttpResponseMessage unknown = await admin.PostAsJsonAsync(
            "/api/setup/probe-profile", new SetupProbeRequest("parser:other-pack:3"), cancellationToken);
        using HttpResponseMessage probe = await admin.PostAsJsonAsync(
            "/api/setup/probe-profile", new SetupProbeRequest("parser:linux-ssh-gateway:0"), cancellationToken);
        SetupStatus status = await StatusAsync(ManagementApiTests.Client(app, BowerRoles.Viewer), cancellationToken);
        AuditRecord[]? audit = await admin.GetFromJsonAsync<AuditRecord[]>("/api/audit", cancellationToken);

        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.OK, probe.StatusCode);
        Assert.Equal(WorkspaceId, status.Destination!.WorkspaceId);
        Assert.Equal("BowerSecurity_CL", status.Destination.Table);
        Assert.Equal("Test principal", status.Destination.UpdatedBy);
        Assert.Equal(SetupStepStates.Complete, Step(status, SetupStepIds.Destination).State);
        Assert.Equal("parser:linux-ssh-gateway:0", status.Probe!.Profile);
        Assert.Equal(SetupStepStates.Complete, Step(status, SetupStepIds.Probe).State);
        Assert.Contains(audit!, item => item.Action == "setup.destination-set" && item.TargetType == "setup");
        Assert.Contains(audit!, item => item.Action == "setup.probe-profile-set");
    }

    [Fact]
    public async Task CollectorStep_ReflectsApprovalsWithoutApprovingAnything()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);
        HttpClient viewer = ManagementApiTests.Client(app, BowerRoles.Viewer);
        await RegisterAsync(app, "edge-01", cancellationToken);

        SetupStatus pending = await StatusAsync(viewer, cancellationToken);
        await ManagementApiTests.Client(app, BowerRoles.Approver).PostAsJsonAsync(
            "/api/approvals/edge-01/approve", new ApprovalRequest("Expected collector"), cancellationToken);
        SetupStatus approved = await StatusAsync(viewer, cancellationToken);

        SetupStep waiting = Step(pending, SetupStepIds.Collector);
        Assert.Equal(SetupStepStates.Attention, waiting.State);
        Assert.Contains(waiting.Checks, check => check.State == SetupCheckStates.Warn && check.Fix!.Contains("Approvals", StringComparison.Ordinal));
        Assert.Equal(SetupCheckStates.Pass, Step(pending, SetupStepIds.Entra).Checks.Single(check => check.Id == "collector-role").State);
        Assert.Equal(SetupStepStates.Complete, Step(approved, SetupStepIds.Collector).State);
    }

    [Fact]
    public async Task Canary_RefusesUntilPrerequisitesAndConfiguration()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        using HttpResponseMessage early = await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        using HttpResponseMessage unconfigured = await admin.PostAsync("/api/setup/canary", null, cancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, early.StatusCode);
        Assert.Contains("Finish these steps first", await early.Content.ReadAsStringAsync(cancellationToken), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Conflict, unconfigured.StatusCode);
        Assert.Contains("not configured", await unconfigured.Content.ReadAsStringAsync(cancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Canary_VerifiedOnlyWhenTheDestinationQueryReturnsTheEvent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string keyFile = Path.Combine(directory.Path, "signing.pem");
        await File.WriteAllTextAsync(keyFile, privateKey, cancellationToken);
        FakeCollector collector = new();
        FakeQuery query = new();
        await using WebApplication app = await StartConfiguredAsync(
            directory, collector, query, cancellationToken, $"--Bower:Setup:Canary:SigningKeyFile={keyFile}");
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        using HttpResponseMessage started = await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupCanaryRun? accepted = await started.Content.ReadFromJsonAsync<SetupCanaryRun>(ManagementApiTests.ApiJson, cancellationToken);
        SetupStatus status = await CompletedAsync(admin, cancellationToken);
        using HttpResponseMessage bundle = await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetAsync($"/api/setup/canary/runs/{status.LatestRun!.Id}/bundle", cancellationToken);
        string bundleJson = await bundle.Content.ReadAsStringAsync(cancellationToken);
        string statusJson = await admin.GetStringAsync("/api/setup", cancellationToken);
        AuditRecord[]? audit = await admin.GetFromJsonAsync<AuditRecord[]>("/api/audit", cancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        Assert.Equal(SetupCanaryRunStates.Running, accepted!.State);
        Assert.Equal("canary-token-value", collector.LastToken);
        SetupCanaryRun run = status.LatestRun;
        Assert.Equal(EvidenceModes.Verified, run.Mode);
        Assert.Equal(ProbeOutcomes.Verified, run.Outcome);
        Assert.True(run.CollectorAccepted);
        Assert.True(run.HasSignature);
        Assert.StartsWith("bower-canary-", run.EventId, StringComparison.Ordinal);
        Assert.Equal(SetupStepStates.Complete, Step(status, SetupStepIds.Canary).State);
        Assert.Equal(SetupStepStates.Complete, Step(status, SetupStepIds.Proof).State);
        Assert.Equal(HttpStatusCode.OK, bundle.StatusCode);
        Assert.True(EvidenceRunner.Verify(EvidenceRunner.Parse(bundleJson), [publicKey]));
        Assert.DoesNotContain("canary-token-value", statusJson, StringComparison.Ordinal);
        Assert.DoesNotContain("canary-token-value", bundleJson, StringComparison.Ordinal);
        Assert.DoesNotContain(directory.Path, statusJson, StringComparison.Ordinal);
        Assert.Contains(audit!, item => item.Action == "setup.canary-requested" && item.TargetId == run.Id);
        Assert.Contains(audit!, item => item.Action == "setup.canary-verified" && item.TargetId == run.Id);
    }

    [Fact]
    public async Task Canary_AcceptedButRowMissingIsNotProof()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeQuery query = new() { Found = false };
        ManualTimeProvider clock = new(DateTimeOffset.UtcNow);
        await using WebApplication app = await StartConfiguredAsync(
            directory, new FakeCollector(), query, cancellationToken, "--Bower:Setup:Canary:TimeoutMinutes=1", clock: clock);
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus status;
        do
        {
            // The runner polls every 30 seconds until the one-minute deadline.
            await Task.Delay(50, cancellationToken);
            clock.Advance(TimeSpan.FromSeconds(30));
            status = await StatusAsync(admin, cancellationToken);
        }
        while (status.LatestRun!.State == SetupCanaryRunStates.Running);

        Assert.Equal(EvidenceModes.Failed, status.LatestRun!.Mode);
        Assert.True(status.LatestRun.CollectorAccepted);
        Assert.Equal(ProbeOutcomes.DestinationRowMissing, status.LatestRun.Outcome);
        Assert.Equal(SetupStepStates.Complete, Step(status, SetupStepIds.Canary).State);
        SetupStep proof = Step(status, SetupStepIds.Proof);
        Assert.Equal(SetupStepStates.Attention, proof.State);
        Assert.Contains(proof.Checks, check => check.State == SetupCheckStates.Fail && !string.IsNullOrWhiteSpace(check.Fix));
    }

    [Fact]
    public async Task Canary_WithoutVerifierIsSimulatedAndNeverProof()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartConfiguredAsync(directory, new FakeCollector(), null, cancellationToken);
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus status = await CompletedAsync(admin, cancellationToken);
        AuditRecord[]? audit = await admin.GetFromJsonAsync<AuditRecord[]>("/api/audit", cancellationToken);

        Assert.False(status.Canary.VerifierConfigured);
        Assert.Equal(EvidenceModes.Simulated, status.LatestRun!.Mode);
        Assert.Equal(ProbeOutcomes.AcceptedNotVerified, status.LatestRun.Outcome);
        Assert.Contains("Simulated", status.LatestRun.Message, StringComparison.Ordinal);
        Assert.False(status.LatestRun.HasSignature);
        Assert.Equal(SetupStepStates.Attention, Step(status, SetupStepIds.Proof).State);
        Assert.Contains(audit!, item => item.Action == "setup.canary-simulated");
    }

    [Theory]
    [InlineData(401, ProbeOutcomes.CollectorPermissionDenied)]
    [InlineData(503, ProbeOutcomes.CollectorRejected)]
    public async Task Canary_CollectorRefusalMapsToFixedFix(int status, string outcome)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeCollector collector = new() { CanaryStatus = status };
        await using WebApplication app = await StartConfiguredAsync(directory, collector, new FakeQuery(), cancellationToken);
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus result = await CompletedAsync(admin, cancellationToken);

        Assert.Equal(EvidenceModes.Failed, result.LatestRun!.Mode);
        Assert.Equal(outcome, result.LatestRun.Outcome);
        Assert.False(result.LatestRun.CollectorAccepted);
        Assert.False(string.IsNullOrWhiteSpace(result.LatestRun.Fix));
        Assert.Equal(SetupStepStates.Attention, Step(result, SetupStepIds.Canary).State);
        Assert.NotEqual(SetupStepStates.Complete, Step(result, SetupStepIds.Proof).State);
    }

    [Fact]
    public async Task Canary_UnreachableCollectorKeepsRawDetailServerSide()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeCollector collector = new() { Throw = new HttpRequestException("Connection refused (collector.internal:4319) secret-detail") };
        await using WebApplication app = await StartConfiguredAsync(directory, collector, new FakeQuery(), cancellationToken);
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus status = await CompletedAsync(admin, cancellationToken);
        string json = await admin.GetStringAsync("/api/setup", cancellationToken);

        Assert.Equal("collector-unreachable", status.LatestRun!.Outcome);
        Assert.Equal(EvidenceModes.Failed, status.LatestRun.Mode);
        Assert.False(status.LatestRun.HasBundle);
        Assert.DoesNotContain("secret-detail", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Canary_ParserProbeUsesProbeOutcomes()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeQuery query = new();
        await using WebApplication app = await StartConfiguredAsync(directory, new FakeCollector(), query, cancellationToken);
        await ReadyAsync(app, "parser:linux-ssh-gateway:0", cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus verified = await CompletedAsync(admin, cancellationToken);
        query.EventType = "process_started";
        await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus wrong = await CompletedAsync(admin, cancellationToken);

        Assert.Equal(EvidenceModes.Verified, verified.LatestRun!.Mode);
        Assert.StartsWith("bower-probe-", verified.LatestRun.EventId, StringComparison.Ordinal);
        Assert.Equal("parser:linux-ssh-gateway:0", verified.LatestRun.Profile);
        Assert.Equal(ProbeOutcomes.DestinationWrongEvent, wrong.LatestRun!.Outcome);
        Assert.Equal(EvidenceModes.Failed, wrong.LatestRun.Mode);
        Assert.NotEqual(verified.LatestRun.Id, wrong.LatestRun.Id);
        Assert.Equal(SetupStepStates.Attention, Step(wrong, SetupStepIds.Proof).State);
    }

    [Fact]
    public async Task Canary_RunsOneAtATime()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeCollector collector = new() { Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) };
        await using WebApplication app = await StartConfiguredAsync(directory, collector, new FakeQuery(), cancellationToken);
        await ReadyAsync(app, ProbeProfiles.Generic, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);

        using HttpResponseMessage first = await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        using HttpResponseMessage second = await admin.PostAsync("/api/setup/canary", null, cancellationToken);
        SetupStatus running = await StatusAsync(admin, cancellationToken);
        collector.Gate.SetResult();
        SetupStatus done = await CompletedAsync(admin, cancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal(SetupStepStates.InProgress, Step(running, SetupStepIds.Canary).State);
        Assert.Equal(EvidenceModes.Verified, done.LatestRun!.Mode);
    }

    [Fact]
    public async Task Store_MarksRunsLeftRunningAsInterrupted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ManagementStore store = new(Path.Combine(directory.Path, "management.db"));
        await store.InitializeAsync(cancellationToken);
        SetupCanaryRun run = await store.StartSetupCanaryRunAsync(
            ProbeProfiles.Generic, WorkspaceId, "BowerSecurity_CL", "admin", "Admin", TestEvents.Now, cancellationToken);

        int interrupted = await store.InterruptSetupCanaryRunsAsync(TestEvents.Now.AddMinutes(1), cancellationToken);
        SetupCanaryRun? latest = await store.LatestSetupCanaryRunAsync(cancellationToken);
        IReadOnlyList<AuditRecord> audit = await store.ListAuditAsync(cancellationToken);

        Assert.Equal(1, interrupted);
        Assert.Equal(run.Id, latest!.Id);
        Assert.Equal(SetupCanaryRunStates.Interrupted, latest.State);
        Assert.Equal("interrupted", latest.Outcome);
        Assert.Null(latest.Mode);
        Assert.Contains(audit, item => item.Action == "setup.canary-interrupted" && item.TargetId == run.Id);
    }

    [Fact]
    public async Task DcrTemplate_IsTheGeneratedDirectRule()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        using HttpResponseMessage response = await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetAsync("/api/setup/dcr-template", cancellationToken);
        JsonNode? template = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            DcrTemplateGenerator.Generate(new DcrTemplateOptions()).ToJsonString(),
            template!.ToJsonString());
    }

    [Fact]
    public async Task DestinationCheck_RunsDcrAndTableDriftReadOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        JsonObject template = DcrTemplateGenerator.Generate(new DcrTemplateOptions());
        JsonObject table = (JsonObject)template["resources"]![0]!.DeepClone();
        JsonObject rule = (JsonObject)template["resources"]![1]!.DeepClone();
        FakeArm arm = new() { [DcrResourceId] = rule, [$"{WorkspaceResourceId}/tables/BowerSecurity_CL"] = table };
        await using WebApplication app = await StartConfiguredAsync(directory, new FakeCollector(), new FakeQuery(), cancellationToken, arm: arm);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);
        await admin.PostAsJsonAsync(
            "/api/setup/destination", new SetupDestinationRequest(WorkspaceId, WorkspaceResourceId, DcrResourceId, null), cancellationToken);

        SetupCheckResult? healthy = await (await admin.PostAsync("/api/setup/destination/check", null, cancellationToken))
            .Content.ReadFromJsonAsync<SetupCheckResult>(ManagementApiTests.ApiJson, cancellationToken);
        arm.Remove(DcrResourceId);
        SetupCheckResult? missing = await (await admin.PostAsync("/api/setup/destination/check", null, cancellationToken))
            .Content.ReadFromJsonAsync<SetupCheckResult>(ManagementApiTests.ApiJson, cancellationToken);
        AuditRecord[]? audit = await admin.GetFromJsonAsync<AuditRecord[]>("/api/audit", cancellationToken);

        Assert.DoesNotContain(healthy!.Checks, check => check.State == SetupCheckStates.Fail);
        Assert.Contains(healthy.Checks, check => check.Id == "dcr" && check.State == SetupCheckStates.Pass);
        Assert.Contains(healthy.Checks, check => check.Id == "table" && check.State == SetupCheckStates.Pass);
        SetupCheck unreadable = Assert.Single(missing!.Checks, check => check.Id == "dcr");
        Assert.Equal(SetupCheckStates.Fail, unreadable.State);
        Assert.Contains("Reader", unreadable.Fix, StringComparison.Ordinal);
        Assert.Contains(audit!, item => item.Action == "setup.destination-checked");
    }

    [Fact]
    public async Task DestinationCheck_WithoutVerifierExplainsConfiguration()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartConfiguredAsync(directory, new FakeCollector(), null, cancellationToken);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);
        await admin.PostAsJsonAsync(
            "/api/setup/destination", new SetupDestinationRequest(WorkspaceId, WorkspaceResourceId, DcrResourceId, null), cancellationToken);

        using HttpResponseMessage response = await admin.PostAsync("/api/setup/destination/check", null, cancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("Bower:Setup:Canary:Credential", await response.Content.ReadAsStringAsync(cancellationToken), StringComparison.Ordinal);
    }

    private static async Task<WebApplication> StartConfiguredAsync(
        TemporaryDirectory directory,
        FakeCollector collector,
        FakeQuery? query,
        CancellationToken cancellationToken,
        string? extra = null,
        FakeArm? arm = null,
        TimeProvider? clock = null)
    {
        string tokenFile = Path.Combine(directory.Path, "canary.token");
        Directory.CreateDirectory(directory.Path);
        await File.WriteAllTextAsync(tokenFile, "canary-token-value\n", cancellationToken);
        List<string> args =
        [
            "--Bower:Setup:Canary:CollectorUrl=http://collector.test:4319",
            $"--Bower:Setup:Canary:IngestTokenFile={tokenFile}"
        ];
        if (query is not null)
        {
            args.Add("--Bower:Setup:Canary:Credential=managed-identity");
        }

        if (extra is not null)
        {
            args.Add(extra);
        }

        SetupEvidenceClients clients = new(collector, collector, query, query is null ? null : arm ?? new FakeArm());
        return await ManagementApiTests.StartAsync(
            directory,
            services => services.AddSingleton<ISetupEvidenceClientFactory>(new FixedClients(clients)),
            clock,
            cancellationToken,
            [.. args]);
    }

    private static async Task ReadyAsync(WebApplication app, string profile, CancellationToken cancellationToken)
    {
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator);
        await RegisterAsync(app, "edge-01", cancellationToken);
        await admin.PostAsJsonAsync("/api/approvals/edge-01/approve", new ApprovalRequest("Expected collector"), cancellationToken);
        (await admin.PostAsJsonAsync(
            "/api/setup/destination", new SetupDestinationRequest(WorkspaceId, null, null, null), cancellationToken)).EnsureSuccessStatusCode();
        (await admin.PostAsJsonAsync("/api/setup/probe-profile", new SetupProbeRequest(profile), cancellationToken)).EnsureSuccessStatusCode();
    }

    private static Task<HttpResponseMessage> RegisterAsync(WebApplication app, string id, CancellationToken cancellationToken) =>
        ManagementApiTests.Client(app, BowerRoles.Collector).PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration(id, id, "test", "0.1.0", "c", "p", [], []),
            cancellationToken);

    private static async Task<SetupStatus> StatusAsync(HttpClient client, CancellationToken cancellationToken) =>
        (await client.GetFromJsonAsync<SetupStatus>("/api/setup", ManagementApiTests.ApiJson, cancellationToken))!;

    private static async Task<SetupStatus> CompletedAsync(HttpClient client, CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        while (true)
        {
            SetupStatus status = await StatusAsync(client, cancellationToken);
            if (status.LatestRun is { State: not SetupCanaryRunStates.Running })
            {
                return status;
            }

            Assert.True(DateTimeOffset.UtcNow < deadline, "The canary run did not complete in time.");
            await Task.Delay(50, cancellationToken);
        }
    }

    private static SetupStep Step(SetupStatus status, string id) => status.Steps.Single(step => step.Id == id);

    private sealed class FixedClients(SetupEvidenceClients clients) : ISetupEvidenceClientFactory
    {
        public SetupEvidenceClients Create(SetupCanaryOptions options) => clients;
    }

    private sealed class FakeCollector : ICanarySender, IParserProbeSender
    {
        public int CanaryStatus { get; init; } = 202;

        public Exception? Throw { get; init; }

        public TaskCompletionSource? Gate { get; init; }

        public string? LastToken { get; private set; }

        public async Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken)
        {
            if (Gate is not null)
            {
                await Gate.Task.WaitAsync(cancellationToken);
            }

            if (Throw is not null)
            {
                throw Throw;
            }

            LastToken = token;
            return (CanaryStatus, new JsonObject { ["decision"] = CanaryStatus == 202 ? "accept" : null });
        }

        public Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken) =>
            Task.FromResult<(int, JsonObject?)>((200, new JsonObject
            {
                ["policy"] = new JsonObject
                {
                    ["hash"] = "sha256:collector-policy",
                    ["packs"] = new JsonArray
                    {
                        (JsonNode)new JsonObject
                        {
                            ["id"] = "linux-ssh-gateway",
                            ["version"] = "1.0.0",
                            ["packHash"] = "sha256:pack",
                            ["parserStatuses"] = new JsonArray { (JsonNode)"active-local-json" }
                        }
                    }
                }
            }));

        public Task<(int Status, JsonObject? Body)> SendRecordAsync(
            Uri collector, string? token, string packId, int parserIndex, string json, CancellationToken cancellationToken)
        {
            LastToken = token;
            string id = JsonNode.Parse(json)!["id"]!.GetValue<string>();
            return Task.FromResult<(int, JsonObject?)>((202, new JsonObject
            {
                ["eventId"] = id,
                ["queued"] = true,
                ["decision"] = "accept",
                ["policy"] = new JsonObject
                {
                    ["policyId"] = "BWR-POL-SSH",
                    ["policyVersion"] = "1.0.0",
                    ["policyHash"] = "sha256:event-policy"
                }
            }));
        }
    }

    private sealed partial class FakeQuery : ILogAnalyticsQuery
    {
        public bool Found { get; init; } = true;

        public string EventType { get; set; } = "authentication_failure";

        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            Match match = EventIdPattern().Match(kql);
            if (!Found || !match.Success)
            {
                return Task.FromResult(new QueryRows([], null));
            }

            Dictionary<string, JsonNode?> row = new(StringComparer.Ordinal)
            {
                ["TimeGenerated"] = "2026-10-27T00:00:00Z",
                ["IngestionTime"] = "2026-10-27T00:00:42Z",
                ["EventId"] = match.Groups[1].Value,
                ["EventType"] = EventType,
                ["PolicyHash"] = "sha256:event-policy"
            };
            return Task.FromResult(new QueryRows([row], null));
        }

        [GeneratedRegex("EventId == \"([^\"]+)\"")]
        private static partial Regex EventIdPattern();
    }

    private sealed class FakeArm : Dictionary<string, JsonObject>, IArmReader
    {
        public FakeArm()
            : base(StringComparer.Ordinal)
        {
        }

        public Task<JsonObject?> GetAsync(string resourceId, string apiVersion, CancellationToken cancellationToken) =>
            Task.FromResult(TryGetValue(resourceId, out JsonObject? value) ? (JsonObject?)value.DeepClone() : null);
    }
}
