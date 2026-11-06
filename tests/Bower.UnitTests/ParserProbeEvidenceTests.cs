using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// Opt-in parser probes (issue 74): a trusted fixture goes through a real in-process
/// collector's signed parser intake, and only the exact event read back from the intended
/// destination verifies. The destination fake answers from the collector's durable queue.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed partial class ParserProbeEvidenceTests
{
    private const string Token = "parser-probe-test-token-0123456789abcdef";
    private const string Profile = "parser:linux-ssh-gateway:0";
    private const string Workspace = "workspace-1";
    private static string Source => Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway");

    [Fact]
    public async Task ParserProbe_FailsClearlyWhenParserIsInactiveWhileGenericIntakeWorks()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, "inactive", cancellation);
        QueueDestination destination = new(app, Workspace);
        EvidenceRunner runner = Runner(app, destination);

        EvidenceBundle generic = await runner.RunAsync(Options(app, Workspace), cancellation);
        EvidenceBundle parser = await runner.RunAsync(Options(app, Workspace) with { ProbeProfile = Profile }, cancellation);

        Assert.Equal(EvidenceModes.Verified, generic.Mode);
        Assert.Null(generic.Probe);
        Assert.Equal(EvidenceModes.Failed, parser.Mode);
        ProbeRecord probe = parser.Probe!;
        Assert.Equal(ProbeOutcomes.ParserInactive, probe.Outcome);
        Assert.Equal("inactive-preview-only", probe.ParserStatus);
        Assert.Equal("1.1.0", probe.PackVersion);
        Assert.StartsWith("sha256:", probe.CollectorPolicyHash, StringComparison.Ordinal);
        Assert.False(string.IsNullOrEmpty(probe.PackHash));
        Assert.Equal(0, parser.Canary.CollectorStatus);
        Assert.Equal(ProbeOutcomes.ParserInactive, parser.Arrival.QueryError);
        Assert.DoesNotContain(destination.Queries, kql => kql.Contains(probe.EventId, StringComparison.Ordinal));
        Assert.Equal("not-evidenced", parser.Controls.Single(control => control.Id == "ISM-0580").Status);
    }

    [Theory]
    [InlineData("not-selected", ProbeOutcomes.ParserNotSelected, 422)]
    [InlineData("policy", ProbeOutcomes.PolicyNotSelected, 422)]
    [InlineData("wrong-event", ProbeOutcomes.ParserWrongEvent, 202)]
    public async Task ParserProbe_MappingOrSelectionRegressionFailsWhileGenericIntakeWorks(string variant, string outcome, int status)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, variant, cancellation);
        QueueDestination destination = new(app, Workspace);
        EvidenceRunner runner = Runner(app, destination);

        EvidenceBundle generic = await runner.RunAsync(Options(app, Workspace), cancellation);
        EvidenceBundle parser = await runner.RunAsync(Options(app, Workspace) with { ProbeProfile = Profile }, cancellation);

        Assert.Equal(EvidenceModes.Verified, generic.Mode);
        Assert.Equal(EvidenceModes.Failed, parser.Mode);
        Assert.Equal(outcome, parser.Probe!.Outcome);
        Assert.Equal("active-local-json", parser.Probe.ParserStatus);
        Assert.Equal(status, parser.Canary.CollectorStatus);
        Assert.False(parser.Arrival.Found);
        Assert.DoesNotContain(destination.Queries, kql => kql.Contains(parser.Probe.EventId, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ParserProbe_VerifiesOnlyTheExactEventFromTheIntendedDestination()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, "active", cancellation);
        QueueDestination destination = new(app, Workspace);

        EvidenceBundle bundle = await Runner(app, destination).RunAsync(Options(app, Workspace) with { ProbeProfile = Profile }, cancellation);

        Assert.Equal(EvidenceModes.Verified, bundle.Mode);
        ProbeRecord probe = bundle.Probe!;
        Assert.Equal(ProbeOutcomes.Verified, probe.Outcome);
        Assert.Equal(Profile, probe.Profile);
        Assert.Equal("linux-ssh-gateway", probe.PackId);
        Assert.Equal(0, probe.ParserIndex);
        Assert.Equal("1.1.0", probe.PackVersion);
        Assert.Equal("active-local-json", probe.ParserStatus);
        Assert.StartsWith("bower-probe-", probe.EventId, StringComparison.Ordinal);
        Assert.Equal(probe.EventId, bundle.Canary.EventId);
        Assert.Equal("authentication_failure", probe.ExpectedEventType);
        Assert.Equal(Workspace, probe.DestinationWorkspaceId);
        Assert.Equal("BowerSecurity_CL", probe.DestinationTable);
        Assert.NotNull(probe.QueriedAt);
        Assert.StartsWith("sha256:", probe.EventPolicyHash, StringComparison.Ordinal);
        Assert.Equal(probe.EventPolicyHash, bundle.Arrival.RowPolicyHash);
        Assert.Contains(probe.UntestedPaths, path => path.Contains("/v1/events", StringComparison.Ordinal));
        Assert.Contains($"EventId == \"{probe.EventId}\"", Assert.Single(destination.Queries, kql => kql.Contains("EventType", StringComparison.Ordinal)), StringComparison.Ordinal);
        // The normal privacy path ran: the fixture username never reached the queue.
        Assert.DoesNotContain("bower-evidence-probe", destination.Payloads, StringComparison.Ordinal);

        // The same event in another workspace, or a different event in this one, never verifies.
        using TemporaryDirectory other = new();
        await using WebApplication elsewhere = await Start(other, "active", cancellation);
        EvidenceBundle wrongWorkspace = await Runner(elsewhere, new QueueDestination(elsewhere, "workspace-2"))
            .RunAsync(Options(elsewhere, Workspace) with { ProbeProfile = Profile }, cancellation);
        Assert.Equal(EvidenceModes.Failed, wrongWorkspace.Mode);
        Assert.Equal(ProbeOutcomes.DestinationRowMissing, wrongWorkspace.Probe!.Outcome);

        EvidenceBundle stale = await Runner(elsewhere, new FixedRowDestination("bower-probe-0000", "authentication_failure"))
            .RunAsync(Options(elsewhere, Workspace) with { ProbeProfile = Profile }, cancellation);
        Assert.Equal(ProbeOutcomes.DestinationWrongEvent, stale.Probe!.Outcome);
        Assert.Equal(EvidenceModes.Failed, stale.Mode);
    }

    [Fact]
    public async Task ParserProbe_AcceptanceAloneNeverVerifies()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, "active", cancellation);

        EvidenceBundle simulated = await Runner(app, null).RunAsync(Options(app, null) with { ProbeProfile = Profile }, cancellation);

        Assert.Equal(202, simulated.Canary.CollectorStatus);
        Assert.Equal(EvidenceModes.Simulated, simulated.Mode);
        Assert.Equal(ProbeOutcomes.AcceptedNotVerified, simulated.Probe!.Outcome);
        Assert.Contains(simulated.Limitations, item => item.StartsWith("SIMULATED", StringComparison.Ordinal));
        Assert.All(simulated.Controls, control => Assert.NotEqual("evidenced", control.Status));
    }

    [Theory]
    [InlineData("permission", ProbeOutcomes.DestinationPermissionDenied, 1, "InsufficientAccessError")]
    [InlineData("missing", ProbeOutcomes.DestinationRowMissing, 3, ProbeOutcomes.DestinationRowMissing)]
    [InlineData("timeout", ProbeOutcomes.DestinationTimeout, 3, ProbeOutcomes.QueryTimeoutCode)]
    [InlineData("gateway", ProbeOutcomes.DestinationTimeout, 3, "GatewayTimeout")]
    [InlineData("other", ProbeOutcomes.DestinationQueryFailed, 3, "BadArgumentError")]
    [InlineData("answered-then-timeout", ProbeOutcomes.DestinationRowMissing, 3, ProbeOutcomes.DestinationRowMissing)]
    [InlineData("answered-then-failed", ProbeOutcomes.DestinationRowMissing, 3, ProbeOutcomes.DestinationRowMissing)]
    // A partial answer at the deadline may have dropped the probe row: never "row missing".
    [InlineData("answered-then-incomplete", ProbeOutcomes.DestinationQueryFailed, 3, ProbeOutcomes.QueryIncompleteCode)]
    public async Task ParserProbe_DestinationFailuresStayDistinct(string failure, string outcome, int attempts, string queryError)
    {
        FakeClock clock = new(TestEvents.Now);
        EvidenceRunner runner = new(new FakeCollector(), new FailingDestination(failure, clock), null, clock);

        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions
            {
                CollectorUrl = new Uri("http://collector.test:4319/"),
                WorkspaceId = Workspace,
                ProbeProfile = Profile,
                Timeout = TimeSpan.FromMinutes(1),
                PollInterval = TimeSpan.Zero
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal(outcome, bundle.Probe!.Outcome);
        Assert.Equal(attempts, bundle.Arrival.Attempts);
        Assert.Equal(queryError, bundle.Arrival.QueryError);
        Assert.False(bundle.Arrival.Found);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<html><body>504 Gateway Time-out</body></html>")]
    public async Task ParserProbe_NonJsonQueryErrorBodyIsATimeoutNotACrash(string body)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        StubHandler handler = new(System.Net.HttpStatusCode.GatewayTimeout, body);
        LogAnalyticsQueryClient client = new(new HttpClient(handler), new StaticCredential());

        QueryRows rows = await client.QueryAsync(Workspace, "BowerSecurity_CL | take 1", TimeSpan.FromHours(1), cancellation);
        EvidenceOptions options = new()
        {
            CollectorUrl = new Uri("http://collector.test:4319/"),
            WorkspaceId = Workspace,
            Timeout = TimeSpan.FromMilliseconds(30),
            PollInterval = TimeSpan.FromMilliseconds(10)
        };
        EvidenceBundle parser = await new EvidenceRunner(new FakeCollector(), client, null, TimeProvider.System)
            .RunAsync(options with { ProbeProfile = Profile }, cancellation);
        EvidenceBundle generic = await new EvidenceRunner(new FakeCollector(), client, null, TimeProvider.System)
            .RunAsync(options, cancellation);

        Assert.Equal("http-504", rows.Error);
        Assert.Empty(rows.Rows);
        Assert.Equal(ProbeOutcomes.DestinationTimeout, parser.Probe!.Outcome);
        Assert.Equal("http-504", parser.Arrival.QueryError);
        Assert.Equal(EvidenceModes.Failed, parser.Mode);
        // The generic probe keeps its claim: not found, with the status code as the error.
        Assert.Equal(EvidenceModes.Failed, generic.Mode);
        Assert.Equal("http-504", generic.Arrival.QueryError);
        Assert.Null(generic.Probe);
    }

    [Fact]
    public async Task LogAnalyticsQuery_BypassesCachedEmptyResults()
    {
        using HttpClient http = new(new CacheAwareQueryHandler());
        LogAnalyticsQueryClient client = new(http, new StaticCredential());

        QueryRows result = await client.QueryAsync(Workspace, "T | take 1", TimeSpan.FromHours(1), TestContext.Current.CancellationToken);

        Assert.Null(result.Error);
        Assert.Equal("fresh", Assert.Single(result.Rows)["EventId"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("""{"error":{"code":"PartialError"},"tables":[{"columns":[{"name":"EventId"}],"rows":[["e1"]]}]}""", "query-incomplete")]
    [InlineData("""{"error":{},"tables":[{"columns":[{"name":"EventId"}],"rows":[["e1"]]}]}""", "query-incomplete")]
    [InlineData("""{"error":{"code":"sensitive query marker"},"tables":[{"columns":[{"name":"EventId"}],"rows":[["e1"]]}]}""", "query-incomplete")]
    // Any non-null error, even a falsy scalar, is a partial result (same as the Rust client).
    [InlineData("""{"error":false,"tables":[{"columns":[{"name":"EventId"}],"rows":[["e1"]]}]}""", "query-incomplete")]
    [InlineData("""{"error":"","tables":[{"columns":[{"name":"EventId"}],"rows":[["e1"]]}]}""", "query-incomplete")]
    [InlineData("""{"error":0,"tables":[{"columns":[{"name":"EventId"}],"rows":[["e1"]]}]}""", "query-incomplete")]
    public async Task LogAnalyticsQuery_DoesNotUseRowsFromPartialSuccess(string body, string expectedError)
    {
        using HttpClient http = new(new StubHandler(System.Net.HttpStatusCode.OK, body));
        LogAnalyticsQueryClient client = new(http, new StaticCredential());

        QueryRows result = await client.QueryAsync(Workspace, "T | take 1", TimeSpan.FromHours(1), TestContext.Current.CancellationToken);

        Assert.Equal(expectedError, result.Error);
        Assert.DoesNotContain("sensitive query marker", result.Error, StringComparison.Ordinal);
        Assert.Empty(result.Rows);
    }

    [Fact]
    public async Task ParserProbe_DestinationPolicyHashMismatchIsNotVerified()
    {
        ProbeEchoDestination destination = new("sha256:another-replica");
        EvidenceRunner runner = new(new FakeCollector(), destination, null, new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/"), WorkspaceId = Workspace, ProbeProfile = Profile },
            TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal(ProbeOutcomes.ConfigurationMismatch, bundle.Probe!.Outcome);
        Assert.False(bundle.Arrival.Found);
        Assert.Equal("sha256:another-replica", bundle.Arrival.RowPolicyHash);
        Assert.Equal("sha256:policy", bundle.Probe.EventPolicyHash);
    }

    [Theory]
    [InlineData("s3", null, "s3")]
    [InlineData("s3", Profile, "s3")]
    [InlineData("foo", null, "foo")]
    [InlineData("foo", Profile, "foo")]
    [InlineData("S3; drop", null, "unknown")]
    public async Task NonSentinelOutput_IsRefusedWithoutSendingAProbe(string output, string? profile, string label)
    {
        ProbeEchoDestination destination = new();
        FakeCollector collector = new(output: output);
        EvidenceRunner runner = new(collector, destination, null, new FakeClock(TestEvents.Now));
        EvidenceOptions options = new()
        {
            CollectorUrl = new Uri("http://collector.test:4319/"),
            WorkspaceId = Workspace,
            ProbeProfile = profile ?? ProbeProfiles.Generic
        };

        EvidenceBundle bundle = await runner.RunAsync(options, TestContext.Current.CancellationToken);
        EvidenceBundle simulated = await new EvidenceRunner(collector, null, null, new FakeClock(TestEvents.Now))
            .RunAsync(options with { WorkspaceId = null }, TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal(EvidenceModes.Simulated, simulated.Mode);
        Assert.False(bundle.Arrival.Found);
        Assert.Equal(ProbeOutcomes.CollectorOutputNotSentinel, bundle.Arrival.QueryError);
        Assert.Contains(ProbeOutcomes.NonSentinelLimitation(label), bundle.Limitations);
        Assert.Contains(ProbeOutcomes.NonSentinelLimitation(label), simulated.Limitations);
        Assert.Equal(0, collector.Canaries + collector.Records);
        Assert.DoesNotContain(destination.Queries, kql => kql.Contains(bundle.Canary.EventId, StringComparison.Ordinal));
        if (profile is not null)
        {
            Assert.Equal(ProbeOutcomes.CollectorOutputNotSentinel, bundle.Probe!.Outcome);
        }
    }

    [Theory]
    [InlineData("azure-logs-ingestion", null, 200)]
    [InlineData("azure-logs-ingestion", Profile, 200)]
    [InlineData("ama-spool", null, 200)]
    [InlineData("ama-spool", Profile, 200)]
    [InlineData("relay", null, 200)]
    [InlineData("relay", Profile, 200)]
    [InlineData(null, null, 200)]
    [InlineData(null, Profile, 200)]
    [InlineData(null, null, 500)]
    public async Task SentinelAllowlistedOrUnknownOutput_ProceedsAndOnlyTheQueryVerifies(string? output, string? profile, int statusCode)
    {
        ProbeEchoDestination destination = new();
        FakeCollector collector = new(statusCode: statusCode, output: output);
        EvidenceRunner runner = new(collector, destination, null, new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions
            {
                CollectorUrl = new Uri("http://collector.test:4319/"),
                WorkspaceId = Workspace,
                ProbeProfile = profile ?? ProbeProfiles.Generic
            },
            TestContext.Current.CancellationToken);

        // Relay, a missing output field and unreadable status all proceed: the canary or probe
        // is sent and only the Sentinel query (here an echoing fake) can verify it.
        Assert.Equal(1, collector.Canaries + collector.Records);
        Assert.Equal(EvidenceModes.Verified, bundle.Mode);
        Assert.True(bundle.Arrival.Found);
        Assert.DoesNotContain(bundle.Limitations, item => item.StartsWith("NOT SENTINEL", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StalledStatus_TimesOutAsUnreadable_AndTheCanaryProceeds()
    {
        StallingStatusCollector handler = new();
        HttpCanarySender sender = new(new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(200) });
        EvidenceRunner runner = new(sender, null, null, new FakeClock(TestEvents.Now), sender);

        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/") },
            TestContext.Current.CancellationToken);

        Assert.Equal(1, handler.StatusReads);
        Assert.Equal(202, bundle.Canary.CollectorStatus);
        Assert.Equal(EvidenceModes.Simulated, bundle.Mode);
        Assert.DoesNotContain(bundle.Limitations, item => item.StartsWith("NOT SENTINEL", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StalledStatus_CallerCancellationStillStopsTheRun()
    {
        StallingStatusCollector handler = new();
        HttpCanarySender sender = new(new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan });
        EvidenceRunner runner = new(sender, null, null, new FakeClock(TestEvents.Now), sender);
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/") }, cancellation.Token));
        Assert.Equal(0, handler.Canaries);
    }

    /// <summary>/v1/status never answers; /v1/events accepts the canary.</summary>
    private sealed class StallingStatusCollector : HttpMessageHandler
    {
        public int StatusReads { get; private set; }

        public int Canaries { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/v1/status")
            {
                StatusReads++;
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            Canaries++;
            return new HttpResponseMessage(System.Net.HttpStatusCode.Accepted)
            {
                Content = new StringContent("""{"decision":"accept"}""", System.Text.Encoding.UTF8, "application/json")
            };
        }
    }

    [Theory]
    [InlineData("queued-false")]
    [InlineData("duplicate")]
    [InlineData("suppressed")]
    public async Task ParserProbe_AcceptedButNotQueuedSkipsTheDestinationQuery(string variant)
    {
        ProbeEchoDestination destination = new();
        EvidenceRunner runner = new(new FakeCollector(notQueued: variant), destination, null, new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/"), WorkspaceId = Workspace, ProbeProfile = Profile },
            TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal(ProbeOutcomes.ProbeNotQueued, bundle.Probe!.Outcome);
        Assert.Equal(202, bundle.Canary.CollectorStatus);
        Assert.DoesNotContain(destination.Queries, kql => kql.Contains(bundle.Probe.EventId, StringComparison.Ordinal));
    }

    private sealed class StubHandler(System.Net.HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, body.Length == 0 ? "text/plain" : "text/html")
            });
    }

    private sealed class CacheAwareQueryHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Headers.CacheControl?.NoCache == true
                ? """{"tables":[{"columns":[{"name":"EventId"}],"rows":[["fresh"]]}]}"""
                : """{"tables":[{"columns":[{"name":"EventId"}],"rows":[]}]}""";
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }

    private sealed class StaticCredential : Azure.Core.TokenCredential
    {
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("synthetic", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    [Theory]
    [InlineData(401, ProbeOutcomes.CollectorPermissionDenied)]
    [InlineData(500, ProbeOutcomes.CollectorStatusUnreadable)]
    public async Task ParserProbe_CollectorStatusFailuresNeverSendTheFixture(int status, string outcome)
    {
        FakeCollector collector = new(statusCode: status);
        EvidenceRunner runner = new(collector, new FixedRowDestination("unused", "unused"), null, new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/"), WorkspaceId = Workspace, ProbeProfile = Profile },
            TestContext.Current.CancellationToken);

        Assert.Equal(outcome, bundle.Probe!.Outcome);
        Assert.Equal(0, collector.Records);
        Assert.Null(bundle.Probe.PackHash);
    }

    [Fact]
    public async Task ParserProbe_UnknownProfileFailsBeforeAnythingIsSent()
    {
        FakeCollector collector = new();
        EvidenceRunner runner = new(collector, null, null, new FakeClock(TestEvents.Now));

        ArgumentException failure = await Assert.ThrowsAsync<ArgumentException>(() => runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/"), ProbeProfile = "parser:linux-ssh-gateway:7" },
            TestContext.Current.CancellationToken));

        Assert.Contains(Profile, failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, collector.StatusReads + collector.Records);
    }

    [Fact]
    public async Task ParserProbe_BundleIsSignedAdditiveAndMetadataOnly()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeClock clock = new(TestEvents.Now);
        EvidenceRunner runner = new(new FakeCollector(), new ProbeEchoDestination(), null, clock);
        EvidenceBundle parser = await runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/"), IngestToken = Token, WorkspaceId = Workspace, ProbeProfile = Profile },
            cancellation);
        EvidenceBundle generic = await runner.RunAsync(
            new EvidenceOptions { CollectorUrl = new Uri("http://collector.test:4319/"), IngestToken = Token, WorkspaceId = Workspace },
            cancellation);
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();

        SignedEvidence signed = EvidenceRunner.Sign(parser, privatePem);
        string json = JsonSerializer.Serialize(signed);

        Assert.Equal(EvidenceModes.Verified, parser.Mode);
        Assert.True(EvidenceRunner.Verify(EvidenceRunner.Parse(json), [publicPem]));
        JsonObject probe = Assert.IsType<JsonObject>(signed.Bundle["probe"]);
        Assert.Equal("sha256:pack", probe["packHash"]!.GetValue<string>());
        Assert.Equal("sha256:bundle", probe["collectorPolicyHash"]!.GetValue<string>());
        Assert.Equal(ProbeOutcomes.UntestedPaths.Count, probe["untestedPaths"]!.AsArray().Count);
        Assert.False(EvidenceRunner.Sign(generic, null).Bundle.ContainsKey("probe"));
        foreach (string forbidden in new[] { Token, "bower-evidence-probe", "192.0.2.10", "\"user\"" })
        {
            Assert.DoesNotContain(forbidden, json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ParserProbeFixture_IsSyntheticBoundedAndMatchesTheShippedParser()
    {
        ParserProbeFixture fixture = ProbeProfiles.ResolveParser(Profile);
        string raw = fixture.Render("bower-probe-0190aaaabbbbccccddddeeeeffff0000", DateTimeOffset.Parse("2026-10-26T01:02:03.4567891Z", System.Globalization.CultureInfo.InvariantCulture));

        // Parity vector shared with rust/crates/bower-evidence/tests/evidence_tests.rs.
        Assert.Equal(
            """{"id":"bower-probe-0190aaaabbbbccccddddeeeeffff0000","timestamp":"2026-10-26T01:02:03.4567891Z","user":"bower-evidence-probe","source_ip":"192.0.2.10","result":"failure"}""",
            raw);
        Assert.True(raw.Length < PackRuntime.MaximumRecordBytes);
        Assert.DoesNotMatch(SecretLike(), raw);
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        LoadedPack pack = PackArchive.Load(PackArchive.Build(Source, privatePem, directory.Path), [publicPem]);
        SecurityEventEnvelope envelope = PackRuntime.Parse(pack.Parsers[fixture.ParserIndex], raw, DateTimeOffset.UnixEpoch)!;
        Assert.Equal("bower-probe-0190aaaabbbbccccddddeeeeffff0000", envelope.EventId);
        Assert.Equal(fixture.ExpectedEventType, envelope.EventType);
    }

    [GeneratedRegex("password|secret|token|key|cookie", RegexOptions.IgnoreCase)]
    private static partial Regex SecretLike();

    private static EvidenceRunner Runner(WebApplication app, ILogAnalyticsQuery? destination)
    {
        HttpCanarySender sender = new(app.GetTestClient());
        return new EvidenceRunner(sender, destination, null, TimeProvider.System, sender);
    }

    private static EvidenceOptions Options(WebApplication app, string? workspace) =>
        new()
        {
            CollectorUrl = app.GetTestClient().BaseAddress!,
            IngestToken = Token,
            WorkspaceId = workspace,
            Timeout = TimeSpan.FromMilliseconds(30),
            PollInterval = TimeSpan.FromMilliseconds(10)
        };

    private static async Task<WebApplication> Start(TemporaryDirectory directory, string variant, CancellationToken cancellation)
    {
        (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string source = Path.Combine(directory.Path, "pack");
        foreach (string path in Directory.EnumerateFiles(Source, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(source, Path.GetRelativePath(Source, path));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(path, target);
        }

        if (variant != "active")
        {
            string parserPath = Path.Combine(source, "parsers", "sshd-json.json");
            JsonObject parser = JsonNode.Parse(File.ReadAllText(parserPath))!.AsObject();
            JsonObject runtime = parser["runtime"]!.AsObject();
            switch (variant)
            {
                case "inactive": parser.Remove("runtime"); break;
                case "not-selected": runtime["match"] = new JsonObject { ["result"] = "denied" }; break;
                case "policy": runtime["eventType"] = "authentication_success"; break;
                case "wrong-event": runtime["fields"]!["eventId"] = "user"; break;
            }

            File.WriteAllText(parserPath, parser.ToJsonString());
            // Raw samples would fail signing for the regressed parser; envelope samples still run.
            string samples = Path.Combine(source, "samples", "ssh.jsonl");
            File.WriteAllLines(samples, File.ReadAllLines(samples).Where(line => !line.Contains("\"raw\":", StringComparison.Ordinal)));
        }

        string archive = PackArchive.Build(source, privateKey, directory.Path);
        string trust = Path.Combine(directory.Path, "trusted.pem");
        string hmac = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(trust, publicKey);
        File.WriteAllText(hmac, Convert.ToBase64String(new byte[32]));
        WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            CollectorId = "parser-probe-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            Packs = [archive],
            PackTrustedKeyFiles = [trust],
            PrivacyHmacKeyFile = hmac,
            IngestToken = Token,
            SingleTrustDomain = true
        }, builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        return app;
    }

    /// <summary>
    /// A destination that holds what the collector queued (standing in for delivery) and
    /// answers only for its own workspace and only for the exact EventId in the query.
    /// </summary>
    private sealed partial class QueueDestination(WebApplication app, string workspace) : ILogAnalyticsQuery
    {
        private readonly Dictionary<string, SecurityEventEnvelope> delivered = new(StringComparer.Ordinal);

        public List<string> Queries { get; } = [];

        public string Payloads { get; private set; } = string.Empty;

        public async Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            Queries.Add(kql);
            foreach (QueuedEvent queued in await app.Services.GetRequiredService<IDurableEventStore>().LeaseAsync(100, TimeSpan.FromHours(1), cancellationToken))
            {
                Payloads += queued.Payload;
                delivered[queued.EventId] = JsonSerializer.Deserialize(queued.Payload, BowerJson.Envelope)!;
            }

            if (workspaceId != workspace || EventIdFilter().Match(kql) is not { Success: true } match
                || !delivered.TryGetValue(match.Groups[1].Value, out SecurityEventEnvelope? row))
            {
                return new QueryRows([], null);
            }

            return new QueryRows(
                [new Dictionary<string, JsonNode?>
                {
                    ["TimeGenerated"] = row.TimeGenerated.ToString("O"),
                    ["IngestionTime"] = DateTimeOffset.UtcNow.ToString("O"),
                    ["EventId"] = row.EventId,
                    ["EventType"] = row.EventType,
                    ["PolicyHash"] = row.Security?.PolicyHash
                }],
                null);
        }

        [GeneratedRegex("EventId == \"([^\"]+)\"")]
        private static partial Regex EventIdFilter();
    }

    private sealed class FixedRowDestination(string eventId, string eventType) : ILogAnalyticsQuery
    {
        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken) =>
            Task.FromResult(new QueryRows(
                [new Dictionary<string, JsonNode?> { ["EventId"] = eventId, ["EventType"] = eventType, ["IngestionTime"] = "2026-07-26T02:16:19Z" }],
                null));
    }

    /// <summary>Returns the probe row for whatever EventId is queried (signing and metadata tests).</summary>
    private sealed partial class ProbeEchoDestination(string policyHash = "sha256:policy") : ILogAnalyticsQuery
    {
        public List<string> Queries { get; } = [];

        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            Queries.Add(kql);
            Match match = Filter().Match(kql);
            return Task.FromResult(match.Success
                ? new QueryRows(
                    [new Dictionary<string, JsonNode?>
                    {
                        ["EventId"] = match.Groups[1].Value,
                        ["EventType"] = kql.Contains("EventType", StringComparison.Ordinal) ? "authentication_failure" : null,
                        ["IngestionTime"] = "2026-07-26T02:16:19Z",
                        ["PolicyHash"] = policyHash
                    }],
                    null)
                : new QueryRows([], null));
        }

        [GeneratedRegex("EventId == \"([^\"]+)\"")]
        private static partial Regex Filter();
    }

    private sealed class FailingDestination(string failure, FakeClock clock) : ILogAnalyticsQuery
    {
        private int probeQueries;

        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            if (kql.StartsWith("DCRLogErrors", StringComparison.Ordinal))
            {
                return Task.FromResult(new QueryRows([], null));
            }

            // Each probe query takes 30 seconds, so three queries cover the one-minute window.
            clock.Advance(TimeSpan.FromSeconds(30));
            if (failure.StartsWith("answered-then-", StringComparison.Ordinal) && ++probeQueries == 1)
            {
                return Task.FromResult(new QueryRows([], null));
            }

            return failure switch
            {
                "permission" => Task.FromResult(new QueryRows([], "InsufficientAccessError")),
                "missing" => Task.FromResult(new QueryRows([], null)),
                "timeout" or "answered-then-timeout" => Task.FromException<QueryRows>(new TaskCanceledException("synthetic timeout")),
                "gateway" => Task.FromResult(new QueryRows([], "GatewayTimeout")),
                "answered-then-incomplete" => Task.FromResult(new QueryRows(
                    [new Dictionary<string, JsonNode?> { ["EventId"] = "candidate" }], ProbeOutcomes.QueryIncompleteCode)),
                _ => Task.FromResult(new QueryRows([], "BadArgumentError"))
            };
        }
    }

    /// <summary>A collector reporting an active linux-ssh-gateway parser that accepts the probe.</summary>
    private sealed class FakeCollector(int statusCode = 200, string? notQueued = null, string? output = null) : ICanarySender, IParserProbeSender
    {
        public int StatusReads { get; private set; }

        public int Records { get; private set; }

        public int Canaries { get; private set; }

        public Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken)
        {
            Canaries++;
            string eventId = JsonNode.Parse(json)!["eventId"]!.GetValue<string>();
            return Task.FromResult<(int, JsonObject?)>((202, new JsonObject { ["eventId"] = eventId, ["decision"] = "accept" }));
        }

        public Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken)
        {
            StatusReads++;
            return Task.FromResult<(int, JsonObject?)>((statusCode, statusCode != 200 ? null : new JsonObject
            {
                ["policy"] = new JsonObject
                {
                    ["hash"] = "sha256:bundle",
                    ["packs"] = new JsonArray(new JsonObject
                    {
                        ["id"] = "linux-ssh-gateway",
                        ["version"] = "1.1.0",
                        ["packHash"] = "sha256:pack",
                        ["parserStatuses"] = new JsonArray("active-local-json")
                    })
                },
                ["output"] = output
            }));
        }

        public Task<(int Status, JsonObject? Body)> SendRecordAsync(
            Uri collector, string? token, string packId, int parserIndex, string json, CancellationToken cancellationToken)
        {
            Records++;
            string eventId = JsonNode.Parse(json)!["id"]!.GetValue<string>();
            return Task.FromResult<(int, JsonObject?)>((202, new JsonObject
            {
                ["eventId"] = eventId,
                ["decision"] = "redactandaccept",
                ["queued"] = notQueued is null or "suppressed",
                ["duplicate"] = notQueued == "duplicate",
                ["suppressed"] = notQueued == "suppressed",
                ["policy"] = new JsonObject { ["policyId"] = "BWR-PACK-SSH-AUTH", ["policyVersion"] = "1.0.0", ["policyHash"] = "sha256:policy" }
            }));
        }
    }
}
