using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Azure.Core;
using Bower.Cli.Commands;
using Bower.Dcr;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Packs;

namespace Bower.UnitTests;

/// <summary>CLI behaviour that the Rust port mirrors (see rust/crates/bower-cli).</summary>
public sealed class CliCommandTests
{
    [Theory]
    [InlineData(new[] { "--foo", "bar", "p.yaml" }, "p.yaml")]
    [InlineData(new[] { "--foo", "bar" }, null)]
    [InlineData(new[] { "--file" }, null)]
    [InlineData(new[] { "aws-security", "--id" }, "aws-security")]
    public void Positional_SkipsEveryOptionAndItsValue(string[] args, string? expected)
    {
        Assert.Equal(expected, CliOptions.Positional(args));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"bundle\":null,\"signature\":null}")]
    [InlineData("{\"bundle\":\"x\"}")]
    [InlineData("{\"bundle\":{},\"signature\":5}")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("not json")]
    public void EvidenceParse_ReportsUnreadableBundlesInsteadOfCrashing(string json)
    {
        InvalidDataException exception = Assert.Throws<InvalidDataException>(() => EvidenceRunner.Parse(json));
        Assert.Equal("Evidence bundle is unreadable.", exception.Message);
    }

    [Fact]
    public void EvidenceParse_ReadsBundleAndMode()
    {
        SignedEvidence evidence = EvidenceRunner.Parse("{\"bundle\":{\"mode\":\"simulated\"},\"signature\":null}");
        Assert.Equal("simulated", EvidenceRunner.ModeOf(evidence));
        Assert.False(EvidenceRunner.Verify(evidence, []));
        Assert.Equal("unknown", EvidenceRunner.ModeOf(EvidenceRunner.Parse("{\"bundle\":{\"mode\":5}}")));
    }

    [Theory]
    [InlineData(new string[0], 15)]
    [InlineData(new[] { "--timeout-minutes", "1" }, 1)]
    [InlineData(new[] { "--timeout-minutes", "1440" }, 1440)]
    public void TimeoutMinutes_AcceptsOneMinuteToOneDay(string[] args, int expected)
    {
        Assert.Equal(expected, EvidenceCommands.TimeoutMinutes(args));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("1441")]
    [InlineData("2147483647")]
    public void TimeoutMinutes_RejectsNonPositiveAndHugeValues(string value)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EvidenceCommands.TimeoutMinutes(["--timeout-minutes", value]));
        Assert.Equal("--timeout-minutes must be between 1 and 1440.", exception.Message);
    }

    [Fact]
    public async Task HttpTimeouts_AreReportedButCancellationIsNot()
    {
        using SilentServer server = SilentServer.Start();
        using HttpClient http = new() { Timeout = TimeSpan.FromMilliseconds(500) };

        TaskCanceledException timeout = await Assert.ThrowsAsync<TaskCanceledException>(() => http.GetAsync(server.Url, TestContext.Current.CancellationToken));
        Assert.True(CliFailures.IsHttpTimeout(timeout));
        Assert.True(CliFailures.IsReportable(timeout));
        Assert.Equal("The request was canceled due to the configured HttpClient.Timeout of 0.5 seconds elapsing.", timeout.Message);

        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();
        OperationCanceledException userCancel = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => http.GetAsync(server.Url, cancelled.Token));
        Assert.False(CliFailures.IsHttpTimeout(userCancel));
        Assert.False(CliFailures.IsReportable(userCancel));
        Assert.True(CliFailures.IsReportable(new InvalidDataException("x")));
    }

    [Fact]
    public async Task DoctorCollectorTimeout_IsAFailedCheck()
    {
        using SilentServer server = SilentServer.Start();
        List<(string Status, string Detail)> checks = [];

        await DoctorCommand.CheckCollectorAsync(
            server.Url.ToString(),
            TimeSpan.FromMilliseconds(500),
            (_, detail) => checks.Add(("PASS", detail)),
            (_, detail) => checks.Add(("WARN", detail)),
            (_, detail) => checks.Add(("FAIL", detail)));

        Assert.Equal(
            [("FAIL", "Unreachable: The request was canceled due to the configured HttpClient.Timeout of 0.5 seconds elapsing.")],
            checks);
    }

    [Fact]
    public async Task AzureResources_ReadEachResourceTypeWithItsProvidersApiVersion()
    {
        const string rule = "/subscriptions/s/resourceGroups/g/providers/Microsoft.Insights/dataCollectionRules/r";
        const string workspace = "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/w";
        RecordingHandler handler = new();
        ArmReader arm = new(new HttpClient(handler), new StaticCredential());

        Assert.NotNull(await AzureResources.GetRuleAsync(arm, rule));
        Assert.NotNull(await AzureResources.GetWorkspaceAsync(arm, workspace));
        Assert.NotNull(await AzureResources.GetTableAsync(arm, workspace, "BowerSecurity_CL"));

        Assert.Equal(
            [
                $"https://management.azure.com{rule}?api-version=2024-03-11",
                $"https://management.azure.com{workspace}?api-version=2025-07-01",
                $"https://management.azure.com{workspace}/tables/BowerSecurity_CL?api-version=2025-07-01"
            ],
            handler.Requests);
        Assert.All(handler.Authorizations, value => Assert.Equal("Bearer token", value));
        Assert.Equal("2024-03-11", AzureApiVersions.DataCollectionRules);
        Assert.Equal("2025-07-01", AzureApiVersions.LogAnalytics);
    }

    [Fact]
    public void PackSamples_AcceptCoversRedactAndAcceptButNotTheReverse()
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", "aws-security"), privatePem, output.Path);
        LoadedPack pack = PackArchive.Load(archive, [publicPem]);
        string plain = pack.SampleLines.Single(line => line.Contains("StopLogging is accepted", StringComparison.Ordinal));
        string redacted = pack.SampleLines.Single(line => line.Contains("access key in an outcome reason", StringComparison.Ordinal));
        string Expect(string line, string expect)
        {
            JsonObject sample = JsonNode.Parse(line)!.AsObject();
            sample["expect"] = expect;
            return sample.ToJsonString();
        }

        LoadedPack variants = pack with
        {
            SampleLines =
            [
                Expect(redacted, "accept"),
                Expect(redacted, "redact-and-accept"),
                Expect(plain, "accept"),
                Expect(plain, "redact-and-accept"),
                Expect(redacted, "reject")
            ]
        };
        IReadOnlyList<PackSampleResult> results = PackTester.Run(variants, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));

        Assert.Equal(
            [
                ("accept", "redactandaccept", true),
                ("redactandaccept", "redactandaccept", true),
                ("accept", "accept", true),
                ("redactandaccept", "accept", false),
                ("reject", "redactandaccept", false)
            ],
            results.Select(result => (result.ExpectedDecision, result.ActualDecision, result.Passed)));
        Assert.Equal(["Expected redactandaccept, got accept."], results[3].Problems);
    }

    /// <summary>Accepts connections on loopback and never answers.</summary>
    private sealed class SilentServer : IDisposable
    {
        private readonly TcpListener listener;
        private readonly List<TcpClient> clients = [];

        private SilentServer(TcpListener listener) => this.listener = listener;

        public Uri Url => new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");

        public static SilentServer Start()
        {
            TcpListener listener = new(IPAddress.Loopback, 0);
            listener.Start();
            SilentServer server = new(listener);
            _ = server.AcceptAsync();
            return server;
        }

        public void Dispose()
        {
            listener.Stop();
            lock (clients)
            {
                clients.ForEach(client => client.Dispose());
            }
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    TcpClient client = await listener.AcceptTcpClientAsync();
                    lock (clients)
                    {
                        clients.Add(client);
                    }
                }
            }
            catch (Exception exception) when (exception is SocketException or ObjectDisposedException)
            {
            }
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        public List<string?> Authorizations { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!.ToString());
            Authorizations.Add(request.Headers.Authorization?.ToString());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"location\":\"australiaeast\"}")
            });
        }
    }

    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("token", DateTimeOffset.MaxValue);

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}
