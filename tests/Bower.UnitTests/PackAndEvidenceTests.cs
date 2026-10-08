using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Packs;

namespace Bower.UnitTests;

public sealed class PackAndEvidenceTests
{
    private static string ExamplePack => Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway");

    [Fact]
    public void Pack_BuildsSignsVerifiesAndPassesItsSamples()
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();

        string archive = PackArchive.Build(ExamplePack, privatePem, output.Path);
        LoadedPack pack = PackArchive.Load(archive, [publicPem]);
        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));

        Assert.Equal(keyId, pack.SignedByKeyId);
        Assert.Equal("linux-ssh-gateway", pack.Manifest.Id);
        Assert.Single(pack.Policies);
        Assert.NotNull(pack.DcrTemplateJson);
        Assert.All(results, result => Assert.True(result.Passed, string.Join(" ", result.Problems)));
    }

    [Fact]
    public void Pack_RejectsUntrustedKeysAndMissingTrust()
    {
        using TemporaryDirectory output = new();
        (string privatePem, _, _) = DetachedSigner.GenerateKeyPair();
        (_, string otherPublic, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(ExamplePack, privatePem, output.Path);

        Assert.Throws<PackVerificationException>(() => PackArchive.Load(archive, [otherPublic]));
        Assert.Throws<PackVerificationException>(() => PackArchive.Load(archive, []));
    }

    [Theory]
    [InlineData("modify")]
    [InlineData("add")]
    [InlineData("manifest")]
    public void Pack_DetectsTampering(string attack)
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(ExamplePack, privatePem, output.Path);
        using (ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Update))
        {
            switch (attack)
            {
                case "modify":
                    ZipArchiveEntry policy = zip.GetEntry("content/policies/ssh-authentication.yaml")!;
                    string text;
                    using (StreamReader reader = new(policy.Open()))
                    {
                        text = reader.ReadToEnd();
                    }

                    policy.Delete();
                    using (StreamWriter writer = new(zip.CreateEntry("content/policies/ssh-authentication.yaml").Open()))
                    {
                        writer.Write(text.Replace("minimumValueScore: 75", "minimumValueScore: 0", StringComparison.Ordinal));
                    }

                    break;
                case "add":
                    using (StreamWriter writer = new(zip.CreateEntry("content/policies/allow-all.yaml").Open()))
                    {
                        writer.Write("extra");
                    }

                    break;
                case "manifest":
                    ZipArchiveEntry manifest = zip.GetEntry(PackArchive.ManifestEntry)!;
                    string json;
                    using (StreamReader reader = new(manifest.Open()))
                    {
                        json = reader.ReadToEnd();
                    }

                    manifest.Delete();
                    using (StreamWriter writer = new(zip.CreateEntry(PackArchive.ManifestEntry).Open()))
                    {
                        writer.Write(json.Replace("1.0.0", "9.9.9", StringComparison.Ordinal));
                    }

                    break;
            }
        }

        Assert.Throws<PackVerificationException>(() => PackArchive.Load(archive, [publicPem]));
    }

    [Fact]
    public void Pack_BuildFailsWhenASampleFails()
    {
        using TemporaryDirectory source = new();
        CopyDirectory(ExamplePack, source.Path);
        string samples = Path.Combine(source.Path, "samples", "ssh.jsonl");
        File.AppendAllText(samples,
            """{"name":"wrong expectation","expect":"reject","event":{"schemaVersion":"1.0.0","eventId":"s9","timeGenerated":"{{now}}","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"a","eventResult":"failure","application":{"name":"x","environment":"y"},"actor":{"username":"u"},"source":{"ipAddress":"192.0.2.1"},"request":{"correlationId":"c"}}}""" + "\n");
        (string privatePem, _, _) = DetachedSigner.GenerateKeyPair();

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PackArchive.Build(source.Path, privatePem, source.Path));
        Assert.Contains("wrong expectation", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Pack_DiffReportsPopulationChangesAndMissingVersionBump()
    {
        using TemporaryDirectory v1 = new();
        using TemporaryDirectory v2 = new();
        using TemporaryDirectory output = new();
        CopyDirectory(ExamplePack, v1.Path);
        CopyDirectory(ExamplePack, v2.Path);
        File.WriteAllText(Path.Combine(v2.Path, "pack.yaml"),
            File.ReadAllText(Path.Combine(v2.Path, "pack.yaml")).Replace("version: 1.0.0", "version: 1.1.0", StringComparison.Ordinal));
        string policy = Path.Combine(v2.Path, "policies", "ssh-authentication.yaml");
        File.WriteAllText(policy, File.ReadAllText(policy).Replace("    - account_lockout\n", "    - account_lockout\n    - authentication_success\n", StringComparison.Ordinal));
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();

        LoadedPack before = PackArchive.Load(PackArchive.Build(v1.Path, privatePem, output.Path), [publicPem]);
        LoadedPack after = PackArchive.Load(PackArchive.Build(v2.Path, privatePem, output.Path), [publicPem]);
        IReadOnlyList<PolicyChange> changes = PackDiff.Compare(before, after);

        Assert.Contains(changes, change => change.Change == "event-type-added" && change.Detail == "authentication_success");
        Assert.Contains(changes, change => change.Change == "version-not-bumped");
    }

    [Fact]
    public async Task Evidence_VerifiedWhenCanaryIsFoundAndSignatureChecks()
    {
        FakeQuery query = new(foundAfter: 2);
        EvidenceRunner runner = new(new FakeSender(202), query, new FakeArm(totalDays: 400, region: "australiaeast"), new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(Options("workspace-1"), TestContext.Current.CancellationToken);
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        SignedEvidence signed = EvidenceRunner.Sign(bundle, privatePem);
        SignedEvidence roundTripped = JsonSerializer.Deserialize<SignedEvidence>(JsonSerializer.Serialize(signed))!;

        Assert.Equal(EvidenceModes.Verified, bundle.Mode);
        Assert.True(bundle.Arrival.Found);
        Assert.Equal(2, bundle.Arrival.Attempts);
        Assert.Equal(400, bundle.Retention?.TotalDays);
        Assert.Equal("evidenced", bundle.Controls.Single(control => control.Id == "ISM-1988").Status);
        Assert.Contains(query.Queries, kql => kql.Contains(bundle.Canary.EventId, StringComparison.Ordinal));
        Assert.True(EvidenceRunner.Verify(roundTripped, [publicPem]));

        roundTripped.Bundle["mode"] = EvidenceModes.Verified + "!";
        Assert.False(EvidenceRunner.Verify(roundTripped, [publicPem]));
    }

    [Fact]
    public async Task Evidence_FailsWhenCanaryNeverArrives()
    {
        EvidenceRunner runner = new(new FakeSender(202), new FakeQuery(foundAfter: int.MaxValue), null, TimeProvider.System);

        EvidenceBundle bundle = await runner.RunAsync(
            Options("workspace-1") with { Timeout = TimeSpan.FromMilliseconds(50), PollInterval = TimeSpan.FromMilliseconds(10) },
            TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal("not-evidenced", bundle.Controls.Single(control => control.Id == "ISM-0580").Status);
    }

    [Fact]
    public async Task Evidence_IsLabelledSimulatedWithoutAWorkspace()
    {
        EvidenceRunner runner = new(new FakeSender(202), null, null, new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(Options(null), TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Simulated, bundle.Mode);
        Assert.Contains(bundle.Limitations, item => item.StartsWith("SIMULATED", StringComparison.Ordinal));
        Assert.All(bundle.Controls, control => Assert.NotEqual("evidenced", control.Status));
    }

    [Fact]
    public async Task Evidence_DoesNotQueryWhenCollectorRejectsTheCanary()
    {
        FakeQuery query = new(foundAfter: 1);
        EvidenceRunner runner = new(new FakeSender(401), query, null, new FakeClock(TestEvents.Now));

        EvidenceBundle bundle = await runner.RunAsync(Options("workspace-1"), TestContext.Current.CancellationToken);

        Assert.Equal(EvidenceModes.Failed, bundle.Mode);
        Assert.Equal("collector-rejected-canary", bundle.Arrival.QueryError);
        Assert.DoesNotContain(query.Queries, kql => kql.Contains("EventId", StringComparison.Ordinal));
    }

    [Fact]
    public void QueryParser_ReadsLogAnalyticsResponse()
    {
        QueryRows rows = LogAnalyticsQueryClient.Parse(
            """{"tables":[{"name":"PrimaryResult","columns":[{"name":"EventId","type":"string"},{"name":"IngestionTime","type":"datetime"}],"rows":[["e1","2026-10-08T00:01:00Z"]]}]}""");

        IReadOnlyDictionary<string, JsonNode?> row = Assert.Single(rows.Rows);
        Assert.Equal("e1", row["EventId"]!.GetValue<string>());
    }

    private static EvidenceOptions Options(string? workspace) =>
        new()
        {
            CollectorUrl = new Uri("http://collector.test:4319/"),
            WorkspaceId = workspace,
            WorkspaceResourceId = workspace is null ? null : "/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w",
            PollInterval = TimeSpan.Zero
        };

    private static void CopyDirectory(string source, string destination)
    {
        foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    private sealed class FakeSender(int status) : ICanarySender
    {
        public Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken) =>
            Task.FromResult<(int, JsonObject?)>((status, status == 202
                ? new JsonObject { ["decision"] = "accept", ["policy"] = new JsonObject { ["policyId"] = "BWR-POL-EVIDENCE-CANARY" } }
                : null));
    }

    private sealed class FakeQuery(int foundAfter) : ILogAnalyticsQuery
    {
        private int canaryQueries;

        public List<string> Queries { get; } = [];

        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            Queries.Add(kql);
            if (kql.StartsWith("DCRLogErrors", StringComparison.Ordinal))
            {
                return Task.FromResult(new QueryRows([new Dictionary<string, JsonNode?> { ["Errors"] = 0 }], null));
            }

            canaryQueries++;
            return Task.FromResult(canaryQueries < foundAfter
                ? new QueryRows([], null)
                : new QueryRows(
                    [new Dictionary<string, JsonNode?>
                    {
                        ["TimeGenerated"] = "2026-07-26T02:14:19Z",
                        ["IngestionTime"] = "2026-07-26T02:16:19Z",
                        ["PolicyHash"] = "sha256:policy"
                    }],
                    null));
        }
    }

    private sealed class FakeArm(int totalDays, string region) : IArmReader
    {
        public Task<JsonObject?> GetAsync(string resourceId, string apiVersion, CancellationToken cancellationToken) =>
            Task.FromResult<JsonObject?>(resourceId.Contains("/tables/", StringComparison.Ordinal)
                ? new JsonObject { ["properties"] = new JsonObject { ["plan"] = "Analytics", ["retentionInDays"] = 90, ["totalRetentionInDays"] = totalDays } }
                : new JsonObject { ["location"] = region });
    }
}
