using Bower.Cli.Commands;
using Bower.Packs;

namespace Bower.UnitTests;

/// <summary>
/// <c>bower policy diff</c> bundle comparison (issue 73). The pinned outputs in
/// <c>rust/crates/bower-cli/tests/fixtures/bundle-diff</c> are what this runtime prints; the
/// Rust port must print the same bytes for the same fixtures at the same <c>--at</c>.
/// </summary>
public sealed class PolicyBundleDiffTests
{
    private const string At = "2026-10-17T01:02:03Z";

    private static readonly string[] Fixtures = ["root-login.json", "access-key.json", "page-view.json", "future.json"];

    private static string Asset(params string[] parts) => Path.Combine([AppContext.BaseDirectory, .. parts]);

    private static string Pack(string name) => Asset("pack-fixtures", name);

    private static readonly string[] CurrentAws =
        ["--candidate-pack", Pack("aws-security-1.1.0.bowerpack"), "--candidate-trusted-key", Pack("csharp-current-signing.pub.pem")];

    private static async Task<PolicyBundleDiffOutput> CompareAsync(string[] args)
    {
        List<(string File, string Json)> events = [];
        foreach (string fixture in Fixtures)
        {
            events.Add((fixture, File.ReadAllText(Asset("bundle-diff", fixture))));
        }

        Assert.True(PolicyCommands.IsBundleComparison(args));
        PolicyBundle baseline = PolicyBundle.Load(PolicyCommands.BundleSources(args, "baseline"));
        PolicyBundle candidate = PolicyBundle.Load(PolicyCommands.BundleSources(args, "candidate"));
        return await PolicyCommands.ComputeBundleDiffAsync(baseline, candidate, events, PolicyCommands.ParseAt(args)!.Value);
    }

    private static string Serialize(PolicyBundleDiffOutput output) =>
        System.Text.Json.JsonSerializer.Serialize(output, CliJsonContext.Default.PolicyBundleDiffOutput);

    private static string[] DetectionArgs() =>
        ["--baseline", Asset("packs", "aws-security", "policies"), .. CurrentAws, "--at", At];

    private static string[] PrivacyArgs() =>
    [
        "--baseline-pack", Pack("aws-security-1.1.0.bowerpack"),
        "--baseline-trusted-key", Pack("csharp-current-signing.pub.pem"),
        .. CurrentAws,
        "--candidate-privacy-profile", Asset("bundle-diff", "mask-aws-keys.privacy.yaml"),
        "--at", At
    ];

    [Theory]
    [InlineData("detections")]
    [InlineData("privacy")]
    public async Task BundleDiff_MatchesPinnedCrossRuntimeOutput(string scenario)
    {
        string[] args = scenario == "detections" ? DetectionArgs() : PrivacyArgs();

        string json = Serialize(await CompareAsync(args));

        string expected = File.ReadAllText(Asset("bundle-diff", $"expected-{scenario}.json"))
            .ReplaceLineEndings("\n").TrimEnd('\n');
        Assert.Equal(expected, json.ReplaceLineEndings("\n"));
    }

    [Fact]
    public async Task BundleDiff_PrivacyOnlyChangeIsReportedWhileAcceptanceIsUnchanged()
    {
        PolicyBundleDiffOutput output = await CompareAsync(PrivacyArgs());

        PolicyBundleDiffChange change = Assert.Single(output.Changes);
        Assert.Equal("access-key.json", change.File);
        Assert.Equal(["privacyActions"], change.ChangedFields);
        Assert.True(change.Baseline.Accepted && change.Candidate.Accepted);
        Assert.Equal(change.Baseline.Decision, change.Candidate.Decision);
        Assert.Equal([new PolicyBundlePrivacyAction("secret.aws", "Removed")], change.Baseline.PrivacyActions);
        Assert.Equal([new PolicyBundlePrivacyAction("secret.aws", "Masked")], change.Candidate.PrivacyActions);
        Assert.Null(output.BaselineBundle.PrivacyProfile);
        Assert.Equal("bundle-diff-mask-aws-keys", output.CandidateBundle.PrivacyProfile?.Id);
        Assert.DoesNotContain("AKIA", Serialize(output), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BundleDiff_DetectionChangesUseStableRuleIdsWithoutMatchedValues()
    {
        PolicyBundleDiffOutput output = await CompareAsync(DetectionArgs());

        Assert.Equal(4, output.Events);
        Assert.All(output.Changes, change => Assert.Equal(["detections"], change.ChangedFields));
        PolicyBundleDiffChange root = output.Changes.Single(change => change.File == "root-login.json");
        Assert.Empty(root.Baseline.Detections);
        Assert.Equal(["bower-pack-aws-console-login-failure-001", "bower-pack-aws-root-activity-001"], root.Candidate.Detections);
        Assert.Equal(0, output.BaselineBundle.DetectionRules);
        Assert.Equal(4, output.CandidateBundle.DetectionRules);
        string json = Serialize(output);
        foreach (string value in new[] { "AKIAIOSFODNN7EXAMPLE", "arn:aws", "203.0.113.10", "123456789012", "Failed authentication" })
        {
            Assert.DoesNotContain(value, json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task BundleDiff_PackOnlySidesLoadWithoutAPolicyDirectory()
    {
        PolicyBundleDiffOutput output = await CompareAsync(
        [
            "--baseline-pack", Pack("aws-security-1.0.0.bowerpack"),
            "--baseline-trusted-key", Pack("csharp-signing.pub.pem"),
            .. CurrentAws,
            "--at", At
        ]);

        Assert.NotEqual(output.BaselineBundleHash, output.CandidateBundleHash);
        Assert.Equal(output.BaselineBundleHash, output.BaselineBundle.BundleHash);
        Assert.Equal(("aws-security", "1.0.0"), (output.BaselineBundle.Packs.Single().Id, output.BaselineBundle.Packs.Single().Version));
        Assert.Equal("1.1.0", output.CandidateBundle.Packs.Single().Version);
        Assert.Equal((2, 3), (output.BaselineBundle.PolicyCount, output.CandidateBundle.PolicyCount));
        Assert.Equal(4, output.Events);
        Assert.Equal(DateTimeOffset.Parse("2026-10-17T01:02:03+00:00", System.Globalization.CultureInfo.InvariantCulture), output.EvaluatedAt);
        Assert.Contains("suppression-windows", output.NotExercisedOffline);
        Assert.Contains("source-silence", output.NotExercisedOffline);
    }

    [Theory]
    [InlineData("csharp-signing.pub.pem")] // untrusted: the 1.1.0 fixture is signed by another key
    [InlineData(null)] // no trusted key at all
    public async Task BundleDiff_UntrustedPackFailsBeforeAnySampleIsEvaluated(string? trustedKey)
    {
        string[] args =
        [
            "--baseline", Asset("packs", "aws-security", "policies"),
            "--candidate-pack", Pack("aws-security-1.1.0.bowerpack"),
            .. trustedKey is null ? Array.Empty<string>() : ["--candidate-trusted-key", Pack(trustedKey)],
            "--at", At,
            Asset("bundle-diff", "root-login.json")
        ];

        await Assert.ThrowsAnyAsync<Exception>(() => PolicyCommands.DiffAsync(args));
    }

    [Fact]
    public async Task BundleDiff_UnsignedPackFailsBeforeAnySampleIsEvaluated()
    {
        using TemporaryDirectory directory = new();
        string unsigned = Path.Combine(directory.Path, "unsigned.bowerpack");
        using (System.IO.Compression.ZipArchive archive = System.IO.Compression.ZipFile.Open(
            unsigned, System.IO.Compression.ZipArchiveMode.Create))
        {
            using StreamWriter writer = new(archive.CreateEntry("pack.yaml").Open());
            writer.Write("id: unsigned\n");
        }

        string[] args =
        [
            "--baseline-pack", unsigned,
            "--baseline-trusted-key", Pack("csharp-current-signing.pub.pem"),
            .. CurrentAws,
            Asset("bundle-diff", "root-login.json")
        ];

        await Assert.ThrowsAnyAsync<Exception>(() => PolicyCommands.DiffAsync(args));
    }

    [Theory]
    [InlineData(new[] { "--baseline", "a", "--candidate", "b", "--fail-on-change" }, false)]
    [InlineData(new[] { "--baseline", "a", "--candidate", "b", "--at", "2026-10-17T00:00:00Z" }, true)]
    [InlineData(new[] { "--baseline", "a", "--candidate-pack", "b.bowerpack" }, true)]
    [InlineData(new[] { "--baseline", "a", "--candidate", "b", "--baseline-privacy-profile", "p.yaml" }, true)]
    public void BundleComparison_OnlyWithBundleOptionsSoDirectoryModeIsUnchanged(string[] args, bool bundle)
    {
        Assert.Equal(bundle, PolicyCommands.IsBundleComparison(args));
    }

    [Fact]
    public void BundleSources_RequireADirectoryOrPackAndAValidTime()
    {
        ArgumentException missing = Assert.Throws<ArgumentException>(
            () => PolicyCommands.BundleSources(["--baseline", "dir", "--candidate-privacy-profile", "p.yaml"], "candidate"));
        Assert.Equal("--candidate or --candidate-pack is required.", missing.Message);
        PolicyBundleSources packOnly = PolicyCommands.BundleSources(
            ["--baseline-pack", "a.bowerpack", "--baseline-hmac-key-id", "k2"], "baseline");
        Assert.Equal((string.Empty, "k2"), (packOnly.PolicyDirectory, packOnly.PrivacyHmacKeyId));
        Assert.Equal(["a.bowerpack"], packOnly.Packs);

        Assert.Equal("--at must be an ISO 8601 timestamp.",
            Assert.Throws<ArgumentException>(() => PolicyCommands.ParseAt(["--at", "soon"])).Message);
        Assert.Throws<ArgumentException>(() => PolicyCommands.ParseAt(["--at"]));
        Assert.Null(PolicyCommands.ParseAt(["--baseline", "x"]));
        Assert.Equal(TimeSpan.Zero, PolicyCommands.ParseAt(["--at", "2026-10-17T11:02:03+10:00"])!.Value.Offset);
    }
}
