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

    /// <summary>The same signed pack on both sides, each with its own privacy profile fixture.</summary>
    private static string[] FieldArgs(string baselineProfile, string candidateProfile) =>
    [
        "--baseline-pack", Pack("aws-security-1.1.0.bowerpack"),
        "--baseline-trusted-key", Pack("csharp-current-signing.pub.pem"),
        "--baseline-privacy-profile", Asset("bundle-diff", $"{baselineProfile}.privacy.yaml"),
        .. CurrentAws,
        "--candidate-privacy-profile", Asset("bundle-diff", $"{candidateProfile}.privacy.yaml"),
        "--at", At
    ];

    [Fact]
    public async Task BundleDiff_AnotherFieldRuleOfTheSameDetectorIsReported()
    {
        PolicyBundleDiffOutput output = await CompareAsync(FieldArgs("remove-username", "remove-username-and-ip"));

        Assert.Equal(4, output.Changed);
        PolicyBundleDiffChange root = output.Changes.Single(change => change.File == "root-login.json");
        // One action per detector hides the second field-rule finding; per-finding metadata does not.
        Assert.Equal(root.Baseline.PrivacyActions, root.Candidate.PrivacyActions);
        Assert.Equal(["privacyFindings", "removedCount"], root.ChangedFields);
        Assert.Equal(
            [new PolicyBundlePrivacyFinding("field-rule", "$.actor.username", "Removed")],
            root.Baseline.PrivacyFindings);
        Assert.Equal(
            [
                new PolicyBundlePrivacyFinding("field-rule", "$.actor.username", "Removed"),
                new PolicyBundlePrivacyFinding("field-rule", "$.source.ipAddress", "Removed")
            ],
            root.Candidate.PrivacyFindings);
        Assert.Equal((1, 2), (root.Baseline.RemovedCount, root.Candidate.RemovedCount));
        string json = Serialize(output);
        foreach (string value in new[] { "203.0.113.10", "198.51.100.7", "visitor", "Admin" })
        {
            Assert.DoesNotContain(value, json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task BundleDiff_ChangedActionOnALaterFindingOfTheSameDetectorIsReported()
    {
        PolicyBundleDiffOutput output = await CompareAsync(FieldArgs("remove-username-and-ip", "remove-username-mask-ip"));

        PolicyBundleDiffChange root = output.Changes.Single(change => change.File == "root-login.json");
        Assert.Equal(root.Baseline.PrivacyActions, root.Candidate.PrivacyActions);
        Assert.Equal(["privacyFindings", "removedCount", "maskedCount"], root.ChangedFields);
        Assert.Contains(new PolicyBundlePrivacyFinding("field-rule", "$.source.ipAddress", "Masked"), root.Candidate.PrivacyFindings);
        Assert.True(root.Baseline.Accepted && root.Candidate.Accepted);
    }

    [Fact]
    public void BundleSources_ExplicitDirectoryMustExistEvenWithPacks()
    {
        string missing = Asset("no-such-policy-directory");
        ArgumentException error = Assert.Throws<ArgumentException>(
            () => PolicyCommands.BundleSources(["--candidate", missing, "--candidate-pack", "x.bowerpack"], "candidate"));
        Assert.Equal($"Policy directory does not exist: {missing}", error.Message);
    }

    [Theory]
    [InlineData("01:02")] // time only: DateTimeOffset.TryParse would silently use today's date
    [InlineData("2026-10-17")] // date only
    [InlineData("2026-10-17T01:02:03")] // no offset
    [InlineData("2026-10-17T01:02:03.123456789Z")] // more than 7 fractional digits
    [InlineData("10/17/2026")]
    [InlineData("Oct 17 2026")]
    [InlineData("2026-10-17 01:02:03Z")]
    [InlineData("2026-10-17T01:02:60Z")]
    [InlineData("2026-10-17T01:02:03+15:00")]
    [InlineData("2026-10-17t01:02:03z")]
    [InlineData(" 2026-10-17T01:02:03Z")]
    [InlineData("2026-02-30T01:02:03Z")]
    [InlineData("0000-01-01T00:00:00Z")]
    [InlineData("0001-01-01T00:00:00+01:00")] // UTC instant before DateTimeOffset.MinValue
    [InlineData("9999-12-31T23:59:59-01:00")] // UTC instant after DateTimeOffset.MaxValue
    [InlineData("2026-10-17T01:02:03.Z")]
    [InlineData("2026-10-17T01:02:03Z\n")]
    [InlineData("")]
    public void Timestamp_RefusesAnythingButIso8601WithAnOffset(string value)
    {
        ArgumentException error = Assert.Throws<ArgumentException>(() => CliOptions.Timestamp(value, "--at"));
        Assert.Equal(
            "--at must be an ISO 8601 timestamp with Z or an offset: YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM).",
            error.Message);
    }

    [Theory]
    [InlineData("2026-10-17T01:02Z", "2026-10-17T01:02:00.0000000+00:00")]
    [InlineData("2026-10-17T11:02:03.1234567+10:00", "2026-10-17T01:02:03.1234567+00:00")]
    [InlineData("2026-10-16T20:02:03.5-05:00", "2026-10-17T01:02:03.5000000+00:00")]
    [InlineData("2026-10-17T01:02:03-00:00", "2026-10-17T01:02:03.0000000+00:00")]
    public void Timestamp_AcceptsIso8601WithAnOffsetAsUtc(string value, string expected)
    {
        Assert.Equal(expected, CliOptions.Timestamp(value, "--from")!.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Null(CliOptions.Timestamp(null, "--from"));
    }

    [Theory]
    [InlineData("detections")]
    [InlineData("privacy")]
    [InlineData("fields")]
    public async Task BundleDiff_MatchesPinnedCrossRuntimeOutput(string scenario)
    {
        string[] args = scenario switch
        {
            "detections" => DetectionArgs(),
            "privacy" => PrivacyArgs(),
            _ => FieldArgs("remove-username", "remove-username-and-ip")
        };

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
        Assert.Equal(["privacyActions", "privacyFindings", "removedCount", "maskedCount"], change.ChangedFields);
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
        Assert.Equal(
            ["bower-pack-aws-console-login-failure-001", "bower-pack-aws-root-activity-001"],
            root.Candidate.Detections.Select(detection => detection.RuleId));
        Assert.All(root.Candidate.Detections, detection =>
        {
            Assert.False(string.IsNullOrEmpty(detection.RuleVersion));
            Assert.Matches("^[0-9a-f]{64}$", detection.RuleHash);
        });
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

        Assert.StartsWith("--at must be an ISO 8601 timestamp",
            Assert.Throws<ArgumentException>(() => PolicyCommands.ParseAt(["--at", "soon"])).Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => PolicyCommands.ParseAt(["--at"]));
        Assert.Null(PolicyCommands.ParseAt(["--baseline", "x"]));
        Assert.Equal(TimeSpan.Zero, PolicyCommands.ParseAt(["--at", "2026-10-17T11:02:03+10:00"])!.Value.Offset);
    }
}
