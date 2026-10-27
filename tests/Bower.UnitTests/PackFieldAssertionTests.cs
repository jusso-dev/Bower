using System.Text.Json.Nodes;
using Bower.Cli.Commands;
using Bower.Integrity;
using Bower.Packs;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

/// <summary>
/// expectFields: post-redaction field assertions in pack samples, parser-scoped runs and
/// CI reports. Mirrored by rust/crates/bower-packs/tests/field_assertion_tests.rs.
/// </summary>
public sealed class PackFieldAssertionTests
{
    private static string Packs => Path.Combine(AppContext.BaseDirectory, "packs");

    private static LoadedPack Build(string source, TemporaryDirectory directory)
    {
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        return PackArchive.Load(PackArchive.Build(source, privatePem, directory.Path), [publicPem]);
    }

    private static string Copy(string pack, TemporaryDirectory directory)
    {
        string source = Path.Combine(Packs, pack);
        string target = Path.Combine(directory.Path, "source");
        foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            string destination = Path.Combine(target, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(file, destination);
        }

        return target;
    }

    /// <summary>The journald pack's first sample (a failed password) with other expectFields.</summary>
    private static string FailedPassword(LoadedPack pack, JsonObject? expectFields, int line = 0)
    {
        JsonObject sample = JsonNode.Parse(pack.SampleLines[line])!.AsObject();
        sample.Remove("expectFields");
        if (expectFields is not null)
        {
            sample["expectFields"] = expectFields;
        }

        return sample.ToJsonString();
    }

    private static IReadOnlyList<PackSampleResult> Run(LoadedPack pack, params string[] lines) =>
        PackTester.Run(pack with { SampleLines = lines }, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml));

    [Fact]
    public void ShippedJournaldExpectations_PassAfterRedaction()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-journald-ssh"), directory);

        Assert.Contains(pack.SampleLines, line => line.Contains("\"expectFields\"", StringComparison.Ordinal));
        Assert.All(
            PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml)),
            result => Assert.True(result.Passed, $"{result.Name}: {string.Join(" ", result.Problems)}"));
    }

    [Fact]
    public void FailingExpectations_ReportPathLevelDiffsOfRedactedValues()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-journald-ssh"), directory);

        PackSampleResult result = Assert.Single(Run(pack, FailedPassword(pack, new JsonObject
        {
            ["eventOutcomeReason"] = "PublicKeyRejected",
            ["request.correlationId"] = "present",
            ["source.ipAddress"] = 5,
            ["application"] = "linux-sshd",
            ["application.name"] = true,
            ["eventId"] = "absent",
            ["actor.username"] = "present",
            ["labels.missing"] = "absent"
        })));

        Assert.False(result.Passed);
        Assert.Equal("redactandaccept", result.ActualDecision);
        Assert.Equal(
            [
                "Field 'eventOutcomeReason': expected \"PublicKeyRejected\", got \"InvalidCredentials\".",
                "Field 'request.correlationId': expected present, but it is absent.",
                "Field 'source.ipAddress': type mismatch, expected number 5, got string \"203.0.113.5\".",
                "Field 'application': type mismatch, expected string \"linux-sshd\", got object.",
                "Field 'application.name': type mismatch, expected boolean true, got string \"linux-sshd\".",
                "Field 'eventId': expected absent, got string \"s=7a1c;i=1f01;b=55aa;m=91;t=63e2;x=c3\"."
            ],
            result.Problems);
    }

    [Fact]
    public void MissingFieldWithAValue_IsReportedAsAbsent()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-ssh-gateway"), directory);
        JsonObject sample = JsonNode.Parse(pack.SampleLines[1])!.AsObject();
        sample["expectFields"] = new JsonObject { ["eventOutcomeReason"] = "AccountLocked", ["source.ipAddress"] = "198.51.100.7" };

        PackSampleResult result = Assert.Single(Run(pack, sample.ToJsonString()));

        Assert.Equal(["Field 'eventOutcomeReason': expected \"AccountLocked\", but it is absent."], result.Problems);
    }

    [Fact]
    public void RawSensitiveExpectations_FailWithoutEchoingTheValue()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-journald-ssh"), directory);

        PackSampleResult result = Assert.Single(Run(pack, FailedPassword(pack, new JsonObject
        {
            // Pseudonymised by the privacy profile; a raw journal field never forwarded; a forbidden value.
            ["actor.username"] = "deploy-admin",
            ["_HOSTNAME"] = "bastion-1",
            ["eventOutcomeReason"] = "Failed password for invalid user deploy-admin"
        })));

        Assert.False(result.Passed);
        Assert.Equal(3, result.Problems.Count);
        Assert.All(result.Problems, problem => Assert.EndsWith(
            "the expected value does not survive redaction; expect only post-redaction values.", problem, StringComparison.Ordinal));
        Assert.DoesNotContain(result.Problems, problem => problem.Contains("deploy-admin", StringComparison.Ordinal)
            || problem.Contains("bastion-1", StringComparison.Ordinal));
    }

    [Fact]
    public void Build_RefusesToSignWhenAFieldAssertionFails()
    {
        using TemporaryDirectory directory = new();
        string source = Copy("linux-journald-ssh", directory);
        string samples = Path.Combine(source, "samples", "journald.jsonl");
        string[] lines = File.ReadAllLines(samples);
        JsonObject first = JsonNode.Parse(lines[0])!.AsObject();
        first["expectFields"] = new JsonObject { ["actor.username"] = "deploy-admin", ["eventOutcomeReason"] = "Nope" };
        lines[0] = first.ToJsonString();
        File.WriteAllLines(samples, lines);
        string output = Path.Combine(directory.Path, "out");
        (string privatePem, _, _) = DetachedSigner.GenerateKeyPair();

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() => PackArchive.Build(source, privatePem, output));

        Assert.Contains("Field 'eventOutcomeReason': expected \"Nope\", got \"InvalidCredentials\".", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Field 'actor.username': the expected value does not survive redaction", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy-admin", exception.Message, StringComparison.Ordinal);
        Assert.False(Directory.Exists(output) && Directory.EnumerateFiles(output).Any());
    }

    [Fact]
    public void FieldAssertions_NeedARedactedEvent()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-journald-ssh"), directory);
        JsonObject expect = new() { ["eventType"] = "authentication_failure" };

        IReadOnlyList<PackSampleResult> results = Run(pack,
            FailedPassword(pack, (JsonObject)expect.DeepClone(), line: 2),
            FailedPassword(pack, (JsonObject)expect.DeepClone(), line: 4));

        Assert.Equal(["Field assertions need a redacted event; got reject."], results[0].Problems);
        Assert.Equal(["Field assertions need a redacted event; got quarantine."], results[1].Problems);
    }

    [Theory]
    [InlineData("\"expectFields\":[]", "Sample 's' expectFields must be an object.")]
    [InlineData("\"expectFields\":{}", "Sample 's' expectFields must have 1 to 64 paths.")]
    [InlineData("\"expectFields\":{\"a..b\":\"present\"}", "Sample 's' expectFields has an invalid path.")]
    [InlineData("\"expectFields\":{\"a b\":\"present\"}", "Sample 's' expectFields has an invalid path.")]
    [InlineData("\"expectFields\":{\"a\\n\":\"present\"}", "Sample 's' expectFields has an invalid path.")]
    [InlineData("\"expectFields\":{\"a\":\"present\",\"a\":\"absent\"}", "Sample 's' expectFields has a duplicate path.")]
    [InlineData("\"expectFields\":{\"a\":null}", "Sample 's' expectFields 'a' must be a string, finite number or boolean.")]
    [InlineData("\"expectFields\":{\"a\":{\"b\":1}}", "Sample 's' expectFields 'a' must be a string, finite number or boolean.")]
    [InlineData("\"expectFields\":{\"a\":1e400}", "Sample 's' expectFields 'a' must be a string, finite number or boolean.")]
    [InlineData("\"expectField\":{\"a\":\"present\"}", "Sample 1 member 'expectField' is unknown or duplicated.")]
    [InlineData("\"name\":\"t\"", "Sample 1 member 'name' is unknown or duplicated.")]
    public void InvalidSamples_FailValidation(string member, string message)
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-ssh-gateway"), directory);
        string line = $"{{\"name\":\"s\",\"expect\":\"reject\",{member},\"event\":{{}}}}";

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() => Run(pack, line));

        Assert.Equal(message, exception.Message);
    }

    [Fact]
    public void ParserFilter_RunsOneParsersRawSamples_ByNameOrPath()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-ssh-gateway"), directory);
        Func<PrivacyPolicy> privacy = () => PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml);

        Assert.Equal(["parsers/sshd-json.json"], pack.ParserPaths);
        IReadOnlyList<PackSampleResult> byName = PackTester.Run(pack, privacy(), parser: "sshd-json");
        IReadOnlyList<PackSampleResult> byPath = PackTester.Run(pack, privacy(), parser: "parsers/sshd-json.json");
        Assert.Equal(
            ["raw failure activates parser and local detection", "raw success remains denied by source filter"],
            byName.Select(result => result.Name));
        Assert.Equal(byName.Select(result => result.Name), byPath.Select(result => result.Name));
        Assert.All(byName, result => Assert.True(result.Passed));
        Assert.Equal("Pack has no parser 'nope'.",
            Assert.Throws<InvalidDataException>(() => PackTester.Run(pack, privacy(), parser: "nope")).Message);

        // A raw sample may name its parser instead of using an index.
        JsonObject named = JsonNode.Parse(pack.SampleLines[5])!.AsObject();
        named["parser"] = "sshd-json";
        Assert.True(Assert.Single(Run(pack, named.ToJsonString())).Passed);
        named["parser"] = "sshd";
        Assert.Equal("Raw sample parser name is unknown or ambiguous.",
            Assert.Throws<InvalidDataException>(() => Run(pack, named.ToJsonString())).Message);
    }

    [Fact]
    public void Build_RunsSamplesInManifestParserOrder_SoIndexesMatchLoad()
    {
        using TemporaryDirectory directory = new();
        string source = Copy("linux-ssh-gateway", directory);
        // A second parser that sorts first: pack.yaml lists it last, the manifest first.
        File.Copy(Path.Combine(Packs, "linux-journald-ssh", "parsers", "sshd-journald.json"),
            Path.Combine(source, "parsers", "a-journald.json"));
        string yaml = Path.Combine(source, "pack.yaml");
        File.WriteAllText(yaml, File.ReadAllText(yaml).Replace(
            "  - parsers/sshd-json.json\n", "  - parsers/sshd-json.json\n  - parsers/a-journald.json\n", StringComparison.Ordinal));
        string samples = Path.Combine(source, "samples", "ssh.jsonl");
        File.WriteAllText(samples, File.ReadAllText(samples).Replace("\"parser\":0", "\"parser\":1", StringComparison.Ordinal));

        LoadedPack pack = Build(source, directory);

        Assert.Equal(["parsers/a-journald.json", "parsers/sshd-json.json"], pack.ParserPaths);
        Assert.All(PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml)), result => Assert.True(result.Passed));
        Assert.Equal(2, PackTester.Run(pack, PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml), parser: "sshd-json").Count);
    }

    [Fact]
    public void Reports_CarryResultsAndEscapeXml()
    {
        using TemporaryDirectory directory = new();
        LoadedPack pack = Build(Path.Combine(Packs, "linux-ssh-gateway"), directory);
        PackSampleResult[] results =
        [
            new("ok", true, "accept", "accept", []),
            new("bad <&\"'>", false, "accept", "reject", ["Field 'a': expected \"x<y\", got \"z\".", "Expected accept, got reject."])
        ];

        string junit = PackTestReport.JUnit(pack.Manifest, "sshd-json", results);
        PackTestReportOutput json = PackTestReport.Json(pack.Manifest, null, results);

        Assert.Equal(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<testsuites name=\"bower pack test\" tests=\"2\" failures=\"1\">\n"
            + "  <testsuite name=\"linux-ssh-gateway@1.1.0:sshd-json\" tests=\"2\" failures=\"1\">\n"
            + "    <testcase classname=\"linux-ssh-gateway\" name=\"ok\" />\n"
            + "    <testcase classname=\"linux-ssh-gateway\" name=\"bad &lt;&amp;&quot;&apos;&gt;\">\n"
            + "      <failure message=\"Field &apos;a&apos;: expected &quot;x&lt;y&quot;, got &quot;z&quot;.\">"
            + "Field &apos;a&apos;: expected &quot;x&lt;y&quot;, got &quot;z&quot;.&#10;Expected accept, got reject.</failure>\n"
            + "    </testcase>\n"
            + "  </testsuite>\n"
            + "</testsuites>\n",
            junit);
        Assert.Equal((2, 1, 1, (string?)null), (json.Total, json.Passed, json.Failed, json.Parser));
        Assert.Equal(results[1].Problems, json.Samples[1].Problems);
    }
}
