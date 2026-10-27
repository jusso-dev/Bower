using System.Text.Json;
using Bower.Integrity;
using Bower.Packs;
using Bower.Redaction.Privacy;

namespace Bower.Cli.Commands;

internal static class KeyCommands
{
    /// <summary>bower keys generate --out-dir DIR [--name NAME]</summary>
    public static int Generate(string[] args)
    {
        string directory = CliOptions.Required(args, "--out-dir");
        string name = CliOptions.Get(args, "--name") ?? "bower-signing";
        Directory.CreateDirectory(directory);
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        string privatePath = Path.Combine(directory, $"{name}.key.pem");
        string publicPath = Path.Combine(directory, $"{name}.pub.pem");
        if (File.Exists(privatePath))
        {
            throw new InvalidOperationException($"{privatePath} already exists; refusing to overwrite a signing key.");
        }

        File.WriteAllText(privatePath, privatePem);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.WriteAllText(publicPath, publicPem);
        Console.WriteLine($"Key id:      {keyId}");
        Console.WriteLine($"Private key: {privatePath} (keep secret; store in a vault or HSM)");
        Console.WriteLine($"Public key:  {publicPath} (distribute to collectors and verifiers)");
        return 0;
    }
}

internal static class PackCommands
{
    /// <summary>bower pack build DIR --key PRIVATE.pem [--out DIR]</summary>
    public static int Build(string[] args)
    {
        string source = CliOptions.Positional(args) ?? throw new ArgumentException("Provide the pack source directory.");
        string key = File.ReadAllText(CliOptions.Required(args, "--key"));
        string output = PackArchive.Build(source, key, CliOptions.Get(args, "--out") ?? "artifacts/packs");
        Console.WriteLine($"Built and signed {output}");
        return 0;
    }

    /// <summary>bower pack verify FILE --trusted-key PUBLIC.pem [--trusted-key ...]</summary>
    public static int Verify(string[] args)
    {
        LoadedPack pack = Load(args);
        Console.WriteLine($"Verified {pack.Manifest.Id}@{pack.Manifest.Version} signed by key {pack.SignedByKeyId}; {pack.Manifest.Files.Count} files, pack hash {pack.Manifest.PackHash}.");
        return 0;
    }

    /// <summary>bower pack inspect FILE --trusted-key PUBLIC.pem</summary>
    public static int Inspect(string[] args)
    {
        LoadedPack pack = Load(args);
        Console.WriteLine(JsonSerializer.Serialize(
            new PackInspectOutput(
                pack.Manifest.Id,
                pack.Manifest.Version,
                pack.Manifest.Name,
                pack.Manifest.Owner,
                pack.SignedByKeyId,
                pack.Manifest.PackHash,
                pack.Manifest.Policies,
                [.. pack.Manifest.Files.Select(file => new PackInspectFile(file.Path, file.Role, file.Bytes))],
                pack.Detections.Count,
                pack.Parsers.Count,
                pack.SampleLines.Count,
                pack.PrivacyProfileYaml is not null,
                pack.DcrTemplateJson is not null),
            CliJsonContext.Default.PackInspectOutput));
        return 0;
    }

    /// <summary>
    /// bower pack test FILE --trusted-key PUBLIC.pem [--hmac-key-file FILE] [--parser NAME]
    /// [--report FILE [--report-format json|junit]]. Exit 1 when any sample fails, or when
    /// <c>--parser</c> selects no samples. Reports carry only post-redaction values.
    /// </summary>
    public static int Test(string[] args)
    {
        string? format = CliOptions.Get(args, "--report-format");
        string? report = CliOptions.Get(args, "--report");
        if (format is not (null or "json" or "junit"))
        {
            throw new ArgumentException("--report-format must be json or junit.");
        }

        if (format is not null && report is null)
        {
            throw new ArgumentException("--report-format requires --report FILE.");
        }

        LoadedPack pack = Load(args);
        PrivacyPolicy privacy = CliOptions.Get(args, "--hmac-key-file") is { } keyFile && pack.PrivacyProfileYaml is not null
            ? PrivacyProfileLoader.Load(pack.PrivacyProfileYaml, PrivacyProfileLoader.ReadKeyFile(keyFile)).Policy
            : PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml);
        string? parser = CliOptions.Get(args, "--parser");
        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, privacy, parser: parser);
        foreach (PackSampleResult result in results)
        {
            Console.WriteLine($"{(result.Passed ? "PASS" : "FAIL"),-5} {result.Name} (expected {result.ExpectedDecision}, got {result.ActualDecision})");
            foreach (string problem in result.Problems)
            {
                Console.WriteLine($"      {problem}");
            }
        }

        if (report is not null)
        {
            File.WriteAllText(report, format == "junit"
                ? PackTestReport.JUnit(pack.Manifest, parser, results)
                : JsonSerializer.Serialize(PackTestReport.Json(pack.Manifest, parser, results), CliJsonContext.Default.PackTestReportOutput) + "\n");
        }

        if (parser is not null && results.Count == 0)
        {
            Console.WriteLine($"No samples for parser '{parser}'.");
            return 1;
        }

        return results.All(result => result.Passed) ? 0 : 1;
    }

    /// <summary>bower pack diff OLD NEW --trusted-key PUBLIC.pem: policy population diff.</summary>
    public static int Diff(string[] args)
    {
        string[] files = args.Where(arg => arg.EndsWith(".bowerpack", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (files.Length != 2)
        {
            throw new ArgumentException("Provide two .bowerpack files: old then new.");
        }

        string[] trusted = TrustedKeys(args);
        LoadedPack before = PackArchive.Load(files[0], trusted);
        LoadedPack after = PackArchive.Load(files[1], trusted);
        IReadOnlyList<PolicyChange> changes = PackDiff.Compare(before, after);
        Console.WriteLine($"{before.Manifest.Id} {before.Manifest.Version} -> {after.Manifest.Version}");
        foreach (PolicyChange change in changes)
        {
            Console.WriteLine($"  {change.PolicyId,-28} {change.Change,-24} {change.Detail}");
        }

        if (changes.Count == 0)
        {
            Console.WriteLine("  No policy population changes.");
        }

        return changes.Any(change => change.Change == "version-not-bumped") ? 1 : 0;
    }

    private static LoadedPack Load(string[] args)
    {
        string file = CliOptions.Positional(args) ?? throw new ArgumentException("Provide a .bowerpack file.");
        return PackArchive.Load(file, TrustedKeys(args));
    }

    private static string[] TrustedKeys(string[] args)
    {
        string[] keys = CliOptions.All(args, "--trusted-key").Select(File.ReadAllText).ToArray();
        return keys.Length > 0 ? keys : throw new ArgumentException("Provide at least one --trusted-key PUBLIC.pem.");
    }
}

/// <summary>Machine-readable <c>bower pack test</c> reports for CI (JSON or JUnit XML).</summary>
internal static class PackTestReport
{
    public static PackTestReportOutput Json(PackManifest manifest, string? parser, IReadOnlyList<PackSampleResult> results) =>
        new(
            manifest.Id,
            manifest.Version,
            parser,
            results.Count,
            results.Count(result => result.Passed),
            results.Count(result => !result.Passed),
            [.. results.Select(result => new PackTestReportSample(
                result.Name, result.Passed, result.ExpectedDecision, result.ActualDecision, result.Problems))]);

    public static string JUnit(PackManifest manifest, string? parser, IReadOnlyList<PackSampleResult> results)
    {
        int failures = results.Count(result => !result.Passed);
        string suite = Xml($"{manifest.Id}@{manifest.Version}" + (parser is null ? string.Empty : $":{parser}"));
        System.Text.StringBuilder text = new();
        text.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        text.Append($"<testsuites name=\"bower pack test\" tests=\"{results.Count}\" failures=\"{failures}\">\n");
        text.Append($"  <testsuite name=\"{suite}\" tests=\"{results.Count}\" failures=\"{failures}\">\n");
        foreach (PackSampleResult result in results)
        {
            text.Append($"    <testcase classname=\"{Xml(manifest.Id)}\" name=\"{Xml(result.Name)}\"");
            if (result.Passed)
            {
                text.Append(" />\n");
                continue;
            }

            string message = result.Problems.Count > 0 ? result.Problems[0] : "Sample failed.";
            text.Append($">\n      <failure message=\"{Xml(message)}\">{Xml(string.Join("\n", result.Problems))}</failure>\n    </testcase>\n");
        }

        text.Append("  </testsuite>\n</testsuites>\n");
        return text.ToString();
    }

    /// <summary>XML 1.0 text and attribute escaping; characters XML cannot carry become U+FFFD.</summary>
    private static string Xml(string value)
    {
        System.Text.StringBuilder text = new(value.Length);
        foreach (char character in value)
        {
            text.Append(character switch
            {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&apos;",
                '\n' => "&#10;",
                '\r' => "&#13;",
                '\t' => "&#9;",
                < ' ' or '\uFFFE' or '\uFFFF' => "\uFFFD",
                _ => character.ToString()
            });
        }

        return text.ToString();
    }
}
