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
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

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
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            pack.Manifest.Id,
            pack.Manifest.Version,
            pack.Manifest.Name,
            pack.Manifest.Owner,
            signedBy = pack.SignedByKeyId,
            pack.Manifest.PackHash,
            policies = pack.Manifest.Policies,
            files = pack.Manifest.Files.Select(file => new { file.Path, file.Role, file.Bytes }),
            detections = pack.Detections.Count,
            parsers = pack.Parsers.Count,
            samples = pack.SampleLines.Count,
            privacyProfile = pack.PrivacyProfileYaml is not null,
            dcrTemplate = pack.DcrTemplateJson is not null
        }, Indented));
        return 0;
    }

    /// <summary>bower pack test FILE --trusted-key PUBLIC.pem [--hmac-key-file FILE]</summary>
    public static int Test(string[] args)
    {
        LoadedPack pack = Load(args);
        PrivacyPolicy privacy = CliOptions.Get(args, "--hmac-key-file") is { } keyFile && pack.PrivacyProfileYaml is not null
            ? PrivacyProfileLoader.Load(pack.PrivacyProfileYaml, PrivacyProfileLoader.ReadKeyFile(keyFile)).Policy
            : PackArchive.TestPrivacyPolicy(pack.PrivacyProfileYaml);
        IReadOnlyList<PackSampleResult> results = PackTester.Run(pack, privacy);
        foreach (PackSampleResult result in results)
        {
            Console.WriteLine($"{(result.Passed ? "PASS" : "FAIL"),-5} {result.Name} (expected {result.ExpectedDecision}, got {result.ActualDecision})");
            foreach (string problem in result.Problems)
            {
                Console.WriteLine($"      {problem}");
            }
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
