using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Dcr;
using Bower.Detection;
using Bower.Integrity;
using Bower.Pipeline;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Bower.Packs;

/// <summary>A verified pack: signature checked, every file hash matched, content parsed.</summary>
public sealed record LoadedPack(
    PackManifest Manifest,
    string SignedByKeyId,
    IReadOnlyList<LoadedPolicy> Policies,
    string? PrivacyProfileYaml,
    IReadOnlyList<DetectionRule> Detections,
    IReadOnlyList<CustomLogParserConfiguration> Parsers,
    IReadOnlyList<string> SampleLines,
    string? DcrTemplateJson);

/// <summary>Builds, signs, verifies and loads <c>.bowerpack</c> archives.</summary>
public static partial class PackArchive
{
    public const string ManifestEntry = "manifest.json";
    public const string SignatureEntry = "manifest.sig";
    private const string ContentPrefix = "content/";
    private const int MaximumEntries = 500;
    private const long MaximumFileBytes = 1_048_576;
    private const long MaximumArchiveBytes = 50L * 1_048_576;

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        PropertyNameCaseInsensitive = true
    };

    /// <summary>Validates a source directory and writes a signed archive. Returns its path.</summary>
    public static string Build(
        string sourceDirectory,
        string privateKeyPem,
        string outputDirectory,
        TimeProvider? clock = null)
    {
        string root = Path.GetFullPath(sourceDirectory);
        PackSource source = ReadSource(Path.Combine(root, "pack.yaml"));
        ValidateSource(source);

        List<(string Path, string Role, byte[] Content)> files = [];
        void Add(string relative, string role)
        {
            string full = SafeJoin(root, relative);
            FileInfo info = new(full);
            if (!info.Exists)
            {
                throw new FileNotFoundException($"Pack file not found: {relative}");
            }

            if (info.Length > MaximumFileBytes)
            {
                throw new InvalidDataException($"Pack file exceeds 1 MiB: {relative}");
            }

            files.Add((NormaliseRelative(relative), role, File.ReadAllBytes(full)));
        }

        source.Policies.ForEach(path => Add(path, PackRoles.Policy));
        if (source.PrivacyProfile is not null)
        {
            Add(source.PrivacyProfile, PackRoles.PrivacyProfile);
        }

        source.Parsers.ForEach(path => Add(path, PackRoles.Parser));
        source.Detections.ForEach(path => Add(path, PackRoles.Detection));
        source.Samples.ForEach(path => Add(path, PackRoles.Sample));
        if (source.Dcr)
        {
            files.Add(("dcr/bower-dcr.json", PackRoles.Dcr,
                Encoding.UTF8.GetBytes(DcrTemplateGenerator.Generate(new DcrTemplateOptions()).ToJsonString(
                    new JsonSerializerOptions { WriteIndented = true }))));
        }

        // Parse everything and run the samples so a broken pack cannot be signed.
        ParsedContent parsed = ParseContent(files.Select(item => (item.Path, item.Role, item.Content)).ToArray());
        LoadedPack candidate = new(
            null!, "unsigned", parsed.Policies, parsed.PrivacyProfile, parsed.Detections, parsed.Parsers, parsed.Samples, parsed.Dcr);
        PackSampleResult[] failures = PackTester
            .Run(candidate, TestPrivacyPolicy(parsed.PrivacyProfile), clock)
            .Where(result => !result.Passed)
            .ToArray();
        if (failures.Length > 0)
        {
            throw new InvalidDataException(
                "Pack samples failed: " + string.Join("; ", failures.Select(item => $"{item.Name}: {string.Join(" ", item.Problems)}")));
        }

        PackFile[] packFiles = files
            .OrderBy(item => item.Path, StringComparer.Ordinal)
            .Select(item => new PackFile(item.Path, item.Role, Sha256Hex.Of(item.Content), item.Content.LongLength))
            .ToArray();
        PackManifest manifest = new(
            "bower.security/v1",
            PackManifest.CurrentKind,
            source.Metadata.Id,
            source.Metadata.Version,
            source.Metadata.Name,
            source.Metadata.Description,
            source.Metadata.Owner,
            (clock ?? TimeProvider.System).GetUtcNow(),
            packFiles,
            parsed.Policies
                .Select(policy => new PackPolicyEntry(
                    policy.Policy.Metadata.Id,
                    policy.Policy.Metadata.Version,
                    policy.Hash,
                    policy.Policy.Match.EventTypes))
                .ToArray(),
            PackHash(packFiles));

        byte[] manifestBytes = CanonicalJson.Bytes(JsonSerializer.SerializeToNode(manifest, JsonOptions));
        DetachedSignature signature = DetachedSigner.Sign(manifestBytes, privateKeyPem);

        Directory.CreateDirectory(outputDirectory);
        string output = Path.Combine(outputDirectory, $"{source.Metadata.Id}-{source.Metadata.Version}.bowerpack");
        using (FileStream stream = new(output, FileMode.Create, FileAccess.Write))
        using (ZipArchive zip = new(stream, ZipArchiveMode.Create))
        {
            WriteEntry(zip, ManifestEntry, manifestBytes);
            WriteEntry(zip, SignatureEntry, JsonSerializer.SerializeToUtf8Bytes(signature, JsonOptions));
            foreach ((string path, _, byte[] content) in files.OrderBy(item => item.Path, StringComparer.Ordinal))
            {
                WriteEntry(zip, ContentPrefix + path, content);
            }
        }

        return output;
    }

    /// <summary>Verifies signature and hashes, then parses the content. Throws on any failure.</summary>
    public static LoadedPack Load(string archivePath, IReadOnlyCollection<string> trustedPublicKeyPems)
    {
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        if (trustedPublicKeyPems.Count == 0)
        {
            throw new PackVerificationException("No trusted public keys configured; refusing to load an unverified pack.");
        }

        FileInfo info = new(archivePath);
        if (!info.Exists || info.Length > MaximumArchiveBytes)
        {
            throw new PackVerificationException("Pack archive is missing or exceeds 50 MiB.");
        }

        using ZipArchive zip = ZipFile.OpenRead(archivePath);
        if (zip.Entries.Count > MaximumEntries)
        {
            throw new PackVerificationException("Pack archive has too many entries.");
        }

        Dictionary<string, byte[]> entries = new(StringComparer.Ordinal);
        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            if (entry.FullName.EndsWith('/'))
            {
                continue;
            }

            if (entry.Length > MaximumFileBytes
                || !SafeEntryName().IsMatch(entry.FullName)
                || entry.FullName.Split('/').Any(segment => segment is ".." or "."))
            {
                throw new PackVerificationException($"Pack entry '{entry.FullName}' is not allowed.");
            }

            using Stream stream = entry.Open();
            using MemoryStream buffer = new();
            stream.CopyTo(buffer);
            entries[entry.FullName] = buffer.ToArray();
        }

        if (!entries.TryGetValue(ManifestEntry, out byte[]? manifestBytes)
            || !entries.TryGetValue(SignatureEntry, out byte[]? signatureBytes))
        {
            throw new PackVerificationException("Pack is missing its manifest or signature.");
        }

        DetachedSignature signature = JsonSerializer.Deserialize<DetachedSignature>(signatureBytes, JsonOptions)
            ?? throw new PackVerificationException("Pack signature is unreadable.");
        PackManifest manifest = JsonSerializer.Deserialize<PackManifest>(manifestBytes, JsonOptions)
            ?? throw new PackVerificationException("Pack manifest is unreadable.");
        byte[] canonical = CanonicalJson.Bytes(JsonSerializer.SerializeToNode(manifest, JsonOptions));
        if (!canonical.AsSpan().SequenceEqual(manifestBytes)
            || !DetachedSigner.Verify(canonical, signature, trustedPublicKeyPems))
        {
            throw new PackVerificationException("Pack signature is invalid or not from a trusted key.");
        }

        if (!string.Equals(PackHash(manifest.Files), manifest.PackHash, StringComparison.Ordinal))
        {
            throw new PackVerificationException("Pack hash does not match its file list.");
        }

        HashSet<string> listed = manifest.Files.Select(file => ContentPrefix + file.Path).ToHashSet(StringComparer.Ordinal);
        foreach (string name in entries.Keys.Where(name => name is not ManifestEntry and not SignatureEntry))
        {
            if (!listed.Contains(name))
            {
                throw new PackVerificationException($"Pack contains an unlisted file: {name}");
            }
        }

        List<(string Path, string Role, byte[] Content)> files = [];
        foreach (PackFile file in manifest.Files)
        {
            if (!entries.TryGetValue(ContentPrefix + file.Path, out byte[]? content)
                || !string.Equals(Sha256Hex.Of(content), file.Sha256, StringComparison.Ordinal))
            {
                throw new PackVerificationException($"Pack file '{file.Path}' is missing or modified.");
            }

            files.Add((file.Path, file.Role, content));
        }

        ParsedContent parsed = ParseContent(files);
        return new LoadedPack(
            manifest,
            signature.KeyId,
            parsed.Policies,
            parsed.PrivacyProfile,
            parsed.Detections,
            parsed.Parsers,
            parsed.Samples,
            parsed.Dcr);
    }

    internal static string PackHash(IReadOnlyList<PackFile> files) =>
        "sha256:" + Sha256Hex.Of(string.Join('\n', files
            .OrderBy(file => file.Path, StringComparer.Ordinal)
            .Select(file => $"{file.Path}\u001f{file.Role}\u001f{file.Sha256}")));

    private sealed record ParsedContent(
        IReadOnlyList<LoadedPolicy> Policies,
        string? PrivacyProfile,
        IReadOnlyList<DetectionRule> Detections,
        IReadOnlyList<CustomLogParserConfiguration> Parsers,
        IReadOnlyList<string> Samples,
        string? Dcr);

    private static ParsedContent ParseContent(IReadOnlyList<(string Path, string Role, byte[] Content)> files)
    {
        List<LoadedPolicy> policies = [];
        List<DetectionRule> detections = [];
        List<CustomLogParserConfiguration> parsers = [];
        List<string> samples = [];
        string? privacy = null;
        string? dcr = null;
        foreach ((string path, string role, byte[] content) in files)
        {
            string text = Encoding.UTF8.GetString(content);
            switch (role)
            {
                case PackRoles.Policy:
                    policies.Add(PolicyLoader.LoadYaml(text, path));
                    break;
                case PackRoles.PrivacyProfile:
                    // Structural validation only: keys are supplied by the host at load time.
                    ValidatePrivacyProfile(text);
                    privacy = text;
                    break;
                case PackRoles.Detection:
                    detections.Add(SigmaRuleLoader.LoadYaml(text, path));
                    break;
                case PackRoles.Parser:
                    CustomLogParserConfiguration configuration =
                        JsonSerializer.Deserialize<CustomLogParserConfiguration>(text, JsonOptions)
                        ?? throw new InvalidDataException($"Parser '{path}' is empty.");
                    IReadOnlyList<string> issues = CustomLogParser.ValidateConfiguration(configuration);
                    if (issues.Count > 0)
                    {
                        throw new InvalidDataException($"Parser '{path}' is invalid: {string.Join(" ", issues)}");
                    }

                    parsers.Add(configuration);
                    break;
                case PackRoles.Sample:
                    samples.AddRange(text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    break;
                case PackRoles.Dcr:
                    _ = JsonNode.Parse(text) ?? throw new InvalidDataException("DCR template is empty.");
                    dcr = text;
                    break;
                default:
                    throw new InvalidDataException($"Unknown pack file role '{role}'.");
            }
        }

        if (policies.Count == 0)
        {
            throw new InvalidDataException("A pack must contain at least one policy.");
        }

        return new ParsedContent(policies, privacy, detections, parsers, samples, dcr);
    }

    /// <summary>Privacy policy for sample tests: the pack's profile with a throwaway HMAC key.</summary>
    public static PrivacyPolicy TestPrivacyPolicy(string? profileYaml) =>
        profileYaml is null
            ? PrivacyPolicy.CreateDefault()
            : PrivacyProfileLoader.Load(profileYaml, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), "test").Policy;

    private static void ValidatePrivacyProfile(string yaml)
    {
        try
        {
            // A throwaway key lets profiles that use Hmac validate structurally.
            PrivacyProfileLoader.Load(yaml, new byte[32], "validation");
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidDataException(exception.Message, exception);
        }
    }

    private static PackSource ReadSource(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("pack.yaml not found.", path);
        }

        try
        {
            return new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build()
                .Deserialize<PackSource>(File.ReadAllText(path))
                ?? throw new InvalidDataException("pack.yaml is empty.");
        }
        catch (YamlException exception)
        {
            throw new InvalidDataException($"pack.yaml is invalid at line {exception.Start.Line}: {exception.Message}", exception);
        }
    }

    private static void ValidateSource(PackSource source)
    {
        if (source.ApiVersion != "bower.security/v1" || source.Kind != "Pack")
        {
            throw new InvalidDataException("pack.yaml must be apiVersion bower.security/v1, kind Pack.");
        }

        if (!PackId().IsMatch(source.Metadata.Id))
        {
            throw new InvalidDataException("Pack id must be lowercase letters, digits and hyphens (3-64).");
        }

        if (!SemVer().IsMatch(source.Metadata.Version))
        {
            throw new InvalidDataException("Pack version must be semantic (for example 1.2.0).");
        }
    }

    private static string SafeJoin(string root, string relative)
    {
        string full = Path.GetFullPath(Path.Combine(root, relative));
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Pack path escapes the pack directory: {relative}");
        }

        return full;
    }

    private static string NormaliseRelative(string relative) =>
        relative.Replace('\\', '/').TrimStart('.', '/');

    private static void WriteEntry(ZipArchive zip, string name, byte[] content)
    {
        ZipArchiveEntry entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        // Fixed timestamp keeps archives reproducible for identical content.
        entry.LastWriteTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using Stream stream = entry.Open();
        stream.Write(content);
    }

    [GeneratedRegex(@"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$", RegexOptions.CultureInvariant)]
    private static partial Regex PackId();

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex SemVer();

    [GeneratedRegex(@"^(manifest\.json|manifest\.sig|content/[A-Za-z0-9_.\-/]+)$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeEntryName();
}

public sealed class PackVerificationException(string message) : Exception(message);
