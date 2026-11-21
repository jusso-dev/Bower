using System.Security.Cryptography;
using Bower.Packs;
using Bower.Redaction.Privacy;

namespace Bower.Management.Api;

/// <summary>
/// Server-side signed pack gallery backed by a configured directory (<c>BOWER_PACK_GALLERY_DIR</c>)
/// and trusted ECDSA public keys (<c>BOWER_PACK_TRUSTED_KEYS</c>). Every archive is signature- and
/// hash-verified via <see cref="PackArchive.Load"/> before being listed as trusted or accepted for
/// installation; untrusted packs are explicitly surfaced with a plain refusal reason and can never
/// be installed.
/// </summary>
public sealed class PackGalleryService
{
    public const string GalleryDirectorySetting = "BOWER_PACK_GALLERY_DIR";
    public const string TrustedKeysSetting = "BOWER_PACK_TRUSTED_KEYS";
    private const int MaximumArchives = 100;

    private readonly string? _galleryDirectory;
    private readonly IReadOnlyList<string> _trustedKeyFiles;

    public PackGalleryService(string? galleryDirectory, IReadOnlyList<string> trustedKeyFiles)
    {
        _galleryDirectory = string.IsNullOrWhiteSpace(galleryDirectory) ? null : Path.GetFullPath(galleryDirectory.Trim());
        _trustedKeyFiles = trustedKeyFiles;
    }

    public static PackGalleryService FromConfiguration(IConfiguration configuration)
    {
        string? directory = configuration[GalleryDirectorySetting];
        string? rawKeys = configuration[TrustedKeysSetting];
        string[] keyFiles = string.IsNullOrWhiteSpace(rawKeys)
            ? []
            : rawKeys.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return new PackGalleryService(directory, keyFiles);
    }

    public bool Configured => _galleryDirectory is not null;

    public (IReadOnlyList<PackGalleryItem> Items, int TrustedKeyCount) List(TimeProvider clock)
    {
        if (_galleryDirectory is null || !Directory.Exists(_galleryDirectory))
        {
            return ([], ReadTrustedKeys().Count);
        }

        List<string> trustedKeys = ReadTrustedKeys();
        string[] archives = Directory.EnumerateFiles(_galleryDirectory, "*.bowerpack", SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.Ordinal)
            .Take(MaximumArchives)
            .ToArray();

        List<PackGalleryItem> items = [];
        foreach (string archivePath in archives)
        {
            items.Add(InspectArchive(archivePath, trustedKeys, clock).Item);
        }

        return (items, trustedKeys.Count);
    }

    /// <summary>
    /// Re-verifies a specific pack by id and version against the configured trusted keys.
    /// Returns either the verified pack or a plain refusal reason.
    /// </summary>
    public (LoadedPack? Pack, string? RefusalReason) ResolveTrusted(string packId, string version)
    {
        if (_galleryDirectory is null || !Directory.Exists(_galleryDirectory))
        {
            return (null, "Pack gallery is not configured on management.");
        }

        List<string> trustedKeys = ReadTrustedKeys();
        if (trustedKeys.Count == 0)
        {
            return (null, "No trusted pack signing keys are configured on management; refusing to trust any pack.");
        }

        string[] archives = Directory.EnumerateFiles(_galleryDirectory, "*.bowerpack", SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.Ordinal)
            .Take(MaximumArchives)
            .ToArray();

        string? matchingRefusal = null;
        string expectedPrefix = $"{packId}-{version}.bowerpack";
        foreach (string archivePath in archives)
        {
            try
            {
                LoadedPack loaded = PackArchive.Load(archivePath, trustedKeys);
                if (string.Equals(loaded.Manifest.Id, packId, StringComparison.Ordinal)
                    && string.Equals(loaded.Manifest.Version, version, StringComparison.Ordinal))
                {
                    return (loaded, null);
                }
            }
            catch (Exception exception) when (exception is PackVerificationException or InvalidDataException)
            {
                if (string.Equals(Path.GetFileName(archivePath), expectedPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    matchingRefusal = SanitiseReason(exception.Message);
                }
            }
        }

        return (null, matchingRefusal ?? $"Signed pack '{packId}' version '{version}' was not found or is not trusted.");
    }

    /// <summary>
    /// Builds the population diff for installing <paramref name="pack"/> onto <paramref name="targets"/>.
    /// </summary>
    public static PackPopulationDiff BuildDiff(LoadedPack pack, IReadOnlyList<CollectorRecord> targets)
    {
        ArgumentNullException.ThrowIfNull(pack);
        ArgumentNullException.ThrowIfNull(targets);

        string[] eventTypes = pack.Policies
            .SelectMany(policy => policy.Policy.Match.EventTypes)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToArray();

        PackPolicyDiffEntry[] policyChanges = pack.Policies
            .OrderBy(policy => policy.Policy.Metadata.Id, StringComparer.Ordinal)
            .Select(policy => new PackPolicyDiffEntry(
                policy.Policy.Metadata.Id,
                "policy-added",
                $"Action {policy.Policy.Decision.Action} for {string.Join(", ", policy.Policy.Match.EventTypes)}."))
            .ToArray();

        PackCollectorDiffEntry[] collectors = targets
            .OrderBy(collector => collector.Id, StringComparer.Ordinal)
            .Select(collector => new PackCollectorDiffEntry(
                collector.Id,
                collector.MachineName,
                collector.Environment,
                collector.PolicyHash,
                collector.DesiredPolicyHash,
                pack.Manifest.PackHash,
                string.Equals(collector.DesiredPolicyHash, pack.Manifest.PackHash, StringComparison.Ordinal)))
            .ToArray();

        return new PackPopulationDiff(
            pack.Manifest.Id,
            pack.Manifest.Version,
            pack.Manifest.PackHash,
            eventTypes,
            policyChanges,
            collectors);
    }

    private static (PackGalleryItem Item, LoadedPack? Loaded) InspectArchive(
        string archivePath,
        List<string> trustedKeys,
        TimeProvider clock)
    {
        string fileName = Path.GetFileName(archivePath);
        if (trustedKeys.Count == 0)
        {
            return (Refused(fileName, "No trusted pack signing keys are configured on management; refusing to trust any pack."), null);
        }

        try
        {
            LoadedPack loaded = PackArchive.Load(archivePath, trustedKeys);
            PrivacyPolicy privacy = BuildPrivacyPolicy(loaded.PrivacyProfileYaml, out string[] redactions);
            PackSampleSummary[] samples = PackTester.Run(loaded, privacy, clock)
                .Select(result => new PackSampleSummary(
                    result.Name,
                    result.Passed,
                    result.ExpectedDecision,
                    result.ActualDecision,
                    result.Problems))
                .ToArray();

            string[] eventTypes = loaded.Policies
                .SelectMany(policy => policy.Policy.Match.EventTypes)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(item => item, StringComparer.Ordinal)
                .ToArray();

            PackPolicySummary[] policies = loaded.Policies
                .OrderBy(policy => policy.Policy.Metadata.Id, StringComparer.Ordinal)
                .Select(policy => new PackPolicySummary(
                    policy.Policy.Metadata.Id,
                    policy.Policy.Metadata.Version,
                    policy.Policy.Decision.Action,
                    policy.Policy.Match.EventTypes,
                    policy.Hash))
                .ToArray();

            PackGalleryItem item = new(
                true,
                fileName,
                loaded.Manifest.Id,
                loaded.Manifest.Version,
                loaded.Manifest.Name,
                loaded.Manifest.Description,
                loaded.Manifest.Owner,
                loaded.Manifest.CreatedAt,
                loaded.Manifest.PackHash,
                loaded.SignedByKeyId,
                eventTypes,
                policies,
                redactions,
                loaded.Detections.Count,
                loaded.Parsers.Count,
                samples,
                null);
            return (item, loaded);
        }
        catch (Exception exception) when (exception is PackVerificationException or InvalidDataException)
        {
            return (Refused(fileName, SanitiseReason(exception.Message)), null);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return (Refused(fileName, "Pack archive could not be verified."), null);
        }
    }

    private static PackGalleryItem Refused(string fileName, string reason) => new(
        false,
        fileName,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        [],
        [],
        [],
        0,
        0,
        [],
        reason);

    private List<string> ReadTrustedKeys()
    {
        List<string> keys = [];
        foreach (string path in _trustedKeyFiles)
        {
            if (File.Exists(path))
            {
                keys.Add(File.ReadAllText(path));
            }
        }

        return keys;
    }

    private static PrivacyPolicy BuildPrivacyPolicy(string? privacyProfileYaml, out string[] summary)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        if (string.IsNullOrWhiteSpace(privacyProfileYaml))
        {
            summary =
            [
                "Default Australian privacy policy (TFN, Medicare, BSB, payment cards, credentials and tokens redacted before persistence)."
            ];
            return PrivacyPolicy.CreateDefault();
        }

        LoadedPrivacyProfile loaded = PrivacyProfileLoader.Load(privacyProfileYaml, key, "gallery-preview");
        List<string> lines =
        [
            $"Bundled privacy profile {loaded.Id} v{loaded.Version} (Australian defaults active)."
        ];
        if (loaded.Policy.SecretFieldNames.Count > 0)
        {
            lines.Add($"Removes {loaded.Policy.SecretFieldNames.Count} additional secret field name(s).");
        }

        if (loaded.Policy.FieldRules.Count > 0)
        {
            lines.Add($"Applies {loaded.Policy.FieldRules.Count} explicit field rule(s).");
        }

        foreach (CustomDetectorDefinition detector in loaded.Policy.CustomDetectors)
        {
            lines.Add($"Custom detector {detector.Id}: {detector.Action} ({detector.Description}).");
        }

        summary = [.. lines];
        return loaded.Policy;
    }

    private static string SanitiseReason(string message) =>
        string.IsNullOrWhiteSpace(message)
            ? "Pack failed signature or integrity verification."
            : message.Length <= 300 ? message : message[..300];
}
