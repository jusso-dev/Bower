using System.Security.Cryptography;
using System.Text;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;

namespace Bower.Packs;

/// <summary>
/// Where a host reads its selection and privacy configuration from. The collector maps its
/// <c>BOWER_*</c> settings onto this; serverless hosts use the same setting names.
/// </summary>
public sealed record PolicyBundleSources
{
    public required string PolicyDirectory { get; init; }

    /// <summary>Signed .bowerpack archives to load policies and privacy profile from.</summary>
    public IReadOnlyList<string> Packs { get; init; } = [];

    /// <summary>PEM public keys trusted to sign packs.</summary>
    public IReadOnlyList<string> PackTrustedKeyFiles { get; init; } = [];

    public string? PrivacyProfilePath { get; init; }

    public string? PrivacyHmacKeyFile { get; init; }

    public string PrivacyHmacKeyId { get; init; } = "k1";

    /// <summary>BOWER_PRIVACY_PROFILE_SOURCE value reported with the bundle.</summary>
    public string PrivacyProfileSource { get; init; } = "local";

    /// <summary>
    /// Management mode only: returns the verified cached assignment for the HMAC key, or
    /// null for the built-in default. Replaces <see cref="PrivacyProfilePath"/> and packs.
    /// </summary>
    public Func<byte[]?, LoadedPrivacyProfile?>? ManagedPrivacyProfile { get; init; }
}

/// <summary>
/// Everything that decides what the collector accepts and how it redacts: policies from
/// the policy directory and signed packs, plus the privacy profile. Its hash is what the
/// collector reports to management, which compares it with the desired policy. Shared by
/// every host so selection and redaction never fork between runtimes.
/// </summary>
public sealed record PolicyBundle(
    IReadOnlyList<LoadedPolicy> Policies,
    IReadOnlyList<PackManifest> Packs,
    PrivacyPolicy Privacy,
    string? PrivacyProfile,
    string Hash)
{
    public IReadOnlyList<LoadedPack> LoadedPacks { get; init; } = [];

    /// <summary>Active privacy profile version; null for the built-in default.</summary>
    public string? PrivacyProfileVersion { get; init; }

    /// <summary>Active privacy profile content hash; null for the built-in default.</summary>
    public string? PrivacyProfileHash { get; init; }

    /// <summary>BOWER_PRIVACY_PROFILE_SOURCE that produced the active privacy profile.</summary>
    public string PrivacyProfileSource { get; init; } = "local";

    public static PolicyBundle Load(PolicyBundleSources settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        List<LoadedPolicy> policies = [];
        if (Directory.Exists(settings.PolicyDirectory))
        {
            policies.AddRange(PolicyLoader.LoadDirectory(settings.PolicyDirectory));
        }
        else if (settings.Packs.Count == 0)
        {
            throw new DirectoryNotFoundException($"Policy directory does not exist: {settings.PolicyDirectory}");
        }

        string[] trusted = settings.PackTrustedKeyFiles.Select(File.ReadAllText).ToArray();
        List<LoadedPack> packs = settings.Packs.Select(path => PackArchive.Load(path, trusted)).ToList();
        if (packs.Select(pack => pack.Manifest.Id).Distinct(StringComparer.Ordinal).Count() != packs.Count
            || packs.Sum(pack => pack.Parsers.Count) > 64 || packs.Sum(pack => pack.Detections.Count) > 64
            || packs.SelectMany(pack => pack.Detections).Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count()
                != packs.Sum(pack => pack.Detections.Count))
        {
            throw new InvalidDataException("Duplicate pack or detection identity, or more than 64 parsers/detections.");
        }
        policies.AddRange(packs.SelectMany(pack => pack.Policies));

        string? duplicate = policies
            .GroupBy(policy => policy.Policy.Metadata.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1)?.Key;
        if (duplicate is not null)
        {
            throw new InvalidDataException($"Policy id '{duplicate}' is defined more than once across the directory and packs.");
        }

        PolicyLoader.ValidateSet(policies);

        string? profileYaml = settings.PrivacyProfilePath is null ? null : File.ReadAllText(settings.PrivacyProfilePath);
        string[] packProfiles = packs.Where(pack => pack.PrivacyProfileYaml is not null).Select(pack => pack.PrivacyProfileYaml!).ToArray();
        if (packProfiles.Length + (profileYaml is null ? 0 : 1) > 1)
        {
            throw new InvalidDataException("Only one privacy profile may be active (BOWER_PRIVACY_PROFILE or one pack).");
        }

        if (settings.ManagedPrivacyProfile is not null && packProfiles.Length > 0)
        {
            throw new InvalidDataException(
                "BOWER_PRIVACY_PROFILE_SOURCE=management cannot be combined with pack privacy profiles.");
        }

        profileYaml ??= packProfiles.FirstOrDefault();
        byte[]? key = settings.PrivacyHmacKeyFile is null ? null : PrivacyProfileLoader.ReadKeyFile(settings.PrivacyHmacKeyFile);
        // Management mode: the verified cached assignment, or the built-in default when none.
        LoadedPrivacyProfile? profile = settings.ManagedPrivacyProfile is not null
            ? settings.ManagedPrivacyProfile(key)
            : profileYaml is null
                ? null
                : PrivacyProfileLoader.Load(profileYaml, key, settings.PrivacyHmacKeyId);
        PrivacyPolicy privacy = profile?.Policy ?? PrivacyPolicy.CreateDefault();

        string material = string.Join(
            '\n',
            policies.OrderBy(policy => policy.Policy.Metadata.Id, StringComparer.Ordinal)
                .Select(policy => $"{policy.Policy.Metadata.Id}@{policy.Policy.Metadata.Version}:{policy.Hash}")
                .Concat(packs.Select(pack => $"pack:{pack.Manifest.Id}@{pack.Manifest.Version}:{pack.Manifest.PackHash}"))
                .Append($"privacy:{profile?.Hash ?? "default"}"));
        string hash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
        return new PolicyBundle(policies, packs.Select(pack => pack.Manifest).ToArray(), privacy, profile?.Id, hash)
        {
            LoadedPacks = packs,
            PrivacyProfileVersion = profile?.Version,
            PrivacyProfileHash = profile?.Hash,
            PrivacyProfileSource = settings.PrivacyProfileSource
        };
    }
}
