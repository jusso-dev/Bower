using System.Security.Cryptography;
using System.Text;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;

namespace Bower.Collector;

/// <summary>
/// Everything that decides what the collector accepts and how it redacts: policies from
/// the policy directory and signed packs, plus the privacy profile. Its hash is what the
/// collector reports to management, which compares it with the desired policy.
/// </summary>
public sealed record PolicyBundle(
    IReadOnlyList<LoadedPolicy> Policies,
    IReadOnlyList<PackManifest> Packs,
    PrivacyPolicy Privacy,
    string? PrivacyProfile,
    string Hash)
{
    public static PolicyBundle Load(CollectorSettings settings)
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
        policies.AddRange(packs.SelectMany(pack => pack.Policies));

        string? duplicate = policies
            .GroupBy(policy => policy.Policy.Metadata.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1)?.Key;
        if (duplicate is not null)
        {
            throw new InvalidDataException($"Policy id '{duplicate}' is defined more than once across the directory and packs.");
        }

        string? profileYaml = settings.PrivacyProfilePath is null ? null : File.ReadAllText(settings.PrivacyProfilePath);
        string[] packProfiles = packs.Where(pack => pack.PrivacyProfileYaml is not null).Select(pack => pack.PrivacyProfileYaml!).ToArray();
        if (packProfiles.Length + (profileYaml is null ? 0 : 1) > 1)
        {
            throw new InvalidDataException("Only one privacy profile may be active (BOWER_PRIVACY_PROFILE or one pack).");
        }

        profileYaml ??= packProfiles.FirstOrDefault();
        byte[]? key = settings.PrivacyHmacKeyFile is null ? null : PrivacyProfileLoader.ReadKeyFile(settings.PrivacyHmacKeyFile);
        LoadedPrivacyProfile? profile = profileYaml is null
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
        return new PolicyBundle(policies, packs.Select(pack => pack.Manifest).ToArray(), privacy, profile?.Id, hash);
    }
}
