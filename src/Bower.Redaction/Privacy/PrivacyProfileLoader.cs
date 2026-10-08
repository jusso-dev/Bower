using System.Security.Cryptography;
using System.Text;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Bower.Redaction.Privacy;

/// <summary>Privacy profile YAML (kind: PrivacyProfile). Keys are never stored in the profile.</summary>
public sealed record PrivacyProfileDocument
{
    public required string ApiVersion { get; init; }

    public required string Kind { get; init; }

    public required PrivacyProfileMetadata Metadata { get; init; }

    public string? DefaultAction { get; init; }

    public Dictionary<string, string> Detectors { get; init; } = [];

    public List<string> Disabled { get; init; } = [];

    public List<string> EnableOptIn { get; init; } = [];

    public List<PrivacyFieldRuleDocument> Fields { get; init; } = [];

    public int? MaximumFieldLength { get; init; }

    public bool? EmitMetadata { get; init; }
}

public sealed record PrivacyProfileMetadata
{
    public required string Id { get; init; }

    public required string Version { get; init; }

    public string? Description { get; init; }
}

public sealed record PrivacyFieldRuleDocument
{
    public required string Path { get; init; }

    public required string Action { get; init; }

    public int? MaxLength { get; init; }
}

public sealed record LoadedPrivacyProfile(PrivacyPolicy Policy, string Id, string Version, string Hash);

/// <summary>
/// Loads a deterministic privacy profile. Strict YAML: unknown keys, unknown detector
/// ids and unknown actions fail the load. The HMAC key comes from the host, never YAML.
/// </summary>
public static class PrivacyProfileLoader
{
    private const int MaximumProfileBytes = 262_144;

    public static LoadedPrivacyProfile Load(string yaml, byte[]? hmacKey = null, string? hmacKeyId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yaml);
        if (Encoding.UTF8.GetByteCount(yaml) > MaximumProfileBytes)
        {
            throw new InvalidDataException("Privacy profile exceeds 256 KiB.");
        }

        PrivacyProfileDocument document;
        try
        {
            document = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build()
                .Deserialize<PrivacyProfileDocument>(yaml)
                ?? throw new InvalidDataException("Privacy profile is empty.");
        }
        catch (YamlException exception)
        {
            throw new InvalidDataException($"Privacy profile is invalid at line {exception.Start.Line}: {exception.Message}", exception);
        }

        if (document.ApiVersion != "bower.security/v1" || document.Kind != "PrivacyProfile")
        {
            throw new InvalidDataException("Privacy profile must be apiVersion bower.security/v1, kind PrivacyProfile.");
        }

        HashSet<string> known = DetectorIds.All.ToHashSet(StringComparer.Ordinal);
        PrivacyPolicy defaults = PrivacyPolicy.CreateDefault();
        Dictionary<string, PrivacyAction> actions = new(defaults.DetectorActions, StringComparer.Ordinal);
        foreach ((string detector, string action) in document.Detectors)
        {
            RequireKnown(known, detector);
            actions[detector] = ParseAction(action);
        }

        foreach (string detector in document.Disabled.Concat(document.EnableOptIn))
        {
            RequireKnown(known, detector);
        }

        List<PrivacyFieldRule> rules = [];
        foreach (PrivacyFieldRuleDocument rule in document.Fields)
        {
            if (string.IsNullOrWhiteSpace(rule.Path)
                || rule.Path.Split('.').Any(segment => segment.Length == 0 || segment.Length > 64))
            {
                throw new InvalidDataException($"Field rule path '{rule.Path}' is invalid.");
            }

            PrivacyAction action = ParseAction(rule.Action);
            if (action == PrivacyAction.Truncate && rule.MaxLength is not (> 0 and <= 65_536))
            {
                throw new InvalidDataException($"Field rule '{rule.Path}' needs maxLength between 1 and 65536 for truncate.");
            }

            rules.Add(new PrivacyFieldRule(rule.Path, action, rule.MaxLength));
        }

        int maximumFieldLength = document.MaximumFieldLength ?? defaults.MaximumFieldLength;
        if (maximumFieldLength is < 256 or > 65_536)
        {
            throw new InvalidDataException("maximumFieldLength must be between 256 and 65536.");
        }

        PrivacyPolicy policy = new()
        {
            DefaultAction = document.DefaultAction is null ? defaults.DefaultAction : ParseAction(document.DefaultAction),
            DetectorActions = actions,
            DisabledDetectors = document.Disabled.ToHashSet(StringComparer.Ordinal),
            EnabledOptInDetectors = document.EnableOptIn.ToHashSet(StringComparer.Ordinal),
            FieldRules = rules,
            MaximumFieldLength = maximumFieldLength,
            EmitMetadata = document.EmitMetadata ?? true,
            HmacKey = hmacKey,
            HmacKeyId = string.IsNullOrWhiteSpace(hmacKeyId) ? "k1" : hmacKeyId
        };

        // Construct once so a profile that needs an absent key fails at load, not at runtime.
        _ = new PolicyApplicator(policy);
        string hash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(yaml.ReplaceLineEndings("\n"))));
        return new LoadedPrivacyProfile(policy, document.Metadata.Id, document.Metadata.Version, hash);
    }

    /// <summary>Reads a key file holding base64 (preferred) or at least 32 raw bytes.</summary>
    public static byte[] ReadKeyFile(string path)
    {
        byte[] raw = File.ReadAllBytes(path);
        string text = Encoding.UTF8.GetString(raw).Trim();
        byte[] key;
        try
        {
            key = Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            key = raw;
        }

        return key.Length >= 32
            ? key
            : throw new InvalidDataException("HMAC key must be at least 32 bytes.");
    }

    private static PrivacyAction ParseAction(string value)
    {
        string normalised = value.Replace("-", string.Empty, StringComparison.Ordinal);
        string? name = Enum.GetNames<PrivacyAction>()
            .FirstOrDefault(item => string.Equals(item, normalised, StringComparison.OrdinalIgnoreCase));
        return name is not null && Enum.TryParse(name, out PrivacyAction action)
            ? action
            : throw new InvalidDataException($"Unknown privacy action '{value}'.");
    }

    private static void RequireKnown(HashSet<string> known, string detector)
    {
        if (!known.Contains(detector))
        {
            throw new InvalidDataException($"Unknown detector id '{detector}'.");
        }
    }
}
