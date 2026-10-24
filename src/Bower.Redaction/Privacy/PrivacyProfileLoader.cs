using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Bower.Redaction.Detectors;
using Bower.Redaction.Privacy.Yaml;
using YamlDotNet.Core;

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

    public List<PrivacyCustomDetectorDocument> CustomDetectors { get; init; } = [];

    public List<string> SecretFieldNames { get; init; } = [];
}

/// <summary>A custom detector (custom redaction rule) as written in a privacy profile.</summary>
public sealed record PrivacyCustomDetectorDocument
{
    public required string Id { get; init; }

    public string? Description { get; init; }

    public required string Pattern { get; init; }

    public bool? IgnoreCase { get; init; }

    public bool? WholeWord { get; init; }

    public required string Action { get; init; }

    public required PrivacyCustomDetectorTestsDocument Tests { get; init; }
}

/// <summary>Samples a custom detector must (<c>match</c>) and must not (<c>noMatch</c>) match.</summary>
public sealed record PrivacyCustomDetectorTestsDocument
{
    public List<string> Match { get; init; } = [];

    public List<string> NoMatch { get; init; } = [];
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

public sealed record LoadedPrivacyProfile(PrivacyPolicy Policy, string Id, string Version, string Hash)
{
    /// <summary>Custom detector test samples (match and noMatch) that passed at load.</summary>
    public int CustomDetectorTests { get; init; }
}

/// <summary>
/// Loads a deterministic privacy profile. Strict YAML: unknown keys, unknown detector
/// ids and unknown actions fail the load. The HMAC key comes from the host, never YAML.
/// </summary>
public static class PrivacyProfileLoader
{
    private const int MaximumProfileBytes = 262_144;
    private const int MaximumCustomDetectors = 32;
    private const int MaximumSamples = 16;
    private const int MaximumSampleLength = 1024;
    private const int MaximumSecretFieldNames = 64;
    private const int MaximumSecretFieldNameLength = 128;

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
            document = PrivacyProfileYamlReader.Read(yaml)
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
        // YamlDotNet does not enforce `required`: explicit YAML nulls arrive as null and
        // must fail the load with a clear message, never a NullReferenceException.
        List<CustomDetectorDefinition> customDetectors =
            LoadCustomDetectors(RequireCollection(document.CustomDetectors, "customDetectors"), out int customDetectorTests);
        HashSet<string> customIds = customDetectors.Select(detector => detector.Id).ToHashSet(StringComparer.Ordinal);
        PrivacyPolicy defaults = PrivacyPolicy.CreateDefault();
        Dictionary<string, PrivacyAction> actions = new(defaults.DetectorActions, StringComparer.Ordinal);
        foreach ((string detector, string? action) in RequireCollection(document.Detectors, "detectors"))
        {
            if (customIds.Contains(detector))
            {
                throw new InvalidDataException($"Custom detector '{detector}' sets its action in customDetectors, not detectors.");
            }

            RequireKnown(known, detector);
            actions[detector] = ParseAction(action
                ?? throw new InvalidDataException($"Privacy profile action for '{detector}' must not be null."));
        }

        foreach (CustomDetectorDefinition detector in customDetectors)
        {
            actions[detector.Id] = detector.Action;
        }

        List<string> disabled = RequireCollection(document.Disabled, "disabled");
        List<string> enableOptIn = RequireCollection(document.EnableOptIn, "enableOptIn");
        foreach (string detector in disabled)
        {
            // Custom detectors are enabled by default and may be disabled, never opted in.
            if (!customIds.Contains(detector))
            {
                RequireKnown(known, detector);
            }
        }

        foreach (string detector in enableOptIn)
        {
            RequireKnown(known, detector);
        }

        List<PrivacyFieldRule> rules = [];
        foreach (PrivacyFieldRuleDocument? rule in RequireCollection(document.Fields, "fields"))
        {
            if (rule is null)
            {
                throw new InvalidDataException("Privacy profile field rule must not be null.");
            }

            if (string.IsNullOrWhiteSpace(rule.Path)
                || rule.Path.Split('.').Any(segment => segment.Length == 0 || segment.Length > 64))
            {
                throw new InvalidDataException($"Field rule path '{rule.Path}' is invalid.");
            }

            PrivacyAction action = ParseAction(rule.Action
                ?? throw new InvalidDataException($"Field rule '{rule.Path}' needs an action."));
            if (action == PrivacyAction.Truncate && rule.MaxLength is not (> 0 and <= 65_536))
            {
                throw new InvalidDataException($"Field rule '{rule.Path}' needs maxLength between 1 and 65536 for truncate.");
            }

            rules.Add(new PrivacyFieldRule(rule.Path, action, rule.MaxLength));
        }

        List<string> secretFieldNames = LoadSecretFieldNames(RequireCollection(document.SecretFieldNames, "secretFieldNames"));

        int maximumFieldLength = document.MaximumFieldLength ?? defaults.MaximumFieldLength;
        if (maximumFieldLength is < 256 or > 65_536)
        {
            throw new InvalidDataException("maximumFieldLength must be between 256 and 65536.");
        }

        PrivacyPolicy policy = new()
        {
            DefaultAction = document.DefaultAction is null ? defaults.DefaultAction : ParseAction(document.DefaultAction),
            DetectorActions = actions,
            DisabledDetectors = disabled.ToHashSet(StringComparer.Ordinal),
            EnabledOptInDetectors = enableOptIn.ToHashSet(StringComparer.Ordinal),
            FieldRules = rules,
            CustomDetectors = customDetectors,
            SecretFieldNames = secretFieldNames,
            MaximumFieldLength = maximumFieldLength,
            EmitMetadata = document.EmitMetadata ?? true,
            HmacKey = hmacKey,
            HmacKeyId = string.IsNullOrWhiteSpace(hmacKeyId) ? "k1" : hmacKeyId
        };

        // Construct once so a profile that needs an absent key fails at load, not at runtime.
        _ = new PolicyApplicator(policy);
        PrivacyProfileMetadata metadata = document.Metadata
            ?? throw new InvalidDataException("Privacy profile metadata is required.");
        string hash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(yaml.ReplaceLineEndings("\n"))));
        return new LoadedPrivacyProfile(policy, metadata.Id, metadata.Version, hash)
        {
            CustomDetectorTests = customDetectorTests
        };
    }

    private static List<CustomDetectorDefinition> LoadCustomDetectors(
        List<PrivacyCustomDetectorDocument> documents,
        out int tests)
    {
        tests = 0;
        if (documents.Count > MaximumCustomDetectors)
        {
            throw new InvalidDataException("Privacy profile may define at most 32 custom detectors.");
        }

        HashSet<string> ids = new(StringComparer.Ordinal);
        List<CustomDetectorDefinition> definitions = [];
        foreach (PrivacyCustomDetectorDocument? document in documents)
        {
            if (document is null)
            {
                throw new InvalidDataException("Privacy profile custom detector must not be null.");
            }

            string id = document.Id;
            CustomDetectorDefinition.RequireValidId(id);
            if (!ids.Add(id))
            {
                throw new InvalidDataException($"Custom detector id '{id}' is defined more than once.");
            }

            CustomDetectorDefinition.RequireValidDescription(id, document.Description);
            bool ignoreCase = document.IgnoreCase ?? false;
            (string canonical, Regex regex) = CustomDetectorDefinition.CompilePattern(id, document.Pattern, ignoreCase);
            PrivacyAction action = ParseAction(document.Action
                ?? throw new InvalidDataException($"Custom detector '{id}' requires an action."));

            List<string>? match = document.Tests?.Match;
            List<string>? noMatch = document.Tests?.NoMatch;
            if (match is not { Count: > 0 })
            {
                throw new InvalidDataException($"Custom detector '{id}' requires at least one tests.match sample.");
            }

            if (match.Count > MaximumSamples
                || noMatch is null
                || noMatch.Count > MaximumSamples
                || match.Concat(noMatch).Any(sample => sample is not { Length: > 0 and <= MaximumSampleLength }))
            {
                throw new InvalidDataException(
                    $"Custom detector '{id}' may have at most 16 tests.match and 16 tests.noMatch samples of 1-1024 characters.");
            }

            CustomDetectorDefinition definition = CustomDetectorDefinition.FromValidated(
                id, document.Description, document.Pattern, canonical, regex, ignoreCase, document.WholeWord ?? false, action);
            CustomPatternDetector detector = new(definition);
            try
            {
                for (int index = 0; index < match.Count; index++)
                {
                    if (!detector.Matches(match[index]))
                    {
                        throw new InvalidDataException($"Custom detector '{id}' did not match tests.match[{index}].");
                    }
                }

                for (int index = 0; index < noMatch.Count; index++)
                {
                    if (detector.Matches(noMatch[index]))
                    {
                        throw new InvalidDataException($"Custom detector '{id}' matched tests.noMatch[{index}].");
                    }
                }
            }
            catch (RegexMatchTimeoutException exception)
            {
                throw new InvalidDataException($"Custom detector '{id}' pattern is too complex.", exception);
            }

            tests += match.Count + noMatch.Count;
            definitions.Add(definition);
        }

        return definitions;
    }

    /// <summary>Normalises like the engine; duplicates after normalisation keep the first occurrence.</summary>
    private static List<string> LoadSecretFieldNames(List<string> names)
    {
        if (names.Count > MaximumSecretFieldNames
            || names.Any(name => name is not { Length: > 0 and <= MaximumSecretFieldNameLength }))
        {
            throw new InvalidDataException("Privacy profile may list at most 64 secretFieldNames of 1-128 characters.");
        }

        HashSet<string> seen = new(StringComparer.Ordinal);
        List<string> normalised = [];
        foreach (string name in names)
        {
            string value = FieldNameNormalizer.Normalize(name);
            if (value.Length == 0)
            {
                throw new InvalidDataException($"Secret field name '{name}' has no letters or digits.");
            }

            if (seen.Add(value))
            {
                normalised.Add(value);
            }
        }

        return normalised;
    }

    private static T RequireCollection<T>(T? value, string name)
        where T : class =>
        value ?? throw new InvalidDataException($"Privacy profile '{name}' must not be null.");

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
