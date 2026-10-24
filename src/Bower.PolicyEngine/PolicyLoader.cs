using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.PolicyEngine.Yaml;
using YamlDotNet.Core;

namespace Bower.PolicyEngine;

public static class PolicyLoader
{
    private const int MaximumPolicyBytes = 1_048_576;

    public static IReadOnlyList<LoadedPolicy> LoadDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Policy directory does not exist: {directory}");
        }

        return Directory
            .EnumerateFiles(directory, "*.yaml", SearchOption.TopDirectoryOnly)
            .Order(StringComparer.Ordinal)
            .Select(LoadFile)
            .ToArray();
    }

    public static LoadedPolicy LoadFile(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Policy file does not exist.", path);
        }

        if (info.Length > MaximumPolicyBytes)
        {
            throw new InvalidDataException("Policy exceeds maximum size.");
        }

        string yaml = File.ReadAllText(path, Encoding.UTF8);
        return LoadYaml(yaml, path);
    }

    /// <summary>Loads a policy from YAML text (used for signed packs).</summary>
    public static LoadedPolicy LoadYaml(string yaml, string sourceName)
    {
        ArgumentNullException.ThrowIfNull(yaml);
        if (Encoding.UTF8.GetByteCount(yaml) > MaximumPolicyBytes)
        {
            throw new InvalidDataException("Policy exceeds maximum size.");
        }

        string path = sourceName;
        // Strict: an unknown or misspelt key (for example "requirments") must fail the load
        // rather than silently drop the requirements it was meant to carry.
        TelemetryPolicy policy;
        try
        {
            policy = PolicyYamlReader.Read(yaml)
                ?? throw new InvalidDataException("Policy is empty.");
        }
        catch (YamlException exception)
        {
            throw new InvalidDataException(
                $"Policy '{Path.GetFileName(path)}' is invalid at line {exception.Start.Line}: {exception.Message}",
                exception);
        }

        Validate(policy);
        string canonicalJson = JsonSerializer.Serialize(policy, PolicyHashJsonContext.Default.TelemetryPolicy);
        string hash = $"sha256:{Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson)))}";
        return new LoadedPolicy(policy, hash, path);
    }

    private static void Validate(TelemetryPolicy policy)
    {
        if (!string.Equals(policy.ApiVersion, "bower.security/v1", StringComparison.Ordinal)
            || !string.Equals(policy.Kind, "TelemetryPolicy", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Unsupported policy apiVersion or kind.");
        }

        // YAML can leave any section, list or list item null (missing key, `~`, `- ~`).
        // The evaluator dereferences all of them, so they are rejected here rather than
        // failing every evaluation later.
        if (policy.Metadata is null
            || string.IsNullOrWhiteSpace(policy.Metadata.Id)
            || string.IsNullOrWhiteSpace(policy.Metadata.Version))
        {
            throw new InvalidDataException("Policy metadata id and version are required.");
        }

        // Default deny: a policy must name the exact event types it approves. A
        // category-only match would accept any new or unknown type in that category.
        if (policy.Match?.EventTypes is not { Count: > 0 } eventTypes
            || eventTypes.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException("Policy match must list at least one eventType.");
        }

        if (policy.Decision is null)
        {
            throw new InvalidDataException("Policy decision section is required.");
        }

        if (!TryParseAction(policy.Decision.Action, out _))
        {
            throw new InvalidDataException($"Unsupported policy action: {policy.Decision.Action}");
        }

        if (policy.Decision.MinimumValueScore is < 0 or > 100)
        {
            throw new InvalidDataException("minimumValueScore must be between 0 and 100.");
        }

        if (policy.Match.EventCategories is null
            || policy.Match.EventCategories.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException(
                "Policy match eventCategories must be a list of non-blank values.");
        }

        if (policy.Requirements is null)
        {
            throw new InvalidDataException("Policy requirements section is required.");
        }

        ValidatePredicate(policy.Match.EventActions, "eventActions");
        ValidatePredicate(policy.Match.EventResults, "eventResults", ["unknown", "success", "failure", "denied"]);
        ValidatePredicate(policy.Match.EventSeverities, "eventSeverities", ["informational", "low", "medium", "high", "critical"]);

        // A null or blank path can never be present: as a required field it would quarantine
        // every matching event with "Missing required field: ".
        ValidateFieldPaths(policy.Requirements.RequiredFields, "requiredFields");
        ValidateFieldPaths(policy.Requirements.AtLeastOne, "atLeastOne");
        ValidateFieldPaths(policy.Requirements.RecommendedFields, "recommendedFields");
    }

    private static void ValidatePredicate(List<string>? values, string name, string[]? allowed = null)
    {
        if (values is not null && (values.Count is 0 or > 256
            || values.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 256
                || allowed is not null && !allowed.Contains(value, StringComparer.Ordinal))))
        {
            throw new InvalidDataException($"Policy match {name} must contain 1–256 approved non-blank values.");
        }
    }

    private static void ValidateFieldPaths(List<string>? paths, string name)
    {
        if (paths is null || paths.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException(
                $"Policy requirements {name} must be a list of non-blank field paths.");
        }
    }

    /// <summary>Parses a named action. Numeric values are rejected.</summary>
    internal static bool TryParseAction(string? value, out DecisionAction action)
    {
        action = default;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string normalized = value.Replace("-", string.Empty, StringComparison.Ordinal);
        string? name = Enum.GetNames<DecisionAction>()
            .FirstOrDefault(item => string.Equals(item, normalized, StringComparison.OrdinalIgnoreCase));
        return name is not null && Enum.TryParse(name, out action);
    }
}

public sealed record LoadedPolicy(TelemetryPolicy Policy, string Hash, string SourcePath);
