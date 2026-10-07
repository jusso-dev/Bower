using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

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
        // Strict: an unknown or misspelt key (for example "requirments") must fail the load
        // rather than silently drop the requirements it was meant to carry.
        IDeserializer deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .Build();

        TelemetryPolicy policy;
        try
        {
            policy = deserializer.Deserialize<TelemetryPolicy>(yaml)
                ?? throw new InvalidDataException("Policy is empty.");
        }
        catch (YamlException exception)
        {
            throw new InvalidDataException(
                $"Policy '{Path.GetFileName(path)}' is invalid at line {exception.Start.Line}: {exception.Message}",
                exception);
        }

        Validate(policy);
        string canonicalJson = JsonSerializer.Serialize(policy);
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

        if (string.IsNullOrWhiteSpace(policy.Metadata.Id)
            || string.IsNullOrWhiteSpace(policy.Metadata.Version))
        {
            throw new InvalidDataException("Policy metadata id and version are required.");
        }

        // Default deny: a policy must name the exact event types it approves. A
        // category-only match would accept any new or unknown type in that category.
        if (policy.Match.EventTypes.Count == 0
            || policy.Match.EventTypes.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException("Policy match must list at least one eventType.");
        }

        if (!TryParseAction(policy.Decision.Action, out _))
        {
            throw new InvalidDataException($"Unsupported policy action: {policy.Decision.Action}");
        }

        if (policy.Decision.MinimumValueScore is < 0 or > 100)
        {
            throw new InvalidDataException("minimumValueScore must be between 0 and 100.");
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
