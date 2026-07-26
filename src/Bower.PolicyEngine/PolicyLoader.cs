using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        IDeserializer deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        TelemetryPolicy policy = deserializer.Deserialize<TelemetryPolicy>(yaml)
            ?? throw new InvalidDataException("Policy is empty.");

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
            || string.IsNullOrWhiteSpace(policy.Metadata.Version)
            || (policy.Match.EventCategories.Count == 0 && policy.Match.EventTypes.Count == 0))
        {
            throw new InvalidDataException("Policy metadata and at least one match value are required.");
        }

        if (!Enum.TryParse<Contracts.DecisionAction>(
                policy.Decision.Action.Replace("-", string.Empty, StringComparison.Ordinal),
                true,
                out _))
        {
            throw new InvalidDataException($"Unsupported policy action: {policy.Decision.Action}");
        }

        if (policy.Decision.MinimumValueScore is < 0 or > 100)
        {
            throw new InvalidDataException("minimumValueScore must be between 0 and 100.");
        }
    }
}

public sealed record LoadedPolicy(TelemetryPolicy Policy, string Hash, string SourcePath);
