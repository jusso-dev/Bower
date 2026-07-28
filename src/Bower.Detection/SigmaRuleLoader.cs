using System.Security.Cryptography;
using System.Text;
using YamlDotNet.RepresentationModel;

namespace Bower.Detection;

public static class SigmaRuleLoader
{
    public static DetectionRule LoadFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string yaml = File.ReadAllText(path);
        return LoadYaml(yaml, path);
    }

    public static IReadOnlyList<DetectionRule> LoadDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Rule directory '{directory}' was not found.");
        }

        return Directory
            .EnumerateFiles(directory, "*.y*ml", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(LoadFile)
            .ToArray();
    }

    public static DetectionRule LoadYaml(string yaml, string? sourceName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yaml);
        if (Encoding.UTF8.GetByteCount(yaml) > 256 * 1024)
        {
            throw new InvalidDataException("Sigma rule exceeds 256 KiB limit.");
        }

        using StringReader reader = new(yaml);
        YamlStream stream = new();
        stream.Load(reader);
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            throw new InvalidDataException("Sigma rule root must be a mapping.");
        }

        string id = RequiredScalar(root, "id", sourceName);
        string title = RequiredScalar(root, "title", sourceName);
        string level = OptionalScalar(root, "level") ?? "medium";
        string status = OptionalScalar(root, "status") ?? "experimental";
        string description = OptionalScalar(root, "description") ?? string.Empty;
        string version = OptionalScalar(root, "version")
            ?? OptionalScalar(root, "date")
            ?? "1.0.0";

        List<string> logSources = [];
        if (root.Children.TryGetValue(new YamlScalarNode("logsource"), out YamlNode? logSourceNode) &&
            logSourceNode is YamlMappingNode logSource)
        {
            foreach (string key in new[] { "product", "service", "category" })
            {
                string? value = OptionalScalar(logSource, key);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    logSources.Add(value);
                }
            }
        }

        Dictionary<string, string> fields = new(StringComparer.OrdinalIgnoreCase);
        string condition = "selection";
        if (root.Children.TryGetValue(new YamlScalarNode("detection"), out YamlNode? detectionNode) &&
            detectionNode is YamlMappingNode detection)
        {
            condition = OptionalScalar(detection, "condition") ?? "selection";
            foreach ((YamlNode keyNode, YamlNode valueNode) in detection.Children)
            {
                string key = keyNode.ToString();
                if (key.Equals("condition", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                fields[key] = FlattenSelection(valueNode);
            }
        }

        if (fields.Count == 0)
        {
            throw new InvalidDataException($"Sigma rule '{id}' has no detection selections.");
        }

        List<string> techniques = [];
        if (root.Children.TryGetValue(new YamlScalarNode("tags"), out YamlNode? tagsNode) &&
            tagsNode is YamlSequenceNode tags)
        {
            foreach (YamlNode tag in tags)
            {
                string value = tag.ToString();
                if (value.StartsWith("attack.t", StringComparison.OrdinalIgnoreCase))
                {
                    techniques.Add(value["attack.".Length..].ToUpperInvariant());
                }
                else if (value.StartsWith("t", StringComparison.OrdinalIgnoreCase) &&
                         value.Length >= 5 &&
                         value.Skip(1).All(char.IsDigit))
                {
                    techniques.Add(value.ToUpperInvariant());
                }
            }
        }

        List<string> falsePositives = [];
        if (root.Children.TryGetValue(new YamlScalarNode("falsepositives"), out YamlNode? fpNode) &&
            fpNode is YamlSequenceNode fpSequence)
        {
            falsePositives.AddRange(fpSequence.Select(item => item.ToString()));
        }

        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(yaml)))
            .ToLowerInvariant();

        return new DetectionRule(
            id,
            title,
            version,
            level.ToLowerInvariant(),
            status.ToLowerInvariant(),
            description,
            logSources,
            fields,
            condition,
            techniques,
            falsePositives,
            hash);
    }

    private static string FlattenSelection(YamlNode node)
    {
        if (node is YamlScalarNode scalar)
        {
            return scalar.Value ?? string.Empty;
        }

        if (node is YamlSequenceNode sequence)
        {
            return string.Join('|', sequence.Select(item => item.ToString()));
        }

        if (node is YamlMappingNode mapping)
        {
            List<string> parts = [];
            foreach ((YamlNode key, YamlNode value) in mapping.Children)
            {
                parts.Add($"{key}:{FlattenSelection(value)}");
            }

            return string.Join(';', parts);
        }

        return node.ToString();
    }

    private static string RequiredScalar(YamlMappingNode root, string name, string? source)
    {
        string? value = OptionalScalar(root, name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(
                $"Sigma rule{(source is null ? string.Empty : $" '{source}'")} missing required field '{name}'.");
        }

        return value;
    }

    private static string? OptionalScalar(YamlMappingNode root, string name)
    {
        return root.Children.TryGetValue(new YamlScalarNode(name), out YamlNode? node)
            ? node.ToString()
            : null;
    }
}
