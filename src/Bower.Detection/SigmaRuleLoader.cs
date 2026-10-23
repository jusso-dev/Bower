using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
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

        ValidateYamlBounds(yaml);
        using StringReader reader = new(yaml);
        YamlStream stream = new();
        stream.Load(reader);
        if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            throw new InvalidDataException("Sigma rule root must be a mapping.");
        }

        int remainingNodes = 8192;
        ValidateTree(root, 0, ref remainingNodes);

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
                string key = keyNode is YamlScalarNode keyScalar ? keyScalar.Value ?? string.Empty : throw DetectionSemantics.Invalid();
                if (key.Equals("condition", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!fields.TryAdd(key, EncodeSelection(valueNode)))
                {
                    throw DetectionSemantics.Invalid();
                }
            }
        }

        if (fields.Count == 0)
        {
            throw new InvalidDataException($"Sigma rule '{id}' has no detection selections.");
        }

        _ = new DetectionSemantics(fields, condition);

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

    private static string EncodeSelection(YamlNode node)
    {
        if (node is not YamlMappingNode mapping) { throw DetectionSemantics.Invalid(); }
        List<string[]> clauses = [];
        foreach ((YamlNode key, YamlNode value) in mapping.Children)
        {
            if (key is not YamlScalarNode scalarKey) { throw DetectionSemantics.Invalid(); }
            string[] parts = (scalarKey.Value ?? string.Empty).Split('|');
            if (parts.Length > 2) { throw DetectionSemantics.Invalid(); }
            List<string> clause = [parts[0], parts.Length == 1 ? "equals" : parts[1]];
            if (value is YamlSequenceNode sequence)
            {
                clause.AddRange(sequence.Select(SelectionScalar));
            }
            else { clause.Add(SelectionScalar(value)); }
            clauses.Add(clause.ToArray());
        }

        string[][] result = clauses.ToArray();
        DetectionSemantics.ValidateClauses(result);
        return JsonSerializer.Serialize(result, DetectionJsonContext.Default.StringArrayArray);
    }

    private static string SelectionScalar(YamlNode node)
    {
        if (node is not YamlScalarNode scalar || scalar.Value is null) { throw DetectionSemantics.Invalid(); }
        // Quote YAML typed scalars; the two YAML libraries resolve them differently.
        string value = scalar.Value;
        if (scalar.Style == ScalarStyle.Plain && (value.Length == 0
            || value.Equals("true", StringComparison.OrdinalIgnoreCase)
            || value.Equals("false", StringComparison.OrdinalIgnoreCase)
            || value.Equals("null", StringComparison.OrdinalIgnoreCase)
            || value == "~" || IsYamlNumber(value)))
        {
            throw DetectionSemantics.Invalid();
        }
        return value;
    }

    private static void ValidateTree(YamlNode node, int depth, ref int remaining)
    {
        if (depth > 32 || --remaining < 0) { throw DetectionSemantics.Invalid(); }
        if (node is YamlMappingNode mapping)
        {
            HashSet<string> keys = new(StringComparer.OrdinalIgnoreCase);
            foreach ((YamlNode key, YamlNode value) in mapping.Children)
            {
                if (key is not YamlScalarNode scalar || !keys.Add(scalar.Value ?? string.Empty)) { throw DetectionSemantics.Invalid(); }
                ValidateTree(key, depth + 1, ref remaining);
                ValidateTree(value, depth + 1, ref remaining);
            }
        }
        else if (node is YamlSequenceNode sequence)
        {
            foreach (YamlNode item in sequence) { ValidateTree(item, depth + 1, ref remaining); }
        }
    }

    private static bool IsYamlNumber(string value)
    {
        string unsigned = value.TrimStart('+', '-');
        if (unsigned.Length > 1 && unsigned[0] == '0' && unsigned.All(char.IsAsciiDigit)) { return false; }
        return double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _)
            || unsigned is ".inf" or ".Inf" or ".INF" or ".nan" or ".NaN" or ".NAN"
            || unsigned.StartsWith("0x", StringComparison.Ordinal) || unsigned.StartsWith("0o", StringComparison.Ordinal)
            || unsigned.StartsWith("0b", StringComparison.Ordinal);
    }

    private static void ValidateYamlBounds(string yaml)
    {
        Parser parser = new(new StringReader(yaml));
        int depth = 0;
        int nodes = 0;
        while (parser.MoveNext())
        {
            if (++nodes > 8192) { throw DetectionSemantics.Invalid(); }
            if (parser.Current is MappingStart or SequenceStart && ++depth > 32) { throw DetectionSemantics.Invalid(); }
            if (parser.Current is MappingEnd or SequenceEnd) { depth--; }
            if (parser.Current is NodeEvent node && !node.Tag.IsEmpty) { throw DetectionSemantics.Invalid(); }
        }
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
            ? node is YamlScalarNode scalar ? scalar.Value : throw DetectionSemantics.Invalid()
            : null;
    }
}
