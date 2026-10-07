using System.Text.Json;

namespace Bower.Source.Docker;

/// <summary>A container that opted in to Bower collection.</summary>
public sealed record DockerContainer(
    string Id,
    string Name,
    string Image,
    string Directory,
    IReadOnlyDictionary<string, string> Labels)
{
    public string ShortId => Id[..12];

    public string LogPath => Path.Combine(Directory, $"{Id}-json.log");
}

public sealed record DockerCatalogOptions
{
    /// <summary>Docker's container state directory, mounted read-only.</summary>
    public required string Root { get; init; }

    /// <summary>Only containers with this label set to "true" are collected.</summary>
    public string OptInLabel { get; init; } = "bower.collect";

    public int MaximumContainers { get; init; } = 500;
}

/// <summary>
/// Discovers opted-in containers from Docker's on-disk metadata. Read-only: no Docker
/// API or socket access, so the sidecar cannot start, stop or exec containers.
/// </summary>
public static class DockerContainerCatalog
{
    private const int MaximumMetadataBytes = 1_048_576;

    public static DockerCatalogResult Discover(DockerCatalogOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Root);
        if (!System.IO.Directory.Exists(options.Root))
        {
            throw new DirectoryNotFoundException(
                $"Docker container directory not found: {options.Root}. Mount it read-only.");
        }

        List<DockerContainer> containers = [];
        int skipped = 0;
        foreach (string directory in System.IO.Directory
                     .EnumerateDirectories(options.Root)
                     .Order(StringComparer.Ordinal))
        {
            string id = Path.GetFileName(directory);
            if (!IsContainerId(id))
            {
                continue;
            }

            DockerContainer? container = TryRead(directory, id, options.OptInLabel, out bool unsupported);
            if (unsupported)
            {
                skipped++;
            }

            if (container is null)
            {
                continue;
            }

            if (containers.Count >= options.MaximumContainers)
            {
                skipped++;
                continue;
            }

            containers.Add(container);
        }

        return new DockerCatalogResult(containers, skipped);
    }

    internal static bool IsContainerId(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigitLower);

    private static DockerContainer? TryRead(
        string directory,
        string id,
        string optInLabel,
        out bool unsupported)
    {
        unsupported = false;
        JsonElement? config = ReadJson(Path.Combine(directory, "config.v2.json"));
        if (config is not { } root || root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        Dictionary<string, string> labels = new(StringComparer.Ordinal);
        if (root.TryGetProperty("Config", out JsonElement settings)
            && settings.ValueKind == JsonValueKind.Object
            && settings.TryGetProperty("Labels", out JsonElement labelElement)
            && labelElement.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty label in labelElement.EnumerateObject())
            {
                if (label.Value.ValueKind == JsonValueKind.String && labels.Count < 256)
                {
                    labels[label.Name] = label.Value.GetString() ?? string.Empty;
                }
            }
        }

        if (!labels.TryGetValue(optInLabel, out string? optIn)
            || !string.Equals(optIn, "true", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Only the json-file driver writes files Bower can tail.
        JsonElement? hostConfig = ReadJson(Path.Combine(directory, "hostconfig.json"));
        string? driver = hostConfig is { ValueKind: JsonValueKind.Object } host
            && host.TryGetProperty("LogConfig", out JsonElement logConfig)
            && logConfig.ValueKind == JsonValueKind.Object
            && logConfig.TryGetProperty("Type", out JsonElement type)
            && type.ValueKind == JsonValueKind.String
                ? type.GetString()
                : null;
        if (driver is not null && !string.Equals(driver, "json-file", StringComparison.Ordinal))
        {
            unsupported = true;
            return null;
        }

        string name = ReadString(root, "Name")?.TrimStart('/') ?? id[..12];
        string image = settings.ValueKind == JsonValueKind.Object
            ? ReadString(settings, "Image") ?? "unknown"
            : "unknown";
        return new DockerContainer(id, Bound(name, 128), Bound(image, 256), directory, labels);
    }

    private static JsonElement? ReadJson(string path)
    {
        FileInfo file = new(path);
        if (!file.Exists || file.Length > MaximumMetadataBytes)
        {
            return null;
        }

        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using JsonDocument document = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 32 });
            return document.RootElement.Clone();
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            // Docker rewrites metadata atomically, but tolerate a racing or unreadable file.
            return null;
        }
    }

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string Bound(string value, int length) =>
        value.Length <= length ? value : value[..length];
}

public sealed record DockerCatalogResult(IReadOnlyList<DockerContainer> Containers, int Skipped);
