using System.Text.Json;

namespace Bower.Collector;

/// <summary>Exact producer identity tuples. Loaded once; changing scopes requires restart.</summary>
public sealed class ProducerAuthorization
{
    private sealed record Identity(
        string Name, string Environment, string? TenantId, string? Instance,
        string? Hostname, string? IpAddress, int? Port);

    private readonly List<(string Producer, Identity Identity)> scopes = [];
    private readonly bool singleTrustDomain;

    public ProducerAuthorization(string? path, bool singleTrustDomain = false)
    {
        this.singleTrustDomain = singleTrustDomain;
        if (path is null)
        {
            return; // Default deny; authentication alone grants no event identity.
        }

        if (singleTrustDomain)
        {
            throw new InvalidOperationException("Producer scopes and single trust domain mode are mutually exclusive.");
        }

        try
        {
            if (new FileInfo(path).Length > 1_048_576)
            {
                throw new FormatException();
            }

            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path),
                new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.GetArrayLength() > 4096)
            {
                throw new FormatException();
            }

            foreach (JsonElement item in document.RootElement.EnumerateArray())
            {
                CheckObject(item, ["producer", "application", "source"]);
                string producer = RequiredString(item, "producer");
                if (producer.Length > 64 || producer.Any(char.IsWhiteSpace))
                {
                    throw new FormatException();
                }

                scopes.Add((producer, ReadIdentity(item, configuration: true)));
            }
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        {
            // Never echo configuration or candidate values in diagnostics.
            throw new FormatException("Invalid producer scopes file.");
        }
    }

    public bool IsAuthorized(string producer, JsonElement candidate)
    {
        if (singleTrustDomain)
        {
            return true;
        }

        try
        {
            Identity identity = ReadIdentity(candidate, configuration: false);
            return scopes.Any(scope => scope.Producer == producer && scope.Identity == identity);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        {
            return false;
        }
    }

    private static Identity ReadIdentity(JsonElement root, bool configuration)
    {
        CheckObject(root);
        JsonElement application = root.GetProperty("application");
        CheckObject(application, configuration ? ["name", "environment", "tenantId", "instance"] : null);
        JsonElement source = root.TryGetProperty("source", out JsonElement value) ? value : default;
        if (source.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null))
        {
            CheckObject(source, configuration ? ["hostname", "ipAddress", "port"] : null);
        }

        return new Identity(
            RequiredString(application, "name"), RequiredString(application, "environment"),
            OptionalString(application, "tenantId"), OptionalString(application, "instance"),
            OptionalString(source, "hostname"), OptionalString(source, "ipAddress"),
            source.ValueKind == JsonValueKind.Object && source.TryGetProperty("port", out JsonElement port)
                && port.ValueKind != JsonValueKind.Null ? port.GetInt32() : null);
    }

    private static void CheckObject(JsonElement value, string[]? allowed = null)
    {
        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
        {
            if (!names.Add(property.Name) || (allowed is not null && !allowed.Contains(property.Name, StringComparer.Ordinal)))
            {
                throw new FormatException();
            }
        }
    }

    private static string RequiredString(JsonElement value, string name) =>
        OptionalString(value, name) is { } text && !string.IsNullOrWhiteSpace(text)
            ? text : throw new FormatException();

    private static string? OptionalString(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out JsonElement field)
            ? field.GetString() : null;
}
