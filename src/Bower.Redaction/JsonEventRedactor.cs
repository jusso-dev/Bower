using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;

namespace Bower.Redaction;

public sealed class JsonEventRedactor : IEventRedactor
{
    public const int MaximumPayloadBytes = 1_048_576;

    private static readonly HashSet<string> RemoveNames = new(
        [
            "password",
            "passwordhash",
            "accesstoken",
            "refreshtoken",
            "bearertoken",
            "apikeysecret",
            "clientsecret",
            "privatekey",
            "connectionstring",
            "authorization",
            "cookie",
            "cookies",
            "credential",
            "credentials",
            "requestbody",
            "responsebody",
            "body",
            "headers",
            "payload",
            "filecontents"
        ],
        StringComparer.Ordinal);

    private static readonly HashSet<string> MaskNames = new(
        ["email", "emailaddress"],
        StringComparer.Ordinal);

    public RedactionResult Redact(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Failure("empty-payload");
        }

        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaximumPayloadBytes)
        {
            return Failure("payload-too-large");
        }

        try
        {
            JsonNode? root = JsonNode.Parse(
                json,
                documentOptions: new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });

            if (root is not JsonObject rootObject)
            {
                return Failure("root-must-be-object");
            }

            List<string> removed = [];
            List<string> masked = [];
            RedactObject(rootObject, "$", removed, masked);

            return new RedactionResult(
                true,
                rootObject.ToJsonString(),
                removed,
                masked,
                null);
        }
        catch (JsonException)
        {
            return Failure("invalid-json");
        }
    }

    private static void RedactObject(
        JsonObject value,
        string parentPath,
        List<string> removed,
        List<string> masked)
    {
        foreach ((string propertyName, JsonNode? child) in value.ToArray())
        {
            string path = $"{parentPath}.{propertyName}";
            string normalizedName = Normalize(propertyName);

            if (RemoveNames.Contains(normalizedName))
            {
                value.Remove(propertyName);
                removed.Add(path);
                continue;
            }

            if (MaskNames.Contains(normalizedName) && child is JsonValue)
            {
                value[propertyName] = Mask(child.ToString());
                masked.Add(path);
                continue;
            }

            RedactNode(child, path, removed, masked);
        }
    }

    private static void RedactNode(
        JsonNode? node,
        string path,
        List<string> removed,
        List<string> masked)
    {
        if (node is JsonObject childObject)
        {
            RedactObject(childObject, path, removed, masked);
            return;
        }

        if (node is not JsonArray array)
        {
            return;
        }

        for (int index = 0; index < array.Count; index++)
        {
            RedactNode(array[index], $"{path}[{index}]", removed, masked);
        }
    }

    private static string Normalize(string value)
    {
        return string.Concat(value.Where(char.IsLetterOrDigit)).ToLowerInvariant();
    }

    private static string Mask(string value)
    {
        int separator = value.IndexOf('@', StringComparison.Ordinal);
        if (separator <= 0)
        {
            return "***";
        }

        return $"{value[0]}***{value[separator..]}";
    }

    private static RedactionResult Failure(string code)
    {
        return new RedactionResult(false, null, [], [], code);
    }
}
