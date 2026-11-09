using System.Text.Json;
using System.Text.Json.Nodes;

namespace AsvsSerilogExample;

/// <summary>Prints the contract events (see ../contract) in Python json.dumps(sort_keys=True) form.</summary>
internal static class Contract
{
    public static void Print(string path)
    {
        JsonObject cases = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        JsonObject app = cases["app"]!.AsObject();
        DateTimeOffset now = DateTimeOffset.Parse(cases["now"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        foreach (JsonNode? item in cases["cases"]!.AsArray())
        {
            JsonObject spec = item!["spec"]!.AsObject();
            Console.WriteLine(PyJson(BowerEvents.Build(app, spec, item["eventId"]!.GetValue<string>(), now)));
        }
    }

    private static string PyJson(JsonNode? node) => node switch
    {
        JsonObject obj => "{" + string.Join(", ", obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Quote(p.Key) + ": " + PyJson(p.Value))) + "}",
        JsonArray array => "[" + string.Join(", ", array.Select(PyJson)) + "]",
        JsonValue value when value.TryGetValue(out string? text) => Quote(text),
        null => "null",
        _ => node.ToJsonString(),
    };

    private static string Quote(string text)
    {
        System.Text.StringBuilder output = new("\"");
        foreach (char c in text)
        {
            output.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                _ when c < 0x20 || c > 0x7e => $"\\u{(int)c:x4}",
                _ => c.ToString(),
            });
        }

        return output.Append('"').ToString();
    }
}
