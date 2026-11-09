using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AsvsSerilogExample;

/// <summary>
/// Bower envelope 1.0.0 events for ASP.NET Core, sanitised before they leave the process, for
/// the event families Bower.Sdk has no typed helper for yet. The collector redacts again.
/// </summary>
public static partial class BowerEvents
{
    private static readonly string[] SecretFragments =
        ["password", "passwd", "passphrase", "secret", "token", "apikey", "cookie", "authorization", "credential", "privatekey", "signature"];

    private static readonly HashSet<string> SecretNames = new(
        ["body", "rawbody", "requestbody", "responsebody", "headers", "payload", "otp", "otpcode", "totp", "mfacode", "verificationcode",
         "recoverycode", "backupcode", "stacktrace", "exceptionmessage", "statement", "querytext", "sqltext", "querystring", "rawquery"],
        StringComparer.Ordinal);

    public static bool IsSecret(string name)
    {
        string normal = NonAlphanumeric().Replace(name.ToLowerInvariant(), string.Empty);
        return SecretNames.Contains(normal) || SecretFragments.Any(normal.Contains);
    }

    /// <summary>UTC, millisecond precision, Z suffix (ASVS 5.0 V16.2.2).</summary>
    public static string FormatTime(DateTimeOffset time) =>
        time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    public static JsonObject Build(JsonObject app, JsonObject spec, string? eventId = null, DateTimeOffset? now = null)
    {
        JsonObject application = [];
        foreach (string key in new[] { "name", "environment", "version", "instance" })
        {
            if (app[key] is JsonNode value)
            {
                application[key] = value.DeepClone();
            }
        }

        if (Text(spec, "tenantId") is string tenant)
        {
            application["tenantId"] = tenant;
        }

        JsonObject envelope = new()
        {
            ["schemaVersion"] = "1.0.0",
            ["eventId"] = eventId ?? Guid.NewGuid().ToString(),
            ["timeGenerated"] = FormatTime(now ?? DateTimeOffset.UtcNow),
            ["eventCategory"] = Text(spec, "eventCategory"),
            ["eventType"] = Text(spec, "eventType"),
            ["eventAction"] = Text(spec, "eventAction"),
            ["eventResult"] = Text(spec, "eventResult"),
            ["eventSeverity"] = Text(spec, "eventSeverity") ?? "informational",
            ["application"] = application,
        };
        if (Text(spec, "reason") is string reason)
        {
            envelope["eventOutcomeReason"] = reason;
        }

        foreach (string part in new[] { "actor", "target" })
        {
            if (spec[part] is JsonObject value && value.Count > 0)
            {
                envelope[part] = value.DeepClone();
            }
        }

        if (Text(spec, "sourceIp") is string ip)
        {
            envelope["source"] = new JsonObject { ["ipAddress"] = ip };
        }

        JsonObject request = spec["request"]?.DeepClone() as JsonObject ?? [];
        if (request["path"] is JsonValue pathValue && pathValue.TryGetValue(out string? path))
        {
            request["path"] = path.Split('?', '#')[0];
        }

        if (request.Count > 0)
        {
            envelope["request"] = request;
        }

        JsonObject labels = [];
        if (spec["labels"] is JsonObject given)
        {
            foreach ((string key, JsonNode? value) in given)
            {
                labels[key] = value?.ToString();
            }
        }

        if (Text(spec, "userAgent") is string agent)
        {
            labels["userAgent"] = agent;
        }

        if (Text(spec, "route") is string route)
        {
            labels["route"] = route;
        }

        if (labels.Count > 0)
        {
            envelope["labels"] = labels;
        }

        if (spec["attributes"] is JsonObject attributes && attributes.Count > 0)
        {
            envelope["attributes"] = attributes.DeepClone();
        }

        if (spec["change"] is JsonObject change && change.Count > 0)
        {
            // Before and after values of settings and credentials never leave the process.
            JsonObject kept = Text(spec, "eventType") == "role_membership_changed"
                ? (JsonObject)change.DeepClone()
                : change["field"] is JsonNode field ? new JsonObject { ["field"] = field.DeepClone() } : [];
            if (kept.Count > 0)
            {
                envelope["change"] = kept;
            }
        }

        return (JsonObject)Clean(envelope, string.Empty)!;
    }

    private static string? Text(JsonObject spec, string key) =>
        spec[key] is JsonValue value && value.TryGetValue(out string? text) ? text : null;

    private static string Truncate(string text, int limit)
    {
        System.Globalization.StringInfo info = new(text);
        return info.LengthInTextElements <= limit ? text : info.SubstringByTextElements(0, limit);
    }

    private static JsonNode? Clean(JsonNode? node, string key) => node switch
    {
        JsonValue value when value.TryGetValue(out string? text) =>
            Truncate(Control().Replace(text, " "), key switch { "eventOutcomeReason" => 1024, "path" => 2048, _ => 256 }),
        JsonObject obj => CleanObject(obj),
        JsonArray array => new JsonArray([.. array.Take(64).Select(item => Clean(item, string.Empty))]),
        _ => node?.DeepClone(),
    };

    private static JsonObject CleanObject(JsonObject obj)
    {
        JsonObject output = [];
        foreach ((string name, JsonNode? item) in obj)
        {
            if (IsSecret(name) || item is null)
            {
                continue;
            }

            JsonNode? cleaned = Clean(item, name);
            if (cleaned is JsonObject { Count: 0 })
            {
                continue;
            }

            output[Truncate(Control().Replace(name, " "), 128)] = cleaned;
        }

        return output;
    }

    [GeneratedRegex("[\\u0000-\\u001f\\u007f\\u2028\\u2029]+")]
    private static partial Regex Control();

    [GeneratedRegex("[^a-z0-9]")]
    private static partial Regex NonAlphanumeric();
}

/// <summary>Posts events to a Bower collector in the background. Never throws into a request.</summary>
public sealed class BowerSender(HttpClient http, ILogger<BowerSender> logger)
{
    public void Send(JsonObject envelope) => _ = SendAsync(envelope);

    private async Task SendAsync(JsonObject envelope)
    {
        try
        {
            using HttpResponseMessage response = await http.PostAsJsonAsync("v1/events", envelope);
            if ((int)response.StatusCode >= 400)
            {
                logger.LogWarning("Bower event {EventType} not accepted: {Status}", envelope["eventType"]?.ToString(), (int)response.StatusCode);
            }
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning("Bower collector unreachable for {EventType}", envelope["eventType"]?.ToString());
        }
    }
}
