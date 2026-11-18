using System.Globalization;
using System.Text.Json;

namespace Bower.AppHost;

/// <summary>
/// The synthetic authentication failure the harness sends (the same shape as
/// <c>bower test emit</c>). Accepted by <c>policies/default</c> and allowed by
/// <see cref="ProducerScopesJson"/>; documentation-range IP, no personal data.
/// </summary>
internal static class CanaryEvent
{
    public const string ApplicationName = "BowerAspireCanary";
    public const string Environment = "development";
    public const string Instance = "aspire";
    public const string SourceIp = "192.0.2.1";

    /// <summary>
    /// Exact producer scopes for the canary identity: the collectors' shared token
    /// (<c>default</c>) and the Functions development authenticator (<c>development</c>).
    /// </summary>
    public static string ProducerScopesJson { get; } = JsonSerializer.Serialize(
        new[] { "default", "development" }.Select(producer => new Dictionary<string, object>
        {
            ["producer"] = producer,
            ["application"] = new Dictionary<string, string>
            {
                ["name"] = ApplicationName,
                ["environment"] = Environment,
                ["instance"] = Instance
            },
            ["source"] = new Dictionary<string, string> { ["ipAddress"] = SourceIp }
        }).ToArray(),
        CanaryJsonContext.Default.DictionaryStringObjectArray);

    /// <summary>A new canary envelope and its event id.</summary>
    public static (string EventId, string Json) Create(TimeProvider? clock = null)
    {
        string eventId = Guid.CreateVersion7().ToString();
        string now = (clock ?? TimeProvider.System).GetUtcNow().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        string json = $$$"""
            {"schemaVersion":"1.0.0","eventId":"{{{eventId}}}","eventOriginalId":"aspire-canary-{{{eventId}}}",
            "timeGenerated":"{{{now}}}","eventCategory":"authentication","eventType":"authentication_failure",
            "eventAction":"authentication.attempt","eventResult":"failure","eventOutcomeReason":"SyntheticInvalidPassword",
            "application":{"name":"{{{ApplicationName}}}","environment":"{{{Environment}}}","instance":"{{{Instance}}}"},
            "actor":{"username":"synthetic-canary","type":"system"},"source":{"ipAddress":"{{{SourceIp}}}"},
            "request":{"correlationId":"aspire-canary-{{{eventId}}}"},"labels":{"evidenceType":"test"}}
            """.ReplaceLineEndings(string.Empty);
        return (eventId, json);
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, object>[]))]
[System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class CanaryJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
