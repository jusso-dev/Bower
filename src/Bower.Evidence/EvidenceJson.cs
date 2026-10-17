using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Bower.Integrity;

namespace Bower.Evidence;

/// <summary>Log Analytics query request body.</summary>
internal sealed record LogAnalyticsQueryRequest(
    [property: JsonPropertyName("query")] string Query,
    [property: JsonPropertyName("timespan")] string Timespan);

/// <summary>
/// Source-generated metadata for evidence artefacts with <see cref="JsonSerializer"/>
/// default options (the former reflection calls), so signed canonical bytes are unchanged.
/// </summary>
[JsonSerializable(typeof(EvidenceBundle))]
[JsonSerializable(typeof(SignedEvidence))]
[JsonSerializable(typeof(DetachedSignature))]
[JsonSerializable(typeof(LogAnalyticsQueryRequest))]
internal sealed partial class EvidenceJsonContext : JsonSerializerContext;

/// <summary>Collector responses, read with Web defaults as ReadFromJsonAsync did.</summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(JsonObject))]
internal sealed partial class EvidenceWebJsonContext : JsonSerializerContext;
