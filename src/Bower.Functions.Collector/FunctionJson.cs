using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Functions.Collector;

// Response bodies. Ingest and error shapes match the HTTP collector (camelCase, same field
// order) with one additive field, `delivered`, because this host has no durable queue.

internal sealed record ErrorResponse(string Error);

internal sealed record HealthResponse(string Status);

internal sealed record IngestResponse(
    string? EventId,
    string Decision,
    bool Queued,
    bool Duplicate,
    IReadOnlyList<string> Reasons,
    IngestPolicyResponse? Policy,
    bool Delivered);

internal sealed record IngestPolicyResponse(string PolicyId, string PolicyVersion, string PolicyHash, int Score);

internal sealed record StatusResponse(
    string Status,
    string Mode,
    StatusPolicyResponse Policy,
    StatusDeliveryResponse Delivery,
    int ProducerScopes);

internal sealed record StatusPolicyResponse(
    string Hash,
    IReadOnlyList<StatusPolicyItem> Policies,
    IReadOnlyList<StatusPackItem> Packs,
    string? PrivacyProfile);

internal sealed record StatusPolicyItem(string Id, string Version);

internal sealed record StatusPackItem(string Id, string Version, string PackHash);

internal sealed record StatusDeliveryResponse(
    string Output,
    string StreamName,
    string Credential,
    bool DurableQueue,
    bool Ledger);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(IngestResponse))]
[JsonSerializable(typeof(StatusResponse))]
internal sealed partial class FunctionJsonContext : JsonSerializerContext;
