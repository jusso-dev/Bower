using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Contracts;
using Bower.Integrity;

namespace Bower.Evidence;

public sealed record EvidenceOptions
{
    public required Uri CollectorUrl { get; init; }

    public string? IngestToken { get; init; }

    /// <summary>Log Analytics workspace (customer) id. Null runs in simulated mode.</summary>
    public string? WorkspaceId { get; init; }

    /// <summary>Workspace ARM resource id, for retention and region readout.</summary>
    public string? WorkspaceResourceId { get; init; }

    public string Table { get; init; } = "BowerSecurity_CL";

    public string ApplicationName { get; init; } = "BowerEvidence";

    public string Environment { get; init; } = "production";

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(15);

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(30);
}

public interface ICanarySender
{
    Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken);
}

public sealed class HttpCanarySender(HttpClient http) : ICanarySender
{
    public async Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(collector, "v1/events"))
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        JsonObject? body = null;
        try
        {
            body = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
        }
        catch (JsonException)
        {
        }

        return ((int)response.StatusCode, body);
    }
}

/// <summary>
/// Proves delivery end to end: emits a synthetic canary through the real collector
/// (redaction, policy, queue, output), then finds it in Sentinel with a KQL query
/// under a separate read-only identity. Never claims delivery without that query.
/// </summary>
public sealed partial class EvidenceRunner(
    ICanarySender sender,
    ILogAnalyticsQuery? query,
    IArmReader? arm,
    TimeProvider? clock = null)
{
    private const string TableApiVersion = "2025-07-01";
    private readonly TimeProvider clock = clock ?? TimeProvider.System;

    public async Task<EvidenceBundle> RunAsync(EvidenceOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!TableName().IsMatch(options.Table))
        {
            throw new ArgumentException("Table must be a Log Analytics table name such as BowerSecurity_CL.");
        }

        bool simulated = options.WorkspaceId is null || query is null;
        DateTimeOffset sentAt = clock.GetUtcNow();
        string eventId = $"bower-canary-{Guid.CreateVersion7():N}";
        SecurityEventEnvelope canary = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            EventOriginalId = eventId,
            TimeGenerated = sentAt,
            EventCategory = SecurityEventCategories.CollectorHealth,
            EventType = SecurityEventTypes.CollectorCanary,
            EventAction = "evidence.canary",
            EventResult = EventResult.Success,
            EventSeverity = EventSeverity.Informational,
            EventOutcomeReason = "Synthetic delivery-proof canary",
            Application = new ApplicationContext { Name = options.ApplicationName, Environment = options.Environment },
            Actor = new ActorContext { Username = "bower.evidence", Type = ActorType.System },
            Request = new RequestContext { CorrelationId = eventId },
            Labels = new Dictionary<string, string>(StringComparer.Ordinal) { ["evidenceType"] = "canary" }
        };

        (int status, JsonObject? body) = await sender.SendAsync(
            options.CollectorUrl,
            options.IngestToken,
            JsonSerializer.Serialize(canary, BowerJson.Options),
            cancellationToken);
        CanaryRecord canaryRecord = new(
            eventId,
            sentAt,
            options.CollectorUrl.Host,
            status,
            body?["decision"]?.GetValue<string>(),
            body?["policy"]?["policyId"]?.GetValue<string>());
        bool collectorAccepted = status is 200 or 202;

        List<string> limitations =
        [
            "Proves delivery for this canary at this time; it does not prove every event was delivered.",
            "Bundles hold metadata only: no event payloads or credentials."
        ];

        ArrivalRecord arrival = new(false, options.WorkspaceId, options.Table, null, 0, null, null, null, null, null);
        if (simulated)
        {
            limitations.Add("SIMULATED: no Sentinel query was run, so this bundle is not delivery evidence.");
        }
        else if (!collectorAccepted)
        {
            arrival = arrival with { QueryError = "collector-rejected-canary" };
        }
        else
        {
            arrival = await PollAsync(options, eventId, sentAt, cancellationToken);
        }

        RetentionRecord? retention = await ReadRetentionAsync(options, cancellationToken);
        long? errors = simulated ? null : await ReadIngestionErrorsAsync(options, cancellationToken);
        string mode = simulated ? EvidenceModes.Simulated : arrival.Found ? EvidenceModes.Verified : EvidenceModes.Failed;
        return new EvidenceBundle(
            EvidenceBundle.CurrentSchema,
            mode,
            clock.GetUtcNow(),
            "bower",
            canaryRecord,
            arrival,
            retention,
            errors,
            ControlMapping.Map(mode, arrival, retention),
            limitations);
    }

    public static SignedEvidence Sign(EvidenceBundle bundle, string? privateKeyPem)
    {
        JsonObject node = (JsonObject)JsonSerializer.SerializeToNode(bundle)!;
        DetachedSignature? signature = privateKeyPem is null ? null : DetachedSigner.Sign(CanonicalJson.Bytes(node), privateKeyPem);
        return new SignedEvidence(node, signature);
    }

    public static bool Verify(SignedEvidence evidence, IEnumerable<string> trustedPublicKeyPems) =>
        evidence.Signature is not null
        && DetachedSigner.Verify(CanonicalJson.Bytes(evidence.Bundle), evidence.Signature, trustedPublicKeyPems);

    private async Task<ArrivalRecord> PollAsync(EvidenceOptions options, string eventId, DateTimeOffset sentAt, CancellationToken cancellationToken)
    {
        string kql =
            $"{options.Table}\n| where TimeGenerated > ago(1d)\n| where EventId == \"{eventId}\"\n" +
            "| project TimeGenerated, IngestionTime = ingestion_time(), EventId, PolicyHash\n| take 1";
        DateTimeOffset deadline = clock.GetUtcNow() + options.Timeout;
        int attempts = 0;
        string? lastError = null;
        while (true)
        {
            attempts++;
            QueryRows result = await query!.QueryAsync(options.WorkspaceId!, kql, TimeSpan.FromDays(1), cancellationToken);
            lastError = result.Error;
            if (result.Rows.Count > 0 && result.Rows[0] is { } row)
            {
                DateTimeOffset? generated = ReadTime(row, "TimeGenerated");
                DateTimeOffset? ingested = ReadTime(row, "IngestionTime");
                return new ArrivalRecord(
                    true, options.WorkspaceId, options.Table, kql, attempts, generated, ingested,
                    ingested is null ? null : Math.Round((ingested.Value - sentAt).TotalSeconds, 1),
                    row.TryGetValue("PolicyHash", out JsonNode? hash) ? hash?.GetValue<string>() : null,
                    null);
            }

            if (clock.GetUtcNow() + options.PollInterval > deadline)
            {
                return new ArrivalRecord(false, options.WorkspaceId, options.Table, kql, attempts, null, null, null, null, lastError ?? "not-found-before-timeout");
            }

            await Task.Delay(options.PollInterval, clock, cancellationToken);
        }
    }

    private async Task<RetentionRecord?> ReadRetentionAsync(EvidenceOptions options, CancellationToken cancellationToken)
    {
        if (arm is null || string.IsNullOrWhiteSpace(options.WorkspaceResourceId))
        {
            return null;
        }

        JsonObject? workspace = await arm.GetAsync(options.WorkspaceResourceId, TableApiVersion, cancellationToken);
        JsonObject? table = await arm.GetAsync($"{options.WorkspaceResourceId}/tables/{options.Table}", TableApiVersion, cancellationToken);
        JsonObject? properties = table?["properties"] as JsonObject;
        return new RetentionRecord(
            properties?["plan"]?.GetValue<string>(),
            ReadInt(properties, "retentionInDays"),
            ReadInt(properties, "totalRetentionInDays"),
            workspace?["location"]?.GetValue<string>());
    }

    private async Task<long?> ReadIngestionErrorsAsync(EvidenceOptions options, CancellationToken cancellationToken)
    {
        // DCRLogErrors only exists when DCR error logging is enabled; absence is not an error.
        QueryRows result = await query!.QueryAsync(
            options.WorkspaceId!,
            "DCRLogErrors | where TimeGenerated > ago(1h) | summarize Errors = count()",
            TimeSpan.FromHours(1),
            cancellationToken);
        return result.Error is null
            && result.Rows.Count > 0
            && result.Rows[0] is { } row
            && row.TryGetValue("Errors", out JsonNode? value)
            && value is JsonValue number
            && number.TryGetValue(out long count)
                ? count
                : null;
    }

    private static DateTimeOffset? ReadTime(IReadOnlyDictionary<string, JsonNode?> row, string column) =>
        row.TryGetValue(column, out JsonNode? value)
        && value is JsonValue text
        && text.TryGetValue(out string? raw)
        && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset parsed)
            ? parsed
            : null;

    private static int? ReadInt(JsonObject? properties, string name) =>
        properties?[name] is JsonValue value && value.TryGetValue(out int result) ? result : null;

    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex TableName();
}
