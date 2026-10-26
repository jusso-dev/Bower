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

    /// <summary>
    /// <see cref="ProbeProfiles.Generic"/> (default) or an opt-in <c>parser:PACK:INDEX</c>
    /// profile with a trusted fixture (<see cref="ParserProbeFixtures"/>).
    /// </summary>
    public string ProbeProfile { get; init; } = ProbeProfiles.Generic;
}

public interface ICanarySender
{
    Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken);
}

public sealed class HttpCanarySender(HttpClient http) : ICanarySender, IParserProbeSender
{
    public Task<(int Status, JsonObject? Body)> SendAsync(Uri collector, string? token, string json, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Post, new Uri(collector, "v1/events"), token, json, cancellationToken);

    public Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, new Uri(collector, "v1/status"), token, null, cancellationToken);

    public Task<(int Status, JsonObject? Body)> SendRecordAsync(
        Uri collector, string? token, string packId, int parserIndex, string json, CancellationToken cancellationToken) =>
        SendAsync(
            HttpMethod.Post,
            new Uri(collector, $"v1/packs/{Uri.EscapeDataString(packId)}/parsers/{parserIndex.ToString(CultureInfo.InvariantCulture)}/events"),
            token,
            json,
            cancellationToken);

    private async Task<(int Status, JsonObject? Body)> SendAsync(
        HttpMethod method, Uri uri, string? token, string? json, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(method, uri);
        if (json is not null)
        {
            request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        }

        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        JsonObject? body = null;
        try
        {
            body = await response.Content.ReadFromJsonAsync(EvidenceWebJsonContext.Default.JsonObject, cancellationToken);
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
    TimeProvider? clock = null,
    IParserProbeSender? parserSender = null)
{
    // Microsoft.OperationalInsights api-version; keep equal to Bower.Dcr.AzureApiVersions.LogAnalytics.
    private const string TableApiVersion = "2025-07-01";
    private readonly TimeProvider clock = clock ?? TimeProvider.System;

    public async Task<EvidenceBundle> RunAsync(EvidenceOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!TableName().IsMatch(options.Table))
        {
            throw new ArgumentException("Table must be a Log Analytics table name such as BowerSecurity_CL.");
        }

        if (!string.Equals(options.ProbeProfile ?? ProbeProfiles.Generic, ProbeProfiles.Generic, StringComparison.Ordinal))
        {
            return await RunParserProbeAsync(options, ProbeProfiles.ResolveParser(options.ProbeProfile!), cancellationToken);
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
            JsonSerializer.Serialize(canary, BowerJson.Envelope),
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

    /// <summary>
    /// Opt-in parser probe: reads the collector's loaded pack and policy configuration, posts
    /// the trusted fixture through the signed parser's HTTP intake (normal authentication,
    /// privacy, policy, queue and delivery), then queries the destination for exactly that
    /// event identity. Collector acceptance alone never verifies.
    /// </summary>
    private async Task<EvidenceBundle> RunParserProbeAsync(
        EvidenceOptions options, ParserProbeFixture fixture, CancellationToken cancellationToken)
    {
        IParserProbeSender probe = parserSender ?? sender as IParserProbeSender
            ?? throw new InvalidOperationException("The collector sender does not support parser probes.");
        bool simulated = options.WorkspaceId is null || query is null;
        DateTimeOffset sentAt = clock.GetUtcNow();
        string eventId = $"bower-probe-{Guid.CreateVersion7():N}";

        string? outcome = null;
        string? collectorPolicyHash = null;
        string? packVersion = null;
        string? packHash = null;
        string? parserStatus = null;
        (int statusCode, JsonObject? status) = await probe.GetStatusAsync(options.CollectorUrl, options.IngestToken, cancellationToken);
        if (statusCode is 401 or 403)
        {
            outcome = ProbeOutcomes.CollectorPermissionDenied;
        }
        else if (statusCode != 200 || status?["policy"] is not JsonObject policy)
        {
            outcome = ProbeOutcomes.CollectorStatusUnreadable;
        }
        else
        {
            collectorPolicyHash = ProbeOutcomes.Text(policy["hash"]);
            JsonObject? pack = (policy["packs"] as JsonArray)?.OfType<JsonObject>()
                .FirstOrDefault(item => ProbeOutcomes.Text(item["id"]) == fixture.PackId);
            packVersion = ProbeOutcomes.Text(pack?["version"]);
            packHash = ProbeOutcomes.Text(pack?["packHash"]);
            parserStatus = pack?["parserStatuses"] is JsonArray statuses && fixture.ParserIndex < statuses.Count
                ? ProbeOutcomes.Text(statuses[fixture.ParserIndex])
                : "absent";
            if (parserStatus != "active-local-json")
            {
                outcome = ProbeOutcomes.ParserInactive;
            }
        }

        int collectorStatus = 0;
        JsonObject? body = null;
        if (outcome is null)
        {
            (collectorStatus, body) = await probe.SendRecordAsync(
                options.CollectorUrl, options.IngestToken, fixture.PackId, fixture.ParserIndex,
                fixture.Render(eventId, sentAt), cancellationToken);
            outcome = ProbeOutcomes.Classify(collectorStatus, body, eventId);
        }

        JsonObject? eventPolicy = body?["policy"] as JsonObject;
        CanaryRecord canaryRecord = new(
            eventId,
            sentAt,
            options.CollectorUrl.Host,
            collectorStatus,
            ProbeOutcomes.Text(body?["decision"]),
            ProbeOutcomes.Text(eventPolicy?["policyId"]));

        List<string> limitations =
        [
            $"Proves delivery for this probe through {fixture.Path} at this time; it does not prove the untested paths listed in the probe record or that every event was delivered.",
            "Bundles hold metadata only: no event payloads or credentials."
        ];

        ArrivalRecord arrival = new(false, options.WorkspaceId, options.Table, null, 0, null, null, null, null, null);
        DateTimeOffset? queriedAt = null;
        if (simulated)
        {
            limitations.Add("SIMULATED: no Sentinel query was run, so this bundle is not delivery evidence.");
            outcome ??= ProbeOutcomes.AcceptedNotVerified;
        }

        if (outcome is null)
        {
            (arrival, outcome, queriedAt) = await PollProbeAsync(
                options, eventId, fixture.ExpectedEventType, ProbeOutcomes.Text(eventPolicy?["policyHash"]), sentAt, cancellationToken);
        }
        else
        {
            arrival = arrival with { QueryError = outcome };
        }

        RetentionRecord? retention = await ReadRetentionAsync(options, cancellationToken);
        long? errors = simulated ? null : await ReadIngestionErrorsAsync(options, cancellationToken);
        string mode = simulated ? EvidenceModes.Simulated : outcome == ProbeOutcomes.Verified ? EvidenceModes.Verified : EvidenceModes.Failed;
        ProbeRecord record = new(
            fixture.Profile,
            $"POST {fixture.Path} -> parser -> privacy -> policy -> queue -> output -> {options.Table}",
            fixture.Id,
            fixture.PackId,
            fixture.ParserIndex,
            packVersion,
            packHash,
            parserStatus,
            collectorPolicyHash,
            eventId,
            fixture.ExpectedEventType,
            ProbeOutcomes.Text(eventPolicy?["policyId"]),
            ProbeOutcomes.Text(eventPolicy?["policyVersion"]),
            ProbeOutcomes.Text(eventPolicy?["policyHash"]),
            options.WorkspaceId,
            options.Table,
            queriedAt,
            outcome,
            ProbeOutcomes.UntestedPaths);
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
            limitations,
            record);
    }

    private async Task<(ArrivalRecord Arrival, string Outcome, DateTimeOffset? QueriedAt)> PollProbeAsync(
        EvidenceOptions options, string eventId, string expectedEventType, string? expectedPolicyHash, DateTimeOffset sentAt,
        CancellationToken cancellationToken)
    {
        string kql =
            $"{options.Table}\n| where TimeGenerated > ago(1d)\n| where EventId == \"{eventId}\"\n" +
            "| project TimeGenerated, IngestionTime = ingestion_time(), EventId, EventType, PolicyHash\n| take 1";
        ArrivalRecord missing = new(false, options.WorkspaceId, options.Table, kql, 0, null, null, null, null, null);
        DateTimeOffset deadline = clock.GetUtcNow() + options.Timeout;
        int attempts = 0;
        bool answered = false;
        while (true)
        {
            attempts++;
            DateTimeOffset queriedAt = clock.GetUtcNow();
            QueryRows result;
            try
            {
                result = await query!.QueryAsync(options.WorkspaceId!, kql, TimeSpan.FromDays(1), cancellationToken);
            }
            catch (Exception exception) when (exception is TaskCanceledException or TimeoutException && !cancellationToken.IsCancellationRequested)
            {
                result = new QueryRows([], ProbeOutcomes.QueryTimeoutCode);
            }
            catch (HttpRequestException)
            {
                result = new QueryRows([], ProbeOutcomes.QueryTransportCode);
            }

            string? error = result.Error;
            if (error is not null && ProbeOutcomes.IsPermissionError(error))
            {
                return (missing with { Attempts = attempts, QueryError = error }, ProbeOutcomes.DestinationPermissionDenied, queriedAt);
            }

            if (error is null && result.Rows.Count > 0 && result.Rows[0] is { } row)
            {
                // Only the exact probe identity, with the event type the parser should map, verifies.
                if (ProbeOutcomes.Text(row.GetValueOrDefault("EventId")) != eventId
                    || ProbeOutcomes.Text(row.GetValueOrDefault("EventType")) != expectedEventType)
                {
                    return (missing with { Attempts = attempts, QueryError = ProbeOutcomes.DestinationWrongEvent },
                        ProbeOutcomes.DestinationWrongEvent, queriedAt);
                }

                // The row must carry the policy hash the collector reported for this probe;
                // otherwise the evidence would not identify the configuration it tested.
                string? rowPolicyHash = ProbeOutcomes.Text(row.GetValueOrDefault("PolicyHash"));
                if (rowPolicyHash != expectedPolicyHash)
                {
                    return (missing with { Attempts = attempts, RowPolicyHash = rowPolicyHash, QueryError = ProbeOutcomes.ConfigurationMismatch },
                        ProbeOutcomes.ConfigurationMismatch, queriedAt);
                }

                DateTimeOffset? generated = ReadTime(row, "TimeGenerated");
                DateTimeOffset? ingested = ReadTime(row, "IngestionTime");
                return (new ArrivalRecord(
                    true, options.WorkspaceId, options.Table, kql, attempts, generated, ingested,
                    ingested is null ? null : Math.Round((ingested.Value - sentAt).TotalSeconds, 1),
                    rowPolicyHash,
                    null), ProbeOutcomes.Verified, queriedAt);
            }

            answered |= error is null;
            if (clock.GetUtcNow() + options.PollInterval > deadline)
            {
                // Any answered query means the destination was reachable and the row absent;
                // timeout or failure only when no query was ever answered.
                string outcome = answered || error is null
                    ? ProbeOutcomes.DestinationRowMissing
                    : ProbeOutcomes.IsTimeoutError(error) ? ProbeOutcomes.DestinationTimeout : ProbeOutcomes.DestinationQueryFailed;
                return (missing with { Attempts = attempts, QueryError = outcome == ProbeOutcomes.DestinationRowMissing ? outcome : error },
                    outcome, queriedAt);
            }

            await Task.Delay(options.PollInterval, clock, cancellationToken);
        }
    }

    public static SignedEvidence Sign(EvidenceBundle bundle, string? privateKeyPem)
    {
        JsonObject node = (JsonObject)JsonSerializer.SerializeToNode(bundle, EvidenceJsonContext.Default.EvidenceBundle)!;
        DetachedSignature? signature = privateKeyPem is null ? null : DetachedSigner.Sign(CanonicalJson.Bytes(node), privateKeyPem);
        return new SignedEvidence(node, signature);
    }

    /// <summary>
    /// Reads a signed bundle file. Anything that is not a JSON object with an object
    /// <c>bundle</c> and an optional signature fails with "Evidence bundle is unreadable."
    /// </summary>
    public static SignedEvidence Parse(string json)
    {
        try
        {
            SignedEvidence? evidence = JsonSerializer.Deserialize(json, EvidenceJsonContext.Default.SignedEvidence);
            if (evidence?.Bundle is not null)
            {
                return evidence;
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or NotSupportedException)
        {
        }

        throw new InvalidDataException("Evidence bundle is unreadable.");
    }

    /// <summary>The bundle's <c>mode</c>, or "unknown" when it is absent or not a string.</summary>
    public static string ModeOf(SignedEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return evidence.Bundle["mode"] is JsonValue value && value.TryGetValue(out string? mode) ? mode : "unknown";
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
