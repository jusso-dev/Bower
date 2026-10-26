using System.Globalization;
using System.Text.Json.Nodes;

namespace Bower.Evidence;

/// <summary>
/// Probe profiles for <c>bower evidence run --probe-profile</c>. <see cref="Generic"/> (the
/// default) posts the canary envelope to <c>/v1/events</c>. <c>parser:PACK:INDEX</c> posts
/// a trusted synthetic raw record through that signed pack parser's HTTP intake.
/// </summary>
public static class ProbeProfiles
{
    public const string Generic = "generic";

    public const string ParserPrefix = "parser:";

    /// <summary>
    /// The trusted fixture for a <c>parser:PACK:INDEX</c> profile. Only repo-owned fixtures
    /// can be probed: an unknown parser fails before anything is sent.
    /// </summary>
    public static ParserProbeFixture ResolveParser(string profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ParserProbeFixture? fixture = ParserProbeFixtures.All.SingleOrDefault(item =>
            string.Equals(item.Profile, profile, StringComparison.Ordinal));
        return fixture ?? throw new ArgumentException(
            $"--probe-profile must be {Generic} or one of: {string.Join(", ", ParserProbeFixtures.All.Select(item => item.Profile))}.");
    }
}

/// <summary>
/// A bounded synthetic raw record for one shipped parser. No real secrets, accounts or
/// production samples: a fixed probe username and a documentation (TEST-NET-1) address.
/// The record id is the unique probe event id, so the destination query matches exactly it.
/// </summary>
public sealed record ParserProbeFixture(
    string Id,
    string PackId,
    int ParserIndex,
    string ExpectedEventType,
    Func<string, DateTimeOffset, JsonObject> Build)
{
    public string Profile => $"{ProbeProfiles.ParserPrefix}{PackId}:{ParserIndex.ToString(CultureInfo.InvariantCulture)}";

    public string Path => $"/v1/packs/{PackId}/parsers/{ParserIndex.ToString(CultureInfo.InvariantCulture)}/events";

    /// <summary>The raw record JSON for <paramref name="eventId"/>; keep byte-identical with the Rust port.</summary>
    public string Render(string eventId, DateTimeOffset sentAt) =>
        Build(eventId, sentAt).ToJsonString();

    /// <summary>Timestamp text every parser runtime accepts: UTC, seven fractional digits.</summary>
    public static string Timestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
}

public static class ParserProbeFixtures
{
    public static readonly ParserProbeFixture LinuxSshGateway = new(
        "linux-ssh-gateway/sshd-json/authentication-failure@1",
        "linux-ssh-gateway",
        0,
        "authentication_failure",
        (eventId, sentAt) => new JsonObject
        {
            ["id"] = eventId,
            ["timestamp"] = ParserProbeFixture.Timestamp(sentAt),
            ["user"] = "bower-evidence-probe",
            ["source_ip"] = "192.0.2.10",
            ["result"] = "failure"
        });

    public static IReadOnlyList<ParserProbeFixture> All { get; } = [LinuxSshGateway];
}

/// <summary>Parser probe results. Only <see cref="Verified"/> is delivery evidence.</summary>
public static class ProbeOutcomes
{
    /// <summary>The exact probe row, with the expected event type, was returned by the destination query.</summary>
    public const string Verified = "verified";

    /// <summary>The collector accepted the probe but no destination query ran (simulated).</summary>
    public const string AcceptedNotVerified = "accepted-not-verified";

    /// <summary>The pack is not loaded or the parser has no active runtime.</summary>
    public const string ParserInactive = "parser-inactive";

    /// <summary>The parser refused the fixture (mapping, field type or bounds regression).</summary>
    public const string ParserRecordRejected = "parser-record-rejected";

    /// <summary>The parser source filter no longer selects the fixture.</summary>
    public const string ParserNotSelected = "parser-not-selected";

    /// <summary>The parser accepted the fixture but produced a different event identity.</summary>
    public const string ParserWrongEvent = "parser-wrong-event";

    /// <summary>The parser mapped the fixture but policy (or redaction) did not accept it.</summary>
    public const string PolicyNotSelected = "policy-not-selected";

    /// <summary>The collector refused the ingest token or producer scope (401/403).</summary>
    public const string CollectorPermissionDenied = "collector-permission-denied";

    /// <summary>Collector <c>/v1/status</c> could not be read, so the tested configuration is unknown.</summary>
    public const string CollectorStatusUnreadable = "collector-status-unreadable";

    /// <summary>The collector refused the probe for another reason (capacity, conflict, rate limit).</summary>
    public const string CollectorRejected = "collector-rejected";

    /// <summary>The verifier identity may not query the destination.</summary>
    public const string DestinationPermissionDenied = "destination-permission-denied";

    /// <summary>Every query answered, and none returned the probe row before the deadline.</summary>
    public const string DestinationRowMissing = "destination-row-missing";

    /// <summary>A row was returned but it is not the exact probe event.</summary>
    public const string DestinationWrongEvent = "destination-wrong-event";

    /// <summary>The destination query timed out until the deadline.</summary>
    public const string DestinationTimeout = "destination-timeout";

    /// <summary>The destination query failed with another error until the deadline.</summary>
    public const string DestinationQueryFailed = "destination-query-failed";

    /// <summary>Query error code when the query call itself timed out.</summary>
    public const string QueryTimeoutCode = "query-timeout";

    /// <summary>Query error code when the query call failed in transport.</summary>
    public const string QueryTransportCode = "query-transport-failed";

    /// <summary>Paths a parser probe never exercises; every parser bundle lists them.</summary>
    public static IReadOnlyList<string> UntestedPaths { get; } =
    [
        "Generic event intake (POST /v1/events).",
        "Other packs and parsers loaded by the collector.",
        "Other event types, selection branches and privacy rules of this pack.",
        "Agents, forwarders and log readers upstream of collector HTTP intake.",
        "Delivery of any event other than this probe."
    ];

    /// <summary>Log Analytics error codes that mean the verifier identity lacks access.</summary>
    public static bool IsPermissionError(string code) =>
        code is "http-401" or "http-403"
        || code.Contains("InsufficientAccess", StringComparison.OrdinalIgnoreCase)
        || code.Contains("Authorization", StringComparison.OrdinalIgnoreCase)
        || code.Contains("Authentication", StringComparison.OrdinalIgnoreCase)
        || code.Contains("Forbidden", StringComparison.OrdinalIgnoreCase)
        || code.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase);

    /// <summary>Query error codes that mean the destination did not answer in time.</summary>
    public static bool IsTimeoutError(string code) =>
        code is QueryTimeoutCode or "http-408" or "http-504"
        || code.Contains("Timeout", StringComparison.OrdinalIgnoreCase);

    /// <summary>Classifies a collector parser intake response. Null means accepted.</summary>
    public static string? Classify(int status, JsonObject? body, string expectedEventId)
    {
        if (status is 200 or 202)
        {
            return string.Equals(Text(body?["eventId"]), expectedEventId, StringComparison.Ordinal) ? null : ParserWrongEvent;
        }

        string? error = Text(body?["error"]);
        return status switch
        {
            401 or 403 => CollectorPermissionDenied,
            404 => ParserInactive,
            422 when error == "pack-record-not-selected" => ParserNotSelected,
            400 or 422 when body?["decision"] is not null => PolicyNotSelected,
            400 or 413 or 415 => ParserRecordRejected,
            _ => CollectorRejected
        };
    }

    internal static string? Text(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out string? text) ? text : null;
}

/// <summary>Collector calls a parser probe makes besides the generic canary post.</summary>
public interface IParserProbeSender
{
    /// <summary>GET <c>/v1/status</c> (bearer authenticated): pack versions, hashes and parser states.</summary>
    Task<(int Status, JsonObject? Body)> GetStatusAsync(Uri collector, string? token, CancellationToken cancellationToken);

    /// <summary>POST one raw record to <c>/v1/packs/PACK/parsers/INDEX/events</c>.</summary>
    Task<(int Status, JsonObject? Body)> SendRecordAsync(
        Uri collector, string? token, string packId, int parserIndex, string json, CancellationToken cancellationToken);
}
