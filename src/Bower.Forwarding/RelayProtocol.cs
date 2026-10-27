using System.Text.Json.Serialization;

namespace Bower.Forwarding;

/// <summary>
/// Wire contract between a downstream collector and a relay (issue #110). The downstream
/// posts already redacted, policy-decided envelopes exactly as its queue stores them; the
/// relay answers only after each event is committed to its own durable queue.
/// </summary>
public static class RelayProtocol
{
    public const int SchemaVersion = 1;

    /// <summary>Batch intake, relative to BOWER_RELAY_URL.</summary>
    public const string BatchPath = "v1/relay/batches";

    /// <summary>Management tunnel (HTTP/1.1 Upgrade), relative to BOWER_RELAY_URL.</summary>
    public const string TunnelPath = "v1/relay/management-tunnel";

    /// <summary>Upgrade token for the management tunnel.</summary>
    public const string TunnelUpgrade = "bower-management-tunnel/1";

    public const int MaximumBatchEvents = 500;

    /// <summary>Relay request body limit.</summary>
    public const int MaximumRequestBytes = 8 * 1024 * 1024;

    /// <summary>Downstream batches stop adding events at this many payload bytes.</summary>
    public const int TargetBatchPayloadBytes = 4 * 1024 * 1024;

    /// <summary>One stored payload; the collector's ingest limit.</summary>
    public const int MaximumPayloadBytes = 1024 * 1024;

    /// <summary>Relay response body limit.</summary>
    public const int MaximumResponseBytes = 1024 * 1024;

    public const int MaximumIdentifierLength = 128;

    /// <summary>Ids that may appear in acknowledgements and status: printable, no separators.</summary>
    public static bool IsValidIdentifier(string? value) =>
        !string.IsNullOrEmpty(value)
        && value.Length <= MaximumIdentifierLength
        && value.All(character => character is > ' ' and < '\u007f');

    /// <summary>Reject codes are short lowercase tokens so they are safe to persist.</summary>
    public static bool IsValidCode(string? value) =>
        !string.IsNullOrEmpty(value)
        && value.Length <= 64
        && value.All(character => character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');
}

/// <summary>Per-event outcome on the relay.</summary>
public static class RelayEventStatuses
{
    /// <summary>Committed to the relay queue by this request.</summary>
    public const string Accepted = "accepted";

    /// <summary>Already in the relay queue (an earlier attempt committed it).</summary>
    public const string Duplicate = "duplicate";

    /// <summary>Refused for good; the downstream dead-letters it with the code.</summary>
    public const string Rejected = "rejected";
}

/// <summary>Relay reject codes (closed set).</summary>
public static class RelayRejectCodes
{
    public const string PayloadInvalid = "payload-invalid";
    public const string PayloadTooLarge = "payload-too-large";
    public const string EventIdMismatch = "event-id-mismatch";
    public const string CollectorMismatch = "collector-mismatch";
    public const string FingerprintMismatch = "fingerprint-mismatch";
    public const string PolicyDecisionMissing = "policy-decision-missing";
    public const string IdentityConflict = "event-identity-conflict";
}

public sealed record RelayBatchResponse(
    int SchemaVersion,
    string RelayId,
    RelayLedgerHead Ledger,
    IReadOnlyList<RelayEventResult> Results);

/// <summary>The relay's queue ledger head after the batch: it commits to every event accepted.</summary>
public sealed record RelayLedgerHead(long Sequence, string Hash);

public sealed record RelayEventResult(string EventId, string Status)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Code { get; init; }
}

[JsonSourceGenerationOptions(System.Text.Json.JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(RelayBatchResponse))]
public sealed partial class RelayJsonContext : JsonSerializerContext;
