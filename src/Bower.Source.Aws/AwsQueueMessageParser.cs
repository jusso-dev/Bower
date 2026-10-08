using System.Text;
using System.Text.Json;
using Bower.Contracts;

namespace Bower.Source.Aws;

public enum AwsQueueMessageKind
{
    /// <summary>Security events mapped from an EventBridge event.</summary>
    Events,

    /// <summary>S3 object notifications; the host fetches and reads the objects.</summary>
    ObjectReferences,

    /// <summary>Well-formed but not a supported security event. Default deny: acknowledge and drop.</summary>
    Unsupported
}

public sealed record AwsS3ObjectReference(string Bucket, string Key, long? Size, string? Region);

public sealed record AwsQueueMessage(
    AwsQueueMessageKind Kind,
    IReadOnlyList<SecurityEventEnvelope> Events,
    IReadOnlyList<AwsS3ObjectReference> Objects,
    string? Description)
{
    public static AwsQueueMessage Unsupported(string description) => new(AwsQueueMessageKind.Unsupported, [], [], description);
}

public sealed record AwsQueueOptions
{
    public required string SourceId { get; init; }

    public string? AccountId { get; init; }

    public string? Region { get; init; }

    public string Environment { get; init; } = "production";

    public string ApplicationName { get; init; } = "aws-security";

    /// <summary>SQS accepts messages up to 1 MiB.</summary>
    public int MaximumMessageBytes { get; init; } = 1_048_576;

    /// <summary>GuardDuty and Security Hub findings can be large; the envelope still keeps only mapped fields.</summary>
    public int MaximumRecordBytes { get; init; } = 262_144;

    public int MaximumFindingsPerMessage { get; init; } = 100;

    public bool IncludeRawRecord { get; init; }
}

/// <summary>
/// Parses SQS message bodies delivered by EventBridge rules (optionally through SNS) and S3
/// event notifications. Pure and bounded: no AWS calls, no logging of bodies.
/// </summary>
public sealed class AwsQueueMessageParser
{
    private const string GuardDutyFinding = "GuardDuty Finding";
    private const string SecurityHubImported = "Security Hub Findings - Imported";

    private static readonly HashSet<string> CloudTrailDetailTypes = new(StringComparer.Ordinal)
    {
        "AWS API Call via CloudTrail",
        "AWS Console Sign In via CloudTrail",
        "AWS Console Action via CloudTrail",
        "AWS Service Event via CloudTrail"
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 64
    };

    private readonly AwsQueueOptions options;
    private readonly AwsSecurityEventMapper cloudTrail;
    private readonly AwsSecurityEventMapper guardDuty;
    private readonly AwsSecurityEventMapper securityHub;

    public AwsQueueMessageParser(AwsQueueOptions options, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.MaximumMessageBytes is < 1_024 or > 4_194_304)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Maximum message size must be between 1 KiB and 4 MiB.");
        }

        this.options = options;
        cloudTrail = Mapper(AwsTelemetrySourceKind.CloudTrail, clock);
        guardDuty = Mapper(AwsTelemetrySourceKind.GuardDuty, clock);
        securityHub = Mapper(AwsTelemetrySourceKind.SecurityHub, clock);
    }

    public AwsQueueMessage Parse(string body, DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(body);
        int bytes = Encoding.UTF8.GetByteCount(body);
        if (bytes > options.MaximumMessageBytes)
        {
            throw new AwsTelemetryPayloadTooLargeException(options.SourceId, bytes, options.MaximumMessageBytes);
        }

        using JsonDocument document = ParseDocument(body);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new AwsTelemetryMalformedRecordException(options.SourceId, root.ValueKind);
        }

        // SNS fan-out wraps the original event as a JSON string in "Message".
        if (ReadString(root, "Type") == "Notification" && ReadString(root, "Message") is { } inner)
        {
            using JsonDocument unwrapped = ParseDocument(inner);
            if (unwrapped.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new AwsTelemetryMalformedRecordException(options.SourceId, unwrapped.RootElement.ValueKind);
            }

            return ParseEvent(unwrapped.RootElement, observedAt);
        }

        return ParseEvent(root, observedAt);
    }

    private AwsQueueMessage ParseEvent(JsonElement root, DateTimeOffset observedAt)
    {
        if (ReadString(root, "detail-type") is { } detailType
            && root.TryGetProperty("detail", out JsonElement detail))
        {
            return ParseEventBridge(detailType, detail, observedAt);
        }

        if (ReadString(root, "Event") == "s3:TestEvent")
        {
            return AwsQueueMessage.Unsupported("s3:TestEvent");
        }

        if (root.TryGetProperty("Records", out JsonElement records) && records.ValueKind == JsonValueKind.Array)
        {
            return ParseS3Notification(records);
        }

        return AwsQueueMessage.Unsupported("unrecognised message shape");
    }

    private AwsQueueMessage ParseEventBridge(string detailType, JsonElement detail, DateTimeOffset observedAt)
    {
        if (detailType == GuardDutyFinding)
        {
            return Events([guardDuty.MapRecord(detail, observedAt)]);
        }

        if (CloudTrailDetailTypes.Contains(detailType))
        {
            return Events([cloudTrail.MapRecord(detail, observedAt)]);
        }

        if (detailType == SecurityHubImported)
        {
            if (detail.ValueKind != JsonValueKind.Object
                || !detail.TryGetProperty("findings", out JsonElement findings)
                || findings.ValueKind != JsonValueKind.Array)
            {
                throw new AwsTelemetryMalformedRecordException(options.SourceId, detail.ValueKind);
            }

            int count = findings.GetArrayLength();
            if (count > options.MaximumFindingsPerMessage)
            {
                throw new AwsTelemetryBatchTooLargeException(options.SourceId, count, options.MaximumFindingsPerMessage);
            }

            return Events(findings.EnumerateArray().Select(finding => securityHub.MapRecord(finding, observedAt)).ToList());
        }

        // Only the detail type is reported: it is an AWS-defined label, not tenant data.
        return AwsQueueMessage.Unsupported($"detail-type {Clip(detailType, 64)}");
    }

    private AwsQueueMessage ParseS3Notification(JsonElement records)
    {
        List<AwsS3ObjectReference> objects = [];
        foreach (JsonElement record in records.EnumerateArray())
        {
            if (record.ValueKind != JsonValueKind.Object)
            {
                throw new AwsTelemetryMalformedRecordException(options.SourceId, record.ValueKind);
            }

            string? eventSource = ReadString(record, "eventSource");
            string? eventName = ReadString(record, "eventName");
            if (eventSource != "aws:s3" || eventName?.StartsWith("ObjectCreated:", StringComparison.Ordinal) != true)
            {
                continue;
            }

            if (!record.TryGetProperty("s3", out JsonElement s3)
                || ReadNested(s3, "bucket", "name") is not { } bucket
                || ReadNested(s3, "object", "key") is not { } encodedKey)
            {
                throw new AwsTelemetryMalformedRecordException(options.SourceId, JsonValueKind.Undefined);
            }

            long? size = s3.TryGetProperty("object", out JsonElement item)
                && item.TryGetProperty("size", out JsonElement sizeElement)
                && sizeElement.TryGetInt64(out long parsed)
                    ? parsed
                    : null;
            objects.Add(new AwsS3ObjectReference(bucket, DecodeKey(encodedKey), size, ReadString(record, "awsRegion")));
        }

        if (objects.Count > options.MaximumFindingsPerMessage)
        {
            throw new AwsTelemetryBatchTooLargeException(options.SourceId, objects.Count, options.MaximumFindingsPerMessage);
        }

        return objects.Count == 0
            ? AwsQueueMessage.Unsupported("no ObjectCreated records")
            : new AwsQueueMessage(AwsQueueMessageKind.ObjectReferences, [], objects, null);
    }

    /// <summary>S3 notifications URL-encode keys and use '+' for spaces.</summary>
    public static string DecodeKey(string key) => Uri.UnescapeDataString(key.Replace('+', ' '));

    private static AwsQueueMessage Events(IReadOnlyList<SecurityEventEnvelope> events) =>
        new(AwsQueueMessageKind.Events, events, [], null);

    private JsonDocument ParseDocument(string json)
    {
        try
        {
            return JsonDocument.Parse(json, DocumentOptions);
        }
        catch (JsonException)
        {
            throw new AwsTelemetryMalformedRecordException(options.SourceId, JsonValueKind.Undefined);
        }
    }

    private AwsSecurityEventMapper Mapper(AwsTelemetrySourceKind kind, TimeProvider? clock) =>
        new(
            new AwsSourceOptions
            {
                SourceId = options.SourceId,
                Kind = kind,
                AccountId = options.AccountId,
                Region = options.Region,
                Environment = options.Environment,
                ApplicationName = options.ApplicationName,
                MaximumRecordBytes = Math.Min(options.MaximumRecordBytes, 1_048_576),
                IncludeRawRecord = options.IncludeRawRecord
            },
            clock);

    private static string? ReadString(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(name, out JsonElement value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? ReadNested(JsonElement element, string parent, string child) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(parent, out JsonElement inner)
            ? ReadString(inner, child)
            : null;

    private static string Clip(string value, int max) => value.Length <= max ? value : value[..max];
}
