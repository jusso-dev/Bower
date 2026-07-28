using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Contracts;

namespace Bower.Source.Aws;

public sealed class AwsSecurityEventMapper
{
    private readonly AwsSourceOptions options;

    public AwsSecurityEventMapper(AwsSourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        this.options = options;
    }

    public IReadOnlyList<SecurityEventEnvelope> MapJsonDocument(
        string json,
        DateTimeOffset? observedAt = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        if (Encoding.UTF8.GetByteCount(json) > options.MaximumRecordBytes * options.MaximumBatchEvents)
        {
            throw new AwsTelemetryPayloadTooLargeException(
                options.SourceId,
                Encoding.UTF8.GetByteCount(json),
                options.MaximumRecordBytes * options.MaximumBatchEvents);
        }

        using JsonDocument document = JsonDocument.Parse(
            json,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });

        List<JsonElement> rawEvents = Expand(document.RootElement);
        if (rawEvents.Count > options.MaximumBatchEvents)
        {
            throw new AwsTelemetryBatchTooLargeException(
                options.SourceId,
                rawEvents.Count,
                options.MaximumBatchEvents);
        }

        DateTimeOffset observed = observedAt ?? DateTimeOffset.UtcNow;
        List<SecurityEventEnvelope> mapped = new(rawEvents.Count);
        foreach (JsonElement element in rawEvents)
        {
            int size = Encoding.UTF8.GetByteCount(element.GetRawText());
            if (size > options.MaximumRecordBytes)
            {
                throw new AwsTelemetryPayloadTooLargeException(
                    options.SourceId,
                    size,
                    options.MaximumRecordBytes);
            }

            mapped.Add(MapSingle(element, observed));
        }

        return mapped;
    }

    private List<JsonElement> Expand(JsonElement root)
    {
        return options.Kind switch
        {
            AwsTelemetrySourceKind.CloudTrail when root.ValueKind == JsonValueKind.Object &&
                                                   root.TryGetProperty("Records", out JsonElement records) &&
                                                   records.ValueKind == JsonValueKind.Array
                => records.EnumerateArray().ToList(),
            AwsTelemetrySourceKind.CloudWatchLogs when root.ValueKind == JsonValueKind.Object &&
                                                       root.TryGetProperty("logEvents", out JsonElement logEvents) &&
                                                       logEvents.ValueKind == JsonValueKind.Array
                => logEvents.EnumerateArray().ToList(),
            _ when root.ValueKind == JsonValueKind.Array
                => root.EnumerateArray().ToList(),
            _ => [root]
        };
    }

    private SecurityEventEnvelope MapSingle(JsonElement element, DateTimeOffset observedAt)
    {
        return options.Kind switch
        {
            AwsTelemetrySourceKind.CloudTrail => MapCloudTrail(element, observedAt),
            AwsTelemetrySourceKind.GuardDuty => MapGuardDuty(element, observedAt),
            AwsTelemetrySourceKind.SecurityHub => MapSecurityHub(element, observedAt),
            AwsTelemetrySourceKind.CloudWatchLogs => MapCloudWatch(element, observedAt),
            AwsTelemetrySourceKind.VpcFlowLogs => MapGenericNetwork(element, observedAt, "vpc_flow"),
            AwsTelemetrySourceKind.Route53Resolver => MapGenericNetwork(element, observedAt, "route53_resolver"),
            _ => throw new InvalidOperationException($"Unsupported AWS source kind '{options.Kind}'.")
        };
    }

    private SecurityEventEnvelope MapCloudTrail(JsonElement element, DateTimeOffset observedAt)
    {
        string eventName = ReadString(element, "eventName") ?? "Unknown";
        string eventSource = ReadString(element, "eventSource") ?? "unknown.amazonaws.com";
        string eventId = ReadString(element, "eventID")
            ?? ReadString(element, "eventId")
            ?? DeterministicId("cloudtrail", element.GetRawText());
        DateTimeOffset timeGenerated = ReadTime(element, "eventTime") ?? observedAt;
        string? accountId = ReadString(element, "recipientAccountId")
            ?? ReadNestedString(element, "userIdentity", "accountId")
            ?? options.AccountId;
        string? region = ReadString(element, "awsRegion") ?? options.Region;
        string? username = ReadNestedString(element, "userIdentity", "userName")
            ?? ReadNestedString(element, "userIdentity", "principalId");
        string? sourceIp = ReadString(element, "sourceIPAddress");
        string? errorCode = ReadString(element, "errorCode");
        EventResult result = errorCode is null ? EventResult.Success : EventResult.Failure;

        return BuildEnvelope(
            eventId,
            timeGenerated,
            observedAt,
            SecurityEventCategories.AdministrativeActivity,
            "aws_cloudtrail",
            eventName,
            result,
            errorCode,
            username,
            ActorType.Service,
            "aws-api",
            eventSource,
            sourceIp,
            region,
            accountId,
            new Dictionary<string, string>
            {
                ["aws.service"] = eventSource,
                ["aws.eventName"] = eventName,
                ["aws.source"] = "cloudtrail"
            },
            element);
    }

    private SecurityEventEnvelope MapGuardDuty(JsonElement element, DateTimeOffset observedAt)
    {
        string findingId = ReadString(element, "id")
            ?? ReadString(element, "Arn")
            ?? DeterministicId("guardduty", element.GetRawText());
        string title = ReadString(element, "title")
            ?? ReadString(element, "type")
            ?? "GuardDutyFinding";
        string type = ReadString(element, "type") ?? "Unknown";
        DateTimeOffset timeGenerated = ReadTime(element, "updatedAt")
            ?? ReadTime(element, "createdAt")
            ?? observedAt;
        double? severityNumber = ReadDouble(element, "severity");
        EventSeverity severity = MapGuardDutySeverity(severityNumber);
        string? accountId = ReadNestedString(element, "accountId")
            ?? ReadNestedString(element, "resource", "accountId")
            ?? options.AccountId;
        string? region = ReadString(element, "region") ?? options.Region;

        return BuildEnvelope(
            findingId,
            timeGenerated,
            observedAt,
            SecurityEventCategories.ApplicationSecurity,
            "aws_guardduty",
            type,
            EventResult.Failure,
            title,
            null,
            ActorType.Unknown,
            "finding",
            type,
            null,
            region,
            accountId,
            new Dictionary<string, string>
            {
                ["aws.source"] = "guardduty",
                ["aws.findingType"] = type,
                ["aws.severity"] = severityNumber?.ToString(CultureInfo.InvariantCulture) ?? "unknown"
            },
            element,
            severity);
    }

    private SecurityEventEnvelope MapSecurityHub(JsonElement element, DateTimeOffset observedAt)
    {
        string findingId = ReadString(element, "Id")
            ?? ReadString(element, "id")
            ?? DeterministicId("securityhub", element.GetRawText());
        string title = ReadString(element, "Title")
            ?? ReadString(element, "GeneratorId")
            ?? "SecurityHubFinding";
        string productArn = ReadString(element, "ProductArn") ?? "securityhub";
        DateTimeOffset timeGenerated = ReadTime(element, "UpdatedAt")
            ?? ReadTime(element, "CreatedAt")
            ?? observedAt;
        string? accountId = ReadString(element, "AwsAccountId") ?? options.AccountId;
        string? region = ReadString(element, "Region") ?? options.Region;
        string? severityLabel = ReadNestedString(element, "Severity", "Label");
        EventSeverity severity = MapAsffSeverity(severityLabel);
        string compliance = ReadNestedString(element, "Compliance", "Status") ?? "UNKNOWN";

        return BuildEnvelope(
            findingId,
            timeGenerated,
            observedAt,
            SecurityEventCategories.ApplicationSecurity,
            "aws_security_hub",
            title,
            compliance.Equals("FAILED", StringComparison.OrdinalIgnoreCase)
                ? EventResult.Failure
                : EventResult.Success,
            compliance,
            null,
            ActorType.System,
            "finding",
            productArn,
            null,
            region,
            accountId,
            new Dictionary<string, string>
            {
                ["aws.source"] = "securityhub",
                ["aws.productArn"] = productArn,
                ["aws.compliance"] = compliance
            },
            element,
            severity);
    }

    private SecurityEventEnvelope MapCloudWatch(JsonElement element, DateTimeOffset observedAt)
    {
        string id = ReadString(element, "id")
            ?? DeterministicId("cloudwatch", element.GetRawText());
        long? timestampMs = element.TryGetProperty("timestamp", out JsonElement timestamp) &&
                            timestamp.ValueKind == JsonValueKind.Number
            ? timestamp.GetInt64()
            : null;
        DateTimeOffset timeGenerated = timestampMs is null
            ? observedAt
            : DateTimeOffset.FromUnixTimeMilliseconds(timestampMs.Value);
        string message = ReadString(element, "message") ?? string.Empty;

        return BuildEnvelope(
            id,
            timeGenerated,
            observedAt,
            SecurityEventCategories.ApplicationSecurity,
            "aws_cloudwatch_logs",
            "log_event",
            EventResult.Unknown,
            null,
            null,
            ActorType.Unknown,
            "log",
            options.SourceId,
            null,
            options.Region,
            options.AccountId,
            new Dictionary<string, string>
            {
                ["aws.source"] = "cloudwatch-logs",
                ["aws.messagePreview"] = Truncate(message, 256)
            },
            element);
    }

    private SecurityEventEnvelope MapGenericNetwork(
        JsonElement element,
        DateTimeOffset observedAt,
        string eventType)
    {
        string id = ReadString(element, "id")
            ?? DeterministicId(eventType, element.GetRawText());
        DateTimeOffset timeGenerated = ReadTime(element, "eventTime")
            ?? ReadTime(element, "start")
            ?? observedAt;
        string? sourceIp = ReadString(element, "srcAddr")
            ?? ReadString(element, "sourceIPAddress")
            ?? ReadString(element, "query_name");

        return BuildEnvelope(
            id,
            timeGenerated,
            observedAt,
            SecurityEventCategories.ApiSecurity,
            eventType,
            eventType,
            EventResult.Unknown,
            null,
            null,
            ActorType.Unknown,
            "network",
            eventType,
            sourceIp,
            options.Region,
            options.AccountId,
            new Dictionary<string, string>
            {
                ["aws.source"] = eventType
            },
            element);
    }

    private SecurityEventEnvelope BuildEnvelope(
        string originalId,
        DateTimeOffset timeGenerated,
        DateTimeOffset observedAt,
        string category,
        string eventType,
        string action,
        EventResult result,
        string? outcomeReason,
        string? username,
        ActorType actorType,
        string targetType,
        string? targetName,
        string? sourceIp,
        string? region,
        string? accountId,
        Dictionary<string, string> labels,
        JsonElement raw,
        EventSeverity severity = EventSeverity.Medium)
    {
        string eventId = Guid.CreateVersion7().ToString();
        string fingerprint = Convert.ToHexString(
                SHA256.HashData(
                    Encoding.UTF8.GetBytes(
                        string.Join(
                            '\u001f',
                            options.SourceId,
                            options.Kind,
                            originalId,
                            timeGenerated.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)))))
            .ToLowerInvariant();

        labels["aws.sourceId"] = options.SourceId;
        labels["bower.fingerprint"] = fingerprint;
        if (!string.IsNullOrWhiteSpace(region))
        {
            labels["aws.region"] = region;
        }

        if (!string.IsNullOrWhiteSpace(accountId))
        {
            labels["aws.accountId"] = accountId;
        }

        Dictionary<string, JsonElement> attributes = new(StringComparer.Ordinal)
        {
            ["aws.raw"] = raw.Clone()
        };

        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            EventOriginalId = originalId,
            TimeGenerated = timeGenerated.ToUniversalTime(),
            TimeObserved = observedAt.ToUniversalTime(),
            EventCategory = category,
            EventType = eventType,
            EventAction = action,
            EventResult = result,
            EventSeverity = severity,
            EventOutcomeReason = outcomeReason,
            Application = new ApplicationContext
            {
                Name = options.ApplicationName,
                Environment = options.Environment,
                TenantId = accountId
            },
            Actor = username is null
                ? null
                : new ActorContext
                {
                    Username = username,
                    Type = actorType
                },
            Target = new TargetContext
            {
                Type = targetType,
                Name = targetName
            },
            Source = sourceIp is null
                ? null
                : new SourceContext
                {
                    IpAddress = sourceIp
                },
            Collector = new CollectorContext
            {
                Id = options.SourceId,
                Version = "0.1.0",
                SourceAdapter = $"aws.{options.Kind.ToString().ToLowerInvariant()}",
                ConfigurationHash = fingerprint[..16],
                ReceivedAt = observedAt.ToUniversalTime()
            },
            Labels = labels,
            Attributes = attributes
        };
    }

    private static EventSeverity MapGuardDutySeverity(double? severity)
    {
        return severity switch
        {
            null => EventSeverity.Medium,
            <= 3.9 => EventSeverity.Low,
            <= 6.9 => EventSeverity.Medium,
            <= 8.9 => EventSeverity.High,
            _ => EventSeverity.Critical
        };
    }

    private static EventSeverity MapAsffSeverity(string? label)
    {
        return label?.ToUpperInvariant() switch
        {
            "INFORMATIONAL" => EventSeverity.Informational,
            "LOW" => EventSeverity.Low,
            "MEDIUM" => EventSeverity.Medium,
            "HIGH" => EventSeverity.High,
            "CRITICAL" => EventSeverity.Critical,
            _ => EventSeverity.Medium
        };
    }

    private static string DeterministicId(string prefix, string material)
    {
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)))
            .ToLowerInvariant();
        return $"{prefix}-{hash[..24]}";
    }

    private static string Truncate(string value, int max)
    {
        return value.Length <= max ? value : value[..max];
    }

    private static string? ReadString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property))
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString(),
            JsonValueKind.Number => property.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    private static string? ReadNestedString(JsonElement element, string parent, string child)
    {
        if (!element.TryGetProperty(parent, out JsonElement parentElement) ||
            parentElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return ReadString(parentElement, child);
    }

    private static string? ReadNestedString(JsonElement element, string name)
    {
        return ReadString(element, name);
    }

    private static DateTimeOffset? ReadTime(JsonElement element, string name)
    {
        string? value = ReadString(element, name);
        if (value is null)
        {
            return null;
        }

        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : null;
    }

    private static double? ReadDouble(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property))
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out double value)
            ? value
            : null;
    }
}

public sealed class AwsTelemetryPayloadTooLargeException(
    string sourceId,
    int actualBytes,
    int maximumBytes)
    : InvalidOperationException(
        $"AWS source '{sourceId}' payload is {actualBytes} bytes; maximum is {maximumBytes} bytes.");

public sealed class AwsTelemetryBatchTooLargeException(
    string sourceId,
    int actualCount,
    int maximumCount)
    : InvalidOperationException(
        $"AWS source '{sourceId}' batch has {actualCount} events; maximum is {maximumCount}.");
