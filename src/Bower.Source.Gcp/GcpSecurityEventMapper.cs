using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Contracts;

namespace Bower.Source.Gcp;

public static class GcpEventTypes
{
    public const string CloudAudit = "gcp_cloud_audit";
    public const string SccFinding = "gcp_scc_finding";
}

public sealed record GcpSourceOptions
{
    public required string SourceId { get; init; }

    public string Environment { get; init; } = "production";

    public string ApplicationName { get; init; } = "gcp-security";

    /// <summary>Pub/Sub accepts messages up to 10 MB; security records are far smaller.</summary>
    public int MaximumMessageBytes { get; init; } = 1_048_576;

    /// <summary>Copies the original record into the <c>gcp.raw</c> attribute. Off by default.</summary>
    public bool IncludeRawRecord { get; init; }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(SourceId);
        if (SourceId.Length > 128)
        {
            throw new ArgumentException("Source identifier cannot exceed 128 characters.");
        }

        if (MaximumMessageBytes is < 1_024 or > 10_485_760)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumMessageBytes),
                "Maximum message size must be between 1 KiB and 10 MiB.");
        }
    }

    public string ConfigurationHash()
    {
        string material = string.Join(
            '\u001f',
            SourceId,
            Environment,
            ApplicationName,
            MaximumMessageBytes.ToString(CultureInfo.InvariantCulture),
            IncludeRawRecord);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant()[..16];
    }
}

public sealed record GcpMappedMessage(SecurityEventEnvelope? Event, string? UnsupportedReason);

/// <summary>
/// Maps Pub/Sub message data from a Cloud Logging sink (Cloud Audit Logs) or a Security
/// Command Center notification config into Bower security event envelopes.
/// </summary>
public sealed class GcpSecurityEventMapper
{
    private const string AuditLogType = "type.googleapis.com/google.cloud.audit.AuditLog";

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 64
    };

    private readonly GcpSourceOptions options;
    private readonly string configurationHash;

    public GcpSecurityEventMapper(GcpSourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        this.options = options;
        configurationHash = options.ConfigurationHash();
    }

    /// <summary>Maps decoded Pub/Sub message data (UTF-8 JSON).</summary>
    public GcpMappedMessage Map(ReadOnlySpan<byte> data, DateTimeOffset observedAt)
    {
        if (data.Length > options.MaximumMessageBytes)
        {
            throw new GcpTelemetryPayloadTooLargeException(options.SourceId, data.Length, options.MaximumMessageBytes);
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(data.ToArray(), DocumentOptions);
        }
        catch (JsonException)
        {
            throw new GcpTelemetryMalformedException(options.SourceId, "invalid JSON");
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new GcpTelemetryMalformedException(options.SourceId, $"record is {root.ValueKind}");
            }

            if (root.TryGetProperty("finding", out JsonElement finding) && finding.ValueKind == JsonValueKind.Object)
            {
                return new GcpMappedMessage(MapSccFinding(root, finding, observedAt), null);
            }

            if (root.TryGetProperty("protoPayload", out JsonElement payload) && payload.ValueKind == JsonValueKind.Object)
            {
                return ReadString(payload, "@type") == AuditLogType
                    ? new GcpMappedMessage(MapAuditLog(root, payload, observedAt), null)
                    : new GcpMappedMessage(null, "protoPayload is not an AuditLog");
            }

            return new GcpMappedMessage(null, "unrecognised message shape");
        }
    }

    private SecurityEventEnvelope MapAuditLog(JsonElement entry, JsonElement payload, DateTimeOffset observedAt)
    {
        string insertId = ReadString(entry, "insertId")
            ?? throw new GcpTelemetryMalformedException(options.SourceId, "LogEntry has no insertId");
        string logName = ReadString(entry, "logName") ?? "unknown";
        DateTimeOffset timeGenerated = ReadTime(entry, "timestamp") ?? ReadTime(entry, "receiveTimestamp") ?? observedAt;
        string methodName = ReadString(payload, "methodName") ?? "unknown";
        string serviceName = ReadString(payload, "serviceName") ?? "unknown";
        string? resourceName = ReadString(payload, "resourceName");
        string? principal = ReadNested(payload, "authenticationInfo", "principalEmail")
            ?? ReadNested(payload, "authenticationInfo", "principalSubject");
        string? callerIp = ReadNested(payload, "requestMetadata", "callerIp");
        string? resourceType = ReadNested(entry, "resource", "type");
        string? projectId = ReadNestedLabel(entry, "resource", "project_id") ?? ProjectFromLogName(logName);

        // google.rpc.Status: 0 or absent is OK; 7 PERMISSION_DENIED and 16 UNAUTHENTICATED are denials.
        int statusCode = payload.TryGetProperty("status", out JsonElement status)
            && status.ValueKind == JsonValueKind.Object
            && status.TryGetProperty("code", out JsonElement code)
            && code.TryGetInt32(out int parsed)
                ? parsed
                : 0;
        EventResult result = statusCode switch
        {
            0 => EventResult.Success,
            7 or 16 => EventResult.Denied,
            _ => EventResult.Failure
        };
        string? reason = statusCode == 0 ? null : ReadNested(payload, "status", "message") ?? $"status {statusCode}";

        Dictionary<string, string> labels = new(StringComparer.Ordinal)
        {
            ["gcp.source"] = "cloud-audit",
            ["gcp.service"] = serviceName,
            ["gcp.method"] = methodName,
            ["gcp.logName"] = Uri.UnescapeDataString(logName),
            ["gcp.auditLog"] = AuditLogKind(logName)
        };
        AddIfPresent(labels, "gcp.projectId", projectId);
        AddIfPresent(labels, "gcp.severity", ReadString(entry, "severity"));
        AddIfPresent(labels, "gcp.callerIp", callerIp is not null && !IPAddress.TryParse(callerIp, out _) ? callerIp : null);
        AddIfPresent(labels, "gcp.serviceAccountDelegation", FirstDelegate(payload));

        return BuildEnvelope(
            originalId: insertId,
            identity: $"{logName}\u001f{insertId}",
            timeGenerated,
            observedAt,
            methodName.EndsWith(".Login", StringComparison.Ordinal) || serviceName == "login.googleapis.com"
                ? SecurityEventCategories.Authentication
                : SecurityEventCategories.AdministrativeActivity,
            GcpEventTypes.CloudAudit,
            action: methodName,
            result,
            reason,
            EventSeverity.Medium,
            principal,
            principal?.EndsWith(".gserviceaccount.com", StringComparison.OrdinalIgnoreCase) == true
                ? ActorType.Service
                : ActorType.Human,
            targetType: resourceType ?? "gcp-resource",
            targetName: resourceName,
            // Internal callers report "private" or "gce-internal-ip" instead of an address.
            sourceIp: callerIp is not null && IPAddress.TryParse(callerIp, out _) ? callerIp : null,
            projectId,
            labels,
            entry);
    }

    private SecurityEventEnvelope MapSccFinding(JsonElement message, JsonElement finding, DateTimeOffset observedAt)
    {
        string name = ReadString(finding, "name")
            ?? ReadString(finding, "canonicalName")
            ?? throw new GcpTelemetryMalformedException(options.SourceId, "finding has no name");
        string category = ReadString(finding, "category") ?? "UNKNOWN";
        string state = ReadString(finding, "state") ?? "STATE_UNSPECIFIED";
        DateTimeOffset timeGenerated = ReadTime(finding, "eventTime") ?? ReadTime(finding, "createTime") ?? observedAt;
        string? resourceName = ReadString(finding, "resourceName") ?? ReadNested(message, "resource", "name");
        string? projectId = ReadNested(message, "resource", "projectDisplayName")
            ?? ReadNested(message, "resource", "gcpMetadata", "projectDisplayName");

        Dictionary<string, string> labels = new(StringComparer.Ordinal)
        {
            ["gcp.source"] = "security-command-center",
            ["gcp.category"] = category,
            ["gcp.state"] = state,
            ["gcp.findingName"] = name
        };
        AddIfPresent(labels, "gcp.findingClass", ReadString(finding, "findingClass"));
        AddIfPresent(labels, "gcp.mute", ReadString(finding, "mute"));
        AddIfPresent(labels, "gcp.projectId", projectId);
        AddIfPresent(labels, "gcp.notificationConfig", ReadString(message, "notificationConfigName"));
        AddIfPresent(labels, "gcp.severity", ReadString(finding, "severity"));

        return BuildEnvelope(
            originalId: name,
            // A finding is re-sent when its state changes; eventTime distinguishes the updates.
            identity: $"{name}\u001f{state}",
            timeGenerated,
            observedAt,
            SecurityEventCategories.ApplicationSecurity,
            GcpEventTypes.SccFinding,
            action: category,
            state == "ACTIVE" ? EventResult.Failure : EventResult.Success,
            reason: state,
            MapSeverity(ReadString(finding, "severity")),
            username: null,
            ActorType.System,
            targetType: ReadNested(message, "resource", "type") ?? "gcp-resource",
            targetName: resourceName,
            sourceIp: null,
            projectId,
            labels,
            message);
    }

    private SecurityEventEnvelope BuildEnvelope(
        string originalId,
        string identity,
        DateTimeOffset timeGenerated,
        DateTimeOffset observedAt,
        string category,
        string eventType,
        string action,
        EventResult result,
        string? reason,
        EventSeverity severity,
        string? username,
        ActorType actorType,
        string targetType,
        string? targetName,
        string? sourceIp,
        string? projectId,
        Dictionary<string, string> labels,
        JsonElement raw)
    {
        string fingerprint = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
                    '\u001f',
                    options.SourceId,
                    eventType,
                    identity,
                    timeGenerated.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)))))
            .ToLowerInvariant();
        labels["gcp.sourceId"] = options.SourceId;
        labels["bower.fingerprint"] = fingerprint;
        foreach (string key in labels.Keys.ToList())
        {
            labels[key] = Clip(labels[key], 256)!;
        }

        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = $"gcp-{fingerprint[..32]}",
            EventOriginalId = Clip(originalId, 256),
            TimeGenerated = timeGenerated.ToUniversalTime(),
            TimeObserved = observedAt.ToUniversalTime(),
            EventCategory = category,
            EventType = eventType,
            EventAction = Clip(action, 128)!,
            EventResult = result,
            EventSeverity = severity,
            EventOutcomeReason = Clip(reason, 1024),
            Application = new ApplicationContext
            {
                Name = options.ApplicationName,
                Environment = options.Environment,
                TenantId = Clip(projectId, 256)
            },
            Actor = username is null ? null : new ActorContext { Username = Clip(username, 256), Type = actorType },
            Target = new TargetContext { Type = Clip(targetType, 128)!, Name = Clip(targetName, 256) },
            Source = sourceIp is null ? null : new SourceContext { IpAddress = sourceIp },
            Collector = new CollectorContext
            {
                Id = options.SourceId,
                Version = "0.1.0",
                SourceAdapter = eventType == GcpEventTypes.SccFinding ? "gcp.scc" : "gcp.audit",
                ConfigurationHash = configurationHash,
                ReceivedAt = observedAt.ToUniversalTime()
            },
            Labels = labels,
            Attributes = options.IncludeRawRecord
                ? new Dictionary<string, JsonElement>(StringComparer.Ordinal) { ["gcp.raw"] = raw.Clone() }
                : null
        };
    }

    private static EventSeverity MapSeverity(string? severity) =>
        severity switch
        {
            "CRITICAL" => EventSeverity.Critical,
            "HIGH" => EventSeverity.High,
            "MEDIUM" => EventSeverity.Medium,
            "LOW" => EventSeverity.Low,
            _ => EventSeverity.Medium
        };

    private static string AuditLogKind(string logName)
    {
        string decoded = Uri.UnescapeDataString(logName);
        int index = decoded.LastIndexOf("cloudaudit.googleapis.com/", StringComparison.Ordinal);
        return index < 0 ? "unknown" : decoded[(index + "cloudaudit.googleapis.com/".Length)..];
    }

    private static string? ProjectFromLogName(string logName) =>
        logName.StartsWith("projects/", StringComparison.Ordinal)
            ? logName["projects/".Length..].Split('/')[0]
            : null;

    private static string? FirstDelegate(JsonElement payload) =>
        payload.TryGetProperty("authenticationInfo", out JsonElement info)
        && info.ValueKind == JsonValueKind.Object
        && info.TryGetProperty("serviceAccountDelegationInfo", out JsonElement delegation)
        && delegation.ValueKind == JsonValueKind.Array
        && delegation.GetArrayLength() > 0
            ? ReadNested(delegation[0], "firstPartyPrincipal", "principalEmail")
                ?? ReadNested(delegation[0], "thirdPartyPrincipal", "principalEmail")
            : null;

    private static void AddIfPresent(Dictionary<string, string> labels, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            labels[key] = value;
        }
    }

    private static string? Clip(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    private static string? ReadString(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(name, out JsonElement value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? ReadNested(JsonElement element, params string[] path)
    {
        JsonElement current = element;
        for (int index = 0; index < path.Length - 1; index++)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(path[index], out current))
            {
                return null;
            }
        }

        return ReadString(current, path[^1]);
    }

    private static string? ReadNestedLabel(JsonElement element, string parent, string label) =>
        ReadNested(element, parent, "labels", label);

    private static DateTimeOffset? ReadTime(JsonElement element, string name) =>
        ReadString(element, name) is { } value
        && DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : null;
}

public sealed class GcpTelemetryMalformedException(string sourceId, string reason)
    : InvalidOperationException($"GCP source '{sourceId}' message is malformed: {reason}.");

public sealed class GcpTelemetryPayloadTooLargeException(string sourceId, int actualBytes, int maximumBytes)
    : InvalidOperationException(
        $"GCP source '{sourceId}' message is {actualBytes} bytes; maximum is {maximumBytes} bytes.");
