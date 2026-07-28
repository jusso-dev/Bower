using System.Globalization;
using System.Text;
using System.Text.Json;
using Bower.Contracts;

namespace Bower.Ocsf;

public interface IOcsfMapper
{
    OcsfSourceKind Kind { get; }

    string MappingVersion { get; }

    OcsfNormalisationResult Map(JsonElement root);
}

public sealed class OcsfNormalisationEngine
{
    public const string EngineVersion = "1.0.0";

    private readonly IReadOnlyDictionary<OcsfSourceKind, IOcsfMapper> mappers;

    public OcsfNormalisationEngine(IEnumerable<IOcsfMapper>? mappers = null)
    {
        Dictionary<OcsfSourceKind, IOcsfMapper> map = (mappers ?? DefaultMappers())
            .ToDictionary(item => item.Kind);
        this.mappers = map;
    }

    public IReadOnlyCollection<OcsfSourceKind> SupportedSources => mappers.Keys.ToArray();

    public OcsfNormalisationResult Normalise(string json, OcsfSourceKind kind)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Fail(kind, "empty-payload");
        }

        if (Encoding.UTF8.GetByteCount(json) > 1_048_576)
        {
            return Fail(kind, "payload-too-large");
        }

        if (!mappers.TryGetValue(kind, out IOcsfMapper? mapper))
        {
            return Fail(kind, "unsupported-source");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64
                });
            return mapper.Map(document.RootElement);
        }
        catch (JsonException)
        {
            return Fail(kind, "invalid-json");
        }
    }

    public OcsfNormalisationResult NormaliseEnvelope(SecurityEventEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        string json = JsonSerializer.Serialize(envelope, BowerJson.Options);
        return Normalise(json, OcsfSourceKind.BowerEnvelope);
    }

    private static OcsfNormalisationResult Fail(OcsfSourceKind kind, string code)
    {
        return new OcsfNormalisationResult(false, null, EngineVersion, kind.ToString(), [], code);
    }

    private static IEnumerable<IOcsfMapper> DefaultMappers()
    {
        yield return new BowerEnvelopeOcsfMapper();
        yield return new CloudTrailOcsfMapper();
        yield return new GuardDutyOcsfMapper();
        yield return new SecurityHubOcsfMapper();
        yield return new WindowsEventOcsfMapper();
        yield return new SysmonOcsfMapper();
        yield return new LinuxSyslogOcsfMapper();
        yield return new GenericVendorOcsfMapper(OcsfSourceKind.CrowdStrike, "CrowdStrike", "CrowdStrike");
        yield return new GenericVendorOcsfMapper(OcsfSourceKind.DefenderXdr, "Microsoft Defender XDR", "Microsoft");
        yield return new GenericVendorOcsfMapper(OcsfSourceKind.PaloAlto, "Palo Alto Networks", "Palo Alto Networks");
        yield return new GenericVendorOcsfMapper(OcsfSourceKind.Fortinet, "Fortinet", "Fortinet");
        yield return new GenericVendorOcsfMapper(OcsfSourceKind.MicrosoftSentinel, "Microsoft Sentinel", "Microsoft");
    }
}

internal static class OcsfSeverity
{
    public static (int Id, string Name) FromEventSeverity(EventSeverity severity)
    {
        return severity switch
        {
            EventSeverity.Informational => (1, "Informational"),
            EventSeverity.Low => (2, "Low"),
            EventSeverity.Medium => (3, "Medium"),
            EventSeverity.High => (4, "High"),
            EventSeverity.Critical => (5, "Critical"),
            _ => (0, "Unknown")
        };
    }

    public static (int Id, string Name) FromNumber(double? value)
    {
        return value switch
        {
            null => (0, "Unknown"),
            <= 1.9 => (1, "Informational"),
            <= 3.9 => (2, "Low"),
            <= 6.9 => (3, "Medium"),
            <= 8.9 => (4, "High"),
            _ => (5, "Critical")
        };
    }

    public static (int Id, string Name) FromLabel(string? label)
    {
        return label?.ToUpperInvariant() switch
        {
            "INFORMATIONAL" or "INFO" => (1, "Informational"),
            "LOW" => (2, "Low"),
            "MEDIUM" or "MED" => (3, "Medium"),
            "HIGH" => (4, "High"),
            "CRITICAL" or "CRIT" => (5, "Critical"),
            _ => (0, "Unknown")
        };
    }
}

internal static class JsonRead
{
    public static string? String(JsonElement element, string name)
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

    public static string? Nested(JsonElement element, string parent, string child)
    {
        if (!element.TryGetProperty(parent, out JsonElement parentElement) ||
            parentElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return String(parentElement, child);
    }

    public static DateTimeOffset? Time(JsonElement element, string name)
    {
        string? value = String(element, name);
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

    public static double? Number(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) ||
            property.ValueKind != JsonValueKind.Number ||
            !property.TryGetDouble(out double value))
        {
            return null;
        }

        return value;
    }
}

internal sealed class BowerEnvelopeOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.BowerEnvelope;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        SecurityEventEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(root.GetRawText(), BowerJson.Options);
        }
        catch (JsonException)
        {
            return new OcsfNormalisationResult(false, null, MappingVersion, Kind.ToString(), [], "schema-invalid");
        }

        if (envelope is null)
        {
            return new OcsfNormalisationResult(false, null, MappingVersion, Kind.ToString(), [], "schema-invalid");
        }

        (int severityId, string severity) = OcsfSeverity.FromEventSeverity(envelope.EventSeverity);
        bool isAuth = envelope.EventCategory.Contains("auth", StringComparison.OrdinalIgnoreCase);
        OcsfEvent mapped = new()
        {
            ClassUid = isAuth ? 3002 : 1001,
            ClassName = isAuth ? "Authentication" : "Security Finding",
            CategoryUid = isAuth ? 3 : 1,
            CategoryName = isAuth ? "Identity & Access Management" : "System Activity",
            ActivityId = envelope.EventResult == EventResult.Failure ? 2 : 1,
            ActivityName = envelope.EventAction,
            SeverityId = severityId,
            Severity = severity,
            Time = envelope.TimeGenerated,
            TypeName = envelope.EventType,
            Message = envelope.EventOutcomeReason,
            Status = envelope.EventResult.ToString(),
            SourceId = envelope.EventOriginalId ?? envelope.EventId,
            MetadataProductName = "Bower",
            MetadataProductVendor = "Bower",
            MetadataVersion = MappingVersion,
            ActorUserName = envelope.Actor?.Username ?? envelope.Actor?.UserId,
            SrcEndpointIp = envelope.Source?.IpAddress,
            TargetName = envelope.Target?.Name ?? envelope.Target?.Id,
            Unmapped = envelope.Labels
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class CloudTrailOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.CloudTrail;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        JsonElement record = root;
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("Records", out JsonElement records) &&
            records.ValueKind == JsonValueKind.Array &&
            records.GetArrayLength() > 0)
        {
            record = records[0];
        }

        string eventName = JsonRead.String(record, "eventName") ?? "Unknown";
        (int severityId, string severity) = OcsfSeverity.FromLabel(
            JsonRead.String(record, "errorCode") is null ? "INFORMATIONAL" : "MEDIUM");

        OcsfEvent mapped = new()
        {
            ClassUid = 3001,
            ClassName = "Account Change",
            CategoryUid = 3,
            CategoryName = "Identity & Access Management",
            ActivityId = 1,
            ActivityName = eventName,
            SeverityId = severityId,
            Severity = severity,
            Time = JsonRead.Time(record, "eventTime") ?? DateTimeOffset.UtcNow,
            TypeName = "CloudTrail",
            Message = JsonRead.String(record, "eventSource"),
            Status = JsonRead.String(record, "errorCode") is null ? "Success" : "Failure",
            SourceId = JsonRead.String(record, "eventID"),
            MetadataProductName = "AWS CloudTrail",
            MetadataProductVendor = "AWS",
            MetadataVersion = MappingVersion,
            ActorUserName = JsonRead.Nested(record, "userIdentity", "userName"),
            SrcEndpointIp = JsonRead.String(record, "sourceIPAddress"),
            TargetName = JsonRead.String(record, "eventSource"),
            Unmapped = new Dictionary<string, string>
            {
                ["awsRegion"] = JsonRead.String(record, "awsRegion") ?? string.Empty
            }
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class GuardDutyOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.GuardDuty;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        (int severityId, string severity) = OcsfSeverity.FromNumber(JsonRead.Number(root, "severity"));
        OcsfEvent mapped = new()
        {
            ClassUid = 2001,
            ClassName = "Security Finding",
            CategoryUid = 2,
            CategoryName = "Findings",
            ActivityId = 1,
            ActivityName = JsonRead.String(root, "type") ?? "Finding",
            SeverityId = severityId,
            Severity = severity,
            Time = JsonRead.Time(root, "updatedAt")
                ?? JsonRead.Time(root, "createdAt")
                ?? DateTimeOffset.UtcNow,
            TypeName = "GuardDuty",
            Message = JsonRead.String(root, "title"),
            Status = "New",
            SourceId = JsonRead.String(root, "id"),
            MetadataProductName = "Amazon GuardDuty",
            MetadataProductVendor = "AWS",
            MetadataVersion = MappingVersion,
            TargetName = JsonRead.String(root, "type")
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class SecurityHubOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.SecurityHub;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        (int severityId, string severity) = OcsfSeverity.FromLabel(
            JsonRead.Nested(root, "Severity", "Label"));
        OcsfEvent mapped = new()
        {
            ClassUid = 2001,
            ClassName = "Security Finding",
            CategoryUid = 2,
            CategoryName = "Findings",
            ActivityId = 1,
            ActivityName = JsonRead.String(root, "Title") ?? "Finding",
            SeverityId = severityId,
            Severity = severity,
            Time = JsonRead.Time(root, "UpdatedAt")
                ?? JsonRead.Time(root, "CreatedAt")
                ?? DateTimeOffset.UtcNow,
            TypeName = "SecurityHub",
            Message = JsonRead.String(root, "Description"),
            Status = JsonRead.Nested(root, "Compliance", "Status") ?? "UNKNOWN",
            SourceId = JsonRead.String(root, "Id"),
            MetadataProductName = "AWS Security Hub",
            MetadataProductVendor = "AWS",
            MetadataVersion = MappingVersion,
            TargetName = JsonRead.String(root, "GeneratorId")
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class WindowsEventOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.WindowsEvent;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        string eventId = JsonRead.String(root, "EventID")
            ?? JsonRead.String(root, "Id")
            ?? "0";
        bool isAuth = eventId is "4624" or "4625" or "4648";
        OcsfEvent mapped = new()
        {
            ClassUid = isAuth ? 3002 : 1007,
            ClassName = isAuth ? "Authentication" : "Process Activity",
            CategoryUid = isAuth ? 3 : 1,
            CategoryName = isAuth ? "Identity & Access Management" : "System Activity",
            ActivityId = eventId == "4625" ? 2 : 1,
            ActivityName = JsonRead.String(root, "Task") ?? $"EventID {eventId}",
            SeverityId = eventId == "4625" ? 3 : 1,
            Severity = eventId == "4625" ? "Medium" : "Informational",
            Time = JsonRead.Time(root, "TimeCreated") ?? DateTimeOffset.UtcNow,
            TypeName = "WindowsEvent",
            Message = JsonRead.String(root, "Message"),
            Status = eventId == "4625" ? "Failure" : "Success",
            SourceId = eventId,
            MetadataProductName = "Windows Event Log",
            MetadataProductVendor = "Microsoft",
            MetadataVersion = MappingVersion,
            ActorUserName = JsonRead.String(root, "TargetUserName")
                ?? JsonRead.String(root, "SubjectUserName"),
            SrcEndpointIp = JsonRead.String(root, "IpAddress"),
            TargetName = JsonRead.String(root, "Computer")
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class SysmonOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.Sysmon;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        string eventId = JsonRead.String(root, "EventID") ?? JsonRead.String(root, "Id") ?? "1";
        OcsfEvent mapped = new()
        {
            ClassUid = 1007,
            ClassName = "Process Activity",
            CategoryUid = 1,
            CategoryName = "System Activity",
            ActivityId = eventId == "1" ? 1 : 2,
            ActivityName = eventId switch
            {
                "1" => "Process Creation",
                "3" => "Network Connection",
                "11" => "File Create",
                _ => $"Sysmon {eventId}"
            },
            SeverityId = 2,
            Severity = "Low",
            Time = JsonRead.Time(root, "UtcTime") ?? DateTimeOffset.UtcNow,
            TypeName = "Sysmon",
            Message = JsonRead.String(root, "Image") ?? JsonRead.String(root, "CommandLine"),
            Status = "Success",
            SourceId = eventId,
            MetadataProductName = "Sysmon",
            MetadataProductVendor = "Microsoft",
            MetadataVersion = MappingVersion,
            ActorUserName = JsonRead.String(root, "User"),
            SrcEndpointIp = JsonRead.String(root, "SourceIp"),
            TargetName = JsonRead.String(root, "DestinationIp") ?? JsonRead.String(root, "TargetFilename")
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class LinuxSyslogOcsfMapper : IOcsfMapper
{
    public OcsfSourceKind Kind => OcsfSourceKind.LinuxSyslog;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        string message = JsonRead.String(root, "message")
            ?? JsonRead.String(root, "MESSAGE")
            ?? string.Empty;
        bool failure = message.Contains("Failed password", StringComparison.OrdinalIgnoreCase)
            || message.Contains("authentication failure", StringComparison.OrdinalIgnoreCase);
        OcsfEvent mapped = new()
        {
            ClassUid = failure ? 3002 : 1001,
            ClassName = failure ? "Authentication" : "System Activity",
            CategoryUid = failure ? 3 : 1,
            CategoryName = failure ? "Identity & Access Management" : "System Activity",
            ActivityId = failure ? 2 : 1,
            ActivityName = JsonRead.String(root, "appname")
                ?? JsonRead.String(root, "SYSLOG_IDENTIFIER")
                ?? "syslog",
            SeverityId = failure ? 3 : 1,
            Severity = failure ? "Medium" : "Informational",
            Time = JsonRead.Time(root, "timestamp")
                ?? JsonRead.Time(root, "__REALTIME_TIMESTAMP")
                ?? DateTimeOffset.UtcNow,
            TypeName = "LinuxSyslog",
            Message = message.Length > 512 ? message[..512] : message,
            Status = failure ? "Failure" : "Unknown",
            SourceId = JsonRead.String(root, "hostname"),
            MetadataProductName = "Linux Syslog",
            MetadataProductVendor = "Linux",
            MetadataVersion = MappingVersion,
            ActorUserName = JsonRead.String(root, "user"),
            SrcEndpointIp = JsonRead.String(root, "source_ip"),
            TargetName = JsonRead.String(root, "hostname")
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}

internal sealed class GenericVendorOcsfMapper(OcsfSourceKind kind, string product, string vendor) : IOcsfMapper
{
    public OcsfSourceKind Kind { get; } = kind;

    public string MappingVersion => "1.0.0";

    public OcsfNormalisationResult Map(JsonElement root)
    {
        (int severityId, string severity) = OcsfSeverity.FromLabel(
            JsonRead.String(root, "severity")
            ?? JsonRead.Nested(root, "Severity", "Label")
            ?? JsonRead.String(root, "Severity"));

        OcsfEvent mapped = new()
        {
            ClassUid = 2001,
            ClassName = "Security Finding",
            CategoryUid = 2,
            CategoryName = "Findings",
            ActivityId = 1,
            ActivityName = JsonRead.String(root, "title")
                ?? JsonRead.String(root, "Title")
                ?? JsonRead.String(root, "type")
                ?? product,
            SeverityId = severityId == 0 ? 3 : severityId,
            Severity = severity == "Unknown" ? "Medium" : severity,
            Time = JsonRead.Time(root, "timestamp")
                ?? JsonRead.Time(root, "time")
                ?? JsonRead.Time(root, "createdAt")
                ?? DateTimeOffset.UtcNow,
            TypeName = Kind.ToString(),
            Message = JsonRead.String(root, "description")
                ?? JsonRead.String(root, "message"),
            Status = JsonRead.String(root, "status") ?? "Unknown",
            SourceId = JsonRead.String(root, "id")
                ?? JsonRead.String(root, "Id"),
            MetadataProductName = product,
            MetadataProductVendor = vendor,
            MetadataVersion = MappingVersion,
            ActorUserName = JsonRead.String(root, "user")
                ?? JsonRead.Nested(root, "actor", "user"),
            SrcEndpointIp = JsonRead.String(root, "src_ip")
                ?? JsonRead.String(root, "sourceIp"),
            TargetName = JsonRead.String(root, "target")
                ?? JsonRead.String(root, "hostname")
        };

        return new OcsfNormalisationResult(true, mapped, MappingVersion, Kind.ToString(), [], null);
    }
}
