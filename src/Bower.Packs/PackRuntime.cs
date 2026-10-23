using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Pipeline;

namespace Bower.Packs;

/// <summary>One bounded JSON record to an allowlisted semantic event. Never forwards raw fields.</summary>
public static class PackRuntime
{
    public const int MaximumRecordBytes = 32 * 1024;

    public static SecurityEventEnvelope? Parse(CustomLogParserConfiguration parser, string raw)
    {
        if (Encoding.UTF8.GetByteCount(raw) > MaximumRecordBytes)
        {
            throw new InvalidDataException("pack-record-too-large");
        }

        if (parser.Runtime is not { } mapping || CustomLogParser.ValidateConfiguration(parser).Count != 0)
        {
            throw new InvalidDataException("pack-parser-inactive");
        }

        using JsonDocument document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 16 });
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() > 64 || HasDuplicates(root))
        {
            throw new InvalidDataException("pack-record-invalid");
        }

        string Read(string name)
        {
            if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String
                || value.GetString() is not { } text || string.IsNullOrWhiteSpace(text) || text.Length > 2048)
            {
                throw new InvalidDataException("pack-field-invalid");
            }

            CustomLogField field = parser.Fields.Single(field => field.SourceName == name);
            bool valid = field.Type switch
            {
                CustomLogValueType.Text => true,
                CustomLogValueType.DateTime => TryTimestamp(text, out _),
                CustomLogValueType.IpAddress => IPAddress.TryParse(text, out _),
                CustomLogValueType.WholeNumber => long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out _),
                CustomLogValueType.Boolean => text is "true" or "false",
                _ => false
            };
            return valid ? text : throw new InvalidDataException("pack-field-type-invalid");
        }

        foreach ((string field, string expected) in mapping.Match)
        {
            if (!string.Equals(Read(field), expected, StringComparison.Ordinal))
            {
                return null; // Unknown or unapproved source actions never become semantic events.
            }
        }

        string? Mapped(string target) => mapping.Fields.TryGetValue(target, out string? source) ? Read(source) : null;
        string id = Mapped("eventId")!;
        string timestamp = Mapped("timeGenerated")!;
        if (id.Length > 128 || !TryTimestamp(timestamp, out DateTimeOffset generated))
        {
            throw new InvalidDataException("pack-identity-or-time-invalid");
        }

        string? username = Mapped("actor.username");
        string? userId = Mapped("actor.userId");
        string? ip = Mapped("source.ipAddress");
        if (ip is not null && !IPAddress.TryParse(ip, out _))
        {
            throw new InvalidDataException("pack-source-invalid");
        }

        string? correlation = Mapped("request.correlationId");
        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = id,
            EventOriginalId = id,
            TimeGenerated = generated,
            EventCategory = mapping.EventCategory,
            EventType = mapping.EventType,
            EventAction = mapping.EventAction,
            EventResult = Enum.Parse<EventResult>(mapping.EventResult, ignoreCase: true),
            EventOutcomeReason = Mapped("eventOutcomeReason"),
            Application = new ApplicationContext { Name = mapping.ApplicationName, Environment = mapping.Environment },
            Actor = username is null && userId is null ? null : new ActorContext { Username = username, UserId = userId },
            Source = ip is null ? null : new SourceContext { IpAddress = ip },
            Request = correlation is null ? null : new RequestContext { CorrelationId = correlation }
        };
    }

    private static bool TryTimestamp(string text, out DateTimeOffset value)
    {
        value = default;
        return text.Contains('T') && (text.EndsWith('Z') || (text.Length >= 6 && text[^6] is '+' or '-' && text[^3] == ':'))
            && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out value);
    }

    private static bool HasDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            HashSet<string> names = new(StringComparer.Ordinal);
            return element.EnumerateObject().Any(property => !names.Add(property.Name) || HasDuplicates(property.Value));
        }

        return element.ValueKind == JsonValueKind.Array && element.EnumerateArray().Any(HasDuplicates);
    }
}
