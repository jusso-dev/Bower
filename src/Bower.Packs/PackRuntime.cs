using System.Globalization;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Pipeline;
using Bower.Pipeline.Transforms;

namespace Bower.Packs;

/// <summary>
/// One bounded JSON record to an allowlisted semantic event. Never forwards raw fields.
/// Order: parse, signed transform program (optional), match and semantic mapping; the
/// caller then redacts, selects and queues the mapped envelope. A transform failure throws
/// <see cref="TransformException"/> with a metadata-only code; callers quarantine.
/// </summary>
public static class PackRuntime
{
    public const int MaximumRecordBytes = 32 * 1024;

    private static readonly ConditionalWeakTable<CustomLogParserConfiguration, TransformProgram> Programs = new();

    /// <param name="evaluationTime">
    /// The only time a transform can read (<c>now()</c> and the RFC 3164 year).
    /// </param>
    public static SecurityEventEnvelope? Parse(CustomLogParserConfiguration parser, string raw, DateTimeOffset evaluationTime)
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

        using JsonDocument? transformed = Transform(parser, mapping, root, evaluationTime);
        if (transformed is not null)
        {
            root = transformed.RootElement;
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
                CustomLogValueType.IpAddress => IsAddress(text),
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
        if (ip is not null && !IsAddress(ip))
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

    /// <summary>
    /// Runs the parser's transform program, if any, and returns the output record. Input the
    /// transform cannot represent is a malformed record (<c>pack-record-invalid</c>), as it is
    /// in the Rust runtime; every other transform failure propagates its code.
    /// </summary>
    private static JsonDocument? Transform(
        CustomLogParserConfiguration parser,
        CustomLogRuntimeMapping mapping,
        JsonElement root,
        DateTimeOffset evaluationTime)
    {
        if (mapping.ToTransformDefinition(parser.Fields) is not { } definition)
        {
            return null;
        }

        TransformProgram program = Programs.GetValue(parser, _ => TransformProgram.Compile(definition));
        TransformOutput output;
        try
        {
            output = program.Execute(root, evaluationTime);
        }
        catch (TransformException exception) when (exception.Code == TransformErrorCodes.InputInvalid)
        {
            throw new InvalidDataException("pack-record-invalid");
        }

        return JsonDocument.Parse(output.RecordJson, new JsonDocumentOptions { MaxDepth = 64 });
    }

    private static bool IsAddress(string text)
    {
        if (text.Contains('%') || !IPAddress.TryParse(text, out IPAddress? address)) { return false; }
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) { return text == address.ToString(); }
        if (!text.Contains('.')) { return true; }
        string ipv4 = text[(text.LastIndexOf(':') + 1)..];
        return IPAddress.TryParse(ipv4, out IPAddress? embedded) && ipv4 == embedded.ToString();
    }

    private static bool TryTimestamp(string text, out DateTimeOffset value)
    {
        value = default;
        return text.Contains('T') && (text.EndsWith('Z') || (text.Length >= 6 && text[^6] is '+' or '-' && text[^3] == ':'))
            && DateTimeOffset.TryParseExact(text, "yyyy-MM-dd\'T\'HH:mm:ss.FFFFFFFK", CultureInfo.InvariantCulture, DateTimeStyles.None, out value);
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
