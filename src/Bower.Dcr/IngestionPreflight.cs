using System.Buffers;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bower.Dcr;

public sealed record PreflightIssue(string Code, string Field, string Detail);

/// <summary>
/// Checks a record against Logs Ingestion API limits before upload. Azure truncates
/// over-long fields and drops malformed rows without a per-record error, so Bower
/// catches them first and dead-letters with an explicit reason.
/// </summary>
public static class IngestionPreflight
{
    /// <summary>Azure truncates any single field value above this size.</summary>
    public const int MaximumFieldBytes = 64 * 1024;

    /// <summary>A single API call is limited to 1 MB; one record must fit.</summary>
    public const int MaximumRecordBytes = 1_000_000;

    /// <summary>Checks a record object as it would be uploaded.</summary>
    public static IReadOnlyList<PreflightIssue> Check(JsonObject record, SentinelSchema schema)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(schema);

        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            record.WriteTo(writer);
        }

        return Check(buffer.WrittenSpan, schema);
    }

    /// <summary>
    /// Checks one record given as the compact UTF-8 JSON object that is uploaded (as
    /// written by <see cref="Utf8JsonWriter"/> with default options). Sizes are measured
    /// on these bytes, so they equal <see cref="JsonNode.ToJsonString"/> of the parsed
    /// record and of each field. A JSON <c>null</c> field counts as absent.
    /// </summary>
    /// <exception cref="JsonException">
    /// The bytes are not one JSON object, or a top-level property name repeats (a record
    /// that <see cref="JsonObject"/> cannot hold).
    /// </exception>
    public static IReadOnlyList<PreflightIssue> Check(ReadOnlySpan<byte> utf8Record, SentinelSchema schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        Dictionary<string, Member> members = ReadMembers(utf8Record);
        List<PreflightIssue> issues = [];

        int recordBytes = utf8Record.Length;
        if (recordBytes > MaximumRecordBytes)
        {
            issues.Add(new("record-too-large", "$", $"Record is {recordBytes} bytes; the API limit is {MaximumRecordBytes}."));
        }

        foreach (StreamColumn column in schema.StreamColumns)
        {
            if (!members.TryGetValue(column.Name, out Member member) || member.Kind == JsonValueKind.Null)
            {
                continue;
            }

            int bytes = member.Length;
            if (bytes > MaximumFieldBytes)
            {
                issues.Add(new("field-too-large", column.Name,
                    $"Field is {bytes} bytes; Azure silently truncates values above {MaximumFieldBytes}."));
            }

            JsonValueKind kind = member.Kind;
            bool typeOk = column.Type switch
            {
                "string" => kind == JsonValueKind.String,
                "datetime" => kind == JsonValueKind.String && DateTimeOffset.TryParse(
                    ReadString(utf8Record.Slice(member.Start, member.Length)),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind,
                    out _),
                "int" or "long" or "real" => kind == JsonValueKind.Number,
                "boolean" => kind is JsonValueKind.True or JsonValueKind.False,
                // The transform reads members of dynamic columns (labels, application.name,
                // ...); a scalar there would land as text and every derived column would
                // be empty.
                "dynamic" => kind is JsonValueKind.Object or JsonValueKind.Array,
                _ => true
            };
            if (!typeOk)
            {
                issues.Add(new("type-mismatch", column.Name,
                    $"Expected {column.Type}, got {kind}; Azure would store an empty or stringified value."));
            }
        }

        if (!members.TryGetValue("timeGenerated", out Member time) || time.Kind == JsonValueKind.Null)
        {
            issues.Add(new("time-generated-missing", "timeGenerated", "Rows without timeGenerated cannot be placed in time."));
        }

        return issues;
    }

    /// <summary>Top-level members by unescaped name (ordinal).</summary>
    private static Dictionary<string, Member> ReadMembers(ReadOnlySpan<byte> utf8Record)
    {
        Dictionary<string, Member> members = new(StringComparer.Ordinal);
        Utf8JsonReader reader = new(utf8Record);
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("A record must be a JSON object.");
        }

        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            string name = reader.GetString()!;
            reader.Read();
            JsonTokenType token = reader.TokenType;
            int start = checked((int)reader.TokenStartIndex);
            reader.Skip();
            int end = checked((int)reader.BytesConsumed);
            if (!members.TryAdd(name, new Member(Kind(token), start, end - start)))
            {
                throw new JsonException("A record must not repeat a top-level property name.");
            }
        }

        if (reader.TokenType != JsonTokenType.EndObject || reader.Read())
        {
            throw new JsonException("A record must be a single JSON object.");
        }

        return members;
    }

    private static string ReadString(ReadOnlySpan<byte> utf8String)
    {
        Utf8JsonReader reader = new(utf8String);
        reader.Read();
        return reader.GetString()!;
    }

    private static JsonValueKind Kind(JsonTokenType token) => token switch
    {
        JsonTokenType.StartObject => JsonValueKind.Object,
        JsonTokenType.StartArray => JsonValueKind.Array,
        JsonTokenType.String => JsonValueKind.String,
        JsonTokenType.Number => JsonValueKind.Number,
        JsonTokenType.True => JsonValueKind.True,
        JsonTokenType.False => JsonValueKind.False,
        JsonTokenType.Null => JsonValueKind.Null,
        _ => JsonValueKind.Undefined
    };

    private readonly record struct Member(JsonValueKind Kind, int Start, int Length);
}
