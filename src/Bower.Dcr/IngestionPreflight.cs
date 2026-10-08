using System.Globalization;
using System.Text;
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

    public static IReadOnlyList<PreflightIssue> Check(JsonObject record, SentinelSchema schema)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(schema);
        List<PreflightIssue> issues = [];

        int recordBytes = Encoding.UTF8.GetByteCount(record.ToJsonString());
        if (recordBytes > MaximumRecordBytes)
        {
            issues.Add(new("record-too-large", "$", $"Record is {recordBytes} bytes; the API limit is {MaximumRecordBytes}."));
        }

        foreach (StreamColumn column in schema.StreamColumns)
        {
            JsonNode? value = record[column.Name];
            if (value is null)
            {
                continue;
            }

            int bytes = Encoding.UTF8.GetByteCount(value.ToJsonString());
            if (bytes > MaximumFieldBytes)
            {
                issues.Add(new("field-too-large", column.Name,
                    $"Field is {bytes} bytes; Azure silently truncates values above {MaximumFieldBytes}."));
            }

            JsonValueKind kind = value.GetValueKind();
            bool typeOk = column.Type switch
            {
                "string" => kind == JsonValueKind.String,
                "datetime" => kind == JsonValueKind.String && DateTimeOffset.TryParse(
                    value.GetValue<string>(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _),
                "int" or "long" or "real" => kind == JsonValueKind.Number,
                "boolean" => kind is JsonValueKind.True or JsonValueKind.False,
                _ => true
            };
            if (!typeOk)
            {
                issues.Add(new("type-mismatch", column.Name,
                    $"Expected {column.Type}, got {kind}; Azure would store an empty or stringified value."));
            }
        }

        if (record["timeGenerated"] is null)
        {
            issues.Add(new("time-generated-missing", "timeGenerated", "Rows without timeGenerated cannot be placed in time."));
        }

        return issues;
    }
}
