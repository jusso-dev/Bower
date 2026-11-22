using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.MicrosoftCloud;

/// <summary>
/// Durable position of one input, stored in the queue database's <c>source_cursors</c> table.
/// Window kinds keep <see cref="Committed"/> (every record before it is durably handled) and an
/// open window with the next page to read. Snapshot kinds keep the last completed UTC day and
/// an open snapshot. A page link is only ever stored after every record of the page before it
/// was durably enqueued or definitively dropped, so a crash re-reads at most one page.
/// </summary>
/// <param name="SchemaVersion">Always 1. Any other value fails closed (<see cref="MicrosoftCloudFailures.CursorInvalid"/>).</param>
/// <param name="SourceKind">Must equal the input's kind; a changed kind fails closed.</param>
/// <param name="Committed">Window kinds: the exclusive upper bound of the last completed window.</param>
/// <param name="WindowStart">Window kinds: inclusive lower bound of the open window (null when none is open).</param>
/// <param name="WindowEnd">Window kinds: exclusive upper bound of the open window.</param>
/// <param name="Page">The next page of the open window or snapshot; null means its first page.</param>
/// <param name="CompletedDate">Snapshot kinds: the last UTC day whose snapshot finished (yyyy-MM-dd).</param>
/// <param name="SnapshotDate">Snapshot kinds: the UTC day of the open snapshot.</param>
/// <param name="SnapshotAt">Snapshot kinds: when the open snapshot started; the event time of its records.</param>
public sealed record MicrosoftCloudCursor(
    int SchemaVersion,
    string SourceKind,
    DateTimeOffset? Committed = null,
    DateTimeOffset? WindowStart = null,
    DateTimeOffset? WindowEnd = null,
    string? Page = null,
    string? CompletedDate = null,
    string? SnapshotDate = null,
    DateTimeOffset? SnapshotAt = null)
{
    public const int CurrentSchemaVersion = 1;

    public string Serialize() => JsonSerializer.Serialize(this, MicrosoftCloudCursorJsonContext.Default.MicrosoftCloudCursor);

    /// <summary>Null for anything that is not a valid schema 1 cursor of <paramref name="kind"/>.</summary>
    public static MicrosoftCloudCursor? Deserialize(string value, string kind)
    {
        MicrosoftCloudCursor? cursor;
        try
        {
            cursor = JsonSerializer.Deserialize(value, MicrosoftCloudCursorJsonContext.Default.MicrosoftCloudCursor);
        }
        catch (JsonException)
        {
            return null;
        }

        if (cursor is null || cursor.SchemaVersion != CurrentSchemaVersion
            || !string.Equals(cursor.SourceKind, kind, StringComparison.Ordinal)
            || (cursor.WindowStart is null) != (cursor.WindowEnd is null)
            || cursor.WindowStart > cursor.WindowEnd
            || (cursor.Page is not null && cursor.WindowStart is null && cursor.SnapshotDate is null)
            || (cursor.SnapshotDate is null) != (cursor.SnapshotAt is null)
            || cursor.Page?.Length > MicrosoftCloudHttp.MaximumUriLength
            || (cursor.Page is not null && !Uri.TryCreate(cursor.Page, UriKind.Absolute, out _))
            || !IsDate(cursor.CompletedDate)
            || !IsDate(cursor.SnapshotDate))
        {
            return null;
        }

        // Window kinds carry window fields only, snapshot kinds snapshot fields only.
        bool snapshotKind = string.Equals(kind, MicrosoftCloudKinds.IntuneDeviceCompliance, StringComparison.Ordinal);
        bool windowFields = cursor.Committed is not null || cursor.WindowStart is not null;
        bool snapshotFields = cursor.CompletedDate is not null || cursor.SnapshotDate is not null;
        if (snapshotKind ? windowFields : snapshotFields)
        {
            return null;
        }

        return cursor;
    }

    private static bool IsDate(string? value) =>
        value is null || DateOnly.TryParseExact(value, "yyyy'-'MM'-'dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _);
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(MicrosoftCloudCursor))]
internal sealed partial class MicrosoftCloudCursorJsonContext : JsonSerializerContext;
