using System.Globalization;
using System.Text;

namespace Bower.Source.WindowsEventLog;

/// <summary>
/// The subscription filter handed to the Windows event log service. Only events matching
/// it are ever returned to (and so read into) the collector. Built from validated,
/// numeric or character-restricted values only; there is no free-text query.
/// </summary>
/// <param name="AfterRecordId">Bookmark position: only records after it are returned.</param>
public sealed record WindowsEventQuery(
    string Channel,
    IReadOnlyList<int> EventIds,
    IReadOnlyList<string>? Providers,
    long AfterRecordId)
{
    public static WindowsEventQuery For(WindowsEventSubscriptionOptions subscription, long afterRecordId)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        ArgumentOutOfRangeException.ThrowIfNegative(afterRecordId);
        return new WindowsEventQuery(subscription.Channel, subscription.EventIds, subscription.Providers, afterRecordId);
    }

    /// <summary>
    /// Structured XPath subset accepted by <c>EvtQuery</c>, for example
    /// <c>*[System[(EventID=4624 or EventID=4625) and (Provider[@Name='Microsoft-Windows-Security-Auditing']) and (EventRecordID&gt;42)]]</c>.
    /// At most 21 expressions (16 IDs, 4 providers and the bookmark).
    /// </summary>
    public string ToXPath()
    {
        StringBuilder builder = new("*[System[(");
        builder.AppendJoin(" or ", EventIds.Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture)));
        builder.Append(')');
        if (Providers is { Count: > 0 })
        {
            // Names never contain quotes (validated), so a single-quoted literal is exact.
            builder.Append(" and (Provider[");
            builder.AppendJoin(" or ", Providers.Select(name => "@Name='" + name + "'"));
            builder.Append("])");
        }

        builder.Append(" and (EventRecordID>")
            .Append(AfterRecordId.ToString(CultureInfo.InvariantCulture))
            .Append(")]]");
        return builder.ToString();
    }

    /// <summary>The same filter as <see cref="ToXPath"/>, for in-memory test channels.</summary>
    public bool Matches(int eventId, string provider, long recordId) =>
        recordId > AfterRecordId
        && EventIds.Contains(eventId)
        && (Providers is not { Count: > 0 } || Providers.Contains(provider, StringComparer.OrdinalIgnoreCase));
}
