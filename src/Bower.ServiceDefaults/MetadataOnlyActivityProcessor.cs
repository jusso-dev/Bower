using System.Diagnostics;
using OpenTelemetry;

namespace Bower.ServiceDefaults;

/// <summary>
/// Reduces every span to approved metadata before it reaches the exporter. ASP.NET Core and
/// HttpClient add request-derived attributes (user agent, client address, full URL and query
/// string, host header); only the allowlisted attributes below are kept, and the status
/// description (which can carry exception text) is cleared.
/// </summary>
public sealed class MetadataOnlyActivityProcessor : BaseProcessor<Activity>
{
    /// <summary>Attributes that may be exported: route templates, methods and status only.</summary>
    public static IReadOnlySet<string> AllowedTags { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "http.request.method",
        "http.route",
        "http.response.status_code",
        "url.scheme",
        "network.protocol.version",
        "error.type"
    };

    public override void OnEnd(Activity data)
    {
        ArgumentNullException.ThrowIfNull(data);
        // Copy the names first: setting a tag to null removes it from the live collection.
        foreach (string name in data.TagObjects.Select(tag => tag.Key).ToArray())
        {
            if (!AllowedTags.Contains(name))
            {
                data.SetTag(name, null);
            }
        }

        if (data.StatusDescription is not null)
        {
            data.SetStatus(data.Status);
        }
    }
}
