using Bower.Contracts;

namespace Bower.Forwarding;

/// <summary>
/// The <c>X-Bower-Origin</c> request header: where a forwarded event came from, reported by a
/// producer the operator trusts (<c>BOWER_ORIGIN_PRODUCERS</c>), never read from the event
/// itself (#228, #253). Format: <c>cloudwatch-logs; logGroup=&lt;group&gt;; logStream=&lt;stream&gt;</c>,
/// each value percent-encoded. Anything else, or any header from an untrusted producer, is
/// ignored: the event is still accepted, just without an origin.
/// </summary>
public static class OriginHeader
{
    public const string Name = "X-Bower-Origin";

    public const string CloudWatchLogs = "cloudwatch-logs";

    /// <summary>CloudWatch Logs limits: log group names 512 characters, stream names 512.</summary>
    public const int MaximumValueLength = 512;

    /// <summary>The header value for a CloudWatch Logs log group and stream.</summary>
    public static string Format(string logGroup, string logStream)
    {
        ArgumentException.ThrowIfNullOrEmpty(logGroup);
        ArgumentException.ThrowIfNullOrEmpty(logStream);
        return $"{CloudWatchLogs}; logGroup={Uri.EscapeDataString(logGroup)}; logStream={Uri.EscapeDataString(logStream)}";
    }

    /// <summary>The origin from a trusted producer's header, or null.</summary>
    public static EventOrigin? Read(string? value, string producer, IReadOnlyList<string> trustedProducers)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 2 * MaximumValueLength * 3 + 64
            || !trustedProducers.Contains(producer, StringComparer.Ordinal))
        {
            return null;
        }

        string[] parts = value.Split(';', StringSplitOptions.TrimEntries);
        if (parts.Length != 3 || parts[0] != CloudWatchLogs)
        {
            return null;
        }

        string? group = Field(parts[1], "logGroup");
        string? stream = Field(parts[2], "logStream");
        return group is null || stream is null
            ? null
            : new EventOrigin { Kind = CloudWatchLogs, LogGroup = group, LogStream = stream };
    }

    private static string? Field(string part, string name)
    {
        if (!part.StartsWith(name + "=", StringComparison.Ordinal))
        {
            return null;
        }

        string decoded;
        try
        {
            decoded = Uri.UnescapeDataString(part[(name.Length + 1)..]);
        }
        catch (UriFormatException)
        {
            return null;
        }

        // No control characters, bounded as CloudWatch bounds them.
        return decoded.Length is < 1 or > MaximumValueLength || decoded.Any(char.IsControl) ? null : decoded;
    }
}
