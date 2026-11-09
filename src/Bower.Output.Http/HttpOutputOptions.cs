using System.Globalization;
using System.Net;

namespace Bower.Output.Http;

/// <summary>Request body format of the HTTP output (BOWER_HTTP_FORMAT).</summary>
public enum HttpOutputFormat
{
    /// <summary>Splunk HTTP Event Collector event envelopes, <c>Authorization: Splunk &lt;token&gt;</c>.</summary>
    SplunkHec,

    /// <summary>One Bower event per line (<c>application/x-ndjson</c>), bearer token or a named header.</summary>
    Ndjson
}

/// <summary>
/// Non-secret settings of <see cref="HttpOutput"/>. The token is passed separately and never
/// held here, so this record can be printed, hashed or compared safely. Messages name the
/// collector variables because the collector is the only host.
/// </summary>
public sealed record HttpOutputOptions
{
    public const string DefaultSourceType = "bower:security";
    public const string DefaultSource = "bower";
    public const int DefaultMaximumBatchBytes = 1_000_000;
    public const int DefaultMaximumBatchEvents = 500;
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    public string Id { get; init; } = HttpOutput.OutputId;

    /// <summary>BOWER_HTTP_URL: the full request URL, for example <c>https://splunk:8088/services/collector/event</c>.</summary>
    public required Uri Endpoint { get; init; }

    public HttpOutputFormat Format { get; init; } = HttpOutputFormat.SplunkHec;

    /// <summary>BOWER_HTTP_ALLOW_INSECURE_LOOPBACK: permits <c>http://</c> to a loopback host only.</summary>
    public bool AllowInsecureLoopback { get; init; }

    /// <summary>
    /// BOWER_HTTP_AUTH_HEADER (ndjson only). Null or <c>Authorization</c> sends
    /// <c>Authorization: Bearer &lt;token&gt;</c>; any other name carries the token as is.
    /// </summary>
    public string? AuthorizationHeader { get; init; }

    /// <summary>BOWER_HTTP_CA_BUNDLE: PEM roots added to the system roots. Verification stays on.</summary>
    public string? CaBundlePath { get; init; }

    /// <summary>BOWER_HTTP_HEC_INDEX; omitted from events when null (the token's default index).</summary>
    public string? HecIndex { get; init; }

    public string HecSourceType { get; init; } = DefaultSourceType;

    public string HecSource { get; init; } = DefaultSource;

    /// <summary>BOWER_HTTP_HEC_HOST; the collector id when unset.</summary>
    public required string HecHost { get; init; }

    /// <summary>BOWER_HTTP_HEC_CHANNEL: sent as <c>X-Splunk-Request-Channel</c>.</summary>
    public string? HecChannel { get; init; }

    /// <summary>Uncompressed request body cap, newlines included (HEC's default limit is 1 MB).</summary>
    public int MaximumBatchBytes { get; init; } = DefaultMaximumBatchBytes;

    public int MaximumBatchEvents { get; init; } = DefaultMaximumBatchEvents;

    /// <summary>One request, from connect to the end of the bounded response read.</summary>
    public TimeSpan Timeout { get; init; } = DefaultTimeout;

    public bool Gzip { get; init; }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
        ArgumentNullException.ThrowIfNull(Endpoint);
        if (!IsValidEndpoint(Endpoint, AllowInsecureLoopback))
        {
            throw new InvalidOperationException(
                "BOWER_HTTP_URL must be an absolute https:// URL with a host and no credentials, query or " +
                "fragment; http:// is allowed only to a loopback IP address (127.0.0.0/8 or ::1) with " +
                "BOWER_HTTP_ALLOW_INSECURE_LOOPBACK=true.");
        }

        if (Format == HttpOutputFormat.SplunkHec && AuthorizationHeader is not null)
        {
            throw new InvalidOperationException(
                "BOWER_HTTP_AUTH_HEADER applies to BOWER_HTTP_FORMAT=ndjson only; Splunk HEC uses Authorization: Splunk.");
        }

        if (AuthorizationHeader is not null && !IsAllowedHeaderName(AuthorizationHeader))
        {
            throw new InvalidOperationException(
                "BOWER_HTTP_AUTH_HEADER must be an HTTP header name (letters, digits and !#$%&'*+-.^_`|~, at most " +
                "64 characters) other than a connection, content or proxy header.");
        }

        if (HecIndex is not null && !IsIndexName(HecIndex))
        {
            throw new InvalidOperationException(
                "BOWER_HTTP_HEC_INDEX must be 1 to 80 lowercase letters, digits, '_' or '-', starting with a letter or digit.");
        }

        RequireMetadata(HecSourceType, "BOWER_HTTP_HEC_SOURCETYPE");
        RequireMetadata(HecSource, "BOWER_HTTP_HEC_SOURCE");
        RequireMetadata(HecHost, "BOWER_HTTP_HEC_HOST");
        if (HecChannel is not null && !IsChannel(HecChannel))
        {
            throw new InvalidOperationException(
                "BOWER_HTTP_HEC_CHANNEL must be a GUID in 8-4-4-4-12 hexadecimal form.");
        }

        Range(MaximumBatchBytes, 1_024, 16 * 1024 * 1024, "BOWER_HTTP_MAX_BATCH_BYTES");
        Range(MaximumBatchEvents, 1, 10_000, "BOWER_HTTP_MAX_BATCH_EVENTS");
        if (Timeout < TimeSpan.FromSeconds(1) || Timeout > TimeSpan.FromSeconds(300))
        {
            throw new InvalidOperationException("BOWER_HTTP_TIMEOUT_SECONDS must be between 1 and 300.");
        }
    }

    /// <summary>
    /// HTTPS with a host and no credentials, query or fragment (a query could carry a token,
    /// and the URL is hashed and shown). <c>http://</c> only to loopback, and only when allowed.
    /// </summary>
    public static bool IsValidEndpoint(Uri endpoint, bool allowInsecureLoopback)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || string.IsNullOrEmpty(endpoint.Host) || !string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            return false;
        }

        return endpoint.Scheme == Uri.UriSchemeHttps
            || (endpoint.Scheme == Uri.UriSchemeHttp && allowInsecureLoopback && IsLoopbackAddress(endpoint.Host));
    }

    /// <summary>
    /// A loopback IP literal: 127.0.0.0/8 or ::1 (brackets trimmed). Never a name such as
    /// <c>localhost</c>, which resolution or a hosts file could send elsewhere.
    /// </summary>
    public static bool IsLoopbackAddress(string host) =>
        IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? address)
        && (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? address.GetAddressBytes()[0] == 127
            : address.Equals(IPAddress.IPv6Loopback));

    /// <summary>A token of printable ASCII without spaces, at most 4096 characters.</summary>
    public static bool IsValidToken(string? token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 4096)
        {
            return false;
        }

        foreach (char c in token)
        {
            if (c is < '!' or > '~')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Header names that cannot carry the token: hop-by-hop and framing headers, proxy
    /// credentials, content headers (.NET refuses them on request headers) and
    /// response-only headers. Pinned by the vectors.
    /// </summary>
    public static IReadOnlyList<string> ReservedHeaders { get; } =
    [
        "host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer",
        "upgrade", "expect", "proxy-authorization", "proxy-authenticate",
        "allow", "content-disposition", "content-encoding", "content-language", "content-length",
        "content-location", "content-md5", "content-range", "content-type", "expires", "last-modified",
        "accept-ranges", "age", "etag", "location", "retry-after", "server", "vary", "www-authenticate"
    ];

    /// <summary>Whether BOWER_HTTP_AUTH_HEADER may name this header.</summary>
    public static bool IsAllowedHeaderName(string name)
    {
        if (name.Length is < 1 or > 64 || ReservedHeaders.Contains(name.ToLowerInvariant(), StringComparer.Ordinal))
        {
            return false;
        }

        foreach (char c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsIndexName(string index)
    {
        if (index.Length is < 1 or > 80 || !(char.IsAsciiLetterLower(index[0]) || char.IsAsciiDigit(index[0])))
        {
            return false;
        }

        foreach (char c in index)
        {
            if (!(char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '_' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsChannel(string channel)
    {
        if (channel.Length != 36)
        {
            return false;
        }

        for (int index = 0; index < channel.Length; index++)
        {
            bool valid = index is 8 or 13 or 18 or 23 ? channel[index] == '-' : char.IsAsciiHexDigit(channel[index]);
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    private static void RequireMetadata(string value, string name)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 256 || value.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{name} must be 1 to 256 characters without control characters.");
        }
    }

    private static void Range(long value, long minimum, long maximum, string name)
    {
        if (value < minimum || value > maximum)
        {
            throw new InvalidOperationException(
                string.Create(CultureInfo.InvariantCulture, $"{name} must be between {minimum} and {maximum}."));
        }
    }
}
