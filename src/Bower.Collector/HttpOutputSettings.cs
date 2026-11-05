using System.Globalization;
using Bower.Output.Http;

namespace Bower.Collector;

/// <summary>
/// BOWER_HTTP_* settings of the HTTP output (BOWER_OUTPUT=http). A class, not a record, so
/// the token read from BOWER_HTTP_TOKEN is never printed with the settings; it is never
/// hashed, logged or reported either. The token file is read when the output is created.
/// </summary>
public sealed class HttpOutputSettings
{
    private string? environmentToken;

    public required Uri? Endpoint { get; init; }

    /// <summary>BOWER_HTTP_FORMAT: <c>splunk-hec</c> (default) or <c>ndjson</c>.</summary>
    public string Format { get; init; } = "splunk-hec";

    /// <summary>BOWER_HTTP_TOKEN_FILE: file holding the token (preferred). Never logged.</summary>
    public string? TokenFile { get; init; }

    /// <summary>BOWER_HTTP_TOKEN is set (its value stays private).</summary>
    public bool HasEnvironmentToken => environmentToken is not null;

    public string? AuthorizationHeader { get; init; }

    public string? CaBundle { get; init; }

    public bool AllowInsecureLoopback { get; init; }

    public string? HecIndex { get; init; }

    public string? HecSourceType { get; init; }

    public string? HecSource { get; init; }

    public string? HecHost { get; init; }

    public string? HecChannel { get; init; }

    public int MaximumBatchBytes { get; init; } = HttpOutputOptions.DefaultMaximumBatchBytes;

    public int MaximumBatchEvents { get; init; } = HttpOutputOptions.DefaultMaximumBatchEvents;

    public int TimeoutSeconds { get; init; } = (int)HttpOutputOptions.DefaultTimeout.TotalSeconds;

    public bool Gzip { get; init; }

    /// <summary>Sets the BOWER_HTTP_TOKEN value (tests and <see cref="FromEnvironment"/>).</summary>
    public HttpOutputSettings WithEnvironmentToken(string? token)
    {
        environmentToken = string.IsNullOrWhiteSpace(token) ? null : token.Trim();
        return this;
    }

    /// <summary>Null when no BOWER_HTTP_* variable is set.</summary>
    public static HttpOutputSettings? FromEnvironment(Func<string, string?> read)
    {
        ArgumentNullException.ThrowIfNull(read);
        string[] names =
        [
            "BOWER_HTTP_URL", "BOWER_HTTP_FORMAT", "BOWER_HTTP_TOKEN_FILE", "BOWER_HTTP_TOKEN", "BOWER_HTTP_AUTH_HEADER",
            "BOWER_HTTP_CA_BUNDLE", "BOWER_HTTP_ALLOW_INSECURE_LOOPBACK", "BOWER_HTTP_HEC_INDEX",
            "BOWER_HTTP_HEC_SOURCETYPE", "BOWER_HTTP_HEC_SOURCE", "BOWER_HTTP_HEC_HOST", "BOWER_HTTP_HEC_CHANNEL",
            "BOWER_HTTP_MAX_BATCH_BYTES", "BOWER_HTTP_MAX_BATCH_EVENTS", "BOWER_HTTP_TIMEOUT_SECONDS", "BOWER_HTTP_GZIP"
        ];
        if (names.All(name => Blank(read(name)) is null))
        {
            return null;
        }

        string? url = Blank(read("BOWER_HTTP_URL"));
        return new HttpOutputSettings
        {
            // The value is never echoed: a mistyped URL may hold a credential.
            Endpoint = url is null ? null : Uri.TryCreate(url.Trim(), UriKind.Absolute, out Uri? endpoint)
                ? endpoint
                : throw new InvalidOperationException("BOWER_HTTP_URL must be an absolute https:// URL."),
            Format = Blank(read("BOWER_HTTP_FORMAT"))?.Trim().ToLowerInvariant() ?? "splunk-hec",
            TokenFile = Blank(read("BOWER_HTTP_TOKEN_FILE")),
            AuthorizationHeader = Blank(read("BOWER_HTTP_AUTH_HEADER"))?.Trim(),
            CaBundle = Blank(read("BOWER_HTTP_CA_BUNDLE")),
            AllowInsecureLoopback = ReadBoolean(read, "BOWER_HTTP_ALLOW_INSECURE_LOOPBACK"),
            HecIndex = Blank(read("BOWER_HTTP_HEC_INDEX"))?.Trim(),
            HecSourceType = Blank(read("BOWER_HTTP_HEC_SOURCETYPE"))?.Trim(),
            HecSource = Blank(read("BOWER_HTTP_HEC_SOURCE"))?.Trim(),
            HecHost = Blank(read("BOWER_HTTP_HEC_HOST"))?.Trim(),
            HecChannel = Blank(read("BOWER_HTTP_HEC_CHANNEL"))?.Trim(),
            MaximumBatchBytes = ReadInt32(read, "BOWER_HTTP_MAX_BATCH_BYTES", HttpOutputOptions.DefaultMaximumBatchBytes),
            MaximumBatchEvents = ReadInt32(read, "BOWER_HTTP_MAX_BATCH_EVENTS", HttpOutputOptions.DefaultMaximumBatchEvents),
            TimeoutSeconds = ReadInt32(read, "BOWER_HTTP_TIMEOUT_SECONDS", (int)HttpOutputOptions.DefaultTimeout.TotalSeconds),
            Gzip = ReadBoolean(read, "BOWER_HTTP_GZIP")
        }.WithEnvironmentToken(read("BOWER_HTTP_TOKEN"));
    }

    /// <summary>
    /// BOWER_OUTPUT=http needs these settings; any other output refuses them, so a
    /// half-configured HTTP output never goes unnoticed.
    /// </summary>
    public static void Validate(string outputType, HttpOutputSettings? settings, string collectorId)
    {
        bool httpOutput = string.Equals(outputType, HttpOutput.OutputId, StringComparison.Ordinal);
        if (settings is null)
        {
            if (httpOutput)
            {
                throw new InvalidOperationException(
                    "BOWER_OUTPUT=http requires BOWER_HTTP_URL and BOWER_HTTP_TOKEN_FILE (or BOWER_HTTP_TOKEN).");
            }

            return;
        }

        if (!httpOutput)
        {
            throw new InvalidOperationException("BOWER_HTTP_* settings require BOWER_OUTPUT=http.");
        }

        if (settings.Endpoint is null)
        {
            throw new InvalidOperationException("BOWER_OUTPUT=http requires BOWER_HTTP_URL.");
        }

        if (settings.TokenFile is not null == settings.HasEnvironmentToken)
        {
            throw new InvalidOperationException(
                "BOWER_OUTPUT=http requires exactly one of BOWER_HTTP_TOKEN_FILE (preferred) or BOWER_HTTP_TOKEN.");
        }

        if (settings.Format is not ("splunk-hec" or "ndjson"))
        {
            throw new InvalidOperationException("BOWER_HTTP_FORMAT must be splunk-hec or ndjson.");
        }

        if (settings.Format == "ndjson" && (settings.HecIndex ?? settings.HecSourceType ?? settings.HecSource
            ?? settings.HecHost ?? settings.HecChannel) is not null)
        {
            throw new InvalidOperationException("BOWER_HTTP_HEC_* settings require BOWER_HTTP_FORMAT=splunk-hec.");
        }

        settings.Options(collectorId).Validate();
    }

    /// <summary>The output options; HEC host defaults to the collector id.</summary>
    public HttpOutputOptions Options(string collectorId) => new()
    {
        Endpoint = Endpoint ?? throw new InvalidOperationException("BOWER_OUTPUT=http requires BOWER_HTTP_URL."),
        Format = Format == "ndjson" ? HttpOutputFormat.Ndjson : HttpOutputFormat.SplunkHec,
        AllowInsecureLoopback = AllowInsecureLoopback,
        AuthorizationHeader = AuthorizationHeader,
        CaBundlePath = CaBundle,
        HecIndex = HecIndex,
        HecSourceType = HecSourceType ?? HttpOutputOptions.DefaultSourceType,
        HecSource = HecSource ?? HttpOutputOptions.DefaultSource,
        HecHost = HecHost ?? collectorId,
        HecChannel = HecChannel,
        MaximumBatchBytes = MaximumBatchBytes,
        MaximumBatchEvents = MaximumBatchEvents,
        Timeout = TimeSpan.FromSeconds(TimeoutSeconds),
        Gzip = Gzip
    };

    /// <summary>
    /// Reads the token: the file (a trailing newline from <c>echo</c> or a secret mount is
    /// not part of it) or BOWER_HTTP_TOKEN. Messages never include the value.
    /// </summary>
    public string ReadToken()
    {
        if (TokenFile is null)
        {
            return environmentToken ?? throw new InvalidOperationException(
                "BOWER_OUTPUT=http requires exactly one of BOWER_HTTP_TOKEN_FILE (preferred) or BOWER_HTTP_TOKEN.");
        }

        try
        {
            return File.ReadAllText(TokenFile).Trim();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException("BOWER_HTTP_TOKEN_FILE must name a readable file.");
        }
    }

    /// <summary>
    /// Configuration hash material: endpoint scheme, host, port and path, format, where the
    /// token comes from (never the token or a digest of it), and the remaining settings.
    /// </summary>
    public string HashMaterial()
    {
        string endpoint = Endpoint is null
            ? string.Empty
            : Endpoint.Scheme + "://" + Endpoint.Host + ":" + Endpoint.Port.ToString(CultureInfo.InvariantCulture) + Endpoint.AbsolutePath;
        return string.Join(
            '\u001f',
            "http-url:" + endpoint,
            "http-format:" + Format,
            "http-token:" + (TokenFile is not null ? "file:" + TokenFile : HasEnvironmentToken ? "environment" : "none"),
            "http-auth-header:" + (AuthorizationHeader ?? string.Empty),
            "http-ca:" + (CaBundle ?? string.Empty),
            "http-hec:" + string.Join(',', HecIndex ?? string.Empty, HecSourceType ?? string.Empty,
                HecSource ?? string.Empty, HecHost ?? string.Empty, HecChannel ?? string.Empty),
            "http-limits:" + string.Join(',',
                MaximumBatchBytes.ToString(CultureInfo.InvariantCulture),
                MaximumBatchEvents.ToString(CultureInfo.InvariantCulture),
                TimeoutSeconds.ToString(CultureInfo.InvariantCulture),
                Gzip.ToString(),
                AllowInsecureLoopback.ToString()));
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static bool ReadBoolean(Func<string, string?> read, string name) =>
        Blank(read(name))?.Trim().ToLowerInvariant() switch
        {
            null or "false" => false,
            "true" => true,
            _ => throw new InvalidOperationException($"{name} must be true or false.")
        };

    private static int ReadInt32(Func<string, string?> read, string name, int fallback)
    {
        string? value = Blank(read(name));
        if (value is null)
        {
            return fallback;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : throw new InvalidOperationException($"{name} must be an integer.");
    }
}
