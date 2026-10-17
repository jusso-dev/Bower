using System.Text.Json;
using System.Text.RegularExpressions;

namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>
/// HTTP for credential flows. Redirects are never followed, every body is read with a
/// hard size limit, and error bodies are never surfaced (only the status and a short OAuth
/// error code). Metadata endpoints (link-local or loopback, plain HTTP) go through a
/// handler without a proxy so instance tokens never cross a forward proxy.
/// </summary>
internal sealed partial class GoogleAuthHttp : IDisposable
{
    /// <summary>Token, metadata and credential-file responses are small; STS tokens are at most 12 KiB.</summary>
    public const int MaximumResponseBytes = 64 * 1024;

    /// <summary>Subject tokens (OIDC JWTs, SAML assertions) can be larger than access tokens.</summary>
    public const int MaximumSubjectTokenBytes = 256 * 1024;

    private readonly HttpClient metadata;
    private readonly HttpClient web;

    public GoogleAuthHttp(HttpMessageHandler metadataHandler, HttpMessageHandler webHandler, bool disposeHandlers)
    {
        metadata = new HttpClient(metadataHandler, disposeHandlers) { Timeout = TimeSpan.FromSeconds(10) };
        web = new HttpClient(webHandler, disposeHandlers) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public static GoogleAuthHttp CreateDefault() =>
        new(
            new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, UseCookies = false },
            new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false },
            disposeHandlers: true);

    /// <summary>
    /// Sends a request and returns the bounded body of a 2xx response. Plain HTTP is only
    /// allowed for metadata (link-local) and loopback hosts.
    /// </summary>
    public async Task<HttpResult> SendAsync(
        HttpRequestMessage request,
        string operation,
        int maximumBytes,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        Uri url = request.RequestUri ?? throw new InvalidOperationException($"{operation}: no request URL.");
        bool local = IsMetadataOrLoopback(url);
        if (url.Scheme != Uri.UriSchemeHttps && !(url.Scheme == Uri.UriSchemeHttp && local))
        {
            throw new InvalidOperationException($"{operation}: HTTPS is required for {url.Host}.");
        }

        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout is { } bound)
        {
            limit.CancelAfter(bound);
        }

        HttpClient client = local ? metadata : web;
        using HttpResponseMessage response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            limit.Token);
        byte[] body = await ReadBoundedAsync(response.Content, maximumBytes, operation, limit.Token);
        if (!response.IsSuccessStatusCode)
        {
            // Never echo the body: OAuth errors can quote subject tokens or assertions.
            string? code = ErrorCode(body);
            throw new HttpRequestException(
                $"{operation} returned {(int)response.StatusCode}{(code is null ? string.Empty : $" ({code})")}.",
                null,
                response.StatusCode);
        }

        return new HttpResult(response.Headers, body);
    }

    public void Dispose()
    {
        metadata.Dispose();
        web.Dispose();
    }

    /// <summary>The metadata servers (GCE, AWS IMDS, Azure IMDS) and loopback.</summary>
    internal static bool IsMetadataOrLoopback(Uri url) => url.IsLoopback || IsMetadataHost(url);

    /// <summary>The well-known metadata server names and addresses.</summary>
    internal static bool IsMetadataHost(Uri url) =>
        url.DnsSafeHost is "metadata.google.internal" or "169.254.169.254" or "fd00:ec2::254";

    internal static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        string operation,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is long declared && declared > maximumBytes)
        {
            throw new InvalidOperationException($"{operation}: response exceeds {maximumBytes} bytes.");
        }

        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream buffer = new();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maximumBytes)
            {
                throw new InvalidOperationException($"{operation}: response exceeds {maximumBytes} bytes.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>The RFC 6749 <c>error</c> code only, when it is a short token.</summary>
    private static string? ErrorCode(byte[] body)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            JsonElement error = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("error", out JsonElement value)
                ? value
                : default;
            // Google APIs nest {"error":{"status":"PERMISSION_DENIED"}}; OAuth uses {"error":"invalid_grant"}.
            string? code = error.ValueKind switch
            {
                JsonValueKind.String => error.GetString(),
                JsonValueKind.Object when error.TryGetProperty("status", out JsonElement status)
                    && status.ValueKind == JsonValueKind.String => status.GetString(),
                _ => null
            };
            return code is not null && ErrorCodePattern().IsMatch(code) ? code : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    [GeneratedRegex("^[A-Za-z_]{1,64}$")]
    private static partial Regex ErrorCodePattern();
}

internal sealed record HttpResult(System.Net.Http.Headers.HttpResponseHeaders Headers, byte[] Body);
