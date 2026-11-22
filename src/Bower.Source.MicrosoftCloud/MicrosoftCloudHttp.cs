using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Bower.Source.MicrosoftCloud;

/// <summary>
/// Access tokens for one input. Implementations keep tokens in memory only and never log
/// them. <paramref name="forceRefresh"/> is set once after a 401.
/// </summary>
public interface IMicrosoftCloudTokenProvider
{
    ValueTask<string> GetTokenAsync(
        MicrosoftCloudInputOptions input,
        string scope,
        bool forceRefresh,
        CancellationToken cancellationToken);
}

/// <summary>Stable, metadata-only failure codes. Never carry a body, URL query or token.</summary>
public static class MicrosoftCloudFailures
{
    /// <summary>403: the app registration lacks the permission or admin consent.</summary>
    public const string PermissionDenied = "mscloud-permission-denied";

    /// <summary>401 after one token refresh, or the token could not be acquired.</summary>
    public const string Unauthorised = "mscloud-unauthorised";

    /// <summary>429 or 5xx after every retry.</summary>
    public const string Throttled = "mscloud-throttled";
    public const string Unavailable = "mscloud-unavailable";

    /// <summary>Another 4xx (bad filter, expired page link, missing subscription).</summary>
    public const string RequestRefused = "mscloud-request-refused";

    /// <summary>A next link or content URI is not HTTPS on the host allow-listed for the input's kind.</summary>
    public const string HostRefused = "mscloud-host-refused";
    public const string RedirectRefused = "mscloud-redirect-refused";
    public const string ResponseTooLarge = "mscloud-response-too-large";
    public const string ResponseInvalid = "mscloud-response-invalid";
    public const string CursorInvalid = "mscloud-cursor-invalid";
    public const string CursorConflict = "mscloud-cursor-conflict";
    public const string SourceFailed = "mscloud-source-failed";
}

public sealed class MicrosoftCloudException(string code, HttpStatusCode? status = null, Exception? innerException = null)
    : Exception(status is null ? code : $"{code} (HTTP {(int)status})", innerException)
{
    public string Code { get; } = code;

    public HttpStatusCode? Status { get; } = status;
}

/// <summary>One response: the parsed JSON body and the headers callers may page with.</summary>
public sealed class MicrosoftCloudResponse(JsonDocument document, string? nextPageUri) : IDisposable
{
    public JsonDocument Document { get; } = document;

    /// <summary>The Office 365 Management Activity API's <c>NextPageUri</c> header, if any.</summary>
    public string? NextPageUri { get; } = nextPageUri;

    public void Dispose() => Document.Dispose();
}

/// <summary>Retry counters for status. Metadata only.</summary>
internal sealed class MicrosoftCloudRetryCounters
{
    public long Retries;
    public long Throttled;
}

/// <summary>
/// Bounded HTTPS client for Microsoft cloud APIs. A bearer token is only ever sent to the
/// one host the caller allow-lists, over HTTPS on the default port; redirects are refused
/// (the handler must not follow them). Responses are capped in size and JSON depth.
/// 429, 5xx and transport failures are retried with exponential backoff and full jitter,
/// honouring <c>Retry-After</c>. A 401 refreshes the token once. A 403 is never retried.
/// </summary>
public sealed class MicrosoftCloudHttp(
    HttpClient client,
    IMicrosoftCloudTokenProvider tokens,
    TimeProvider clock,
    Func<double>? jitter = null)
{
    public const int DefaultMaximumResponseBytes = 16 * 1024 * 1024;
    public const int MaximumUriLength = 4_096;

    private readonly Func<double> jitter = jitter ?? Random.Shared.NextDouble;

    public int MaximumAttempts { get; init; } = 6;

    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(1);

    public TimeSpan MaximumDelay { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Longest <c>Retry-After</c> honoured; a longer one fails the poll, which backs off itself.</summary>
    public TimeSpan MaximumRetryAfter { get; init; } = TimeSpan.FromMinutes(5);

    public int MaximumResponseBytes { get; init; } = DefaultMaximumResponseBytes;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, MicrosoftCloudRetryCounters> counters =
        new(StringComparer.Ordinal);

    /// <summary>Retry and throttle counts for one input (inputs share this client).</summary>
    internal MicrosoftCloudRetryCounters Counters(string inputId) => counters.GetOrAdd(inputId, static _ => new());

    /// <summary>True when <paramref name="uri"/> is HTTPS on <paramref name="host"/> at the default port.</summary>
    public static bool IsAllowed(Uri uri, string host) =>
        uri.IsAbsoluteUri
        && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
        && uri.IsDefaultPort
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.Equals(uri.IdnHost, host, StringComparison.OrdinalIgnoreCase)
        && uri.OriginalString.Length <= MaximumUriLength;

    public async Task<MicrosoftCloudResponse> SendAsync(
        HttpMethod method,
        Uri uri,
        MicrosoftCloudInputOptions input,
        string scope,
        string allowedHost,
        CancellationToken cancellationToken)
    {
        if (!IsAllowed(uri, allowedHost))
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.HostRefused);
        }

        MicrosoftCloudRetryCounters inputCounters = Counters(input.Id);
        bool refreshed = false;
        bool forceRefresh = false;
        for (int attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string token;
            try
            {
                token = await tokens.GetTokenAsync(input, scope, forceRefresh, cancellationToken);
                // Refresh exactly once after a 401, never on the retries that follow it.
                forceRefresh = false;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // The credential's own message can name files or claims; report the code only.
                throw new MicrosoftCloudException(MicrosoftCloudFailures.Unauthorised, innerException: null);
            }

            using HttpRequestMessage request = new(method, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (method == HttpMethod.Post)
            {
                request.Content = new ByteArrayContent([]);
            }

            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            }
            catch (Exception exception) when (IsTransport(exception, cancellationToken))
            {
                await RetryTransportAsync(attempt, inputCounters, cancellationToken);
                continue;
            }

            using (response)
            {
                HttpStatusCode status = response.StatusCode;
                if (status == HttpStatusCode.Unauthorized && !refreshed)
                {
                    refreshed = true;
                    forceRefresh = true;
                    continue;
                }

                if (status == HttpStatusCode.Unauthorized)
                {
                    throw new MicrosoftCloudException(MicrosoftCloudFailures.Unauthorised, status);
                }

                if (status == HttpStatusCode.Forbidden)
                {
                    throw new MicrosoftCloudException(MicrosoftCloudFailures.PermissionDenied, status);
                }

                if ((int)status is >= 300 and < 400)
                {
                    throw new MicrosoftCloudException(MicrosoftCloudFailures.RedirectRefused, status);
                }

                bool throttled = status == HttpStatusCode.TooManyRequests;
                if (throttled || IsTransient(status))
                {
                    if (throttled)
                    {
                        Interlocked.Increment(ref inputCounters.Throttled);
                    }

                    TimeSpan? retryAfter = RetryAfter(response.Headers.RetryAfter);
                    if (attempt >= MaximumAttempts || retryAfter > MaximumRetryAfter)
                    {
                        throw new MicrosoftCloudException(
                            throttled ? MicrosoftCloudFailures.Throttled : MicrosoftCloudFailures.Unavailable, status);
                    }

                    Interlocked.Increment(ref inputCounters.Retries);
                    // A zero or past Retry-After falls back to jittered backoff, never a burst.
                    await WaitAsync(retryAfter is { } after && after > TimeSpan.Zero ? after : Backoff(attempt), cancellationToken);
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    throw new MicrosoftCloudException(MicrosoftCloudFailures.RequestRefused, status);
                }

                string? nextPage = response.Headers.TryGetValues("NextPageUri", out IEnumerable<string>? values)
                    ? values.FirstOrDefault()
                    : null;
                JsonDocument document;
                try
                {
                    // Headers arrived; the body can still fail in transit. Retry that the same way.
                    document = await ReadJsonAsync(response, cancellationToken);
                }
                catch (Exception exception) when (IsTransport(exception, cancellationToken))
                {
                    await RetryTransportAsync(attempt, inputCounters, cancellationToken);
                    continue;
                }

                return new MicrosoftCloudResponse(document, nextPage);
            }
        }
    }

    private static bool IsTransport(Exception exception, CancellationToken cancellationToken) =>
        exception is HttpRequestException or IOException
            || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested);

    private async Task RetryTransportAsync(int attempt, MicrosoftCloudRetryCounters inputCounters, CancellationToken cancellationToken)
    {
        if (attempt >= MaximumAttempts)
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.Unavailable);
        }

        Interlocked.Increment(ref inputCounters.Retries);
        await WaitAsync(Backoff(attempt), cancellationToken);
    }

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout or HttpStatusCode.RequestTimeout;

    private TimeSpan? RetryAfter(RetryConditionHeaderValue? header)
    {
        if (header?.Delta is { } delta)
        {
            return delta < TimeSpan.Zero ? TimeSpan.Zero : delta;
        }

        if (header?.Date is { } date)
        {
            TimeSpan wait = date - clock.GetUtcNow();
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait;
        }

        return null;
    }

    /// <summary>Full jitter: a uniform wait between zero and the capped exponential delay.</summary>
    internal TimeSpan Backoff(int attempt)
    {
        double ceiling = Math.Min(MaximumDelay.Ticks, BaseDelay.Ticks * Math.Pow(2, Math.Min(attempt - 1, 16)));
        return TimeSpan.FromTicks((long)(ceiling * Math.Clamp(jitter(), 0, 1)));
    }

    private Task WaitAsync(TimeSpan wait, CancellationToken cancellationToken) =>
        wait <= TimeSpan.Zero ? Task.CompletedTask : Task.Delay(wait, clock, cancellationToken);

    private async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseTooLarge, response.StatusCode);
        }

        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream buffer = new();
        byte[] chunk = new byte[81_920];
        int read;
        while (true)
        {
            try
            {
                read = await stream.ReadAsync(chunk, cancellationToken);
            }
            catch (InvalidDataException)
            {
                // Corrupt gzip or deflate content.
                throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseInvalid, response.StatusCode);
            }

            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaximumResponseBytes)
            {
                throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseTooLarge, response.StatusCode);
            }

            buffer.Write(chunk, 0, read);
        }

        try
        {
            return JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length), new JsonDocumentOptions { MaxDepth = 32 });
        }
        catch (JsonException)
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseInvalid, response.StatusCode);
        }
    }

    internal static string Escape(string value) => Uri.EscapeDataString(value);

    internal static string Time(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'", CultureInfo.InvariantCulture);
}
