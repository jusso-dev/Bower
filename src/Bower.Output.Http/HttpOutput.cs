using System.Buffers;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Bower.Abstractions;

namespace Bower.Output.Http;

/// <summary>
/// Output to Splunk HTTP Event Collector or a generic NDJSON endpoint (BOWER_OUTPUT=http).
/// Posts leased events, already redacted and decided, in bounded batches, one at a time. An
/// event is acknowledged only when the endpoint accepted its request (2xx, and for HEC a
/// <c>code</c> of 0): that is acceptance by the endpoint, not Sentinel delivery and not
/// proof of indexing. Everything else stays in the queue or is dead-lettered with a bounded
/// code. The token is held in memory only and never appears in failures or logs.
/// </summary>
public sealed partial class HttpOutput : IOutputAdapter, IDisposable
{
    public const string OutputId = "http";

    /// <summary>Largest response body read (HEC replies are a few dozen bytes).</summary>
    public const int MaximumResponseBytes = 64 * 1024;

    /// <summary>413 splits per delivery, so a hostile endpoint cannot multiply requests.</summary>
    public const int SplitBudget = 16;

    public const string SplunkHecContentType = "application/json; charset=utf-8";
    public const string NdjsonContentType = "application/x-ndjson; charset=utf-8";
    public const string ChannelHeader = "X-Splunk-Request-Channel";

    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";
    private static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromHours(1);
    private static readonly DateTimeOffset MinimumEventTime = DateTimeOffset.UnixEpoch;

    private readonly HttpOutputOptions options;
    private readonly HttpClient client;
    private readonly TimeProvider time;
    private readonly string authorizationName;
    private readonly string authorizationValue;
    private readonly byte[] hecMetadata;

    /// <param name="token">The endpoint token (BOWER_HTTP_TOKEN_FILE or BOWER_HTTP_TOKEN). Kept in memory only.</param>
    /// <param name="handler">Test seam; production builds a handler with the TLS policy of <paramref name="options"/>.</param>
    public HttpOutput(HttpOutputOptions options, string token, HttpMessageHandler? handler = null, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (!HttpOutputOptions.IsValidToken(token))
        {
            // Never echo the value.
            throw new InvalidOperationException(
                "The HTTP output token (BOWER_HTTP_TOKEN_FILE or BOWER_HTTP_TOKEN) must be 1 to 4096 printable " +
                "ASCII characters without spaces.");
        }

        this.options = options;
        time = clock ?? TimeProvider.System;
        (authorizationName, authorizationValue) = options.Format == HttpOutputFormat.SplunkHec
            ? ("Authorization", "Splunk " + token)
            : options.AuthorizationHeader is null
                || string.Equals(options.AuthorizationHeader, "Authorization", StringComparison.OrdinalIgnoreCase)
                ? ("Authorization", "Bearer " + token)
                : (options.AuthorizationHeader, token);
        hecMetadata = HecMetadata(options);
        client = new HttpClient(handler ?? CreateHandler(options)) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
    }

    public string Id => options.Id;

    /// <summary>Queue acknowledgement text: acceptance by the endpoint, nothing more.</summary>
    public string Acknowledgement => options.Format == HttpOutputFormat.SplunkHec
        ? "http:splunk-hec:endpoint-accepted"
        : "http:ndjson:endpoint-accepted";

    public void Dispose() => client.Dispose();

    public async Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);
        List<DeliveryFailure> failures = [];
        List<List<Record>> pending = [];
        List<Record> current = [];
        int bytes = 0;
        foreach (QueuedEvent item in events)
        {
            byte[]? record = Encode(item, out string? poison);
            if (record is null)
            {
                // Never succeeds anywhere: dead-letter it alone, as the other outputs do.
                failures.Add(new DeliveryFailure(item.EventId, poison!, false, null));
                continue;
            }

            if (record.Length > options.MaximumBatchBytes)
            {
                failures.Add(new DeliveryFailure(item.EventId, "payload-too-large", false, null));
                continue;
            }

            if (current.Count > 0
                && (current.Count == options.MaximumBatchEvents || bytes + record.Length > options.MaximumBatchBytes))
            {
                pending.Add(current);
                current = [];
                bytes = 0;
            }

            current.Add(new Record(item.EventId, record));
            bytes += record.Length;
        }

        if (current.Count > 0)
        {
            pending.Add(current);
        }

        List<string> acknowledged = [];
        int splits = SplitBudget;
        for (int index = 0; index < pending.Count; index++)
        {
            List<Record> batch = pending[index];
            (int Status, DeliveryFailure? Failure) outcome;
            try
            {
                outcome = await SendAsync(batch, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested && acknowledged.Count > 0)
            {
                // Keep the acknowledged batches; never replay known acceptances.
                foreach (Record record in pending.Skip(index).SelectMany(item => item))
                {
                    failures.Add(new DeliveryFailure(record.EventId, "destination-http-cancelled", true, null));
                }

                break;
            }

            if (outcome.Failure is null)
            {
                acknowledged.AddRange(batch.Select(record => record.EventId));
                continue;
            }

            if (outcome.Status == 413 && batch.Count > 1 && splits > 0)
            {
                // Too large for this endpoint: send the halves in order instead.
                splits--;
                int middle = batch.Count / 2;
                pending.Insert(index + 1, batch.GetRange(0, middle));
                pending.Insert(index + 2, batch.GetRange(middle, batch.Count - middle));
                continue;
            }

            // A multi-record 413 past the split budget retries (and splits again) next time;
            // only a single record the endpoint refuses as too large is dead-lettered.
            DeliveryFailure failure = outcome.Status == 413 && batch.Count > 1
                ? outcome.Failure with { IsRetryable = true }
                : outcome.Failure;
            foreach (Record record in batch)
            {
                failures.Add(failure with { EventId = record.EventId });
            }

            if (failure.IsDestinationFailure)
            {
                // The endpoint is unavailable or refuses this collector: keep the rest queued
                // behind the destination circuit instead of sending them into the same failure.
                foreach (Record record in pending.Skip(index + 1).SelectMany(item => item))
                {
                    failures.Add(failure with { EventId = record.EventId });
                }

                break;
            }
        }

        return new DeliveryResult(acknowledged, failures, acknowledged.Count == 0 ? null : Acknowledgement);
    }

    /// <summary>
    /// The request body of one batch: every record followed by a newline. Public for the
    /// shared request vectors.
    /// </summary>
    public static byte[] Join(IEnumerable<byte[]> records)
    {
        using MemoryStream body = new();
        foreach (byte[] record in records)
        {
            body.Write(record);
            body.WriteByte((byte)'\n');
        }

        return body.ToArray();
    }

    /// <summary>
    /// One record without its newline, or null with a poison code. The payload is embedded
    /// as stored (raw CR and LF, which valid JSON holds only as whitespace, are removed).
    /// </summary>
    public byte[]? Encode(QueuedEvent item, out string? poison)
    {
        ArgumentNullException.ThrowIfNull(item);
        byte[] payload = Encoding.UTF8.GetBytes(item.Payload.Contains('\r', StringComparison.Ordinal)
            || item.Payload.Contains('\n', StringComparison.Ordinal)
                ? item.Payload.Replace("\r", string.Empty, StringComparison.Ordinal).Replace("\n", string.Empty, StringComparison.Ordinal)
                : item.Payload);
        if (!TryInspect(payload, out string? eventId, out string? timeGenerated))
        {
            poison = "payload-invalid-json";
            return null;
        }

        if (!string.Equals(eventId, item.EventId, StringComparison.Ordinal))
        {
            poison = "payload-event-id-mismatch";
            return null;
        }

        poison = null;
        if (options.Format == HttpOutputFormat.Ndjson)
        {
            return payload;
        }

        using MemoryStream record = new(payload.Length + hecMetadata.Length + 160);
        record.WriteByte((byte)'{');
        if (EventTime(timeGenerated) is { } seconds)
        {
            record.Write("\"time\":"u8);
            record.Write(Encoding.ASCII.GetBytes(seconds));
            record.WriteByte((byte)',');
        }

        record.Write(hecMetadata);
        record.Write(",\"event\":"u8);
        record.Write(payload);
        record.Write(",\"fields\":{\"bower_event_id\":"u8);
        record.Write(JsonString(item.EventId));
        record.Write(",\"bower_fingerprint\":"u8);
        record.Write(JsonString(item.Fingerprint));
        record.Write("}}"u8);
        return record.ToArray();
    }

    /// <summary>
    /// HEC <c>time</c>: Unix seconds with three decimals (milliseconds, truncated) from a
    /// strict ISO 8601 <c>timeGenerated</c>. Null (the field is omitted and Splunk uses
    /// receipt time) when it is missing, not strict, or before 1970.
    /// </summary>
    public static string? EventTime(string? timeGenerated)
    {
        if (timeGenerated is null || !StrictTimestamp().IsMatch(timeGenerated)
            || !DateTimeOffset.TryParseExact(timeGenerated, "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset parsed)
            || parsed < MinimumEventTime)
        {
            return null;
        }

        long milliseconds = (parsed.UtcTicks - MinimumEventTime.UtcTicks) / TimeSpan.TicksPerMillisecond;
        return string.Create(CultureInfo.InvariantCulture, $"{milliseconds / 1000}.{milliseconds % 1000:000}");
    }

    /// <summary>
    /// The outcome of one response: accepted (no failure) or a bounded failure code. HEC
    /// error codes are added as <c>:hec-&lt;n&gt;</c> metadata; response text never is.
    /// </summary>
    public static (int Status, DeliveryFailure? Failure) Classify(
        HttpOutputFormat format, int status, DateTimeOffset? retryAfter, byte[]? body)
    {
        int? hec = format == HttpOutputFormat.SplunkHec ? ReadHecCode(body) : null;
        if (status is >= 200 and < 300)
        {
            return format == HttpOutputFormat.Ndjson || hec == 0
                ? (status, null)
                // A 2xx that is not a HEC success (a captive portal, a proxy page) is not acceptance.
                : (status, new DeliveryFailure(string.Empty, "destination-http-response-invalid", true, null));
        }

        string suffix = hec is { } code ? string.Create(CultureInfo.InvariantCulture, $":hec-{code}") : string.Empty;
        string text = status.ToString(CultureInfo.InvariantCulture);
        if (status == 413)
        {
            return (status, new DeliveryFailure(string.Empty, $"http-413{suffix}", false, null));
        }

        // Endpoint-wide refusals and outages hold the stream without spending poison budgets:
        // a wrong or revoked token (401/403) or path (404) is fixed by the operator, not the event.
        bool destination = status is < 200 or (>= 300 and < 400) or 401 or 403 or 404 or 408 or 429 or >= 500;
        return destination
            ? (status, new DeliveryFailure(string.Empty, $"destination-http-{text}{suffix}", true, retryAfter))
            : (status, new DeliveryFailure(string.Empty, $"http-{text}{suffix}", false, null));
    }

    /// <summary>The integer HEC <c>code</c> (0-99) of a JSON object body, or null.</summary>
    public static int? ReadHecCode(byte[]? body)
    {
        if (body is null || body.Length == 0)
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 64 });
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("code", out JsonElement code)
                && code.ValueKind == JsonValueKind.Number
                && code.TryGetInt64(out long value)
                && value is >= 0 and <= 99
                    ? (int)value
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Retry-After as delta seconds or an HTTP date; past values are ignored and future ones
    /// capped at one hour.
    /// </summary>
    public static DateTimeOffset? ReadRetryAfter(RetryConditionHeaderValue? header, DateTimeOffset now)
    {
        DateTimeOffset? at = header?.Delta is { } delta ? now.Add(delta) : header?.Date;
        return at is null || at <= now ? null : at > now.Add(MaximumRetryAfter) ? now.Add(MaximumRetryAfter) : at;
    }

    private async Task<(int Status, DeliveryFailure? Failure)> SendAsync(List<Record> batch, CancellationToken cancellationToken)
    {
        byte[] body = Join(batch.Select(record => record.Utf8Json));
        using HttpRequestMessage request = new(HttpMethod.Post, options.Endpoint)
        {
            Content = new ByteArrayContent(options.Gzip ? Compress(body) : body)
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            options.Format == HttpOutputFormat.SplunkHec ? SplunkHecContentType : NdjsonContentType);
        if (options.Gzip)
        {
            request.Content.Headers.ContentEncoding.Add("gzip");
        }

        request.Headers.TryAddWithoutValidation(authorizationName, authorizationValue);
        if (options.HecChannel is not null)
        {
            request.Headers.TryAddWithoutValidation(ChannelHeader, options.HecChannel);
        }

        // One deadline from connect to the end of the bounded body read, so a stalled
        // endpoint cannot hold delivery.
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.Timeout);
        int status;
        DateTimeOffset? retryAfter;
        byte[]? response = null;
        try
        {
            using HttpResponseMessage message = await client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            status = (int)message.StatusCode;
            retryAfter = ReadRetryAfter(message.Headers.RetryAfter, time.GetUtcNow());
            if (options.Format == HttpOutputFormat.SplunkHec)
            {
                response = await ReadBoundedAsync(message.Content, deadline.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (0, new DeliveryFailure(string.Empty, "destination-http-timeout", true, null));
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            // Transport and TLS failures (an untrusted certificate included). Text is never kept.
            return (0, new DeliveryFailure(string.Empty, "destination-http-unavailable", true, null));
        }

        return Classify(options.Format, status, retryAfter, response);
    }

    private static byte[] Compress(byte[] body)
    {
        using MemoryStream compressed = new();
        using (GZipStream gzip = new(compressed, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(body);
        }

        return compressed.ToArray();
    }

    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumResponseBytes)
        {
            return null;
        }

        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream copy = new();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                if (copy.Length + read > MaximumResponseBytes)
                {
                    return null;
                }

                copy.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return copy.ToArray();
    }

    /// <summary>
    /// One JSON object within 64 levels, nothing after it, with at most one top-level
    /// <c>eventId</c> and one <c>timeGenerated</c> (each a string or null).
    /// </summary>
    private static bool TryInspect(ReadOnlySpan<byte> utf8, out string? eventId, out string? timeGenerated)
    {
        eventId = null;
        timeGenerated = null;
        bool seenId = false;
        bool seenTime = false;
        try
        {
            Utf8JsonReader reader = new(utf8, new JsonReaderOptions { MaxDepth = 64 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                bool isId = reader.ValueTextEquals("eventId"u8);
                bool isTime = !isId && reader.ValueTextEquals("timeGenerated"u8);
                if (!reader.Read())
                {
                    return false;
                }

                if (!isId && !isTime)
                {
                    reader.Skip();
                    continue;
                }

                if ((isId && seenId) || (isTime && seenTime)
                    || reader.TokenType is not (JsonTokenType.String or JsonTokenType.Null))
                {
                    return false;
                }

                string? value = reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
                seenId |= isId;
                seenTime |= isTime;
                if (isId)
                {
                    eventId = value;
                }
                else
                {
                    timeGenerated = value;
                }
            }

            return reader.TokenType == JsonTokenType.EndObject && reader.CurrentDepth == 0 && !reader.Read();
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static byte[] HecMetadata(HttpOutputOptions options)
    {
        using MemoryStream metadata = new();
        metadata.Write("\"host\":"u8);
        metadata.Write(JsonString(options.HecHost));
        metadata.Write(",\"source\":"u8);
        metadata.Write(JsonString(options.HecSource));
        metadata.Write(",\"sourcetype\":"u8);
        metadata.Write(JsonString(options.HecSourceType));
        if (options.HecIndex is not null)
        {
            metadata.Write(",\"index\":"u8);
            metadata.Write(JsonString(options.HecIndex));
        }

        return metadata.ToArray();
    }

    /// <summary>A JSON string with System.Text.Json's default escaping.</summary>
    private static byte[] JsonString(string value)
    {
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStringValue(value);
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static SocketsHttpHandler CreateHandler(HttpOutputOptions options)
    {
        SocketsHttpHandler handler = new()
        {
            // A redirect is a misconfigured URL; it would also resend the token elsewhere.
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = options.Timeout < TimeSpan.FromSeconds(10) ? options.Timeout : TimeSpan.FromSeconds(10)
        };
        if (options.CaBundlePath is not null)
        {
            X509Certificate2Collection roots = ReadCaBundle(options.CaBundlePath);
            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, chain, errors) => Validate(certificate, chain, errors, roots);
        }

        return handler;
    }

    /// <summary>
    /// Accepts what the platform accepts. Otherwise only a chain error may be retried, and
    /// only against the configured roots: a name mismatch or a missing certificate is final.
    /// </summary>
    private static bool Validate(
        X509Certificate? certificate,
        X509Chain? presented,
        SslPolicyErrors errors,
        X509Certificate2Collection roots)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || certificate is null)
        {
            return false;
        }

        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthentication));
        if (presented is not null)
        {
            foreach (X509ChainElement element in presented.ChainElements)
            {
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }

        return chain.Build(leaf);
    }

    private static X509Certificate2Collection ReadCaBundle(string path)
    {
        X509Certificate2Collection roots = [];
        try
        {
            roots.ImportFromPemFile(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            roots.Clear();
        }

        return roots.Count > 0
            ? roots
            : throw new InvalidOperationException("BOWER_HTTP_CA_BUNDLE must name a readable PEM file of CA certificates.");
    }

    [GeneratedRegex(@"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?(Z|[+-][0-9]{2}:[0-9]{2})\z",
        RegexOptions.CultureInvariant)]
    private static partial Regex StrictTimestamp();

    private sealed record Record(string EventId, byte[] Utf8Json);
}
