using System.IO.Compression;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Bower.DevSinks;
using Bower.ServiceDefaults;

// Local stand-in destinations for the Aspire harness (src/Bower.AppHost). Development only:
// an NDJSON HTTP endpoint for BOWER_OUTPUT=http, a Unix datagram socket for
// BOWER_OUTPUT=ama-syslog, and a read-only view of the S3 emulator bucket. Never deployed.
WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);
builder.AddBowerServiceDefaults();
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, DevSinkJsonContext.Default));
builder.Services.AddSingleton<DevSinkStore>();
builder.Services.AddHttpClient("s3");
builder.Services.AddHostedService<SyslogSocketListener>();

WebApplication app = builder.Build();
DevSinkStore store = app.Services.GetRequiredService<DevSinkStore>();
string? httpToken = app.Configuration["DEVSINKS_HTTP_TOKEN"];

app.MapGet("/health", () => Results.Text("healthy"));

// BOWER_OUTPUT=http with BOWER_HTTP_FORMAT=ndjson: one envelope per line, bearer token.
app.MapPost("/ndjson", async (HttpRequest request, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrEmpty(httpToken)
        || !string.Equals(request.Headers.Authorization.ToString(), "Bearer " + httpToken, StringComparison.Ordinal))
    {
        return Results.StatusCode(StatusCodes.Status401Unauthorized);
    }

    Stream body = request.Headers.ContentEncoding.ToString().Contains("gzip", StringComparison.OrdinalIgnoreCase)
        ? new GZipStream(request.Body, CompressionMode.Decompress)
        : request.Body;
    await using (body)
    {
        using StreamReader reader = new(body, Encoding.UTF8);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (line.Length > 0)
            {
                store.Add("http", DevSinkStore.ReadEventId(Encoding.UTF8.GetBytes(line)), line);
            }
        }
    }

    return Results.Ok();
});

app.MapGet("/api/summary", () => store.Summary());
app.MapGet("/api/{sink}", (string sink) => store.Records(sink));
app.MapGet("/api/events/{eventId}", (string eventId) =>
    store.Contains(eventId) ? Results.Ok() : Results.NotFound());

// Pulls every object from the S3 emulator bucket into the "s3" sink (S3Mock serves
// unauthenticated reads). Idempotent: an object is marked read only after all its records
// were stored, and refreshes run one at a time.
HashSet<string> readKeys = new(StringComparer.Ordinal);
SemaphoreSlim refreshGate = new(1, 1);
app.MapPost("/api/s3/refresh", async (IHttpClientFactory clients, CancellationToken cancellationToken) =>
{
    string? endpoint = app.Configuration["DEVSINKS_S3_ENDPOINT"];
    string? bucket = app.Configuration["DEVSINKS_S3_BUCKET"];
    if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(bucket))
    {
        return Results.Problem("DEVSINKS_S3_ENDPOINT and DEVSINKS_S3_BUCKET are not set.");
    }

    await refreshGate.WaitAsync(cancellationToken);
    try
    {
        HttpClient client = clients.CreateClient("s3");
        Uri bucketUri = new(new Uri(endpoint.TrimEnd('/') + "/"), bucket + "/");
        int added = 0;
        string? continuation = null;
        do
        {
            string query = continuation is null ? "?list-type=2" : "?list-type=2&continuation-token=" + Uri.EscapeDataString(continuation);
            S3ListPage page = S3ListPage.Parse(await client.GetStringAsync(new Uri(bucketUri, query), cancellationToken));
            foreach (string key in page.Keys.Where(key => !readKeys.Contains(key)))
            {
                byte[] content = await client.GetByteArrayAsync(
                    new Uri(bucketUri, Uri.EscapeDataString(key).Replace("%2F", "/", StringComparison.Ordinal)), cancellationToken);
                // Decode the whole object before storing any record, so a corrupt object
                // stores nothing and stays retryable without duplicates.
                List<string> lines = await S3ListPage.ReadLinesAsync(content, cancellationToken);
                foreach (string line in lines)
                {
                    store.Add("s3", DevSinkStore.ReadEventId(Encoding.UTF8.GetBytes(line)), line);
                }

                added += lines.Count;
                readKeys.Add(key);
            }

            continuation = page.NextContinuationToken;
        }
        while (continuation is not null);

        return Results.Ok(new S3RefreshResponse(readKeys.Count, added));
    }
    finally
    {
        refreshGate.Release();
    }
});

app.Run();

/// <summary>Receives AmaSyslog datagrams on DEVSINKS_SYSLOG_SOCKET (Unix only).</summary>
internal sealed class SyslogSocketListener(DevSinkStore store, IConfiguration configuration, ILogger<SyslogSocketListener> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? path = configuration["DEVSINKS_SYSLOG_SOCKET"];
        if (string.IsNullOrEmpty(path) || OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.Delete(path);
        using Socket socket = new(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        // Room for a burst of default-size (7680 byte) Bower frames.
        socket.ReceiveBufferSize = 1024 * 1024;
        socket.Bind(new UnixDomainSocketEndPoint(path));
        Log.Listening(logger, path);
        byte[] buffer = new byte[65536];
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                int received = await socket.ReceiveAsync(buffer, SocketFlags.None, stoppingToken);
                if (SyslogFrame.DecodeEnvelope(buffer.AsSpan(0, received)) is { } envelope)
                {
                    store.Add("syslog", DevSinkStore.ReadEventId(Encoding.UTF8.GetBytes(envelope)), envelope);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            File.Delete(path);
        }
    }
}

internal static partial class Log
{
    [LoggerMessage(1, LogLevel.Information, "Syslog stand-in listening on {Path}")]
    public static partial void Listening(ILogger logger, string path);
}

/// <summary>One ListObjectsV2 page from the S3 emulator.</summary>
internal sealed record S3ListPage(IReadOnlyList<string> Keys, string? NextContinuationToken)
{
    private static readonly XNamespace Ns = "http://s3.amazonaws.com/doc/2006-03-01/";

    public static S3ListPage Parse(string xml)
    {
        XElement root = XDocument.Parse(xml).Root ?? throw new InvalidDataException("Empty S3 listing.");
        bool truncated = string.Equals(root.Element(Ns + "IsTruncated")?.Value, "true", StringComparison.OrdinalIgnoreCase);
        string? next = root.Element(Ns + "NextContinuationToken")?.Value;
        return new S3ListPage(
            [.. root.Elements(Ns + "Contents").Select(item => item.Element(Ns + "Key")?.Value).OfType<string>()],
            truncated && !string.IsNullOrEmpty(next) ? next : null);
    }

    /// <summary>Non-empty NDJSON lines of an object, gunzipped when it starts with the gzip magic.</summary>
    public static async Task<List<string>> ReadLinesAsync(byte[] content, CancellationToken cancellationToken)
    {
        bool gzip = content.Length > 2 && content[0] == 0x1f && content[1] == 0x8b;
        using StreamReader reader = new(gzip
            ? new GZipStream(new MemoryStream(content), CompressionMode.Decompress)
            : new MemoryStream(content));
        List<string> lines = [];
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (line.Length > 0)
            {
                lines.Add(line);
            }
        }

        return lines;
    }
}

internal sealed record S3RefreshResponse(int Objects, int Added);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(DevSinkSummary))]
[JsonSerializable(typeof(IReadOnlyList<DevSinkRecord>))]
[JsonSerializable(typeof(S3RefreshResponse))]
internal sealed partial class DevSinkJsonContext : JsonSerializerContext;
