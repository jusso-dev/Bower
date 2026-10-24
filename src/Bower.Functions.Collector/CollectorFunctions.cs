using System.Globalization;
using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace Bower.Functions.Collector;

/// <summary>
/// Thin HTTP trigger adapter. Function-level auth is Anonymous on purpose: function keys
/// are shared secrets, and every protected route validates an Entra token in code instead.
/// Routes match the HTTP collector (host.json sets an empty route prefix).
/// </summary>
public sealed class CollectorFunctions(FunctionCollector collector)
{
    [Function("ingest")]
    public async Task<HttpResponseData> IngestAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "v1/events")] HttpRequestData request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        long? length = long.TryParse(Header(request, "Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture, out long value)
            ? value
            : null;
        CollectorResponse response = await collector.IngestAsync(
            new IngestRequest(Header(request, "Authorization"), Header(request, "Content-Type"), length, request.Body),
            cancellationToken);
        return await WriteAsync(request, response, cancellationToken);
    }

    /// <summary>Anonymous liveness: status only, no configuration or delivery detail.</summary>
    [Function("health")]
    public static Task<HttpResponseData> HealthAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "health")] HttpRequestData request,
        CancellationToken cancellationToken) =>
        WriteAsync(request, FunctionCollector.Health(), cancellationToken);

    /// <summary>Metadata-only status for authenticated producers (policy hash, mode, limits).</summary>
    [Function("status")]
    public async Task<HttpResponseData> StatusAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "v1/status")] HttpRequestData request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        CollectorResponse response = await collector.StatusAsync(Header(request, "Authorization"), cancellationToken);
        return await WriteAsync(request, response, cancellationToken);
    }

    private static string? Header(HttpRequestData request, string name) =>
        request.Headers.TryGetValues(name, out IEnumerable<string>? values) ? values.FirstOrDefault() : null;

    private static async Task<HttpResponseData> WriteAsync(
        HttpRequestData request,
        CollectorResponse response,
        CancellationToken cancellationToken)
    {
        HttpResponseData result = request.CreateResponse((HttpStatusCode)response.StatusCode);
        result.Headers.Add("Content-Type", "application/json; charset=utf-8");
        result.Headers.Add("Cache-Control", "no-store");
        result.Headers.Add("X-Content-Type-Options", "nosniff");
        foreach ((string name, string value) in response.Headers)
        {
            result.Headers.Add(name, value);
        }

        await result.WriteStringAsync(response.Body, cancellationToken);
        return result;
    }
}
