using System.Net.Http.Headers;
using System.Net.Http.Json;
using Bower.Contracts;

namespace Bower.Sdk;

internal sealed class LocalCollectorTransport : IDisposable
{
    private readonly HttpClient client;
    private readonly string? ingestToken;

    public LocalCollectorTransport(LocalCollectorOptions options)
    {
        ingestToken = options.IngestToken;
        client = new HttpClient
        {
            BaseAddress = new Uri(EnsureTrailingSlash(options.Endpoint)),
            Timeout = options.RequestTimeout
        };
    }

    public async Task SendAsync(
        SecurityEventEnvelope securityEvent,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "v1/events")
        {
            Content = JsonContent.Create(securityEvent, options: BowerJson.Options)
        };
        if (!string.IsNullOrEmpty(ingestToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ingestToken);
        }

        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public void Dispose()
    {
        client.Dispose();
    }

    private static string EnsureTrailingSlash(string value)
    {
        return value.EndsWith('/') ? value : $"{value}/";
    }
}
