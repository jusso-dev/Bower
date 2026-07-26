using System.Net.Http.Json;
using Bower.Contracts;

namespace Bower.Sdk;

internal sealed class LocalCollectorTransport : IDisposable
{
    private readonly HttpClient client;

    public LocalCollectorTransport(LocalCollectorOptions options)
    {
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
        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "v1/events",
            securityEvent,
            BowerJson.Options,
            cancellationToken);
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
