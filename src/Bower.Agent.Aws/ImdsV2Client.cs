using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Bower.Agent.Aws;

/// <summary>
/// Minimal, bounded IMDSv2 reader. Session-token only (no IMDSv1 fallback), link-local
/// endpoint, short timeouts and capped response sizes. Returns null when a value is absent
/// or the service is unreachable so hosts outside EC2 run without enrichment.
/// </summary>
public sealed class ImdsV2Client : IDisposable
{
    public static readonly Uri DefaultEndpoint = new("http://169.254.169.254/");
    private const int MaximumResponseBytes = 64 * 1024;
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(6);

    private readonly HttpClient client;
    private readonly bool ownsClient;
    private readonly TimeProvider clock;
    private readonly SemaphoreSlim tokenLock = new(1, 1);
    private string? token;
    private DateTimeOffset tokenExpiresAt;

    public ImdsV2Client(HttpClient? client = null, TimeProvider? clock = null)
    {
        ownsClient = client is null;
        this.client = client ?? new HttpClient(new SocketsHttpHandler { UseProxy = false })
        {
            BaseAddress = DefaultEndpoint,
            Timeout = TimeSpan.FromSeconds(2)
        };
        this.clock = clock ?? TimeProvider.System;
    }

    /// <summary>Reads one logical key understood by <see cref="Ec2MetadataClient"/>.</summary>
    public async Task<string?> FetchAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            return key switch
            {
                "instance-id" => await GetAsync("latest/meta-data/instance-id", cancellationToken),
                "region" => await GetAsync("latest/meta-data/placement/region", cancellationToken),
                "availability-zone" =>
                    await GetAsync("latest/meta-data/placement/availability-zone", cancellationToken),
                "ami-id" => await GetAsync("latest/meta-data/ami-id", cancellationToken),
                "security-groups" => await GetAsync("latest/meta-data/security-groups", cancellationToken),
                "identity-account-id" => await ReadIdentityAccountAsync(cancellationToken),
                "vpc-id" => await ReadInterfaceValueAsync("vpc-id", cancellationToken),
                "subnet-id" => await ReadInterfaceValueAsync("subnet-id", cancellationToken),
                "tags" => await ReadTagsAsync(cancellationToken),
                // Not exposed by IMDS; supplied by orchestration-specific integrations.
                _ => null
            };
        }
        catch (Exception exception) when (
            exception is HttpRequestException or TaskCanceledException or JsonException
                && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    public void Dispose()
    {
        tokenLock.Dispose();
        if (ownsClient)
        {
            client.Dispose();
        }
    }

    private async Task<string?> ReadIdentityAccountAsync(CancellationToken cancellationToken)
    {
        string? document = await GetAsync("latest/dynamic/instance-identity/document", cancellationToken);
        if (document is null)
        {
            return null;
        }

        using JsonDocument parsed = JsonDocument.Parse(document);
        return parsed.RootElement.TryGetProperty("accountId", out JsonElement value)
            ? value.GetString()
            : null;
    }

    private async Task<string?> ReadInterfaceValueAsync(string name, CancellationToken cancellationToken)
    {
        string? mac = (await GetAsync("latest/meta-data/mac", cancellationToken))?.Trim();
        // Only a well-formed MAC is interpolated into the next path.
        return mac is { Length: 17 } && mac.All(c => char.IsAsciiHexDigit(c) || c == ':')
            ? await GetAsync($"latest/meta-data/network/interfaces/macs/{mac}/{name}", cancellationToken)
            : null;
    }

    /// <summary>Instance tags, when "Allow tags in instance metadata" is enabled.</summary>
    private async Task<string?> ReadTagsAsync(CancellationToken cancellationToken)
    {
        string? keys = await GetAsync("latest/meta-data/tags/instance", cancellationToken);
        if (string.IsNullOrWhiteSpace(keys))
        {
            return null;
        }

        Dictionary<string, string> tags = new(StringComparer.Ordinal);
        foreach (string key in keys.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Take(50))
        {
            string? value = await GetAsync(
                $"latest/meta-data/tags/instance/{Uri.EscapeDataString(key)}",
                cancellationToken);
            if (value is not null)
            {
                tags[key] = value;
            }
        }

        return JsonSerializer.Serialize(tags);
    }

    private async Task<string?> GetAsync(string path, CancellationToken cancellationToken)
    {
        string? sessionToken = await GetTokenAsync(cancellationToken);
        if (sessionToken is null)
        {
            return null;
        }

        using HttpRequestMessage request = new(HttpMethod.Get, path);
        request.Headers.Add("X-aws-ec2-metadata-token", sessionToken);
        using HttpResponseMessage response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await ReadBoundedAsync(response, cancellationToken);
    }

    private async Task<string?> GetTokenAsync(CancellationToken cancellationToken)
    {
        await tokenLock.WaitAsync(cancellationToken);
        try
        {
            if (token is not null && clock.GetUtcNow() < tokenExpiresAt)
            {
                return token;
            }

            using HttpRequestMessage request = new(HttpMethod.Put, "latest/api/token");
            request.Headers.Add(
                "X-aws-ec2-metadata-token-ttl-seconds",
                ((int)TokenLifetime.TotalSeconds).ToString(CultureInfo.InvariantCulture));
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            token = await ReadBoundedAsync(response, cancellationToken);
            tokenExpiresAt = clock.GetUtcNow() + TokenLifetime - TimeSpan.FromMinutes(5);
            return token;
        }
        finally
        {
            tokenLock.Release();
        }
    }

    private static async Task<string> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw new HttpRequestException("IMDS response exceeds the size limit.");
        }

        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        byte[] buffer = new byte[MaximumResponseBytes + 1];
        int total = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken)) > 0)
        {
            total += read;
            if (total > MaximumResponseBytes)
            {
                throw new HttpRequestException("IMDS response exceeds the size limit.");
            }
        }

        return Encoding.UTF8.GetString(buffer, 0, total);
    }
}
