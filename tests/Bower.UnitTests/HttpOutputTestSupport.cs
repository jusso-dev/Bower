using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

/// <summary>One request as the test endpoint received it: lower-case header names, raw body.</summary>
internal sealed record CapturedRequest(string Path, IReadOnlyDictionary<string, string> Headers, byte[] Body);

/// <summary>What the test endpoint answers. A null body writes nothing; <see cref="Chunked"/> omits Content-Length.</summary>
internal sealed record EndpointReply(int Status, byte[]? Body = null, IReadOnlyDictionary<string, string>? Headers = null, bool Chunked = false)
{
    public static EndpointReply HecSuccess { get; } = new(200, """{"text":"Success","code":0}"""u8.ToArray());
}

/// <summary>A real Kestrel endpoint on a loopback port (HTTP, or HTTPS with the given certificate).</summary>
internal sealed class TestHttpEndpoint : IAsyncDisposable
{
    private readonly WebApplication app;

    private TestHttpEndpoint(WebApplication app) => this.app = app;

    public ConcurrentQueue<CapturedRequest> Requests { get; } = new();

    public Func<CapturedRequest, CancellationToken, Task<EndpointReply>> Reply { get; set; } =
        (_, _) => Task.FromResult(EndpointReply.HecSuccess);

    public int Port => new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

    public Uri Url(string host = "127.0.0.1", string path = "/services/collector/event") =>
        new($"{(Https ? "https" : "http")}://{host}:{Port}{path}");

    private bool Https { get; init; }

    public static async Task<TestHttpEndpoint> StartAsync(X509Certificate2? certificate, CancellationToken cancellationToken)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Configuration["AllowedHosts"] = "*";
        builder.Logging.ClearProviders();
        if (certificate is not null)
        {
            builder.WebHost.UseKestrelHttpsConfiguration();
        }

        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen =>
        {
            if (certificate is not null)
            {
                listen.UseHttps(certificate);
            }
        }));
        WebApplication app = builder.Build();
        TestHttpEndpoint endpoint = new(app) { Https = certificate is not null };
        app.Run(async context =>
        {
            using MemoryStream body = new();
            await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            Dictionary<string, string> headers = new(StringComparer.Ordinal);
            foreach (KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues> header in context.Request.Headers)
            {
                headers[header.Key.ToLowerInvariant()] = header.Value.ToString();
            }

            CapturedRequest captured = new(context.Request.Path.Value ?? string.Empty, headers, body.ToArray());
            endpoint.Requests.Enqueue(captured);
            EndpointReply reply = await endpoint.Reply(captured, context.RequestAborted);
            context.Response.StatusCode = reply.Status;
            foreach (KeyValuePair<string, string> header in reply.Headers ?? new Dictionary<string, string>())
            {
                context.Response.Headers[header.Key] = header.Value;
            }

            if (reply.Body is not null)
            {
                if (!reply.Chunked)
                {
                    context.Response.ContentLength = reply.Body.Length;
                }

                for (int offset = 0; offset < reply.Body.Length; offset += 8192)
                {
                    await context.Response.Body.WriteAsync(
                        reply.Body.AsMemory(offset, Math.Min(8192, reply.Body.Length - offset)), context.RequestAborted);
                    await context.Response.Body.FlushAsync(context.RequestAborted);
                }
            }
        });
        await app.StartAsync(cancellationToken);
        return endpoint;
    }

    public async ValueTask DisposeAsync()
    {
        using CancellationTokenSource stop = new(TimeSpan.FromSeconds(1));
        await app.StopAsync(stop.Token);
        await app.DisposeAsync();
    }
}

/// <summary>A private CA and server certificates for HTTPS endpoint tests (no committed keys).</summary>
internal sealed class TestCertificateAuthority : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public TestCertificateAuthority(string directory)
    {
        CertificateRequest request = new("CN=Bower HTTP Output Test CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        Certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        BundlePath = Path.Combine(directory, $"ca-{Guid.NewGuid():N}.pem");
        File.WriteAllText(BundlePath, Certificate.ExportCertificatePem());
    }

    public X509Certificate2 Certificate { get; }

    public string BundlePath { get; }

    /// <summary>A server certificate for <paramref name="dnsName"/> (and 127.0.0.1 when requested).</summary>
    public X509Certificate2 Issue(string dnsName, bool includeLoopbackAddress)
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new($"CN={dnsName}", leafKey, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName(dnsName);
        if (includeLoopbackAddress)
        {
            names.AddIpAddress(IPAddress.Loopback);
        }

        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        using X509Certificate2 issued = request.Create(
            Certificate, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(8));
        using X509Certificate2 withKey = issued.CopyWithPrivateKey(leafKey);
        // Round-trip through PKCS#12 so the platform TLS stack can use the private key.
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null);
    }

    /// <summary>An intermediate CA certificate issued by this authority (no key kept).</summary>
    public X509Certificate2 IssueIntermediate()
    {
        using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=Bower HTTP Output Test Intermediate", intermediateKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.Create(Certificate, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(8));
    }

    public void Dispose()
    {
        Certificate.Dispose();
        key.Dispose();
    }
}
