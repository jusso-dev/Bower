using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Bower.Collector;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// The management channel through an authenticated CONNECT proxy to an HTTPS endpoint whose
/// certificate chains to a private CA (what a TLS-inspection proxy presents).
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class ManagementProxyTests
{
    private const string Host = "management.bower.test";
    private const string User = "bower";
    private const string Password = "s3cret-proxy-password";

    [Fact]
    public async Task ExplicitProxy_WithCredentialsAndCaBundle_ReachesManagement()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using X509Certificate2 ca = CreateCa();
        using X509Certificate2 leaf = CreateLeaf(ca, Host);
        await using WebApplication server = await StartHttpsAsync(leaf, ct);
        using ConnectProxy proxy = new(Port(server));

        string body = await GetAsync(Settings(directory, proxy.Port, ca, Password), ct);

        Assert.Equal("pong", body);
        Assert.True(proxy.AuthorizedTunnels >= 1);
        // .NET first tries without credentials and answers the 407 challenge.
        Assert.True(proxy.Challenges >= 1);
    }

    [Fact]
    public async Task TlsVerificationIsNeverDisabled()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using X509Certificate2 ca = CreateCa();
        using X509Certificate2 wrongName = CreateLeaf(ca, "other.bower.test");
        await using WebApplication server = await StartHttpsAsync(wrongName, ct);
        using ConnectProxy proxy = new(Port(server));
        using X509Certificate2 unrelatedCa = CreateCa();

        // The configured CA cannot excuse a host name mismatch.
        await Assert.ThrowsAsync<HttpRequestException>(() => GetAsync(Settings(directory, proxy.Port, ca, Password), ct));
        // A CA that did not issue the certificate is not trusted.
        using X509Certificate2 rightName = CreateLeaf(ca, Host);
        await using WebApplication second = await StartHttpsAsync(rightName, ct);
        using ConnectProxy secondProxy = new(Port(second));
        await Assert.ThrowsAsync<HttpRequestException>(
            () => GetAsync(Settings(directory, secondProxy.Port, unrelatedCa, Password), ct));
        // Without the CA bundle the private chain is refused.
        await Assert.ThrowsAsync<HttpRequestException>(
            () => GetAsync(Settings(directory, secondProxy.Port, null, Password), ct));
    }

    [Fact]
    public async Task WrongProxyPassword_FailsWithoutLeakingIt()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using X509Certificate2 ca = CreateCa();
        using X509Certificate2 leaf = CreateLeaf(ca, Host);
        await using WebApplication server = await StartHttpsAsync(leaf, ct);
        using ConnectProxy proxy = new(Port(server));

        HttpRequestException failure = await Assert.ThrowsAsync<HttpRequestException>(
            () => GetAsync(Settings(directory, proxy.Port, ca, "wrong-password"), ct));

        Assert.Equal(0, proxy.AuthorizedTunnels);
        Assert.DoesNotContain("wrong-password", failure.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_ValidateProxyCaAndCommandKeys()
    {
        CollectorSettings managed = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = "queue.db",
            PolicyDirectory = "policies",
            CollectorId = "edge-01",
            ManagementEndpoint = new Uri("https://management.example.test"),
            ManagementScope = "api://bower/.default"
        };
        Uri proxy = new("http://proxy.example.test:3128");

        (managed with { ManagementProxy = proxy }).Validate();
        (managed with { ManagementProxy = proxy, ManagementProxyUsername = "u", ManagementProxyPasswordFile = "p" }).Validate();
        InvalidOperationException credentials = Assert.Throws<InvalidOperationException>(
            (managed with { ManagementProxy = new Uri("http://user:hunter2@proxy.example.test:3128") }).Validate);
        Assert.DoesNotContain("hunter2", credentials.Message, StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>((managed with { ManagementProxy = new Uri("socks5://proxy:1080") }).Validate);
        Assert.Throws<InvalidOperationException>((managed with { ManagementProxy = new Uri("http://proxy:3128/path") }).Validate);
        Assert.Throws<InvalidOperationException>((managed with { ManagementProxy = proxy, ManagementProxyUsername = "u" }).Validate);
        Assert.Throws<InvalidOperationException>((managed with { ManagementProxyUsername = "u", ManagementProxyPasswordFile = "p" }).Validate);
        Assert.Throws<InvalidOperationException>((managed with
        {
            ManagementEndpoint = null,
            ManagementScope = null,
            ManagementCommandTrustedKeyFiles = ["k.pem"]
        }).Validate);
        Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(name => name switch
            {
                "BOWER_MANAGEMENT_ENDPOINT" => "https://management.example.test",
                "BOWER_MANAGEMENT_SCOPE" => "api://bower/.default",
                "BOWER_MANAGEMENT_PROXY" => "not a url",
                _ => null
            }));

        CollectorSettings fromEnvironment = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_MANAGEMENT_ENDPOINT" => "https://management.example.test",
            "BOWER_MANAGEMENT_SCOPE" => "api://bower/.default",
            "BOWER_MANAGEMENT_PROXY" => "https://proxy.example.test:8443",
            "BOWER_MANAGEMENT_PROXY_USERNAME" => "bower",
            "BOWER_MANAGEMENT_PROXY_PASSWORD_FILE" => "/run/secrets/proxy",
            "BOWER_MANAGEMENT_CA_BUNDLE" => "/etc/bower/inspection-ca.pem",
            "BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS" => "/etc/bower/a.pem, /etc/bower/b.pem",
            _ => null
        });
        Assert.Equal(new Uri("https://proxy.example.test:8443"), fromEnvironment.ManagementProxy);
        Assert.Equal(["/etc/bower/a.pem", "/etc/bower/b.pem"], fromEnvironment.ManagementCommandTrustedKeyFiles);
        // The hash covers proxy host and port, never credentials; unset settings leave it unchanged.
        Assert.NotEqual(managed.ConfigurationHash(), fromEnvironment.ConfigurationHash());
        Assert.Equal(
            managed.ConfigurationHash(),
            (managed with { ManagementEndpoint = new Uri("https://other.example.test") }).ConfigurationHash());
        Assert.Equal(
            (managed with { ManagementProxy = proxy, ManagementProxyUsername = "u", ManagementProxyPasswordFile = "a" }).ConfigurationHash(),
            (managed with { ManagementProxy = proxy, ManagementProxyUsername = "v", ManagementProxyPasswordFile = "b" }).ConfigurationHash());
        // Pinned in the Rust collector too (tests/management_commands.rs).
        CollectorSettings pinned = fromEnvironment with
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = "queue.db",
            PolicyDirectory = "policies",
            CollectorId = "edge-01",
            Environment = "unknown",
            ManagementCommandTrustedKeyFiles = ["/etc/bower/a.pem"]
        };
        Assert.Equal(
            "sha256:a53aa3777ee29ae7496974c8b2328e7b100fa0cd7839de0b835823f09fc091af",
            pinned.ConfigurationHash());
    }

    [Fact]
    public void CaBundle_ThatIsMissingOrEmptyFailsStartup()
    {
        using TemporaryDirectory directory = new();
        string empty = Path.Combine(directory.Path, "empty.pem");
        File.WriteAllText(empty, "no certificates here");

        Assert.Throws<InvalidOperationException>(() => ManagementHttp.ReadCaBundle(Path.Combine(directory.Path, "absent.pem")));
        Assert.Throws<InvalidOperationException>(() => ManagementHttp.ReadCaBundle(empty));
    }

    private static async Task<string> GetAsync(CollectorSettings settings, CancellationToken ct)
    {
        using SocketsHttpHandler handler = ManagementHttp.CreateHandler(settings);
        using HttpClient client = new(handler) { BaseAddress = settings.ManagementEndpoint, Timeout = TimeSpan.FromSeconds(15) };
        return await client.GetStringAsync("ping", ct);
    }

    private static CollectorSettings Settings(TemporaryDirectory directory, int proxyPort, X509Certificate2? ca, string password)
    {
        string passwordFile = Path.Combine(directory.Path, $"proxy-password-{Guid.NewGuid():N}");
        File.WriteAllText(passwordFile, password + "\n");
        string? bundle = null;
        if (ca is not null)
        {
            bundle = Path.Combine(directory.Path, $"ca-{Guid.NewGuid():N}.pem");
            File.WriteAllText(bundle, ca.ExportCertificatePem());
        }

        return new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = "policies",
            CollectorId = "edge-01",
            ManagementEndpoint = new Uri($"https://{Host}/"),
            ManagementScope = "api://bower/.default",
            ManagementProxy = new Uri($"http://127.0.0.1:{proxyPort}"),
            ManagementProxyUsername = User,
            ManagementProxyPasswordFile = passwordFile,
            ManagementCaBundle = bundle
        };
    }

    private static X509Certificate2 CreateCa()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=Bower Test Inspection CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string host)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new($"CN={host}", key, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName(host);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], false));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        using X509Certificate2 issued = request.Create(
            ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(8));
        using X509Certificate2 withKey = issued.CopyWithPrivateKey(key);
        // Round-trip through PKCS#12 so the platform TLS stack can use the private key.
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null);
    }

    private static async Task<WebApplication> StartHttpsAsync(X509Certificate2 certificate, CancellationToken ct)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        // The test output's appsettings.json restricts hosts to loopback names.
        builder.Configuration["AllowedHosts"] = "*";
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(certificate)));
        WebApplication app = builder.Build();
        app.MapGet("/ping", () => Results.Text("pong"));
        await app.StartAsync(ct);
        return app;
    }

    private static int Port(WebApplication app) =>
        new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

    /// <summary>
    /// A minimal HTTP CONNECT proxy requiring Basic credentials. Every tunnel goes to the test
    /// server, so the client never resolves the management host name itself.
    /// </summary>
    private sealed class ConnectProxy : IDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly int target;
        private readonly CancellationTokenSource stop = new();
        private int authorized;
        private int challenges;

        public ConnectProxy(int target)
        {
            this.target = target;
            listener.Start();
            _ = AcceptAsync();
        }

        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public int AuthorizedTunnels => Volatile.Read(ref authorized);

        public int Challenges => Volatile.Read(ref challenges);

        public void Dispose()
        {
            stop.Cancel();
            listener.Stop();
            stop.Dispose();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    TcpClient client = await listener.AcceptTcpClientAsync(stop.Token);
                    _ = HandleAsync(client);
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    NetworkStream stream = client.GetStream();
                    List<string> headers = await ReadHeadersAsync(stream);
                    string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{User}:{Password}"));
                    bool connect = headers.Count > 0 && headers[0].StartsWith($"CONNECT {Host}:443 ", StringComparison.Ordinal);
                    bool authenticated = headers.Any(line =>
                        line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase)
                        && line["Proxy-Authorization:".Length..].Trim() == expected);
                    if (!connect || !authenticated)
                    {
                        Interlocked.Increment(ref challenges);
                        await stream.WriteAsync(Encoding.ASCII.GetBytes(
                            "HTTP/1.1 407 Proxy Authentication Required\r\n" +
                            "Proxy-Authenticate: Basic realm=\"bower\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
                        return;
                    }

                    Interlocked.Increment(ref authorized);
                    using TcpClient upstream = new();
                    await upstream.ConnectAsync(IPAddress.Loopback, target, stop.Token);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"));
                    NetworkStream server = upstream.GetStream();
                    await Task.WhenAny(stream.CopyToAsync(server, stop.Token), server.CopyToAsync(stream, stop.Token));
                }
                catch (Exception exception) when (exception is IOException or SocketException
                    or OperationCanceledException or ObjectDisposedException)
                {
                }
            }
        }

        private static async Task<List<string>> ReadHeadersAsync(NetworkStream stream)
        {
            List<string> lines = [];
            StringBuilder line = new();
            byte[] buffer = new byte[1];
            while (lines.Count < 64 && await stream.ReadAsync(buffer) == 1)
            {
                if (buffer[0] == '\n')
                {
                    string text = line.ToString().TrimEnd('\r');
                    if (text.Length == 0)
                    {
                        break;
                    }

                    lines.Add(text);
                    line.Clear();
                }
                else
                {
                    line.Append((char)buffer[0]);
                }
            }

            return lines;
        }
    }
}
