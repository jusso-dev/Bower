using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Bower.Forwarding;

namespace Bower.Collector.Relay;

/// <summary>
/// Downstream side of the relay hop. Both the batch client and the management tunnel use
/// mutual TLS to BOWER_RELAY_URL: the client certificate from
/// BOWER_RELAY_CLIENT_CERTIFICATE_FILE, and the relay's server certificate verified against
/// the system roots plus BOWER_RELAY_CA_BUNDLE, host name included. Verification is never
/// disabled. Environment proxies never apply to the relay hop.
/// </summary>
public sealed class RelayHttp : IDisposable
{
    private const int MaximumResponseHeadBytes = 8 * 1024;
    private static readonly TimeSpan TunnelHandshakeTimeout = TimeSpan.FromSeconds(15);

    private readonly Uri relay;
    private readonly X509Certificate2 clientCertificate;
    private readonly X509Certificate2Collection? roots;

    public RelayHttp(CollectorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        relay = settings.RelayUrl ?? throw new InvalidOperationException("BOWER_RELAY_URL is required.");
        // Read here so a bad certificate, key or CA bundle stops start-up.
        clientCertificate = RelayCertificates.Load(
            settings.RelayClientCertificateFile!,
            settings.RelayClientKeyFile!,
            "BOWER_RELAY_CLIENT_CERTIFICATE_FILE and BOWER_RELAY_CLIENT_KEY_FILE");
        roots = settings.RelayCaBundle is null ? null : ReadCaBundle(settings.RelayCaBundle);
    }

    public Uri RelayUrl => relay;

    /// <summary>Handler for the batch client (<see cref="RelayOutput"/>).</summary>
    public SocketsHttpHandler CreateBatchHandler()
    {
        SocketsHttpHandler handler = new()
        {
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(10)
        };
        handler.SslOptions = ClientOptions();
        return handler;
    }

    /// <summary>
    /// Management traffic through the relay's tunnel: the handler's connections are opened by
    /// <see cref="OpenTunnelAsync"/>, and TLS to management then runs inside the tunnel.
    /// </summary>
    public void UseTunnel(SocketsHttpHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        handler.UseProxy = false;
        handler.Proxy = null;
        handler.ConnectCallback = (_, cancellationToken) => OpenTunnelAsync(cancellationToken);
    }

    /// <summary>
    /// Opens one tunnel: mutual TLS to the relay, then an HTTP/1.1 upgrade. The response head
    /// is read byte by byte so no tunnelled byte is consumed.
    /// </summary>
    public async ValueTask<Stream> OpenTunnelAsync(CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TunnelHandshakeTimeout);
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        SslStream? tls = null;
        try
        {
            await socket.ConnectAsync(RelayCertificates.ConnectHost(relay), relay.Port, timeout.Token);
            tls = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);
            SslClientAuthenticationOptions options = ClientOptions();
            options.TargetHost = RelayCertificates.ConnectHost(relay);
            await tls.AuthenticateAsClientAsync(options, timeout.Token);
            // Host header keeps IPv6 brackets; sockets and TLS take the bare address.
            string authority = relay.IsDefaultPort ? relay.IdnHost : $"{relay.IdnHost}:{relay.Port}";
            byte[] request = Encoding.ASCII.GetBytes(
                $"GET /{RelayProtocol.TunnelPath} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\n" +
                $"Upgrade: {RelayProtocol.TunnelUpgrade}\r\n\r\n");
            await tls.WriteAsync(request, timeout.Token);
            await tls.FlushAsync(timeout.Token);
            string head = await ReadHeadAsync(tls, timeout.Token);
            if (!head.StartsWith("HTTP/1.1 101", StringComparison.Ordinal))
            {
                throw new HttpRequestException(HttpRequestError.ProxyTunnelError, "The relay refused the management tunnel.");
            }

            // SocketsHttpHandler skips its own TLS when a connect callback returns an SslStream.
            // Hide the relay hop's SslStream so TLS to management is layered inside the tunnel.
            return new TunnelStream(tls);
        }
        catch
        {
            if (tls is not null)
            {
                await tls.DisposeAsync();
            }
            else
            {
                socket.Dispose();
            }

            throw;
        }
    }

    public void Dispose() => clientCertificate.Dispose();

    private SslClientAuthenticationOptions ClientOptions() => new()
    {
        ApplicationProtocols = [SslApplicationProtocol.Http11],
        ClientCertificates = [clientCertificate],
        // The relay pins certificates and sends no acceptable-issuer list: always offer ours.
        LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate,
        RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
            roots is null ? errors == SslPolicyErrors.None : ManagementHttp.Validate(certificate, chain, errors, roots)
    };

    private static async Task<string> ReadHeadAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] head = new byte[MaximumResponseHeadBytes];
        int length = 0;
        while (length < head.Length)
        {
            if (await stream.ReadAsync(head.AsMemory(length, 1), cancellationToken) == 0)
            {
                break;
            }

            length++;
            if (length >= 4 && head[length - 4] == '\r' && head[length - 3] == '\n' && head[length - 2] == '\r' && head[length - 1] == '\n')
            {
                return Encoding.ASCII.GetString(head, 0, length);
            }
        }

        throw new HttpRequestException(HttpRequestError.ProxyTunnelError, "The relay sent no valid tunnel response.");
    }

    /// <summary>A plain pass-through over the relay connection (deliberately not an SslStream).</summary>
    private sealed class TunnelStream(Stream inner) : Stream
    {
        public override bool CanRead => true;

        public override bool CanWrite => true;

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.ReadAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.WriteAsync(buffer, offset, count, cancellationToken);

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync();
            await base.DisposeAsync();
        }
    }

    private static X509Certificate2Collection ReadCaBundle(string path)
    {
        X509Certificate2Collection collection = [];
        try
        {
            collection.ImportFromPemFile(path);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or System.Security.Cryptography.CryptographicException)
        {
            collection.Clear();
        }

        return collection.Count > 0
            ? collection
            : throw new InvalidOperationException("BOWER_RELAY_CA_BUNDLE must name a readable PEM file of CA certificates.");
    }
}
