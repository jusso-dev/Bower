using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Bower.Forwarding;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Bower.Collector.Relay;

/// <summary>
/// The relay listener (BOWER_RELAY_LISTEN_URL): a second Kestrel server in the collector
/// process, HTTP/1.1 over TLS with a required client certificate pinned in
/// BOWER_RELAY_DOWNSTREAMS_FILE. Two endpoints:
/// <list type="bullet">
/// <item><c>POST /v1/relay/batches</c>: downstream events into the relay queue (<see cref="RelayIntake"/>).</item>
/// <item><c>GET /v1/relay/management-tunnel</c> with <c>Upgrade: bower-management-tunnel/1</c>: a
/// byte tunnel to this relay's own management endpoint. TLS to management runs inside it,
/// end to end, so the relay neither reads nor alters management traffic and cannot be
/// pointed anywhere else.</item>
/// </list>
/// Delivery from the relay queue stays in <see cref="QueueDeliveryWorker"/>.
/// </summary>
public sealed partial class RelayListener : IHostedService, IAsyncDisposable
{
    public const int MaximumConcurrentBatches = 8;
    public const int MaximumTunnels = 64;
    public const int MaximumTunnelsPerDownstream = 4;
    public static readonly TimeSpan TunnelConnectTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan TunnelIdleTimeout = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan TunnelLifetime = TimeSpan.FromMinutes(15);

    private readonly CollectorSettings settings;
    private readonly RelayDownstreams downstreams;
    private readonly RelayIntake intake;
    private readonly RelayTelemetry telemetry;
    private readonly TimeProvider clock;
    private readonly X509Certificate2 certificate;
    private readonly ILogger<RelayListener> logger;
    private readonly SemaphoreSlim batchSlots = new(MaximumConcurrentBatches, MaximumConcurrentBatches);
    private readonly ConcurrentDictionary<string, int> tunnelsByDownstream = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource stopping = new();
    private int tunnels;
    private WebApplication? app;

    public RelayListener(
        CollectorSettings settings,
        RelayDownstreams downstreams,
        RelayIntake intake,
        RelayTelemetry telemetry,
        TimeProvider clock,
        ILogger<RelayListener> logger)
    {
        this.settings = settings;
        this.downstreams = downstreams;
        this.intake = intake;
        this.telemetry = telemetry;
        this.clock = clock;
        this.logger = logger;
        // Read at construction so a bad certificate or key stops start-up.
        certificate = RelayCertificates.Load(
            settings.RelayCertificateFile!,
            settings.RelayKeyFile!,
            "BOWER_RELAY_CERTIFICATE_FILE and BOWER_RELAY_KEY_FILE");
    }

    /// <summary>Bound addresses once started (the port is assigned when the URL uses port 0).</summary>
    public IReadOnlyList<Uri> Addresses =>
        app?.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses
            .Select(address => new Uri(address)).ToArray() ?? [];

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        // Only this code configures the relay server: no URLs, endpoints or host filtering
        // from the environment or appsettings meant for the main listener.
        builder.Configuration.Sources.Clear();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestBodySize = RelayProtocol.MaximumRequestBytes;
            options.Limits.MaxConcurrentConnections = 512;
            options.Limits.MaxConcurrentUpgradedConnections = MaximumTunnels;
            Uri listen = settings.RelayListenUrl!;
            Action<ListenOptions> configure = listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http1;
                listenOptions.UseHttps(new HttpsConnectionAdapterOptions
                {
                    ServerCertificate = certificate,
                    ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CheckCertificateRevocation = false,
                    // The pin is the trust anchor: an unknown, expired or wrong-usage
                    // certificate fails the handshake before any request is read.
                    ClientCertificateValidation = (presented, _, _) =>
                        downstreams.Resolve(presented, clock.GetUtcNow()) is not null
                });
            };
            if (string.Equals(listen.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                options.ListenLocalhost(listen.Port, configure);
            }
            else if (IPAddress.TryParse(listen.Host.Trim('[', ']'), out IPAddress? address))
            {
                options.Listen(address, listen.Port, configure);
            }
            else
            {
                options.ListenAnyIP(listen.Port, configure);
            }
        });
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ ";
            options.UseUtcTimestamp = true;
        });
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting", LogLevel.Warning);

        WebApplication relay = builder.Build();
        relay.MapPost("/" + RelayProtocol.BatchPath, AcceptBatchAsync);
        relay.MapGet("/" + RelayProtocol.TunnelPath, OpenTunnelAsync);
        await relay.StartAsync(cancellationToken);
        app = relay;
        LogStarted(logger, downstreams.CollectorIds.Count, settings.RelayManagementTunnel);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await stopping.CancelAsync();
        if (app is not null)
        {
            await app.StopAsync(cancellationToken);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (app is not null)
        {
            await app.DisposeAsync();
            app = null;
        }

        certificate.Dispose();
        batchSlots.Dispose();
        stopping.Dispose();
    }

    private string? Identify(HttpContext context) =>
        downstreams.Resolve(context.Connection.ClientCertificate, clock.GetUtcNow());

    private async Task AcceptBatchAsync(HttpContext context)
    {
        string? downstream = Identify(context);
        if (downstream is null)
        {
            await WriteErrorAsync(context, StatusCodes.Status403Forbidden, "Client certificate is not a pinned downstream.");
            return;
        }

        if (!await batchSlots.WaitAsync(0, context.RequestAborted))
        {
            context.Response.Headers.RetryAfter = "1";
            await WriteErrorAsync(context, StatusCodes.Status429TooManyRequests, "Relay is busy; retry shortly.");
            return;
        }

        try
        {
            byte[] body;
            try
            {
                body = await ReadBodyAsync(context.Request, context.RequestAborted);
            }
            catch (Microsoft.AspNetCore.Http.BadHttpRequestException exception)
            {
                await WriteErrorAsync(context, exception.StatusCode, "Relay batch could not be read.");
                return;
            }

            RelayIntakeOutcome outcome = await intake.AcceptAsync(downstream, body, context.RequestAborted);
            if (outcome.Response is { } response)
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.WriteAsJsonAsync(response, RelayJsonContext.Default.RelayBatchResponse, contentType: null, context.RequestAborted);
                return;
            }

            if (outcome.StatusCode == StatusCodes.Status503ServiceUnavailable)
            {
                context.Response.Headers.RetryAfter = "30";
            }

            await WriteErrorAsync(context, outcome.StatusCode, outcome.Message ?? "Relay batch refused.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !context.RequestAborted.IsCancellationRequested)
        {
            // Storage errors (for example SQLITE_BUSY): nothing is acknowledged, the
            // downstream keeps the batch and retries.
            LogBatchFailure(logger, exception.GetType().Name);
            context.Response.Headers.RetryAfter = "5";
            await WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "Relay storage is unavailable; retry later.");
        }
        finally
        {
            batchSlots.Release();
        }
    }

    private async Task OpenTunnelAsync(HttpContext context)
    {
        string? downstream = Identify(context);
        if (downstream is null)
        {
            await WriteErrorAsync(context, StatusCodes.Status403Forbidden, "Client certificate is not a pinned downstream.");
            return;
        }

        if (!settings.RelayManagementTunnel || settings.ManagementEndpoint is not { } management)
        {
            await WriteErrorAsync(context, StatusCodes.Status404NotFound, "The management tunnel is not enabled on this relay.");
            return;
        }

        IHttpUpgradeFeature? upgrade = context.Features.Get<IHttpUpgradeFeature>();
        if (upgrade is not { IsUpgradableRequest: true }
            || !string.Equals(context.Request.Headers.Upgrade, RelayProtocol.TunnelUpgrade, StringComparison.OrdinalIgnoreCase))
        {
            await WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Expected an upgrade to " + RelayProtocol.TunnelUpgrade + ".");
            return;
        }

        if (!TryAcquireTunnel(downstream))
        {
            telemetry.RecordTunnelRefused();
            context.Response.Headers.RetryAfter = "5";
            await WriteErrorAsync(context, StatusCodes.Status429TooManyRequests, "Too many management tunnels.");
            return;
        }

        try
        {
            using Socket? upstream = await ConnectAsync(management, context.RequestAborted);
            if (upstream is null)
            {
                await WriteErrorAsync(context, StatusCodes.Status502BadGateway, "Management endpoint is unreachable from the relay.");
                return;
            }

            context.Response.Headers.Upgrade = RelayProtocol.TunnelUpgrade;
            await using Stream client = await upgrade.UpgradeAsync();
            await using NetworkStream server = new(upstream, ownsSocket: false);
            telemetry.RecordTunnelOpened();
            try
            {
                await SpliceAsync(client, server, TunnelIdleTimeout, TunnelLifetime, stopping.Token);
            }
            finally
            {
                telemetry.RecordTunnelClosed();
            }
        }
        finally
        {
            ReleaseTunnel(downstream);
        }
    }

    private async Task<Socket?> ConnectAsync(Uri management, CancellationToken cancellationToken)
    {
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, stopping.Token);
        timeout.CancelAfter(TunnelConnectTimeout);
        try
        {
            await socket.ConnectAsync(RelayCertificates.ConnectHost(management), management.Port, timeout.Token);
            return socket;
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException)
        {
            LogTunnelConnectFailure(logger, exception.GetType().Name);
            socket.Dispose();
            return null;
        }
    }

    private bool TryAcquireTunnel(string downstream)
    {
        if (Interlocked.Increment(ref tunnels) > MaximumTunnels)
        {
            Interlocked.Decrement(ref tunnels);
            return false;
        }

        bool acquired = false;
        tunnelsByDownstream.AddOrUpdate(
            downstream,
            _ =>
            {
                acquired = true;
                return 1;
            },
            (_, count) =>
            {
                acquired = count < MaximumTunnelsPerDownstream;
                return acquired ? count + 1 : count;
            });
        if (!acquired)
        {
            Interlocked.Decrement(ref tunnels);
        }

        return acquired;
    }

    private void ReleaseTunnel(string downstream)
    {
        tunnelsByDownstream.AddOrUpdate(downstream, 0, (_, count) => Math.Max(0, count - 1));
        Interlocked.Decrement(ref tunnels);
    }

    /// <summary>
    /// Copies both directions until either side closes, the tunnel is idle for
    /// <paramref name="idle"/>, it reaches <paramref name="lifetime"/>, or the relay stops.
    /// </summary>
    internal static async Task SpliceAsync(
        Stream first,
        Stream second,
        TimeSpan idle,
        TimeSpan lifetime,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource done = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        done.CancelAfter(lifetime);
        Activity activity = new();
        Task forward = PumpAsync(first, second, activity, done.Token);
        Task backward = PumpAsync(second, first, activity, done.Token);
        Task watchdog = WatchAsync(activity, idle, done.Token);
        await Task.WhenAny(forward, backward, watchdog);
        await done.CancelAsync();
        await Task.WhenAll(forward, backward, watchdog).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

        static async Task PumpAsync(Stream from, Stream to, Activity activity, CancellationToken token)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
            try
            {
                int read;
                while ((read = await from.ReadAsync(buffer, token)) > 0)
                {
                    activity.Touch();
                    await to.WriteAsync(buffer.AsMemory(0, read), token);
                    await to.FlushAsync(token);
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException
                or SocketException or ObjectDisposedException or ConnectionResetException)
            {
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        static async Task WatchAsync(Activity activity, TimeSpan idle, CancellationToken token)
        {
            TimeSpan tick = TimeSpan.FromMilliseconds(Math.Clamp(idle.TotalMilliseconds / 4, 10, 5_000));
            try
            {
                while (activity.IdleFor < idle)
                {
                    await Task.Delay(tick, token);
                }
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private static async Task<byte[]> ReadBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        using MemoryStream copy = new();
        // Kestrel enforces MaxRequestBodySize (413) while this reads.
        await request.Body.CopyToAsync(copy, cancellationToken);
        return copy.ToArray();
    }

    private static Task WriteErrorAsync(HttpContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        return context.Response.WriteAsJsonAsync(new ErrorResponse(message), CollectorJsonContext.Default.ErrorResponse);
    }

    private sealed class Activity
    {
        private long last = Environment.TickCount64;

        public TimeSpan IdleFor => TimeSpan.FromMilliseconds(Environment.TickCount64 - Volatile.Read(ref last));

        public void Touch() => Volatile.Write(ref last, Environment.TickCount64);
    }

    [LoggerMessage(EventId = 1400, Level = LogLevel.Information,
        Message = "Relay listener started for {Downstreams} downstream collector(s); management tunnel enabled: {Tunnel}.")]
    private static partial void LogStarted(ILogger logger, int downstreams, bool tunnel);

    [LoggerMessage(EventId = 1401, Level = LogLevel.Warning,
        Message = "Relay batch failed with {FailureType}; the downstream will retry.")]
    private static partial void LogBatchFailure(ILogger logger, string failureType);

    [LoggerMessage(EventId = 1402, Level = LogLevel.Warning,
        Message = "Relay management tunnel could not connect ({FailureType}).")]
    private static partial void LogTunnelConnectFailure(ILogger logger, string failureType);
}
