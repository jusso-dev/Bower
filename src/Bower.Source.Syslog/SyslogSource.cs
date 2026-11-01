using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

namespace Bower.Source.Syslog;

/// <summary>What happened to one record handed to the collector.</summary>
public enum SyslogSubmitOutcome
{
    /// <summary>Durably enqueued. This is an internal admission result, not a wire acknowledgement.</summary>
    Queued,
    Duplicate,
    Suppressed,

    /// <summary>The pack parser's filter did not select the record.</summary>
    NotSelected,

    /// <summary>Policy rejected or quarantined the event.</summary>
    Rejected,

    /// <summary>The record does not satisfy the pack parser's field types.</summary>
    Invalid,
    TooLarge,

    /// <summary>Queue at capacity or ingest gated: TCP waits and retries, UDP drops.</summary>
    Unavailable
}

/// <summary>Collector side of the source: pack parser, redaction, policy and durable enqueue.</summary>
public interface ISyslogSink
{
    ValueTask<SyslogSubmitOutcome> SubmitAsync(
        SyslogListenerOptions listener,
        SyslogRoute route,
        string record,
        CancellationToken cancellationToken);
}

/// <summary>Per-listener counters since start. Metadata only: no frame content, ever.</summary>
public sealed record SyslogListenerStatus(
    string Id,
    string Protocol,
    string Endpoint,
    long ActiveConnections,
    long ConnectionsAccepted,
    long ConnectionsRejected,
    long SendersDenied,
    long TlsHandshakeFailures,
    long FramesReceived,
    long BytesReceived,
    long Queued,
    long Duplicates,
    long Suppressed,
    long NotRouted,
    long NotSelected,
    long Rejected,
    long ParserErrors,
    long Malformed,
    long Oversized,
    long FramingErrors,
    long Timeouts,
    long Dropped,
    long Retries,
    long SubmitFailures,
    long ReceiveErrors,
    DateTimeOffset? LastFrameAt)
{
    /// <summary>TLS material reloads applied after a file change.</summary>
    public long TlsReloads { get; init; }

    /// <summary>Changed TLS files that could not be loaded; the last good material stays in use.</summary>
    public long TlsReloadFailures { get; init; }

    /// <summary>Handshakes refused by the revocation lists (listed, unknown issuer, stale or badly signed list).</summary>
    public long TlsRevoked { get; init; }

    /// <summary>Open sessions closed because their client certificate is no longer trusted.</summary>
    public long TlsSessionsClosed { get; init; }

    public DateTimeOffset? ServerCertificateNotAfter { get; init; }

    public DateTimeOffset? ClientCertificateAuthorityNotAfter { get; init; }

    public DateTimeOffset? ClientRevocationListNextUpdate { get; init; }

    /// <summary>Connections Bower half-closed (idle timeout or stop) instead of resetting them.</summary>
    public long HalfCloses { get; init; }

    /// <summary>Frames received after Bower half-closed their connection.</summary>
    public long DrainedFrames { get; init; }

    /// <summary>Connections a sender or middlebox reset; frames in flight may be lost.</summary>
    public long PeerResets { get; init; }

    /// <summary>RELP <c>syslog</c> transactions answered <c>200 OK</c>, each after a final durable decision.</summary>
    public long RelpAcknowledged { get; init; }

    /// <summary>RELP sessions Bower ended with a <c>serverclose</c> hint (stop, idle or busy).</summary>
    public long RelpServerCloses { get; init; }

    /// <summary>RELP sessions closed because the queue refused a message for longer than the busy limit; the sender keeps and resends it.</summary>
    public long RelpBusyCloses { get; init; }
}

/// <summary>
/// TCP (RFC 6587 octet counting and LF framing), TLS and UDP syslog listeners.
/// <para>
/// TCP and TLS: each connection handles one frame at a time and reads the next frame only
/// after the sink has durably enqueued (or definitively dropped) the current one, so a full
/// queue stops reading and TCP flow control pushes back on the sender. Plain syslog has no
/// application acknowledgement, so Bower never resets a healthy connection: an idle timeout
/// or a stop half-closes it (TCP FIN, no TLS close_notify, which a sender that never reads
/// would mistake for data) and keeps reading the frames the sender already sent until it
/// closes or goes quiet. Frames still in flight when the process is killed are lost unless
/// the sender retransmits. UDP is best effort: datagrams are queued in a bounded buffer and
/// dropped (and counted) when it is full or the queue is at capacity.
/// </para>
/// <para>
/// RELP (rsyslog <c>omrelp</c>): one transaction at a time, in order. A <c>syslog</c> transaction is
/// answered <c>200 OK</c> only after the sink has durably enqueued it or made a final decision
/// (duplicate, suppressed, unrouted, malformed, oversized or rejected by policy). A full queue or a
/// failed sink is never answered: the sender keeps the message in its window and resends it after
/// reconnecting, and the event id makes the resend a duplicate. A refusal that outlasts
/// <see cref="RelpBusyTimeout"/>, an idle timeout or a stop ends the session with a <c>serverclose</c>
/// hint; frames the sender wrote before it saw the hint are still enqueued, unacknowledged.
/// </para>
/// <para>
/// TLS material is reloaded when its files change, without dropping connections: new
/// handshakes use the newest valid certificate, key, client CAs and revocation lists, and a
/// failed reload keeps the last good material. Open mutual-TLS sessions are validated again
/// before their next frame after a reload, or once a certificate in their chain or a
/// revocation list expires; a session whose client is no longer trusted is closed.
/// </para>
/// </summary>
public sealed class SyslogSource : IAsyncDisposable
{
    /// <summary>Datagrams buffered per UDP listener before new ones are dropped.</summary>
    public const int UdpQueueCapacity = 256;

    /// <summary>Submissions in flight across all listeners; others wait (and stop reading).</summary>
    public const int MaximumConcurrentSubmissions = 16;

    /// <summary>
    /// TCP keepalive on accepted connections: first probe after two minutes of silence, which
    /// also keeps load balancer and firewall flow state alive (AWS NLB 350 s, Azure Load
    /// Balancer 4 minutes by default).
    /// </summary>
    public static readonly TimeSpan KeepAliveTime = TimeSpan.FromSeconds(120);

    public static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Unanswered probes before a dead peer's connection closes, about 17 minutes in all:
    /// longer than a Linux sender's own retransmission timeout (about 15 minutes), so an
    /// outage the sender survives never makes Bower reset what it retransmits afterwards.
    /// </summary>
    public const int KeepAliveProbes = 30;

    private readonly ISyslogSink sink;
    private readonly TimeProvider clock;
    private readonly List<Listener> listeners;
    private readonly SemaphoreSlim gate = new(MaximumConcurrentSubmissions);
    private readonly CancellationTokenSource draining = new();
    private readonly CancellationTokenSource stopping = new();
    private readonly ConcurrentDictionary<Task, byte> running = new();
    private readonly List<Task> listenerTasks = [];
    private readonly List<Task> tlsRefreshTasks = [];
    private Dictionary<string, IPEndPoint> endpoints = [];
    private int started;
    private int disposed;

    public SyslogSource(SyslogSourceConfiguration configuration, ISyslogSink sink, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(sink);
        this.sink = sink;
        this.clock = clock ?? TimeProvider.System;
        listeners = [.. configuration.Listeners.Select(options => new Listener(options))];
    }

    /// <summary>Wait before retrying a frame the queue could not take yet.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>How often a background loop checks the TLS files for changes (at least 10 ms).</summary>
    public TimeSpan TlsReloadInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Loads every TLS listener's certificate, key, CA bundle and revocation lists as
    /// <see cref="StartAsync"/> would, then releases them. Start-up and the signed reload
    /// pre-check call this, so a reload is refused for files that would stop a restart.
    /// </summary>
    public static void ValidateTls(SyslogSourceConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        foreach (SyslogListenerOptions listener in configuration.Listeners.Where(listener => listener.Tls is not null))
        {
            SyslogTlsMaterial.Validate(listener);
        }
    }

    /// <summary>TLS material generations not yet disposed for a listener (tests: no handle growth across reloads).</summary>
    internal int TlsMaterialsAlive(string listenerId) =>
        listeners.Single(listener => listener.Options.Id == listenerId).Tls?.MaterialsAlive ?? 0;

    /// <summary>Handshakes holding TLS material for a listener (tests).</summary>
    internal long TlsHandshakesInFlight(string listenerId) =>
        Interlocked.Read(ref listeners.Single(listener => listener.Options.Id == listenerId).Counters.TlsHandshakesInFlight);

    /// <summary>After Bower half-closes a connection, how long it waits for each further frame the sender already sent.</summary>
    public TimeSpan DrainTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long a RELP session holds one message the queue keeps refusing before it ends the
    /// session (unacknowledged) with <c>serverclose</c>. Shorter than rsyslog <c>omrelp</c>'s
    /// 90-second response timeout, so the sender reconnects and resends instead of timing out.
    /// </summary>
    public TimeSpan RelpBusyTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Time allowed for graceful drain before cancellation. Final shutdown still waits for
    /// listener and sink operations to finish; it requires cooperative cancellation and is
    /// not bounded by this timeout.
    /// </summary>
    public TimeSpan StopTimeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Bound endpoints by listener id (after <see cref="StartAsync"/>).</summary>
    public IReadOnlyDictionary<string, IPEndPoint> Endpoints => endpoints;

    /// <summary>Binds every listener (failing start-up on any error), then starts serving.</summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Interlocked.Exchange(ref started, 1) != 0)
        {
            throw new InvalidOperationException("Syslog source is already started.");
        }

        Dictionary<string, IPEndPoint> bound = new(StringComparer.Ordinal);
        try
        {
            foreach (Listener listener in listeners)
            {
                SyslogListenerOptions options = listener.Options;
                listener.Tls = options.Tls is not null ? new SyslogTlsSource(options) : null;
                IPAddress address = IPAddress.Parse(options.Address);
                bool datagram = options.Protocol == "udp";
                Socket socket = datagram
                    ? new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
                    : new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                listener.Socket = socket;
                socket.Bind(new IPEndPoint(address, options.Port));
                if (!datagram)
                {
                    socket.Listen(Math.Min(options.MaximumConnections, 512));
                }

                IPEndPoint local = (IPEndPoint)socket.LocalEndPoint!;
                listener.Endpoint = local.ToString();
                bound[options.Id] = local;
            }
        }
        catch
        {
            foreach (Listener listener in listeners)
            {
                listener.Socket?.Dispose();
                listener.Tls?.Dispose();
            }

            throw;
        }

        endpoints = bound;
        CancellationToken token = stopping.Token;
        foreach (Listener listener in listeners)
        {
            Task listenerTask = listener.Options.Protocol == "udp"
                ? Task.Run(() => ServeUdpAsync(listener, token), CancellationToken.None)
                : Task.Run(() => AcceptAsync(listener, token), CancellationToken.None);
            listenerTasks.Add(listenerTask);
            if (listener.Tls is { } tls)
            {
                // Keep trust material current throughout the drain. Refresh loops are
                // awaited separately so they do not hold the drain open.
                tlsRefreshTasks.Add(Task.Run(() => RefreshTlsAsync(tls, token), CancellationToken.None));
            }
        }

        return Task.CompletedTask;
    }

    public IReadOnlyList<SyslogListenerStatus> Snapshot() => [.. listeners.Select(listener => listener.Snapshot())];

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        // Stop accepting and half-close every connection, so senders see the end of the stream
        // while the frames they already sent are still read and enqueued; then stop the rest.
        await draining.CancelAsync();
        foreach (Listener listener in listeners)
        {
            listener.Socket?.Dispose();
        }

        try
        {
            await WaitForListenersAndConnectionsAsync(listenerTasks, () => [.. running.Keys]).WaitAsync(StopTimeout);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException or SocketException or ObjectDisposedException or IOException)
        {
            // Connections still open after the drain are stopped below.
        }

        await stopping.CancelAsync();
        try
        {
            await WaitForListenersAndConnectionsAsync(listenerTasks, () => [.. running.Keys]);
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException or IOException)
        {
            // Stopping: connections and loops end by cancellation or a closed socket.
        }

        try
        {
            await Task.WhenAll(tlsRefreshTasks);
        }
        catch (OperationCanceledException)
        {
            // The refresh loops stop with the source.
        }

        foreach (Listener listener in listeners)
        {
            listener.Tls?.Dispose();
        }

        draining.Dispose();
        stopping.Dispose();
        gate.Dispose();
    }

    // A listener can finish accepting just as shutdown takes its first snapshot and register
    // a connection afterwards. Wait for all producers of connection tasks to exit before
    // taking the final snapshot, so no task can outlive the resources it uses.
    internal static async Task WaitForListenersAndConnectionsAsync(
        IReadOnlyCollection<Task> listenerTasks,
        Func<Task[]> snapshotConnections)
    {
        try
        {
            await Task.WhenAll(listenerTasks);
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException or IOException)
        {
            // Closed listeners are normal during shutdown; still wait for their connections.
        }

        await Task.WhenAll(snapshotConnections());
    }

    private void Track(Task task)
    {
        running.TryAdd(task, 0);
        _ = task.ContinueWith(
            completed => running.TryRemove(completed, out _),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>Wait after a failed accept or UDP receive: 100 ms, doubling to 1 s, reset by a success.</summary>
    internal static TimeSpan NextAcceptBackoff(TimeSpan current) =>
        current <= TimeSpan.Zero
            ? TimeSpan.FromMilliseconds(100)
            : TimeSpan.FromTicks(Math.Min(current.Ticks * 2, TimeSpan.FromSeconds(1).Ticks));

    private async Task AcceptAsync(Listener listener, CancellationToken cancellationToken)
    {
        TimeSpan backoff = TimeSpan.Zero;
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await listener.Socket!.AcceptAsync(cancellationToken);
                backoff = TimeSpan.Zero;
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (draining.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                // A reset before accept completed, or descriptor exhaustion: back off instead
                // of spinning, then keep listening.
                backoff = NextAcceptBackoff(backoff);
                try
                {
                    await Task.Delay(backoff, clock, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                continue;
            }

            IPAddress sender = NormaliseSender(((IPEndPoint)socket.RemoteEndPoint!).Address);
            if (!listener.Options.Allows(sender))
            {
                Interlocked.Increment(ref listener.Counters.SendersDenied);
                socket.Dispose();
                continue;
            }

            if (Interlocked.Increment(ref listener.Counters.ActiveConnections) > listener.Options.MaximumConnections)
            {
                Interlocked.Decrement(ref listener.Counters.ActiveConnections);
                Interlocked.Increment(ref listener.Counters.ConnectionsRejected);
                socket.Dispose();
                continue;
            }

            Interlocked.Increment(ref listener.Counters.ConnectionsAccepted);
            Track(Task.Run(() => ServeConnectionAsync(listener, socket, sender, cancellationToken), CancellationToken.None));
        }
    }

    private async Task ServeConnectionAsync(Listener listener, Socket socket, IPAddress sender, CancellationToken cancellationToken)
    {
        SyslogListenerOptions options = listener.Options;
        TimeSpan? idle = options.IdleTimeoutSeconds == 0 ? null : TimeSpan.FromSeconds(options.IdleTimeoutSeconds);
        TimeSpan frameTimeout = TimeSpan.FromSeconds(options.FrameTimeoutSeconds);
        ConfigureKeepAlive(socket);
        NetworkStream network = new(socket, ownsSocket: true);
        Stream stream = network;
        SyslogTlsSession? session = null;
        StrongBox<Task?> reading = new();
        Task? pending = null;
        try
        {
            if (listener.Tls is { } tls)
            {
                // Bound unauthenticated connections even when established-session idle is disabled.
                // Some senders initiate TLS only when they have data; qualify their reconnect behavior.
                Task<int> first = socket.ReceiveAsync(new byte[1], SocketFlags.Peek, cancellationToken).AsTask();
                pending = first;
                if (!await CompletesAsync(first, TimeSpan.FromSeconds(options.HandshakeStartTimeoutSeconds), draining.Token, cancellationToken))
                {
                    if (!draining.IsCancellationRequested)
                    {
                        Interlocked.Increment(ref listener.Counters.Timeouts);
                    }

                    return;
                }

                pending = null;
                if (await first == 0)
                {
                    return;
                }

                SslStream secure = new(network, leaveInnerStreamOpen: false);
                stream = secure;
                session = new SyslogTlsSession();
                using CancellationTokenSource handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, draining.Token);
                handshake.CancelAfter(frameTimeout);
                // The material is held for the handshake only, so a reload never disposes
                // certificates a handshake in flight is still using.
                SyslogTlsMaterial material = tls.Acquire();
                Interlocked.Increment(ref listener.Counters.TlsHandshakesInFlight);
                try
                {
                    await secure.AuthenticateAsServerAsync(material.CreateOptions(session, clock), handshake.Token);
                }
                catch (Exception exception) when (!cancellationToken.IsCancellationRequested && !draining.IsCancellationRequested
                    && exception is AuthenticationException or IOException or OperationCanceledException or System.ComponentModel.Win32Exception)
                {
                    Interlocked.Increment(ref listener.Counters.TlsHandshakeFailures);
                    if (session.Revoked)
                    {
                        Interlocked.Increment(ref listener.Counters.TlsRevoked);
                    }

                    return;
                }
                finally
                {
                    material.Release();
                    Interlocked.Decrement(ref listener.Counters.TlsHandshakesInFlight);
                }
            }

            if (options.Protocol == "relp")
            {
                await ServeRelpAsync(listener, socket, stream, session, sender.ToString(), reading, cancellationToken);
                return;
            }

            SyslogFrameReader reader = new(stream, options.MaximumMessageBytes);
            string senderText = sender.ToString();
            bool halfClosed = false;
            while (true)
            {
                if (!halfClosed && draining.IsCancellationRequested)
                {
                    halfClosed = HalfClose(listener, socket);
                    if (!halfClosed)
                    {
                        return;
                    }
                }

                // Between frames: an idle connection is closed only gracefully, never reset.
                Task<bool> next = reader.WaitForFrameAsync(cancellationToken).AsTask();
                pending = next;
                if (!halfClosed && !await CompletesAsync(next, idle, draining.Token, cancellationToken))
                {
                    if (!draining.IsCancellationRequested)
                    {
                        Interlocked.Increment(ref listener.Counters.Timeouts);
                    }

                    halfClosed = HalfClose(listener, socket);
                    if (!halfClosed)
                    {
                        return;
                    }
                }

                if (halfClosed && !await CompletesAsync(next, DrainTimeout, CancellationToken.None, cancellationToken))
                {
                    return;
                }

                pending = null;
                if (!await next)
                {
                    return;
                }

                // A frame has started: the rest must arrive within the frame timeout, so a sender
                // that trickles bytes (slow loris) is closed.
                Task<SyslogFrameResult> read = reader.ReadFrameAsync(cancellationToken).AsTask();
                pending = read;
                if (!await CompletesAsync(read, frameTimeout, CancellationToken.None, cancellationToken))
                {
                    Interlocked.Increment(ref listener.Counters.Timeouts);
                    return;
                }

                pending = null;
                SyslogFrameResult result = await read;
                if (result.IsEnd)
                {
                    return;
                }

                if (result.Failure is { } failure)
                {
                    Interlocked.Increment(ref failure == SyslogFailures.FrameTooLarge
                        ? ref listener.Counters.Oversized
                        : ref listener.Counters.FramingErrors);
                    return;
                }

                listener.Received(result.Frame.Length, clock.GetUtcNow());
                if (session is not null && !StillTrusted(listener.Tls!, session))
                {
                    // The client CA was removed, the certificate was revoked or something in
                    // its chain expired: refuse this frame and end the session.
                    Interlocked.Increment(ref listener.Counters.TlsSessionsClosed);
                    return;
                }

                if (halfClosed)
                {
                    Interlocked.Increment(ref listener.Counters.DrainedFrames);
                }

                if (await HandleFrameAsync(listener, senderText, result.Frame, waitWhenUnavailable: true, cancellationToken,
                    session is null ? null : () => StillTrusted(listener.Tls!, session)) != FrameDisposition.Decided)
                {
                    return;
                }
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
        {
            // Peer reset, shutdown or a closed socket: the connection simply ends. A reset can
            // discard frames the sender wrote after its last successful send, so it is counted.
            if (!cancellationToken.IsCancellationRequested && IsReset(exception))
            {
                Interlocked.Increment(ref listener.Counters.PeerResets);
            }
        }
        finally
        {
            await stream.DisposeAsync();
            pending ??= reading.Value;
            if (pending is not null)
            {
                try
                {
                    await pending;
                }
                catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
                {
                    // The read ended with the stream it was reading.
                }
            }

            session?.Dispose();
            Interlocked.Decrement(ref listener.Counters.ActiveConnections);
        }
    }

    /// <summary>
    /// One RELP session after any TLS handshake. Transactions are handled strictly in order: the
    /// next frame is read only after the current one is answered, so the sender's window (rsyslog
    /// default 128) bounds what it has in flight and TCP flow control bounds the rest. The first
    /// frame must be <c>open</c> (transaction 1) within the handshake-start timeout; any framing,
    /// sequence or command error ends the session without an answer.
    /// </summary>
    private async Task ServeRelpAsync(
        Listener listener,
        Socket socket,
        Stream stream,
        SyslogTlsSession? session,
        string sender,
        StrongBox<Task?> pending,
        CancellationToken cancellationToken)
    {
        SyslogListenerOptions options = listener.Options;
        TimeSpan? idle = options.IdleTimeoutSeconds == 0 ? null : TimeSpan.FromSeconds(options.IdleTimeoutSeconds);
        TimeSpan frameTimeout = TimeSpan.FromSeconds(options.FrameTimeoutSeconds);
        TimeSpan openTimeout = TimeSpan.FromSeconds(options.HandshakeStartTimeoutSeconds);
        Func<bool>? isTrusted = session is null ? null : () => StillTrusted(listener.Tls!, session);
        // The data limit leaves room for the CR LF some senders append; the message itself is
        // checked against maximumMessageBytes once the line ending is removed.
        RelpFrameReader reader = new(stream, Math.Max(options.MaximumMessageBytes + 2, RelpProtocol.MaximumOfferBytes));
        long expected = 1;
        bool open = false;

        // After serverclose (stop, idle, busy) Bower writes nothing more. It keeps reading and
        // enqueuing what the sender wrote before it saw the hint; those stay unacknowledged and
        // deduplicate when the sender resends them.
        bool closing = false;
        while (true)
        {
            if (!closing && draining.IsCancellationRequested)
            {
                if (!open || !await ServerCloseAsync(listener, socket, stream, frameTimeout, cancellationToken))
                {
                    return;
                }

                closing = true;
            }

            Task<bool> next = reader.WaitForFrameAsync(cancellationToken).AsTask();
            pending.Value = next;
            if (!closing && !await CompletesAsync(next, open ? idle : openTimeout, draining.Token, cancellationToken))
            {
                if (!draining.IsCancellationRequested)
                {
                    Interlocked.Increment(ref listener.Counters.Timeouts);
                }

                if (!open || !await ServerCloseAsync(listener, socket, stream, frameTimeout, cancellationToken))
                {
                    return;
                }

                closing = true;
            }

            if (closing && !await CompletesAsync(next, DrainTimeout, CancellationToken.None, cancellationToken))
            {
                return;
            }

            pending.Value = null;
            if (!await next)
            {
                return;
            }

            Task<RelpFrameResult> read = reader.ReadFrameAsync(cancellationToken).AsTask();
            pending.Value = read;
            if (!await CompletesAsync(read, frameTimeout, CancellationToken.None, cancellationToken))
            {
                Interlocked.Increment(ref listener.Counters.Timeouts);
                return;
            }

            pending.Value = null;
            RelpFrameResult frame = await read;
            if (frame.IsEnd)
            {
                return;
            }

            if (frame.Failure is { } failure)
            {
                Interlocked.Increment(ref failure == RelpFailures.DataTooLarge
                    ? ref listener.Counters.Oversized
                    : ref listener.Counters.FramingErrors);
                return;
            }

            if (frame.Transaction != expected || (frame.Command == RelpCommand.Open) == open)
            {
                // Out of sequence, a repeated open, or anything before open.
                Interlocked.Increment(ref listener.Counters.FramingErrors);
                return;
            }

            expected = RelpProtocol.Next(expected);
            switch (frame.Command)
            {
                case RelpCommand.Open:
                    if (!RelpProtocol.TryAcceptOffers(frame.Data.Span, out _))
                    {
                        Interlocked.Increment(ref listener.Counters.FramingErrors);
                        await WriteAsync(stream, RelpProtocol.OpenRefused(frame.Transaction), frameTimeout, cancellationToken);
                        return;
                    }

                    if (!await WriteAsync(stream, RelpProtocol.OpenAccepted(frame.Transaction), frameTimeout, cancellationToken))
                    {
                        Interlocked.Increment(ref listener.Counters.Timeouts);
                        return;
                    }

                    open = true;
                    continue;
                case RelpCommand.Close:
                    // Every earlier transaction is already answered.
                    if (!closing)
                    {
                        await WriteAsync(stream, RelpProtocol.CloseAccepted(frame.Transaction), frameTimeout, cancellationToken);
                    }

                    return;
                case RelpCommand.Syslog:
                    break;
                default:
                    Interlocked.Increment(ref listener.Counters.FramingErrors);
                    return;
            }

            ReadOnlyMemory<byte> message = TrimLineEnding(frame.Data);
            listener.Received(message.Length, clock.GetUtcNow());
            if (isTrusted is not null && !isTrusted())
            {
                Interlocked.Increment(ref listener.Counters.TlsSessionsClosed);
                return;
            }

            if (closing)
            {
                Interlocked.Increment(ref listener.Counters.DrainedFrames);
            }

            FrameDisposition disposition;
            if (frame.Oversized || message.Length > options.MaximumMessageBytes)
            {
                // Final: the same bytes would be refused again, so answer instead of making the sender resend forever.
                Interlocked.Increment(ref listener.Counters.Oversized);
                disposition = FrameDisposition.Decided;
            }
            else
            {
                disposition = await HandleFrameAsync(listener, sender, message, waitWhenUnavailable: true, cancellationToken,
                    isTrusted, closing ? null : RelpBusyTimeout);
            }

            if (disposition == FrameDisposition.Close)
            {
                return;
            }

            if (disposition == FrameDisposition.Busy)
            {
                Interlocked.Increment(ref listener.Counters.RelpBusyCloses);
                await ServerCloseAsync(listener, socket, stream, frameTimeout, cancellationToken);
                return;
            }

            if (!closing)
            {
                if (!await WriteAsync(stream, RelpProtocol.Acknowledge(frame.Transaction), frameTimeout, cancellationToken))
                {
                    Interlocked.Increment(ref listener.Counters.Timeouts);
                    return;
                }

                Interlocked.Increment(ref listener.Counters.RelpAcknowledged);
            }
        }
    }

    /// <summary>Removes one trailing LF or CR LF (rsyslog templates end with LF), as LF framing does.</summary>
    internal static ReadOnlyMemory<byte> TrimLineEnding(ReadOnlyMemory<byte> data)
    {
        ReadOnlySpan<byte> span = data.Span;
        int length = span.Length;
        if (length > 0 && span[length - 1] == (byte)'\n')
        {
            length--;
            if (length > 0 && span[length - 1] == (byte)'\r')
            {
                length--;
            }
        }

        return data[..length];
    }

    /// <summary>Sends the <c>serverclose</c> hint, then half-closes. False when the connection is already gone.</summary>
    private static async Task<bool> ServerCloseAsync(Listener listener, Socket socket, Stream stream, TimeSpan limit, CancellationToken cancellationToken)
    {
        try
        {
            if (!await WriteAsync(stream, RelpProtocol.ServerClose(), limit, cancellationToken))
            {
                return false;
            }
        }
        catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException)
        {
            return false;
        }

        Interlocked.Increment(ref listener.Counters.RelpServerCloses);
        return HalfClose(listener, socket);
    }

    /// <summary>Writes and flushes within <paramref name="limit"/>, so a sender that stops reading cannot hold a session.</summary>
    private static async Task<bool> WriteAsync(Stream stream, byte[] frame, TimeSpan limit, CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(limit);
        try
        {
            await stream.WriteAsync(frame, timeout.Token);
            await stream.FlushAsync(timeout.Token);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>
    /// True when <paramref name="task"/> completes within <paramref name="limit"/> (null: no
    /// limit); false when the limit passes or <paramref name="interrupt"/> fires first. The task
    /// keeps running either way, so a read in progress is never cancelled half way.
    /// </summary>
    private static async Task<bool> CompletesAsync(Task task, TimeSpan? limit, CancellationToken interrupt, CancellationToken cancellationToken)
    {
        if (task.IsCompleted)
        {
            return true;
        }

        using CancellationTokenSource wait = CancellationTokenSource.CreateLinkedTokenSource(interrupt, cancellationToken);
        try
        {
            await task.WaitAsync(limit ?? Timeout.InfiniteTimeSpan, wait.Token);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && interrupt.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>
    /// Sends TCP FIN and keeps the receive side open. No TLS close_notify: a sender that never
    /// reads (rsyslog checks for end of stream with a non-blocking peek) would mistake it for
    /// data and keep writing into a connection about to close.
    /// </summary>
    private static bool HalfClose(Listener listener, Socket socket)
    {
        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (Exception exception) when (exception is SocketException or ObjectDisposedException)
        {
            return false;
        }

        Interlocked.Increment(ref listener.Counters.HalfCloses);
        return true;
    }

    private static bool IsReset(Exception exception) =>
        (exception as SocketException ?? exception.InnerException as SocketException)?.SocketErrorCode
            is SocketError.ConnectionReset or SocketError.ConnectionAborted;

    /// <summary>Enables keepalive with Bower's timing; a platform without per-socket timing keeps its own.</summary>
    internal static void ConfigureKeepAlive(Socket socket)
    {
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, (int)KeepAliveTime.TotalSeconds);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, (int)KeepAliveInterval.TotalSeconds);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, KeepAliveProbes);
        }
        catch (SocketException)
        {
            // Already reset, or the platform refuses per-socket keepalive timing.
        }
    }

    private async Task ServeUdpAsync(Listener listener, CancellationToken cancellationToken)
    {
        Channel<(string Sender, byte[] Frame)> queue = Channel.CreateBounded<(string, byte[])>(
            new BoundedChannelOptions(UdpQueueCapacity) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        Task worker = Task.Run(async () =>
        {
            try
            {
                await foreach ((string sender, byte[] frame) in queue.Reader.ReadAllAsync(cancellationToken))
                {
                    _ = await HandleFrameAsync(listener, sender, frame, waitWhenUnavailable: false, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Stopping.
            }
        }, CancellationToken.None);

        Socket socket = listener.Socket!;
        byte[] buffer = new byte[65_536];
        EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        TimeSpan backoff = TimeSpan.Zero;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken);
                    backoff = TimeSpan.Zero;
                }
                catch (SocketException exception) when (exception.SocketErrorCode == SocketError.MessageSize)
                {
                    Interlocked.Increment(ref listener.Counters.Oversized);
                    continue;
                }
                catch (SocketException exception) when (exception.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // ICMP port unreachable reported on Windows; not a datagram.
                    continue;
                }
                catch (SocketException) when (!cancellationToken.IsCancellationRequested)
                {
                    // Any other receive error (NetworkReset, NoBufferSpaceAvailable): count it,
                    // back off as accept does so a persistent error cannot spin, keep listening.
                    Interlocked.Increment(ref listener.Counters.ReceiveErrors);
                    backoff = NextAcceptBackoff(backoff);
                    await Task.Delay(backoff, clock, cancellationToken);
                    continue;
                }

                IPAddress sender = NormaliseSender(((IPEndPoint)received.RemoteEndPoint).Address);
                if (!listener.Options.Allows(sender))
                {
                    Interlocked.Increment(ref listener.Counters.SendersDenied);
                    continue;
                }

                int length = received.ReceivedBytes;
                if (length > 0 && buffer[length - 1] == (byte)'\n')
                {
                    length--;
                    if (length > 0 && buffer[length - 1] == (byte)'\r')
                    {
                        length--;
                    }
                }

                listener.Received(length, clock.GetUtcNow());
                if (length > listener.Options.MaximumMessageBytes)
                {
                    Interlocked.Increment(ref listener.Counters.Oversized);
                    continue;
                }

                if (!queue.Writer.TryWrite((sender.ToString(), buffer.AsSpan(0, length).ToArray())))
                {
                    Interlocked.Increment(ref listener.Counters.Dropped);
                }
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException)
        {
            // Stopping: cancellation, disposal, or a socket error raised while stopping.
        }
        finally
        {
            queue.Writer.TryComplete();
            await worker;
        }
    }

    /// <summary>
    /// Parse, route, build the record and submit. <see cref="FrameDisposition.Decided"/> means the
    /// frame was durably enqueued or finally dropped; <see cref="FrameDisposition.Close"/> means the
    /// connection should close because it was not (the sink failed or the session lost trust);
    /// <see cref="FrameDisposition.Busy"/> means the queue refused it for longer than
    /// <paramref name="busyLimit"/>.
    /// </summary>
    private async Task<FrameDisposition> HandleFrameAsync(
        Listener listener,
        string sender,
        ReadOnlyMemory<byte> frame,
        bool waitWhenUnavailable,
        CancellationToken cancellationToken,
        Func<bool>? isTrusted = null,
        TimeSpan? busyLimit = null)
    {
        SyslogListenerOptions options = listener.Options;
        DateTimeOffset receivedAt = clock.GetUtcNow();
        if (!SyslogParser.TryParse(frame.Span, receivedAt, out SyslogMessage? message, out _))
        {
            Interlocked.Increment(ref listener.Counters.Malformed);
            return FrameDisposition.Decided;
        }

        if (options.Route(message, IPAddress.Parse(sender)) is not { } route)
        {
            Interlocked.Increment(ref listener.Counters.NotRouted);
            return FrameDisposition.Decided;
        }

        string record;
        try
        {
            record = SyslogRecord.Build(message, frame.Span, options.Id, options.Protocol, sender, receivedAt);
        }
        catch (SyslogFormatException)
        {
            Interlocked.Increment(ref listener.Counters.Oversized);
            return FrameDisposition.Decided;
        }

        long refusedSince = clock.GetTimestamp();
        while (true)
        {
            SyslogSubmitOutcome outcome;
            await gate.WaitAsync(cancellationToken);
            try
            {
                // A frame may have waited on the gate or queue after the session was
                // validated. Recheck before each retry so revocation closes it.
                if (isTrusted is not null && !isTrusted())
                {
                    Interlocked.Increment(ref listener.Counters.TlsSessionsClosed);
                    return FrameDisposition.Close;
                }

                outcome = await sink.SubmitAsync(options, route, record, cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                Interlocked.Increment(ref listener.Counters.SubmitFailures);
                return FrameDisposition.Close;
            }
            finally
            {
                gate.Release();
            }

            switch (outcome)
            {
                case SyslogSubmitOutcome.Unavailable when waitWhenUnavailable:
                    if (busyLimit is { } limit && clock.GetElapsedTime(refusedSince) >= limit)
                    {
                        return FrameDisposition.Busy;
                    }

                    Interlocked.Increment(ref listener.Counters.Retries);
                    await Task.Delay(RetryDelay, clock, cancellationToken);
                    continue;
                case SyslogSubmitOutcome.Unavailable:
                    Interlocked.Increment(ref listener.Counters.Dropped);
                    break;
                case SyslogSubmitOutcome.Queued:
                    Interlocked.Increment(ref listener.Counters.Queued);
                    break;
                case SyslogSubmitOutcome.Duplicate:
                    Interlocked.Increment(ref listener.Counters.Duplicates);
                    break;
                case SyslogSubmitOutcome.Suppressed:
                    Interlocked.Increment(ref listener.Counters.Suppressed);
                    break;
                case SyslogSubmitOutcome.NotSelected:
                    Interlocked.Increment(ref listener.Counters.NotSelected);
                    break;
                case SyslogSubmitOutcome.Invalid:
                    Interlocked.Increment(ref listener.Counters.ParserErrors);
                    break;
                case SyslogSubmitOutcome.TooLarge:
                    Interlocked.Increment(ref listener.Counters.Oversized);
                    break;
                default:
                    Interlocked.Increment(ref listener.Counters.Rejected);
                    break;
            }

            return FrameDisposition.Decided;
        }
    }

    private enum FrameDisposition
    {
        Decided,
        Close,
        Busy
    }

    /// <summary>
    /// Sender identity for allow-lists, routes, <c>senderAddress</c> and event ids: IPv4-mapped
    /// IPv6 becomes IPv4, and an IPv6 interface scope (<c>fe80::1%2</c>) is dropped because it
    /// is host-local and the Rust port never includes it.
    /// </summary>
    internal static IPAddress NormaliseSender(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4()
        : address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0 ? new IPAddress(address.GetAddressBytes())
        : address;

    private bool StillTrusted(SyslogTlsSource tls, SyslogTlsSession session)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (tls.Peek.Generation == session.Generation && now < session.RevalidateAt)
        {
            return true;
        }

        SyslogTlsMaterial material = tls.Acquire();
        try
        {
            return material.StillTrusted(session, now);
        }
        finally
        {
            material.Release();
        }
    }

    /// <summary>Checks the TLS files every interval off the connection and frame paths.</summary>
    private async Task RefreshTlsAsync(SyslogTlsSource tls, CancellationToken cancellationToken)
    {
        TimeSpan interval = TlsReloadInterval < TimeSpan.FromMilliseconds(10) ? TimeSpan.FromMilliseconds(10) : TlsReloadInterval;
        try
        {
            while (true)
            {
                await Task.Delay(interval, clock, cancellationToken);
                tls.Refresh();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Stopping.
        }
    }

    private sealed class Listener(SyslogListenerOptions options)
    {
        public SyslogListenerOptions Options { get; } = options;

        public Socket? Socket { get; set; }

        public SyslogTlsSource? Tls { get; set; }

        public string Endpoint { get; set; } = string.Empty;

        public Counters Counters { get; } = new();

        public void Received(int bytes, DateTimeOffset now)
        {
            Interlocked.Increment(ref Counters.FramesReceived);
            Interlocked.Add(ref Counters.BytesReceived, bytes);
            Interlocked.Exchange(ref Counters.LastFrameTicks, now.UtcTicks);
        }

        public SyslogListenerStatus Snapshot()
        {
            long last = Interlocked.Read(ref Counters.LastFrameTicks);
            // Generation and dates only: no certificate handle is touched.
            SyslogTlsMaterial? material = Tls?.Peek;
            return new SyslogListenerStatus(
                Options.Id,
                Options.Protocol,
                Endpoint,
                Interlocked.Read(ref Counters.ActiveConnections),
                Interlocked.Read(ref Counters.ConnectionsAccepted),
                Interlocked.Read(ref Counters.ConnectionsRejected),
                Interlocked.Read(ref Counters.SendersDenied),
                Interlocked.Read(ref Counters.TlsHandshakeFailures),
                Interlocked.Read(ref Counters.FramesReceived),
                Interlocked.Read(ref Counters.BytesReceived),
                Interlocked.Read(ref Counters.Queued),
                Interlocked.Read(ref Counters.Duplicates),
                Interlocked.Read(ref Counters.Suppressed),
                Interlocked.Read(ref Counters.NotRouted),
                Interlocked.Read(ref Counters.NotSelected),
                Interlocked.Read(ref Counters.Rejected),
                Interlocked.Read(ref Counters.ParserErrors),
                Interlocked.Read(ref Counters.Malformed),
                Interlocked.Read(ref Counters.Oversized),
                Interlocked.Read(ref Counters.FramingErrors),
                Interlocked.Read(ref Counters.Timeouts),
                Interlocked.Read(ref Counters.Dropped),
                Interlocked.Read(ref Counters.Retries),
                Interlocked.Read(ref Counters.SubmitFailures),
                Interlocked.Read(ref Counters.ReceiveErrors),
                last == 0 ? null : new DateTimeOffset(last, TimeSpan.Zero))
            {
                TlsReloads = Tls?.Reloads ?? 0,
                TlsReloadFailures = Tls?.ReloadFailures ?? 0,
                TlsRevoked = Interlocked.Read(ref Counters.TlsRevoked),
                TlsSessionsClosed = Interlocked.Read(ref Counters.TlsSessionsClosed),
                ServerCertificateNotAfter = material?.ServerCertificateNotAfter,
                ClientCertificateAuthorityNotAfter = material?.ClientCertificateAuthorityNotAfter,
                ClientRevocationListNextUpdate = material?.ClientRevocationListNextUpdate,
                HalfCloses = Interlocked.Read(ref Counters.HalfCloses),
                DrainedFrames = Interlocked.Read(ref Counters.DrainedFrames),
                PeerResets = Interlocked.Read(ref Counters.PeerResets),
                RelpAcknowledged = Interlocked.Read(ref Counters.RelpAcknowledged),
                RelpServerCloses = Interlocked.Read(ref Counters.RelpServerCloses),
                RelpBusyCloses = Interlocked.Read(ref Counters.RelpBusyCloses)
            };
        }
    }

    private sealed class Counters
    {
        public long TlsHandshakesInFlight;
        public long ActiveConnections;
        public long ConnectionsAccepted;
        public long ConnectionsRejected;
        public long SendersDenied;
        public long TlsHandshakeFailures;
        public long TlsRevoked;
        public long TlsSessionsClosed;
        public long FramesReceived;
        public long BytesReceived;
        public long Queued;
        public long Duplicates;
        public long Suppressed;
        public long NotRouted;
        public long NotSelected;
        public long Rejected;
        public long ParserErrors;
        public long Malformed;
        public long Oversized;
        public long FramingErrors;
        public long Timeouts;
        public long Dropped;
        public long Retries;
        public long SubmitFailures;
        public long ReceiveErrors;
        public long HalfCloses;
        public long DrainedFrames;
        public long PeerResets;
        public long RelpAcknowledged;
        public long RelpServerCloses;
        public long RelpBusyCloses;
        public long LastFrameTicks;
    }
}
