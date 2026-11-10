using System.Buffers.Text;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Dcr;

namespace Bower.Output.Syslog;

/// <summary>
/// Writes each envelope to the local syslog daemon as one datagram on a Unix socket, in the
/// local format <c>syslog(3)</c> uses (<c>&lt;PRI&gt;Mmm dd hh:mm:ss bower: MSG</c>), which rsyslog's
/// socket input and journald both parse. MSG is <c>bower-b64:</c> followed by the envelope
/// JSON in base64: Azure Monitor Agent removes semicolons from syslog messages during
/// ingestion, and base64 carries every byte unchanged. The collection rule decodes it.
/// <para>
/// The socket is non-blocking. When the daemon's queue is full, one datagram waits up to
/// <see cref="SyslogOutputOptions.BusyWait"/> for room, then the rest of the batch is retried.
/// The delivery worker's timeout bounds the whole batch, and cancellation (shutdown, deadline)
/// returns what was already sent as acknowledged, so nothing is sent twice by this adapter.
/// </para>
/// </summary>
public sealed class SyslogOutput : IOutputAdapter, IDisposable
{
    /// <summary>The socket is missing, refuses connections or was reset; retried.</summary>
    public const string SocketUnavailableCode = "destination-syslog-unavailable";

    /// <summary>The daemon took nothing for <see cref="SyslogOutputOptions.BusyWait"/>; retried.</summary>
    public const string SocketBusyCode = "destination-syslog-busy";

    /// <summary>The collector's account may not write to the socket; retried until fixed.</summary>
    public const string AccessDeniedCode = "destination-syslog-access-denied";

    /// <summary>Delivery stopped part-way (shutdown or deadline); the unsent rest is retried.</summary>
    public const string CancelledCode = "destination-syslog-cancelled";

    /// <summary>The message does not fit one datagram; never truncated.</summary>
    public const string MessageTooLargeCode = "payload-too-large";

    /// <summary>The payload is not one JSON object in valid UTF-16 text.</summary>
    public const string InvalidPayloadCode = "payload-invalid-json";

    /// <summary>The payload's eventId differs from the queued event's.</summary>
    public const string EventIdMismatchCode = "payload-event-id-mismatch";

    /// <summary>Marks the encoded envelope inside the syslog message.</summary>
    public const string MessagePrefix = "bower-b64:";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly TimeSpan NoBufferRetry = TimeSpan.FromMilliseconds(10);
    private readonly SyslogOutputOptions options;
    private readonly TimeProvider clock;
    private readonly string priority;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly CancellationTokenSource disposing = new();
    private Socket? socket;
    private bool disposed;

    /// <param name="options">Validated on construction.</param>
    /// <param name="clock">
    /// Only writes the header timestamp. journald and rsyslog stamp their own receive time, so
    /// the value keeps the format well formed and lets tests pin the exact datagram.
    /// </param>
    public SyslogOutput(SyslogOutputOptions options, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        this.options = options;
        this.clock = clock ?? TimeProvider.System;
        priority = string.Create(CultureInfo.InvariantCulture, $"<{(options.Facility * 8) + options.Severity}>");
    }

    public string Id => options.Id;

    public async Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);
        List<string> acknowledged = [];
        List<DeliveryFailure> failures = [];
        if (Volatile.Read(ref disposed))
        {
            return new DeliveryResult([], [.. events.Select(item => Retry(item, CancelledCode))], null);
        }

        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, disposing.Token);
        try
        {
            await gate.WaitAsync(stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return new DeliveryResult([], [.. events.Select(item => Retry(item, CancelledCode))], null);
        }

        try
        {
            for (int index = 0; index < events.Count; index++)
            {
                QueuedEvent item = events[index];
                if (stop.IsCancellationRequested)
                {
                    FailRest(events, index, CancelledCode, failures);
                    break;
                }

                if (Prepare(item) is { } refusal)
                {
                    failures.Add(new DeliveryFailure(item.EventId, refusal, false, null));
                    continue;
                }

                SendOutcome outcome = await SendAsync(TryFormat(item.Payload)!, stop.Token).ConfigureAwait(false);
                if (outcome == SendOutcome.Sent)
                {
                    acknowledged.Add(item.EventId);
                }
                else if (outcome == SendOutcome.TooLarge)
                {
                    // The kernel refused this datagram (larger than the socket allows). A property
                    // of the event, not of the daemon: dead-letter it and carry on with the batch.
                    failures.Add(new DeliveryFailure(item.EventId, MessageTooLargeCode, false, null));
                }
                else
                {
                    FailRest(events, index, outcome switch
                    {
                        SendOutcome.Busy => SocketBusyCode,
                        SendOutcome.AccessDenied => AccessDeniedCode,
                        SendOutcome.Cancelled => CancelledCode,
                        _ => SocketUnavailableCode
                    }, failures);
                    break;
                }
            }
        }
        finally
        {
            gate.Release();
        }

        return new DeliveryResult(acknowledged, failures, null);
    }

    /// <summary>
    /// Connects a fresh socket once, sends nothing. Null when the daemon accepts connections,
    /// otherwise the socket error name (for a start-up warning or <c>bower doctor</c>).
    /// </summary>
    public string? Probe() => Probe(options.SocketPath);

    /// <inheritdoc cref="Probe()"/>
    public static string? Probe(string socketPath)
    {
        try
        {
            using Socket probe = new(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            probe.Connect(new UnixDomainSocketEndPoint(socketPath));
            return null;
        }
        catch (SocketException exception)
        {
            return exception.SocketErrorCode.ToString();
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or NotSupportedException or ArgumentException)
        {
            return "NotSupported";
        }
    }

    /// <summary>The failure code that refuses this event before sending, or null to send it.</summary>
    private string? Prepare(QueuedEvent item)
    {
        byte[] json;
        try
        {
            json = StrictUtf8.GetBytes(item.Payload);
        }
        catch (EncoderFallbackException)
        {
            // An unpaired surrogate: not a size problem.
            return InvalidPayloadCode;
        }

        // The same record checks the Logs Ingestion output runs, against the same table.
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return InvalidPayloadCode;
            }

            if (!document.RootElement.TryGetProperty("eventId", out JsonElement eventId)
                || eventId.ValueKind != JsonValueKind.String
                || !string.Equals(eventId.GetString(), item.EventId, StringComparison.Ordinal))
            {
                return EventIdMismatchCode;
            }

            if (IngestionPreflight.Check(json, SentinelSchema.Default) is { Count: > 0 } issues)
            {
                return $"preflight-{issues[0].Code}";
            }
        }
        catch (JsonException)
        {
            return InvalidPayloadCode;
        }

        return MessageBytes(json.Length) > options.MaximumMessageBytes ? MessageTooLargeCode : null;
    }

    /// <summary>Header bytes before the base64 body, for the configured tag and priority.</summary>
    private int HeaderBytes => priority.Length + "Mmm dd hh:mm:ss ".Length + options.AppName.Length + ": ".Length + MessagePrefix.Length;

    /// <summary>Whole datagram size for a JSON payload of this many UTF-8 bytes.</summary>
    internal int MessageBytes(int jsonBytes) => HeaderBytes + Base64.GetMaxEncodedToUtf8Length(jsonBytes);

    /// <summary>
    /// The largest envelope JSON, in UTF-8 bytes, that fits <see cref="SyslogOutputOptions.MaximumMessageBytes"/>
    /// (5,730 at the defaults). The collector keeps its own records, such as collector_health,
    /// within it.
    /// </summary>
    public int MaximumJsonBytes => (options.MaximumMessageBytes - HeaderBytes) / 4 * 3;

    /// <summary>The datagram for one envelope, or null when it is invalid text or exceeds the limit.</summary>
    internal byte[]? TryFormat(string payload)
    {
        byte[] json;
        try
        {
            json = StrictUtf8.GetBytes(payload);
        }
        catch (EncoderFallbackException)
        {
            return null;
        }

        int length = MessageBytes(json.Length);
        if (length > options.MaximumMessageBytes)
        {
            return null;
        }

        // The daemon stamps its own receive time; this one only keeps the format well formed.
        string timestamp = clock.GetUtcNow().UtcDateTime.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (timestamp[4] == '0')
        {
            timestamp = string.Concat(timestamp.AsSpan(0, 4), " ", timestamp.AsSpan(5));
        }

        // One exact allocation: ASCII header, then base64 written in place. Every header part is
        // ASCII (validated tag, digits, invariant month names), so characters equal bytes.
        byte[] message = new byte[length];
        int written = Encoding.ASCII.GetBytes($"{priority}{timestamp} {options.AppName}: {MessagePrefix}", message);
        if (written != HeaderBytes
            || Base64.EncodeToUtf8(json, message.AsSpan(written), out _, out int encoded) != System.Buffers.OperationStatus.Done
            || written + encoded != length)
        {
            throw new InvalidOperationException("Syslog message length differs from its computed size.");
        }

        return message;
    }

    private async Task<SendOutcome> SendAsync(byte[] message, CancellationToken cancellationToken)
    {
        Socket connected;
        try
        {
            connected = Connected();
        }
        catch (SocketException exception)
        {
            Reset();
            return Classify(exception.SocketErrorCode);
        }

        long started = clock.GetTimestamp();
        while (true)
        {
            SocketError error;
            try
            {
                connected.Send(message);
                return SendOutcome.Sent;
            }
            catch (SocketException exception)
            {
                error = exception.SocketErrorCode;
            }

            if (error == SocketError.WouldBlock)
            {
                // Linux reports a full receiver queue or send buffer as EAGAIN. Wait for room
                // without holding a thread, up to the busy wait or until delivery is cancelled.
                using CancellationTokenSource wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                wait.CancelAfter(Remaining(started));
                try
                {
                    await connected.SendAsync(message, SocketFlags.None, wait.Token).ConfigureAwait(false);
                    return SendOutcome.Sent;
                }
                catch (OperationCanceledException)
                {
                    // A cancelled pending send leaves the socket in an unknown state: reconnect next time.
                    Reset();
                    return cancellationToken.IsCancellationRequested ? SendOutcome.Cancelled : SendOutcome.Busy;
                }
                catch (SocketException exception)
                {
                    error = exception.SocketErrorCode;
                }
            }

            if (error == SocketError.NoBufferSpaceAvailable && Remaining(started) > TimeSpan.Zero)
            {
                // macOS and BSD report a full queue as ENOBUFS, which the socket cannot wait on.
                try
                {
                    await Task.Delay(NoBufferRetry, clock, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return SendOutcome.Cancelled;
                }

                continue;
            }

            SendOutcome outcome = Classify(error);
            if (outcome is not SendOutcome.TooLarge)
            {
                // Back-pressure past the wait, or a connection fault: reconnect next time.
                Reset();
            }

            return outcome;
        }
    }

    private TimeSpan Remaining(long started)
    {
        TimeSpan remaining = options.BusyWait - clock.GetElapsedTime(started);
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    private static SendOutcome Classify(SocketError error) => error switch
    {
        SocketError.MessageSize => SendOutcome.TooLarge,
        SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable => SendOutcome.Busy,
        SocketError.AccessDenied => SendOutcome.AccessDenied,
        SocketError.OperationAborted => SendOutcome.Cancelled,
        // ConnectionRefused, AddressNotAvailable (no such path), NotConnected, ConnectionReset,
        // Shutdown and anything unexpected: the daemon is not there to take the message.
        _ => SendOutcome.Unavailable
    };

    private static DeliveryFailure Retry(QueuedEvent item, string code) => new(item.EventId, code, true, null);

    private static void FailRest(IReadOnlyList<QueuedEvent> events, int from, string code, List<DeliveryFailure> failures)
    {
        // Keep the rest queued in order; the delivery worker backs off and retries.
        for (int rest = from; rest < events.Count; rest++)
        {
            failures.Add(Retry(events[rest], code));
        }
    }

    private Socket Connected()
    {
        if (socket is null)
        {
            Socket created = new(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            try
            {
                if (options.SendBufferBytes is { } bytes)
                {
                    created.SendBufferSize = bytes;
                }

                created.Connect(new UnixDomainSocketEndPoint(options.SocketPath));
                // Never block a thread on a slow daemon: a full queue fails the send at once
                // (WouldBlock) and SendAsync waits for room, bounded and cancellable.
                created.Blocking = false;
            }
            catch
            {
                created.Dispose();
                throw;
            }

            socket = created;
        }

        return socket;
    }

    private void Reset()
    {
        socket?.Dispose();
        socket = null;
    }

    /// <summary>
    /// Cancels a delivery in progress (it returns within one send), then closes the socket.
    /// Waits at most <see cref="SyslogOutputOptions.BusyWait"/> for that delivery to let go.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, true))
        {
            return;
        }

        disposing.Cancel();
        bool entered = gate.Wait(options.BusyWait);
        try
        {
            Reset();
        }
        finally
        {
            if (entered)
            {
                gate.Release();
            }
        }

        // The token source stays undisposed: a delivery racing this call may still link to it.
    }

    private enum SendOutcome
    {
        Sent,
        TooLarge,
        Busy,
        AccessDenied,
        Cancelled,
        Unavailable
    }
}

public sealed record SyslogOutputOptions
{
    /// <summary>Smallest accepted <see cref="MaximumMessageBytes"/>.</summary>
    public const int MinimumMessageBytes = 1_024;

    /// <summary>Largest accepted <see cref="MaximumMessageBytes"/>: the largest UDP-sized datagram.</summary>
    public const int MaximumMessageBytesLimit = 65_507;

    /// <summary>
    /// Default whole-datagram limit. rsyslog forwards at most 8,096 characters per line,
    /// including the header it writes for the agent (measured with stock rsyslog, #230), so
    /// this leaves 416 characters for that header. Keep at least 512 below rsyslog's
    /// <c>MaxMessageSize</c> when raising either.
    /// </summary>
    public const int DefaultMaximumMessageBytes = 7_680;

    /// <summary>Default <see cref="BusyWait"/>.</summary>
    public static readonly TimeSpan DefaultBusyWait = TimeSpan.FromSeconds(2);

    /// <summary>Longest accepted <see cref="BusyWait"/>.</summary>
    public static readonly TimeSpan MaximumBusyWait = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Longest socket path in bytes, without the terminator: <c>sun_path</c> is 108 bytes on
    /// Linux and 104 on macOS.
    /// </summary>
    public static int MaximumSocketPathBytes => OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD() ? 103 : 107;

    /// <summary>
    /// Facilities the collection rule can be set to collect (<c>local0</c> to <c>local7</c>,
    /// the <c>facility</c> parameter's allowed values in <c>deploy/bicep/ama-syslog-dcr.bicep</c>).
    /// </summary>
    public static IReadOnlyList<string> FacilityNames { get; } = ["local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"];

    /// <summary>Facility number of <c>local0</c>.</summary>
    public const int FirstLocalFacility = 16;

    public required string Id { get; init; }

    /// <summary>The local daemon's datagram socket.</summary>
    public string SocketPath { get; init; } = "/dev/log";

    /// <summary>Syslog facility number, 16 (local0) to 23 (local7); 20 is local4.</summary>
    public int Facility { get; init; } = 20;

    /// <summary>
    /// Syslog severity; 5 is notice. The rule collects Notice and above
    /// (<c>logLevels</c> in the template), so change both together.
    /// </summary>
    public int Severity { get; init; } = 5;

    /// <summary>The syslog tag, which Azure Monitor Agent records as ProcessName (the rule checks it).</summary>
    public string AppName { get; init; } = "bower";

    /// <summary>Whole datagram limit, header included.</summary>
    public int MaximumMessageBytes { get; init; } = DefaultMaximumMessageBytes;

    /// <summary>How long one datagram may wait for the daemon to make room before the rest of the batch is retried.</summary>
    public TimeSpan BusyWait { get; init; } = DefaultBusyWait;

    /// <summary>
    /// The socket's send buffer, when set. Linux refuses a datagram larger than this with
    /// EMSGSIZE, so tests use it to provoke that error; the product leaves the kernel default.
    /// </summary>
    internal int? SendBufferBytes { get; init; }

    /// <summary>The facility's name (<c>local4</c>), or its number when it has none here.</summary>
    public static string FacilityName(int facility) =>
        facility is >= FirstLocalFacility and < FirstLocalFacility + 8
            ? FacilityNames[facility - FirstLocalFacility]
            : facility.ToString(CultureInfo.InvariantCulture);

    /// <summary>Reads <c>local0</c> to <c>local7</c>, or the numbers 16 to 23; false otherwise.</summary>
    public static bool TryParseFacility(string? value, out int facility)
    {
        facility = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmed = value.Trim();
        for (int index = 0; index < FacilityNames.Count; index++)
        {
            if (string.Equals(trimmed, FacilityNames[index], StringComparison.OrdinalIgnoreCase))
            {
                facility = FirstLocalFacility + index;
                return true;
            }
        }

        return int.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out facility)
            && facility is >= FirstLocalFacility and < FirstLocalFacility + 8;
    }

    /// <summary>Null when the socket path is usable, otherwise why not.</summary>
    public static string? SocketPathProblem(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !path.StartsWith('/'))
        {
            return "must be an absolute path";
        }

        return Encoding.UTF8.GetByteCount(path) > MaximumSocketPathBytes
            ? $"must be at most {MaximumSocketPathBytes} bytes"
            : null;
    }

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
        if (SocketPathProblem(SocketPath) is { } problem)
        {
            throw new ArgumentException($"The syslog socket path {problem}.", nameof(SocketPath));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(Facility, FirstLocalFacility);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Facility, FirstLocalFacility + 7);
        ArgumentOutOfRangeException.ThrowIfLessThan(Severity, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Severity, 7);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaximumMessageBytes, MinimumMessageBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaximumMessageBytes, MaximumMessageBytesLimit);
        ArgumentOutOfRangeException.ThrowIfLessThan(BusyWait, TimeSpan.FromMilliseconds(1));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(BusyWait, MaximumBusyWait);
        // A tag of letters, digits, '-', '_' and '.' parses the same in rsyslog and journald.
        if (string.IsNullOrEmpty(AppName) || AppName.Length > 32
            || !AppName.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new ArgumentException("AppName must be 1-32 ASCII letters, digits, '-', '_' or '.'.", nameof(AppName));
        }
    }
}
