using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using Bower.Abstractions;

namespace Bower.Output.Syslog;

/// <summary>
/// Writes each envelope to the local syslog daemon as one datagram on a Unix socket, in the
/// local format <c>syslog(3)</c> uses (<c>&lt;PRI&gt;Mmm dd hh:mm:ss bower: MSG</c>), which rsyslog's
/// socket input and journald both parse. MSG is <c>bower-b64:</c> followed by the envelope
/// JSON in base64: Azure Monitor Agent removes semicolons from syslog messages during
/// ingestion, and base64 carries every byte unchanged. The collection rule decodes it.
/// </summary>
public sealed class SyslogOutput : IOutputAdapter, IDisposable
{
    /// <summary>Datagram send failed with a full buffer or a missing daemon; retried.</summary>
    public const string SocketUnavailableCode = "destination-syslog-unavailable";

    /// <summary>The message does not fit one datagram; never truncated.</summary>
    public const string MessageTooLargeCode = "payload-too-large";

    /// <summary>Marks the encoded envelope inside the syslog message.</summary>
    public const string MessagePrefix = "bower-b64:";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly SyslogOutputOptions options;
    private readonly TimeProvider clock;
    private readonly Func<Socket> socketFactory;
    private readonly string priority;
    private readonly Lock gate = new();
    private Socket? socket;

    public SyslogOutput(SyslogOutputOptions options, TimeProvider? clock = null, Func<Socket>? socketFactory = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        this.options = options;
        this.clock = clock ?? TimeProvider.System;
        this.socketFactory = socketFactory ?? (() => new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified));
        priority = string.Create(CultureInfo.InvariantCulture, $"<{(options.Facility * 8) + options.Severity}>");
    }

    public string Id => options.Id;

    public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);
        List<string> acknowledged = [];
        List<DeliveryFailure> failures = [];
        lock (gate)
        {
            for (int index = 0; index < events.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                QueuedEvent item = events[index];
                if (!TryFormat(item.Payload, out byte[]? message))
                {
                    failures.Add(new DeliveryFailure(item.EventId, MessageTooLargeCode, false, null));
                    continue;
                }

                try
                {
                    Connected().Send(message);
                    acknowledged.Add(item.EventId);
                }
                catch (SocketException)
                {
                    // The daemon is down, restarting or its buffer is full. Keep the rest queued
                    // in order; the delivery worker backs off and retries.
                    Reset();
                    for (int rest = index; rest < events.Count; rest++)
                    {
                        failures.Add(new DeliveryFailure(events[rest].EventId, SocketUnavailableCode, true, null));
                    }

                    break;
                }
            }
        }

        return Task.FromResult(new DeliveryResult(acknowledged, failures, null));
    }

    /// <summary>The datagram for one envelope, or false when it would exceed the limit.</summary>
    internal bool TryFormat(string payload, [NotNullWhen(true)] out byte[]? message)
    {
        message = null;
        byte[] json;
        try
        {
            json = StrictUtf8.GetBytes(payload);
        }
        catch (EncoderFallbackException)
        {
            return false;
        }

        // The daemon stamps its own receive time; this one only keeps the format well formed.
        string timestamp = clock.GetUtcNow().UtcDateTime.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (timestamp[4] == '0')
        {
            timestamp = string.Concat(timestamp.AsSpan(0, 4), " ", timestamp.AsSpan(5));
        }

        string text = $"{priority}{timestamp} {options.AppName}: {MessagePrefix}{Convert.ToBase64String(json)}";
        if (text.Length > options.MaximumMessageBytes)
        {
            return false;
        }

        message = Encoding.ASCII.GetBytes(text);
        return true;
    }

    private Socket Connected()
    {
        if (socket is null)
        {
            Socket created = socketFactory();
            try
            {
                created.Connect(new UnixDomainSocketEndPoint(options.SocketPath));
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

    public void Dispose()
    {
        lock (gate)
        {
            Reset();
        }
    }
}

public sealed record SyslogOutputOptions
{
    public required string Id { get; init; }

    /// <summary>The local daemon's datagram socket.</summary>
    public string SocketPath { get; init; } = "/dev/log";

    /// <summary>Syslog facility number; 20 is local4.</summary>
    public int Facility { get; init; } = 20;

    /// <summary>Syslog severity; 5 is notice.</summary>
    public int Severity { get; init; } = 5;

    /// <summary>The syslog tag, which Azure Monitor Agent records as ProcessName.</summary>
    public string AppName { get; init; } = "bower";

    /// <summary>Whole datagram limit. rsyslog's default MaxMessageSize is 8 KiB.</summary>
    public int MaximumMessageBytes { get; init; } = 8_192;

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
        ArgumentException.ThrowIfNullOrWhiteSpace(SocketPath);
        if (!Path.IsPathFullyQualified(SocketPath))
        {
            throw new ArgumentException("The syslog socket path must be absolute.", nameof(SocketPath));
        }

        // sun_path is 104 bytes on macOS and 108 on Linux, including the terminator.
        if (Encoding.UTF8.GetByteCount(SocketPath) > 103)
        {
            throw new ArgumentException("The syslog socket path must be at most 103 bytes.", nameof(SocketPath));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(Facility, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Facility, 23);
        ArgumentOutOfRangeException.ThrowIfLessThan(Severity, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Severity, 7);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaximumMessageBytes, 1_024);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaximumMessageBytes, 65_507);
        // A tag of letters, digits, '-', '_' and '.' parses the same in rsyslog and journald.
        if (string.IsNullOrEmpty(AppName) || AppName.Length > 32
            || !AppName.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new ArgumentException("AppName must be 1-32 ASCII letters, digits, '-', '_' or '.'.", nameof(AppName));
        }
    }
}
