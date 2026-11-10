using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Output.Syslog;

namespace Bower.UnitTests;

/// <summary>
/// BOWER_OUTPUT=syslog: each envelope becomes one local-format datagram on the syslog
/// socket, with the envelope JSON base64-encoded in MSG, so Azure Monitor Agent's syslog
/// collection can carry it to BowerSecurity_CL. A real Unix datagram socket stands in for /dev/log.
/// </summary>
public sealed class SyslogOutputTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 1, 2, 3, 456, TimeSpan.Zero);

    [Fact]
    public async Task Deliver_SendsOneDatagramPerEnvelopeWithTheJsonEncodedInTheMessage()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
        {
            return;
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        using SyslogOutput output = new(new SyslogOutputOptions { Id = "syslog", SocketPath = daemon.Path }, new FixedClock(Now));
        string first = """{"schemaVersion":"1.0.0","eventId":"event-1","eventType":"authentication_failure"}""";
        // Semicolons and non-ASCII text are exactly what syslog ingestion would damage.
        string second = """{"schemaVersion":"1.0.0","eventId":"event-2","actor":{"username":"zoë"},"labels":{"route":"a;b"}}""";

        DeliveryResult result = await output.DeliverAsync(
            [new("event-1", "sha256:one", first, Now), new("event-2", "sha256:two", second, Now)],
            cancellationToken);

        Assert.Equal(["event-1", "event-2"], result.AcknowledgedEventIds);
        Assert.Empty(result.Failures);
        // Facility 20 (local4) * 8 + severity 5 (notice) = 165, then the syslog(3) local format.
        Assert.Equal($"<165>Nov 10 01:02:03 bower: bower-b64:{Base64(first)}", daemon.Receive());
        string message = daemon.Receive();
        Assert.DoesNotContain(";", message, StringComparison.Ordinal);
        Assert.True(message.All(char.IsAscii));

        // What the collection rule's transform does with SyslogMessage.
        Assert.Equal(second, Decode(message));
        using JsonDocument parsed = JsonDocument.Parse(Decode(message));
        Assert.Equal("zoë", parsed.RootElement.GetProperty("actor").GetProperty("username").GetString());
    }

    [Fact]
    public async Task Deliver_RefusesAnEnvelopeThatDoesNotFitOneMessageAndSendsTheRest()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
        {
            return;
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        using SyslogOutput output = new(new SyslogOutputOptions { Id = "syslog", SocketPath = daemon.Path, MaximumMessageBytes = 1_024 });
        string large = "{\"eventId\":\"big\",\"attributes\":{\"note\":\"" + new string('a', 2_000) + "\"}}";

        DeliveryResult result = await output.DeliverAsync(
            [new("big", "sha256:big", large, Now), new("small", "sha256:small", """{"eventId":"small"}""", Now)],
            cancellationToken);

        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal(("big", SyslogOutput.MessageTooLargeCode, false), (failure.EventId, failure.Code, failure.IsRetryable));
        Assert.Equal(["small"], result.AcknowledgedEventIds);
        Assert.Equal("""{"eventId":"small"}""", Decode(daemon.Receive()));
    }

    [Fact]
    public void Format_PadsSingleDigitDaysWithASpace()
    {
        using SyslogOutput output = new(new SyslogOutputOptions { Id = "syslog" }, new FixedClock(new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero)));

        Assert.True(output.TryFormat("{}", out byte[]? message));
        Assert.StartsWith("<165>Mar  4 05:06:07 bower: ", Encoding.ASCII.GetString(message), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deliver_RetriesEveryEventWhenTheDaemonIsNotListening()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
        {
            return;
        }

        using ShortDirectory directory = new();
        using SyslogOutput output = new(new SyslogOutputOptions { Id = "syslog", SocketPath = Path.Combine(directory.Path, "missing.sock") });

        DeliveryResult result = await output.DeliverAsync(
            [new("a", "sha256:a", """{"eventId":"a"}""", Now), new("b", "sha256:b", """{"eventId":"b"}""", Now)],
            TestContext.Current.CancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal(SyslogOutput.SocketUnavailableCode, failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
        });
        Assert.Equal(["a", "b"], result.Failures.Select(failure => failure.EventId));
    }

    [Fact]
    public async Task Deliver_DoesNotBlockWhenTheDaemonQueueIsFull()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
        {
            return;
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        // A daemon that never reads: its receive queue fills and stays full. On Linux a blocking
        // send would wait here for ever (macOS fails it at once), so this guards the Linux path CI runs.
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"), receiveBufferBytes: 4_096);
        using SyslogOutput output = new(new SyslogOutputOptions { Id = "syslog", SocketPath = daemon.Path });
        string payload = "{\"eventId\":\"x\",\"attributes\":{\"note\":\"" + new string('a', 4_000) + "\"}}";
        QueuedEvent[] events = [.. Enumerable.Range(0, 2_000).Select(index => new QueuedEvent($"e{index}", $"sha256:{index}", payload, Now))];

        Task<DeliveryResult> delivery = output.DeliverAsync(events, cancellationToken);
        Task finished = await Task.WhenAny(delivery, Task.Delay(TimeSpan.FromSeconds(10), cancellationToken));

        Assert.Same(delivery, finished);
        DeliveryResult result = await delivery;
        Assert.NotEmpty(result.Failures);
        Assert.All(result.Failures, failure => Assert.Equal((SyslogOutput.SocketUnavailableCode, true), (failure.Code, failure.IsRetryable)));
        // Nothing is lost: every event is either acknowledged or kept for retry, in order.
        Assert.Equal(events.Select(item => item.EventId), result.AcknowledgedEventIds.Concat(result.Failures.Select(failure => failure.EventId)));
    }

    [Fact]
    public async Task Deliver_ReconnectsAfterTheDaemonRestarts()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
        {
            return;
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        string path = Path.Combine(directory.Path, "log.sock");
        using SyslogOutput output = new(new SyslogOutputOptions { Id = "syslog", SocketPath = path });
        using (FakeDaemon first = new(path))
        {
            Assert.Single((await output.DeliverAsync([new("a", "sha256:a", """{"eventId":"a"}""", Now)], cancellationToken)).AcknowledgedEventIds);
            first.Receive();
        }

        DeliveryResult whileDown = await output.DeliverAsync([new("b", "sha256:b", """{"eventId":"b"}""", Now)], cancellationToken);
        Assert.Equal(SyslogOutput.SocketUnavailableCode, Assert.Single(whileDown.Failures).Code);

        using FakeDaemon restarted = new(path);
        DeliveryResult afterRestart = await output.DeliverAsync([new("b", "sha256:b", """{"eventId":"b"}""", Now)], cancellationToken);
        Assert.Equal(["b"], afterRestart.AcknowledgedEventIds);
        Assert.Equal("""{"eventId":"b"}""", Decode(restarted.Receive()));
    }

    [Theory]
    [InlineData("BOWER_SYSLOG_OUTPUT_SOCKET", "relative/log.sock", "absolute path")]
    [InlineData("BOWER_SYSLOG_OUTPUT_SOCKET", "/run/a-socket-path-that-is-far-too-long-for-sun-path-because-it-keeps-going-and-going-and-going/log.sock", "at most 103 bytes")]
    [InlineData("BOWER_SYSLOG_OUTPUT_FACILITY", "24", "between 0 and 23")]
    [InlineData("BOWER_SYSLOG_OUTPUT_MAX_BYTES", "512", "between 1024 and 65507")]
    public void Settings_RefuseAnInvalidSyslogOutput(string name, string value, string message)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(Syslog(new() { [name] = value })));

        Assert.Contains(message, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_DefaultToDevLogAndLocal4()
    {
        CollectorSettings settings = CollectorSettings.FromEnvironment(Syslog([]));

        Assert.Equal(("syslog", "/dev/log", 20, 8_192), (settings.OutputType, settings.SyslogOutputSocket, settings.SyslogOutputFacility, settings.SyslogOutputMaximumBytes));
    }

    private static string Base64(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

    /// <summary>The transform: base64_decodestring(substring(SyslogMessage, indexof(...) + 10)).</summary>
    private static string Decode(string message)
    {
        int start = message.IndexOf(SyslogOutput.MessagePrefix, StringComparison.Ordinal);
        Assert.True(start >= 0, message);
        return Encoding.UTF8.GetString(Convert.FromBase64String(message[(start + SyslogOutput.MessagePrefix.Length)..]));
    }

    private static Func<string, string?> Syslog(Dictionary<string, string> overrides)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal)
        {
            ["BOWER_COLLECTOR_ID"] = "edge-01",
            ["BOWER_OUTPUT"] = "syslog"
        };
        foreach ((string name, string value) in overrides)
        {
            values[name] = value;
        }

        return name => values.GetValueOrDefault(name);
    }

    /// <summary>A directory under /tmp: Unix socket paths are limited to about 104 bytes.</summary>
    private sealed class ShortDirectory : IDisposable
    {
        public ShortDirectory()
        {
            Path = System.IO.Path.Combine("/tmp", $"bws-{Guid.NewGuid():N}"[..12]);
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FakeDaemon : IDisposable
    {
        private readonly Socket socket = new(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);

        public FakeDaemon(string path, int? receiveBufferBytes = null)
        {
            Path = path;
            if (receiveBufferBytes is { } bytes)
            {
                socket.ReceiveBufferSize = bytes;
            }

            socket.Bind(new UnixDomainSocketEndPoint(path));
            socket.ReceiveTimeout = 5_000;
        }

        public string Path { get; }

        public string Receive()
        {
            byte[] buffer = new byte[70_000];
            int length = socket.Receive(buffer);
            return Encoding.UTF8.GetString(buffer, 0, length);
        }

        public void Dispose()
        {
            socket.Dispose();
            File.Delete(Path);
        }
    }
}
