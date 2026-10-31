using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Bower.Source.Syslog;

namespace Bower.UnitTests;

/// <summary>
/// Syslog source: RFC 5424/3164 vectors shared with the Rust port
/// (<c>rust/crates/bower-source-syslog/tests/fixtures</c>), framing bounds, configuration
/// validation and the TCP, TLS and UDP listeners against a fake sink. The TLS fixtures are
/// TEST-ONLY keys generated for these tests.
/// </summary>
public sealed class SyslogSourceTests
{
    private static string Fixtures => Path.Combine(AppContext.BaseDirectory, "syslog-vectors");

    [Fact]
    public void SharedVectors_ParseToTheSameRecordsAndFailureCodesAsRust()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Fixtures, "syslog-vectors.json")));
        JsonElement root = document.RootElement;
        string listener = root.GetProperty("listener").GetString()!;
        string protocol = root.GetProperty("protocol").GetString()!;
        string sender = root.GetProperty("sender").GetString()!;
        int count = 0;
        foreach (JsonElement vector in root.GetProperty("vectors").EnumerateArray())
        {
            string name = vector.GetProperty("name").GetString()!;
            byte[] frame = vector.TryGetProperty("frame", out JsonElement text)
                ? Encoding.UTF8.GetBytes(text.GetString()!)
                : Convert.FromBase64String(vector.GetProperty("frameBase64").GetString()!);
            DateTimeOffset receivedAt = DateTimeOffset.Parse(vector.GetProperty("receivedAt").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            string? failure = null;
            string? record = null;
            if (SyslogParser.TryParse(frame, receivedAt, out SyslogMessage? message, out string? parseFailure))
            {
                try
                {
                    record = SyslogRecord.Build(message, frame, listener, protocol, sender, receivedAt);
                }
                catch (SyslogFormatException exception)
                {
                    failure = exception.Code;
                }
            }
            else
            {
                failure = parseFailure;
            }

            if (vector.TryGetProperty("failure", out JsonElement expectedFailure))
            {
                Assert.True(expectedFailure.GetString() == failure, $"{name}: expected {expectedFailure.GetString()}, got {failure ?? "a record"}");
            }
            else
            {
                Assert.True(record is not null, $"{name}: expected a record, got {failure}");
                using JsonDocument actual = JsonDocument.Parse(record);
                string[] expected = [.. vector.GetProperty("record").EnumerateObject().Select(field => $"{field.Name}={field.Value.GetString()}")];
                string[] produced = [.. actual.RootElement.EnumerateObject().Select(field => $"{field.Name}={field.Value.GetString()}")];
                Assert.True(expected.SequenceEqual(produced), $"{name}: record differs");
            }
            count++;
        }
        Assert.True(count > 80);
    }

    [Fact]
    public void Record_IdIsStableForRetransmitsAndDistinctPerSenderAndListener()
    {
        byte[] frame = Encoding.UTF8.GetBytes("<13>1 2026-10-26T08:00:00Z h a - - - msg");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Assert.True(SyslogParser.TryParse(frame, now, out SyslogMessage? message, out _));
        string first = Id(SyslogRecord.Build(message, frame, "edge", "tcp", "192.0.2.10", now));
        string later = Id(SyslogRecord.Build(message, frame, "edge", "udp", "192.0.2.10", now.AddMinutes(5)));
        Assert.Equal(first, later);
        Assert.NotEqual(first, Id(SyslogRecord.Build(message, frame, "edge", "tcp", "192.0.2.11", now)));
        Assert.NotEqual(first, Id(SyslogRecord.Build(message, frame, "core", "tcp", "192.0.2.10", now)));
        Assert.StartsWith("syslog-", first, StringComparison.Ordinal);
        Assert.Equal(39, first.Length);

        static string Id(string record) => JsonDocument.Parse(record).RootElement.GetProperty("id").GetString()!;
    }

    [Fact]
    public void Record_IdentityCannotDistinguishIdenticalEventsFromRetransmissions()
    {
        DateTimeOffset firstTime = new(2026, 10, 26, 8, 0, 0, TimeSpan.Zero);
        foreach (bool timestamped in new[] { true, false })
        {
            byte[] frame = Encoding.UTF8.GetBytes(timestamped
                ? "<13>1 2026-10-26T08:00:00Z h a - - - msg"
                : "<13>1 - h a - - - msg");
            Assert.True(SyslogParser.TryParse(frame, firstTime, out SyslogMessage? message, out _));
            static string Id(string record) => JsonDocument.Parse(record).RootElement.GetProperty("id").GetString()!;
            string first = Id(SyslogRecord.Build(message, frame, "edge", "tcp", "192.0.2.10", firstTime));
            string later = Id(SyslogRecord.Build(message, frame, "edge", "tcp", "192.0.2.10", firstTime.AddSeconds(1)));
            if (timestamped) Assert.Equal(first, later);
            else Assert.NotEqual(first, later);
        }
    }

    [Theory]
    [InlineData("17 <13>1 - - - - - -17 <14>1 - - - - - -", 1)]
    [InlineData("<13>1 - - - - - -\n<14>1 - - - - - -\r\n", 1)]
    [InlineData("<13>1 - - - - - -\n17 <14>1 - - - - - -\n\n", 1)]
    [InlineData("17 <13>1 - - - - - -17 <14>1 - - - - - -", 7)]
    [InlineData("<13>1 - - - - - -\n<14>1 - - - - - -\r\n", 3)]
    public async Task FrameReader_SplitsOctetCountedAndLineFramesAcrossArbitraryReads(string input, int chunk)
    {
        using ChunkedStream stream = new(Encoding.ASCII.GetBytes(input), chunk);
        SyslogFrameReader reader = new(stream, 480);
        List<string> frames = [];
        while (true)
        {
            SyslogFrameResult result = await reader.ReadFrameAsync(TestContext.Current.CancellationToken);
            if (result.IsEnd) { break; }
            Assert.Null(result.Failure);
            frames.Add(Encoding.ASCII.GetString(result.Frame.Span));
        }
        Assert.Equal(["<13>1 - - - - - -", "<14>1 - - - - - -"], frames);
    }

    [Theory]
    [InlineData("481 <13>1 -", "syslog-frame-too-large")]
    [InlineData("99999999 <13>", "syslog-frame-too-large")]
    [InlineData("12a <13>1 - - -", "syslog-octet-count-invalid")]
    [InlineData("12<13>1 - - -", "syslog-octet-count-invalid")]
    [InlineData("0 <13>1 - - -", "syslog-framing-invalid")]
    [InlineData("x<13>1 - - -\n", "syslog-framing-invalid")]
    [InlineData("\u0000<13>1\n", "syslog-framing-invalid")]
    [InlineData("50 <13>1 - - - - - -", "syslog-frame-truncated")]
    [InlineData("20", "syslog-frame-truncated")]
    [InlineData("<13>1 - - - - - - no newline", "syslog-frame-truncated")]
    public async Task FrameReader_FailsClosedOnBadFraming(string input, string expected)
    {
        using ChunkedStream stream = new(Encoding.ASCII.GetBytes(input), 4);
        SyslogFrameReader reader = new(stream, 480);
        SyslogFrameResult result = await reader.ReadFrameAsync(TestContext.Current.CancellationToken);
        Assert.Equal(expected, result.Failure);
    }

    [Fact]
    public async Task FrameReader_BoundsLineFramesWithoutBufferingPastTheLimit()
    {
        byte[] oversized = Encoding.ASCII.GetBytes("<13>" + new string('x', 10_000) + "\n");
        using ChunkedStream stream = new(oversized, 1024);
        SyslogFrameReader reader = new(stream, 480);
        SyslogFrameResult result = await reader.ReadFrameAsync(TestContext.Current.CancellationToken);
        Assert.Equal("syslog-frame-too-large", result.Failure);
        Assert.True(stream.Position < 2048, "reader must stop reading once the bound is exceeded");

        // Exactly the limit is accepted, with or without a trailing CR.
        foreach (string suffix in new[] { "\n", "\r\n" })
        {
            using ChunkedStream exact = new(Encoding.ASCII.GetBytes("<13>" + new string('y', 476) + suffix), 64);
            SyslogFrameResult frame = await new SyslogFrameReader(exact, 480).ReadFrameAsync(TestContext.Current.CancellationToken);
            Assert.Null(frame.Failure);
            Assert.Equal(480, frame.Frame.Length);
        }
        using ChunkedStream counted = new(Encoding.ASCII.GetBytes("480 <13>" + new string('z', 476)), 64);
        Assert.Equal(480, (await new SyslogFrameReader(counted, 480).ReadFrameAsync(TestContext.Current.CancellationToken)).Frame.Length);
    }

    [Fact]
    public async Task FrameReader_WaitsForTheFirstByteOfTheNextFrameSkippingBlankLines()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using ChunkedStream stream = new(Encoding.ASCII.GetBytes("\r\n\n<13>1 - - - - - -\n\r\n"), 2);
        SyslogFrameReader reader = new(stream, 480);
        Assert.True(await reader.WaitForFrameAsync(cancellation));
        Assert.Equal("<13>1 - - - - - -", Encoding.ASCII.GetString((await reader.ReadFrameAsync(cancellation)).Frame.Span));
        // Trailing blank lines do not start a frame: the stream simply ends.
        Assert.False(await reader.WaitForFrameAsync(cancellation));
        Assert.True((await reader.ReadFrameAsync(cancellation)).IsEnd);
    }

    [Theory]
    [InlineData("tcp", "0.0.0.0", false, "a non-loopback address requires protocol tls")]
    [InlineData("udp", "192.0.2.1", false, "a non-loopback address requires protocol tls")]
    [InlineData("tcp", "::", false, "a non-loopback address requires protocol tls")]
    [InlineData("tcp", "0.0.0.0", true, null)]
    [InlineData("udp", "0.0.0.0", true, null)]
    [InlineData("tcp", "127.0.0.1", false, null)]
    [InlineData("tcp", "::1", false, null)]
    [InlineData("udp", "127.0.0.1", false, null)]
    public void Configuration_RefusesNonLoopbackWithoutTlsUnlessOverridden(string protocol, string address, bool allowInsecure, string? expected)
    {
        string json = Config(listener: $$"""
            "id": "edge", "protocol": "{{protocol}}", "address": "{{address}}", "port": 5514,
            "allowInsecureNonLoopback": {{(allowInsecure ? "true" : "false")}},
            "allowedSenders": ["127.0.0.1"], "routes": [{"pack": "p", "parser": 0}]
            """);
        if (expected is null)
        {
            Assert.Single(SyslogSourceConfigurationLoader.Parse(json).Listeners);
        }
        else
        {
            InvalidDataException failure = Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse(json));
            Assert.Contains(expected, failure.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("\"protocol\": \"tls\", \"address\": \"0.0.0.0\"", "tls settings are required for protocol tls")]
    [InlineData("\"protocol\": \"tcp\", \"tls\": {\"certificateFile\": \"c\", \"privateKeyFile\": \"k\"}", "tls settings are required for protocol tls and not allowed otherwise")]
    [InlineData("\"protocol\": \"sctp\"", "protocol must be tcp, tls or udp")]
    [InlineData("\"protocol\": \"tcp\", \"address\": \"localhost\"", "address must be an IP address")]
    [InlineData("\"protocol\": \"tcp\", \"address\": \"127.1\"", "address must be an IP address")]
    [InlineData("\"protocol\": \"tcp\", \"port\": 70000", "port must be between 0 and 65535")]
    [InlineData("\"protocol\": \"tcp\", \"allowedSenders\": []", "allowedSenders must list 1–64")]
    [InlineData("\"protocol\": \"tcp\", \"allowedSenders\": [\"10.0.0.1/8\"]", "is not a valid address or CIDR range")]
    [InlineData("\"protocol\": \"tcp\", \"allowedSenders\": [\"10.0.0.0/33\"]", "is not a valid address or CIDR range")]
    [InlineData("\"protocol\": \"tcp\", \"allowedSenders\": [\"fe80::1%1\"]", "is not a valid address or CIDR range")]
    [InlineData("\"protocol\": \"tcp\", \"maximumMessageBytes\": 65537", "maximumMessageBytes must be between 480 and 65536")]
    [InlineData("\"protocol\": \"tcp\", \"maximumMessageBytes\": 479", "maximumMessageBytes must be between 480 and 65536")]
    [InlineData("\"protocol\": \"tcp\", \"maximumConnections\": 0", "maximumConnections must be between 1 and 1024")]
    [InlineData("\"protocol\": \"tcp\", \"idleTimeoutSeconds\": -1", "idleTimeoutSeconds must be between 0 and 3600")]
    [InlineData("\"protocol\": \"tcp\", \"idleTimeoutSeconds\": 3601", "idleTimeoutSeconds must be between 0 and 3600")]
    [InlineData("\"protocol\": \"tcp\", \"frameTimeoutSeconds\": 0", "frameTimeoutSeconds must be between 1 and 3600")]
    [InlineData("\"protocol\": \"tcp\", \"frameTimeoutSeconds\": 3601", "frameTimeoutSeconds must be between 1 and 3600")]
    [InlineData("\"protocol\": \"tcp\", \"handshakeStartTimeoutSeconds\": 0", "handshakeStartTimeoutSeconds must be between 1 and 3600")]
    [InlineData("\"protocol\": \"tcp\", \"handshakeStartTimeoutSeconds\": 3601", "handshakeStartTimeoutSeconds must be between 1 and 3600")]
    [InlineData("\"protocol\": \"tcp\", \"routes\": []", "routes must list 1–64 entries")]
    [InlineData("\"protocol\": \"tcp\", \"routes\": [{\"pack\": \"\", \"parser\": 0}]", "each route needs a pack id and a parser index of 0 or more")]
    [InlineData("\"protocol\": \"tcp\", \"routes\": [{\"pack\": \"p\", \"parser\": -1}]", "each route needs a pack id and a parser index of 0 or more")]
    [InlineData("\"protocol\": \"tcp\", \"routes\": [{\"pack\": \"p\", \"parser\": 0, \"appName\": \"bad name\"}]", "route hostname and appName must be")]
    [InlineData("\"protocol\": \"tcp\", \"id\": \"Edge\"", "Syslog listener id must be")]
    [InlineData("\"protocol\": \"tcp\", \"unknownSetting\": true", "Syslog source configuration is invalid")]
    public void Configuration_ValidatesEveryBound(string overrides, string expected)
    {
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            ["id"] = "\"edge\"",
            ["address"] = "\"127.0.0.1\"",
            ["port"] = "5514",
            ["allowedSenders"] = "[\"127.0.0.1\"]",
            ["routes"] = "[{\"pack\": \"p\", \"parser\": 0}]"
        };
        using (JsonDocument parsed = JsonDocument.Parse("{" + overrides + "}"))
        {
            foreach (JsonProperty property in parsed.RootElement.EnumerateObject())
            {
                fields[property.Name] = property.Value.GetRawText();
            }
        }
        string json = Config(listener: string.Join(", ", fields.Select(pair => $"\"{pair.Key}\": {pair.Value}")));
        InvalidDataException failure = Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse(json));
        Assert.Contains(expected, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Configuration_RejectsDuplicateListenersWrongKindAndOversizedFiles()
    {
        const string listener = "\"id\": \"edge\", \"protocol\": \"udp\", \"port\": 5514, \"allowedSenders\": [\"127.0.0.1\"], \"routes\": [{\"pack\": \"p\", \"parser\": 0}]";
        string duplicate = $$"""{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{ {{listener}} }, { {{listener}} }]}""";
        Assert.Contains("is listed more than once", Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse(duplicate)).Message, StringComparison.Ordinal);
        Assert.Contains("kind SyslogSource", Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse(Config(listener).Replace("SyslogSource", "Other", StringComparison.Ordinal))).Message, StringComparison.Ordinal);
        Assert.Contains("1–16 listeners", Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse("""{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": []}""")).Message, StringComparison.Ordinal);

        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "syslog.json");
        File.WriteAllText(path, Config(listener) + new string(' ', 262_145));
        Assert.Contains("exceeds 256 KiB", Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.LoadFile(path)).Message, StringComparison.Ordinal);
        Assert.Throws<FileNotFoundException>(() => SyslogSourceConfigurationLoader.LoadFile(Path.Combine(directory.Path, "missing.json")));

        SyslogListenerOptions options = SyslogSourceConfigurationLoader.Parse(Config(listener)).Listeners[0];
        Assert.Equal(65_536, options.MaximumMessageBytes);
        Assert.Equal(64, options.MaximumConnections);
        Assert.Equal(0, options.IdleTimeoutSeconds);
        Assert.Equal(60, options.FrameTimeoutSeconds);
        Assert.Equal(60, options.HandshakeStartTimeoutSeconds);
    }

    /// <summary>
    /// <c>config-vectors.json</c>, shared with the Rust port: non-canonical addresses
    /// (brackets, ports, scopes, whitespace), wrong-case property names and duplicate keys
    /// fail in both runtimes.
    /// </summary>
    [Fact]
    public void ConfigurationVectors_FailClosedLikeRust()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Fixtures, "config-vectors.json")));
        int count = 0;
        foreach (JsonElement vector in document.RootElement.GetProperty("vectors").EnumerateArray())
        {
            string name = vector.GetProperty("name").GetString()!;
            string expected = vector.GetProperty("error").GetString()!;
            string? message = null;
            try
            {
                SyslogSourceConfigurationLoader.Parse(vector.GetProperty("configuration").GetString()!);
            }
            catch (InvalidDataException exception)
            {
                message = exception.Message;
            }
            Assert.True(message is not null && message.Contains(expected, StringComparison.Ordinal), $"{name}: {message ?? "accepted"}");
            count++;
        }
        Assert.True(count >= 30);
    }

    [Fact]
    public void Routes_MatchHostnameAndAppNameInOrder()
    {
        string json = Config(listener: """
            "id": "edge", "protocol": "udp", "port": 5514, "allowedSenders": ["127.0.0.0/8", "::1"],
            "routes": [
              {"hostname": "gw01", "appName": "sshd", "pack": "ssh", "parser": 1},
              {"appName": "sshd", "pack": "ssh", "parser": 0},
              {"hostname": "fw01", "pack": "firewall", "parser": 0},
              {"hostname": "core01", "allowedSenders": ["127.0.0.2"], "pack": "core", "parser": 0}
            ]
            """);
        SyslogListenerOptions listener = SyslogSourceConfigurationLoader.Parse(json).Listeners[0];
        Assert.Equal(1, Route("<13>1 - gw01 sshd - - -")!.Parser);
        Assert.Equal(0, Route("<13>1 - gw02 sshd - - -")!.Parser);
        Assert.Equal("firewall", Route("<13>1 - fw01 kernel - - -")!.Pack);
        Assert.Null(Route("<13>1 - fw02 kernel - - -"));
        Assert.Null(Route("<13>1 - GW01 SSHD - - -"));
        // Hostname and app-name are claimed by the sender; a per-route sender restriction pins them.
        Assert.Null(Route("<13>1 - core01 kernel - - -"));
        Assert.Equal("core", Route("<13>1 - core01 kernel - - -", "127.0.0.2")!.Pack);
        Assert.Equal("core", Route("<13>1 - core01 kernel - - -", "::ffff:127.0.0.2")!.Pack);
        Assert.True(listener.Allows(IPAddress.Parse("127.4.5.6")));
        Assert.True(listener.Allows(IPAddress.Parse("::ffff:127.0.0.1")));
        Assert.True(listener.Allows(IPAddress.IPv6Loopback));
        Assert.False(listener.Allows(IPAddress.Parse("10.0.0.1")));

        SyslogRoute? Route(string frame, string sender = "127.0.0.1")
        {
            Assert.True(SyslogParser.TryParse(Encoding.UTF8.GetBytes(frame), DateTimeOffset.UtcNow, out SyslogMessage? message, out _));
            return listener.Route(message, IPAddress.Parse(sender));
        }
    }

    [Fact]
    public async Task Tcp_AcceptsBothFramingsAndCountsMetadataOnly()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        await using SyslogSource source = await Start("tcp", sink, cancellation);
        using TcpClient client = await Connect(source, cancellation);
        NetworkStream stream = client.GetStream();
        string first = "<38>1 2026-10-26T08:15:00Z gw01 sshd 1 - [auth@32473 user=\"deploy-admin\"] secret-marker";
        await stream.WriteAsync(Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetByteCount(first)} {first}<38>Oct 11 22:14:15 gw01 sshd: line framed\n"), cancellation);
        await sink.WaitForAsync(2, cancellation);
        Assert.Equal("sshd", JsonDocument.Parse(sink.Records[0]).RootElement.GetProperty("appName").GetString());
        Assert.Equal("rfc3164", JsonDocument.Parse(sink.Records[1]).RootElement.GetProperty("format").GetString());

        // An unrouted application is dropped before the sink (default deny) and counted.
        await stream.WriteAsync(Encoding.UTF8.GetBytes("<38>Oct 11 22:14:15 gw01 cron: unrouted\n"), cancellation);
        await stream.WriteAsync(Encoding.UTF8.GetBytes("<999>1 - - - - - -\n"), cancellation);
        SyslogListenerStatus status = await WaitFor(source, value => value.NotRouted == 1 && value.Malformed == 1, cancellation);
        Assert.Equal(4, status.FramesReceived);
        Assert.Equal(2, status.Queued);
        Assert.Equal(1, status.ActiveConnections);
        string serialized = JsonSerializer.Serialize(source.Snapshot(), SyslogJsonContext.Default.IReadOnlyListSyslogListenerStatus);
        Assert.DoesNotContain("secret-marker", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy-admin", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tcp_SlowlorisFramesAreClosedByTheFrameTimeoutButIdleConnectionsStayOpen()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        await using SyslogSource source = await Start("tcp", sink, cancellation, idleTimeoutSeconds: 0, frameTimeoutSeconds: 1);
        using TcpClient slow = await Connect(source, cancellation);
        NetworkStream stream = slow.GetStream();
        // One byte every 300 ms keeps the socket busy but never completes a frame in time.
        byte[] trickle = Encoding.ASCII.GetBytes("<13>1 - - - - - - slow");
        int sent = 0;
        try
        {
            for (; sent < trickle.Length; sent++)
            {
                await stream.WriteAsync(trickle.AsMemory(sent, 1), cancellation);
                await Task.Delay(300, cancellation);
            }
        }
        catch (IOException)
        {
            // Closed by the listener mid-trickle.
        }
        Assert.True(sent < trickle.Length, "connection should close before the trickle completes");
        await WaitFor(source, value => value.Timeouts == 1 && value.ActiveConnections == 0, cancellation);

        // Idle time between frames is not frame time: with idleTimeoutSeconds 0 a quiet sender
        // keeps its connection well past the frame timeout, and its next frame is accepted.
        using TcpClient idle = await Connect(source, cancellation);
        await Task.Delay(2_500, cancellation);
        await idle.GetStream().WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: after a quiet spell\n"), cancellation);
        await sink.WaitForAsync(1, cancellation);
        SyslogListenerStatus status = source.Snapshot()[0];
        Assert.Equal(1, status.Timeouts);
        Assert.Equal(0, status.HalfCloses);
        Assert.Equal(1, status.ActiveConnections);
    }

    [Fact]
    public async Task Tcp_IdleTimeoutHalfClosesAndStillAcceptsFramesTheSenderAlreadySent()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        await using SyslogSource source = await Start("tcp", sink, cancellation, idleTimeoutSeconds: 1, drainMilliseconds: 2_000);
        using TcpClient client = await Connect(source, cancellation);
        NetworkStream stream = client.GetStream();
        // The listener sends FIN (end of stream), not a reset: the sender can still write.
        Assert.Equal(0, await stream.ReadAsync(new byte[1], cancellation));
        await stream.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: crossed the close\n"), cancellation);
        await sink.WaitForAsync(1, cancellation);
        SyslogListenerStatus status = await WaitFor(source, value => value.DrainedFrames == 1, cancellation);
        Assert.Equal(1, status.Timeouts);
        Assert.Equal(1, status.HalfCloses);
        Assert.Equal(1, status.Queued);

        // The sender closes once it sees end of stream; nothing was reset.
        client.Client.Shutdown(SocketShutdown.Send);
        status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal(0, status.PeerResets);
    }

    [Fact]
    public async Task Tcp_DrainEndsAQuietHalfClosedConnection()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        await using SyslogSource source = await Start("tcp", new FakeSink(), cancellation, idleTimeoutSeconds: 1, drainMilliseconds: 300);
        using TcpClient client = await Connect(source, cancellation);
        Assert.Equal(0, await client.GetStream().ReadAsync(new byte[1], cancellation));
        SyslogListenerStatus status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal(1, status.HalfCloses);
        Assert.Equal(0, status.DrainedFrames);
    }

    [Fact]
    public async Task Tcp_APeerResetIsCounted()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        await using SyslogSource source = await Start("tcp", new FakeSink(), cancellation);
        // A raw socket: TcpClient.Dispose shuts down (FIN) before closing.
        Socket client = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(source.Endpoints["edge"], cancellation);
        await WaitFor(source, value => value.ActiveConnections == 1, cancellation);
        // Linger 0: close sends RST, as a sender closing with unread data does.
        client.LingerState = new LingerOption(true, 0);
        client.Dispose();
        SyslogListenerStatus status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal(1, status.PeerResets);
    }

    [Fact]
    public void KeepAlive_IsEnabledWithBowerTiming()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        SyslogSource.ConfigureKeepAlive(socket);
        Assert.NotEqual(0, (int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive)!);
        Assert.Equal(120, (int)socket.GetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime)!);
        Assert.Equal(30, (int)socket.GetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval)!);
        Assert.Equal(30, (int)socket.GetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount)!);
    }

    [Theory]
    [InlineData("70000 <13>1 - - - - - -", "oversized")]
    [InlineData("12x <13>", "framing")]
    [InlineData("hello\n", "framing")]
    public async Task Tcp_BadFramingClosesTheConnectionWithoutSubmitting(string input, string counter)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        await using SyslogSource source = await Start("tcp", sink, cancellation);
        using TcpClient client = await Connect(source, cancellation);
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(input), cancellation);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], cancellation));
        SyslogListenerStatus status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal(counter == "oversized" ? 1 : 0, status.Oversized);
        Assert.Equal(counter == "framing" ? 1 : 0, status.FramingErrors);
        Assert.Empty(sink.Records);
    }

    [Fact]
    public void AcceptFailures_BackOffFrom100MillisecondsToOneSecond()
    {
        TimeSpan[] waits = new TimeSpan[6];
        TimeSpan current = TimeSpan.Zero;
        for (int index = 0; index < waits.Length; index++)
        {
            waits[index] = current = SyslogSource.NextAcceptBackoff(current);
        }
        Assert.Equal([100, 200, 400, 800, 1000, 1000], waits.Select(wait => (int)wait.TotalMilliseconds));
    }

    [Fact]
    public void SenderVectors_NormalisePeersAndIdsLikeRust()
    {
        // Shared with Rust: IPv4-mapped IPv6 becomes IPv4 and an IPv6 interface scope is dropped,
        // so senderAddress and the event id agree across runtimes.
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Fixtures, "sender-vectors.json")));
        JsonElement root = document.RootElement;
        byte[] frame = Encoding.UTF8.GetBytes(root.GetProperty("frame").GetString()!);
        DateTimeOffset receivedAt = DateTimeOffset.Parse(root.GetProperty("receivedAt").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(SyslogParser.TryParse(frame, receivedAt, out SyslogMessage? message, out _));
        JsonElement[] vectors = [.. root.GetProperty("vectors").EnumerateArray()];
        Assert.Equal(5, vectors.Length);
        foreach (JsonElement vector in vectors)
        {
            string name = vector.GetProperty("name").GetString()!;
            string sender = SyslogSource.NormaliseSender(IPEndPoint.Parse(vector.GetProperty("peer").GetString()!).Address).ToString();
            Assert.True(vector.GetProperty("senderAddress").GetString() == sender, $"{name}: {sender}");
            using JsonDocument record = JsonDocument.Parse(SyslogRecord.Build(
                message, frame, root.GetProperty("listener").GetString()!, root.GetProperty("protocol").GetString()!, sender, receivedAt));
            Assert.Equal(sender, record.RootElement.GetProperty("senderAddress").GetString());
            Assert.True(vector.GetProperty("id").GetString() == record.RootElement.GetProperty("id").GetString(), name);
        }
    }

    [Fact]
    public async Task Tcp_ConnectionLimitAndSenderAllowListAreEnforced()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        await using (SyslogSource source = await Start("tcp", sink, cancellation, maximumConnections: 1))
        {
            using TcpClient first = await Connect(source, cancellation);
            await first.GetStream().WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: one\n"), cancellation);
            await sink.WaitForAsync(1, cancellation);
            using TcpClient second = await Connect(source, cancellation);
            Assert.Equal(0, await second.GetStream().ReadAsync(new byte[1], cancellation));
            SyslogListenerStatus status = await WaitFor(source, value => value.ConnectionsRejected == 1, cancellation);
            Assert.Equal(1, status.ConnectionsAccepted);
        }

        await using SyslogSource denied = await Start("tcp", sink, cancellation, allowedSenders: "\"192.0.2.0/24\"");
        using TcpClient outsider = await Connect(denied, cancellation);
        Assert.Equal(0, await outsider.GetStream().ReadAsync(new byte[1], cancellation));
        SyslogListenerStatus refused = await WaitFor(denied, value => value.SendersDenied == 1, cancellation);
        Assert.Equal(0, refused.ConnectionsAccepted);
    }

    [Fact]
    public async Task Tcp_QueueBackpressureStopsReadingAndRetriesTheSameFrame()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new() { UnavailableResponses = 3 };
        await using SyslogSource source = await Start("tcp", sink, cancellation);
        using TcpClient client = await Connect(source, cancellation);
        await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: first\n<38>Oct 11 22:14:15 gw01 sshd: second\n"), cancellation);
        await sink.WaitForAsync(2, cancellation);
        Assert.Contains("first", JsonDocument.Parse(sink.Records[0]).RootElement.GetProperty("message").GetString(), StringComparison.Ordinal);
        Assert.Contains("second", JsonDocument.Parse(sink.Records[1]).RootElement.GetProperty("message").GetString(), StringComparison.Ordinal);
        SyslogListenerStatus status = source.Snapshot()[0];
        Assert.Equal(3, status.Retries);
        Assert.Equal(0, status.Dropped);
        Assert.Equal(2, status.Queued);
        Assert.Equal(5, sink.Attempts);
    }

    [Fact]
    public async Task Tcp_SinkFailureClosesTheConnectionSoTheSenderSeesIt()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new() { Throw = true };
        await using SyslogSource source = await Start("tcp", sink, cancellation);
        using TcpClient client = await Connect(source, cancellation);
        await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: first\n"), cancellation);
        Assert.Equal(0, await client.GetStream().ReadAsync(new byte[1], cancellation));
        Assert.Equal(1, (await WaitFor(source, value => value.SubmitFailures == 1, cancellation)).SubmitFailures);
    }

    [Fact]
    public async Task Udp_IsBestEffortAndCountsDropsUnderBackpressure()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new() { UnavailableResponses = 1 };
        await using SyslogSource source = await Start("udp", sink, cancellation);
        using UdpClient client = new(AddressFamily.InterNetwork);
        IPEndPoint endpoint = source.Endpoints["edge"];
        await client.SendAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: dropped when the queue is full\n"), endpoint, cancellation);
        await client.SendAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: accepted"), endpoint, cancellation);
        await client.SendAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: " + new string('x', 600)), endpoint, cancellation);
        SyslogListenerStatus status = await WaitFor(source, value => value.Queued == 1 && value.Dropped == 1 && value.Oversized == 1, cancellation);
        Assert.Equal(0, status.Retries);
        Assert.Equal("accepted", JsonDocument.Parse(Assert.Single(sink.Records)).RootElement.GetProperty("message").GetString());

        // A blocked sink fills the bounded datagram queue; further datagrams are dropped, never buffered without bound.
        sink.Block = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        for (int index = 0; index < SyslogSource.UdpQueueCapacity + 64; index++)
        {
            await client.SendAsync(Encoding.ASCII.GetBytes($"<38>Oct 11 22:14:15 gw01 sshd: flood {index}"), endpoint, cancellation);
        }
        status = await WaitFor(source, value => value.Dropped > 1, cancellation);
        sink.Block.SetResult();
        Assert.True(status.FramesReceived <= SyslogSource.UdpQueueCapacity + 64 + 3);
    }

    [Fact]
    public async Task Tls_RequiresTheConfiguredCertificateAndOptionalClientCertificate()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        string tls = Path.Combine(Fixtures, "tls");
        string serverTls = $$"""{"certificateFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server.pem"))}}, "privateKeyFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server-key.pem"))}}}""";
        await using (SyslogSource source = await Start("tls", sink, cancellation, tls: serverTls))
        {
            await using SslStream stream = await ConnectTls(source, client: null, cancellation);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: over tls\n"), cancellation);
            await sink.WaitForAsync(1, cancellation);
            Assert.Equal("tls", JsonDocument.Parse(sink.Records[0]).RootElement.GetProperty("protocol").GetString());

            // Plain text to a TLS listener is a handshake failure, never a frame.
            using TcpClient plain = await Connect(source, cancellation);
            await plain.GetStream().WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: plain\n"), cancellation);
            await WaitFor(source, value => value.TlsHandshakeFailures == 1, cancellation);
            Assert.Single(sink.Records);
        }

        string mutualTls = serverTls.TrimEnd('}') + $$""", "clientCertificateAuthorityFile": {{JsonSerializer.Serialize(Path.Combine(tls, "ca.pem"))}}}""";
        await using SyslogSource mutual = await Start("tls", sink, cancellation, tls: mutualTls);
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using SslStream anonymous = await ConnectTls(mutual, client: null, cancellation);
            await anonymous.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: anonymous\n"), cancellation);
            Assert.Equal(0, await anonymous.ReadAsync(new byte[1], cancellation));
            throw new AuthenticationException("closed");
        });
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using SslStream rogue = await ConnectTls(mutual, LoadClient("rogue"), cancellation);
            await rogue.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: rogue\n"), cancellation);
            Assert.Equal(0, await rogue.ReadAsync(new byte[1], cancellation));
            throw new AuthenticationException("closed");
        });
        await WaitFor(mutual, value => value.TlsHandshakeFailures == 2, cancellation);
        await using SslStream trusted = await ConnectTls(mutual, LoadClient("client"), cancellation);
        await trusted.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: mutual\n"), cancellation);
        await sink.WaitForAsync(2, cancellation);
        Assert.Equal("mutual", JsonDocument.Parse(sink.Records[1]).RootElement.GetProperty("message").GetString());

        X509Certificate2 LoadClient(string name)
        {
            using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(Path.Combine(tls, name + ".pem"), Path.Combine(tls, name + "-key.pem"));
            return X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
        }
    }

    [Fact]
    public async Task Tls_AConnectionMayWaitIdleBeforeItsHandshake()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        string tls = Path.Combine(Fixtures, "tls");
        string serverTls = $$"""{"certificateFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server.pem"))}}, "privateKeyFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server-key.pem"))}}}""";
        await using SyslogSource source = await Start("tls", sink, cancellation, tls: serverTls, idleTimeoutSeconds: 0, frameTimeoutSeconds: 1);
        // syslog-ng connects first and starts TLS only when it has a message: that wait is idle
        // time, so it is not cut short by the frame (handshake) timeout or counted as a failure.
        using TcpClient tcp = await Connect(source, cancellation);
        await Task.Delay(2_500, cancellation);
        await using SslStream stream = new(tcp.GetStream(), leaveInnerStreamOpen: true, (_, certificate, _, _) => IssuedByTestCa(certificate));
        await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "localhost" }, cancellation);
        await stream.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: late handshake\n"), cancellation);
        await sink.WaitForAsync(1, cancellation);
        SyslogListenerStatus status = source.Snapshot()[0];
        Assert.Equal((0, 0), (status.TlsHandshakeFailures, status.Timeouts));
    }

    [Fact]
    public async Task Tls_UnstartedHandshakeExpiresAndReleasesConnectionSlot()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        string tls = Path.Combine(Fixtures, "tls");
        string serverTls = $$"""{"certificateFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server.pem"))}}, "privateKeyFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server-key.pem"))}}}""";
        await using SyslogSource source = await Start("tls", sink, cancellation, tls: serverTls,
            idleTimeoutSeconds: 0, maximumConnections: 1, handshakeStartTimeoutSeconds: 1);
        using TcpClient stalled = await Connect(source, cancellation);
        await WaitFor(source, value => value.ActiveConnections == 1, cancellation);
        SyslogListenerStatus expired = await WaitFor(source, value => value.ActiveConnections == 0 && value.Timeouts == 1, cancellation);
        Assert.Equal(0, expired.TlsHandshakeFailures);
        await using SslStream stream = await ConnectTls(source, null, cancellation);
        // Established TLS uses the independent idle setting, not the handshake-start bound.
        await Task.Delay(1_500, cancellation);
        await stream.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: after timeout\n"), cancellation);
        await sink.WaitForAsync(1, cancellation);
    }

    [Fact]
    public async Task Tls_AcceptsAClientCertificateIssuedByAnIntermediateTheSenderSupplies()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        string tls = Path.Combine(Fixtures, "tls");
        string mutual = $$"""{"certificateFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server.pem"))}}, "privateKeyFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server-key.pem"))}}, "clientCertificateAuthorityFile": {{JsonSerializer.Serialize(Path.Combine(tls, "ca.pem"))}}}""";
        await using SyslogSource source = await Start("tls", sink, cancellation, tls: mutual);
        // chained-client.pem: leaf issued by an intermediate, followed by that intermediate.
        X509Certificate2Collection chain = [];
        chain.ImportFromPemFile(Path.Combine(tls, "chained-client.pem"));
        using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(Path.Combine(tls, "chained-client.pem"), Path.Combine(tls, "chained-client-key.pem"));
        X509Certificate2 leaf = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
        await using SslStream stream = await ConnectTls(source, leaf, cancellation, [.. chain.Skip(1)]);
        await stream.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: chained\n"), cancellation);
        await sink.WaitForAsync(1, cancellation);
        Assert.Equal("chained", JsonDocument.Parse(sink.Records[0]).RootElement.GetProperty("message").GetString());
        Assert.Equal(0, source.Snapshot()[0].TlsHandshakeFailures);
    }

    [Fact]
    public async Task Tls_UnreadableCertificateStopsStartWithoutLeakingPaths()
    {
        using TemporaryDirectory directory = new();
        string key = Path.Combine(directory.Path, "key.pem");
        File.WriteAllText(key, "not a key");
        string tls = $$"""{"certificateFile": {{JsonSerializer.Serialize(key)}}, "privateKeyFile": {{JsonSerializer.Serialize(key)}}}""";
        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using SyslogSource source = await Start("tls", new FakeSink(), TestContext.Current.CancellationToken, tls: tls);
        });
        Assert.Contains("TLS certificate or key could not be loaded", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("not a key", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Stop_WaitsForConnectionsRegisteredAfterShutdownSnapshot()
    {
        TaskCompletionSource releaseListener = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource registered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource snapshotTaken = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource connection = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ConcurrentDictionary<Task, byte> running = new();
        async Task RegisterConnectionAsync()
        {
            await releaseListener.Task;
            running.TryAdd(connection.Task, 0);
            registered.SetResult();
        }

        Task listener = RegisterConnectionAsync();
        Task stopped = SyslogSource.WaitForListenersAndConnectionsAsync([listener], () =>
        {
            snapshotTaken.SetResult();
            return [.. running.Keys];
        });
        releaseListener.SetResult();
        await registered.Task.WaitAsync(TestContext.Current.CancellationToken);
        await snapshotTaken.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.False(stopped.IsCompleted);
        connection.SetResult();
        await stopped.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Stop_WaitsForConnectionsWhenListenerEndsWithCancellation()
    {
        TaskCompletionSource connection = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ConcurrentDictionary<Task, byte> running = new();
        running.TryAdd(connection.Task, 0);
        Task listener = Task.FromException(new OperationCanceledException());
        Task stopped = SyslogSource.WaitForListenersAndConnectionsAsync([listener], () => [.. running.Keys]);
        Assert.False(stopped.IsCompleted);
        connection.SetResult();
        await stopped.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Stop_CancelsOpenConnectionsAndBlockedSubmissionsPromptly()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new() { UnavailableResponses = int.MaxValue };
        SyslogSource source = await Start("tcp", sink, cancellation);
        using TcpClient idle = await Connect(source, cancellation);
        using TcpClient blocked = await Connect(source, cancellation);
        await blocked.GetStream().WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: never durable\n"), cancellation);
        await WaitFor(source, value => value.Retries > 0, cancellation);
        System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();
        await source.DisposeAsync();
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
        Assert.Equal(0, source.Snapshot()[0].Queued);
        Assert.Equal(0, await idle.GetStream().ReadAsync(new byte[1], cancellation));
    }

    [Fact]
    public async Task Stop_HalfClosesAndEnqueuesFramesTheSenderSendsBeforeItSeesTheEnd()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeSink sink = new();
        SyslogSource source = await Start("tcp", sink, cancellation, drainMilliseconds: 3_000, stopMilliseconds: 8_000);
        using TcpClient client = await Connect(source, cancellation);
        NetworkStream stream = client.GetStream();
        await WaitFor(source, value => value.ActiveConnections == 1, cancellation);
        ValueTask stopping = source.DisposeAsync();
        // The sender sees end of stream, but what it writes until then is still accepted.
        Assert.Equal(0, await stream.ReadAsync(new byte[1], cancellation));
        await stream.WriteAsync(Encoding.ASCII.GetBytes("<38>Oct 11 22:14:15 gw01 sshd: in flight at stop\n"), cancellation);
        await sink.WaitForAsync(1, cancellation);
        client.Client.Shutdown(SocketShutdown.Send);
        await stopping;
        SyslogListenerStatus status = source.Snapshot()[0];
        Assert.Equal(1, status.Queued);
        Assert.Equal(1, status.HalfCloses);
        Assert.Equal(1, status.DrainedFrames);
        Assert.Equal(0, status.ActiveConnections);
    }

    internal static string Config(string listener) =>
        $$"""{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{ {{listener}} }]}""";

    private static async Task<SyslogSource> Start(string protocol, FakeSink sink, CancellationToken cancellation,
        int idleTimeoutSeconds = 30, int maximumConnections = 8, string allowedSenders = "\"127.0.0.1\", \"::1\"", string? tls = null,
        int frameTimeoutSeconds = 30, int drainMilliseconds = 500, int stopMilliseconds = 1_000,
        int handshakeStartTimeoutSeconds = 60)
    {
        string json = Config(listener: $$"""
            "id": "edge", "protocol": "{{protocol}}", "address": "127.0.0.1", "port": 0,
            "allowedSenders": [{{allowedSenders}}], "maximumMessageBytes": 512,
            "maximumConnections": {{maximumConnections}}, "idleTimeoutSeconds": {{idleTimeoutSeconds}},
            "frameTimeoutSeconds": {{frameTimeoutSeconds}},
            "handshakeStartTimeoutSeconds": {{handshakeStartTimeoutSeconds}},
            {{(tls is null ? "" : "\"tls\": " + tls + ",")}}
            "routes": [{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}]
            """);
        SyslogSource source = new(SyslogSourceConfigurationLoader.Parse(json), sink)
        {
            RetryDelay = TimeSpan.FromMilliseconds(20),
            DrainTimeout = TimeSpan.FromMilliseconds(drainMilliseconds),
            StopTimeout = TimeSpan.FromMilliseconds(stopMilliseconds)
        };
        try
        {
            await source.StartAsync(cancellation);
        }
        catch
        {
            await source.DisposeAsync();
            throw;
        }
        return source;
    }

    private static async Task<TcpClient> Connect(SyslogSource source, CancellationToken cancellation)
    {
        TcpClient client = new(AddressFamily.InterNetwork);
        await client.ConnectAsync(source.Endpoints["edge"], cancellation);
        return client;
    }

    private static async Task<SslStream> ConnectTls(SyslogSource source, X509Certificate2? client, CancellationToken cancellation,
        X509Certificate2Collection? intermediates = null)
    {
        TcpClient tcp = await Connect(source, cancellation);
        SslStream stream = new(tcp.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) => IssuedByTestCa(certificate));
        await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            ClientCertificates = client is null || intermediates is not null ? null : new X509CertificateCollection(new X509Certificate[] { client }),
            // Sends the intermediates with the leaf, as a sender with a chained certificate does.
            ClientCertificateContext = client is null || intermediates is null ? null : SslStreamCertificateContext.Create(client, intermediates, offline: true),
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        }, cancellation);
        return stream;
    }

    private static bool IssuedByTestCa(X509Certificate? certificate)
    {
        if (certificate is null) { return false; }
        X509Certificate2Collection authorities = [];
        authorities.ImportFromPemFile(Path.Combine(Fixtures, "tls", "ca.pem"));
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(authorities[0]);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));
    }

    private static async Task<SyslogListenerStatus> WaitFor(SyslogSource source, Func<SyslogListenerStatus, bool> condition, CancellationToken cancellation)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (true)
        {
            SyslogListenerStatus status = source.Snapshot()[0];
            if (condition(status)) { return status; }
            await Task.Delay(20, timeout.Token);
        }
    }

    internal sealed class FakeSink : ISyslogSink
    {
        private readonly ConcurrentQueue<string> records = new();
        private int unavailable;

        public int UnavailableResponses { get => unavailable; init => unavailable = value; }

        public bool Throw { get; init; }

        public TaskCompletionSource? Block { get; set; }

        public int Attempts;

        public IReadOnlyList<string> Records => [.. records];

        public async ValueTask<SyslogSubmitOutcome> SubmitAsync(SyslogListenerOptions listener, SyslogRoute route, string record, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Attempts);
            if (Block is { } block) { await block.Task.WaitAsync(cancellationToken); }
            if (Throw) { throw new IOException("synthetic-storage-failure"); }
            if (Interlocked.Decrement(ref unavailable) >= 0) { return SyslogSubmitOutcome.Unavailable; }
            records.Enqueue(record);
            return SyslogSubmitOutcome.Queued;
        }

        public async Task WaitForAsync(int count, CancellationToken cancellation)
        {
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            while (records.Count < count) { await Task.Delay(20, timeout.Token); }
        }
    }

    private sealed class ChunkedStream(byte[] data, int chunk) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, chunk)], cancellationToken);
    }
}
