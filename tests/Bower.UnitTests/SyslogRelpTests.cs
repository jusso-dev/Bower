using System.Collections.Concurrent;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Bower.Source.Syslog;

namespace Bower.UnitTests;

/// <summary>
/// RELP listener: framing and offer vectors
/// (<c>tests/fixtures/syslog-vectors/relp-vectors.json</c>), malformed and
/// oversized input, acknowledgement only after a durable decision, bounded backpressure,
/// crash/resend deduplication, stop, and mutual TLS. The TLS fixtures are TEST-ONLY keys.
/// </summary>
public sealed class SyslogRelpTests
{
    private const string Offers = "relp_version=0\nrelp_software=librelp,1.12.0,http://librelp.adiscon.com\ncommands=syslog";

    private static string Fixtures => Path.Combine(AppContext.BaseDirectory, "syslog-vectors");

    private static JsonElement Vectors => JsonDocument.Parse(File.ReadAllText(Path.Combine(Fixtures, "relp-vectors.json"))).RootElement;

    public static TheoryData<string, int> Chunks => new() { { "whole", 1 << 20 }, { "bytes", 1 }, { "sevens", 7 } };

    [Theory]
    [MemberData(nameof(Chunks))]
    public async Task FrameVectors_ParseAcrossArbitraryReads(string name, int chunk)
    {
        Assert.NotEmpty(name);
        foreach (JsonElement vector in Vectors.GetProperty("frames").EnumerateArray())
        {
            string label = vector.GetProperty("name").GetString()!;
            RelpFrameReader reader = new(new ChunkedStream(Encoding.ASCII.GetBytes(vector.GetProperty("input").GetString()!), chunk),
                vector.GetProperty("maximum").GetInt32());
            foreach (JsonElement expected in vector.GetProperty("results").EnumerateArray())
            {
                RelpFrameResult result = await reader.ReadFrameAsync(TestContext.Current.CancellationToken);
                if (expected.ValueKind == JsonValueKind.String)
                {
                    Assert.True(result.IsEnd, label);
                }
                else if (expected.TryGetProperty("failure", out JsonElement failure))
                {
                    Assert.True(failure.GetString() == result.Failure, $"{label}: {result.Failure}");
                }
                else
                {
                    Assert.True(result.Failure is null, $"{label}: {result.Failure}");
                    Assert.Equal(expected.GetProperty("transaction").GetInt64(), result.Transaction);
                    Assert.Equal(expected.GetProperty("command").GetString(), Name(result.Command));
                    Assert.Equal(expected.GetProperty("data").GetString(), Encoding.ASCII.GetString(result.Data.Span));
                    Assert.Equal(expected.GetProperty("oversized").GetBoolean(), result.Oversized);
                }
            }
        }
    }

    [Fact]
    public void OfferAndResponseVectors_Match()
    {
        foreach (JsonElement vector in Vectors.GetProperty("offers").EnumerateArray())
        {
            bool accepted = RelpProtocol.TryAcceptOffers(Encoding.ASCII.GetBytes(vector.GetProperty("data").GetString()!), out string? failure);
            Assert.True(vector.GetProperty("accepted").GetBoolean() == accepted, vector.GetProperty("name").GetString());
            Assert.Equal(accepted ? null : RelpFailures.OffersInvalid, failure);
        }

        foreach (JsonElement vector in Vectors.GetProperty("responses").EnumerateArray())
        {
            long transaction = vector.GetProperty("transaction").GetInt64();
            byte[] frame = vector.GetProperty("kind").GetString() switch
            {
                "openAccepted" => RelpProtocol.OpenAccepted(transaction),
                "acknowledge" => RelpProtocol.Acknowledge(transaction),
                "openRefused" => RelpProtocol.OpenRefused(transaction),
                "closeAccepted" => RelpProtocol.CloseAccepted(transaction),
                _ => RelpProtocol.ServerClose()
            };
            Assert.Equal(vector.GetProperty("text").GetString(), Encoding.ASCII.GetString(frame));
        }

        foreach (JsonElement pair in Vectors.GetProperty("transactions").EnumerateArray())
        {
            Assert.Equal(pair[1].GetInt64(), RelpProtocol.Next(pair[0].GetInt64()));
        }
    }

    [Fact]
    public async Task FrameReader_RandomAndMutatedInputFailsClosedWithinItsBuffer()
    {
        // Fuzz-style: arbitrary bytes and single-byte mutations of valid frames never throw,
        // never return data beyond the limit and always end in a frame, a failure or the end.
        Random random = new(5424);
        byte[] valid = Encoding.ASCII.GetBytes($"1 open {Offers.Length} {Offers}\n2 syslog 13 <13>1 - - - -\n3 close 0\n");
        for (int round = 0; round < 2_000; round++)
        {
            byte[] input;
            if (round % 2 == 0)
            {
                input = new byte[random.Next(0, 200)];
                random.NextBytes(input);
            }
            else
            {
                input = (byte[])valid.Clone();
                input[random.Next(input.Length)] = (byte)random.Next(256);
            }

            RelpFrameReader reader = new(new ChunkedStream(input, random.Next(1, 16)), 128);
            for (int frames = 0; frames < 8; frames++)
            {
                RelpFrameResult result = await reader.ReadFrameAsync(TestContext.Current.CancellationToken);
                Assert.True(result.Data.Length <= 128);
                if (result.IsEnd || result.Failure is not null)
                {
                    break;
                }
            }
        }
    }

    [Fact]
    public void Configuration_RelpNeedsTlsBeyondLoopbackAndAcceptsTlsSettings()
    {
        string tls = $$"""{"certificateFile": "/s.pem", "privateKeyFile": "/k.pem"}""";
        InvalidDataException plain = Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse(Listener("relp", "10.0.0.5", tls: null)));
        Assert.Contains("requires protocol tls (or relp with tls)", plain.Message, StringComparison.Ordinal);
        Assert.Equal("relp", SyslogSourceConfigurationLoader.Parse(Listener("relp", "10.0.0.5", tls)).Listeners[0].Protocol);
        Assert.Equal("relp", SyslogSourceConfigurationLoader.Parse(Listener("relp", "127.0.0.1", tls: null)).Listeners[0].Protocol);
        Assert.Contains("optional for relp", Assert.Throws<InvalidDataException>(() =>
            SyslogSourceConfigurationLoader.Parse(Listener("tcp", "127.0.0.1", tls))).Message, StringComparison.Ordinal);
        Assert.Contains("protocol must be tcp, tls, udp or relp", Assert.Throws<InvalidDataException>(() =>
            SyslogSourceConfigurationLoader.Parse(Listener("RELP", "127.0.0.1", tls: null))).Message, StringComparison.Ordinal);

        static string Listener(string protocol, string address, string? tls) => SyslogSourceTests.Config($$"""
            "id": "edge", "protocol": "{{protocol}}", "address": "{{address}}", "port": 0, "allowedSenders": ["10.0.0.1"],
            {{(tls is null ? "" : "\"tls\": " + tls + ",")}}
            "routes": [{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}]
            """);
    }

    [Fact]
    public void Record_RelpIdsIncludeReceiveTimeOnlyWithoutATimestamp()
    {
        DateTimeOffset first = DateTimeOffset.Parse("2026-11-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        byte[] bare = "<38>1 - gw01 sshd - - - no timestamp"u8.ToArray();
        byte[] stamped = "<38>1 2026-11-01T00:00:00.000001Z gw01 sshd - - - timestamp"u8.ToArray();
        // Without a timestamp, distinct identical messages stay distinct, as for plain TCP.
        Assert.NotEqual(Id(bare, first), Id(bare, first.AddSeconds(1)));
        // With one, a resend is the same event whenever it arrives.
        Assert.Equal(Id(stamped, first), Id(stamped, first.AddMinutes(30)));

        static string Id(byte[] frame, DateTimeOffset at)
        {
            Assert.True(SyslogParser.TryParse(frame, at, out SyslogMessage? message, out _));
            return JsonDocument.Parse(SyslogRecord.Build(message!, frame, "edge", "relp", "10.0.0.1", at)).RootElement.GetProperty("id").GetString()!;
        }
    }

    [Fact]
    public async Task Session_IdenticalTimestamplessMessagesAreAllKeptAndATimestampedResendIsADuplicate()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        DurableSink sink = new() { CommitLimit = int.MaxValue };
        TimeProvider clock = new SteppingClock();
        await using SyslogSource source = await Start(sink, cancellation, clock: clock);
        await using (Client client = await Client.ConnectAsync(source, cancellation))
        {
            await client.OpenAsync(cancellation);
            // Two genuinely distinct events with identical bytes and no timestamp.
            await client.SendAsync(2, "<38>1 - gw01 sshd - - - repeated denial", cancellation);
            await client.SendAsync(3, "<38>1 - gw01 sshd - - - repeated denial", cancellation);
            await client.SendAsync(4, "<38>1 2026-11-01T00:00:00.000001Z gw01 sshd - - - stamped", cancellation);
            for (int transaction = 2; transaction <= 4; transaction++)
            {
                Assert.Equal($"{transaction} rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
            }
        }

        // The sender reconnects and resends the timestamped message: one event, not two.
        await using Client again = await Client.ConnectAsync(source, cancellation);
        await again.OpenAsync(cancellation);
        await again.SendAsync(2, "<38>1 2026-11-01T00:00:00.000001Z gw01 sshd - - - stamped", cancellation);
        Assert.Equal("2 rsp 6 200 OK\n", await again.ReadFrameAsync(cancellation));
        Assert.Equal(["repeated denial", "repeated denial", "stamped"], sink.Committed.Values.Order(StringComparer.Ordinal));
        SyslogListenerStatus status = source.Snapshot()[0];
        Assert.Equal((3, 1), (status.Queued, status.Duplicates));
    }

    [Fact]
    public async Task Session_OpensAcknowledgesEachMessageAfterItsDecisionAndCloses()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(sink, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        Assert.Equal("1 rsp 57 200 OK\nrelp_version=0\nrelp_software=bower\ncommands=syslog\n", await client.OpenAsync(cancellation));
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: accepted\n", cancellation);
        await client.SendAsync(3, "<38>Oct 11 22:14:15 gw01 cron: not routed", cancellation);
        await client.SendAsync(4, "not syslog", cancellation);
        Assert.Equal("2 rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        Assert.Equal("3 rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        Assert.Equal("4 rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        await client.WriteAsync("5 close 0\n", cancellation);
        Assert.Equal("5 rsp 0\n", await client.ReadFrameAsync(cancellation));
        Assert.Null(await client.ReadFrameAsync(cancellation));
        JsonElement record = JsonDocument.Parse(Assert.Single(sink.Records)).RootElement;
        Assert.Equal("relp", record.GetProperty("protocol").GetString());
        Assert.Equal("accepted", record.GetProperty("message").GetString());
        SyslogListenerStatus status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal((1, 1, 1, 3, 0), (status.Queued, status.NotRouted, status.Malformed, status.RelpAcknowledged, status.FramingErrors));
    }

    [Fact]
    public async Task Session_NeverAcknowledgesBeforeTheSinkCommits()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new() { Block = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) };
        await using SyslogSource source = await Start(sink, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: held", cancellation);
        Task<string?> response = client.ReadFrameAsync(cancellation);
        await Task.Delay(300, cancellation);
        Assert.False(response.IsCompleted);
        Assert.Equal(0, source.Snapshot()[0].RelpAcknowledged);
        sink.Block.SetResult();
        Assert.Equal("2 rsp 6 200 OK\n", await response);
        Assert.Single(sink.Records);
    }

    [Fact]
    public async Task Session_AFailedCommitIsNeverAcknowledgedAndEndsTheSession()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new() { Throw = true };
        await using SyslogSource source = await Start(sink, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: storage fails", cancellation);
        Assert.Null(await client.ReadFrameAsync(cancellation));
        SyslogListenerStatus status = await WaitFor(source, value => value.SubmitFailures == 1, cancellation);
        Assert.Equal(0, status.RelpAcknowledged);
    }

    [Fact]
    public async Task Session_AQueueThatKeepsRefusingEndsTheSessionUnacknowledgedThenTheResendIsQueued()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new() { UnavailableResponses = 1_000_000 };
        await using SyslogSource source = await Start(sink, cancellation, busy: TimeSpan.FromMilliseconds(300));
        string message = "<38>1 2026-11-01T00:00:00.000001Z gw01 sshd - - - refused then accepted";
        await using (Client refused = await Client.ConnectAsync(source, cancellation))
        {
            await refused.OpenAsync(cancellation);
            await refused.SendAsync(2, message, cancellation);
            Assert.Equal("0 serverclose 0\n", await refused.ReadFrameAsync(cancellation));
            Assert.Null(await refused.ReadFrameAsync(cancellation));
        }

        SyslogListenerStatus status = await WaitFor(source, value => value.RelpBusyCloses == 1 && value.ActiveConnections == 0, cancellation);
        Assert.Equal((0, 1, 0), (status.RelpAcknowledged, status.RelpServerCloses, status.Queued));
        Assert.True(status.Retries > 0);

        // Capacity returns: the sender reconnects and resends; the message is queued exactly once.
        sink.Accept();
        await using Client resend = await Client.ConnectAsync(source, cancellation);
        await resend.OpenAsync(cancellation);
        await resend.SendAsync(2, message, cancellation);
        Assert.Equal("2 rsp 6 200 OK\n", await resend.ReadFrameAsync(cancellation));
        Assert.Single(sink.Records);
    }

    [Fact]
    public async Task Session_CrashAfterCommitBeforeAcknowledgementThenResendYieldsTheExactSetOnce()
    {
        // A durable sink shared by two collector "processes". The first stops responding right
        // after its 37th commit, before that commit is acknowledged, and is then stopped like a
        // crashed process; the client resends everything it has no acknowledgement for.
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        DurableSink sink = new() { CommitLimit = 37 };
        string[] messages = [.. Enumerable.Range(0, 128).Select(index => $"<38>1 2026-11-01T00:00:00.{index:000000}Z gw01 sshd - - - seq={index}")];
        HashSet<int> acknowledged = [];
        SyslogSource first = await Start(sink, cancellation, stopMilliseconds: 200);
        await using (Client client = await Client.ConnectAsync(first, cancellation))
        {
            await client.OpenAsync(cancellation);
            for (int index = 0; index < messages.Length; index++)
            {
                await client.SendAsync(index + 2, messages[index], cancellation);
            }

            await sink.LimitReached.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellation);
            await first.DisposeAsync();
            while (await client.ReadFrameAsync(cancellation) is { } frame)
            {
                Assert.EndsWith(" rsp 6 200 OK\n", frame, StringComparison.Ordinal);
                acknowledged.Add(int.Parse(frame[..frame.IndexOf(' ', StringComparison.Ordinal)], System.Globalization.CultureInfo.InvariantCulture) - 2);
            }
        }

        Assert.Equal(37, sink.Committed.Count);
        Assert.Equal(Enumerable.Range(0, 36), acknowledged.Order());

        sink.CommitLimit = int.MaxValue;
        await using SyslogSource second = await Start(sink, cancellation);
        await using Client again = await Client.ConnectAsync(second, cancellation);
        await again.OpenAsync(cancellation);
        long transaction = 2;
        foreach (int index in Enumerable.Range(0, messages.Length).Where(index => !acknowledged.Contains(index)))
        {
            await again.SendAsync(transaction++, messages[index], cancellation);
        }

        for (long expected = 2; expected < transaction; expected++)
        {
            Assert.Equal($"{expected} rsp 6 200 OK\n", await again.ReadFrameAsync(cancellation));
        }

        Assert.Equal(Enumerable.Range(0, 128).Select(index => $"seq={index}").Order(StringComparer.Ordinal),
            sink.Committed.Values.Order(StringComparer.Ordinal));
        SyslogListenerStatus status = second.Snapshot()[0];
        Assert.Equal((91, 1), (status.Queued, status.Duplicates));
    }

    [Fact]
    public async Task Session_AFullWindowIsAcknowledgedInOrderWithoutReadingAhead()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(sink, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        StringBuilder window = new();
        for (int index = 0; index < 128; index++)
        {
            string data = $"<38>Oct 11 22:14:15 gw01 sshd: window {index}";
            window.Append(CultureInfo(index + 2)).Append(" syslog ").Append(CultureInfo(data.Length)).Append(' ').Append(data).Append('\n');
        }

        await client.WriteAsync(window.ToString(), cancellation);
        for (int index = 0; index < 128; index++)
        {
            Assert.Equal($"{index + 2} rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        }

        Assert.Equal(128, sink.Records.Count);
        Assert.Equal("window 127", JsonDocument.Parse(sink.Records[127]).RootElement.GetProperty("message").GetString());

        static string CultureInfo(int value) => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    [Theory]
    [InlineData("2 syslog 3 abc\n", "before open")]
    [InlineData("1 open 14 relp_version=0\n", "no syslog command")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n3 syslog 1 x\n", "skipped transaction")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 open 30 relp_version=0\ncommands=syslog\n", "second open")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 rsp 6 200 OK\n", "client response")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 starttls 0\n", "unknown command")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 syslog 3 abcd\n", "bad trailer")]
    [InlineData("1Xopen 30 relp_version=0\ncommands=syslog\n", "letter after the transaction")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2:syslog 1 x\n", "colon after the transaction")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 syslog:1 x\n", "colon after the command")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 syslog 1:x\n", "colon after the length")]
    [InlineData("1 open 30 relp_version=0\ncommands=syslog\n2 open 2000000 x\n", "oversized non-syslog frame")]
    public async Task Session_ProtocolErrorsEndTheSessionWithoutSubmitting(string input, string reason)
    {
        Assert.NotEmpty(reason);
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(sink, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.WriteAsync(input, cancellation);
        while (await client.ReadFrameAsync(cancellation) is { } frame)
        {
            Assert.DoesNotContain("rsp 6 200 OK", frame, StringComparison.Ordinal);
        }

        SyslogListenerStatus status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Empty(sink.Records);
        Assert.Equal(1, status.FramingErrors + status.Oversized);
    }

    [Fact]
    public async Task Session_AnOversizedMessageIsAFinalDropAndTheSessionContinues()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(sink, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: " + new string('x', 5_000), cancellation);
        await client.SendAsync(3, "<38>Oct 11 22:14:15 gw01 sshd: " + new string('y', 600), cancellation);
        // Larger than any buffer (and than the former 1 MiB bound): read past and answered, never resent forever.
        await client.SendAsync(4, "<38>Oct 11 22:14:15 gw01 sshd: " + new string('z', 1_200_000), cancellation);
        await client.SendAsync(5, "<38>Oct 11 22:14:15 gw01 sshd: fits", cancellation);
        for (int transaction = 2; transaction <= 5; transaction++)
        {
            Assert.Equal($"{transaction} rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        }

        Assert.Equal("fits", JsonDocument.Parse(Assert.Single(sink.Records)).RootElement.GetProperty("message").GetString());
        Assert.Equal(3, source.Snapshot()[0].Oversized);
    }

    [Fact]
    public async Task Session_MustOpenWithinTheHandshakeStartTimeout()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        await using SyslogSource source = await Start(new SyslogSourceTests.FakeSink(), cancellation, handshakeStartTimeoutSeconds: 1);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        Assert.Null(await client.ReadFrameAsync(cancellation));
        Assert.Equal(1, (await WaitFor(source, value => value.Timeouts == 1 && value.ActiveConnections == 0, cancellation)).Timeouts);
    }

    [Fact]
    public async Task Session_ASlowFrameIsClosedByTheFrameTimeout()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(sink, cancellation, frameTimeoutSeconds: 1);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        await client.WriteAsync("2 syslog 40 <38>Oct", cancellation);
        Assert.Null(await client.ReadFrameAsync(cancellation));
        Assert.Equal(1, (await WaitFor(source, value => value.Timeouts == 1, cancellation)).Timeouts);
        Assert.Empty(sink.Records);
    }

    [Fact]
    public async Task Stop_SendsServerCloseThenEnqueuesWhatTheSenderAlreadySentWithoutAcknowledging()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        SyslogSource source = await Start(sink, cancellation, drainMilliseconds: 2_000, stopMilliseconds: 5_000);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: before stop", cancellation);
        Assert.Equal("2 rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        ValueTask stopping = source.DisposeAsync();
        Assert.Equal("0 serverclose 0\n", await client.ReadFrameAsync(cancellation));
        // A sender writes before it processes the hint; the frame is still committed.
        await client.SendAsync(3, "<38>Oct 11 22:14:15 gw01 sshd: in flight", cancellation);
        Assert.Null(await client.ReadFrameAsync(cancellation));
        client.Shutdown();
        await stopping;
        Assert.Equal(["before stop", "in flight"], sink.Records.Select(record => JsonDocument.Parse(record).RootElement.GetProperty("message").GetString()!));
        SyslogListenerStatus status = source.Snapshot()[0];
        Assert.Equal((1, 1, 1), (status.RelpAcknowledged, status.RelpServerCloses, status.DrainedFrames));
    }

    [Fact]
    public async Task Stop_MakesOneAttemptForAFrameAfterServerCloseWhenTheQueueRefuses()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        SyslogSource source = await Start(sink, cancellation, drainMilliseconds: 2_000, stopMilliseconds: 10_000);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        sink.Refuse();
        System.Diagnostics.Stopwatch elapsed = System.Diagnostics.Stopwatch.StartNew();
        ValueTask stopping = source.DisposeAsync();
        Assert.Equal("0 serverclose 0\n", await client.ReadFrameAsync(cancellation));
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: refused while closing", cancellation);
        await WaitFor(source, value => sink.Attempts == 1, cancellation);
        client.Shutdown();
        await stopping;
        // One attempt, no retry loop until the stop timeout; the sender resends it later.
        Assert.Equal(1, sink.Attempts);
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(8), elapsed.Elapsed.ToString());
        Assert.Equal((0, 0), (source.Snapshot()[0].Retries, source.Snapshot()[0].RelpBusyCloses));
        Assert.Empty(sink.Records);
    }

    [Fact]
    public async Task BusyClose_ReadsTheRestOfTheWindowSoTheCloseIsAFinNotAReset()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new() { UnavailableResponses = 1_000_000 };
        await using SyslogSource source = await Start(sink, cancellation, busy: TimeSpan.FromMilliseconds(200), drainMilliseconds: 1_000);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: refused", cancellation);
        Assert.Equal("0 serverclose 0\n", await client.ReadFrameAsync(cancellation));
        // The rest of the window was already on its way when the sender saw the hint.
        StringBuilder window = new();
        for (long transaction = 3; transaction < 130; transaction++)
        {
            string data = "<38>Oct 11 22:14:15 gw01 sshd: in flight " + new string('w', 400);
            window.Append(CultureInfo(transaction)).Append(" syslog ").Append(CultureInfo(data.Length)).Append(' ').Append(data).Append('\n');
        }

        await client.WriteAsync(window.ToString(), cancellation);
        client.Shutdown();
        // A graceful end of stream: Bower read the unanswered frames away before closing.
        Assert.Equal(0, await client.ReadRawAsync(cancellation));
        SyslogListenerStatus status = await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal((1, 0, 0), (status.RelpBusyCloses, status.RelpAcknowledged, status.Queued));

        static string CultureInfo(long value) => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    [Fact]
    public async Task IdleTimeout_EndsAnOpenSessionWithServerClose()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        await using SyslogSource source = await Start(new SyslogSourceTests.FakeSink(), cancellation, idleTimeoutSeconds: 1, drainMilliseconds: 200);
        await using Client client = await Client.ConnectAsync(source, cancellation);
        await client.OpenAsync(cancellation);
        Assert.Equal("0 serverclose 0\n", await client.ReadFrameAsync(cancellation));
        Assert.Null(await client.ReadFrameAsync(cancellation));
        Assert.Equal(1, (await WaitFor(source, value => value.ActiveConnections == 0, cancellation)).RelpServerCloses);
    }

    [Fact]
    public async Task Tls_MutualAuthenticationIsEnforcedForRelp()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        SyslogSourceTests.FakeSink sink = new();
        string tls = Path.Combine(Fixtures, "tls");
        string mutual = $$"""{"certificateFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server.pem"))}}, "privateKeyFile": {{JsonSerializer.Serialize(Path.Combine(tls, "server-key.pem"))}}, "clientCertificateAuthorityFile": {{JsonSerializer.Serialize(Path.Combine(tls, "ca.pem"))}}}""";
        await using SyslogSource source = await Start(sink, cancellation, tls: mutual);
        try
        {
            await using Client anonymous = await Client.ConnectAsync(source, cancellation, Tls(null));
            Assert.Null(await anonymous.OpenAsync(cancellation));
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException)
        {
            // TLS 1.2 refuses the handshake; TLS 1.3 closes the session after it.
        }

        await WaitFor(source, value => value.TlsHandshakeFailures == 1, cancellation);
        await using Client client = await Client.ConnectAsync(source, cancellation, Tls(Load("client")));
        await client.OpenAsync(cancellation);
        await client.SendAsync(2, "<38>Oct 11 22:14:15 gw01 sshd: over mutual tls", cancellation);
        Assert.Equal("2 rsp 6 200 OK\n", await client.ReadFrameAsync(cancellation));
        Assert.Equal("relp", JsonDocument.Parse(Assert.Single(sink.Records)).RootElement.GetProperty("protocol").GetString());

        X509Certificate2 Load(string name)
        {
            using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(Path.Combine(tls, name + ".pem"), Path.Combine(tls, name + "-key.pem"));
            return X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
        }

        SslClientAuthenticationOptions Tls(X509Certificate2? certificate) => new()
        {
            TargetHost = "localhost",
            ClientCertificates = certificate is null ? null : new X509CertificateCollection(new X509Certificate[] { certificate }),
            RemoteCertificateValidationCallback = (_, certificate, _, _) => SyslogSourceTests.IssuedByTestCa(certificate),
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        };
    }

    private static string Name(RelpCommand command) => command switch
    {
        RelpCommand.Open => "open",
        RelpCommand.Syslog => "syslog",
        RelpCommand.Close => "close",
        RelpCommand.Response => "rsp",
        RelpCommand.ServerClose => "serverclose",
        _ => "unknown"
    };

    private static async Task<SyslogSource> Start(ISyslogSink sink, CancellationToken cancellation, TimeSpan? busy = null,
        int idleTimeoutSeconds = 0, int frameTimeoutSeconds = 30, int handshakeStartTimeoutSeconds = 60,
        int drainMilliseconds = 500, int stopMilliseconds = 1_000, string? tls = null, TimeProvider? clock = null)
    {
        string json = SyslogSourceTests.Config($$"""
            "id": "edge", "protocol": "relp", "address": "127.0.0.1", "port": 0,
            "allowedSenders": ["127.0.0.1"], "maximumMessageBytes": 512, "maximumConnections": 8,
            "idleTimeoutSeconds": {{idleTimeoutSeconds}}, "frameTimeoutSeconds": {{frameTimeoutSeconds}},
            "handshakeStartTimeoutSeconds": {{handshakeStartTimeoutSeconds}},
            {{(tls is null ? "" : "\"tls\": " + tls + ",")}}
            "routes": [{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}]
            """);
        SyslogSource source = new(SyslogSourceConfigurationLoader.Parse(json), sink, clock)
        {
            RetryDelay = TimeSpan.FromMilliseconds(20),
            RelpBusyTimeout = busy ?? TimeSpan.FromSeconds(30),
            DrainTimeout = TimeSpan.FromMilliseconds(drainMilliseconds),
            StopTimeout = TimeSpan.FromMilliseconds(stopMilliseconds)
        };
        await source.StartAsync(cancellation);
        return source;
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

    /// <summary>A test RELP client: writes frames and reads the server's frames one at a time.</summary>
    internal sealed class Client : IAsyncDisposable
    {
        private readonly TcpClient tcp;
        private readonly Stream stream;
        private readonly RelpFrameReader reader;

        private Client(TcpClient tcp, Stream stream)
        {
            this.tcp = tcp;
            this.stream = stream;
            reader = new RelpFrameReader(stream, 4_096);
        }

        public static Task<Client> ConnectAsync(SyslogSource source, CancellationToken cancellation, SslClientAuthenticationOptions? tls = null) =>
            ConnectAsync(source.Endpoints["edge"], cancellation, tls);

        public static async Task<Client> ConnectAsync(System.Net.IPEndPoint endpoint, CancellationToken cancellation, SslClientAuthenticationOptions? tls = null)
        {
            TcpClient tcp = new(AddressFamily.InterNetwork);
            await tcp.ConnectAsync(endpoint, cancellation);
            Stream stream = tcp.GetStream();
            if (tls is not null)
            {
                SslStream secure = new(stream, leaveInnerStreamOpen: false);
                await secure.AuthenticateAsClientAsync(tls, cancellation);
                stream = secure;
            }

            return new Client(tcp, stream);
        }

        public async Task<string?> OpenAsync(CancellationToken cancellation)
        {
            await SendAsync(1, Offers, "open", cancellation);
            return await ReadFrameAsync(cancellation);
        }

        public Task SendAsync(long transaction, string data, CancellationToken cancellation) => SendAsync(transaction, data, "syslog", cancellation);

        private Task SendAsync(long transaction, string data, string command, CancellationToken cancellation) =>
            WriteAsync($"{transaction} {command} {Encoding.UTF8.GetByteCount(data)} {data}\n", cancellation);

        public async Task WriteAsync(string text, CancellationToken cancellation)
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes(text), cancellation);
            await stream.FlushAsync(cancellation);
        }

        /// <summary>The next frame as text, or null when the server closed or reset the connection.</summary>
        public async Task<string?> ReadFrameAsync(CancellationToken cancellation)
        {
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                RelpFrameResult frame = await reader.ReadFrameAsync(timeout.Token);
                if (frame.IsEnd || frame.Failure is not null)
                {
                    return null;
                }

                string command = frame.Command == RelpCommand.Response ? "rsp" : frame.Command == RelpCommand.ServerClose ? "serverclose" : "?";
                return frame.Data.IsEmpty
                    ? $"{frame.Transaction} {command} 0\n"
                    : $"{frame.Transaction} {command} {frame.Data.Length} {Encoding.ASCII.GetString(frame.Data.Span)}\n";
            }
            catch (IOException)
            {
                return null;
            }
        }

        public void Shutdown() => tcp.Client.Shutdown(SocketShutdown.Send);

        /// <summary>One raw read: 0 at a graceful end of stream; a reset throws.</summary>
        public async Task<int> ReadRawAsync(CancellationToken cancellation)
        {
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            return await stream.ReadAsync(new byte[4_096], timeout.Token);
        }

        public async ValueTask DisposeAsync()
        {
            await stream.DisposeAsync();
            tcp.Dispose();
        }
    }

    /// <summary>
    /// A durable, deduplicating sink that survives a collector "restart": committed records stay,
    /// and a resent id is a duplicate. The commit that reaches <see cref="CommitLimit"/> never
    /// returns, standing in for a process killed after its commit and before its answer.
    /// </summary>
    private sealed class DurableSink : ISyslogSink
    {
        public ConcurrentDictionary<string, string> Committed { get; } = new(StringComparer.Ordinal);

        public TaskCompletionSource LimitReached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CommitLimit { get; set; }

        public async ValueTask<SyslogSubmitOutcome> SubmitAsync(SyslogListenerOptions listener, SyslogRoute route, string record, CancellationToken cancellationToken)
        {
            JsonElement root = JsonDocument.Parse(record).RootElement;
            string id = root.GetProperty("id").GetString()!;
            if (Committed.ContainsKey(id))
            {
                return SyslogSubmitOutcome.Duplicate;
            }

            Committed[id] = root.GetProperty("message").GetString()!;
            if (Committed.Count == CommitLimit)
            {
                // Committed, then the process dies before it can answer.
                LimitReached.TrySetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return SyslogSubmitOutcome.Queued;
        }
    }

    /// <summary>System time that moves at least one second per reading, so receive times differ.</summary>
    private sealed class SteppingClock : TimeProvider
    {
        private long seconds;

        public override DateTimeOffset GetUtcNow() => base.GetUtcNow().AddSeconds(Interlocked.Increment(ref seconds));
    }

    private sealed class ChunkedStream(byte[] data, int chunk) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, chunk)], cancellationToken);
    }
}
