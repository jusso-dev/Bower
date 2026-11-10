using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Output.AmaSyslog;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

/// <summary>
/// BOWER_OUTPUT=ama-syslog: each envelope becomes one local-format datagram on the syslog
/// socket, with the envelope JSON base64-encoded in MSG, so Azure Monitor Agent's syslog
/// collection can carry it to BowerSecurity_CL. A real Unix datagram socket stands in for /dev/log.
/// <para>
/// Datagram sockets behave differently by platform, exactly where this adapter is sensitive:
/// macOS refuses a Unix datagram over 2,048 bytes (EMSGSIZE) and reports a full queue as
/// ENOBUFS; Linux accepts 64 KiB and reports a full queue as EAGAIN. Tests that fill a queue
/// use datagrams under 2,048 bytes so both platforms exercise back-pressure, not size.
/// Windows has no datagram Unix sockets: those tests are skipped there, with the reason.
/// </para>
/// </summary>
public sealed class AmaSyslogOutputTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 1, 2, 3, 456, TimeSpan.Zero);

    private const string NoDatagramSockets = "Datagram Unix sockets exist only on Linux and macOS.";

    // AmaSyslogOutputOptions takes a Unix path such as /dev/log, which Windows doesn't treat as a full path.
    private const string NoUnixSocketPath = "The syslog output takes a Unix socket path; Windows refuses it.";

    private static bool DatagramSockets => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [Fact]
    public async Task Deliver_SendsOneDatagramPerEnvelopeWithTheJsonEncodedInTheMessage()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path }, new FixedClock(Now));
        string first = Envelope("event-1");
        // Semicolons and non-ASCII text are exactly what syslog ingestion would damage.
        string second = Envelope("event-2", """ "actor":{"username":"zoë"},"labels":{"route":"a;b"}, """);

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
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path, MaximumMessageBytes = 1_024 });
        string large = Envelope("big", $$""" "attributes":{"note":"{{new string('a', 2_000)}}"}, """);
        string small = Envelope("small");

        DeliveryResult result = await output.DeliverAsync(
            [new("big", "sha256:big", large, Now), new("small", "sha256:small", small, Now)],
            cancellationToken);

        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal(("big", AmaSyslogOutput.MessageTooLargeCode, false), (failure.EventId, failure.Code, failure.IsRetryable));
        Assert.Equal(["small"], result.AcknowledgedEventIds);
        Assert.Equal(small, Decode(daemon.Receive()));
    }

    [Fact]
    public void Format_PadsSingleDigitDaysWithASpace()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), NoUnixSocketPath);
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog" }, new FixedClock(new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero)));

        byte[]? message = output.TryFormat("{}");

        Assert.NotNull(message);
        Assert.StartsWith("<165>Mar  4 05:06:07 bower: ", Encoding.ASCII.GetString(message), StringComparison.Ordinal);
    }

    [Fact]
    public void Format_DefaultLimitLeavesRoomForTheHeaderRsyslogAddsWhenForwarding()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), NoUnixSocketPath);
        // rsyslog forwards at most 8,096 characters per line, its own header included
        // (measured with stock rsyslog on Rocky Linux 9, #230). The default leaves 416 for it.
        Assert.Equal(7_680, AmaSyslogOutputOptions.DefaultMaximumMessageBytes);
        Assert.True(8_096 - AmaSyslogOutputOptions.DefaultMaximumMessageBytes >= 256);

        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog" }, new FixedClock(Now));
        // 38 header bytes, then base64: the largest JSON that fits is 5,730 bytes.
        string Json(int bytes) => "{\"n\":\"" + new string('a', bytes - 8) + "\"}";
        byte[]? largest = output.TryFormat(Json(5_730));
        Assert.NotNull(largest);
        Assert.Equal(7_678, largest.Length);
        Assert.Null(output.TryFormat(Json(5_731)));
        // The computed size is the byte count actually written.
        Assert.Equal(output.MessageBytes(5_730), largest.Length);
        Assert.True(largest.All(value => value < 0x80));
    }

    [Fact]
    public async Task Deliver_RetriesEveryEventWhenTheDaemonIsNotListening()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        using ShortDirectory directory = new();
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = Path.Combine(directory.Path, "missing.sock") });

        DeliveryResult result = await output.DeliverAsync(
            [new("a", "sha256:a", Envelope("a"), Now), new("b", "sha256:b", Envelope("b"), Now)],
            TestContext.Current.CancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal(AmaSyslogOutput.SocketUnavailableCode, failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
        });
        Assert.Equal(["a", "b"], result.Failures.Select(failure => failure.EventId));
    }

    [Fact]
    public async Task Deliver_WaitsForADaemonThatDrainsAndDeliversTheWholeBurst()
    {
        // #225: a non-blocking send fills the queue within a few dozen messages even when the
        // daemon is healthy. The adapter must wait for room, not fail the rest of the batch.
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"), receiveBufferBytes: 4_096);
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path });
        QueuedEvent[] events = Burst(2_000, padding: 1_000);
        using CancellationTokenSource reading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<int> reader = daemon.DrainAsync(reading.Token);

        DeliveryResult result = await Task.Run(() => output.DeliverAsync(events, cancellationToken), cancellationToken);

        Assert.Empty(result.Failures);
        Assert.Equal(events.Select(item => item.EventId), result.AcknowledgedEventIds);
        await daemon.WaitForAsync(2_000, cancellationToken);
        await reading.CancelAsync();
        Assert.Equal(2_000, await reader);
    }

    [Fact]
    public async Task Deliver_DoesNotBlockWhenTheDaemonQueueIsFull()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        // A daemon that never reads: its receive queue fills and stays full. A blocking send
        // would wait here for ever. Datagrams under 2,048 bytes, so macOS fills the queue too
        // instead of refusing every message for size.
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"), receiveBufferBytes: 4_096);
        AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path, BusyWait = TimeSpan.FromSeconds(1) });
        QueuedEvent[] events = Burst(2_000, padding: 1_000);

        // On another thread: DeliverAsync must not hold this one, and the guard below must be
        // able to fire if it ever blocks.
        Stopwatch elapsed = Stopwatch.StartNew();
        Task<DeliveryResult> delivery = Task.Run(() => output.DeliverAsync(events, cancellationToken), cancellationToken);
        Task finished = await Task.WhenAny(delivery, Task.Delay(TimeSpan.FromSeconds(10), cancellationToken));

        // A send stuck in the kernel also blocks Dispose on Linux, so a hung delivery is
        // reported here and the output is left to the daemon's close to wake.
        Assert.True(ReferenceEquals(delivery, finished), "Delivery to a full daemon queue did not return within 10 seconds.");
        using AmaSyslogOutput disposeAfterDelivery = output;
        DeliveryResult result = await delivery;
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(5), $"One busy wait of 1 s took {elapsed.Elapsed}.");
        Assert.NotEmpty(result.AcknowledgedEventIds);
        Assert.NotEmpty(result.Failures);
        Assert.All(result.Failures, failure => Assert.Equal((AmaSyslogOutput.SocketBusyCode, true), (failure.Code, failure.IsRetryable)));
        // Nothing is lost: every event is either acknowledged or kept for retry, in order.
        Assert.Equal(events.Select(item => item.EventId), result.AcknowledgedEventIds.Concat(result.Failures.Select(failure => failure.EventId)));
    }

    [Fact]
    public async Task Deliver_ReturnsWhatWasSentWhenCancelledPartWay()
    {
        // #229: a cancelled delivery must acknowledge what the daemon already took, so the
        // worker does not send it again, and keep only the rest for retry, in order.
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"), receiveBufferBytes: 4_096);
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path, BusyWait = TimeSpan.FromSeconds(30) });
        QueuedEvent[] events = Burst(500, padding: 1_000);
        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // The queue fills, the adapter waits for room, and the deadline cancels the wait.
        cancel.CancelAfter(TimeSpan.FromMilliseconds(500));
        DeliveryResult result = await Task.Run(() => output.DeliverAsync(events, cancel.Token), cancellationToken);

        int sent = result.AcknowledgedEventIds.Count;
        Assert.InRange(sent, 1, events.Length - 1);
        Assert.Equal(events.Take(sent).Select(item => item.EventId), result.AcknowledgedEventIds);
        Assert.Equal(events.Skip(sent).Select(item => item.EventId), result.Failures.Select(failure => failure.EventId));
        Assert.All(result.Failures, failure => Assert.Equal((AmaSyslogOutput.CancelledCode, true), (failure.Code, failure.IsRetryable)));
        Assert.Equal(sent, daemon.ReceiveAll());
    }

    [Fact]
    public async Task Deliver_DeadLettersADatagramTheKernelRefusesForSizeAndSendsTheRest()
    {
        // #227: EMSGSIZE is a property of the event, not an outage. Linux refuses a datagram
        // larger than the sender's send buffer; macOS refuses any over 2,048 bytes.
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions
        {
            Id = "ama-syslog",
            SocketPath = daemon.Path,
            MaximumMessageBytes = 65_507,
            SendBufferBytes = 4_096
        });
        string huge = Envelope("huge", $$""" "attributes":{"note":"{{new string('a', 40_000)}}"}, """);

        DeliveryResult result = await output.DeliverAsync(
            [new("huge", "sha256:huge", huge, Now), new("after", "sha256:after", Envelope("after"), Now)],
            cancellationToken);

        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal(("huge", AmaSyslogOutput.MessageTooLargeCode, false), (failure.EventId, failure.Code, failure.IsRetryable));
        Assert.Equal(["after"], result.AcknowledgedEventIds);
        Assert.Equal(Envelope("after"), Decode(daemon.Receive()));
    }

    [Fact]
    public async Task Deliver_ReportsASocketItMayNotWriteToByName()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        Assert.SkipWhen(Environment.UserName == "root", "root can write to any socket.");
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(daemon.Path, UnixFileMode.UserRead);
        }

        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path });

        DeliveryResult result = await output.DeliverAsync([new("a", "sha256:a", Envelope("a"), Now)], TestContext.Current.CancellationToken);

        Assert.Equal((AmaSyslogOutput.AccessDeniedCode, true), (Assert.Single(result.Failures).Code, result.Failures[0].IsRetryable));
    }

    [Theory]
    [InlineData("""{"schemaVersion":"1.0.0","eventId":"bad","eventType":"authentication_failure"}""", "preflight-time-generated-missing")]
    [InlineData("""{"schemaVersion":"1.0.0","eventId":"bad","timeGenerated":"2026-11-10T01:02:03Z","actor":"a string, not an object"}""", "preflight-type-mismatch")]
    [InlineData("""{"schemaVersion":"1.0.0","eventId":"other","timeGenerated":"2026-11-10T01:02:03Z"}""", "payload-event-id-mismatch")]
    [InlineData("""not json""", "payload-invalid-json")]
    [InlineData("\"bad\ud800\"", "payload-invalid-json")]
    public async Task Deliver_RefusesWhatTheLogsIngestionOutputRefuses(string payload, string code)
    {
        // #232: both outputs feed BowerSecurity_CL, so both run the same record checks and
        // dead-letter by the same names.
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path });

        DeliveryResult result = await output.DeliverAsync(
            [new("bad", "sha256:bad", payload, Now), new("good", "sha256:good", Envelope("good"), Now)],
            cancellationToken);

        Assert.Equal(("bad", code, false), (Assert.Single(result.Failures).EventId, result.Failures[0].Code, result.Failures[0].IsRetryable));
        Assert.Equal(["good"], result.AcknowledgedEventIds);

        // The Logs Ingestion output refuses the same record with the same code.
        Assert.Equal(code, await LogsIngestionRefusalAsync(payload, cancellationToken));
    }

    [Fact]
    public async Task Deliver_ReconnectsAfterTheDaemonRestarts()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        string path = Path.Combine(directory.Path, "log.sock");
        using AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = path });
        using (FakeDaemon first = new(path))
        {
            Assert.Single((await output.DeliverAsync([new("a", "sha256:a", Envelope("a"), Now)], cancellationToken)).AcknowledgedEventIds);
            first.Receive();
        }

        DeliveryResult whileDown = await output.DeliverAsync([new("b", "sha256:b", Envelope("b"), Now)], cancellationToken);
        Assert.Equal(AmaSyslogOutput.SocketUnavailableCode, Assert.Single(whileDown.Failures).Code);

        using FakeDaemon restarted = new(path);
        DeliveryResult afterRestart = await output.DeliverAsync([new("b", "sha256:b", Envelope("b"), Now)], cancellationToken);
        Assert.Equal(["b"], afterRestart.AcknowledgedEventIds);
        Assert.Equal(Envelope("b"), Decode(restarted.Receive()));
    }

    [Fact]
    public async Task Dispose_StopsADeliveryThatIsWaitingForTheDaemon()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"), receiveBufferBytes: 4_096);
        AmaSyslogOutput output = new(new AmaSyslogOutputOptions { Id = "ama-syslog", SocketPath = daemon.Path, BusyWait = TimeSpan.FromSeconds(30) });
        Task<DeliveryResult> delivery = Task.Run(() => output.DeliverAsync(Burst(500, padding: 1_000), cancellationToken), cancellationToken);
        await Task.Delay(300, cancellationToken);

        Stopwatch elapsed = Stopwatch.StartNew();
        output.Dispose();
        DeliveryResult result = await delivery.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);

        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(5));
        Assert.All(result.Failures, failure => Assert.Equal(AmaSyslogOutput.CancelledCode, failure.Code));
        Assert.Equal(500, result.AcknowledgedEventIds.Count + result.Failures.Count);
    }

    [Fact]
    public void Probe_NamesTheErrorForAMissingSocket()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));

        Assert.Null(AmaSyslogOutput.Probe(daemon.Path));
        Assert.NotNull(AmaSyslogOutput.Probe(Path.Combine(directory.Path, "missing.sock")));
    }

    [Theory]
    [InlineData("BOWER_AMA_SYSLOG_SOCKET", "relative/log.sock", "must be an absolute path")]
    [InlineData("BOWER_AMA_SYSLOG_SOCKET", "/run/a-socket-path-that-is-far-too-long-for-sun-path-because-it-keeps-going-and-going-and-going-and-on/log.sock", "must be at most")]
    [InlineData("BOWER_AMA_SYSLOG_FACILITY", "1", "local0, local1, local2, local3, local4, local5, local6, local7")]
    [InlineData("BOWER_AMA_SYSLOG_FACILITY", "24", "local0")]
    [InlineData("BOWER_AMA_SYSLOG_FACILITY", "user", "local0")]
    [InlineData("BOWER_AMA_SYSLOG_FACILITY", "4294967316", "local0")]
    [InlineData("BOWER_AMA_SYSLOG_MAX_BYTES", "512", "between 1024 and 65507")]
    [InlineData("BOWER_AMA_SYSLOG_MAX_BYTES", "4294975488", "must be an integer")]
    [InlineData("BOWER_AMA_SYSLOG_BUSY_WAIT_SECONDS", "4294967298", "must be an integer")]
    [InlineData("BOWER_AMA_SYSLOG_BUSY_WAIT_SECONDS", "0", "between 1 and 30")]
    [InlineData("BOWER_AMA_SYSLOG_BUSY_WAIT_SECONDS", "31", "between 1 and 30")]
    public void Settings_RefuseAnInvalidSyslogOutput(string name, string value, string message)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows refuses BOWER_OUTPUT=ama-syslog before these checks.");
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(Syslog(new() { [name] = value })));

        Assert.Contains(message, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_RefuseTheOldOutputNameWithNoAlias()
    {
        // #242: renamed before release, so BOWER_OUTPUT=syslog is not kept as an alias.
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_COLLECTOR_ID" => "edge-01",
            "BOWER_OUTPUT" => "syslog",
            _ => null
        }));

        Assert.Equal("Unsupported BOWER_OUTPUT value: syslog", error.Message);
    }

    [Fact]
    public void Settings_BusyWaitMustFitInsideTheDeliveryTimeout()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows refuses BOWER_OUTPUT=ama-syslog before these checks.");
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(Syslog(new()
        {
            ["BOWER_DELIVERY_TIMEOUT_SECONDS"] = "5",
            ["BOWER_AMA_SYSLOG_BUSY_WAIT_SECONDS"] = "5"
        })));

        Assert.Contains("below BOWER_DELIVERY_TIMEOUT_SECONDS", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_DefaultToDevLogAndLocal4()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows refuses BOWER_OUTPUT=ama-syslog.");
        CollectorSettings settings = CollectorSettings.FromEnvironment(Syslog([]));

        Assert.Equal(("ama-syslog", "/dev/log", 20, 7_680, TimeSpan.FromSeconds(2)),
            (settings.OutputType, settings.AmaSyslogSocket, settings.AmaSyslogFacility, settings.AmaSyslogMaximumBytes, settings.AmaSyslogBusyWait));
    }

    [Fact]
    public void Settings_AcceptALinuxSocketPathOfUpTo107Bytes()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "sun_path is 108 bytes on Linux and 104 on macOS.");
        string path = "/" + new string('a', 106);

        Assert.Equal(path, CollectorSettings.FromEnvironment(Syslog(new() { ["BOWER_AMA_SYSLOG_SOCKET"] = path })).AmaSyslogSocket);
        Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(Syslog(new() { ["BOWER_AMA_SYSLOG_SOCKET"] = path + "a" })));
    }

    [Fact]
    public void Settings_RefuseTheAmaSyslogOutputOnWindowsAndNameThePlatform()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Checks the Windows start-up message.");
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(Syslog([])));

        Assert.Contains("Linux only", error.Message, StringComparison.Ordinal);
        Assert.Contains("azure-logs-ingestion", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("local0", 16)]
    [InlineData("local1", 17)]
    [InlineData("local2", 18)]
    [InlineData("local3", 19)]
    [InlineData("local4", 20)]
    [InlineData("LOCAL5", 21)]
    [InlineData("local6", 22)]
    [InlineData("local7", 23)]
    [InlineData("20", 20)]
    [InlineData("16", 16)]
    [InlineData("23", 23)]
    public void Settings_AcceptEveryFacilityTheRuleCanCollectByName(string value, int number)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows refuses BOWER_OUTPUT=ama-syslog.");
        CollectorSettings settings = CollectorSettings.FromEnvironment(Syslog(new() { ["BOWER_AMA_SYSLOG_FACILITY"] = value }));

        Assert.Equal(number, settings.AmaSyslogFacility);
        // The name Bower reports is one the rule's facility parameter allows.
        string bicep = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "ama-syslog-dcr.bicep"));
        string allowed = bicep[bicep.IndexOf("@allowed(", StringComparison.Ordinal)..];
        allowed = allowed[..allowed.IndexOf(')', StringComparison.Ordinal)];
        Assert.Contains($"'{AmaSyslogOutputOptions.FacilityName(number)}'", allowed, StringComparison.Ordinal);
        Assert.Equal(AmaSyslogOutputOptions.FacilityNames.Select(name => $"'{name}'"), allowed.Split('[', ']')[1].Split(", "));
    }

    [Fact]
    public async Task Collector_DeliversAnAcceptedEventToTheSyslogSocketAndReportsTheOutput()
    {
        // #245: the factory mapping, policy, redaction, queue, worker and status together.
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using FakeDaemon daemon = new(Path.Combine(directory.Path, "log.sock"));
        await using WebApplication app = await StartCollectorAsync(directory, daemon.Path, cancellationToken);
        HttpClient client = app.GetTestClient();

        Assert.True((await PostAsync(client, "syslog-e2e-1", cancellationToken)).IsSuccessStatusCode);

        string message = await Task.Run(daemon.Receive, cancellationToken);
        Assert.StartsWith("<165>", message, StringComparison.Ordinal);
        Assert.Contains(" bower: bower-b64:", message, StringComparison.Ordinal);
        using JsonDocument envelope = JsonDocument.Parse(Decode(message));
        Assert.Equal("syslog-e2e-1", envelope.RootElement.GetProperty("eventId").GetString());
        // The arranged envelope: policy decision and collector stamped before persistence.
        Assert.Equal("collector-test", envelope.RootElement.GetProperty("collector").GetProperty("id").GetString());
        Assert.False(string.IsNullOrEmpty(envelope.RootElement.GetProperty("security").GetProperty("policyId").GetString()));
        string status = await Polling.UntilAsync(
            () => StatusAsync(client, cancellationToken),
            static body => body.Contains("\"delivered\":1", StringComparison.Ordinal),
            cancellationToken);
        Assert.Contains("\"output\":\"ama-syslog\"", status, StringComparison.Ordinal);
        await app.StopAsync(cancellationToken);
    }

    [Fact]
    public async Task Collector_ReportsAMissingSyslogSocketAtStartUpAndInStatus()
    {
        Assert.SkipUnless(DatagramSockets, NoDatagramSockets);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using ShortDirectory directory = new();
        using CapturingLoggerProvider logs = new();
        string missing = Path.Combine(directory.Path, "missing.sock");
        await using WebApplication app = await StartCollectorAsync(directory, missing, cancellationToken, logs);
        HttpClient client = app.GetTestClient();

        Assert.Contains(logs.Messages, line => line.Contains($"AMA syslog output socket {missing} does not accept connections", StringComparison.Ordinal));
        Assert.Contains(logs.Messages, line => line.Contains("on facility local4", StringComparison.Ordinal));
        Assert.True((await PostAsync(client, "syslog-e2e-2", cancellationToken)).IsSuccessStatusCode);
        string status = await Polling.UntilAsync(
            () => StatusAsync(client, cancellationToken),
            static body => body.Contains("destination-ama-syslog-unavailable", StringComparison.Ordinal)
                && body.Contains("\"retrying\":1", StringComparison.Ordinal),
            cancellationToken);
        Assert.Contains("\"output\":\"ama-syslog\"", status, StringComparison.Ordinal);
        await app.StopAsync(cancellationToken);
    }

    private const string IngestToken = "ama-syslog-output-ingest-token-0123456789abcdef";

    private static async Task<WebApplication> StartCollectorAsync(
        ShortDirectory directory, string socket, CancellationToken cancellationToken, CapturingLoggerProvider? logs = null)
    {
        CollectorSettings settings = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "collector-test",
            SingleTrustDomain = true,
            IngestToken = IngestToken,
            OutputType = "ama-syslog",
            AmaSyslogSocket = socket
        };
        WebApplication app = CollectorApplication.Build(settings, builder =>
        {
            builder.WebHost.UseTestServer();
            if (logs is not null)
            {
                builder.Logging.AddProvider(logs);
            }
        });
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string eventId, CancellationToken cancellationToken)
    {
        using HttpRequestMessage post = new(HttpMethod.Post, "/v1/events")
        {
            Content = JsonContent.Create(TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, eventId), options: BowerJson.Options)
        };
        post.Headers.Authorization = new AuthenticationHeaderValue("Bearer", IngestToken);
        return await client.SendAsync(post, cancellationToken);
    }

    private static async Task<string> StatusAsync(HttpClient client, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", IngestToken);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        return await response.Content.ReadAsStringAsync(cancellationToken);
    }

    /// <summary>The code the Logs Ingestion output gives this payload before any upload.</summary>
    private static async Task<string> LogsIngestionRefusalAsync(string payload, CancellationToken cancellationToken)
    {
        Bower.Output.AzureLogsIngestion.AzureLogsIngestionOutput output = new(
            new Bower.Output.AzureLogsIngestion.AzureLogsIngestionOptions
            {
                Id = "azure-logs-ingestion",
                Endpoint = new Uri("https://example.invalid"),
                DcrImmutableId = "dcr-00000000000000000000000000000000",
                StreamName = "Custom-BowerSecurity"
            },
            new NeverCredential());
        DeliveryResult result = await output.DeliverAsync([new("bad", "sha256:bad", payload, Now)], cancellationToken);
        return Assert.Single(result.Failures).Code;
    }

    private sealed class NeverCredential : Azure.Core.TokenCredential
    {
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No upload is expected for a refused record.");

        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No upload is expected for a refused record.");
    }

    /// <summary>A minimal envelope that passes the record checks, with optional extra members.</summary>
    private static string Envelope(string eventId, string extra = "") =>
        $$"""{"schemaVersion":"1.0.0","eventId":"{{eventId}}",{{extra.Trim()}}"timeGenerated":"2026-11-10T01:02:03.456Z"}""";

    private static QueuedEvent[] Burst(int count, int padding)
    {
        string note = new('a', padding);
        return [.. Enumerable.Range(0, count).Select(index =>
            new QueuedEvent($"e{index}", $"sha256:{index}", Envelope($"e{index}", $$""" "attributes":{"note":"{{note}}"}, """), Now))];
    }

    private static string Base64(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

    /// <summary>The transform: base64_decodestring of what follows the marker.</summary>
    private static string Decode(string message)
    {
        int start = message.IndexOf(AmaSyslogOutput.MessagePrefix, StringComparison.Ordinal);
        Assert.True(start >= 0, message);
        return Encoding.UTF8.GetString(Convert.FromBase64String(message[(start + AmaSyslogOutput.MessagePrefix.Length)..]));
    }

    private static Func<string, string?> Syslog(Dictionary<string, string> overrides)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal)
        {
            ["BOWER_COLLECTOR_ID"] = "edge-01",
            ["BOWER_OUTPUT"] = "ama-syslog"
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
        private int received;

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

        /// <summary>Reads every queued datagram without waiting; returns how many.</summary>
        public int ReceiveAll()
        {
            byte[] buffer = new byte[70_000];
            int count = 0;
            while (socket.Poll(TimeSpan.FromMilliseconds(200), SelectMode.SelectRead))
            {
                socket.Receive(buffer);
                count++;
            }

            return count;
        }

        /// <summary>Reads continuously, as a healthy daemon does, until cancelled.</summary>
        public Task<int> DrainAsync(CancellationToken cancellationToken) => Task.Run(async () =>
        {
            byte[] buffer = new byte[70_000];
            try
            {
                while (true)
                {
                    await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
                    Interlocked.Increment(ref received);
                }
            }
            catch (OperationCanceledException)
            {
            }

            return Volatile.Read(ref received);
        }, CancellationToken.None);

        public Task WaitForAsync(int count, CancellationToken cancellationToken) =>
            Polling.UntilAsync(() => Volatile.Read(ref received) >= count, cancellationToken);

        public void Dispose()
        {
            socket.Dispose();
            File.Delete(Path);
        }
    }
}
