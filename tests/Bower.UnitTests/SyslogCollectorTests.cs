using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Bower.Integrity;
using Bower.Packs;
using Bower.Source.Syslog;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// The syslog source inside the collector: a frame becomes a durable event only through a
/// signed pack parser, redaction and policy; the queue is the TCP acknowledgement point.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class SyslogCollectorTests
{
    private const string Token = "syslog-collector-test-token-0123456789abcdef";
    private static string PackSource => Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway");

    [Fact]
    public async Task SelectedFrame_IsRedactedDurablyQueuedDeduplicatedAndKeepsTheSourceActive()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        SyslogSource source = app.Services.GetRequiredService<SyslogSource>();
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();

        using TcpClient client = new(AddressFamily.InterNetwork);
        await client.ConnectAsync(source.Endpoints["edge"], cancellation);
        NetworkStream stream = client.GetStream();
        string selected = Frame("failure");
        await Send(stream, selected, cancellation);
        await WaitFor(source, status => status.Queued == 1, cancellation);
        // The frame is acknowledged only once durable: the queue already holds it.
        Assert.Equal(1, (await store.GetSnapshotAsync(cancellation)).Queued);

        await Send(stream, selected, cancellation);
        await Send(stream, Frame("success"), cancellation);
        await Send(stream, "<38>Oct 11 22:14:15 gw01 cron: unrouted secret-marker", cancellation);
        SyslogListenerStatus counted = await WaitFor(source, status => status.Duplicates == 1 && status.NotSelected == 1 && status.NotRouted == 1, cancellation);
        Assert.Equal(4, counted.FramesReceived);

        QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        SecurityEventEnvelope stored = JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!;
        Assert.Equal("authentication_failure", stored.EventType);
        Assert.Equal("syslog:edge:linux-ssh-gateway:0", stored.Collector!.SourceAdapter);
        Assert.Equal("203.0.113.5", stored.Source!.IpAddress);
        Assert.StartsWith("syslog-", stored.EventId, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy-admin", row.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-marker", row.Payload, StringComparison.Ordinal);
        foreach (string path in Directory.EnumerateFiles(directory.Path, "queue.db*"))
        {
            string bytes = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path, cancellation));
            Assert.DoesNotContain("deploy-admin", bytes, StringComparison.Ordinal);
            Assert.DoesNotContain("secret-marker", bytes, StringComparison.Ordinal);
        }

        using HttpClient http = app.GetTestClient();
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage response = await http.SendAsync(request, cancellation);
        string body = await response.Content.ReadAsStringAsync(cancellation);
        using JsonDocument status = JsonDocument.Parse(body);
        JsonElement listener = status.RootElement.GetProperty("syslog")[0];
        Assert.Equal("edge", listener.GetProperty("id").GetString());
        Assert.Equal(1, listener.GetProperty("queued").GetInt64());
        Assert.Equal(1, listener.GetProperty("notRouted").GetInt64());
        JsonElement expected = Assert.Single(status.RootElement.GetProperty("sources").EnumerateArray());
        Assert.Equal("ssh-gateway", expected.GetProperty("application").GetString());
        Assert.Equal("active", expected.GetProperty("state").GetString());
        Assert.NotEqual(JsonValueKind.Null, expected.GetProperty("lastSeenAt").ValueKind);
        Assert.DoesNotContain("deploy-admin", body, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-marker", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FullQueue_StopsTcpUntilSpaceIsFreedAndDropsUdp()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await Start(directory, cancellation);
        SyslogSource source = app.Services.GetRequiredService<SyslogSource>();
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        await store.EnqueueAsync(new QueuedEvent("filler", "sha256:filler", new string('x', 1_048_000), DateTimeOffset.UtcNow), cancellation);

        using UdpClient udp = new(AddressFamily.InterNetwork);
        await udp.SendAsync(Encoding.UTF8.GetBytes(Frame("failure", "udp-user")), source.Endpoints["edge-udp"], cancellation);
        await WaitFor(source, status => status.Dropped == 1, cancellation, "edge-udp");

        using TcpClient client = new(AddressFamily.InterNetwork);
        await client.ConnectAsync(source.Endpoints["edge"], cancellation);
        await Send(client.GetStream(), Frame("failure"), cancellation);
        await WaitFor(source, status => status.Retries >= 2, cancellation);
        Assert.Equal(0, source.Snapshot()[0].Queued);

        QueuedEvent filler = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        await store.MarkDeliveredAsync(filler.EventId, "test-ack", filler.LeaseToken, cancellation);
        await WaitFor(source, status => status.Queued == 1, cancellation);
        QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        Assert.StartsWith("syslog-", row.EventId, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TransformFailure_QuarantinesWithoutPersistingAndKeepsTheConnectionOpen()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        // A string condition is a run-time type error for every sshd frame.
        await using WebApplication app = await Start(directory, cancellation, transforms: ["if .appName { .appName = \"sshd\" }"]);
        using EventTapSession tap = app.Services.GetRequiredService<EventTap>().TryOpen(
            new EventTapRequest("test", TapPoint.Redacted, null, null, 2, TimeSpan.FromSeconds(30), 1))!;
        SyslogSource source = app.Services.GetRequiredService<SyslogSource>();
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();

        using TcpClient client = new(AddressFamily.InterNetwork);
        await client.ConnectAsync(source.Endpoints["edge"], cancellation);
        NetworkStream stream = client.GetStream();
        await Send(stream, Frame("failure"), cancellation);
        await Send(stream, Frame("failure", "second-user"), cancellation);
        // The connection stays open: a deterministic per-record failure is not a sink failure.
        SyslogListenerStatus counted = await WaitFor(source, status => status.Rejected == 2, cancellation);
        Assert.Equal(0, counted.SubmitFailures);
        Assert.Equal(2, tap.Reader.Count);
        while (tap.Reader.TryRead(out EventTapRecord? frame))
        {
            Assert.Equal("transform", frame.Stage);
            Assert.Equal("quarantine", frame.Action);
            Assert.Null(frame.Event);
            Assert.Contains("transform-type-error", frame.Reasons);
        }
        Assert.Equal(0, counted.Queued);
        Assert.Equal(0, (await store.GetSnapshotAsync(cancellation)).Queued);

        using HttpClient http = app.GetTestClient();
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage response = await http.SendAsync(request, cancellation);
        string body = await response.Content.ReadAsStringAsync(cancellation);
        using JsonDocument status = JsonDocument.Parse(body);
        JsonElement transformRow = Assert.Single(
            status.RootElement.GetProperty("pipeline").GetProperty("rows").EnumerateArray(),
            row => row.GetProperty("stage").GetString() == "transform");
        Assert.Equal("quarantine", transformRow.GetProperty("action").GetString());
        Assert.Equal(2, transformRow.GetProperty("events").GetInt64());
        Assert.DoesNotContain("deploy-admin", body, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-marker", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownOrInactiveRouteParser_StopsStartUp()
    {
        using TemporaryDirectory directory = new();
        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Start(directory, TestContext.Current.CancellationToken, parser: 7));
        Assert.Contains("route pack linux-ssh-gateway parser 7 is not an active parser", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_ReadSyslogConfigAndChangeTheConfigurationHash()
    {
        Dictionary<string, string?> environment = new(StringComparer.Ordinal)
        {
            ["BOWER_COLLECTOR_ID"] = "syslog-settings",
            ["BOWER_QUEUE_PATH"] = "/tmp/bower-syslog-settings.db"
        };
        CollectorSettings without = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        environment["BOWER_SYSLOG_CONFIG"] = "/etc/bower/syslog.json";
        CollectorSettings with = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        Assert.Null(without.SyslogConfigPath);
        Assert.Equal("/etc/bower/syslog.json", with.SyslogConfigPath);
        Assert.NotEqual(without.ConfigurationHash(), with.ConfigurationHash());
        Assert.Equal(without.ConfigurationHash(), (with with { SyslogConfigPath = null }).ConfigurationHash());
        // Pinned in the Rust port too (bower-collector tests/syslog_source.rs).
        Assert.Equal("sha256:217176a1055394e50f32c294b934ba760dfeac3097cf12b15ac208bf05208ad1", with.ConfigurationHash());
    }

    [Fact]
    public void ListenerStatus_SerializesWithTheNamesTheRustPortWrites()
    {
        SyslogListenerStatus status = new("edge", "tcp", "127.0.0.1:5514", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null);
        Assert.Equal(
            """{"id":"edge","protocol":"tcp","endpoint":"127.0.0.1:5514","activeConnections":0,"connectionsAccepted":0,"connectionsRejected":0,"sendersDenied":0,"tlsHandshakeFailures":0,"framesReceived":0,"bytesReceived":0,"queued":0,"duplicates":0,"suppressed":0,"notRouted":0,"notSelected":0,"rejected":0,"parserErrors":0,"malformed":0,"oversized":0,"framingErrors":0,"timeouts":0,"dropped":0,"retries":0,"submitFailures":0,"receiveErrors":0,"lastFrameAt":null,"tlsReloads":0,"tlsReloadFailures":0,"tlsRevoked":0,"tlsSessionsClosed":0,"serverCertificateNotAfter":null,"clientCertificateAuthorityNotAfter":null,"clientRevocationListNextUpdate":null}""",
            JsonSerializer.Serialize<IReadOnlyList<SyslogListenerStatus>>([status], SyslogJsonContext.Default.IReadOnlyListSyslogListenerStatus)[1..^1]);
    }

    private static string Frame(string result, string user = "deploy-admin") =>
        $"<38>1 {DateTimeOffset.UtcNow:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'} gw01 sshd 4242 auth " +
        $"[auth@32473 user=\"{user}\" src=\"203.0.113.5\" result=\"{result}\"] Failed password secret-marker";

    private static async Task Send(NetworkStream stream, string frame, CancellationToken cancellation)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(frame);
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"{bytes.Length} "), cancellation);
        await stream.WriteAsync(bytes, cancellation);
    }

    private static async Task<SyslogListenerStatus> WaitFor(SyslogSource source, Func<SyslogListenerStatus, bool> condition,
        CancellationToken cancellation, string listener = "edge")
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        while (true)
        {
            SyslogListenerStatus status = source.Snapshot().Single(item => item.Id == listener);
            if (condition(status)) { return status; }
            await Task.Delay(20, timeout.Token);
        }
    }

    private static async Task<WebApplication> Start(TemporaryDirectory directory, CancellationToken cancellation, int parser = 0,
        string[]? transforms = null)
    {
        string pack = Path.Combine(directory.Path, "syslog-pack");
        foreach (string path in Directory.EnumerateFiles(PackSource, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(pack, Path.GetRelativePath(PackSource, path));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(path, target);
        }

        File.WriteAllText(Path.Combine(pack, "parsers", "sshd-json.json"), SyslogParser(transforms));
        string samples = Path.Combine(pack, "samples", "ssh.jsonl");
        File.WriteAllLines(samples, File.ReadAllLines(samples).Where(line => !line.Contains("\"raw\":", StringComparison.Ordinal)));
        (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(pack, privateKey, directory.Path);
        string trust = Path.Combine(directory.Path, "trusted.pem");
        string hmac = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(trust, publicKey);
        File.WriteAllText(hmac, Convert.ToBase64String(new byte[32]));
        string syslog = Path.Combine(directory.Path, "syslog.json");
        File.WriteAllText(syslog, $$"""
            {"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [
              {"id": "edge", "protocol": "tcp", "port": 0, "allowedSenders": ["127.0.0.1"],
               "routes": [{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": {{parser}}}]},
              {"id": "edge-udp", "protocol": "udp", "port": 0, "allowedSenders": ["127.0.0.1"],
               "routes": [{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": {{parser}}}]}
            ]}
            """);
        string expectations = Path.Combine(directory.Path, "expectations.json");
        File.WriteAllText(expectations, """
            {"apiVersion": "bower.security/v1", "kind": "SourceExpectations",
             "sources": [{"application": "ssh-gateway", "environment": "production", "maximumSilenceMinutes": 5}]}
            """);
        WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            CollectorId = "syslog-collector-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [archive],
            PackTrustedKeyFiles = [trust],
            PrivacyHmacKeyFile = hmac,
            MaximumQueueBytes = 1_048_576,
            IngestToken = Token,
            SingleTrustDomain = true,
            SyslogConfigPath = syslog,
            SourceExpectationsPath = expectations
        }, builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        // Short retry delay so the backpressure test does not wait a second per attempt.
        typeof(SyslogSource).GetProperty(nameof(SyslogSource.RetryDelay))!.SetValue(
            app.Services.GetRequiredService<SyslogSource>(), TimeSpan.FromMilliseconds(50));
        return app;
    }

    private static string SyslogParser(string[]? transforms)
    {
        JsonObject Field(string name, string type, string ocsf, string asim, bool sensitive) => new()
        {
            ["sourceName"] = name,
            ["type"] = type,
            ["ocsfPath"] = ocsf,
            ["asimField"] = asim,
            ["sensitive"] = sensitive
        };
        JsonObject parser = new()
        {
            ["version"] = "1.0",
            ["format"] = "Json",
            ["fields"] = new JsonArray(
                Field("id", "Text", "metadata.uid", "EventOriginalUid", false),
                Field("timestamp", "DateTime", "time", "TimeGenerated", false),
                Field("appName", "Text", "metadata.product.name", "EventProduct", false),
                Field("sd.auth@32473.user", "Text", "actor.user.name", "TargetUsername", true),
                Field("sd.auth@32473.src", "IpAddress", "src_endpoint.ip", "SrcIpAddr", false),
                Field("sd.auth@32473.result", "Text", "status", "EventResult", false)),
            ["runtime"] = new JsonObject
            {
                ["applicationName"] = "ssh-gateway",
                ["environment"] = "production",
                ["eventCategory"] = "authentication",
                ["eventType"] = "authentication_failure",
                ["eventAction"] = "authentication.attempt",
                ["eventResult"] = "failure",
                ["match"] = new JsonObject { ["appName"] = "sshd", ["sd.auth@32473.result"] = "failure" },
                ["fields"] = new JsonObject
                {
                    ["eventId"] = "id",
                    ["timeGenerated"] = "timestamp",
                    ["actor.username"] = "sd.auth@32473.user",
                    ["source.ipAddress"] = "sd.auth@32473.src"
                }
            }
        };
        if (transforms is not null)
        {
            parser["runtime"]!["transforms"] = new JsonArray([.. transforms.Select(program => JsonValue.Create(program))]);
        }

        return parser.ToJsonString();
    }
}
