using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Cli.Commands;
using Bower.Collector;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// WEC runtime status parsing (<c>wecutil gr</c>), per-subscription source silence degrading
/// <c>/health</c>, <c>/v1/status</c> reporting, and <c>bower doctor</c> WEC host checks (#91).
/// </summary>
public sealed class WecRuntimeAndDoctorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public void WecRuntimeStatusParser_ParsesActiveInactiveAndErrorClientsAndCapsSources()
    {
        const string output = """
            Subscription: bower-security-logon
                    RunTimeStatus: Active
                    LastError: 0
                    EventSources:
                            dc01.corp.example
                                    RunTimeStatus: Active
                                    LastError: 0
                                    LastHeartbeatTime: 2026-11-22T00:59:10.000Z
                            app02.corp.example
                                    RunTimeStatus: Inactive
                                    LastError: 0
                                    LastHeartbeatTime: 2026-11-21T12:00:00.000Z
                            dmz03.corp.example
                                    RunTimeStatus: Error
                                    LastError: 2150859027
                                    LastHeartbeatTime: 2026-11-22T00:45:00.000Z
            """;

        WecSubscriptionRuntimeStatus parsed = WecRuntimeStatusParser.Parse("bower-security-logon", output, Now, maximumSources: 2);

        Assert.Equal("bower-security-logon", parsed.SubscriptionId);
        Assert.Equal("active", parsed.State);
        Assert.Equal(1, parsed.ActiveClients);
        Assert.Equal(1, parsed.InactiveClients);
        Assert.Equal(1, parsed.ErrorClients);
        Assert.True(parsed.Truncated);
        Assert.Equal(2, parsed.Sources.Count);
        Assert.Equal("dc01.corp.example", parsed.Sources[0].Machine);
        Assert.Equal("active", parsed.Sources[0].State);
        Assert.Equal(0, parsed.Sources[0].LastErrorCode);
        Assert.Equal(new DateTimeOffset(2026, 11, 22, 0, 59, 10, TimeSpan.Zero), parsed.Sources[0].LastHeartbeatAt);
        Assert.Equal("app02.corp.example", parsed.Sources[1].Machine);
        Assert.Equal("inactive", parsed.Sources[1].State);
    }

    [Fact]
    public void WecDoctorEvaluator_ParsesWindowsUtilitiesAndReportsPassWarnAndFail()
    {
        Assert.Equal("Running", WecDoctorEvaluator.ParseServiceState("SERVICE_NAME: Wecsvc\n        STATE              : 4  RUNNING"));
        Assert.Equal("Stopped", WecDoctorEvaluator.ParseServiceState("SERVICE_NAME: Wecsvc\n        STATE              : 1  STOPPED"));
        Assert.True(WecDoctorEvaluator.ParseSubscriptionEnabled("SubscriptionId: bower-security-logon\nEnabled: true\n"));
        Assert.False(WecDoctorEvaluator.ParseSubscriptionEnabled("SubscriptionId: bower-security-logon\nEnabled: false\n"));

        (bool enabled, long? maxSize, long? fileSize) = WecDoctorEvaluator.ParseChannelProperties(
            "name: ForwardedEvents\nenabled: true\nlogFileName: %SystemRoot%\\System32\\Winevt\\Logs\\ForwardedEvents.evtx\nmaxSize: 2147483648\n",
            "creationTime: 2026-10-01T00:00:00.000Z\nfileSize: 536870912\n");
        Assert.True(enabled);
        Assert.Equal(2_147_483_648L, maxSize);
        Assert.Equal(536_870_912L, fileSize);

        (bool hasHttps, int? port, string? thumbprint) = WecDoctorEvaluator.ParseWinRmListeners("""
            Listener
                Address = *
                Transport = HTTP
                Port = 5985
                Enabled = true

            Listener
                Address = *
                Transport = HTTPS
                Port = 5986
                Hostname = wec01.corp.example
                Enabled = true
                CertificateThumbprint = ab cd 12 34 56 78 90 ef 12 34 56 78 90 ab cd ef 12 34 56 78
            """);
        Assert.True(hasHttps);
        Assert.Equal(5986, port);
        Assert.Equal("ABCD1234567890EF1234567890ABCDEF12345678", thumbprint);

        // Healthy WEC host passes all checks.
        WecHostSnapshot healthy = new(
            IsWindows: true,
            ServiceState: "Running",
            Subscriptions:
            [
                new WecDoctorSubscriptionSnapshot(
                    "bower-security-logon",
                    Exists: true,
                    Enabled: true,
                    Runtime: new WecSubscriptionRuntimeStatus("bower-security-logon", "active", 12, 0, 0, Now, []))
            ],
            Channel: new WecChannelSnapshot("ForwardedEvents", true, true, 2L * 1024 * 1024 * 1024, 100L * 1024 * 1024),
            WinRmHttps: new WecWinRmListenerSnapshot(true, 5986, "ABCD", true, Now.AddDays(120)));

        IReadOnlyList<WecDoctorFinding> healthyFindings = WecDoctorEvaluator.Evaluate(healthy, Now);
        Assert.Equal(5, healthyFindings.Count);
        Assert.All(healthyFindings, finding => Assert.Equal("PASS", finding.Status));

        // Degraded/failing WEC host reports exact failures and warnings.
        WecHostSnapshot degraded = new(
            IsWindows: true,
            ServiceState: "Stopped",
            Subscriptions:
            [
                new WecDoctorSubscriptionSnapshot("bower-missing", Exists: false, Enabled: false, Runtime: null),
                new WecDoctorSubscriptionSnapshot(
                    "bower-quiet",
                    Exists: true,
                    Enabled: true,
                    Runtime: new WecSubscriptionRuntimeStatus("bower-quiet", "active", 0, 3, 0, Now, []))
            ],
            Channel: new WecChannelSnapshot("ForwardedEvents", true, true, 20L * 1024 * 1024, 18L * 1024 * 1024),
            WinRmHttps: new WecWinRmListenerSnapshot(true, 5986, "ABCD", true, Now.AddDays(5)));

        IReadOnlyList<WecDoctorFinding> findings = WecDoctorEvaluator.Evaluate(degraded, Now);
        Assert.Contains(findings, item => item.Status == "FAIL" && item.Detail.Contains("Wecsvc", StringComparison.Ordinal));
        Assert.Contains(findings, item => item.Status == "FAIL" && item.Detail.Contains("bower-missing", StringComparison.Ordinal));
        Assert.Contains(findings, item => item.Status == "WARN" && item.Detail.Contains("0 active clients", StringComparison.Ordinal));
        Assert.Contains(findings, item => item.Status == "WARN" && item.Detail.Contains("recommended >= 1024 MiB", StringComparison.Ordinal));
        Assert.Contains(findings, item => item.Status == "WARN" && item.Detail.Contains("expires in 5 day", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DoctorCommand_CheckWecHostAsync_MapsFindingsToPassWarnFail()
    {
        WecHostSnapshot snapshot = new(
            IsWindows: true,
            ServiceState: "Running",
            Subscriptions:
            [
                new WecDoctorSubscriptionSnapshot(
                    "bower-security-logon",
                    Exists: true,
                    Enabled: true,
                    Runtime: new WecSubscriptionRuntimeStatus("bower-security-logon", "active", 4, 1, 0, Now, []))
            ],
            Channel: new WecChannelSnapshot("ForwardedEvents", true, true, 2L * 1024 * 1024 * 1024, 200L * 1024 * 1024),
            WinRmHttps: new WecWinRmListenerSnapshot(true, 5986, "ABCD", true, Now.AddDays(-2)));

        List<string> results = [];
        await DoctorCommand.CheckWecHostAsync(
            ["bower-security-logon"],
            "ForwardedEvents",
            new StaticWecProbe(snapshot),
            Now,
            (area, detail) => results.Add($"PASS:{area}:{detail}"),
            (area, detail) => results.Add($"WARN:{area}:{detail}"),
            (area, detail) => results.Add($"FAIL:{area}:{detail}"),
            TestContext.Current.CancellationToken);

        Assert.Equal(4, results.Count(item => item.StartsWith("PASS:wec:", StringComparison.Ordinal)));
        Assert.Contains(results, item => item.StartsWith("FAIL:wec:", StringComparison.Ordinal) && item.Contains("expired", StringComparison.Ordinal));
    }

    [Fact]
    public void WecSubscription_Generate_DeclaresUtf8MatchingWrittenBytes()
    {
        WindowsEventSubscriptionOptions subscription = new(
            Id: "security-logon",
            Channel: "Security",
            EventIds: [4625],
            Pack: "windows-security-logon",
            Parser: 0,
            Providers: ["Microsoft-Windows-Security-Auditing"]);

        string xml = WecSubscription.Generate(subscription, new WecSubscriptionOptions());

        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("encoding=\"utf-16\"", xml, StringComparison.OrdinalIgnoreCase);

        byte[] utf8Bytes = new System.Text.UTF8Encoding(false).GetBytes(xml);
        using MemoryStream stream = new(utf8Bytes);
        System.Xml.Linq.XDocument doc = System.Xml.Linq.XDocument.Load(stream);
        Assert.Equal("Subscription", doc.Root?.Name.LocalName);
    }

    [Fact]
    public async Task Collector_WecRuntimeStatusAndPerSubscriptionSilence_ReportInStatusAndDegradeHealth()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string packPath = PackArchive.Build(
            Path.Combine(AppContext.BaseDirectory, "packs", "windows-security-logon"),
            privatePem,
            directory.Path);
        string keyPath = Path.Combine(directory.Path, "pack.pub.pem");
        await File.WriteAllTextAsync(keyPath, publicPem, cancellation);
        string hmacPath = Path.Combine(directory.Path, "hmac.key");
        await File.WriteAllBytesAsync(hmacPath, new byte[32], cancellation);

        string welConfigPath = Path.Combine(directory.Path, "wel.json");
        await File.WriteAllTextAsync(welConfigPath, """
            {
              "apiVersion": "bower.security/v1",
              "kind": "WindowsEventLogSource",
              "subscriptions": [
                {
                  "id": "security-logon",
                  "channel": "ForwardedEvents",
                  "eventIds": [4625],
                  "providers": ["Microsoft-Windows-Security-Auditing"],
                  "pack": "windows-security-logon",
                  "parser": 0,
                  "wecSubscriptionName": "bower-security-logon",
                  "maxSilentSeconds": 120
                }
              ]
            }
            """, cancellation);

        const string token = "wec-runtime-test-token-0123456789abcdef";
        StepClock clock = new(Now);
        StaticWecRuntimeReader reader = new(
            new WecSubscriptionRuntimeStatus(
                "bower-security-logon",
                "active",
                ActiveClients: 3,
                InactiveClients: 1,
                ErrorClients: 0,
                CapturedAt: Now,
                Sources: [new WecEventSourceRuntimeStatus("dc01.corp.example", "active", Now, 0)]));

        CollectorSettings settings = new()
        {
            CollectorId = "wec-host-01",
            Environment = "test",
            ListenUrl = "http://127.0.0.1:4319",
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            OutputType = "none",
            IngestToken = token,
            Packs = [packPath],
            PackTrustedKeyFiles = [keyPath],
            PrivacyHmacKeyFile = hmacPath,
            WindowsEventLogConfigPath = welConfigPath
        };

        await using WebApplication app = CollectorApplication.Build(
            settings,
            configure: builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddSingleton<TimeProvider>(clock);
                builder.Services.AddSingleton<IWindowsEventChannelFactory>(new EmptyChannelFactory());
                builder.Services.AddSingleton<IWecRuntimeReader>(reader);
            });
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);

        try
        {
            // Trigger one refresh synchronously so WecRuntime is populated deterministically.
            await app.Services.GetRequiredService<WecRuntimeStatusTracker>().RefreshAsync(cancellation);

            using HttpClient client = app.GetTestClient();

            // Before maxSilentSeconds (120 s): /health is healthy and /v1/status reports wecRuntime.
            using (HttpResponseMessage healthResponse = await client.GetAsync("/health", cancellation))
            {
                Assert.Equal(HttpStatusCode.OK, healthResponse.StatusCode);
                using JsonDocument health = JsonDocument.Parse(await healthResponse.Content.ReadAsStringAsync(cancellation));
                Assert.Equal("healthy", health.RootElement.GetProperty("status").GetString());
            }

            using (HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status"))
            {
                statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using HttpResponseMessage statusResponse = await client.SendAsync(statusRequest, cancellation);
                Assert.Equal(HttpStatusCode.OK, statusResponse.StatusCode);
                using JsonDocument status = JsonDocument.Parse(await statusResponse.Content.ReadAsStringAsync(cancellation));
                Assert.Equal("healthy", status.RootElement.GetProperty("status").GetString());
                JsonElement wec = status.RootElement.GetProperty("wecRuntime")[0];
                Assert.Equal("bower-security-logon", wec.GetProperty("subscriptionId").GetString());
                Assert.Equal(3, wec.GetProperty("activeClients").GetInt32());
                Assert.Equal(1, wec.GetProperty("inactiveClients").GetInt32());
            }

            // Advance past maxSilentSeconds (120 s) without any event arriving: /health degrades.
            clock.Advance(TimeSpan.FromSeconds(180));
            using (HttpResponseMessage degradedResponse = await client.GetAsync("/health", cancellation))
            {
                Assert.Equal(HttpStatusCode.OK, degradedResponse.StatusCode);
                using JsonDocument health = JsonDocument.Parse(await degradedResponse.Content.ReadAsStringAsync(cancellation));
                Assert.Equal("degraded", health.RootElement.GetProperty("status").GetString());
            }

            using (HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status"))
            {
                statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using HttpResponseMessage statusResponse = await client.SendAsync(statusRequest, cancellation);
                using JsonDocument status = JsonDocument.Parse(await statusResponse.Content.ReadAsStringAsync(cancellation));
                Assert.Equal("degraded", status.RootElement.GetProperty("status").GetString());
                JsonElement sub = status.RootElement.GetProperty("windowsEventLog")[0];
                Assert.True(sub.GetProperty("isSilent").GetBoolean());
                Assert.True(sub.GetProperty("silentSeconds").GetInt64() >= 180);
            }
        }
        finally
        {
            await app.StopAsync(cancellation);
        }
    }

    private sealed class StaticWecProbe(WecHostSnapshot snapshot) : IWecHostProbe
    {
        public Task<WecHostSnapshot> ProbeAsync(IReadOnlyList<string> subscriptions, string channelName, CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);
    }

    private sealed class StaticWecRuntimeReader(WecSubscriptionRuntimeStatus status) : IWecRuntimeReader
    {
        public Task<WecSubscriptionRuntimeStatus> ReadAsync(string subscriptionId, CancellationToken cancellationToken) =>
            Task.FromResult(status);
    }

    private sealed class EmptyChannelFactory : IWindowsEventChannelFactory
    {
        public IWindowsEventChannel Open(string channel) => new EmptyChannel();

        private sealed class EmptyChannel : IWindowsEventChannel
        {
            public WindowsChannelRange GetRange() => new(0, 0);
            public IReadOnlyList<WindowsRawEvent> Read(WindowsEventQuery query, int maximum, bool includeMessage, CancellationToken cancellationToken) => [];
            public void Dispose() { }
        }
    }

    private sealed class StepClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset current = start;
        public void Advance(TimeSpan delta) => current += delta;
        public override DateTimeOffset GetUtcNow() => current;
    }
}
