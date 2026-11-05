using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.Source.File;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// The file tail source inside the collector: a plain-text auth.log line becomes a durable
/// event only through the signed <c>linux-authlog-ssh</c> parser (transforms, match filter),
/// redaction and policy. Lines the parser does not select are counted and dropped.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class FileTailCollectorTests
{
    private const string Token = "file-tail-collector-test-token-0123456789abcdef";
    // RFC 3339 with an offset, as rsyslog writes by default on current distributions. Recent,
    // so policy does not refuse the time; the transform converts it to UTC.
    private static readonly DateTimeOffset At = new DateTimeOffset(DateTime.UtcNow.AddMinutes(-1).Ticks / 10 * 10, TimeSpan.Zero).ToOffset(TimeSpan.FromHours(11));
    private static readonly string Time = At.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'ffffffzzz", System.Globalization.CultureInfo.InvariantCulture);
    private static readonly string Failed = $"{Time} bastion-1 sshd[4242]: Failed password for invalid user deploy-admin from 203.0.113.5 port 52144 ssh2";
    private static readonly string Accepted = $"{Time} bastion-1 sshd[4243]: Accepted publickey for deploy-admin from 203.0.113.5 port 52145 ssh2";
    private static readonly string Cron = $"{Time} bastion-1 CRON[4244]: pam_unix(cron:session): session opened for user secret-marker";
    private static string PackSource => Path.Combine(AppContext.BaseDirectory, "packs", "linux-authlog-ssh");

    [Fact]
    public async Task SelectedAuthLogLine_IsTransformedRedactedQueuedAndTheRestIsCountedAndDropped()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string log = Path.Combine(directory.Path, "log", "auth.log");
        Directory.CreateDirectory(Path.GetDirectoryName(log)!);
        await File.WriteAllTextAsync(log, Cron + "\n", cancellation);
        await using WebApplication app = await Start(directory, log, cancellation);
        FileTailSource source = app.Services.GetRequiredService<FileTailSource>();
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        // startAt end: the line already in the file is history and is not read.
        await WaitFor(source, status => status.Offset is not null, cancellation);

        await File.AppendAllTextAsync(log, Failed + "\n" + Accepted + "\n" + Cron + "\n", cancellation);
        FileTailInputStatus counted = await WaitFor(source, status => status.Queued == 1 && status.NotSelected == 2, cancellation);
        Assert.Equal(3, counted.LinesRead);

        QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
        SecurityEventEnvelope stored = JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!;
        Assert.Equal("authentication_failure", stored.EventType);
        Assert.Equal("file:auth:linux-authlog-ssh:0", stored.Collector!.SourceAdapter);
        Assert.Equal("203.0.113.5", stored.Source!.IpAddress);
        Assert.Equal(At, stored.TimeGenerated);
        Assert.StartsWith("file-", stored.EventId, StringComparison.Ordinal);
        Assert.Equal("InvalidCredentials", stored.EventOutcomeReason);
        foreach (string text in (string[])["deploy-admin", "secret-marker", "Failed password", log])
        {
            Assert.DoesNotContain(text, row.Payload, StringComparison.Ordinal);
        }

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
        JsonElement input = status.RootElement.GetProperty("fileTail")[0];
        Assert.Equal("auth", input.GetProperty("id").GetString());
        Assert.Equal(1, input.GetProperty("queued").GetInt64());
        Assert.Equal(2, input.GetProperty("notSelected").GetInt64());
        Assert.Equal("running", input.GetProperty("state").GetString());
        Assert.DoesNotContain("deploy-admin", body, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-marker", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Restart_ResumesFromTheDurableCursorWithoutLossOrDuplicates()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string log = Path.Combine(directory.Path, "log", "auth.log");
        Directory.CreateDirectory(Path.GetDirectoryName(log)!);
        await File.WriteAllTextAsync(log, Failed + "\n", cancellation);
        await using (WebApplication first = await Start(directory, log, cancellation, startAt: "beginning"))
        {
            await WaitFor(first.Services.GetRequiredService<FileTailSource>(), status => status.Queued == 1, cancellation);
            await first.StopAsync(cancellation);
        }

        // Written while the collector was down: read after the restart, and the first line is not read again.
        await File.AppendAllTextAsync(log, Failed.Replace("4242", "4250", StringComparison.Ordinal) + "\n", cancellation);
        await using WebApplication second = await Start(directory, log, cancellation, startAt: "beginning");
        FileTailInputStatus status = await WaitFor(second.Services.GetRequiredService<FileTailSource>(), item => item.Queued == 1, cancellation);
        Assert.Equal((1, 0), (status.LinesRead, status.Duplicates));
        Assert.Equal(2, (await second.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation)).Queued);
    }

    [Fact]
    public async Task RouteToAMissingParser_StopsStartUpAndRefusesASignedReload()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string log = Path.Combine(directory.Path, "log", "auth.log");
        CollectorSettings settings = Settings(directory, log, "end", parser: 1);

        InvalidOperationException refused = Assert.Throws<InvalidOperationException>(() => CollectorApplication.Build(settings));
        Assert.Contains("File tail input auth: route pack linux-authlog-ssh parser 1", refused.Message, StringComparison.Ordinal);
        Assert.Equal(nameof(InvalidOperationException), ManagementCommandWorker.ReloadRefusal(settings));
        Assert.Null(ManagementCommandWorker.ReloadRefusal(Settings(directory, log, "end")));

        await File.WriteAllTextAsync(settings.FileTailConfigPath!, """{"apiVersion":"bower.security/v1","kind":"FileTailSource","allowedRoots":["/var/log"],"inputs":[],"globs":["*"]}""", cancellation);
        Assert.Equal(nameof(InvalidDataException), ManagementCommandWorker.ReloadRefusal(settings));
    }

    [Fact]
    public void ConfigurationHash_ChangesOnlyWhenTheFileSourceIsConfigured()
    {
        CollectorSettings plain = CollectorSettings.FromEnvironment(name => name == "BOWER_INGEST_TOKEN" ? Token : null);
        CollectorSettings file = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_INGEST_TOKEN" => Token,
            "BOWER_FILE_CONFIG" => "/etc/bower/file.json",
            _ => null
        });
        Assert.Equal("/etc/bower/file.json", file.FileTailConfigPath);
        Assert.Null(plain.FileTailConfigPath);
        Assert.NotEqual(plain.ConfigurationHash(), file.ConfigurationHash());

        // Appended after syslog (and Windows Event Log, which Rust refuses). Pinned in the
        // Rust collector too (rust/crates/bower-collector/tests/file_tail_source.rs).
        CollectorSettings pinned = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = "queue.db",
            PolicyDirectory = "policies",
            CollectorId = "edge-01",
            SyslogConfigPath = "/etc/bower/syslog.json",
            FileTailConfigPath = "/etc/bower/file.json"
        };
        Assert.Equal("sha256:71d6a33e0d2c55df95ea9b44bc947d9bf28439afedb36e22f37b96b3d800bcae", pinned.ConfigurationHash());
    }

    private static async Task<FileTailInputStatus> WaitFor(FileTailSource source, Func<FileTailInputStatus, bool> condition, CancellationToken cancellation)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        while (true)
        {
            FileTailInputStatus status = Assert.Single(source.Snapshot());
            if (condition(status))
            {
                return status;
            }

            if (timeout.IsCancellationRequested)
            {
                Assert.Fail("Timed out waiting for the file tail input: " + JsonSerializer.Serialize(status));
            }

            await Task.Delay(25, CancellationToken.None);
        }
    }

    private static async Task<WebApplication> Start(TemporaryDirectory directory, string log, CancellationToken cancellation, string startAt = "end")
    {
        WebApplication app = CollectorApplication.Build(Settings(directory, log, startAt), builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        return app;
    }

    private static CollectorSettings Settings(TemporaryDirectory directory, string log, string startAt, int parser = 0)
    {
        string archive = Path.Combine(directory.Path, "linux-authlog-ssh.bowerpack");
        string trust = Path.Combine(directory.Path, "trusted.pem");
        if (!File.Exists(archive))
        {
            (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
            File.Move(PackArchive.Build(PackSource, privateKey, directory.Path), archive);
            File.WriteAllText(trust, publicKey);
            File.WriteAllText(Path.Combine(directory.Path, "hmac.key"), Convert.ToBase64String(new byte[32]));
        }

        string configuration = Path.Combine(directory.Path, "file.json");
        File.WriteAllText(configuration, new System.Text.Json.Nodes.JsonObject
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "FileTailSource",
            ["allowedRoots"] = new System.Text.Json.Nodes.JsonArray(Path.GetDirectoryName(log)),
            ["pollIntervalMilliseconds"] = 100,
            ["inputs"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject
            {
                ["id"] = "auth",
                ["path"] = log,
                ["startAt"] = startAt,
                ["route"] = new System.Text.Json.Nodes.JsonObject { ["pack"] = "linux-authlog-ssh", ["parser"] = parser }
            })
        }.ToJsonString());
        return new CollectorSettings
        {
            CollectorId = "file-tail-collector-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [archive],
            PackTrustedKeyFiles = [trust],
            PrivacyHmacKeyFile = Path.Combine(directory.Path, "hmac.key"),
            MaximumQueueBytes = 1_048_576,
            IngestToken = Token,
            SingleTrustDomain = true,
            FileTailConfigPath = configuration
        };
    }
}
