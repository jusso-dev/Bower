using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// The Windows Event Log source inside the collector, against an in-memory channel: an
/// event becomes a durable event only through the signed <c>windows-security-logon</c>
/// pack parser, redaction and policy; the bookmark lives in the queue database.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class WindowsEventLogCollectorTests
{
    private const string Token = "windows-eventlog-collector-test-token-0123456789";
    private static string PackSource => Path.Combine(AppContext.BaseDirectory, "packs", "windows-security-logon");

    [Fact]
    public async Task ShutdownDeadlineBoundsAStalledChannelReadAndCleanupFinishesAfterRelease()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        BlockingWindowsEventChannel channels = new();
        await using WebApplication app = await Start(directory, channels, cancellation);
        try
        {
            await channels.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellation);
            using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            deadline.CancelAfter(TimeSpan.FromMilliseconds(100));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => app.StopAsync(deadline.Token).WaitAsync(TimeSpan.FromSeconds(5), cancellation));
            Assert.False(channels.Disposed.Task.IsCompleted);
        }
        finally
        {
            channels.Release.TrySetResult();
            await channels.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellation);
        }
    }

    private sealed class BlockingWindowsEventChannel : IWindowsEventChannelFactory, IWindowsEventChannel
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Disposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IWindowsEventChannel Open(string channel) => this;

        public WindowsChannelRange GetRange()
        {
            Entered.TrySetResult();
            Release.Task.GetAwaiter().GetResult();
            return new WindowsChannelRange(0, 0);
        }

        public IReadOnlyList<WindowsRawEvent> Read(WindowsEventQuery query, int maximum, bool includeMessage, CancellationToken cancellationToken) => [];

        public void Dispose() => Disposed.TrySetResult();
    }

    [Fact]
    public async Task SelectedEvent_IsRedactedQueuedAndBookmarkedInTheQueueDatabaseAcrossRestarts()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel security = channels["Security"];
        string selected = WindowsEventFixtures.Read("security-4625.xml");
        security.Add(selected);
        // Local console failure: no source address, so the pack parser does not select it.
        security.Add(selected.Replace("184467", "184468", StringComparison.Ordinal)
            .Replace("<Data Name='IpAddress'>203.0.113.5</Data>", "<Data Name='IpAddress'>-</Data>", StringComparison.Ordinal));
        // Not on the allow-list: never read.
        security.Add(WindowsEventFixtures.Event(184469, 4624, "Microsoft-Windows-Security-Auditing", "Security", "app01.corp.example",
            data: [("TargetUserName", "allow-list-marker")]));

        await using (WebApplication app = await Start(directory, channels, cancellation))
        {
            WindowsEventLogSource source = app.Services.GetRequiredService<WindowsEventLogSource>();
            IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
            WindowsEventSubscriptionStatus counted = await WindowsEventLogSourceTests.WaitFor(
                source, status => status.Queued == 1 && status.NotSelected == 1 && status.BookmarkRecordId == 184469, cancellation);
            // Caught up: the bookmark moves to the newest record scanned, past the 4624 it never read.
            Assert.Equal((2L, 184469L), (counted.EventsRead, counted.BookmarkRecordId!.Value));
            Assert.Equal([184467L, 184468L], security.Returned);

            QueuedEvent row = Assert.Single(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
            SecurityEventEnvelope stored = JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!;
            Assert.Equal("authentication_failure", stored.EventType);
            Assert.Equal("InvalidCredentials", stored.EventOutcomeReason);
            Assert.Equal("203.0.113.5", stored.Source!.IpAddress);
            Assert.Equal("winevt-65de927a5a517c41e8e00b5a161bd834", stored.EventId);
            Assert.Equal("windows-eventlog:security-logon:windows-security-logon:0", stored.Collector!.SourceAdapter);
            Assert.NotEqual("deploy-admin", stored.Actor!.Username);

            using HttpClient http = app.GetTestClient();
            using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            using HttpResponseMessage response = await http.SendAsync(request, cancellation);
            string body = await response.Content.ReadAsStringAsync(cancellation);
            using JsonDocument status = JsonDocument.Parse(body);
            JsonElement subscription = status.RootElement.GetProperty("windowsEventLog")[0];
            Assert.Equal("security-logon", subscription.GetProperty("id").GetString());
            Assert.Equal(1, subscription.GetProperty("queued").GetInt64());
            Assert.Equal(184469, subscription.GetProperty("bookmarkRecordId").GetInt64());
            JsonElement expected = Assert.Single(status.RootElement.GetProperty("sources").EnumerateArray());
            Assert.Equal("windows-security", expected.GetProperty("application").GetString());
            Assert.Equal("active", expected.GetProperty("state").GetString());
            Assert.DoesNotContain("deploy-admin", body, StringComparison.Ordinal);
            Assert.DoesNotContain("ATTACKER-PC", body, StringComparison.Ordinal);
        }

        // The bookmark is a row in the queue database itself.
        await using (SqliteConnection connection = new($"Data Source={Path.Combine(directory.Path, "queue.db")};Pooling=False"))
        {
            await connection.OpenAsync(cancellation);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """SELECT "Value" FROM "source_cursors" WHERE "SourceId" = 'windows-eventlog:security-logon';""";
            Assert.Equal("""{"schemaVersion":2,"channel":"Security","recordId":184469}""", await command.ExecuteScalarAsync(cancellation));
        }

        // Disposing the host returns SQLite handles to the pool. Release them before
        // reading the database bytes: Windows rejects File.ReadAllBytes's share mode
        // while a pooled connection still holds the database open.
        SqliteConnection.ClearAllPools();
        foreach (string path in Directory.EnumerateFiles(directory.Path, "queue.db*"))
        {
            string bytes = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path, cancellation));
            Assert.DoesNotContain("deploy-admin", bytes, StringComparison.Ordinal);
            Assert.DoesNotContain("ATTACKER-PC", bytes, StringComparison.Ordinal);
            Assert.DoesNotContain("allow-list-marker", bytes, StringComparison.Ordinal);
        }

        // Restart: resumes after the bookmark; the earlier events are neither lost nor re-queued.
        security.Add(selected.Replace("184467", "184470", StringComparison.Ordinal)
            .Replace("10:00:00.1234567Z", "10:05:00.0000000Z", StringComparison.Ordinal));
        await using (WebApplication restarted = await Start(directory, channels, cancellation))
        {
            WindowsEventLogSource source = restarted.Services.GetRequiredService<WindowsEventLogSource>();
            WindowsEventSubscriptionStatus resumed = await WindowsEventLogSourceTests.WaitFor(
                source, status => status.Queued == 1 && status.BookmarkRecordId == 184470, cancellation);
            Assert.Equal((1L, 0L), (resumed.EventsRead, resumed.Duplicates));
            QueueSnapshot queue = await restarted.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(cancellation);
            // One still leased from the first run, one new: two events in total.
            Assert.Equal(2, queue.Queued + queue.Uploading);
        }

        Assert.Equal([184467L, 184468L, 184470L], security.Returned);
    }

    [Fact]
    public async Task UnknownParser_StopsStartUp()
    {
        using SqliteTemporaryDirectory directory = new();
        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Start(directory, new FakeWindowsEventChannelFactory(), TestContext.Current.CancellationToken, parser: 3));
        Assert.Contains("pack windows-security-logon parser 3 is not an active parser", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutTheWindowsEventLogService_StartUpFailsClosed()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows has the event log service; WindowsEventLogWindowsTests covers the real reader.");
        }

        using SqliteTemporaryDirectory directory = new();
        PlatformNotSupportedException failure = await Assert.ThrowsAsync<PlatformNotSupportedException>(
            () => Start(directory, channels: null, TestContext.Current.CancellationToken));
        Assert.Contains("BOWER_WINDOWS_EVENTLOG_CONFIG needs Windows", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_ReadTheWindowsEventLogConfigAndChangeTheConfigurationHash()
    {
        Dictionary<string, string?> environment = new(StringComparer.Ordinal)
        {
            ["BOWER_COLLECTOR_ID"] = "windows-eventlog-settings",
            ["BOWER_QUEUE_PATH"] = "/tmp/bower-windows-eventlog-settings.db"
        };
        CollectorSettings without = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        environment["BOWER_WINDOWS_EVENTLOG_CONFIG"] = @"C:\ProgramData\Bower\windows-eventlog.json";
        CollectorSettings with = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        Assert.Null(without.WindowsEventLogConfigPath);
        Assert.Equal(@"C:\ProgramData\Bower\windows-eventlog.json", with.WindowsEventLogConfigPath);
        Assert.NotEqual(without.ConfigurationHash(), with.ConfigurationHash());
        Assert.Equal(without.ConfigurationHash(), (with with { WindowsEventLogConfigPath = null }).ConfigurationHash());
    }

    private static async Task<WebApplication> Start(
        SqliteTemporaryDirectory directory,
        IWindowsEventChannelFactory? channels,
        CancellationToken cancellation,
        int parser = 0)
    {
        string archive = Path.Combine(directory.Path, "pack");
        string trust = Path.Combine(directory.Path, "trusted.pem");
        string hmac = Path.Combine(directory.Path, "hmac.key");
        if (!File.Exists(trust))
        {
            (string privateKey, string publicKey, _) = DetachedSigner.GenerateKeyPair();
            Directory.CreateDirectory(archive);
            File.WriteAllText(Path.Combine(archive, "path.txt"), PackArchive.Build(PackSource, privateKey, archive));
            File.WriteAllText(trust, publicKey);
            File.WriteAllText(hmac, Convert.ToBase64String(new byte[32]));
        }

        string config = Path.Combine(directory.Path, "windows-eventlog.json");
        File.WriteAllText(config, $$"""
            {"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [
              {"id": "security-logon", "channel": "Security", "eventIds": [4625],
               "providers": ["Microsoft-Windows-Security-Auditing"], "pack": "windows-security-logon", "parser": {{parser}},
               "readExisting": true, "pollIntervalSeconds": 1}
            ]}
            """);
        string expectations = Path.Combine(directory.Path, "expectations.json");
        File.WriteAllText(expectations, """
            {"apiVersion": "bower.security/v1", "kind": "SourceExpectations",
             "sources": [{"application": "windows-security", "environment": "production", "maximumSilenceMinutes": 5}]}
            """);
        WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            CollectorId = "windows-eventlog-collector-test",
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(directory.Path, "no-defaults"),
            Packs = [File.ReadAllText(Path.Combine(archive, "path.txt"))],
            PackTrustedKeyFiles = [trust],
            PrivacyHmacKeyFile = hmac,
            IngestToken = Token,
            SingleTrustDomain = true,
            WindowsEventLogConfigPath = config,
            SourceExpectationsPath = expectations
        }, builder =>
        {
            builder.WebHost.UseTestServer();
            if (channels is not null)
            {
                builder.Services.AddSingleton<IWindowsEventChannelFactory>(channels);
            }
        });
        try
        {
            await CollectorApplication.InitializeAsync(app, cancellation);
            await app.StartAsync(cancellation);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }

        return app;
    }
}
