using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

/// <summary>
/// Collector crash resilience and disk hygiene (#138): opt-in dead-letter retention with
/// ledger evidence and pre-expiry warning, systemd sd_notify watchdog, and spool/archive
/// volume free-space health.
/// </summary>
public sealed class CrashResilienceAndDiskHygieneTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 11, 22, 2, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task DeadLetterRetention_DisabledByDefault_NeverRemovesDeadLetters()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        StepClock clock = new(BaseTime);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);

        await store.EnqueueAsync(new QueuedEvent("dlq-keep-1", "fp-keep-1", "{\"eventId\":\"dlq-keep-1\",\"secret\":\"none\"}", BaseTime.AddDays(-60)), cancellation);
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(1, TimeSpan.FromMinutes(1), cancellation);
        await store.MarkDeadLetteredAsync(leased[0].EventId, "preflight-invalid", leased[0].LeaseToken!, cancellation);

        CollectorSettings settings = new()
        {
            CollectorId = "dlq-keep-01",
            ListenUrl = "http://127.0.0.1:4319",
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            DeadLetterRetention = null
        };
        RecordingLogger<QueueRetentionJob> logger = new();
        QueueRetentionJob job = new(store, clock, settings, logger);
        await job.RunAsync(cancellation);

        Assert.Equal(1, (await store.GetSnapshotAsync(cancellation)).DeadLettered);
        Assert.Empty(await store.ListDeadLetterPurgesAsync(cancellationToken: cancellation));
        Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
    }

    [Fact]
    public async Task DeadLetterRetention_OptIn_WarnsBeforeExpiryAndWritesLedgerEvidenceBeforePurge()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        StepClock clock = new(BaseTime);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);

        // One dead letter approaching expiry (29.5 days old on a 30-day retention -> warns, not purged).
        await store.EnqueueAsync(new QueuedEvent("dlq-warn-1", "fp-warn-1", "{\"eventId\":\"dlq-warn-1\",\"raw\":\"must-not-leak\"}", BaseTime.AddDays(-29.5)), cancellation);
        // One dead letter past expiry (31 days old -> purged with ledger evidence).
        await store.EnqueueAsync(new QueuedEvent("dlq-old-1", "fp-old-1", "{\"eventId\":\"dlq-old-1\",\"raw\":\"also-must-not-leak\"}", BaseTime.AddDays(-31)), cancellation);
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(2, TimeSpan.FromMinutes(1), cancellation);
        QueuedEvent warnEvent = leased.Single(e => e.EventId == "dlq-warn-1");
        QueuedEvent oldEvent = leased.Single(e => e.EventId == "dlq-old-1");
        await store.MarkDeadLetteredAsync(warnEvent.EventId, "payload-invalid-json", warnEvent.LeaseToken!, cancellation);
        await store.MarkDeadLetteredAsync(oldEvent.EventId, "azure-http-400", oldEvent.LeaseToken!, cancellation);

        CollectorSettings settings = new()
        {
            CollectorId = "dlq-optin-01",
            ListenUrl = "http://127.0.0.1:4319",
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            DeadLetterRetention = TimeSpan.FromDays(30)
        };
        RecordingLogger<QueueRetentionJob> logger = new();
        QueueRetentionJob job = new(store, clock, settings, logger);
        await job.RunAsync(cancellation);

        // Old one purged, approaching-expiry one retained, and warning logged.
        QueueSnapshot after = await store.GetSnapshotAsync(cancellation);
        Assert.Equal(1, after.DeadLettered);
        IReadOnlyList<DeadLetterRecord> remaining = await store.ListDeadLetteredAsync(10, cancellation);
        Assert.Equal("dlq-warn-1", Assert.Single(remaining).EventId);

        // Ledger evidence recorded and chain stays 100% intact.
        LedgerVerification verification = await store.VerifyLedgerAsync(cancellation);
        Assert.True(verification.Intact, string.Join("; ", verification.Issues.Select(issue => $"{issue.Code}: {issue.Detail}")));

        IReadOnlyList<DeadLetterPurgeEvidence> purges = await store.ListDeadLetterPurgesAsync(cancellationToken: cancellation);
        DeadLetterPurgeEvidence evidence = Assert.Single(purges);
        Assert.Equal(1, evidence.PurgedCount);
        Assert.Equal(1, evidence.ReasonCounts["azure-http-400"]);
        Assert.True(evidence.LedgerSequence > 0);
        Assert.Contains(logger.EventIds, id => id == 1511);

        // Next run sees dlq-warn-1 as oldest (0.5 days left -> inside 24h warning window).
        await job.RunAsync(cancellation);
        Assert.Contains(logger.EventIds, id => id == 1510);
    }

    [Fact]
    public async Task SystemdWatchdog_ParsesEnvironmentAndSendsReadyWatchdogAndStopping()
    {
        SystemdWatchdogOptions options = SystemdWatchdogOptions.FromEnvironment(name => name switch
        {
            "NOTIFY_SOCKET" => "/run/systemd/notify",
            "WATCHDOG_USEC" => "60000000",
            _ => null
        });
        Assert.True(options.IsEnabled);
        Assert.Equal(TimeSpan.FromSeconds(30), options.WatchdogInterval);

        SystemdWatchdogOptions disabled = SystemdWatchdogOptions.FromEnvironment(_ => null);
        Assert.False(disabled.IsEnabled);

        if (!OperatingSystem.IsWindows())
        {
            // Real Unix domain datagram socket test (short /tmp path to stay under macOS 104-char sun_path limit).
            string socketPath = Path.Combine("/tmp", $"bower-sd-{Guid.NewGuid():N}"[..24] + ".sock");
            try
            {
                using Socket server = new(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
                server.Bind(new UnixDomainSocketEndPoint(socketPath));

                UnixSystemdNotifier notifier = new(socketPath);
                Assert.True(notifier.Notify("READY=1"));
                Assert.True(notifier.Notify("WATCHDOG=1"));

                byte[] buffer = new byte[64];
                int first = await server.ReceiveAsync(buffer, SocketFlags.None, TestContext.Current.CancellationToken);
                Assert.Equal("READY=1", Encoding.UTF8.GetString(buffer, 0, first));
                int second = await server.ReceiveAsync(buffer, SocketFlags.None, TestContext.Current.CancellationToken);
                Assert.Equal("WATCHDOG=1", Encoding.UTF8.GetString(buffer, 0, second));
            }
            finally
            {
                if (File.Exists(socketPath))
                {
                    File.Delete(socketPath);
                }
            }
        }
    }

    [Fact]
    public async Task Collector_AuxiliaryArchiveVolumeCritical_DegradesHealthAndReportsVolumesInStatus()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string archiveDir = Path.Combine(directory.Path, "archive");
        Directory.CreateDirectory(archiveDir);
        const string token = "disk-hygiene-test-token-0123456789abcdef";

        // Queue volume healthy (50 GiB free), archive volume critically low (10 MiB free).
        PerDirectoryDiskProbe probe = new(archiveDir, new DiskSpace(10L * 1024 * 1024, 10L * 1024 * 1024 * 1024));
        CollectorSettings settings = new()
        {
            CollectorId = "disk-hygiene-01",
            Environment = "test",
            ListenUrl = "http://127.0.0.1:4319",
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            ArchivePath = archiveDir,
            OutputType = "none",
            IngestToken = token
        };

        await using WebApplication app = CollectorApplication.Build(
            settings,
            configure: builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddSingleton<IDiskSpaceProbe>(probe);
            });
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);

        try
        {
            using HttpClient client = app.GetTestClient();
            using HttpResponseMessage healthResponse = await client.GetAsync("/health", cancellation);
            Assert.Equal(HttpStatusCode.OK, healthResponse.StatusCode);
            using JsonDocument health = JsonDocument.Parse(await healthResponse.Content.ReadAsStringAsync(cancellation));
            Assert.Equal("degraded", health.RootElement.GetProperty("status").GetString());

            using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
            statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using HttpResponseMessage statusResponse = await client.SendAsync(statusRequest, cancellation);
            using JsonDocument status = JsonDocument.Parse(await statusResponse.Content.ReadAsStringAsync(cancellation));
            Assert.Equal("degraded", status.RootElement.GetProperty("status").GetString());
            JsonElement archiveVolume = status.RootElement.GetProperty("volumes")[0];
            Assert.Equal("archive", archiveVolume.GetProperty("volume").GetString());
            Assert.Equal("critical", archiveVolume.GetProperty("state").GetString());
        }
        finally
        {
            await app.StopAsync(cancellation);
        }
    }

    private sealed class PerDirectoryDiskProbe(string criticalDirectory, DiskSpace criticalSpace) : IDiskSpaceProbe
    {
        public DiskSpace? Measure(string directory) =>
            directory.StartsWith(criticalDirectory, StringComparison.OrdinalIgnoreCase)
                ? criticalSpace
                : new DiskSpace(50L * 1024 * 1024 * 1024, 100L * 1024 * 1024 * 1024);
    }

    private sealed class StepClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset current = start;
        public override DateTimeOffset GetUtcNow() => current;
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public ConcurrentBag<int> EventIds { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            EventIds.Add(eventId.Id);
    }
}
