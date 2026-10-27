using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;

namespace Bower.UnitTests;

/// <summary>
/// The real Windows reader against the local event log service: a dedicated test log and
/// event source, allow-list filtering by the service, restart from the durable bookmark
/// and a cleared log. Runs on Windows as an administrator (the <c>windows</c> CI job sets
/// <c>BOWER_REQUIRE_WINDOWS_EVENTLOG_TESTS=1</c> so it can never skip there); skipped
/// elsewhere.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class WindowsEventLogWindowsTests
{
    private const string LogName = "BowerCiTest";
    private const string SourceName = "BowerCiSource";

    [Fact]
    public async Task RealEventLog_CollectsOnlyAllowListedEventsAndResumesFromTheBookmark()
    {
        if (OperatingSystem.IsWindows() && IsAdministrator())
        {
            await RunAsync(TestContext.Current.CancellationToken);
            return;
        }

        Assert.False(
            Environment.GetEnvironmentVariable("BOWER_REQUIRE_WINDOWS_EVENTLOG_TESTS") == "1",
            "The Windows Event Log tests must run (Windows, administrator) in this job.");
        Assert.Skip("Needs Windows and administrator rights to create a test event source.");
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunAsync(CancellationToken cancellation)
    {
        if (!EventLog.SourceExists(SourceName))
        {
            EventLog.CreateEventSource(new EventSourceCreationData(SourceName, LogName));
        }

        using EventLog log = new(LogName) { Source = SourceName };
        try
        {
            log.Clear();
            log.WriteEntry("before the first start", EventLogEntryType.Information, 1000);

            using SqliteTemporaryDirectory directory = new();
            WindowsEventLogSourceConfiguration configuration = WindowsEventLogSourceConfigurationLoader.Parse($$"""
                {"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [
                  {"id": "ci", "channel": "{{LogName}}", "eventIds": [1000], "providers": ["{{SourceName}}"],
                   "pack": "pack", "parser": 0, "includeMessage": true, "batchSize": 2}
                ]}
                """);
            RecordingWindowsEventSink sink = new();
            WindowsEventLogChannelFactory channels = new();

            await using (WindowsEventLogSource source = new(configuration, sink, await WindowsEventLogSourceTests.Cursors(directory), channels))
            {
                // First start: bookmark at the newest event, nothing read.
                Assert.Equal(0, (await source.PollOnceAsync("ci", cancellation)).Read);

                log.WriteEntry("order=1 result=failure", EventLogEntryType.Warning, 1000);
                log.WriteEntry("not allow-listed marker", EventLogEntryType.Information, 1001);
                log.WriteEntry("order=2 result=failure", EventLogEntryType.Warning, 1000);
                await PollUntil(source, sink, 2, cancellation);

                WindowsEventSubscriptionStatus status = source.Snapshot()[0];
                // The service filtered 1001 out: it was never returned to this process.
                Assert.Equal((2L, 2L, 0L), (status.EventsRead, status.Queued, status.Malformed));
                Assert.DoesNotContain(sink.Records, record => record.Contains("not allow-listed marker", StringComparison.Ordinal));
                Assert.All(sink.Records, record => Assert.Contains("\"provider\":\"BowerCiSource\"", record, StringComparison.Ordinal));
                Assert.All(sink.Records, record => Assert.Contains("\"eventId\":\"1000\"", record, StringComparison.Ordinal));
            }

            // Restart with the same queue database: resumes after the bookmark.
            log.WriteEntry("order=3 result=failure", EventLogEntryType.Warning, 1000);
            await using (WindowsEventLogSource restarted = new(configuration, sink, await WindowsEventLogSourceTests.Cursors(directory), channels))
            {
                await PollUntil(restarted, sink, 3, cancellation);
                Assert.Equal((1L, 0L), (restarted.Snapshot()[0].EventsRead, restarted.Snapshot()[0].Duplicates));

                // Cleared log: whether or not record ids restart, the next event is collected.
                long bookmark = restarted.Snapshot()[0].BookmarkRecordId!.Value;
                log.Clear();
                log.WriteEntry("order=4 result=failure", EventLogEntryType.Warning, 1000);
                await PollUntil(restarted, sink, 4, cancellation);
                long recordId = long.Parse(
                    System.Text.Json.Nodes.JsonNode.Parse(sink.Records.Last())!["recordId"]!.GetValue<string>(),
                    System.Globalization.CultureInfo.InvariantCulture);
                Assert.Equal(recordId <= bookmark ? 1 : 0, restarted.Snapshot()[0].Resets);
            }

            Assert.Equal(4, sink.Records.Count);
            Assert.Equal(4, sink.Queued.Count);

            // A missing channel is a stable code, not a crash.
            WindowsEventLogSourceConfiguration missing = WindowsEventLogSourceConfigurationLoader.Parse("""
                {"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [
                  {"id": "missing", "channel": "Bower-Missing-Channel/Operational", "eventIds": [1], "pack": "pack", "parser": 0}
                ]}
                """);
            await using WindowsEventLogSource absent = new(missing, sink, await WindowsEventLogSourceTests.Cursors(directory), channels);
            WindowsEventChannelException failure = await Assert.ThrowsAsync<WindowsEventChannelException>(
                () => absent.PollOnceAsync("missing", cancellation));
            Assert.Equal(WindowsEventChannelFailures.ChannelNotFound, failure.Code);
        }
        finally
        {
            EventLog.DeleteEventSource(SourceName);
            EventLog.Delete(LogName);
        }
    }

    private static async Task PollUntil(WindowsEventLogSource source, RecordingWindowsEventSink sink, int records, CancellationToken cancellation)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        while (sink.Records.Count < records)
        {
            await source.PollOnceAsync(source.Snapshot()[0].Id, timeout.Token);
            await Task.Delay(100, timeout.Token);
        }
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
