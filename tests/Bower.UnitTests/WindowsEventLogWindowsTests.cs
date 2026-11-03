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

                // Observe the empty log before writing again. Windows can retain record
                // IDs after a clear; the reset is determined by the range at poll time,
                // not by the ID of an event written after that observation.
                log.Clear();
                Assert.Equal(0, (await restarted.PollOnceAsync("ci", cancellation)).Read);
                Assert.Equal(1, restarted.Snapshot()[0].Resets);
                log.WriteEntry("order=4 result=failure", EventLogEntryType.Warning, 1000);
                await PollUntil(restarted, sink, 4, cancellation);
                long recordId = long.Parse(
                    System.Text.Json.Nodes.JsonNode.Parse(sink.Records.Last())!["recordId"]!.GetValue<string>(),
                    System.Globalization.CultureInfo.InvariantCulture);
                Assert.Equal(recordId, restarted.Snapshot()[0].BookmarkRecordId);
                using (IWindowsEventChannel boundary = channels.Open(LogName))
                {
                    Assert.Equal(recordId, boundary.GetRange().NewestRecordId);
                }
                Assert.Equal(0, (await restarted.PollOnceAsync("ci", cancellation)).Read);
                Assert.Equal(1, restarted.Snapshot()[0].Resets);
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

    [Fact]
    public void RealEventLog_PollCostDoesNotGrowWithChannelSize()
    {
        if (OperatingSystem.IsWindows() && IsAdministrator())
        {
            PollCostAtTwoSizes();
            return;
        }

        Assert.False(
            Environment.GetEnvironmentVariable("BOWER_REQUIRE_WINDOWS_EVENTLOG_TESTS") == "1",
            "The Windows Event Log tests must run (Windows, administrator) in this job.");
        Assert.Skip("Needs Windows and administrator rights to create a test event source.");
    }

    /// <summary>
    /// One idle poll (boundary range, then the allow-listed query resumed from a bookmark at
    /// the newest record) at 200 and at 20,200 records. The wecfix profile measured 0.8-0.9 ms
    /// per poll from 10,000 to 1,040,000 ForwardedEvents records; the bound here is generous
    /// so a slow runner cannot fail it, while a per-poll scan of the channel would.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void PollCostAtTwoSizes()
    {
        const string scaleLog = "BowerCiScale";
        const string scaleSource = "BowerCiScaleSource";
        if (!EventLog.SourceExists(scaleSource))
        {
            EventLog.CreateEventSource(new EventSourceCreationData(scaleSource, scaleLog));
        }

        using EventLog log = new(scaleLog) { Source = scaleSource };
        try
        {
            log.Clear();
            log.MaximumKilobytes = 256 * 1024;
            Write(log, 200);
            double small = MedianPollMilliseconds(scaleLog, scaleSource);
            Write(log, 20_000);
            double large = MedianPollMilliseconds(scaleLog, scaleSource);
            Assert.True(large <= small * 5 + 5, $"median poll {small:F3} ms at 200 records, {large:F3} ms at 20,200");
        }
        finally
        {
            EventLog.DeleteEventSource(scaleSource);
            EventLog.Delete(scaleLog);
        }

        static void Write(EventLog log, int count)
        {
            for (int index = 0; index < count; index++)
            {
                // Mostly not allow-listed, as on a WEC: the service filters them out.
                log.WriteEntry("scale", EventLogEntryType.Information, index % 10 == 0 ? 1000 : 1001);
            }
        }

        static double MedianPollMilliseconds(string channel, string provider)
        {
            using IWindowsEventChannel reader = new WindowsEventLogChannelFactory().Open(channel);
            long newest = reader.GetRange().NewestRecordId;
            WindowsEventQuery query = new(channel, [1000], [provider], newest);
            double[] samples = new double[41];
            for (int index = 0; index < samples.Length; index++)
            {
                long started = Stopwatch.GetTimestamp();
                Assert.Equal(newest, reader.GetRange().NewestRecordId);
                Assert.Empty(reader.Read(query, 256, includeMessage: false, CancellationToken.None));
                samples[index] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            }

            Array.Sort(samples);
            return samples[samples.Length / 2];
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
