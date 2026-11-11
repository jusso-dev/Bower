using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.ExceptionServices;
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
    private const string ScaleLogName = "BowerCiScale";
    private const string ScaleSourceName = "BowerCiScaleSource";

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
        Exception? setupOrTest = null;
        try
        {
            CreateLog(LogName, SourceName, maximumSizeInBytes: 0);
            using EventLog log = new(LogName) { Source = SourceName };
            log.Clear();
            WriteEntry(log, "before the first start", EventLogEntryType.Information, 1000);

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

                WriteEntry(log, "order=1 result=failure", EventLogEntryType.Warning, 1000);
                WriteEntry(log, "not allow-listed marker", EventLogEntryType.Information, 1001);
                WriteEntry(log, "order=2 result=failure", EventLogEntryType.Warning, 1000);
                await PollUntil(source, sink, 2, cancellation);

                WindowsEventSubscriptionStatus status = source.Snapshot()[0];
                // The service filtered 1001 out: it was never returned to this process.
                Assert.Equal((2L, 2L, 0L), (status.EventsRead, status.Queued, status.Malformed));
                Assert.DoesNotContain(sink.Records, record => record.Contains("not allow-listed marker", StringComparison.Ordinal));
                Assert.All(sink.Records, record => Assert.Contains("\"provider\":\"BowerCiSource\"", record, StringComparison.Ordinal));
                Assert.All(sink.Records, record => Assert.Contains("\"eventId\":\"1000\"", record, StringComparison.Ordinal));
            }

            // Restart with the same queue database: resumes after the bookmark.
            WriteEntry(log, "order=3 result=failure", EventLogEntryType.Warning, 1000);
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
                WriteEntry(log, "order=4 result=failure", EventLogEntryType.Warning, 1000);
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
        catch (Exception exception)
        {
            setupOrTest = exception;
            throw;
        }
        finally
        {
            DeleteLog(LogName, SourceName, setupOrTest);
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
        Exception? setupOrTest = null;
        try
        {
            CreateLog(ScaleLogName, ScaleSourceName, maximumSizeInBytes: 256L * 1024 * 1024);
            using EventLog log = new(ScaleLogName) { Source = ScaleSourceName };
            log.Clear();
            Write(log, 200);
            long oldest = Range(ScaleLogName).OldestRecordId;
            double small = MedianPollMilliseconds(ScaleLogName, ScaleSourceName);
            Write(log, 20_000);
            // Outside the timed polls: the log holds the whole population, so a size the
            // service ignored cannot shrink the proof by overwriting the oldest records.
            Assert.Equal(20_200, log.Entries.Count);
            Assert.Equal(oldest, Range(ScaleLogName).OldestRecordId);
            double large = MedianPollMilliseconds(ScaleLogName, ScaleSourceName);
            Assert.True(large <= small * 5 + 5, $"median poll {small:F3} ms at 200 records, {large:F3} ms at 20,200");
        }
        catch (Exception exception)
        {
            setupOrTest = exception;
            throw;
        }
        finally
        {
            DeleteLog(ScaleLogName, ScaleSourceName, setupOrTest);
        }

        static void Write(EventLog log, int count)
        {
            for (int index = 0; index < count; index++)
            {
                // Mostly not allow-listed, as on a WEC: the service filters them out.
                WriteEntry(log, "scale", EventLogEntryType.Information, index % 10 == 0 ? 1000 : 1001);
            }
        }

        static WindowsChannelRange Range(string channel)
        {
            using IWindowsEventChannel reader = new WindowsEventLogChannelFactory().Open(channel);
            return reader.GetRange();
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

    /// <summary>
    /// Removes the test source and log, also after a failed setup. A cleanup failure never
    /// hides the setup or test failure: both are reported together.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void DeleteLog(string logName, string sourceName, Exception? setupOrTest)
    {
        List<Exception> failures = [];
        try
        {
            if (EventLog.SourceExists(sourceName))
            {
                EventLog.DeleteEventSource(sourceName);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        try
        {
            if (EventLog.Exists(logName))
            {
                EventLog.Delete(logName);
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        if (failures.Count == 0)
        {
            return;
        }

        if (setupOrTest is null && failures.Count == 1)
        {
            ExceptionDispatchInfo.Throw(failures[0]);
        }

        throw new AggregateException(setupOrTest is null ? failures : [setupOrTest, .. failures]);
    }

    /// <summary>
    /// Creates the test log and waits until the event log service serves it.
    /// <c>CreateEventSource</c> only writes the registry; the service registers the new log
    /// asynchronously, and until it has, opening, clearing or writing the log fails with
    /// Access is denied. A maximum size is set through the service
    /// (<c>EvtSaveChannelConfig</c>), not <c>EventLog.MaximumKilobytes</c>: that also only
    /// writes the registry, and writes are denied while the service reconfigures the log.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CreateLog(string logName, string sourceName, long maximumSizeInBytes)
    {
        if (!EventLog.SourceExists(sourceName))
        {
            EventLog.CreateEventSource(new EventSourceCreationData(sourceName, logName));
        }

        WaitUntilServed(logName, sourceName, "created");
        if (maximumSizeInBytes > 0)
        {
            using (EventLogConfiguration configuration = new(logName))
            {
                configuration.MaximumSizeInBytes = maximumSizeInBytes;
                configuration.SaveChanges();
            }

            WaitUntilServed(logName, sourceName, "resized");
        }
    }

    /// <summary>
    /// Served means the classic API opens the log for reading (as <c>Clear</c> does) and a
    /// probe event written through the source reads back from the channel after the newest
    /// record seen before this attempt's write. Each attempt uses new handles, so a handle
    /// that failed is never reused. The probe (999) is not allow-listed and each test clears
    /// the log. The retry count and wait time go to the test output.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void WaitUntilServed(string logName, string sourceName, string stage)
    {
        WindowsEventLogChannelFactory channels = new();
        Stopwatch waited = Stopwatch.StartNew();
        for (int retries = 0; ; retries++)
        {
            Exception? unavailable = null;
            try
            {
                using EventLog log = new(logName) { Source = sourceName };
                _ = log.Entries.Count;
                using IWindowsEventChannel channel = channels.Open(logName);
                long before = channel.GetRange().NewestRecordId;
                log.WriteEntry("registration probe", EventLogEntryType.Information, 999);
                if (channel.Read(new WindowsEventQuery(logName, [999], [sourceName], before), 1, includeMessage: false, CancellationToken.None).Count > 0)
                {
                    TestContext.Current.TestOutputHelper?.WriteLine(
                        $"{logName} {stage}: served after {retries} retries, {waited.Elapsed.TotalMilliseconds:F0} ms");
                    return;
                }
            }
            catch (Exception exception) when (NotServedYet(exception))
            {
                unavailable = exception;
            }

            if (waited.Elapsed > TimeSpan.FromSeconds(30))
            {
                throw new TimeoutException($"The event log service did not serve the log {logName} ({stage}) within 30 seconds, {retries} retries.", unavailable);
            }

            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Writes one event, waiting while the service denies writes. After #205 the poll-cost test
    /// still failed in three CI runs with Access is denied from <c>WriteEntry</c>, in the first
    /// batch of writes after <c>Clear</c>, a few milliseconds after the log was served (#198).
    /// The likely cause is that <c>Clear</c> returns before the service has reopened the log; that
    /// is inferred from the logs, not reproduced. A denied write records nothing (the poll-cost
    /// test's exact count of 20,200 would show a duplicate). The handles are closed before each
    /// retry, so a refused one is never reused. Retries go to the test output.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void WriteEntry(EventLog log, string message, EventLogEntryType type, int eventId)
    {
        Stopwatch waited = Stopwatch.StartNew();
        for (int retries = 0; ; retries++)
        {
            try
            {
                log.WriteEntry(message, type, eventId);
                if (retries > 0)
                {
                    TestContext.Current.TestOutputHelper?.WriteLine(
                        $"{log.Log} write: accepted after {retries} retries, {waited.Elapsed.TotalMilliseconds:F0} ms");
                }

                return;
            }
            catch (Exception exception) when (NotServedYet(exception) && waited.Elapsed < TimeSpan.FromSeconds(30))
            {
                log.Close();
                Thread.Sleep(100);
            }
        }
    }

    private static bool NotServedYet(Exception exception) => exception switch
    {
        Win32Exception { NativeErrorCode: 5 } => true,
        // OpenForRead keeps only the Win32 message: "Cannot open log ... Access is denied."
        // OpenForWrite (RegisterEventSource) keeps it as the inner exception instead.
        InvalidOperationException => exception.Message.EndsWith(new Win32Exception(5).Message, StringComparison.Ordinal)
            || exception.InnerException is Win32Exception { NativeErrorCode: 5 },
        WindowsEventChannelException { Code: WindowsEventChannelFailures.AccessDenied or WindowsEventChannelFailures.ChannelNotFound } => true,
        _ => false
    };

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
