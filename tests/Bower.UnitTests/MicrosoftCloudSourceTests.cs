using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Source.MicrosoftCloud;

namespace Bower.UnitTests;

/// <summary>
/// The Microsoft cloud pull source against a fake Graph: bounded records, durable window and
/// snapshot cursors, backpressure, crash recovery, retry and the token host allow-list.
/// Fixtures are synthetic (tests/fixtures/microsoft-cloud). No live tenant calls.
/// </summary>
public sealed class MicrosoftCloudSourceTests
{
    private const string Tenant = "a1b2c3d4-0000-4000-8000-00000000aaaa";
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task AuditWindow_PagesRecordsAndCommitsTheWindowWithoutModifiedValues()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        MemorySink sink = new();
        FileTailSourceTests.MemoryCursors cursors = new();
        MicrosoftCloudSource source = Source(graph, sink, cursors, Audit());

        MicrosoftCloudPollResult result = await source.PollOnceAsync("intune-audit", cancellation);

        Assert.False(result.Backpressure);
        Assert.Equal(2, sink.Records.Count);
        Assert.All(sink.Records, record => Assert.DoesNotContain("secret-", record, StringComparison.Ordinal));
        using JsonDocument wipe = JsonDocument.Parse(sink.Records[0]);
        JsonElement root = wipe.RootElement;
        Assert.StartsWith("mscloud-", root.GetProperty("id").GetString(), StringComparison.Ordinal);
        Assert.Equal("Wipe ManagedDevice", root.GetProperty("activity").GetString());
        Assert.Equal("WipeKeepEnrollmentData", root.GetProperty("modifiedProperties").GetString());
        Assert.Equal("203.0.113.40", root.GetProperty("actorIpAddress").GetString());
        Assert.Equal("1", root.GetProperty("resourceCount").GetString());
        using JsonDocument role = JsonDocument.Parse(sink.Records[1]);
        Assert.Equal("Members,ScopeTags", role.RootElement.GetProperty("modifiedProperties").GetString());

        // The second page's third item had no time: out of scope, never a record.
        MicrosoftCloudInputStatus status = Assert.Single(source.Snapshot());
        Assert.Equal(2, status.Pages);
        Assert.Equal(3, status.Items);
        Assert.Equal(1, status.OutOfScope);
        Assert.Equal(2, status.Queued);
        MicrosoftCloudCursor cursor = MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!;
        Assert.Equal(Now - TimeSpan.FromSeconds(300), cursor.Committed);
        Assert.Null(cursor.WindowStart);
        Assert.Null(cursor.Page);

        // The first request filtered the window; the bearer token went only to Graph.
        Uri first = graph.Requests[0];
        string filter = Uri.UnescapeDataString(first.Query);
        Assert.Contains("activityDateTime ge 2026-11-21T10:00:00Z and activityDateTime lt 2026-11-22T09:55:00Z", filter, StringComparison.Ordinal);
        Assert.All(graph.Requests, uri => Assert.Equal("graph.microsoft.com", uri.Host));
    }

    [Fact]
    public async Task NextPoll_StartsOneOverlapBeforeTheCommittedBoundAndWaitsForTheSettleDelay()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        FakeClock clock = new(Now);
        FileTailSourceTests.MemoryCursors cursors = new();
        MicrosoftCloudSource source = Source(graph, new MemorySink(), cursors, Audit(), clock);
        await source.PollOnceAsync("intune-audit", cancellation);

        // Caught up: nothing to read until the settled bound passes the committed one.
        MicrosoftCloudPollResult idle = await source.PollOnceAsync("intune-audit", cancellation);
        Assert.Equal(0, idle.Records);
        Assert.Equal("idle", Assert.Single(source.Snapshot()).State);
        Assert.Equal(2, graph.Requests.Count);

        clock.Advance(TimeSpan.FromMinutes(15));
        graph.Respond(_ => true, """{"value":[]}""");
        await source.PollOnceAsync("intune-audit", cancellation);
        string filter = Uri.UnescapeDataString(graph.Requests[^1].Query);
        // Committed 09:55; overlap 600 s gives 09:45; settle 300 s gives 10:10.
        Assert.Contains("activityDateTime ge 2026-11-22T09:45:00Z and activityDateTime lt 2026-11-22T10:10:00Z", filter, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OverlapReRead_GivesTheSameEventIds()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        MemorySink first = new();
        await Source(graph, first, new FileTailSourceTests.MemoryCursors(), Audit()).PollOnceAsync("intune-audit", cancellation);
        FakeGraph again = new();
        again.AuditPages(Now);
        MemorySink second = new();

        await Source(again, second, new FileTailSourceTests.MemoryCursors(), Audit()).PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(first.Records.Select(Id), second.Records.Select(Id));
        Assert.Equal(2, first.Records.Select(Id).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task Backpressure_KeepsThePageAndTheNextPollReadsItAgain()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        MemorySink sink = new() { RefuseAfter = 1 };
        FileTailSourceTests.MemoryCursors cursors = new();
        MicrosoftCloudSource source = Source(graph, sink, cursors, Audit());

        MicrosoftCloudPollResult refused = await source.PollOnceAsync("intune-audit", cancellation);

        Assert.True(refused.Backpressure);
        Assert.Equal("backpressure", Assert.Single(source.Snapshot()).State);
        // Page 1 (one record) completed and was committed; page 2 was refused and is kept.
        MicrosoftCloudCursor open = MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!;
        Assert.NotNull(open.WindowStart);
        Assert.Contains("skiptoken=page2", open.Page, StringComparison.Ordinal);
        Assert.Null(open.Committed);
        Assert.Single(sink.Records);

        sink.RefuseAfter = null;
        await source.PollOnceAsync("intune-audit", cancellation);

        // Page 2 was read again from its stored link; page 1 was not re-read and nothing was lost.
        Assert.Equal(2, sink.Records.Count);
        Assert.Equal(2, graph.Requests.Count(uri => uri.Query.Contains("skiptoken=page2", StringComparison.Ordinal)));
        Assert.NotNull(MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!.Committed);
    }

    [Fact]
    public async Task BackpressureOnTheFirstRecord_StoresTheOpenWindowAndReReadsTheSamePage()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        MemorySink sink = new() { RefuseAfter = 0 };
        FileTailSourceTests.MemoryCursors cursors = new();
        FakeClock clock = new(Now);
        MicrosoftCloudSource source = Source(graph, sink, cursors, Audit(), clock);

        Assert.True((await source.PollOnceAsync("intune-audit", cancellation)).Backpressure);
        MicrosoftCloudCursor open = MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!;
        Assert.Null(open.Page);
        Assert.Empty(sink.Records);

        // Later polls keep the stored window even though the clock moved on.
        clock.Advance(TimeSpan.FromMinutes(30));
        sink.RefuseAfter = null;
        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(2, sink.Records.Count);
        Uri[] firstPages = [.. graph.Requests.Where(uri => !uri.Query.Contains("skiptoken", StringComparison.Ordinal))];
        Assert.Equal(2, firstPages.Length);
        Assert.Equal(firstPages[0], firstPages[1]);
    }

    [Fact]
    public async Task CrashBeforePageCommit_ReReadsOnlyThatPageAfterRestart()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        FileTailSourceTests.MemoryCursors durable = new();
        MemorySink sink = new();
        // Commits: open window (1), page 1 (2); the page 2 commit fails as a crash would.
        CrashingCursors crashing = new(durable, failOnCommit: 3);
        MicrosoftCloudSource first = Source(graph, sink, crashing, Audit());
        await Assert.ThrowsAsync<IOException>(() => first.PollOnceAsync("intune-audit", cancellation));
        MicrosoftCloudCursor afterCrash = MicrosoftCloudCursor.Deserialize(durable.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!;
        Assert.Contains("skiptoken=page2", afterCrash.Page, StringComparison.Ordinal);

        MicrosoftCloudSource restarted = Source(graph, sink, durable, Audit());
        await restarted.PollOnceAsync("intune-audit", cancellation);

        // Page 2 was read twice (before and after the crash); page 1 was never read again.
        Assert.Equal(3, sink.Records.Count);
        Assert.Equal(sink.Records[1], sink.Records[2]);
        Assert.Equal(2, graph.Requests.Count(uri => uri.Query.Contains("skiptoken=page2", StringComparison.Ordinal)));
        Assert.Equal(1, graph.Requests.Count(uri => uri.AbsolutePath.EndsWith("/auditEvents", StringComparison.Ordinal) && !uri.Query.Contains("skiptoken", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ExpiredPageLink_RestartsTheWindowFromItsFirstPage()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        FileTailSourceTests.MemoryCursors cursors = new();
        MemorySink sink = new();
        await cursors.TryAdvanceAsync(
            "mscloud:intune-audit",
            0,
            new MicrosoftCloudCursor(1, MicrosoftCloudKinds.IntuneAudit, null, Now.AddHours(-2), Now.AddHours(-1),
                "https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?$skiptoken=expired").Serialize(),
            Now,
            cancellation);
        graph.Respond(uri => uri.Query.Contains("expired", StringComparison.Ordinal), "{}", HttpStatusCode.BadRequest, first: true);

        MicrosoftCloudSource source = Source(graph, sink, cursors, Audit());
        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(2, sink.Records.Count);
        Assert.Equal(1, Assert.Single(source.Snapshot()).PageRestarts);
    }

    [Fact]
    public async Task ComplianceSnapshot_KeepsOnlyAttentionStatesAndRunsOncePerDay()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(uri => uri.AbsolutePath.EndsWith("/managedDevices", StringComparison.Ordinal), Fixture("intune-managed-devices.json", Now));
        FakeClock clock = new(Now);
        MemorySink sink = new();
        FileTailSourceTests.MemoryCursors cursors = new();
        MicrosoftCloudSource source = Source(graph, sink, cursors, Compliance(), clock);

        await source.PollOnceAsync("intune-compliance", cancellation);

        Assert.Equal(2, sink.Records.Count);
        Assert.DoesNotContain(sink.Records, record => record.Contains("ADELE-PHONE", StringComparison.Ordinal));
        using JsonDocument device = JsonDocument.Parse(sink.Records[0]);
        Assert.Equal("2026-11-22", device.RootElement.GetProperty("snapshotDate").GetString());
        Assert.Equal("false", device.RootElement.GetProperty("isEncrypted").GetString());
        Assert.Equal(1, Assert.Single(source.Snapshot()).OutOfScope);
        string select = Uri.UnescapeDataString(graph.Requests[0].Query);
        Assert.Contains("$select=id,complianceState", select, StringComparison.Ordinal);
        Assert.DoesNotContain("deviceName", select, StringComparison.Ordinal);
        Assert.DoesNotContain("imei", select, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("serialNumber", select, StringComparison.Ordinal);
        Assert.DoesNotContain("phoneNumber", select, StringComparison.Ordinal);

        clock.Advance(TimeSpan.FromHours(6));
        await source.PollOnceAsync("intune-compliance", cancellation);
        Assert.Single(graph.Requests);

        clock.Advance(TimeSpan.FromHours(10));
        await source.PollOnceAsync("intune-compliance", cancellation);
        Assert.Equal(2, graph.Requests.Count);
        using JsonDocument nextDay = JsonDocument.Parse(sink.Records[^1]);
        Assert.Equal("2026-11-23", nextDay.RootElement.GetProperty("snapshotDate").GetString());
        // A new day is a new event for the same device.
        Assert.NotEqual(Id(sink.Records[0]), Id(sink.Records[2]));
    }

    [Fact]
    public async Task Throttling_HonoursRetryAfterThenSucceeds()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        graph.Respond(_ => true, "{}", HttpStatusCode.TooManyRequests, first: true, retryAfterSeconds: 7);
        ManualTimeProvider clock = new(Now);
        MemorySink sink = new();
        MicrosoftCloudSource source = Source(graph, sink, new FileTailSourceTests.MemoryCursors(), Audit(), clock);

        Task<MicrosoftCloudPollResult> poll = source.PollOnceAsync("intune-audit", cancellation);
        await Polling.UntilAsync(() => clock.ActiveTimers > 0, cancellation);
        clock.Advance(TimeSpan.FromSeconds(6));
        Assert.False(poll.IsCompleted);
        clock.Advance(TimeSpan.FromSeconds(1));
        await poll;

        Assert.Equal(2, sink.Records.Count);
        MicrosoftCloudInputStatus status = Assert.Single(source.Snapshot());
        Assert.Equal(1, status.Throttled);
        Assert.Equal(1, status.Retries);
    }

    [Fact]
    public async Task Forbidden_FailsAtOnceWithThePermissionCodeAndNoRetry()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, """{"error":{"code":"Forbidden","message":"secret-body-marker"}}""", HttpStatusCode.Forbidden);
        FileTailSourceTests.MemoryCursors cursors = new();
        MicrosoftCloudSource source = Source(graph, new MemorySink(), cursors, Audit());

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.PermissionDenied, failure.Code);
        Assert.DoesNotContain("secret-body-marker", failure.Message, StringComparison.Ordinal);
        Assert.Single(graph.Requests);
        Assert.Equal(MicrosoftCloudFailures.PermissionDenied, Assert.Single(source.Snapshot()).State);
        Assert.Null(MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!.Committed);
    }

    [Fact]
    public async Task Unauthorised_RefreshesTheTokenOnce()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        graph.Respond(_ => true, "{}", HttpStatusCode.Unauthorized, first: true);
        FakeTokens tokens = new();
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Audit(), tokens: tokens);

        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(1, tokens.Refreshes);
    }

    [Theory]
    [InlineData("https://evil.example/v1.0/deviceManagement/auditEvents?$skiptoken=x")]
    [InlineData("http://graph.microsoft.com/v1.0/deviceManagement/auditEvents?$skiptoken=x")]
    [InlineData("https://graph.microsoft.com:8443/v1.0/deviceManagement/auditEvents?$skiptoken=x")]
    [InlineData("https://user@graph.microsoft.com/v1.0/deviceManagement/auditEvents?$skiptoken=x")]
    public async Task NextLinkOffTheAllowedHost_IsRefusedAndNoTokenIsSent(string link)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, JsonSerializer.Serialize(new Dictionary<string, object> { ["value"] = Array.Empty<object>(), ["@odata.nextLink"] = link }));
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Audit());

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.HostRefused, failure.Code);
        Assert.Single(graph.Requests);
        Assert.All(graph.Requests, uri => Assert.Equal("graph.microsoft.com", uri.Host));
    }

    [Theory]
    [InlineData("""{"value":{}}""")]
    [InlineData("""{"nothing":[]}""")]
    [InlineData("""not json""")]
    [InlineData("""{"value":[],"@odata.nextLink":42}""")]
    public async Task MalformedResponse_FailsWithoutMovingTheCursor(string body)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, body);
        FileTailSourceTests.MemoryCursors cursors = new();
        MicrosoftCloudSource source = Source(graph, new MemorySink(), cursors, Audit());

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.ResponseInvalid, failure.Code);
        Assert.Null(MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!.Committed);
    }

    [Fact]
    public async Task OversizedResponse_IsRefused()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, "{\"value\":[\"" + new string('a', 4_096) + "\"]}");
        MicrosoftCloudHttp http = new(new HttpClient(graph), new FakeTokens(), TimeProvider.System) { MaximumResponseBytes = 1_024 };
        MicrosoftCloudSource source = new(Configuration(Audit()), new MemorySink(), new FileTailSourceTests.MemoryCursors(), http, new FakeClock(Now));

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.ResponseTooLarge, failure.Code);
    }

    [Fact]
    public async Task Redirect_IsRefused()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, "{}", HttpStatusCode.Found);
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Audit());

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.RedirectRefused, failure.Code);
    }

    [Theory]
    [InlineData("""{"schemaVersion":2,"sourceKind":"intune-audit"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-device-compliance"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-audit","windowStart":"2026-11-22T00:00:00Z"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-audit","page":"https://graph.microsoft.com/x"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-audit","unknown":true}""")]
    [InlineData("""not json""")]
    public async Task DamagedCursor_FailsClosed(string value)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        FileTailSourceTests.MemoryCursors cursors = new();
        await cursors.TryAdvanceAsync("mscloud:intune-audit", 0, value, Now, cancellation);

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => Source(graph, new MemorySink(), cursors, Audit()).PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.CursorInvalid, failure.Code);
        Assert.Empty(graph.Requests);
    }

    [Fact]
    public async Task StoppedLongerThanTheApiKeeps_StartsAtTheFloorAndCountsOneGap()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, """{"value":[]}""");
        FileTailSourceTests.MemoryCursors cursors = new();
        await cursors.TryAdvanceAsync(
            "mscloud:intune-audit", 0,
            new MicrosoftCloudCursor(1, MicrosoftCloudKinds.IntuneAudit, Now.AddDays(-30)).Serialize(), Now, cancellation);
        MicrosoftCloudSource source = Source(graph, new MemorySink(), cursors, Audit());

        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(1, Assert.Single(source.Snapshot()).Gaps);
        Assert.Contains("activityDateTime ge 2026-11-15T10:00:00Z", Uri.UnescapeDataString(graph.Requests[0].Query), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CursorConflict_IsReportedAndNothingIsCommittedOverTheOtherWriter()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        FileTailSourceTests.MemoryCursors cursors = new();
        RacingCursors racing = new(cursors);

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => Source(graph, new MemorySink(), racing, Audit()).PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.CursorConflict, failure.Code);
        Assert.Equal("other-writer", cursors.Value("mscloud:intune-audit"));
    }

    [Fact]
    public async Task Cancellation_StopsThePollWithoutCommitting()
    {
        FakeGraph graph = new();
        graph.AuditPages(Now);
        FileTailSourceTests.MemoryCursors cursors = new();
        using CancellationTokenSource stop = new();
        MemorySink sink = new() { OnSubmit = stop.Cancel };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Source(graph, sink, cursors, Audit()).PollOnceAsync("intune-audit", stop.Token));

        MicrosoftCloudCursor cursor = MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!;
        Assert.Null(cursor.Committed);
        Assert.Null(cursor.Page);
    }

    [Theory]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[]}""", "1 to 16 inputs")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"Other","inputs":[]}""", "kind MicrosoftCloudSource")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"all","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0}}]}""", "sourceKind must be one of")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"common","route":{"pack":"p","parser":0}}]}""", "tenantId must be a lowercase GUID")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"X","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0}}]}""", "input id must be")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0},"clientSecret":"s"}]}""", "configuration is invalid")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0},"credential":{"clientId":"b1b2c3d4-0000-4000-8000-00000000bbbb","certificatePath":"cert.pem"}}]}""", "absolute path")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0},"complianceStates":["noncompliant"]}]}""", "intune-device-compliance only")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-device-compliance","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0},"complianceStates":["everything"]}]}""", "complianceStates must list")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0},"overlapSeconds":86400}]}""", "overlapSeconds must be between 0 and 43200")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-device-compliance","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0},"complianceStates":["compliant"]}]}""", "complianceStates must list")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","pollIntervalSeconds":5,"inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0}}]}""", "pollIntervalSeconds")]
    [InlineData("""{"apiVersion":"bower.security/v1","kind":"MicrosoftCloudSource","inputs":[{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0}},{"id":"x","sourceKind":"intune-audit","tenantId":"a1b2c3d4-0000-4000-8000-00000000aaaa","route":{"pack":"p","parser":0}}]}""", "more than once")]
    public void Configuration_RefusesUnsafeOrUnknownShapes(string json, string message)
    {
        InvalidDataException failure = Assert.Throws<InvalidDataException>(() => MicrosoftCloudSourceConfigurationLoader.Parse(json));
        Assert.Contains(message, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Backoff_IsCappedFullJitter()
    {
        MicrosoftCloudHttp http = new(new HttpClient(new FakeGraph()), new FakeTokens(), TimeProvider.System, () => 1.0);
        Assert.Equal(TimeSpan.FromSeconds(1), http.Backoff(1));
        Assert.Equal(TimeSpan.FromSeconds(8), http.Backoff(4));
        Assert.Equal(TimeSpan.FromSeconds(60), http.Backoff(12));
        MicrosoftCloudHttp none = new(new HttpClient(new FakeGraph()), new FakeTokens(), TimeProvider.System, () => 0.0);
        Assert.Equal(TimeSpan.Zero, none.Backoff(5));
    }

    [Fact]
    public async Task ExpiredPageLinkTwiceInOnePoll_FailsInsteadOfSpinning()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        // Page 2 is always refused: one restart, then the poll fails and the loop backs off.
        graph.Respond(uri => uri.Query.Contains("skiptoken=page2", StringComparison.Ordinal), "{}", HttpStatusCode.BadRequest);
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Audit());

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.RequestRefused, failure.Code);
        Assert.Equal(1, Assert.Single(source.Snapshot()).PageRestarts);
        Assert.Equal(2, graph.Requests.Count(uri => uri.Query.Contains("skiptoken=page2", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task CyclicNextLink_FailsThePollWithoutSpinning()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        const string Loop = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=loop";
        graph.Respond(_ => true, JsonSerializer.Serialize(new Dictionary<string, object> { ["value"] = Array.Empty<object>(), ["@odata.nextLink"] = Loop }));
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Compliance());

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => source.PollOnceAsync("intune-compliance", cancellation));

        Assert.Equal(MicrosoftCloudFailures.ResponseInvalid, failure.Code);
        Assert.Equal(2, graph.Requests.Count);
    }

    [Fact]
    public async Task PagesWithNothingInScope_StillYieldAfterThePageCap()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        int page = 0;
        graph.Respond(_ => true, string.Empty);
        FakeGraph.Dynamic = _ => JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["value"] = new[] { new Dictionary<string, object> { ["id"] = "d", ["complianceState"] = "compliant" } },
            ["@odata.nextLink"] = $"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken={Interlocked.Increment(ref page)}"
        });
        try
        {
            MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Compliance());

            MicrosoftCloudPollResult result = await source.PollOnceAsync("intune-compliance", cancellation);

            Assert.True(result.More);
            Assert.Equal(MicrosoftCloudSource.MaximumPagesPerPoll, graph.Requests.Count);
            Assert.Equal(MicrosoftCloudSource.MaximumPagesPerPoll, Assert.Single(source.Snapshot()).OutOfScope);
        }
        finally
        {
            FakeGraph.Dynamic = null;
        }
    }

    [Fact]
    public async Task OffHostNextLink_IsNeverCommittedToTheCursor()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, Fixture("intune-audit-page1.json", Now).Replace(
            "https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?$filter=x&$skiptoken=page2",
            "https://evil.example/v1.0/deviceManagement/auditEvents?$skiptoken=page2", StringComparison.Ordinal));
        MemorySink sink = new();
        FileTailSourceTests.MemoryCursors cursors = new();

        MicrosoftCloudException failure = await Assert.ThrowsAsync<MicrosoftCloudException>(
            () => Source(graph, sink, cursors, Audit()).PollOnceAsync("intune-audit", cancellation));

        Assert.Equal(MicrosoftCloudFailures.HostRefused, failure.Code);
        Assert.Empty(sink.Records);
        MicrosoftCloudCursor cursor = MicrosoftCloudCursor.Deserialize(cursors.Value("mscloud:intune-audit")!, MicrosoftCloudKinds.IntuneAudit)!;
        Assert.Null(cursor.Page);
        Assert.DoesNotContain("evil.example", cursors.Value("mscloud:intune-audit")!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BodyFailingInTransit_IsRetried()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        graph.FailBodyOnce = true;
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Audit());

        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(1, Assert.Single(source.Snapshot()).Retries);
    }

    [Fact]
    public async Task UnauthorisedThenThrottled_RefreshesTheTokenExactlyOnce()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        graph.Respond(_ => true, "{}", HttpStatusCode.ServiceUnavailable, first: true);
        graph.Respond(_ => true, "{}", HttpStatusCode.ServiceUnavailable, first: true);
        graph.Respond(_ => true, "{}", HttpStatusCode.Unauthorized, first: true);
        FakeTokens tokens = new();
        MicrosoftCloudSource source = Source(graph, new MemorySink(), new FileTailSourceTests.MemoryCursors(), Audit(), tokens: tokens);

        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(1, tokens.Refreshes);
    }

    [Fact]
    public async Task RetryAfterZero_FallsBackToBackoff()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.AuditPages(Now);
        graph.Respond(_ => true, "{}", HttpStatusCode.TooManyRequests, first: true, retryAfterSeconds: 0);
        ManualTimeProvider clock = new(Now);
        MicrosoftCloudHttp http = new(new HttpClient(graph), new FakeTokens(), clock, () => 1.0);
        MicrosoftCloudSource source = new(Configuration(Audit()), new MemorySink(), new FileTailSourceTests.MemoryCursors(), http, clock);

        Task<MicrosoftCloudPollResult> poll = source.PollOnceAsync("intune-audit", cancellation);
        await Polling.UntilAsync(() => clock.ActiveTimers > 0, cancellation);
        Assert.False(poll.IsCompleted);
        clock.Advance(TimeSpan.FromSeconds(1));
        await poll;
    }

    [Theory]
    [InlineData("203.0.113.40:51234", "203.0.113.40")]
    [InlineData("[2001:db8::40]:443", "2001:db8::40")]
    [InlineData("2001:db8::40", "2001:db8::40")]
    [InlineData("010.0.0.1", null)]
    [InlineData("1.2.3.4.5", null)]
    [InlineData("dead", null)]
    [InlineData("fe80::1%eth0", null)]
    public void Address_IsCanonicalOrAbsentNeverAnEventBreaker(string input, string? expected)
    {
        Assert.Equal(expected, MicrosoftCloudRecord.Address(input));
    }

    [Fact]
    public void Record_StaysBelowThePackLimitWithEscapedValues()
    {
        static string Wide()
        {
            MicrosoftCloudRecord record = new(Audit());
            string wide = new('\u00e9', 5_000);
            for (int index = 0; index < 30; index++)
            {
                record.Add("field" + index, wide);
            }

            return record.Build("x");
        }

        string json = Wide();

        Assert.True(Encoding.UTF8.GetByteCount(json) < Bower.Packs.PackRuntime.MaximumRecordBytes);
        // Clipping depends only on the input, so a re-read gives the same record and id.
        Assert.Equal(json, Wide());
    }

    [Fact]
    public void ActionValues_AreClippedToTheEnvelopeLimit()
    {
        FakeGraph graph = new();
        string body = Fixture("intune-audit-page2.json", Now).Replace("\"Patch RoleAssignment\"", "\"" + new string('x', 400) + "\"", StringComparison.Ordinal);
        using MicrosoftCloudResponse response = new(JsonDocument.Parse(body), null);

        MicrosoftCloudPage page = new IntuneAuditReader().Read(Audit(), new MicrosoftCloudSpan(Now.AddHours(-1), Now), response);

        using JsonDocument record = JsonDocument.Parse(page.Records[0]);
        Assert.Equal(128, record.RootElement.GetProperty("activity").GetString()!.Length);
    }

    [Fact]
    public async Task OverlapNearTheFloor_IsNotAGap()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, """{"value":[]}""");
        FileTailSourceTests.MemoryCursors cursors = new();
        await cursors.TryAdvanceAsync(
            "mscloud:intune-audit", 0,
            new MicrosoftCloudCursor(1, MicrosoftCloudKinds.IntuneAudit, Now.AddDays(-7).AddMinutes(5)).Serialize(), Now, cancellation);
        MicrosoftCloudSource source = Source(graph, new MemorySink(), cursors, Audit());

        await source.PollOnceAsync("intune-audit", cancellation);

        Assert.Equal(0, Assert.Single(source.Snapshot()).Gaps);
    }

    [Fact]
    public async Task ClockSteppedBackAcrossMidnight_DoesNotReRunACompletedSnapshot()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        FakeGraph graph = new();
        graph.Respond(_ => true, """{"value":[]}""");
        FileTailSourceTests.MemoryCursors cursors = new();
        await cursors.TryAdvanceAsync(
            "mscloud:intune-compliance", 0,
            new MicrosoftCloudCursor(1, MicrosoftCloudKinds.IntuneDeviceCompliance, CompletedDate: "2026-11-23").Serialize(), Now, cancellation);
        MicrosoftCloudSource source = Source(graph, new MemorySink(), cursors, Compliance());

        await source.PollOnceAsync("intune-compliance", cancellation);

        Assert.Empty(graph.Requests);
    }

    [Fact]
    public void ComplianceSnapshot_NeverRequestsTheDeviceName()
    {
        Assert.DoesNotContain("deviceName", IntuneComplianceReader.Select, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-audit","windowStart":"2026-11-22T00:00:00Z","windowEnd":"2026-11-22T01:00:00Z","page":"not a uri"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-audit","completedDate":"2026-11-22"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-device-compliance","committed":"2026-11-22T00:00:00Z"}""")]
    [InlineData("""{"schemaVersion":1,"sourceKind":"intune-device-compliance","completedDate":"22/11/2026"}""")]
    public void MixedOrMalformedCursorFields_AreRefused(string value)
    {
        string kind = value.Contains("compliance", StringComparison.Ordinal) ? MicrosoftCloudKinds.IntuneDeviceCompliance : MicrosoftCloudKinds.IntuneAudit;
        Assert.Null(MicrosoftCloudCursor.Deserialize(value, kind));
    }

    internal static MicrosoftCloudInputOptions Audit() =>
        new("intune-audit", MicrosoftCloudKinds.IntuneAudit, Tenant, new MicrosoftCloudRoute("microsoft-intune", 0));

    internal static MicrosoftCloudInputOptions Compliance() =>
        new("intune-compliance", MicrosoftCloudKinds.IntuneDeviceCompliance, Tenant, new MicrosoftCloudRoute("microsoft-intune", 1));

    internal static MicrosoftCloudSourceConfiguration Configuration(params MicrosoftCloudInputOptions[] inputs) =>
        new("bower.security/v1", "MicrosoftCloudSource", inputs, 300);

    internal static string Fixture(string name, DateTimeOffset now) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "microsoft-cloud", name))
            .Replace("{{start}}", Format(now.AddHours(-20)), StringComparison.Ordinal)
            .Replace("{{mid}}", Format(now.AddHours(-2)), StringComparison.Ordinal)
            .Replace("{{end}}", Format(now.AddMinutes(-10)), StringComparison.Ordinal);

    private static string Format(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static string Id(string record)
    {
        using JsonDocument document = JsonDocument.Parse(record);
        return document.RootElement.GetProperty("id").GetString()!;
    }

    private static MicrosoftCloudSource Source(
        FakeGraph graph,
        IMicrosoftCloudSink sink,
        ISourceCursorStore cursors,
        MicrosoftCloudInputOptions input,
        TimeProvider? clock = null,
        FakeTokens? tokens = null)
    {
        clock ??= new FakeClock(Now);
        MicrosoftCloudHttp http = new(new HttpClient(graph), tokens ?? new FakeTokens(), clock, () => 0.0);
        return new MicrosoftCloudSource(Configuration(input), sink, cursors, http, clock);
    }

    internal sealed class MemorySink : IMicrosoftCloudSink
    {
        public List<string> Records { get; } = [];

        public int? RefuseAfter { get; set; }

        public Action? OnSubmit { get; set; }

        public ValueTask<MicrosoftCloudSubmitOutcome> SubmitAsync(MicrosoftCloudInputOptions input, string record, CancellationToken cancellationToken)
        {
            OnSubmit?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            if (RefuseAfter is { } limit && Records.Count >= limit)
            {
                return ValueTask.FromResult(MicrosoftCloudSubmitOutcome.Unavailable);
            }

            Records.Add(record);
            return ValueTask.FromResult(MicrosoftCloudSubmitOutcome.Queued);
        }
    }

    internal sealed class FakeTokens : IMicrosoftCloudTokenProvider
    {
        public int Refreshes;

        public ValueTask<string> GetTokenAsync(MicrosoftCloudInputOptions input, string scope, bool forceRefresh, CancellationToken cancellationToken)
        {
            if (forceRefresh)
            {
                Interlocked.Increment(ref Refreshes);
            }

            return ValueTask.FromResult("fake-access-token");
        }
    }

    /// <summary>Answers by predicate, newest rule first; one-shot rules answer once. Records every URI.</summary>
    internal sealed class FakeGraph : HttpMessageHandler
    {
        private readonly List<Rule> rules = [];

        public ConcurrentQueue<Uri> RequestLog { get; } = new();

        public List<Uri> Requests => [.. RequestLog];

        public void Respond(Func<Uri, bool> match, string body, HttpStatusCode status = HttpStatusCode.OK, bool first = false, int? retryAfterSeconds = null)
        {
            lock (rules)
            {
                rules.Insert(0, new Rule(match, body, status, first, retryAfterSeconds));
            }
        }

        public void AuditPages(DateTimeOffset now)
        {
            Respond(uri => uri.AbsolutePath.EndsWith("/auditEvents", StringComparison.Ordinal), Fixture("intune-audit-page1.json", now));
            Respond(uri => uri.Query.Contains("skiptoken=page2", StringComparison.Ordinal), Fixture("intune-audit-page2.json", now));
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Uri uri = request.RequestUri!;
            RequestLog.Enqueue(uri);
            Rule rule;
            lock (rules)
            {
                rule = rules.FirstOrDefault(item => item.Match(uri))
                    ?? throw new InvalidOperationException("No fake response for " + uri.AbsolutePath);
                if (rule.Once)
                {
                    rules.Remove(rule);
                }
            }

            string body = Dynamic is { } dynamic && rule.Body.Length == 0 ? dynamic(uri) : rule.Body;
            HttpContent content = FailBodyOnce && rule.Status == HttpStatusCode.OK
                ? new FailingContent()
                : new StringContent(body, Encoding.UTF8, "application/json");
            if (content is FailingContent)
            {
                FailBodyOnce = false;
            }

            HttpResponseMessage response = new(rule.Status) { Content = content };
            if (rule.RetryAfterSeconds is { } seconds)
            {
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));
            }

            return Task.FromResult(response);
        }

        /// <summary>Builds the body for rules registered with an empty body (paging tests).</summary>
        public static Func<Uri, string>? Dynamic { get; set; }

        /// <summary>The next successful response's body fails while it is read, as a reset connection would.</summary>
        public bool FailBodyOnce { get; set; }

        private sealed record Rule(Func<Uri, bool> Match, string Body, HttpStatusCode Status, bool Once, int? RetryAfterSeconds);

        private sealed class FailingContent : HttpContent
        {
            protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) =>
                throw new IOException("connection reset");

            protected override Task<Stream> CreateContentReadStreamAsync() =>
                Task.FromResult<Stream>(new FailingStream());

            protected override bool TryComputeLength(out long length)
            {
                length = 0;
                return false;
            }
        }

        private sealed class FailingStream : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => 0; set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => throw new IOException("connection reset");
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
                throw new IOException("connection reset");
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }

    /// <summary>Throws on the Nth commit, as a crash between enqueue and commit would.</summary>
    private sealed class CrashingCursors(ISourceCursorStore inner, int failOnCommit) : ISourceCursorStore
    {
        private int commits;

        public Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(sourceId, cancellationToken);

        public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value, DateTimeOffset updatedAt, CancellationToken cancellationToken = default) =>
            Interlocked.Increment(ref commits) == failOnCommit
                ? throw new IOException("injected crash before commit")
                : inner.TryAdvanceAsync(sourceId, expectedVersion, value, updatedAt, cancellationToken);
    }

    /// <summary>Another writer advances the cursor between this poll's read and its first commit.</summary>
    private sealed class RacingCursors(FileTailSourceTests.MemoryCursors inner) : ISourceCursorStore
    {
        public async Task<SourceCursorSnapshot?> ReadAsync(string sourceId, CancellationToken cancellationToken = default)
        {
            SourceCursorSnapshot? snapshot = await inner.ReadAsync(sourceId, cancellationToken);
            await inner.TryAdvanceAsync(sourceId, snapshot?.Version ?? 0, "other-writer", Now, cancellationToken);
            return snapshot;
        }

        public Task<bool> TryAdvanceAsync(string sourceId, long expectedVersion, string value, DateTimeOffset updatedAt, CancellationToken cancellationToken = default) =>
            inner.TryAdvanceAsync(sourceId, expectedVersion, value, updatedAt, cancellationToken);
    }
}
