using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;

namespace Bower.UnitTests;

/// <summary>
/// Platform-neutral parts of the Windows Event Log source: event XML parsing, the record a
/// pack parser sees, configuration, the generated query, bookmarks and the reader loop
/// (against an in-memory channel). The Windows reader itself is covered by
/// <see cref="WindowsEventLogWindowsTests"/>.
/// </summary>
public sealed class WindowsEventLogSourceTests
{
    private const string Subscription = "app";

    [Fact]
    public void NativeBookmark_UsesReceivingChannelPositionAndEscapesChannel()
    {
        string xml = WindowsNativeBookmark.Create("ForwardedEvents", 17);
        Assert.Equal(17, WindowsNativeBookmark.Position(xml, "ForwardedEvents"));
        Assert.Equal(17, WindowsNativeBookmark.Position(xml, "forwardedevents"));
        Assert.Throws<WindowsEventChannelException>(() => WindowsNativeBookmark.Position(xml, "Security"));
        Assert.Equal(42, WindowsNativeBookmark.Position(WindowsNativeBookmark.Create("a&b", 42), "a&b"));
        WindowsEventQuery query = new("ForwardedEvents", [4625], null, 17);
        Assert.Equal("*[System[(EventID=4625)]]", query.ToXPath(includeRecordPosition: false));
        Assert.Contains("EventRecordID>17", query.ToXPath(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("<BookmarkList><Bookmark Channel='ForwardedEvents' RecordId='-1'/></BookmarkList>")]
    [InlineData("<BookmarkList><Bookmark Channel='ForwardedEvents' RecordId='9223372036854775808'/></BookmarkList>")]
    [InlineData("<BookmarkList/>")]
    [InlineData("<BookmarkList><Bookmark Channel='ForwardedEvents' RecordId='1'/><Bookmark Channel='ForwardedEvents' RecordId='2'/></BookmarkList>")]
    public void NativeBookmark_RejectsInvalidPositions(string xml) =>
        Assert.Throws<WindowsEventChannelException>(() => WindowsNativeBookmark.Position(xml, "ForwardedEvents"));

    [Fact]
    public void Parse_SecurityEvent_ReadsTheSystemHeaderAndNamedEventData()
    {
        WindowsEvent parsed = WindowsEventXml.Parse(WindowsEventFixtures.Read("security-4625.xml"));

        Assert.Equal("Security", parsed.Channel);
        Assert.Equal("Microsoft-Windows-Security-Auditing", parsed.Provider);
        Assert.Equal(4625, parsed.EventId);
        Assert.Equal(184467, parsed.RecordId);
        Assert.Equal("app01.corp.example", parsed.Computer);
        Assert.Equal(new DateTimeOffset(2026, 10, 23, 10, 0, 0, TimeSpan.Zero).AddTicks(1_234_567), parsed.TimeCreated);
        Assert.Equal(
            ["version", "level", "task", "opcode", "keywords", "processId", "threadId", "activityId"],
            parsed.Header.Select(item => item.Key));
        Assert.Equal("0d3a7b52-5d1f-0002-6a7b-3a0d1f5ddb01", parsed.Header.Single(item => item.Key == "activityId").Value);
        Assert.Equal(21, parsed.Data.Count);
        Assert.Equal(new KeyValuePair<string, string>("data.TargetUserName", "deploy-admin"), parsed.Data[5]);
        // Values are kept exactly, including trailing spaces Windows writes.
        Assert.Equal("NtLmSsp ", parsed.Data.Single(item => item.Key == "data.LogonProcessName").Value);
    }

    [Fact]
    public void Parse_ClassicEvent_IndexesUnnamedDataAndIgnoresBinary()
    {
        WindowsEvent parsed = WindowsEventXml.Parse(WindowsEventFixtures.Read("application-classic.xml"));

        Assert.Equal(1000, parsed.EventId);
        Assert.Equal("BowerCiSource", parsed.Provider);
        // Nine fraction digits are truncated to 100 ns.
        Assert.Equal(new DateTimeOffset(2026, 10, 23, 12, 0, 0, 500, TimeSpan.Zero), parsed.TimeCreated);
        Assert.Equal(
            [new("data.0", "order=42 result=failure"), new("data.1", "second value")],
            parsed.Data);
        Assert.DoesNotContain(parsed.Header, item => item.Key is "version" or "opcode" or "processId");
    }

    [Fact]
    public void Parse_UserData_FlattensLeafValuesOnly()
    {
        WindowsEvent parsed = WindowsEventXml.Parse(WindowsEventFixtures.Read("security-1102-userdata.xml"));

        Assert.Equal(1102, parsed.EventId);
        Assert.Equal("S-1-5-21-1111111111-2222222222-3333333333-500", parsed.Header.Single(item => item.Key == "userSid").Value);
        Assert.Equal(
            ["userData.SubjectUserSid", "userData.SubjectUserName", "userData.SubjectDomainName", "userData.SubjectLogonId"],
            parsed.Data.Select(item => item.Key));
    }

    public static TheoryData<string, string> MalformedEvents()
    {
        string valid = WindowsEventFixtures.Event(5, 1000);
        return new TheoryData<string, string>
        {
            { "", WindowsEventFailures.XmlInvalid },
            { "<Event", WindowsEventFailures.XmlInvalid },
            { "not xml at all", WindowsEventFailures.XmlInvalid },
            // Entity expansion and external entities are refused before anything is read.
            { "<!DOCTYPE Event [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]>" + valid.Replace("BowerTest", "&b;", StringComparison.Ordinal), WindowsEventFailures.XmlInvalid },
            { "<!DOCTYPE Event [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" + valid.Replace("host01", "&x;", StringComparison.Ordinal), WindowsEventFailures.XmlInvalid },
            { valid.Replace("http://schemas.microsoft.com/win/2004/08/events/event", "urn:other", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData/></Event>", WindowsEventFailures.SystemInvalid },
            { valid.Replace("<EventID>1000</EventID>", "", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<EventID>1000</EventID>", "<EventID>70000</EventID>", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<EventID>1000</EventID>", "<EventID> 1000</EventID>", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<EventRecordID>5</EventRecordID>", "<EventRecordID>0</EventRecordID>", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<EventRecordID>5</EventRecordID>", "<EventRecordID>-5</EventRecordID>", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<Channel>Application</Channel>", "", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<Computer>host01</Computer>", "<Computer> </Computer>", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { valid.Replace("<Provider Name='BowerTest'/>", "<Provider/>", StringComparison.Ordinal), WindowsEventFailures.SystemInvalid },
            { WindowsEventFixtures.Event(5, 1000, time: "2026-10-23 10:00:00Z"), WindowsEventFailures.SystemInvalid },
            { WindowsEventFixtures.Event(5, 1000, time: "2026-10-23T10:00:00+10:00"), WindowsEventFailures.SystemInvalid },
            { WindowsEventFixtures.Event(5, 1000, time: "2026-10-23T10:00:00.1234567890Z"), WindowsEventFailures.SystemInvalid },
            { WindowsEventFixtures.Event(5, 1000, data: [("blob", new string('x', WindowsEventXml.MaximumXmlCharacters))]), WindowsEventFailures.XmlTooLarge },
            { WindowsEventFixtures.Event(5, 1000, data: [.. Enumerable.Range(0, 129).Select(index => ($"f{index}", "v"))]), WindowsEventFailures.RecordTooLarge }
        };
    }

    [Theory]
    [MemberData(nameof(MalformedEvents))]
    public void Parse_MalformedEvent_FailsClosedWithAStableCode(string xml, string code)
    {
        WindowsEventFormatException failure = Assert.Throws<WindowsEventFormatException>(() => WindowsEventXml.Parse(xml));
        Assert.Equal(code, failure.Code);
        // Codes only: never the event content.
        Assert.Equal(code, failure.Message);
    }

    public static TheoryData<string, string> ForbiddenCharacters => new()
    {
        { "a\u0007b", "a\u0007b" },
        { "\u001b[31mred", "\u001b[31mred" },
        { "nul\0end", "nul\0end" },
        { "&#x1;&#x1F;", "\u0001\u001f" },
        { "&#x0;", "\0" },
        { "lone\uD800x", "lone\uD800x" },
        { "&#xD800;", "\uD800" },
        { "\uFFFE", "\uFFFE" },
        { "pair\U0001F600", "pair\U0001F600" }
    };

    [Theory]
    [MemberData(nameof(ForbiddenCharacters))]
    public void Parse_KeepsEventsWithCharactersXmlForbids(string rendered, string expected)
    {
        // An attacker chooses the account name of a failed logon. Characters XML 1.0
        // forbids, raw or as references, must not make the event unreadable (and so
        // invisible); the value is kept exactly for HMAC and redaction.
        string xml = WindowsEventFixtures.Read("security-4625.xml").Replace("deploy-admin", rendered, StringComparison.Ordinal);

        WindowsEvent parsed = WindowsEventXml.Parse(xml);

        Assert.Equal(expected, parsed.Data.Single(item => item.Key == "data.TargetUserName").Value);
        Assert.Equal(4625, parsed.EventId);
    }

    [Fact]
    public void Record_MatchesTheSampleThePackIsTestedWith()
    {
        string record = WindowsEventRecord.Build(
            WindowsEventXml.Parse(WindowsEventFixtures.Read("security-4625.xml")), "security-logon", message: null);
        string sample = File.ReadLines(Path.Combine(AppContext.BaseDirectory, "packs", "windows-security-logon", "samples", "security-4625.jsonl")).First();

        // The signed pack's samples are exactly what this source produces for the event.
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(sample)!["raw"], JsonNode.Parse(record)));
        using JsonDocument document = JsonDocument.Parse(record);
        Assert.Equal(
            ["id", "subscription", "channel", "provider", "eventId", "recordId", "computer", "timeCreated"],
            document.RootElement.EnumerateObject().Take(8).Select(property => property.Name));
        Assert.Equal("winevt-65de927a5a517c41e8e00b5a161bd834", document.RootElement.GetProperty("id").GetString());
        Assert.Equal("2026-10-23T10:00:00.123456Z", document.RootElement.GetProperty("timeCreated").GetString());
        Assert.All(document.RootElement.EnumerateObject(), property => Assert.Equal(JsonValueKind.String, property.Value.ValueKind));
    }

    [Fact]
    public void Record_IdDependsOnChannelComputerRecordAndTimeOnly()
    {
        string Id(string xml, string subscription = Subscription) =>
            JsonNode.Parse(WindowsEventRecord.Build(WindowsEventXml.Parse(xml), subscription, null))!["id"]!.GetValue<string>();

        string time = "2026-10-23T10:00:00.0000000Z";
        string baseline = Id(WindowsEventFixtures.Event(9, 1000, time: time));
        Assert.Equal(baseline, Id(WindowsEventFixtures.Event(9, 1000, time: time, data: [("changed", "payload")])));
        Assert.Equal(baseline, Id(WindowsEventFixtures.Event(9, 1000, time: time), "other-subscription"));
        Assert.NotEqual(baseline, Id(WindowsEventFixtures.Event(10, 1000, time: time)));
        Assert.NotEqual(baseline, Id(WindowsEventFixtures.Event(9, 1000, channel: "System", time: time)));
        Assert.NotEqual(baseline, Id(WindowsEventFixtures.Event(9, 1000, computer: "host02", time: time)));
        // A cleared log reuses record ids; the creation time keeps the ids apart.
        Assert.NotEqual(baseline, Id(WindowsEventFixtures.Event(9, 1000, time: "2026-10-24T10:00:00.0000000Z")));
        Assert.Matches("^winevt-[0-9a-f]{32}$", baseline);
    }

    [Fact]
    public void Record_LeavesOutUnreadableNamesLongValuesAndRepeatsAndBoundsTheFieldCount()
    {
        string xml = WindowsEventFixtures.Event(3, 1000, data:
        [
            ("Good", "kept"),
            ("bad name", "dropped"),
            ("Long", new string('x', WindowsEventRecord.MaximumValueLength + 1)),
            ("Good", "second copy"),
            ("Edge", new string('y', WindowsEventRecord.MaximumValueLength))
        ]);
        JsonNode record = JsonNode.Parse(WindowsEventRecord.Build(WindowsEventXml.Parse(xml), Subscription, "a message"))!;
        Assert.Equal("kept", record["data.Good"]!.GetValue<string>());
        Assert.Equal("a message", record["message"]!.GetValue<string>());
        Assert.Null(record["data.bad name"]);
        Assert.Null(record["data.Long"]);
        Assert.NotNull(record["data.Edge"]);

        JsonNode noMessage = JsonNode.Parse(WindowsEventRecord.Build(WindowsEventXml.Parse(xml), Subscription,
            new string('m', WindowsEventRecord.MaximumValueLength + 1)))!;
        Assert.Null(noMessage["message"]);

        string wide = WindowsEventFixtures.Event(4, 1000, data: [.. Enumerable.Range(0, 60).Select(index => ($"f{index}", "v"))]);
        WindowsEventFormatException failure = Assert.Throws<WindowsEventFormatException>(
            () => WindowsEventRecord.Build(WindowsEventXml.Parse(wide), Subscription, null));
        Assert.Equal(WindowsEventFailures.RecordTooLarge, failure.Code);
    }

    [Fact]
    public void Configuration_ParsesDefaultsAndNormalisesTheAllowList()
    {
        WindowsEventLogSourceConfiguration configuration = WindowsEventLogSourceConfigurationLoader.Parse("""
            {"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [
              {"id": "security-logon", "channel": "Security", "eventIds": [4625, 4624],
               "providers": ["Microsoft-Windows-Security-Auditing"], "pack": "windows-security-logon", "parser": 0},
              {"id": "sysmon", "channel": "Microsoft-Windows-Sysmon/Operational", "eventIds": [1],
               "pack": "sysmon", "parser": 2, "readExisting": true, "includeMessage": true, "pollIntervalSeconds": 10, "batchSize": 8}
            ]}
            """);

        WindowsEventSubscriptionOptions security = configuration.Subscriptions[0];
        Assert.Equal([4624, 4625], security.EventIds);
        Assert.False(security.ReadExisting);
        Assert.False(security.IncludeMessage);
        Assert.Equal(2, security.PollIntervalSeconds);
        Assert.Equal(64, security.BatchSize);
        Assert.Equal("windows-eventlog:security-logon", security.SourceId);
        WindowsEventSubscriptionOptions sysmon = configuration.Subscriptions[1];
        Assert.Null(sysmon.Providers);
        Assert.True(sysmon.ReadExisting && sysmon.IncludeMessage);
        Assert.Equal((10, 8), (sysmon.PollIntervalSeconds, sysmon.BatchSize));
    }

    [Theory]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "SyslogSource", "subscriptions": []}""", "kind WindowsEventLogSource")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": []}""", "1–16 subscriptions")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [], "pack": "p", "parser": 0}]}""", "no collect-all form")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "pack": "p", "parser": 0}]}""", "is invalid")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17], "pack": "p", "parser": 0}]}""", "1–16 event IDs")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [4625, 4625], "pack": "p", "parser": 0}]}""", "distinct values")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [65536], "pack": "p", "parser": 0}]}""", "between 0 and 65535")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "*", "eventIds": [1], "pack": "p", "parser": 0}]}""", "channel must be")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security]] or *[System[", "eventIds": [1], "pack": "p", "parser": 0}]}""", "channel must be")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "providers": ["x' or @Name!='"], "pack": "p", "parser": 0}]}""", "providers must list")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "providers": [], "pack": "p", "parser": 0}]}""", "providers must list")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "A", "channel": "Security", "eventIds": [1], "pack": "p", "parser": 0}]}""", "subscription id must be")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "pack": "", "parser": 0}]}""", "pack and a parser index")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "pack": "p", "parser": 0, "batchSize": 0}]}""", "batchSize")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "pack": "p", "parser": 0, "pollIntervalSeconds": 301}]}""", "pollIntervalSeconds")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "pack": "p", "parser": 0, "query": "*"}]}""", "is invalid")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1], "pack": "p", "parser": 0}, {"id": "a", "channel": "System", "eventIds": [1], "pack": "p", "parser": 0}]}""", "listed more than once")]
    [InlineData("""{"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [{"id": "a", "channel": "Security", "eventIds": [1, 2], "pack": "p", "parser": 0}, {"id": "b", "channel": "SECURITY", "eventIds": [2], "pack": "p", "parser": 0}]}""", "already selected by another subscription")]
    public void Configuration_RefusesUnsafeOrAmbiguousSubscriptions(string json, string message)
    {
        InvalidDataException failure = Assert.Throws<InvalidDataException>(() => WindowsEventLogSourceConfigurationLoader.Parse(json));
        Assert.Contains(message, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Query_IsGeneratedFromTheAllowListAndBookmark()
    {
        WindowsEventSubscriptionOptions options = WindowsEventLogSourceConfigurationLoader.Parse("""
            {"apiVersion": "bower.security/v1", "kind": "WindowsEventLogSource", "subscriptions": [
              {"id": "a", "channel": "Security", "eventIds": [4625, 4624], "providers": ["Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog"], "pack": "p", "parser": 0},
              {"id": "b", "channel": "Application", "eventIds": [1000], "pack": "p", "parser": 0}
            ]}
            """).Subscriptions[0];
        Assert.Equal(
            "*[System[(EventID=4624 or EventID=4625) and (Provider[@Name='Microsoft-Windows-Eventlog' or @Name='Microsoft-Windows-Security-Auditing']) and (EventRecordID>184467)]]",
            WindowsEventQuery.For(options, 184467).ToXPath());
        Assert.Equal(
            "*[System[(EventID=1000) and (EventRecordID>0)]]",
            new WindowsEventQuery("Application", [1000], null, 0).ToXPath());

        WindowsEventQuery query = WindowsEventQuery.For(options, 10);
        Assert.True(query.Matches(4625, "microsoft-windows-security-auditing", 11));
        Assert.False(query.Matches(4625, "Microsoft-Windows-Security-Auditing", 10));
        Assert.False(query.Matches(4634, "Microsoft-Windows-Security-Auditing", 11));
        Assert.False(query.Matches(4625, "Spoofed", 11));
    }

    [Fact]
    public void Bookmark_RoundTripsAndRefusesAnotherChannelOrVersion()
    {
        string text = WindowsEventBookmark.At("Security", 42).Serialize();
        Assert.Equal("""{"schemaVersion":2,"channel":"Security","recordId":42}""", text);
        Assert.Equal(42, WindowsEventBookmark.Deserialize(text, "security").RecordId);
        Assert.Throws<InvalidDataException>(() => WindowsEventBookmark.Deserialize(text, "System"));
        Assert.Throws<InvalidDataException>(() => WindowsEventBookmark.Deserialize("""{"schemaVersion":3,"channel":"Security","recordId":42}""", "Security"));
        Assert.Throws<InvalidDataException>(() => WindowsEventBookmark.Deserialize("""{"schemaVersion":1,"channel":"Security","recordId":-1}""", "Security"));
        Assert.Throws<InvalidDataException>(() => WindowsEventBookmark.Deserialize("""{"schemaVersion":1,"channel":"Security"}""", "Security"));
        Assert.Throws<InvalidDataException>(() => WindowsEventBookmark.Deserialize("{", "Security"));
    }

    [Fact]
    public async Task FirstStart_BeginsAtTheNewestEventUnlessReadExistingIsSet()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        channels["Application"].Add(WindowsEventFixtures.Event(2, 1000));
        RecordingWindowsEventSink sink = new();

        await using (WindowsEventLogSource source = Source(sink, cursors, channels))
        {
            WindowsEventPollResult first = await source.PollOnceAsync(Subscription, cancellation);
            Assert.Equal(0, first.Read);
            Assert.Equal(2, source.Snapshot()[0].BookmarkRecordId);
            channels["Application"].Add(WindowsEventFixtures.Event(3, 1000));
            await source.PollOnceAsync(Subscription, cancellation);
        }

        Assert.Single(sink.Queued);
        Assert.Equal([3L], channels["Application"].Returned);

        RecordingWindowsEventSink existing = new();
        await using WindowsEventLogSource backfill = Source(existing, cursors, channels, id: "backfill", readExisting: true, channel: "Application", eventIds: [1000]);
        await backfill.PollOnceAsync("backfill", cancellation);
        Assert.Equal(3, existing.Queued.Count);
    }

    [Fact]
    public async Task OnlyAllowListedEventsAreEverReadAndEachIsQueuedOnce()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        RecordingWindowsEventSink sink = new();
        await using WindowsEventLogSource source = Source(sink, cursors, channels, readExisting: true, providers: ["BowerTest"]);

        channel.Add(WindowsEventFixtures.Event(1, 1000));
        channel.Add(WindowsEventFixtures.Event(2, 1001));
        channel.Add(WindowsEventFixtures.Event(3, 1000, provider: "Other"));
        channel.Add(WindowsEventFixtures.Event(4, 1002, data: [("secret", "never-read-marker")]));
        channel.Add(WindowsEventFixtures.Event(5, 1000));
        channel.Add(WindowsEventFixtures.Event(6, 1003));
        await source.PollOnceAsync(Subscription, cancellation);

        Assert.Equal([1L, 5L], channel.Returned);
        Assert.Equal(2, sink.Queued.Count);
        Assert.DoesNotContain(sink.Records, record => record.Contains("never-read-marker", StringComparison.Ordinal));
        WindowsEventSubscriptionStatus status = source.Snapshot()[0];
        // Caught up, so the bookmark moves to the newest record scanned (6, never read).
        Assert.Equal((2, 2, 6L), (status.EventsRead, status.Queued, status.BookmarkRecordId!.Value));
        Assert.Equal("*[System[(EventID=1000) and (Provider[@Name='BowerTest']) and (EventRecordID>0)]]", channel.Queries[0].ToXPath());
    }

    [Fact]
    public async Task LegacyBookmark_ReplaysRetainedEventsThroughDeduplication()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        channel.Add(WindowsEventFixtures.Event(1, 1000));
        channel.Add(WindowsEventFixtures.Event(2, 1000));
        RecordingWindowsEventSink sink = new();
        EfSourceCursorStore store = await Cursors(directory);
        await using (WindowsEventLogSource initial = Source(sink, store, channels, readExisting: true))
        {
            await initial.PollOnceAsync(Subscription, cancellation);
        }
        var saved = (await store.ReadAsync("windows-eventlog:app", cancellation))!;
        // An origin ID inside the receiving range must not be accepted as a cursor.
        Assert.True(await store.TryAdvanceAsync("windows-eventlog:app", saved.Version,
            new WindowsEventBookmark(1, "Application", 2).Serialize(), DateTimeOffset.UtcNow, cancellation));
        channel.Add(WindowsEventFixtures.Event(3, 1000));
        await using WindowsEventLogSource upgraded = Source(sink, store, channels, readExisting: false);
        sink.Override = _ => WindowsEventSubmitOutcome.Unavailable;
        await upgraded.PollOnceAsync(Subscription, cancellation);
        WindowsEventBookmark blocked = WindowsEventBookmark.Deserialize(
            (await store.ReadAsync("windows-eventlog:app", cancellation))!.Value, "Application");
        Assert.Equal((2, 0L), (blocked.SchemaVersion, blocked.RecordId));
        Assert.Equal(2, sink.Queued.Count);
        sink.Override = null;
        await upgraded.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(3, sink.Queued.Count);
        Assert.Equal(2, upgraded.Snapshot()[0].Duplicates);
        WindowsEventBookmark migrated = WindowsEventBookmark.Deserialize(
            (await store.ReadAsync("windows-eventlog:app", cancellation))!.Value, "Application");
        Assert.Equal((2, 3L), (migrated.SchemaVersion, migrated.RecordId));
        int submissions = sink.Records.Count;
        await upgraded.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(submissions, sink.Records.Count);
    }

    [Fact]
    public async Task LegacyEmptyChannel_UpgradesZeroPositionOnlyOnce()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore store = await Cursors(directory);
        Assert.True(await store.TryAdvanceAsync("windows-eventlog:app", 0,
            new WindowsEventBookmark(1, "Application", 0).Serialize(), DateTimeOffset.UtcNow, cancellation));
        await using WindowsEventLogSource source = Source(new RecordingWindowsEventSink(), store,
            new FakeWindowsEventChannelFactory(), readExisting: false);
        await source.PollOnceAsync(Subscription, cancellation);
        var migrated = (await store.ReadAsync("windows-eventlog:app", cancellation))!;
        Assert.Equal(2, WindowsEventBookmark.Deserialize(migrated.Value, "Application").SchemaVersion);
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(migrated.Version, (await store.ReadAsync("windows-eventlog:app", cancellation))!.Version);
        Assert.Equal(1, source.Snapshot()[0].Resets);
    }

    [Fact]
    public async Task Restart_ResumesFromTheDurableBookmarkWithoutLossOrDuplicates()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        RecordingWindowsEventSink sink = new();
        for (int record = 1; record <= 5; record++)
        {
            channel.Add(WindowsEventFixtures.Event(record, 1000));
        }

        await using (WindowsEventLogSource first = Source(sink, await Cursors(directory), channels, readExisting: true, batchSize: 2))
        {
            WindowsEventPollResult result = await first.PollOnceAsync(Subscription, cancellation);
            Assert.True(result.More);
        }

        // A new process: new store instance over the same database, events written while stopped.
        channel.Add(WindowsEventFixtures.Event(6, 1000));
        await using (WindowsEventLogSource second = Source(sink, await Cursors(directory), channels, readExisting: true, batchSize: 2))
        {
            while ((await second.PollOnceAsync(Subscription, cancellation)).More)
            {
            }

            Assert.Equal(0, second.Snapshot()[0].Duplicates);
        }

        Assert.Equal(6, sink.Queued.Count);
        Assert.Equal(6, sink.Records.Count);
        Assert.Equal([1L, 2L, 3L, 4L, 5L, 6L], channel.Returned);
    }

    [Fact]
    public async Task CrashBeforeTheBookmarkCommit_ReplaysIntoQueueDeduplication()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        RecordingWindowsEventSink sink = new();
        channel.Add(WindowsEventFixtures.Event(1, 1000));
        EfSourceCursorStore store = await Cursors(directory);
        await using (WindowsEventLogSource start = Source(sink, store, channels, readExisting: true))
        {
            await start.PollOnceAsync(Subscription, cancellation);
        }

        channel.Add(WindowsEventFixtures.Event(2, 1000));
        channel.Add(WindowsEventFixtures.Event(3, 1000));
        CrashingCursorStore crashing = new(store) { FailNextCommits = 1 };
        await using (WindowsEventLogSource crashed = Source(sink, crashing, channels, readExisting: true))
        {
            // Both events are durably queued, then the process dies before the bookmark moves.
            await Assert.ThrowsAsync<IOException>(() => crashed.PollOnceAsync(Subscription, cancellation));
        }

        Assert.Equal(1, WindowsEventBookmark.Deserialize((await store.ReadAsync("windows-eventlog:app", cancellation))!.Value, "Application").RecordId);
        await using WindowsEventLogSource restarted = Source(sink, await Cursors(directory), channels, readExisting: true);
        await restarted.PollOnceAsync(Subscription, cancellation);

        // Re-read, but the queue's event-id deduplication keeps exactly one copy of each.
        Assert.Equal(3, sink.Queued.Count);
        WindowsEventSubscriptionStatus status = restarted.Snapshot()[0];
        Assert.Equal((0, 2, 3L), (status.Queued, status.Duplicates, status.BookmarkRecordId!.Value));
    }

    [Fact]
    public async Task FullQueue_StopsReadingAndRetriesTheSameEvent()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        for (int record = 1; record <= 4; record++)
        {
            channels["Application"].Add(WindowsEventFixtures.Event(record, 1000));
        }

        RecordingWindowsEventSink sink = new();
        bool full = false;
        sink.Override = record => full ? WindowsEventSubmitOutcome.Unavailable : null;
        await using WindowsEventLogSource source = Source(sink, cursors, channels, readExisting: true, batchSize: 2);
        await source.PollOnceAsync(Subscription, cancellation);
        full = true;

        WindowsEventPollResult blocked = await source.PollOnceAsync(Subscription, cancellation);
        Assert.True(blocked.Backpressure);
        Assert.False(blocked.More);
        WindowsEventSubscriptionStatus waiting = source.Snapshot()[0];
        Assert.Equal(("backpressure", 2L, 1L), (waiting.State, waiting.BookmarkRecordId!.Value, waiting.Retries));

        full = false;
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(4, sink.Queued.Count);
        Assert.Equal(4, source.Snapshot()[0].BookmarkRecordId);
        Assert.Equal("running", source.Snapshot()[0].State);
    }

    [Fact]
    public async Task SinkFailure_KeepsTheBookmarkBeforeTheFailedEvent()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(1, 1000));
        channels["Application"].Add(WindowsEventFixtures.Event(2, 1000, data: [("fail", "yes")]));
        channels["Application"].Add(WindowsEventFixtures.Event(3, 1000));
        RecordingWindowsEventSink sink = new();
        sink.Override = record => record.Contains("\"data.fail\"", StringComparison.Ordinal)
            ? throw new InvalidOperationException("storage unavailable")
            : null;
        await using WindowsEventLogSource source = Source(sink, cursors, channels, readExisting: true);

        WindowsEventChannelException failure = await Assert.ThrowsAsync<WindowsEventChannelException>(
            () => source.PollOnceAsync(Subscription, cancellation));
        Assert.Equal(WindowsEventChannelFailures.SubmitFailed, failure.Code);
        WindowsEventSubscriptionStatus status = source.Snapshot()[0];
        Assert.Equal((WindowsEventChannelFailures.SubmitFailed, 1L, 1L), (status.State, status.BookmarkRecordId!.Value, status.SubmitFailures));
        Assert.Single(sink.Queued);
    }

    [Fact]
    public async Task MalformedAndOversizedEvents_AreCountedAndSkipped()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        channel.Write(1, 1000, "BowerTest", "<Event><broken");
        channel.Write(2, 1000, "BowerTest", WindowsEventFixtures.Event(2, 1000, data: [("blob", new string('x', 70_000))]));
        channel.Write(3, 1000, "BowerTest", WindowsEventFixtures.Event(3, 1000, data: [.. Enumerable.Range(0, 60).Select(index => ($"f{index}", "v"))]));
        channel.Add(WindowsEventFixtures.Event(4, 1000));
        RecordingWindowsEventSink sink = new();
        await using WindowsEventLogSource source = Source(sink, cursors, channels, readExisting: true);

        await source.PollOnceAsync(Subscription, cancellation);

        WindowsEventSubscriptionStatus status = source.Snapshot()[0];
        Assert.Equal((4L, 1L, 2L, 1L, 4L), (status.EventsRead, status.Malformed, status.Oversized, status.Queued, status.BookmarkRecordId!.Value));
        Assert.Single(sink.Records);
    }

    [Fact]
    public async Task ClearedLogIsReadFromTheStartAndOverwrittenEventsAreAGap()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        for (int record = 1; record <= 10; record++)
        {
            channel.Add(WindowsEventFixtures.Event(record, 1000));
        }

        RecordingWindowsEventSink sink = new();
        await using WindowsEventLogSource source = Source(sink, cursors, channels, readExisting: true);
        await source.PollOnceAsync(Subscription, cancellation);

        // Cleared: record ids restart below the bookmark.
        channel.Clear();
        channel.Add(WindowsEventFixtures.Event(1, 1000, time: "2027-01-01T00:00:00.0000000Z"));
        channel.Add(WindowsEventFixtures.Event(2, 1000, time: "2027-01-01T00:00:01.0000000Z"));
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(12, sink.Queued.Count);
        Assert.Equal((1L, 2L), (source.Snapshot()[0].Resets, source.Snapshot()[0].BookmarkRecordId!.Value));

        // Log full: the oldest record is now past the bookmark, so some events were never read.
        for (int record = 3; record <= 20; record++)
        {
            channel.Add(WindowsEventFixtures.Event(record, 1000, time: $"2027-01-01T00:01:{record:00}.0000000Z"));
        }

        channel.OldestOverride = 15;
        await source.PollOnceAsync(Subscription, cancellation);
        Assert.Equal(1, source.Snapshot()[0].Gaps);
    }

    [Fact]
    public async Task InvalidStoredBookmark_FailsClosedWithoutReading()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        Assert.True(await cursors.TryAdvanceAsync("windows-eventlog:app", 0, WindowsEventBookmark.At("System", 5).Serialize(), DateTimeOffset.UtcNow, cancellation));
        FakeWindowsEventChannelFactory channels = new();
        channels["Application"].Add(WindowsEventFixtures.Event(6, 1000));
        await using WindowsEventLogSource source = Source(new RecordingWindowsEventSink(), cursors, channels, readExisting: true);

        WindowsEventChannelException failure = await Assert.ThrowsAsync<WindowsEventChannelException>(
            () => source.PollOnceAsync(Subscription, cancellation));
        Assert.Equal(WindowsEventChannelFailures.BookmarkInvalid, failure.Code);
        Assert.Empty(channels["Application"].Returned);
        Assert.Equal(WindowsEventChannelFailures.BookmarkInvalid, source.Snapshot()[0].State);
    }

    [Fact]
    public async Task ChannelFailure_IsReportedAndRetriedUntilTheChannelRecovers()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        FakeWindowsEventChannel channel = channels["Application"];
        channel.FailWith = WindowsEventChannelFailures.AccessDenied;
        channel.Add(WindowsEventFixtures.Event(1, 1000));
        RecordingWindowsEventSink sink = new();
        await using WindowsEventLogSource source = new(Configuration(readExisting: true, pollIntervalSeconds: 1), sink, cursors, channels)
        {
            MaximumBackoff = TimeSpan.FromMilliseconds(50)
        };

        await source.StartAsync(cancellation);
        WindowsEventSubscriptionStatus denied = await WaitFor(source, status => status.ReadErrors >= 2, cancellation);
        Assert.Equal(WindowsEventChannelFailures.AccessDenied, denied.State);

        channel.FailWith = null;
        WindowsEventSubscriptionStatus recovered = await WaitFor(source, status => status.Queued == 1 && status.State == "running", cancellation);
        Assert.NotNull(recovered.LastEventAt);
        Assert.NotNull(recovered.LastPollAt);
    }

    [Fact]
    public async Task Dispose_StopsTheLoopsAndReleasesTheChannels()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        EfSourceCursorStore cursors = await Cursors(directory);
        FakeWindowsEventChannelFactory channels = new();
        WindowsEventLogSource source = Source(new RecordingWindowsEventSink(), cursors, channels, pollIntervalSeconds: 300);
        await source.StartAsync(cancellation);
        await WaitFor(source, status => status.State == "running", cancellation);

        Task disposing = source.DisposeAsync().AsTask();
        Assert.Same(disposing, await Task.WhenAny(disposing, Task.Delay(TimeSpan.FromSeconds(10), cancellation)));
        Assert.Equal("stopped", source.Snapshot()[0].State);
        Assert.Equal(1, channels["Application"].Disposed);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Source(new RecordingWindowsEventSink(), cursors, channels).PollOnceAsync(Subscription, new CancellationToken(canceled: true)));
    }

    [Fact]
    public void Status_SerializesMetadataOnlyWithStableNames()
    {
        WindowsEventSubscriptionStatus status = new("app", "Application", "running", 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, null, null);
        Assert.Equal(
            """{"id":"app","channel":"Application","state":"running","bookmarkRecordId":7,"eventsRead":1,"bytesRead":2,"queued":3,"duplicates":4,"suppressed":5,"notSelected":6,"rejected":7,"parserErrors":8,"malformed":9,"oversized":10,"retries":11,"submitFailures":12,"readErrors":13,"gaps":14,"resets":15,"cursorConflicts":16,"lastEventAt":null,"lastPollAt":null}""",
            JsonSerializer.Serialize<IReadOnlyList<WindowsEventSubscriptionStatus>>([status], WindowsEventLogJsonContext.Default.IReadOnlyListWindowsEventSubscriptionStatus)[1..^1]);
    }

    internal static async Task<EfSourceCursorStore> Cursors(SqliteTemporaryDirectory directory)
    {
        EfSourceCursorStore store = new(Path.Combine(directory.Path, "queue.db"));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        return store;
    }

    private static WindowsEventLogSourceConfiguration Configuration(
        string id = Subscription,
        string channel = "Application",
        int[]? eventIds = null,
        string[]? providers = null,
        bool readExisting = false,
        int batchSize = 64,
        int pollIntervalSeconds = 2) =>
        new("bower.security/v1", "WindowsEventLogSource",
        [
            new WindowsEventSubscriptionOptions(id, channel, eventIds ?? [1000], "pack", 0, providers, readExisting,
                IncludeMessage: false, PollIntervalSeconds: pollIntervalSeconds, BatchSize: batchSize)
        ]);

    private static WindowsEventLogSource Source(
        RecordingWindowsEventSink sink,
        Bower.Abstractions.ISourceCursorStore cursors,
        FakeWindowsEventChannelFactory channels,
        string id = Subscription,
        string channel = "Application",
        int[]? eventIds = null,
        string[]? providers = null,
        bool readExisting = false,
        int batchSize = 64,
        int pollIntervalSeconds = 2) =>
        new(Configuration(id, channel, eventIds, providers, readExisting, batchSize, pollIntervalSeconds), sink, cursors, channels);

    internal static async Task<WindowsEventSubscriptionStatus> WaitFor(
        WindowsEventLogSource source,
        Func<WindowsEventSubscriptionStatus, bool> condition,
        CancellationToken cancellation)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        while (true)
        {
            WindowsEventSubscriptionStatus status = source.Snapshot()[0];
            if (condition(status))
            {
                return status;
            }

            await Task.Delay(20, timeout.Token);
        }
    }
}
