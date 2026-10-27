using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Bower.Cli.Commands;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

/// <summary>Tap session caps, back-pressure and filters (bower tap). The Rust port mirrors these in bower-core.</summary>
public sealed class EventTapTests
{
    private static EventTapRecord Accepted(string payload = """{"eventId":"e-1"}""") => new(
        TestEvents.Now, "policy", "accept", true, false, false, "auth.failure", "TestApplication", "test",
        "BWR-POL-AUTH-FAILURE", [], payload, null);

    private static ProcessingResult Queued() => new(
        DecisionAction.Accept, "e-1", true, false, [], null, Stage: ProcessingStage.Policy);

    private static EventTapRequest Request(
        int limit = 100, int sample = 1, TapPoint point = TapPoint.Redacted, string? application = null, string? eventType = null) =>
        new("default", point, application, eventType, limit, TimeSpan.FromSeconds(60), sample);

    [Fact]
    public void Publish_WithoutSessionsDoesNothing()
    {
        EventTap tap = new(new EventTapOptions(), new FakeClock(TestEvents.Now));
        Assert.False(tap.IsActive);
        tap.Publish(Queued(), null, "{}");
        Assert.Equal(new EventTapSnapshot(true, 0, 2, 0, 0, 0, 0, 0), tap.Snapshot());
    }

    [Fact]
    public void Publish_NeverBlocksOnAStalledReaderAndCountsEveryDrop()
    {
        EventTap tap = new(new EventTapOptions { MaximumEventsPerSecond = 1000 }, new FakeClock(TestEvents.Now));
        using EventTapSession session = tap.TryOpen(Request(limit: 1000))!;

        Stopwatch watch = Stopwatch.StartNew();
        for (int index = 0; index < 5000; index++)
        {
            tap.Publish(Queued(), null, "{}");
        }

        // Bounded impact: publishing to a reader that never reads stays fast and bounded.
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
        Assert.Equal(EventTap.SessionBufferFrames, session.Reader.Count);
        Assert.Equal(1000 - EventTap.SessionBufferFrames, session.Dropped);
        Assert.Equal(4000, session.RateLimited);
        EventTapSnapshot snapshot = tap.Snapshot();
        Assert.Equal(1000 - EventTap.SessionBufferFrames, snapshot.FramesDropped);
        Assert.Equal(4000, snapshot.FramesRateLimited);
    }

    [Fact]
    public void Session_RateCapRefillsWithTime()
    {
        FakeClock clock = new(TestEvents.Now);
        EventTap tap = new(new EventTapOptions { MaximumEventsPerSecond = 5 }, clock);
        using EventTapSession session = tap.TryOpen(Request())!;
        for (int index = 0; index < 10; index++)
        {
            tap.Publish(Queued(), null, "{}");
        }

        Assert.Equal(5, session.Reader.Count);
        Assert.Equal(5, session.RateLimited);
        clock.Advance(TimeSpan.FromSeconds(1));
        for (int index = 0; index < 10; index++)
        {
            tap.Publish(Queued(), null, "{}");
        }

        Assert.Equal(10, session.Reader.Count);
        Assert.Equal(10, session.RateLimited);
    }

    [Fact]
    public void TryOpen_EnforcesConcurrentSessionCapAndClampsLimits()
    {
        EventTap tap = new(new EventTapOptions { MaximumSessions = 2, MaximumEvents = 50, MaximumDuration = TimeSpan.FromSeconds(30) },
            new FakeClock(TestEvents.Now));
        EventTapSession first = tap.TryOpen(Request(limit: 5000) with { Duration = TimeSpan.FromHours(1) })!;
        using EventTapSession second = tap.TryOpen(Request())!;

        Assert.Null(tap.TryOpen(Request()));
        Assert.Equal(50, first.Request.Limit);
        Assert.Equal(TimeSpan.FromSeconds(30), first.Request.Duration);
        first.Dispose();
        first.Dispose();
        using EventTapSession third = tap.TryOpen(Request())!;
        Assert.NotNull(third);
        EventTapSnapshot snapshot = tap.Snapshot();
        Assert.Equal(2, snapshot.ActiveSessions);
        Assert.Equal(3, snapshot.SessionsOpened);
        Assert.Equal(1, snapshot.SessionsRefused);
    }

    [Fact]
    public void TryOpen_RefusesWhenDisabled()
    {
        EventTap tap = new(new EventTapOptions { Enabled = false }, new FakeClock(TestEvents.Now));
        Assert.Null(tap.TryOpen(Request()));
        Assert.Equal(1, tap.Snapshot().SessionsRefused);
    }

    [Fact]
    public void Session_SamplesAndStopsAtItsLimit()
    {
        EventTap tap = new(new EventTapOptions(), new FakeClock(TestEvents.Now));
        using EventTapSession sampled = tap.TryOpen(Request(sample: 3))!;
        using EventTapSession limited = tap.TryOpen(Request(limit: 2))!;
        for (int index = 0; index < 9; index++)
        {
            tap.Publish(Queued(), null, "{}");
        }

        Assert.Equal(3, sampled.Reader.Count);
        Assert.Equal(2, limited.Reader.Count);
        Assert.Equal(0, limited.Dropped);
    }

    [Fact]
    public void Record_MatchesTapPointsAndExactFilters()
    {
        EventTapRecord queued = Accepted();
        EventTapRecord rejected = queued with { Action = "reject", Queued = false, Event = null, EventOmitted = "not-accepted" };
        EventTapRecord invalid = rejected with { Stage = "validation", Action = "quarantine" };

        Assert.True(invalid.Matches(Request()));
        Assert.False(invalid.Matches(Request(point: TapPoint.Decided)));
        Assert.True(rejected.Matches(Request(point: TapPoint.Decided)));
        Assert.False(rejected.Matches(Request(point: TapPoint.Queued)));
        Assert.True(queued.Matches(Request(point: TapPoint.Queued, application: "TestApplication", eventType: "auth.failure")));
        Assert.False(queued.Matches(Request(application: "testapplication")));
        Assert.False(queued.Matches(Request(eventType: "auth")));
        Assert.Null(EventTapRequest.ParsePoint("parsed"));
        Assert.Null(EventTapRequest.ParsePoint("raw"));
        Assert.False(EventTapRequest.IsValidFilter("bad value"));
        Assert.False(EventTapRequest.IsValidFilter(new string('a', 129)));
        Assert.True(EventTapRequest.IsValidFilter("auth.failure:v1/x@y-z_1"));
    }

    [Fact]
    public void Publish_ShowsOnlyAcceptedPayloadsWithinTheSizeCap()
    {
        EventTap tap = new(new EventTapOptions { MaximumEventBytes = 1024 }, new FakeClock(TestEvents.Now));
        using EventTapSession session = tap.TryOpen(Request())!;
        SecurityEventEnvelope subject = TestEvents.AuthenticationFailure(TestEvents.Now) with { EventType = new string('t', 300) };

        tap.Publish(Queued(), subject, "{\"small\":true}");
        tap.Publish(Queued(), subject, "{\"large\":\"" + new string('x', 2000) + "\"}");
        tap.Publish(new ProcessingResult(DecisionAction.Reject, "e-2", false, false, ["no policy"], null), subject, "{\"never\":1}");

        Assert.True(session.Reader.TryRead(out EventTapRecord? small));
        Assert.Equal("{\"small\":true}", small!.Event);
        Assert.Equal(EventTap.MaximumMetadataLength, small.EventType!.Length);
        Assert.True(session.Reader.TryRead(out EventTapRecord? large));
        Assert.Null(large!.Event);
        Assert.Equal(EventTapRecord.OmittedSizeCap, large.EventOmitted);
        Assert.True(session.Reader.TryRead(out EventTapRecord? rejected));
        Assert.Null(rejected!.Event);
        Assert.Equal(EventTapRecord.OmittedNotAccepted, rejected.EventOmitted);
        Assert.Equal("reject", rejected.Action);
    }
}

/// <summary>GET /v1/tap end to end, plus bower top reconciliation and snapshot output.</summary>
[Collection(SerialHostTests.Name)]
public sealed class TapHostTests
{
    private const string Token = "test-ingest-token-0123456789abcdef0123456789";

    // Known secrets in field names the privacy engine removes and values its detectors mask.
    private static readonly string[] Secrets =
    [
        "tap-canary-password-value", "AKIAIOSFODNN7EXAMPLE", "4111111111111111",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "tap-canary-api-token"
    ];

    private static Dictionary<string, JsonElement> SecretAttributes() => new()
    {
        ["dbPassword"] = JsonSerializer.SerializeToElement(Secrets[0]),
        ["awsKey"] = JsonSerializer.SerializeToElement(Secrets[1]),
        ["pan"] = JsonSerializer.SerializeToElement(Secrets[2]),
        ["detail"] = JsonSerializer.SerializeToElement(Secrets[3]),
        ["apiToken"] = JsonSerializer.SerializeToElement(Secrets[4])
    };

    [Fact]
    public async Task Tap_NeverReturnsPreRedactionValuesAndAuditsTheSession()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CapturingLoggerProvider logs = new();
        await using WebApplication app = await StartAsync(directory, cancellation, logs: logs);
        HttpClient client = app.GetTestClient();

        await using TapStream tap = await TapStream.OpenAsync(client, "v1/tap?limit=3&durationSeconds=30", Token, cancellation);
        Assert.Equal(HttpStatusCode.OK, tap.Status);
        (string startName, JsonElement start) = await tap.NextAsync(cancellation);
        Assert.Equal("start", startName);
        Assert.Equal("redacted", start.GetProperty("tapPoint").GetString());

        SecurityEventEnvelope accepted = Event() with { Attributes = SecretAttributes() };
        SecurityEventEnvelope rejected = Event() with
        {
            EventType = "custom.unlisted",
            EventCategory = "custom",
            Attributes = SecretAttributes()
        };
        SecurityEventEnvelope invalid = Event() with { TimeGenerated = DateTimeOffset.UnixEpoch, Attributes = SecretAttributes() };
        Assert.Equal(HttpStatusCode.Accepted, await PostAsync(client, accepted, cancellation));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, await PostAsync(client, rejected, cancellation));
        Assert.Equal(HttpStatusCode.BadRequest, await PostAsync(client, invalid, cancellation));

        List<JsonElement> frames = [];
        (string name, JsonElement data) next;
        while ((next = await tap.NextAsync(cancellation)).name == "frame")
        {
            frames.Add(next.data);
        }

        Assert.Equal("end", next.name);
        Assert.Equal("limit", next.data.GetProperty("reason").GetString());
        Assert.Equal(3, frames.Count);
        Assert.Equal("redact-and-accept", frames[0].GetProperty("action").GetString());
        Assert.Equal(accepted.EventId, frames[0].GetProperty("event").GetProperty("eventId").GetString());
        Assert.Equal("reject", frames[1].GetProperty("action").GetString());
        Assert.Equal("not-accepted", frames[1].GetProperty("eventOmitted").GetString());
        Assert.False(frames[1].TryGetProperty("event", out _));
        Assert.Equal("validation", frames[2].GetProperty("stage").GetString());
        Assert.Equal("quarantine", frames[2].GetProperty("action").GetString());
        Assert.False(frames[2].TryGetProperty("event", out _));

        string stream = tap.Text;
        foreach (string secret in Secrets)
        {
            Assert.DoesNotContain(secret, stream, StringComparison.Ordinal);
        }

        using JsonDocument status = await StatusAsync(client, cancellation);
        JsonElement counters = status.RootElement.GetProperty("tap");
        Assert.Equal(1, counters.GetProperty("sessionsOpened").GetInt64());
        Assert.Equal(3, counters.GetProperty("framesSent").GetInt64());

        await tap.DisposeAsync();
        await WaitForAsync(() => logs.Messages.Any(message => message.Contains("closed (limit)", StringComparison.Ordinal)), cancellation);
        string audit = string.Join('\n', logs.Messages.Where(message => message.StartsWith("Tap session", StringComparison.Ordinal)));
        Assert.Contains("opened by producer default: tap point redacted, source -, event type -, limit 3, duration 30 s, sample 1 in 1.", audit, StringComparison.Ordinal);
        Assert.Contains("closed (limit) after", audit, StringComparison.Ordinal);
        Assert.Contains("3 frames sent, 0 dropped, 0 rate limited.", audit, StringComparison.Ordinal);
        string allLogs = string.Join('\n', logs.Messages);
        Assert.DoesNotContain(Token, allLogs, StringComparison.Ordinal);
        foreach (string secret in Secrets)
        {
            Assert.DoesNotContain(secret, allLogs, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Tap_IsRefusedWithoutTheOperatorCredential()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        const string producerToken = "producer-token-0123456789abcdef0123456789";
        const string operatorToken = "operator-token-0123456789abcdef0123456789";
        string tokensFile = Path.Combine(directory.Path, "tokens");
        File.WriteAllLines(tokensFile,
        [
            IngestAuthentication.TokensFileLine("sidecar-01", producerToken),
            IngestAuthentication.TokensFileLine("soc-operator", operatorToken)
        ]);
        CapturingLoggerProvider logs = new();
        await using WebApplication app = await StartAsync(directory, cancellation,
            settings => settings with { IngestTokensFile = tokensFile, TapProducers = ["soc-operator"] }, logs);
        HttpClient client = app.GetTestClient();

        await using (TapStream missing = await TapStream.OpenAsync(client, "v1/tap", null, cancellation))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, missing.Status);
        }

        await using (TapStream wrong = await TapStream.OpenAsync(client, "v1/tap", "wrong-token", cancellation))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.Status);
        }

        await using (TapStream producer = await TapStream.OpenAsync(client, "v1/tap", producerToken, cancellation))
        {
            Assert.Equal(HttpStatusCode.Forbidden, producer.Status);
            Assert.Contains("tap-not-authorized", producer.Text, StringComparison.Ordinal);
        }

        await using (TapStream listed = await TapStream.OpenAsync(client, "v1/tap?limit=1&durationSeconds=5", operatorToken, cancellation))
        {
            Assert.Equal(HttpStatusCode.OK, listed.Status);
            Assert.Equal("start", (await listed.NextAsync(cancellation)).name);
        }

        await using (TapStream shared = await TapStream.OpenAsync(client, "v1/tap?limit=1&durationSeconds=5", Token, cancellation))
        {
            Assert.Equal(HttpStatusCode.OK, shared.Status);
        }

        Assert.Contains(logs.Messages, message => message == "Tap session refused for producer sidecar-01: tap-not-authorized.");
        Assert.Contains(logs.Messages, message => message.Contains("opened by producer soc-operator", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Tap_WithoutIngestAuthenticationNeedsALoopbackListener()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellation,
            settings => settings with { IngestToken = null, ListenUrl = "http://0.0.0.0:4319", AllowUnauthenticatedIngest = true });
        await using TapStream tap = await TapStream.OpenAsync(app.GetTestClient(), "v1/tap", null, cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, tap.Status);
    }

    [Fact]
    public async Task Tap_EnforcesSessionCapParametersAndDisablement()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellation,
            settings => settings with { TapMaximumSessions = 1 });
        HttpClient client = app.GetTestClient();

        await using TapStream first = await TapStream.OpenAsync(client, "v1/tap?durationSeconds=30", Token, cancellation);
        Assert.Equal("start", (await first.NextAsync(cancellation)).name);
        await using (TapStream second = await TapStream.OpenAsync(client, "v1/tap", Token, cancellation))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, second.Status);
            Assert.Contains("tap-session-limit", second.Text, StringComparison.Ordinal);
        }

        foreach ((string query, string error) in new[]
                 {
                     ("stage=parsed", "tap-stage-invalid"), ("stage=raw", "tap-stage-invalid"),
                     ("limit=abc", "tap-parameter-invalid"), ("limit=0", "tap-parameter-invalid"),
                     ("sample=10001", "tap-parameter-invalid"), ("source=bad%20value", "tap-filter-invalid")
                 })
        {
            await using TapStream invalid = await TapStream.OpenAsync(client, "v1/tap?" + query, Token, cancellation);
            Assert.Equal(HttpStatusCode.BadRequest, invalid.Status);
            Assert.Contains(error, invalid.Text, StringComparison.Ordinal);
        }

        using TemporaryDirectory other = new();
        await using WebApplication disabled = await StartAsync(other, cancellation, settings => settings with { TapEnabled = false });
        await using TapStream refused = await TapStream.OpenAsync(disabled.GetTestClient(), "v1/tap", Token, cancellation);
        Assert.Equal(HttpStatusCode.NotFound, refused.Status);
    }

    [Fact]
    public async Task Tap_DurationCapEndsTheSession()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellation,
            settings => settings with { TapMaximumDurationSeconds = 1, TapMaximumEvents = 5 });
        await using TapStream tap = await TapStream.OpenAsync(
            app.GetTestClient(), "v1/tap?durationSeconds=600&limit=900", Token, cancellation);

        (string name, JsonElement start) = await tap.NextAsync(cancellation);
        Assert.Equal("start", name);
        Assert.Equal(1, start.GetProperty("durationSeconds").GetInt32());
        Assert.Equal(5, start.GetProperty("limit").GetInt32());
        (string endName, JsonElement end) = await tap.NextAsync(cancellation);
        Assert.Equal("end", endName);
        Assert.Equal("duration", end.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Top_StageCountsReconcileWithSelectionMetrics()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, cancellation);
        HttpClient client = app.GetTestClient();
        using JsonDocument before = await StatusAsync(client, cancellation);
        for (int index = 0; index < 3; index++)
        {
            await PostAsync(client, Event(), cancellation);
        }

        await PostAsync(client, Event() with { EventType = "custom.unlisted", EventCategory = "custom" }, cancellation);
        await PostAsync(client, Event() with { TimeGenerated = DateTimeOffset.UnixEpoch }, cancellation);
        using JsonDocument after = await StatusAsync(client, cancellation);

        string view = TopView.Render("collector", before.RootElement, after.RootElement, 1000, DateTimeOffset.UtcNow);
        JsonElement pipeline = after.RootElement.GetProperty("pipeline");
        Assert.Equal(5, pipeline.GetProperty("eventsIn").GetInt64());
        string totalRow = view.Split('\n').Single(line => line.StartsWith("total ", StringComparison.Ordinal));
        string[] total = totalRow.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // total, events, /s, accepted, rejected, quarantined, other, suppressed, queued, duplicates
        Assert.Equal(pipeline.GetProperty("eventsIn").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture), total[1]);
        Assert.Equal("5.0", total[2]);
        Assert.Equal("3", total[3]);
        Assert.Equal("1", total[4]);
        Assert.Equal("1", total[5]);
        Assert.Equal(pipeline.GetProperty("eventsQueued").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture), total[8]);
        long stageSum = view.Split('\n')
            .Where(line => line.StartsWith("policy ", StringComparison.Ordinal) || line.StartsWith("validation ", StringComparison.Ordinal))
            .Where(line => !line.Contains("BWR-", StringComparison.Ordinal) && !line.Contains(" - ", StringComparison.Ordinal))
            .Sum(line => long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1], System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(5, stageSum);
        Assert.Contains("TestApplication", view, StringComparison.Ordinal);
        Assert.Contains("Tap       enabled  sessions 0/2", view, StringComparison.Ordinal);
    }

    [Fact]
    public void TopView_MatchesTheSharedSnapshot()
    {
        string directory = Path.Combine(AppContext.BaseDirectory, "top-fixtures");
        using JsonDocument previous = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "status-previous.json")));
        using JsonDocument current = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "status-current.json")));
        DateTimeOffset now = new(2026, 7, 26, 2, 14, 19, TimeSpan.Zero);

        string view = TopView.Render("http://127.0.0.1:4319", previous.RootElement, current.RootElement, 2000, now);
        string first = TopView.Render("http://127.0.0.1:4319", null, current.RootElement, 0, now);

        Assert.Equal(File.ReadAllText(Path.Combine(directory, "expected.txt")), view);
        Assert.Equal(File.ReadAllText(Path.Combine(directory, "expected-first.txt")), first);
    }

    [Fact]
    public void TapRefusal_MessagesNameTheFix()
    {
        Assert.Contains("BOWER_INGEST_TOKEN", TapAndTopCommands.TapRefusal(HttpStatusCode.Unauthorized, null), StringComparison.Ordinal);
        Assert.Contains("BOWER_TAP_PRODUCERS", TapAndTopCommands.TapRefusal(HttpStatusCode.Forbidden, null), StringComparison.Ordinal);
        Assert.Equal("Tap refused: HTTP 400 (tap-stage-invalid).", TapAndTopCommands.TapRefusal(HttpStatusCode.BadRequest, "tap-stage-invalid"));
    }

    private static async Task WaitForAsync(Func<bool> condition, CancellationToken cancellation)
    {
        for (int attempt = 0; attempt < 200 && !condition(); attempt++)
        {
            await Task.Delay(25, cancellation);
        }

        Assert.True(condition());
    }

    private static async Task<HttpStatusCode> PostAsync(HttpClient client, SecurityEventEnvelope candidate, CancellationToken cancellation)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "/v1/events")
        {
            Content = JsonContent.Create(candidate, options: BowerJson.Options)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellation);
        return response.StatusCode;
    }

    private static async Task<JsonDocument> StatusAsync(HttpClient client, CancellationToken cancellation)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellation);
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellation));
    }

    private static SecurityEventEnvelope Event() =>
        TestEvents.AuthenticationFailure(
            DateTimeOffset.UtcNow, eventId: Guid.NewGuid().ToString(), originalId: Guid.NewGuid().ToString());

    private static async Task<WebApplication> StartAsync(
        TemporaryDirectory directory,
        CancellationToken cancellation,
        Func<CollectorSettings, CollectorSettings>? adjust = null,
        CapturingLoggerProvider? logs = null)
    {
        CollectorSettings settings = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "collector-test",
            SingleTrustDomain = true,
            IngestToken = Token
        };
        settings = adjust?.Invoke(settings) ?? settings;
        WebApplication app = CollectorApplication.Build(settings, builder =>
        {
            builder.WebHost.UseTestServer();
            if (logs is not null)
            {
                builder.Logging.AddProvider(logs);
            }
        });
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);
        return app;
    }

    /// <summary>A server-sent event reader over one tap response.</summary>
    private sealed class TapStream : IAsyncDisposable
    {
        private readonly HttpResponseMessage response;
        private readonly StreamReader? reader;
        private readonly StringBuilder text = new();

        private TapStream(HttpResponseMessage response, StreamReader? reader, string body)
        {
            this.response = response;
            this.reader = reader;
            text.Append(body);
        }

        public HttpStatusCode Status => response.StatusCode;

        public string Text => text.ToString();

        public static async Task<TapStream> OpenAsync(HttpClient client, string path, string? token, CancellationToken cancellation)
        {
            using HttpRequestMessage request = new(HttpMethod.Get, "/" + path);
            if (token is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
            if (!response.IsSuccessStatusCode)
            {
                return new TapStream(response, null, await response.Content.ReadAsStringAsync(cancellation));
            }

            Assert.StartsWith("text/event-stream", response.Content.Headers.ContentType?.ToString(), StringComparison.Ordinal);
            return new TapStream(response, new StreamReader(await response.Content.ReadAsStreamAsync(cancellation)), string.Empty);
        }

        public async Task<(string name, JsonElement data)> NextAsync(CancellationToken cancellation)
        {
            string? name = null;
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            while (await reader!.ReadLineAsync(timeout.Token) is { } line)
            {
                text.Append(line).Append('\n');
                if (line.StartsWith("event: ", StringComparison.Ordinal))
                {
                    name = line["event: ".Length..];
                }
                else if (line.StartsWith("data: ", StringComparison.Ordinal))
                {
                    using JsonDocument document = JsonDocument.Parse(line["data: ".Length..]);
                    return (name!, document.RootElement.Clone());
                }
            }

            return ("eof", default);
        }

        public ValueTask DisposeAsync()
        {
            reader?.Dispose();
            response.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> messages = new();

    public IReadOnlyList<string> Messages => [.. messages];

    public ILogger CreateLogger(string categoryName) => new Logger(messages);

    public void Dispose()
    {
    }

    private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(formatter(state, exception));
    }
}
