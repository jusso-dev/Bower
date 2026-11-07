using System.Net;
using Bower.Agent.Docker;
using Bower.Forwarding;
using Bower.Persistence;
using Bower.Source.Docker;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class DockerSidecarWorkerTests
{
    private const string Token = "sidecar-token-0123456789abcdef0123456789";

    [Fact]
    public async Task Pass_ForwardsRecognisedLinesAndDropsTheRest()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container,
            "Server listening on 0.0.0.0 port 22.\n",
            "Failed password for root from 203.0.113.5 port 22 ssh2\n",
            "Accepted publickey for deploy from 192.0.2.4 port 50000 ssh2\n");
        RecordingHandler handler = new(_ => HttpStatusCode.Accepted);
        (DockerSidecarWorker worker, EfSourceCursorStore _) = await CreateAsync(root, handler, cancellationToken);

        SidecarPassResult result = await worker.ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, result.Forwarded);
        Assert.Equal(2, result.Dropped);
        string body = Assert.Single(handler.Bodies);
        Assert.Contains("\"eventType\":\"authentication_failure\"", body, StringComparison.Ordinal);
        Assert.Equal($"Bearer {Token}", handler.Authorizations.Single());
    }

    [Fact]
    public async Task Pass_DoesNotResendAfterRestart()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "Invalid user a from 192.0.2.1 port 1\n");
        RecordingHandler handler = new(_ => HttpStatusCode.Accepted);
        (DockerSidecarWorker first, _) = await CreateAsync(root, handler, cancellationToken);
        await first.ProcessOnceAsync(cancellationToken);

        (DockerSidecarWorker restarted, _) = await CreateAsync(root, handler, cancellationToken);
        DockerFixture.Append(container, "Invalid user b from 192.0.2.2 port 1\n");
        await restarted.ProcessOnceAsync(cancellationToken);

        Assert.Equal(2, handler.Bodies.Count);
        Assert.Contains("\"username\":\"b\"", handler.Bodies[1], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.Conflict)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task Pass_BacksOffWithoutAdvancingOnTransientFailures(HttpStatusCode status)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container,
            "Invalid user a from 192.0.2.1 port 1\n",
            "Invalid user b from 192.0.2.2 port 1\n");
        HttpStatusCode current = status;
        RecordingHandler handler = new(_ => current);
        (DockerSidecarWorker worker, _) = await CreateAsync(root, handler, cancellationToken);

        SidecarPassResult failed = await worker.ProcessOnceAsync(cancellationToken);
        current = HttpStatusCode.Accepted;
        SidecarPassResult recovered = await worker.ProcessOnceAsync(cancellationToken);

        Assert.True(failed.Backpressure);
        Assert.Equal(0, failed.Forwarded);
        Assert.Equal(0, failed.Rejected);
        Assert.Equal(0, failed.Dropped);
        Assert.Equal(2, recovered.Forwarded);
        Assert.Equal(3, handler.Bodies.Count);
        // The retried event keeps its deterministic id, so the collector deduplicates.
        Assert.Equal(EventId(handler.Bodies[0]), EventId(handler.Bodies[1]));
    }

    [Fact]
    public async Task Pass_AdvancesPastPolicyRejections()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "Invalid user a from 192.0.2.1 port 1\n");
        RecordingHandler handler = new(_ => HttpStatusCode.UnprocessableEntity);
        (DockerSidecarWorker worker, _) = await CreateAsync(root, handler, cancellationToken);

        SidecarPassResult first = await worker.ProcessOnceAsync(cancellationToken);
        SidecarPassResult second = await worker.ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, first.Rejected);
        Assert.False(first.Backpressure);
        Assert.Equal(0, second.Rejected);
        Assert.Single(handler.Bodies);
    }

    [Fact]
    public async Task Pass_TreatsNetworkFailureAsBackpressure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "Invalid user a from 192.0.2.1 port 1\n");
        RecordingHandler handler = new(_ => throw new HttpRequestException("connection refused"));
        (DockerSidecarWorker worker, _) = await CreateAsync(root, handler, cancellationToken);

        SidecarPassResult result = await worker.ProcessOnceAsync(cancellationToken);

        Assert.True(result.Backpressure);
    }

    [Fact]
    public async Task Pass_LogsALineOpenAtRotationOnceWhenTheMoveIsCommitted()
    {
        // Event 3006 belongs to the move to the new file. A pass that rewinds into .1 under
        // backpressure reads the rotation again, so only the pass that commits it logs it.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        HttpStatusCode status = HttpStatusCode.Accepted;
        RecordingHandler handler = new(_ => status);
        RecordingLogger logger = new();
        (DockerSidecarWorker worker, _) = await CreateAsync(root, handler, cancellationToken, logger);
        await worker.ProcessOnceAsync(cancellationToken);
        DockerFixture.Append(container, "Invalid user a from 192.0.2.1 port 1\n", "Invalid user b from 192.0.2.2 port ");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, "1\n");

        status = HttpStatusCode.ServiceUnavailable;
        SidecarPassResult refused = await worker.ProcessOnceAsync(cancellationToken);
        int afterRefusal = logger.Count(3006);
        status = HttpStatusCode.Accepted;
        SidecarPassResult moved = await worker.ProcessOnceAsync(cancellationToken);
        int afterMove = logger.Count(3006);
        SidecarPassResult joined = await worker.ProcessOnceAsync(cancellationToken);

        Assert.True(refused.Backpressure);
        Assert.Equal((0, 1), (afterRefusal, afterMove));
        Assert.Equal(1, logger.Count(3006));
        Assert.Equal((1, 1), (moved.Forwarded, joined.Forwarded));
        Assert.Contains("\"username\":\"b\"", handler.Bodies[^1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Pass_DropsAndCountsFragmentsWithoutSendingThem()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        DockerContainer container = DockerFixture.Catalogued(root);
        DockerFixture.Append(container, "before rotation, long enough to fingerprint\n");
        RecordingHandler handler = new(_ => HttpStatusCode.Accepted);
        RecordingLogger logger = new();
        (DockerSidecarWorker worker, _) = await CreateAsync(root, handler, cancellationToken, logger);
        await worker.ProcessOnceAsync(cancellationToken);
        DockerFixture.Append(container, "comment from a user: ");
        File.Move(container.LogPath, container.LogPath + ".1");
        DockerFixture.Append(container, DockerLineIdentityTests.Envelope() + "\n");
        await worker.ProcessOnceAsync(cancellationToken);
        // The head is lost before the rest is read: the rest, a whole envelope, is a fragment.
        File.Delete(container.LogPath + ".1");

        SidecarPassResult result = await worker.ProcessOnceAsync(cancellationToken);

        Assert.Equal((1, 0, 0), (result.Fragments, result.Forwarded, result.Dropped));
        Assert.Empty(handler.Bodies);
        // The lost head is a gap (event 3003); the pass summary (3001) carries the count.
        Assert.Equal(1, logger.Count(3003));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task Pass_RewindsToTheRecordsResumeCursorSoInterleavedLinesKeepTheirIds(int refusedSend)
    {
        // A stderr line between two chunks of a stdout line. Whichever send is refused, the
        // retry re-reads both lines whole, with the same event ids as a pass that was not refused.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        List<string> expected = await IdsAsync(refuse: null);
        List<string> retried = await IdsAsync(refusedSend);

        Assert.Equal(2, expected.Count);
        Assert.Equal(expected.Order(StringComparer.Ordinal), retried.Distinct().Order(StringComparer.Ordinal));

        async Task<List<string>> IdsAsync(int? refuse)
        {
            using TemporaryDirectory root = new();
            DockerContainer container = DockerFixture.Catalogued(root);
            DockerFixture.AppendAt(container, "stdout", DockerFixture.Time(1), "sshd[1]: Failed password for root from 10.0.0.");
            DockerFixture.AppendAt(container, "stderr", DockerFixture.Time(2), "Invalid user a from 192.0.2.1 port 1\n");
            DockerFixture.AppendAt(container, "stdout", DockerFixture.Time(1), "12 port 22 ssh2\n");
            int sends = 0;
            List<string> accepted = [];
            RecordingHandler handler = new(body =>
            {
                if (sends++ == refuse)
                {
                    return HttpStatusCode.ServiceUnavailable;
                }

                accepted.Add(body);
                return HttpStatusCode.Accepted;
            });
            (DockerSidecarWorker worker, _) = await CreateAsync(root, handler, cancellationToken);
            await worker.ProcessOnceAsync(cancellationToken);
            await worker.ProcessOnceAsync(cancellationToken);
            Assert.Contains(accepted, body => body.Contains("\"ipAddress\":\"10.0.0.12\"", StringComparison.Ordinal));
            return [.. accepted.Select(EventId)];
        }
    }

    [Theory]
    [InlineData("http://bower-collector:4319", true)]
    [InlineData("http://127.0.0.1:4319", true)]
    [InlineData("https://collector.example.test", true)]
    [InlineData("http://collector.example.test", false)]
    public void Settings_RequireHttpsForRemoteCollectorWithToken(string url, bool valid)
    {
        Dictionary<string, string> environment = new()
        {
            ["BOWER_COLLECTOR_URL"] = url,
            ["BOWER_INGEST_TOKEN"] = Token
        };

        if (valid)
        {
            SidecarSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        }
        else
        {
            Assert.Throws<InvalidOperationException>(
                () => SidecarSettings.FromEnvironment(name => environment.GetValueOrDefault(name)));
        }
    }

    [Fact]
    public void Health_FailsWithoutRecentHeartbeat()
    {
        using TemporaryDirectory directory = new();
        SidecarSettings settings = Settings(directory.Path) with
        {
            HeartbeatPath = Path.Combine(directory.Path, "heartbeat")
        };

        int missing = SidecarHealth.Check(settings);
        File.WriteAllText(settings.HeartbeatPath, TestEvents.Now.ToString("O"));
        int fresh = SidecarHealth.Check(settings, new FakeClock(TestEvents.Now.AddSeconds(20)));
        int stale = SidecarHealth.Check(settings, new FakeClock(TestEvents.Now.AddHours(1)));

        Assert.Equal(1, missing);
        Assert.Equal(0, fresh);
        Assert.Equal(1, stale);
    }

    private static async Task<(DockerSidecarWorker Worker, EfSourceCursorStore Store)> CreateAsync(
        TemporaryDirectory root,
        RecordingHandler handler,
        CancellationToken cancellationToken,
        ILogger<DockerSidecarWorker>? logger = null)
    {
        SidecarSettings settings = Settings(root.Path);
        EfSourceCursorStore store = new(Path.Combine(root.Path, "cursors.db"));
        await store.InitializeAsync(cancellationToken);
        HttpClient client = new(handler) { BaseAddress = settings.CollectorUrl };
        DockerSidecarWorker worker = new(
            settings,
            store,
            new CollectorClient(client, settings.IngestToken),
            TimeProvider.System,
            logger ?? NullLogger<DockerSidecarWorker>.Instance);
        return (worker, store);
    }

    private static string EventId(string json) =>
        System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("eventId").GetString()!;

    private static SidecarSettings Settings(string root) =>
        new()
        {
            SidecarId = "sidecar-test",
            CollectorUrl = new Uri("http://bower-collector:4319/"),
            IngestToken = Token,
            DockerRoot = root,
            ReadExistingLogs = true
        };

    /// <summary>Counts log events by id (metadata only: the sidecar never logs line content).</summary>
    private sealed class RecordingLogger : ILogger<DockerSidecarWorker>
    {
        private readonly List<int> events = [];

        public int Count(int eventId) => events.Count(id => id == eventId);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            events.Add(eventId.Id);
    }

    private sealed class RecordingHandler(Func<string, HttpStatusCode> respond) : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];

        public List<string> Authorizations { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Bodies.Add(body);
            Authorizations.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            return new HttpResponseMessage(respond(body));
        }
    }
}
