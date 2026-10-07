using System.Net;
using Bower.Agent.Docker;
using Bower.Persistence;
using Bower.Source.Docker;
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
        CancellationToken cancellationToken)
    {
        SidecarSettings settings = Settings(root.Path);
        EfSourceCursorStore store = new(Path.Combine(root.Path, "cursors.db"));
        await store.InitializeAsync(cancellationToken);
        HttpClient client = new(handler) { BaseAddress = settings.CollectorUrl };
        DockerSidecarWorker worker = new(
            settings,
            store,
            new CollectorClient(client, settings),
            TimeProvider.System,
            NullLogger<DockerSidecarWorker>.Instance);
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
