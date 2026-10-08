using System.Net;
using System.Text;
using System.Text.Json;
using Bower.Agent.Cloud;
using Bower.Agent.Cloud.Aws;
using Bower.Agent.Cloud.Gcp;
using Bower.Contracts;
using Bower.Forwarding;
using Bower.Source.Aws;
using Bower.Source.Gcp;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class CloudForwarderWorkerTests
{
    private const string Token = "cloud-token-0123456789abcdef0123456789";

    [Fact]
    public async Task Pass_AcknowledgesOnlyAfterCollectorAccepts()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("m1", CloudSourceTests.StopLogging), Message("m2", CloudSourceTests.GuardDutyEvent));
        Collector collector = new(_ => HttpStatusCode.Accepted);

        CloudPassResult result = await Worker(source, collector).ProcessOnceAsync(cancellationToken);

        Assert.Equal(2, result.Forwarded);
        Assert.False(result.Backpressure);
        Assert.Equal(["m1", "m2"], source.Acknowledged);
        Assert.Empty(source.Released);
        Assert.All(collector.Authorizations, item => Assert.Equal($"Bearer {Token}", item));
    }

    [Fact]
    public async Task Pass_PolicyRejectionStillAcknowledges()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("m1", CloudSourceTests.StopLogging));

        CloudPassResult result = await Worker(source, new Collector(_ => HttpStatusCode.UnprocessableEntity))
            .ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, result.Rejected);
        Assert.Equal(["m1"], source.Acknowledged);
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task Pass_BackpressureReleasesWithoutDeleting(HttpStatusCode status)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(
            Message("m1", CloudSourceTests.StopLogging),
            Message("m2", CloudSourceTests.SecurityHubEvent),
            Message("m3", CloudSourceTests.GuardDutyEvent));
        int calls = 0;
        // First message lands, then the collector pushes back part-way through the Security Hub batch.
        Collector collector = new(_ => ++calls <= 2 ? HttpStatusCode.Accepted : status);

        CloudPassResult result = await Worker(source, collector).ProcessOnceAsync(cancellationToken);

        Assert.True(result.Backpressure);
        Assert.Equal(["m1"], source.Acknowledged);
        Assert.Equal(["m2", "m3"], source.Released.Select(item => item.Id));
        Assert.All(source.Released, item => Assert.Equal(TimeSpan.FromSeconds(60), item.Delay));
    }

    [Fact]
    public async Task Pass_RetriedMessageResendsSameEventIds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("m1", CloudSourceTests.StopLogging));
        HttpStatusCode status = HttpStatusCode.ServiceUnavailable;
        Collector collector = new(_ => status);
        CloudForwarderWorker worker = Worker(source, collector);

        await worker.ProcessOnceAsync(cancellationToken);
        source.Redeliver();
        status = HttpStatusCode.Accepted;
        await worker.ProcessOnceAsync(cancellationToken);

        Assert.Equal(2, collector.Bodies.Count);
        Assert.Equal(EventId(collector.Bodies[0]), EventId(collector.Bodies[1]));
        Assert.Equal(["m1"], source.Acknowledged);
    }

    [Fact]
    public async Task Pass_MalformedMessagesAreReleasedImmediatelyForDeadLettering()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("bad", "not json"), Message("good", CloudSourceTests.StopLogging));

        CloudPassResult result = await Worker(source, new Collector(_ => HttpStatusCode.Accepted)).ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, result.Malformed);
        Assert.Equal(["good"], source.Acknowledged);
        (string id, TimeSpan delay) = Assert.Single(source.Released);
        Assert.Equal("bad", id);
        Assert.Equal(TimeSpan.Zero, delay);
    }

    [Fact]
    public async Task Pass_UnsupportedMessagesAreAcknowledgedAndNotForwarded()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("noise", """{"detail-type":"EC2 Instance State-change Notification","detail":{}}"""));
        Collector collector = new(_ => HttpStatusCode.Accepted);

        CloudPassResult result = await Worker(source, collector).ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, result.Unsupported);
        Assert.Empty(collector.Bodies);
        Assert.Equal(["noise"], source.Acknowledged);
    }

    [Fact]
    public async Task Pass_DoesNotReceiveWhileCollectorIsUnreachable()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("m1", CloudSourceTests.StopLogging));
        Collector collector = new(_ => HttpStatusCode.Accepted, reachable: false);

        CloudPassResult result = await Worker(source, collector).ProcessOnceAsync(cancellationToken);

        Assert.True(result.Backpressure);
        Assert.Equal(0, source.Receives);
    }

    [Fact]
    public async Task Pass_ThrottledEventIsRetriedInPlace()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("m1", CloudSourceTests.StopLogging));
        int calls = 0;
        Collector collector = new(_ => ++calls == 1 ? HttpStatusCode.TooManyRequests : HttpStatusCode.Accepted);

        CloudPassResult result = await Worker(source, collector).ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, result.Forwarded);
        Assert.Equal(["m1"], source.Acknowledged);
    }

    [Fact]
    public async Task Pass_S3ObjectsAreReadOnlyFromAllowedBuckets()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string envelope = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(TestEvents.Now, "app-1"), BowerJson.Options);
        FakeObjects objects = new(Encoding.UTF8.GetBytes(envelope + "\nplain\n"));
        FakeSource source = new(
            Message("allowed", CloudSourceTests.S3Notification),
            Message("other", CloudSourceTests.S3Notification.Replace("bower-app-logs", "someone-else", StringComparison.Ordinal)));
        Collector collector = new(_ => HttpStatusCode.Accepted);

        CloudPassResult result = await Worker(source, collector, objects).ProcessOnceAsync(cancellationToken);

        Assert.Equal(1, result.Forwarded);
        Assert.Equal(1, result.Unsupported);
        Assert.Equal(["bower-app-logs"], objects.Buckets);
        Assert.Equal("123456789012", objects.Owners.Single());
        Assert.Equal(["allowed", "other"], source.Acknowledged);
    }

    [Fact]
    public async Task Pass_S3ReadFailureKeepsMessage()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeObjects objects = new(null);
        FakeSource source = new(Message("m1", CloudSourceTests.S3Notification));

        CloudPassResult result = await Worker(source, new Collector(_ => HttpStatusCode.Accepted), objects)
            .ProcessOnceAsync(cancellationToken);

        Assert.True(result.Backpressure);
        Assert.Empty(source.Acknowledged);
        Assert.Equal("m1", source.Released.Single().Id);
    }

    [Fact]
    public async Task Pass_PubSubMessagesAreMapped()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(
            new CloudMessage("p1", "ack-1", Encoding.UTF8.GetBytes(CloudSourceTests.AuditLogEntry), 1),
            new CloudMessage("p2", "ack-2", Encoding.UTF8.GetBytes(CloudSourceTests.SccNotification), 1),
            new CloudMessage("p3", "ack-3", [], 1));
        Collector collector = new(_ => HttpStatusCode.Accepted);
        PubSubMessageTranslator translator = new(new GcpSecurityEventMapper(new GcpSourceOptions { SourceId = "gcp:test" }), TimeProvider.System);

        CloudPassResult result = await new CloudForwarderWorker(
                source, translator, Client(collector), Settings(), TimeProvider.System, NullLogger<CloudForwarderWorker>.Instance)
            .ProcessOnceAsync(cancellationToken);

        Assert.Equal(2, result.Forwarded);
        Assert.Equal(1, result.Malformed);
        Assert.Contains("\"eventType\":\"gcp_cloud_audit\"", collector.Bodies[0], StringComparison.Ordinal);
        Assert.Contains("\"eventType\":\"gcp_scc_finding\"", collector.Bodies[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task PubSub_RestCallsUseSubscriptionAndBearerToken()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string data = Convert.ToBase64String(Encoding.UTF8.GetBytes(CloudSourceTests.AuditLogEntry));
        List<(string Path, string Body, string? Authorization)> calls = [];
        Handler handler = new(async request =>
        {
            calls.Add((request.RequestUri!.AbsolutePath, await request.Content!.ReadAsStringAsync(cancellationToken), request.Headers.Authorization?.ToString()));
            string json = request.RequestUri.AbsolutePath.EndsWith(":pull", StringComparison.Ordinal)
                ? $$"""{"receivedMessages":[{"ackId":"a1","message":{"data":"{{data}}","messageId":"42"},"deliveryAttempt":3}]}"""
                : "{}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        });
        PubSubMessageSource source = new(
            new HttpClient(handler) { BaseAddress = new Uri("https://pubsub.googleapis.com/") },
            new StaticToken(),
            "projects/bower-prod/subscriptions/bower-security");

        CloudMessage message = Assert.Single(await source.ReceiveAsync(10, cancellationToken));
        await source.AcknowledgeAsync(message, cancellationToken);
        await source.ReleaseAsync(message, TimeSpan.FromSeconds(90), cancellationToken);

        Assert.Equal("42", message.Id);
        Assert.Equal(3, message.DeliveryAttempt);
        Assert.Equal(CloudSourceTests.AuditLogEntry, Encoding.UTF8.GetString(message.Body));
        Assert.Equal("/v1/projects/bower-prod/subscriptions/bower-security:pull", calls[0].Path);
        Assert.Equal("/v1/projects/bower-prod/subscriptions/bower-security:acknowledge", calls[1].Path);
        Assert.Contains("\"ackIds\":[\"a1\"]", calls[1].Body, StringComparison.Ordinal);
        Assert.Contains("\"ackDeadlineSeconds\":90", calls[2].Body, StringComparison.Ordinal);
        Assert.All(calls, call => Assert.Equal("Bearer test-access-token", call.Authorization));
    }

    [Fact]
    public async Task PubSub_ErrorStatusThrowsWithoutBody()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        Handler handler = new(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("{\"error\":{\"message\":\"projects/secret-name denied\"}}")
        }));
        PubSubMessageSource source = new(
            new HttpClient(handler) { BaseAddress = new Uri("https://pubsub.googleapis.com/") },
            new StaticToken(),
            "projects/bower-prod/subscriptions/bower-security");

        HttpRequestException exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => source.ReceiveAsync(10, cancellationToken));

        Assert.DoesNotContain("secret-name", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://sqs.ap-southeast-2.amazonaws.com/123456789012/bower-security", null, "ap-southeast-2")]
    [InlineData("https://sqs.ap-southeast-4.amazonaws.com/123456789012/bower-security", null, "ap-southeast-4")]
    [InlineData("https://vpce-123.sqs.ap-southeast-2.vpce.amazonaws.com/123456789012/q", "ap-southeast-2", "ap-southeast-2")]
    public void Settings_ReadRegionAndAccountFromQueueUrl(string url, string? region, string expected)
    {
        Dictionary<string, string?> environment = new()
        {
            ["BOWER_AWS_SQS_QUEUE_URL"] = url,
            ["BOWER_AWS_REGION"] = region,
            ["BOWER_REQUIRE_AU_REGION"] = "true"
        };

        CloudAgentSettings settings = CloudAgentSettings.FromEnvironment(name => environment.GetValueOrDefault(name));

        Assert.Equal(expected, settings.Aws!.Region);
        Assert.Equal("123456789012", settings.Aws.AccountId);
    }

    [Theory]
    [InlineData("BOWER_AWS_SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/q", "BOWER_REQUIRE_AU_REGION", "true")]
    [InlineData("BOWER_AWS_SQS_QUEUE_URL", "http://sqs.ap-southeast-2.amazonaws.com/123456789012/q", null, null)]
    [InlineData("BOWER_AWS_SQS_QUEUE_URL", "https://sqs.ap-southeast-2.amazonaws.com/123456789012/q", "AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")]
    [InlineData("BOWER_GCP_SUBSCRIPTION", "bower-security", null, null)]
    [InlineData("BOWER_GCP_SUBSCRIPTION", "projects/bower-prod/subscriptions/s1", "BOWER_GCP_PUBSUB_ENDPOINT", "http://pubsub.example.test")]
    [InlineData("BOWER_COLLECTOR_URL", "http://bower-collector:4319", null, null)]
    public void Settings_RejectUnsafeOrIncompleteConfiguration(string name, string value, string? extraName, string? extraValue)
    {
        Dictionary<string, string?> environment = new() { [name] = value };
        if (extraName is not null)
        {
            environment[extraName] = extraValue;
        }

        Assert.Throws<InvalidOperationException>(
            () => CloudAgentSettings.FromEnvironment(item => environment.GetValueOrDefault(item)));
    }

    [Fact]
    public void Settings_AllowTemporaryAwsCredentials()
    {
        Dictionary<string, string?> environment = new()
        {
            ["BOWER_AWS_SQS_QUEUE_URL"] = "https://sqs.ap-southeast-2.amazonaws.com/123456789012/q",
            ["AWS_ACCESS_KEY_ID"] = "ASIAEXAMPLE",
            ["AWS_SESSION_TOKEN"] = "session"
        };

        Assert.NotNull(CloudAgentSettings.FromEnvironment(name => environment.GetValueOrDefault(name)).Aws);
    }

    [Fact]
    public void Health_RequiresHeartbeatForEverySource()
    {
        using TemporaryDirectory directory = new();
        CloudAgentSettings settings = Settings() with
        {
            HeartbeatDirectory = directory.Path,
            Gcp = new GcpSubscriptionSettings { Subscription = "projects/bower-prod/subscriptions/s1" }
        };
        File.WriteAllText(settings.HeartbeatPath("aws-sqs"), TestEvents.Now.ToString("O"));

        int partial = CloudHealth.Check(settings, new FakeClock(TestEvents.Now));
        File.WriteAllText(settings.HeartbeatPath("gcp-pubsub"), TestEvents.Now.ToString("O"));
        int healthy = CloudHealth.Check(settings, new FakeClock(TestEvents.Now.AddMinutes(1)));
        int stale = CloudHealth.Check(settings, new FakeClock(TestEvents.Now.AddHours(1)));

        Assert.Equal(1, partial);
        Assert.Equal(0, healthy);
        Assert.Equal(1, stale);
    }

    [Fact]
    public void GoogleCredentials_RefuseServiceAccountKeysByDefault()
    {
        using System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(2048);
        Google.Apis.Auth.OAuth2.ServiceAccountCredential key = new(
            new Google.Apis.Auth.OAuth2.ServiceAccountCredential.Initializer("bower@bower-prod.iam.gserviceaccount.com")
            {
                Key = rsa
            });

        Assert.Throws<InvalidOperationException>(() => GoogleAccessTokenSource.Check(key, allowServiceAccountKey: false));
        GoogleAccessTokenSource.Check(key, allowServiceAccountKey: true);
    }

    private static CloudMessage Message(string id, string body) => new(id, $"handle-{id}", Encoding.UTF8.GetBytes(body), 1);

    private static string EventId(string json) => JsonDocument.Parse(json).RootElement.GetProperty("eventId").GetString()!;

    private static CloudAgentSettings Settings() =>
        new()
        {
            AgentId = "cloud-test",
            CollectorUrl = new Uri("http://bower-collector:4319/"),
            IngestToken = Token,
            Aws = new AwsQueueSettings
            {
                QueueUrl = new Uri("https://sqs.ap-southeast-2.amazonaws.com/123456789012/bower-security"),
                Region = "ap-southeast-2",
                AccountId = "123456789012",
                AllowedBuckets = new HashSet<string>(["bower-app-logs"], StringComparer.Ordinal)
            }
        };

    private static CollectorClient Client(Collector collector) =>
        new(new HttpClient(collector) { BaseAddress = new Uri("http://bower-collector:4319/") }, Token);

    private static CloudForwarderWorker Worker(FakeSource source, Collector collector, IS3ObjectReader? objects = null)
    {
        CloudAgentSettings settings = Settings();
        AwsMessageTranslator translator = new(
            new AwsQueueMessageParser(new AwsQueueOptions
            {
                SourceId = "aws:123456789012:ap-southeast-2",
                AccountId = "123456789012",
                Region = "ap-southeast-2"
            }),
            objects,
            settings.Aws!,
            TimeProvider.System,
            NullLogger<AwsMessageTranslator>.Instance);
        return new CloudForwarderWorker(source, translator, Client(collector), settings, TimeProvider.System, NullLogger<CloudForwarderWorker>.Instance);
    }

    private sealed class FakeSource(params CloudMessage[] messages) : ICloudMessageSource
    {
        private List<CloudMessage> pending = [.. messages];

        public string Name => "fake";

        public int Receives { get; private set; }

        public List<string> Acknowledged { get; } = [];

        public List<(string Id, TimeSpan Delay)> Released { get; } = [];

        public void Redeliver() => pending = [.. messages.Where(item => !Acknowledged.Contains(item.Id))];

        public Task<IReadOnlyList<CloudMessage>> ReceiveAsync(int maximum, CancellationToken cancellationToken)
        {
            Receives++;
            IReadOnlyList<CloudMessage> batch = pending.Take(maximum).ToList();
            pending = [];
            return Task.FromResult(batch);
        }

        public Task AcknowledgeAsync(CloudMessage message, CancellationToken cancellationToken)
        {
            Acknowledged.Add(message.Id);
            return Task.CompletedTask;
        }

        public Task ReleaseAsync(CloudMessage message, TimeSpan delay, CancellationToken cancellationToken)
        {
            Released.Add((message.Id, delay));
            return Task.CompletedTask;
        }

        public Task ExtendAsync(CloudMessage message, TimeSpan lease, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FakeObjects(byte[]? content) : IS3ObjectReader
    {
        public List<string> Buckets { get; } = [];

        public List<string> Owners { get; } = [];

        public Task<byte[]> ReadAsync(string bucket, string key, string expectedOwner, long maximumBytes, CancellationToken cancellationToken)
        {
            Buckets.Add(bucket);
            Owners.Add(expectedOwner);
            return content is null
                ? throw new HttpRequestException("s3 unavailable")
                : Task.FromResult(content);
        }
    }

    private sealed class StaticToken : IGoogleAccessTokenSource
    {
        public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult("test-access-token");
    }

    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond(request);
    }

    /// <summary>Collector stand-in: /health reports reachability; /v1/events uses the responder.</summary>
    private sealed class Collector(Func<string, HttpStatusCode> respond, bool reachable = true) : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];

        public List<string> Authorizations { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Get)
            {
                return reachable ? new HttpResponseMessage(HttpStatusCode.OK) : throw new HttpRequestException("connection refused");
            }

            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Bodies.Add(body);
            Authorizations.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            return new HttpResponseMessage(respond(body));
        }
    }
}
