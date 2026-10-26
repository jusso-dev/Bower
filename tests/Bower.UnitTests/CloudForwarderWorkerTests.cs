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
    private static readonly TimeSpan Lease = TimeSpan.FromSeconds(60);

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
    [InlineData(HttpStatusCode.Conflict)]
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

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task Pass_RetriedMessageResendsSameEventIds(HttpStatusCode initialStatus)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeSource source = new(Message("m1", CloudSourceTests.StopLogging));
        HttpStatusCode status = initialStatus;
        Collector collector = new(_ => status);
        CloudForwarderWorker worker = Worker(source, collector);

        await worker.ProcessOnceAsync(cancellationToken);
        Assert.Empty(source.Acknowledged);
        Assert.Equal("m1", Assert.Single(source.Released).Id);
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
    public async Task Pass_InvalidPermissionContextIsReleasedForDeadLetterWithoutAcknowledgement()
    {
        const string body = """
            {"detail-type":"AWS API Call via CloudTrail","source":"aws.iam","detail":
            {"eventID":"bad-permission","eventName":"AttachUserPolicy","eventSource":"iam.amazonaws.com",
             "requestParameters":{"userName":"affected-user","policyArn":{"password":"unapproved-canary"}}}}
            """;
        FakeSource source = new(Message("bad", body));
        Collector collector = new(_ => HttpStatusCode.Accepted);
        CloudPassResult result = await Worker(source, collector).ProcessOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, result.Malformed);
        Assert.Empty(source.Acknowledged);
        Assert.Empty(collector.Bodies);
        Assert.Equal(("bad", TimeSpan.Zero), Assert.Single(source.Released));
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

    [Theory]
    [InlineData("forwarding")]
    [InlineData("translation")]
    [InlineData("throttling")]
    public async Task Lease_EveryOutstandingMessageIsRenewedByElapsedTime(string slow)
    {
        // Issue #65: 60 s lease, a slow first message (31 events at 2 s each, a 90 s
        // translation, or three events throttled for 25 s each) and a second message
        // waiting in the batch. Fewer than 200 events, so count-based renewal never ran.
        ManualTimeProvider clock = new(TestEvents.Now);
        LeasedSource source = new(clock, Lease, Message("m1", "{}"), Message("m2", "{}"));
        SlowTranslator translator = new(clock, message => slow switch
        {
            "translation" when message.Id == "m1" => (TimeSpan.FromSeconds(90), 1),
            "forwarding" when message.Id == "m1" => (TimeSpan.Zero, 31),
            "throttling" when message.Id == "m1" => (TimeSpan.Zero, 3),
            _ => (TimeSpan.Zero, 1)
        });
        Dictionary<string, int> attempts = new(StringComparer.Ordinal);
        TimedCollector collector = new(
            clock,
            _ => slow == "forwarding" ? TimeSpan.FromSeconds(2) : TimeSpan.Zero,
            body => slow == "throttling" && body.Contains("m1", StringComparison.Ordinal)
                && (attempts[body] = attempts.GetValueOrDefault(body) + 1) <= 25
                    ? HttpStatusCode.TooManyRequests
                    : HttpStatusCode.Accepted);

        CloudPassResult result = await DriveAsync(clock, () => LeaseWorker(source, translator, collector, clock)
            .ProcessOnceAsync(TestContext.Current.CancellationToken));

        Assert.True(clock.GetUtcNow() - TestEvents.Now > Lease, "the scenario must outlast one lease");
        Assert.Equal(0, result.LeaseLost);
        Assert.False(result.Backpressure);
        Assert.Equal(["m1", "m2"], source.Acknowledged);
        Assert.Empty(source.Released);
        Assert.Equal(0, source.ExpiredCalls);
        // The waiting message is renewed while the first one is still being worked on.
        DateTimeOffset waitingStarted = translator.Translated.Single(item => item.Id == "m2").At;
        Assert.True(source.Extensions.Count(item => item.Id == "m2" && item.At < waitingStarted) >= 2);
    }

    [Theory]
    [InlineData("m1")]
    [InlineData("m2")]
    public async Task Lease_RenewalFailureStopsWorkAndIsNotAcknowledged(string failing)
    {
        ManualTimeProvider clock = new(TestEvents.Now);
        LeasedSource source = new(clock, Lease, Message("m1", "{}"), Message("m2", "{}"))
        {
            // The first renewal (on receive) succeeds; the one at 30 s fails.
            Extend = (id, attempt, _) => id == failing && attempt == 2
                ? Task.FromException(new HttpRequestException("queue unavailable"))
                : Task.CompletedTask
        };
        SlowTranslator translator = new(clock, message => (TimeSpan.Zero, message.Id == "m1" ? 31 : 1));
        TimedCollector collector = new(clock, SlowFirstMessage, _ => HttpStatusCode.Accepted);

        CloudPassResult result = await DriveAsync(clock, () => LeaseWorker(source, translator, collector, clock)
            .ProcessOnceAsync(TestContext.Current.CancellationToken));

        string other = failing == "m1" ? "m2" : "m1";
        Assert.Equal(1, result.LeaseLost);
        Assert.True(result.Backpressure);
        Assert.Equal([other], source.Acknowledged);
        Assert.DoesNotContain(source.Released, item => item.Id == failing);
        Assert.Equal(0, source.ExpiredCalls);
        if (failing == "m1")
        {
            // Forwarding stopped when ownership was lost instead of running to the end.
            Assert.InRange(collector.Bodies.Count(body => body.Contains("m1", StringComparison.Ordinal)), 1, 16);
        }
        else
        {
            Assert.DoesNotContain(translator.Translated, item => item.Id == "m2");
        }
    }

    [Fact]
    public async Task Lease_StalledRenewalLosesOwnershipAtTheDeadline()
    {
        ManualTimeProvider clock = new(TestEvents.Now);
        LeasedSource source = new(clock, Lease, Message("m1", "{}"), Message("m2", "{}"))
        {
            Extend = (id, attempt, token) => id == "m1" && attempt == 2
                ? clock.Delay(Timeout.InfiniteTimeSpan, token)
                : Task.CompletedTask
        };
        SlowTranslator translator = new(clock, message => (TimeSpan.Zero, message.Id == "m1" ? 31 : 1));
        TimedCollector collector = new(clock, SlowFirstMessage, _ => HttpStatusCode.Accepted);

        CloudPassResult result = await DriveAsync(clock, () => LeaseWorker(source, translator, collector, clock)
            .ProcessOnceAsync(TestContext.Current.CancellationToken));

        Assert.Equal(1, result.LeaseLost);
        Assert.Equal(["m2"], source.Acknowledged);
        Assert.Equal(0, source.ExpiredCalls);
        // Ownership from the receive-time renewal ended at 60 s: no m1 event was sent after it.
        Assert.InRange(collector.Bodies.Count(body => body.Contains("m1", StringComparison.Ordinal)), 1, 30);
    }

    [Fact]
    public async Task Lease_LateTimerCallbacksNeverRenewOrSettleAfterTheDeadline()
    {
        // Timer callbacks can run late (a starved thread pool). Translation takes 90 s while
        // no timer fires, then the overdue renewal and expiry timers fire together: the worker
        // must judge ownership by the clock, not by whether the expiry callback has run.
        ManualTimeProvider clock = new(TestEvents.Now);
        LeasedSource source = new(clock, Lease, Message("m1", "{}"), Message("m2", "{}"));
        SlowTranslator translator = new(clock, message =>
        {
            if (message.Id == "m1")
            {
                clock.Jump(TimeSpan.FromSeconds(90));
                clock.Advance(TimeSpan.Zero);
            }

            return (TimeSpan.Zero, 1);
        });
        TimedCollector collector = new(clock, _ => TimeSpan.Zero, _ => HttpStatusCode.Accepted);

        CloudPassResult result = await DriveAsync(clock, () => LeaseWorker(source, translator, collector, clock)
            .ProcessOnceAsync(TestContext.Current.CancellationToken));

        Assert.Equal(0, source.ExpiredCalls);
        Assert.Equal(2, result.LeaseLost);
        Assert.Empty(source.Acknowledged);
        Assert.Empty(source.Released);
        Assert.Equal(2, source.Extensions.Count);
    }

    [Fact]
    public async Task Lease_SettlementJudgesTheDeadlineByTheClock()
    {
        // The expiry callback never gets to run before settlement.
        ManualTimeProvider clock = new(TestEvents.Now);
        LeasedSource source = new(clock, Lease, Message("m1", "{}"));
        SlowTranslator translator = new(clock, _ =>
        {
            clock.Jump(TimeSpan.FromSeconds(61));
            return (TimeSpan.Zero, 1);
        });
        TimedCollector collector = new(clock, _ => TimeSpan.Zero, _ => HttpStatusCode.Accepted);

        CloudPassResult result = await LeaseWorker(source, translator, collector, clock)
            .ProcessOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, source.ExpiredCalls);
        Assert.Equal(1, result.LeaseLost);
        Assert.Empty(source.Acknowledged);
    }

    [Fact]
    public async Task Lease_CancellationStopsRenewalAndDoesNotAcknowledge()
    {
        ManualTimeProvider clock = new(TestEvents.Now);
        LeasedSource source = new(clock, Lease, Message("m1", "{}"), Message("m2", "{}"));
        SlowTranslator translator = new(clock, message => (TimeSpan.Zero, message.Id == "m1" ? 31 : 1));
        TimedCollector collector = new(clock, _ => TimeSpan.FromSeconds(2), _ => HttpStatusCode.Accepted);
        using CancellationTokenSource stopping = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        Task<CloudPassResult> pass = null!;
        Inline(() =>
        {
            pass = LeaseWorker(source, translator, collector, clock).ProcessOnceAsync(stopping.Token);
            clock.Advance(TimeSpan.FromSeconds(40));
        });
        Assert.False(pass.IsCompleted);
        Inline(stopping.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pass);
        int renewals = source.Extensions.Count;
        Inline(() => clock.Advance(TimeSpan.FromMinutes(5)));

        Assert.True(renewals >= 4);
        Assert.Equal(renewals, source.Extensions.Count);
        Assert.Equal(0, clock.ActiveTimers);
        Assert.Empty(source.Acknowledged);
        Assert.Equal(0, source.ExpiredCalls);
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
    [InlineData("BOWER_AWS_SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/q", "BOWER_AWS_REGION", "ap-southeast-2")]
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

    [Theory]
    [InlineData(9)]
    [InlineData(601)]
    public void Settings_RejectLeaseOutsideQueueLimits(int seconds)
    {
        Assert.Throws<InvalidOperationException>(() => (Settings() with { Lease = TimeSpan.FromSeconds(seconds) }).Validate());
        (Settings() with { Lease = TimeSpan.FromSeconds(60) }).Validate();
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
        using TemporaryDirectory directory = new();
        string key = Path.Combine(directory.Path, "key.json");
        File.WriteAllText(
            key,
            JsonSerializer.Serialize(
                new Dictionary<string, string>
                {
                    ["type"] = "service_account",
                    ["client_email"] = "bower@bower-prod.iam.gserviceaccount.com",
                    ["private_key"] = rsa.ExportPkcs8PrivateKeyPem()
                },
                TestJson.Default.DictionaryStringString));
        using GoogleAccessTokenSource refused = new(allowServiceAccountKey: false);
        using GoogleAccessTokenSource allowed = new(allowServiceAccountKey: true);

        Assert.Throws<InvalidOperationException>(() => refused.FromFile(key, "test"));
        Assert.NotNull(allowed.FromFile(key, "test"));
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

    /// <summary>Only m1's events take fake time, so work after m1's lease is lost does not.</summary>
    private static TimeSpan SlowFirstMessage(string body) =>
        body.Contains("m1", StringComparison.Ordinal) ? TimeSpan.FromSeconds(2) : TimeSpan.Zero;

    private static CloudForwarderWorker LeaseWorker(
        LeasedSource source,
        ICloudMessageTranslator translator,
        HttpMessageHandler collector,
        TimeProvider clock) =>
        new(
            source,
            translator,
            new CollectorClient(new HttpClient(collector) { BaseAddress = new Uri("http://bower-collector:4319/") }, Token),
            Settings() with { Lease = Lease },
            clock,
            NullLogger<CloudForwarderWorker>.Instance);

    /// <summary>
    /// Every fake here waits only on the fake clock, and timer continuations run inline, so
    /// advancing the clock steps the pass deterministically. Continuations of cancelled waits
    /// may resume on the thread pool, so work after a lease is lost or the batch ends must not
    /// need fake time; the pass is then awaited in real time.
    /// </summary>
    private static async Task<T> DriveAsync<T>(ManualTimeProvider clock, Func<Task<T>> start)
    {
        Task<T> pass = null!;
        Inline(() =>
        {
            pass = start();
            for (int second = 0; !pass.IsCompleted && second < 3600; second++)
            {
                clock.Advance(TimeSpan.FromSeconds(1));
            }
        });

        return await pass.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Runs on a fresh thread with a large stack and no synchronization context. Continuations
    /// are only inlined while enough stack remains, and a test thread can already be deep.
    /// </summary>
    private static void Inline(Action action)
    {
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? failure = null;
        Thread thread = new(
            () =>
            {
                try
                {
                    action();
                }
                catch (Exception exception)
                {
                    failure = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception);
                }
            },
            64 * 1024 * 1024);
        thread.Start();
        thread.Join();
        failure?.Throw();
    }

    /// <summary>
    /// Queue with real lease semantics: a message received or extended is owned for the
    /// lease; any call made for it after the deadline counts as an expired call.
    /// </summary>
    private sealed class LeasedSource(TimeProvider clock, TimeSpan visibility, params CloudMessage[] messages) : ICloudMessageSource
    {
        private readonly Dictionary<string, DateTimeOffset> deadlines = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> extendAttempts = new(StringComparer.Ordinal);
        private bool received;

        public string Name => "fake";

        /// <summary>Called before each extension with the message id and 1-based attempt.</summary>
        public Func<string, int, CancellationToken, Task>? Extend { get; init; }

        public List<string> Acknowledged { get; } = [];

        public List<(string Id, TimeSpan Delay)> Released { get; } = [];

        public List<(string Id, DateTimeOffset At)> Extensions { get; } = [];

        public int ExpiredCalls { get; private set; }

        public Task<IReadOnlyList<CloudMessage>> ReceiveAsync(int maximum, CancellationToken cancellationToken)
        {
            IReadOnlyList<CloudMessage> batch = received ? [] : messages.Take(maximum).ToList();
            received = true;
            foreach (CloudMessage message in batch)
            {
                deadlines[message.Id] = clock.GetUtcNow() + visibility;
            }

            return Task.FromResult(batch);
        }

        public Task AcknowledgeAsync(CloudMessage message, CancellationToken cancellationToken)
        {
            CountExpired(message);
            Acknowledged.Add(message.Id);
            return Task.CompletedTask;
        }

        public Task ReleaseAsync(CloudMessage message, TimeSpan delay, CancellationToken cancellationToken)
        {
            CountExpired(message);
            Released.Add((message.Id, delay));
            return Task.CompletedTask;
        }

        public async Task ExtendAsync(CloudMessage message, TimeSpan lease, CancellationToken cancellationToken)
        {
            int attempt = extendAttempts[message.Id] = extendAttempts.GetValueOrDefault(message.Id) + 1;
            if (Extend is not null)
            {
                await Extend(message.Id, attempt, cancellationToken);
            }

            CountExpired(message);
            deadlines[message.Id] = clock.GetUtcNow() + lease;
            Extensions.Add((message.Id, clock.GetUtcNow()));
        }

        private void CountExpired(CloudMessage message)
        {
            if (clock.GetUtcNow() >= deadlines[message.Id])
            {
                ExpiredCalls++;
            }
        }
    }

    private sealed class SlowTranslator(ManualTimeProvider clock, Func<CloudMessage, (TimeSpan Delay, int Events)> plan)
        : ICloudMessageTranslator
    {
        public List<(string Id, DateTimeOffset At)> Translated { get; } = [];

        public async Task<CloudTranslation> TranslateAsync(CloudMessage message, CancellationToken cancellationToken)
        {
            Translated.Add((message.Id, clock.GetUtcNow()));
            (TimeSpan delay, int events) = plan(message);
            if (delay > TimeSpan.Zero)
            {
                await clock.Delay(delay, cancellationToken);
            }

            return new CloudTranslation(
                [.. Enumerable.Range(0, events).Select(index => $$"""{"eventId":"{{message.Id}}-{{index}}"}""")],
                0,
                null);
        }
    }

    /// <summary>Collector whose event posts take <paramref name="delay"/> of fake time.</summary>
    private sealed class TimedCollector(ManualTimeProvider clock, Func<string, TimeSpan> delay, Func<string, HttpStatusCode> respond) : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Get)
            {
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Bodies.Add(body);
            if (delay(body) is { Ticks: > 0 } wait)
            {
                await clock.Delay(wait, cancellationToken);
            }

            return new HttpResponseMessage(respond(body));
        }
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
